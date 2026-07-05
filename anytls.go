// Package anytls implements a Caddy listener wrapper that detects AnyTLS
// connections after TLS termination and falls back to the normal site path
// for non-AnyTLS traffic.
package anytls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&ListenerWrapper{})
}

// ListenerWrapper is a Caddy listener wrapper that peeks decrypted bytes to
// decide whether the connection should be handled as AnyTLS or returned to the
// normal website path.
type ListenerWrapper struct {
	Users               []User         `json:"users,omitempty"`
	ProbeTimeout        caddy.Duration `json:"probe_timeout,omitempty"`
	IdleTimeout         caddy.Duration `json:"idle_timeout,omitempty"`
	ConnectTimeout      caddy.Duration `json:"connect_timeout,omitempty"`
	MaxConcurrent       int            `json:"max_concurrent,omitempty"`
	Fallback            bool           `json:"fallback,omitempty"`
	AllowPrivateTargets bool           `json:"allow_private_targets,omitempty"`
	AllowCIDRs          []string       `json:"allow_cidrs,omitempty"`
	DenyCIDRs           []string       `json:"deny_cidrs,omitempty"`
	AllowPorts          []uint16       `json:"allow_ports,omitempty"`
	DenyPorts           []uint16       `json:"deny_ports,omitempty"`
	AllowDomains        []string       `json:"allow_domains,omitempty"`
	DenyDomains         []string       `json:"deny_domains,omitempty"`
	PaddingScheme       string         `json:"padding_scheme,omitempty"`
	LogNodeInfo         bool           `json:"log_node_info,omitempty"`
	NodeHosts           []string       `json:"node_hosts,omitempty"`
	NodePort            uint16         `json:"node_port,omitempty"`
	NodeSNI             string         `json:"node_sni,omitempty"`
	NodeInsecure        bool           `json:"node_insecure,omitempty"`

	logger            *zap.Logger
	active            int64
	connSeq           uint64
	fallbackSet       bool
	registry          *sessionRegistry
	detector          Detector
	service           *singanytls.Service
	websiteConns      sync.Map
	allowCIDRPrefixes []netip.Prefix
	denyCIDRPrefixes  []netip.Prefix
	dialFunc          func(ctx context.Context, network string, address string) (net.Conn, error)
	listenPacketFunc  func(ctx context.Context, network string, address string) (net.PacketConn, error)
	resolveFunc       func(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

// User defines one AnyTLS account.
type User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision sets defaults and runtime dependencies.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.logger = ctx.Logger(lw)

	if lw.ProbeTimeout == 0 {
		lw.ProbeTimeout = caddy.Duration(5 * time.Second)
	}
	if lw.IdleTimeout == 0 {
		lw.IdleTimeout = caddy.Duration(2 * time.Minute)
	}
	if lw.ConnectTimeout == 0 {
		lw.ConnectTimeout = caddy.Duration(10 * time.Second)
	}
	if lw.MaxConcurrent == 0 {
		lw.MaxConcurrent = 128
	}
	if !lw.fallbackSet {
		lw.Fallback = true
	}
	if lw.PaddingScheme == "" {
		lw.PaddingScheme = string(padding.DefaultPaddingScheme)
	}
	if lw.registry == nil {
		lw.registry = newSessionRegistry()
	}
	var server *caddyhttp.Server
	if serverFromContext, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok && serverFromContext != nil {
		server = serverFromContext
		server.RegisterConnContext(lw.websiteConnContext)
		server.RegisterConnState(lw.cleanupWebsiteConn)
	}
	ctx.OnCancel(func() {
		lw.closeActiveSessions("config_unload")
	})
	if err := lw.compileCIDRPolicies(); err != nil {
		return err
	}

	lw.detector = NewPasswordHashDetector(lw.Users)

	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(lw.PaddingScheme),
		Users:         lw.anyTLSUsers(),
		Handler:       &directTCPHandler{config: lw},
		Logger:        zapLogger{base: lw.logger},
	})
	if err != nil {
		return fmt.Errorf("create sing-anytls service: %w", err)
	}
	lw.service = service
	lw.logNodeInfo(server)

	return nil
}

// Validate checks static configuration safety.
func (lw *ListenerWrapper) Validate() error {
	if lw.MaxConcurrent < 0 {
		return fmt.Errorf("max_concurrent must be positive")
	}
	if lw.ProbeTimeout < 0 {
		return fmt.Errorf("probe_timeout must be non-negative")
	}
	if lw.IdleTimeout < 0 {
		return fmt.Errorf("idle_timeout must be non-negative")
	}
	if lw.ConnectTimeout < 0 {
		return fmt.Errorf("connect_timeout must be non-negative")
	}
	if err := lw.compileCIDRPolicies(); err != nil {
		return err
	}
	for _, domain := range append(append([]string{}, lw.AllowDomains...), lw.DenyDomains...) {
		if domain == "" {
			return fmt.Errorf("domain policy entry must not be empty")
		}
	}

	seen := make([]string, 0, len(lw.Users))
	for _, user := range lw.Users {
		if user.Name == "" {
			return fmt.Errorf("user name must not be empty")
		}
		if user.Password == "" {
			return fmt.Errorf("user %q password must not be empty", user.Name)
		}
		if slices.Contains(seen, user.Name) {
			return fmt.Errorf("duplicate user %q", user.Name)
		}
		seen = append(seen, user.Name)
	}

	return nil
}

// WrapListener wraps the listener with AnyTLS-aware connection routing.
func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &wrappedListener{
		Listener: l,
		config:   lw,
	}
}

var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.Validator       = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

func (lw *ListenerWrapper) anyTLSUsers() []singanytls.User {
	users := make([]singanytls.User, 0, len(lw.Users))
	for _, user := range lw.Users {
		if !user.Enabled {
			continue
		}
		users = append(users, singanytls.User{
			Name:     user.Name,
			Password: user.Password,
		})
	}
	return users
}

func (lw *ListenerWrapper) logFallback(conn net.Conn, err error) {
	lw.logger.Debug("connection routed to website",
		zap.String("remote", conn.RemoteAddr().String()),
		zap.String("event", "fallback"),
		zap.String("outcome", "fallback"),
		zap.String("reason", probeFailureReason(err)),
		zap.Error(err),
	)
}

func (lw *ListenerWrapper) prepareWebsiteConn(conn *bufferedConn) (net.Conn, error) {
	prefix, err := conn.BufferedBytes()
	if err != nil {
		return nil, err
	}

	websiteConn := newPrependConn(conn.Conn, prefix)
	if stater, ok := conn.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		lw.websiteConns.Store(websiteConn, tlsStateConn{
			Conn:  websiteConn,
			state: stater.ConnectionState(),
		})
	}

	return websiteConn, nil
}

func (lw *ListenerWrapper) websiteConnContext(ctx context.Context, conn net.Conn) context.Context {
	shadowConn, ok := lw.websiteConns.Load(conn)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, caddyhttp.ConnCtxKey, shadowConn)
}

func (lw *ListenerWrapper) cleanupWebsiteConn(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		lw.websiteConns.Delete(conn)
	}
}

var (
	errInvalidDestination       = errors.New("invalid destination")
	errPrivateDestinationDenied = errors.New("private destination denied")
	errDestinationPolicyDenied  = errors.New("destination policy denied")
	errInvalidUDPOverTCPRequest = errors.New("invalid udp over tcp request")
	errUnsupportedUDPOverTCP    = errors.New("unsupported udp over tcp")
)

func (lw *ListenerWrapper) nextConnectionID() uint64 {
	return atomic.AddUint64(&lw.connSeq, 1)
}

func probeFailureReason(err error) string {
	switch {
	case errors.Is(err, errShortPreview):
		return "short_preview"
	case errors.Is(err, errUnknownUserHash):
		return "unknown_user_hash"
	case errors.Is(err, errDisabledUserHash):
		return "disabled_user"
	default:
		return "probe_error"
	}
}

func dialFailureReason(err error) string {
	switch {
	case errors.Is(err, errInvalidDestination):
		return "invalid_destination"
	case errors.Is(err, errPrivateDestinationDenied):
		return "private_target_denied"
	case errors.Is(err, errDestinationPolicyDenied):
		return "destination_policy_denied"
	case errors.Is(err, errInvalidUDPOverTCPRequest):
		return "invalid_udp_over_tcp_request"
	case errors.Is(err, errUnsupportedUDPOverTCP):
		return "udp_over_tcp_unsupported"
	default:
		return "dial_failed"
	}
}
