// Package anytls implements a Caddy listener wrapper that detects AnyTLS
// connections after TLS termination and falls back to the normal site path
// for non-AnyTLS traffic.
package anytls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
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
	PaddingScheme       string         `json:"padding_scheme,omitempty"`

	logger           *zap.Logger
	active           int64
	connSeq          uint64
	fallbackSet      bool
	registry         *sessionRegistry
	detector         Detector
	service          *singanytls.Service
	websiteConns     sync.Map
	dialFunc         func(ctx context.Context, network string, address string) (net.Conn, error)
	listenPacketFunc func(ctx context.Context, network string, address string) (net.PacketConn, error)
	resolveFunc      func(ctx context.Context, network string, host string) ([]netip.Addr, error)
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
	if server, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok && server != nil {
		server.RegisterConnContext(lw.websiteConnContext)
		server.RegisterConnState(lw.cleanupWebsiteConn)
	}
	ctx.OnCancel(func() {
		lw.closeActiveSessions("config_unload")
	})

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

// UnmarshalCaddyfile configures the listener wrapper from Caddyfile tokens.
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "probe_timeout":
			dur, err := parseDurationDirective(d, "probe_timeout")
			if err != nil {
				return err
			}
			lw.ProbeTimeout = caddy.Duration(dur)

		case "idle_timeout":
			dur, err := parseDurationDirective(d, "idle_timeout")
			if err != nil {
				return err
			}
			lw.IdleTimeout = caddy.Duration(dur)

		case "connect_timeout":
			dur, err := parseDurationDirective(d, "connect_timeout")
			if err != nil {
				return err
			}
			lw.ConnectTimeout = caddy.Duration(dur)

		case "max_concurrent":
			if !d.NextArg() {
				return d.ArgErr()
			}
			value, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("parsing max_concurrent: %v", err)
			}
			lw.MaxConcurrent = value

		case "fallback":
			value, err := parseBoolDirective(d, "fallback")
			if err != nil {
				return err
			}
			lw.Fallback = value
			lw.fallbackSet = true

		case "allow_private_targets":
			value, err := parseBoolDirective(d, "allow_private_targets")
			if err != nil {
				return err
			}
			lw.AllowPrivateTargets = value

		case "padding_scheme":
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.PaddingScheme = d.Val()

		case "user":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.ArgErr()
			}
			lw.Users = append(lw.Users, User{
				Name:     args[0],
				Password: args[1],
				Enabled:  true,
			})

		default:
			return d.ArgErr()
		}
	}

	return nil
}

// UnmarshalJSON preserves explicit false values for booleans with non-zero
// defaults and applies the documented enabled-by-default user behavior.
func (lw *ListenerWrapper) UnmarshalJSON(data []byte) error {
	var config struct {
		Users               []User         `json:"users,omitempty"`
		ProbeTimeout        caddy.Duration `json:"probe_timeout,omitempty"`
		IdleTimeout         caddy.Duration `json:"idle_timeout,omitempty"`
		ConnectTimeout      caddy.Duration `json:"connect_timeout,omitempty"`
		MaxConcurrent       int            `json:"max_concurrent,omitempty"`
		Fallback            bool           `json:"fallback,omitempty"`
		AllowPrivateTargets bool           `json:"allow_private_targets,omitempty"`
		PaddingScheme       string         `json:"padding_scheme,omitempty"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	lw.Users = config.Users
	lw.ProbeTimeout = config.ProbeTimeout
	lw.IdleTimeout = config.IdleTimeout
	lw.ConnectTimeout = config.ConnectTimeout
	lw.MaxConcurrent = config.MaxConcurrent
	lw.Fallback = config.Fallback
	lw.AllowPrivateTargets = config.AllowPrivateTargets
	lw.PaddingScheme = config.PaddingScheme

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if _, ok := raw["fallback"]; ok {
		lw.fallbackSet = true
	} else {
		lw.Fallback = true
	}
	return nil
}

// UnmarshalJSON makes JSON users enabled by default while still allowing
// "enabled": false to disable an account.
func (u *User) UnmarshalJSON(data []byte) error {
	type userAlias User
	var alias userAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*u = User(alias)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if _, ok := raw["enabled"]; !ok {
		u.Enabled = true
	}
	return nil
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

type directTCPHandler struct {
	config *ListenerWrapper
}

func (h *directTCPHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	startedAt := time.Now()
	connectionID := connectionIDFromContext(ctx)
	h.config.updateSessionUser(connectionID, userFromContext(ctx))
	closeOnce := N.OnceClose(func(err error) {
		if onClose != nil {
			onClose(err)
		}
	})

	if isUDPOverTCPDestination(destination) {
		h.handleUDPOverTCP(ctx, conn, source, destination, startedAt, connectionID, closeOnce)
		return
	}

	outbound, err := h.dialContext(ctx, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "tcp"),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
	)

	relay(ctx, conn, outbound, closeOnce)
}

func (h *directTCPHandler) handleUDPOverTCP(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, connectionID uint64, closeOnce N.CloseHandlerFunc) {
	request, err := h.readUDPOverTCPRequest(ctx, conn, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	packetConn, err := h.listenPacketContext(ctx)
	if err != nil {
		h.logOutboundFailure(connectionID, source, request.Destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	uotConn := uot.NewConn(conn, *request)
	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "udp_over_tcp_v2"),
		zap.Bool("uot_is_connect", request.IsConnect),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", request.Destination.String()),
	)

	relayUDPOverTCP(ctx, uotConn, packetConn, h.preparePacketDestination, closeOnce)
}

func (h *directTCPHandler) dialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	resolvedDestination, err := h.validateStreamDestination(ctx, destination)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(h.config.ConnectTimeout),
	}
	if h.config.dialFunc != nil {
		return h.config.dialFunc(ctx, "tcp", resolvedDestination.String())
	}
	return dialer.DialContext(ctx, "tcp", resolvedDestination.String())
}

func (h *directTCPHandler) listenPacketContext(ctx context.Context) (net.PacketConn, error) {
	if h.config.listenPacketFunc != nil {
		return h.config.listenPacketFunc(ctx, "udp", "")
	}

	listenConfig := net.ListenConfig{}
	return listenConfig.ListenPacket(ctx, "udp", "")
}

func (h *directTCPHandler) readUDPOverTCPRequest(ctx context.Context, conn net.Conn, destination M.Socksaddr) (*uot.Request, error) {
	switch destination.Fqdn {
	case uot.MagicAddress:
		request, err := uot.ReadRequest(conn)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidUDPOverTCPRequest, err)
		}
		if request.IsConnect {
			if _, err := h.validatePacketDestination(ctx, request.Destination); err != nil {
				return nil, err
			}
		}
		return request, nil
	case uot.LegacyMagicAddress:
		return &uot.Request{}, nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedUDPOverTCP, destination.String())
	}
}

func (h *directTCPHandler) validateStreamDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsValid() || destination.Port == 0 {
		return M.Socksaddr{}, fmt.Errorf("%w", errInvalidDestination)
	}
	if h.config.AllowPrivateTargets {
		return destination, nil
	}
	resolvedDestination, err := h.resolveDestination(ctx, destination)
	if err != nil {
		return M.Socksaddr{}, err
	}
	if isPrivateDestination(resolvedDestination) {
		return M.Socksaddr{}, fmt.Errorf("%w: %s", errPrivateDestinationDenied, destination.String())
	}
	return resolvedDestination, nil
}

func (h *directTCPHandler) validatePacketDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsValid() || destination.Port == 0 {
		return M.Socksaddr{}, fmt.Errorf("%w", errInvalidDestination)
	}
	if h.config.AllowPrivateTargets {
		return destination, nil
	}
	resolvedDestination, err := h.resolveDestination(ctx, destination)
	if err != nil {
		return M.Socksaddr{}, err
	}
	if isPrivateDestination(resolvedDestination) {
		return M.Socksaddr{}, fmt.Errorf("%w: %s", errPrivateDestinationDenied, destination.String())
	}
	return resolvedDestination, nil
}

func (h *directTCPHandler) preparePacketDestination(ctx context.Context, destination M.Socksaddr) (net.Addr, error) {
	resolvedDestination, err := h.validatePacketDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	return resolveUDPAddr(resolvedDestination)
}

func (h *directTCPHandler) resolveDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if destination.Addr.IsValid() {
		return destination, nil
	}
	resolveFunc := h.config.resolveFunc
	if resolveFunc == nil {
		resolver := net.DefaultResolver
		resolveFunc = resolver.LookupNetIP
	}
	addresses, err := resolveFunc(ctx, "ip", destination.Fqdn)
	if err != nil {
		return M.Socksaddr{}, fmt.Errorf("resolve destination %s: %w", destination.String(), err)
	}
	if len(addresses) == 0 {
		return M.Socksaddr{}, fmt.Errorf("resolve destination %s: no addresses", destination.String())
	}
	for _, addr := range addresses {
		resolved := M.Socksaddr{Addr: addr, Port: destination.Port}
		if isPrivateDestination(resolved) {
			return M.Socksaddr{}, fmt.Errorf("%w: %s resolves to %s", errPrivateDestinationDenied, destination.String(), addr.String())
		}
	}
	return M.Socksaddr{Addr: addresses[0], Port: destination.Port}, nil
}

func (h *directTCPHandler) logOutboundFailure(connectionID uint64, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, user string, err error) {
	protocol := "tcp"
	if isUDPOverTCPDestination(destination) {
		protocol = "udp_over_tcp_v2"
	}
	h.config.logger.Warn("anytls outbound dial failed",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_outbound"),
		zap.String("outcome", "rejected"),
		zap.String("reason", dialFailureReason(err)),
		zap.String("protocol", protocol),
		zap.String("user", user),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
		zap.Duration("duration", time.Since(startedAt)),
		zap.Error(err),
	)
}

func isUDPOverTCPDestination(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}

func isPrivateDestination(destination M.Socksaddr) bool {
	if !destination.Addr.IsValid() {
		return false
	}
	addr := destination.Addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	privateRanges := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
	}
	for _, prefix := range privateRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
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
	case errors.Is(err, errInvalidUDPOverTCPRequest):
		return "invalid_udp_over_tcp_request"
	case errors.Is(err, errUnsupportedUDPOverTCP):
		return "udp_over_tcp_unsupported"
	default:
		return "dial_failed"
	}
}

func parseDurationDirective(d *caddyfile.Dispenser, name string) (time.Duration, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return 0, d.Errf("parsing %s duration: %v", name, err)
	}
	return dur, nil
}

func parseBoolDirective(d *caddyfile.Dispenser, name string) (bool, error) {
	if !d.NextArg() {
		return false, d.ArgErr()
	}
	value, err := strconv.ParseBool(d.Val())
	if err != nil {
		return false, d.Errf("parsing %s boolean: %v", name, err)
	}
	return value, nil
}
