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
	"net/url"
	"slices"
	"strconv"
	"strings"
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
	var server *caddyhttp.Server
	if serverFromContext, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok && serverFromContext != nil {
		server = serverFromContext
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
	for _, cidr := range append(append([]string{}, lw.AllowCIDRs...), lw.DenyCIDRs...) {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid cidr %q: %w", cidr, err)
		}
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

		case "allow_cidr":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			lw.AllowCIDRs = append(lw.AllowCIDRs, values...)

		case "deny_cidr":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			lw.DenyCIDRs = append(lw.DenyCIDRs, values...)

		case "allow_port":
			values, err := parsePortListDirective(d, "allow_port")
			if err != nil {
				return err
			}
			lw.AllowPorts = append(lw.AllowPorts, values...)

		case "deny_port":
			values, err := parsePortListDirective(d, "deny_port")
			if err != nil {
				return err
			}
			lw.DenyPorts = append(lw.DenyPorts, values...)

		case "allow_domain":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			lw.AllowDomains = append(lw.AllowDomains, values...)

		case "deny_domain":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			lw.DenyDomains = append(lw.DenyDomains, values...)

		case "padding_scheme":
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.PaddingScheme = d.Val()

		case "log_node_info":
			value, err := parseBoolDirective(d, "log_node_info")
			if err != nil {
				return err
			}
			lw.LogNodeInfo = value

		case "node_host":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			lw.NodeHosts = append(lw.NodeHosts, values...)

		case "node_port":
			values, err := parsePortListDirective(d, "node_port")
			if err != nil {
				return err
			}
			if len(values) != 1 {
				return d.Errf("node_port expects exactly one port")
			}
			lw.NodePort = values[0]

		case "node_sni":
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.NodeSNI = d.Val()

		case "node_insecure":
			value, err := parseBoolDirective(d, "node_insecure")
			if err != nil {
				return err
			}
			lw.NodeInsecure = value

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
	lw.AllowCIDRs = config.AllowCIDRs
	lw.DenyCIDRs = config.DenyCIDRs
	lw.AllowPorts = config.AllowPorts
	lw.DenyPorts = config.DenyPorts
	lw.AllowDomains = config.AllowDomains
	lw.DenyDomains = config.DenyDomains
	lw.PaddingScheme = config.PaddingScheme
	lw.LogNodeInfo = config.LogNodeInfo
	lw.NodeHosts = config.NodeHosts
	lw.NodePort = config.NodePort
	lw.NodeSNI = config.NodeSNI
	lw.NodeInsecure = config.NodeInsecure

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

func (lw *ListenerWrapper) logNodeInfo(server *caddyhttp.Server) {
	if !lw.LogNodeInfo {
		return
	}

	hosts := lw.nodeHosts(server)
	if len(hosts) == 0 {
		lw.logger.Warn("anytls node info requested but no node host found",
			zap.String("event", "anytls_node"),
			zap.String("reason", "missing_node_host"),
		)
		return
	}

	port := lw.nodePort(server)
	for _, user := range lw.Users {
		if !user.Enabled {
			continue
		}
		for _, host := range hosts {
			sni := lw.NodeSNI
			if sni == "" {
				sni = host
			}
			lw.logger.Info("anytls node available",
				zap.String("event", "anytls_node"),
				zap.String("user", user.Name),
				zap.String("host", host),
				zap.Uint16("port", port),
				zap.String("sni", sni),
				zap.Bool("insecure", lw.NodeInsecure),
				zap.String("uri", anyTLSURI(user.Password, host, port, sni, lw.NodeInsecure)),
			)
		}
	}
}

func (lw *ListenerWrapper) nodeHosts(server *caddyhttp.Server) []string {
	var hosts []string
	if len(lw.NodeHosts) > 0 {
		hosts = append(hosts, lw.NodeHosts...)
	} else {
		hosts = append(hosts, inferNodeHosts(server)...)
	}
	return normalizeNodeHosts(hosts)
}

func (lw *ListenerWrapper) nodePort(server *caddyhttp.Server) uint16 {
	if lw.NodePort != 0 {
		return lw.NodePort
	}
	if server == nil {
		return 443
	}
	for _, listen := range server.Listen {
		if port, ok := portFromListenAddress(listen); ok {
			return port
		}
	}
	return 443
}

func inferNodeHosts(server *caddyhttp.Server) []string {
	if server == nil {
		return nil
	}

	var hosts []string
	for _, route := range server.Routes {
		for _, matcherSet := range route.MatcherSets {
			for _, matcher := range matcherSet {
				if hostMatcher, ok := matcher.(*caddyhttp.MatchHost); ok {
					hosts = append(hosts, []string(*hostMatcher)...)
				}
			}
		}
		for _, matcherSet := range route.MatcherSetsRaw {
			if rawHosts, ok := matcherSet["host"]; ok {
				var hostMatcher caddyhttp.MatchHost
				if err := json.Unmarshal(rawHosts, &hostMatcher); err == nil {
					hosts = append(hosts, []string(hostMatcher)...)
				}
			}
		}
	}
	return hosts
}

func normalizeNodeHosts(hosts []string) []string {
	normalized := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" || strings.ContainsAny(host, "{*") {
			continue
		}
		host = strings.Trim(host, "[]")
		key := strings.ToLower(host)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, host)
	}
	return normalized
}

func portFromListenAddress(listen string) (uint16, bool) {
	if strings.TrimSpace(listen) == "" {
		return 0, false
	}
	if strings.Contains(listen, "/") {
		return 0, false
	}

	_, portText, err := net.SplitHostPort(listen)
	if err != nil {
		portText = strings.TrimPrefix(listen, ":")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, false
	}
	return uint16(port), true
}

func anyTLSURI(password, host string, port uint16, sni string, insecure bool) string {
	authorityHost := host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		authorityHost = "[" + host + "]"
	}
	if port != 0 && port != 443 {
		authorityHost = net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	}

	values := url.Values{}
	if sni != "" && sni != host {
		values.Set("sni", sni)
	}
	if insecure {
		values.Set("insecure", "1")
	}

	uri := "anytls://" + url.User(password).String() + "@" + authorityHost + "/"
	if encoded := values.Encode(); encoded != "" {
		uri += "?" + encoded
	}
	return uri
}

type directTCPHandler struct {
	config *ListenerWrapper
}

func (h *directTCPHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	startedAt := time.Now()
	connectionID := connectionIDFromContext(ctx)
	h.config.updateSessionUser(connectionID, userFromContext(ctx))
	inbound := newCountingConn(conn)
	var outboundCounter *countingConn
	closeOnce := N.OnceClose(func(err error) {
		if outboundCounter != nil {
			h.config.logger.Debug("anytls relay closed",
				zap.Uint64("connection_id", connectionID),
				zap.String("event", "anytls_relay"),
				zap.String("outcome", "closed"),
				zap.String("protocol", "tcp"),
				zap.String("user", userFromContext(ctx)),
				zap.String("source", source.String()),
				zap.String("destination", destination.String()),
				zap.Int64("bytes_from_client", inbound.BytesRead()),
				zap.Int64("bytes_to_client", inbound.BytesWritten()),
				zap.Int64("bytes_from_target", outboundCounter.BytesRead()),
				zap.Int64("bytes_to_target", outboundCounter.BytesWritten()),
				zap.Duration("duration", time.Since(startedAt)),
			)
		}
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
	outboundCounter = newCountingConn(outbound)

	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "tcp"),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
	)

	relay(ctx, inbound, outboundCounter, closeOnce)
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
	resolvedDestinations, err := h.validateStreamDestination(ctx, destination)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(h.config.ConnectTimeout),
	}
	var errs []error
	for _, resolvedDestination := range resolvedDestinations {
		var conn net.Conn
		if h.config.dialFunc != nil {
			conn, err = h.config.dialFunc(ctx, "tcp", resolvedDestination.String())
		} else {
			conn, err = dialer.DialContext(ctx, "tcp", resolvedDestination.String())
		}
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("dial %s: %w", resolvedDestination.String(), err))
	}
	return nil, errors.Join(errs...)
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

func (h *directTCPHandler) validateStreamDestination(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, error) {
	if !destination.IsValid() || destination.Port == 0 {
		return nil, fmt.Errorf("%w", errInvalidDestination)
	}
	if err := h.validateNameAndPortPolicy(destination); err != nil {
		return nil, err
	}
	if h.config.AllowPrivateTargets && !h.needsCIDRPolicy() {
		return []M.Socksaddr{destination}, nil
	}
	resolvedDestinations, err := h.resolveDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if err := h.validateResolvedDestinationPolicy(destination, resolvedDestinations); err != nil {
		return nil, err
	}
	return resolvedDestinations, nil
}

func (h *directTCPHandler) validatePacketDestination(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, error) {
	if !destination.IsValid() || destination.Port == 0 {
		return nil, fmt.Errorf("%w", errInvalidDestination)
	}
	if err := h.validateNameAndPortPolicy(destination); err != nil {
		return nil, err
	}
	if h.config.AllowPrivateTargets && !h.needsCIDRPolicy() {
		return []M.Socksaddr{destination}, nil
	}
	resolvedDestinations, err := h.resolveDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if err := h.validateResolvedDestinationPolicy(destination, resolvedDestinations); err != nil {
		return nil, err
	}
	return resolvedDestinations, nil
}

func (h *directTCPHandler) preparePacketDestination(ctx context.Context, destination M.Socksaddr) (net.Addr, error) {
	resolvedDestinations, err := h.validatePacketDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	return resolveUDPAddr(resolvedDestinations[0])
}

func (h *directTCPHandler) resolveDestination(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, error) {
	if destination.Addr.IsValid() {
		return []M.Socksaddr{destination}, nil
	}
	resolveFunc := h.config.resolveFunc
	if resolveFunc == nil {
		resolver := net.DefaultResolver
		resolveFunc = resolver.LookupNetIP
	}
	addresses, err := resolveFunc(ctx, "ip", destination.Fqdn)
	if err != nil {
		return nil, fmt.Errorf("resolve destination %s: %w", destination.String(), err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve destination %s: no addresses", destination.String())
	}
	destinations := make([]M.Socksaddr, 0, len(addresses))
	for _, addr := range addresses {
		destinations = append(destinations, M.Socksaddr{Addr: addr, Port: destination.Port})
	}
	return destinations, nil
}

func (h *directTCPHandler) validateNameAndPortPolicy(destination M.Socksaddr) error {
	if containsPort(h.config.DenyPorts, destination.Port) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	if len(h.config.AllowPorts) > 0 && !containsPort(h.config.AllowPorts, destination.Port) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	if destination.Fqdn == "" {
		return nil
	}
	if matchesDomainPolicy(h.config.DenyDomains, destination.Fqdn) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	if len(h.config.AllowDomains) > 0 && !matchesDomainPolicy(h.config.AllowDomains, destination.Fqdn) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	return nil
}

func (h *directTCPHandler) needsCIDRPolicy() bool {
	return len(h.config.AllowCIDRs) > 0 || len(h.config.DenyCIDRs) > 0 || !h.config.AllowPrivateTargets
}

func (h *directTCPHandler) validateResolvedDestinationPolicy(original M.Socksaddr, destinations []M.Socksaddr) error {
	for _, destination := range destinations {
		if matchesCIDRPolicy(h.config.DenyCIDRs, destination.Addr) {
			return fmt.Errorf("%w: %s resolves to %s", errDestinationPolicyDenied, original.String(), destination.Addr.String())
		}
	}
	for _, destination := range destinations {
		private := isPrivateDestination(destination)
		allowedCIDR := matchesCIDRPolicy(h.config.AllowCIDRs, destination.Addr)
		if private && !h.config.AllowPrivateTargets && !allowedCIDR {
			return fmt.Errorf("%w: %s resolves to %s", errPrivateDestinationDenied, original.String(), destination.Addr.String())
		}
		if len(h.config.AllowCIDRs) > 0 && !allowedCIDR {
			return fmt.Errorf("%w: %s resolves to %s", errDestinationPolicyDenied, original.String(), destination.Addr.String())
		}
	}
	return nil
}

func containsPort(ports []uint16, port uint16) bool {
	return slices.Contains(ports, port)
}

func matchesCIDRPolicy(cidrs []string, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func matchesDomainPolicy(patterns []string, domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	for _, pattern := range patterns {
		pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
		switch {
		case pattern == domain:
			return true
		case strings.HasPrefix(pattern, ".") && strings.HasSuffix(domain, pattern):
			return true
		case strings.HasPrefix(pattern, "*.") && strings.HasSuffix(domain, strings.TrimPrefix(pattern, "*")):
			return true
		}
	}
	return false
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

func parsePortListDirective(d *caddyfile.Dispenser, name string) ([]uint16, error) {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return nil, d.ArgErr()
	}
	ports := make([]uint16, 0, len(args))
	for _, arg := range args {
		value, err := strconv.ParseUint(arg, 10, 16)
		if err != nil || value == 0 {
			return nil, d.Errf("parsing %s port %q: must be between 1 and 65535", name, arg)
		}
		ports = append(ports, uint16(value))
	}
	return ports, nil
}
