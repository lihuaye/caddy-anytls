package anytls

import (
	"context"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// Outbound establishes the server-side connections used to reach AnyTLS
// targets after authentication. The built-in "direct" outbound dials from the
// local network stack. External modules can register under the
// caddy.listeners.anytls.outbounds namespace to route egress traffic elsewhere
// (for example through a WireGuard tunnel to another exit host).
//
// Destination policy (private-target and CIDR/port/domain checks) and name
// resolution are applied by the wrapper before the outbound is invoked, so an
// Outbound only needs to move bytes.
//
// Contract for implementers:
//
//   - Both methods are called concurrently from many handler goroutines (one
//     per AnyTLS connection); implementations must be safe for concurrent use.
//   - Every returned net.Conn / net.PacketConn is owned and closed by the
//     relay. Return a dedicated connection per call; never hand out shared or
//     cached connections.
//   - ctx carries the dial deadline and cancellation (connect_timeout);
//     honor it during connection establishment.
type Outbound interface {
	// DialContext opens a stream connection to address for the given network
	// (always "tcp" for AnyTLS TCP targets). The address is always an
	// already-resolved "ip:port" — domains are resolved on the host running
	// Caddy before the outbound is invoked.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// ListenPacket opens a packet connection used for UDP-over-TCP relaying.
	// network is "udp" and address is empty to request an ephemeral socket.
	// The returned connection is used unconnected: the relay calls WriteTo
	// with arbitrary already-resolved UDP destinations, so it must support
	// sending to any address reachable through the outbound.
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

func init() {
	caddy.RegisterModule(&DirectOutbound{})
}

// DirectOutbound dials targets directly from the local network stack. It is the
// default when no outbound is configured and preserves the original egress
// behaviour of the wrapper.
type DirectOutbound struct{}

// CaddyModule returns the Caddy module information.
func (*DirectOutbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.direct",
		New: func() caddy.Module { return new(DirectOutbound) },
	}
}

// DialContext dials directly using the default dialer. The caller is
// responsible for any connect timeout via ctx.
func (*DirectOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

// ListenPacket opens a local UDP socket for UDP-over-TCP relaying.
func (*DirectOutbound) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var listenConfig net.ListenConfig
	return listenConfig.ListenPacket(ctx, network, address)
}

// UnmarshalCaddyfile accepts the bare directive and rejects any options, for
// symmetry with outbounds that do take configuration.
func (*DirectOutbound) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the outbound name
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		return d.Errf("unrecognized direct outbound option %q", d.Val())
	}
	return nil
}

var (
	_ Outbound              = (*DirectOutbound)(nil)
	_ caddy.Module          = (*DirectOutbound)(nil)
	_ caddyfile.Unmarshaler = (*DirectOutbound)(nil)
)
