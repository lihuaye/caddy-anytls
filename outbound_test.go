package anytls

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	M "github.com/sagernet/sing/common/metadata"
	"go.uber.org/zap"
)

// recordingOutbound wraps another Outbound and records the addresses it dials,
// so tests can assert the handler routes egress through the configured module.
type recordingOutbound struct {
	inner         Outbound
	mu            sync.Mutex
	dialed        []string
	packetNetwork string
	packetAddress string
	packetConn    net.PacketConn
}

func (o *recordingOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	o.mu.Lock()
	o.dialed = append(o.dialed, address)
	o.mu.Unlock()
	return o.inner.DialContext(ctx, network, address)
}

func (o *recordingOutbound) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	o.mu.Lock()
	o.packetNetwork = network
	o.packetAddress = address
	packetConn := o.packetConn
	o.mu.Unlock()
	if packetConn != nil {
		return packetConn, nil
	}
	return o.inner.ListenPacket(ctx, network, address)
}

func (o *recordingOutbound) dials() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.dialed...)
}

type stubPacketConn struct{}

func (*stubPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func (*stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (*stubPacketConn) Close() error                              { return nil }
func (*stubPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (*stubPacketConn) SetDeadline(time.Time) error               { return nil }
func (*stubPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*stubPacketConn) SetWriteDeadline(time.Time) error          { return nil }

type blockingOutbound struct{}

func (*blockingOutbound) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*blockingOutbound) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

// testRecorderOutbound is a registered outbound module used to verify Caddyfile
// selection and module loading end to end.
type testRecorderOutbound struct {
	DirectOutbound
}

func (*testRecorderOutbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.test-recorder",
		New: func() caddy.Module { return new(testRecorderOutbound) },
	}
}

// UnmarshalCaddyfile is inherited from the embedded DirectOutbound.

// testNotOutbound registers in the outbounds namespace WITHOUT implementing
// Outbound, to exercise the JSON-path type check in Provision.
type testNotOutbound struct{}

func (*testNotOutbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.test-not-outbound",
		New: func() caddy.Module { return new(testNotOutbound) },
	}
}

func init() {
	caddy.RegisterModule(&testRecorderOutbound{})
	caddy.RegisterModule(&testNotOutbound{})
}

func TestDirectOutboundDialsTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = conn.Write([]byte("ok"))
		_ = conn.Close()
	}()

	var outbound DirectOutbound
	conn, err := outbound.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer closeTest(conn)

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("Read() = %q, want %q", buf, "ok")
	}
}

func TestDirectOutboundListenPacket(t *testing.T) {
	var outbound DirectOutbound
	packetConn, err := outbound.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer closeTest(packetConn)

	if _, ok := packetConn.LocalAddr().(*net.UDPAddr); !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", packetConn.LocalAddr())
	}
}

func TestUnmarshalCaddyfileOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound direct
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(wrapper.OutboundRaw, &object); err != nil {
		t.Fatalf("OutboundRaw is not a JSON object: %v", err)
	}
	var dialer string
	if err := json.Unmarshal(object["dialer"], &dialer); err != nil {
		t.Fatalf("dialer key not decodable: %v", err)
	}
	if dialer != "direct" {
		t.Fatalf("dialer = %q, want %q", dialer, "direct")
	}
}

func TestUnmarshalCaddyfileRejectsDuplicateOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound direct
		outbound direct
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("UnmarshalCaddyfile() error = nil, want duplicate outbound error")
	}
}

func TestUnmarshalCaddyfileRejectsUnknownOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound missing
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("UnmarshalCaddyfile() error = nil, want unknown module error")
	}
}

func TestProvisionDefaultsToDirectOutbound(t *testing.T) {
	wrapper := &ListenerWrapper{
		Users:    []User{{Name: "alice", Password: "secret", Enabled: true}},
		logger:   zap.NewNop(),
		registry: newSessionRegistry(),
	}
	if err := wrapper.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := wrapper.outbound.(*DirectOutbound); !ok {
		t.Fatalf("outbound = %T, want *DirectOutbound", wrapper.outbound)
	}
}

func TestProvisionExplicitNullOutboundFallsBackToDirect(t *testing.T) {
	var wrapper ListenerWrapper
	if err := json.Unmarshal([]byte(`{"users":[{"name":"alice","password":"secret"}],"outbound":null}`), &wrapper); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	wrapper.logger = zap.NewNop()
	wrapper.registry = newSessionRegistry()
	if err := wrapper.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := wrapper.outbound.(*DirectOutbound); !ok {
		t.Fatalf("outbound = %T, want *DirectOutbound", wrapper.outbound)
	}
}

func TestProvisionLoadsConfiguredOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound test-recorder
	}
	`)

	wrapper := &ListenerWrapper{
		logger:   zap.NewNop(),
		registry: newSessionRegistry(),
	}
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := wrapper.Provision(ctx); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := wrapper.outbound.(*testRecorderOutbound); !ok {
		t.Fatalf("outbound = %T, want *testRecorderOutbound", wrapper.outbound)
	}
}

func TestProvisionRejectsNonOutboundModule(t *testing.T) {
	wrapper := &ListenerWrapper{
		Users:       []User{{Name: "alice", Password: "secret", Enabled: true}},
		OutboundRaw: json.RawMessage(`{"dialer":"test-not-outbound"}`),
		logger:      zap.NewNop(),
		registry:    newSessionRegistry(),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	err := wrapper.Provision(ctx)
	if err == nil || !strings.Contains(err.Error(), "is not an anytls outbound") {
		t.Fatalf("Provision() error = %v, want rejection of a module that does not implement Outbound", err)
	}
}

func TestDirectOutboundUnmarshalCaddyfileRejectsConfig(t *testing.T) {
	if err := new(DirectOutbound).UnmarshalCaddyfile(caddyfile.NewTestDispenser("direct extra")); err == nil {
		t.Fatal("UnmarshalCaddyfile() accepted an extra argument, want error")
	}
	if err := new(DirectOutbound).UnmarshalCaddyfile(caddyfile.NewTestDispenser("direct {\n\tfoo\n}")); err == nil {
		t.Fatal("UnmarshalCaddyfile() accepted a config block, want error")
	}
}

func TestHandlerDialsThroughConfiguredOutbound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)
	go acceptLoop(context.Background(), listener)

	recorder := &recordingOutbound{inner: new(DirectOutbound)}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.outbound = recorder

	handler := &directTCPHandler{config: wrapper}
	conn, err := handler.dialContext(context.Background(), M.ParseSocksaddr(listener.Addr().String()))
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	closeTest(conn)

	dials := recorder.dials()
	if len(dials) != 1 || dials[0] != listener.Addr().String() {
		t.Fatalf("recorded dials = %v, want [%s]", dials, listener.Addr().String())
	}
}

func TestHandlerListensThroughConfiguredOutbound(t *testing.T) {
	packetConn := new(stubPacketConn)
	recorder := &recordingOutbound{packetConn: packetConn}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.outbound = recorder

	got, err := (&directTCPHandler{config: wrapper}).listenPacketContext(context.Background())
	if err != nil {
		t.Fatalf("listenPacketContext() error = %v", err)
	}
	if got != packetConn {
		t.Fatalf("listenPacketContext() = %T, want configured packet connection", got)
	}
	recorder.mu.Lock()
	network, address := recorder.packetNetwork, recorder.packetAddress
	recorder.mu.Unlock()
	if network != "udp" || address != "" {
		t.Fatalf("ListenPacket() args = (%q, %q), want (\"udp\", \"\")", network, address)
	}
}

func TestHandlerOutboundDialHonorsConnectTimeout(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.ConnectTimeout = caddy.Duration(20 * time.Millisecond)
	wrapper.outbound = new(blockingOutbound)

	_, err := (&directTCPHandler{config: wrapper}).dialResolved(context.Background(), "192.0.2.1:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialResolved() error = %v, want context deadline exceeded", err)
	}
}

func TestHandlerOutboundDialPropagatesCancellation(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.ConnectTimeout = caddy.Duration(time.Second)
	wrapper.outbound = new(blockingOutbound)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := (&directTCPHandler{config: wrapper}).dialResolved(ctx, "192.0.2.1:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dialResolved() error = %v, want context canceled", err)
	}
}

// Domains must be resolved on the host running Caddy before the outbound is
// invoked, even on the allow_private_targets fast path that skips CIDR policy
// checks — the Outbound contract promises an already-resolved "ip:port".
func TestHandlerResolvesDomainBeforeOutbound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)
	go acceptLoop(context.Background(), listener)

	recorder := &recordingOutbound{inner: new(DirectOutbound)}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.outbound = recorder
	wrapper.resolveFunc = func(_ context.Context, _ string, host string) ([]netip.Addr, error) {
		if host != "internal.test" {
			t.Errorf("resolveFunc host = %q, want %q", host, "internal.test")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	port := listener.Addr().(*net.TCPAddr).Port
	handler := &directTCPHandler{config: wrapper}
	conn, err := handler.dialContext(context.Background(), M.Socksaddr{Fqdn: "internal.test", Port: uint16(port)})
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	closeTest(conn)

	want := listener.Addr().String()
	dials := recorder.dials()
	if len(dials) != 1 || dials[0] != want {
		t.Fatalf("recorded dials = %v, want [%s] (outbound must receive a resolved ip:port, not a domain)", dials, want)
	}
}
