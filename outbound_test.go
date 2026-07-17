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
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	"go.uber.org/zap"
)

// recordingOutbound wraps another Outbound and records the addresses it dials,
// so tests can assert the handler routes egress through the configured module.
type recordingOutbound struct {
	inner         Outbound
	mu            sync.Mutex
	dialed        []string
	lookedUp      []string
	lookup        func(context.Context, string, string) ([]netip.Addr, error)
	packetNetwork string
	packetAddress string
	packetConn    net.PacketConn
}

func (o *recordingOutbound) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	o.mu.Lock()
	o.lookedUp = append(o.lookedUp, host)
	lookup := o.lookup
	inner := o.inner
	o.mu.Unlock()
	if lookup != nil {
		return lookup(ctx, network, host)
	}
	if inner == nil {
		return nil, errors.New("lookup not configured")
	}
	return inner.LookupNetIP(ctx, network, host)
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

func (o *recordingOutbound) lookups() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.lookedUp...)
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

func (*blockingOutbound) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("not implemented")
}

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
	conn, err := outbound.DialContext(t.Context(), "tcp", listener.Addr().String())
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
	packetConn, err := outbound.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer closeTest(packetConn)

	if _, ok := packetConn.LocalAddr().(*net.UDPAddr); !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", packetConn.LocalAddr())
	}
}

func TestDirectOutboundLookupNetIP(t *testing.T) {
	var outbound DirectOutbound
	addresses, err := outbound.LookupNetIP(t.Context(), "ip", "localhost")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	if len(addresses) == 0 {
		t.Fatal("LookupNetIP() returned no localhost addresses")
	}
	for _, address := range addresses {
		if !address.IsValid() {
			t.Fatalf("LookupNetIP() returned invalid address %v", address)
		}
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
	if err := wrapper.Provision(caddy.Context{Context: t.Context()}); err != nil {
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
	if err := wrapper.Provision(caddy.Context{Context: t.Context()}); err != nil {
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

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
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
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
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
	go acceptLoop(t.Context(), listener)

	recorder := &recordingOutbound{inner: new(DirectOutbound)}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.outbound = recorder

	handler := &directTCPHandler{config: wrapper}
	conn, err := handler.dialContext(t.Context(), M.ParseSocksaddr(listener.Addr().String()))
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

	got, err := (&directTCPHandler{config: wrapper}).listenPacketContext(t.Context())
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

	_, err := (&directTCPHandler{config: wrapper}).dialResolved(t.Context(), "192.0.2.1:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialResolved() error = %v, want context deadline exceeded", err)
	}
}

func TestHandlerOutboundDialPropagatesCancellation(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.ConnectTimeout = caddy.Duration(time.Second)
	wrapper.outbound = new(blockingOutbound)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := (&directTCPHandler{config: wrapper}).dialResolved(ctx, "192.0.2.1:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dialResolved() error = %v, want context canceled", err)
	}
}

// Domain lookup and dialing must use the same per-user outbound. The outbound
// still receives a resolved ip:port for policy enforcement and happy-eyeballs.
func TestHandlerResolvesDomainThroughSelectedOutbound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)
	go acceptLoop(t.Context(), listener)

	recorder := &recordingOutbound{
		inner: new(DirectOutbound),
		lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip" {
				t.Errorf("LookupNetIP network = %q, want ip", network)
			}
			if host != "internal.test" {
				t.Errorf("LookupNetIP host = %q, want internal.test", host)
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.userOutbound = map[string]Outbound{"alice": recorder}
	wrapper.userOutboundName = map[string]string{"alice": "wg-home"}

	port := listener.Addr().(*net.TCPAddr).Port
	handler := &directTCPHandler{config: wrapper}
	ctx := auth.ContextWithUser(t.Context(), "alice")
	conn, err := handler.dialContext(ctx, M.Socksaddr{Fqdn: "internal.test", Port: uint16(port)})
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	closeTest(conn)

	want := listener.Addr().String()
	dials := recorder.dials()
	if len(dials) != 1 || dials[0] != want {
		t.Fatalf("recorded dials = %v, want [%s] (outbound must receive a resolved ip:port, not a domain)", dials, want)
	}
	if lookups := recorder.lookups(); len(lookups) != 1 || lookups[0] != "internal.test" {
		t.Fatalf("recorded lookups = %v, want [internal.test]", lookups)
	}
}

func TestResolveDestinationSelectsPerUserOutboundResolver(t *testing.T) {
	newResolver := func(address string) *recordingOutbound {
		return &recordingOutbound{
			lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(address)}, nil
			},
		}
	}

	recA := newResolver("192.0.2.10")
	recB := newResolver("192.0.2.20")
	recDefault := newResolver("192.0.2.30")
	wrapper := newTestWrapper(t, []User{
		{Name: "alice", Password: "a-pw", Enabled: true, Outbound: "wg-a"},
		{Name: "bob", Password: "b-pw", Enabled: true, Outbound: "wg-b"},
		{Name: "carol", Password: "c-pw", Enabled: true},
	}, true)
	wrapper.userOutbound = map[string]Outbound{"alice": recA, "bob": recB}
	wrapper.userOutboundName = map[string]string{"alice": "wg-a", "bob": "wg-b"}
	wrapper.defaultOutbound = recDefault
	wrapper.defaultOutboundName = "wg-default"
	handler := &directTCPHandler{config: wrapper}

	for _, tt := range []struct {
		user string
		want string
	}{
		{user: "alice", want: "192.0.2.10:443"},
		{user: "bob", want: "192.0.2.20:443"},
		{user: "carol", want: "192.0.2.30:443"},
	} {
		destinations, err := handler.resolveDestination(
			auth.ContextWithUser(t.Context(), tt.user),
			M.Socksaddr{Fqdn: "service.test", Port: 443},
		)
		if err != nil {
			t.Fatalf("resolveDestination(%s) error = %v", tt.user, err)
		}
		if len(destinations) != 1 || destinations[0].String() != tt.want {
			t.Fatalf("resolveDestination(%s) = %v, want [%s]", tt.user, destinations, tt.want)
		}
	}

	if lookups := recA.lookups(); len(lookups) != 1 || lookups[0] != "service.test" {
		t.Fatalf("alice resolver lookups = %v, want [service.test]", lookups)
	}
	if lookups := recB.lookups(); len(lookups) != 1 || lookups[0] != "service.test" {
		t.Fatalf("bob resolver lookups = %v, want [service.test]", lookups)
	}
	if lookups := recDefault.lookups(); len(lookups) != 1 || lookups[0] != "service.test" {
		t.Fatalf("default resolver lookups = %v, want [service.test]", lookups)
	}
}

// trackedConn is a fake net.Conn that records whether it has been closed, so
// tests can assert loser connections from concurrent dials are cleaned up.
type trackedConn struct {
	closed atomic.Bool
}

func (c *trackedConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (c *trackedConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *trackedConn) Close() error                    { c.closed.Store(true); return nil }
func (c *trackedConn) LocalAddr() net.Addr             { return dummyAddr("tracked-local") }
func (c *trackedConn) RemoteAddr() net.Addr            { return dummyAddr("tracked-remote") }
func (c *trackedConn) SetDeadline(time.Time) error     { return nil }
func (c *trackedConn) SetReadDeadline(time.Time) error { return nil }
func (c *trackedConn) SetWriteDeadline(time.Time) error {
	return nil
}

// gateDialOutbound blocks every DialContext until release is closed, so tests
// can deterministically hold multiple happy-eyeballs dials in flight at once.
type gateDialOutbound struct {
	mu      sync.Mutex
	conns   []*trackedConn
	entered chan struct{}
	release chan struct{}
}

func (*gateDialOutbound) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("not implemented")
}

func (o *gateDialOutbound) DialContext(context.Context, string, string) (net.Conn, error) {
	o.entered <- struct{}{}
	<-o.release
	conn := new(trackedConn)
	o.mu.Lock()
	o.conns = append(o.conns, conn)
	o.mu.Unlock()
	return conn, nil
}

func (o *gateDialOutbound) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (o *gateDialOutbound) trackedConns() []*trackedConn {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]*trackedConn(nil), o.conns...)
}

func TestUnmarshalCaddyfileNamedOutbounds(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret wg-a
		user bob secret2
		outbound wg-a test-recorder
		outbound wg-b direct
		outbound direct
		default_outbound wg-b
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if len(wrapper.OutboundsRaw) != 2 {
		t.Fatalf("len(OutboundsRaw) = %d, want 2", len(wrapper.OutboundsRaw))
	}
	for name, wantDialer := range map[string]string{"wg-a": "test-recorder", "wg-b": "direct"} {
		raw, ok := wrapper.OutboundsRaw[name]
		if !ok {
			t.Fatalf("OutboundsRaw missing key %q", name)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatalf("OutboundsRaw[%q] is not a JSON object: %v", name, err)
		}
		var dialer string
		if err := json.Unmarshal(object["dialer"], &dialer); err != nil {
			t.Fatalf("OutboundsRaw[%q] dialer key not decodable: %v", name, err)
		}
		if dialer != wantDialer {
			t.Fatalf("OutboundsRaw[%q] dialer = %q, want %q", name, dialer, wantDialer)
		}
	}
	if len(wrapper.OutboundRaw) == 0 {
		t.Fatal("OutboundRaw is empty, want single outbound to coexist with named outbounds")
	}
	if wrapper.DefaultOutbound != "wg-b" {
		t.Fatalf("DefaultOutbound = %q, want %q", wrapper.DefaultOutbound, "wg-b")
	}
	if len(wrapper.Users) != 2 || wrapper.Users[0].Outbound != "wg-a" || wrapper.Users[1].Outbound != "" {
		t.Fatalf("Users = %#v, want alice with outbound wg-a and bob without", wrapper.Users)
	}
}

func TestUnmarshalCaddyfileRejectsDuplicateNamedOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound wg direct
		outbound wg direct
	}
	`)

	var wrapper ListenerWrapper
	err := wrapper.UnmarshalCaddyfile(dispenser)
	if err == nil || !strings.Contains(err.Error(), "may only be declared once") {
		t.Fatalf("UnmarshalCaddyfile() error = %v, want duplicate named outbound error", err)
	}
}

func TestUnmarshalCaddyfileRejectsDuplicateDefaultOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound wg direct
		default_outbound wg
		default_outbound wg
	}
	`)

	var wrapper ListenerWrapper
	err := wrapper.UnmarshalCaddyfile(dispenser)
	if err == nil || !strings.Contains(err.Error(), "may only be specified once") {
		t.Fatalf("UnmarshalCaddyfile() error = %v, want duplicate default_outbound error", err)
	}
}

func TestUnmarshalCaddyfileDefaultOutboundArgCount(t *testing.T) {
	for name, input := range map[string]string{
		"missing argument": "anytls {\n\tdefault_outbound\n}",
		"extra argument":   "anytls {\n\tdefault_outbound wg extra\n}",
	} {
		t.Run(name, func(t *testing.T) {
			var wrapper ListenerWrapper
			if err := wrapper.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("UnmarshalCaddyfile() error = nil, want argument count error")
			}
		})
	}
}

func TestUnmarshalCaddyfileUserArgCount(t *testing.T) {
	for name, input := range map[string]string{
		"one argument":   "anytls {\n\tuser alice\n}",
		"four arguments": "anytls {\n\tuser alice secret wg extra\n}",
	} {
		t.Run(name, func(t *testing.T) {
			var wrapper ListenerWrapper
			if err := wrapper.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("UnmarshalCaddyfile() error = nil, want argument count error")
			}
		})
	}
}

func TestUnmarshalJSONNamedOutboundFields(t *testing.T) {
	input := `{
		"users": [{"name": "alice", "password": "secret", "outbound": "wg"}],
		"outbounds": {"wg": {"dialer": "direct"}},
		"default_outbound": "wg"
	}`

	var wrapper ListenerWrapper
	if err := json.Unmarshal([]byte(input), &wrapper); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if _, ok := wrapper.OutboundsRaw["wg"]; !ok {
		t.Fatalf("OutboundsRaw = %v, want key wg", wrapper.OutboundsRaw)
	}
	if wrapper.DefaultOutbound != "wg" {
		t.Fatalf("DefaultOutbound = %q, want %q", wrapper.DefaultOutbound, "wg")
	}
	if len(wrapper.Users) != 1 || wrapper.Users[0].Outbound != "wg" {
		t.Fatalf("Users = %#v, want alice referencing wg", wrapper.Users)
	}
}

func newProvisionedWrapper(t *testing.T, configJSON string) (*ListenerWrapper, error) {
	t.Helper()

	var wrapper ListenerWrapper
	if err := json.Unmarshal([]byte(configJSON), &wrapper); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	wrapper.logger = zap.NewNop()
	wrapper.registry = newSessionRegistry()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	return &wrapper, wrapper.Provision(ctx)
}

func TestProvisionNamedOutboundsAndUserMaps(t *testing.T) {
	wrapper, err := newProvisionedWrapper(t, `{
		"users": [
			{"name": "alice", "password": "a-pw", "outbound": "rec"},
			{"name": "bob", "password": "b-pw", "outbound": "direct"},
			{"name": "carol", "password": "c-pw"}
		],
		"outbounds": {
			"rec": {"dialer": "test-recorder"},
			"other": {"dialer": "direct"}
		},
		"default_outbound": "other"
	}`)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	if len(wrapper.namedOutbounds) != 3 {
		t.Fatalf("len(namedOutbounds) = %d, want 3 (rec, other, injected direct)", len(wrapper.namedOutbounds))
	}
	if _, ok := wrapper.namedOutbounds["rec"].(*testRecorderOutbound); !ok {
		t.Fatalf("namedOutbounds[rec] = %T, want *testRecorderOutbound", wrapper.namedOutbounds["rec"])
	}
	if _, ok := wrapper.namedOutbounds["direct"].(*DirectOutbound); !ok {
		t.Fatalf("namedOutbounds[direct] = %T, want injected *DirectOutbound", wrapper.namedOutbounds["direct"])
	}
	if wrapper.defaultOutbound != wrapper.namedOutbounds["other"] || wrapper.defaultOutboundName != "other" {
		t.Fatalf("default outbound = (%T, %q), want (namedOutbounds[other], other)", wrapper.defaultOutbound, wrapper.defaultOutboundName)
	}
	if len(wrapper.userOutbound) != 2 || len(wrapper.userOutboundName) != 2 {
		t.Fatalf("user maps sizes = (%d, %d), want (2, 2): only explicit references get entries", len(wrapper.userOutbound), len(wrapper.userOutboundName))
	}
	if wrapper.userOutbound["alice"] != wrapper.namedOutbounds["rec"] || wrapper.userOutboundName["alice"] != "rec" {
		t.Fatalf("alice outbound = (%T, %q), want (namedOutbounds[rec], rec)", wrapper.userOutbound["alice"], wrapper.userOutboundName["alice"])
	}
	if wrapper.userOutbound["bob"] != wrapper.namedOutbounds["direct"] || wrapper.userOutboundName["bob"] != "direct" {
		t.Fatalf("bob outbound = (%T, %q), want the built-in direct without a declaration", wrapper.userOutbound["bob"], wrapper.userOutboundName["bob"])
	}
	if _, ok := wrapper.userOutbound["carol"]; ok {
		t.Fatal("userOutbound has entry for carol, want none for users without explicit outbound")
	}
}

func TestProvisionDefaultOutboundResolutionOrder(t *testing.T) {
	t.Run("default_outbound wins over single outbound", func(t *testing.T) {
		wrapper, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret"}],
			"outbound": {"dialer": "test-recorder"},
			"outbounds": {"named": {"dialer": "direct"}},
			"default_outbound": "named"
		}`)
		if err != nil {
			t.Fatalf("Provision() error = %v", err)
		}
		if wrapper.defaultOutbound != wrapper.namedOutbounds["named"] || wrapper.defaultOutboundName != "named" {
			t.Fatalf("default outbound = (%T, %q), want (namedOutbounds[named], named)", wrapper.defaultOutbound, wrapper.defaultOutboundName)
		}
		if _, ok := wrapper.outbound.(*testRecorderOutbound); !ok {
			t.Fatalf("outbound = %T, want single outbound still loaded", wrapper.outbound)
		}
	})

	t.Run("single outbound uses the default sentinel", func(t *testing.T) {
		wrapper, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret"}],
			"outbound": {"dialer": "test-recorder"}
		}`)
		if err != nil {
			t.Fatalf("Provision() error = %v", err)
		}
		if wrapper.defaultOutbound != wrapper.outbound || wrapper.defaultOutboundName != "default" {
			t.Fatalf("default outbound = (%T, %q), want (single outbound, default)", wrapper.defaultOutbound, wrapper.defaultOutboundName)
		}
	})

	t.Run("no outbound falls back to direct", func(t *testing.T) {
		wrapper, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret"}]
		}`)
		if err != nil {
			t.Fatalf("Provision() error = %v", err)
		}
		if _, ok := wrapper.defaultOutbound.(*DirectOutbound); !ok || wrapper.defaultOutboundName != "direct" {
			t.Fatalf("default outbound = (%T, %q), want (*DirectOutbound, direct)", wrapper.defaultOutbound, wrapper.defaultOutboundName)
		}
	})
}

func TestProvisionRejectsReservedOutboundNames(t *testing.T) {
	for _, reserved := range []string{"direct", "default"} {
		t.Run("json declares "+reserved, func(t *testing.T) {
			_, err := newProvisionedWrapper(t, `{
				"users": [{"name": "alice", "password": "secret"}],
				"outbounds": {"`+reserved+`": {"dialer": "direct"}}
			}`)
			if err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("Provision() error = %v, want reserved name error", err)
			}
		})
	}

	t.Run("caddyfile declares direct", func(t *testing.T) {
		dispenser := caddyfile.NewTestDispenser(`
		anytls {
			user alice secret
			outbound direct direct
		}
		`)
		wrapper := &ListenerWrapper{logger: zap.NewNop(), registry: newSessionRegistry()}
		if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		defer cancel()
		err := wrapper.Provision(ctx)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("Provision() error = %v, want reserved name error", err)
		}
	})
}

func TestProvisionRejectsUndeclaredOutboundReferences(t *testing.T) {
	t.Run("json user reference", func(t *testing.T) {
		_, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret", "outbound": "missing"}]
		}`)
		if err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("Provision() error = %v, want undeclared outbound error", err)
		}
	})

	t.Run("json default_outbound reference", func(t *testing.T) {
		_, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret"}],
			"default_outbound": "missing"
		}`)
		if err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("Provision() error = %v, want undeclared outbound error", err)
		}
	})

	t.Run("caddyfile user reference", func(t *testing.T) {
		dispenser := caddyfile.NewTestDispenser(`
		anytls {
			user alice secret missing
		}
		`)
		wrapper := &ListenerWrapper{logger: zap.NewNop(), registry: newSessionRegistry()}
		if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		defer cancel()
		err := wrapper.Provision(ctx)
		if err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("Provision() error = %v, want undeclared outbound error", err)
		}
	})
}

func TestProvisionAllowsDirectReferenceWithoutDeclaration(t *testing.T) {
	wrapper, err := newProvisionedWrapper(t, `{
		"users": [{"name": "alice", "password": "secret", "outbound": "direct"}]
	}`)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := wrapper.userOutbound["alice"].(*DirectOutbound); !ok {
		t.Fatalf("userOutbound[alice] = %T, want *DirectOutbound", wrapper.userOutbound["alice"])
	}
	if wrapper.userOutboundName["alice"] != "direct" {
		t.Fatalf("userOutboundName[alice] = %q, want %q", wrapper.userOutboundName["alice"], "direct")
	}
}

func TestProvisionRejectsEmptyNamedOutboundName(t *testing.T) {
	wrapper := &ListenerWrapper{
		Users:        []User{{Name: "alice", Password: "secret", Enabled: true}},
		OutboundsRaw: map[string]json.RawMessage{"": json.RawMessage(`{"dialer":"direct"}`)},
		logger:       zap.NewNop(),
		registry:     newSessionRegistry(),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	err := wrapper.Provision(ctx)
	if err == nil || !strings.Contains(err.Error(), "empty name") {
		t.Fatalf("Provision() error = %v, want empty name error", err)
	}
}

func TestProvisionRejectsNonOutboundNamedModule(t *testing.T) {
	_, err := newProvisionedWrapper(t, `{
		"users": [{"name": "alice", "password": "secret"}],
		"outbounds": {"bad": {"dialer": "test-not-outbound"}}
	}`)
	if err == nil || !strings.Contains(err.Error(), "is not an anytls outbound") {
		t.Fatalf("Provision() error = %v, want rejection of a module that does not implement Outbound", err)
	}
}

func TestOutboundForUserFallbackChain(t *testing.T) {
	recorder := &recordingOutbound{inner: new(DirectOutbound)}
	named := &recordingOutbound{inner: new(DirectOutbound)}

	// Tier 4: nothing configured at all -> built-in direct.
	bare := &directTCPHandler{config: &ListenerWrapper{}}
	outbound, name := bare.outboundForUser(t.Context())
	if _, ok := outbound.(*DirectOutbound); !ok || name != "direct" {
		t.Fatalf("bare wrapper outbound = (%T, %q), want (*DirectOutbound, direct)", outbound, name)
	}

	// Tier 3: only config.outbound set (hand-built wrappers) -> sentinel name.
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	handler := &directTCPHandler{config: wrapper}
	outbound, name = handler.outboundForUser(t.Context())
	if outbound != wrapper.outbound || name != "default" {
		t.Fatalf("config.outbound tier = (%T, %q), want (config.outbound, default)", outbound, name)
	}

	// Tier 2: resolved default outbound wins over config.outbound.
	wrapper.defaultOutbound = named
	wrapper.defaultOutboundName = "wg-home"
	outbound, name = handler.outboundForUser(t.Context())
	if outbound != Outbound(named) || name != "wg-home" {
		t.Fatalf("default tier = (%T, %q), want (named default, wg-home)", outbound, name)
	}

	// Tier 1: explicit per-user reference wins over everything.
	wrapper.userOutbound = map[string]Outbound{"alice": recorder}
	wrapper.userOutboundName = map[string]string{"alice": "wg-a"}
	outbound, name = handler.outboundForUser(auth.ContextWithUser(t.Context(), "alice"))
	if outbound != Outbound(recorder) || name != "wg-a" {
		t.Fatalf("user tier = (%T, %q), want (user outbound, wg-a)", outbound, name)
	}
	// Unknown users still get the default.
	outbound, name = handler.outboundForUser(auth.ContextWithUser(t.Context(), "mallory"))
	if outbound != Outbound(named) || name != "wg-home" {
		t.Fatalf("unknown user = (%T, %q), want the default outbound", outbound, name)
	}
}

// A destination given as an IP literal resolves to exactly one candidate, so
// the happy-eyeballs dialer performs exactly one DialContext and the per-user
// hit assertion is deterministic.
func TestDialContextSelectsPerUserOutbound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)
	go acceptLoop(t.Context(), listener)
	address := listener.Addr().String()

	recA := &recordingOutbound{inner: new(DirectOutbound)}
	recB := &recordingOutbound{inner: new(DirectOutbound)}
	recDefault := &recordingOutbound{inner: new(DirectOutbound)}
	users := []User{
		{Name: "alice", Password: "a-pw", Enabled: true, Outbound: "wg-a"},
		{Name: "bob", Password: "b-pw", Enabled: true, Outbound: "wg-b"},
		{Name: "carol", Password: "c-pw", Enabled: true},
	}
	wrapper := newTestWrapper(t, users, true)
	wrapper.outbound = recDefault
	wrapper.userOutbound = map[string]Outbound{"alice": recA, "bob": recB}
	wrapper.userOutboundName = map[string]string{"alice": "wg-a", "bob": "wg-b"}
	handler := &directTCPHandler{config: wrapper}

	for _, tt := range []struct {
		user     string
		recorder *recordingOutbound
	}{
		{user: "alice", recorder: recA},
		{user: "bob", recorder: recB},
		{user: "carol", recorder: recDefault},
	} {
		conn, err := handler.dialContext(auth.ContextWithUser(t.Context(), tt.user), M.ParseSocksaddr(address))
		if err != nil {
			t.Fatalf("dialContext(%s) error = %v", tt.user, err)
		}
		closeTest(conn)
		dials := tt.recorder.dials()
		if len(dials) != 1 || dials[0] != address {
			t.Fatalf("user %s recorded dials = %v, want exactly [%s]", tt.user, dials, address)
		}
	}

	if extra := recA.dials(); len(extra) != 1 {
		t.Fatalf("recA dials = %v, want no cross-user dials", extra)
	}
	if extra := recB.dials(); len(extra) != 1 {
		t.Fatalf("recB dials = %v, want no cross-user dials", extra)
	}
}

func TestListenPacketContextSelectsPerUserOutbound(t *testing.T) {
	packetA := new(stubPacketConn)
	packetB := new(stubPacketConn)
	packetDefault := new(stubPacketConn)
	recA := &recordingOutbound{packetConn: packetA}
	recB := &recordingOutbound{packetConn: packetB}
	recDefault := &recordingOutbound{packetConn: packetDefault}

	users := []User{
		{Name: "alice", Password: "a-pw", Enabled: true, Outbound: "wg-a"},
		{Name: "bob", Password: "b-pw", Enabled: true, Outbound: "wg-b"},
	}
	wrapper := newTestWrapper(t, users, true)
	wrapper.outbound = recDefault
	wrapper.userOutbound = map[string]Outbound{"alice": recA, "bob": recB}
	wrapper.userOutboundName = map[string]string{"alice": "wg-a", "bob": "wg-b"}
	handler := &directTCPHandler{config: wrapper}

	for _, tt := range []struct {
		name string
		ctx  context.Context
		want net.PacketConn
	}{
		{name: "alice", ctx: auth.ContextWithUser(t.Context(), "alice"), want: packetA},
		{name: "bob", ctx: auth.ContextWithUser(t.Context(), "bob"), want: packetB},
		{name: "no user", ctx: t.Context(), want: packetDefault},
	} {
		got, err := handler.listenPacketContext(tt.ctx)
		if err != nil {
			t.Fatalf("listenPacketContext(%s) error = %v", tt.name, err)
		}
		if got != tt.want {
			t.Fatalf("listenPacketContext(%s) = %p, want the per-user packet connection", tt.name, got)
		}
	}
}

// With multiple candidate addresses, the same per-user outbound is dialed
// concurrently; the winner is kept and the loser must be closed by
// drainDialResults. The gate holds both dials in flight before releasing
// them, so the concurrent path is exercised deterministically despite the
// hardcoded 250ms fallback delay.
func TestDialContextConcurrentPerUserDialsDoNotLeak(t *testing.T) {
	gate := &gateDialOutbound{
		entered: make(chan struct{}, 4),
		release: make(chan struct{}),
	}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true, Outbound: "wg-a"}}, true)
	wrapper.ConnectTimeout = caddy.Duration(5 * time.Second)
	wrapper.userOutbound = map[string]Outbound{"alice": gate}
	wrapper.userOutboundName = map[string]string{"alice": "wg-a"}
	wrapper.resolveFunc = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.21"), netip.MustParseAddr("192.0.2.22")}, nil
	}
	handler := &directTCPHandler{config: wrapper}

	type dialOutcome struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialOutcome, 1)
	go func() {
		conn, err := handler.dialContext(auth.ContextWithUser(t.Context(), "alice"), M.Socksaddr{Fqdn: "multi.test", Port: 443})
		done <- dialOutcome{conn: conn, err: err}
	}()

	// The first dial launches immediately, the second after the fallback
	// delay; wait until both are in flight before releasing either.
	for i := range 2 {
		select {
		case <-gate.entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for concurrent dial %d", i+1)
		}
	}
	close(gate.release)

	var outcome dialOutcome
	select {
	case outcome = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dialContext to return")
	}
	if outcome.err != nil {
		t.Fatalf("dialContext() error = %v", outcome.err)
	}
	winner, ok := outcome.conn.(*trackedConn)
	if !ok {
		t.Fatalf("dialContext() = %T, want *trackedConn", outcome.conn)
	}

	if !waitForCondition(time.Second, func() bool {
		conns := gate.trackedConns()
		if len(conns) != 2 {
			return false
		}
		closedCount := 0
		for _, conn := range conns {
			if conn.closed.Load() {
				closedCount++
			}
		}
		return closedCount == 1
	}) {
		conns := gate.trackedConns()
		t.Fatalf("expected exactly 2 dials with the loser closed by drainDialResults, got %d conns", len(conns))
	}
	if winner.closed.Load() {
		t.Fatal("winning connection was closed, want only the loser drained")
	}
	closeTest(winner)
}
