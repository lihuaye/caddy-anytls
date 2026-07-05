package anytls

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestValidateStreamDestinationRejectsResolvedPrivateAddress(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
	wrapper.resolveFunc = func(ctx context.Context, network string, host string) ([]netip.Addr, error) {
		if host != "internal.example.test" {
			t.Fatalf("resolve host = %q, want internal.example.test", host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	handler := &directTCPHandler{config: wrapper}

	_, err := handler.validateStreamDestination(context.Background(), M.ParseSocksaddr("internal.example.test:443"))
	if !errors.Is(err, errPrivateDestinationDenied) {
		t.Fatalf("validateStreamDestination() error = %v, want private destination denied", err)
	}
}

func TestValidateStreamDestinationResolvesPublicAddress(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
	wrapper.resolveFunc = func(ctx context.Context, network string, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	handler := &directTCPHandler{config: wrapper}

	got, err := handler.validateStreamDestination(context.Background(), M.ParseSocksaddr("example.test:443"))
	if err != nil {
		t.Fatalf("validateStreamDestination() error = %v", err)
	}
	if len(got) != 1 || got[0].String() != "93.184.216.34:443" {
		t.Fatalf("resolved destination = %v, want 93.184.216.34:443", got)
	}
}

func TestDialContextFallsBackAcrossResolvedAddresses(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
	wrapper.resolveFunc = func(ctx context.Context, network string, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("93.184.216.35"),
		}, nil
	}
	var dialed []string
	wrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		if address == "93.184.216.34:443" {
			return nil, errors.New("first address failed")
		}
		server, client := net.Pipe()
		closeTest(server)
		return client, nil
	}
	handler := &directTCPHandler{config: wrapper}

	conn, err := handler.dialContext(context.Background(), M.ParseSocksaddr("example.test:443"))
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	closeTest(conn)
	if strings.Join(dialed, ",") != "93.184.216.34:443,93.184.216.35:443" {
		t.Fatalf("dialed = %v, want both resolved addresses", dialed)
	}
}

func TestDestinationPolicies(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*ListenerWrapper)
		destination string
		resolved    string
		wantErr     error
	}{
		{
			name: "deny port",
			mutate: func(wrapper *ListenerWrapper) {
				wrapper.DenyPorts = []uint16{25}
			},
			destination: "example.test:25",
			resolved:    "93.184.216.34",
			wantErr:     errDestinationPolicyDenied,
		},
		{
			name: "allow port excludes other ports",
			mutate: func(wrapper *ListenerWrapper) {
				wrapper.AllowPorts = []uint16{443}
			},
			destination: "example.test:80",
			resolved:    "93.184.216.34",
			wantErr:     errDestinationPolicyDenied,
		},
		{
			name: "deny domain",
			mutate: func(wrapper *ListenerWrapper) {
				wrapper.DenyDomains = []string{".blocked.test"}
			},
			destination: "api.blocked.test:443",
			resolved:    "93.184.216.34",
			wantErr:     errDestinationPolicyDenied,
		},
		{
			name: "allow domain excludes other domains",
			mutate: func(wrapper *ListenerWrapper) {
				wrapper.AllowDomains = []string{"allowed.test"}
			},
			destination: "blocked.test:443",
			resolved:    "93.184.216.34",
			wantErr:     errDestinationPolicyDenied,
		},
		{
			name: "deny cidr",
			mutate: func(wrapper *ListenerWrapper) {
				wrapper.DenyCIDRs = []string{"93.184.216.0/24"}
			},
			destination: "example.test:443",
			resolved:    "93.184.216.34",
			wantErr:     errDestinationPolicyDenied,
		},
		{
			name: "allow cidr can explicitly permit private target",
			mutate: func(wrapper *ListenerWrapper) {
				wrapper.AllowCIDRs = []string{"10.0.0.0/8"}
			},
			destination: "internal.test:443",
			resolved:    "10.0.0.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
			tt.mutate(wrapper)
			if err := wrapper.compileCIDRPolicies(); err != nil {
				t.Fatalf("compileCIDRPolicies() error = %v", err)
			}
			wrapper.resolveFunc = func(ctx context.Context, network string, host string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(tt.resolved)}, nil
			}
			handler := &directTCPHandler{config: wrapper}

			_, err := handler.validateStreamDestination(context.Background(), M.ParseSocksaddr(tt.destination))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("validateStreamDestination() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateStreamDestination() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestPreparePacketDestinationRejectsResolvedPrivateAddress(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
	wrapper.resolveFunc = func(ctx context.Context, network string, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.10")}, nil
	}
	handler := &directTCPHandler{config: wrapper}

	_, err := handler.preparePacketDestination(context.Background(), M.ParseSocksaddr("dns.internal.test:53"))
	if !errors.Is(err, errPrivateDestinationDenied) {
		t.Fatalf("preparePacketDestination() error = %v, want private destination denied", err)
	}
}
