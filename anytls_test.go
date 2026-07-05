package anytls

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/net/http2"
)

func TestBufferedConnPeekPreservesBytes(t *testing.T) {
	server, client := net.Pipe()
	defer closeTest(server)
	defer closeTest(client)

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\n"))
	}()

	conn := newBufferedConn(server)
	preview, err := conn.Peek(1, time.Second)
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	if string(preview) != "G" {
		t.Fatalf("Peek() = %q, want %q", string(preview), "G")
	}

	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(buf) != "GET" {
		t.Fatalf("read bytes = %q, want %q", string(buf), "GET")
	}
}

func TestBufferedConnPreservesConnectionState(t *testing.T) {
	expected := tls.ConnectionState{
		ServerName:         "example.com",
		NegotiatedProtocol: "h2",
	}

	conn := newBufferedConn(testTLSStateConn{
		Conn:  &net.TCPConn{},
		state: expected,
	})

	got := conn.ConnectionState()
	if got.ServerName != expected.ServerName {
		t.Fatalf("ConnectionState().ServerName = %q, want %q", got.ServerName, expected.ServerName)
	}
	if got.NegotiatedProtocol != expected.NegotiatedProtocol {
		t.Fatalf("ConnectionState().NegotiatedProtocol = %q, want %q", got.NegotiatedProtocol, expected.NegotiatedProtocol)
	}
}

func TestBufferedConnBufferedBytesPreservesBytes(t *testing.T) {
	server, client := net.Pipe()
	defer closeTest(server)
	defer closeTest(client)

	go func() {
		_, _ = client.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	}()

	conn := newBufferedConn(server)
	preview, err := conn.Peek(8, time.Second)
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	if string(preview) != "PRI * HT" {
		t.Fatalf("Peek() = %q, want %q", string(preview), "PRI * HT")
	}

	buffered, err := conn.BufferedBytes()
	if err != nil {
		t.Fatalf("BufferedBytes() error = %v", err)
	}
	if string(buffered) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		t.Fatalf("BufferedBytes() = %q, want %q", string(buffered), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	}

	buf := make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(buf) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		t.Fatalf("read bytes = %q, want %q", string(buf), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ListenerWrapper
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ListenerWrapper{
				MaxConcurrent: 1,
				Users: []User{
					{Name: "alice", Password: "secret", Enabled: true},
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate user",
			config: &ListenerWrapper{
				Users: []User{
					{Name: "alice", Password: "secret"},
					{Name: "alice", Password: "secret-2"},
				},
			},
			wantErr: true,
		},
		{
			name: "negative concurrency",
			config: &ListenerWrapper{
				MaxConcurrent: -1,
			},
			wantErr: true,
		},
		{
			name: "empty password",
			config: &ListenerWrapper{
				Users: []User{
					{Name: "alice"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want non-nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func TestWebsiteFallbackEndToEnd(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)

	base := newChanListener()
	defer closeTest(base)

	wrapped := wrapper.WrapListener(base)
	request := "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

	serverErr := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer closeTest(conn)

		buf := make([]byte, len(request))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != request {
			serverErr <- io.ErrUnexpectedEOF
			return
		}

		_, err = io.WriteString(conn, response)
		serverErr <- err
	}()

	serverConn, client := net.Pipe()
	defer closeTest(client)
	base.enqueue(serverConn)

	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	body, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != response {
		t.Fatalf("response = %q, want %q", string(body), response)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestHTTP2FallbackUsesOpaqueConnAndShadowTLSState(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)

	base := newChanListener()
	defer closeTest(base)

	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	wrapped := wrapper.WrapListener(tlsListener)

	serverErr := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer closeTest(conn)

		if _, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			serverErr <- errors.New("wrapped listener should not expose ConnectionState on fallback connection")
			return
		}

		ctx := wrapper.websiteConnContext(context.Background(), conn)
		shadowConn, ok := ctx.Value(caddyhttp.ConnCtxKey).(interface{ ConnectionState() tls.ConnectionState })
		if !ok {
			serverErr <- errors.New("ConnContext did not expose shadow TLS connection")
			return
		}
		if got := shadowConn.ConnectionState().NegotiatedProtocol; got != "h2" {
			serverErr <- errors.New("unexpected negotiated protocol: " + got)
			return
		}

		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			serverErr <- err
			return
		}
		if string(preface) != http2.ClientPreface {
			serverErr <- errors.New("http2 preface was not preserved")
			return
		}

		serverErr <- nil
	}()

	serverConn, clientConn := net.Pipe()
	base.enqueue(serverConn)

	client := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         "example.test",
	})
	defer closeTest(client)

	if err := client.Handshake(); err != nil {
		t.Fatalf("client Handshake() error = %v", err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("client negotiated protocol = %q, want %q", got, "h2")
	}
	if _, err := io.WriteString(client, http2.ClientPreface); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestHTTP2PrefaceFallsBackWithoutFullAnyTLSPeek(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
	wrapped := &wrappedListener{config: wrapper}

	server, client := net.Pipe()
	defer closeTest(server)
	defer closeTest(client)
	go func() {
		_, _ = client.Write([]byte(http2.ClientPreface))
	}()

	decision, err := wrapped.classifyBufferedConn(newBufferedConn(server))
	if err != nil {
		t.Fatalf("classifyBufferedConn() error = %v", err)
	}
	if decision != DecisionFallback {
		t.Fatalf("decision = %v, want fallback", decision)
	}
}

func TestHTTP1FallbackUsesOpaqueConnAndShadowTLSState(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)

	base := newChanListener()
	defer closeTest(base)

	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"http/1.1"},
	})
	wrapped := wrapper.WrapListener(tlsListener)

	serverErr := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer closeTest(conn)

		if _, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			serverErr <- errors.New("wrapped listener should not expose ConnectionState on fallback connection")
			return
		}

		ctx := wrapper.websiteConnContext(context.Background(), conn)
		shadowConn, ok := ctx.Value(caddyhttp.ConnCtxKey).(interface{ ConnectionState() tls.ConnectionState })
		if !ok {
			serverErr <- errors.New("ConnContext did not expose shadow TLS connection")
			return
		}
		if got := shadowConn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
			serverErr <- errors.New("unexpected negotiated protocol: " + got)
			return
		}
		if got := shadowConn.ConnectionState().ServerName; got != "example.test" {
			serverErr <- errors.New("unexpected server name: " + got)
			return
		}

		request := "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != request {
			serverErr <- errors.New("http/1.1 request bytes were not preserved")
			return
		}

		serverErr <- nil
	}()

	serverConn, clientConn := net.Pipe()
	base.enqueue(serverConn)

	client := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		ServerName:         "example.test",
	})
	defer closeTest(client)

	if err := client.Handshake(); err != nil {
		t.Fatalf("client Handshake() error = %v", err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("client negotiated protocol = %q, want %q", got, "http/1.1")
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestCleanupWebsiteConnRemovesShadowState(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)

	server, client := net.Pipe()
	defer closeTest(server)
	defer closeTest(client)

	buffered := newBufferedConn(testTLSStateConn{
		Conn:  server,
		state: tls.ConnectionState{ServerName: "example.test", NegotiatedProtocol: "h2"},
	})
	go func() {
		_, _ = client.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	}()
	if _, err := buffered.Peek(8, time.Second); err != nil {
		t.Fatalf("Peek() error = %v", err)
	}

	websiteConn, err := wrapper.prepareWebsiteConn(buffered)
	if err != nil {
		t.Fatalf("prepareWebsiteConn() error = %v", err)
	}

	ctx := wrapper.websiteConnContext(context.Background(), websiteConn)
	if _, ok := ctx.Value(caddyhttp.ConnCtxKey).(interface{ ConnectionState() tls.ConnectionState }); !ok {
		t.Fatal("expected shadow TLS connection before cleanup")
	}

	wrapper.cleanupWebsiteConn(websiteConn, http.StateClosed)

	ctx = wrapper.websiteConnContext(context.Background(), websiteConn)
	if got := ctx.Value(caddyhttp.ConnCtxKey); got != nil {
		t.Fatalf("expected shadow TLS connection to be removed, got %#v", got)
	}
}

func TestPostTLSWrapperAfterAnyTLSFallbackLosesConnectionState(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)

	base := newChanListener()
	defer closeTest(base)

	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"http/1.1"},
	})
	afterAnyTLS := wrapper.WrapListener(tlsListener)
	checker := &stateCheckingListener{
		Listener: afterAnyTLS,
		seenCh:   make(chan net.Conn, 1),
		errCh:    make(chan error, 1),
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := checker.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer closeTest(conn)
		serverErr <- nil
	}()

	serverConn, clientConn := net.Pipe()
	base.enqueue(serverConn)

	client := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		ServerName:         "example.test",
	})
	defer closeTest(client)

	if err := client.Handshake(); err != nil {
		t.Fatalf("client Handshake() error = %v", err)
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	select {
	case err := <-checker.errCh:
		if err == nil || err.Error() != "missing ConnectionState" {
			t.Fatalf("checker err = %v, want missing ConnectionState", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected checker to report missing ConnectionState")
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestPostTLSWrapperAfterAnyTLSDoesNotSeeAnyTLSConnections(t *testing.T) {
	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer closeTest(destination)

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.ProbeTimeout = caddy.Duration(time.Second)
	wrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}

	destDone := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			destDone <- err
			return
		}
		defer closeTest(conn)

		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			destDone <- err
			return
		}

		_, err = io.WriteString(conn, strings.ToUpper(line))
		destDone <- err
	}()

	base := newChanListener()
	defer closeTest(base)
	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	afterAnyTLS := wrapper.WrapListener(tlsListener)
	checker := &stateCheckingListener{
		Listener: afterAnyTLS,
		seenCh:   make(chan net.Conn, 1),
		errCh:    make(chan error, 1),
	}

	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	defer cancelAccept()
	go acceptLoop(acceptCtx, checker)

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)

			tlsClient := tls.Client(clientConn, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         "example.test",
			})
			if err := tlsClient.HandshakeContext(ctx); err != nil {
				_ = tlsClient.Close()
				return nil, err
			}
			return tlsClient, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client)

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer closeTest(proxyConn)

	if _, err := io.WriteString(proxyConn, "hello through anytls over tls\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	reply, err := bufio.NewReader(proxyConn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if reply != "HELLO THROUGH ANYTLS OVER TLS\n" {
		t.Fatalf("reply = %q, want %q", reply, "HELLO THROUGH ANYTLS OVER TLS\n")
	}

	if err := <-destDone; err != nil {
		t.Fatalf("destination error = %v", err)
	}

	select {
	case conn := <-checker.seenCh:
		_ = conn.Close()
		t.Fatal("post-TLS wrapper should not see AnyTLS connections")
	case err := <-checker.errCh:
		t.Fatalf("post-TLS wrapper should not see AnyTLS connections, got err %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestAnyTLSEndToEndProxyOverTLSWithH2ALPN(t *testing.T) {
	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer closeTest(destination)

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.ProbeTimeout = caddy.Duration(time.Second)
	wrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}

	destDone := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			destDone <- err
			return
		}
		defer closeTest(conn)

		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			destDone <- err
			return
		}

		_, err = io.WriteString(conn, strings.ToUpper(line))
		destDone <- err
	}()

	base := newChanListener()
	defer closeTest(base)
	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})

	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	defer cancelAccept()
	go acceptLoop(acceptCtx, wrapper.WrapListener(tlsListener))

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)

			tlsClient := tls.Client(clientConn, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         "example.test",
			})
			if err := tlsClient.HandshakeContext(ctx); err != nil {
				_ = tlsClient.Close()
				return nil, err
			}
			return tlsClient, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client)

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer closeTest(proxyConn)

	if _, err := io.WriteString(proxyConn, "hello through anytls over tls\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	reply, err := bufio.NewReader(proxyConn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if reply != "HELLO THROUGH ANYTLS OVER TLS\n" {
		t.Fatalf("reply = %q, want %q", reply, "HELLO THROUGH ANYTLS OVER TLS\n")
	}

	if err := <-destDone; err != nil {
		t.Fatalf("destination error = %v", err)
	}
}

func TestAnyTLSEndToEndProxy(t *testing.T) {
	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer closeTest(destination)
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}

	destDone := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			destDone <- err
			return
		}
		defer closeTest(conn)

		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			destDone <- err
			return
		}

		_, err = io.WriteString(conn, strings.ToUpper(line))
		destDone <- err
	}()

	base := newChanListener()
	defer closeTest(base)

	wrapped := wrapper.WrapListener(base)
	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	defer cancelAccept()
	go acceptLoop(acceptCtx, wrapped)

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client)

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer closeTest(proxyConn)

	if _, err := io.WriteString(proxyConn, "hello through anytls\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	reply, err := bufio.NewReader(proxyConn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if reply != "HELLO THROUGH ANYTLS\n" {
		t.Fatalf("reply = %q, want %q", reply, "HELLO THROUGH ANYTLS\n")
	}

	if err := <-destDone; err != nil {
		t.Fatalf("destination error = %v", err)
	}
}

func TestAnyTLSEndToEndUDPOverTCP(t *testing.T) {
	serverPacketConn, handlerPacketConn := newPacketPipe()
	defer closeTest(serverPacketConn)
	defer closeTest(handlerPacketConn)

	udpDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, addr, err := serverPacketConn.ReadFrom(buffer)
		if err != nil {
			udpDone <- err
			return
		}
		_, err = serverPacketConn.WriteTo([]byte(strings.ToUpper(string(buffer[:n]))), addr)
		udpDone <- err
	}()

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.listenPacketFunc = func(ctx context.Context, network string, address string) (net.PacketConn, error) {
		return handlerPacketConn, nil
	}
	base := newChanListener()
	defer closeTest(base)

	wrapped := wrapper.WrapListener(base)
	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	defer cancelAccept()
	go acceptLoop(acceptCtx, wrapped)

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client)

	uotClient := &uot.Client{
		Dialer:  anyTLSTestDialer{client: client},
		Version: uot.Version,
	}

	uotConn, err := uotClient.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer closeTest(uotConn)

	if _, err := io.WriteString(uotConn, "hello over udp\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	reply, err := bufio.NewReader(uotConn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if reply != "HELLO OVER UDP\n" {
		t.Fatalf("reply = %q, want %q", reply, "HELLO OVER UDP\n")
	}

	if err := <-udpDone; err != nil {
		t.Fatalf("udp server error = %v", err)
	}
}

func TestAnyTLSEndToEndUDPOverTCPDatagramMode(t *testing.T) {
	serverPacketConn, handlerPacketConn := newPacketPipe()
	defer closeTest(serverPacketConn)
	defer closeTest(handlerPacketConn)

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, addr, err := serverPacketConn.ReadFrom(buffer)
		if err != nil {
			firstDone <- err
			return
		}
		_, err = serverPacketConn.WriteTo([]byte(strings.ToUpper(string(buffer[:n]))), addr)
		firstDone <- err
	}()
	go func() {
		buffer := make([]byte, 2048)
		n, addr, err := serverPacketConn.ReadFrom(buffer)
		if err != nil {
			secondDone <- err
			return
		}
		_, err = serverPacketConn.WriteTo([]byte(strings.ToUpper(string(buffer[:n]))), addr)
		secondDone <- err
	}()

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.listenPacketFunc = func(ctx context.Context, network string, address string) (net.PacketConn, error) {
		return handlerPacketConn, nil
	}
	base := newChanListener()
	defer closeTest(base)

	go acceptLoop(context.Background(), wrapper.WrapListener(base))

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client)

	uotClient := &uot.Client{
		Dialer:  anyTLSTestDialer{client: client},
		Version: uot.Version,
	}

	packetConn, err := uotClient.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer closeTest(packetConn)

	dest1 := M.ParseSocksaddr("1.1.1.1:53")
	dest2 := M.ParseSocksaddr("8.8.8.8:53")
	if _, err := packetConn.WriteTo([]byte("first datagram"), dest1); err != nil {
		t.Fatalf("WriteTo(dest1) error = %v", err)
	}
	if _, err := packetConn.WriteTo([]byte("second datagram"), dest2); err != nil {
		t.Fatalf("WriteTo(dest2) error = %v", err)
	}

	buf := make([]byte, 2048)
	replies := make(map[string]string, 2)
	for i := 0; i < 2; i++ {
		n, addr, err := packetConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom() error = %v", err)
		}
		replies[addr.String()] = string(buf[:n])
	}
	if replies[dest1.String()] != "FIRST DATAGRAM" {
		t.Fatalf("reply for %s = %q, want %q", dest1.String(), replies[dest1.String()], "FIRST DATAGRAM")
	}
	if replies[dest2.String()] != "SECOND DATAGRAM" {
		t.Fatalf("reply for %s = %q, want %q", dest2.String(), replies[dest2.String()], "SECOND DATAGRAM")
	}

	if err := <-firstDone; err != nil {
		t.Fatalf("first udp server error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second udp server error = %v", err)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		probe_timeout 2s
		idle_timeout 3m
		connect_timeout 4s
		max_concurrent 64
		fallback true
		allow_private_targets false
		allow_cidr 10.0.0.0/8
		deny_cidr 127.0.0.0/8
		allow_port 443 8443
		deny_port 25
		allow_domain example.com .example.org
		deny_domain blocked.example
		log_node_info true
		node_host example.com alt.example.com
		node_port 8443
		node_sni real.example.com
		node_insecure true
		user alice secret
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if wrapper.ProbeTimeout != caddy.Duration(2*time.Second) {
		t.Fatalf("ProbeTimeout = %v, want %v", wrapper.ProbeTimeout, 2*time.Second)
	}
	if wrapper.IdleTimeout != caddy.Duration(3*time.Minute) {
		t.Fatalf("IdleTimeout = %v, want %v", wrapper.IdleTimeout, 3*time.Minute)
	}
	if wrapper.ConnectTimeout != caddy.Duration(4*time.Second) {
		t.Fatalf("ConnectTimeout = %v, want %v", wrapper.ConnectTimeout, 4*time.Second)
	}
	if wrapper.MaxConcurrent != 64 {
		t.Fatalf("MaxConcurrent = %d, want %d", wrapper.MaxConcurrent, 64)
	}
	if !wrapper.Fallback {
		t.Fatal("Fallback = false, want true")
	}
	if wrapper.AllowPrivateTargets {
		t.Fatal("AllowPrivateTargets = true, want false")
	}
	if strings.Join(wrapper.AllowCIDRs, ",") != "10.0.0.0/8" {
		t.Fatalf("AllowCIDRs = %v, want 10.0.0.0/8", wrapper.AllowCIDRs)
	}
	if strings.Join(wrapper.DenyCIDRs, ",") != "127.0.0.0/8" {
		t.Fatalf("DenyCIDRs = %v, want 127.0.0.0/8", wrapper.DenyCIDRs)
	}
	if !slices.Equal(wrapper.AllowPorts, []uint16{443, 8443}) {
		t.Fatalf("AllowPorts = %v, want [443 8443]", wrapper.AllowPorts)
	}
	if !slices.Equal(wrapper.DenyPorts, []uint16{25}) {
		t.Fatalf("DenyPorts = %v, want [25]", wrapper.DenyPorts)
	}
	if strings.Join(wrapper.AllowDomains, ",") != "example.com,.example.org" {
		t.Fatalf("AllowDomains = %v, want example.com and .example.org", wrapper.AllowDomains)
	}
	if strings.Join(wrapper.DenyDomains, ",") != "blocked.example" {
		t.Fatalf("DenyDomains = %v, want blocked.example", wrapper.DenyDomains)
	}
	if !wrapper.LogNodeInfo {
		t.Fatal("LogNodeInfo = false, want true")
	}
	if strings.Join(wrapper.NodeHosts, ",") != "example.com,alt.example.com" {
		t.Fatalf("NodeHosts = %v, want example.com and alt.example.com", wrapper.NodeHosts)
	}
	if wrapper.NodePort != 8443 {
		t.Fatalf("NodePort = %d, want 8443", wrapper.NodePort)
	}
	if wrapper.NodeSNI != "real.example.com" {
		t.Fatalf("NodeSNI = %q, want real.example.com", wrapper.NodeSNI)
	}
	if !wrapper.NodeInsecure {
		t.Fatal("NodeInsecure = false, want true")
	}
	if len(wrapper.Users) != 1 || wrapper.Users[0].Name != "alice" || wrapper.Users[0].Password != "secret" || !wrapper.Users[0].Enabled {
		t.Fatalf("Users = %#v, want one enabled user", wrapper.Users)
	}
}

func TestAnyTLSURI(t *testing.T) {
	tests := []struct {
		name     string
		password string
		host     string
		port     uint16
		sni      string
		insecure bool
		want     string
	}{
		{
			name:     "default port omits port",
			password: "secret",
			host:     "example.com",
			port:     443,
			sni:      "example.com",
			want:     "anytls://secret@example.com/",
		},
		{
			name:     "encodes password and query",
			password: "change:this password",
			host:     "example.com",
			port:     8443,
			sni:      "real.example.com",
			insecure: true,
			want:     "anytls://change%3Athis%20password@example.com:8443/?insecure=1&sni=real.example.com",
		},
		{
			name:     "brackets ipv6 host",
			password: "secret",
			host:     "2001:db8::1",
			port:     443,
			want:     "anytls://secret@[2001:db8::1]/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := anyTLSURI(tt.password, tt.host, tt.port, tt.sni, tt.insecure)
			if got != tt.want {
				t.Fatalf("anyTLSURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLogNodeInfo(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	wrapper := &ListenerWrapper{
		Users: []User{
			{Name: "alice", Password: "change:this password", Enabled: true},
			{Name: "bob", Password: "disabled", Enabled: false},
		},
		LogNodeInfo:  true,
		NodeHosts:    []string{"example.com"},
		NodePort:     8443,
		NodeSNI:      "real.example.com",
		NodeInsecure: true,
		logger:       zap.New(core),
	}

	wrapper.logNodeInfo(nil)

	entries := logs.FilterMessage("anytls node available").All()
	if len(entries) != 1 {
		t.Fatalf("node log count = %d, want 1", len(entries))
	}

	fields := entries[0].ContextMap()
	if fields["event"] != "anytls_node" {
		t.Fatalf("event = %v, want anytls_node", fields["event"])
	}
	if fields["user"] != "alice" {
		t.Fatalf("user = %v, want alice", fields["user"])
	}
	wantURI := "anytls://change%3Athis%20password@example.com:8443/?insecure=1&sni=real.example.com"
	if fields["uri"] != wantURI {
		t.Fatalf("uri = %v, want %s", fields["uri"], wantURI)
	}
}

func TestInferNodeHosts(t *testing.T) {
	server := &caddyhttp.Server{
		Routes: caddyhttp.RouteList{
			{
				MatcherSetsRaw: caddyhttp.RawMatcherSets{
					{"host": json.RawMessage(`["example.com","*.wild.example","{placeholder}.example"]`)},
				},
			},
		},
	}

	wrapper := &ListenerWrapper{}
	hosts := wrapper.nodeHosts(server)
	if !slices.Equal(hosts, []string{"example.com"}) {
		t.Fatalf("nodeHosts() = %v, want [example.com]", hosts)
	}
}

func TestUnmarshalCaddyfileAllowsFallbackFalse(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		fallback false
		user alice secret
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	wrapper.logger = zap.NewNop()
	wrapper.registry = newSessionRegistry()
	if err := wrapper.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	if wrapper.Fallback {
		t.Fatal("Fallback = true, want false")
	}
}

func TestUnmarshalJSONDefaults(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantFallback bool
		wantEnabled  bool
	}{
		{
			name:         "omitted booleans use documented defaults",
			input:        `{"users":[{"name":"alice","password":"secret"}]}`,
			wantFallback: true,
			wantEnabled:  true,
		},
		{
			name:         "explicit false values are preserved",
			input:        `{"fallback":false,"allow_cidrs":["10.0.0.0/8"],"deny_cidrs":["127.0.0.0/8"],"allow_ports":[443],"deny_ports":[25],"allow_domains":["example.com"],"deny_domains":["blocked.example"],"users":[{"name":"alice","password":"secret","enabled":false}]}`,
			wantFallback: false,
			wantEnabled:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wrapper ListenerWrapper
			if err := json.Unmarshal([]byte(tt.input), &wrapper); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if wrapper.Fallback != tt.wantFallback {
				t.Fatalf("Fallback = %v, want %v", wrapper.Fallback, tt.wantFallback)
			}
			if len(wrapper.Users) != 1 {
				t.Fatalf("len(Users) = %d, want 1", len(wrapper.Users))
			}
			if wrapper.Users[0].Enabled != tt.wantEnabled {
				t.Fatalf("Users[0].Enabled = %v, want %v", wrapper.Users[0].Enabled, tt.wantEnabled)
			}
			if tt.name == "explicit false values are preserved" {
				if strings.Join(wrapper.AllowCIDRs, ",") != "10.0.0.0/8" || strings.Join(wrapper.DenyCIDRs, ",") != "127.0.0.0/8" {
					t.Fatalf("cidr policies were not decoded: allow=%v deny=%v", wrapper.AllowCIDRs, wrapper.DenyCIDRs)
				}
				if !slices.Equal(wrapper.AllowPorts, []uint16{443}) || !slices.Equal(wrapper.DenyPorts, []uint16{25}) {
					t.Fatalf("port policies were not decoded: allow=%v deny=%v", wrapper.AllowPorts, wrapper.DenyPorts)
				}
				if strings.Join(wrapper.AllowDomains, ",") != "example.com" || strings.Join(wrapper.DenyDomains, ",") != "blocked.example" {
					t.Fatalf("domain policies were not decoded: allow=%v deny=%v", wrapper.AllowDomains, wrapper.DenyDomains)
				}
			}
		})
	}
}

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

func TestIdleTimeoutConnRefreshesDeadlines(t *testing.T) {
	base := &deadlineConn{}
	conn := newIdleTimeoutConn(base, time.Minute)

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if base.writeDeadline.IsZero() {
		t.Fatal("write deadline was not refreshed")
	}

	buf := []byte{0}
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if base.readDeadline.IsZero() {
		t.Fatal("read deadline was not refreshed")
	}
}

func TestReloadStyleUserDisableStopsNewAnyTLSDetection(t *testing.T) {
	enabled := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	disabled := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: false}}, true)

	sum := sha256.Sum256([]byte("secret"))
	preview := sum[:]

	decision, err := enabled.detector.Detect(preview)
	if err != nil || decision != DecisionAnyTLS {
		t.Fatalf("enabled detector = (%v, %v), want AnyTLS", decision, err)
	}

	decision, err = disabled.detector.Detect(preview)
	if err == nil || decision != DecisionReject {
		t.Fatalf("disabled detector = (%v, %v), want reject with error", decision, err)
	}
}

func TestStructuredLogsForFallbackAndProxy(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	fallbackWrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
	fallbackWrapper.logger = logger
	fallbackWrapper.service, _ = singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(fallbackWrapper.PaddingScheme),
		Users:         fallbackWrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: fallbackWrapper},
		Logger:        zapLogger{base: logger},
	})

	base := newChanListener()
	defer closeTest(base)
	wrapped := fallbackWrapper.WrapListener(base)
	serverConn, client := net.Pipe()
	base.enqueue(serverConn)
	go func() {
		conn, err := wrapped.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	_ = client.Close()

	if !waitForLogs(logs, "connection routed to website") {
		t.Fatal("expected fallback log entry")
	}
	if logs.FilterFieldKey("outcome").Len() == 0 {
		t.Fatal("expected structured outcome field in logs")
	}
	if logs.FilterFieldKey("reason").Len() == 0 {
		t.Fatal("expected structured reason field in logs")
	}

	core2, logs2 := observer.New(zapcore.DebugLevel)
	logger2 := zap.New(core2)
	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer closeTest(destination)
	proxyWrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	proxyWrapper.logger = logger2
	proxyWrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}
	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(proxyWrapper.PaddingScheme),
		Users:         proxyWrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: proxyWrapper},
		Logger:        zapLogger{base: logger2},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	proxyWrapper.service = service

	destDone := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			destDone <- err
			return
		}
		defer closeTest(conn)
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			destDone <- err
			return
		}
		_, err = io.WriteString(conn, strings.ToUpper(line))
		destDone <- err
	}()

	base2 := newChanListener()
	defer closeTest(base2)
	go acceptLoop(context.Background(), proxyWrapper.WrapListener(base2))

	client2, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base2.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client2)

	proxyConn, err := client2.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer closeTest(proxyConn)
	if _, err := io.WriteString(proxyConn, "ping\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if _, err := bufio.NewReader(proxyConn).ReadString('\n'); err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if err := <-destDone; err != nil {
		t.Fatalf("destination error = %v", err)
	}

	entry := logs2.FilterMessage("anytls connection established")
	if entry.Len() == 0 {
		t.Fatal("expected anytls connection log entry")
	}
	if entry.FilterFieldKey("user").Len() == 0 || entry.FilterFieldKey("destination").Len() == 0 || entry.FilterFieldKey("connection_id").Len() == 0 {
		t.Fatal("expected structured user, destination, and connection_id fields")
	}
	if entry.FilterFieldKey("protocol").Len() == 0 {
		t.Fatal("expected structured protocol field")
	}
}

func TestReloadStyleClosesExistingSessions(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer closeTest(destination)

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.logger = logger
	wrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}
	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(wrapper.PaddingScheme),
		Users:         wrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: wrapper},
		Logger:        zapLogger{base: logger},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	wrapper.service = service

	destReady := make(chan net.Conn, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			return
		}
		destReady <- conn
	}()

	base := newChanListener()
	defer closeTest(base)
	go acceptLoop(context.Background(), wrapper.WrapListener(base))

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client)

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer closeTest(proxyConn)

	if _, err := io.WriteString(proxyConn, "hold-open\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	var destConn net.Conn
	select {
	case destConn = <-destReady:
		defer closeTest(destConn)
	case <-time.After(time.Second):
		t.Fatal("destination connection was not established")
	}

	if !waitForCondition(time.Second, func() bool { return wrapper.activeSessionCount() == 1 }) {
		t.Fatal("expected one active session")
	}

	wrapper.closeActiveSessions("config_unload")

	_ = proxyConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = proxyConn.Read(buf)
	if err == nil {
		t.Fatal("expected closed proxy connection after config unload")
	}

	if !waitForLogs(logs, "anytls session terminated") {
		t.Fatal("expected termination audit log")
	}
}

func TestCaddyfileAdapterIncludesAnyTLSListenerWrapper(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter is not registered")
	}

	configJSON, warnings, err := adapter.Adapt([]byte(`
{
	servers :443 {
		listener_wrappers {
			anytls {
				probe_timeout 5s
				idle_timeout 2m
				connect_timeout 10s
				max_concurrent 64
				fallback true
				allow_private_targets false
				user alice secret
			}
		}
	}
}

example.com {
	respond "ok"
}
`), nil)
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}
	for _, warning := range warnings {
		if !strings.Contains(warning.Message, "not formatted") {
			t.Fatalf("Adapt() warnings = %v, want only formatting warnings or none", warnings)
		}
	}

	var adapted map[string]any
	if err := json.Unmarshal(configJSON, &adapted); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	apps := adapted["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	var found bool
	for _, rawServer := range servers {
		server := rawServer.(map[string]any)
		rawWrappers, ok := server["listener_wrappers"].([]any)
		if !ok {
			continue
		}
		for _, rawWrapper := range rawWrappers {
			wrapper := rawWrapper.(map[string]any)
			if wrapper["wrapper"] == "anytls" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("adapted config does not contain anytls listener wrapper")
	}
}

func newTestWrapper(t *testing.T, users []User, allowPrivateTargets bool) *ListenerWrapper {
	t.Helper()

	wrapper := &ListenerWrapper{
		Users:               users,
		ProbeTimeout:        caddy.Duration(250 * time.Millisecond),
		IdleTimeout:         caddy.Duration(2 * time.Second),
		ConnectTimeout:      caddy.Duration(time.Second),
		MaxConcurrent:       8,
		Fallback:            true,
		AllowPrivateTargets: allowPrivateTargets,
		PaddingScheme:       string(padding.DefaultPaddingScheme),
		logger:              zap.NewNop(),
		registry:            newSessionRegistry(),
	}
	wrapper.detector = NewPasswordHashDetector(wrapper.Users)

	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(wrapper.PaddingScheme),
		Users:         wrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: wrapper},
		Logger:        zapLogger{base: wrapper.logger},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	wrapper.service = service

	return wrapper
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
		Leaf:        template,
	}
}

func acceptLoop(ctx context.Context, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			return
		}
		_ = conn.Close()
	}
}

func waitForLogs(logs *observer.ObservedLogs, message string) bool {
	return waitForCondition(500*time.Millisecond, func() bool {
		return logs.FilterMessage(message).Len() > 0
	})
}

func waitForCondition(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

func closeTest(closer io.Closer) {
	_ = closer.Close()
}

type chanListener struct {
	connCh chan net.Conn
	once   sync.Once
	closed chan struct{}
}

type testTLSStateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c testTLSStateConn) ConnectionState() tls.ConnectionState {
	return c.state
}

type anyTLSTestDialer struct {
	client *singanytls.Client
}

func (d anyTLSTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.client.CreateProxy(ctx, destination)
}

func (d anyTLSTestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented in tests")
}

type stateCheckingListener struct {
	net.Listener
	seenCh chan net.Conn
	errCh  chan error
}

func (l *stateCheckingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if _, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); !ok {
		l.errCh <- errors.New("missing ConnectionState")
	} else {
		l.seenCh <- conn
	}
	return conn, nil
}

func newChanListener() *chanListener {
	return &chanListener{
		connCh: make(chan net.Conn, 16),
		closed: make(chan struct{}),
	}
}

func (l *chanListener) enqueue(conn net.Conn) {
	select {
	case <-l.closed:
		_ = conn.Close()
	case l.connCh <- conn:
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.connCh:
		return conn, nil
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return dummyAddr("chan-listener")
}

type dummyAddr string

func (a dummyAddr) Network() string { return "memory" }

func (a dummyAddr) String() string { return string(a) }

type deadlineConn struct {
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if len(p) > 0 {
		p[0] = 'x'
	}
	return 1, nil
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *deadlineConn) Close() error {
	return nil
}

func (c *deadlineConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (c *deadlineConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

type packetPayload struct {
	data []byte
	addr net.Addr
}

type packetConn struct {
	localAddr net.Addr
	peer      *packetConn
	recvCh    chan packetPayload
	closed    chan struct{}
	once      sync.Once
}

func newPacketPipe() (*packetConn, *packetConn) {
	left := &packetConn{
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 10), Port: 10010},
		recvCh:    make(chan packetPayload, 16),
		closed:    make(chan struct{}),
	}
	right := &packetConn{
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 11), Port: 10011},
		recvCh:    make(chan packetPayload, 16),
		closed:    make(chan struct{}),
	}
	left.peer = right
	right.peer = left
	return left, right
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case payload := <-c.recvCh:
		n := copy(p, payload.data)
		return n, payload.addr, nil
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	default:
	}

	data := append([]byte(nil), p...)
	select {
	case c.peer.recvCh <- packetPayload{data: data, addr: addr}:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	}
}

func (c *packetConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *packetConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *packetConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	return nil
}
