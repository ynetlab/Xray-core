package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/policy"
)

func TestFallbackTargetsValidation(t *testing.T) {
	for _, tc := range []struct {
		name, network, dest, normalized string
		valid                           bool
	}{
		{"port", "", "8080", "127.0.0.1:8080", true},
		{"IPv4", "", "127.0.0.1:8080", "127.0.0.1:8080", true},
		{"IPv6", "tcp", "[::1]:8080", "[::1]:8080", true},
		{"domain", "", "localhost:8080", "localhost:8080", true},
		{"zero-port", "", "0", "", false},
		{"port-overflow", "", "65536", "", false},
		{"missing-host", "", ":80", "", false},
		{"missing-port", "tcp", "localhost", "", false},
		{"wildcard", "tcp", "0.0.0.0:80", "", false},
		{"wildcard-v6", "tcp", "[::]:80", "", false},
		{"multicast", "tcp", "224.0.0.1:80", "", false},
		{"broadcast", "tcp", "255.255.255.255:80", "", false},
		{"URL", "", "http://localhost:80", "", false},
		{"user-info", "tcp", "user@localhost:80", "", false},
		{"invalid-host", "tcp", "*.example.com:80", "", false},
		{"control-character", "tcp", "localhost\x00:80", "", false},
		{"UDP", "udp", "localhost:80", "", false},
		{"relative-unix", "unix", "relative.sock", "", false},
		{"empty-unix", "unix", "@", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := fallbackTargets([]*Fallback{{Type: tc.network, Dest: tc.dest}})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err == nil && (targets[""].address != tc.normalized || targets[""].network != "tcp") {
				t.Fatal("unexpected backend normalization", targets)
			}
		})
	}
	for _, config := range [][]*Fallback{
		{nil},
		{{Alpn: "h2", Dest: "80"}, {Alpn: "h2", Dest: "81"}},
		{{Dest: "80"}, {Dest: "81"}},
		{{Alpn: "bad\x00protocol", Dest: "80"}},
	} {
		if err := ValidateFallbacks(config); err == nil {
			t.Fatal("accepted invalid/ambiguous fallback configuration", config)
		}
	}
}

func fallbackTestServer(t *testing.T, address string) *Server {
	t.Helper()
	s := newUserServer()
	var err error
	s.fallback, err = newFallbackHandler([]*Fallback{{Dest: address}}, s.policyManager, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func startFallbackPipe(t *testing.T, s *Server) (net.Conn, <-chan error) {
	t.Helper()
	server, client := net.Pipe()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { client.Close() })
	result := make(chan error, 1)
	go func() { result <- s.Process(context.Background(), xnet.Network_TCP, server, nil) }()
	return client, result
}

func TestFallbackResourceLimitAndRelease(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := fallbackTestServer(t, listener.Addr().String())
	s.fallback.slots = make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		client, _ := startFallbackPipe(t, s)
		if _, err := client.Write(bytes.Repeat([]byte{byte(i)}, 32)); err != nil {
			t.Fatal(err)
		}
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		backend, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		backend.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(backend, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	_, rejected := startFallbackPipe(t, s)
	select {
	case err := <-rejected:
		if err == nil {
			t.Fatal("resource limit did not reject connection")
		}
	case <-time.After(time.Second):
		t.Fatal("connection limit blocked instead of rejecting")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(s.fallback.slots) != 0 {
		t.Fatal("fallback slots leaked after shutdown")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections) != 0 {
		t.Fatal("connections retained after server close")
	}
}

func TestFallbackAuthenticatedConnectionReleasesSlot(t *testing.T) {
	s := fallbackTestServer(t, "127.0.0.1:1")
	s.fallback.slots = make(chan struct{}, 1)
	if err := s.AddUser(context.Background(), &protocol.MemoryUser{Account: &MemoryAccount{Password: "valid-password"}}); err != nil {
		t.Fatal(err)
	}
	client, result := startFallbackPipe(t, s)
	digest := sha256.Sum256([]byte("valid-password"))
	if _, err := client.Write(digest[:]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(s.fallback.slots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("authenticated session retained a fallback slot")
		}
		time.Sleep(time.Millisecond)
	}
	// Successful selection must not close the connection while the library is
	// waiting for its padding length. Server shutdown must interrupt that read.
	select {
	case err := <-result:
		t.Fatal("authenticated connection closed before shutdown", err)
	default:
	}
	s.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("authenticated library read survived shutdown")
	}
}

func TestFallbackRelayIdleAndCancel(t *testing.T) {
	for _, mode := range []string{"idle", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			client, clientPeer := net.Pipe()
			backend, backendPeer := net.Pipe()
			defer clientPeer.Close()
			defer backendPeer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := policy.SessionDefault()
			p.Timeouts.ConnectionIdle = 30 * time.Millisecond
			done := make(chan error, 1)
			go func() { done <- relayFallback(ctx, client, backend, p) }()
			if mode == "cancel" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay did not join blocked copy tasks after idle/cancel")
			}
			for _, peer := range []net.Conn{clientPeer, backendPeer} {
				peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := peer.Read(make([]byte, 1)); err == nil {
					t.Fatal("relay endpoint remained open")
				}
			}
		})
	}
}

func TestFallbackDialFailureAndCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	s := fallbackTestServer(t, address)
	for _, canceled := range []bool{false, true} {
		server, client := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		if err := s.fallback.handle(ctx, server); err == nil {
			t.Fatal("failed/canceled dial succeeded")
		}
		cancel()
		client.Close()
	}
}
