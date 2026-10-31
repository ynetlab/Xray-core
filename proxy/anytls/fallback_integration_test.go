package anytls_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	singanytls "github.com/sagernet/sing-anytls"
	sbuf "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/uot"
	goreality "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet/reality"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func startFallbackServer(t *testing.T, fallbacks []map[string]any, tlsEnabled bool, streamSettings ...map[string]any) (*core.Instance, string, *tls.Config) {
	t.Helper()
	address := freeTCPAddress(t)
	_, port, _ := net.SplitHostPort(address)
	var portNumber int
	fmt.Sscan(port, &portNumber)
	inbound := map[string]any{"listen": "127.0.0.1", "port": portNumber, "protocol": "anytls", "tag": "anytls-in",
		"settings": map[string]any{"users": []any{map[string]any{"password": "fallback-password", "email": "fallback@example.com"}}, "fallbacks": fallbacks}}
	var tlsConfig *tls.Config
	if tlsEnabled {
		settings, clientTLS, _ := compatCertificate(t)
		settings["tlsSettings"].(map[string]any)["alpn"] = []string{"h2", "http/1.1"}
		inbound["streamSettings"] = settings
		tlsConfig = clientTLS
	}
	if len(streamSettings) > 0 {
		inbound["streamSettings"] = streamSettings[0]
	}
	config := map[string]any{"log": map[string]any{"loglevel": "error"},
		"policy":   map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 1}}},
		"inbounds": []any{inbound}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := core.StartInstance("json", encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, address, tlsConfig
}

func TestFallbackHTTPProtocols(t *testing.T) {
	var http1, http2Requests atomic.Int32
	handler := func(marker string, count *atomic.Int32) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			fmt.Fprintf(w, "%s|%s|%s|%x", marker, r.Proto, r.RequestURI, sha256.Sum256(body))
		})
	}
	backend1 := httptest.NewServer(handler("default", &http1))
	t.Cleanup(backend1.Close)
	backend2 := httptest.NewServer(h2c.NewHandler(handler("h2", &http2Requests), &http2.Server{}))
	t.Cleanup(backend2.Close)
	_, address, tlsConfig := startFallbackServer(t, []map[string]any{
		{"dest": strings.TrimPrefix(backend1.URL, "http://")},
		{"alpn": "h2", "dest": strings.TrimPrefix(backend2.URL, "http://")},
	}, true)
	for _, alpn := range []string{"http/1.1", "h2", ""} {
		t.Run("alpn="+alpn, func(t *testing.T) {
			config := tlsConfig.Clone()
			config.NextProtos = nil
			if alpn != "" {
				config.NextProtos = []string{alpn}
			}
			dialTLS := func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", address)
			}
			var transport http.RoundTripper
			if alpn == "h2" {
				tr := &http2.Transport{TLSClientConfig: config,
					DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
						return dialTLS(ctx, network, addr)
					}}
				transport = tr
				defer tr.CloseIdleConnections()
			} else {
				tr := &http.Transport{DialTLSContext: dialTLS, TLSClientConfig: config}
				transport = tr
				defer tr.CloseIdleConnections()
			}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			// Two requests on a reused connection exercise the preface/header replay
			// and bytes beyond the 32-byte selector without duplicate consumption.
			for i := 0; i < 2; i++ {
				body := bytes.Repeat([]byte{byte(i), 0, 255, 128}, 32768)
				response, err := client.Post("https://client-selected.invalid/path?q=preserved", "application/octet-stream", bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(response.Body)
				response.Body.Close()
				marker, protocol := "default", "HTTP/1.1"
				if alpn == "h2" {
					marker, protocol = "h2", "HTTP/2.0"
				}
				want := fmt.Sprintf("%s|%s|/path?q=preserved|%x", marker, protocol, sha256.Sum256(body))
				if err != nil || response.StatusCode != 200 || string(got) != want {
					t.Fatalf("HTTP request corrupted/misrouted: %q want %q error=%v", got, want, err)
				}
			}
		})
	}
	if http1.Load() != 4 || http2Requests.Load() != 2 {
		t.Fatal("wrong ALPN backend counts", http1.Load(), http2Requests.Load())
	}
}

func fallbackEcho(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	count := new(atomic.Int32)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), count
}

func TestFallbackReplayAndAuthentication(t *testing.T) {
	backend, fallbackDials := fallbackEcho(t)
	_, address, tlsConfig := startFallbackServer(t, []map[string]any{{"dest": backend}}, true)
	tlsConfig.NextProtos = []string{"http/1.1"}
	for _, mode := range []string{"wrong-digest", "empty-password-digest", "binary", "fragmented-http"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := tls.Dial("tcp", address, tlsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{0, 255, 13, 10, 128}, 10000)
			if mode == "wrong-digest" || mode == "empty-password-digest" {
				password := "wrong-password"
				if mode == "empty-password-digest" {
					password = ""
				}
				digest := sha256.Sum256([]byte(password))
				payload = append(digest[:], payload...)
			} else if mode == "fragmented-http" {
				payload = []byte("GET /fragmented HTTP/1.1\r\nHost: preserved.example\r\n\r\n")
			}
			if mode == "fragmented-http" {
				for _, b := range payload {
					if _, err := conn.Write([]byte{b}); err != nil {
						t.Fatal(err)
					}
				}
			} else if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("fallback did not replay every byte exactly once:", err)
			}
		})
	}
	if fallbackDials.Load() != 4 {
		t.Fatal("wrong fallback connection count", fallbackDials.Load())
	}
	// The standard client writes the initial authentication byte by byte.
	// Valid fragmented credentials must retain the normal AnyTLS path.
	client, _ := standardClient(t, address, "fallback-password", tlsConfig)
	conn, err := client.DialContext(context.Background(), compatTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := checkTCP(conn, []byte("authenticated-stream")); err != nil {
		t.Fatal(err)
	}
	for _, connected := range []bool{true, false} {
		target := compatUDPEcho(t, "udp4", "127.0.0.1:0")
		stream, err := client.DialContext(context.Background(), uot.RequestDestination(uot.Version))
		if err != nil {
			t.Fatal(err)
		}
		stream.SetDeadline(time.Now().Add(3 * time.Second))
		request := uot.Request{IsConnect: connected, Destination: target}
		if err := uot.WriteRequest(stream, request); err != nil {
			t.Fatal(err)
		}
		packets := uot.NewConn(stream, request)
		payload := bytes.Repeat([]byte{1, 0, 255}, 2000)
		if err := packets.WritePacket(sbuf.As(payload), target); err != nil {
			t.Fatal(err)
		}
		packet := sbuf.NewPacket()
		source, err := packets.ReadPacket(packet)
		ok := bytes.Equal(packet.Bytes(), payload)
		packet.Release()
		stream.Close()
		if err != nil || !ok || source != target {
			t.Fatal("authenticated UDP entered fallback or changed datagram", connected, source, err)
		}
	}
	if fallbackDials.Load() != 4 {
		t.Fatal("valid authentication entered fallback")
	}
}

func TestFallbackDisabledAndALPNOnly(t *testing.T) {
	backend, dials := fallbackEcho(t)
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint("enabled=", enabled), func(t *testing.T) {
			var fallbacks []map[string]any
			if enabled {
				fallbacks = []map[string]any{{"alpn": "h2", "dest": backend}}
			}
			_, address, config := startFallbackServer(t, fallbacks, true)
			config.NextProtos = []string{"http/1.1"}
			conn, err := tls.Dial("tcp", address, config)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write(bytes.Repeat([]byte("x"), 32))
			if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatal("invalid credential or unmapped ALPN was accepted")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("invalid credential/unmapped ALPN connection was left open")
			}
			if dials.Load() != 0 {
				t.Fatal("disabled/unmapped fallback dialed a backend")
			}
		})
	}
}

func TestFallbackShortRequestHalfClose(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "short-request-ok") }))
	t.Cleanup(backend.Close)
	_, address, _ := startFallbackServer(t, []map[string]any{{"dest": strings.TrimPrefix(backend.URL, "http://")}}, false)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	request := []byte("GET / HTTP/1.0\r\n\r\n")
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || !bytes.Contains(response, []byte("short-request-ok")) {
		t.Fatalf("partial selector EOF lost HTTP response: %q %v", response, err)
	}
}

func TestFallbackShortHTTPRequestWithoutHalfClose(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s|%s", r.Method, r.Host)
	}))
	t.Cleanup(backend.Close)
	_, address, _ := startFallbackServer(t, []map[string]any{{"dest": strings.TrimPrefix(backend.URL, "http://")}}, false)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost:a\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal("short complete request was discarded at auth timeout", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "GET|a" {
		t.Fatalf("short HTTP request changed: %q %v", body, err)
	}
}

func TestFallbackAuthenticationTimeoutAndShutdown(t *testing.T) {
	backend, dials := fallbackEcho(t)
	server, address, _ := startFallbackServer(t, []map[string]any{{"dest": backend}}, false)
	partial, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer partial.Close()
	partial.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := partial.Read(make([]byte, 1)); err == nil {
		t.Fatal("empty authentication did not time out")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("server did not enforce authentication deadline")
	}
	if dials.Load() != 0 {
		t.Fatal("authentication timeout dialed backend")
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("active-fallback"), 4)
	conn.Write(payload)
	if _, err := io.ReadFull(conn, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server close did not join fallback tasks")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("fallback connection survived server close")
	}
}

func TestFallbackREALITY(t *testing.T) {
	_, _, pair := compatCertificate(t)
	front, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })
	go func() {
		for {
			conn, err := front.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "fallback|%s|%s", r.Proto, r.RequestURI)
	}), &http2.Server{}))
	t.Cleanup(backend.Close)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{
		"target": front.Addr().String(), "serverNames": []string{"localhost"},
		"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"0123456789abcdef"},
	}}
	// This REALITY version reports no negotiated ALPN. Use an explicitly
	// configured HTTP/2 default backend and send HTTP/2 with prior knowledge;
	// never infer a negotiated protocol from the client's offered ALPN list.
	_, address, _ := startFallbackServer(t, []map[string]any{{"dest": strings.TrimPrefix(backend.URL, "http://")}}, false, settings)
	waitRealityFront(t, front.Addr().String())
	destination, err := xnet.ParseDestination("tcp:" + address)
	if err != nil {
		t.Fatal(err)
	}
	dialReality := func(ctx context.Context) (net.Conn, error) {
		raw, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		conn, err := reality.UClient(raw, &reality.Config{Fingerprint: "chrome", ServerName: "localhost",
			PublicKey: key.PublicKey().Bytes(), ShortId: []byte{1, 35, 69, 103, 137, 171, 205, 239},
			SpiderX: "/", SpiderY: make([]int64, 10)}, ctx, destination)
		if err != nil {
			raw.Close()
			return nil, err
		}
		conn.SetDeadline(time.Time{})
		return conn, nil
	}
	transport := &http2.Transport{DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		return dialReality(ctx)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://localhost/reality-fallback")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "fallback|HTTP/2.0|/reality-fallback" {
		t.Fatalf("REALITY decrypted ALPN fallback: %q %v", body, err)
	}
	client, err := singanytls.NewClient(singanytls.ClientOptions{Password: "fallback-password", DialOut: dialReality})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, udp := range []bool{false, true} {
		target := compatTCPEcho(t)
		if udp {
			target = uot.RequestDestination(uot.Version)
		}
		conn, err := client.DialContext(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if udp {
			echo := compatUDPEcho(t, "udp4", "127.0.0.1:0")
			request := uot.Request{IsConnect: true, Destination: echo}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if err := uot.WriteRequest(conn, request); err != nil {
				t.Fatal(err)
			}
			packets := uot.NewConn(conn, request)
			if _, err := packets.Write([]byte("reality-udp")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 64)
			n, err := packets.Read(got)
			if err != nil || string(got[:n]) != "reality-udp" {
				t.Fatal("REALITY authenticated UDP regression", err)
			}
		} else if err := checkTCP(conn, []byte("reality-tcp")); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
}

func waitRealityFront(t *testing.T, target string) {
	t.Helper()
	// The transport starts its target probe asynchronously. A connection that
	// arrives while the cache holds the in-progress bool waits in REALITY for
	// five seconds, racing the local test front's deadline. Wait for the actual
	// probe result rather than replacing the library's cache with a fake value.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if value, found := goreality.GlobalPostHandshakeRecordsLens.Load(target + " localhost 2"); found {
			if _, ready := value.([]int); ready {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("REALITY target probe was not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
