package anytls_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	singanytls "github.com/sagernet/sing-anytls"
	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/app/proxyman/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
)

func compatCertificate(t *testing.T) (map[string]any, *tls.Config, tls.Certificate) {
	t.Helper()
	c, err := cert.Generate(nil, cert.DNSNames("localhost"))
	if err != nil {
		t.Fatal(err)
	}
	certificate, key := c.ToPEM()
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	settings := map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{
		"alpn": []string{"h2"}, "certificates": []any{map[string]any{
			"certificate": strings.Split(strings.TrimSpace(string(certificate)), "\n"),
			"key":         strings.Split(strings.TrimSpace(string(key)), "\n"),
		}},
	}}
	return settings, &tls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13}, pair
}

func startCompatServer(t *testing.T, password string, streamSettings map[string]any) (*core.Instance, string) {
	t.Helper()
	address := freeTCPAddress(t)
	_, port, _ := net.SplitHostPort(address)
	var portNumber int
	fmt.Sscan(port, &portNumber)
	config := map[string]any{
		"log": map[string]any{"loglevel": "error"}, "stats": map[string]any{},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 2, "statsUserUplink": true, "statsUserDownlink": true}}},
		"inbounds": []any{map[string]any{
			"tag": "anytls-in", "listen": "127.0.0.1", "port": portNumber, "protocol": "anytls",
			"settings":       map[string]any{"users": []any{map[string]any{"password": password, "email": "compat@example.com"}}, "paddingScheme": []string{"stop=2", "0=5-5", "1=128-128"}},
			"streamSettings": streamSettings,
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4", "finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8", "::1/128"}}}}}},
	}
	encoded, _ := json.Marshal(config)
	server, err := core.StartInstance("json", encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, address
}

func compatTCPEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); conn.SetDeadline(time.Now().Add(10 * time.Second)); io.Copy(conn, conn) }()
		}
	}()
	return M.SocksaddrFromNet(l.Addr())
}

func compatUDPEcho(t *testing.T, network, address string) M.Socksaddr {
	t.Helper()
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		packet := make([]byte, 65535)
		for {
			n, source, err := conn.ReadFrom(packet)
			if err != nil {
				return
			}
			conn.WriteTo(packet[:n], source)
		}
	}()
	return M.SocksaddrFromNet(conn.LocalAddr())
}

type fragmentedConn struct {
	net.Conn
	first bool
}

func (c *fragmentedConn) Write(p []byte) (int, error) {
	if c.first {
		c.first = false
		for i := range p {
			if _, err := c.Conn.Write(p[i : i+1]); err != nil {
				return i, err
			}
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func standardClient(t *testing.T, address, password string, tlsConfig *tls.Config) (*singanytls.Client, *atomic.Int32) {
	t.Helper()
	count := new(atomic.Int32)
	client, err := singanytls.NewClient(singanytls.ClientOptions{Password: password, DialOut: func(ctx context.Context) (net.Conn, error) {
		count.Add(1)
		var conn net.Conn
		var err error
		if tlsConfig == nil {
			conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
		} else {
			conn, err = (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", address)
		}
		if err != nil {
			return nil, err
		}
		return &fragmentedConn{Conn: conn, first: true}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, count
}

func checkTCP(conn net.Conn, payload []byte) error {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("payload differs")
	}
	return nil
}

func TestStandardClientTLSUoT2AndReuse(t *testing.T) {
	settings, tlsConfig, _ := compatCertificate(t)
	server, address := startCompatServer(t, "standard-password", settings)
	client, dials := standardClient(t, address, "standard-password", tlsConfig)
	target := compatTCPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		conn, err := client.DialContext(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkTCP(conn, bytes.Repeat([]byte{byte(i)}, 32768)); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	if dials.Load() != 1 {
		t.Fatalf("sequential streams used %d sessions", dials.Load())
	}
	udpTargets := []M.Socksaddr{compatUDPEcho(t, "udp4", "127.0.0.1:0"), compatUDPEcho(t, "udp4", "127.0.0.1:0"), compatUDPEcho(t, "udp6", "[::1]:0")}
	direct, err := net.Dial("udp6", udpTargets[2].String())
	if err != nil {
		t.Fatal(err)
	}
	direct.SetDeadline(time.Now().Add(200 * time.Millisecond))
	direct.Write([]byte("ipv6-baseline"))
	if _, err := direct.Read(make([]byte, 64)); err != nil {
		t.Log("IPv6 UDP baseline unavailable on this host; IPv6 wire encoding is covered separately:", err)
		udpTargets = udpTargets[:2]
	}
	direct.Close()
	udpTargets = append(udpTargets, M.Socksaddr{Fqdn: "localhost", Port: udpTargets[0].Port})
	var payloadBytes int64 = 3 * 32768
	for _, connected := range []bool{true, false} {
		conn, err := client.DialContext(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		request := uot.Request{IsConnect: connected, Destination: udpTargets[0]}
		if err := uot.WriteRequest(conn, request); err != nil {
			t.Fatal(err)
		}
		packets := uot.NewConn(conn, request)
		for i, size := range []int{1, 63, 4096, 8000, 17} {
			destination := udpTargets[0]
			if !connected {
				destination = udpTargets[i%len(udpTargets)]
			}
			payload := bytes.Repeat([]byte{byte(i + 1)}, size)
			if err := packets.WritePacket(sbuf.As(payload), destination); err != nil {
				t.Fatal(err)
			}
			buffer := sbuf.NewPacket()
			source, err := packets.ReadPacket(buffer)
			ok := bytes.Equal(buffer.Bytes(), payload)
			buffer.Release()
			if err != nil || !ok || source != destination {
				t.Fatalf("UoT2 connected=%v size=%d source=%v want=%v err=%v", connected, size, source, destination, err)
			}
			payloadBytes += int64(size)
		}
		conn.Close()
	}
	manager := server.GetFeature(stats.ManagerType()).(stats.Manager)
	for _, direction := range []string{"uplink", "downlink"} {
		counter := manager.GetCounter("user>>>compat@example.com>>>traffic>>>" + direction)
		if counter == nil || counter.Value() != payloadBytes {
			t.Fatalf("%s payload stats: %v want %d", direction, counter, payloadBytes)
		}
	}
}

func TestStandardClientConcurrentAndShutdown(t *testing.T) {
	server, address := startCompatServer(t, "concurrent-password", nil)
	client, _ := standardClient(t, address, "concurrent-password", nil)
	target := compatTCPEcho(t)
	var workers sync.WaitGroup
	errors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, target)
			if err == nil {
				defer conn.Close()
				err = checkTCP(conn, bytes.Repeat([]byte{byte(i)}, 65536))
			}
			errors <- err
		}(i)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	conn, err := client.DialContext(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTCP(conn, []byte("before-close")); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("server close left stream open")
	}
	conn.Close()
	client.Close()
	if _, err := client.DialContext(context.Background(), target); err == nil {
		t.Fatal("closed client opened a stream")
	}
}

type standardEchoHandler struct{}

func (standardEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if destination.Fqdn == uot.MagicAddress {
		N.ReportHandshakeSuccess(conn)
		request, err := uot.ReadRequest(conn)
		if err != nil {
			return
		}
		packets := uot.NewConn(conn, *request)
		packet := sbuf.NewPacket()
		defer packet.Release()
		for {
			packet.Reset()
			destination, err := packets.ReadPacket(packet)
			if err != nil {
				return
			}
			if err := packets.WritePacket(packet, destination); err != nil {
				return
			}
		}
	}
	N.ReportHandshakeSuccess(conn)
	io.Copy(conn, conn)
}

func TestXrayOutboundToStandardServiceTLS(t *testing.T) {
	_, _, pair := compatCertificate(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	service, err := singanytls.NewService("upstream-password", singanytls.ServiceOptions{Handler: standardEchoHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	var connections atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	pin := sha256.Sum256(pair.Certificate[0])
	config := fmt.Sprintf(`{"log":{"loglevel":"error"},"outbounds":[{"protocol":"anytls","settings":{"address":"127.0.0.1","port":%d,"password":"upstream-password"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"localhost","pinnedPeerCertSha256":%q,"alpn":["h2"]}}}]}`, port, hex.EncodeToString(pin[:]))
	client, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, network := range []xnet.Network{xnet.Network_TCP, xnet.Network_UDP, xnet.Network_TCP} {
		destination := xnet.Destination{Network: network, Address: xnet.LocalHostIP, Port: 12345}
		conn, err := core.Dial(ctx, client, destination)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- checkTCP(conn, []byte("standard-service-echo")) }()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		conn.Close()
	}
	if connections.Load() > 2 {
		t.Fatalf("outbound failed to reuse sessions: %d", connections.Load())
	}
}

func writeWireFrame(writer io.Writer, cmd byte, sid uint32, body []byte) error {
	header := make([]byte, 7)
	header[0] = cmd
	binary.BigEndian.PutUint32(header[1:], sid)
	binary.BigEndian.PutUint16(header[5:], uint16(len(body)))
	_, err := writer.Write(append(header, body...))
	return err
}

func TestMalformedAndFragmentedWire(t *testing.T) {
	_, address := startCompatServer(t, "wire-password", nil)
	for _, mode := range []string{"wrong-password", "short-auth", "truncated-padding", "missing-settings", "truncated-frame", "bad-address", "bad-uot"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			digest := sha256.Sum256([]byte("wire-password"))
			if mode == "wrong-password" {
				digest = sha256.Sum256([]byte("wrong-password"))
			}
			if mode == "short-auth" {
				conn.Write(digest[:7])
			} else {
				conn.Write(digest[:])
				if mode == "truncated-padding" {
					conn.Write([]byte{0, 4, 1})
				} else {
					conn.Write([]byte{0, 0})
					if mode != "missing-settings" {
						writeWireFrame(conn, 4, 0, []byte("v=2"))
					}
					writeWireFrame(conn, 1, 1, nil)
					switch mode {
					case "truncated-frame":
						conn.Write([]byte{2, 0, 0})
					case "bad-address":
						writeWireFrame(conn, 2, 1, []byte{255})
					case "bad-uot":
						var addr bytes.Buffer
						M.SocksaddrSerializer.WriteAddrPort(&addr, uot.RequestDestination(uot.Version))
						writeWireFrame(conn, 2, 1, append(addr.Bytes(), 1, 255))
					}
				}
			}
			conn.(*net.TCPConn).CloseWrite()
			// A malformed stream may receive settings/SYNACK/FIN before closure.
			_, err = io.Copy(io.Discard, conn)
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("malformed peer was left hanging")
			}
		})
	}
	client, _ := standardClient(t, address, "wire-password", nil)
	conn, err := client.DialContext(context.Background(), compatTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := checkTCP(conn, []byte("healthy-after-malformed")); err != nil {
		t.Fatal(err)
	}
}

func TestAnyTLSOverXrayReality(t *testing.T) {
	_, _, pair := compatCertificate(t)
	front, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
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
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{
		"target": front.Addr().String(), "serverNames": []string{"localhost"}, "privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"0123456789abcdef"},
	}}
	_, address := startCompatServer(t, "reality-password", settings)
	waitRealityFront(t, front.Addr().String())
	_, port, _ := net.SplitHostPort(address)
	config := fmt.Sprintf(`{"log":{"loglevel":"error"},"outbounds":[{"protocol":"anytls","settings":{"address":"127.0.0.1","port":%s,"password":"reality-password"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"localhost","fingerprint":"chrome","password":%q,"shortId":"0123456789abcdef","spiderX":"/"}}}]}`, port, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()))
	client, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for _, network := range []xnet.Network{xnet.Network_TCP, xnet.Network_UDP} {
		target := compatTCPEcho(t)
		if network == xnet.Network_UDP {
			target = compatUDPEcho(t, "udp4", "127.0.0.1:0")
		}
		destination, _ := xnet.ParseDestination(network.SystemString() + ":" + target.String())
		conn, err := core.Dial(ctx, client, destination)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- checkTCP(conn, []byte("reality-echo")) }()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		conn.Close()
	}
}

func TestUserRemovalKeepsAuthenticatedSession(t *testing.T) {
	server, address := startCompatServer(t, "retained-password", nil)
	client, dials := standardClient(t, address, "retained-password", nil)
	target := compatTCPEcho(t)
	request := func() {
		t.Helper()
		conn, err := client.DialContext(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := checkTCP(conn, []byte("retained-session")); err != nil {
			t.Fatal(err)
		}
	}
	request()
	handler, err := server.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(context.Background(), "anytls-in")
	if err != nil {
		t.Fatal(err)
	}
	operation := &command.RemoveUserOperation{Email: "compat@example.com"}
	if err := operation.ApplyInbound(context.Background(), handler); err != nil {
		t.Fatal(err)
	}
	request()
	if dials.Load() != 1 {
		t.Fatal("existing authentication was not reused")
	}
	newClient, _ := standardClient(t, address, "retained-password", nil)
	conn, err := newClient.DialContext(context.Background(), target)
	if err == nil {
		defer conn.Close()
		if err := checkTCP(conn, []byte("should-reject")); err == nil {
			t.Fatal("removed user authenticated a new connection")
		}
	}
}

func TestAnyTLSAuthenticationRejectedAccessLogs(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback=%v", fallback), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "access.log")
			address := freeTCPAddress(t)
			_, port, _ := net.SplitHostPort(address)
			var portNumber int
			fmt.Sscan(port, &portNumber)
			settings := map[string]any{"users": []any{map[string]any{"password": "access-password", "email": "access@example.com"}}}
			if fallback {
				settings["fallbacks"] = []any{map[string]any{"dest": compatTCPEcho(t).String()}}
			}
			config := map[string]any{
				"log": map[string]any{"loglevel": "error", "access": path},
				"inbounds": []any{map[string]any{
					"tag": "anytls-in", "listen": "127.0.0.1", "port": portNumber, "protocol": "anytls", "settings": settings,
				}},
				"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{
					"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}},
				}}},
			}
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			server, err := core.StartInstance("json", encoded)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
			conn, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			peer := conn.LocalAddr().String()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			digest := sha256.Sum256([]byte("wrong-password"))
			if _, err := conn.Write(digest[:]); err != nil {
				t.Fatal(err)
			}
			if fallback {
				got := make([]byte, len(digest))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, digest[:]) {
					t.Fatalf("fallback did not replay rejected credential: %x, %v", got, err)
				}
			} else if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("invalid credential was not rejected")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("invalid credential was not closed promptly")
			}
			conn.Close()
			client, _ := standardClient(t, address, "access-password", nil)
			validConn, err := client.DialContext(context.Background(), compatTCPEcho(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := checkTCP(validConn, []byte("valid credential")); err != nil {
				validConn.Close()
				t.Fatal(err)
			}
			validConn.Close()
			deadline := time.Now().Add(2 * time.Second)
			for {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Count(data, []byte("\n")) >= 2 {
					lines := strings.Split(strings.TrimSpace(string(data)), "\n")
					if len(lines) != 2 || !strings.Contains(lines[0], "from "+peer+" rejected ") ||
						!strings.Contains(lines[0], singanytls.ErrAuthentication.Error()) || strings.Contains(lines[0], "email:") ||
						!strings.Contains(lines[1], " accepted ") || !strings.Contains(lines[1], "email: access@example.com") {
						t.Fatalf("unexpected authentication access logs: %q", data)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("authentication access logs did not arrive: %q", data)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestAnyTLSAccessLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	address := freeTCPAddress(t)
	_, port, _ := net.SplitHostPort(address)
	var portNumber int
	fmt.Sscan(port, &portNumber)
	freedom := map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}
	config := map[string]any{
		"log": map[string]any{"loglevel": "error", "access": path},
		"inbounds": []any{map[string]any{
			"tag": "anytls-in", "listen": "127.0.0.1", "port": portNumber, "protocol": "anytls",
			"settings": map[string]any{"users": []any{map[string]any{"password": "access-password", "email": "access@example.com"}}},
		}},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": freedom},
			map[string]any{"tag": "udp-direct", "protocol": "freedom", "settings": freedom},
		},
		"routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "udp", "outboundTag": "udp-direct"}}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := core.StartInstance("json", encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	client, dials := standardClient(t, address, "access-password", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	want := make(map[string]int)
	for i := 0; i < 2; i++ {
		target := compatTCPEcho(t)
		conn, err := client.DialContext(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkTCP(conn, []byte("logged TCP stream")); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.Close()
		want["tcp:"+target.String()]++
	}
	udpTargets := []M.Socksaddr{compatUDPEcho(t, "udp4", "127.0.0.1:0"), compatUDPEcho(t, "udp4", "127.0.0.1:0")}
	for _, connected := range []bool{true, false} {
		conn, err := client.DialContext(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		request := uot.Request{IsConnect: connected, Destination: udpTargets[0]}
		if err := uot.WriteRequest(conn, request); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		packets := uot.NewConn(conn, request)
		targets := udpTargets
		if connected {
			targets = targets[:1]
		}
		for round := 0; round < 3; round++ {
			for _, target := range targets {
				payload := []byte("logged UDP target")
				if err := packets.WritePacket(sbuf.As(payload), target); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				buffer := sbuf.NewPacket()
				source, err := packets.ReadPacket(buffer)
				ok := source == target && bytes.Equal(buffer.Bytes(), payload)
				buffer.Release()
				if err != nil || !ok {
					conn.Close()
					t.Fatalf("UDP echo differs: source=%v target=%v err=%v", source, target, err)
				}
			}
		}
		conn.Close()
		for _, target := range targets {
			want["udp:"+target.String()]++
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("expected pooled AnyTLS session reuse, got %d connections", dials.Load())
	}
	wantLines := 0
	for _, count := range want {
		wantLines += count
	}
	var data []byte
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(data, []byte("\n")) >= wantLines {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("access logs did not arrive: got %q, want %d records", data, wantLines)
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := make(map[string]int)
	var peer string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 11 || fields[2] != "from" || fields[4] != "accepted" || fields[9] != "email:" || fields[10] != "access@example.com" {
			t.Fatalf("invalid access-log fields: %q", line)
		}
		host, _, err := net.SplitHostPort(fields[3])
		if err != nil || host != "127.0.0.1" || (peer != "" && peer != fields[3]) {
			t.Fatalf("expected original pooled connection source: %q", line)
		}
		peer = fields[3]
		detour := "[anytls-in >> direct]"
		if strings.HasPrefix(fields[5], "udp:") {
			detour = "[anytls-in -> udp-direct]"
		}
		if strings.Join(fields[6:9], " ") != detour {
			t.Fatalf("incorrect inbound/outbound tags: %q", line)
		}
		got[fields[5]]++
	}
	if len(got) != len(want) {
		t.Fatalf("logged destinations: got %v, want %v", got, want)
	}
	for destination, count := range want {
		if got[destination] != count {
			t.Errorf("access logs for %s: got %d, want %d", destination, got[destination], count)
		}
	}
}
