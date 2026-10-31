package anytls_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

func routeEcho(t *testing.T, marker byte) string {
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
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := make([]byte, len("route-test"))
				if _, err := io.ReadFull(conn, payload); err == nil {
					conn.Write(append([]byte{marker}, payload...))
				}
			}()
		}
	}()
	return l.Addr().String()
}

// Use the original AnyTLS wire format directly, so the test does not depend
// on matching client/server changes to authentication or request framing.
func routedRequest(address, password string) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	hash := sha256.Sum256([]byte(password))
	wire := bytes.NewBuffer(append(hash[:], 0, 3, 'p', 'a', 'd'))
	frame := func(cmd byte, sid uint32, body []byte) {
		wire.WriteByte(cmd)
		binary.Write(wire, binary.BigEndian, sid)
		binary.Write(wire, binary.BigEndian, uint16(len(body)))
		wire.Write(body)
	}
	frame(4, 0, []byte("v=2"))
	frame(1, 1, nil)
	frame(2, 1, []byte{1, 127, 0, 0, 1, 0, 7})
	frame(2, 1, []byte("route-test"))
	if _, err := conn.Write(wire.Bytes()); err != nil {
		return nil, err
	}
	var response []byte
	for len(response) < len("Aroute-test") {
		var header [7]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, err
		}
		body := make([]byte, binary.BigEndian.Uint16(header[5:7]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		if header[0] == 2 {
			response = append(response, body...)
		}
		if header[0] == 3 && len(response) < len("Aroute-test") {
			return nil, io.ErrUnexpectedEOF
		}
	}
	return response, nil
}

func TestRouteAPIAndSharedStats(t *testing.T) {
	echoA, echoB := routeEcho(t, 'A'), routeEcho(t, 'B')
	address, apiAddress := freeTCPAddress(t), freeTCPAddress(t)
	_, port, _ := net.SplitHostPort(address)
	const base = "5783a3e7-e373-0000-8642-c83782b807c5"
	const email = "shared@example.com"
	config := fmt.Sprintf(`{
		"api":{"tag":"api","listen":%q,"services":["HandlerService"]},
		"stats":{},
		"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true},"1":{"statsUserUplink":true,"statsUserDownlink":true}}},
		"inbounds":[{"tag":"anytls-in","listen":"127.0.0.1","port":%s,"protocol":"anytls","settings":{"users":[{"password":%q,"email":%q}]}}],
		"outbounds":[{"tag":"deny","protocol":"blackhole"},{"tag":"route-a","protocol":"freedom","settings":{"redirect":%q}},{"tag":"route-b","protocol":"freedom","settings":{"redirect":%q}}],
		"routing":{"rules":[{"type":"field","inboundTag":["anytls-in"],"vlessRoute":"1001","outboundTag":"route-a"},{"type":"field","inboundTag":["anytls-in"],"vlessRoute":"1100","outboundTag":"route-b"}]}
	}`, apiAddress, port, base, email, echoA, echoB)
	server, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	conn, err := grpc.NewClient(apiAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	api := command.NewHandlerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	userCount := func(want int64) {
		t.Helper()
		count, err := api.GetInboundUsersCount(ctx, &command.GetInboundUserRequest{Tag: "anytls-in"})
		if err != nil || count.GetCount() != want {
			t.Fatalf("user count: %v, error %v; want %d", count, err, want)
		}
		users, err := api.GetInboundUsers(ctx, &command.GetInboundUserRequest{Tag: "anytls-in"})
		if err != nil || int64(len(users.GetUsers())) != want {
			t.Fatalf("user list: %v, error %v", users, err)
		}
	}
	alter := func(operation proto.Message) {
		t.Helper()
		if _, err := api.AlterInbound(ctx, &command.AlterInboundRequest{Tag: "anytls-in", Operation: serial.ToTypedMessage(operation)}); err != nil {
			t.Fatal(err)
		}
	}
	request := func(password, want string) {
		t.Helper()
		got, err := routedRequest(address, password)
		if err != nil || string(got) != want {
			t.Fatalf("routed request: %q, error %v; want %q", got, err, want)
		}
	}
	userCount(1)
	for _, tc := range []struct{ group, response string }{{"03e9", "Aroute-test"}, {"044c", "Broute-test"}, {"03e9", "Aroute-test"}} {
		request(strings.Replace(base, "-0000-", "-"+tc.group+"-", 1), tc.response)
	}
	manager := server.GetFeature(stats.ManagerType()).(stats.Manager)
	checkStats := func(wantUplink, wantDownlink int64) {
		t.Helper()
		for suffix, want := range map[string]int64{"uplink": wantUplink, "downlink": wantDownlink} {
			counter := manager.GetCounter("user>>>" + email + ">>>traffic>>>" + suffix)
			if counter == nil || counter.Value() != want {
				t.Fatalf("shared %s counter: %v, want %d", suffix, counter, want)
			}
		}
	}
	checkStats(3*int64(len("route-test")), 3*int64(len("Aroute-test")))
	const replacement = "6783a3e7-e373-0000-8642-c83782b807c5"
	alter(&command.AddUserOperation{User: &protocol.User{Email: email, Level: 1, Account: serial.ToTypedMessage(&anytls.Account{Password: replacement})}})
	userCount(1)
	for _, group := range []string{"0000", "03e9", "044c"} {
		if _, err := routedRequest(address, strings.Replace(base, "-0000-", "-"+group+"-", 1)); err == nil {
			t.Fatal("old UUID still authenticates after API replacement")
		}
	}
	request(strings.Replace(replacement, "-0000-", "-044c-", 1), "Broute-test")
	checkStats(4*int64(len("route-test")), 4*int64(len("Aroute-test")))
	alter(&command.RemoveUserOperation{Email: email})
	userCount(0)
	for _, group := range []string{"0000", "03e9", "044c"} {
		if _, err := routedRequest(address, strings.Replace(replacement, "-0000-", "-"+group+"-", 1)); err == nil {
			t.Fatal("removed UUID still authenticates")
		}
	}
	alter(&command.AddUserOperation{User: &protocol.User{Email: email, Account: serial.ToTypedMessage(&anytls.Account{Password: base})}})
	userCount(1)
	request(strings.Replace(base, "-0000-", "-03e9-", 1), "Aroute-test")
	checkStats(5*int64(len("route-test")), 5*int64(len("Aroute-test")))
}
