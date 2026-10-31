package anytls_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	appRouter "github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
)

func udpRouteEcho(t *testing.T, marker byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
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
			conn.WriteTo(append([]byte{marker}, packet[:n]...), source)
		}
	}()
	return conn.LocalAddr().String()
}

func TestUDPAssociationRoutingSnapshotUpdate(t *testing.T) {
	a, b := udpRouteEcho(t, 'A'), udpRouteEcho(t, 'B')
	address := freeTCPAddress(t)
	_, port, _ := net.SplitHostPort(address)
	const password = "5783a3e7-e373-0000-8642-c83782b807c5"
	config := fmt.Sprintf(`{
		"log":{"loglevel":"error"},"stats":{},
		"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},
		"inbounds":[{"tag":"anytls-in","listen":"127.0.0.1","port":%s,"protocol":"anytls","settings":{"users":[{"password":%q,"email":"udp-route@example.com"}]}}],
		"outbounds":[{"tag":"deny","protocol":"blackhole"},
		{"tag":"A","protocol":"freedom","settings":{"redirect":%q,"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}},
		{"tag":"B","protocol":"freedom","settings":{"redirect":%q,"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}],
		"routing":{"rules":[{"type":"field","ruleTag":"udp-route","inboundTag":["anytls-in"],"vlessRoute":"1234","outboundTag":"A"}]}
	}`, port, password, a, b)
	server, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, _ := standardClient(t, address, strings.Replace(password, "-0000-", "-04d2-", 1), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, uot.RequestDestination(uot.Version))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := uot.Request{Destination: M.ParseSocksaddr("192.0.2.1:53")}
	if err := uot.WriteRequest(conn, request); err != nil {
		t.Fatal(err)
	}
	packets := uot.NewConn(conn, request)
	roundTrip := func(destination M.Socksaddr, want string) {
		t.Helper()
		if err := packets.WritePacket(sbuf.As([]byte("route")), destination); err != nil {
			t.Fatal(err)
		}
		packet := sbuf.NewPacket()
		defer packet.Release()
		source, err := packets.ReadPacket(packet)
		if err != nil || source != destination || string(packet.Bytes()) != want {
			t.Fatalf("UDP routing: source=%v want=%v payload=%q error=%v", source, destination, packet.Bytes(), err)
		}
	}
	first := M.ParseSocksaddr("192.0.2.1:53")
	roundTrip(first, "Aroute")
	router := server.GetFeature(routing.RouterType()).(routing.Router)
	updated := &appRouter.Config{Rule: []*appRouter.RoutingRule{{RuleTag: "udp-route",
		TargetTag: &appRouter.RoutingRule_Tag{Tag: "B"}, InboundTag: []string{"anytls-in"},
		VlessRouteList: &xnet.PortList{Range: []*xnet.PortRange{{From: 1234, To: 1234}}}}}}
	if err := router.AddRule(serial.ToTypedMessage(updated), false); err != nil {
		t.Fatal(err)
	}
	// Existing targets keep their link; new targets in the same authenticated
	// association pick up the new routing snapshot and retain UUID identity.
	roundTrip(M.ParseSocksaddr("192.0.2.2:53"), "Broute")
	roundTrip(first, "Aroute")
	manager := server.GetFeature(stats.ManagerType()).(stats.Manager)
	for direction, want := range map[string]int64{"uplink": 3 * 5, "downlink": 3 * 6} {
		counter := manager.GetCounter("user>>>udp-route@example.com>>>traffic>>>" + direction)
		if counter == nil || counter.Value() != want {
			t.Fatalf("UDP shared %s stats: %v want %d", direction, counter, want)
		}
	}
}
