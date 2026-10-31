package anytls_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	appRouter "github.com/xtls/xray-core/app/router"
	routerCommand "github.com/xtls/xray-core/app/router/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/anytls"
	"github.com/xtls/xray-core/proxy/trojan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func trojanRoutedRequest(address, password string) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	hash := sha256.Sum224([]byte(password))
	wire := append([]byte(fmt.Sprintf("%x\r\n", hash)), 1, 1, 127, 0, 0, 1, 0, 7, '\r', '\n')
	wire = append(wire, []byte("route-test")...)
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	response := make([]byte, len("Aroute-test"))
	_, err = io.ReadFull(conn, response)
	return response, err
}

func TestRoutingAndUserAPIsAcrossProtocols(t *testing.T) {
	for _, mode := range []struct {
		protocol string
		fallback bool
	}{{"anytls", false}, {"anytls", true}, {"trojan", false}} {
		t.Run(fmt.Sprintf("%s/fallback=%v", mode.protocol, mode.fallback), func(t *testing.T) {
			protocolName := mode.protocol
			echo := routeEcho(t, 'A')
			address, apiAddress := freeTCPAddress(t), freeTCPAddress(t)
			_, port, _ := net.SplitHostPort(address)
			const base = "5783a3e7-e373-0000-8642-c83782b807c5"
			const replacement = "6783a3e7-e373-0000-8642-c83782b807c5"
			const email = "shared@example.com"
			usersKey := "users"
			if protocolName == "trojan" {
				usersKey = "clients"
			}
			fallbackConfig := ""
			if mode.fallback {
				backend, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { backend.Close() })
				go func() {
					for {
						conn, err := backend.Accept()
						if err != nil {
							return
						}
						conn.Close()
					}
				}()
				fallbackConfig = fmt.Sprintf(`,"fallbacks":[{"dest":%q}]`, backend.Addr().String())
			}
			config := fmt.Sprintf(`{
		"api":{"tag":"api","listen":%q,"services":["HandlerService","RoutingService"]},"stats":{},
		"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},
		"inbounds":[{"tag":"test-in","listen":"127.0.0.1","port":%s,"protocol":%q,"settings":{%q:[{"password":%q,"email":%q}]%s}}],
		"outbounds":[{"tag":"deny","protocol":"blackhole"},{"tag":"echo","protocol":"freedom","settings":{"redirect":%q,"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}],
		"routing":{"rules":[{"type":"field","ruleTag":"initial","inboundTag":["test-in"],"vlessRoute":"2000","outboundTag":"echo"}]}
		}`, apiAddress, port, protocolName, usersKey, base, email, fallbackConfig, echo)
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
			users, routes := command.NewHandlerServiceClient(conn), routerCommand.NewRoutingServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			routeConfig := func(value uint32) *appRouter.Config {
				return &appRouter.Config{Rule: []*appRouter.RoutingRule{{RuleTag: "dynamic", TargetTag: &appRouter.RoutingRule_Tag{Tag: "echo"}, InboundTag: []string{"test-in"}, VlessRouteList: &xnet.PortList{Range: []*xnet.PortRange{{From: value, To: value}}}}}}
			}
			setRoute := func(value uint32) error {
				_, err := routes.AddRule(ctx, &routerCommand.AddRuleRequest{Config: serial.ToTypedMessage(routeConfig(value))})
				return err
			}
			request := func(password string, route uint16, want bool) {
				t.Helper()
				password = strings.Replace(password, "-0000-", fmt.Sprintf("-%04x-", route), 1)
				var response []byte
				var err error
				if protocolName == "anytls" {
					response, err = routedRequest(address, password)
				} else {
					response, err = trojanRoutedRequest(address, password)
				}
				if want && (err != nil || string(response) != "Aroute-test") {
					t.Fatalf("route %d: %q %v", route, response, err)
				}
				if !want && err == nil {
					t.Fatalf("unconfigured/deleted credential route %d authenticated", route)
				}
			}
			request(base, 2000, true)
			request(base, 3000, false)
			if err := setRoute(3000); err != nil {
				t.Fatal(err)
			}
			request(base, 3000, true)
			request(base, 2000, false)
			if _, err := routes.RemoveRule(ctx, &routerCommand.RemoveRuleRequest{RuleTag: "dynamic"}); err != nil {
				t.Fatal(err)
			}
			request(base, 3000, false)
			if err := setRoute(65535); err != nil {
				t.Fatal(err)
			}
			request(base, 65535, true)
			alter := func(operation proto.Message) error {
				_, err := users.AlterInbound(ctx, &command.AlterInboundRequest{Tag: "test-in", Operation: serial.ToTypedMessage(operation)})
				return err
			}
			var wg sync.WaitGroup
			failures := make(chan error, 2)
			wg.Add(2)
			go func() { defer wg.Done(); failures <- setRoute(4000) }()
			go func() {
				defer wg.Done()
				if err := alter(&command.RemoveUserOperation{Email: email}); err != nil {
					failures <- err
					return
				}
				var account proto.Message = &anytls.Account{Password: replacement}
				if protocolName == "trojan" {
					account = &trojan.Account{Password: replacement}
				}
				failures <- alter(&command.AddUserOperation{User: &protocol.User{Email: email, Account: serial.ToTypedMessage(account)}})
			}()
			wg.Wait()
			close(failures)
			for err := range failures {
				if err != nil {
					t.Fatal(err)
				}
			}
			request(replacement, 4000, true)
			request(base, 4000, false)
			count, err := users.GetInboundUsersCount(ctx, &command.GetInboundUserRequest{Tag: "test-in"})
			if err != nil || count.GetCount() != 1 {
				t.Fatal("wrong logical user count", count, err)
			}
			manager := server.GetFeature(stats.ManagerType()).(stats.Manager)
			for direction, want := range map[string]int64{"uplink": 4 * int64(len("route-test")), "downlink": 4 * int64(len("Aroute-test"))} {
				counter := manager.GetCounter("user>>>" + email + ">>>traffic>>>" + direction)
				if counter == nil || counter.Value() != want {
					t.Fatal("route variants split accounting", direction, counter, want)
				}
			}
			if err := alter(&command.RemoveUserOperation{Email: email}); err != nil {
				t.Fatal(err)
			}
			if err := setRoute(5000); err != nil {
				t.Fatal(err)
			}
			request(replacement, 5000, false)
		})
	}
}
