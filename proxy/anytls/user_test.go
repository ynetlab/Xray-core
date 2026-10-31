package anytls

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	sessionctx "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
)

const basePassword = "5783a3e7-e373-0000-8642-c83782b807c5"

type authRouter struct{ routing.DefaultRouter }

func (authRouter) WithVlessRouteSnapshot(use func(*routing.VlessRouteSnapshot)) {
	use(routing.NewVlessRouteSnapshot(1, []xnet.Port{2000, 65535}))
}

type authPolicy struct{ policy.Manager }

func (authPolicy) ForLevel(uint32) policy.Session { return policy.SessionDefault() }
func routePassword(route uint16) string {
	return fmt.Sprintf("5783a3e7-e373-%04x-8642-c83782b807c5", route)
}
func newUserServer() *Server {
	return &Server{validator: newUserValidator(authRouter{}), policyManager: authPolicy{}}
}

func TestRouteAuthenticationWire(t *testing.T) {
	s := newUserServer()
	if err := s.AddUser(context.Background(), &protocol.MemoryUser{Email: "wire", Level: 7, Account: &MemoryAccount{Password: basePassword}}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []uint16{0, 2000, 65535, 1100} {
		server, client := net.Pipe()
		inb := &sessionctx.Inbound{}
		ctx := sessionctx.ContextWithInbound(context.Background(), inb)
		result := make(chan error, 1)
		go func() { defer server.Close(); result <- s.Process(ctx, xnet.Network_TCP, server, nil) }()
		hash := sha256.Sum256([]byte(routePassword(route)))
		client.Write(append(hash[:], 0, 3, 'p', 'a', 'd'))
		client.Close()
		<-result
		if route == 1100 {
			if inb.User != nil {
				t.Fatal("unconfigured route authenticated")
			}
		} else if inb.User != s.GetUser(ctx, "wire") || inb.VlessRoute != xnet.Port(route) || inb.User.Level != 7 {
			t.Fatalf("route %d: %+v", route, inb)
		}
	}
}
func TestAnyTLSUserAPIReplacesEveryVariant(t *testing.T) {
	s := newUserServer()
	ctx := context.Background()
	user := &protocol.MemoryUser{Email: "user", Account: &MemoryAccount{Password: basePassword}}
	if err := s.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if s.GetUsersCount(ctx) != 1 || len(s.GetUsers(ctx)) != 1 {
		t.Fatal("variants counted as users")
	}
	user.Account = &MemoryAccount{Password: "ordinary-password"}
	if err := s.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(routePassword(2000)))
	if s.validator.Authenticate(string(hash[:])).User != nil {
		t.Fatal("old UUID variant still valid")
	}
	if err := s.RemoveUser(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	if s.GetUsersCount(ctx) != 0 {
		t.Fatal("user not deleted")
	}
}
