package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	singanytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/uuidroute"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Server struct {
	policyManager policy.Manager
	validator     *uuidroute.Validator
	paddingScheme string
	mu            sync.Mutex
	closed        bool
	connections   map[net.Conn]struct{}
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     newUserValidator(v.GetFeature(routing.RouterType()).(routing.Router)),
		paddingScheme: config.PaddingScheme,
		connections:   make(map[net.Conn]struct{}),
	}
	if _, err := singanytls.NewService("", singanytls.ServiceOptions{PaddingScheme: []byte(s.paddingScheme)}); err != nil {
		return nil, err
	}
	credentials := make([]uuidroute.Credential, 0, len(config.Users))
	for _, u := range config.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, errors.New("anytls: bad user").Base(err)
		}
		credential, err := userCredential(mu)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	if err := s.validator.AddUsers(credentials, true); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UNIX}
}

func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	connections := make([]net.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	return nil
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	if s.connections == nil {
		s.connections = make(map[net.Conn]struct{})
	}
	s.connections[conn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.connections, conn)
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetReadDeadline(time.Now().Add(s.policyManager.ForLevel(0).Timeouts.Handshake)); err != nil {
		return err
	}

	// Upstream has no authentication callback. Peek only its password digest to
	// select the immutable UUID-route match, then replay it unchanged. Coalescing
	// the digest also accommodates upstream's single ReadOnceFrom on TCP.
	var digest [sha256.Size]byte
	if _, err := io.ReadFull(conn, digest[:]); err != nil {
		return errors.New("anytls: read credential selector").Base(err)
	}
	match := s.validator.Authenticate(string(digest[:]))
	if match.User == nil {
		return singanytls.ErrAuthentication
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.Name, inbound.User, inbound.VlessRoute = protocolName, match.User, match.Route
		inbound.CanSpliceCopy = 3
	}
	password := match.User.Account.(*MemoryAccount).Password
	if sha256.Sum256([]byte(password)) != digest {
		id, err := uuid.Parse(password)
		if err != nil {
			return singanytls.ErrAuthentication
		}
		id[6], id[7] = byte(match.Route>>8), byte(match.Route)
		password = id.String()
	}
	// Per-connection services avoid a second mutable user/route index. The
	// library verifies the selected credential and owns the whole wire protocol.
	handler := &inboundAdapter{server: s, dispatcher: dispatcher, conn: conn, match: match}
	service, err := singanytls.NewService(password, singanytls.ServiceOptions{
		PaddingScheme: []byte(s.paddingScheme), Handler: handler,
	})
	if err != nil {
		return err
	}
	return service.NewConnection(ctx, &prefixConn{Conn: conn, prefix: bytes.NewReader(digest[:])}, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
}

type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

type inboundAdapter struct {
	server     *Server
	dispatcher routing.Dispatcher
	conn       net.Conn
	match      uuidroute.Match
	ready      sync.Once
}

func (h *inboundAdapter) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	h.ready.Do(func() { h.conn.SetReadDeadline(time.Time{}) })
	ctx = streamContext(ctx)
	inbound := session.InboundFromContext(ctx)
	inbound.Name, inbound.User, inbound.VlessRoute = protocolName, h.match.User, h.match.Route
	inbound.CanSpliceCopy = 3
	p := h.server.policyManager.ForLevel(h.match.User.Level)
	ctx = policy.ContextWithBufferPolicy(ctx, p.Buffer)
	var err error
	if destination.Fqdn == uot.MagicAddress {
		err = h.handleUDP(ctx, conn, p)
	} else {
		err = h.handleTCP(ctx, conn, destination, p)
	}
	if onClose != nil {
		onClose(err)
	}
	if err != nil {
		errors.LogDebugInner(ctx, err, "anytls: stream closed")
	}
}
