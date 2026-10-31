package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	stderrors "errors"
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
	fallback      *fallbackHandler
	mu            sync.Mutex
	workers       sync.WaitGroup
	closed        bool
	connections   map[net.Conn]context.CancelFunc
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     newUserValidator(v.GetFeature(routing.RouterType()).(routing.Router)),
		paddingScheme: config.PaddingScheme,
		connections:   make(map[net.Conn]context.CancelFunc),
	}
	if _, err := singanytls.NewService("", singanytls.ServiceOptions{PaddingScheme: []byte(s.paddingScheme)}); err != nil {
		return nil, err
	}
	if len(config.Fallbacks) > 0 {
		var err error
		s.fallback, err = newFallbackHandler(config.Fallbacks, s.policyManager, s.paddingScheme)
		if err != nil {
			return nil, err
		}
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
	connections := make(map[net.Conn]context.CancelFunc, len(s.connections))
	for conn, cancel := range s.connections {
		connections[conn] = cancel
	}
	s.mu.Unlock()
	for conn, cancel := range connections {
		cancel()
		conn.Close()
	}
	s.workers.Wait()
	return nil
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	if s.connections == nil {
		s.connections = make(map[net.Conn]context.CancelFunc)
	}
	s.connections[conn] = cancel
	s.workers.Add(1)
	s.mu.Unlock()
	defer s.workers.Done()
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.connections, conn)
		s.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	handshakeTimeout := s.policyManager.ForLevel(0).Timeouts.Handshake
	var release func()
	if s.fallback != nil {
		select {
		case s.fallback.slots <- struct{}{}:
			release = sync.OnceFunc(func() { <-s.fallback.slots })
			defer release()
		default:
			return errors.New("anytls: authentication/fallback connection limit reached")
		}
		if handshakeTimeout <= 0 || handshakeTimeout > fallbackAuthTimeout {
			handshakeTimeout = fallbackAuthTimeout
		}
	}
	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}

	// Upstream has no authentication callback. Peek only its password digest to
	// select the immutable UUID-route match, then replay it unchanged. Coalescing
	// the digest also accommodates upstream's single ReadOnceFrom on TCP.
	var digest [sha256.Size]byte
	n, err := io.ReadFull(conn, digest[:])
	if err != nil {
		timeout, isNetError := err.(net.Error)
		// A complete short HTTP request can be less than 32 bytes and wait for
		// a response without half-closing. At the authentication deadline replay
		// its partial prefix to the fixed fallback, rather than discarding it.
		if s.fallback == nil || n == 0 || ctx.Err() != nil ||
			(!stderrors.Is(err, io.EOF) && !stderrors.Is(err, io.ErrUnexpectedEOF) && !(isNetError && timeout.Timeout())) {
			return errors.New("anytls: read credential selector").Base(err)
		}
	}
	var match uuidroute.Match
	if n == len(digest) {
		match = s.validator.Authenticate(string(digest[:]))
	}
	if match.User == nil {
		if s.fallback != nil {
			ctx = context.WithValue(ctx, fallbackALPNKey{}, negotiatedALPN(conn))
			var fallbackErr error
			serviceErr := s.fallback.service.NewConnection(ctx,
				&prefixConn{Conn: conn, prefix: bytes.NewReader(digest[:n])},
				M.SocksaddrFromNet(conn.RemoteAddr()), func(err error) { fallbackErr = err })
			if serviceErr != nil {
				return serviceErr
			}
			return fallbackErr
		}
		return singanytls.ErrAuthentication
	}
	if release != nil {
		release()
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
