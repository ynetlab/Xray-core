package anytls

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	sessionctx "github.com/xtls/xray-core/common/session"
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
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     newUserValidator(v.GetFeature(routing.RouterType()).(routing.Router)),
		paddingScheme: config.PaddingScheme,
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

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessPol := s.policyManager.ForLevel(0)
	_ = conn.SetReadDeadline(time.Now().Add(sessPol.Timeouts.Handshake))

	sess := &session{
		isClient:   false,
		server:     s,
		conn:       conn,
		br:         &buf.BufferedReader{Reader: buf.NewReader(conn)},
		bw:         buf.NewBufferedWriter(buf.NewWriter(conn)),
		streams:    make(map[uint32]*stream),
		dispatcher: dispatcher,
	}
	sess.fw = newFrameWriter(sess.bw)
	sess.peerVersion = 1

	// auth header: 32B sha256(password) + 2B padlen
	var h [34]byte
	if _, err := io.ReadFull(sess.br, h[:]); err != nil {
		return errors.New("anytls: read auth").Base(err)
	}

	auth := s.validator.Authenticate(string(h[:32]))
	if auth.User == nil {
		return errors.New("anytls: invalid user")
	}

	padlen := binary.BigEndian.Uint16(h[32:34])
	if padlen > 0 {
		if err := discardBytes(sess.br, int(padlen)); err != nil {
			return errors.New("anytls: read padding0").Base(err)
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	inb := sessionctx.InboundFromContext(ctx)
	inb.Name = protocolName
	inb.User = auth.User
	inb.VlessRoute = auth.Route
	inb.CanSpliceCopy = 3

	return sess.readLoop(ctx)
}
