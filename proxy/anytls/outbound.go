package anytls

import (
	"context"
	"net"
	"sync"
	"time"

	singanytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type dialerKey struct{}

const (
	defaultIdleSessionCheckInterval = 30 * time.Second
	defaultIdleSessionTimeout       = 60 * time.Second
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	client        *singanytls.Client
	closeContext  context.Context
	cancel        context.CancelFunc
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config == nil || config.Server == nil {
		return nil, errors.New("anytls: no server specified")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if server.User == nil {
		return nil, errors.New("anytls: no user specified")
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return nil, errors.New("anytls: invalid account type")
	}
	v := core.MustFromContext(ctx)
	c := &Client{server: server, policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager)}
	c.closeContext, c.cancel = context.WithCancel(ctx)
	checkInterval, idleTimeout := defaultIdleSessionCheckInterval, defaultIdleSessionTimeout
	if config.GetIdleSessionCheckInterval() > 0 {
		checkInterval = time.Duration(config.GetIdleSessionCheckInterval()) * time.Second
	}
	if config.GetIdleSessionTimeout() > 0 {
		idleTimeout = time.Duration(config.GetIdleSessionTimeout()) * time.Second
	}
	c.client, err = singanytls.NewClient(singanytls.ClientOptions{
		Password: account.Password, ClientMetadata: "xray",
		IdleSessionCheckInterval: checkInterval,
		IdleSessionTimeout:       idleTimeout,
		MinIdleSession:           int(config.GetMinIdleSession()),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			dialer, ok := ctx.Value(dialerKey{}).(internet.Dialer)
			if !ok {
				return nil, errors.New("anytls: missing Xray dialer")
			}
			var conn net.Conn
			err := retry.ExponentialBackoff(5, 100).On(func() error {
				if err := ctx.Err(); err != nil {
					return err
				}
				var err error
				conn, err = dialer.Dial(ctx, server.Destination)
				return err
			})
			if err != nil {
				return nil, err
			}
			guard := &handshakeConn{Conn: conn, ctx: ctx, timeout: c.policyManager.ForLevel(server.User.Level).Timeouts.Handshake}
			guard.stop = context.AfterFunc(ctx, func() { conn.Close() })
			return guard, nil
		},
	})
	if err != nil {
		c.cancel()
		return nil, err
	}
	return c, nil
}

func (c *Client) Close() error {
	c.cancel()
	return c.client.Close()
}

// The library registers a session after its authentication write. Bound and
// cancel that initial write too, without binding the pooled connection to the
// lifetime of its first stream after the handshake has completed.
type handshakeConn struct {
	net.Conn
	ctx     context.Context
	timeout time.Duration
	first   sync.Once
	stop    func() bool
}

func (c *handshakeConn) Write(p []byte) (n int, err error) {
	initial := false
	c.first.Do(func() {
		initial = true
		deadline := time.Now().Add(c.timeout)
		if value, ok := c.ctx.Deadline(); ok && value.Before(deadline) {
			deadline = value
		}
		if err = c.Conn.SetWriteDeadline(deadline); err == nil {
			n, err = c.Conn.Write(p)
		}
		c.stop()
	})
	if initial {
		return
	}
	return c.Conn.Write(p)
}

func (c *handshakeConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.closeContext, cancel)
	defer stop()
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || !outbounds[len(outbounds)-1].Target.IsValid() {
		return errors.New("target not specified")
	}
	ob := outbounds[len(outbounds)-1]
	ob.Name, ob.CanSpliceCopy = protocolName, 3
	target := toSocksaddr(ob.Target)
	if ob.Target.Network == xnet.Network_UDP {
		target = uot.RequestDestination(uot.Version)
	}
	conn, err := c.client.DialContext(context.WithValue(ctx, dialerKey{}, dialer), target)
	if err != nil {
		return errors.New("anytls: failed to open stream").Base(err)
	}
	defer conn.Close()
	var reader buf.Reader = buf.NewReader(conn)
	var writer buf.Writer = buf.NewWriter(conn)
	if ob.Target.Network == xnet.Network_UDP {
		request := uot.Request{IsConnect: true, Destination: toSocksaddr(ob.Target)}
		packetConn := uot.NewLazyConn(conn, request)
		reader = &packetReader{conn: packetConn}
		writer = &packetWriter{conn: packetConn, destination: request.Destination}
	}
	p := c.policyManager.ForLevel(c.server.User.Level)
	return relay(ctx, conn, link, reader, writer, p, false)
}
