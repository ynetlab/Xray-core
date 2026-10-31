package anytls

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	singanytls "github.com/sagernet/sing-anytls"
	sbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	fallbackMaxConnections = 128
	fallbackAuthTimeout    = 10 * time.Second
	fallbackDialTimeout    = 5 * time.Second
	fallbackIdleTimeout    = 2 * time.Minute
)

type fallbackTarget struct{ network, address string }
type fallbackALPNKey struct{}

type fallbackHandler struct {
	targets map[string]fallbackTarget
	slots   chan struct{}
	policy  policy.Manager
	// This service deliberately has no users: it can only call FallbackHandler.
	// Authenticated connections still use the existing UUID snapshot selector.
	service *singanytls.MultiService[struct{}]
}

func fallbackTargets(config []*Fallback) (map[string]fallbackTarget, error) {
	targets := make(map[string]fallbackTarget, len(config))
	for _, fb := range config {
		if fb == nil || fb.Dest == "" || len(fb.Alpn) > 255 || strings.ContainsAny(fb.Alpn, "\x00\r\n") {
			return nil, errors.New("anytls: invalid fallback")
		}
		if _, exists := targets[fb.Alpn]; exists {
			return nil, errors.New("anytls: duplicate fallback alpn: ", fb.Alpn)
		}
		target := fallbackTarget{network: fb.Type, address: fb.Dest}
		if target.network == "" {
			if filepath.IsAbs(target.address) || strings.HasPrefix(target.address, "@") {
				target.network = "unix"
			} else {
				target.network = "tcp"
			}
		}
		switch target.network {
		case "tcp":
			if port, err := strconv.ParseUint(target.address, 10, 16); err == nil && port != 0 {
				target.address = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
			}
			host, portString, err := net.SplitHostPort(target.address)
			port, portErr := strconv.ParseUint(portString, 10, 16)
			if err != nil || portErr != nil || port == 0 || host == "" || strings.ContainsAny(host, "*/\\ \t\r\n\x00?#@") {
				return nil, errors.New("anytls: invalid TCP fallback dest: ", fb.Dest)
			}
			if ip := net.ParseIP(strings.Split(host, "%")[0]); ip != nil && (ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast)) {
				return nil, errors.New("anytls: fallback dest must be a unicast backend")
			}
		case "unix":
			if strings.ContainsRune(target.address, 0) || (!filepath.IsAbs(target.address) && !strings.HasPrefix(target.address, "@")) || target.address == "@" {
				return nil, errors.New("anytls: invalid Unix fallback dest")
			}
		default:
			return nil, errors.New("anytls: fallback type must be tcp or unix")
		}
		targets[fb.Alpn] = target
	}
	return targets, nil
}

// ValidateFallbacks validates JSON and protobuf configurations identically.
func ValidateFallbacks(config []*Fallback) error {
	_, err := fallbackTargets(config)
	return err
}

func newFallbackHandler(config []*Fallback, p policy.Manager, padding string) (*fallbackHandler, error) {
	targets, err := fallbackTargets(config)
	if err != nil {
		return nil, err
	}
	h := &fallbackHandler{targets: targets, slots: make(chan struct{}, fallbackMaxConnections), policy: p}
	h.service, err = singanytls.NewMultiService[struct{}](singanytls.ServiceOptions{
		PaddingScheme: []byte(padding), FallbackHandler: h,
	})
	return h, err
}

func negotiatedALPN(conn net.Conn) string {
	switch conn := stat.TryUnwrapStatsConn(conn).(type) {
	case *tls.Conn:
		return conn.ConnectionState().NegotiatedProtocol
	case *reality.Conn:
		return conn.ConnectionState().NegotiatedProtocol
	default:
		return ""
	}
}

func (h *fallbackHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	err := h.handle(ctx, conn)
	if onClose != nil {
		onClose(err)
	}
}

func (h *fallbackHandler) handle(ctx context.Context, conn net.Conn) error {
	// CachedConn.Close touches its unread buffer and cannot race with Read.
	// Take ownership before starting workers, copy every cached byte, and close
	// only the underlying connection during cancellation. No library changes.
	if cached, ok := conn.(*sbufio.CachedConn); ok {
		prefix := cached.ReadCached()
		conn = cached.Conn
		if prefix != nil {
			conn = &prefixConn{Conn: conn, prefix: bytes.NewReader(bytes.Clone(prefix.Bytes()))}
			prefix.Release()
		}
	}
	defer conn.Close()
	alpn, _ := ctx.Value(fallbackALPNKey{}).(string)
	target, found := h.targets[alpn]
	if !found {
		target, found = h.targets[""]
	}
	if !found {
		return errors.New("anytls: no fallback for negotiated alpn: ", alpn)
	}
	errors.LogDebug(ctx, "anytls: fallback alpn=", alpn, " backend=", target.address)
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	// Only an administrator-configured address is dialed. HTTP Host, CONNECT
	// authority and the AnyTLS request destination never select this backend.
	dialCtx, cancel := context.WithTimeout(ctx, fallbackDialTimeout)
	backend, err := (&net.Dialer{}).DialContext(dialCtx, target.network, target.address)
	cancel()
	if err != nil {
		return errors.New("anytls: fallback dial failed").Base(err)
	}
	return relayFallback(ctx, conn, backend, h.policy.ForLevel(0))
}

// Reuse Xray's buffered copy and activity policy while joining both directions.
// A client EOF half-closes the backend so HTTP responses can still be delivered.
func relayFallback(parent context.Context, client, backend net.Conn, p policy.Session) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var once sync.Once
	closeAll := func() { once.Do(func() { client.Close(); backend.Close() }) }
	defer closeAll()
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	idle := fallbackIdleTimeout
	if p.Timeouts.ConnectionIdle > 0 && p.Timeouts.ConnectionIdle < idle {
		idle = p.Timeouts.ConnectionIdle
	}
	timer := signal.CancelAfterInactivity(ctx, cancel, idle)
	defer timer.SetTimeout(0)
	type result struct {
		err    error
		uplink bool
	}
	results := make(chan result, 2)
	go func() {
		err := buf.Copy(buf.NewReader(client), buf.NewWriter(backend), buf.UpdateActivity(timer))
		if err == nil {
			if half, ok := backend.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			}
			if timeout := p.Timeouts.DownlinkOnly; timeout > 0 && timeout < idle {
				timer.SetTimeout(timeout)
			}
		}
		results <- result{err: err, uplink: true}
	}()
	go func() {
		results <- result{err: buf.Copy(buf.NewReader(backend), buf.NewWriter(client), buf.UpdateActivity(timer))}
	}()
	first := <-results
	if !first.uplink || first.err != nil {
		closeAll()
	}
	second := <-results
	if first.err != nil {
		return first.err
	}
	if second.err != nil {
		return second.err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

var _ N.TCPConnectionHandlerEx = (*fallbackHandler)(nil)
