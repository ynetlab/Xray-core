package anytls

import (
	"context"
	"io"
	"maps"
	"net"
	"sync"
	"time"

	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

func toSocksaddr(destination xnet.Destination) M.Socksaddr {
	return M.ParseSocksaddrHostPort(destination.Address.String(), uint16(destination.Port))
}

func fromSocksaddr(address M.Socksaddr, network xnet.Network) xnet.Destination {
	return xnet.Destination{Network: network, Address: xnet.ParseAddress(address.AddrString()), Port: xnet.Port(address.Port)}
}

func streamContext(ctx context.Context) context.Context {
	inbound := new(session.Inbound)
	if parent := session.InboundFromContext(ctx); parent != nil {
		*inbound = *parent
	}
	content := new(session.Content)
	if parent := session.ContentFromContext(ctx); parent != nil {
		*content = *parent
		content.Attributes = maps.Clone(parent.Attributes)
	}
	return session.ContextWithContent(session.ContextWithOutbounds(session.ContextWithInbound(ctx, inbound), []*session.Outbound{{}}), content)
}

func (h *inboundAdapter) handleTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr, p policy.Session) error {
	if !destination.IsValid() {
		return io.ErrUnexpectedEOF
	}
	link, err := h.dispatcher.Dispatch(ctx, fromSocksaddr(destination, xnet.Network_TCP))
	if err != nil {
		N.ReportHandshakeFailure(conn, err)
		return err
	}
	if err := N.ReportHandshakeSuccess(conn); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return err
	}
	return relay(ctx, conn, link, buf.NewReader(conn), buf.NewWriter(conn), p, true)
}

func (h *inboundAdapter) handleUDP(ctx context.Context, conn net.Conn, p policy.Session) error {
	// Clients may wait for SYNACK before writing the UoT request.
	if err := N.ReportHandshakeSuccess(conn); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(p.Timeouts.Handshake))
	request, err := uot.ReadRequest(conn)
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})
	packetConn := uot.NewConn(conn, *request)
	return h.dispatchPackets(ctx, conn, packetConn, p)
}

// Each association destination gets a Dispatcher link, preserving routing and
// stats while retaining domain addresses and complete datagrams through UoT2.
func (h *inboundAdapter) dispatchPackets(ctx context.Context, conn net.Conn, packetConn *uot.Conn, p policy.Session) error {
	idle := udpTargetIdleTimeout
	if p.Timeouts.ConnectionIdle > 0 && p.Timeouts.ConnectionIdle < idle {
		idle = p.Timeouts.ConnectionIdle
	}
	return runUDPAssociation(ctx, conn, packetConn, p, h.dispatcher.Dispatch, idle, udpMaxTargets)
}

// relay owns both copy workers and joins them after interruption. Cancellation
// closes only this stream and its Xray pipes, never the pooled TLS session.
func relay(ctx context.Context, conn net.Conn, link *transport.Link, reader buf.Reader, writer buf.Writer, p policy.Session, inbound bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			conn.Close()
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		})
	}
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	defer closeAll()
	results := make(chan error, 2)
	go func() {
		var err error
		if inbound {
			err = buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
			common.Close(link.Writer)
		} else {
			err = buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
		}
		results <- err
	}()
	go func() {
		var err error
		if inbound {
			err = buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
		} else {
			err = buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
			common.Close(link.Writer)
		}
		results <- err
	}()
	first := <-results
	// AnyTLS FIN closes a whole stream; there is no half-close. Closing either
	// direction must release it back to the library's session pool promptly.
	closeAll()
	<-results
	return first
}

type packetReader struct{ conn *uot.Conn }

func (r *packetReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	packet := sbuf.NewPacket()
	defer packet.Release()
	for {
		packet.Reset()
		destination, err := r.conn.ReadPacket(packet)
		if err != nil {
			return nil, err
		}
		if !destination.IsValid() {
			return nil, io.ErrUnexpectedEOF
		}
		// Xray's shared pipes ignore empty datagrams. Consume them here without
		// handing an unreleased empty allocation to a pipe or buf.Copy.
		if packet.IsEmpty() {
			continue
		}
		b := buf.NewWithSize(int32(packet.Len()))
		b.Write(packet.Bytes())
		dest := fromSocksaddr(destination, xnet.Network_UDP)
		b.UDP = &dest
		return buf.MultiBuffer{b}, nil
	}
}

type packetWriter struct {
	conn        *uot.Conn
	destination M.Socksaddr
}

func (w *packetWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		destination := w.destination
		if b.UDP != nil {
			destination = toSocksaddr(*b.UDP)
		}
		if b.Len() > 65535 {
			return io.ErrShortBuffer
		}
		if err := w.conn.WritePacket(sbuf.As(b.Bytes()), destination); err != nil {
			return err
		}
	}
	return nil
}
