package anytls

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/uuidroute"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type udpCountReader struct {
	*pipe.Reader
	interrupts atomic.Int32
}

func (r *udpCountReader) Interrupt() { r.interrupts.Add(1); r.Reader.Interrupt() }

type udpCountWriter struct {
	*pipe.Writer
	interrupts atomic.Int32
}

func (w *udpCountWriter) Interrupt() { w.interrupts.Add(1); w.Writer.Interrupt() }

type udpTestTarget struct {
	ctx         context.Context
	destination xnet.Destination
	up          *pipe.Reader
	down        *pipe.Writer
	reader      *udpCountReader
	writer      *udpCountWriter
}

type udpAssociationTest struct {
	t       *testing.T
	client  *uot.Conn
	cancel  context.CancelFunc
	done    chan error
	created chan *udpTestTarget
	mu      sync.Mutex
	targets []*udpTestTarget
}

type udpTestDispatcher struct {
	routing.Dispatcher
	dispatch func(context.Context, xnet.Destination) (*transport.Link, error)
}

func (d udpTestDispatcher) Dispatch(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
	return d.dispatch(ctx, destination)
}

func newUDPAssociationTest(t *testing.T, connected bool, idle time.Duration, limit int, useAdapter bool) *udpAssociationTest {
	t.Helper()
	server, client := net.Pipe()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	ctx = session.ContextWithContent(ctx, &session.Content{Attributes: map[string]string{"test": "parent"}})
	request := uot.Request{IsConnect: connected, Destination: M.ParseSocksaddr("192.0.2.1:53")}
	f := &udpAssociationTest{t: t, client: uot.NewConn(client, request), cancel: cancel,
		done: make(chan error, 1), created: make(chan *udpTestTarget, 128)}
	dispatch := func(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
		up, writer := pipe.New(pipe.WithSizeLimit(0))
		reader, down := pipe.New(pipe.WithSizeLimit(0))
		target := &udpTestTarget{ctx: ctx, destination: destination, up: up, down: down,
			reader: &udpCountReader{Reader: reader}, writer: &udpCountWriter{Writer: writer}}
		f.mu.Lock()
		f.targets = append(f.targets, target)
		f.mu.Unlock()
		f.created <- target
		return &transport.Link{Reader: target.reader, Writer: target.writer}, nil
	}
	go func() {
		if useAdapter {
			h := &inboundAdapter{dispatcher: udpTestDispatcher{dispatch: dispatch}, conn: server,
				match: uuidroute.Match{User: &protocol.MemoryUser{Email: "udp@example.com"}}}
			f.done <- h.dispatchPackets(ctx, server, uot.NewConn(server, request), policy.SessionDefault())
			return
		}
		f.done <- runUDPAssociation(ctx, server, uot.NewConn(server, request), policy.SessionDefault(), dispatch, idle, limit)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		select {
		case <-f.done:
		case <-time.After(3 * time.Second):
			t.Error("association did not join all workers")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, target := range f.targets {
			if target.ctx.Err() == nil || target.reader.interrupts.Load() != 1 || target.writer.interrupts.Load() != 1 {
				t.Errorf("target %v not released exactly once: ctx=%v reader=%d writer=%d", target.destination,
					target.ctx.Err(), target.reader.interrupts.Load(), target.writer.interrupts.Load())
			}
		}
	})
	return f
}

func (f *udpAssociationTest) send(destination M.Socksaddr, payload []byte) {
	f.t.Helper()
	if err := f.client.WritePacket(sbuf.As(payload), destination); err != nil {
		f.t.Fatal("write UoT packet:", err)
	}
}

func (f *udpAssociationTest) nextTarget() *udpTestTarget {
	f.t.Helper()
	select {
	case target := <-f.created:
		return target
	case <-time.After(2 * time.Second):
		f.t.Fatal("dispatcher target was not created")
		return nil
	}
}

func (f *udpAssociationTest) readUp(target *udpTestTarget, want []byte) {
	f.t.Helper()
	mb, err := target.up.ReadMultiBufferTimeout(2 * time.Second)
	defer buf.ReleaseMulti(mb)
	if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), want) || *mb[0].UDP != target.destination {
		f.t.Fatalf("uplink datagram differs: buffers=%d error=%v", len(mb), err)
	}
}

func (f *udpAssociationTest) receive(destination M.Socksaddr, want []byte) {
	f.t.Helper()
	packet := sbuf.NewPacket()
	defer packet.Release()
	source, err := f.client.ReadPacket(packet)
	if err != nil || source != destination || !bytes.Equal(packet.Bytes(), want) {
		f.t.Fatalf("downlink datagram differs: source=%v want=%v size=%d error=%v", source, destination, packet.Len(), err)
	}
}

func udpTestPacket(payload []byte) buf.MultiBuffer {
	b := buf.NewWithSize(int32(len(payload)))
	b.Write(payload)
	return buf.MultiBuffer{b}
}

func waitUDPContext(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("target context was not canceled")
	}
}

func TestUDPAssociationWorkerIsolation(t *testing.T) {
	for _, direction := range []string{"downlink", "uplink"} {
		t.Run(direction, func(t *testing.T) {
			f := newUDPAssociationTest(t, false, time.Minute, 4, true)
			a, b := M.ParseSocksaddr("192.0.2.1:53"), M.ParseSocksaddr("example.com:123")
			f.send(a, []byte("a"))
			first := f.nextTarget()
			f.readUp(first, []byte("a"))
			f.send(b, []byte("b"))
			second := f.nextTarget()
			f.readUp(second, []byte("b"))
			if direction == "downlink" {
				first.down.Close()
			} else {
				first.up.Interrupt()
				f.send(a, []byte("fail-write"))
			}
			waitUDPContext(t, first.ctx)
			if second.ctx.Err() != nil {
				t.Fatal("one target canceled another target")
			}
			f.send(b, []byte("still-alive"))
			f.readUp(second, []byte("still-alive"))
			if err := second.down.WriteMultiBuffer(udpTestPacket([]byte("reply"))); err != nil {
				t.Fatal(err)
			}
			f.receive(b, []byte("reply"))
			// Repeated datagrams also exercise completion racing with redispatch.
			deadline := time.Now().Add(2 * time.Second)
			for {
				f.send(a, []byte("reopen"))
				select {
				case replacement := <-f.created:
					if replacement == first || replacement.destination != first.destination {
						t.Fatal("wrong replacement link")
					}
					return
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("exited target remained cached")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestUDPAssociationConcurrentDatagrams(t *testing.T) {
	for _, connected := range []bool{true, false} {
		t.Run(fmt.Sprint("connect=", connected), func(t *testing.T) {
			f := newUDPAssociationTest(t, connected, time.Minute, 4, true)
			destinations := []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:53")}
			if !connected {
				destinations = append(destinations, M.ParseSocksaddr("[2001:db8::1]:53"), M.ParseSocksaddr("example.com:53"))
			}
			targets := make([]*udpTestTarget, len(destinations))
			for i, destination := range destinations {
				f.send(destination, []byte("start"))
				targets[i] = f.nextTarget()
				f.readUp(targets[i], []byte("start"))
			}
			// All target workers read and reply concurrently through one UoT stream.
			var echoes sync.WaitGroup
			for _, target := range targets {
				echoes.Add(1)
				go func(target *udpTestTarget) {
					defer echoes.Done()
					for {
						mb, err := target.up.ReadMultiBuffer()
						if err != nil {
							buf.ReleaseMulti(mb)
							return
						}
						if err := target.down.WriteMultiBuffer(mb); err != nil {
							return
						}
					}
				}(target)
			}
			defer func() { f.cancel(); echoes.Wait() }()
			for _, size := range []int{1, 1200, 8000, 16000} {
				for i, destination := range destinations {
					f.send(destination, bytes.Repeat([]byte{byte(i + 1)}, size))
				}
				seen := make(map[M.Socksaddr]bool)
				for range destinations {
					packet := sbuf.NewSize(65535)
					source, err := f.client.ReadPacket(packet)
					index := -1
					for i, destination := range destinations {
						if destination == source {
							index = i
						}
					}
					ok := index >= 0 && !seen[source] && bytes.Equal(packet.Bytes(), bytes.Repeat([]byte{byte(index + 1)}, size))
					packet.Release()
					if err != nil || !ok {
						t.Fatalf("concurrent datagram corrupted: source=%v size=%d error=%v", source, size, err)
					}
					seen[source] = true
				}
			}
		})
	}
}

func TestUDPAssociationIdleAndLimit(t *testing.T) {
	f := newUDPAssociationTest(t, false, 120*time.Millisecond, 2, false)
	a, b, c := M.ParseSocksaddr("192.0.2.1:1"), M.ParseSocksaddr("192.0.2.1:2"), M.ParseSocksaddr("192.0.2.1:3")
	f.send(a, []byte("idle"))
	first := f.nextTarget()
	f.readUp(first, []byte("idle"))
	f.send(b, []byte("active"))
	second := f.nextTarget()
	f.readUp(second, []byte("active"))
	for i := 0; i < 15; i++ {
		f.send(c, []byte("over-limit"))
		f.send(b, []byte("keep-alive"))
		f.readUp(second, []byte("keep-alive"))
		if first.ctx.Err() != nil {
			break
		}
		select {
		case <-f.created:
			t.Fatal("target limit exceeded")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitUDPContext(t, first.ctx)
	if second.ctx.Err() != nil {
		t.Fatal("active target was reaped")
	}
	deadline := time.Now().Add(time.Second)
	for {
		f.send(c, []byte("new-target"))
		select {
		case target := <-f.created:
			if target.destination != fromSocksaddr(c, xnet.Network_UDP) {
				t.Fatal("wrong target after idle eviction")
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("idle target did not release capacity")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUDPAssociationBlockedIOShutdown(t *testing.T) {
	f := newUDPAssociationTest(t, false, time.Minute, 2, false)
	a, b := M.ParseSocksaddr("192.0.2.1:1"), M.ParseSocksaddr("192.0.2.1:2")
	f.send(a, []byte("blocked"))
	first := f.nextTarget()
	// No consumer for A: its pipe, worker and bounded queue fill up.
	for i := 0; i < 100; i++ {
		f.send(a, []byte("queued"))
	}
	f.send(b, []byte("healthy"))
	second := f.nextTarget()
	f.readUp(second, []byte("healthy"))
	// No UoT reader: fill shared replies and block downlink delivery as well.
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		for {
			if err := first.down.WriteMultiBuffer(udpTestPacket([]byte("blocked-reply"))); err != nil {
				return
			}
		}
	}()
	<-started
	t.Cleanup(func() {
		f.cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("blocked backend writer leaked")
		}
	})
	// Cleanup cancels with both directions blocked, joins workers, and checks
	// every link endpoint is interrupted exactly once.
}

func TestUDPAssociationDownlinkActivityAndContexts(t *testing.T) {
	f := newUDPAssociationTest(t, false, 150*time.Millisecond, 2, false)
	a, b := M.ParseSocksaddr("192.0.2.1:1"), M.ParseSocksaddr("192.0.2.1:2")
	f.send(a, []byte("a"))
	first := f.nextTarget()
	f.readUp(first, []byte("a"))
	f.send(b, []byte("b"))
	second := f.nextTarget()
	f.readUp(second, []byte("b"))
	content := session.ContentFromContext(first.ctx)
	content.Attributes["test"] = "first"
	if session.ContentFromContext(second.ctx).Attributes["test"] != "parent" ||
		session.InboundFromContext(first.ctx) == session.InboundFromContext(second.ctx) ||
		session.OutboundsFromContext(first.ctx)[0] == session.OutboundsFromContext(second.ctx)[0] {
		t.Fatal("targets share mutable routing context")
	}
	for i := 0; i < 10; i++ {
		if err := first.down.WriteMultiBuffer(udpTestPacket([]byte("downlink-only"))); err != nil {
			t.Fatal(err)
		}
		f.receive(a, []byte("downlink-only"))
		time.Sleep(30 * time.Millisecond)
	}
	if first.ctx.Err() != nil {
		t.Fatal("downlink traffic did not refresh target activity")
	}
	waitUDPContext(t, second.ctx)
}

func TestUDPAssociationPeerClose(t *testing.T) {
	f := newUDPAssociationTest(t, false, time.Minute, 2, true)
	f.send(M.ParseSocksaddr("192.0.2.1:1"), []byte("open"))
	target := f.nextTarget()
	f.client.Close()
	waitUDPContext(t, target.ctx)
}

func TestUDPAssociationFinalDownlinkPacket(t *testing.T) {
	f := newUDPAssociationTest(t, false, time.Minute, 2, true)
	destination := M.ParseSocksaddr("example.com:53")
	f.send(destination, []byte("open"))
	target := f.nextTarget()
	f.readUp(target, []byte("open"))
	if err := target.down.WriteMultiBuffer(udpTestPacket([]byte("last-reply"))); err != nil {
		t.Fatal(err)
	}
	target.down.Close()
	f.receive(destination, []byte("last-reply"))
	waitUDPContext(t, target.ctx)
}
