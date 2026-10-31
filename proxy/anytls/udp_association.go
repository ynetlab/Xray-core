package anytls

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

const (
	udpMaxTargets        = 64
	udpTargetQueueSize   = 16
	udpTargetIdleTimeout = time.Minute
)

type udpTarget struct {
	ctx         context.Context
	cancel      context.CancelFunc
	link        *transport.Link
	destination xnet.Destination
	packets     chan buf.MultiBuffer
	created     time.Time
	activity    atomic.Int64
	// Only the association manager accesses these fields and the target map.
	closing bool
	workers int
}

func (t *udpTarget) Update() { t.activity.Store(int64(time.Since(t.created))) }

func (t *udpTarget) close() {
	if t.closing {
		return
	}
	t.closing = true
	t.cancel()
	common.Interrupt(t.link.Reader)
	common.Interrupt(t.link.Writer)
}

func (t *udpTarget) drain() {
	for {
		select {
		case mb := <-t.packets:
			buf.ReleaseMulti(mb)
		default:
			return
		}
	}
}

type udpReply struct {
	target *udpTarget
	mb     buf.MultiBuffer
}

// A target worker never writes directly to the shared UoT stream. A slow client
// must not prevent idle target cancellation or keep a target worker alive.
type udpReplyWriter struct {
	target  *udpTarget
	replies chan<- udpReply
}

func (w *udpReplyWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	select {
	case <-w.target.ctx.Done():
		buf.ReleaseMulti(mb)
		return w.target.ctx.Err()
	case w.replies <- udpReply{target: w.target, mb: mb}:
		return nil
	}
}

// runUDPAssociation is the sole owner of target membership and link shutdown.
// Workers report completion through a channel; retiring targets count toward
// the limit until both workers have exited. Overflow datagrams are dropped,
// keeping existing destinations usable without unbounded queues or goroutines.
func runUDPAssociation(parent context.Context, conn net.Conn, packetConn *uot.Conn, p policy.Session,
	dispatch func(context.Context, xnet.Destination) (*transport.Link, error), idle time.Duration, maxTargets int,
) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { conn.Close() }) }
	stop := context.AfterFunc(ctx, closeConn)
	defer stop()
	targets := make(map[xnet.Destination]*udpTarget)
	incoming := make(chan buf.MultiBuffer)
	failures := make(chan error, 2)
	completed := make(chan *udpTarget, 2*maxTargets)
	replies := make(chan udpReply, udpTargetQueueSize)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		closeConn()
		for _, target := range targets {
			target.close()
		}
		workers.Wait()
		for _, target := range targets {
			target.drain()
		}
		for {
			select {
			case reply := <-replies:
				buf.ReleaseMulti(reply.mb)
			default:
				return
			}
		}
	}()

	workers.Add(2)
	go func() {
		defer workers.Done()
		reader := &packetReader{conn: packetConn}
		for {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(mb)
				failures <- err
				return
			}
			select {
			case incoming <- mb:
			case <-ctx.Done():
				buf.ReleaseMulti(mb)
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case reply := <-replies:
				writer := &packetWriter{conn: packetConn, destination: toSocksaddr(reply.target.destination)}
				if err := writer.WriteMultiBuffer(reply.mb); err != nil {
					failures <- err
					return
				}
			}
		}
	}()

	workerDone := func(target *udpTarget) {
		defer workers.Done()
		select {
		case completed <- target:
		case <-ctx.Done():
		}
	}
	ticker := time.NewTicker(idle / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failures:
			return err
		case target := <-completed:
			target.close()
			target.workers--
			if target.workers == 0 {
				delete(targets, target.destination)
				target.drain()
			}
		case <-ticker.C:
			for _, target := range targets {
				if time.Since(target.created)-time.Duration(target.activity.Load()) >= idle {
					target.close()
				}
			}
		case mb := <-incoming:
			destination := *mb[0].UDP
			if !destination.IsValid() {
				buf.ReleaseMulti(mb)
				return io.ErrUnexpectedEOF
			}
			timer.Update()
			target := targets[destination]
			if target == nil {
				if len(targets) >= maxTargets || ctx.Err() != nil {
					buf.ReleaseMulti(mb)
					continue
				}
				targetCtx, targetCancel := context.WithCancel(streamContext(ctx))
				link, err := dispatch(targetCtx, destination)
				if err != nil {
					targetCancel()
					buf.ReleaseMulti(mb)
					continue
				}
				target = &udpTarget{ctx: targetCtx, cancel: targetCancel, link: link, destination: destination,
					packets: make(chan buf.MultiBuffer, udpTargetQueueSize), created: time.Now(), workers: 2}
				targets[destination] = target
				workers.Add(2)
				go func(target *udpTarget) {
					defer workerDone(target)
					_ = buf.Copy(target.link.Reader, &udpReplyWriter{target: target, replies: replies},
						buf.UpdateActivity(target), buf.UpdateActivity(timer))
				}(target)
				go func(target *udpTarget) {
					defer workerDone(target)
					for {
						select {
						case <-target.ctx.Done():
							return
						case packet := <-target.packets:
							if target.ctx.Err() != nil {
								buf.ReleaseMulti(packet)
								return
							}
							if err := target.link.Writer.WriteMultiBuffer(packet); err != nil {
								return
							}
						}
					}
				}(target)
			}
			if target.closing {
				buf.ReleaseMulti(mb)
				continue
			}
			select {
			case target.packets <- mb:
				target.Update()
			default:
				buf.ReleaseMulti(mb)
			}
		}
	}
}
