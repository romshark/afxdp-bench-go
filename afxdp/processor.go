//go:build linux

package afxdp

import (
	"context"
	"runtime"
	"sync"
)

type Packet struct {
	Buf     []byte
	Addr    uint64
	Len     uint32
	Ingress string
	Queue   uint32
}

// RunProcessor starts listening on all RX queues of all interfaces and
// calls fn for every Packet received.
// Stops listening if ctx is canceled and returns context.Canceled.
// If fn returns an error, RunProcessor stops immediately and returns it.
// If fn returns forwardToIface > -1 then the packet is automatically forwarded
// to the interface where index=forwardToIface, otherwise the packet is dropped.
// Interface index refers to the Linux interface index, not the index in slice interfaces.
func RunProcessor(
	ctx context.Context,
	interfaces []*Interface,
	fn func(*Packet) (forwardToIface int, err error),
) error {
	if len(interfaces) == 0 {
		return nil
	}

	type worker struct {
		iface      *Interface
		ifaceName  string
		ifaceIndex int
		queue      uint32
		sock       *Socket
		batch      uint32

		// Multiple RX workers may forward packets to the same TX worker
		// (same egress iface:queue).
		txLock sync.Mutex
		txAddr []uint64
		txLen  []uint32
	}

	type byIface = map[int]map[uint32]*worker

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var workers []*worker
	socketsByIface := make(byIface)

	for _, iface := range interfaces {
		ifaceName, ifaceIndex := iface.Info()
		queues, err := iface.RXQueueIDs()
		if err != nil {
			return err
		}
		for _, qid := range queues {
			sock, err := iface.Open(SocketConfig{QueueID: qid})
			if err != nil {
				for _, w := range workers {
					_ = w.sock.Close()
				}
				return err
			}

			w := &worker{
				iface:      iface,
				ifaceName:  ifaceName,
				ifaceIndex: ifaceIndex,
				queue:      qid,
				sock:       sock,
				batch:      sock.conf.BatchSize,
				txAddr:     make([]uint64, 0, sock.conf.BatchSize),
				txLen:      make([]uint32, 0, sock.conf.BatchSize),
			}

			workers = append(workers, w)
			if socketsByIface[ifaceIndex] == nil {
				socketsByIface[ifaceIndex] = make(map[uint32]*worker)
			}
			socketsByIface[ifaceIndex][qid] = w
		}
	}

	for _, w := range workers {
		if w.batch == 0 {
			w.batch = DefaultBatchSize
		}
		if w.txAddr == nil {
			w.txAddr = make([]uint64, 0, w.batch)
			w.txLen = make([]uint32, 0, w.batch)
		}
	}

	forward := func(target *worker, data []byte) (bool, error) {
		target.txLock.Lock()
		defer target.txLock.Unlock()

		if target.sock.FreeFrames() == 0 {
			target.sock.PollCompletions(target.batch)
			// If the pool is still empty after polling completions,
			// we cannot forward this packet right now without blocking.
			// This prevents head-of-line blocking and avoids RX ring overflow
			// under sustained load, but drops the packet.
			if target.sock.FreeFrames() == 0 {
				return false, nil
			}
		}

		frame := target.sock.NextFrame()
		if len(frame.Buf) == 0 {
			return false, nil
		}

		n := copy(frame.Buf, data)
		target.txAddr = append(target.txAddr, frame.Addr)
		target.txLen = append(target.txLen, uint32(n))

		if len(target.txAddr) >= int(target.batch) {
			if _, err := target.sock.SubmitBatch(target.txAddr, target.txLen); err != nil {
				target.txAddr = target.txAddr[:0]
				target.txLen = target.txLen[:0]
				return false, err
			}
			if err := target.sock.FlushTx(); err != nil {
				target.txAddr = target.txAddr[:0]
				target.txLen = target.txLen[:0]
				return false, err
			}
			target.txAddr = target.txAddr[:0]
			target.txLen = target.txLen[:0]
		}

		return true, nil
	}

	flushPending := func(target *worker) error {
		target.txLock.Lock()
		defer target.txLock.Unlock()
		if len(target.txAddr) == 0 {
			return nil
		}
		if _, err := target.sock.SubmitBatch(target.txAddr, target.txLen); err != nil {
			target.txAddr = target.txAddr[:0]
			target.txLen = target.txLen[:0]
			return err
		}
		if err := target.sock.FlushTx(); err != nil {
			target.txAddr = target.txAddr[:0]
			target.txLen = target.txLen[:0]
			return err
		}
		target.txAddr = target.txAddr[:0]
		target.txLen = target.txLen[:0]
		return nil
	}

	errCh := make(chan error, len(workers))
	var wg sync.WaitGroup
	wg.Add(len(workers))

	for _, w := range workers {
		w := w
		go func() {
			defer wg.Done()
			defer w.sock.Close()

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			rxBuf := make([]Frame, w.batch)
			releaseBuf := make([]Frame, 0, w.batch)
			usedTargets := make(map[*worker]struct{})

			var p Packet

			for ctx.Err() == nil {
				frames := w.sock.Receive(rxBuf)
				if len(frames) == 0 {
					if err := w.sock.Wait(1); err != nil {
						errCh <- err
						return
					}
					continue
				}

				releaseBuf = releaseBuf[:0]
				for k := range usedTargets {
					delete(usedTargets, k)
				}

				for _, fr := range frames {
					p.Buf = fr.Buf
					p.Addr = fr.Addr
					p.Len = uint32(len(fr.Buf))
					p.Ingress = w.ifaceName
					p.Queue = w.queue

					fwdIdx, err := fn(&p)
					if err != nil {
						errCh <- err
						return
					}

					if fwdIdx >= 0 {
						if ifaceTargets := socketsByIface[fwdIdx]; ifaceTargets != nil {
							if tgt := ifaceTargets[w.queue]; tgt != nil {
								ok, err := forward(tgt, fr.Buf)
								if err != nil {
									errCh <- err
									return
								}
								if ok {
									usedTargets[tgt] = struct{}{}
									releaseBuf = append(releaseBuf, fr)
									continue
								}
							}
						}
					}

					releaseBuf = append(releaseBuf, fr)
				}

				if len(releaseBuf) > 0 {
					w.sock.ReleaseBatch(releaseBuf)
				}

				for tgt := range usedTargets {
					if err := flushPending(tgt); err != nil {
						errCh <- err
						return
					}
				}
			}

			for tgt := range usedTargets {
				_ = flushPending(tgt)
			}
		}()
	}

	select {
	case err := <-errCh:
		cancel()
		wg.Wait()
		return err
	case <-ctx.Done():
		cancel()
		wg.Wait()
		return context.Canceled
	}
}
