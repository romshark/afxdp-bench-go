//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	afxdp "github.com/romshark/afxdp-bench-go/afxdp"
)

func main() {
	fIface := flag.String("i", "", "Interface")
	fZeroCopy := flag.Bool("z", false, "Use zerocopy")
	flag.Parse()

	if *fIface == "" {
		fmt.Fprint(os.Stderr, "missing -i interface\n")
		os.Exit(1)
	}

	iface, err := afxdp.MakeInterface(*fIface, afxdp.InterfaceConfig{
		PreferZerocopy: *fZeroCopy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "initializing interface: %v\n", err)
		os.Exit(1)
	}

	queues, err := iface.RXQueueIDs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "listing queue ids: %v\n", err)
		os.Exit(1)
	}
	if len(queues) == 0 {
		fmt.Fprintf(os.Stderr, "no RX queues found for %s\n", *fIface)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr,
		"AF_XDP RX: iface=%s use_zerocopy=%t queues=%v\n",
		*fIface, *fZeroCopy, queues,
	)

	var totalPackets atomic.Uint64
	var totalBytes atomic.Uint64

	// Start 1 socket per queue, each in a separate goroutine bound to its thread.
	waitTimeoutMS := int((100 * time.Millisecond).Milliseconds())
	for _, qid := range queues {
		go func(queueID uint32) {
			runtime.LockOSThread()
			sock, err := iface.Open(afxdp.SocketConfig{
				QueueID: queueID,
			})
			if err != nil {
				panic(fmt.Sprintf("queue %d: %v", queueID, err))
			}
			defer sock.Close()
			fmt.Fprintf(os.Stderr, "socket %p on queue %d (zerocopy=%t)\n",
				sock, qid, sock.IsZerocopy())

			bufFrames := make([]afxdp.Frame, 64)

			for {
				frames := sock.Receive(bufFrames)
				if len(frames) == 0 {
					if err := sock.Wait(waitTimeoutMS); err != nil {
						panic(err)
					}
					continue
				}

				for _, frame := range frames {
					totalPackets.Add(1)
					totalBytes.Add(uint64(len(frame.Buf)))
					if err := sock.Release(frame); err != nil {
						panic(err)
					}
				}
			}
		}(qid)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var (
		lastPackets uint64
		lastBytes   uint64
		maxPPS      float64
		maxMbps     float64
	)

	lastTime := time.Now()

	for range ticker.C {
		now := time.Now()
		elapsed := now.Sub(lastTime).Seconds()

		pkts := totalPackets.Load()
		bytes := totalBytes.Load()

		curPkts := pkts - lastPackets
		curBytes := bytes - lastBytes

		pps := float64(curPkts) / elapsed
		mbps := float64(curBytes*8) / elapsed / 1e6

		if pps > maxPPS {
			maxPPS = pps
		}
		if mbps > maxMbps {
			maxMbps = mbps
		}

		fmt.Printf(
			"total=%d | cur=%.0f pps %.2f Mbit/s | max=%.0f pps %.2f Mbit/s\n",
			pkts,
			pps,
			mbps,
			maxPPS,
			maxMbps,
		)

		lastPackets = pkts
		lastBytes = bytes
		lastTime = now
	}
}
