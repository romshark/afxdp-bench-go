//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	afxdp "github.com/romshark/afxdp-bench-go/afxdp"
	"github.com/romshark/afxdp-bench-go/ifacestat"
	"github.com/romshark/afxdp-bench-go/ratelimit"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v3"
)

// Topology:
//
// sender.interface  <->  router.interface1
// router.interface2 <->  receiver.interface
//
// Router:
//   dst IP 10.0.1.x -> out interface1
//   dst IP 10.0.2.x -> out interface2
//   else            -> drop

type Config struct {
	Router struct {
		Interface1     string `yaml:"interface1"`
		Interface2     string `yaml:"interface2"`
		PreferZerocopy bool   `yaml:"prefer-zerocopy"`
		BatchSize      uint32 `yaml:"batch-size"`
	} `yaml:"router"`

	Sender struct {
		Interface      string `yaml:"interface"`
		PreferZerocopy bool   `yaml:"prefer-zerocopy"`
		Queue          uint   `yaml:"queue"`

		DestMAC   string `yaml:"dest-mac"` // MAC of router.interface1
		SrcIP     string `yaml:"src-ip"`
		DstIP     string `yaml:"dst-ip"`
		SrcPort   uint16 `yaml:"src-port"`
		DstPort   uint16 `yaml:"dst-port"`
		BatchSize uint32 `yaml:"batch-size"`
		RatePPS   uint64 `yaml:"rate-pps"` // 0 = unlimited, max speed.
	} `yaml:"sender"`

	Receiver struct {
		Interface      string `yaml:"interface"`
		PreferZerocopy bool   `yaml:"prefer-zerocopy"`
		BatchSize      uint32 `yaml:"batch-size"`
	} `yaml:"receiver"`

	MTU   uint32 `yaml:"mtu"`
	Count uint64 `yaml:"count"`
	Test  bool   `yaml:"test"`
}

func loadConfig() (*Config, error) {
	fConfig := flag.String("config", "route.yaml", "path to config YAML file")
	fMode := flag.String("m", "", "overwrite copy/zc mode for all interfaces")
	fRate := flag.Int64("r", -1, "sender rate limit in PPS (<0 falls back to config)")
	fCount := flag.Uint64("n", 0, "packet count override")
	fMTU := flag.Uint("l", 0, "pkt size override (MTU)")
	fTest := flag.Bool("test", false, "enable test mode (override)")
	flag.Parse()

	b, err := os.ReadFile(*fConfig)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var conf Config
	if err := yaml.Unmarshal(b, &conf); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	switch *fMode {
	case "copy":
		conf.Sender.PreferZerocopy, conf.Receiver.PreferZerocopy = false, false
	case "zerocopy":
		conf.Sender.PreferZerocopy, conf.Receiver.PreferZerocopy = true, true
	}
	if *fRate >= 0 {
		conf.Sender.RatePPS = uint64(*fRate)
	}
	if *fCount != 0 {
		conf.Count = *fCount
	}
	if *fMTU != 0 {
		conf.MTU = uint32(*fMTU)
	}
	if *fTest {
		conf.Test = true
	}

	// Basic validation
	if conf.Router.Interface1 == "" || conf.Router.Interface2 == "" {
		return nil, errors.New("router.interface1 and router.interface2 must be set")
	}
	if conf.Sender.Interface == "" {
		return nil, errors.New("sender.interface must be set")
	}
	if conf.Receiver.Interface == "" {
		return nil, errors.New("receiver.interface must be set")
	}
	if conf.Sender.DestMAC == "" {
		return nil, errors.New("sender.dest-mac must be set (MAC of router.interface1)")
	}
	if _, err := net.ParseMAC(conf.Sender.DestMAC); err != nil {
		return nil, fmt.Errorf("invalid sender.dest-mac %q: %w", conf.Sender.DestMAC, err)
	}
	if conf.Sender.SrcIP == "" || net.ParseIP(conf.Sender.SrcIP) == nil {
		return nil, fmt.Errorf("invalid sender.src-ip %q", conf.Sender.SrcIP)
	}
	if conf.Sender.DstIP == "" || net.ParseIP(conf.Sender.DstIP) == nil {
		return nil, fmt.Errorf("invalid sender.dst-ip %q", conf.Sender.DstIP)
	}
	if conf.Count == 0 {
		return nil, errors.New("count must be > 0")
	}
	if conf.MTU < 64 || conf.MTU > 1500 {
		return nil, errors.New("unsupported mtu")
	}
	if conf.Router.BatchSize == 0 {
		conf.Router.BatchSize = 64
	}
	if conf.Sender.BatchSize == 0 {
		conf.Sender.BatchSize = 64
	}
	if conf.Receiver.BatchSize == 0 {
		conf.Receiver.BatchSize = 64
	}

	return &conf, nil
}

func fatalIf(err error, msgf string, a ...any) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msgf+": %v\n", append(a, err)...)
		os.Exit(1)
	}
}

func mustGetIfaceInfo(name string) (idx int, mac [6]byte) {
	iface, err := net.InterfaceByName(name)
	fatalIf(err, "getting interface %q", name)
	copy(mac[:], iface.HardwareAddr)
	return iface.Index, mac
}

func ipChecksum(buf []byte) uint16 {
	var sum uint32
	for len(buf) > 1 {
		sum += uint32(binary.BigEndian.Uint16(buf))
		buf = buf[2:]
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildUDPPacket(
	buf []byte,
	srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seq uint32,
	pktSize uint32,
) uint32 {

	const ethLen = 14
	const ipLen = 20
	const udpLen = 8

	minSize := uint32(ethLen + ipLen + udpLen + 4)
	if pktSize < minSize {
		pktSize = minSize
	}

	payloadLen := pktSize - (ethLen + ipLen + udpLen)

	copy(buf[0:6], dstMAC)
	copy(buf[6:12], srcMAC)
	buf[12], buf[13] = 0x08, 0x00

	ip := buf[ethLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(ipLen+udpLen+payloadLen))
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip[:20]))

	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen+payloadLen))

	payload := udp[8:]
	binary.BigEndian.PutUint32(payload, seq)

	return pktSize
}

type Stats struct {
	TxPackets   atomic.Uint64
	TxCompleted atomic.Uint64
	TxBytes     atomic.Uint64

	RxPackets atomic.Uint64
	RxBytes   atomic.Uint64

	Elapsed atomic.Int64
}

type TestResult struct {
	Received atomic.Uint64
	Errors   atomic.Uint64
}

// makeRouterHandler builds the router callback:
//   - 10.0.1.x -> out interface1
//   - 10.0.2.x -> out interface2
//   - else     -> drop
//
// Additionally, for packets going to 10.0.2.x, it rewrites L2 MACs:
//
//	dstMAC = receiverMAC
//	srcMAC = router2MAC
func makeRouterHandler(
	if1Index, if2Index int, router2MAC, receiverMAC [6]byte,
) func(*afxdp.Packet) (int, error) {
	const (
		EthHdrLen = 14
		IPHdrMin  = 20
	)

	return func(p *afxdp.Packet) (int, error) {
		buf := p.Buf

		// Fast path: single bounds check
		if len(buf) < EthHdrLen+IPHdrMin {
			return -1, nil
		}

		// EtherType (big-endian uint16)
		ethType := binary.BigEndian.Uint16(buf[12:14])
		if ethType != 0x0800 { // IPv4
			return -1, nil
		}

		ip := buf[EthHdrLen:]

		// IPv4 version check (header length ignored since you don't route TCP options)
		if ip[0]>>4 != 4 {
			return -1, nil
		}

		// Destination IP (fast uint32 load)
		dst := binary.BigEndian.Uint32(ip[16:20])

		// Match 10.0.X.X using mask
		if (dst & 0xFFFF0000) != 0x0A000000 {
			return -1, nil
		}

		third := byte(dst >> 8) // dst[2]

		switch third {
		case 1:
			// -> out interface1
			return if1Index, nil

		case 2:
			// -> out interface2 (MAC rewrite)
			copy(buf[0:6], receiverMAC[:])
			copy(buf[6:12], router2MAC[:])
			return if2Index, nil
		}

		return -1, nil
	}
}

// runRouter starts the router processor.
func runRouter(ctx context.Context, conf *Config, router2MAC, receiverMAC [6]byte) error {
	iface1, err := afxdp.MakeInterface(conf.Router.Interface1,
		afxdp.InterfaceConfig{PreferZerocopy: conf.Router.PreferZerocopy})
	if err != nil {
		return fmt.Errorf("router iface1: %w", err)
	}
	defer iface1.Close()

	iface2, err := afxdp.MakeInterface(conf.Router.Interface2,
		afxdp.InterfaceConfig{PreferZerocopy: conf.Router.PreferZerocopy})
	if err != nil {
		return fmt.Errorf("router iface2: %w", err)
	}
	defer iface2.Close()

	_, if1Index := iface1.Info()
	_, if2Index := iface2.Info()

	handler := makeRouterHandler(if1Index, if2Index, router2MAC, receiverMAC)

	return afxdp.RunProcessor(ctx, []*afxdp.Interface{iface1, iface2}, handler)
}

// ----- Sender / Receiver (edge) -----

type SenderConfig struct {
	Iface   string
	DstMAC  string
	SrcIP   string
	DstIP   string
	SrcPort uint16
	Port    uint16
	Count   uint64
	PktSize uint32
	Queue   uint
	ZC      bool
	RatePPS uint64
}

func runSender(
	iface *afxdp.Interface,
	conf *SenderConfig,
	stats *Stats,
	batchSize uint32,
) {
	// Not locking the sender seems to reduce packet loss.
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	_, srcMAC := mustGetIfaceInfo(conf.Iface)
	dstMAC, err := net.ParseMAC(conf.DstMAC)
	fatalIf(err, "parse sender dst mac")

	srcIP := net.ParseIP(conf.SrcIP).To4()
	dstIP := net.ParseIP(conf.DstIP).To4()

	sock, err := iface.Open(afxdp.SocketConfig{
		QueueID:   uint32(conf.Queue),
		NumFrames: 1024 * 16,
		RxSize:    1024 * 2,
		TxSize:    1024 * 2,
		CqSize:    1024 * 2,
		BatchSize: batchSize,
	})
	fatalIf(err, "open TX socket")
	defer sock.Close()

	ifaceName, _ := iface.Info()
	fmt.Fprintf(os.Stderr, "TX on %s:%d (zerocopy=%t)\n",
		ifaceName, conf.Queue, sock.IsZerocopy())

	addrs := make([]uint64, 0, batchSize)
	lens := make([]uint32, 0, batchSize)
	var seq uint32

	limiter := ratelimit.New(conf.RatePPS)
	start := time.Now()

	for stats.TxPackets.Load() < conf.Count {

		for {
			if sock.TxFree() > 0 && sock.FreeFrames() > 0 {
				break
			}
			if c := sock.PollCompletions(batchSize); c > 0 {
				stats.TxCompleted.Add(uint64(c))
			} else {
				fatalIf(sock.Wait(1), "TX wait")
			}
		}

		sendable := min(sock.TxFree(), sock.FreeFrames(), batchSize)
		remaining := conf.Count - stats.TxPackets.Load()
		if uint64(sendable) > remaining {
			sendable = uint32(remaining)
		}

		addrs = addrs[:0]
		lens = lens[:0]

		limiter.ThrottleN(uint64(sendable)) // No-op if unlimited.

		for range sendable {
			f := sock.NextFrame()

			plen := buildUDPPacket(
				f.Buf, srcMAC[:], dstMAC, srcIP, dstIP,
				conf.SrcPort, conf.Port, seq, conf.PktSize,
			)

			addrs = append(addrs, f.Addr)
			lens = append(lens, plen)

			stats.TxPackets.Add(1)
			stats.TxBytes.Add(uint64(plen))

			seq++
		}

		n, err := sock.SubmitBatch(addrs, lens)
		fatalIf(err, "submit batch")

		fatalIf(sock.FlushTx(), "flush tx")

		if c := sock.PollCompletions(uint32(n)); c > 0 {
			stats.TxCompleted.Add(uint64(c))
		}
	}

	for stats.TxCompleted.Load() < stats.TxPackets.Load() {
		if c := sock.PollCompletions(batchSize); c > 0 {
			stats.TxCompleted.Add(uint64(c))
		} else {
			fatalIf(sock.Wait(1), "final TX wait")
		}
	}

	stats.Elapsed.Store(time.Since(start).Nanoseconds())
}

func runReceiverBenchmark(
	ctx context.Context,
	iface *afxdp.Interface,
	stats *Stats,
	batch uint32,
) *sync.WaitGroup {
	qs, err := iface.RXQueueIDs()
	fatalIf(err, "listing RX queues")
	if len(qs) == 0 {
		panic("no RX queues on receiver")
	}

	ifaceName, _ := iface.Info()

	var done sync.WaitGroup
	var wgReady sync.WaitGroup
	wgReady.Add(len(qs))

	for _, qid := range qs {
		q := qid
		done.Go(func() {
			// Not locking the receiver seems to reduce packet loss.
			// runtime.LockOSThread()
			// defer runtime.UnlockOSThread()

			sock, err := iface.Open(afxdp.SocketConfig{
				QueueID:   q,
				NumFrames: 1024 * 16,
				RxSize:    1024 * 2,
				TxSize:    1024 * 2,
				CqSize:    1024 * 2,
				BatchSize: batch,
			})
			fatalIf(err, "opening RX socket")
			defer sock.Close()

			fmt.Fprintf(os.Stderr, "RX on %s:%d (zerocopy=%t)\n",
				ifaceName, q, sock.IsZerocopy())
			wgReady.Done()

			batchBuf := make([]afxdp.Frame, batch)

			for ctx.Err() == nil {
				frames := sock.Receive(batchBuf)
				if len(frames) == 0 {
					fatalIf(sock.Wait(1), "RX wait")
					continue
				}

				for _, fr := range frames {
					stats.RxBytes.Add(uint64(len(fr.Buf)))
				}
				stats.RxPackets.Add(uint64(len(frames)))

				sock.ReleaseBatch(frames)
			}
		})
	}

	wgReady.Wait()
	return &done
}

// Test receiver: verify ordered seq and integrity on final interface.
func runReceiverTest(
	ctx context.Context,
	iface *afxdp.Interface,
	conf *Config,
	routerMAC, recvMAC [6]byte,
	result *TestResult,
	stats *Stats,
) *sync.WaitGroup {
	qs, err := iface.RXQueueIDs()
	fatalIf(err, "listing RX queues")
	if len(qs) == 0 {
		panic("no RX queues on receiver")
	}

	ifaceName, _ := iface.Info()
	expectedCount := conf.Count

	dstMAC := recvMAC
	srcMAC := routerMAC

	etherTypeIPv4 := []byte{0x08, 0x00}
	srcIP := net.ParseIP(conf.Sender.SrcIP).To4()
	dstIP := net.ParseIP(conf.Sender.DstIP).To4()
	srcPort := conf.Sender.SrcPort
	dstPort := conf.Sender.DstPort

	var done sync.WaitGroup
	var wgReady sync.WaitGroup
	wgReady.Add(len(qs))

	var nextSeq atomic.Uint64

	for _, qid := range qs {
		q := qid
		done.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			sock, err := iface.Open(afxdp.SocketConfig{
				QueueID:   q,
				NumFrames: 1024 * 16,
				RxSize:    1024 * 2,
				TxSize:    1024 * 2,
				CqSize:    1024 * 2,
				BatchSize: conf.Receiver.BatchSize,
			})
			fatalIf(err, "opening test RX socket")
			defer sock.Close()

			fmt.Fprintf(os.Stderr,
				"TEST RX on %s:%d (zerocopy=%t)\n",
				ifaceName, q, sock.IsZerocopy(),
			)
			wgReady.Done()

			batch := make([]afxdp.Frame, conf.Receiver.BatchSize)

			for ctx.Err() == nil {
				frames := sock.Receive(batch)
				if len(frames) == 0 {
					fatalIf(sock.Wait(1), "RX wait")
					continue
				}

				for _, fr := range frames {
					buf := fr.Buf
					if len(buf) < 14+20+8+4 {
						continue
					}

					// MAC filter: from router.interface2 -> receiver.interface
					if !equalBytes(buf[0:6], dstMAC[:]) ||
						!equalBytes(buf[6:12], srcMAC[:]) ||
						!equalBytes(buf[12:14], etherTypeIPv4) {
						continue
					}

					ip := buf[14:]
					if ip[0]>>4 != 4 {
						continue
					}
					if !equalBytes(ip[12:16], srcIP) || !equalBytes(ip[16:20], dstIP) {
						continue
					}
					if ip[9] != 17 {
						continue
					}

					udp := ip[20:]
					if len(udp) < 8+4 {
						continue
					}

					if binary.BigEndian.Uint16(udp[0:2]) != srcPort ||
						binary.BigEndian.Uint16(udp[2:4]) != dstPort {
						continue
					}

					payload := udp[8:]
					if len(payload) < 4 {
						continue
					}

					seq := binary.BigEndian.Uint32(payload)

					exp := nextSeq.Load()
					if uint64(seq) != exp {
						result.Errors.Add(1)
						fmt.Fprintf(os.Stderr,
							"TEST ERROR: out-of-order seq: got %d want %d\n",
							seq, exp)
						os.Exit(1)
					}

					nextSeq.Add(1)
					received := result.Received.Add(1)
					stats.RxPackets.Add(1)
					stats.RxBytes.Add(uint64(len(fr.Buf)))

					if received == expectedCount {
						return
					}
				}

				sock.ReleaseBatch(frames)
			}
		})
	}

	wgReady.Wait()
	return &done
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func runStatsPrinter(stats *Stats) {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	var lastTxPkts, lastTxBytes uint64
	var lastRxPkts, lastRxBytes uint64
	lastTime := time.Now()

	for range t.C {
		now := time.Now()
		dt := now.Sub(lastTime).Seconds()
		lastTime = now

		txPkts := stats.TxPackets.Load()
		rxPkts := stats.RxPackets.Load()
		txBytes := stats.TxBytes.Load()
		rxBytes := stats.RxBytes.Load()

		dTxPkts := txPkts - lastTxPkts
		dRxPkts := rxPkts - lastRxPkts
		dTxBytes := txBytes - lastTxBytes
		dRxBytes := rxBytes - lastRxBytes

		lastTxPkts = txPkts
		lastTxBytes = txBytes
		lastRxPkts = rxPkts
		lastRxBytes = rxBytes

		txPPS := uint64(float64(dTxPkts) / dt)
		rxPPS := uint64(float64(dRxPkts) / dt)
		txMbps := float64(dTxBytes*8) / 1e6 / dt
		rxMbps := float64(dRxBytes*8) / 1e6 / dt

		fmt.Printf(
			"TX=%d RX=%d TX-PPS=%d RX-PPS=%d TX-Mbps=%.1f RX-Mbps=%.1f\n",
			txPkts, rxPkts, txPPS, rxPPS, txMbps, rxMbps,
		)
	}
}

func printFinalReport(stats *Stats) {
	txPackets := stats.TxPackets.Load()
	rxPackets := stats.RxPackets.Load()
	txBytes := stats.TxBytes.Load()
	rxBytes := stats.RxBytes.Load()

	drops := txPackets - rxPackets
	elapsed := float64(stats.Elapsed.Load()) / 1e9
	txAvgPPS := uint64(float64(txPackets) / elapsed)
	rxAvgPPS := uint64(float64(rxPackets) / elapsed)
	txAvgMbps := float64(txBytes*8) / 1e6 / elapsed
	rxAvgMbps := float64(rxBytes*8) / 1e6 / elapsed

	p := message.NewPrinter(language.English)
	p.Print("\nFINAL REPORT\n")
	p.Printf(" Elapsed:           %.3f s\n", elapsed)
	p.Printf(" TX:                %d packets\n", txPackets)
	p.Printf(" RX:                %d packets\n", rxPackets)
	p.Printf(" TX Avg PPS:        %d\n", txAvgPPS)
	p.Printf(" RX Avg PPS:        %d\n", rxAvgPPS)
	p.Printf(" TX Avg rate:       %.1f Mbps\n", txAvgMbps)
	p.Printf(" RX Avg rate:       %.1f Mbps\n", rxAvgMbps)
	p.Printf(" Dropped:           %d (%.4f%%)\n",
		drops, float64(drops)/float64(txPackets)*100)
}

func runBenchmark(ctx context.Context, conf *Config, stats *Stats) {
	b, err := yaml.Marshal(conf)
	fatalIf(err, "encoding final YAML config")
	_, _ = os.Stderr.Write(b)
	fmt.Fprintln(os.Stderr)

	// Get MACs for router.interface2 and receiver.interface for L2 rewrite + test.
	_, router2MAC := mustGetIfaceInfo(conf.Router.Interface2)
	_, recvMAC := mustGetIfaceInfo(conf.Receiver.Interface)

	// Sender / receiver interfaces.
	ifaceSender, err := afxdp.MakeInterface(conf.Sender.Interface,
		afxdp.InterfaceConfig{PreferZerocopy: conf.Sender.PreferZerocopy})
	fatalIf(err, "sender iface")

	ifaceReceiver, err := afxdp.MakeInterface(conf.Receiver.Interface,
		afxdp.InterfaceConfig{PreferZerocopy: conf.Receiver.PreferZerocopy})
	fatalIf(err, "receiver iface")

	ctxRouter, cancelRouter := context.WithCancel(ctx)
	defer cancelRouter()

	go func() {
		err := runRouter(ctxRouter, conf, router2MAC, recvMAC)
		if err != nil && !errors.Is(err, context.Canceled) {
			fatalIf(err, "running router")
		}
	}()

	wait(1000*time.Millisecond, "router")

	go runStatsPrinter(stats)

	ctxRecv, cancelRecv := context.WithCancel(ctx)
	defer cancelRecv()
	wgRecvDone := runReceiverBenchmark(
		ctxRecv, ifaceReceiver, stats, conf.Receiver.BatchSize)

	wait(1000*time.Millisecond, "receiver")

	runSender(ifaceSender, &SenderConfig{
		Iface:   conf.Sender.Interface,
		DstMAC:  conf.Sender.DestMAC,
		SrcIP:   conf.Sender.SrcIP,
		DstIP:   conf.Sender.DstIP,
		SrcPort: conf.Sender.SrcPort,
		Port:    conf.Sender.DstPort,
		Count:   conf.Count,
		PktSize: conf.MTU,
		Queue:   conf.Sender.Queue,
		ZC:      conf.Sender.PreferZerocopy,
		RatePPS: conf.Sender.RatePPS,
	}, stats, conf.Sender.BatchSize)

	wait(1000*time.Millisecond, "sender")
	cancelRecv()
	wgRecvDone.Wait()

	printFinalReport(stats)
}

func runTest(ctx context.Context, conf *Config, stats *Stats) {
	fmt.Fprintf(os.Stderr, "FORWARDING TEST CONFIG:\n")
	b, err := yaml.Marshal(conf)
	fatalIf(err, "encoding final YAML config")
	_, _ = os.Stderr.Write(b)
	fmt.Fprintln(os.Stderr)

	_, router2MAC := mustGetIfaceInfo(conf.Router.Interface2)
	_, recvMAC := mustGetIfaceInfo(conf.Receiver.Interface)

	// Sender / receiver interfaces.
	ifaceSender, err := afxdp.MakeInterface(conf.Sender.Interface,
		afxdp.InterfaceConfig{PreferZerocopy: conf.Sender.PreferZerocopy})
	fatalIf(err, "sender iface")

	ifaceReceiver, err := afxdp.MakeInterface(conf.Receiver.Interface,
		afxdp.InterfaceConfig{PreferZerocopy: conf.Receiver.PreferZerocopy})
	fatalIf(err, "receiver iface")

	ctxRouter, cancelRouter := context.WithCancel(ctx)
	defer cancelRouter()

	go func() {
		err := runRouter(ctxRouter, conf, router2MAC, recvMAC)
		if err != nil && !errors.Is(err, context.Canceled) {
			fatalIf(err, "running router")
		}
	}()

	wait(1000*time.Millisecond, "router")

	var result TestResult

	go runStatsPrinter(stats)

	ctxRecv, cancelRecv := context.WithCancel(ctx)
	wgRecvDone := runReceiverTest(
		ctxRecv, ifaceReceiver, conf, router2MAC, recvMAC, &result, stats)

	wait(1000*time.Millisecond, "receiver")

	runSender(ifaceSender, &SenderConfig{
		Iface:   conf.Sender.Interface,
		DstMAC:  conf.Sender.DestMAC,
		SrcIP:   conf.Sender.SrcIP,
		DstIP:   conf.Sender.DstIP,
		SrcPort: conf.Sender.SrcPort,
		Port:    conf.Sender.DstPort,
		Count:   conf.Count,
		PktSize: conf.MTU,
		Queue:   conf.Sender.Queue,
		ZC:      conf.Sender.PreferZerocopy,
		RatePPS: conf.Sender.RatePPS,
	}, stats, conf.Sender.BatchSize)

	wait(1000*time.Millisecond, "sender")

	cancelRecv()
	wgRecvDone.Wait()

	if result.Errors.Load() > 0 {
		fmt.Fprintf(os.Stderr, "TEST FAILED: %d errors\n", result.Errors.Load())
		os.Exit(1)
	}
	if received := result.Received.Load(); received != conf.Count {
		fmt.Fprintf(os.Stderr, "TEST FAILED: received %d of %d\n", received, conf.Count)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "TEST PASSED: received all %d packets in order\n", conf.Count)
	printFinalReport(stats)
}

func main() {
	conf, err := loadConfig()
	fatalIf(err, "reading config")

	ifaceList := []string{
		conf.Sender.Interface,
		conf.Router.Interface1,
		conf.Router.Interface2,
		conf.Receiver.Interface,
	}
	counters := []ifacestat.Counter{
		ifacestat.TxPackets, ifacestat.TxBytes,
		ifacestat.RxPackets, ifacestat.RxBytes,
	}

	ifaceStatsBefore, err := ifacestat.Snapshot(ifaceList, counters...)
	fatalIf(err, "taking interface stats (before)")

	ctx := context.Background()

	var stats Stats
	if conf.Test {
		runTest(ctx, conf, &stats)
	} else {
		runBenchmark(ctx, conf, &stats)
	}

	statsAfter, err := ifacestat.Snapshot(ifaceList, counters...)
	fatalIf(err, "taking interface stats (after)")

	ifaceDeltas := statsAfter.Since(ifaceStatsBefore)

	fmt.Fprintf(os.Stderr, "\nINTERFACE COUNTERS:\n")
	err = ifacestat.Print(os.Stderr, ifaceDeltas, map[string]string{
		conf.Sender.Interface:   "sender",
		conf.Router.Interface1:  "router1",
		conf.Router.Interface2:  "router2",
		conf.Receiver.Interface: "receiver",
	})
	fatalIf(err, "printing interface stats diff")
	fmt.Fprintln(os.Stderr)
}

func wait(dur time.Duration, subject string) {
	fmt.Fprintf(os.Stderr, "waiting %s for %s...\n", dur, subject)
	time.Sleep(dur)
}
