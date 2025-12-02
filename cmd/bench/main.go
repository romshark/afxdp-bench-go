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
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Egress struct {
		Interface string `yaml:"interface"`
		Zerocopy  bool   `yaml:"zerocopy"`
		Queue     uint   `yaml:"queue"`
		DestMAC   string `yaml:"dest-mac"`
		SrcIP     string `yaml:"src-ip"`
		DstIP     string `yaml:"dst-ip"`
		SrcPort   int    `yaml:"src-port"`
		DstPort   int    `yaml:"dst-port"`
		BatchSize uint32 `yaml:"batch-size"`
	} `yaml:"egress"`

	Ingress struct {
		Interface string `yaml:"interface"`
		Zerocopy  bool   `yaml:"zerocopy"`
		BatchSize uint32 `yaml:"batch-size"`
	} `yaml:"ingress"`

	MTU   uint64 `yaml:"mtu"`
	Count uint64 `yaml:"count"`
	Test  bool   `yaml:"test"`
}

func loadConfig() (*Config, error) {
	fConfig := flag.String("config", "bench.yaml", "path to config YAML file")
	fIfaceE := flag.String("ie", "", "egress")
	fIfaceI := flag.String("ii", "", "ingress")
	fPreferZC := flag.Bool("z", false, "zerocopy")
	fDestMAC := flag.String("d", "", "dest mac")
	fSrcIP := flag.String("s", "", "src ip")
	fDstIP := flag.String("D", "", "dst ip")
	fPort := flag.Int("p", 0, "dst udp port")
	fCount := flag.Uint64("n", 0, "packet count")
	fPktSize := flag.Uint("l", 1500, "pkt size")
	fQueue := flag.Uint("q", 0, "queue id")
	fTest := flag.Bool("test", false, "enable test mode")

	flag.Parse()

	b, err := os.ReadFile(*fConfig)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var conf Config
	if err := yaml.Unmarshal(b, &conf); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	if *fIfaceE != "" {
		conf.Egress.Interface = *fIfaceE
	}
	if *fIfaceI != "" {
		conf.Ingress.Interface = *fIfaceI
	}
	if *fPreferZC {
		conf.Egress.Zerocopy, conf.Ingress.Zerocopy = true, true
	}
	if *fDestMAC != "" {
		conf.Egress.DestMAC = *fDestMAC
	}
	if *fSrcIP != "" {
		conf.Egress.SrcIP = *fSrcIP
	}
	if *fDstIP != "" {
		conf.Egress.DstIP = *fDstIP
	}
	if *fPort != 0 {
		conf.Egress.DstPort = *fPort
	}
	if *fQueue != 0 {
		conf.Egress.Queue = *fQueue
	}
	if *fPktSize != 1500 {
		conf.MTU = uint64(*fPktSize)
	}
	if *fCount != 0 {
		conf.Count = *fCount
	}
	if *fTest {
		conf.Test = true
	}

	if conf.Egress.Interface == "" {
		return nil, errors.New("egress.interface must be set")
	}
	if conf.Ingress.Interface == "" {
		return nil, errors.New("ingress.interface must be set")
	}
	if conf.Egress.DestMAC == "" {
		return nil, errors.New("egress.dest-mac must be set")
	}
	if _, err := net.ParseMAC(conf.Egress.DestMAC); err != nil {
		return nil, fmt.Errorf("invalid egress.dest-mac %q: %w", conf.Egress.DestMAC, err)
	}
	if conf.Egress.SrcIP == "" {
		return nil, errors.New("egress.src-ip must be set")
	}
	if net.ParseIP(conf.Egress.SrcIP) == nil {
		return nil, fmt.Errorf("invalid egress.src-ip %q", conf.Egress.SrcIP)
	}
	if conf.Egress.DstIP == "" {
		return nil, errors.New("egress.dst-ip must be set")
	}
	if net.ParseIP(conf.Egress.DstIP) == nil {
		return nil, fmt.Errorf("invalid egress.dst-ip %q", conf.Egress.DstIP)
	}
	if conf.Egress.DstPort <= 0 || conf.Egress.DstPort > 65535 {
		return nil, errors.New("egress.dst-port must be 1-65535")
	}
	if conf.Egress.SrcPort <= 0 || conf.Egress.SrcPort > 65535 {
		return nil, errors.New("egress.src-port must be 1-65535")
	}
	if conf.Count == 0 {
		return nil, errors.New("count must be > 0")
	}
	if conf.MTU < 64 || conf.MTU > 1500 {
		return nil, errors.New("unsupported mtu")
	}
	if conf.Egress.BatchSize == 0 {
		conf.Egress.BatchSize = 64
	}
	if conf.Ingress.BatchSize == 0 {
		conf.Ingress.BatchSize = 64
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
	fatalIf(err, "getting interface")
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

func runReceiverBenchmark(
	ctx context.Context, iface *afxdp.Interface, stats *Stats, batch uint32,
) (done *sync.WaitGroup) {
	qs, err := iface.RXQueueIDs()
	fatalIf(err, "listing RX queues")
	if len(qs) == 0 {
		panic("no RX queues")
	}

	ifaceName, _ := iface.Info()

	done = new(sync.WaitGroup)
	var wgReady sync.WaitGroup
	wgReady.Add(len(qs))

	for _, qid := range qs {
		q := qid
		done.Add(1)
		go func() {
			defer done.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			sock, err := iface.Open(afxdp.SocketConfig{
				QueueID:   q,
				NumFrames: 1024 * 32,
				RxSize:    1024 * 8,
				TxSize:    1024 * 8,
				CqSize:    1024 * 8,
				BatchSize: batch,
			})
			fatalIf(err, "opening RX socket")
			defer sock.Close()

			fmt.Fprintf(os.Stderr, "RX on %s:%d (zerocopy=%t)\n",
				ifaceName, q, sock.IsZerocopy())
			wgReady.Done()

			buf := make([]afxdp.Frame, batch)

			for ctx.Err() == nil {
				frames := sock.Receive(buf)
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
		}()
	}

	wgReady.Wait()
	return done
}

type TestResult struct {
	Received uint64
	Errors   atomic.Uint64
}

func runReceiverTest(
	ctx context.Context,
	iface *afxdp.Interface,
	conf *Config,
	result *TestResult,
) (done *sync.WaitGroup) {

	qs, err := iface.RXQueueIDs()
	fatalIf(err, "listing RX queues")
	if len(qs) == 0 {
		panic("no RX queues")
	}

	ifaceName, _ := iface.Info()
	expectedCount := conf.Count

	// Parse config params for filtering
	dstMAC, _ := net.ParseMAC(conf.Egress.DestMAC)
	srcMACIdx, srcMAC := mustGetIfaceInfo(conf.Egress.Interface)
	_ = srcMACIdx
	srcIP := net.ParseIP(conf.Egress.SrcIP).To4()
	dstIP := net.ParseIP(conf.Egress.DstIP).To4()
	srcPort := uint16(conf.Egress.SrcPort)
	dstPort := uint16(conf.Egress.DstPort)

	etherTypeIPv4 := []byte{0x08, 0x00}

	done = new(sync.WaitGroup)
	var wgReady sync.WaitGroup
	wgReady.Add(len(qs))

	// Global next expected seq
	var nextSeq atomic.Uint64

	for _, qid := range qs {
		q := qid
		done.Add(1)

		go func() {
			defer done.Done()

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			sock, err := iface.Open(afxdp.SocketConfig{
				QueueID:   q,
				NumFrames: 1024 * 32,
				RxSize:    1024 * 8,
				TxSize:    1024 * 8,
				CqSize:    1024 * 8,
				BatchSize: conf.Ingress.BatchSize,
			})
			fatalIf(err, "opening RX socket")
			defer sock.Close()

			fmt.Fprintf(os.Stderr,
				"TEST RX on %s:%d (zerocopy=%t)\n",
				ifaceName, q, sock.IsZerocopy(),
			)
			wgReady.Done()

			batch := make([]afxdp.Frame, conf.Ingress.BatchSize)

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

					// Filter packets
					if !equalMAC(buf[0:6], dstMAC) ||
						!equalMAC(buf[6:12], srcMAC[:]) ||
						!equal(buf[12:14], etherTypeIPv4) {
						continue
					}

					ip := buf[14:]
					if ip[0]>>4 != 4 {
						continue
					}
					if !equal(ip[12:16], srcIP) || !equal(ip[16:20], dstIP) {
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
					result.Received++
					if result.Received == expectedCount {
						return
					}
				}

				sock.ReleaseBatch(frames)
			}
		}()
	}

	wgReady.Wait()
	return done
}

func equal(a, b []byte) bool {
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

func equalMAC(a []byte, b net.HardwareAddr) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type SenderConfig struct {
	Iface   string
	DstMAC  string
	SrcIP   string
	DstIP   string
	SrcPort int
	Port    int
	Count   uint64
	PktSize uint
	Queue   uint
	ZC      bool
}

func runSender(
	iface *afxdp.Interface,
	conf *SenderConfig,
	stats *Stats,
	batchSize uint32,
) {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	_, srcMAC := mustGetIfaceInfo(conf.Iface)
	dstMAC, err := net.ParseMAC(conf.DstMAC)
	fatalIf(err, "parse dst mac")

	srcIP := net.ParseIP(conf.SrcIP).To4()
	dstIP := net.ParseIP(conf.DstIP).To4()

	sock, err := iface.Open(afxdp.SocketConfig{
		QueueID:   uint32(conf.Queue),
		NumFrames: 1024 * 32,
		RxSize:    1024 * 8,
		TxSize:    1024 * 8,
		CqSize:    1024 * 8,
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

	start := time.Now()

	srcPort := uint16(conf.SrcPort)
	dstPort := uint16(conf.Port)
	pktSize := uint32(conf.PktSize)

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

		for range sendable {
			f := sock.NextFrame()

			plen := buildUDPPacket(
				f.Buf, srcMAC[:], dstMAC, srcIP, dstIP,
				srcPort, dstPort, seq, pktSize,
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

func main() {
	conf, err := loadConfig()
	fatalIf(err, "reading config")

	fmt.Fprintf(os.Stderr, "FINAL CONFIG:\n")
	b, err := yaml.Marshal(conf)
	fatalIf(err, "encoding final YAML config")
	_, _ = os.Stderr.Write(b)
	fmt.Fprintln(os.Stderr)

	ifaceE, err := afxdp.MakeInterface(
		conf.Egress.Interface, afxdp.InterfaceConfig{
			PreferZerocopy: conf.Egress.Zerocopy,
		})
	fatalIf(err, "egress iface")

	ifaceI, err := afxdp.MakeInterface(
		conf.Ingress.Interface, afxdp.InterfaceConfig{
			PreferZerocopy: conf.Ingress.Zerocopy,
		})
	fatalIf(err, "ingress iface")

	var stats Stats
	go runStatsPrinter(&stats)

	if conf.Test {
		// Run integrity test.
		runTest(ifaceI, ifaceE, conf, &stats)
		return
	}

	// Run benchmark.
	ctxRecv, cancelRecv := context.WithCancel(context.Background())
	defer cancelRecv()

	wgRecvDone := runReceiverBenchmark(ctxRecv, ifaceI, &stats, conf.Ingress.BatchSize)

	{
		d := 300 * time.Millisecond
		fmt.Fprintf(os.Stderr, "waiting %s for receivers...\n", d)
		time.Sleep(d) // Wait for the receivers to spin up.
	}

	runSender(ifaceE, &SenderConfig{
		Iface:   conf.Egress.Interface,
		DstMAC:  conf.Egress.DestMAC,
		SrcIP:   conf.Egress.SrcIP,
		DstIP:   conf.Egress.DstIP,
		SrcPort: conf.Egress.SrcPort,
		Port:    conf.Egress.DstPort,
		Count:   conf.Count,
		PktSize: uint(conf.MTU),
		Queue:   conf.Egress.Queue,
		ZC:      conf.Egress.Zerocopy,
	}, &stats, conf.Egress.BatchSize)

	time.Sleep(300 * time.Millisecond)
	cancelRecv()
	wgRecvDone.Wait()

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

func runTest(ifaceI, ifaceE *afxdp.Interface, conf *Config, stats *Stats) {
	var result TestResult

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wgRecvDone := runReceiverTest(ctx, ifaceI, conf, &result)

	{
		d := 300 * time.Millisecond
		fmt.Fprintf(os.Stderr, "waiting %s for receivers...\n", d)
		time.Sleep(d) // Wait for the receivers to spin up.
	}

	runSender(ifaceE, &SenderConfig{
		Iface:   conf.Egress.Interface,
		DstMAC:  conf.Egress.DestMAC,
		SrcIP:   conf.Egress.SrcIP,
		DstIP:   conf.Egress.DstIP,
		SrcPort: conf.Egress.SrcPort,
		Port:    conf.Egress.DstPort,
		Count:   conf.Count,
		PktSize: uint(conf.MTU),
		Queue:   conf.Egress.Queue,
		ZC:      conf.Egress.Zerocopy,
	}, stats, conf.Egress.BatchSize)

	{
		d := 300 * time.Millisecond
		fmt.Fprintf(os.Stderr, "waiting %s for sender...\n", d)
		time.Sleep(d) // Wait for the receivers to spin up.
	}

	cancel()
	wgRecvDone.Wait()

	if result.Errors.Load() > 0 {
		fmt.Fprintf(os.Stderr, "TEST FAILED: %d errors\n",
			result.Errors.Load())
		os.Exit(1)
	}
	if result.Received != conf.Count {
		fmt.Fprintf(os.Stderr,
			"TEST FAILED: received %d of %d\n",
			result.Received, conf.Count)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "TEST PASSED: received all %d packets in order\n", conf.Count)
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
