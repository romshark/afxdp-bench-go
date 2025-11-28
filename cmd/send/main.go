//go:build linux

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/dustin/go-humanize"
	afxdp "github.com/romshark/afxdp-bench-go/afxdp"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustGetIfaceInfo(name string) (index int, macAddr [6]byte) {
	iface, err := net.InterfaceByName(name)
	must(err)
	copy(macAddr[:], iface.HardwareAddr[:6])
	return iface.Index, macAddr
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
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip[:20]))

	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen+payloadLen))

	payload := udp[8:]
	binary.BigEndian.PutUint32(payload[:4], seq)

	return pktSize
}

func main() {
	fIface := flag.String("i", "", "Interface")
	dstMACStr := flag.String("d", "", "Destination MAC")
	srcIPStr := flag.String("s", "", "Source IP")
	dstIPStr := flag.String("D", "", "Destination IP")
	fPort := flag.Int("p", 0, "Destination port")
	fCount := flag.Uint64("n", 0, "Packets to send")
	fPktSize := flag.Uint("l", 1360, "Packet size")
	fQueue := flag.Uint("q", 0, "Queue ID")
	fZeroCopy := flag.Bool("z", false, "Prefer zerocopy "+
		"(automatically falls back to copy mode if not supported)")
	flag.Parse()

	ifaceIndex, srcMAC := mustGetIfaceInfo(*fIface)
	fDestMAC, err := net.ParseMAC(*dstMACStr)
	must(err)

	fSrcIP := net.ParseIP(*srcIPStr).To4()
	fDestIP := net.ParseIP(*dstIPStr).To4()

	iface, err := afxdp.MakeInterface(*fIface, afxdp.InterfaceConfig{
		PreferZerocopy: *fZeroCopy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "initializing interface: %v\n", err)
		os.Exit(1)
	}

	sock, err := iface.Open(afxdp.SocketConfig{
		QueueID:   uint32(*fQueue),
		NumFrames: 4096,
		FrameSize: 2048,
		TxSize:    2048,
		CqSize:    2048,
	})
	must(err)
	defer sock.Close()

	fmt.Fprintf(os.Stderr,
		"AF_XDP TX:\niface=%s queue_id=%d dst_mac=%s src_ip=%s dst_ip=%s "+
			"dst_port=%d count=%d pkt_size=%d zerocopy=%t\n",
		*fIface, *fQueue, fDestMAC, fSrcIP, fDestIP,
		*fPort, *fCount, *fPktSize, *fZeroCopy,
	)

	fmt.Fprintf(os.Stderr,
		"bound AF_XDP socket: ifindex=%d zerocopy=%t\n",
		ifaceIndex, sock.IsZerocopy())

	start := time.Now()

	var (
		seq   uint32
		sent  uint64
		bytes uint64
		batch uint32
	)

	const batchSize = 64

	for sent < *fCount {
		frame := sock.NextFrame()
		if frame.Buf == nil {
			sock.PollCompletions(64)
			continue
		}

		length := buildUDPPacket(
			frame.Buf,
			srcMAC[:],
			fDestMAC,
			fSrcIP,
			fDestIP,
			12345,
			uint16(*fPort),
			seq,
			uint32(*fPktSize),
		)

		must(sock.Submit(frame.Addr, length))

		sent++
		bytes += uint64(length)
		seq++
		batch++

		if batch == batchSize {
			must(sock.FlushTx())
			batch = 0
		}
	}

	if batch > 0 {
		must(sock.FlushTx())
	}

	elapsed := time.Since(start)

	pps := float64(sent) / elapsed.Seconds()
	bps := float64(bytes*8) / elapsed.Seconds()
	bytesPerSec := float64(bytes) / elapsed.Seconds()

	fmt.Fprintf(os.Stderr,
		"finished: packets=%s | duration=%s | rate=%s pps | %.2f Mbit/s (%s/s)\n",
		humanize.Comma(int64(sent)),
		elapsed,
		humanize.Comma(int64(pps)),
		bps/1e6,
		humanize.Bytes(uint64(bytesPerSec)),
	)
}
