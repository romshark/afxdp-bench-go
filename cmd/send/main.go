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

func buildUDPPacket(buf []byte,
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
	fDestMACStr := flag.String("d", "", "Destination MAC")
	fSrcIPStr := flag.String("s", "", "Source IP")
	fDestIPStr := flag.String("D", "", "Destination IP")
	fPort := flag.Int("p", 0, "Destination port")
	fCount := flag.Uint64("n", 0, "Packets to send")
	fPktSize := flag.Uint("l", 1360, "Packet size")
	fQueue := flag.Uint("q", 0, "Queue ID")
	fZeroCopy := flag.Bool("z", false, "Prefer zerocopy "+
		"(automatically falls back to copy mode if not supported)")
	flag.Parse()

	ifaceIndex, srcMAC := mustGetIfaceInfo(*fIface)

	dstMAC, err := net.ParseMAC(*fDestMACStr)
	must(err)
	srcIP := net.ParseIP(*fSrcIPStr).To4()
	dstIP := net.ParseIP(*fDestIPStr).To4()

	iface, err := afxdp.MakeInterface(*fIface, afxdp.InterfaceConfig{
		PreferZerocopy: *fZeroCopy,
	})
	must(err)

	sock, err := iface.Open(afxdp.SocketConfig{
		QueueID:   uint32(*fQueue),
		FrameSize: 2048,
		NumFrames: 1024 * 8,
		TxSize:    2048,
		CqSize:    2048,
	})
	must(err)
	defer sock.Close()

	fmt.Fprintf(os.Stderr,
		"AF_XDP TX:\niface=%s queue=%d dst_mac=%s src_ip=%s dst_ip=%s dst_port=%d count=%d zc=%t\n",
		*fIface, *fQueue, dstMAC, srcIP, dstIP, *fPort, *fCount, sock.IsZerocopy(),
	)
	fmt.Fprintf(os.Stderr, "bound: ifindex=%d zerocopy=%t\n", ifaceIndex, sock.IsZerocopy())

	const dstPort = 12345
	var (
		seq       uint32
		sent      uint64
		completed uint64
		bytes     uint64
	)

	addrs := make([]uint64, 0, 128)
	lens := make([]uint32, 0, 128)

	start := time.Now()

	for sent < *fCount {

		// wait for space
		for {
			if sock.TxFree() > 0 && sock.FreeFrames() > 0 {
				break
			}
			// reclaim anything that completed
			if c := sock.PollCompletions(128); c > 0 {
				completed += uint64(c)
				continue
			}
			// NIC not progressing yet -> wait for progress
			_ = sock.Wait(1) // ignore errors for now
		}

		sendable := sock.TxFree()
		if sendable > sock.FreeFrames() {
			sendable = sock.FreeFrames()
		}
		if sendable > 128 {
			sendable = 128
		}

		if sent+uint64(sendable) > *fCount {
			sendable = uint32(*fCount - sent)
		}

		addrs = addrs[:0]
		lens = lens[:0]

		for i := uint32(0); i < sendable; i++ {
			frame := sock.NextFrame()
			plen := buildUDPPacket(
				frame.Buf,
				srcMAC[:],
				dstMAC,
				srcIP,
				dstIP,
				dstPort,
				uint16(*fPort),
				seq,
				uint32(*fPktSize),
			)
			addrs = append(addrs, frame.Addr)
			lens = append(lens, plen)

			seq++
			sent++
			bytes += uint64(plen)
		}

		n, err := sock.SubmitBatch(addrs, lens)
		must(err)
		must(sock.FlushTx())

		// reclaim what completed from this batch
		if c := sock.PollCompletions(uint32(n)); c > 0 {
			completed += uint64(c)
		}
	}

	// drain completions: wait until all sent packets are completed
	for completed < sent {
		if c := sock.PollCompletions(128); c > 0 {
			completed += uint64(c)
			continue
		}
		// nothing new yet, let NIC progress
		_ = sock.Wait(1)
	}

	elapsed := time.Since(start)
	pps := float64(sent) / elapsed.Seconds()

	fmt.Fprintf(os.Stderr,
		"finished: sent=%s completed=%s bytes=%s | duration=%s | rate=%s pps\n",
		humanize.Comma(int64(sent)),
		humanize.Comma(int64(completed)),
		humanize.Bytes(bytes),
		elapsed,
		humanize.Comma(int64(pps)),
	)
}
