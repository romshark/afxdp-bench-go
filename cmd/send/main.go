//go:build linux

// Package main implements an AF_XDP zero-copy capable bulk sender.
// See https://docs.kernel.org/networking/af_xdp.html
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/dustin/go-humanize"

	"github.com/romshark/afxdp-bench-go/xdp"
)

func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		panic(err)
	}
	return iface.Index
}

func registerXSK(objs *xdp.XdpProgObjects, fd int, queue uint32) error {
	if objs.XsksMap == nil {
		return fmt.Errorf("xsks_map not found")
	}
	return objs.XsksMap.Update(queue, uint32(fd), ebpf.UpdateAny)
}

func attachXDP(iface string, zerocopy bool) (link.Link, *xdp.XdpProgObjects, error) {
	var objs xdp.XdpProgObjects
	if err := xdp.LoadXdpProgObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("load XDP BPF: %w", err)
	}

	prog := objs.XdpSockProg
	if prog == nil {
		objs.Close()
		return nil, nil, fmt.Errorf("xdp_sock_prog not found")
	}

	opts := link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex(iface),
	}
	if zerocopy {
		// Request driver-mode XDP for zerocopy.
		opts.Flags = link.XDPDriverMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attach XDP: %w", err)
	}

	return l, &objs, nil
}

// AF_XDP / UAPI constants.
const (
	// AF_XDP is the address family for XDP sockets in Linux.
	// See https://elixir.bootlin.com/linux/v5.15.77/source/include/linux/socket.h#L225
	AF_XDP = 44

	// SOL_XDP is the socket-level constant used with setsockopt/getsockopt
	// to set or get XDP-specific socket options.
	// See https://elixir.bootlin.com/linux/v5.15.77/source/include/linux/socket.h#L366
	SOL_XDP = 283

	// bind_flags
	// See https://elixir.bootlin.com/linux/v6.1/source/include/uapi/linux/if_xdp.h#L16
	XDP_SHARED_UMEM     = 1
	XDP_COPY            = 2
	XDP_ZEROCOPY        = 4
	XDP_USE_NEED_WAKEUP = 8

	// Socket options
	// See https://elixir.bootlin.com/linux/v6.1/source/include/uapi/linux/if_xdp.h#L58
	XDP_MMAP_OFFSETS         = 1
	XDP_RX_RING              = 2
	XDP_TX_RING              = 3
	XDP_UMEM_REG             = 4
	XDP_UMEM_FILL_RING       = 5
	XDP_UMEM_COMPLETION_RING = 6
	XDP_STATISTICS           = 7
	XDP_OPTIONS              = 8

	// mmap offsets
	// See https://elixir.bootlin.com/linux/v6.1/source/include/uapi/linux/if_xdp.h#L92
	XDP_PGOFF_RX_RING              = 0
	XDP_PGOFF_TX_RING              = 0x80000000
	XDP_UMEM_PGOFF_FILL_RING       = 0x100000000
	XDP_UMEM_PGOFF_COMPLETION_RING = 0x180000000
)

// Program-specific constants.
const (
	NumFrames          = 4096
	FrameSize          = 2048
	TxQueueSize        = 2048
	CompletionRingSize = 2048
	BatchSize          = 64 // TX batching
)

/*---- Kernel structs ----*/

// sockaddr_xdp is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L32
type sockaddr_xdp struct {
	Family       uint16
	Flags        uint16
	Ifindex      uint32
	QueueID      uint32
	SharedUmemFD uint32
}

// xdp_ring_offset is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L43
type xdp_ring_offset struct {
	Producer uint64
	Consumer uint64
	Desc     uint64
	Flags    uint64
}

// xdp_mmap_offsets is defined in linux/if_xdp.h
// https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L50
type xdp_mmap_offsets struct {
	Rx xdp_ring_offset
	Tx xdp_ring_offset
	Fr xdp_ring_offset
	Cr xdp_ring_offset
}

// xdp_umem_reg is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L67
type xdp_umem_reg struct {
	Addr      uint64
	Len       uint64
	ChunkSize uint32
	Headroom  uint32
}

// xdp_desc is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L103
type xdp_desc struct {
	Addr uint64
	Len  uint32
	Opts uint32
}

/*---- Queue wrappers ----*/

type xdpUQueue struct {
	cachedProd uint32
	cachedCons uint32
	mask       uint32
	size       uint32
	prod       *uint32
	cons       *uint32
	descs      []xdp_desc
}

type xdpUMemQueue struct {
	cachedProd uint32
	cachedCons uint32
	mask       uint32
	size       uint32
	prod       *uint32
	cons       *uint32
	addrs      []uint64
}

/*---- Helper functions ----*/

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func rawBind(fd int, sa *sockaddr_xdp) error {
	_, _, e := syscall.Syscall(syscall.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(sa)),
		unsafe.Sizeof(*sa),
	)
	if e != 0 {
		return e
	}
	return nil
}

func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(name),
		uintptr(val), vallen, 0)
	if e != 0 {
		return e
	}
	return nil
}

func getsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	l := uint32(vallen) // socklen_t
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		uintptr(unsafe.Pointer(&l)),
		0,
	)
	if e != 0 {
		return e
	}
	return nil
}

// mmapRegion maps RX/TX/FQ/CQ rings on the AF_XDP socket.
func mmapRegion(fd int, length uintptr, offset uintptr) []byte {
	addr, _, errno := syscall.Syscall6(syscall.SYS_MMAP,
		0,
		length,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd),
		offset,
	)
	if errno != 0 {
		panic(errno)
	}
	sh := &struct {
		Addr uintptr
		Len  int
		Cap  int
	}{addr, int(length), int(length)}
	return *(*[]byte)(unsafe.Pointer(sh))
}

// mmapUmem maps an anonymous, page-backed region for UMEM.
func mmapUmem(length uintptr) []byte {
	addr, _, errno := syscall.Syscall6(syscall.SYS_MMAP,
		0,
		length,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_POPULATE,
		^uintptr(0), // fd = -1
		0,
	)
	if errno != 0 {
		panic(errno)
	}
	sh := &struct {
		Addr uintptr
		Len  int
		Cap  int
	}{addr, int(length), int(length)}
	return *(*[]byte)(unsafe.Pointer(sh))
}

// makeTxQueue builds TX user queue from mmap + offsets.
func makeTxQueue(region []byte, off xdp_ring_offset, size uint32) *xdpUQueue {
	if len(region) == 0 {
		panic("tx region is empty")
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))

	descPtr := unsafe.Add(base, off.Desc)
	descs := unsafe.Slice((*xdp_desc)(descPtr), size)

	return &xdpUQueue{
		mask:       size - 1,
		size:       size,
		prod:       prod,
		cons:       cons,
		descs:      descs,
		cachedProd: 0,
		cachedCons: 0, // libbpf sets cached_cons = size, but xq_nb_free logic works with 0 as well.
	}
}

// makeUMemQueue builds UMEM completion queue from mmap + offsets.
func makeUMemQueue(region []byte, off xdp_ring_offset, size uint32) *xdpUMemQueue {
	if len(region) == 0 {
		panic("cq region is empty")
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))

	addrPtr := unsafe.Add(base, off.Desc)
	addrs := unsafe.Slice((*uint64)(addrPtr), size)

	return &xdpUMemQueue{
		mask:       size - 1,
		size:       size,
		prod:       prod,
		cons:       cons,
		addrs:      addrs,
		cachedProd: 0,
		cachedCons: 0,
	}
}

/*---- Queue operations ----*/

// txRingAvailableSlots returns number of TX descriptors that are currently free.
//
// TX ring semantics:
// - cachedProd = user-space producer position (what we have reserved)
// - cachedCons = user-space view of kernel consumer position
//
// Free descriptors = cachedCons - cachedProd
//
// If not enough space is visible, we refresh cachedCons by reading the
// real kernel consumer index (*q.cons) and extending it by ring size.
// This mirrors xsk_ring_prod__nb_free() from libbpf.
func txRingAvailableSlots(q *xdpUQueue, ndescs uint32) uint32 {
	free := q.cachedCons - q.cachedProd
	if free >= ndescs {
		return free
	}
	// Refresh tail from kernel.
	cons := atomic.LoadUint32(q.cons)
	q.cachedCons = cons + q.size
	return q.cachedCons - q.cachedProd
}

// reserveTxDescriptors attempts to reserve n descriptors in the TX ring.
// Returns the starting index in idx, or 0 if ring is full.
func reserveTxDescriptors(q *xdpUQueue, ndescs uint32, idx *uint32) int {
	if txRingAvailableSlots(q, ndescs) < ndescs {
		return 0
	}
	*idx = q.cachedProd
	q.cachedProd += ndescs
	return int(ndescs)
}

// commitTxDescriptors publishes queued TX descriptors to the kernel.
func commitTxDescriptors(q *xdpUQueue) {
	// Descriptors are written; now publish producer index.
	atomic.StoreUint32(q.prod, q.cachedProd)
}

func umemNbAvail(q *xdpUMemQueue, nb uint32) uint32 {
	entries := q.cachedProd - q.cachedCons
	if entries == 0 {
		prod := atomic.LoadUint32(q.prod)
		q.cachedProd = prod
		entries = q.cachedProd - q.cachedCons
	}
	if entries > nb {
		return nb
	}
	return entries
}

func umemCompleteFromKernel(q *xdpUMemQueue, dst []uint64, nb uint32) uint32 {
	entries := umemNbAvail(q, nb)
	var i uint32
	for i = range entries {
		idx := q.cachedCons & q.mask
		dst[i] = q.addrs[idx]
		q.cachedCons++
	}
	if entries > 0 {
		atomic.StoreUint32(q.cons, q.cachedCons)
	}
	return entries
}

// getIfaceMAC returns the given network's MAC address.
func getIfaceMAC(name string) [6]byte {
	var mac [6]byte
	iface, err := net.InterfaceByName(name)
	must(err)
	if len(iface.HardwareAddr) < 6 {
		panic("unexpected MAC length")
	}
	copy(mac[:], iface.HardwareAddr[:6])
	return mac
}

// ipChecksum returns the checksum of the given IPv4 header.
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

// buildUDPPacket constructs an Ethernet + IPv4 + UDP packet in buf.
func buildUDPPacket(buf []byte, srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP, srcPort, dstPort uint16,
	seq uint32, pktSize uint32) uint32 {

	const ethLen = 14
	const ipLen = 20
	const udpLen = 8

	minSize := uint32(ethLen + ipLen + udpLen + 4)
	if pktSize < minSize {
		pktSize = minSize
	}
	if pktSize > FrameSize {
		pktSize = FrameSize
	}

	payloadLen := pktSize - (ethLen + ipLen + udpLen)

	// Ethernet
	copy(buf[0:6], dstMAC)
	copy(buf[6:12], srcMAC)
	buf[12] = 0x08
	buf[13] = 0x00

	// IPv4
	ip := buf[ethLen:]
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:], uint16(ipLen+udpLen+payloadLen))
	binary.BigEndian.PutUint16(ip[4:], 0)
	binary.BigEndian.PutUint16(ip[6:], 0)
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip[:20]))

	// UDP
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen+payloadLen))
	binary.BigEndian.PutUint16(udp[6:], 0)

	// Payload: first 4 bytes = sequence, rest zero.
	payload := udp[8:]
	binary.BigEndian.PutUint32(payload[:4], seq)
	if payloadLen > 4 {
		for i := 4; i < int(payloadLen); i++ {
			payload[i] = 0
		}
	}

	return pktSize
}

// wakeupTxQueue notifies the kernel/NIC that new TX descriptors are ready.
// AF_XDP interprets a zero-length sendto() as a doorbell signal to process
// the TX ring. This is required when XDP_USE_NEED_WAKEUP is enabled.
func wakeupTxQueue(fd int) {
	// zero-length wakeup; AF_XDP treats this as a "kick"
	_ = syscall.Sendto(fd, []byte{}, syscall.MSG_DONTWAIT, nil)
}

func txLoop(
	fd int,
	tx *xdpUQueue,
	cq *xdpUMemQueue,
	umem []byte,
	srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	pktSize uint32,
	count uint64,
	zerocopy bool,
) {
	runtime.LockOSThread()

	// Local free-frame pool.
	frames := make([]uint64, NumFrames)
	for i := range frames {
		frames[i] = uint64(i) * FrameSize
	}
	freeCnt := uint32(NumFrames)

	var sent uint64
	var seq uint32
	reclaimBuf := make([]uint64, BatchSize)

	for sent < count {
		// Recover completed frames from CQ.
		nComp := umemCompleteFromKernel(cq, reclaimBuf, BatchSize)
		for i := uint32(0); i < nComp; i++ {
			frames[freeCnt] = reclaimBuf[i]
			freeCnt++
		}

		if !zerocopy {
			// In copy mode, once the kernel has copied out, the "addr"
			// can be reused immediately. CQ still works, but to avoid
			// stalling, keep kicking TX.
			wakeupTxQueue(fd)
		}

		if freeCnt == 0 {
			// NIC still owns all buffers; try to drive progress.
			wakeupTxQueue(fd)
			continue
		}

		remaining := count - sent
		toSend := uint32(BatchSize)
		if uint64(toSend) > remaining {
			toSend = uint32(remaining)
		}
		if toSend > freeCnt {
			toSend = freeCnt
		}
		if toSend == 0 {
			continue
		}

		var idx uint32
		if reserveTxDescriptors(tx, toSend, &idx) <= 0 {
			// TX ring full; wake up driver and reclaim completions.
			wakeupTxQueue(fd)
			nComp = umemCompleteFromKernel(cq, reclaimBuf, BatchSize)
			for i := uint32(0); i < nComp; i++ {
				frames[freeCnt] = reclaimBuf[i]
				freeCnt++
			}
			continue
		}

		for i := uint32(0); i < toSend && sent < count; i++ {
			addr := frames[freeCnt-1]
			freeCnt--

			pkt := umem[addr : addr+FrameSize]
			length := buildUDPPacket(
				pkt,
				srcMAC,
				dstMAC,
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				seq,
				pktSize,
			)

			d := &tx.descs[(idx+i)&tx.mask]
			d.Addr = addr
			d.Len = length
			d.Opts = 0

			seq++
			sent++
		}

		// Publish descriptors and wake NIC.
		commitTxDescriptors(tx)
		wakeupTxQueue(fd)
	}
}

func main() {
	fIfaceName := flag.String("i", "", "Interface name")
	fDestMAC := flag.String("d", "", "Destination MAC (like aa:bb:cc:dd:ee:ff)")
	fSrcIP := flag.String("s", "", "Source IPv4")
	fDestIP := flag.String("D", "", "Destination IPv4")
	fDestPort := flag.Int("p", 0, "Destination UDP port")
	fQueueID := flag.Uint("q", 0, "Queue id")
	fPktSize := flag.Uint("l", 1360, "Packet size L2 bytes")
	fCount := flag.Uint64("n", 0, "Total number of packets to send")
	fUseZerocopy := flag.Bool("z", false, "Enables XDP_ZEROCOPY (otherwise XDP_COPY)")
	flag.Parse()

	if *fIfaceName == "" || *fDestMAC == "" || *fSrcIP == "" || *fDestIP == "" || *fDestPort == 0 || *fCount == 0 {
		fmt.Fprintf(os.Stderr,
			"Usage: %s -i iface -d dst-mac -s src-ip -D dst-ip -p dst-port -n count [-l pkt-size] [-q queue-id] [-z]\n",
			os.Args[0])
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "AF_XDP TX (%s):\n",
		map[bool]string{true: "XDP_ZEROCOPY", false: "XDP_COPY"}[*fUseZerocopy])
	fmt.Fprintf(os.Stderr,
		"iface=%s queue_id=%d dst_mac=%s src_ip=%s dst_ip=%s dst_port=%d count=%d pkt_size=%d\n",
		*fIfaceName, *fQueueID, *fDestMAC, *fSrcIP, *fDestIP, *fDestPort, *fCount, *fPktSize)

	// Interface + MAC
	iface, err := net.InterfaceByName(*fIfaceName)
	must(err)
	srcMACArr := getIfaceMAC(*fIfaceName)
	dstHW, err := net.ParseMAC(*fDestMAC)
	must(err)
	if len(dstHW) < 6 {
		panic("bad dst mac")
	}

	srcIP := net.ParseIP(*fSrcIP).To4()
	dstIP := net.ParseIP(*fDestIP).To4()
	srcPort := uint16(12345) // fixed source port for now.

	if srcIP == nil || dstIP == nil {
		panic("invalid IPv4")
	}

	// Attach XDP program.
	xdpLink, objs, err := attachXDP(*fIfaceName, *fUseZerocopy)
	must(err)
	defer xdpLink.Close()
	defer objs.Close()

	// AF_XDP socket.
	fd, err := syscall.Socket(AF_XDP, syscall.SOCK_RAW, 0)
	must(err)
	defer syscall.Close(fd)

	/*---- UMEM registration ----*/

	umemLen := uintptr(NumFrames * FrameSize)
	umem := mmapUmem(umemLen)

	reg := xdp_umem_reg{
		Addr:      uint64(uintptr(unsafe.Pointer(&umem[0]))),
		Len:       uint64(len(umem)),
		ChunkSize: FrameSize,
		Headroom:  0,
	}
	must(setsockopt(fd, SOL_XDP, XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg)))

	// UMEM ring sizes.
	fillSize := uint32(TxQueueSize)
	compSize := uint32(CompletionRingSize)
	must(setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, unsafe.Pointer(&fillSize), unsafe.Sizeof(fillSize)))
	must(setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, unsafe.Pointer(&compSize), unsafe.Sizeof(compSize)))

	// TX ring size on socket.
	txSize := uint32(TxQueueSize)
	must(setsockopt(fd, SOL_XDP, XDP_TX_RING, unsafe.Pointer(&txSize), unsafe.Sizeof(txSize)))

	// Query mmap offsets for all rings.
	var offs xdp_mmap_offsets
	must(getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, unsafe.Pointer(&offs), unsafe.Sizeof(offs)))

	// Map TX ring (descriptors).
	txRegionLen := uintptr(offs.Tx.Desc) + uintptr(TxQueueSize)*unsafe.Sizeof(xdp_desc{})
	txRegion := mmapRegion(fd, txRegionLen, XDP_PGOFF_TX_RING)

	// Map CQ ring (UMEM completion ring, uint64 addresses).
	cqRegionLen := uintptr(offs.Cr.Desc) + uintptr(CompletionRingSize)*unsafe.Sizeof(uint64(0))
	cqRegion := mmapRegion(fd, cqRegionLen, XDP_UMEM_PGOFF_COMPLETION_RING)

	// Map FQ ring (UMEM fill ring, uint64 addresses) – populated only for zerocopy.
	fqRegionLen := uintptr(offs.Fr.Desc) + uintptr(TxQueueSize)*unsafe.Sizeof(uint64(0))
	fqRegion := mmapRegion(fd, fqRegionLen, XDP_UMEM_PGOFF_FILL_RING)

	// Build queues.
	txQ := makeTxQueue(txRegion, offs.Tx, TxQueueSize)
	cqQ := makeUMemQueue(cqRegion, offs.Cr, CompletionRingSize)

	// Populate FQ for zerocopy (mirrors C code).
	if *fUseZerocopy {
		base := unsafe.Pointer(&fqRegion[0])
		fqProd := (*uint32)(unsafe.Add(base, offs.Fr.Producer))
		prod := *fqProd

		ringSize := uint32(TxQueueSize)
		for i := range ringSize {
			idx := (prod + i) & (ringSize - 1)
			entryPtr := unsafe.Add(base,
				uintptr(offs.Fr.Desc)+uintptr(idx)*unsafe.Sizeof(uint64(0)))
			*(*uint64)(entryPtr) = uint64(i) * FrameSize
		}
		*fqProd = prod + ringSize
	}

	// Bind AF_XDP socket to iface:queue.
	sa := &sockaddr_xdp{
		Family:  AF_XDP,
		Ifindex: uint32(iface.Index),
		QueueID: uint32(*fQueueID),
	}

	if *fUseZerocopy {
		sa.Flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP
	} else {
		sa.Flags = XDP_COPY | XDP_USE_NEED_WAKEUP
	}

	err = rawBind(fd, sa)
	if err != nil && *fUseZerocopy {
		// If zerocopy is not supported for this queue, fall back to copy mode.
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EPROTONOSUPPORT {
			fmt.Fprintln(os.Stderr, "XDP_ZEROCOPY not supported on this interface/queue, falling back to XDP_COPY")
			sa.Flags = XDP_COPY | XDP_USE_NEED_WAKEUP
			err = rawBind(fd, sa)
		}
	}
	must(err)

	must(registerXSK(objs, fd, uint32(*fQueueID)))

	fmt.Fprintf(os.Stderr, "bound AF_XDP socket: ifindex=%d flags=0x%x zerocopy=%v\n",
		iface.Index, sa.Flags, *fUseZerocopy)
	fmt.Fprintf(os.Stderr, "srcMAC=%v dstMAC=%v\n", srcMACArr, dstHW[:6])

	// Main transmission loop.
	start := time.Now()
	txLoop(
		fd,
		txQ,
		cqQ,
		umem,
		srcMACArr[:],
		dstHW,
		srcIP,
		dstIP,
		srcPort,
		uint16(*fDestPort),
		uint32(*fPktSize),
		*fCount,
		*fUseZerocopy,
	)
	elapsed := time.Since(start)

	pps := float64(*fCount) / elapsed.Seconds()
	bps := float64(*fCount) * float64(*fPktSize*8) / elapsed.Seconds()
	mbit := bps / 1e6

	fmt.Fprintf(os.Stderr,
		"finished: requested=%s, duration=%s, rate=%s pps, %0.2f Mbit/s (%s)\n",
		humanize.Comma(int64(*fCount)),
		elapsed,
		humanize.Comma(int64(pps)),
		mbit,
		humanize.Bytes(uint64(bps/8))+"/s",
	)
}
