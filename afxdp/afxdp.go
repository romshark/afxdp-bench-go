//go:build linux

// Package afxdp implements an AF_XDP zero-copy capable socket.
// See https://docs.kernel.org/networking/af_xdp.html
package afxdp

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/romshark/afxdp-bench-go/afxdp/xdp"
)

var (
	ErrMissingIface        = errors.New("iface not set")
	ErrXSKSMapNotFound     = errors.New("xsks_map not found")
	ErrXDPSockProgNotFound = errors.New("xdp_sock_prog not found")
	ErrTXRegionIsEmpty     = errors.New("tx region is empty")
	ErrCQRegionIsEmpty     = errors.New("cq region is empty")
)

func registerXSK(objs *xdp.XdpProgObjects, fd int, queue uint32) error {
	if objs.XsksMap == nil {
		return ErrXSKSMapNotFound
	}
	return objs.XsksMap.Update(queue, uint32(fd), ebpf.UpdateAny)
}

func attachXDP(ifaceName string, zerocopy bool) (link.Link, *xdp.XdpProgObjects, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("getting interface index by name: %w", err)
	}

	var objs xdp.XdpProgObjects
	if err := xdp.LoadXdpProgObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading XDP BPF: %w", err)
	}

	prog := objs.XdpSockProg
	if prog == nil {
		objs.Close()
		return nil, nil, ErrXDPSockProgNotFound
	}

	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	}
	if zerocopy {
		// Request driver-mode XDP for zerocopy.
		opts.Flags = link.XDPDriverMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attaching XDP: %w", err)
	}

	return l, &objs, nil
}

const (
	DefaultNumFrames          = 4096
	DefaultFrameSize          = 2048
	DefaultTxQueueSize        = 2048
	DefaultCompletionRingSize = 2048
	DefaultBatchSize          = 64 // TX batching
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

func rawBind(fd int, sa *sockaddr_xdp) error {
	_, _, e := unix.Syscall(unix.SYS_BIND,
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
	_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(name),
		uintptr(val), vallen, 0)
	if e != 0 {
		return e
	}
	return nil
}

func getsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	l := uint32(vallen) // socklen_t
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT,
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
func mmapRegion(fd int, length uintptr, offset uintptr) ([]byte, error) {
	addr, _, errno := unix.Syscall6(unix.SYS_MMAP,
		0,
		length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(fd),
		offset,
	)
	if errno != 0 {
		return nil, errno
	}
	sh := &struct {
		Addr uintptr
		Len  int
		Cap  int
	}{addr, int(length), int(length)}
	return *(*[]byte)(unsafe.Pointer(sh)), nil
}

// mmapUmem maps an anonymous, page-backed region for UMEM.
func mmapUmem(length uintptr) ([]byte, error) {
	addr, _, errno := unix.Syscall6(unix.SYS_MMAP,
		0,
		length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE,
		^uintptr(0), // fd = -1
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	sh := &struct {
		Addr uintptr
		Len  int
		Cap  int
	}{addr, int(length), int(length)}
	return *(*[]byte)(unsafe.Pointer(sh)), nil
}

// makeTxQueue builds TX user queue from mmap + offsets.
func makeTxQueue(region []byte, off xdp_ring_offset, size uint32) (*xdpUQueue, error) {
	if len(region) == 0 {
		return nil, ErrTXRegionIsEmpty
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
		cachedCons: size,
	}, nil
}

// makeUMemQueue builds UMEM completion queue from mmap + offsets.
func makeUMemQueue(
	region []byte, off xdp_ring_offset, size uint32,
) (*xdpUMemQueue, error) {
	if len(region) == 0 {
		return nil, ErrCQRegionIsEmpty
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
	}, nil
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

var zeroBuf []byte

// wakeupTxQueue notifies the kernel/NIC that new TX descriptors are ready.
// AF_XDP interprets a zero-length sendto() as a doorbell signal to process
// the TX ring. This is required when XDP_USE_NEED_WAKEUP is enabled.
func wakeupTxQueue(fd int) error {
	// zero-length wakeup; AF_XDP treats this as a "kick"
	err := unix.Sendto(fd, zeroBuf, unix.MSG_DONTWAIT, nil)
	if err == unix.EAGAIN || err == unix.EBUSY {
		// Treat EAGAIN (and optionally EBUSY) as non-fatal backpressure.
		return nil
	}
	return err
}

type Config struct {
	Iface     string
	QueueID   uint32
	Zerocopy  bool
	BatchSize uint32

	NumFrames uint32
	FrameSize uint32
	TxSize    uint32
	CqSize    uint32
}

type Stats struct {
	TxPackets uint64
	TxBytes   uint64
}

// Socket is an AF_XDP bidirectional socket.
//
// WARNING: Socket is not safe for concurrent use.
type Socket struct {
	cfg Config

	fd int

	umem []byte
	tx   *xdpUQueue
	cq   *xdpUMemQueue

	txRegion []byte
	cqRegion []byte

	freeFrames []uint64
	freeCnt    uint32

	compBuf []uint64

	stats Stats

	xdpLink link.Link
	xdpObjs *xdp.XdpProgObjects

	fqRegion []byte
}

// Open creates and initializes an AF_XDP socket with UMEM, TX + CQ rings.
func Open(cfg Config) (*Socket, error) {
	if cfg.Iface == "" {
		return nil, ErrMissingIface
	}

	// Apply defaults if necessary.
	if cfg.NumFrames == 0 {
		cfg.NumFrames = DefaultNumFrames
	}
	if cfg.FrameSize == 0 {
		cfg.FrameSize = DefaultFrameSize
	}
	if cfg.TxSize == 0 {
		cfg.TxSize = DefaultTxQueueSize
	}
	if cfg.CqSize == 0 {
		cfg.CqSize = DefaultCompletionRingSize
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultBatchSize
	}

	// TODO: currently, Open would leak memory if some of the following
	// operations fail.

	// Attach XDP program.
	xdpLink, objs, err := attachXDP(cfg.Iface, cfg.Zerocopy)
	if err != nil {
		return nil, fmt.Errorf("attaching XDP to iface: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("fetching iface info by name: %w", err)
	}

	// AF_XDP socket.
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("opening AF_XDP socket: %w", err)
	}

	// UMEM registration.
	umemLen := uintptr(cfg.NumFrames) * uintptr(cfg.FrameSize)
	umem, err := mmapUmem(umemLen)
	if err != nil {
		return nil, fmt.Errorf("mmap UMEM: %w", err)
	}

	reg := xdp_umem_reg{
		Addr:      uint64(uintptr(unsafe.Pointer(&umem[0]))),
		Len:       uint64(len(umem)),
		ChunkSize: cfg.FrameSize,
		Headroom:  0,
	}
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_REG,
		unsafe.Pointer(&reg), unsafe.Sizeof(reg),
	); err != nil {
		unix.Close(fd)
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("setsockopt XDP_UMEM_REG: %w", err)
	}

	// UMEM ring sizes.
	fillSize := cfg.TxSize
	compSize := cfg.CqSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING,
		unsafe.Pointer(&fillSize), unsafe.Sizeof(fillSize),
	); err != nil {
		unix.Close(fd)
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("setsockopt XDP_UMEM_FILL_RING: %w", err)
	}
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING,
		unsafe.Pointer(&compSize), unsafe.Sizeof(compSize),
	); err != nil {
		unix.Close(fd)
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("setsockopt XDP_UMEM_COMPLETION_RING: %w", err)
	}

	// TX ring size on socket.
	txSize := cfg.TxSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_TX_RING,
		unsafe.Pointer(&txSize), unsafe.Sizeof(txSize),
	); err != nil {
		unix.Close(fd)
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("setsockopt XDP_TX_RING: %w", err)
	}

	// Query mmap offsets for all rings.
	var offs xdp_mmap_offsets
	if err := getsockopt(
		fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		unsafe.Pointer(&offs), unsafe.Sizeof(offs),
	); err != nil {
		unix.Close(fd)
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("setsockopt XDP_MMAP_OFFSETS: %w", err)
	}

	// Map TX ring (descriptors).
	txRegionLen := uintptr(offs.Tx.Desc) + uintptr(cfg.TxSize)*unsafe.Sizeof(xdp_desc{})
	txRegion, err := mmapRegion(fd, txRegionLen, unix.XDP_PGOFF_TX_RING)
	if err != nil {
		return nil, fmt.Errorf("mmap TX ring: %w", err)
	}

	// Map CQ ring (UMEM completion ring, uint64 addresses).
	cqRegionLen := uintptr(offs.Cr.Desc) + uintptr(cfg.CqSize)*unsafe.Sizeof(uint64(0))
	cqRegion, err := mmapRegion(fd, cqRegionLen, unix.XDP_UMEM_PGOFF_COMPLETION_RING)
	if err != nil {
		return nil, fmt.Errorf("mmap CQ ring: %w", err)
	}

	// Map FQ ring (UMEM fill ring, uint64 addresses) – populated only for zerocopy.
	var fqRegion []byte
	if cfg.Zerocopy {
		fqRegionLen := uintptr(offs.Fr.Desc) + uintptr(cfg.TxSize)*unsafe.Sizeof(uint64(0))
		fqRegion, err = mmapRegion(fd, fqRegionLen, unix.XDP_UMEM_PGOFF_FILL_RING)
		if err != nil {
			return nil, fmt.Errorf("mmap FQ ring: %w", err)
		}
	}

	// Build queues.
	txQ, err := makeTxQueue(txRegion, offs.Tx, cfg.TxSize)
	if err != nil {
		return nil, fmt.Errorf("making TX queue: %w", err)
	}
	cqQ, err := makeUMemQueue(cqRegion, offs.Cr, cfg.CqSize)
	if err != nil {
		return nil, fmt.Errorf("making CQ queue: %w", err)
	}

	// Populate FQ for zerocopy.
	if cfg.Zerocopy {
		base := unsafe.Pointer(&fqRegion[0])
		fqProd := (*uint32)(unsafe.Add(base, offs.Fr.Producer))
		prod := *fqProd

		ringSize := cfg.TxSize
		for i := uint32(0); i < ringSize; i++ {
			idx := (prod + i) & (ringSize - 1)
			entryPtr := unsafe.Add(base,
				uintptr(offs.Fr.Desc)+uintptr(idx)*unsafe.Sizeof(uint64(0)))
			*(*uint64)(entryPtr) = uint64(i) * uint64(cfg.FrameSize)
		}
		*fqProd = prod + ringSize
	}

	// Bind AF_XDP socket to iface:queue.
	sa := &sockaddr_xdp{
		Family:  unix.AF_XDP,
		Ifindex: uint32(iface.Index),
		QueueID: cfg.QueueID,
	}

	if cfg.Zerocopy {
		sa.Flags = unix.XDP_ZEROCOPY | unix.XDP_USE_NEED_WAKEUP
	} else {
		sa.Flags = unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP
	}

	err = rawBind(fd, sa)
	if err != nil && cfg.Zerocopy {
		// If zerocopy is not supported for this queue, fall back to copy mode.
		if errno, ok := err.(unix.Errno); ok && errno == unix.EPROTONOSUPPORT {
			sa.Flags = unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP
			cfg.Zerocopy = false
			err = rawBind(fd, sa)
		}
	}
	if err != nil {
		unix.Close(fd)
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("binding socket: %w", err)
	}

	if err := registerXSK(objs, fd, cfg.QueueID); err != nil {
		unix.Close(fd)
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("registering XSK: %w", err)
	}

	// Local free-frame pool.
	freeFrames := make([]uint64, cfg.NumFrames)
	for i := uint32(0); i < cfg.NumFrames; i++ {
		freeFrames[i] = uint64(i) * uint64(cfg.FrameSize)
	}

	s := &Socket{
		cfg:        cfg,
		fd:         fd,
		umem:       umem,
		tx:         txQ,
		cq:         cqQ,
		txRegion:   txRegion,
		cqRegion:   cqRegion,
		freeFrames: freeFrames,
		freeCnt:    cfg.NumFrames,
		compBuf:    make([]uint64, cfg.BatchSize),
		stats:      Stats{},
		xdpLink:    xdpLink,
		xdpObjs:    objs,
		fqRegion:   fqRegion,
	}

	return s, nil
}

// Close releases the socket, UMEM and kernel resources.
func (s *Socket) Close() error {
	var errs []error

	if s.fd != 0 {
		if err := unix.Close(s.fd); err != nil {
			errs = append(errs, fmt.Errorf("closing fd: %w", err))
		}
		s.fd = 0
	}

	if s.xdpLink != nil {
		if err := s.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP link: %w", err))
		}
		s.xdpLink = nil
	}

	if s.xdpObjs != nil {
		if err := s.xdpObjs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP objs: %w", err))
		}
		s.xdpObjs = nil
	}

	// Explicitly unmap UMEM and ring regions.
	if s.txRegion != nil {
		if err := unix.Munmap(s.txRegion); err != nil {
			errs = append(errs, err)
		}
		s.txRegion = nil
	}

	if s.cqRegion != nil {
		if err := unix.Munmap(s.cqRegion); err != nil {
			errs = append(errs, err)
		}
		s.cqRegion = nil
	}

	if s.fqRegion != nil {
		if err := unix.Munmap(s.fqRegion); err != nil {
			errs = append(errs, err)
		}
		s.fqRegion = nil
	}

	if s.umem != nil {
		if err := unix.Munmap(s.umem); err != nil {
			errs = append(errs, err)
		}
		s.umem = nil
	}

	return errors.Join(errs...)
}

// Frame represents a borrowed UMEM frame from an AF_XDP socket.
type Frame struct {
	// Buf points directly into the UMEM region and can be written to
	// without additional copying.
	Buf []byte

	// Addr is the UMEM address that must be passed
	// back to Submit() after the frame has been filled.
	Addr uint64
}

// NextFrame returns a writable UMEM buffer and its address.
// A zero-value frame indicates that no frame is currently available and the
// caller should retry after PollCompletions().
func (s *Socket) NextFrame() Frame {
	if s.freeCnt == 0 {
		// Try to reclaim some completions.
		s.PollCompletions(uint32(len(s.compBuf)))
		if s.freeCnt == 0 {
			return Frame{}
		}
	}

	s.freeCnt--
	addr := s.freeFrames[s.freeCnt]

	frameSize := s.cfg.FrameSize
	if frameSize == 0 {
		frameSize = DefaultFrameSize
	}

	start := int(addr)
	end := start + int(frameSize)

	return Frame{
		Buf:  s.umem[start:end],
		Addr: addr,
	}
}

// Submit publishes the frame to the TX ring.
func (s *Socket) Submit(addr uint64, length uint32) error {
	var idx uint32

	// Reserve one descriptor; spin until we get space.
	for {
		if reserveTxDescriptors(s.tx, 1, &idx) > 0 {
			break
		}
		// Ring full: try to reclaim and wake up the NIC.
		if s.PollCompletions(s.cfg.BatchSize) == 0 {
			if err := wakeupTxQueue(s.fd); err != nil {
				return err
			}
		}
	}

	d := &s.tx.descs[idx&s.tx.mask]
	d.Addr = addr
	d.Len = length
	d.Opts = 0

	s.stats.TxPackets++
	s.stats.TxBytes += uint64(length)
	return nil
}

// FlushTx notifies the kernel/NIC that TX descriptors are available.
// Required when XDP_USE_NEED_WAKEUP is enabled.
func (s *Socket) FlushTx() error {
	// Commit all pending descriptors and ring the doorbell.
	commitTxDescriptors(s.tx)
	return wakeupTxQueue(s.fd)
}

// PollCompletions reclaims completed frames from the kernel.
// maxFrames specifies the maximum number of completed frames the caller wishes
// to reclaim in this call. The actual number processed may be lower if
// fewer completions are available. The value is also capped internally
// by the size of the completion buffer.
func (s *Socket) PollCompletions(maxFrames uint32) uint32 {
	if maxFrames == 0 {
		return 0
	}
	maxFrames = min(maxFrames, uint32(len(s.compBuf)))

	n := umemCompleteFromKernel(s.cq, s.compBuf, maxFrames)
	for i := range n {
		s.freeFrames[s.freeCnt] = s.compBuf[i]
		s.freeCnt++
	}
	return n
}

// StatsTx returns cumulative transmission counters.
func (s *Socket) StatsTx() Stats {
	return s.stats
}
