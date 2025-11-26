//go:build ignore
// +build ignore

// This file is compiled by clang into eBPF bytecode, not by the Go compiler.
// The build tag prevents Go from trying to compile it.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// XSKMAP: Special eBPF map type used by AF_XDP.
// Maps RX queue IDs to AF_XDP socket file descriptors.
//
// Key:   queue_id (u32)
// Value: socket FD (u32)
//
// Userspace inserts entries so the kernel knows
// which AF_XDP socket should receive packets for which queue.
struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64); // Maximum number of RX queues supported
    __type(key, __u32);      // Queue index
    __type(value, __u32);    // AF_XDP socket FD
} xsks_map SEC(".maps");

// XDP program entrypoint.
// Runs for every received packet at driver level.
// Extremely hot path.
SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    // Extract RX queue ID from context.
    // Each hardware RX queue has its own AF_XDP socket.
    __u32 qid = ctx->rx_queue_index;

    // Redirect packet to userspace via AF_XDP socket.
    // The map lookup selects the socket based on queue ID.
    // Equivalent to sending packet to AF_XDP socket bound to this queue.
    return bpf_redirect_map(&xsks_map, qid, 0);
}

// GPL allows access to all helper functions.
char _license[] SEC("license") = "GPL";
