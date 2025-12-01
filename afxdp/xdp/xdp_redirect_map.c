// go:build ignore
//  +build ignore

// This file is compiled by clang into eBPF bytecode, not by the Go compiler.
// The build tag prevents Go from trying to compile it.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

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

    // Drop packets not targeting UDP port 9000
    // We must safely parse:
    // - Ethernet header
    // - IPv4 header (ihl must be respected)
    // - UDP header
    // If the destination port != 9000 → DROP

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Only IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_DROP;

    // IPv4 header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Only UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_DROP;

    // Variable IP header length
    __u32 ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = (void *)((void *)ip + ip_hdr_len);

    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    // Only allow packets destined for UDP port 9000
    if (udp->dest != __constant_htons(9000))
        return XDP_DROP;

    // -------------------------------------------------------------------------
    // END of new filtering code
    // -------------------------------------------------------------------------

    // Redirect packet to userspace via AF_XDP socket.
    // The map lookup selects the socket based on queue ID.
    // Equivalent to sending packet to AF_XDP socket bound to this queue.
    return bpf_redirect_map(&xsks_map, qid, 0);
}

// GPL allows access to all helper functions.
char _license[] SEC("license") = "GPL";