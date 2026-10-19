#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

static const __be32 outer_src = bpf_htonl(0x0a000001); /* 10.0.0.1 */
static const __be32 outer_dst = bpf_htonl(0x0a000002); /* 10.0.0.2 */

/*
 * Example: insert a base IPv4 header after Ethernet/VLAN.
 *
 * The existing Ethernet payload must be IPv4. The new outer IPv4 header uses
 * protocol IPPROTO_IPIP; callers can retrieve it with bnt_eth__next_ipv4()
 * after insertion and apply further bnt_ipv4__set_* customisation if needed.
 */
SEC("xdp")
int xdp_insert_ipv4_outer(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 inner;
    bnt_ipv4 outer;
    __u16 inner_len;
    __u32 inner_hlen;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_ipv4(&eth, &inner))
        return XDP_PASS;
    if (bnt_ipv4__get_hlen(&inner, &inner_hlen) ||
        bnt_ipv4__get_total_len(&inner, &inner_len))
        return XDP_PASS;
    /* insert_ipv4() derives the outer total_len from the packet size: reject
     * inner options and a length that would overflow it */
    if (inner_hlen != sizeof(struct iphdr) ||
        inner_len > 0xffff - sizeof(struct iphdr))
        return XDP_PASS;

    if (bnt_eth__insert_ipv4(&eth, IPPROTO_IPIP, outer_src, outer_dst))
        return XDP_ABORTED;
    /* the insert leaves inner stale; eth stays valid */
    if (bnt_eth__next_ipv4(&eth, &outer))
        return XDP_ABORTED;

    /* Optional post-insert customisation through the ordinary IPv4 setters. */
    if (bnt_ipv4__set_tos(&outer, 0x2e))
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
