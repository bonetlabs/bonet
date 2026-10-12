#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example: SRv6 H.Insert — add a Segment Routing Header to IPv6/UDP traffic.
 *
 * Validation goal:
 *   - validates bnt_ipv6__insert_srh()
 *
 * Behavior:
 *   - for UDP traffic on port 5353, inserts a 2-segment SRH right after the
 *     IPv6 base header
 *   - leaves all other traffic unchanged
 */
SEC("xdp")
int xdp_insert_srh(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_udp udp;
    __u16 dport;
    __u32 l3_off;
    __u32 l4_off;
    int ret;

    /* Segments in forward visitation order: the packet reaches segs[0]
     * first, then segs[1]. */
    struct in6_addr segs[2] = {
        { .in6_u.u6_addr8 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 1 } },
        { .in6_u.u6_addr8 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 2 } },
    };

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    if (bnt_eth__get_ethertype(&eth) != ETH_P_IPV6)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv6__parse(ctx, l3_off, &ip6);
    if (ret)
        return XDP_PASS;

    if (bnt_ipv6__get_l4_proto(&ip6) != IPPROTO_UDP)
        return XDP_PASS;

    ret = bnt_ipv6__next_off(&ip6, &l4_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_udp__parse(ctx, l4_off, &udp);
    if (ret)
        return XDP_PASS;

    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != 5353)
        return XDP_PASS;

    /* insert_srh() shifts everything after the IPv6 base header forward;
     * the udp view above is now stale and isn't reused after this call. */
    ret = bnt_ipv6__insert_srh(&ip6, segs, 2);
    if (ret)
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
