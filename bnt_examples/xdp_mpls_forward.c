#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example: MPLS label stack walk with TTL handling.
 *
 * Validation goal:
 *   - validates bnt_eth__next_mpls(), bnt_mpls__get_ttl()/set_ttl()
 *   - validates bnt_mpls__is_bos() and bnt_mpls__next_mpls() (stack walk)
 *   - validates bnt_mpls__next_ipv4()/next_ipv6() (reaching the payload)
 *
 * Behavior:
 *   - drops the packet if the top label's TTL is <= 1
 *   - otherwise decrements the top label's TTL
 *   - walks down to the bottom of the stack and logs whether the payload
 *     underneath is IPv4 or IPv6
 */
#define MPLS_MAX_WALK 8   /* caller-chosen bound: the library imposes none */

SEC("xdp")
int xdp_mpls_forward(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_mpls label;
    bnt_mpls next;
    bnt_ipv4 ip4;
    bnt_ipv6 ip6;
    __u8 ttl;
    bool bos;
    int ret;
    int i;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    ret = bnt_eth__next_mpls(&eth, &label);
    if (ret)
        return XDP_PASS;

    ret = bnt_mpls__get_ttl(&label, &ttl);
    if (ret)
        return XDP_PASS;

    /* Same convention as bnt_ipv4__dec_ttl()/bnt_ipv6__dec_hop_limit(): a
     * label switch router refuses to forward once TTL would reach 0. */
    if (ttl <= 1)
        return XDP_DROP;

    ret = bnt_mpls__set_ttl(&label, ttl - 1);
    if (ret)
        return XDP_ABORTED;

    /* Unlike the VLAN tag count or IPv6 extension headers, the label stack
     * has no library-imposed depth bound; the caller picks and enforces its
     * own, here a small constant for #pragma unroll. */
    ret = bnt_mpls__is_bos(&label, &bos);
    if (ret)
        return XDP_ABORTED;

#pragma unroll
    for (i = 0; i < MPLS_MAX_WALK; i++) {
        if (bos)
            break;
        ret = bnt_mpls__next_mpls(&label, &next);
        if (ret)
            return XDP_ABORTED;
        label = next;
        ret = bnt_mpls__is_bos(&label, &bos);
        if (ret)
            return XDP_ABORTED;
    }
    /* A stack deeper than MPLS_MAX_WALK is this program's own scope limit,
     * not a malformed packet; pass it on rather than treat it as an error. */
    if (!bos)
        return XDP_PASS;

    if (bnt_mpls__next_ipv4(&label, &ip4) == BNT_OK)
        bpf_printk("MPLS payload: IPv4\n");
    else if (bnt_mpls__next_ipv6(&label, &ip6) == BNT_OK)
        bpf_printk("MPLS payload: IPv6\n");

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
