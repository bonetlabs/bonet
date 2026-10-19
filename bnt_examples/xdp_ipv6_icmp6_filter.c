#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example 3: IPv6 + extension-header-aware ICMPv6 filter.
 *
 * Validation goal:
 *   - validates bnt_ipv6__parse() bounded extension-header walk
 *   - validates bnt_icmp6__parse()
 *   - validates that fragment headers are handled conservatively
 *
 * Behavior:
 *   - drops ICMPv6 Echo Request packets
 *   - passes all fragmented IPv6 packets unchanged
 *   - passes non-ICMPv6 traffic unchanged
 */
SEC("xdp")
int xdp_drop_icmp6_echo(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_icmp6 icmp6;
    __u8 type;
    __u32 l3_off;
    __u32 l4_off;
    int ret;
    bool has_frag;
    __u16 ethertype;
    __u8 l4_proto;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IPV6)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv6__parse(ctx, l3_off, &ip6);
    if (ret)
        return XDP_PASS;

    /* every fragment passes, the first too (it carries the ICMPv6 header) */
    if (bnt_ipv6__has_fragment_header(&ip6, &has_frag) || has_frag)
        return XDP_PASS;

    /* get_l4_proto() is the protocol past any extension headers, not the
     * IPv6 header's own next-header field. */
    if (bnt_ipv6__get_l4_proto(&ip6, &l4_proto) || l4_proto != IPPROTO_ICMPV6)
        return XDP_PASS;

    ret = bnt_ipv6__next_off(&ip6, &l4_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_icmp6__parse(ctx, l4_off, &icmp6);
    if (ret)
        return XDP_PASS;

    ret = bnt_icmp6__get_type(&icmp6, &type);
    if (ret)
        return XDP_PASS;

    if (type == ICMPV6_ECHO_REQUEST)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
