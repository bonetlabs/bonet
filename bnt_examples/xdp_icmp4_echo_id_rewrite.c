#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

/*
 * Example 7: ICMPv4 echo identifier rewrite.
 *
 * Validation goal:
 *   - validates bnt_icmp4__parse()
 *   - validates bnt_icmp4__get_type() and bnt_icmp4__set_echo_id()
 *   - validates ICMPv4 checksum update after a field rewrite
 *
 * Behavior:
 *   - rewrites the ICMP echo identifier to 0x1234
 *   - only acts on non-fragmented IPv4 echo requests
 */
SEC("xdp")
int xdp_icmp4_echo_id_rewrite(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_icmp4 icmp4;
    __u8 type;
    __u8 proto;
    __u32 l3_off;
    __u32 l4_off;
    bool is_fragment;
    int ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__is_fragment(&ip4, &is_fragment);
    if (ret || is_fragment)
        return XDP_PASS;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret || proto != IPPROTO_ICMP)
        return XDP_PASS;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_icmp4__parse(ctx, l4_off, &icmp4);
    if (ret)
        return XDP_PASS;

    ret = bnt_icmp4__get_type(&icmp4, &type);
    if (ret)
        return XDP_PASS;

    /* the echo identifier exists only in Echo Request/Reply */
    if (type != ICMP_ECHO)
        return XDP_PASS;

    /* ICMPv4 has no pseudo-header, so no IPv4 view is needed */
    ret = bnt_icmp4__set_echo_id(&icmp4, 0x1234);
    if (ret)
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
