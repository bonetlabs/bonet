#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#ifndef ICMPV6_ECHO_REQUEST
#define ICMPV6_ECHO_REQUEST 128
#endif

SEC("xdp")
int xdp_ipv6_ext_icmp6(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_icmp6 icmp6;
    __u32 l3_off;
    __u32 l4_off;
    __u8 type = 0;
    int ret;
    __u16 ethertype;
    __u8 ext_depth;
    __u8 l4_proto;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret || bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IPV6)
        return XDP_PASS;
    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        goto fail;
    ret = bnt_ipv6__parse(ctx, l3_off, &ip6);
    if (ret)
        goto fail;
    if (bnt_ipv6__get_ext_depth(&ip6, &ext_depth) || ext_depth != 1)
        goto fail;
    if (bnt_ipv6__get_l4_proto(&ip6, &l4_proto) || l4_proto != IPPROTO_ICMPV6)
        goto fail;
    ret = bnt_ipv6__next_off(&ip6, &l4_off);
    if (ret)
        goto fail;
    ret = bnt_icmp6__parse(ctx, l4_off, &icmp6);
    if (ret)
        goto fail;
    ret = bnt_icmp6__get_type(&icmp6, &type);
    if (ret || type != ICMPV6_ECHO_REQUEST)
        goto fail;

    bnt_test_ok(type, ICMPV6_ECHO_REQUEST);
    return XDP_DROP;

fail:
    bnt_test_fail(type, ICMPV6_ECHO_REQUEST);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
