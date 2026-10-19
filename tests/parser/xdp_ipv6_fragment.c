#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#define PORT_FROM 7777

SEC("xdp")
int xdp_ipv6_fragment(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_udp udp;
    __u32 l3_off;
    __u16 dport = 0;
    bool has_fragment = false;
    bool is_fragment = false;
    int ret;
    __u16 ethertype;
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
    ret = bnt_ipv6__has_fragment_header(&ip6, &has_fragment);
    if (ret || !has_fragment)
        goto fail;
    ret = bnt_ipv6__is_fragment(&ip6, &is_fragment);
    if (ret || !is_fragment)
        goto fail;
    if (bnt_ipv6__get_l4_proto(&ip6, &l4_proto) || l4_proto != IPPROTO_UDP)
        goto fail;

    ret = bnt_ipv6__next_udp(&ip6, &udp);
    if (ret)
        goto fail;
    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM)
        goto fail;

    bnt_test_ok((__u64)dport, PORT_FROM);
    return XDP_DROP;

fail:
    bnt_test_fail((__u64)dport, PORT_FROM);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
