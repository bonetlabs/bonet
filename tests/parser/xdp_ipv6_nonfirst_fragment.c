#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

SEC("xdp")
int xdp_ipv6_nonfirst_fragment(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_udp udp;
    __u32 l3_off;
    __u32 l4_off;
    bool is_fragment = false;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret || bnt_eth__get_ethertype(&eth) != ETH_P_IPV6)
        return XDP_PASS;
    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        goto fail;
    ret = bnt_ipv6__parse(ctx, l3_off, &ip6);
    if (ret)
        goto fail;
    ret = bnt_ipv6__is_fragmented(&ip6, &is_fragment);
    if (ret || !is_fragment)
        goto fail;
    if (bnt_ipv6__get_l4_proto(&ip6) != 0)
        goto fail;

    ret = bnt_ipv6__next_off(&ip6, &l4_off);
    if (ret != BNT_ERR_FRAGMENT)
        goto fail;
    ret = bnt_ipv6__next_udp(&ip6, &udp);
    if (ret != BNT_ERR_FRAGMENT)
        goto fail;

    bnt_test_ok((__u64)is_fragment, 1);
    return XDP_DROP;

fail:
    bnt_test_fail((__u64)ret, BNT_ERR_FRAGMENT);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
