#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

SEC("xdp")
int xdp_ipv4_nonfirst_fragment(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_udp udp;
    __u32 l3_off;
    __u32 l4_off;
    bool is_fragment = false;
    int ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret || bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return XDP_PASS;
    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        goto fail;
    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret)
        goto fail;
    ret = bnt_ipv4__is_fragment(&ip4, &is_fragment);
    if (ret || !is_fragment)
        goto fail;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret != BNT_ERR_FRAGMENT)
        goto fail;
    ret = bnt_ipv4__next_udp(&ip4, &udp);
    if (ret != BNT_ERR_FRAGMENT)
        goto fail;

    bnt_test_ok((__u64)is_fragment, 1);
    return XDP_DROP;

fail:
    bnt_test_fail((__u64)ret, BNT_ERR_FRAGMENT);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
