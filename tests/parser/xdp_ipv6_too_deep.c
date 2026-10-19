#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

SEC("xdp")
int xdp_ipv6_too_deep(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    __u32 l3_off;
    __u32 l4_off;
    int ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret || bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IPV6)
        return XDP_PASS;
    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        goto fail;
    ret = bnt_ipv6__parse(ctx, l3_off, &ip6);
    if (ret)
        goto fail;
    ret = bnt_ipv6__next_off(&ip6, &l4_off);
    if (ret == BNT_ERR_TOO_DEEP) {
        bnt_test_ok(BNT_ERR_TOO_DEEP, BNT_ERR_TOO_DEEP);
        return XDP_DROP;
    }

fail:
    bnt_test_fail((__u64)ret, BNT_ERR_TOO_DEEP);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
