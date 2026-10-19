#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#define PORT_FROM 7777

SEC("xdp")
int xdp_ipv4_fragment(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_udp udp;
    __u32 l3_off;
    __u32 l4_off;
    __u16 dport = 0;
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
    if (ret)
        goto fail;
    ret = bnt_udp__parse(ctx, l4_off, &udp);
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
