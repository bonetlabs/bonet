#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "bnt_debug.h"

static __always_inline void debug_vlans_printk(const bnt_eth *eth)
{
    __u8 depth;
    __u32 i;

    bnt_eth__get_vlan_depth(eth, &depth);   /* 0 on error */
#pragma unroll
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        if (i < depth)
            bnt_dbg_vlan__printk(eth, i);
    }
}

SEC("xdp")
int xdp_drop_telnet_syn_debug_printk(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_tcp tcp;
    __u16 dport;
    __u16 flags;
    __u8 proto;
    __u32 l3_off;
    __u32 l4_off;
    bool is_fragment;
    int ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;
    bnt_dbg_eth__printk(&eth);
    debug_vlans_printk(&eth);

    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret)
        return XDP_PASS;
    bnt_dbg_ipv4__printk(&ip4);

    ret = bnt_ipv4__is_fragment(&ip4, &is_fragment);
    if (ret || is_fragment)
        return XDP_PASS;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret || proto != IPPROTO_TCP)
        return XDP_PASS;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_tcp__parse(ctx, l4_off, &tcp);
    if (ret)
        return XDP_PASS;
    bnt_dbg_tcp__printk(&tcp);

    ret = bnt_tcp__get_dport(&tcp, &dport);
    if (ret)
        return XDP_PASS;

    ret = bnt_tcp__get_flags(&tcp, &flags);
    if (ret)
        return XDP_PASS;

    if (dport == 23 && (flags & BNT_TCP_SYN))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
