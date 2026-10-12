#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example 1: basic parser chain for Ethernet -> IPv4 -> TCP.
 *
 * Validation goal:
 *   - exercises bnt_eth__parse(), bnt_ipv4__parse(), bnt_tcp__parse()
 *   - exercises TCP getters and fragment-safe handling
 *
 * Behavior:
 *   - drops IPv4/TCP SYN packets destined to port 23 (Telnet)
 *   - passes everything else unchanged
 */
SEC("xdp")
int xdp_drop_telnet_syn(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_tcp tcp;
    __u16 dport;
    __u16 flags;
    __u8 proto;
    __u32 l3_off;
    __u32 l4_off;
    int is_fragment;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    /* get_ethertype() resolves past any VLAN tags; non-IPv4 traffic is out
     * of scope for this example, not an error. */
    if (bnt_eth__get_ethertype(&eth) != ETH_P_IP)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret)
        return XDP_PASS;

    /* A non-first fragment carries no TCP header at this offset; let it
     * through rather than misreading fragment payload as a TCP header. */
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

    ret = bnt_tcp__get_dest(&tcp, &dport);
    if (ret)
        return XDP_PASS;

    ret = bnt_tcp__get_flags(&tcp, &flags);
    if (ret)
        return XDP_PASS;

    /* SYN-only: blocks new connections without resetting ones already
     * established before this program was attached. */
    if (dport == 23 && (flags & BNT_TCP_SYN))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
