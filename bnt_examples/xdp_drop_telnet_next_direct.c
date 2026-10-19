#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"

/*
 * Example: Ethernet -> IPv4 -> TCP using explicit typed next helpers.
 *
 * Validation goal:
 *   - exercises bnt_eth__next_ipv4() and bnt_ipv4__next_tcp()
 *   - exercises TCP getters after direct typed parsing
 *
 * Behavior:
 *   - drops IPv4/TCP SYN packets destined to port 23 (Telnet)
 *   - passes everything else unchanged
 */
SEC("xdp")
int xdp_drop_telnet_syn_next_direct(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_tcp tcp;
    __u16 dport;
    __u16 flags;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    /* Typed calls spelled out explicitly; xdp_drop_telnet_next_macro.c does
     * the same walk through the type-dispatched next_header() macro instead. */
    ret = bnt_eth__next_ipv4(&eth, &ip4);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__next_tcp(&ip4, &tcp);
    if (ret)
        return XDP_PASS;

    ret = bnt_tcp__get_dport(&tcp, &dport);
    if (ret)
        return XDP_PASS;

    ret = bnt_tcp__get_flags(&tcp, &flags);
    if (ret)
        return XDP_PASS;

    if (dport == 23 && (flags & BNT_TCP_SYN)) {
        bpf_printk("TCP dport=%d flags=%x\n", dport, flags);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
