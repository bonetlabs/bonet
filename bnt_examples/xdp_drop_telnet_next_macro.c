#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"

/*
 * Example: Ethernet -> IPv4 -> TCP using bnt_*__next_header().
 *
 * Validation goal:
 *   - exercises typed next-header macro dispatch
 *   - exercises TCP getters after macro-dispatched parsing
 *
 * Behavior:
 *   - drops IPv4/TCP SYN packets destined to port 23 (Telnet)
 *   - passes everything else unchanged
 */
SEC("xdp")
int xdp_drop_telnet_syn_next_macro(struct xdp_md *ctx)
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

    /* picks bnt_eth__next_ipv4() at compile time from the type of &ip4 */
    ret = bnt_eth__next_header(&eth, &ip4);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__next_header(&ip4, &tcp);
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
