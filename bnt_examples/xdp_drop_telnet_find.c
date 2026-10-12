#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"

/*
 * Example: TCP lookup from ctx using the high-level bnt_ctx__find_tcp() helper.
 *
 * Validation goal:
 *   - exercises bnt_ctx__find_tcp()
 *   - demonstrates the optional ctx-level walker without declaring Ethernet,
 *     IPv4, or IPv6 intermediate views in the caller
 *
 * Behavior:
 *   - drops TCP SYN packets destined to port 23 (Telnet) on supported stacks
 *   - passes everything else unchanged
 */
SEC("xdp")
int xdp_drop_telnet_syn_find(struct xdp_md *ctx)
{
    bnt_tcp tcp;
    __u16 dport;
    __u16 flags;
    int ret;

    /* One call replaces the whole Ethernet/VLAN -> IPv4-or-IPv6 -> TCP walk
     * from xdp_drop_telnet.c; fragments, non-TCP, and unsupported stacks all
     * fold into this single non-zero return. */
    ret = bnt_ctx__find_tcp(ctx, &tcp);
    if (ret)
        return XDP_PASS;

    ret = bnt_tcp__get_dest(&tcp, &dport);
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
