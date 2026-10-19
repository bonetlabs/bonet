#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"

/*
 * Checksum test: IPv4 + TCP, payload strip on ingress (Machine B) via XDP.
 *
 * Loaded on Machine B XDP ingress.
 *
 * For each TCP packet to PORT_FROM this program:
 *   1. Strips PADDING_LEN bytes from the tail when the packet carries padding.
 *   2. Updates IPv4 total_len to reflect the shorter packet.
 *   3. Rewrites destination port PORT_FROM -> PORT_TO.
 *   4. Tail-calls the csum program which recomputes IPv4 and TCP checksums.
 *
 * The checksum recompute is in a separate tail-called program so that the
 * payload loop (bnt_core.h) starts with a fresh 1 000 000-instruction budget,
 * independent of the instruction count used by the main program above.
 */

#define PORT_FROM   7777
#define PORT_TO     8888
#define PADDING_LEN 16

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} prog_map SEC(".maps");

SEC("xdp")
int xdp_adjust_ipv4_tcp_ingress(struct xdp_md *ctx)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_tcp  tcp;
    __u8  proto;
    __u16 dport;
    __u16 old_total_len;
    __u32 ip_hlen;
    __u32 tcp_hlen;
    __u32 payload_len;
    __u32 l3_off, l4_off;
    bool  is_fragment;
    int   ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;
    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret)
        return XDP_PASS;

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

    ret = bnt_tcp__get_dport(&tcp, &dport);
    if (ret || dport != PORT_FROM)
        return XDP_PASS;

    ret = bnt_ipv4__get_total_len(&ip4, &old_total_len);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__get_hlen(&ip4, &ip_hlen);
    if (ret)
        return XDP_PASS;

    bnt_tcp__get_doff(&tcp, &tcp_hlen);   /* 0 on error */
    tcp_hlen *= 4;
    if (!tcp_hlen || old_total_len < ip_hlen + tcp_hlen)
        return XDP_PASS;

    payload_len = old_total_len - ip_hlen - tcp_hlen;
    if (payload_len >= PADDING_LEN) {
        if (bpf_xdp_adjust_tail(ctx, -PADDING_LEN))
            return XDP_ABORTED;

        ret = bnt_ipv4__set_total_len_no_csum(&ip4, old_total_len - PADDING_LEN);
        if (ret)
            return XDP_ABORTED;
    }

    /* Rewrite destination port for the listener */
    ret = bnt_tcp__set_dport_no_csum(&tcp, PORT_TO);
    if (ret)
        return XDP_ABORTED;

    /* Hand off checksum recompute to a fresh program with a clean budget */
    bpf_tail_call(ctx, &prog_map, 0);
    return XDP_ABORTED;
}

/* Re-parses the (already modified) packet and recomputes both checksums. */
SEC("xdp")
int xdp_adjust_ipv4_tcp_ingress_csum(struct xdp_md *ctx)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_tcp  tcp;
    __u8  proto;
    __u32 l3_off, l4_off;
    bool  is_fragment;
    int   ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret) return XDP_ABORTED;
    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP) return XDP_ABORTED;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret) return XDP_ABORTED;

    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret) return XDP_ABORTED;

    ret = bnt_ipv4__is_fragment(&ip4, &is_fragment);
    if (ret || is_fragment) return XDP_ABORTED;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret || proto != IPPROTO_TCP) return XDP_ABORTED;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret) return XDP_ABORTED;

    ret = bnt_tcp__parse(ctx, l4_off, &tcp);
    if (ret) return XDP_ABORTED;

    ret = bnt_ipv4__recompute_csum(&ip4);
    if (ret) return XDP_ABORTED;

    ret = bnt_tcp__recompute_csum(&tcp, &ip4);
    if (ret) return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
