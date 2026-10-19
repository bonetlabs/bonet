#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"

/*
 * Checksum test: IPv4 + UDP, payload strip on ingress (Machine B) via XDP.
 *
 * Loaded on Machine B XDP ingress.
 *
 * When the packet carries padding, both IPv4 total_len and UDP len are
 * decremented before recompute.
 */

#define PORT_FROM   7777
#define PORT_TO     8888
#define PADDING_LEN 16

SEC("xdp")
int xdp_adjust_ipv4_udp_ingress(struct xdp_md *ctx)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_udp  udp;
    __u8  proto;
    __u16 dport;
    __u16 old_total_len;
    __u16 old_udp_len;
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
    if (ret || proto != IPPROTO_UDP)
        return XDP_PASS;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_udp__parse(ctx, l4_off, &udp);
    if (ret)
        return XDP_PASS;

    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return XDP_PASS;

    ret = bnt_ipv4__get_total_len(&ip4, &old_total_len);
    if (ret)
        return XDP_PASS;

    ret = bnt_udp__get_len(&udp, &old_udp_len);
    if (ret)
        return XDP_PASS;

    if (old_udp_len >= sizeof(struct udphdr) + PADDING_LEN) {
        if (bpf_xdp_adjust_tail(ctx, -PADDING_LEN))
            return XDP_ABORTED;

        ret = bnt_ipv4__set_total_len_no_csum(&ip4, old_total_len - PADDING_LEN);
        if (ret)
            return XDP_ABORTED;

        ret = bnt_udp__set_len_no_csum(&udp, old_udp_len - PADDING_LEN);
        if (ret)
            return XDP_ABORTED;
    }

    /* Rewrite destination port for the listener */
    ret = bnt_udp__set_dport_no_csum(&udp, PORT_TO);
    if (ret)
        return XDP_ABORTED;

    /* Recompute checksums: shorter payload + new port */
    ret = bnt_ipv4__recompute_csum(&ip4);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_udp__recompute_csum(&udp, &ip4);
    if (ret)
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
