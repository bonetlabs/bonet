#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"

/*
 * Checksum test: IPv4 + TCP, payload strip on ingress (Machine B).
 *
 * Loaded on Machine B TC INGRESS.
 *
 * For each TCP packet to PORT_FROM this program:
 *   1. Strips PADDING_LEN bytes from the tail when the packet carries padding.
 *   2. Updates IPv4 total_len to reflect the shorter packet.
 *   3. Rewrites destination port PORT_FROM -> PORT_TO.
 *   4. Full recomputes IPv4 and TCP checksums over the shorter packet.
 *
 * If the kernel delivers the packet to PORT_TO, the ingress recompute over
 * the modified packet was correct.
 */

#define PORT_FROM   7777
#define PORT_TO     8888
#define PADDING_LEN 16

SEC("classifier")
int tc_adjust_ipv4_tcp_ingress(struct __sk_buff *skb)
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

    ret = bnt_eth__parse(skb, 0, &eth);
    if (ret)
        return TC_ACT_OK;
    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return TC_ACT_OK;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_ipv4__parse(skb, l3_off, &ip4);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_ipv4__is_fragment(&ip4, &is_fragment);
    if (ret || is_fragment)
        return TC_ACT_OK;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret || proto != IPPROTO_TCP)
        return TC_ACT_OK;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_tcp__parse(skb, l4_off, &tcp);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_tcp__get_dport(&tcp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    ret = bnt_ipv4__get_total_len(&ip4, &old_total_len);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_ipv4__get_hlen(&ip4, &ip_hlen);
    if (ret)
        return TC_ACT_OK;

    bnt_tcp__get_doff(&tcp, &tcp_hlen);   /* 0 on error */
    tcp_hlen *= 4;
    if (!tcp_hlen)
        return TC_ACT_OK;
    if (old_total_len < ip_hlen + tcp_hlen)
        return TC_ACT_OK;

    payload_len = old_total_len - ip_hlen - tcp_hlen;
    if (payload_len >= PADDING_LEN) {
        if (bpf_skb_change_tail(skb, skb->len - PADDING_LEN, 0))
            return TC_ACT_SHOT;

        ret = bnt_ipv4__set_total_len_no_csum(&ip4, old_total_len - PADDING_LEN);
        if (ret)
            return TC_ACT_SHOT;
    }

    /* Rewrite destination port for the listener */
    ret = bnt_tcp__set_dport_no_csum(&tcp, PORT_TO);
    if (ret)
        return TC_ACT_SHOT;

    /* Recompute checksums: shorter payload + new port */
    ret = bnt_ipv4__recompute_csum(&ip4);
    if (ret)
        return TC_ACT_SHOT;

    ret = bnt_tcp__recompute_csum(&tcp, &ip4);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
