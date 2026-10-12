#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"

/*
 * Checksum test: IPv6 + TCP, payload strip on ingress (Machine B).
 *
 * Loaded on Machine B TC INGRESS.
 */

#define PORT_FROM   7777
#define PORT_TO     8888
#define PADDING_LEN 16

SEC("classifier")
int tc_adjust_ipv6_tcp_ingress(struct __sk_buff *skb)
{
    bnt_eth  eth;
    bnt_ipv6 ip6;
    bnt_tcp  tcp;
    __u16 dport;
    __u16 old_payload_len;
    __u32 tcp_hlen;
    __u32 data_len;
    __u32 l3_off, l4_off;
    int   ret;

    ret = bnt_eth__parse(skb, 0, &eth);
    if (ret)
        return TC_ACT_OK;
    if (bnt_eth__get_ethertype(&eth) != ETH_P_IPV6)
        return TC_ACT_OK;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_ipv6__parse(skb, l3_off, &ip6);
    if (ret)
        return TC_ACT_OK;

    if (bnt_ipv6__has_fragment_hdr(&ip6))
        return TC_ACT_OK;

    if (bnt_ipv6__get_l4_proto(&ip6) != IPPROTO_TCP)
        return TC_ACT_OK;

    ret = bnt_ipv6__next_off(&ip6, &l4_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_tcp__parse(skb, l4_off, &tcp);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_tcp__get_dest(&tcp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    ret = bnt_ipv6__get_payload_len(&ip6, &old_payload_len);
    if (ret)
        return TC_ACT_OK;

    tcp_hlen = bnt_tcp__get_doff(&tcp) * 4;
    if (!tcp_hlen || old_payload_len < tcp_hlen)
        return TC_ACT_OK;

    data_len = old_payload_len - tcp_hlen;
    if (data_len >= PADDING_LEN) {
        if (bpf_skb_change_tail(skb, skb->len - PADDING_LEN, 0))
            return TC_ACT_SHOT;

        ret = bnt_ipv6__set_payload_len_no_csum(&ip6, old_payload_len - PADDING_LEN);
        if (ret)
            return TC_ACT_SHOT;
    }

    ret = bnt_tcp__set_dest_no_csum(&tcp, PORT_TO);
    if (ret)
        return TC_ACT_SHOT;

    /* Recompute: shorter payload + new port, IPv6 pseudo-header */
    ret = bnt_tcp__recompute_csum6(&tcp, &ip6);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
