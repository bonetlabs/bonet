#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"

/*
 * Checksum test: IPv4 + UDP, full recompute.
 *
 * Same scenario as tc_csum_ipv4_udp_inc but uses set_*_no_csum()
 * followed by recompute_csum() instead of incremental updates.
 */

#define PORT_FROM 7777
#define PORT_TO   8888
#define NEW_TTL   200

SEC("classifier")
int tc_csum_ipv4_udp_full(struct __sk_buff *skb)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_udp  udp;
    __u8  proto;
    __u16 dport;
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
    if (ret || proto != IPPROTO_UDP)
        return TC_ACT_OK;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_udp__parse(skb, l4_off, &udp);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    /* Write fields without touching checksums */
    ret = bnt_ipv4__set_ttl_no_csum(&ip4, NEW_TTL);
    if (ret)
        return TC_ACT_SHOT;
    ret = bnt_udp__set_dport_no_csum(&udp, PORT_TO);
    if (ret)
        return TC_ACT_SHOT;

    /* Full recompute: IPv4 header, then UDP header+payload */
    ret = bnt_ipv4__recompute_csum(&ip4);
    if (ret)
        return TC_ACT_SHOT;
    ret = bnt_udp__recompute_csum4(&udp, &ip4);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
