#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_egress.h"

/*
 * Egress counterpart of tc_csum_ipv4_tcp_full.
 *
 * Loaded on Machine B TC egress.
 * Rewrites sport 8888→7777 so Machine A's TCP stack accepts the SYN/ACK.
 *
 * On TC egress ip_summed=CHECKSUM_PARTIAL: the TCP checksum field holds only
 * the pseudo-header sum P.  skb_checksum_help computes the final checksum
 * after TC egress using P as the initial seed. So the checksum field is left
 * alone: rewriting the port bytes is enough.
 */

#define PORT_FROM 7777
#define PORT_TO   8888

SEC("classifier")
int tc_csum_ipv4_tcp_full_egress(struct __sk_buff *skb)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_tcp  tcp;
    __u8  proto;
    __u16 sport;
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

    ret = bnt_tcp__get_sport(&tcp, &sport);
    if (ret || sport != PORT_TO)
        return TC_ACT_OK;

    ret = bnt_tcp__set_sport(&tcp, PORT_FROM);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
