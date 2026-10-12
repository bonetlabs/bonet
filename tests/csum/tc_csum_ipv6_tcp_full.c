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
 * Checksum test: IPv6 + TCP, full recompute.
 *
 * Same scenario as tc_csum_ipv6_tcp_inc but uses set_*_no_csum()
 * followed by bnt_tcp__recompute_csum6() which recalculates the
 * TCP checksum from scratch using the IPv6 pseudo-header.
 */

#define PORT_FROM 7777
#define PORT_TO   8888

static const __u8 fake_saddr6[16] = {
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef
};

SEC("classifier")
int tc_csum_ipv6_tcp_full(struct __sk_buff *skb)
{
    bnt_eth  eth;
    bnt_ipv6 ip6;
    bnt_tcp  tcp;
    __u16 dport;
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

    /* Write fields without touching checksums */
    ret = bnt_ipv6__set_saddr_no_csum(&ip6, (const struct in6_addr *)fake_saddr6);
    if (ret)
        return TC_ACT_SHOT;
    ret = bnt_tcp__set_dest_no_csum(&tcp, PORT_TO);
    if (ret)
        return TC_ACT_SHOT;

    /* Full recompute from scratch using IPv6 pseudo-header */
    ret = bnt_tcp__recompute_csum6(&tcp, &ip6);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
