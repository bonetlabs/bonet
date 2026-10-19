#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"

/*
 * Checksum test: IPv6 + UDP, incremental updates.
 *
 * Same scenario as tc_csum_ipv6_tcp_inc but for UDP traffic.
 * Machine A sends UDP to Machine B IPv6 port PORT_FROM.
 * Machine B listens on PORT_TO.
 */

#define PORT_FROM 7777
#define PORT_TO   8888

static const __u8 fake_saddr6[16] = {
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef
};

SEC("classifier")
int tc_csum_ipv6_udp_inc(struct __sk_buff *skb)
{
    bnt_eth  eth;
    bnt_ipv6 ip6;
    bnt_udp  udp;
    __u16 dport;
    __u32 l3_off, l4_off;
    int   ret;
    bool  has_frag;
    __u16 ethertype;
    __u8 l4_proto;

    ret = bnt_eth__parse(skb, 0, &eth);
    if (ret)
        return TC_ACT_OK;
    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IPV6)
        return TC_ACT_OK;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_ipv6__parse(skb, l3_off, &ip6);
    if (ret)
        return TC_ACT_OK;

    if (bnt_ipv6__has_fragment_header(&ip6, &has_frag) || has_frag)
        return TC_ACT_OK;

    if (bnt_ipv6__get_l4_proto(&ip6, &l4_proto) || l4_proto != IPPROTO_UDP)
        return TC_ACT_OK;

    ret = bnt_ipv6__next_off(&ip6, &l4_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_udp__parse(skb, l4_off, &udp);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    /* Incremental: source IPv6 rewrite updates UDP pseudo-header checksum */
    ret = bnt_ipv6__set_saddr(&ip6, (const struct in6_addr *)fake_saddr6);
    if (ret)
        return TC_ACT_SHOT;

    /* Incremental: port change updates UDP checksum field */
    ret = bnt_udp__set_dport(&udp, PORT_TO);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
