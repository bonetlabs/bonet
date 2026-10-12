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
 * Checksum test: IPv4 + TCP, incremental updates.
 *
 * Loaded on Machine B TC ingress.
 * Machine A sends TCP to Machine B port PORT_FROM.
 * This program rewrites TTL (tests IPv4 header checksum) and the
 * destination port (tests TCP checksum) using incremental updates.
 * Machine B listens on PORT_TO; reception confirms correct checksums.
 */

#define PORT_FROM 7777
#define PORT_TO   8888
#define NEW_TTL   200

SEC("classifier")
int tc_csum_ipv4_tcp_inc(struct __sk_buff *skb)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_tcp  tcp;
    __u8  proto;
    __u16 dport;
    __u32 l3_off, l4_off;
    int   is_fragment;
    int   ret;

    ret = bnt_eth__parse(skb, 0, &eth);
    if (ret)
        return TC_ACT_OK;
    if (bnt_eth__get_ethertype(&eth) != ETH_P_IP)
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

    ret = bnt_tcp__get_dest(&tcp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    /* Incremental: TTL change updates IPv4 header checksum */
    ret = bnt_ipv4__set_ttl(&ip4, NEW_TTL);
    if (ret)
        return TC_ACT_SHOT;

    /* Incremental: port change updates TCP checksum */
    ret = bnt_tcp__set_dest(&tcp, PORT_TO);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
