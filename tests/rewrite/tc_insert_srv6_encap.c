#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#define PORT_FROM 7777

SEC("classifier")
int tc_insert_srv6_encap(struct __sk_buff *skb)
{
    const __u8 seg_addr[16] = {
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    bnt_eth eth;
    bnt_ipv6 outer;
    bnt_udp udp;
    struct in6_addr segs[1];
    __u16 inner_ethertype;
    __u8 inner_nexthdr;
    __u16 dport = 0;
    int ret;

    ret = bnt_ctx__find_udp(skb, &udp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    __builtin_memcpy(&segs[0], seg_addr, sizeof(segs[0]));
    ret = bnt_eth__parse(skb, 0, &eth);
    if (ret)
        goto fail;
    inner_ethertype = bnt_eth__get_ethertype(&eth);
    if (inner_ethertype == ETH_P_IP)
        inner_nexthdr = IPPROTO_IPIP;
    else if (inner_ethertype == ETH_P_IPV6)
        inner_nexthdr = IPPROTO_IPV6;
    else
        goto fail;
    ret = bnt_eth__insert_ipv6(&eth, inner_nexthdr, &segs[0], &segs[0]);
    if (ret)
        goto fail;
    ret = bnt_eth__next_ipv6(&eth, &outer);
    if (ret)
        goto fail;
    ret = bnt_ipv6__insert_srh(&outer, segs, 1);
    if (ret)
        goto fail;

    /* After encap: Eth -> outer IPv6 (nexthdr=43) -> SRH (nexthdr=4) -> inner IPv4 -> UDP. */
    {
        bnt_ipv6 ip6;
        bnt_ipv4 ip4_inner;
        ret = bnt_eth__parse(skb, 0, &eth);
        if (ret)
            goto fail;
        ret = bnt_eth__next_header(&eth, &ip6);
        if (ret)
            goto fail;
        ret = bnt_ipv6__next_header(&ip6, &ip4_inner);
        if (ret)
            goto fail;
        ret = bnt_ipv4__next_header(&ip4_inner, &udp);
        if (ret)
            goto fail;
    }
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        goto fail;

    bnt_test_ok(dport, PORT_FROM);
    return TC_ACT_OK;

fail:
    bnt_test_fail(dport, PORT_FROM);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
