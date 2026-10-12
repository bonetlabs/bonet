#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#define PORT_FROM 7777
#define PORT_TO   8888

SEC("classifier")
int tc_ipv6_udp_setters(struct __sk_buff *skb)
{
    bnt_ipv6 ip6;
    bnt_udp udp;
    __u16 payload_len = 0;
    __u16 dport = 0;
    __u32 flow = 0;
    __u8 tc = 0;
    __u8 hop = 0;
    int ret;

    ret = bnt_ctx__find_ipv6(skb, &ip6);
    if (ret)
        return TC_ACT_OK;
    if (bnt_ipv6__get_l4_proto(&ip6) != IPPROTO_UDP)
        return TC_ACT_OK;
    ret = bnt_ctx__find_udp(skb, &udp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;
    ret = bnt_ipv6__get_payload_len(&ip6, &payload_len);
    if (ret)
        goto fail;

    ret = bnt_ipv6__set_traffic_class(&ip6, 0x5a);
    if (ret)
        goto fail;
    ret = bnt_ipv6__set_flow_label(&ip6, 0xabcde);
    if (ret)
        goto fail;
    ret = bnt_ipv6__set_hop_limit(&ip6, 56);
    if (ret)
        goto fail;
    ret = bnt_ipv6__dec_hop_limit(&ip6, NULL);
    if (ret)
        goto fail;
    ret = bnt_ipv6__set_payload_len(&ip6, payload_len);
    if (ret)
        goto fail;
    ret = bnt_udp__set_dest(&udp, PORT_TO);
    if (ret)
        goto fail;

    ret = bnt_ipv6__get_traffic_class(&ip6, &tc);
    if (ret)
        goto fail;
    ret = bnt_ipv6__get_flow_label(&ip6, &flow);
    if (ret)
        goto fail;
    ret = bnt_ipv6__get_hop_limit(&ip6, &hop);
    if (ret)
        goto fail;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret)
        goto fail;
    if (tc != 0x5a || flow != 0xabcde || hop != 55 || dport != PORT_TO)
        goto fail;

    bnt_test_ok(((__u64)tc << 56) | ((__u64)hop << 48) | ((__u64)flow << 16) | dport,
                 ((__u64)0x5a << 56) | ((__u64)55 << 48) | ((__u64)0xabcde << 16) | PORT_TO);
    return TC_ACT_OK;

fail:
    bnt_test_fail(((__u64)tc << 56) | ((__u64)hop << 48) | ((__u64)flow << 16) | dport,
                   ((__u64)0x5a << 56) | ((__u64)55 << 48) | ((__u64)0xabcde << 16) | PORT_TO);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
