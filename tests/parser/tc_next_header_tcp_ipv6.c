#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#define PORT_FROM 7777

SEC("classifier")
int tc_next_header_tcp_ipv6(struct __sk_buff *skb)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_tcp tcp;
    __u16 dport = 0;
    int ret;

    ret = bnt_eth__parse(skb, 0, &eth);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_eth__next_header(&eth, &ip6);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_ipv6__next_header(&ip6, &tcp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_tcp__get_dport(&tcp, &dport);
    if (ret || dport != PORT_FROM) {
        bnt_test_fail(dport, PORT_FROM);
        return TC_ACT_OK;
    }

    bnt_test_ok(dport, PORT_FROM);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
