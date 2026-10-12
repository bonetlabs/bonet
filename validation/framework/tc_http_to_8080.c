#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_tc_ingress.h>

SEC("classifier")
int tc_http_to_8080(struct __sk_buff *skb)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_ipv6 ip6;
    bnt_tcp tcp;
    __u16 dport;

    if (bnt_eth__parse(skb, 0, &eth))
        return TC_ACT_OK;

    if (!bnt_eth__next_ipv4(&eth, &ip4)) {
        if (bnt_ipv4__next_tcp(&ip4, &tcp))
            return TC_ACT_OK;
    } else if (!bnt_eth__next_ipv6(&eth, &ip6)) {
        if (bnt_ipv6__next_tcp(&ip6, &tcp))
            return TC_ACT_OK;
    } else {
        return TC_ACT_OK;
    }

    if (bnt_tcp__get_dest(&tcp, &dport) || dport != 80)
        return TC_ACT_OK;

    if (bnt_tcp__set_dest(&tcp, 8080))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
