#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_tc_ingress.h>

static const __be32 old_ip = BNT_IPV4(192, 168, 1, 100);
static const __be32 new_ip = BNT_IPV4(10, 0, 0, 2);

SEC("classifier")
int tc_ipv4_dnat(struct __sk_buff *skb)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_tcp tcp;
    bnt_udp udp;
    __be32 daddr;
    __u16 dport;
    __u32 l4_off;
    __u8 proto;

    if (bnt_eth__parse(skb, 0, &eth))
        return TC_ACT_OK;
    if (bnt_eth__next_ipv4(&eth, &ip4))
        return TC_ACT_OK;
    if (bnt_ipv4__get_daddr(&ip4, &daddr) || daddr != old_ip)
        return TC_ACT_OK;
    if (bnt_ipv4__next_proto_off(&ip4, &proto, &l4_off))
        return TC_ACT_OK;

    if (proto == IPPROTO_TCP) {
        bnt_tcp__parse(skb, l4_off, &tcp);
        if (bnt_tcp__get_dport(&tcp, &dport))
            return TC_ACT_OK;
        if (dport == 443 && bnt_tcp__set_dport(&tcp, 8443))
            return TC_ACT_SHOT;
    } else if (proto == IPPROTO_UDP) {
        bnt_udp__parse(skb, l4_off, &udp);
        if (bnt_udp__get_dport(&udp, &dport))
            return TC_ACT_OK;
        if (dport == 53 && bnt_udp__set_dport(&udp, 1053))
            return TC_ACT_SHOT;
    }

    if (bnt_ipv4__set_daddr(&ip4, new_ip))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
