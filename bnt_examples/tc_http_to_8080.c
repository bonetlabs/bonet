#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_tc_ingress.h"

/*
 * Example 4: TC ingress/egress TCP destination-port rewrite.
 *
 * Validation goal:
 *   - validates dual-stack dispatch (IPv4 and IPv6)
 *   - validates bnt_tcp__set_dport() checksum adjustment on skb packets
 *
 * Behavior:
 *   - rewrites TCP destination port 80 to 8080
 *   - leaves all other traffic untouched
 */
SEC("classifier")
int tc_http_to_8080(struct __sk_buff *skb)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_ipv6 ip6;
    bnt_tcp tcp;
    __u16 dport;
    __u16 ethertype;
    __u8 proto;
    __u32 l3_off;
    __u32 l4_off;
    bool is_fragment;
    int ret;
    bool has_frag;
        __u8 l4_proto;

    /* Same call as the XDP examples; only the context type (struct
     * __sk_buff *) and the included backend header change. */
    ret = bnt_eth__parse(skb, 0, &eth);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return TC_ACT_OK;

    bnt_eth__get_ethertype(&eth, &ethertype);
    if (ethertype == ETH_P_IP) {
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
    } else if (ethertype == ETH_P_IPV6) {
        ret = bnt_ipv6__parse(skb, l3_off, &ip6);
        if (ret || bnt_ipv6__has_fragment_header(&ip6, &has_frag) || has_frag)
            return TC_ACT_OK;
        if (bnt_ipv6__get_l4_proto(&ip6, &l4_proto) || l4_proto != IPPROTO_TCP)
            return TC_ACT_OK;
        ret = bnt_ipv6__next_off(&ip6, &l4_off);
        if (ret)
            return TC_ACT_OK;
        ret = bnt_tcp__parse(skb, l4_off, &tcp);
        if (ret)
            return TC_ACT_OK;
    } else {
        return TC_ACT_OK;
    }

    ret = bnt_tcp__get_dport(&tcp, &dport);
    if (ret)
        return TC_ACT_OK;

    if (dport != 80)
        return TC_ACT_OK;

    /* host byte order; also fixes the TCP checksum */
    ret = bnt_tcp__set_dport(&tcp, 8080);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
