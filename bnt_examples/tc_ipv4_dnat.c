#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_tc_ingress.h"

#define IPV4_CONST(a, b, c, d) ((__be32)bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d)))

/*
 * Example 5: TC IPv4 DNAT-style rewrite.
 *
 * Validation goal:
 *   - validates bnt_ipv4__get_daddr() and bnt_ipv4__set_daddr()
 *   - validates pseudo-header checksum updates for TCP/UDP after IPv4 address rewrite
 *   - validates combined L3+L4 field rewrites on the skb backend
 *
 * Behavior:
 *   - if destination IPv4 is 192.168.1.100, rewrite it to 10.0.0.2
 *   - if the packet is TCP/443, also rewrite the port to 8443
 *   - if the packet is UDP/53, also rewrite the port to 1053
 */
static const __be32 old_ip = IPV4_CONST(192, 168, 1, 100);
static const __be32 new_ip = IPV4_CONST(10, 0, 0, 2);

SEC("classifier")
int tc_ipv4_dnat(struct __sk_buff *skb)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_tcp tcp;
    bnt_udp udp;
    __be32 daddr;
    __u16 dport;
    __u8 proto;
    __u32 l3_off;
    __u32 l4_off;
    bool is_fragment;
    int ret;
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

    /* IPv4 addresses stay in network byte order end to end (get_daddr's
     * output and old_ip alike); only port numbers below are host order. */
    ret = bnt_ipv4__get_daddr(&ip4, &daddr);
    if (ret)
        return TC_ACT_OK;

    if (daddr != old_ip)
        return TC_ACT_OK;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return TC_ACT_OK;

    if (proto == IPPROTO_TCP) {
        ret = bnt_tcp__parse(skb, l4_off, &tcp);
        if (ret)
            return TC_ACT_OK;
        ret = bnt_tcp__get_dport(&tcp, &dport);
        if (ret)
            return TC_ACT_OK;
        if (dport == 443) {
            ret = bnt_tcp__set_dport(&tcp, 8443);
            if (ret)
                return TC_ACT_SHOT;
        }
    } else if (proto == IPPROTO_UDP) {
        ret = bnt_udp__parse(skb, l4_off, &udp);
        if (ret)
            return TC_ACT_OK;
        ret = bnt_udp__get_dport(&udp, &dport);
        if (ret)
            return TC_ACT_OK;
        if (dport == 53) {
            ret = bnt_udp__set_dport(&udp, 1053);
            if (ret)
                return TC_ACT_SHOT;
        }
    }

    /* incremental updates: the port and address rewrites can come in any order */
    ret = bnt_ipv4__set_daddr(&ip4, new_ip);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
