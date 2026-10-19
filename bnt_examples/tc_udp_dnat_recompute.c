#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"

#define IPV4_CONST(a, b, c, d) ((__be32)bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d)))

/*
 * Example 9: TC UDP DNAT with full checksum recompute.
 *
 * Validation goal:
 *   - validates bnt_ipv4__set_daddr_no_csum() and bnt_udp__set_dport_no_csum()
 *   - validates bnt_ipv4__recompute_csum() on the TC (skb) backend
 *   - validates bnt_udp__recompute_csum() (full UDP checksum with payload loop)
 *   - exercises the BPF verifier with the BNT_MAX_PAYLOAD iteration bound on TC
 *
 * Behavior:
 *   - if destination IPv4 is 192.168.1.100 and destination UDP port is 5353,
 *     rewrite:
 *       destination IP   -> 10.0.0.53
 *       destination port -> 53
 *   - checksums are updated via full recompute (not incremental)
 */
static const __be32 match_ip   = IPV4_CONST(192, 168, 1, 100);
static const __be32 rewrite_ip = IPV4_CONST(10, 0, 0, 53);

SEC("classifier")
int tc_udp_dnat_recompute(struct __sk_buff *skb)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_udp  udp;
    __be32 daddr;
    __u16  dport;
    __u8   proto;
    __u32  l3_off;
    __u32  l4_off;
    bool   is_fragment;
    int    ret;
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

    ret = bnt_ipv4__get_daddr(&ip4, &daddr);
    if (ret)
        return TC_ACT_OK;

    if (daddr != match_ip)
        return TC_ACT_OK;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret || proto != IPPROTO_UDP)
        return TC_ACT_OK;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_udp__parse(skb, l4_off, &udp);
    if (ret)
        return TC_ACT_OK;

    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret)
        return TC_ACT_OK;

    if (dport != 5353)
        return TC_ACT_OK;

    /* no checksum update here: the recompute below rebuilds it */
    ret = bnt_ipv4__set_daddr_no_csum(&ip4, rewrite_ip);
    if (ret)
        return TC_ACT_SHOT;

    ret = bnt_udp__set_dport_no_csum(&udp, 53);
    if (ret)
        return TC_ACT_SHOT;

    /* Full recompute: L3 header, then L4 header + payload. UDP's recompute
     * always leaves an active (non-zero) checksum, even if the original
     * packet had it disabled (checksum 0, valid for UDP over IPv4). */
    ret = bnt_ipv4__recompute_csum(&ip4);
    if (ret)
        return TC_ACT_SHOT;

    ret = bnt_udp__recompute_csum(&udp, &ip4);
    if (ret)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
