#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

#define IPV4_CONST(a, b, c, d) ((__be32)bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d)))

/*
 * Example 8: XDP TCP SNAT with full checksum recompute.
 *
 * Validation goal:
 *   - validates bnt_ipv4__set_saddr_no_csum() and bnt_tcp__set_sport_no_csum()
 *   - validates bnt_ipv4__recompute_csum() (full IPv4 header recompute)
 *   - validates bnt_tcp__recompute_csum4() (full TCP checksum with payload loop)
 *   - exercises the BPF verifier with the BNT_MAX_PAYLOAD iteration bound
 *
 * Behavior:
 *   - if source IPv4 is 10.0.0.1 and the packet is TCP, rewrite:
 *       source IP  -> 172.16.0.1
 *       source port -> 40000
 *   - checksums are updated via full recompute (not incremental)
 */
static const __be32 match_ip  = IPV4_CONST(10, 0, 0, 1);
static const __be32 rewrite_ip = IPV4_CONST(172, 16, 0, 1);

SEC("xdp")
int xdp_tcp_snat_recompute(struct xdp_md *ctx)
{
    bnt_eth  eth;
    bnt_ipv4 ip4;
    bnt_tcp  tcp;
    __be32 saddr;
    __u8   proto;
    __u32  l3_off;
    __u32  l4_off;
    bool   is_fragment;
    int    ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__is_fragment(&ip4, &is_fragment);
    if (ret || is_fragment)
        return XDP_PASS;

    ret = bnt_ipv4__get_saddr(&ip4, &saddr);
    if (ret)
        return XDP_PASS;

    if (saddr != match_ip)
        return XDP_PASS;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret || proto != IPPROTO_TCP)
        return XDP_PASS;

    ret = bnt_ipv4__next_off(&ip4, &l4_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_tcp__parse(ctx, l4_off, &tcp);
    if (ret)
        return XDP_PASS;

    /* no checksum update here: the recompute below rebuilds it */
    ret = bnt_ipv4__set_saddr_no_csum(&ip4, rewrite_ip);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_tcp__set_sport_no_csum(&tcp, 40000);
    if (ret)
        return XDP_ABORTED;

    /* Full recompute: L3 header, then L4 header + payload. */
    ret = bnt_ipv4__recompute_csum(&ip4);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_tcp__recompute_csum4(&tcp, &ip4);
    if (ret)
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
