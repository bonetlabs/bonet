#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#define PORT_FROM 7777
#define PORT_TO   8888
#define IPV4_CONST(a, b, c, d) ((__be32)bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d)))

static const __be32 rewrite_saddr = IPV4_CONST(198, 51, 100, 20);

enum {
    /* The Go loader installs non-main XDP programs sorted by name. */
    CSUM_IPV4_PROG = 0,
    CSUM_UDP_PROG  = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} prog_map SEC(".maps");

static __always_inline int parse_ipv4_udp(struct xdp_md *ctx, bnt_ipv4 *ip4, bnt_udp *udp)
{
    bnt_eth eth;
    __u32 l3_off;
    __u32 l4_off;
    __u16 udp_len;
    __u8 proto;
    bool is_fragment;
    int ret;
    __u16 ethertype;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return ret;
    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return BNT_ERR_BAD_PROTO;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return ret;

    ret = bnt_ipv4__parse(ctx, l3_off, ip4);
    if (ret)
        return ret;

    ret = bnt_ipv4__is_fragment(ip4, &is_fragment);
    if (ret)
        return ret;
    if (is_fragment)
        return BNT_ERR_FRAGMENT;

    ret = bnt_ipv4__get_protocol(ip4, &proto);
    if (ret)
        return ret;
    if (proto != IPPROTO_UDP)
        return BNT_ERR_BAD_PROTO;

    ret = bnt_ipv4__next_off(ip4, &l4_off);
    if (ret)
        return ret;

    ret = bnt_udp__parse(ctx, l4_off, udp);
    if (ret)
        return ret;

    ret = bnt_udp__get_len(udp, &udp_len);
    if (ret)
        return ret;
    if (udp_len < sizeof(struct udphdr))
        return BNT_ERR_BAD_PROTO;

    return BNT_OK;
}

SEC("xdp")
int xdp_ipv4_udp_saddr_full(struct xdp_md *ctx)
{
    bnt_ipv4 ip4;
    bnt_udp udp;
    __u16 dport = 0;
    int ret;

    ret = parse_ipv4_udp(ctx, &ip4, &udp);
    if (ret)
        return XDP_PASS;
    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return XDP_PASS;

    ret = bnt_ipv4__set_saddr_no_csum(&ip4, rewrite_saddr);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 1, 0, 0);
        return XDP_ABORTED;
    }
    ret = bnt_udp__set_dport_no_csum(&udp, PORT_TO);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 2, 0, 0);
        return XDP_ABORTED;
    }

    bpf_tail_call(ctx, &prog_map, CSUM_IPV4_PROG);
    /* d[0]=10: tail_call to CSUM_IPV4_PROG(0) returned — prog not jumped */
    bnt_test_fail_detail(dport, PORT_TO, 10, CSUM_IPV4_PROG, 0);
    return XDP_ABORTED;
}

SEC("xdp")
int xdp_ipv4_udp_saddr_full_ip_csum(struct xdp_md *ctx)
{
    bnt_ipv4 ip4;
    bnt_udp udp;
    int ret;

    ret = parse_ipv4_udp(ctx, &ip4, &udp);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 3, 0, 0);
        return XDP_ABORTED;
    }

    ret = bnt_ipv4__recompute_csum(&ip4);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 4, 0, 0);
        return XDP_ABORTED;
    }

    bpf_tail_call(ctx, &prog_map, CSUM_UDP_PROG);
    /* d[0]=11: tail_call to CSUM_UDP_PROG(1) returned — prog not jumped */
    bnt_test_fail_detail(0, PORT_TO, 11, CSUM_UDP_PROG, 0);
    return XDP_ABORTED;
}

SEC("xdp")
int xdp_ipv4_udp_saddr_full_udp_csum(struct xdp_md *ctx)
{
    bnt_ipv4 ip4;
    bnt_udp udp;
    __u16 dport = 0;
    __be32 saddr = 0;
    int ret;

    ret = parse_ipv4_udp(ctx, &ip4, &udp);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 5, 0, 0);
        return XDP_ABORTED;
    }

    ret = bnt_udp__recompute_csum(&udp, &ip4);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 6, 0, 0);
        return XDP_ABORTED;
    }
    ret = bnt_ipv4__get_saddr(&ip4, &saddr);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 7, 0, 0);
        return XDP_ABORTED;
    }
    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret) {
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 8, 0, 0);
        return XDP_ABORTED;
    }
    if (saddr != rewrite_saddr || dport != PORT_TO) {
        /* d[0]=9: value mismatch; d[1]=actual saddr, d[2]=rewrite_saddr */
        bnt_test_fail_detail(dport, PORT_TO, 9, saddr, rewrite_saddr);
        return XDP_ABORTED;
    }

    bnt_test_ok(dport, PORT_TO);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
