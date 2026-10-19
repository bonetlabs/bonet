#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

static const struct in6_addr outer_src = {
    .in6_u.u6_addr8 = {
        0xfd, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    }
};

static const struct in6_addr outer_dst = {
    .in6_u.u6_addr8 = {
        0xfd, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    }
};

SEC("xdp")
int xdp_ip6ip6_encap(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 outer;
    bnt_fib6 fib;
    __u16 ethertype;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;

    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IPV6)
        return XDP_PASS;

    if (bnt_eth__insert_ipv6(&eth, IPPROTO_IPV6, &outer_src, &outer_dst))
        return XDP_ABORTED;
    if (bnt_eth__next_ipv6(&eth, &outer))
        return XDP_ABORTED;

    if (bnt_ipv6__fib_lookup(&outer, &fib))
        return XDP_PASS;
    if (!bnt_fib6__is_success(&fib))
        return XDP_PASS;

    if (bnt_eth__set_smac(&eth, bnt_fib6__get_smac(&fib)) ||
        bnt_eth__set_dmac(&eth, bnt_fib6__get_dmac(&fib)))
        return XDP_ABORTED;

    return bpf_redirect(bnt_fib6__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
