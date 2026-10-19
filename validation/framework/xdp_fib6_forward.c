#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

SEC("xdp")
int xdp_fib6_forward(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_fib6 fib;
    bool hop_limit_expired;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_ipv6(&eth, &ip6))
        return XDP_PASS;

    if (bnt_ipv6__fib_lookup(&ip6, &fib))
        return XDP_PASS;
    if (!bnt_fib6__is_success(&fib))
        return XDP_PASS;

    if (bnt_ipv6__dec_hop_limit(&ip6, &hop_limit_expired))
        return hop_limit_expired ? XDP_DROP : XDP_ABORTED;

    if (bnt_eth__set_smac(&eth, bnt_fib6__get_smac(&fib)) ||
        bnt_eth__set_dmac(&eth, bnt_fib6__get_dmac(&fib)))
        return XDP_ABORTED;

    return bpf_redirect(bnt_fib6__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
