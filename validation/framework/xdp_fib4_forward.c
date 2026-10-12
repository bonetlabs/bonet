#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

SEC("xdp")
int xdp_fib4_forward(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_fib4 fib;
    bool ttl_expired;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;

    if (bnt_eth__next_ipv4(&eth, &ip4))
        return XDP_PASS;

    if (bnt_ipv4__fib_lookup(&ip4, &fib))
        return XDP_PASS;
    if (!bnt_fib4__is_success(&fib))
        return XDP_PASS;

    if (bnt_ipv4__dec_ttl(&ip4, &ttl_expired))
        return ttl_expired ? XDP_DROP : XDP_ABORTED;

    if (bnt_eth__set_src(&eth, bnt_fib4__get_smac(&fib)) ||
        bnt_eth__set_dst(&eth, bnt_fib4__get_dmac(&fib)))
        return XDP_ABORTED;

    return bpf_redirect(bnt_fib4__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
