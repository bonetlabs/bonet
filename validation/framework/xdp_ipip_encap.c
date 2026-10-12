#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

static const __be32 outer_src = BNT_IPV4(10, 8, 0, 2);
static const __be32 outer_dst = BNT_IPV4(48, 0, 0, 2);

SEC("xdp")
int xdp_ipip_encap(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 outer;
    bnt_fib4 fib;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;

    if (bnt_eth__insert_ipv4(&eth, IPPROTO_IPIP, outer_src, outer_dst))
        return XDP_ABORTED;
    if (bnt_eth__next_ipv4(&eth, &outer))
        return XDP_ABORTED;

    if (bnt_ipv4__fib_lookup(&outer, &fib))
        return XDP_PASS;
    if (!bnt_fib4__is_success(&fib))
        return XDP_PASS;

    if (bnt_eth__set_src(&eth, bnt_fib4__get_smac(&fib)) ||
        bnt_eth__set_dst(&eth, bnt_fib4__get_dmac(&fib)))
        return XDP_ABORTED;

    return bpf_redirect(bnt_fib4__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
