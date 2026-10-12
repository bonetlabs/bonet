#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

static const __be32 blacklist_src = BNT_IPV4(10, 8, 0, 1);
static const __u8 marked_tos = 0x2e;

SEC("xdp")
int xdp_mmlf(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_fib4 fib;
    __be32 saddr;
    bool ttl_expired;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_ipv4(&eth, &ip4))
        return XDP_PASS;

    if (bnt_ipv4__get_saddr(&ip4, &saddr))
        return XDP_PASS;
    if (saddr == blacklist_src && bnt_ipv4__set_tos(&ip4, marked_tos))
        return XDP_ABORTED;

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
