#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example: minimal IPv6 FIB forwarding.
 *
 * Policy stays explicit in this program:
 *   - non-successful FIB results are passed unchanged;
 *   - after a successful lookup, hop limit <= 1 is dropped;
 *   - otherwise hop limit is decremented, L2 is rewritten, and the packet
 *     redirects.
 */
SEC("xdp")
int xdp_fib6_forward(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_fib6 fib;
    bool hop_limit_expired;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    ret = bnt_ctx__find_ipv6(ctx, &ip6);
    if (ret)
        return XDP_PASS;

    /* fib_lookup() returning BNT_OK only means the lookup ran; is_success()
     * is the separate check for whether it actually found a route. Checked
     * before touching the hop limit so an unroutable packet is passed
     * unchanged rather than decremented for nothing. */
    ret = bnt_ipv6__fib_lookup(&ip6, &fib);
    if (ret)
        return XDP_PASS;
    if (!bnt_fib6__is_success(&fib))
        return XDP_PASS;

    /* dec_hop_limit() overloads its return: non-zero means either "hop
     * limit expired" (hop_limit_expired set, an expected outcome to drop
     * on) or a real failure (hop_limit_expired clear). The ternary
     * distinguishes the two, same as bnt_ipv4__dec_ttl() in
     * xdp_fib4_forward.c. */
    ret = bnt_ipv6__dec_hop_limit(&ip6, &hop_limit_expired);
    if (ret)
        return hop_limit_expired ? XDP_DROP : XDP_ABORTED;

    ret = bnt_eth__set_src(&eth, bnt_fib6__get_smac(&fib));
    if (ret)
        return XDP_ABORTED;
    ret = bnt_eth__set_dst(&eth, bnt_fib6__get_dmac(&fib));
    if (ret)
        return XDP_ABORTED;

    return bpf_redirect(bnt_fib6__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
