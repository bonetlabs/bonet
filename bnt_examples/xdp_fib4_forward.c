#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example: minimal IPv4 FIB forwarding.
 *
 * Policy stays explicit in this program:
 *   - non-successful FIB results are passed unchanged;
 *   - after a successful lookup, TTL <= 1 is dropped;
 *   - otherwise TTL is decremented, L2 is rewritten, and the packet redirects.
 */
SEC("xdp")
int xdp_fib4_forward(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_fib4 fib;
    bool ttl_expired;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    ret = bnt_ctx__find_ipv4(ctx, &ip4);
    if (ret)
        return XDP_PASS;

    /* fib_lookup() returning BNT_OK only means the lookup ran; is_success()
     * is the separate check for whether it actually found a route. Checked
     * before touching the TTL so an unroutable packet is passed unchanged
     * rather than decremented for nothing. */
    ret = bnt_ipv4__fib_lookup(&ip4, &fib);
    if (ret)
        return XDP_PASS;
    if (!bnt_fib4__is_success(&fib))
        return XDP_PASS;

    /* dec_ttl() overloads its return: non-zero means either "TTL expired"
     * (ttl_expired set, an expected outcome to drop on) or a real failure
     * (ttl_expired clear). The ternary distinguishes the two. */
    ret = bnt_ipv4__dec_ttl(&ip4, &ttl_expired);
    if (ret)
        return ttl_expired ? XDP_DROP : XDP_ABORTED;

    ret = bnt_eth__set_src(&eth, bnt_fib4__get_smac(&fib));
    if (ret)
        return XDP_ABORTED;
    ret = bnt_eth__set_dst(&eth, bnt_fib4__get_dmac(&fib));
    if (ret)
        return XDP_ABORTED;

    return bpf_redirect(bnt_fib4__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
