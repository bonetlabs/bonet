#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

/* fd08::1 — must match traffic_src_ipv6 in config */
static const __u8 blacklist_src[16] = {
    0xfd, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
static const __u8 marked_tc = 0x2e;

SEC("xdp")
int xdp_mmlf6(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_fib6 fib;
    struct in6_addr saddr;
    bool hop_limit_expired;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_ipv6(&eth, &ip6))
        return XDP_PASS;

    if (bnt_ipv6__get_saddr(&ip6, &saddr))
        return XDP_PASS;
    if (__builtin_memcmp(&saddr, blacklist_src, 16) == 0 && bnt_ipv6__set_traffic_class(&ip6, marked_tc))
        return XDP_ABORTED;

    if (bnt_ipv6__fib_lookup(&ip6, &fib))
        return XDP_PASS;
    if (!bnt_fib6__is_success(&fib))
        return XDP_PASS;

    if (bnt_ipv6__dec_hop_limit(&ip6, &hop_limit_expired))
        return hop_limit_expired ? XDP_DROP : XDP_ABORTED;
    if (bnt_eth__set_src(&eth, bnt_fib6__get_smac(&fib)) ||
        bnt_eth__set_dst(&eth, bnt_fib6__get_dmac(&fib)))
        return XDP_ABORTED;

    return bpf_redirect(bnt_fib6__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
