#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

/* old_dst: fd03::2 (traffic_dst_ipv6) */
static const __u8 old_dst_bytes[16] = {
    0xfd, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};
/* new_dst: fd07::1 (tg_rx_ipv6) */
static const __u8 new_dst_bytes[16] = {
    0xfd, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

SEC("xdp")
int xdp_static_dnat6(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_fib6 fib;
    struct in6_addr daddr;
    struct in6_addr new_dst;
    bool hop_limit_expired;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_ipv6(&eth, &ip6))
        return XDP_PASS;

    if (bnt_ipv6__get_daddr(&ip6, &daddr))
        return XDP_PASS;
    if (__builtin_memcmp(&daddr, old_dst_bytes, 16) != 0)
        return XDP_PASS;

    __builtin_memcpy(&new_dst, new_dst_bytes, sizeof(new_dst));
    if (bnt_ipv6__set_daddr(&ip6, &new_dst))
        return XDP_ABORTED;

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
