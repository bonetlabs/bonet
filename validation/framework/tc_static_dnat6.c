#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_tc_ingress.h>

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

SEC("tc")
int tc_static_dnat6(struct __sk_buff *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_fib6 fib;
    struct in6_addr daddr;
    struct in6_addr new_dst;

    if (bnt_eth__parse(ctx, 0, &eth))
        return TC_ACT_OK;
    if (bnt_eth__next_ipv6(&eth, &ip6))
        return TC_ACT_OK;

    if (bnt_ipv6__get_daddr(&ip6, &daddr))
        return TC_ACT_OK;
    if (__builtin_memcmp(&daddr, old_dst_bytes, 16) != 0)
        return TC_ACT_OK;

    __builtin_memcpy(&new_dst, new_dst_bytes, sizeof(new_dst));
    if (bnt_ipv6__set_daddr(&ip6, &new_dst))
        return TC_ACT_SHOT;

    if (bnt_ipv6__fib_lookup(&ip6, &fib))
        return TC_ACT_OK;
    if (!bnt_fib6__is_success(&fib))
        return TC_ACT_OK;

    if (bnt_ipv6__dec_hop_limit(&ip6, NULL))
        return TC_ACT_SHOT;
    if (bnt_eth__set_smac(&eth, bnt_fib6__get_smac(&fib)) ||
        bnt_eth__set_dmac(&eth, bnt_fib6__get_dmac(&fib)))
        return TC_ACT_SHOT;

    return bpf_redirect(bnt_fib6__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
