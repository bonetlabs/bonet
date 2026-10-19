#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_tc_ingress.h>

/* fd08::1 — must match traffic_src_ipv6 in config */
static const __u8 blacklist_src[16] = {
    0xfd, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
static const __u8 marked_tc = 0x2e;

SEC("tc")
int tc_mmlf6(struct __sk_buff *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_fib6 fib;
    struct in6_addr saddr;

    if (bnt_eth__parse(ctx, 0, &eth))
        return TC_ACT_OK;
    if (bnt_eth__next_ipv6(&eth, &ip6))
        return TC_ACT_OK;

    if (bnt_ipv6__get_saddr(&ip6, &saddr))
        return TC_ACT_OK;
    if (__builtin_memcmp(&saddr, blacklist_src, 16) == 0 && bnt_ipv6__set_traffic_class(&ip6, marked_tc))
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
