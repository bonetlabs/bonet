#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_tc_ingress.h>

SEC("tc")
int tc_fib6_forward(struct __sk_buff *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_fib6 fib;

    if (bnt_eth__parse(ctx, 0, &eth))
        return TC_ACT_OK;
    if (bnt_eth__next_ipv6(&eth, &ip6))
        return TC_ACT_OK;

    if (bnt_ipv6__fib_lookup(&ip6, &fib))
        return TC_ACT_OK;
    if (!bnt_fib6__is_success(&fib))
        return TC_ACT_OK;

    if (bnt_ipv6__dec_hop_limit(&ip6, NULL))
        return TC_ACT_SHOT;
    if (bnt_eth__set_src(&eth, bnt_fib6__get_smac(&fib)) ||
        bnt_eth__set_dst(&eth, bnt_fib6__get_dmac(&fib)))
        return TC_ACT_SHOT;

    return bpf_redirect(bnt_fib6__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
