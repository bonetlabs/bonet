#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_tc_ingress.h>

SEC("tc")
int tc_fib4_forward(struct __sk_buff *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_fib4 fib;

    if (bnt_eth__parse(ctx, 0, &eth))
        return TC_ACT_OK;
    if (bnt_eth__next_ipv4(&eth, &ip4))
        return TC_ACT_OK;

    if (bnt_ipv4__fib_lookup(&ip4, &fib))
        return TC_ACT_OK;
    if (!bnt_fib4__is_success(&fib))
        return TC_ACT_OK;

    if (bnt_ipv4__dec_ttl(&ip4, NULL))
        return TC_ACT_SHOT;
    if (bnt_eth__set_smac(&eth, bnt_fib4__get_smac(&fib)) ||
        bnt_eth__set_dmac(&eth, bnt_fib4__get_dmac(&fib)))
        return TC_ACT_SHOT;

    return bpf_redirect(bnt_fib4__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
