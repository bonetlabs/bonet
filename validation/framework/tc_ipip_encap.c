#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_tc_ingress.h>

static const __be32 outer_src = BNT_IPV4(10, 8, 0, 2);
static const __be32 outer_dst = BNT_IPV4(48, 0, 0, 2);

SEC("tc")
int tc_ipip_encap(struct __sk_buff *ctx)
{
    bnt_eth eth;
    bnt_ipv4 outer;
    bnt_fib4 fib;

    if (bnt_eth__parse(ctx, 0, &eth))
        return TC_ACT_OK;

    if (bnt_eth__insert_ipv4(&eth, IPPROTO_IPIP, outer_src, outer_dst))
        return TC_ACT_SHOT;
    if (bnt_eth__next_ipv4(&eth, &outer))
        return TC_ACT_SHOT;

    if (bnt_ipv4__fib_lookup(&outer, &fib))
        return TC_ACT_OK;
    if (!bnt_fib4__is_success(&fib))
        return TC_ACT_OK;

    if (bnt_eth__set_src(&eth, bnt_fib4__get_smac(&fib)) ||
        bnt_eth__set_dst(&eth, bnt_fib4__get_dmac(&fib)))
        return TC_ACT_SHOT;

    return bpf_redirect(bnt_fib4__get_out_ifindex(&fib), 0);
}

char LICENSE[] SEC("license") = "GPL";
