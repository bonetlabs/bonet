#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

SEC("xdp")
int xdp_ipv6_icmp6_filter(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_icmp6 icmp6;
    __u8 type;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_ipv6(&eth, &ip6))
        return XDP_PASS;
    if (bnt_ipv6__next_icmp6(&ip6, &icmp6))
        return XDP_PASS;
    if (bnt_icmp6__get_type(&icmp6, &type))
        return XDP_PASS;

    if (type == ICMPV6_ECHO_REQUEST)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
