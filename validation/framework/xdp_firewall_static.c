#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

SEC("xdp")
int xdp_firewall_static(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_tcp tcp;
    __u16 dport;
    bool syn;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_ipv4(&eth, &ip4))
        return XDP_PASS;
    if (bnt_ipv4__next_tcp(&ip4, &tcp))
        return XDP_PASS;
    if (bnt_tcp__get_dest(&tcp, &dport))
        return XDP_PASS;
    if (bnt_tcp__is_syn(&tcp, &syn))
        return XDP_PASS;

    if (dport == 23 && syn)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
