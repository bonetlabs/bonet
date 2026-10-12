#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#define PORT_FROM 7777

/*
 * Explicit step-by-step navigation for SRv6 H.Encaps:
 *   Eth -> outer IPv6 (nexthdr=43/Routing) -> SRH (nexthdr=4/IPIP) -> inner IPv4 -> UDP
 */
SEC("xdp")
int xdp_find_udp_srv6encap(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_ipv4 ip4;
    bnt_udp udp;
    __u16 dport = 0;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        goto fail;
    ret = bnt_eth__next_header(&eth, &ip6);
    if (ret)
        goto fail;
    ret = bnt_ipv6__next_header(&ip6, &ip4);
    if (ret)
        goto fail;
    ret = bnt_ipv4__next_header(&ip4, &udp);
    if (ret)
        goto fail;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        goto fail;

    bnt_test_ok(dport, PORT_FROM);
    return XDP_DROP;

fail:
    bnt_test_fail(dport, PORT_FROM);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
