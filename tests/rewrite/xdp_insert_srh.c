#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#define PORT_FROM 7777

SEC("xdp")
int xdp_insert_srh(struct xdp_md *ctx)
{
    const __u8 seg_addr[16] = {
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    bnt_eth eth;
    bnt_ipv6 ip6;
    bnt_udp udp;
    struct in6_addr segs[1];
    __u16 dport = 0;
    int ret;

    ret = bnt_ctx__find_udp(ctx, &udp);
    if (ret)
        return XDP_PASS;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return XDP_PASS;

    __builtin_memcpy(&segs[0], seg_addr, sizeof(segs[0]));
    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        goto fail;
    ret = bnt_eth__next_header(&eth, &ip6);
    if (ret)
        goto fail;
    ret = bnt_ipv6__insert_srh(&ip6, segs, 1);
    if (ret)
        goto fail;

    /* After SRH insert, find_udp must traverse outer IPv6 + new SRH + UDP. */
    ret = bnt_ctx__find_udp(ctx, &udp);
    if (ret)
        goto fail;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        goto fail;

    bnt_test_ok(dport, PORT_FROM);
    return XDP_PASS;

fail:
    bnt_test_fail(dport, PORT_FROM);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
