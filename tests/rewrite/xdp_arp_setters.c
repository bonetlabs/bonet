#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2
#endif

SEC("xdp")
int xdp_arp_setters(struct xdp_md *ctx)
{
    bnt_arp arp;
    unsigned char sha[ETH_ALEN];
    unsigned char tha[ETH_ALEN];
    __u16 oper = 0;
    int ret;

    ret = bnt_ctx__find_arp(ctx, &arp);
    if (ret)
        return XDP_PASS;
    if (!bnt_arp__is_eth_ipv4(&arp))
        return XDP_PASS;
    ret = bnt_arp__get_sha(&arp, sha);
    if (ret)
        goto fail;
    ret = bnt_arp__set_oper(&arp, ARPOP_REPLY);
    if (ret)
        goto fail;
    ret = bnt_arp__set_tha(&arp, sha);
    if (ret)
        goto fail;
    ret = bnt_arp__get_oper(&arp, &oper);
    if (ret)
        goto fail;
    ret = bnt_arp__get_tha(&arp, tha);
    if (ret)
        goto fail;
    if (oper != ARPOP_REPLY || tha[0] != sha[0] || tha[5] != sha[5])
        goto fail;

    bnt_test_ok(oper, ARPOP_REPLY);
    return XDP_DROP;

fail:
    bnt_test_fail(oper, ARPOP_REPLY);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
