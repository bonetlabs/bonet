#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#define PORT_FROM 7777
#define MPLS_LABEL 100

SEC("xdp")
int xdp_insert_mpls(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_udp udp;
    bnt_mpls mpls;
    __u32 label = 0;
    __u16 dport = 0;
    int ret;

    ret = bnt_ctx__find_udp(ctx, &udp);
    if (ret)
        return XDP_PASS;
    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return XDP_PASS;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        goto fail;
    ret = bnt_eth__insert_mpls(&eth, MPLS_LABEL, 0, 64);
    if (ret)
        goto fail;
    ret = bnt_eth__next_header(&eth, &mpls);
    if (ret)
        goto fail;
    ret = bnt_mpls__get_label(&mpls, &label);
    if (ret || label != MPLS_LABEL)
        goto fail;

    bnt_test_ok(label, MPLS_LABEL);
    return XDP_PASS;

fail:
    bnt_test_fail(label, MPLS_LABEL);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
