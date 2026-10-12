#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#define PORT_FROM 7777
#define MPLS_LABEL 100

SEC("classifier")
int tc_insert_mpls(struct __sk_buff *skb)
{
    bnt_eth eth;
    bnt_udp udp;
    bnt_mpls mpls;
    __u32 label = 0;
    __u16 dport = 0;
    int ret;

    ret = bnt_ctx__find_udp(skb, &udp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    ret = bnt_eth__parse(skb, 0, &eth);
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
    return TC_ACT_OK;

fail:
    bnt_test_fail(label, MPLS_LABEL);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
