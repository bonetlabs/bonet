#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#define PORT_FROM 7777

SEC("classifier")
int tc_ctx_find_udp_ipv6(struct __sk_buff *skb)
{
    bnt_udp udp;
    __u16 dport = 0;
    int ret;

    ret = bnt_ctx__find_udp(skb, &udp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM) {
        bnt_test_fail(dport, PORT_FROM);
        return TC_ACT_OK;
    }

    bnt_test_ok(dport, PORT_FROM);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
