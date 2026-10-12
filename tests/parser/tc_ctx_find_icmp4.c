#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

SEC("classifier")
int tc_ctx_find_icmp4(struct __sk_buff *skb)
{
    bnt_icmp4 icmp;
    __u8 type = 0;
    int ret;

    ret = bnt_ctx__find_icmp4(skb, &icmp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_icmp4__get_type(&icmp, &type);
    if (ret || type != ICMP_ECHO) {
        bnt_test_fail(type, ICMP_ECHO);
        return TC_ACT_OK;
    }

    bnt_test_ok(type, ICMP_ECHO);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
