#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#ifndef ICMPV6_ECHO_REQUEST
#define ICMPV6_ECHO_REQUEST 128
#endif

SEC("classifier")
int tc_ctx_find_icmp6(struct __sk_buff *skb)
{
    bnt_icmp6 icmp;
    __u8 type = 0;
    int ret;

    ret = bnt_ctx__find_icmp6(skb, &icmp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_icmp6__get_type(&icmp, &type);
    if (ret || type != ICMPV6_ECHO_REQUEST) {
        bnt_test_fail(type, ICMPV6_ECHO_REQUEST);
        return TC_ACT_OK;
    }

    bnt_test_ok(type, ICMPV6_ECHO_REQUEST);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
