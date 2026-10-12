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
int tc_icmp6_echo_setters(struct __sk_buff *skb)
{
    bnt_icmp6 icmp;
    __u8 type = 0;
    __u16 id = 0;
    __u16 seq = 0;
    int ret;

    ret = bnt_ctx__find_icmp6(skb, &icmp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_icmp6__get_type(&icmp, &type);
    if (ret || type != ICMPV6_ECHO_REQUEST)
        return TC_ACT_OK;

    ret = bnt_icmp6__set_echo_id(&icmp, 0x2468);
    if (ret)
        goto fail;
    ret = bnt_icmp6__set_echo_seq(&icmp, 0x1357);
    if (ret)
        goto fail;
    ret = bnt_icmp6__get_echo_id(&icmp, &id);
    if (ret)
        goto fail;
    ret = bnt_icmp6__get_echo_seq(&icmp, &seq);
    if (ret)
        goto fail;
    if (id != 0x2468 || seq != 0x1357)
        goto fail;

    bnt_test_ok(((__u64)id << 16) | seq, ((__u64)0x2468 << 16) | 0x1357);
    return TC_ACT_SHOT;

fail:
    bnt_test_fail(((__u64)id << 16) | seq, ((__u64)0x2468 << 16) | 0x1357);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
