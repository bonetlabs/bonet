#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

SEC("classifier")
int tc_icmp4_echo_inc(struct __sk_buff *skb)
{
    bnt_icmp4 icmp;
    __u8 type = 0;
    __u16 id = 0;
    __u16 seq = 0;
    int ret;

    ret = bnt_ctx__find_icmp4(skb, &icmp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_icmp4__get_type(&icmp, &type);
    if (ret || type != ICMP_ECHO)
        return TC_ACT_OK;

    ret = bnt_icmp4__set_echo_id(&icmp, 0x1111);
    if (ret)
        goto fail;
    ret = bnt_icmp4__set_echo_seq(&icmp, 0x2222);
    if (ret)
        goto fail;
    ret = bnt_icmp4__get_echo_id(&icmp, &id);
    if (ret)
        goto fail;
    ret = bnt_icmp4__get_echo_seq(&icmp, &seq);
    if (ret)
        goto fail;
    if (id != 0x1111 || seq != 0x2222)
        goto fail;

    bnt_test_ok(((__u64)id << 16) | seq, ((__u64)0x1111 << 16) | 0x2222);
    return TC_ACT_SHOT;

fail:
    bnt_test_fail(((__u64)id << 16) | seq, ((__u64)0x1111 << 16) | 0x2222);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
