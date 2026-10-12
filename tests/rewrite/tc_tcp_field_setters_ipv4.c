#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#define PORT_FROM 7777

SEC("classifier")
int tc_tcp_field_setters_ipv4(struct __sk_buff *skb)
{
    bnt_tcp tcp;
    __u16 dport = 0;
    __u16 sport = 0;
    __u16 flags = 0;
    __u16 window = 0;
    __u16 urg = 0;
    __u32 seq = 0;
    __u32 ack = 0;
    bool is_ack = false;
    bool is_syn = false;
    int ret;

    ret = bnt_ctx__find_tcp(skb, &tcp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_tcp__get_dest(&tcp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    ret = bnt_tcp__set_source(&tcp, 4444);
    if (ret)
        goto fail;
    ret = bnt_tcp__set_seq(&tcp, 0x01020304);
    if (ret)
        goto fail;
    ret = bnt_tcp__set_ack_seq(&tcp, 0x05060708);
    if (ret)
        goto fail;
    ret = bnt_tcp__set_flags(&tcp, BNT_TCP_ACK);
    if (ret)
        goto fail;
    ret = bnt_tcp__clear_ack(&tcp);
    if (ret)
        goto fail;
    ret = bnt_tcp__set_ack(&tcp);
    if (ret)
        goto fail;
    ret = bnt_tcp__set_syn(&tcp);
    if (ret)
        goto fail;
    ret = bnt_tcp__clear_syn(&tcp);
    if (ret)
        goto fail;
    ret = bnt_tcp__set_window(&tcp, 4096);
    if (ret)
        goto fail;
    ret = bnt_tcp__set_urg_ptr(&tcp, 9);
    if (ret)
        goto fail;

    ret = bnt_tcp__get_source(&tcp, &sport);
    if (ret)
        goto fail;
    ret = bnt_tcp__get_seq(&tcp, &seq);
    if (ret)
        goto fail;
    ret = bnt_tcp__get_ack_seq(&tcp, &ack);
    if (ret)
        goto fail;
    ret = bnt_tcp__get_flags(&tcp, &flags);
    if (ret)
        goto fail;
    ret = bnt_tcp__is_ack(&tcp, &is_ack);
    if (ret || !is_ack)
        goto fail;
    ret = bnt_tcp__is_syn(&tcp, &is_syn);
    if (ret || is_syn)
        goto fail;
    ret = bnt_tcp__get_window(&tcp, &window);
    if (ret)
        goto fail;
    ret = bnt_tcp__get_urg_ptr(&tcp, &urg);
    if (ret)
        goto fail;
    if (sport != 4444 || seq != 0x01020304 || ack != 0x05060708 ||
        flags != BNT_TCP_ACK || window != 4096 || urg != 9)
        goto fail;

    bnt_test_ok(sport, 4444);
    return TC_ACT_SHOT;

fail:
    bnt_test_fail(sport, 4444);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
