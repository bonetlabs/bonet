#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

SEC("xdp")
int xdp_icmp4_echo_setters(struct xdp_md *ctx)
{
    bnt_icmp4 icmp;
    __u8 type = 0;
    __u16 id = 0;
    __u16 seq = 0;
    int ret;

    ret = bnt_ctx__find_icmp4(ctx, &icmp);
    if (ret)
        return XDP_PASS;
    ret = bnt_icmp4__get_type(&icmp, &type);
    if (ret || type != ICMP_ECHO)
        return XDP_PASS;

    ret = bnt_icmp4__set_echo_id(&icmp, 0x1234);
    if (ret)
        goto fail;
    ret = bnt_icmp4__set_echo_seq(&icmp, 0x5678);
    if (ret)
        goto fail;
    ret = bnt_icmp4__get_echo_id(&icmp, &id);
    if (ret)
        goto fail;
    ret = bnt_icmp4__get_echo_seq(&icmp, &seq);
    if (ret)
        goto fail;
    if (id != 0x1234 || seq != 0x5678)
        goto fail;

    bnt_test_ok(((__u64)id << 16) | seq, ((__u64)0x1234 << 16) | 0x5678);
    return XDP_DROP;

fail:
    bnt_test_fail(((__u64)id << 16) | seq, ((__u64)0x1234 << 16) | 0x5678);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
