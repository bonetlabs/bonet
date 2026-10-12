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
#define PORT_TO   8888

SEC("xdp")
int xdp_ipv4_udp_setters(struct xdp_md *ctx)
{
    bnt_udp udp;
    bnt_ipv4 ip4;
    __u16 dport = 0;
    __u16 id = 0;
    __u8 tos = 0;
    __u8 ttl = 0;
    int ret;

    ret = bnt_ctx__find_ipv4(ctx, &ip4);
    if (ret)
        return XDP_PASS;
    ret = bnt_ctx__find_udp(ctx, &udp);
    if (ret)
        return XDP_PASS;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return XDP_PASS;

    ret = bnt_ipv4__set_tos(&ip4, 0x2e);
    if (ret)
        goto fail;
    ret = bnt_ipv4__set_ttl(&ip4, 43);
    if (ret)
        goto fail;
    ret = bnt_ipv4__dec_ttl(&ip4, NULL);
    if (ret)
        goto fail;
    ret = bnt_ipv4__set_id(&ip4, 0x4242);
    if (ret)
        goto fail;
    ret = bnt_udp__set_dest(&udp, PORT_TO);
    if (ret)
        goto fail;

    ret = bnt_ipv4__get_tos(&ip4, &tos);
    if (ret)
        goto fail;
    ret = bnt_ipv4__get_ttl(&ip4, &ttl);
    if (ret)
        goto fail;
    ret = bnt_ipv4__get_id(&ip4, &id);
    if (ret)
        goto fail;
    ret = bnt_udp__get_dest(&udp, &dport);
    if (ret)
        goto fail;
    if (tos != 0x2e || ttl != 42 || id != 0x4242 || dport != PORT_TO)
        goto fail;

    bnt_test_ok(((__u64)ttl << 48) | ((__u64)tos << 40) | ((__u64)id << 16) | dport,
                 ((__u64)42 << 48) | ((__u64)0x2e << 40) | ((__u64)0x4242 << 16) | PORT_TO);
    return XDP_PASS;

fail:
    bnt_test_fail(((__u64)ttl << 48) | ((__u64)tos << 40) | ((__u64)id << 16) | dport,
                   ((__u64)42 << 48) | ((__u64)0x2e << 40) | ((__u64)0x4242 << 16) | PORT_TO);
    return XDP_ABORTED;
}

char LICENSE[] SEC("license") = "GPL";
