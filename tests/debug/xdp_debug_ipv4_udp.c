#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "bnt_debug.h"
#include "test_result.h"

#define PORT_FROM 7777

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bnt_dbg_udp_event);
} bnt_dbg_udp_latest SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} bnt_dbg_events SEC(".maps");

SEC("xdp")
int xdp_debug_ipv4_udp(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_udp udp;
    struct bnt_dbg_eth_event eth_event = {};
    struct bnt_dbg_ipv4_event ip_event = {};
    struct bnt_dbg_udp_event udp_event = {};
    __u32 key = 0;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret || bnt_eth__get_ethertype(&eth) != ETH_P_IP)
        return XDP_PASS;
    ret = bnt_ctx__find_ipv4(ctx, &ip4);
    if (ret)
        return XDP_PASS;
    ret = bnt_ctx__find_udp(ctx, &udp);
    if (ret)
        return XDP_PASS;

    ret = bnt_dbg_eth__fill_event(&eth, &eth_event);
    if (ret)
        goto fail;
    ret = bnt_dbg_ipv4__fill_event(&ip4, &ip_event);
    if (ret)
        goto fail;
    ret = bnt_dbg_udp__fill_event(&udp, &udp_event);
    if (ret)
        goto fail;
    if (eth_event.ethertype != ETH_P_IP || ip_event.protocol != IPPROTO_UDP ||
        udp_event.dest != PORT_FROM)
        goto fail;
    ret = bnt_dbg_udp__update_map(&udp, &bnt_dbg_udp_latest, &key, BPF_ANY);
    if (ret)
        goto fail;
    ret = bnt_dbg_udp__emit_ringbuf(&udp, &bnt_dbg_events);
    if (ret)
        goto fail;
    ret = bnt_dbg_udp__printk(&udp);
    if (ret)
        goto fail;

    bnt_test_ok(udp_event.dest, PORT_FROM);
    return XDP_PASS;

fail:
    bnt_test_fail(udp_event.dest, PORT_FROM);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
