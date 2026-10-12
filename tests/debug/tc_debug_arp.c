#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "bnt_debug.h"
#include "test_result.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bnt_dbg_arp_event);
} bnt_dbg_arp_latest SEC(".maps");

SEC("classifier")
int tc_debug_arp(struct __sk_buff *skb)
{
    bnt_arp arp;
    struct bnt_dbg_arp_event event = {};
    __u32 key = 0;
    int ret;

    ret = bnt_ctx__find_arp(skb, &arp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_dbg_arp__fill_event(&arp, &event);
    if (ret)
        goto fail;
    if (!event.is_eth_ipv4 || event.htype != 1 || event.ptype != ETH_P_IP)
        goto fail;
    ret = bnt_dbg_arp__update_map(&arp, &bnt_dbg_arp_latest, &key, BPF_ANY);
    if (ret)
        goto fail;
    ret = bnt_dbg_arp__printk(&arp);
    if (ret)
        goto fail;

    bnt_test_ok(event.ptype, ETH_P_IP);
    return TC_ACT_SHOT;

fail:
    bnt_test_fail(event.ptype, ETH_P_IP);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
