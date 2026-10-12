#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_tc_ingress.h"

/*
 * Example: TC counterpart of xdp_vlan_insert_remove.c — push or pop one
 * 802.1Q tag depending on what's already there.
 */
SEC("classifier")
int tc_vlan_insert_remove(struct __sk_buff *skb)
{
    bnt_eth eth;
    __u8 depth;

    if (bnt_eth__parse(skb, 0, &eth))
        return TC_ACT_OK;

    /* get_vlan_depth() returns 0 both for genuinely untagged traffic and on
     * error (e.g. a truncated packet); either way the insert below is what
     * actually validates the packet, and fails safely if it can't proceed. */
    depth = bnt_eth__get_vlan_depth(&eth);
    if (depth == 0) {
        if (bnt_eth__insert_vlan(&eth, ETH_P_8021Q, 100))
            return TC_ACT_SHOT;
    } else {
        if (bnt_eth__remove_vlan(&eth))
            return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
