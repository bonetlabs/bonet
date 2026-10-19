#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example: push or pop one 802.1Q tag depending on what's already there.
 *
 * Untagged traffic gets tagged, tagged traffic gets untagged; sending the
 * same flow through repeatedly toggles it back and forth.
 */
SEC("xdp")
int xdp_vlan_insert_remove(struct xdp_md *ctx)
{
    bnt_eth eth;
    __u8 depth;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;

    /* depth is 0 on error too: the insert below then fails on the bad header */
    bnt_eth__get_vlan_depth(&eth, &depth);
    if (depth == 0) {
        if (bnt_eth__insert_vlan(&eth, ETH_P_8021Q, 100))
            return XDP_ABORTED;
    } else {
        if (bnt_eth__remove_vlan(&eth))
            return XDP_ABORTED;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
