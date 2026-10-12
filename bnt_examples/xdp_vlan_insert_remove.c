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

    /* get_vlan_depth() returns 0 both for genuinely untagged traffic and on
     * error (e.g. a truncated packet); either way the insert below is what
     * actually validates the packet, and fails safely if it can't proceed. */
    depth = bnt_eth__get_vlan_depth(&eth);
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
