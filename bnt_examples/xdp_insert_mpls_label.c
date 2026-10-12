#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

#define PUSH_LABEL 100

/*
 * Example: push an MPLS label onto an IPv4 packet after Ethernet/VLAN.
 *
 * Validation goal:
 *   - validates bnt_eth__insert_mpls()
 *
 * Behavior:
 *   - pushes label 100 (TC 0, TTL 64) onto IPv4 traffic
 *   - leaves non-IPv4 traffic unchanged
 */
SEC("xdp")
int xdp_insert_mpls_label(struct xdp_md *ctx)
{
    bnt_eth eth;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__get_ethertype(&eth) != ETH_P_IP)
        return XDP_PASS;

    /* BOS is set automatically: the current EtherType is IPv4, not MPLS, so
     * this becomes the bottom (and only) label of a new stack. Pushing onto
     * an existing MPLS stack instead would clear it. */
    if (bnt_eth__insert_mpls(&eth, PUSH_LABEL, 0, 64))
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
