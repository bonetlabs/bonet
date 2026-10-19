#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example 2: VLAN-aware IPv4/UDP processing.
 *
 * Validation goal:
 *   - validates that bnt_eth__parse() correctly skips one or two VLAN tags
 *   - validates bnt_eth__get_vlan_depth()
 *   - validates bnt_ipv4__get_ttl() and bnt_ipv4__set_ttl()
 *   - validates automatic IPv4 header checksum update after TTL change
 *
 * Behavior:
 *   - only acts on VLAN-tagged IPv4/UDP traffic
 *   - drops packets with TTL <= 1
 *   - decrements TTL otherwise
 */
SEC("xdp")
int xdp_vlan_ipv4_ttl_guard(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_ipv4 ip4;
    __u8 ttl;
    __u8 proto;
    __u32 l3_off;
    int ret;
    __u16 ethertype;
    __u8 depth;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    /* untagged traffic, or a header that cannot be read: nothing to do */
    if (bnt_eth__get_vlan_depth(&eth, &depth) || depth == 0)
        return XDP_PASS;

    if (bnt_eth__get_ethertype(&eth, &ethertype) || ethertype != ETH_P_IP)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__parse(ctx, l3_off, &ip4);
    if (ret)
        return XDP_PASS;

    ret = bnt_ipv4__get_protocol(&ip4, &proto);
    if (ret || proto != IPPROTO_UDP)
        return XDP_PASS;

    ret = bnt_ipv4__get_ttl(&ip4, &ttl);
    if (ret)
        return XDP_PASS;

    /* TTL 1 would decrement to 0 and must not be forwarded, same as a router
     * hop would refuse it. */
    if (ttl <= 1)
        return XDP_DROP;

        ret = bnt_ipv4__set_ttl(&ip4, ttl - 1);
    if (ret)
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
