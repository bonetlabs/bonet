#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_tc_ingress.h"

static const struct in6_addr outer_src = {
    .in6_u.u6_addr8 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 1 },
};
static const struct in6_addr outer_dst = {
    .in6_u.u6_addr8 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 2 },
};

/*
 * Example: TC ingress insertion of a base IPv6 header after Ethernet/VLAN.
 *
 * TC uses bpf_skb_adjust_room(BPF_ADJ_ROOM_NET) internally; the helper then
 * writes the new IPv6 header and updates the effective Ethernet type.
 */
SEC("classifier")
int tc_insert_ipv6_outer(struct __sk_buff *skb)
{
    bnt_eth eth;
    bnt_ipv4 inner;
    bnt_ipv6 outer;

    if (bnt_eth__parse(skb, 0, &eth))
        return TC_ACT_OK;
    if (bnt_eth__next_ipv4(&eth, &inner))
        return TC_ACT_OK;

    /* IPPROTO_IPIP is also the IPv6 next header of IPv4-in-IPv6 */
    if (bnt_eth__insert_ipv6(&eth, IPPROTO_IPIP, &outer_src, &outer_dst))
        return TC_ACT_SHOT;
    /* the insert leaves inner stale; eth stays valid */
    if (bnt_eth__next_ipv6(&eth, &outer))
        return TC_ACT_SHOT;

    if (bnt_ipv6__set_hop_limit(&outer, 32))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
