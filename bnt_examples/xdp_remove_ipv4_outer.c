#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

/*
 * Example: remove a base outer IPv4 header after Ethernet/VLAN.
 *
 * The helper accepts outer IPv4 headers with IHL=5 and maps IPPROTO_IPIP back
 * to ETH_P_IP, or IPPROTO_IPV6 back to ETH_P_IPV6.
 */
SEC("xdp")
int xdp_remove_ipv4_outer(struct xdp_md *ctx)
{
    bnt_eth eth;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__remove_ipv4(&eth))
        return XDP_PASS;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
