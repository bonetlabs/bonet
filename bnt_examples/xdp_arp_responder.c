#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/bnt_xdp.h"

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2
#endif

#define IPV4_CONST(a, b, c, d) ((__be32)bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d)))

/*
 * Example 6: in-place ARP responder.
 *
 * Validation goal:
 *   - validates bnt_arp__parse() and bnt_arp__is_eth_ipv4()
 *   - validates ARP getters and setters for SHA/SPA/THA/TPA
 *   - validates Ethernet address rewrite helpers
 *   - validates a full in-place packet transformation followed by XDP_TX
 *
 * Behavior:
 *   - answers ARP requests for 10.0.0.2 with a fixed service MAC address
 *   - transmits the modified packet back through the ingress interface
 */
static const __be32 service_ip = IPV4_CONST(10, 0, 0, 2);
static const unsigned char service_mac[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

SEC("xdp")
int xdp_arp_responder(struct xdp_md *ctx)
{
    bnt_eth eth;
    bnt_arp arp;
    unsigned char requester_mac[ETH_ALEN];
    __be32 requester_ip;
    __be32 target_ip;
    __u16 oper;
    __u32 l3_off;
    int ret;

    ret = bnt_eth__parse(ctx, 0, &eth);
    if (ret)
        return XDP_PASS;

    if (bnt_eth__get_ethertype(&eth) != ETH_P_ARP)
        return XDP_PASS;

    ret = bnt_eth__next_off(&eth, &l3_off);
    if (ret)
        return XDP_PASS;

    ret = bnt_arp__parse(ctx, l3_off, &arp);
    if (ret)
        return XDP_PASS;

    /* ARP isn't Ethernet/IPv4-specific on the wire; this guard rejects other
     * hardware/protocol address sizes before the SHA/SPA/THA/TPA accessors
     * below, which assume Ethernet MACs and IPv4 addresses. */
    if (!bnt_arp__is_eth_ipv4(&arp))
        return XDP_PASS;

    ret = bnt_arp__get_oper(&arp, &oper);
    if (ret)
        return XDP_PASS;

    if (oper != ARPOP_REQUEST)
        return XDP_PASS;

    ret = bnt_arp__get_tpa(&arp, &target_ip);
    if (ret)
        return XDP_PASS;

    if (target_ip != service_ip)
        return XDP_PASS;

    /* Capture the requester's MAC/IP before any field below is overwritten:
     * the reply's destination fields are the request's source fields, so
     * this packet is turned into its own reply in place rather than built
     * from scratch. */
    ret = bnt_eth__get_src(&eth, requester_mac);
    if (ret)
        return XDP_PASS;

    ret = bnt_arp__get_spa(&arp, &requester_ip);
    if (ret)
        return XDP_PASS;

    ret = bnt_eth__set_dst(&eth, requester_mac);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_eth__set_src(&eth, service_mac);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_arp__set_oper(&arp, ARPOP_REPLY);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_arp__set_tha(&arp, requester_mac);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_arp__set_tpa(&arp, requester_ip);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_arp__set_sha(&arp, service_mac);
    if (ret)
        return XDP_ABORTED;

    ret = bnt_arp__set_spa(&arp, service_ip);
    if (ret)
        return XDP_ABORTED;

    /* XDP_TX sends the now-rewritten frame back out the interface it
     * arrived on, instead of up the stack (XDP_PASS) or out a different
     * interface (bpf_redirect()). */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
