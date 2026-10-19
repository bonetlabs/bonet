#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2
#endif

static const __be32 service_ip = BNT_IPV4(10, 0, 0, 2);
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
    bool  eth_ipv4;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;
    if (bnt_eth__next_arp(&eth, &arp))
        return XDP_PASS;
    if (bnt_arp__is_eth_ipv4(&arp, &eth_ipv4) || !eth_ipv4)
        return XDP_PASS;
    if (bnt_arp__get_oper(&arp, &oper) || oper != ARPOP_REQUEST)
        return XDP_PASS;
    if (bnt_arp__get_tpa(&arp, &target_ip) || target_ip != service_ip)
        return XDP_PASS;
    if (bnt_eth__get_smac(&eth, requester_mac) || bnt_arp__get_spa(&arp, &requester_ip))
        return XDP_PASS;

    if (bnt_eth__set_dmac(&eth, requester_mac) ||
        bnt_eth__set_smac(&eth, service_mac) ||
        bnt_arp__set_oper(&arp, ARPOP_REPLY) ||
        bnt_arp__set_tha(&arp, requester_mac) ||
        bnt_arp__set_tpa(&arp, requester_ip) ||
        bnt_arp__set_sha(&arp, service_mac) ||
        bnt_arp__set_spa(&arp, service_ip))
        return XDP_ABORTED;

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
