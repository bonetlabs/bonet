#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2
#endif
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

struct arp_eth_ipv4 {
    struct arphdr ar;
    unsigned char sha[ETH_ALEN];
    __be32 spa;
    unsigned char tha[ETH_ALEN];
    __be32 tpa;
} __attribute__((packed));

static const __be32 service_ip = bpf_htonl(0x0a000002);
static const unsigned char service_mac[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

SEC("xdp")
int xdp_arp_responder(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct arp_eth_ipv4 *arp;
    unsigned char requester_mac[ETH_ALEN];
    __be16 eth_proto;
    __be32 requester_ip;
    __u32 l3_off;
    int i;

    if ((unsigned char *)(eth + 1) > data_end)
        return XDP_PASS;

    eth_proto = eth->h_proto;
    l3_off = sizeof(*eth);

#pragma unroll
    for (i = 0; i < 2; i++) {
        struct baseline_vlan_hdr *vh;

        if (eth_proto != bpf_htons(ETH_P_8021Q) &&
            eth_proto != bpf_htons(ETH_P_8021AD))
            break;

        vh = (struct baseline_vlan_hdr *)(data + l3_off);
        if ((unsigned char *)(vh + 1) > data_end)
            return XDP_PASS;

        eth_proto = vh->h_vlan_encapsulated_proto;
        l3_off += sizeof(*vh);
    }

    if (eth_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    arp = (struct arp_eth_ipv4 *)(data + l3_off);
    if ((unsigned char *)(arp + 1) > data_end)
        return XDP_PASS;

    if (arp->ar.ar_hrd != bpf_htons(ARPHRD_ETHER) ||
        arp->ar.ar_pro != bpf_htons(ETH_P_IP) ||
        arp->ar.ar_hln != ETH_ALEN ||
        arp->ar.ar_pln != 4 ||
        arp->ar.ar_op != bpf_htons(ARPOP_REQUEST) ||
        arp->tpa != service_ip)
        return XDP_PASS;

    __builtin_memcpy(requester_mac, eth->h_source, ETH_ALEN);
    requester_ip = arp->spa;

    __builtin_memcpy(eth->h_dest, requester_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, service_mac, ETH_ALEN);
    arp->ar.ar_op = bpf_htons(ARPOP_REPLY);
    __builtin_memcpy(arp->tha, requester_mac, ETH_ALEN);
    arp->tpa = requester_ip;
    __builtin_memcpy(arp->sha, service_mac, ETH_ALEN);
    arp->spa = service_ip;

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
