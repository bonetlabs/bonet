#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} blocked_tcp_ports SEC(".maps");

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif
#define TCP_FLAG_SYN 0x002

SEC("xdp")
int xdp_firewall_map(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __be16 eth_proto;
    __u16 dport;
    __u16 flags;
    __u16 frag;
    __u32 l3_off;
    __u32 l4_off;
    __u32 hlen;
    __u8 *blocked;
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

    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(data + l3_off);
    if ((unsigned char *)(ip + 1) > data_end || ip->version != 4)
        return XDP_PASS;

    hlen = (__u32)ip->ihl * 4;
    if (hlen < sizeof(*ip) || hlen > 60 ||
        data + l3_off + hlen > data_end ||
        bpf_ntohs(ip->tot_len) < hlen)
        return XDP_PASS;

    frag = bpf_ntohs(ip->frag_off);
    if ((frag & (IP_MF | IP_OFFSET)) || ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    l4_off = l3_off + hlen;
    tcp = (struct tcphdr *)(data + l4_off);
    if ((unsigned char *)(tcp + 1) > data_end)
        return XDP_PASS;

    dport = bpf_ntohs(tcp->dest);
    flags = bpf_ntohs(*(__be16 *)((unsigned char *)tcp + 12)) & 0x01ff;
    blocked = bpf_map_lookup_elem(&blocked_tcp_ports, &dport);
    if (blocked && *blocked && (flags & TCP_FLAG_SYN))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
