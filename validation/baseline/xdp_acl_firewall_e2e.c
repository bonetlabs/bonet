#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ACL_PASS 0
#define ACL_DROP 1

#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP 0
#endif
#ifndef NEXTHDR_ROUTING
#define NEXTHDR_ROUTING 43
#endif
#ifndef NEXTHDR_FRAGMENT
#define NEXTHDR_FRAGMENT 44
#endif
#ifndef NEXTHDR_AUTH
#define NEXTHDR_AUTH 51
#endif
#ifndef NEXTHDR_DEST
#define NEXTHDR_DEST 60
#endif
#ifndef NEXTHDR_MOBILITY
#define NEXTHDR_MOBILITY 135
#endif
#ifndef NEXTHDR_HIP
#define NEXTHDR_HIP 139
#endif
#ifndef NEXTHDR_SHIM
#define NEXTHDR_SHIM 140
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif

struct vlan_hdr_local {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct acl_key {
    __u8  l4_proto;
    __u8  pad0;
    __u16 dport;
};

struct acl_value {
    __u8 action;
    __u8 pad[7];
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct acl_key);
    __type(value, struct acl_value);
} acl_rules SEC(".maps");

SEC("xdp")
int xdp_acl_firewall_e2e(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    __u64 bytes = data_end - data;
    struct acl_key key = {};
    struct acl_value *rule;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip4;
    struct ipv6hdr *ip6;
    __be16 eth_proto;
    __u8 proto;
    __u32 l3_off;
    __u32 l4_off;
    __u32 hlen;
    __u16 frag;
    int i;

    if ((unsigned char *)(eth + 1) > data_end)
        return XDP_PASS;

    eth_proto = eth->h_proto;
    l3_off = sizeof(*eth);

#pragma unroll
    for (i = 0; i < 2; i++) {
        struct vlan_hdr_local *vh;

        if (eth_proto != bpf_htons(ETH_P_8021Q) &&
            eth_proto != bpf_htons(ETH_P_8021AD))
            break;

        vh = (struct vlan_hdr_local *)(data + l3_off);
        if ((unsigned char *)(vh + 1) > data_end)
            return XDP_PASS;

        eth_proto = vh->h_vlan_encapsulated_proto;
        l3_off += sizeof(*vh);
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        ip4 = (struct iphdr *)(data + l3_off);
        if ((unsigned char *)(ip4 + 1) > data_end || ip4->version != 4)
            return XDP_PASS;

        hlen = (__u32)ip4->ihl * 4;
        if (hlen < sizeof(*ip4) || hlen > 60 ||
            data + l3_off + hlen > data_end ||
            bpf_ntohs(ip4->tot_len) < hlen)
            return XDP_PASS;

        frag = bpf_ntohs(ip4->frag_off);
        if (frag & (IP_MF | IP_OFFSET))
            return XDP_PASS;

        proto = ip4->protocol;
        l4_off = l3_off + hlen;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ip6 = (struct ipv6hdr *)(data + l3_off);
        if ((unsigned char *)(ip6 + 1) > data_end || ip6->version != 6)
            return XDP_PASS;

        proto = ip6->nexthdr;
        l4_off = l3_off + sizeof(*ip6);

#pragma unroll
        for (i = 0; i < 6; i++) {
            unsigned char *ext;
            __u32 ext_len;

            if (proto != NEXTHDR_HOP &&
                proto != NEXTHDR_ROUTING &&
                proto != NEXTHDR_FRAGMENT &&
                proto != NEXTHDR_AUTH &&
                proto != NEXTHDR_DEST &&
                proto != NEXTHDR_MOBILITY &&
                proto != NEXTHDR_HIP &&
                proto != NEXTHDR_SHIM)
                break;

            ext = data + l4_off;
            if (ext + 8 > data_end)
                return XDP_PASS;

            if (proto == NEXTHDR_FRAGMENT)
                return XDP_PASS;

            if (proto == NEXTHDR_AUTH)
                ext_len = ((__u32)ext[1] + 2) * 4;
            else
                ext_len = ((__u32)ext[1] + 1) * 8;

            if (ext_len < 8 || data + l4_off + ext_len > data_end)
                return XDP_PASS;

            proto = ext[0];
            l4_off += ext_len;
        }

        if (proto == NEXTHDR_HOP ||
            proto == NEXTHDR_ROUTING ||
            proto == NEXTHDR_FRAGMENT ||
            proto == NEXTHDR_AUTH ||
            proto == NEXTHDR_DEST ||
            proto == NEXTHDR_MOBILITY ||
            proto == NEXTHDR_HIP ||
            proto == NEXTHDR_SHIM)
            return XDP_PASS;
    } else {
        return XDP_PASS;
    }

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);

        if ((unsigned char *)(tcp + 1) > data_end)
            return XDP_PASS;

        key.l4_proto = IPPROTO_TCP;
        key.dport = bpf_ntohs(tcp->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(data + l4_off);

        if ((unsigned char *)(udp + 1) > data_end)
            return XDP_PASS;

        key.l4_proto = IPPROTO_UDP;
        key.dport = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    rule = bpf_map_lookup_elem(&acl_rules, &key);
    if (!rule)
        return XDP_PASS;

    __sync_fetch_and_add(&rule->packets, 1);
    __sync_fetch_and_add(&rule->bytes, bytes);

    if (rule->action == ACL_DROP)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
