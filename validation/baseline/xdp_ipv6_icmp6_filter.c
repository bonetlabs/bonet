#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

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

SEC("xdp")
int xdp_ipv6_icmp6_filter(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *ip6;
    struct icmp6hdr *icmp6;
    __be16 eth_proto;
    __u8 nexthdr;
    __u32 l3_off;
    __u32 l4_off;
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

    if (eth_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    ip6 = (struct ipv6hdr *)(data + l3_off);
    if ((unsigned char *)(ip6 + 1) > data_end || ip6->version != 6)
        return XDP_PASS;

    nexthdr = ip6->nexthdr;
    l4_off = l3_off + sizeof(*ip6);

#pragma unroll
    for (i = 0; i < 6; i++) {
        unsigned char *ext;
        __u32 ext_len;

        if (nexthdr != NEXTHDR_HOP &&
            nexthdr != NEXTHDR_ROUTING &&
            nexthdr != NEXTHDR_FRAGMENT &&
            nexthdr != NEXTHDR_AUTH &&
            nexthdr != NEXTHDR_DEST &&
            nexthdr != NEXTHDR_MOBILITY &&
            nexthdr != NEXTHDR_HIP &&
            nexthdr != NEXTHDR_SHIM)
            break;

        ext = data + l4_off;
        if (ext + 8 > data_end)
            return XDP_PASS;

        if (nexthdr == NEXTHDR_FRAGMENT)
            return XDP_PASS;

        if (nexthdr == NEXTHDR_AUTH)
            ext_len = ((__u32)ext[1] + 2) * 4;
        else
            ext_len = ((__u32)ext[1] + 1) * 8;

        if (ext_len < 8 || data + l4_off + ext_len > data_end)
            return XDP_PASS;

        nexthdr = ext[0];
        l4_off += ext_len;
    }

    if (nexthdr == NEXTHDR_HOP ||
        nexthdr == NEXTHDR_ROUTING ||
        nexthdr == NEXTHDR_FRAGMENT ||
        nexthdr == NEXTHDR_AUTH ||
        nexthdr == NEXTHDR_DEST ||
        nexthdr == NEXTHDR_MOBILITY ||
        nexthdr == NEXTHDR_HIP ||
        nexthdr == NEXTHDR_SHIM ||
        nexthdr != IPPROTO_ICMPV6)
        return XDP_PASS;

    icmp6 = (struct icmp6hdr *)(data + l4_off);
    if ((unsigned char *)(icmp6 + 1) > data_end)
        return XDP_PASS;

    if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
