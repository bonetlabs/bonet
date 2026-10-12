#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/* fd08::1 — must match traffic_src_ipv6 in config */
static const __u8 blacklist_src[16] = {
    0xfd, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
static const __u8 marked_tc = 0x2e;

SEC("xdp")
int xdp_mmlf6(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *ip6;
    struct bpf_fib_lookup fib = {};
    __be16 eth_proto;
    __be32 *word0;
    __u32 l3_off;
    __u32 old_w, new_w;
    __u8 hop_limit;
    int ret;
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

    /* Mark traffic class if src matches blacklist (no checksum in IPv6). */
    if (__builtin_memcmp(&ip6->saddr, blacklist_src, 16) == 0) {
        word0  = (__be32 *)ip6;
        old_w  = bpf_ntohl(*word0);
        new_w  = (old_w & 0xf00fffff) | ((__u32)marked_tc << 20);
        *word0 = bpf_htonl(new_w);
    }

    hop_limit = ip6->hop_limit;
    if (hop_limit <= 1)
        return XDP_DROP;

    fib.family      = AF_INET6;
    fib.flowinfo    = *(__be32 *)ip6 & bpf_htonl(0x0fffffff);
    fib.l4_protocol = ip6->nexthdr;
    fib.tot_len     = bpf_ntohs(ip6->payload_len) + (__u16)sizeof(struct ipv6hdr);
    fib.ifindex     = ctx->ingress_ifindex;
    __builtin_memcpy(fib.ipv6_src, &ip6->saddr, sizeof(fib.ipv6_src));
    __builtin_memcpy(fib.ipv6_dst, &ip6->daddr, sizeof(fib.ipv6_dst));

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    ip6->hop_limit = hop_limit - 1;

    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
