#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/in.h>
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

static const struct in6_addr outer_src = {
    .in6_u.u6_addr8 = {
        0xfd, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    }
};

static const struct in6_addr outer_dst = {
    .in6_u.u6_addr8 = {
        0xfd, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    }
};

SEC("xdp")
int xdp_ip6ip6_encap(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;          // [CC]
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;  // [CC]
    struct ethhdr *eth = (struct ethhdr *)data;                  // [C]
    struct ipv6hdr *outer;
    struct bpf_fib_lookup fib = {};
    __be16 eth_proto;
    __u32 l3_off;
    __u32 pkt_len;
    __u16 payload_len;
    int ret;
    int i;

    if ((unsigned char *)(eth + 1) > data_end)                   // [B]
        return XDP_PASS;

    eth_proto = eth->h_proto;
    l3_off = sizeof(*eth);

#pragma unroll
    for (i = 0; i < 2; i++) {                                    // [L]
        struct baseline_vlan_hdr *vh;

        if (eth_proto != bpf_htons(ETH_P_8021Q) &&              // [E]
            eth_proto != bpf_htons(ETH_P_8021AD))               // [E]
            break;

        vh = (struct baseline_vlan_hdr *)(data + l3_off);        // [C P]
        if ((unsigned char *)(vh + 1) > data_end)                // [B]
            return XDP_PASS;

        eth_proto = vh->h_vlan_encapsulated_proto;
        l3_off += sizeof(*vh);
    }

    if (eth_proto != bpf_htons(ETH_P_IPV6))                     // [E]
        return XDP_PASS;

    /* As bnt_eth__insert_ipv6: a prefix other than an Ethernet header at
     * offset 0 is moved from a 64-byte window. */
    if (l3_off != sizeof(*eth) && data + 64 > data_end)         // [B P]
        return XDP_ABORTED;

    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct ipv6hdr)))
        return XDP_ABORTED;

    data = (unsigned char *)(long)ctx->data;                     // [CC]
    data_end = (unsigned char *)(long)ctx->data_end;             // [CC]

    if (l3_off == ETH_HLEN) {                                    /* Ethernet only: 3 loads, 3 stores */
        __u64 w0;
        __u32 w1;
        __u16 w2;

        if (data + sizeof(struct ipv6hdr) + ETH_HLEN > data_end)
            return XDP_ABORTED;
        w0 = *(__u64 *)(data + sizeof(struct ipv6hdr));
        w1 = *(__u32 *)(data + sizeof(struct ipv6hdr) + 8);
        w2 = *(__u16 *)(data + sizeof(struct ipv6hdr) + 12);
        *(__u64 *)data = w0;
        *(__u32 *)(data + 8) = w1;
        *(__u16 *)(data + 12) = w2;
    } else {
#pragma unroll
        for (i = 0; i < 22; i++) {                                   // [L]
            if ((__u32)i >= l3_off)
                break;
            if (data + sizeof(struct ipv6hdr) + i + 1 > data_end)   // [B P]
                return XDP_ABORTED;
            data[i] = data[sizeof(struct ipv6hdr) + i];             // [P BW]
        }
    }

    if (data + l3_off > data_end)                                // [B P]
        return XDP_ABORTED;
    *((__be16 *)(data + l3_off - 2)) = bpf_htons(ETH_P_IPV6);   // [P E]

    outer = (struct ipv6hdr *)(data + l3_off);                   // [C P]
    if ((unsigned char *)(outer + 1) > data_end)                 // [B]
        return XDP_ABORTED;

    pkt_len = (__u32)((unsigned char *)data_end - data);
    payload_len = (__u16)(pkt_len - l3_off - sizeof(*outer));

    __builtin_memset(outer, 0, sizeof(*outer));                  // [BW]
    outer->version = 6;
    outer->payload_len = bpf_htons(payload_len);                 // [E]
    outer->nexthdr = IPPROTO_IPV6;
    outer->hop_limit = 64;
    __builtin_memcpy(&outer->saddr, &outer_src, sizeof(outer->saddr)); // [BW]
    __builtin_memcpy(&outer->daddr, &outer_dst, sizeof(outer->daddr)); // [BW]

    fib.family = AF_INET6;
    fib.flowinfo = *(__be32 *)outer & bpf_htonl(0x0fffffff);    // [E]
    fib.l4_protocol = outer->nexthdr;
    fib.tot_len = payload_len + (__u16)sizeof(*outer);
    fib.ifindex = ctx->ingress_ifindex;
    __builtin_memcpy(fib.ipv6_src, &outer->saddr, sizeof(fib.ipv6_src));
    __builtin_memcpy(fib.ipv6_dst, &outer->daddr, sizeof(fib.ipv6_dst));

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    __builtin_memcpy(data + offsetof(struct ethhdr, h_source), fib.smac, ETH_ALEN); // [P]
    __builtin_memcpy(data + offsetof(struct ethhdr, h_dest), fib.dmac, ETH_ALEN);   // [P]

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
