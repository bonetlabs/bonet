#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef NEXTHDR_ROUTING
#define NEXTHDR_ROUTING 43
#endif
#ifndef BPF_ADJ_ROOM_NET
#define BPF_ADJ_ROOM_NET 0
#endif

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/* SRv6 Segment Routing Header (RFC 8754). */
struct baseline_sr_hdr {
    __u8   nexthdr;
    __u8   hdrlen;
    __u8   type;
    __u8   segments_left;
    __u8   first_segment;
    __u8   flags;
    __be16 tag;
};

static const struct in6_addr outer_src = {
    .in6_u.u6_addr8 = {
        0xfd, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    }
};

static const struct in6_addr first_seg = {
    .in6_u.u6_addr8 = {
        0xfd, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    }
};

/* Total encap overhead: outer IPv6 (40) + SRH base (8) + 1 segment (16) = 64 bytes. */
#define SRV6_ENCAP_LEN 64

SEC("tc")
int tc_srv6_encap(struct __sk_buff *ctx)
{
    unsigned char *data     = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    __be16 eth_proto;
    __u32 l3_off;
    struct ipv6hdr outer_hdr = {};
    struct baseline_sr_hdr srh_hdr = {};
    struct bpf_fib_lookup fib = {};
    __u16 inner_len;
    __u16 payload_len;
    __u8 inner_nexthdr;
    int ret;
    int i;

    if ((unsigned char *)(eth + 1) > data_end)
        return TC_ACT_OK;

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
            return TC_ACT_OK;

        eth_proto = vh->h_vlan_encapsulated_proto;
        l3_off += sizeof(*vh);
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip4_inner = (struct iphdr *)(data + l3_off);

        if ((unsigned char *)(ip4_inner + 1) > data_end)
            return TC_ACT_OK;
        inner_len = bpf_ntohs(ip4_inner->tot_len);
        inner_nexthdr = IPPROTO_IPIP;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6_inner = (struct ipv6hdr *)(data + l3_off);

        if ((unsigned char *)(ip6_inner + 1) > data_end)
            return TC_ACT_OK;
        inner_len = bpf_ntohs(ip6_inner->payload_len) +
                    (__u16)sizeof(*ip6_inner);
        inner_nexthdr = IPPROTO_IPV6;
    } else {
        return TC_ACT_OK;
    }

    /* BPF_ADJ_ROOM_NET inserts space at the L3 boundary (l3_off). */
    if (bpf_skb_adjust_room(ctx, SRV6_ENCAP_LEN, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    /* payload_len = SRH (8 base + 16 segment) + inner packet. */
    payload_len = (__u16)(sizeof(srh_hdr) + 16u + inner_len);

    /* Build outer IPv6 header. */
    outer_hdr.version     = 6;
    outer_hdr.payload_len = bpf_htons(payload_len);
    outer_hdr.nexthdr     = NEXTHDR_ROUTING;
    outer_hdr.hop_limit   = 64;
    __builtin_memcpy(&outer_hdr.saddr, &outer_src, sizeof(outer_hdr.saddr));
    __builtin_memcpy(&outer_hdr.daddr, &first_seg,   sizeof(outer_hdr.daddr));

    if (bpf_skb_store_bytes(ctx, l3_off, &outer_hdr, sizeof(outer_hdr), 0))
        return TC_ACT_SHOT;

    /* Build SRH. */
    srh_hdr.nexthdr       = inner_nexthdr;
    srh_hdr.hdrlen        = 2;  /* (2+1)*8 = 24 = 8 base + 16 segment */
    srh_hdr.type          = 4;
    srh_hdr.segments_left = 0;
    srh_hdr.first_segment = 0;
    srh_hdr.flags         = 0;
    srh_hdr.tag           = 0;

    if (bpf_skb_store_bytes(ctx, l3_off + sizeof(outer_hdr),
                            &srh_hdr, sizeof(srh_hdr), 0))
        return TC_ACT_SHOT;

    /* Write single segment. */
    if (bpf_skb_store_bytes(ctx,
                            l3_off + sizeof(outer_hdr) + sizeof(srh_hdr),
                            &first_seg, sizeof(first_seg), 0))
        return TC_ACT_SHOT;

    /* Update the innermost ethertype (ETH h_proto or VLAN encap_proto) to IPv6. */
    {
        __be16 proto = bpf_htons(ETH_P_IPV6);

        if (bpf_skb_store_bytes(ctx, l3_off - 2, &proto, sizeof(proto), 0))
            return TC_ACT_SHOT;
    }

    /* FIB lookup on outer IPv6 dst. */
    fib.family      = AF_INET6;
    fib.flowinfo    = 0; /* tc=0, fl=0, version nibble stripped */
    fib.l4_protocol = NEXTHDR_ROUTING;
    fib.tot_len     = payload_len + (__u16)sizeof(struct ipv6hdr);
    fib.ifindex     = ctx->ingress_ifindex;
    __builtin_memcpy(fib.ipv6_src, &outer_src, sizeof(fib.ipv6_src));
    __builtin_memcpy(fib.ipv6_dst, &first_seg,   sizeof(fib.ipv6_dst));

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_dest),
                            fib.dmac, ETH_ALEN, 0) ||
        bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_source),
                            fib.smac, ETH_ALEN, 0))
        return TC_ACT_SHOT;

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
