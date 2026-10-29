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
#ifndef NEXTHDR_ROUTING
#define NEXTHDR_ROUTING 43
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

SEC("xdp")
int xdp_srv6_encap(struct xdp_md *ctx)
{
    unsigned char *data     = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;                  // [C]
    struct ipv6hdr *outer;
    struct baseline_sr_hdr *srh;
    struct in6_addr *seg_ptr;
    struct bpf_fib_lookup fib = {};
    __be16 eth_proto;
    __u32 l3_off;
    __u16 pkt_payload_len;
    __u32 pkt_len;
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

    if (eth_proto != bpf_htons(ETH_P_IP) &&                     // [E]
        eth_proto != bpf_htons(ETH_P_IPV6))                     // [E]
        return XDP_PASS;

    /* Extend headroom: new layout is [64 new bytes][old ETH+VLAN][inner...] */
    if (bpf_xdp_adjust_head(ctx, -SRV6_ENCAP_LEN))
        return XDP_ABORTED;

    data     = (unsigned char *)(long)ctx->data;
    data_end = (unsigned char *)(long)ctx->data_end;

    /*
     * After adjust_head(-64), shift ETH+VLAN prefix left by 64 so it sits
     * at data[0..l3_off-1], then write outer headers at data[l3_off].
     * Max prefix: 14 (ETH) + 2*4 (VLANs) = 22 bytes.
     */
    if (l3_off == ETH_HLEN) {                                    /* Ethernet only: 3 loads, 3 stores */
        __u64 w0;
        __u32 w1;
        __u16 w2;

        if (data + SRV6_ENCAP_LEN + ETH_HLEN > data_end)
            return XDP_ABORTED;
        w0 = *(__u64 *)(data + SRV6_ENCAP_LEN);
        w1 = *(__u32 *)(data + SRV6_ENCAP_LEN + 8);
        w2 = *(__u16 *)(data + SRV6_ENCAP_LEN + 12);
        *(__u64 *)data = w0;
        *(__u32 *)(data + 8) = w1;
        *(__u16 *)(data + 12) = w2;
    } else {
#pragma unroll
        for (i = 0; i < 22; i++) {                                   // [L]
            if ((__u32)i >= l3_off)
                break;
            if (data + SRV6_ENCAP_LEN + i + 1 > data_end)           // [B P]
                return XDP_ABORTED;
            data[i] = data[SRV6_ENCAP_LEN + i];                     // [P BW]
        }
    }

    /* Update proto field (ETH h_proto or innermost VLAN encap_proto) to IPv6. */
    if (data + l3_off > data_end)                                // [B P]
        return XDP_ABORTED;
    *((__be16 *)(data + l3_off - 2)) = bpf_htons(ETH_P_IPV6);  // [P E]

    outer   = (struct ipv6hdr *)(data + l3_off);                 // [C P]
    srh     = (struct baseline_sr_hdr *)((unsigned char *)outer + sizeof(*outer));
    seg_ptr = (struct in6_addr *)((unsigned char *)srh + sizeof(*srh));

    if ((unsigned char *)(seg_ptr + 1) > data_end)               // [B]
        return XDP_ABORTED;

    /* pkt_payload_len = everything after the outer IPv6 header. */
    pkt_len = (__u32)((unsigned char *)data_end - (unsigned char *)data);
    pkt_payload_len = (__u16)(pkt_len - l3_off - sizeof(*outer));

    /* Outer IPv6 header: nexthdr=Routing, dst=segment. */
    __builtin_memset(outer, 0, sizeof(*outer));                  // [BW]
    outer->version     = 6;
    outer->payload_len = bpf_htons(pkt_payload_len);             // [E]
    outer->nexthdr     = NEXTHDR_ROUTING;
    outer->hop_limit   = 64;
    __builtin_memcpy(&outer->saddr, &outer_src, sizeof(outer->saddr)); // [BW]
    __builtin_memcpy(&outer->daddr, &first_seg,    sizeof(outer->daddr)); // [BW]

    /* SRH: 1 segment, nexthdr=IPIP (inner IPv4) or IPv6. */
    srh->nexthdr       = (eth_proto == bpf_htons(ETH_P_IP))     // [E]
                         ? IPPROTO_IPIP : IPPROTO_IPV6;
    srh->hdrlen        = 2;  /* (2+1)*8 = 24 = 8 base + 16 segment */
    srh->type          = 4;
    srh->segments_left = 0;
    srh->first_segment = 0;
    srh->flags         = 0;
    srh->tag           = 0;

    /* Single segment entry. */
    __builtin_memcpy(seg_ptr, &first_seg, sizeof(*seg_ptr));       // [BW]

    /* FIB lookup on outer IPv6 dst to find egress interface and MACs. */
    fib.family      = AF_INET6;
    fib.flowinfo    = *(__be32 *)outer & bpf_htonl(0x0fffffff); // [E]
    fib.l4_protocol = NEXTHDR_ROUTING;
    fib.tot_len     = pkt_payload_len + (__u16)sizeof(struct ipv6hdr);
    fib.ifindex     = ctx->ingress_ifindex;
    __builtin_memcpy(fib.ipv6_src, &outer->saddr, sizeof(fib.ipv6_src));
    __builtin_memcpy(fib.ipv6_dst, &outer->daddr, sizeof(fib.ipv6_dst));

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    __builtin_memcpy(data + offsetof(struct ethhdr, h_source), fib.smac, ETH_ALEN); // [P]
    __builtin_memcpy(data + offsetof(struct ethhdr, h_dest),   fib.dmac, ETH_ALEN); // [P]

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
