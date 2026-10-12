#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IP_DF
#define IP_DF 0x4000
#endif
#ifndef BPF_ADJ_ROOM_NET
#define BPF_ADJ_ROOM_NET 0
#endif

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static const __be32 outer_src = bpf_htonl(0x0a080002); /* 10.8.0.2 */
static const __be32 outer_dst = bpf_htonl(0x30000002); /* 48.0.0.2 */

SEC("tc")
int tc_ipip_encap(struct __sk_buff *ctx)
{
    unsigned char *data     = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr  *inner;
    struct iphdr   outer_hdr = {};
    struct bpf_fib_lookup fib = {};
    __be16 eth_proto;
    __u32 l3_off;
    __u16 inner_tot_len;
    __u16 outer_tot_len;
    __wsum csum;
    __u32 s;
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

    if (eth_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    inner = (struct iphdr *)(data + l3_off);
    if ((unsigned char *)(inner + 1) > data_end)
        return TC_ACT_OK;

    /* Save inner tot_len before headroom adjustment invalidates pointers. */
    inner_tot_len = bpf_ntohs(inner->tot_len);

    if (bpf_skb_adjust_room(ctx, (__s32)sizeof(struct iphdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    outer_tot_len = inner_tot_len + (__u16)sizeof(struct iphdr);
    outer_hdr.version  = 4;
    outer_hdr.ihl      = 5;
    outer_hdr.tos      = 0;
    outer_hdr.tot_len  = bpf_htons(outer_tot_len);
    outer_hdr.id       = 0;
    outer_hdr.frag_off = bpf_htons(IP_DF);
    outer_hdr.ttl      = 64;
    outer_hdr.protocol = IPPROTO_IPIP;
    outer_hdr.check    = 0;
    outer_hdr.saddr    = outer_src;
    outer_hdr.daddr    = outer_dst;

    csum = bpf_csum_diff(NULL, 0, (__be32 *)&outer_hdr, sizeof(outer_hdr), 0);
    if ((long)csum < 0)
        return TC_ACT_SHOT;
    s = (__u32)csum;
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    outer_hdr.check = (__be16)~s;

    /* BPF_ADJ_ROOM_NET inserts space at the L3 boundary (l3_off). */
    if (bpf_skb_store_bytes(ctx, l3_off, &outer_hdr, sizeof(outer_hdr), 0))
        return TC_ACT_SHOT;

    fib.family      = AF_INET;
    fib.l4_protocol = IPPROTO_IPIP;
    fib.tot_len     = outer_tot_len;
    fib.ifindex     = ctx->ingress_ifindex;
    fib.tos         = 0;
    fib.ipv4_src    = outer_src;
    fib.ipv4_dst    = outer_dst;

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
