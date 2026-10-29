#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IP_DF
#define IP_DF 0x4000
#endif

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static const __be32 outer_src = bpf_htonl(0x0a080002); /* 10.8.0.2 */
static const __be32 outer_dst = bpf_htonl(0x30000002); /* 48.0.0.2 */

SEC("xdp")
int xdp_ipip_encap(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *inner;
    struct iphdr *outer;
    struct bpf_fib_lookup fib = {};
    __be16 eth_proto;
    __u32 l3_off;
    __u16 inner_len;
    __u16 outer_len;
    __wsum csum;
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

    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    inner = (struct iphdr *)(data + l3_off);
    if ((unsigned char *)(inner + 1) > data_end)
        return XDP_PASS;

    inner_len = bpf_ntohs(inner->tot_len);

    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr)))
        return XDP_ABORTED;

    data = (unsigned char *)(long)ctx->data;
    data_end = (unsigned char *)(long)ctx->data_end;

    /*
     * After adjust_head(-20), layout is:
     *   [20 new bytes][old ETH+VLAN][inner IP][...]
     * Shift ETH+VLAN prefix left by 20 so it sits at data[0..l3_off-1],
     * then write outer IP at data[l3_off].
     * Max prefix: 14 (ETH) + 2*4 (VLANs) = 22 bytes.
     */
    if (l3_off == ETH_HLEN) {                                    /* Ethernet only: 3 loads, 3 stores */
        __u64 w0;
        __u32 w1;
        __u16 w2;

        if (data + 20 + ETH_HLEN > data_end)
            return XDP_ABORTED;
        w0 = *(__u64 *)(data + 20);
        w1 = *(__u32 *)(data + 20 + 8);
        w2 = *(__u16 *)(data + 20 + 12);
        *(__u64 *)data = w0;
        *(__u32 *)(data + 8) = w1;
        *(__u16 *)(data + 12) = w2;
    } else {
#pragma unroll
        for (i = 0; i < 22; i++) {
            if ((__u32)i >= l3_off)
                break;
            if (data + 20 + i + 1 > data_end)
                return XDP_ABORTED;
            data[i] = data[20 + i];
        }
    }

    /* Update proto field (ETH h_proto or innermost VLAN encap_proto). */
    if (data + l3_off > data_end)
        return XDP_ABORTED;
    *((__be16 *)(data + l3_off - 2)) = bpf_htons(ETH_P_IP);

    outer = (struct iphdr *)(data + l3_off);
    inner = (struct iphdr *)(data + l3_off + sizeof(*outer));
    if ((unsigned char *)(inner + 1) > data_end)
        return XDP_ABORTED;

    outer_len = inner_len + (__u16)sizeof(*outer);
    outer->version  = 4;
    outer->ihl      = 5;
    outer->tos      = 0;
    outer->tot_len  = bpf_htons(outer_len);
    outer->id       = 0;
    outer->frag_off = bpf_htons(IP_DF);
    outer->ttl      = 64;
    outer->protocol = IPPROTO_IPIP;
    outer->check    = 0;
    outer->saddr    = outer_src;
    outer->daddr    = outer_dst;

    csum = bpf_csum_diff(NULL, 0, (__be32 *)outer, sizeof(*outer), 0);
    if ((long)csum < 0)
        return XDP_ABORTED;
    {
        __u32 s = (__u32)csum;
        s = (s & 0xffff) + (s >> 16);
        s = (s & 0xffff) + (s >> 16);
        outer->check = (__be16)~s;
    }

    fib.family      = AF_INET;
    fib.l4_protocol = outer->protocol;
    fib.tot_len     = outer_len;
    fib.ifindex     = ctx->ingress_ifindex;
    fib.tos         = outer->tos;
    fib.ipv4_src    = outer->saddr;
    fib.ipv4_dst    = outer->daddr;

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    __builtin_memcpy(data + offsetof(struct ethhdr, h_source), fib.smac, ETH_ALEN);
    __builtin_memcpy(data + offsetof(struct ethhdr, h_dest), fib.dmac, ETH_ALEN);

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
