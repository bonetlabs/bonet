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

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static const __be32 blacklist_src = bpf_htonl(0x0a080001); /* 10.8.0.1 */
static const __u8 marked_tos = 0x2e;

SEC("xdp")
int xdp_mmlf(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;          // [CC]
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;  // [CC]
    struct ethhdr *eth = (struct ethhdr *)data;                  // [C]
    struct iphdr *ip;
    struct bpf_fib_lookup fib = {};
    __be16 eth_proto;
    __be16 old_word;
    __be16 new_word;
    __u32 sum;
    __u32 l3_off;
    __u32 hlen;
    __u16 total_len;
    __u8 ttl;
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

    if (eth_proto != bpf_htons(ETH_P_IP))                       // [E]
        return XDP_PASS;

    ip = (struct iphdr *)(data + l3_off);                        // [C P]
    if ((unsigned char *)(ip + 1) > data_end || ip->version != 4) // [B]
        return XDP_PASS;

    hlen = (__u32)ip->ihl * 4;
    if (hlen < sizeof(*ip) || hlen > 60 ||
        data + l3_off + hlen > data_end)                         // [B P]
        return XDP_PASS;

    total_len = bpf_ntohs(ip->tot_len);                          // [E]
    if (total_len < hlen)
        return XDP_PASS;

    if (ip->saddr == blacklist_src) {
        old_word = *(__be16 *)ip;
        new_word = bpf_htons((bpf_ntohs(old_word) & 0xff00) | marked_tos); // [E]
        ip->tos = marked_tos;
        sum  = (~(__u32)bpf_ntohs(ip->check)) & 0xffff;         // [E]
        sum += (~(__u32)bpf_ntohs(old_word)) & 0xffff;          // [E]
        sum += (__u32)bpf_ntohs(new_word);                       // [E]
        sum  = (sum & 0xffff) + (sum >> 16);
        sum  = (sum & 0xffff) + (sum >> 16);
        ip->check = bpf_htons((__u16)~sum);                      // [E CS]
    }

    ttl = ip->ttl;
    if (ttl <= 1)
        return XDP_DROP;

    fib.family = AF_INET;
    fib.l4_protocol = ip->protocol;
    fib.tot_len = total_len;
    fib.ifindex = ctx->ingress_ifindex;
    fib.tos = ip->tos;
    fib.ipv4_src = ip->saddr;
    fib.ipv4_dst = ip->daddr;

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    old_word = *(__be16 *)((unsigned char *)ip + offsetof(struct iphdr, ttl));
    new_word = bpf_htons(((__u16)(ttl - 1) << 8) |               // [E]
                         (bpf_ntohs(old_word) & 0x00ff));        // [E]
    ip->ttl = ttl - 1;
    sum  = (~(__u32)bpf_ntohs(ip->check)) & 0xffff;              // [E]
    sum += (~(__u32)bpf_ntohs(old_word)) & 0xffff;               // [E]
    sum += (__u32)bpf_ntohs(new_word);                           // [E]
    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
    ip->check = bpf_htons((__u16)~sum);                          // [E CS]

    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
