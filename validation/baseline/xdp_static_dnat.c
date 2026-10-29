#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static const __be32 old_dst = bpf_htonl(0x30000002); /* 48.0.0.2 */
static const __be32 new_dst = bpf_htonl(0x0a070001); /* 10.7.0.1 */

SEC("xdp")
int xdp_static_dnat(struct xdp_md *ctx)
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
    __u32 old_h;
    __u32 new_h;
    __u32 l3_off;
    __u32 hlen;
    __u32 l4_off;
    __be16 *check;
    __u16 frag;
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
    if ((unsigned char *)(ip + 1) > data_end)                    // [B]
        return XDP_PASS;

    if (ip->daddr != old_dst)
        return XDP_PASS;

    /* Find the L4 checksum before writing anything. It is there only with a
     * complete IP header, in a non-subsequent fragment (IP_OFFSET == 0). */
    hlen = (__u32)ip->ihl * 4;
    frag = bpf_ntohs(ip->frag_off);                              // [E]
    check = NULL;
    if (hlen >= sizeof(*ip) && !(frag & IP_OFFSET) &&
        (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)) {
        l4_off = l3_off + hlen + (ip->protocol == IPPROTO_TCP ? offsetof(struct tcphdr, check)
                                                              : offsetof(struct udphdr, check));
        check = (__be16 *)(data + l4_off);                       // [C P]
        if ((unsigned char *)(check + 1) > data_end)             // [B]
            return XDP_ABORTED;
        if (ip->protocol == IPPROTO_UDP && *check == 0)
            check = NULL;                                        /* UDP checksum 0 = none */
    }

    old_h = bpf_ntohl(old_dst); new_h = bpf_ntohl(new_dst);     // [E]
    sum  = (~(__u32)bpf_ntohs(ip->check)) & 0xffff;             // [E]
    sum += (~(old_h >> 16)) & 0xffff; sum += (~old_h) & 0xffff;
    sum += new_h >> 16;               sum += new_h & 0xffff;
    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
    ip->check = bpf_htons((__u16)~sum);                          // [E CS]

    if (check) {
        sum  = (~(__u32)bpf_ntohs(*check)) & 0xffff;            // [E]
        sum += (~(old_h >> 16)) & 0xffff; sum += (~old_h) & 0xffff;
        sum += new_h >> 16;               sum += new_h & 0xffff;
        sum  = (sum & 0xffff) + (sum >> 16);
        sum  = (sum & 0xffff) + (sum >> 16);
        *check = bpf_htons((__u16)~sum);                         // [E CS]
        if (ip->protocol == IPPROTO_UDP && *check == 0)
            *check = bpf_htons(0xffff);                          // [E CS]
    }

    ip->daddr = new_dst;

    fib.family = AF_INET;
    fib.l4_protocol = ip->protocol;
    fib.tot_len = bpf_ntohs(ip->tot_len);                        // [E]
    fib.ifindex = ctx->ingress_ifindex;
    fib.tos = ip->tos;
    fib.ipv4_src = ip->saddr;
    fib.ipv4_dst = ip->daddr;

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    ttl = ip->ttl;
    if (ttl <= 1)
        return XDP_DROP;

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
