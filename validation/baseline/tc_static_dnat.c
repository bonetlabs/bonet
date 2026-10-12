#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
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

SEC("tc")
int tc_static_dnat(struct __sk_buff *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
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
    __u16 total_len;
    __u16 frag;
    __u8 ttl;
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

    ip = (struct iphdr *)(data + l3_off);
    if ((unsigned char *)(ip + 1) > data_end || ip->version != 4)
        return TC_ACT_OK;

    hlen = (__u32)ip->ihl * 4;
    if (hlen < sizeof(*ip) || hlen > 60 ||
        data + l3_off + hlen > data_end)
        return TC_ACT_OK;

    total_len = bpf_ntohs(ip->tot_len);
    if (total_len < hlen)
        return TC_ACT_OK;

    frag = bpf_ntohs(ip->frag_off);

    if (ip->daddr == old_dst) {
        l4_off = l3_off + hlen;
        old_h  = bpf_ntohl(old_dst); new_h = bpf_ntohl(new_dst);
        sum  = (~(__u32)bpf_ntohs(ip->check)) & 0xffff;
        sum += (~(old_h >> 16)) & 0xffff; sum += (~old_h) & 0xffff;
        sum += new_h >> 16;               sum += new_h & 0xffff;
        sum  = (sum & 0xffff) + (sum >> 16);
        sum  = (sum & 0xffff) + (sum >> 16);
        ip->check = bpf_htons((__u16)~sum);

        /* L4 header present only in non-subsequent fragments (IP_OFFSET == 0). */
        if (!(frag & IP_OFFSET)) {
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);

                if ((unsigned char *)(tcp + 1) <= data_end) {
                    sum  = (~(__u32)bpf_ntohs(tcp->check)) & 0xffff;
                    sum += (~(old_h >> 16)) & 0xffff; sum += (~old_h) & 0xffff;
                    sum += new_h >> 16;               sum += new_h & 0xffff;
                    sum  = (sum & 0xffff) + (sum >> 16);
                    sum  = (sum & 0xffff) + (sum >> 16);
                    tcp->check = bpf_htons((__u16)~sum);
                }
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (struct udphdr *)(data + l4_off);

                if ((unsigned char *)(udp + 1) <= data_end && udp->check != 0) {
                    sum  = (~(__u32)bpf_ntohs(udp->check)) & 0xffff;
                    sum += (~(old_h >> 16)) & 0xffff; sum += (~old_h) & 0xffff;
                    sum += new_h >> 16;               sum += new_h & 0xffff;
                    sum  = (sum & 0xffff) + (sum >> 16);
                    sum  = (sum & 0xffff) + (sum >> 16);
                    udp->check = bpf_htons((__u16)~sum);
                    if (udp->check == 0)
                        udp->check = bpf_htons(0xffff);
                }
            }
        }

        ip->daddr = new_dst;
    }

    ttl = ip->ttl;
    if (ttl <= 1)
        return TC_ACT_SHOT;

    fib.family      = AF_INET;
    fib.l4_protocol = ip->protocol;
    fib.tot_len     = total_len;
    fib.ifindex     = ctx->ingress_ifindex;
    fib.tos         = ip->tos;
    fib.ipv4_src    = ip->saddr;
    fib.ipv4_dst    = ip->daddr;

    ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return TC_ACT_OK;

    old_word = *(__be16 *)((unsigned char *)ip + offsetof(struct iphdr, ttl));
    new_word = bpf_htons(((__u16)(ttl - 1) << 8) |
                         (bpf_ntohs(old_word) & 0x00ff));
    ip->ttl = ttl - 1;
    sum  = (~(__u32)bpf_ntohs(ip->check)) & 0xffff;
    sum += (~(__u32)bpf_ntohs(old_word)) & 0xffff;
    sum += (__u32)bpf_ntohs(new_word);
    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
    ip->check = bpf_htons((__u16)~sum);

    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
