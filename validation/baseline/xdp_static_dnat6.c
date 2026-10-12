#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct baseline_icmp6_hdr {
    __u8   type;
    __u8   code;
    __be16 cksum;
};

/* old_dst: fd03::2 (traffic_dst_ipv6) */
static const __u8 old_dst_bytes[16] = {
    0xfd, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};
/* new_dst: fd07::1 (tg_rx_ipv6) */
static const __u8 new_dst_bytes[16] = {
    0xfd, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

SEC("xdp")
int xdp_static_dnat6(struct xdp_md *ctx)
{
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *ip6;
    struct bpf_fib_lookup fib = {};
    __be16 eth_proto;
    __u32 l3_off;
    __u32 l4_off;
    __u32 sum;
    __u8 hop_limit;
    int ret;
    int i;
    int j;

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

    if (__builtin_memcmp(&ip6->daddr, old_dst_bytes, 16) != 0)
        return XDP_PASS;

    l4_off = l3_off + sizeof(*ip6);

    /* Update L4 checksum before writing new daddr to the IP header. */
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);

        if ((unsigned char *)(tcp + 1) <= data_end) {
            sum = (~(__u32)bpf_ntohs(tcp->check)) & 0xffff;
#pragma unroll
            for (j = 0; j < 8; j++) {
                __u16 ow = ((__u16)old_dst_bytes[j * 2] << 8) | old_dst_bytes[j * 2 + 1];
                __u16 nw = ((__u16)new_dst_bytes[j * 2] << 8) | new_dst_bytes[j * 2 + 1];
                sum += (~(__u32)ow) & 0xffff;
                sum += (__u32)nw;
            }
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            tcp->check = bpf_htons((__u16)~sum);
        }
    } else if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(data + l4_off);

        if ((unsigned char *)(udp + 1) <= data_end && udp->check != 0) {
            sum = (~(__u32)bpf_ntohs(udp->check)) & 0xffff;
#pragma unroll
            for (j = 0; j < 8; j++) {
                __u16 ow = ((__u16)old_dst_bytes[j * 2] << 8) | old_dst_bytes[j * 2 + 1];
                __u16 nw = ((__u16)new_dst_bytes[j * 2] << 8) | new_dst_bytes[j * 2 + 1];
                sum += (~(__u32)ow) & 0xffff;
                sum += (__u32)nw;
            }
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            udp->check = bpf_htons((__u16)~sum);
            if (udp->check == 0)
                udp->check = bpf_htons(0xffff);
        }
    } else if (ip6->nexthdr == IPPROTO_ICMPV6) {
        struct baseline_icmp6_hdr *icmp6 =
            (struct baseline_icmp6_hdr *)(data + l4_off);

        if ((unsigned char *)(icmp6 + 1) <= data_end) {
            sum = (~(__u32)bpf_ntohs(icmp6->cksum)) & 0xffff;
#pragma unroll
            for (j = 0; j < 8; j++) {
                __u16 ow = ((__u16)old_dst_bytes[j * 2] << 8) | old_dst_bytes[j * 2 + 1];
                __u16 nw = ((__u16)new_dst_bytes[j * 2] << 8) | new_dst_bytes[j * 2 + 1];
                sum += (~(__u32)ow) & 0xffff;
                sum += (__u32)nw;
            }
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            icmp6->cksum = bpf_htons((__u16)~sum);
        }
    }

    __builtin_memcpy(&ip6->daddr, new_dst_bytes, 16);

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
    __builtin_memcpy(eth->h_dest,   fib.dmac, ETH_ALEN);

    return bpf_redirect(fib.ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
