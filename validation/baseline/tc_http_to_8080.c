#include <stddef.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct baseline_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif
#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP 0
#endif
#ifndef NEXTHDR_ROUTING
#define NEXTHDR_ROUTING 43
#endif
#ifndef NEXTHDR_FRAGMENT
#define NEXTHDR_FRAGMENT 44
#endif
#ifndef NEXTHDR_AUTH
#define NEXTHDR_AUTH 51
#endif
#ifndef NEXTHDR_DEST
#define NEXTHDR_DEST 60
#endif
#ifndef NEXTHDR_MOBILITY
#define NEXTHDR_MOBILITY 135
#endif
#ifndef NEXTHDR_HIP
#define NEXTHDR_HIP 139
#endif
#ifndef NEXTHDR_SHIM
#define NEXTHDR_SHIM 140
#endif

SEC("classifier")
int tc_http_to_8080(struct __sk_buff *skb)
{
    struct baseline_vlan_hdr vh;
    struct ethhdr eth;
    struct iphdr ip4;
    struct ipv6hdr ip6;
    __be16 eth_proto;
    __be16 dport_be;
    __be16 new_dport_be;
    __u8 ext[8];
    __u8 l4_proto;
    __u32 ext_len;
    __u32 l3_off;
    __u32 l4_off;
    __u32 hlen;
    __u16 frag;
    int i;

    if (sizeof(eth) > skb->len ||
        bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK;

    eth_proto = eth.h_proto;
    l3_off = sizeof(eth);

#pragma unroll
    for (i = 0; i < 2; i++) {
        if (eth_proto != bpf_htons(ETH_P_8021Q) &&
            eth_proto != bpf_htons(ETH_P_8021AD))
            break;

        if (l3_off > skb->len || sizeof(vh) > skb->len - l3_off ||
            bpf_skb_load_bytes(skb, l3_off, &vh, sizeof(vh)) < 0)
            return TC_ACT_OK;

        eth_proto = vh.h_vlan_encapsulated_proto;
        l3_off += sizeof(vh);
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        if (l3_off > skb->len || sizeof(ip4) > skb->len - l3_off ||
            bpf_skb_load_bytes(skb, l3_off, &ip4, sizeof(ip4)) < 0 ||
            ip4.version != 4)
            return TC_ACT_OK;

        hlen = (__u32)ip4.ihl * 4;
        if (hlen < sizeof(ip4) || hlen > 60 ||
            l3_off > skb->len || hlen > skb->len - l3_off ||
            bpf_ntohs(ip4.tot_len) < hlen)
            return TC_ACT_OK;

        frag = bpf_ntohs(ip4.frag_off);
        if ((frag & (IP_MF | IP_OFFSET)) || ip4.protocol != IPPROTO_TCP)
            return TC_ACT_OK;

        l4_proto = ip4.protocol;
        l4_off = l3_off + hlen;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        if (l3_off > skb->len || sizeof(ip6) > skb->len - l3_off ||
            bpf_skb_load_bytes(skb, l3_off, &ip6, sizeof(ip6)) < 0 ||
            ip6.version != 6)
            return TC_ACT_OK;

        l4_proto = ip6.nexthdr;
        l4_off = l3_off + sizeof(ip6);

#pragma unroll
        for (i = 0; i < 6; i++) {
            if (l4_proto != NEXTHDR_HOP &&
                l4_proto != NEXTHDR_ROUTING &&
                l4_proto != NEXTHDR_FRAGMENT &&
                l4_proto != NEXTHDR_AUTH &&
                l4_proto != NEXTHDR_DEST &&
                l4_proto != NEXTHDR_MOBILITY &&
                l4_proto != NEXTHDR_HIP &&
                l4_proto != NEXTHDR_SHIM)
                break;

            if (l4_off > skb->len || sizeof(ext) > skb->len - l4_off ||
                bpf_skb_load_bytes(skb, l4_off, ext, sizeof(ext)) < 0)
                return TC_ACT_OK;

            if (l4_proto == NEXTHDR_FRAGMENT)
                return TC_ACT_OK;

            if (l4_proto == NEXTHDR_AUTH)
                ext_len = ((__u32)ext[1] + 2) * 4;
            else
                ext_len = ((__u32)ext[1] + 1) * 8;

            if (ext_len < 8 || l4_off > skb->len || ext_len > skb->len - l4_off)
                return TC_ACT_OK;

            l4_proto = ext[0];
            l4_off += ext_len;
        }

        if (l4_proto == NEXTHDR_HOP ||
            l4_proto == NEXTHDR_ROUTING ||
            l4_proto == NEXTHDR_FRAGMENT ||
            l4_proto == NEXTHDR_AUTH ||
            l4_proto == NEXTHDR_DEST ||
            l4_proto == NEXTHDR_MOBILITY ||
            l4_proto == NEXTHDR_HIP ||
            l4_proto == NEXTHDR_SHIM ||
            l4_proto != IPPROTO_TCP)
            return TC_ACT_OK;
    } else {
        return TC_ACT_OK;
    }

    if (l4_proto != IPPROTO_TCP ||
        l4_off > skb->len ||
        sizeof(struct tcphdr) > skb->len - l4_off ||
        bpf_skb_load_bytes(skb,
                           l4_off + offsetof(struct tcphdr, dest),
                           &dport_be,
                           sizeof(dport_be)) < 0 ||
        bpf_ntohs(dport_be) != 80)
        return TC_ACT_OK;

    new_dport_be = bpf_htons(8080);
    if (bpf_l4_csum_replace(skb,
                            l4_off + offsetof(struct tcphdr, check),
                            dport_be,
                            new_dport_be,
                            sizeof(new_dport_be)) < 0)
        return TC_ACT_SHOT;

    if (bpf_skb_store_bytes(skb,
                            l4_off + offsetof(struct tcphdr, dest),
                            &new_dport_be,
                            sizeof(new_dport_be),
                            BPF_F_INVALIDATE_HASH) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
