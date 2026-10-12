#include <stddef.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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

static const __be32 old_ip = bpf_htonl(0xc0a80164);
static const __be32 new_ip = bpf_htonl(0x0a000002);

SEC("classifier")
int tc_ipv4_dnat(struct __sk_buff *skb)
{
    struct baseline_vlan_hdr vh;
    struct ethhdr eth;
    struct iphdr ip4;
    __be16 eth_proto;
    __be16 dport_be;
    __be16 new_dport_be;
    __be16 udp_check;
    __u32 l3_off;
    __u32 l4_off;
    __u32 hlen;
    __u16 dport;
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

    if (eth_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (l3_off > skb->len || sizeof(ip4) > skb->len - l3_off ||
        bpf_skb_load_bytes(skb, l3_off, &ip4, sizeof(ip4)) < 0 ||
        ip4.version != 4)
        return TC_ACT_OK;

    hlen = (__u32)ip4.ihl * 4;
    if (hlen < sizeof(ip4) || hlen > 60 ||
        l3_off > skb->len || hlen > skb->len - l3_off ||
        bpf_ntohs(ip4.tot_len) < hlen ||
        ip4.daddr != old_ip)
        return TC_ACT_OK;

    frag = bpf_ntohs(ip4.frag_off);
    if (frag & (IP_MF | IP_OFFSET))
        return TC_ACT_OK;

    l4_off = l3_off + hlen;

    if (ip4.protocol == IPPROTO_TCP) {
        if (l4_off > skb->len ||
            sizeof(struct tcphdr) > skb->len - l4_off ||
            bpf_skb_load_bytes(skb,
                               l4_off + offsetof(struct tcphdr, dest),
                               &dport_be,
                               sizeof(dport_be)) < 0)
            return TC_ACT_OK;

        dport = bpf_ntohs(dport_be);
        if (dport == 443) {
            new_dport_be = bpf_htons(8443);
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
        }
    } else if (ip4.protocol == IPPROTO_UDP) {
        if (l4_off > skb->len ||
            sizeof(struct udphdr) > skb->len - l4_off ||
            bpf_skb_load_bytes(skb,
                               l4_off + offsetof(struct udphdr, dest),
                               &dport_be,
                               sizeof(dport_be)) < 0)
            return TC_ACT_OK;

        dport = bpf_ntohs(dport_be);
        if (dport == 53) {
            new_dport_be = bpf_htons(1053);
            if (bpf_skb_load_bytes(skb,
                                   l4_off + offsetof(struct udphdr, check),
                                   &udp_check,
                                   sizeof(udp_check)) < 0)
                return TC_ACT_SHOT;
            if (udp_check != 0 &&
                bpf_l4_csum_replace(skb,
                                    l4_off + offsetof(struct udphdr, check),
                                    dport_be,
                                    new_dport_be,
                                    sizeof(new_dport_be) |
                                        BPF_F_MARK_MANGLED_0) < 0)
                return TC_ACT_SHOT;
            if (bpf_skb_store_bytes(skb,
                                    l4_off + offsetof(struct udphdr, dest),
                                    &new_dport_be,
                                    sizeof(new_dport_be),
                                    BPF_F_INVALIDATE_HASH) < 0)
                return TC_ACT_SHOT;
        }
    }

    if (bpf_l3_csum_replace(skb,
                            l3_off + offsetof(struct iphdr, check),
                            old_ip,
                            new_ip,
                            sizeof(new_ip)) < 0)
        return TC_ACT_SHOT;

    if (ip4.protocol == IPPROTO_TCP) {
        if (bpf_l4_csum_replace(skb,
                                l4_off + offsetof(struct tcphdr, check),
                                old_ip,
                                new_ip,
                                sizeof(new_ip) | BPF_F_PSEUDO_HDR) < 0)
            return TC_ACT_SHOT;
    } else if (ip4.protocol == IPPROTO_UDP) {
        if (bpf_skb_load_bytes(skb,
                               l4_off + offsetof(struct udphdr, check),
                               &udp_check,
                               sizeof(udp_check)) < 0)
            return TC_ACT_SHOT;
        if (udp_check != 0 &&
            bpf_l4_csum_replace(skb,
                                l4_off + offsetof(struct udphdr, check),
                                old_ip,
                                new_ip,
                                sizeof(new_ip) |
                                    BPF_F_PSEUDO_HDR |
                                    BPF_F_MARK_MANGLED_0) < 0)
            return TC_ACT_SHOT;
    }

    if (bpf_skb_store_bytes(skb,
                            l3_off + offsetof(struct iphdr, daddr),
                            &new_ip,
                            sizeof(new_ip),
                            BPF_F_INVALIDATE_HASH) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
