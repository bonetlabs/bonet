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

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif

struct vlan_hdr_local {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct service_key {
    __be32 vip;
    __u8 proto;
    __u8 pad0;
    __u16 port;
};

struct backend_value {
    __be32 daddr;
    __u16 dport;
    __u16 pad0;
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct service_key);
    __type(value, struct backend_value);
} service_table SEC(".maps");

SEC("classifier")
int tc_service_dnat_e2e(struct __sk_buff *skb)
{
    struct service_key key = {};
    struct backend_value *backend;
    struct vlan_hdr_local vh;
    struct ethhdr eth;
    struct iphdr ip4;
    __be16 eth_proto;
    __be16 dport_be;
    __be16 new_dport_be;
    __be16 udp_check;
    __u32 l3_off;
    __u32 l4_off;
    __u32 hlen;
    __u64 bytes = skb->len;
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
        bpf_ntohs(ip4.tot_len) < hlen)
        return TC_ACT_OK;

    frag = bpf_ntohs(ip4.frag_off);
    if (frag & (IP_MF | IP_OFFSET))
        return TC_ACT_OK;

    if (ip4.protocol != IPPROTO_TCP && ip4.protocol != IPPROTO_UDP)
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
    } else {
        if (l4_off > skb->len ||
            sizeof(struct udphdr) > skb->len - l4_off ||
            bpf_skb_load_bytes(skb,
                               l4_off + offsetof(struct udphdr, dest),
                               &dport_be,
                               sizeof(dport_be)) < 0)
            return TC_ACT_OK;
    }

    key.vip = ip4.daddr;
    key.proto = ip4.protocol;
    key.port = bpf_ntohs(dport_be);

    backend = bpf_map_lookup_elem(&service_table, &key);
    if (!backend)
        return TC_ACT_OK;

    __sync_fetch_and_add(&backend->packets, 1);
    __sync_fetch_and_add(&backend->bytes, bytes);

    if (ip4.protocol == IPPROTO_TCP) {
        if (backend->dport != key.port) {
            new_dport_be = bpf_htons(backend->dport);
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
    } else if (backend->dport != key.port) {
        new_dport_be = bpf_htons(backend->dport);
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

    if (backend->daddr == key.vip)
        return TC_ACT_OK;

    if (bpf_l3_csum_replace(skb,
                            l3_off + offsetof(struct iphdr, check),
                            key.vip,
                            backend->daddr,
                            sizeof(backend->daddr)) < 0)
        return TC_ACT_SHOT;

    if (ip4.protocol == IPPROTO_TCP) {
        if (bpf_l4_csum_replace(skb,
                                l4_off + offsetof(struct tcphdr, check),
                                key.vip,
                                backend->daddr,
                                sizeof(backend->daddr) | BPF_F_PSEUDO_HDR) < 0)
            return TC_ACT_SHOT;
    } else {
        if (bpf_skb_load_bytes(skb,
                               l4_off + offsetof(struct udphdr, check),
                               &udp_check,
                               sizeof(udp_check)) < 0)
            return TC_ACT_SHOT;
        if (udp_check != 0 &&
            bpf_l4_csum_replace(skb,
                                l4_off + offsetof(struct udphdr, check),
                                key.vip,
                                backend->daddr,
                                sizeof(backend->daddr) |
                                    BPF_F_PSEUDO_HDR |
                                    BPF_F_MARK_MANGLED_0) < 0)
            return TC_ACT_SHOT;
    }

    if (bpf_skb_store_bytes(skb,
                            l3_off + offsetof(struct iphdr, daddr),
                            &backend->daddr,
                            sizeof(backend->daddr),
                            BPF_F_INVALIDATE_HASH) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
