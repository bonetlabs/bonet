#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"

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
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_tcp tcp;
    bnt_udp udp;
    __be32 vip;
    __u16 dport;
    __u32 l4_off;
    __u8 proto;
    __u64 bytes = skb->len;

    if (bnt_eth__parse(skb, 0, &eth))
        return TC_ACT_OK;

    if (bnt_eth__next_ipv4(&eth, &ip4))
        return TC_ACT_OK;

    if (bnt_ipv4__get_daddr(&ip4, &vip))
        return TC_ACT_OK;

    if (bnt_ipv4__next_proto_off(&ip4, &proto, &l4_off))
        return TC_ACT_OK;

    if (proto == IPPROTO_TCP) {
        if (bnt_tcp__parse(skb, l4_off, &tcp))
            return TC_ACT_OK;
        if (bnt_tcp__get_dport(&tcp, &dport))
            return TC_ACT_OK;
    } else if (proto == IPPROTO_UDP) {
        if (bnt_udp__parse(skb, l4_off, &udp))
            return TC_ACT_OK;
        if (bnt_udp__get_dport(&udp, &dport))
            return TC_ACT_OK;
    } else {
        return TC_ACT_OK;
    }

    key.vip = vip;
    key.proto = proto;
    key.port = dport;

    backend = bpf_map_lookup_elem(&service_table, &key);
    if (!backend)
        return TC_ACT_OK;

    __sync_fetch_and_add(&backend->packets, 1);
    __sync_fetch_and_add(&backend->bytes, bytes);

    if (proto == IPPROTO_TCP) {
        if (backend->dport != dport &&
            bnt_tcp__set_dport(&tcp, backend->dport))
            return TC_ACT_SHOT;
    } else if (proto == IPPROTO_UDP) {
        if (backend->dport != dport &&
            bnt_udp__set_dport(&udp, backend->dport))
            return TC_ACT_SHOT;
    }

    if (backend->daddr != vip &&
        bnt_ipv4__set_daddr(&ip4, backend->daddr))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
