#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bnt_xdp.h>

#define ACL_PASS 0
#define ACL_DROP 1

struct acl_key {
    __u8  l4_proto;
    __u8  pad0;
    __u16 dport;
};

struct acl_value {
    __u8 action;
    __u8 pad[7];
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct acl_key);
    __type(value, struct acl_value);
} acl_rules SEC(".maps");

SEC("xdp")
int xdp_acl_firewall_e2e(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 bytes = data_end - data;
    bnt_eth eth;
    bnt_ipv4 ip4;
    bnt_ipv6 ip6;
    bnt_tcp tcp;
    bnt_udp udp;
    struct acl_key key = {};
    struct acl_value *rule;
    __u16 dport;

    if (bnt_eth__parse(ctx, 0, &eth))
        return XDP_PASS;

    if (!bnt_eth__next_ipv4(&eth, &ip4)) {
        if (!bnt_ipv4__next_tcp(&ip4, &tcp)) {
            if (bnt_tcp__get_dest(&tcp, &dport))
                return XDP_PASS;
            key.l4_proto = IPPROTO_TCP;
            key.dport = dport;
            goto apply_rule;
        }

        if (!bnt_ipv4__next_udp(&ip4, &udp)) {
            if (bnt_udp__get_dest(&udp, &dport))
                return XDP_PASS;
            key.l4_proto = IPPROTO_UDP;
            key.dport = dport;
            goto apply_rule;
        }

        return XDP_PASS;
    }

    if (!bnt_eth__next_ipv6(&eth, &ip6)) {
        if (!bnt_ipv6__next_tcp(&ip6, &tcp)) {
            if (bnt_tcp__get_dest(&tcp, &dport))
                return XDP_PASS;
            key.l4_proto = IPPROTO_TCP;
            key.dport = dport;
            goto apply_rule;
        }

        if (!bnt_ipv6__next_udp(&ip6, &udp)) {
            if (bnt_udp__get_dest(&udp, &dport))
                return XDP_PASS;
            key.l4_proto = IPPROTO_UDP;
            key.dport = dport;
            goto apply_rule;
        }

        return XDP_PASS;
    }

    return XDP_PASS;

apply_rule:
    rule = bpf_map_lookup_elem(&acl_rules, &key);
    if (!rule)
        return XDP_PASS;

    __sync_fetch_and_add(&rule->packets, 1);
    __sync_fetch_and_add(&rule->bytes, bytes);

    if (rule->action == ACL_DROP)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
