#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_tc_ingress.h"
#include "test_result.h"

#define PORT_FROM 7777
#define PORT_TO   8888
#define IPV4_CONST(a, b, c, d) ((__be32)bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d)))

static const __be32 rewrite_saddr = IPV4_CONST(198, 51, 100, 10);

SEC("classifier")
int tc_ipv4_udp_saddr_inc(struct __sk_buff *skb)
{
    bnt_ipv4 ip4;
    bnt_udp udp;
    __u16 dport = 0;
    __be32 saddr = 0;
    int ret;

    ret = bnt_ctx__find_ipv4(skb, &ip4);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_ctx__find_udp(skb, &udp);
    if (ret)
        return TC_ACT_OK;
    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret || dport != PORT_FROM)
        return TC_ACT_OK;

    ret = bnt_ipv4__set_saddr(&ip4, rewrite_saddr);
    if (ret) {
        /* d[0]=1: set_saddr failed; seen=error code */
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 1, 0, 0);
        return TC_ACT_SHOT;
    }
    ret = bnt_udp__set_dport(&udp, PORT_TO);
    if (ret) {
        /* d[0]=2: set_dport failed; seen=error code */
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 2, 0, 0);
        return TC_ACT_SHOT;
    }
    ret = bnt_ipv4__get_saddr(&ip4, &saddr);
    if (ret) {
        /* d[0]=3: get_saddr failed; seen=error code */
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 3, 0, 0);
        return TC_ACT_SHOT;
    }
    ret = bnt_udp__get_dport(&udp, &dport);
    if (ret) {
        /* d[0]=4: get_dport failed; seen=error code */
        bnt_test_fail_detail((__u64)(unsigned int)ret, PORT_TO, 4, 0, 0);
        return TC_ACT_SHOT;
    }
    if (saddr != rewrite_saddr || dport != PORT_TO) {
        /* d[0]=5: value mismatch; d[1]=actual saddr, d[2]=rewrite_saddr */
        bnt_test_fail_detail(dport, PORT_TO, 5, saddr, rewrite_saddr);
        return TC_ACT_SHOT;
    }

    bnt_test_ok(dport, PORT_TO);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
