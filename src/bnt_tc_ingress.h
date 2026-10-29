/* SPDX-License-Identifier: MIT */
#ifndef BNT_TC_INGRESS_H
#define BNT_TC_INGRESS_H

/* gcc only: #pragma unroll is clang's (gcc ignores it, as it should), and
 * -Wmaybe-uninitialized misfires on views that a parse call fills in only on
 * success. Both are silenced inside the BONet headers only. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

/*
 * bnt_tc_ingress.h - verifier-friendly packet parsing helpers for TC ingress.
 *
 * Public header views are lightweight packet cursors: they keep only the skb
 * context pointer and the header offset. Packet fields are read from packet
 * memory by getters/setters or by internal __bnt_* metadata helpers.
 */

#include <stddef.h>

#ifndef __VMLINUX_H__
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/in6.h>
#include <linux/in.h>
#endif

#ifndef __BPF_HELPERS__
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) =
    (void *)BPF_FUNC_skb_load_bytes;
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset, const void *from, __u32 len, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*bpf_skb_adjust_room)(void *skb, __s32 len_diff, __u32 mode, __u64 flags) =
    (void *)BPF_FUNC_skb_adjust_room;
static long (*bpf_skb_vlan_push)(void *skb, __be16 vlan_proto, __u16 vlan_tci) =
    (void *)BPF_FUNC_skb_vlan_push;
static long (*bpf_skb_vlan_pop)(void *skb) =
    (void *)BPF_FUNC_skb_vlan_pop;
static __wsum (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) =
    (void *)BPF_FUNC_csum_diff;
static long (*bpf_l4_csum_replace)(void *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
static long (*bpf_l3_csum_replace)(void *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l3_csum_replace;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) =
    (void *)BPF_FUNC_fib_lookup;
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef bpf_htons
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) ((__be16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) ((__u16)__builtin_bswap16((__be16)(x)))
#define bpf_htonl(x) ((__be32)__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) ((__u32)__builtin_bswap32((__be32)(x)))
#else
#define bpf_htons(x) ((__be16)(x))
#define bpf_ntohs(x) ((__u16)(x))
#define bpf_htonl(x) ((__be32)(x))
#define bpf_ntohl(x) ((__u32)(x))
#endif
#endif

#ifndef BNT_STATUS_DEFINED
#define BNT_STATUS_DEFINED
enum bnt_status {
    BNT_OK                = 0,
    BNT_ERR_TRUNC         = -1,
    BNT_ERR_UNSUPPORTED   = -2,
    BNT_ERR_BAD_PROTO     = -3,
    BNT_ERR_FRAGMENT      = -4,
    BNT_ERR_WRITE         = -5,
    BNT_ERR_BAD_ARG       = -6,
    BNT_ERR_BAD_STATE     = -7,
    BNT_ERR_TOO_DEEP      = -8,
};
#endif

static __always_inline __u32 __bnt_len(struct __sk_buff *ctx)
{
    return ctx->len;
}

static __always_inline int __bnt_bounds_len(__u32 pkt_len, __u32 off, __u32 len)
{
    if (off > pkt_len)
        return BNT_ERR_TRUNC;
    if (len > pkt_len - off)
        return BNT_ERR_TRUNC;
    return BNT_OK;
}

static __always_inline int __bnt_bounds(struct __sk_buff *ctx, __u32 off, __u32 len)
{
    return __bnt_bounds_len(__bnt_len(ctx), off, len);
}

static __always_inline int __bnt_read(struct __sk_buff *ctx, __u32 off, void *dst, __u32 len)
{
    if (!dst)
        return BNT_ERR_BAD_ARG;

    /* bpf_skb_load_bytes bounds-checks [off, off+len) against skb->len in the
     * kernel (returns <0 out of range); an explicit __bnt_bounds here would be
     * redundant — same TRUNC result, extra verifier work on every read. */
    if (bpf_skb_load_bytes(ctx, off, dst, len) < 0)
        return BNT_ERR_TRUNC;
    return BNT_OK;
}

static __always_inline int __bnt_write(struct __sk_buff *ctx, __u32 off, const void *src, __u32 len)
{
    if (!src)
        return BNT_ERR_BAD_ARG;

    /* bpf_skb_store_bytes bounds-checks in the kernel; explicit __bnt_bounds
     * would be redundant (same WRITE result, extra verifier work per write). */
    if (bpf_skb_store_bytes(ctx, off, src, len, BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/*
 * TC uses bpf_skb_load_bytes for checksum loops: direct ctx->data pointer
 * arithmetic is not needed, so the XDP verifier workarounds do not apply.
 * BNT_MAX_PAYLOAD=65535 covers GRO super-segments.
 */
#ifndef BNT_MAX_PAYLOAD
#define BNT_MAX_PAYLOAD 65535
#endif

#ifndef BNT_CSUM_CHUNK
#define BNT_CSUM_CHUNK 256
#endif

/* Define context type before including shared helpers. */
#define BNT_CTX_TYPE struct __sk_buff
#include "bnt_rw.h"

static __always_inline int __bnt_csum_range(struct __sk_buff *ctx, __u32 off, __u32 len,
                                             __wsum seed, __wsum *out)
{
    __u8   buf[BNT_CSUM_CHUNK];
    __wsum acc = seed;
    __s64  res;
    __u32  i;
    __u8   b;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;

    if (len > BNT_MAX_PAYLOAD)
        return BNT_ERR_TRUNC;

    for (i = 0; i < BNT_MAX_PAYLOAD / BNT_CSUM_CHUNK + 1; i++) {
        if (len < BNT_CSUM_CHUNK)
            break;
        if (__bnt_read(ctx, off, buf, BNT_CSUM_CHUNK))
            return BNT_ERR_TRUNC;
        res = bpf_csum_diff(NULL, 0, (__be32 *)buf, BNT_CSUM_CHUNK, acc);
        if (res < 0)
            return BNT_ERR_TRUNC;
        acc = (__wsum)res;
        off += BNT_CSUM_CHUNK;
        len -= BNT_CSUM_CHUNK;
    }

    for (i = 0; i < BNT_CSUM_CHUNK / 4; i++) {
        if (len < 4)
            break;
        if (__bnt_read(ctx, off, buf, 4))
            return BNT_ERR_TRUNC;
        res = bpf_csum_diff(NULL, 0, (__be32 *)buf, 4, acc);
        if (res < 0)
            return BNT_ERR_TRUNC;
        acc = (__wsum)res;
        off += 4;
        len -= 4;
    }

    if (len > 0) {
        __be32 tail = 0;
        __u8  *t    = (__u8 *)&tail;
        if (__bnt_read(ctx, off, &b, 1))
            return BNT_ERR_TRUNC;
        t[0] = b;
        if (len >= 2) {
            if (__bnt_read(ctx, off + 1, &b, 1))
                return BNT_ERR_TRUNC;
            t[1] = b;
        }
        if (len >= 3) {
            if (__bnt_read(ctx, off + 2, &b, 1))
                return BNT_ERR_TRUNC;
            t[2] = b;
        }
        res = bpf_csum_diff(NULL, 0, &tail, 4, acc);
        if (res < 0)
            return BNT_ERR_TRUNC;
        acc = (__wsum)res;
    }

    *out = acc;
    return BNT_OK;
}

/*
 * TC: bpf_l4_csum_replace is context-aware (no-op on checksum field for
 * CHECKSUM_PARTIAL non-pseudo-header fields; skb_checksum_help completes it).
 * BPF_F_PSEUDO_HDR makes it update the pseudo-header seed P on CHECKSUM_PARTIAL,
 * or do a direct incremental update on CHECKSUM_NONE/UNNECESSARY.
 * bpf_l3_csum_replace does direct incremental update (correct for L3 always).
 */
static __always_inline int __bnt_l4_csum16(struct __sk_buff *ctx, __u32 off,
                                             __be16 from, __be16 to, int mangled)
{
    return (int)bpf_l4_csum_replace(ctx, off, from, to,
                                     2 | (mangled ? BPF_F_MARK_MANGLED_0 : 0));
}
static __always_inline int __bnt_l4_csum32(struct __sk_buff *ctx, __u32 off,
                                             __be32 from, __be32 to, int mangled)
{
    return (int)bpf_l4_csum_replace(ctx, off, from, to,
                                     4 | (mangled ? BPF_F_MARK_MANGLED_0 : 0));
}
static __always_inline int __bnt_l4_pseudo_csum16(struct __sk_buff *ctx, __u32 off,
                                                    __be16 from, __be16 to, int mangled)
{
    return (int)bpf_l4_csum_replace(ctx, off, from, to,
                                     2 | BPF_F_PSEUDO_HDR | (mangled ? BPF_F_MARK_MANGLED_0 : 0));
}
static __always_inline int __bnt_l4_pseudo_csum32(struct __sk_buff *ctx, __u32 off,
                                                    __be32 from, __be32 to, int mangled)
{
    return (int)bpf_l4_csum_replace(ctx, off, from, to,
                                     4 | BPF_F_PSEUDO_HDR | (mangled ? BPF_F_MARK_MANGLED_0 : 0));
}
static __always_inline int __bnt_l3_csum16(struct __sk_buff *ctx, __u32 off,
                                             __be16 from, __be16 to)
{
    return (int)bpf_l3_csum_replace(ctx, off, from, to, 2);
}
static __always_inline int __bnt_l3_csum32(struct __sk_buff *ctx, __u32 off,
                                             __be32 from, __be32 to)
{
    return (int)bpf_l3_csum_replace(ctx, off, from, to, 4);
}

/* TC is always inline: its packet I/O goes through bounds-checking skb helpers
 * (bpf_skb_load_bytes/store_bytes, l4_csum_replace, skb_adjust_room), with no
 * packet-pointer arithmetic, so globals would only add calls. For the same
 * reason the BNT_LEGACY_KERNEL barriers have nothing to protect: TC loads on
 * pre-5.6 kernels without it. */
#ifndef BNT_LEGACY_KERNEL
#define BNT_LEGACY_KERNEL 0
#endif

#ifdef BNT_INLINE_ALL
#undef BNT_INLINE_ALL
#endif
#define BNT_INLINE_ALL 1

#include "bnt_core.h"
#undef BNT_CTX_TYPE

#define try_or_return_ok(expr)   __bnt_try_or_return(expr, TC_ACT_OK)
#define try_or_return_shot(expr) __bnt_try_or_return(expr, TC_ACT_SHOT)

/* Raw setters for callers that will recompute checksums from scratch. */
static __always_inline int bnt_ipv4__set_tos_no_csum(bnt_ipv4 *ip, __u8 tos)
    { return __bnt_ipv4__set_tos_raw(ip, tos); }
/** Sets the IPv4 TTL WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_ttl_no_csum(bnt_ipv4 *ip, __u8 ttl)
    { return __bnt_ipv4__set_ttl_raw(ip, ttl); }
/** Sets the IPv4 source address WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_saddr_no_csum(bnt_ipv4 *ip, __be32 saddr)
    { return __bnt_ipv4__set_saddr_raw(ip, saddr); }
/** Sets the IPv4 destination address WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_daddr_no_csum(bnt_ipv4 *ip, __be32 daddr)
    { return __bnt_ipv4__set_daddr_raw(ip, daddr); }
/** Sets the IPv4 identification field WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_id_no_csum(bnt_ipv4 *ip, __u16 id)
    { return __bnt_ipv4__set_id_raw(ip, id); }
/** Sets the IPv4 total length field WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_total_len_no_csum(bnt_ipv4 *ip, __u16 total_len)
    { return __bnt_ipv4__set_total_len_raw(ip, total_len); }
/** Sets the IPv4 protocol field WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_protocol_no_csum(bnt_ipv4 *ip, __u8 protocol)
    { return __bnt_ipv4__set_protocol_raw(ip, protocol); }
/** Sets the IPv4 fragment offset/flags word WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_frag_off_no_csum(bnt_ipv4 *ip, __u16 frag_off)
    { return __bnt_ipv4__set_frag_off_raw(ip, frag_off); }
/** Sets the IPv4 IHL (header length) WITHOUT updating any checksum (recompute it yourself). */
static __always_inline int bnt_ipv4__set_hlen_no_csum(bnt_ipv4 *ip, __u32 hlen)
    { return __bnt_ipv4__set_hlen_raw(ip, hlen); }


#ifndef BPF_ADJ_ROOM_NET
#define BPF_ADJ_ROOM_NET 0
#endif
#ifndef BPF_ADJ_ROOM_MAC
#define BPF_ADJ_ROOM_MAC 1
#endif

/** Inserts an outer VLAN header using the TC skb VLAN helper. */
static __always_inline int bnt_eth__insert_vlan(bnt_eth *eth, __u16 tpid, __u16 tci)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    if (bpf_skb_vlan_push(eth->__ctx, bpf_htons(tpid), tci) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** Removes the outermost VLAN header using the TC skb VLAN helper. */
static __always_inline int bnt_eth__remove_vlan(bnt_eth *eth)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    if (bpf_skb_vlan_pop(eth->__ctx) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

static __always_inline int __bnt_eth_tc_adjust_after(struct __sk_buff *ctx,
                                                       __s32 delta)
{
    if (bpf_skb_adjust_room(ctx, delta, BPF_ADJ_ROOM_NET, 0) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/* Inserts/removes delta bytes between L2 and L3 (MAC boundary). */
static __always_inline int __bnt_eth_tc_adjust_mac(struct __sk_buff *ctx,
                                                     __s32 delta)
{
    if (bpf_skb_adjust_room(ctx, delta, BPF_ADJ_ROOM_MAC, 0) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** Inserts a base IPv4 header immediately after Ethernet/VLAN and initializes it. */
static __always_inline int bnt_eth__insert_ipv4(bnt_eth *eth,
                                                  __u8 protocol,
                                                  __be32 saddr,
                                                  __be32 daddr)
{
    struct __bnt_eth_meta meta;
    struct iphdr ip = {};
    __u32 prefix_len;
    __u32 pkt_len;
    __u32 total_len;
    __wsum csum;
    int ret;

    ret = __bnt_eth_meta_view(eth, &meta);
    if (ret)
        return ret;

    prefix_len = eth->__off + meta.hlen;
    ret = __bnt_eth_tc_adjust_mac(eth->__ctx, sizeof(ip));
    if (ret)
        return ret;

    pkt_len = __bnt_len(eth->__ctx);
    if (prefix_len > pkt_len)
        return BNT_ERR_TRUNC;
    total_len = pkt_len - prefix_len;
    if (total_len < sizeof(ip) || total_len > 0xffff)
        return BNT_ERR_TRUNC;

    ip.version = 4;
    ip.ihl = 5;
    ip.tos = 0;
    ip.tot_len = bpf_htons((__u16)total_len);
    ip.id = 0;
    ip.frag_off = bpf_htons(IP_DF);
    ip.ttl = 64;
    ip.protocol = protocol;
    ip.check = 0;
    ip.saddr = saddr;
    ip.daddr = daddr;

    csum = bpf_csum_diff(NULL, 0, (__be32 *)&ip, sizeof(ip), 0);
    ip.check = __bnt_csum_fold(csum);

    ret = bnt_eth__set_ethertype(eth, ETH_P_IP);
    if (ret)
        return ret;
    return __bnt_write(eth->__ctx, prefix_len, &ip, sizeof(ip));
}

/** Inserts a base IPv6 header immediately after Ethernet/VLAN and initializes it. */
static __always_inline int bnt_eth__insert_ipv6(bnt_eth *eth,
                                                  __u8 nexthdr,
                                                  const struct in6_addr *saddr,
                                                  const struct in6_addr *daddr)
{
    struct __bnt_eth_meta meta;
    struct ipv6hdr ip = {};
    __u32 prefix_len;
    __u32 pkt_len;
    __u32 payload_len;
    int ret;

    if (!saddr || !daddr)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_eth_meta_view(eth, &meta);
    if (ret)
        return ret;

    prefix_len = eth->__off + meta.hlen;
    ret = __bnt_eth_tc_adjust_mac(eth->__ctx, sizeof(ip));
    if (ret)
        return ret;

    pkt_len = __bnt_len(eth->__ctx);
    if (prefix_len > pkt_len)
        return BNT_ERR_TRUNC;
    payload_len = pkt_len - prefix_len - sizeof(ip);
    if (payload_len > 0xffff)
        return BNT_ERR_TRUNC;

    ip.version = 6;
    ip.priority = 0;
    ip.flow_lbl[0] = 0;
    ip.flow_lbl[1] = 0;
    ip.flow_lbl[2] = 0;
    ip.payload_len = bpf_htons((__u16)payload_len);
    ip.nexthdr = nexthdr;
    ip.hop_limit = 64;
    __builtin_memcpy(&ip.saddr, saddr, sizeof(ip.saddr));
    __builtin_memcpy(&ip.daddr, daddr, sizeof(ip.daddr));

    ret = bnt_eth__set_ethertype(eth, ETH_P_IPV6);
    if (ret)
        return ret;
    return __bnt_write(eth->__ctx, prefix_len, &ip, sizeof(ip));
}

/** Removes a base IPv4 header immediately after Ethernet/VLAN. */
static __always_inline int bnt_eth__remove_ipv4(bnt_eth *eth)
{
    struct __bnt_eth_meta meta;
    struct iphdr ip;
    __u32 prefix_len;
    int ret;

    ret = __bnt_eth_meta_view(eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IP)
        return BNT_ERR_BAD_PROTO;

    prefix_len = eth->__off + meta.hlen;
    ret = __bnt_read(eth->__ctx, prefix_len, &ip, sizeof(ip));
    if (ret)
        return ret;
    if (ip.version != 4 || ip.ihl != 5)
        return BNT_ERR_UNSUPPORTED;

    if (ip.protocol == IPPROTO_IPIP)
        ret = bnt_eth__set_ethertype(eth, ETH_P_IP);
    else if (ip.protocol == IPPROTO_IPV6)
        ret = bnt_eth__set_ethertype(eth, ETH_P_IPV6);
    else
        return BNT_ERR_UNSUPPORTED;
    if (ret)
        return ret;

    return __bnt_eth_tc_adjust_mac(eth->__ctx, -(__s32)sizeof(ip));
}

/** Removes a base IPv6 header immediately after Ethernet/VLAN. */
static __always_inline int bnt_eth__remove_ipv6(bnt_eth *eth)
{
    struct __bnt_eth_meta meta;
    struct ipv6hdr ip;
    __u32 prefix_len;
    int ret;

    ret = __bnt_eth_meta_view(eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IPV6)
        return BNT_ERR_BAD_PROTO;

    prefix_len = eth->__off + meta.hlen;
    ret = __bnt_read(eth->__ctx, prefix_len, &ip, sizeof(ip));
    if (ret)
        return ret;
    if (ip.version != 6)
        return BNT_ERR_UNSUPPORTED;

    if (ip.nexthdr == IPPROTO_IPIP)
        ret = bnt_eth__set_ethertype(eth, ETH_P_IP);
    else if (ip.nexthdr == IPPROTO_IPV6)
        ret = bnt_eth__set_ethertype(eth, ETH_P_IPV6);
    else
        return BNT_ERR_UNSUPPORTED;
    if (ret)
        return ret;

    return __bnt_eth_tc_adjust_mac(eth->__ctx, -(__s32)sizeof(ip));
}

/** Sets the IPv6 source address WITHOUT updating the L4 checksum (recompute it yourself). */
static __always_inline int bnt_ipv6__set_saddr_no_csum(bnt_ipv6 *ip6, const struct in6_addr *addr)
    { return __bnt_ipv6__set_saddr_raw(ip6, addr); }
/** Sets the IPv6 destination address WITHOUT updating the L4 checksum (recompute it yourself). */
static __always_inline int bnt_ipv6__set_daddr_no_csum(bnt_ipv6 *ip6, const struct in6_addr *addr)
    { return __bnt_ipv6__set_daddr_raw(ip6, addr); }
/** Sets the IPv6 payload length WITHOUT updating any checksum. */
static __always_inline int bnt_ipv6__set_payload_len_no_csum(bnt_ipv6 *ip6, __u16 payload_len)
    { return __bnt_ipv6__set_payload_len_raw(ip6, payload_len); }

/** Sets the TCP source port WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_sport_no_csum(bnt_tcp *tcp, __u16 port)
    { return __bnt_tcp__set_sport_raw(tcp, port); }
/** Sets the TCP destination port WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_dport_no_csum(bnt_tcp *tcp, __u16 port)
    { return __bnt_tcp__set_dport_raw(tcp, port); }
/** Sets the TCP sequence number WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_seq_no_csum(bnt_tcp *tcp, __u32 seq)
    { return __bnt_tcp__set_seq_raw(tcp, seq); }
/** Sets the TCP acknowledgment number WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_ack_seq_no_csum(bnt_tcp *tcp, __u32 ack_seq)
    { return __bnt_tcp__set_ack_seq_raw(tcp, ack_seq); }
/** Sets the TCP flags byte WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_flags_no_csum(bnt_tcp *tcp, __u16 flags)
    { return __bnt_tcp__set_flags_raw(tcp, flags); }
/** Sets the TCP window size WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_window_no_csum(bnt_tcp *tcp, __u16 window)
    { return __bnt_tcp__set_window_raw(tcp, window); }
/** Sets the TCP urgent pointer WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_urg_ptr_no_csum(bnt_tcp *tcp, __u16 urg_ptr)
    { return __bnt_tcp__set_urg_ptr_raw(tcp, urg_ptr); }
/** Sets the TCP data offset WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_tcp__set_doff_no_csum(bnt_tcp *tcp, __u32 doff)
    { return __bnt_tcp__set_doff_raw(tcp, doff); }

/** Sets the UDP source port WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_udp__set_sport_no_csum(bnt_udp *udp, __u16 port)
    { return __bnt_udp__set_sport_raw(udp, port); }
/** Sets the UDP destination port WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_udp__set_dport_no_csum(bnt_udp *udp, __u16 port)
    { return __bnt_udp__set_dport_raw(udp, port); }
/** Sets the UDP length field WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_udp__set_len_no_csum(bnt_udp *udp, __u16 len)
    { return __bnt_udp__set_len_raw(udp, len); }

/** Sets the ICMPv4 type WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp4__set_type_no_csum(bnt_icmp4 *icmp, __u8 type)
    { return __bnt_icmp4__set_type_raw(icmp, type); }
/** Sets the ICMPv4 code WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp4__set_code_no_csum(bnt_icmp4 *icmp, __u8 code)
    { return __bnt_icmp4__set_code_raw(icmp, code); }
/** Sets the ICMPv4 echo identifier WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp4__set_echo_id_no_csum(bnt_icmp4 *icmp, __u16 id)
    { return __bnt_icmp4__set_echo_id_raw(icmp, id); }
/** Sets the ICMPv4 echo sequence number WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp4__set_echo_seq_no_csum(bnt_icmp4 *icmp, __u16 seq)
    { return __bnt_icmp4__set_echo_seq_raw(icmp, seq); }

/** Sets the ICMPv6 type WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp6__set_type_no_csum(bnt_icmp6 *icmp, __u8 type)
    { return __bnt_icmp6__set_type_raw(icmp, type); }
/** Sets the ICMPv6 code WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp6__set_code_no_csum(bnt_icmp6 *icmp, __u8 code)
    { return __bnt_icmp6__set_code_raw(icmp, code); }
/** Sets the ICMPv6 echo identifier WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp6__set_echo_id_no_csum(bnt_icmp6 *icmp, __u16 id)
    { return __bnt_icmp6__set_echo_id_raw(icmp, id); }
/** Sets the ICMPv6 echo sequence number WITHOUT updating the checksum (recompute it yourself). */
static __always_inline int bnt_icmp6__set_echo_seq_no_csum(bnt_icmp6 *icmp, __u16 seq)
    { return __bnt_icmp6__set_echo_seq_raw(icmp, seq); }

/* Full checksum recompute helpers for TC ingress packets. */
static __always_inline int bnt_ipv4__recompute_csum(bnt_ipv4 *ip)
    { return __bnt_ipv4__recompute_csum(ip); }
/** Recomputes the full TCP checksum over the IPv4 pseudo-header and payload. */
static __always_inline int bnt_tcp__recompute_csum4(bnt_tcp *tcp, bnt_ipv4 *ip4)
    { return __bnt_tcp__recompute_csum_v4(tcp, ip4); }
/** Recomputes the full TCP checksum over the IPv6 pseudo-header and payload. */
static __always_inline int bnt_tcp__recompute_csum6(bnt_tcp *tcp, bnt_ipv6 *ip6)
    { return __bnt_tcp__recompute_csum_v6(tcp, ip6); }
/** Recomputes the full UDP checksum over the IPv4 pseudo-header and payload. */
static __always_inline int bnt_udp__recompute_csum4(bnt_udp *udp, bnt_ipv4 *ip4)
    { return __bnt_udp__recompute_csum_v4(udp, ip4); }
/** Recomputes the full UDP checksum over the IPv6 pseudo-header and payload. */
static __always_inline int bnt_udp__recompute_csum6(bnt_udp *udp, bnt_ipv6 *ip6)
    { return __bnt_udp__recompute_csum_v6(udp, ip6); }
/** Recomputes the full ICMPv4 checksum over the ICMP message. */
static __always_inline int bnt_icmp4__recompute_csum(bnt_icmp4 *icmp, __u16 icmp_len)
    { return __bnt_icmp4__recompute_csum(icmp, icmp_len); }
/** Recomputes the full ICMPv6 checksum over the IPv6 pseudo-header and ICMP message. */
static __always_inline int bnt_icmp6__recompute_csum(bnt_icmp6 *icmp, bnt_ipv6 *ip6,
                                                       __u16 icmp_len)
    { return __bnt_icmp6__recompute_csum(icmp, ip6, icmp_len); }



/** Inserts an SRH immediately after an existing IPv6 base header (H.Insert).
 * Segment addresses are passed in forward visitation order. */
static __always_inline int bnt_ipv6__insert_srh(bnt_ipv6 *ip6,
                                                  const struct in6_addr *segs,
                                                  __u8 n_segs)
{
    struct ipv6hdr hdr;
    struct bnt_sr_hdr srh = {};
    struct in6_addr seg;
    __u8 orig_nexthdr;
    __u32 srh_off, segs_off, srh_size;
    __u16 old_plen, new_plen;
    __u32 i;
    int ret;

    if (!ip6 || !segs || !n_segs || n_segs > BNT_SRV6_MAX_SEGS)
        return BNT_ERR_BAD_ARG;

    srh_size = (__u32)sizeof(struct bnt_sr_hdr) +
               (__u32)n_segs * (__u32)sizeof(struct in6_addr);

    /* Read the IPv6 header BEFORE adjusting the room so we have a stable local
     * copy regardless of how bpf_skb_adjust_room(NET) shifts the packet data. */
    ret = __bnt_read(ip6->__ctx, ip6->__off, &hdr, sizeof(hdr));
    if (ret)
        return ret;
    if (((*(__u8 *)&hdr) >> 4) != 6)
        return BNT_ERR_BAD_PROTO;

    orig_nexthdr = hdr.nexthdr;
    old_plen     = bpf_ntohs(hdr.payload_len);
    if ((__u32)old_plen + srh_size > 0xffffu)
        return BNT_ERR_TRUNC;
    new_plen = (__u16)(old_plen + (__u16)srh_size);

    ret = __bnt_eth_tc_adjust_after(ip6->__ctx, (__s32)srh_size);
    if (ret)
        return ret;

    hdr.nexthdr     = NEXTHDR_ROUTING;
    hdr.payload_len = bpf_htons(new_plen);
    ret = __bnt_write(ip6->__ctx, ip6->__off, &hdr, sizeof(hdr));
    if (ret)
        return ret;

    srh_off           = ip6->__off + (__u32)sizeof(struct ipv6hdr);
    srh.nexthdr       = orig_nexthdr;
    srh.hdrlen        = (__u8)(n_segs * 2u);
    srh.type          = 4;
    srh.segments_left = n_segs - 1;
    srh.first_segment = n_segs - 1;
    ret = __bnt_write(ip6->__ctx, srh_off, &srh, sizeof(srh));
    if (ret)
        return ret;

    segs_off = srh_off + (__u32)sizeof(struct bnt_sr_hdr);
#pragma unroll
    for (i = 0; i < BNT_SRV6_MAX_SEGS; i++) {
        __u8 rev;

        if (i >= (__u32)n_segs)
            break;
        rev = n_segs - 1 - (__u8)i;
        if (rev >= BNT_SRV6_MAX_SEGS)
            return BNT_ERR_BAD_ARG;
#if BNT_LEGACY_KERNEL || __clang_major__ >= 22
        asm volatile("" : "+r"(rev));   /* clang>=22: keep the clamp below from being elided */
#endif
        rev &= (__u8)(BNT_SRV6_MAX_SEGS - 1u);  /* verifier bound for segs[] index */
        __builtin_memcpy(&seg, &segs[rev], sizeof(seg));
        ret = __bnt_write(ip6->__ctx,
                           segs_off + i * (__u32)sizeof(struct in6_addr),
                           &seg, sizeof(seg));
        if (ret)
            return ret;
    }
    return BNT_OK;
}

/** Pushes one MPLS label after Ethernet/VLAN; BOS is set automatically. */
static __always_inline int bnt_eth__insert_mpls(bnt_eth *eth,
                                                  __u32 label, __u8 tc, __u8 ttl)
{
    struct __bnt_eth_meta meta;
    __be32 lse;
    bool bos;
    __u32 prefix_len;
    int ret;

    if (!eth || label > 0xFFFFFu)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_eth_meta_view(eth, &meta);
    if (ret)
        return ret;

    bos = (meta.proto != ETH_P_MPLS_UC && meta.proto != ETH_P_MPLS_MC);
    lse = bpf_htonl((label << 12) |
                     ((__u32)(tc & 0x7u) << 9) |
                     (bos ? (1u << 8) : 0u) |
                     (__u32)ttl);

    prefix_len = eth->__off + meta.hlen;
    ret = __bnt_eth_tc_adjust_mac(eth->__ctx, (__s32)sizeof(lse));
    if (ret)
        return ret;

    ret = bnt_eth__set_ethertype(eth, ETH_P_MPLS_UC);
    if (ret)
        return ret;
    return __bnt_write(eth->__ctx, prefix_len, &lse, sizeof(lse));
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* BNT_TC_INGRESS_H */
