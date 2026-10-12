/* SPDX-License-Identifier: MIT */
/*
 * bnt_debug.h - optional packet-header debug/logging helpers.
 *
 * Include this header after bnt_xdp.h or bnt_tc.h in BPF programs.
 *
 * The binary event ABI uses one typed struct per header. Numeric fields are
 * stored in host byte order unless the bnt API exposes the field as raw
 * network-order data, such as MAC, IPv4, and IPv6 addresses.
 */

#ifndef BNT_DEBUG_H
#define BNT_DEBUG_H

#include <stddef.h>

#ifndef __VMLINUX_H__
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef BNT_DBG_MAX_VLAN_DEPTH
#ifdef BNT_MAX_VLAN_DEPTH
#define BNT_DBG_MAX_VLAN_DEPTH BNT_MAX_VLAN_DEPTH
#else
#define BNT_DBG_MAX_VLAN_DEPTH 2
#endif
#endif

#ifndef BNT_DBG_MAC_LEN
#ifdef BNT_MAC_LEN
#define BNT_DBG_MAC_LEN BNT_MAC_LEN
#else
#define BNT_DBG_MAC_LEN 6
#endif
#endif

struct bnt_dbg_event_meta {
    __u32 offset;
    __u32 header_len;
    __u32 packet_len;
};

struct bnt_dbg_eth_event {
    struct bnt_dbg_event_meta meta;
    unsigned char dst[BNT_DBG_MAC_LEN];
    unsigned char src[BNT_DBG_MAC_LEN];
    __u16 outer_proto;
    __u16 ethertype;
    __u8 vlan_depth;
    __u8 _pad[3];
    __u16 vlan_tci[BNT_DBG_MAX_VLAN_DEPTH];
};

struct bnt_dbg_vlan_event {
    struct bnt_dbg_event_meta meta;
    __u32 index;
    __u16 tci;
    __u16 encapsulated_proto;
    __u16 vid;
    __u8 pcp;
    __u8 dei;
};

struct bnt_dbg_ipv4_event {
    struct bnt_dbg_event_meta meta;
    __u32 next_off;
    __be32 saddr;
    __be32 daddr;
    __u16 total_len;
    __u16 id;
    __u16 frag_off;
    __u16 check;
    __u8 version;
    __u8 ihl;
    __u8 tos;
    __u8 ttl;
    __u8 protocol;
    __u8 is_fragment;
    __u8 _pad[2];
};

struct bnt_dbg_ipv6_event {
    struct bnt_dbg_event_meta meta;
    struct in6_addr saddr;
    struct in6_addr daddr;
    __u32 next_off;
    __u32 flow_label;
    __u16 payload_len;
    __u8 version;
    __u8 traffic_class;
    __u8 base_nexthdr;
    __u8 l4_proto;
    __u8 hop_limit;
    __u8 ext_depth;
    __u8 has_fragment_hdr;
    __u8 is_fragment;
};

struct bnt_dbg_tcp_event {
    struct bnt_dbg_event_meta meta;
    __u32 seq;
    __u32 ack_seq;
    __u16 source;
    __u16 dest;
    __u16 flags;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
    __u8 doff;
    __u8 _pad[3];
};

struct bnt_dbg_udp_event {
    struct bnt_dbg_event_meta meta;
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
};

struct bnt_dbg_icmp4_event {
    struct bnt_dbg_event_meta meta;
    __u16 checksum;
    __u16 echo_id;
    __u16 echo_seq;
    __u8 type;
    __u8 code;
};

struct bnt_dbg_icmp6_event {
    struct bnt_dbg_event_meta meta;
    __u16 checksum;
    __u16 echo_id;
    __u16 echo_seq;
    __u8 type;
    __u8 code;
};

struct bnt_dbg_arp_event {
    struct bnt_dbg_event_meta meta;
    unsigned char sha[BNT_DBG_MAC_LEN];
    unsigned char tha[BNT_DBG_MAC_LEN];
    __be32 spa;
    __be32 tpa;
    __u16 htype;
    __u16 ptype;
    __u16 oper;
    __u8 haddr_len;
    __u8 paddr_len;
    __u8 is_eth_ipv4;
    __u8 _pad[3];
};

#ifdef BNT_CORE_INCLUDED

#ifndef __BPF_HELPERS__
#include <bpf/bpf_helpers.h>
#endif

static __always_inline void __bnt_dbg_init_meta(struct bnt_dbg_event_meta *meta,
                                                 __u32 offset,
                                                 __u32 header_len,
                                                 __u32 packet_len)
{
    meta->offset = offset;
    meta->header_len = header_len;
    meta->packet_len = packet_len;
}

static __always_inline __u32 __bnt_dbg_mac_hi(const unsigned char mac[BNT_DBG_MAC_LEN])
{
    return ((__u32)mac[0] << 16) | ((__u32)mac[1] << 8) | mac[2];
}

static __always_inline __u32 __bnt_dbg_mac_lo(const unsigned char mac[BNT_DBG_MAC_LEN])
{
    return ((__u32)mac[3] << 16) | ((__u32)mac[4] << 8) | mac[5];
}

/*
 * Generates the public fill wrapper from an always_inline
 * __bnt_dbg_<HDR>__fill_impl(view, event).  In XDP global mode the struct is
 * built inside an internal global sub-program (__bnt_dbg_<HDR>__fill_event_g):
 * caller-independent, so the per-program register pressure that would otherwise
 * spill the inlined packet-length scalar never reaches it.  Elsewhere (TC /
 * inline mode) the impl is inlined directly.  The map/ringbuf pointer never
 * enters the global — the emit wrappers keep it and pass only the filled struct.
 */
#if !BNT_INLINE_ALL && defined(BNT_XDP_H)
#define __BNT_DBG_DEFINE_FILL(HDR, VTYPE, ETYPE)                                \
    __attribute__((noinline, weak))                                                  \
    int __bnt_dbg_##HDR##__fill_event_g(struct xdp_md *ctx, __u32 off,         \
                                        ETYPE *event)                          \
    {                                                                          \
        VTYPE __v = { ctx, off };                                              \
        return __bnt_dbg_##HDR##__fill_impl(&__v, event);                      \
    }                                                                          \
    static __always_inline int bnt_dbg_##HDR##__fill_event(const VTYPE *__v,   \
                                                           ETYPE *event)       \
    {                                                                          \
        if (!__v) {                                                            \
            if (event)                                                         \
                __builtin_memset(event, 0, sizeof(*event));                    \
            return BNT_ERR_BAD_ARG;                                            \
        }                                                                      \
        return __bnt_dbg_##HDR##__fill_event_g(__v->__ctx, __v->__off, event); \
    }
#else
#define __BNT_DBG_DEFINE_FILL(HDR, VTYPE, ETYPE)                                \
    static __always_inline int bnt_dbg_##HDR##__fill_event(const VTYPE *__v,   \
                                                           ETYPE *event)       \
    {                                                                          \
        return __bnt_dbg_##HDR##__fill_impl(__v, event);                       \
    }
#endif

static __always_inline int __bnt_dbg_eth__fill_impl(const bnt_eth *eth,
                                                    struct bnt_dbg_eth_event *event)
{
    struct __bnt_eth_meta meta;
    __u16 outer_proto;
    __u32 i;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!eth)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;

    __builtin_memset(event, 0, sizeof(*event));
    __bnt_dbg_init_meta(&event->meta, eth->__off, meta.hlen, __bnt_len(eth->__ctx));

    ret = bnt_eth__get_dst(eth, event->dst);
    if (ret)
        return ret;
    ret = bnt_eth__get_src(eth, event->src);
    if (ret)
        return ret;
    ret = bnt_eth__get_outer_proto(eth, &outer_proto);
    if (ret)
        return ret;

    event->outer_proto = outer_proto;
    event->ethertype = meta.proto;
    event->vlan_depth = meta.vlan_depth;

#pragma unroll
    for (i = 0; i < BNT_DBG_MAX_VLAN_DEPTH; i++) {
        if (i < meta.vlan_depth)
            event->vlan_tci[i] = meta.vlan_tci[i];
    }

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed Ethernet view.
 *
 * @param eth   Parsed Ethernet view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_eth__fill_event(const bnt_eth *eth,
                                                     struct bnt_dbg_eth_event *event);
__BNT_DBG_DEFINE_FILL(eth, bnt_eth, struct bnt_dbg_eth_event)

static __always_inline int __bnt_dbg_vlan__fill_impl(const bnt_eth *eth,
                                                     __u32 index,
                                                     struct bnt_dbg_vlan_event *event)
{
    struct __bnt_eth_meta meta;
    __be16 encap;
    __u32 off;
    __u16 tci;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!eth)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    if (index >= meta.vlan_depth)
        return BNT_ERR_BAD_ARG;

    off = eth->__off + sizeof(struct ethhdr) + index * sizeof(struct bnt_vlan_hdr);
    if ((ret = bnt_eth__get_vlan_tci(eth, index, &tci)))
        return ret;
    if ((ret = __bnt_read_be16(eth->__ctx,
                                off + offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto),
                                &encap)))
        return ret;

    __bnt_dbg_init_meta(&event->meta, off, sizeof(struct bnt_vlan_hdr),
                         __bnt_len(eth->__ctx));
    event->index = index;
    event->tci = tci;
    event->encapsulated_proto = bpf_ntohs(encap);
    event->vid = tci & 0x0fff;
    event->pcp = (__u8)(tci >> 13);
    event->dei = (__u8)((tci >> 12) & 0x1);

    return BNT_OK;
}

#if !BNT_INLINE_ALL && defined(BNT_XDP_H)
__attribute__((noinline, weak))
int __bnt_dbg_vlan__fill_event_g(struct xdp_md *ctx, __u32 off, __u32 index,
                                 struct bnt_dbg_vlan_event *event)
{
    bnt_eth __v = { ctx, off };
    return __bnt_dbg_vlan__fill_impl(&__v, index, event);
}
/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the VLAN tag at depth @p index.
 *
 * @param eth   Parsed Ethernet view.
 * @param index VLAN header depth.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p event is NULL, or @p index is out of range.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_vlan__fill_event(const bnt_eth *eth, __u32 index,
                                                    struct bnt_dbg_vlan_event *event)
{
    if (!eth) { if (event) __builtin_memset(event, 0, sizeof(*event)); return BNT_ERR_BAD_ARG; }
    return __bnt_dbg_vlan__fill_event_g(eth->__ctx, eth->__off, index, event);
}
#else
/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the VLAN tag at depth @p index.
 *
 * @param eth   Parsed Ethernet view.
 * @param index VLAN header depth.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p event is NULL, or @p index is out of range.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_vlan__fill_event(const bnt_eth *eth, __u32 index,
                                                    struct bnt_dbg_vlan_event *event)
{
    return __bnt_dbg_vlan__fill_impl(eth, index, event);
}
#endif

static __always_inline int __bnt_dbg_ipv4__fill_impl(const bnt_ipv4 *ip4,
                                                     struct bnt_dbg_ipv4_event *event)
{
    __be32 saddr, daddr;
    __u16 total_len, id, frag_off, check;
    __u8 version, ihl, tos, ttl, protocol;
    __u32 next_off;
    int is_fragment;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!ip4)
        return BNT_ERR_BAD_ARG;

    if ((ret = bnt_ipv4__next_off(ip4, &next_off)))     return ret;
    if ((ret = bnt_ipv4__get_saddr(ip4, &saddr)))       return ret;
    if ((ret = bnt_ipv4__get_daddr(ip4, &daddr)))       return ret;
    if ((ret = bnt_ipv4__get_total_len(ip4, &total_len))) return ret;
    if ((ret = bnt_ipv4__get_id(ip4, &id)))             return ret;
    if ((ret = bnt_ipv4__get_frag_off(ip4, &frag_off))) return ret;
    if ((ret = bnt_ipv4__get_check(ip4, &check)))       return ret;
    if ((ret = bnt_ipv4__get_version(ip4, &version)))   return ret;
    if ((ret = bnt_ipv4__get_ihl(ip4, &ihl)))           return ret;
    if ((ret = bnt_ipv4__get_tos(ip4, &tos)))           return ret;
    if ((ret = bnt_ipv4__get_ttl(ip4, &ttl)))           return ret;
    if ((ret = bnt_ipv4__get_protocol(ip4, &protocol))) return ret;
    if ((ret = bnt_ipv4__is_fragment(ip4, &is_fragment))) return ret;

    __bnt_dbg_init_meta(&event->meta, ip4->__off, next_off - ip4->__off,
                         __bnt_len(ip4->__ctx));
    event->next_off = next_off;
    event->saddr = saddr;
    event->daddr = daddr;
    event->total_len = total_len;
    event->id = id;
    event->frag_off = frag_off;
    event->check = check;
    event->version = version;
    event->ihl = ihl;
    event->tos = tos;
    event->ttl = ttl;
    event->protocol = protocol;
    event->is_fragment = is_fragment;

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed IPv4 view.
 *
 * @param ip4   Parsed IPv4 view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip4 or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_ipv4__fill_event(const bnt_ipv4 *ip4,
                                                      struct bnt_dbg_ipv4_event *event);
__BNT_DBG_DEFINE_FILL(ipv4, bnt_ipv4, struct bnt_dbg_ipv4_event)

static __always_inline int __bnt_dbg_ipv6__fill_impl(const bnt_ipv6 *ip6,
                                                     struct bnt_dbg_ipv6_event *event)
{
    struct __bnt_ipv6_meta meta;
    struct in6_addr saddr, daddr;
    __u32 flow_label;
    __u16 payload_len;
    __u8 version, traffic_class, base_nexthdr, hop_limit;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!ip6)
        return BNT_ERR_BAD_ARG;

    if ((ret = __bnt_ipv6_meta_dispatch(ip6, &meta)))              return ret;
    if ((ret = bnt_ipv6__get_saddr(ip6, &saddr)))                 return ret;
    if ((ret = bnt_ipv6__get_daddr(ip6, &daddr)))                 return ret;
    if ((ret = bnt_ipv6__get_version(ip6, &version)))             return ret;
    if ((ret = bnt_ipv6__get_traffic_class(ip6, &traffic_class))) return ret;
    if ((ret = bnt_ipv6__get_flow_label(ip6, &flow_label)))       return ret;
    if ((ret = bnt_ipv6__get_payload_len(ip6, &payload_len)))     return ret;
    if ((ret = bnt_ipv6__get_base_nexthdr(ip6, &base_nexthdr)))   return ret;
    if ((ret = bnt_ipv6__get_hop_limit(ip6, &hop_limit)))         return ret;

    __bnt_dbg_init_meta(&event->meta, ip6->__off, sizeof(struct ipv6hdr),
                         __bnt_len(ip6->__ctx));
    __builtin_memcpy(&event->saddr, &saddr, sizeof(event->saddr));
    __builtin_memcpy(&event->daddr, &daddr, sizeof(event->daddr));
    event->next_off = meta.next_off;
    event->flow_label = flow_label;
    event->payload_len = payload_len;
    event->version = version;
    event->traffic_class = traffic_class;
    event->base_nexthdr = base_nexthdr;
    event->l4_proto = meta.l4_proto;
    event->hop_limit = hop_limit;
    event->ext_depth = meta.ext_depth;
    event->has_fragment_hdr = meta.has_fragment_hdr;
    event->is_fragment = meta.is_fragment;

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed IPv6 view.
 *
 * @param ip6   Parsed IPv6 view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_ipv6__fill_event(const bnt_ipv6 *ip6,
                                                      struct bnt_dbg_ipv6_event *event);
__BNT_DBG_DEFINE_FILL(ipv6, bnt_ipv6, struct bnt_dbg_ipv6_event)

static __always_inline int __bnt_dbg_tcp__fill_impl(const bnt_tcp *tcp,
                                                    struct bnt_dbg_tcp_event *event)
{
    __u32 seq, ack_seq;
    __u16 source, dest, flags, window, check, urg_ptr;
    __u32 hlen;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!tcp)
        return BNT_ERR_BAD_ARG;

    if ((ret = __bnt_tcp_hlen(tcp, &hlen)))           return ret;
    if ((ret = bnt_tcp__get_seq(tcp, &seq)))          return ret;
    if ((ret = bnt_tcp__get_ack_seq(tcp, &ack_seq)))  return ret;
    if ((ret = bnt_tcp__get_source(tcp, &source)))    return ret;
    if ((ret = bnt_tcp__get_dest(tcp, &dest)))        return ret;
    if ((ret = bnt_tcp__get_flags(tcp, &flags)))      return ret;
    if ((ret = bnt_tcp__get_window(tcp, &window)))    return ret;
    if ((ret = bnt_tcp__get_check(tcp, &check)))      return ret;
    if ((ret = bnt_tcp__get_urg_ptr(tcp, &urg_ptr)))  return ret;

    __bnt_dbg_init_meta(&event->meta, tcp->__off, hlen, __bnt_len(tcp->__ctx));
    event->seq = seq;
    event->ack_seq = ack_seq;
    event->source = source;
    event->dest = dest;
    event->flags = flags & 0x01ff;
    event->window = window;
    event->check = check;
    event->urg_ptr = urg_ptr;
    event->doff = (__u8)(hlen / 4);

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed TCP view.
 *
 * @param tcp   Parsed TCP view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_tcp__fill_event(const bnt_tcp *tcp,
                                                     struct bnt_dbg_tcp_event *event);
__BNT_DBG_DEFINE_FILL(tcp, bnt_tcp, struct bnt_dbg_tcp_event)

static __always_inline int __bnt_dbg_udp__fill_impl(const bnt_udp *udp,
                                                    struct bnt_dbg_udp_event *event)
{
    __u16 source, dest, len, check;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!udp)
        return BNT_ERR_BAD_ARG;

    if ((ret = bnt_udp__get_source(udp, &source))) return ret;
    if ((ret = bnt_udp__get_dest(udp, &dest)))     return ret;
    if ((ret = bnt_udp__get_len(udp, &len)))       return ret;
    if ((ret = bnt_udp__get_check(udp, &check)))   return ret;

    if (len < sizeof(struct udphdr))
        return BNT_ERR_BAD_PROTO;

    __bnt_dbg_init_meta(&event->meta, udp->__off, sizeof(struct udphdr),
                         __bnt_len(udp->__ctx));
    event->source = source;
    event->dest = dest;
    event->len = len;
    event->check = check;

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed UDP view.
 *
 * @param udp   Parsed UDP view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_udp__fill_event(const bnt_udp *udp,
                                                     struct bnt_dbg_udp_event *event);
__BNT_DBG_DEFINE_FILL(udp, bnt_udp, struct bnt_dbg_udp_event)

static __always_inline int __bnt_dbg_icmp4__fill_impl(const bnt_icmp4 *icmp,
                                                      struct bnt_dbg_icmp4_event *event)
{
    __u8 type, code;
    __u16 checksum, echo_id, echo_seq;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!icmp)
        return BNT_ERR_BAD_ARG;

    if ((ret = bnt_icmp4__get_type(icmp, &type)))         return ret;
    if ((ret = bnt_icmp4__get_code(icmp, &code)))         return ret;
    if ((ret = bnt_icmp4__get_checksum(icmp, &checksum))) return ret;
    if ((ret = bnt_icmp4__get_echo_id(icmp, &echo_id)))   return ret;
    if ((ret = bnt_icmp4__get_echo_seq(icmp, &echo_seq))) return ret;

    __bnt_dbg_init_meta(&event->meta, icmp->__off, sizeof(struct bnt_icmp4_hdr),
                         __bnt_len(icmp->__ctx));
    event->checksum = checksum;
    event->echo_id = echo_id;
    event->echo_seq = echo_seq;
    event->type = type;
    event->code = code;

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed ICMPv4 view.
 *
 * @param icmp  Parsed ICMPv4 view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_icmp4__fill_event(const bnt_icmp4 *icmp,
                                                       struct bnt_dbg_icmp4_event *event);
__BNT_DBG_DEFINE_FILL(icmp4, bnt_icmp4, struct bnt_dbg_icmp4_event)

static __always_inline int __bnt_dbg_icmp6__fill_impl(const bnt_icmp6 *icmp,
                                                      struct bnt_dbg_icmp6_event *event)
{
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 echo_id;
    __u16 echo_seq;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!icmp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_bounds(icmp->__ctx, icmp->__off, sizeof(struct icmp6hdr));
    if (ret)
        return ret;
    ret = bnt_icmp6__get_type(icmp, &type);
    if (ret)
        return ret;
    ret = bnt_icmp6__get_code(icmp, &code);
    if (ret)
        return ret;
    ret = bnt_icmp6__get_checksum(icmp, &checksum);
    if (ret)
        return ret;
    ret = bnt_icmp6__get_echo_id(icmp, &echo_id);
    if (ret)
        return ret;
    ret = bnt_icmp6__get_echo_seq(icmp, &echo_seq);
    if (ret)
        return ret;

    __builtin_memset(event, 0, sizeof(*event));
    __bnt_dbg_init_meta(&event->meta, icmp->__off, sizeof(struct icmp6hdr),
                         __bnt_len(icmp->__ctx));
    event->checksum = checksum;
    event->echo_id = echo_id;
    event->echo_seq = echo_seq;
    event->type = type;
    event->code = code;

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed ICMPv6 view.
 *
 * @param icmp  Parsed ICMPv6 view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_icmp6__fill_event(const bnt_icmp6 *icmp,
                                                       struct bnt_dbg_icmp6_event *event);
__BNT_DBG_DEFINE_FILL(icmp6, bnt_icmp6, struct bnt_dbg_icmp6_event)

static __always_inline int __bnt_dbg_arp__fill_impl(const bnt_arp *arp,
                                                    struct bnt_dbg_arp_event *event)
{
    struct __bnt_arp_meta meta;
    __u16 oper;
    int ret;

    if (!event)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(event, 0, sizeof(*event));
    if (!arp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_arp_meta(arp, &meta);
    if (ret)
        return ret;
    ret = bnt_arp__get_oper(arp, &oper);
    if (ret)
        return ret;

    __builtin_memset(event, 0, sizeof(*event));
    __bnt_dbg_init_meta(&event->meta, arp->__off, meta.hlen, __bnt_len(arp->__ctx));
    event->htype = meta.htype;
    event->ptype = meta.ptype;
    event->oper = oper;
    event->haddr_len = meta.haddr_len;
    event->paddr_len = meta.paddr_len;
    event->is_eth_ipv4 = __bnt_arp_is_eth_ipv4_meta(&meta);

    if (event->is_eth_ipv4) {
        ret = bnt_arp__get_sha(arp, event->sha);
        if (ret)
            return ret;
        ret = bnt_arp__get_spa(arp, &event->spa);
        if (ret)
            return ret;
        ret = bnt_arp__get_tha(arp, event->tha);
        if (ret)
            return ret;
        ret = bnt_arp__get_tpa(arp, &event->tpa);
        if (ret)
            return ret;
    }

    return BNT_OK;
}

/**
 * @ingroup bnt_debug
 * @brief Fills @p event from the parsed ARP view.
 *
 * @param arp   Parsed ARP view.
 * @param event Event struct filled on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p event is NULL.
 * @retval BNT_ERR_TRUNC   a read falls outside the packet.
 */
static __always_inline int bnt_dbg_arp__fill_event(const bnt_arp *arp,
                                                     struct bnt_dbg_arp_event *event);
__BNT_DBG_DEFINE_FILL(arp, bnt_arp, struct bnt_dbg_arp_event)

static __always_inline void __bnt_dbg_ipv6_words(const struct in6_addr *addr,
                                                  __u32 *w0,
                                                  __u32 *w1,
                                                  __u32 *w2,
                                                  __u32 *w3)
{
    __be32 a;
    __be32 b;
    __be32 c;
    __be32 d;

    __builtin_memcpy(&a, &addr->s6_addr32[0], sizeof(a));
    __builtin_memcpy(&b, &addr->s6_addr32[1], sizeof(b));
    __builtin_memcpy(&c, &addr->s6_addr32[2], sizeof(c));
    __builtin_memcpy(&d, &addr->s6_addr32[3], sizeof(d));
    *w0 = bpf_ntohl(a);
    *w1 = bpf_ntohl(b);
    *w2 = bpf_ntohl(c);
    *w3 = bpf_ntohl(d);
}

/** @ingroup bnt_debug
 *  Writes a filled Ethernet debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_eth_event__printk(const struct bnt_dbg_eth_event *event)
{
    __u16 tci0 = 0;
    __u16 tci1 = 0;

    if (!event)
        return BNT_ERR_BAD_ARG;

#if BNT_DBG_MAX_VLAN_DEPTH > 0
    tci0 = event->vlan_tci[0];
#endif
#if BNT_DBG_MAX_VLAN_DEPTH > 1
    tci1 = event->vlan_tci[1];
#endif
    bpf_printk("bnt eth off=%u len=%u pkt_len=%u dst=%06x%06x src=%06x%06x outer=0x%x ethertype=0x%x vlans=%u tci0=0x%x tci1=0x%x\n",
               event->meta.offset, event->meta.header_len, event->meta.packet_len,
               __bnt_dbg_mac_hi(event->dst), __bnt_dbg_mac_lo(event->dst),
               __bnt_dbg_mac_hi(event->src), __bnt_dbg_mac_lo(event->src),
               event->outer_proto, event->ethertype, event->vlan_depth,
               tci0, tci1);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled VLAN debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_vlan_event__printk(const struct bnt_dbg_vlan_event *event)
{
    if (!event)
        return BNT_ERR_BAD_ARG;

    bpf_printk("bnt vlan idx=%u off=%u len=%u pkt_len=%u tci=0x%x pcp=%u dei=%u vid=%u encap=0x%x\n",
               event->index, event->meta.offset, event->meta.header_len,
               event->meta.packet_len, event->tci, event->pcp, event->dei,
               event->vid, event->encapsulated_proto);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled IPv4 debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_ipv4_event__printk(const struct bnt_dbg_ipv4_event *event)
{
    const __u8 *s;
    const __u8 *d;

    if (!event)
        return BNT_ERR_BAD_ARG;

    s = (const __u8 *)&event->saddr;
    d = (const __u8 *)&event->daddr;
    bpf_printk("bnt ipv4 off=%u total_len=%u ttl=%u proto=%u saddr=%d.%d.%d.%d daddr=%d.%d.%d.%d\n",
               event->meta.offset, event->total_len, event->ttl, event->protocol,
               s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled IPv6 debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_ipv6_event__printk(const struct bnt_dbg_ipv6_event *event)
{
    __u32 s0;
    __u32 s1;
    __u32 s2;
    __u32 s3;
    __u32 d0;
    __u32 d1;
    __u32 d2;
    __u32 d3;

    if (!event)
        return BNT_ERR_BAD_ARG;

    __bnt_dbg_ipv6_words(&event->saddr, &s0, &s1, &s2, &s3);
    __bnt_dbg_ipv6_words(&event->daddr, &d0, &d1, &d2, &d3);
    bpf_printk("bnt ipv6 off=%u payload_len=%u l4=%u hop=%u saddr=%08x:%08x:%08x:%08x daddr=%08x:%08x:%08x:%08x\n",
               event->meta.offset, event->payload_len, event->l4_proto, event->hop_limit,
               s0, s1, s2, s3, d0, d1, d2, d3);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled TCP debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_tcp_event__printk(const struct bnt_dbg_tcp_event *event)
{
    if (!event)
        return BNT_ERR_BAD_ARG;

    bpf_printk("bnt tcp off=%u hlen=%u sport=%u dport=%u seq=%u ack=%u doff=%u flags=0x%x win=%u check=0x%x urg=%u\n",
               event->meta.offset, event->meta.header_len, event->source, event->dest,
               event->seq, event->ack_seq, event->doff, event->flags,
               event->window, event->check, event->urg_ptr);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled UDP debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_udp_event__printk(const struct bnt_dbg_udp_event *event)
{
    if (!event)
        return BNT_ERR_BAD_ARG;

    bpf_printk("bnt udp off=%u hlen=%u sport=%u dport=%u len=%u check=0x%x\n",
               event->meta.offset, event->meta.header_len, event->source, event->dest,
               event->len, event->check);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled ICMPv4 debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_icmp4_event__printk(const struct bnt_dbg_icmp4_event *event)
{
    if (!event)
        return BNT_ERR_BAD_ARG;

    bpf_printk("bnt icmp4 off=%u hlen=%u type=%u code=%u check=0x%x echo_id=%u echo_seq=%u\n",
               event->meta.offset, event->meta.header_len, event->type, event->code,
               event->checksum, event->echo_id, event->echo_seq);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled ICMPv6 debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_icmp6_event__printk(const struct bnt_dbg_icmp6_event *event)
{
    if (!event)
        return BNT_ERR_BAD_ARG;

    bpf_printk("bnt icmp6 off=%u hlen=%u type=%u code=%u check=0x%x echo_id=%u echo_seq=%u\n",
               event->meta.offset, event->meta.header_len, event->type, event->code,
               event->checksum, event->echo_id, event->echo_seq);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Writes a filled ARP debug event to the kernel trace pipe. */
static __always_inline int bnt_dbg_arp_event__printk(const struct bnt_dbg_arp_event *event)
{
    __u32 spa;
    __u32 tpa;

    if (!event)
        return BNT_ERR_BAD_ARG;

    spa = bpf_ntohl(event->spa);
    tpa = bpf_ntohl(event->tpa);
    bpf_printk("bnt arp off=%u hlen=%u htype=%u ptype=0x%x oper=%u sha=%06x%06x spa=0x%x tha=%06x%06x tpa=0x%x eth_ipv4=%u\n",
               event->meta.offset, event->meta.header_len, event->htype, event->ptype,
               event->oper, __bnt_dbg_mac_hi(event->sha), __bnt_dbg_mac_lo(event->sha),
               spa, __bnt_dbg_mac_hi(event->tha), __bnt_dbg_mac_lo(event->tha),
               tpa, event->is_eth_ipv4);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an Ethernet debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_eth__printk(const bnt_eth *eth)
{
    struct bnt_dbg_eth_event event;
    int ret;

    ret = bnt_dbg_eth__fill_event(eth, &event);
    if (ret)
        return ret;
    return bnt_dbg_eth_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills a VLAN debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_vlan__printk(const bnt_eth *eth, __u32 index)
{
    struct bnt_dbg_vlan_event event;
    int ret;

    ret = bnt_dbg_vlan__fill_event(eth, index, &event);
    if (ret)
        return ret;
    return bnt_dbg_vlan_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills an IPv4 debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_ipv4__printk(const bnt_ipv4 *ip4)
{
    struct bnt_dbg_ipv4_event event;
    int ret;

    ret = bnt_dbg_ipv4__fill_event(ip4, &event);
    if (ret)
        return ret;
    return bnt_dbg_ipv4_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills an IPv6 debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_ipv6__printk(const bnt_ipv6 *ip6)
{
    struct bnt_dbg_ipv6_event event;
    int ret;

    ret = bnt_dbg_ipv6__fill_event(ip6, &event);
    if (ret)
        return ret;
    return bnt_dbg_ipv6_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills a TCP debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_tcp__printk(const bnt_tcp *tcp)
{
    struct bnt_dbg_tcp_event event;
    int ret;

    ret = bnt_dbg_tcp__fill_event(tcp, &event);
    if (ret)
        return ret;
    return bnt_dbg_tcp_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills an UDP debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_udp__printk(const bnt_udp *udp)
{
    struct bnt_dbg_udp_event event;
    int ret;

    ret = bnt_dbg_udp__fill_event(udp, &event);
    if (ret)
        return ret;
    return bnt_dbg_udp_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills an ICMPv4 debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_icmp4__printk(const bnt_icmp4 *icmp)
{
    struct bnt_dbg_icmp4_event event;
    int ret;

    ret = bnt_dbg_icmp4__fill_event(icmp, &event);
    if (ret)
        return ret;
    return bnt_dbg_icmp4_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills an ICMPv6 debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_icmp6__printk(const bnt_icmp6 *icmp)
{
    struct bnt_dbg_icmp6_event event;
    int ret;

    ret = bnt_dbg_icmp6__fill_event(icmp, &event);
    if (ret)
        return ret;
    return bnt_dbg_icmp6_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills an ARP debug event from the view and writes it to the kernel trace pipe. */
static __always_inline int bnt_dbg_arp__printk(const bnt_arp *arp)
{
    struct bnt_dbg_arp_event event;
    int ret;

    ret = bnt_dbg_arp__fill_event(arp, &event);
    if (ret)
        return ret;
    return bnt_dbg_arp_event__printk(&event);
}

/** @ingroup bnt_debug
 *  Fills an Ethernet debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_eth__emit_ringbuf(const bnt_eth *eth, void *ringbuf)
{
    struct bnt_dbg_eth_event event;
    struct bnt_dbg_eth_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_eth__fill_event(eth, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills a VLAN debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_vlan__emit_ringbuf(const bnt_eth *eth,
                                                       __u32 index,
                                                       void *ringbuf)
{
    struct bnt_dbg_vlan_event event;
    struct bnt_dbg_vlan_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_vlan__fill_event(eth, index, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an IPv4 debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_ipv4__emit_ringbuf(const bnt_ipv4 *ip4, void *ringbuf)
{
    struct bnt_dbg_ipv4_event event;
    struct bnt_dbg_ipv4_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_ipv4__fill_event(ip4, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an IPv6 debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_ipv6__emit_ringbuf(const bnt_ipv6 *ip6, void *ringbuf)
{
    struct bnt_dbg_ipv6_event event;
    struct bnt_dbg_ipv6_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_ipv6__fill_event(ip6, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills a TCP debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_tcp__emit_ringbuf(const bnt_tcp *tcp, void *ringbuf)
{
    struct bnt_dbg_tcp_event event;
    struct bnt_dbg_tcp_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_tcp__fill_event(tcp, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an UDP debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_udp__emit_ringbuf(const bnt_udp *udp, void *ringbuf)
{
    struct bnt_dbg_udp_event event;
    struct bnt_dbg_udp_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_udp__fill_event(udp, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an ICMPv4 debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_icmp4__emit_ringbuf(const bnt_icmp4 *icmp, void *ringbuf)
{
    struct bnt_dbg_icmp4_event event;
    struct bnt_dbg_icmp4_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_icmp4__fill_event(icmp, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an ICMPv6 debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_icmp6__emit_ringbuf(const bnt_icmp6 *icmp, void *ringbuf)
{
    struct bnt_dbg_icmp6_event event;
    struct bnt_dbg_icmp6_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_icmp6__fill_event(icmp, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an ARP debug event from the view and submits it to a BPF ring buffer. */
static __always_inline int bnt_dbg_arp__emit_ringbuf(const bnt_arp *arp, void *ringbuf)
{
    struct bnt_dbg_arp_event event;
    struct bnt_dbg_arp_event *dst;
    int ret;

    if (!ringbuf)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_arp__fill_event(arp, &event);
    if (ret)
        return ret;
    dst = bpf_ringbuf_reserve(ringbuf, sizeof(*dst), 0);
    if (!dst)
        return BNT_ERR_WRITE;
    *dst = event;
    bpf_ringbuf_submit(dst, 0);
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an Ethernet debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_eth__update_map(const bnt_eth *eth,
                                                    void *map,
                                                    const void *key,
                                                    __u64 flags)
{
    struct bnt_dbg_eth_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_eth__fill_event(eth, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills a VLAN debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_vlan__update_map(const bnt_eth *eth,
                                                     __u32 index,
                                                     void *map,
                                                     const void *key,
                                                     __u64 flags)
{
    struct bnt_dbg_vlan_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_vlan__fill_event(eth, index, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an IPv4 debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_ipv4__update_map(const bnt_ipv4 *ip4,
                                                     void *map,
                                                     const void *key,
                                                     __u64 flags)
{
    struct bnt_dbg_ipv4_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_ipv4__fill_event(ip4, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an IPv6 debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_ipv6__update_map(const bnt_ipv6 *ip6,
                                                     void *map,
                                                     const void *key,
                                                     __u64 flags)
{
    struct bnt_dbg_ipv6_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_ipv6__fill_event(ip6, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills a TCP debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_tcp__update_map(const bnt_tcp *tcp,
                                                    void *map,
                                                    const void *key,
                                                    __u64 flags)
{
    struct bnt_dbg_tcp_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_tcp__fill_event(tcp, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an UDP debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_udp__update_map(const bnt_udp *udp,
                                                    void *map,
                                                    const void *key,
                                                    __u64 flags)
{
    struct bnt_dbg_udp_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_udp__fill_event(udp, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an ICMPv4 debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_icmp4__update_map(const bnt_icmp4 *icmp,
                                                      void *map,
                                                      const void *key,
                                                      __u64 flags)
{
    struct bnt_dbg_icmp4_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_icmp4__fill_event(icmp, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an ICMPv6 debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_icmp6__update_map(const bnt_icmp6 *icmp,
                                                      void *map,
                                                      const void *key,
                                                      __u64 flags)
{
    struct bnt_dbg_icmp6_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_icmp6__fill_event(icmp, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

/** @ingroup bnt_debug
 *  Fills an ARP debug event from the view and stores it under @p key in @p map. */
static __always_inline int bnt_dbg_arp__update_map(const bnt_arp *arp,
                                                    void *map,
                                                    const void *key,
                                                    __u64 flags)
{
    struct bnt_dbg_arp_event event;
    int ret;

    if (!map || !key)
        return BNT_ERR_BAD_ARG;
    ret = bnt_dbg_arp__fill_event(arp, &event);
    if (ret)
        return ret;
    if (bpf_map_update_elem(map, key, &event, flags) < 0)
        return BNT_ERR_WRITE;
    return BNT_OK;
}

#endif /* BNT_CORE_INCLUDED */

#endif /* BNT_DEBUG_H */
