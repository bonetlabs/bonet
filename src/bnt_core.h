/* SPDX-License-Identifier: MIT */
/*
 * bnt_core.h - common bnt packet-view implementation.
 *
 * This file is included by bnt_xdp.h and the TC backend headers after they define:
 *   - BNT_CTX_TYPE
 *   - __bnt_len(ctx)
 *   - __bnt_bounds(ctx, off, len)
 *   - __bnt_read(ctx, off, dst, len)
 *   - __bnt_write(ctx, off, src, len)
 *   - __bnt_l4_csum16/32, __bnt_l4_pseudo_csum16/32, __bnt_l3_csum16/32
 *
 * bnt_rw.h must be included first (provides read_be16/32, write_be16/32,
 * update_csum16/32, csum_apply_diff, header_set).
 *
 * Integer API convention:
 *   - getters return host-order integers unless documented otherwise
 *   - setters accept host-order integers unless documented otherwise
 *   - IPv4 addresses use __be32 (network byte order)
 *   - IPv6 addresses use struct in6_addr
 *   - MAC addresses are raw 6-byte arrays
 *   - non-NULL getter/offset output parameters are zeroed before any parsing
 *     that can fail, so output values remain verifier-initialized on errors
 *
 * Supported protocols:
 *   - Ethernet + up to BNT_MAX_VLAN_DEPTH VLAN tags
 *   - IPv4 base header + variable IHL
 *   - IPv6 base header + bounded extension-header walk
 *   - TCP, UDP, ICMPv4, ICMPv6, ARP
 *
 * Non-goals:
 *   - high-level tunnel/NAT/firewall semantics
 *   - full IPv4/TCP option parsing
 *   - unbounded IPv6 extension-header traversal
 */

#ifndef BNT_CTX_TYPE
#error "bnt_core.h must be included by a bnt backend header"
#endif

#ifdef BNT_CORE_INCLUDED
#error "bnt_core.h cannot be included more than once in the same translation unit"
#endif
#define BNT_CORE_INCLUDED

/*
 * Minimum supported compiler is clang 16. clang 15 and earlier generate BPF
 * bytecode that loses the offset->range relation the verifier needs (packet
 * reads off a derived offset are rejected with r=0), and fail to unroll the SRH
 * segment loop; neither is fixable with the verifier barriers used here. See the
 * barrier notes below.
 */
#if defined(__clang_major__) && __clang_major__ < 16
#error "BONet requires clang 16 or newer"
#endif

/*
 * Verifier barriers (global mode).
 *
 * In a global sub-program clang can drop the tight bound of a narrowed scalar
 * (header offset / prefix length / SRH segment offset), which the verifier then
 * rejects. Which scalars lose their bound depends on the clang version, so each
 * barrier site below has its own #if listing the versions that need it, found
 * by removing one site at a time over the insert/remove/encap tests. Only tested
 * versions are listed (clang 16 is the floor; 23+ is untested). The need is not
 * monotonic: clang 20 needs none, 18/19 need the most. clang 22 needs none of these — at
 * its _g entry BNT_TIGHTEN_OFFSET (below) covers it instead. In legacy mode
 * (old/stricter verifiers) every site is on.
 *
 * BNT_PIN(x) pins x in a register so clang can't re-derive it through a wider
 * intermediate and lose the bound. It is the only barrier primitive: every site
 * uses it directly under its own #if (a few sites that no supported clang needs
 * in global mode sit under a plain `#if BNT_LEGACY_KERNEL`, on only for old
 * verifiers).
 */
#define BNT_PIN(x) asm volatile("" : "+r"(x))

/*
 * Pin a packet offset, then clamp its var_off to a maximum so derived pointer
 * offsets stay bounded (and never sign-extend negative). The barrier keeps clang
 * from proving the clamp a no-op and dropping it. A no-op for valid offsets,
 * which are always <= the cap. Needed by clang 22 (and legacy); compiled out
 * everywhere else. Gated to exactly 22, as later versions are untested.
 */
#if BNT_LEGACY_KERNEL || __clang_major__ == 22
#define BNT_TIGHTEN_OFFSET(x, cap)                                              \
    do { asm volatile("" : "+r"(x)); (x) &= (cap); } while (0)
#else
#define BNT_TIGHTEN_OFFSET(x, cap) ((void)(x))
#endif

/*
 * Two orthogonal verifier modes (set by the backend header or the build):
 *   BNT_INLINE_ALL=0     - packet access lives in global BPF subprograms,
 *                           verified in isolation, independent of the caller.
 *                           One bpf2bpf call per operation. Implies
 *                           the XDP backend, so code under #if !BNT_INLINE_ALL
 *                           may freely use the XDP-only __bnt_data_ptr. This is
 *                           the default; BNT_INLINE_ALL=1 inlines every
 *                           operation into the program instead.
 *   BNT_LEGACY_KERNEL  - inline bodies use CSE/volatile barriers to pass the
 *                           verifier without globals (only meaningful when
 *                           BNT_INLINE_ALL=1).
 * Three meaningful modes: (1,0) fast inline, (1,1) hardened inline, (0,*) globals.
 * The globals mode does not need the barriers (a global starts from a clean
 * verifier state), so it forces BNT_LEGACY_KERNEL off.
 */
#ifndef BNT_INLINE_ALL
#define BNT_INLINE_ALL 1
#endif
#ifndef BNT_LEGACY_KERNEL
#define BNT_LEGACY_KERNEL 0
#endif
#if !BNT_INLINE_ALL
#undef BNT_LEGACY_KERNEL
#define BNT_LEGACY_KERNEL 0
#endif

/*
 * Global mode is verified with -mcpu=v3 (32-bit ALU and jumps). Below it,
 * clang 16/17 rebuild packet pointers after their bounds check in the insert
 * globals under BNT_STRICT_ALIGN, and the verifier rejects them. clang 18+
 * reports the level in __BPF_CPU_VERSION__; clang 16/17 do not, so for them
 * the requirement is only documented.
 */
#if !BNT_INLINE_ALL && defined(__BPF_CPU_VERSION__) && __BPF_CPU_VERSION__ < 3
#error "BONet global mode needs -mcpu=v3 or newer (or set BNT_INLINE_ALL=1)"
#endif

#ifndef BNT_MAX_VLAN_DEPTH
#define BNT_MAX_VLAN_DEPTH 2
#endif

#ifndef BNT_MAX_IPV6_EXT_DEPTH
#define BNT_MAX_IPV6_EXT_DEPTH 6
#endif

#define BNT_MAC_LEN 6

/* Typed MAC wrapper — needed for BTF-correct global function signatures.
 * Raw unsigned char[6] decays to unsigned char * in a function parameter,
 * losing size information in the BTF encoding. */
/* 4-byte aligned so the MAC globals can copy it as 4 + 2 bytes; it is only ever
 * a temporary owned by the wrappers, never the caller's array. */
struct __bnt_mac { unsigned char addr[6]; } __attribute__((aligned(4)));

#define BNT_IPV4(a, b, c, d) \
    ((__be32)bpf_htonl((((__u32)(a)) << 24) | (((__u32)(b)) << 16) | \
                        (((__u32)(c)) <<  8) |  ((__u32)(d))))

#ifndef BNT_VLAN_DEI
#define BNT_VLAN_DEI 0x1000
#endif

#ifndef IP_RF
#define IP_RF 0x8000
#endif

#ifndef IP_DF
#define IP_DF 0x4000
#endif

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

#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC 0x8847
#endif
#ifndef ETH_P_MPLS_MC
#define ETH_P_MPLS_MC 0x8848
#endif
#ifndef BNT_SRV6_MAX_SEGS
#define BNT_SRV6_MAX_SEGS 8
#endif
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif

#ifndef BNT_ICMP6_ND_ROUTER_ADVERT
#define BNT_ICMP6_ND_ROUTER_ADVERT 134
#endif

#ifndef BNT_ICMP6_ND_NEIGHBOR_ADVERT
#define BNT_ICMP6_ND_NEIGHBOR_ADVERT 136
#endif

#ifndef BNT_ICMP6_RA_MANAGED
#define BNT_ICMP6_RA_MANAGED    0x80
#endif
#ifndef BNT_ICMP6_RA_OTHER
#define BNT_ICMP6_RA_OTHER      0x40
#endif
#ifndef BNT_ICMP6_RA_HOME_AGENT
#define BNT_ICMP6_RA_HOME_AGENT 0x20
#endif
#ifndef BNT_ICMP6_RA_PREFERENCE_MASK
#define BNT_ICMP6_RA_PREFERENCE_MASK 0x18
#endif
#ifndef BNT_ICMP6_RA_PREFERENCE_SHIFT
#define BNT_ICMP6_RA_PREFERENCE_SHIFT 3
#endif
#ifndef BNT_ICMP6_RA_PREFERENCE_MEDIUM
#define BNT_ICMP6_RA_PREFERENCE_MEDIUM 0x0
#endif
#ifndef BNT_ICMP6_RA_PREFERENCE_HIGH
#define BNT_ICMP6_RA_PREFERENCE_HIGH 0x1
#endif
#ifndef BNT_ICMP6_RA_PREFERENCE_RESERVED
#define BNT_ICMP6_RA_PREFERENCE_RESERVED 0x2
#endif
#ifndef BNT_ICMP6_RA_PREFERENCE_LOW
#define BNT_ICMP6_RA_PREFERENCE_LOW 0x3
#endif
#ifndef BNT_ICMP6_RA_PROXY
#define BNT_ICMP6_RA_PROXY 0x04
#endif

#ifndef BNT_ICMP6_NA_ROUTER
#define BNT_ICMP6_NA_ROUTER    0x80
#endif
#ifndef BNT_ICMP6_NA_SOLICITED
#define BNT_ICMP6_NA_SOLICITED 0x40
#endif
#ifndef BNT_ICMP6_NA_OVERRIDE
#define BNT_ICMP6_NA_OVERRIDE  0x20
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

struct bnt_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct bnt_icmp4_hdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        __be32 unused;
    } un;
};

struct bnt_arp_hdr {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8 ar_hln;
    __u8 ar_pln;
    __be16 ar_op;
};

/* SRv6 Segment Routing Header (RFC 8754). Defined locally to avoid dependency
 * on linux/seg6.h, which is not always available in BPF include paths. */
struct bnt_sr_hdr {
    __u8   nexthdr;
    __u8   hdrlen;        /* (hdrlen+1)*8 = total bytes */
    __u8   type;          /* must be 4 */
    __u8   segments_left;
    __u8   first_segment; /* index of last entry = n_segs - 1 */
    __u8   flags;
    __be16 tag;
    /* Followed by (first_segment+1) * sizeof(struct in6_addr) bytes. */
};

#define BNT_TCP_FIN 0x001
#define BNT_TCP_SYN 0x002
#define BNT_TCP_RST 0x004
#define BNT_TCP_PSH 0x008
#define BNT_TCP_ACK 0x010
#define BNT_TCP_URG 0x020
#define BNT_TCP_ECE 0x040
#define BNT_TCP_CWR 0x080
#define BNT_TCP_NS  0x100

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
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

/*
 * Per-header offset bounds.  Each bnt_*__next_off clamps the offset it returns
 * to a power-of-two maximum where that next header can begin. This rejects
 * implausibly deep nesting and gives the returned offset a tight verifier range, so a developer can take it and keep parsing an
 * unsupported header with ordinary inline `data + off` code.  Without the clamp
 * the offset carries the wide range of the global BPF function that computed it,
 * and an inline access on it would fail to verify.  Override before include to
 * support deeper stacks (must stay <= 0x7fff for inline access to verify).
 */
#ifndef BNT_OFF_BOUND_L2
#define BNT_OFF_BOUND_L2 0x3fu     /* 63  - after Ethernet/VLAN */
#endif
#ifndef BNT_OFF_BOUND_L3
#define BNT_OFF_BOUND_L3 0xffu     /* 255 - after MPLS/ARP, start of L4 over IPv4 */
#endif
#ifndef BNT_OFF_BOUND_L4
#define BNT_OFF_BOUND_L4 0x1ffu    /* 511 - L4 / payload, incl. IPv6 extension headers */
#endif

/*
 * Extending past the supported protocols (hand-parsing an unsupported header at
 * an offset bnt returned).  Two equivalent, verifier-safe options — no bnt
 * block-reader is needed because the kernel and the clamp already cover it:
 *
 *   1. Kernel helper: bpf_xdp_load_bytes(ctx, off, &hdr, sizeof(hdr)) on XDP,
 *      bpf_skb_load_bytes(skb, off, &hdr, sizeof(hdr)) on TC.  The helper takes a
 *      runtime offset and bounds-checks in the kernel, so it verifies regardless
 *      of how wide the offset's range is.
 *   2. Inline parsing: ordinary `hdr = data + off; if (hdr + N > data_end) ...;`
 *      directly on the offset a bnt_*__next_off returned — it is clamped (see
 *      BNT_OFF_BOUND_* above), so it carries a tight enough range to verify.
 */

/* Clamp a computed next-header offset to `bound` and store it; see above. */
static __always_inline int __bnt_off_ret(__u32 off, __u32 bound, __u32 *out)
{
    if (off > bound)
        return BNT_ERR_TRUNC;
    *out = off;
    return BNT_OK;
}

typedef struct bnt_eth   { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_eth;
typedef struct bnt_ipv4  { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_ipv4;
typedef struct bnt_ipv6  { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_ipv6;
typedef struct bnt_tcp   { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_tcp;
typedef struct bnt_udp   { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_udp;
typedef struct bnt_icmp4 { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_icmp4;
typedef struct bnt_icmp6 { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_icmp6;
typedef struct bnt_arp   { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_arp;
typedef struct bnt_mpls  { BNT_CTX_TYPE *__ctx; __u32 __off; } bnt_mpls;

typedef struct bnt_fib4 {
    struct bpf_fib_lookup __fib;
    int __status;
} bnt_fib4;

typedef struct bnt_fib6 {
    struct bpf_fib_lookup __fib;
    int __status;
} bnt_fib6;


struct __bnt_eth_meta {
    __u32 hlen;
    __u16 proto;
    __u8 vlan_depth;
    __u16 vlan_tci[BNT_MAX_VLAN_DEPTH];
};

struct __bnt_ipv4_meta {
    __u32 next_off;
    __u8 protocol;
    /* MF set or non-zero fragment offset. */
    __u8 is_fragment;
    /* next_off points at L4 for whole datagrams and first fragments. */
    __u8 l4_off_valid;
};

struct __bnt_ipv6_meta {
    __u32 next_off;
    __u32 frag_hdr_off;
    __u8 l4_proto;
    __u8 ext_depth;
    __u8 has_fragment_hdr;
    /* Fragment Header with M set or non-zero fragment offset. */
    __u8 is_fragment;
    /* next_off points at resolved L4 only when fragment offset is zero. */
    __u8 l4_off_valid;
    __u16 frag_off_flags;
};

struct __bnt_arp_meta {
    __u32 hlen;
    __u16 htype;
    __u16 ptype;
    __u8 haddr_len;
    __u8 paddr_len;
};

/*
 * Maximum payload length for full-checksum recompute loops.
 * Sets the worst-case iteration bound seen by the BPF verifier.
 * Default of 65535 covers GRO super-segments in TC. For standard Ethernet
 * (no GRO) you can reduce this to 1500 before including the backend header.
 */
/*
 * BNT_MAX_PAYLOAD and BNT_CSUM_CHUNK must be defined by the backend header
 * (bnt_xdp.h or a TC backend header) before including this file.
 *
 * BNT_MAX_PAYLOAD: maximum payload bytes the checksum loop covers.
 * BNT_CSUM_CHUNK:  bytes read per iteration; multiple of 4, ≤ 512
 *                   (bpf_csum_diff scratchpad and BPF stack frame limits).
 *                   Larger chunks → fewer verifier iterations, more stack.
 */
#if !defined(BNT_MAX_PAYLOAD) || !defined(BNT_CSUM_CHUNK)
#error "bnt_core.h must be included via bnt_xdp.h or a TC backend header"
#endif

/* Fold a 32-bit partial checksum to a network-order 16-bit checksum.
 * bpf_csum_diff accumulates in native LE format on x86-64; the result after
 * complement is also LE, and stored as-is (raw bytes end up network order). */
static __always_inline __be16 __bnt_csum_fold(__wsum w)
{
    __u32 sum = (__u32)w;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (__be16)(__u16)~sum;
}

/*
 * Accumulate a checksum over [off, off+len).
 *
 * Two constant-size loops (BNT_CSUM_CHUNK / 4 byte) plus a tail ensure
 * __bnt_read is always inlined with a compile-time-constant size argument:
 *   - XDP: __builtin_memcpy only accepts constant sizes in BPF target
 *   - TC:  bpf_skb_load_bytes must receive a verifier-provably non-zero size
 * The break-before-read pattern guarantees the size literal is reachable only
 * when len >= that literal, satisfying both constraints.
 *
 * Secondary loop bound is BNT_CSUM_CHUNK/4 so it covers the full remainder
 * after the main loop (up to BNT_CSUM_CHUNK-4 bytes in 4-byte steps).
 */

static __always_inline int __bnt_is_ipv6_ext(__u8 nexthdr)
{
    switch (nexthdr) {
    case NEXTHDR_HOP:
    case NEXTHDR_ROUTING:
    case NEXTHDR_FRAGMENT:
    case NEXTHDR_AUTH:
    case NEXTHDR_DEST:
    case NEXTHDR_MOBILITY:
    case NEXTHDR_HIP:
    case NEXTHDR_SHIM:
        return 1;
    default:
        return 0;
    }
}

/* Same set as __bnt_is_ipv6_ext, with the values below 64 tested by one mask
 * first. Used by the global-mode fast paths: there clang lowers the switch so
 * that a plain next header (TCP, UDP, ICMPv6) runs both halves of it. */
static __always_inline int __bnt_is_ipv6_ext_split(__u8 nexthdr)
{
    if (nexthdr < 64)
        return (int)((((1ULL << NEXTHDR_HOP) | (1ULL << NEXTHDR_ROUTING) |
                       (1ULL << NEXTHDR_FRAGMENT) | (1ULL << NEXTHDR_AUTH) |
                       (1ULL << NEXTHDR_DEST)) >> nexthdr) & 1);
    return nexthdr == NEXTHDR_MOBILITY || nexthdr == NEXTHDR_HIP ||
           nexthdr == NEXTHDR_SHIM;
}

static __always_inline int __bnt_ipv4_l4_has_pseudo_csum(__u8 protocol)
{
    return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

static __always_inline int __bnt_ipv6_l4_has_pseudo_csum(__u8 protocol)
{
    return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMPV6;
}

static __always_inline int __bnt_ipv6_l4_maybe_has_pseudo_csum(const struct __bnt_ipv6_meta *m)
{
    if (!m)
        return 0;
    if (__bnt_ipv6_l4_has_pseudo_csum(m->l4_proto))
        return 1;
    return !m->l4_off_valid && __bnt_is_ipv6_ext(m->l4_proto);
}

static __always_inline int __bnt_eth_meta_view(const bnt_eth *eth, struct __bnt_eth_meta *m)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    /* Global mode (the ctx_find globals inline this): read the fields from a
     * bounded packet pointer instead of copying each header. */
    const struct ethhdr *h;
#else
    struct ethhdr h;
#endif
    __be16 proto;
    __u32 cur;
    __u32 i;
    int ret;

    if (!eth || !m)
        return BNT_ERR_BAD_ARG;

    __builtin_memset(m, 0, sizeof(*m));

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    ret = __bnt_data_ptr(eth->__ctx, eth->__off, sizeof(*h), (void **)&h);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(h->h_proto);
#else
    ret = __bnt_read(eth->__ctx, eth->__off, &h, sizeof(h));
    if (ret)
        return ret;
    proto = h.h_proto;
#endif

    m->hlen = sizeof(struct ethhdr);
    m->proto = bpf_ntohs(proto);
    cur = eth->__off + sizeof(struct ethhdr);

#pragma unroll
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
        const struct bnt_vlan_hdr *vh;
#else
        struct bnt_vlan_hdr vh;
#endif

        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
        ret = __bnt_data_ptr(eth->__ctx, cur, sizeof(*vh), (void **)&vh);
        if (ret)
            return ret;
        m->vlan_tci[i] = bpf_ntohs(__BNT_PKT_LOAD(vh->h_vlan_TCI));
        proto = __BNT_PKT_LOAD(vh->h_vlan_encapsulated_proto);
#else
        ret = __bnt_read(eth->__ctx, cur, &vh, sizeof(vh));
        if (ret)
            return ret;
        m->vlan_tci[i] = bpf_ntohs(vh.h_vlan_TCI);
        proto = vh.h_vlan_encapsulated_proto;
#endif
        m->vlan_depth++;
        m->hlen += sizeof(struct bnt_vlan_hdr);
        cur += sizeof(struct bnt_vlan_hdr);
    }

    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
        return BNT_ERR_TOO_DEEP;

    m->proto = bpf_ntohs(proto);
    return BNT_OK;
}

static __always_inline int __bnt_ipv4_meta(const bnt_ipv4 *ip, struct __bnt_ipv4_meta *m)
{
    struct iphdr h;
    __u8 vihl;
    __u16 frag;
    int ret;

    if (!ip || !m)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read(ip->__ctx, ip->__off, &h, sizeof(h));
    if (ret)
        return ret;

    vihl = *(__u8 *)&h;
    if ((vihl >> 4) != 4)
        return BNT_ERR_BAD_PROTO;

    __u32 hlen = (__u32)(vihl & 0x0f) * 4;
    if (hlen < sizeof(struct iphdr))
        return BNT_ERR_BAD_PROTO;
#if BNT_LEGACY_KERNEL
    BNT_PIN(hlen);
#endif

    ret = __bnt_bounds(ip->__ctx, ip->__off, hlen);
    if (ret)
        return ret;

    __u16 total_len = bpf_ntohs(h.tot_len);
    if (total_len < hlen)
        return BNT_ERR_BAD_PROTO;

    m->protocol = h.protocol;
    m->next_off = ip->__off + hlen;
    frag = bpf_ntohs(h.frag_off);
    m->is_fragment = ((frag & (IP_MF | IP_OFFSET)) != 0);
    m->l4_off_valid = ((frag & IP_OFFSET) == 0);
    return BNT_OK;
}

static __always_inline int __bnt_ipv6_meta(const bnt_ipv6 *ip6, struct __bnt_ipv6_meta *m)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    /* Global mode (the ctx_find globals inline this): read the fields from a
     * bounded packet pointer instead of copying each header. */
    const struct ipv6hdr *h;
#else
    struct ipv6hdr h;
#endif
    __u8 first;
    __u8 nexthdr;
    __u32 cur;
    __u32 i;
    int ret;

    if (!ip6 || !m)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    ret = __bnt_data_ptr(ip6->__ctx, ip6->__off, sizeof(*h), (void **)&h);
    if (ret)
        return ret;

    first = *(const __u8 *)h;
    if ((first >> 4) != 6)
        return BNT_ERR_BAD_PROTO;
    nexthdr = h->nexthdr;
#else
    ret = __bnt_read(ip6->__ctx, ip6->__off, &h, sizeof(h));
    if (ret)
        return ret;

    first = *(__u8 *)&h;
    if ((first >> 4) != 6)
        return BNT_ERR_BAD_PROTO;
    nexthdr = h.nexthdr;
#endif

    m->l4_proto = nexthdr;
    m->frag_hdr_off = 0;
    m->ext_depth = 0;
    m->has_fragment_hdr = 0;
    m->is_fragment = 0;
    m->l4_off_valid = 1;
    m->frag_off_flags = 0;

    cur = ip6->__off + sizeof(struct ipv6hdr);

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    /* Common case, no extension headers: one test, no walk. */
    if (!__bnt_is_ipv6_ext_split(nexthdr)) {
        m->next_off = cur;
        return BNT_OK;
    }
#endif

#pragma unroll
    for (i = 0; i < BNT_MAX_IPV6_EXT_DEPTH; i++) {
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
        const __u8 *ext;
#else
        __u8 ext[8];
#endif
        __u32 ext_len;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
        /* The fast path above already tested the first next header. */
        if (i && !__bnt_is_ipv6_ext(nexthdr))
#else
        if (!__bnt_is_ipv6_ext(nexthdr))
#endif
            break;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
        ret = __bnt_data_ptr(ip6->__ctx, cur, 8, (void **)&ext);
#else
        ret = __bnt_read(ip6->__ctx, cur, ext, sizeof(ext));
#endif
        if (ret)
            return ret;

        m->ext_depth++;

        if (nexthdr == NEXTHDR_FRAGMENT) {
            __u16 frag_off_flags;

            ext_len = 8;
            frag_off_flags = ((__u16)ext[2] << 8) | ext[3];
            m->has_fragment_hdr = 1;
            m->frag_hdr_off = cur;
            m->frag_off_flags = frag_off_flags;
            if ((frag_off_flags & 0xfff8) != 0 || (frag_off_flags & 0x1) != 0)
                m->is_fragment = 1;
            if ((frag_off_flags & 0xfff8) != 0) {
                m->l4_off_valid = 0;
                m->l4_proto = ext[0];
                m->next_off = cur + ext_len;
                return BNT_OK;
            }
        } else if (nexthdr == NEXTHDR_AUTH) {
            ext_len = ((__u32)ext[1] + 2) * 4;
        } else {
            ext_len = ((__u32)ext[1] + 1) * 8;
        }

        if (ext_len < 8)
            return BNT_ERR_BAD_PROTO;
#if BNT_LEGACY_KERNEL
        BNT_PIN(ext_len);
        BNT_PIN(cur);
#endif

        ret = __bnt_bounds(ip6->__ctx, cur, ext_len);
        if (ret)
            return ret;

        nexthdr = ext[0];
        cur += ext_len;
    }

    if (__bnt_is_ipv6_ext(nexthdr) && m->ext_depth >= BNT_MAX_IPV6_EXT_DEPTH)
        return BNT_ERR_TOO_DEEP;

    m->l4_proto = nexthdr;
    m->next_off = cur;
    return BNT_OK;
}

static __always_inline int __bnt_tcp_hlen(const bnt_tcp *tcp, __u32 *out)
{
    __u8 doff_flags0;
    __u32 hlen;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_u8(tcp->__ctx, tcp->__off + 12, &doff_flags0);
    if (ret)
        return ret;

    hlen = ((__u32)(doff_flags0 >> 4)) * 4;
    if (hlen < sizeof(struct tcphdr))
        return BNT_ERR_BAD_PROTO;
#if BNT_LEGACY_KERNEL
    BNT_PIN(hlen);
#endif

    ret = __bnt_bounds(tcp->__ctx, tcp->__off, hlen);
    if (ret)
        return ret;

    *out = hlen;
    return BNT_OK;
}

static __always_inline int __bnt_arp_meta(const bnt_arp *arp, struct __bnt_arp_meta *m)
{
    struct bnt_arp_hdr h;
    __u32 hlen;
    int ret;

    if (!arp || !m)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read(arp->__ctx, arp->__off, &h, sizeof(h));
    if (ret)
        return ret;

    hlen = sizeof(struct bnt_arp_hdr) + 2 * h.ar_hln + 2 * h.ar_pln;
    ret = __bnt_bounds(arp->__ctx, arp->__off, hlen);
    if (ret)
        return ret;

    m->hlen = hlen;
    m->htype = bpf_ntohs(h.ar_hrd);
    m->ptype = bpf_ntohs(h.ar_pro);
    m->haddr_len = h.ar_hln;
    m->paddr_len = h.ar_pln;
    return BNT_OK;
}

static __always_inline int __bnt_arp_is_eth_ipv4_meta(const struct __bnt_arp_meta *m)
{
    return m && m->htype == ARPHRD_ETHER && m->ptype == ETH_P_IP &&
           m->haddr_len == ETH_ALEN && m->paddr_len == 4;
}

static __always_inline __u32 __bnt_arp_sha_off(const bnt_arp *arp)
{
    return arp->__off + sizeof(struct bnt_arp_hdr);
}

static __always_inline __u32 __bnt_arp_spa_off(const bnt_arp *arp, const struct __bnt_arp_meta *m)
{
    return __bnt_arp_sha_off(arp) + m->haddr_len;
}

static __always_inline __u32 __bnt_arp_tha_off(const bnt_arp *arp, const struct __bnt_arp_meta *m)
{
    return __bnt_arp_spa_off(arp, m) + m->paddr_len;
}

static __always_inline __u32 __bnt_arp_tpa_off(const bnt_arp *arp, const struct __bnt_arp_meta *m)
{
    return __bnt_arp_tha_off(arp, m) + m->haddr_len;
}

/* ── !BNT_INLINE_ALL: global BPF functions ────────────────────────────────
 *
 * When BNT_INLINE_ALL=0 every packet access is encapsulated
 * inside a non-static (global) BPF function verified once in isolation.
 * Callers pass only (ctx, off, typed_out) and never handle PTR_TO_PACKET.
 *
 * Primitive globals: one typed read/write.
 * Operation globals: a whole API call (loops, helpers, checksum).
 *
 * They are defined before their callers. __attribute__((noinline, weak, nonnull(1))):
 *   - non-static keeps them BTF_FUNC_GLOBAL, so the verifier checks each once
 *     in isolation (static would verify them with the caller's state);
 *   - weak lets the BPF static linker keep one copy when several objects that
 *     include this header are linked together;
 *   - nonnull(1): a global can only be called with the program's ctx, so ctx
 *     is never NULL.
 */
#ifdef BNT_XDP_H

/* Shared by the globals below: header walks and checksum updates on bounded
 * packet pointers, with no nested global call. */

/* *check after the 16-bit packet words from become to; mangled: a zero UDP
 * checksum means none and stays zero, and an update never stores zero. */
static __always_inline void __bnt_api_csum16(__be16 *check, __be16 from, __be16 to, int mangled)
{
    __be16 c = __BNT_PKT_LOAD(*check);

    if (mangled && c == 0)
        return;
    c = __bnt_csum16_update(c, from, to);
    if (mangled && c == 0)
        c = bpf_htons(0xffff);
    __BNT_PKT_STORE(*check, c);
}

/* Bound on a header offset before a walk from it. The walk adds constants to
 * the offset, and the verifier tracks a packet pointer only while offset plus
 * constants stay within 64 KiB (MAX_PACKET_OFF). No XDP frame reaches this
 * far, so the bound changes no result. */
#define __BNT_API_MAX_OFF (BNT_XDP_MAX_PACKET_OFFSET - 64)

/* The L4 checksum offset (from the L4 header) of a transport whose pseudo
 * header the IP lengths are in, or 0. */
static __always_inline __u32 __bnt_api_l4_check_off(__u8 proto)
{
    if (proto == IPPROTO_TCP)
        return offsetof(struct tcphdr, check);
    if (proto == IPPROTO_UDP)
        return offsetof(struct udphdr, check);
    return 0;
}

/* __bnt_is_ipv6_ext without a branch: one bit per next-header value, in two
 * 64-bit masks (0-63, and 128-191 for 135, 139, 140). A branch here ends up as
 * the global's last block, and the frozen asm has to end with its exit. */
static __always_inline __u32 __bnt_api_is_ext(__u8 nh)
{
    __u32 idx = nh >> 6;                                    /* 0..3 */
    __u32 lo = 1 - ((idx | (idx >> 1)) & 1);                /* idx == 0 */
    __u32 hi = (idx >> 1) & ~idx & 1;                       /* idx == 2 */
    __u64 low = (1ULL << NEXTHDR_HOP) | (1ULL << NEXTHDR_ROUTING) | (1ULL << NEXTHDR_FRAGMENT) |
                (1ULL << NEXTHDR_AUTH) | (1ULL << NEXTHDR_DEST);
    __u64 high = (1ULL << (NEXTHDR_MOBILITY - 128)) | (1ULL << (NEXTHDR_HIP - 128)) |
                 (1ULL << (NEXTHDR_SHIM - 128));

    return (((low >> (nh & 63)) & lo) | ((high >> (nh & 63)) & hi)) & 1;
}

/* The IPv6 extension-header walk on bounded packet pointers. With stop_at_frag
 * (a constant at every call) it returns at the Fragment header, for the
 * callers that only need that header: the rest of the chain is not walked, and
 * its errors are not reported. m's L4 fields are then not set. */
static __always_inline int __bnt_api_ipv6_walk_to(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_ipv6_meta *m,
                                                  int stop_at_frag)
{
    const __u8 *h;
    __u8 nexthdr;
    __u32 cur, i;
    int ret;

    __builtin_memset(m, 0, sizeof(*m));
    if (off > __BNT_API_MAX_OFF)
        return BNT_ERR_TRUNC;
    BNT_PIN(off);
    ret = __bnt_data_ptr_in_range(ctx, off, 8, (void **)&h);
    if (ret)
        return ret;
    if ((h[0] >> 4) != 6)
        return BNT_ERR_BAD_PROTO;
    nexthdr = h[offsetof(struct ipv6hdr, nexthdr)];
    m->l4_proto = nexthdr;
    m->l4_off_valid = 1;
    cur = off + sizeof(struct ipv6hdr);
    if (!__bnt_is_ipv6_ext_split(nexthdr)) {
        m->next_off = cur;
        return BNT_OK;
    }
    /* Give the verifier a bound on cur, or it loses the range of the pointer
     * below; a mask, not a test, since on old kernels every branch in this
     * loop counts toward the verifier's limit on pending jumps. It never
     * changes cur: cur comes from a read that succeeded, so it is below the
     * XDP frame's length (a page) plus one extension header (2 KB). Masked
     * here and at the end of each iteration, every state reaches the loop
     * head with the same range, and the verifier prunes them. */
    BNT_PIN(cur);
    cur &= 0x7fff;
#pragma clang loop unroll(disable)
    for (i = 0; i < BNT_MAX_IPV6_EXT_DEPTH; i++) {
        const __u8 *e;
        __u32 ext_len;

        if (i && !__bnt_api_is_ext(nexthdr))
            break;
        /* Next header and length, or the offset field of a fragment header. */
        if (nexthdr == NEXTHDR_FRAGMENT)
            ret = __bnt_data_ptr(ctx, cur, 4, (void **)&e);
        else
            ret = __bnt_data_ptr(ctx, cur, 2, (void **)&e);
        if (ret)
            return ret;
        m->ext_depth++;
        if (nexthdr == NEXTHDR_FRAGMENT) {
            __u16 fo = ((__u16)e[2] << 8) | e[3];

            ext_len = 8;
            m->has_fragment_hdr = 1;
            m->frag_hdr_off = cur;
            m->frag_off_flags = fo;
            if ((fo & 0xfff8) != 0 || (fo & 0x1) != 0)
                m->is_fragment = 1;
            if (stop_at_frag)
                return BNT_OK;
            if ((fo & 0xfff8) != 0) {
                m->l4_off_valid = 0;
                m->l4_proto = e[0];
                m->next_off = cur + ext_len;
                return BNT_OK;
            }
        } else if (nexthdr == NEXTHDR_AUTH) {
            ext_len = ((__u32)e[1] + 2) * 4;
        } else {
            ext_len = ((__u32)e[1] + 1) * 8;
        }
        nexthdr = e[0];
        cur += ext_len;
        BNT_PIN(cur);
        cur &= 0x7fff;
    }
    if (__bnt_api_is_ext(nexthdr) && m->ext_depth >= BNT_MAX_IPV6_EXT_DEPTH)
        return BNT_ERR_TOO_DEEP;
    m->l4_proto = nexthdr;
    m->next_off = cur;
    return BNT_OK;
}

static __always_inline int __bnt_api_ipv6_walk(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_ipv6_meta *m)
{
    return __bnt_api_ipv6_walk_to(ctx, off, m, 0);
}

/* The Ethernet + VLAN walk for the globals: one bound on the offset, one test
 * against the end of the packet per header, the fields read in place. Fills
 * m (cleared first) as __bnt_eth_meta does. */
static __always_inline int __bnt_api_eth_walk(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_eth_meta *m)
{
    const __u8 *h;
    void *end;
    __be16 proto;
    __u32 i;

    __builtin_memset(m, 0, sizeof(*m));
    BNT_PIN(off);
    if (off > __BNT_API_MAX_OFF)
        return BNT_ERR_TRUNC;
    h = (const __u8 *)__bnt_xdp_data(ctx) + off;
    end = __bnt_xdp_data_end(ctx);
    if ((void *)(h + sizeof(struct ethhdr)) > end)
        return BNT_ERR_TRUNC;
    proto = __BNT_PKT_LOAD(((const struct ethhdr *)h)->h_proto);
    m->hlen = sizeof(struct ethhdr);
#pragma unroll
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        const struct bnt_vlan_hdr *vh = (const void *)(h + sizeof(struct ethhdr) + i * sizeof(*vh));

        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        if ((void *)(vh + 1) > end)
            return BNT_ERR_TRUNC;
        m->vlan_tci[i] = bpf_ntohs(__BNT_PKT_LOAD(vh->h_vlan_TCI));
        proto = __BNT_PKT_LOAD(vh->h_vlan_encapsulated_proto);
        m->vlan_depth++;
        m->hlen += sizeof(*vh);
    }
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
        return BNT_ERR_TOO_DEEP;
    m->proto = bpf_ntohs(proto);
    return BNT_OK;
}

/* The IPv4 header walk, for the globals that need it
 * without a nested call. */
static __always_inline int __bnt_api_ipv4_meta(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_ipv4_meta *m)
{
    struct iphdr *ip;
    __u8 vihl, protocol;
    __u16 total_len, frag;
    __u32 hlen;
    int ret;

    if (!m)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(m, 0, sizeof(*m));

    /* One bounded packet pointer (a straight-line access keeps the range even
     * for a wide off), then fields read directly: no per-field calls, no copy. */
    ret = __bnt_data_ptr(ctx, off, sizeof(struct iphdr), (void **)&ip);
    if (ret)
        return ret;

    vihl = *(__u8 *)ip;
    if ((vihl >> 4) != 4)
        return BNT_ERR_BAD_PROTO;
    hlen = (__u32)(vihl & 0x0f) * 4;
    if (hlen < sizeof(struct iphdr))
        return BNT_ERR_BAD_PROTO;

    total_len = bpf_ntohs(__BNT_PKT_LOAD(ip->tot_len));
    frag      = bpf_ntohs(__BNT_PKT_LOAD(ip->frag_off));
    protocol  = ip->protocol;

    /* With options (hlen > 20), confirm the full variable-length header is present. */
    if (hlen > sizeof(struct iphdr)) {
        void *opt_end;
        ret = __bnt_data_ptr(ctx, off + hlen - 1, 1, &opt_end);
        if (ret)
            return ret;
    }

    if (total_len < hlen)
        return BNT_ERR_BAD_PROTO;

    m->protocol     = protocol;
    m->next_off     = off + hlen;
    m->is_fragment  = ((frag & (IP_MF | IP_OFFSET)) != 0);
    m->l4_off_valid = ((frag & IP_OFFSET) == 0);
    return BNT_OK;
}

/* The read globals keep the bnt_rw.h output convention (a non-NULL destination
 * is zero on failure) but zero it only when the read fails: __bnt_read writes
 * nothing on failure and the whole destination on success. */
#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_u8_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_u8_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read(ctx, off, out, sizeof(*out));
    if (ret)
        *out = 0;
    return ret;
}
#endif
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_be16_g(BNT_CTX_TYPE *ctx, __u32 off, __be16 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_be16_g(BNT_CTX_TYPE *ctx, __u32 off, __be16 *out)
{
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read(ctx, off, out, sizeof(*out));
    if (ret)
        *out = 0;
    return ret;
}
#endif
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_be32_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_be32_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out)
{
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read(ctx, off, out, sizeof(*out));
    if (ret)
        *out = 0;
    return ret;
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_read_mac(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out)
{
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
#if !BNT_STRICT_ALIGN
    ret = __bnt_read_wide(ctx, off, out->addr, BNT_MAC_LEN, __alignof__(*out));
#else
    ret = __bnt_read(ctx, off, out->addr, BNT_MAC_LEN);
#endif
    if (ret)
        __builtin_memset(out->addr, 0, BNT_MAC_LEN);
    return ret;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_mac_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_mac_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out)
{
    return __bnt_read_mac(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_read_in6(BNT_CTX_TYPE *ctx, __u32 off, struct in6_addr *out)
{
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read(ctx, off, out, sizeof(*out));
    if (ret)
        __builtin_memset(out, 0, sizeof(*out));
    return ret;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_in6_g(BNT_CTX_TYPE *ctx, __u32 off, struct in6_addr *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_read_in6_g(BNT_CTX_TYPE *ctx, __u32 off, struct in6_addr *out)
{
    return __bnt_read_in6(ctx, off, out);
}
#endif
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_u8_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 val);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_u8_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 val)
{
    return __bnt_write_u8(ctx, off, val);
}
#endif
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_be16_g(BNT_CTX_TYPE *ctx, __u32 off, __be16 val);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_be16_g(BNT_CTX_TYPE *ctx, __u32 off, __be16 val)
{
    return __bnt_write_be16(ctx, off, val);
}
#endif
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_be32_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 val);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_be32_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 val)
{
    return __bnt_write_be32(ctx, off, val);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_write_mac(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *in)
{
    if (!in)
        return BNT_ERR_BAD_ARG;
#if !BNT_STRICT_ALIGN
    return __bnt_write_wide(ctx, off, in->addr, BNT_MAC_LEN, __alignof__(*in));
#else
    return __bnt_write(ctx, off, in->addr, BNT_MAC_LEN);
#endif
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_mac_g(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *in);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_write_mac_g(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *in)
{
    return __bnt_write_mac(ctx, off, in);
}
#endif
#endif

/* ── Navigation globals ─────────────────────────────────────────────────── */
/*
 * The header walks run on bounded packet pointers inside the global, from an
 * offset bounded first (__BNT_API_MAX_OFF), so the verifier keeps the
 * pointer ranges without a nested read global per field.
 */

#ifdef BNT_XDP_H
static __always_inline int __bnt_eth_next_off(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    struct __bnt_eth_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_eth_walk(ctx, off, &meta);
    if (ret)
        return ret;
    *out = off + meta.hlen;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_eth_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_eth_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    return __bnt_eth_next_off(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_next_off(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    struct iphdr *ip;
    __u8 vihl;
    __u16 total_len, frag;
    __u32 hlen;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;

    /* One bounded packet pointer, fields read directly (no per-field calls). */
    ret = __bnt_data_ptr(ctx, off, sizeof(struct iphdr), (void **)&ip);
    if (ret)
        return ret;

    vihl = *(__u8 *)ip;
    if ((vihl >> 4) != 4)
        return BNT_ERR_BAD_PROTO;
    hlen = (__u32)(vihl & 0x0f) * 4;
    if (hlen < sizeof(struct iphdr))
        return BNT_ERR_BAD_PROTO;

    total_len = bpf_ntohs(__BNT_PKT_LOAD(ip->tot_len));
    frag      = bpf_ntohs(__BNT_PKT_LOAD(ip->frag_off));

    /* With options (hlen > 20), confirm the full variable-length header is present. */
    if (hlen > sizeof(struct iphdr)) {
        void *opt_end;
        ret = __bnt_data_ptr(ctx, off + hlen - 1, 1, &opt_end);
        if (ret)
            return ret;
    }

    if ((__u32)total_len < hlen)
        return BNT_ERR_BAD_PROTO;
    if ((frag & IP_OFFSET) != 0)
        return BNT_ERR_FRAGMENT;

    *out = off + hlen;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv4_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv4_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    return __bnt_ipv4_next_off(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_next_proto_off(BNT_CTX_TYPE *ctx, __u32 off,
                                                            __u8 *proto, __u32 *proto_off)
{
    struct iphdr *ip;
    __u8 vihl, protocol;
    __u16 total_len, frag;
    __u32 hlen;
    int ret;

    if (proto)
        *proto = 0;
    if (proto_off)
        *proto_off = 0;
    if (!proto || !proto_off)
        return BNT_ERR_BAD_ARG;

    /* One bounded packet pointer, fields read directly (no per-field calls). */
    ret = __bnt_data_ptr(ctx, off, sizeof(struct iphdr), (void **)&ip);
    if (ret)
        return ret;

    vihl = *(__u8 *)ip;
    if ((vihl >> 4) != 4)
        return BNT_ERR_BAD_PROTO;
    hlen = (__u32)(vihl & 0x0f) * 4;
    if (hlen < sizeof(struct iphdr))
        return BNT_ERR_BAD_PROTO;

    total_len = bpf_ntohs(__BNT_PKT_LOAD(ip->tot_len));
    frag      = bpf_ntohs(__BNT_PKT_LOAD(ip->frag_off));
    protocol  = ip->protocol;

    /* With options (hlen > 20), confirm the full variable-length header is present. */
    if (hlen > sizeof(struct iphdr)) {
        void *opt_end;
        ret = __bnt_data_ptr(ctx, off + hlen - 1, 1, &opt_end);
        if (ret)
            return ret;
    }

    if ((__u32)total_len < hlen)
        return BNT_ERR_BAD_PROTO;
    if ((frag & IP_OFFSET) != 0)
        return BNT_ERR_FRAGMENT;

    *proto = protocol;
    *proto_off = off + hlen;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv4_next_proto_off_g(BNT_CTX_TYPE *ctx, __u32 off,
                                                            __u8 *proto, __u32 *proto_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv4_next_proto_off_g(BNT_CTX_TYPE *ctx, __u32 off,
                                                            __u8 *proto, __u32 *proto_off)
{
    return __bnt_ipv4_next_proto_off(ctx, off, proto, proto_off);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_next_off(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_ipv6_walk(ctx, off, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    *out = meta.next_off;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv6_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv6_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    return __bnt_ipv6_next_off(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_next_off(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    const __u8 *h;
    __u32 hlen;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    /* The data offset is the high nibble of byte 12. */
    ret = __bnt_data_ptr(ctx, off + 12, 1, (void **)&h);
    if (ret)
        return ret;
    hlen = ((__u32)(h[0] >> 4)) * 4;
    if (hlen < sizeof(struct tcphdr))
        return BNT_ERR_BAD_PROTO;
    ret = __bnt_bounds(ctx, off, hlen);
    if (ret)
        return ret;
    *out = off + hlen;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_tcp_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_tcp_next_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *out)
{
    return __bnt_tcp_next_off(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_eth_meta(BNT_CTX_TYPE *ctx, __u32 off,
                                                struct __bnt_eth_meta *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    return __bnt_api_eth_walk(ctx, off, out);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_eth_meta_g(BNT_CTX_TYPE *ctx, __u32 off,
                                                struct __bnt_eth_meta *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_eth_meta_g(BNT_CTX_TYPE *ctx, __u32 off,
                                                struct __bnt_eth_meta *out)
{
    return __bnt_eth_meta(ctx, off, out);
}
#endif
#endif

/* The IPv6 walk for ipv6_set_addr and ipv6_set_payload_len: fills only the
 * fields they use (l4_proto, next_off, l4_off_valid, is_fragment), so the
 * rest of the walk's bookkeeping is compiled out. The caller clears m. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_l4_meta(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_ipv6_meta *m)
{
    struct __bnt_ipv6_meta w;
    int ret;

    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_ipv6_walk(ctx, off, &w);
    if (ret)
        return ret;
    m->l4_proto = w.l4_proto;
    m->next_off = w.next_off;
    m->l4_off_valid = w.l4_off_valid;
    m->is_fragment = w.is_fragment;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_l4_meta_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_ipv6_meta *m);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_l4_meta_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_ipv6_meta *m)
{
    return __bnt_ipv6_l4_meta(ctx, off, m);
}
#endif
#endif

#endif /* !BNT_INLINE_ALL */

#ifdef BNT_XDP_H
/*
 * API globals: the whole of an API call that needs more than one packet
 * access, in one global with no nested global call. Each takes one bounded
 * pointer per header, sized to the last byte the call touches, and checks
 * every bound before it writes, so a call that fails leaves the packet as it
 * was. The wrapper only checks its pointers and unpacks the view.
 */

/*
 * Information globals: the fields an API wrapper needs, packed in one integer,
 * so nothing goes through a struct on the caller's stack.
 */

/* Ethernet: EtherType after the VLANs (bits 0-15), header length with the
 * VLANs (16-23), VLAN depth (24-31). */
#ifdef BNT_XDP_H
static __always_inline int __bnt_eth_info(BNT_CTX_TYPE *ctx, __u32 off, __u32 *info)
{
    struct __bnt_eth_meta m;
    int ret;

    if (!info)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_eth_walk(ctx, off, &m);
    if (ret)
        return ret;
    *info = m.proto | m.hlen << 16 | (__u32)m.vlan_depth << 24;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_info_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *info);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_info_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *info)
{
    return __bnt_eth_info(ctx, off, info);
}
#endif
#endif

/* IPv6: the L4 protocol and its offset after the extension headers, like
 * __bnt_ipv4_next_proto_off_g (BNT_ERR_FRAGMENT on a non-first fragment). */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_next_proto_off(BNT_CTX_TYPE *ctx, __u32 off, __u8 *proto, __u32 *next)
{
    struct __bnt_ipv6_meta m;
    int ret;

    if (!proto || !next)
        return BNT_ERR_BAD_ARG;
    *proto = 0;
    *next = 0;
    ret = __bnt_api_ipv6_walk(ctx, off, &m);
    if (ret)
        return ret;
    if (!m.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    *proto = m.l4_proto;
    *next = m.next_off;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_next_proto_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *proto, __u32 *next);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_next_proto_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *proto, __u32 *next)
{
    return __bnt_ipv6_next_proto_off(ctx, off, proto, next);
}
#endif
#endif

/* ipv6__get_ext_depth */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_ext_depth(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    struct __bnt_ipv6_meta m;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_ipv6_walk(ctx, off, &m);
    if (ret)
        return ret;
    *out = m.ext_depth;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_ext_depth_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_ext_depth_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_ipv6_ext_depth(ctx, off, out);
}
#endif
#endif

/* ipv6__has_fragment_header */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_has_frag_hdr(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    struct __bnt_ipv6_meta m;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_ipv6_walk_to(ctx, off, &m, 1);
    if (ret)
        return ret;
    *out = m.has_fragment_hdr;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_has_frag_hdr_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_has_frag_hdr_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_ipv6_has_frag_hdr(ctx, off, out);
}
#endif
#endif

/* ipv6__is_fragment */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_is_frag(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    struct __bnt_ipv6_meta m;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_ipv6_walk_to(ctx, off, &m, 1);
    if (ret)
        return ret;
    *out = m.is_fragment;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_is_frag_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_is_frag_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_ipv6_is_frag(ctx, off, out);
}
#endif
#endif

/* ipv6__get_fragment_off_flags and is_more_fragments: BNT_ERR_BAD_PROTO without a fragment header */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_frag_off_flags(BNT_CTX_TYPE *ctx, __u32 off, __u16 *out)
{
    struct __bnt_ipv6_meta m;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_ipv6_walk_to(ctx, off, &m, 1);
    if (ret)
        return ret;
    if (!m.has_fragment_hdr)
        return BNT_ERR_BAD_PROTO;
    *out = m.frag_off_flags;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_frag_off_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_frag_off_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 *out)
{
    return __bnt_ipv6_frag_off_flags(ctx, off, out);
}
#endif
#endif

/* The ARP header with its variable part: a pointer to its fixed 8 bytes, and
 * its full length once that is known to be in the packet. */
static __always_inline int __bnt_api_arp_hdr(BNT_CTX_TYPE *ctx, __u32 off, const __u8 **h, __u32 *hlen)
{
    int ret;

    /* Bounded so that the address offsets added below keep the pointer's range. */
    if (off > __BNT_API_MAX_OFF)
        return BNT_ERR_TRUNC;
    BNT_PIN(off);
    ret = __bnt_data_ptr_in_range(ctx, off, sizeof(struct bnt_arp_hdr), (void **)h);
    if (ret)
        return ret;
    /* At most 8 + 4 * 255 bytes, tested on the same pointer. */
    *hlen = sizeof(struct bnt_arp_hdr) + 2 * (__u32)(*h)[4] + 2 * (__u32)(*h)[5];
    if ((void *)(*h + *hlen) > __bnt_xdp_data_end(ctx))
        return BNT_ERR_TRUNC;
    return BNT_OK;
}

/* arp__next_off: the header length. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_hlen(BNT_CTX_TYPE *ctx, __u32 off, __u32 *hlen)
{
    const __u8 *h;
    __u32 n;
    int ret;

    if (!hlen)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_arp_hdr(ctx, off, &h, &n);
    if (ret)
        return ret;
    *hlen = n;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_hlen_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *hlen);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_hlen_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 *hlen)
{
    return __bnt_arp_hlen(ctx, off, hlen);
}
#endif
#endif

/* arp__is_eth_ipv4: Ethernet hardware and IPv4 protocol addresses. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_is_eth_ipv4(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    const __u8 *h;
    __u32 n;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_arp_hdr(ctx, off, &h, &n);
    if (ret)
        return ret;
    *out = h[0] == 0 && h[1] == 1 && h[2] == 0x08 && h[3] == 0x00 && h[4] == 6 && h[5] == 4;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_is_eth_ipv4_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_is_eth_ipv4_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_arp_is_eth_ipv4(ctx, off, out);
}
#endif
#endif

/* ipv4__set_total_len: the field, the header checksum and the TCP/UDP
 * pseudo-header checksum (the L4 length is in it). */
static __always_inline int __bnt_ipv4_set_total_len(BNT_CTX_TYPE *ctx, __u32 off, __u16 total_len)
{
    struct iphdr *ip;
    __be16 *check = NULL;
    __be16 old, v = bpf_htons(total_len);
    __u32 hlen, coff;
    __u16 frag;
    __u8 vihl, proto;
    int ret;

    ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    vihl = *(__u8 *)ip;
    if ((vihl >> 4) != 4)
        return BNT_ERR_BAD_PROTO;
    hlen = (__u32)(vihl & 0x0f) * 4;
    if (hlen < sizeof(struct iphdr))
        return BNT_ERR_BAD_PROTO;
    if ((void *)((__u8 *)ip + hlen) > __bnt_xdp_data_end(ctx))    /* the options */
        return BNT_ERR_TRUNC;
    old = __BNT_PKT_LOAD(ip->tot_len);
    if (bpf_ntohs(old) < hlen)
        return BNT_ERR_BAD_PROTO;
    frag = bpf_ntohs(__BNT_PKT_LOAD(ip->frag_off));
    proto = ip->protocol;
    if ((frag & (IP_MF | IP_OFFSET)) && __bnt_ipv4_l4_has_pseudo_csum(proto))
        return BNT_ERR_FRAGMENT;
    if (total_len < hlen)
        return BNT_ERR_BAD_PROTO;
    coff = (frag & IP_OFFSET) ? 0 : __bnt_api_l4_check_off(proto);
    if (coff) {
        ret = __bnt_data_ptr(ctx, off + hlen + coff, sizeof(*check), (void **)&check);
        if (ret)
            return ret;
    }
    __BNT_PKT_STORE(ip->tot_len, v);
    __bnt_api_csum16(&ip->check, old, v, 0);
    if (check)
        __bnt_api_csum16(check, old, v, proto == IPPROTO_UDP);
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_total_len_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 total_len);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_total_len_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 total_len)
{
    return __bnt_ipv4_set_total_len(ctx, off, total_len);
}
#endif
#endif /* !BNT_INLINE_ALL */

/* A 16-bit IPv4 header field at the constant fo, and the header checksum. */
static __always_inline int __bnt_ipv4_set_word(BNT_CTX_TYPE *ctx, __u32 off, const __u32 fo, __u16 value)
{
    struct iphdr *ip;
    __be16 old, v = bpf_htons(value);
    int ret = __bnt_data_ptr(ctx, off, offsetof(struct iphdr, check) + 2, (void **)&ip);

    if (ret)
        return ret;
    old = __BNT_PKT_LOAD(*(__be16 *)((__u8 *)ip + fo));
    __BNT_PKT_STORE(*(__be16 *)((__u8 *)ip + fo), v);
    __bnt_api_csum16(&ip->check, old, v, 0);
    return BNT_OK;
}

/* ipv4__set_id */
static __always_inline int __bnt_ipv4_set_id(BNT_CTX_TYPE *ctx, __u32 off, __u16 id)
{
    return __bnt_ipv4_set_word(ctx, off, offsetof(struct iphdr, id), id);
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_id_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 id);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_id_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 id)
{
    return __bnt_ipv4_set_id(ctx, off, id);
}
#endif
#endif /* !BNT_INLINE_ALL */

/* ipv4__set_frag_off */
static __always_inline int __bnt_ipv4_set_frag_off(BNT_CTX_TYPE *ctx, __u32 off, __u16 frag_off)
{
    return __bnt_ipv4_set_word(ctx, off, offsetof(struct iphdr, frag_off), frag_off);
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_frag_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 frag_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_frag_off_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 frag_off)
{
    return __bnt_ipv4_set_frag_off(ctx, off, frag_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

/* ipv4__set_hlen with (csum) or without the header checksum update. */
static __always_inline int __bnt_ipv4_set_hlen_csum(BNT_CTX_TYPE *ctx, __u32 off, __u32 hlen, const int csum)
{
    struct iphdr *ip;
    __be16 old_w, new_w;
    __u8 first;
    int ret;

    if (hlen < sizeof(struct iphdr) || hlen > 60 || (hlen & 3) != 0)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    if ((void *)((__u8 *)ip + hlen) > __bnt_xdp_data_end(ctx))    /* the new header length */
        return BNT_ERR_TRUNC;
    old_w = __BNT_PKT_LOAD(*(__be16 *)ip);
    first = (*(__u8 *)ip & 0xf0) | (__u8)(hlen / 4);
    *(__u8 *)ip = first;
    if (!csum)
        return BNT_OK;
    new_w = bpf_htons(((__u16)first << 8) | (bpf_ntohs(old_w) & 0x00ff));
    __bnt_api_csum16(&ip->check, old_w, new_w, 0);
    return BNT_OK;
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_set_hlen(BNT_CTX_TYPE *ctx, __u32 off, __u32 hlen)
{
    return __bnt_ipv4_set_hlen_csum(ctx, off, hlen, 1);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_hlen_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 hlen);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_hlen_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 hlen)
{
    return __bnt_ipv4_set_hlen(ctx, off, hlen);
}
#endif
#endif

/* ipv4__set_hlen_no_csum */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_set_hlen_raw(BNT_CTX_TYPE *ctx, __u32 off, __u32 hlen)
{
    return __bnt_ipv4_set_hlen_csum(ctx, off, hlen, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_hlen_raw_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 hlen);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_hlen_raw_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 hlen)
{
    return __bnt_ipv4_set_hlen_raw(ctx, off, hlen);
}
#endif
#endif

/*
 * A 16-bit word of the TCP header at the constant fo: its masked bits take
 * value; with csum, the checksum follows. need: header length the packet must
 * hold first (doff * 4), or 0. One pointer up to the last byte touched.
 */
static __always_inline int __bnt_tcp_set_word(BNT_CTX_TYPE *ctx, __u32 off, const __u32 fo, const __u16 mask,
                                              __u16 value, const int csum, __u32 need)
{
    __be16 old, v, *w;
    __u8 *h;
    int ret;

    if (need) {
        ret = __bnt_bounds(ctx, off, need);
        if (ret)
            return ret;
    }
    if (!csum)
        ret = __bnt_data_ptr(ctx, off + fo, 2, (void **)&h);
    else if (fo + 2 > offsetof(struct tcphdr, check) + 2)
        ret = __bnt_data_ptr(ctx, off, fo + 2, (void **)&h);
    else
        ret = __bnt_data_ptr(ctx, off, offsetof(struct tcphdr, check) + 2, (void **)&h);
    if (ret)
        return ret;
    w = (__be16 *)(csum ? h + fo : h);
    old = __BNT_PKT_LOAD(*w);
    v = bpf_htons((bpf_ntohs(old) & (__u16)~mask) | (value & mask));
    __BNT_PKT_STORE(*w, v);
    if (csum)
        __bnt_api_csum16((__be16 *)(h + offsetof(struct tcphdr, check)), old, v, 0);
    return BNT_OK;
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_set_flags(BNT_CTX_TYPE *ctx, __u32 off, __u16 flags)
{
    return __bnt_tcp_set_word(ctx, off, 12, 0x01ff, flags, 1, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flags);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flags)
{
    return __bnt_tcp_set_flags(ctx, off, flags);
}
#endif
#endif

/* tcp__set_flags_no_csum */
#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_set_flags_raw(BNT_CTX_TYPE *ctx, __u32 off, __u16 flags)
{
    return __bnt_tcp_set_word(ctx, off, 12, 0x01ff, flags, 0, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_flags_raw_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flags);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_flags_raw_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flags)
{
    return __bnt_tcp_set_flags_raw(ctx, off, flags);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_set_window(BNT_CTX_TYPE *ctx, __u32 off, __u16 window)
{
    return __bnt_tcp_set_word(ctx, off, offsetof(struct tcphdr, window), 0xffff, window, 1, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_window_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 window);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_window_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 window)
{
    return __bnt_tcp_set_window(ctx, off, window);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_set_urg_ptr(BNT_CTX_TYPE *ctx, __u32 off, __u16 urg_ptr)
{
    return __bnt_tcp_set_word(ctx, off, offsetof(struct tcphdr, urg_ptr), 0xffff, urg_ptr, 1, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_urg_ptr_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 urg_ptr);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_urg_ptr_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 urg_ptr)
{
    return __bnt_tcp_set_urg_ptr(ctx, off, urg_ptr);
}
#endif
#endif

/* tcp__set_doff (doff checked by the wrapper) */
#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_set_doff(BNT_CTX_TYPE *ctx, __u32 off, __u32 doff)
{
    return __bnt_tcp_set_word(ctx, off, 12, 0xf000, (__u16)(doff << 12), 1, doff * 4);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_doff_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 doff);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_doff_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 doff)
{
    return __bnt_tcp_set_doff(ctx, off, doff);
}
#endif
#endif

/* tcp__set_doff_no_csum (doff checked by the wrapper) */
#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_set_doff_raw(BNT_CTX_TYPE *ctx, __u32 off, __u32 doff)
{
    return __bnt_tcp_set_word(ctx, off, 12, 0xf000, (__u16)(doff << 12), 0, doff * 4);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_doff_raw_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 doff);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_doff_raw_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 doff)
{
    return __bnt_tcp_set_doff_raw(ctx, off, doff);
}
#endif
#endif

/* udp__set_len: the field and the checksum (the UDP length is in it). */
#ifdef BNT_XDP_H
static __always_inline int __bnt_udp_set_len(BNT_CTX_TYPE *ctx, __u32 off, __u16 len)
{
    struct udphdr *udp;
    __be16 old, v = bpf_htons(len);
    int ret = __bnt_data_ptr(ctx, off, sizeof(*udp), (void **)&udp);

    if (ret)
        return ret;
    old = __BNT_PKT_LOAD(udp->len);
    __BNT_PKT_STORE(udp->len, v);
    __bnt_api_csum16(&udp->check, old, v, 1);
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_udp_set_len_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 len);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_udp_set_len_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 len)
{
    return __bnt_udp_set_len(ctx, off, len);
}
#endif
#endif

/* ipv6__set_payload_len: the field and the pseudo-header checksum of the
 * transport (TCP, UDP or ICMPv6) it covers. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_set_payload_len(BNT_CTX_TYPE *ctx, __u32 off, __u16 payload_len)
{
    struct __bnt_ipv6_meta meta = {};
    struct ipv6hdr *ip6;
    __be16 *check = NULL;
    __be16 old, v = bpf_htons(payload_len);
    __u32 coff = 0;
    int ret;

    if (off > __BNT_API_MAX_OFF)
        return BNT_ERR_TRUNC;
    BNT_PIN(off);
    ret = __bnt_data_ptr_in_range(ctx, off, 8, (void **)&ip6);
    if (ret)
        return ret;
    if (ip6->version != 6)
        return BNT_ERR_BAD_PROTO;
    if (__bnt_is_ipv6_ext(ip6->nexthdr)) {
        /* The walk stays in its own global: inlined, the verifier would take
         * every exit state of its loop through the code below. */
        ret = __BNT_OP(__bnt_ipv6_l4_meta)(ctx, off, &meta);
        if (ret)
            return ret;
    } else {                                            /* common case: no walk */
        meta.l4_proto = ip6->nexthdr;
        meta.next_off = off + (__u32)sizeof(struct ipv6hdr);
        meta.l4_off_valid = 1;
    }
    if (meta.is_fragment && __bnt_ipv6_l4_maybe_has_pseudo_csum(&meta))
        return BNT_ERR_FRAGMENT;
    if (meta.l4_off_valid) {
        if (meta.l4_proto == IPPROTO_ICMPV6)
            coff = offsetof(struct icmp6hdr, icmp6_cksum);
        else
            coff = __bnt_api_l4_check_off(meta.l4_proto);
    }
    if (coff) {
        coff += meta.next_off;
        BNT_PIN(coff);
        ret = __bnt_data_ptr(ctx, coff, sizeof(*check), (void **)&check);
        if (ret)
            return ret;
    }
    old = __BNT_PKT_LOAD(ip6->payload_len);
    if (check)
        __bnt_api_csum16(check, old, v, meta.l4_proto == IPPROTO_UDP);
    /* Written last, so that every path ends in the same block: the frozen
     * asm has to end with the exit. */
    __BNT_PKT_STORE(ip6->payload_len, v);
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_payload_len_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 payload_len);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_payload_len_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 payload_len)
{
    return __bnt_ipv6_set_payload_len(ctx, off, payload_len);
}
#endif
#endif

/* ipv6__set_traffic_class / set_flow_label: the masked bits of the first word. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_set_vtcflow(BNT_CTX_TYPE *ctx, __u32 off, __u32 mask, __u32 value)
{
    __be32 *w;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*w), (void **)&w);

    if (ret)
        return ret;
    __BNT_PKT_STORE(*w, bpf_htonl((bpf_ntohl(__BNT_PKT_LOAD(*w)) & ~mask) | (value & mask)));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_vtcflow_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 mask, __u32 value);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_vtcflow_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 mask, __u32 value)
{
    return __bnt_ipv6_set_vtcflow(ctx, off, mask, value);
}
#endif
#endif

/* The flags byte of an ICMPv6 router (kind 134, byte 5) or neighbor (136,
 * byte 4) advertisement; kind is a constant. */
static __always_inline int __bnt_icmp6_advert_flags(BNT_CTX_TYPE *ctx, __u32 off, const __u8 kind, __u8 *out)
{
    const __u8 *h;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_data_ptr(ctx, off, 1, (void **)&h);
    if (ret)
        return ret;
    if (h[0] != kind)
        return BNT_ERR_BAD_PROTO;
    off += kind == BNT_ICMP6_ND_ROUTER_ADVERT ? 5 : 4;
    BNT_PIN(off);
    ret = __bnt_data_ptr(ctx, off, 1, (void **)&h);
    if (ret)
        return ret;
    *out = h[0];
    return BNT_OK;
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_icmp6_ra_flags(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_icmp6_advert_flags(ctx, off, BNT_ICMP6_ND_ROUTER_ADVERT, out);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_ra_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_ra_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_icmp6_ra_flags(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_icmp6_na_flags(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_icmp6_advert_flags(ctx, off, BNT_ICMP6_ND_NEIGHBOR_ADVERT, out);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_na_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_na_flags_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    return __bnt_icmp6_na_flags(ctx, off, out);
}
#endif
#endif

/* icmp6__set_router_advert_preference (the preference is checked by the
 * wrapper): the preference bits of the flags and the checksum. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_icmp6_set_ra_pref(BNT_CTX_TYPE *ctx, __u32 off, __u8 preference)
{
    __u8 *h;
    __be16 old, v;
    int ret;

    ret = __bnt_data_ptr(ctx, off, 1, (void **)&h);
    if (ret)
        return ret;
    if (h[0] != BNT_ICMP6_ND_ROUTER_ADVERT)
        return BNT_ERR_BAD_PROTO;
    BNT_PIN(off);
    ret = __bnt_data_ptr(ctx, off, 6, (void **)&h);
    if (ret)
        return ret;
    old = __BNT_PKT_LOAD(*(__be16 *)(h + 4));
    v = bpf_htons((bpf_ntohs(old) & ~(__u16)BNT_ICMP6_RA_PREFERENCE_MASK) |
                  (((__u16)preference << BNT_ICMP6_RA_PREFERENCE_SHIFT) & BNT_ICMP6_RA_PREFERENCE_MASK));
    __BNT_PKT_STORE(*(__be16 *)(h + 4), v);
    __bnt_api_csum16((__be16 *)(h + offsetof(struct icmp6hdr, icmp6_cksum)), old, v, 0);
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_set_ra_pref_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 preference);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_set_ra_pref_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 preference)
{
    return __bnt_icmp6_set_ra_pref(ctx, off, preference);
}
#endif
#endif

/* An address of an Ethernet/IPv4 ARP header, at the constant at (sha 8,
 * spa 14, tha 18, tpa 24) and len (6 or 4): read into buf, or with write, from
 * buf into the packet. */
static __always_inline int __bnt_arp_addr(BNT_CTX_TYPE *ctx, __u32 off, const __u32 at, const __u32 len,
                                          void *buf, const int write)
{
    const __u8 *h;
    __u8 *a;
    __u32 hlen;
    int ret;

    if (!buf)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_arp_hdr(ctx, off, &h, &hlen);
    if (ret)
        return ret;
    /* Ethernet/IPv4: htype 1, ptype 0x0800, hln 6, pln 4 */
    if (h[0] != 0 || h[1] != 1 || h[2] != 0x08 || h[3] != 0x00 || h[4] != 6 || h[5] != 4)
        return BNT_ERR_UNSUPPORTED;
    /* hlen is 28 and already in the packet. Testing it again as a constant
     * gives the pointer its range; the pin keeps clang from dropping the test. */
    BNT_PIN(h);
    if ((void *)(h + 28) > __bnt_xdp_data_end(ctx))
        return BNT_ERR_TRUNC;
    a = (__u8 *)h + at;
    if (write)
        __builtin_memcpy(a, buf, len);
    else
        __builtin_memcpy(buf, a, len);
    return BNT_OK;
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_get_sha(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out)
{
    return __bnt_arp_addr(ctx, off, 8, BNT_MAC_LEN, out ? out->addr : NULL, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_sha_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_sha_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out)
{
    return __bnt_arp_get_sha(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_set_sha(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *mac)
{
    return __bnt_arp_addr(ctx, off, 8, BNT_MAC_LEN, mac ? (void *)mac->addr : NULL, 1);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_sha_g(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *mac);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_sha_g(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *mac)
{
    return __bnt_arp_set_sha(ctx, off, mac);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_get_spa(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out)
{
    return __bnt_arp_addr(ctx, off, 14, sizeof(*out), out, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_spa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_spa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out)
{
    return __bnt_arp_get_spa(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_set_spa(BNT_CTX_TYPE *ctx, __u32 off, __be32 spa)
{
    return __bnt_arp_addr(ctx, off, 14, sizeof(spa), &spa, 1);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_spa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 spa);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_spa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 spa)
{
    return __bnt_arp_set_spa(ctx, off, spa);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_get_tha(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out)
{
    return __bnt_arp_addr(ctx, off, 18, BNT_MAC_LEN, out ? out->addr : NULL, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_tha_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_tha_g(BNT_CTX_TYPE *ctx, __u32 off, struct __bnt_mac *out)
{
    return __bnt_arp_get_tha(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_set_tha(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *mac)
{
    return __bnt_arp_addr(ctx, off, 18, BNT_MAC_LEN, mac ? (void *)mac->addr : NULL, 1);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_tha_g(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *mac);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_tha_g(BNT_CTX_TYPE *ctx, __u32 off, const struct __bnt_mac *mac)
{
    return __bnt_arp_set_tha(ctx, off, mac);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_get_tpa(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out)
{
    return __bnt_arp_addr(ctx, off, 24, sizeof(*out), out, 0);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_tpa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_get_tpa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out)
{
    return __bnt_arp_get_tpa(ctx, off, out);
}
#endif
#endif

#ifdef BNT_XDP_H
static __always_inline int __bnt_arp_set_tpa(BNT_CTX_TYPE *ctx, __u32 off, __be32 tpa)
{
    return __bnt_arp_addr(ctx, off, 24, sizeof(tpa), &tpa, 1);
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_tpa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 tpa);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_arp_set_tpa_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 tpa)
{
    return __bnt_arp_set_tpa(ctx, off, tpa);
}
#endif
#endif

/* MPLS label stack entry: the masked bits take value. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_mpls_set_lse(BNT_CTX_TYPE *ctx, __u32 off, __u32 mask, __u32 value)
{
    __be32 *lse;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*lse), (void **)&lse);

    if (ret)
        return ret;
    __BNT_PKT_STORE(*lse, bpf_htonl((bpf_ntohl(__BNT_PKT_LOAD(*lse)) & ~mask) | (value & mask)));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_mpls_set_lse_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 mask, __u32 value);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_mpls_set_lse_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 mask, __u32 value)
{
    return __bnt_mpls_set_lse(ctx, off, mask, value);
}
#endif
#endif

/* mpls__next_ipv4 / next_ipv6: the label is the bottom of the stack and an IP
 * header of that version follows. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_mpls_next_ip(BNT_CTX_TYPE *ctx, __u32 off, __u8 version)
{
    const __u8 *h;
    int ret = __bnt_data_ptr(ctx, off, 4, (void **)&h);

    if (ret)
        return ret;
    if (!(h[2] & 1))                    /* BOS: bit 8 of the label stack entry */
        return BNT_ERR_BAD_PROTO;
    off += 4;
    BNT_PIN(off);
    ret = __bnt_data_ptr(ctx, off, 1, (void **)&h);
    if (ret)
        return ret;
    if ((h[0] >> 4) != version)
        return BNT_ERR_BAD_PROTO;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_mpls_next_ip_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 version);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_mpls_next_ip_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 version)
{
    return __bnt_mpls_next_ip(ctx, off, version);
}
#endif
#endif

/* eth__set_ethertype: the EtherType after the VLAN stack. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_eth_set_ethertype(BNT_CTX_TYPE *ctx, __u32 off, __u16 ethertype)
{
    struct __bnt_eth_meta meta;
    __be16 *p;
    __u32 at;
    int ret;

    ret = __bnt_api_eth_walk(ctx, off, &meta);
    if (ret)
        return ret;
    at = off + meta.hlen - 2;
    BNT_PIN(at);
    ret = __bnt_data_ptr(ctx, at, sizeof(*p), (void **)&p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*p, bpf_htons(ethertype));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_set_ethertype_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 ethertype);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_set_ethertype_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 ethertype)
{
    return __bnt_eth_set_ethertype(ctx, off, ethertype);
}
#endif
#endif

/* The TCI of the VLAN tag at depth idx: read into *old and then, when the
 * mask (maskval high half) is not zero, the masked bits take the value (low
 * half). The TCI is read from the packet, so idx never indexes the stack. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_eth_vlan_tci(BNT_CTX_TYPE *ctx, __u32 off, __u32 idx, __u32 maskval, __u16 *old)
{
    struct __bnt_eth_meta meta;
    __u16 mask = maskval >> 16, tci;
    __be16 *p;
    __u32 at;
    int ret;

    if (!old)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_eth_walk(ctx, off, &meta);
    if (ret)
        return ret;
    if (idx >= meta.vlan_depth)
        return BNT_ERR_BAD_ARG;
    at = off + sizeof(struct ethhdr) + idx * sizeof(struct bnt_vlan_hdr) +
         offsetof(struct bnt_vlan_hdr, h_vlan_TCI);
    BNT_PIN(at);
    ret = __bnt_data_ptr(ctx, at, sizeof(*p), (void **)&p);
    if (ret)
        return ret;
    tci = bpf_ntohs(__BNT_PKT_LOAD(*p));
    *old = tci;
    if (mask)
        __BNT_PKT_STORE(*p, bpf_htons((tci & (__u16)~mask) | ((__u16)maskval & mask)));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_vlan_tci_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 idx, __u32 maskval, __u16 *old);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_vlan_tci_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 idx, __u32 maskval, __u16 *old)
{
    return __bnt_eth_vlan_tci(ctx, off, idx, maskval, old);
}
#endif
#endif

/* ctx__find_arp: the offset of a whole ARP header after Ethernet and VLANs. */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ctx_find_arp(BNT_CTX_TYPE *ctx, __u32 *arp_off)
{
    struct __bnt_eth_meta meta;
    const __u8 *h;
    __u32 hlen;
    int ret;

    if (!arp_off)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_api_eth_walk(ctx, 0, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_ARP) {
        if (meta.proto == ETH_P_IP || meta.proto == ETH_P_IPV6 ||
            meta.proto == ETH_P_MPLS_UC || meta.proto == ETH_P_MPLS_MC)
            return BNT_ERR_BAD_PROTO;
        return BNT_ERR_UNSUPPORTED;
    }
    ret = __bnt_api_arp_hdr(ctx, meta.hlen, &h, &hlen);
    if (ret)
        return ret;
    if (meta.hlen + hlen > BNT_OFF_BOUND_L3)
        return BNT_ERR_TRUNC;
    *arp_off = meta.hlen;
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ctx_find_arp_g(BNT_CTX_TYPE *ctx, __u32 *arp_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ctx_find_arp_g(BNT_CTX_TYPE *ctx, __u32 *arp_off)
{
    return __bnt_ctx_find_arp(ctx, arp_off);
}
#endif
#endif
#endif /* !BNT_INLINE_ALL */

/*
 * Primitive redirect macros: in global mode, shadow the inline read/write
 * primitives with their global BPF equivalents. The globals are defined
 * above (before this #define) so their own bodies still call the real
 * inlines; all callers from this point forward call the globals.
 */
#if !BNT_INLINE_ALL
#define __bnt_read_u8    __bnt_read_u8_g
#define __bnt_read_be16  __bnt_read_be16_g
#define __bnt_read_be32  __bnt_read_be32_g
#define __bnt_write_u8   __bnt_write_u8_g
#define __bnt_write_be16 __bnt_write_be16_g
#define __bnt_write_be32 __bnt_write_be32_g
#endif /* !BNT_INLINE_ALL */

/* The meta dispatchers, for the inline paths. The Ethernet one calls
 * __bnt_eth_meta_g in global mode, which bnt_debug.h uses. */
static __always_inline int __bnt_eth_meta_dispatch(const bnt_eth *eth, struct __bnt_eth_meta *m)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!eth || !m)
        return BNT_ERR_BAD_ARG;
    /* The global clears *m itself, but verifiers before 6.3 reject stack
     * memory passed to a global unless it is already initialized. */
    __builtin_memset(m, 0, sizeof(*m));
    return __BNT_OP(__bnt_eth_meta)(eth->__ctx, eth->__off, m);
#else
    return __bnt_eth_meta_view(eth, m);
#endif
}

static __always_inline int __bnt_ipv4_meta_dispatch(const bnt_ipv4 *ip, struct __bnt_ipv4_meta *m)
{
    return __bnt_ipv4_meta(ip, m);
}

static __always_inline int __bnt_ipv6_meta_dispatch(const bnt_ipv6 *ip6, struct __bnt_ipv6_meta *m)
{
    return __bnt_ipv6_meta(ip6, m);
}

static __always_inline int __bnt_arp_meta_dispatch(const bnt_arp *arp, struct __bnt_arp_meta *m)
{
    return __bnt_arp_meta(arp, m);
}

/**
 * @ingroup bnt_eth
 * @brief Initializes an Ethernet header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param off Byte offset of the Ethernet header.
 * @param eth View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_eth__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_eth *eth)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    eth->__ctx = ctx;
    eth->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_eth
 * @brief Returns the offset of the payload following the Ethernet header and VLAN stack.
 *
 * @param eth Parsed Ethernet view.
 * @param out Byte offset of the payload on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p out is NULL.
 * @retval BNT_ERR_TRUNC   a header on the VLAN stack is truncated.
 * @retval BNT_ERR_TOO_DEEP the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) is
 *                          exhausted (see @ref limits).
 */
static __always_inline int bnt_eth__next_off(const bnt_eth *eth, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!eth)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_eth_next_off)(eth->__ctx, eth->__off, &off);
        if (ret)
            return ret;
        return __bnt_off_ret(off, BNT_OFF_BOUND_L2, out);
    }
#else
    {
        struct __bnt_eth_meta meta;
        int ret = __bnt_eth_meta_view(eth, &meta);
        if (ret)
            return ret;
        return __bnt_off_ret(eth->__off + meta.hlen, BNT_OFF_BOUND_L2, out);
    }
#endif
}

/** @ingroup bnt_eth
 *  Reads the Ethernet source MAC address.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_eth__get_smac(const bnt_eth *eth, unsigned char out[BNT_MAC_LEN])
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, BNT_MAC_LEN);
    if (!eth)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        int ret = __BNT_OP(__bnt_read_mac)(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_source), &tmp);
        if (ret) return ret;
        __builtin_memcpy(out, tmp.addr, BNT_MAC_LEN);
        return BNT_OK;
    }
#else
    return __bnt_read(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_source), out, ETH_ALEN);
#endif
}

/** @ingroup bnt_eth
 *  Reads the Ethernet destination MAC address.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_eth__get_dmac(const bnt_eth *eth, unsigned char out[BNT_MAC_LEN])
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, BNT_MAC_LEN);
    if (!eth)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        int ret = __BNT_OP(__bnt_read_mac)(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_dest), &tmp);
        if (ret) return ret;
        __builtin_memcpy(out, tmp.addr, BNT_MAC_LEN);
        return BNT_OK;
    }
#else
    return __bnt_read(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_dest), out, ETH_ALEN);
#endif
}

/** @ingroup bnt_eth
 *  Reads the final inner EtherType, past any VLAN tags.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth or @p out is NULL.
 * @retval BNT_ERR_TRUNC    the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__get_ethertype(const bnt_eth *eth, __u16 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(eth->__ctx, eth->__off, &info);
    if (ret)
        return ret;
    *out = info & 0xffff;
    return BNT_OK;
#else
    struct __bnt_eth_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    *out = meta.proto;
    return BNT_OK;
#endif
}

/** @ingroup bnt_eth
 *  Reads the EtherType field immediately after the destination and source MAC addresses.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_eth__get_outer_ethertype(const bnt_eth *eth, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!eth)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_proto), &v);
    if (ret)
        return ret;

    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_eth
 *  Reads the number of VLAN headers present after the Ethernet header.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth or @p out is NULL.
 * @retval BNT_ERR_TRUNC    the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__get_vlan_depth(const bnt_eth *eth, __u8 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(eth->__ctx, eth->__off, &info);
    if (ret)
        return ret;
    *out = info >> 24;
    return BNT_OK;
#else
    struct __bnt_eth_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    *out = meta.vlan_depth;
    return BNT_OK;
#endif
}

/** @ingroup bnt_eth
 *  Reads the VLAN TCI for the VLAN header at depth @p idx.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth or @p out is NULL, or @p idx is not below the
 *                          VLAN depth.
 * @retval BNT_ERR_TRUNC    the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__get_vlan_tci(const bnt_eth *eth, __u32 idx, __u16 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_vlan_tci)(eth->__ctx, eth->__off, idx, 0, out);
#else
    struct __bnt_eth_meta meta;
    __u32 i;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    if (idx >= meta.vlan_depth)
        return BNT_ERR_BAD_ARG;

    /* The pin keeps each load at a constant stack offset: otherwise clang turns
     * the loop into vlan_tci[idx], which the verifier rejects for a runtime idx
     * (bounded only by vlan_depth, a __u8). */
#pragma unroll
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        __u16 tci = meta.vlan_tci[i];

        BNT_PIN(tci);
        if (idx == i) {
            *out = tci;
            return BNT_OK;
        }
    }

    return BNT_ERR_BAD_ARG;
#endif
}

/** @ingroup bnt_eth
 *  Reads the Drop Eligible Indicator (DEI) bit of the VLAN tag at depth @p idx into @p out.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth or @p out is NULL, or @p idx is not below the
 *                          VLAN depth.
 * @retval BNT_ERR_TRUNC    the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__is_vlan_drop_eligible(const bnt_eth *eth, __u32 idx, bool *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u16 tci = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_vlan_tci)(eth->__ctx, eth->__off, idx, 0, &tci);
    if (ret)
        return ret;
    *out = (tci & BNT_VLAN_DEI) != 0;
    return BNT_OK;
#else
    __u16 tci;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = bnt_eth__get_vlan_tci(eth, idx, &tci);
    if (ret)
        return ret;

    *out = (tci & BNT_VLAN_DEI) != 0;
    return BNT_OK;
#endif
}

/** @ingroup bnt_eth
 *  Writes the Ethernet source MAC address.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p mac is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_eth__set_smac(bnt_eth *eth, const unsigned char mac[BNT_MAC_LEN])
{
    if (!eth || !mac)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        __builtin_memcpy(tmp.addr, mac, BNT_MAC_LEN);
        return __BNT_OP(__bnt_write_mac)(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_source), &tmp);
    }
#else
    return __bnt_write(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_source), mac, ETH_ALEN);
#endif
}

/** @ingroup bnt_eth
 *  Writes the Ethernet destination MAC address.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth or @p mac is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_eth__set_dmac(bnt_eth *eth, const unsigned char mac[BNT_MAC_LEN])
{
    if (!eth || !mac)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        __builtin_memcpy(tmp.addr, mac, BNT_MAC_LEN);
        return __BNT_OP(__bnt_write_mac)(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_dest), &tmp);
    }
#else
    return __bnt_write(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_dest), mac, ETH_ALEN);
#endif
}

/** @ingroup bnt_eth
 *  Writes the final EtherType field: the encapsulated-protocol field of the
 *  last VLAN tag when VLANs are present, otherwise the base EtherType.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth is NULL.
 * @retval BNT_ERR_TRUNC    the write falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__set_ethertype(bnt_eth *eth, __u16 ethertype)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_set_ethertype)(eth->__ctx, eth->__off, ethertype);
#else
    struct __bnt_eth_meta meta;
    __u32 off;
    int ret;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;

    off = eth->__off + offsetof(struct ethhdr, h_proto);
    if (meta.vlan_depth > 0)
        off = eth->__off + sizeof(struct ethhdr) +
              (meta.vlan_depth - 1) * sizeof(struct bnt_vlan_hdr) +
              offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto);

    return __bnt_write_be16(eth->__ctx, off, bpf_htons(ethertype));
#endif
}

/** @ingroup bnt_eth
 *  Writes the VLAN TCI for the VLAN header at depth @p idx.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth is NULL, or @p idx is not below the VLAN
 *                          depth.
 * @retval BNT_ERR_TRUNC    the write falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__set_vlan_tci(bnt_eth *eth, __u32 idx, __u16 tci)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u16 old = 0;

    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_vlan_tci)(eth->__ctx, eth->__off, idx, 0xffffu << 16 | tci, &old);
#else
    struct __bnt_eth_meta meta;
    __u32 off;
    int ret;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    if (idx >= meta.vlan_depth)
        return BNT_ERR_BAD_ARG;

    off = eth->__off + sizeof(struct ethhdr) + idx * sizeof(struct bnt_vlan_hdr) +
          offsetof(struct bnt_vlan_hdr, h_vlan_TCI);
    return __bnt_write_be16(eth->__ctx, off, bpf_htons(tci));
#endif
}

static __always_inline int __bnt_eth__set_vlan_flag(bnt_eth *eth,
                                                     __u32 idx,
                                                     __u16 flag,
                                                     bool enabled)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u16 old = 0;

    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_vlan_tci)(eth->__ctx, eth->__off, idx, (__u32)flag << 16 | (enabled ? flag : 0), &old);
#else
    __u16 tci;
    int ret;

    ret = bnt_eth__get_vlan_tci(eth, idx, &tci);
    if (ret)
        return ret;

    if (enabled)
        tci |= flag;
    else
        tci &= ~flag;

    return bnt_eth__set_vlan_tci(eth, idx, tci);
#endif
}

/** @ingroup bnt_eth
 *  Sets the Drop Eligible Indicator (DEI) bit of the VLAN tag at depth @p idx.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth is NULL, or @p idx is not below the VLAN
 *                          depth.
 * @retval BNT_ERR_TRUNC    the write falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__set_vlan_drop_eligible(bnt_eth *eth, __u32 idx)
{
    return __bnt_eth__set_vlan_flag(eth, idx, BNT_VLAN_DEI, true);
}

/** @ingroup bnt_eth
 *  Clears the Drop Eligible Indicator (DEI) bit of the VLAN tag at depth @p idx.
 *
 * @retval BNT_OK           on success.
 * @retval BNT_ERR_BAD_ARG  @p eth is NULL, or @p idx is not below the VLAN
 *                          depth.
 * @retval BNT_ERR_TRUNC    the write falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP the VLAN stack exceeds @c BNT_MAX_VLAN_DEPTH.
 */
static __always_inline int bnt_eth__clear_vlan_drop_eligible(bnt_eth *eth, __u32 idx)
{
    return __bnt_eth__set_vlan_flag(eth, idx, BNT_VLAN_DEI, false);
}

/** @ingroup bnt_eth
 *  Writes the EtherType field immediately after the destination and source MAC addresses.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_eth__set_outer_ethertype(bnt_eth *eth, __u16 ethertype)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(eth->__ctx, eth->__off + offsetof(struct ethhdr, h_proto), bpf_htons(ethertype));
}

/**
 * @ingroup bnt_ipv4
 * @brief Initializes an IPv4 header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param off Byte offset of the IPv4 header.
 * @param ip  View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_ipv4__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_ipv4 *ip)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    ip->__ctx = ctx;
    ip->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_ipv4
 * @brief Returns the offset of the header following IPv4.
 *
 * @param ip  Parsed IPv4 view.
 * @param out Byte offset of the next header on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC     the IPv4 header is truncated.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv4 header.
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv4__next_off(const bnt_ipv4 *ip, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ipv4_next_off)(ip->__ctx, ip->__off, &off);
        if (ret)
            return ret;
        return __bnt_off_ret(off, BNT_OFF_BOUND_L3, out);
    }
#else
    {
        struct __bnt_ipv4_meta meta;
        int ret = __bnt_ipv4_meta_dispatch(ip, &meta);
        if (ret)
            return ret;
        if (!meta.l4_off_valid)
            return BNT_ERR_FRAGMENT;
        return __bnt_off_ret(meta.next_off, BNT_OFF_BOUND_L3, out);
    }
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Returns the upper-layer protocol and the offset of the header following IPv4.
 *
 * @param ip       Parsed IPv4 view.
 * @param protocol Upper-layer protocol number on success.
 * @param off      Byte offset of the next header on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip, @p protocol, or @p off is NULL.
 * @retval BNT_ERR_TRUNC     the IPv4 header is truncated.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv4 header.
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv4__next_proto_off(const bnt_ipv4 *ip,
                                                     __u8 *protocol,
                                                     __u32 *off)
{
    if (protocol)
        *protocol = 0;
    if (off)
        *off = 0;
    if (!protocol || !off)
        return BNT_ERR_BAD_ARG;
    if (!ip)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 o = 0;
        int ret = __BNT_OP(__bnt_ipv4_next_proto_off)(ip->__ctx, ip->__off, protocol, &o);
        if (ret)
            return ret;
        return __bnt_off_ret(o, BNT_OFF_BOUND_L3, off);
    }
#else
    {
        struct __bnt_ipv4_meta meta;
        int ret = __bnt_ipv4_meta_dispatch(ip, &meta);
        if (ret)
            return ret;
        if (!meta.l4_off_valid)
            return BNT_ERR_FRAGMENT;
        *protocol = meta.protocol;
        return __bnt_off_ret(meta.next_off, BNT_OFF_BOUND_L3, off);
    }
#endif
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 TOS/DSCP+ECN byte.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_tos(const bnt_ipv4 *ip, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, tos), out);
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 total length field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_total_len(const bnt_ipv4 *ip, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, tot_len), &v);
    if (ret)
        return ret;

    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 identification field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_id(const bnt_ipv4 *ip, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, id), &v);
    if (ret)
        return ret;

    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 fragment offset and flags field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_frag_off(const bnt_ipv4 *ip, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, frag_off), &v);
    if (ret)
        return ret;

    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 TTL field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_ttl(const bnt_ipv4 *ip, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, ttl), out);
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 protocol field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_protocol(const bnt_ipv4 *ip, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, protocol), out);
}

/** @ingroup bnt_ipv4
 *  Returns the IPv4 header length in bytes.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv4 header.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_hlen(const bnt_ipv4 *ip, __u32 *out)
{
    __u8 vihl = 0;
    __u32 hlen;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_u8(ip->__ctx, ip->__off, &vihl);
    if (ret)
        return ret;

    if ((vihl >> 4) != 4)
        return BNT_ERR_BAD_PROTO;

    hlen = (__u32)(vihl & 0x0f) * 4;
    if (hlen < sizeof(struct iphdr))
        return BNT_ERR_BAD_PROTO;

    *out = hlen;
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 version field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_version(const bnt_ipv4 *ip, __u8 *out)
{
    __u8 vihl = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_u8(ip->__ctx, ip->__off, &vihl);
    if (ret)
        return ret;
    *out = vihl >> 4;
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reads the raw IPv4 IHL field, in 32-bit words.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_ihl(const bnt_ipv4 *ip, __u8 *out)
{
    __u8 vihl = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_u8(ip->__ctx, ip->__off, &vihl);
    if (ret)
        return ret;
    *out = vihl & 0x0f;
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reports through @p out whether the IPv4 packet is a fragment (non-zero offset or MF set).
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__is_fragment(const bnt_ipv4 *ip, bool *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, frag_off), &v);
    if (ret)
        return ret;

    *out = ((bpf_ntohs(v) & (IP_MF | IP_OFFSET)) != 0);
    return BNT_OK;
}

static __always_inline int __bnt_ipv4__is_frag_flag_set(const bnt_ipv4 *ip,
                                                         __u16 flag,
                                                         bool *out)
{
    __u16 frag_off;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = bnt_ipv4__get_frag_off(ip, &frag_off);
    if (ret)
        return ret;

    *out = (frag_off & flag) != 0;
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reads the reserved (evil) bit of the IPv4 fragment flags into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__is_reserved_fragment_flag(const bnt_ipv4 *ip, bool *out)
{
    return __bnt_ipv4__is_frag_flag_set(ip, IP_RF, out);
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 Don't Fragment (DF) flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__is_dont_fragment(const bnt_ipv4 *ip, bool *out)
{
    return __bnt_ipv4__is_frag_flag_set(ip, IP_DF, out);
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 More Fragments (MF) flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__is_more_fragments(const bnt_ipv4 *ip, bool *out)
{
    return __bnt_ipv4__is_frag_flag_set(ip, IP_MF, out);
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 header checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_check(const bnt_ipv4 *ip, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), &v);
    if (ret)
        return ret;

    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 source address, in network byte order.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_saddr(const bnt_ipv4 *ip, __be32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, saddr), out);
}

/** @ingroup bnt_ipv4
 *  Reads the IPv4 destination address, in network byte order.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv4__get_daddr(const bnt_ipv4 *ip, __be32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, daddr), out);
}

/** @ingroup bnt_ipv4
 *  Writes the IPv4 header checksum directly, without incremental update.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_check(bnt_ipv4 *ip, __u16 check)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), bpf_htons(check));
}

/** Writes the IPv4 TOS byte without updating the checksum. */
static __always_inline int __bnt_ipv4__set_tos_raw(bnt_ipv4 *ip, __u8 tos)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, tos), tos);
}

/** Writes the IPv4 TTL byte without updating the checksum. */
static __always_inline int __bnt_ipv4__set_ttl_raw(bnt_ipv4 *ip, __u8 ttl)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, ttl), ttl);
}

/** Writes the IPv4 source address without updating any checksum. */
static __always_inline int __bnt_ipv4__set_saddr_raw(bnt_ipv4 *ip, __be32 saddr)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, saddr), saddr);
}

/** Writes the IPv4 destination address without updating any checksum. */
static __always_inline int __bnt_ipv4__set_daddr_raw(bnt_ipv4 *ip, __be32 daddr)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, daddr), daddr);
}

/** Writes the IPv4 identification field without updating the checksum. */
static __always_inline int __bnt_ipv4__set_id_raw(bnt_ipv4 *ip, __u16 id)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, id), bpf_htons(id));
}

/** Writes the IPv4 total length field without updating the checksum. */
static __always_inline int __bnt_ipv4__set_total_len_raw(bnt_ipv4 *ip, __u16 total_len)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, tot_len), bpf_htons(total_len));
}

/** Writes the IPv4 protocol field without updating the checksum. */
static __always_inline int __bnt_ipv4__set_protocol_raw(bnt_ipv4 *ip, __u8 protocol)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, protocol), protocol);
}

/** Writes the IPv4 fragment offset and flags field without updating the checksum. */
static __always_inline int __bnt_ipv4__set_frag_off_raw(bnt_ipv4 *ip, __u16 frag_off)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, frag_off), bpf_htons(frag_off));
}

/** Writes the IPv4 IHL field without updating the checksum. */
static __always_inline int __bnt_ipv4__set_hlen_raw(bnt_ipv4 *ip, __u32 hlen)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv4_set_hlen_raw)(ip->__ctx, ip->__off, hlen);
#else
    __u8 old_first = 0;
    __u8 new_first;
    int ret;

    if (!ip)
        return BNT_ERR_BAD_ARG;
    if (hlen < sizeof(struct iphdr) || hlen > 60 || (hlen & 3) != 0)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_bounds(ip->__ctx, ip->__off, hlen);
    if (ret)
        return ret;
    ret = __bnt_read_u8(ip->__ctx, ip->__off, &old_first);
    if (ret)
        return ret;
    new_first = (old_first & 0xf0) | (__u8)(hlen / 4);
    return __bnt_write_u8(ip->__ctx, ip->__off, new_first);
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Initializes an IPv6 header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param off Byte offset of the IPv6 header.
 * @param ip6 View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_ipv6__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_ipv6 *ip6)
{
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    ip6->__ctx = ctx;
    ip6->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_ipv6
 * @brief Returns the offset of the upper-layer header after IPv6, walking
 * past any extension headers.
 *
 * @param ip6 Parsed IPv6 view.
 * @param out Byte offset of the upper-layer header on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC     a header on the extension chain is truncated.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TOO_DEEP  the extension header chain exceeds
 *                           @c BNT_MAX_IPV6_EXT_DEPTH (see @ref limits).
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv6__next_off(const bnt_ipv6 *ip6, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ipv6_next_off)(ip6->__ctx, ip6->__off, &off);
        if (ret)
            return ret;
        return __bnt_off_ret(off, BNT_OFF_BOUND_L4, out);
    }
#else
    {
        struct __bnt_ipv6_meta meta;
        int ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
        if (ret)
            return ret;
        if (!meta.l4_off_valid)
            return BNT_ERR_FRAGMENT;
        return __bnt_off_ret(meta.next_off, BNT_OFF_BOUND_L4, out);
    }
#endif
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 traffic class field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_traffic_class(const bnt_ipv6 *ip6, __u8 *out)
{
    __be32 vtc_flow = 0;
    __u32 host;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be32(ip6->__ctx, ip6->__off, &vtc_flow);
    if (ret)
        return ret;

    host = bpf_ntohl(vtc_flow);
    *out = (__u8)((host >> 20) & 0xff);
    return BNT_OK;
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 version field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_version(const bnt_ipv6 *ip6, __u8 *out)
{
    __u8 first = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_u8(ip6->__ctx, ip6->__off, &first);
    if (ret)
        return ret;
    *out = first >> 4;
    return BNT_OK;
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 flow label field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_flow_label(const bnt_ipv6 *ip6, __u32 *out)
{
    __be32 vtc_flow = 0;
    __u32 host;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be32(ip6->__ctx, ip6->__off, &vtc_flow);
    if (ret)
        return ret;

    host = bpf_ntohl(vtc_flow);
    *out = host & 0x000fffff;
    return BNT_OK;
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 payload length field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_payload_len(const bnt_ipv6 *ip6, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, payload_len), &v);
    if (ret)
        return ret;

    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_ipv6
 *  Reads the final upper-layer protocol, past any extension headers.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TRUNC     a header on the chain is truncated.
 * @retval BNT_ERR_TOO_DEEP  the extension header chain exceeds
 *                           @c BNT_MAX_IPV6_EXT_DEPTH.
 * @retval BNT_ERR_FRAGMENT  a non-first fragment, which has no upper-layer
 *                           header (*out is 0).
 */
static __always_inline int bnt_ipv6__get_l4_proto(const bnt_ipv6 *ip6, __u8 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 next = 0;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_next_proto_off)(ip6->__ctx, ip6->__off, out, &next);
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    *out = meta.l4_proto;
    return BNT_OK;
#endif
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 next-header field from the fixed header.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_base_nexthdr(const bnt_ipv6 *ip6, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, nexthdr), out);
}

/** @ingroup bnt_ipv6
 *  Reports through @p out whether the IPv6 header chain contains a Fragment extension header.
 *  The extension chain is walked only up to the Fragment header.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  more than @c BNT_MAX_IPV6_EXT_DEPTH extension
 *                           headers come before the Fragment header.
 */
static __always_inline int bnt_ipv6__has_fragment_header(const bnt_ipv6 *ip6, bool *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_has_frag_hdr)(ip6->__ctx, ip6->__off, (__u8 *)out);
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;

    *out = meta.has_fragment_hdr != 0;
    return BNT_OK;
#endif
}

/** @ingroup bnt_ipv6
 *  Reports through @p out whether the IPv6 packet is a fragment (non-zero offset or MF set).
 *  The extension chain is walked only up to the Fragment header.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  more than @c BNT_MAX_IPV6_EXT_DEPTH extension
 *                           headers come before the Fragment header.
 */
static __always_inline int bnt_ipv6__is_fragment(const bnt_ipv6 *ip6, bool *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_is_frag)(ip6->__ctx, ip6->__off, (__u8 *)out);
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;

    *out = meta.is_fragment != 0;
    return BNT_OK;
#endif
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 Fragment header offset-and-flags word into @p out.
 *  The extension chain is walked only up to the Fragment header.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header, or the
 *                           chain has no Fragment header.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  more than @c BNT_MAX_IPV6_EXT_DEPTH extension
 *                           headers come before the Fragment header.
 */
static __always_inline int bnt_ipv6__get_fragment_off_flags(const bnt_ipv6 *ip6, __u16 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_frag_off_flags)(ip6->__ctx, ip6->__off, out);
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (!meta.has_fragment_hdr)
        return BNT_ERR_BAD_PROTO;

    *out = meta.frag_off_flags;
    return BNT_OK;
#endif
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 More Fragments (MF) flag from the Fragment header into @p out.
 *  The extension chain is walked only up to the Fragment header.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header, or the
 *                           chain has no Fragment header.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  more than @c BNT_MAX_IPV6_EXT_DEPTH extension
 *                           headers come before the Fragment header.
 */
static __always_inline int bnt_ipv6__is_more_fragments(const bnt_ipv6 *ip6, bool *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u16 flags = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv6_frag_off_flags)(ip6->__ctx, ip6->__off, &flags);
    if (ret)
        return ret;
    *out = flags & 1;
    return BNT_OK;
#else
    __u16 frag_off_flags;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = bnt_ipv6__get_fragment_off_flags(ip6, &frag_off_flags);
    if (ret)
        return ret;

    *out = (frag_off_flags & 0x1) != 0;
    return BNT_OK;
#endif
}

#ifdef BNT_XDP_H
/* IPv6 Fragment-header flags. The Fragment header is an extension header, so
 * the walk always runs and gives its offset and the current flags. No checksum
 * to update: the flags are not in the L4 pseudo-header. */
static __always_inline int __bnt_ipv6_set_frag_flag(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled)
{
    struct __bnt_ipv6_meta meta;
    __be16 *p;
    __u32 at;
    int ret = __bnt_api_ipv6_walk_to(ctx, off, &meta, 1);

    if (ret)
        return ret;
    if (!meta.has_fragment_hdr)
        return BNT_ERR_BAD_PROTO;
    at = meta.frag_hdr_off + 2;
    BNT_PIN(at);
    ret = __bnt_data_ptr(ctx, at, sizeof(*p), (void **)&p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*p, bpf_htons(enabled ? meta.frag_off_flags | flag
                                          : meta.frag_off_flags & (__u16)~flag));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_frag_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_frag_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled)
{
    return __bnt_ipv6_set_frag_flag(ctx, off, flag, enabled);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

static __always_inline int __bnt_ipv6__set_fragment_off_flags(bnt_ipv6 *ip6,
                                                               __u16 frag_off_flags)
{
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    {
        struct __bnt_ipv6_meta meta;
        int ret;
        ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
        if (ret)
            return ret;
        if (!meta.has_fragment_hdr)
            return BNT_ERR_BAD_PROTO;
        return __bnt_write_be16(ip6->__ctx, meta.frag_hdr_off + 2, bpf_htons(frag_off_flags));
    }
}

static __always_inline int __bnt_ipv6__set_fragment_flag(bnt_ipv6 *ip6,
                                                          __u16 flag,
                                                          bool enabled)
{
    if (!ip6)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv6_set_frag_flag)(ip6->__ctx, ip6->__off, flag, enabled);
#else
    {
        __u16 frag_off_flags;
        int ret;
        ret = bnt_ipv6__get_fragment_off_flags(ip6, &frag_off_flags);
        if (ret)
            return ret;
        if (enabled)
            frag_off_flags |= flag;
        else
            frag_off_flags &= ~flag;
        return __bnt_ipv6__set_fragment_off_flags(ip6, frag_off_flags);
    }
#endif
}

/** @ingroup bnt_ipv6
 *  Sets the More Fragments (MF) flag in the IPv6 Fragment header.
 *  The extension chain is walked only up to the Fragment header.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header, or the
 *                           chain has no Fragment header.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  more than @c BNT_MAX_IPV6_EXT_DEPTH extension
 *                           headers come before the Fragment header.
 */
static __always_inline int bnt_ipv6__set_more_fragments(bnt_ipv6 *ip6)
{
    return __bnt_ipv6__set_fragment_flag(ip6, 0x1, true);
}

/** @ingroup bnt_ipv6
 *  Clears the More Fragments (MF) flag in the IPv6 Fragment header.
 *  The extension chain is walked only up to the Fragment header.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header, or the
 *                           chain has no Fragment header.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  more than @c BNT_MAX_IPV6_EXT_DEPTH extension
 *                           headers come before the Fragment header.
 */
static __always_inline int bnt_ipv6__clear_more_fragments(bnt_ipv6 *ip6)
{
    return __bnt_ipv6__set_fragment_flag(ip6, 0x1, false);
}

/** @ingroup bnt_ipv6
 *  Reads the number of extension headers parsed during the IPv6 header walk.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  the extension header chain exceeds @c
 *                           BNT_MAX_IPV6_EXT_DEPTH.
 */
static __always_inline int bnt_ipv6__get_ext_depth(const bnt_ipv6 *ip6, __u8 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_ext_depth)(ip6->__ctx, ip6->__off, out);
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    *out = meta.ext_depth;
    return BNT_OK;
#endif
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 hop limit field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_hop_limit(const bnt_ipv6 *ip6, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, hop_limit), out);
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 source address.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_saddr(const bnt_ipv6 *ip6, struct in6_addr *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, sizeof(*out));
    if (!ip6)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_read_in6)(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), out);
#else
    return __bnt_read(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), out, sizeof(*out));
#endif
}

/** @ingroup bnt_ipv6
 *  Reads the IPv6 destination address.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_ipv6__get_daddr(const bnt_ipv6 *ip6, struct in6_addr *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, sizeof(*out));
    if (!ip6)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_read_in6)(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, daddr), out);
#else
    return __bnt_read(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, daddr), out, sizeof(*out));
#endif
}

#ifdef BNT_XDP_H
/* Isolated subprogram for the default (global) build mode, same convention as
 * every other bnt_*_g helper: keeps the FIB lookup's stack usage and verifier
 * state out of the caller. Portable across backends (BNT_CTX_TYPE, __bnt_read). */
static __always_inline int __bnt_ipv4_fib_lookup(BNT_CTX_TYPE *ctx, __u32 ip_off, bnt_fib4 *fib)
{
    const struct iphdr *ip;
    int ret;

    if (!fib)
        return BNT_ERR_BAD_ARG;
    /* *fib arrives cleared by bnt_ipv4__fib_lookup(). */

    /* One bounded packet pointer, fields read directly (no header copy). */
    ret = __bnt_data_ptr(ctx, ip_off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;

    fib->__fib.family      = AF_INET;
    fib->__fib.l4_protocol = ip->protocol;
    fib->__fib.tot_len     = bpf_ntohs(__BNT_PKT_LOAD(ip->tot_len));
    fib->__fib.ifindex     = ctx->ingress_ifindex;
    fib->__fib.tos         = ip->tos;
    fib->__fib.ipv4_src    = __BNT_PKT_LOAD(ip->saddr);
    fib->__fib.ipv4_dst    = __BNT_PKT_LOAD(ip->daddr);
    fib->__status = bpf_fib_lookup(ctx, &fib->__fib, sizeof(fib->__fib), 0);
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_fib_lookup_g(BNT_CTX_TYPE *ctx, __u32 ip_off, bnt_fib4 *fib);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_fib_lookup_g(BNT_CTX_TYPE *ctx, __u32 ip_off, bnt_fib4 *fib)
{
    return __bnt_ipv4_fib_lookup(ctx, ip_off, fib);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_ipv4
 * @brief Performs a kernel FIB lookup for the IPv4 destination.
 *
 * @c BNT_OK means the lookup ran; check bnt_fib4__is_success() for whether it
 * found a route. See @ref fib.
 *
 * @param ip  Parsed IPv4 view.
 * @param fib Result view filled on success.
 * @retval BNT_OK            the lookup ran.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p fib is NULL.
 * @retval BNT_ERR_TRUNC     the IPv4 header is truncated.
 */
static __always_inline int bnt_ipv4__fib_lookup(const bnt_ipv4 *ip, bnt_fib4 *fib)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip || !fib)
        return BNT_ERR_BAD_ARG;
    /* Cleared here, not in the global: verifiers before 6.3 reject stack
     * memory passed to a global unless it is already initialized. */
    __builtin_memset(fib, 0, sizeof(*fib));
    return __BNT_OP(__bnt_ipv4_fib_lookup)(ip->__ctx, ip->__off, fib);
#else
    {
        struct iphdr h = {};
        int ret;

        if (!fib)
            return BNT_ERR_BAD_ARG;
        __builtin_memset(fib, 0, sizeof(*fib));

        if (!ip)
            return BNT_ERR_BAD_ARG;

        ret = __bnt_read(ip->__ctx, ip->__off, &h, sizeof(h));
        if (ret)
            return ret;

        fib->__fib.family = AF_INET;
        fib->__fib.l4_protocol = h.protocol;
        fib->__fib.tot_len = bpf_ntohs(h.tot_len);
        fib->__fib.ifindex = ip->__ctx->ingress_ifindex;
        fib->__fib.tos = h.tos;
        fib->__fib.ipv4_src = h.saddr;
        fib->__fib.ipv4_dst = h.daddr;
        fib->__status = bpf_fib_lookup(ip->__ctx, &fib->__fib, sizeof(fib->__fib), 0);

        return BNT_OK;
    }
#endif /* !BNT_INLINE_ALL */
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_fib_lookup(BNT_CTX_TYPE *ctx, __u32 ip_off, bnt_fib6 *fib)
{
    const struct ipv6hdr *ip6;
    int ret;

    if (!fib)
        return BNT_ERR_BAD_ARG;
    /* *fib arrives cleared by bnt_ipv6__fib_lookup(). */

    /* One bounded packet pointer, fields read directly (no header copy). */
    ret = __bnt_data_ptr(ctx, ip_off, sizeof(*ip6), (void **)&ip6);
    if (ret)
        return ret;

    fib->__fib.family      = AF_INET6;
    fib->__fib.l4_protocol = ip6->nexthdr;
    fib->__fib.tot_len     = bpf_ntohs(__BNT_PKT_LOAD(ip6->payload_len)) +
                             (__u16)sizeof(struct ipv6hdr);
    fib->__fib.ifindex     = ctx->ingress_ifindex;
    fib->__fib.flowinfo    = __BNT_PKT_LOAD(*(const __be32 *)ip6) & bpf_htonl(0x0fffffff);
    __BNT_PKT_MEMCPY(fib->__fib.ipv6_src, &ip6->saddr, sizeof(fib->__fib.ipv6_src));
    __BNT_PKT_MEMCPY(fib->__fib.ipv6_dst, &ip6->daddr, sizeof(fib->__fib.ipv6_dst));
    fib->__status = bpf_fib_lookup(ctx, &fib->__fib, sizeof(fib->__fib), 0);
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
/* Isolated subprogram for the default (global) build mode; see
 * __bnt_ipv4_fib_lookup_g above. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_fib_lookup_g(BNT_CTX_TYPE *ctx, __u32 ip_off, bnt_fib6 *fib);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_fib_lookup_g(BNT_CTX_TYPE *ctx, __u32 ip_off, bnt_fib6 *fib)
{
    return __bnt_ipv6_fib_lookup(ctx, ip_off, fib);
}
#endif
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_ipv6
 * @brief Performs a kernel FIB lookup for the IPv6 destination.
 *
 * @c BNT_OK means the lookup ran; check bnt_fib6__is_success() for whether it
 * found a route. See @ref fib.
 *
 * @param ip6 Parsed IPv6 view.
 * @param fib Result view filled on success.
 * @retval BNT_OK            the lookup ran.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p fib is NULL.
 * @retval BNT_ERR_TRUNC     the IPv6 header is truncated.
 */
static __always_inline int bnt_ipv6__fib_lookup(const bnt_ipv6 *ip6, bnt_fib6 *fib)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip6 || !fib)
        return BNT_ERR_BAD_ARG;
    /* Cleared here, not in the global: verifiers before 6.3 reject stack
     * memory passed to a global unless it is already initialized. */
    __builtin_memset(fib, 0, sizeof(*fib));
    return __BNT_OP(__bnt_ipv6_fib_lookup)(ip6->__ctx, ip6->__off, fib);
#else
    {
        struct ipv6hdr h = {};
        __be32 vtc_flow = 0;
        int ret;

        if (!fib)
            return BNT_ERR_BAD_ARG;
        __builtin_memset(fib, 0, sizeof(*fib));

        if (!ip6)
            return BNT_ERR_BAD_ARG;

        ret = __bnt_read(ip6->__ctx, ip6->__off, &h, sizeof(h));
        if (ret)
            return ret;

        ret = __bnt_read_be32(ip6->__ctx, ip6->__off, &vtc_flow);
        if (ret)
            return ret;

        fib->__fib.family = AF_INET6;
        fib->__fib.l4_protocol = h.nexthdr;
        fib->__fib.tot_len = bpf_ntohs(h.payload_len) + sizeof(struct ipv6hdr);
        fib->__fib.ifindex = ip6->__ctx->ingress_ifindex;
        fib->__fib.flowinfo = vtc_flow & bpf_htonl(0x0fffffff);
        __builtin_memcpy(fib->__fib.ipv6_src, &h.saddr, sizeof(fib->__fib.ipv6_src));
        __builtin_memcpy(fib->__fib.ipv6_dst, &h.daddr, sizeof(fib->__fib.ipv6_dst));
        fib->__status = bpf_fib_lookup(ip6->__ctx, &fib->__fib, sizeof(fib->__fib), 0);

        return BNT_OK;
    }
#endif /* !BNT_INLINE_ALL */
}

/** @ingroup bnt_ipv4
 *  Returns the FIB lookup result code for the IPv4 lookup.
 *
 * @return the bpf_fib_lookup() result code (@c BPF_FIB_LKUP_RET_*), or
 *         BNT_ERR_BAD_ARG when @p fib is NULL.
 */
static __always_inline int bnt_fib4__get_status(const bnt_fib4 *fib)
{
    if (!fib)
        return BNT_ERR_BAD_ARG;
    return fib->__status;
}

/** @ingroup bnt_ipv4
 *  Returns the output interface index from the IPv4 FIB lookup result. */
static __always_inline __u32 bnt_fib4__get_out_ifindex(const bnt_fib4 *fib)
{
    if (!fib)
        return 0;
    return fib->__fib.ifindex;
}

/** @ingroup bnt_ipv4
 *  Returns a pointer to the source MAC from the IPv4 FIB lookup result. */
static __always_inline const unsigned char *bnt_fib4__get_smac(const bnt_fib4 *fib)
{
    if (!fib)
        return NULL;
    return fib->__fib.smac;
}

/** @ingroup bnt_ipv4
 *  Returns a pointer to the next-hop destination MAC from the IPv4 FIB lookup result. */
static __always_inline const unsigned char *bnt_fib4__get_dmac(const bnt_fib4 *fib)
{
    if (!fib)
        return NULL;
    return fib->__fib.dmac;
}

/** @ingroup bnt_ipv4
 *  Returns true if the IPv4 FIB lookup found a forwardable next hop. */
static __always_inline bool bnt_fib4__is_success(const bnt_fib4 *fib)
{
    return fib && fib->__status == BPF_FIB_LKUP_RET_SUCCESS;
}

/** @ingroup bnt_ipv6
 *  Returns the FIB lookup result code for the IPv6 lookup.
 *
 * @return the bpf_fib_lookup() result code (@c BPF_FIB_LKUP_RET_*), or
 *         BNT_ERR_BAD_ARG when @p fib is NULL.
 */
static __always_inline int bnt_fib6__get_status(const bnt_fib6 *fib)
{
    if (!fib)
        return BNT_ERR_BAD_ARG;
    return fib->__status;
}

/** @ingroup bnt_ipv6
 *  Returns the output interface index from the IPv6 FIB lookup result. */
static __always_inline __u32 bnt_fib6__get_out_ifindex(const bnt_fib6 *fib)
{
    if (!fib)
        return 0;
    return fib->__fib.ifindex;
}

/** @ingroup bnt_ipv6
 *  Returns a pointer to the source MAC from the IPv6 FIB lookup result. */
static __always_inline const unsigned char *bnt_fib6__get_smac(const bnt_fib6 *fib)
{
    if (!fib)
        return NULL;
    return fib->__fib.smac;
}

/** @ingroup bnt_ipv6
 *  Returns a pointer to the next-hop destination MAC from the IPv6 FIB lookup result. */
static __always_inline const unsigned char *bnt_fib6__get_dmac(const bnt_fib6 *fib)
{
    if (!fib)
        return NULL;
    return fib->__fib.dmac;
}

/** @ingroup bnt_ipv6
 *  Returns true if the IPv6 FIB lookup found a forwardable next hop. */
static __always_inline bool bnt_fib6__is_success(const bnt_fib6 *fib)
{
    return fib && fib->__status == BPF_FIB_LKUP_RET_SUCCESS;
}

/** @ingroup bnt_ipv6
 *  Writes the IPv6 hop limit field. IPv6 has no header checksum to fix.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv6__set_hop_limit(bnt_ipv6 *ip6, __u8 hop_limit)
{
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, hop_limit), hop_limit);
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv6_dec_hop_limit(BNT_CTX_TYPE *ctx, __u32 off, bool *expired)
{
    struct ipv6hdr *ip6;
    int ret;

    if (expired)
        *expired = false;
    ret = __bnt_data_ptr(ctx, off, sizeof(*ip6), (void **)&ip6);
    if (ret)
        return ret;
    if (ip6->hop_limit <= 1) {
        if (expired)
            *expired = true;
        return BNT_ERR_BAD_STATE;
    }
    ip6->hop_limit = ip6->hop_limit - 1;   /* IPv6 has no header checksum */
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_dec_hop_limit_g(BNT_CTX_TYPE *ctx, __u32 off, bool *expired);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_dec_hop_limit_g(BNT_CTX_TYPE *ctx, __u32 off, bool *expired)
{
    return __bnt_ipv6_dec_hop_limit(ctx, off, expired);
}
#endif
#endif

/**
 * @ingroup bnt_ipv6
 * @brief Decrements the IPv6 hop limit by one.
 *
 * Refuses to decrement a hop limit that is already at or below 1, matching
 * bnt_ipv4__dec_ttl(). IPv6 has no header checksum to fix.
 *
 * @param ip6     Parsed IPv6 view.
 * @param expired Set to true if the hop limit was already at or below 1,
 *                false otherwise. May be NULL.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC     the read or write falls outside the packet.
 * @retval BNT_ERR_BAD_STATE the hop limit is already at or below 1.
 */
static __always_inline int bnt_ipv6__dec_hop_limit(bnt_ipv6 *ip6, bool *expired)
{
    if (expired)
        *expired = false;
    if (!ip6)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv6_dec_hop_limit)(ip6->__ctx, ip6->__off, expired);
#else
    {
        __u8 hop_limit;
        int ret;
        ret = bnt_ipv6__get_hop_limit(ip6, &hop_limit);
        if (ret)
            return ret;
        if (hop_limit <= 1) {
            if (expired)
                *expired = true;
            return BNT_ERR_BAD_STATE;
        }
        return bnt_ipv6__set_hop_limit(ip6, hop_limit - 1);
    }
#endif
}

static __always_inline int __bnt_ipv6_update_l4_addr_csum(bnt_ipv6 *ip6,
                                                           const struct __bnt_ipv6_meta *meta,
                                                           const struct in6_addr *old,
                                                           const struct in6_addr *addr)
{
    __u32 base;
    __u32 i;
    int ret;

    if (!meta->l4_off_valid)
        return BNT_OK;
    if (!__bnt_ipv6_l4_has_pseudo_csum(meta->l4_proto))
        return BNT_OK;

    if (meta->l4_proto == IPPROTO_TCP)
        base = meta->next_off + offsetof(struct tcphdr, check);
    else if (meta->l4_proto == IPPROTO_UDP)
        base = meta->next_off + offsetof(struct udphdr, check);
    else
        base = meta->next_off + offsetof(struct icmp6hdr, icmp6_cksum);

#pragma unroll
    for (i = 0; i < 4; i++) {
        __be32 from;
        __be32 to;

        __builtin_memcpy(&from, &old->s6_addr32[i], sizeof(from));
        __builtin_memcpy(&to, &addr->s6_addr32[i], sizeof(to));
        ret = __bnt_l4_pseudo_csum32(ip6->__ctx, base, from, to, meta->l4_proto == IPPROTO_UDP);
        if (ret)
            return ret;
    }

    return BNT_OK;
}

/** Writes the IPv6 source address and updates supported upper-layer checksums. */
#ifdef BNT_XDP_H
/* IPv6 set_saddr/set_daddr and the pseudo-header checksum of the transport.
 * Reads the base nexthdr directly from the IPv6 header: in the common case (L4
 * directly after the base header) there is no walk and no call; only extension
 * headers go through __bnt_ipv6_l4_meta_g. */
static __always_inline int __bnt_ipv6_set_addr(BNT_CTX_TYPE *ctx, __u32 off,
                           const struct in6_addr *addr, int is_daddr)
{
    struct ipv6hdr *ip6;
    struct __bnt_ipv6_meta meta = {};
    struct in6_addr newv;
    __be32 *a;
    __be16 *check = NULL;
    __be16 c = 0;
    __u32 coff = 0, aoff;
    __u8 nexthdr;
    int ret, i;

    if (!addr)
        return BNT_ERR_BAD_ARG;
    __builtin_memcpy(&newv, addr, sizeof(newv));        /* rodata -> stack */
    ret = __bnt_data_ptr(ctx, off, sizeof(*ip6), (void **)&ip6);
    if (ret)
        return ret;
    /* Every bound first, so a call that fails writes nothing. */
    nexthdr = ip6->nexthdr;
    if (__bnt_is_ipv6_ext(nexthdr)) {
        /* The walk stays in its own global: inlined, it would double the
         * verifier's work to save a few instructions. */
        ret = __BNT_OP(__bnt_ipv6_l4_meta)(ctx, off, &meta);
        if (ret)
            return ret;
    } else {                                            /* common case: no walk */
        meta.l4_proto = nexthdr;
        meta.next_off = off + (__u32)sizeof(struct ipv6hdr);
        meta.l4_off_valid = 1;
    }
    if (meta.l4_off_valid && __bnt_ipv6_l4_has_pseudo_csum(meta.l4_proto)) {
        coff = meta.next_off + (meta.l4_proto == IPPROTO_TCP ? offsetof(struct tcphdr, check)
                                : meta.l4_proto == IPPROTO_UDP ? offsetof(struct udphdr, check)
                                : offsetof(struct icmp6hdr, icmp6_cksum));
        BNT_PIN(coff);
        ret = __bnt_data_ptr(ctx, coff, sizeof(*check), (void **)&check);
        if (ret)
            return ret;
    }
    /* After the call, a pointer to the address to write. */
    aoff = off + (is_daddr ? offsetof(struct ipv6hdr, daddr) : offsetof(struct ipv6hdr, saddr));
    BNT_PIN(aoff);
    ret = __bnt_data_ptr(ctx, aoff, sizeof(newv), (void **)&a);
    if (ret)
        return ret;
    if (check) {
        c = __BNT_PKT_LOAD(*check);
        if (meta.l4_proto == IPPROTO_UDP && c == 0)     /* UDP checksum 0 = none */
            check = NULL;
    }
    /* Word by word, each old word read in place: no copy of the old address,
     * which with BNT_STRICT_ALIGN would go through the stack byte by byte. */
#pragma unroll
    for (i = 0; i < 4; i++) {
        __be32 from = __BNT_PKT_LOAD(a[i]), to;

        __builtin_memcpy(&to, &newv.s6_addr32[i], sizeof(to));
        __BNT_PKT_STORE(a[i], to);
        if (check)
            c = __bnt_csum32_update(c, from, to);
    }
    if (check) {
        if (meta.l4_proto == IPPROTO_UDP && c == 0)
            c = bpf_htons(0xffff);
        __BNT_PKT_STORE(*check, c);
    }
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_addr_g(BNT_CTX_TYPE *ctx, __u32 off,
                           const struct in6_addr *addr, int is_daddr);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_set_addr_g(BNT_CTX_TYPE *ctx, __u32 off,
                           const struct in6_addr *addr, int is_daddr)
{
    return __bnt_ipv6_set_addr(ctx, off, addr, is_daddr);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

/**
 * @ingroup bnt_ipv6
 * @brief Sets the IPv6 source address and fixes the affected checksum.
 *
 * IPv6 has no header checksum. When the upper layer is TCP, UDP, or ICMPv6,
 * updates its pseudo-header checksum; this update is skipped on a fragment.
 *
 * @param ip6  Parsed IPv6 view.
 * @param addr New source address.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p addr is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TOO_DEEP the extension header chain exceeds
 *                         @c BNT_MAX_IPV6_EXT_DEPTH.
 */
static __always_inline int bnt_ipv6__set_saddr(bnt_ipv6 *ip6, const struct in6_addr *addr)
{
    if (!ip6 || !addr)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv6_set_addr)(ip6->__ctx, ip6->__off, addr, 0);
#else
    {
        struct __bnt_ipv6_meta meta;
        struct in6_addr old;
        int ret;
        ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
        if (ret)
            return ret;
        ret = __bnt_read(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), &old, sizeof(old));
        if (ret)
            return ret;
        ret = __bnt_write(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), addr, sizeof(*addr));
        if (ret)
            return ret;
        return __bnt_ipv6_update_l4_addr_csum(ip6, &meta, &old, addr);
    }
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Sets the IPv6 destination address and fixes the affected checksum.
 *
 * IPv6 has no header checksum. When the upper layer is TCP, UDP, or ICMPv6,
 * updates its pseudo-header checksum; this update is skipped on a fragment.
 *
 * @param ip6  Parsed IPv6 view.
 * @param addr New destination address.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 or @p addr is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TOO_DEEP the extension header chain exceeds
 *                         @c BNT_MAX_IPV6_EXT_DEPTH.
 */
static __always_inline int bnt_ipv6__set_daddr(bnt_ipv6 *ip6, const struct in6_addr *addr)
{
    if (!ip6 || !addr)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv6_set_addr)(ip6->__ctx, ip6->__off, addr, 1);
#else
    {
        struct __bnt_ipv6_meta meta;
        struct in6_addr old;
        int ret;
        ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
        if (ret)
            return ret;
        ret = __bnt_read(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, daddr), &old, sizeof(old));
        if (ret)
            return ret;
        ret = __bnt_write(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, daddr), addr, sizeof(*addr));
        if (ret)
            return ret;
        return __bnt_ipv6_update_l4_addr_csum(ip6, &meta, &old, addr);
    }
#endif
}

/** Writes the IPv6 source address without updating any L4 checksum. */
static __always_inline int __bnt_ipv6__set_saddr_raw(bnt_ipv6 *ip6, const struct in6_addr *addr)
{
    if (!ip6 || !addr)
        return BNT_ERR_BAD_ARG;
    return __bnt_write(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), addr, sizeof(*addr));
}

/** Writes the IPv6 destination address without updating any L4 checksum. */
static __always_inline int __bnt_ipv6__set_daddr_raw(bnt_ipv6 *ip6, const struct in6_addr *addr)
{
    if (!ip6 || !addr)
        return BNT_ERR_BAD_ARG;
    return __bnt_write(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, daddr), addr, sizeof(*addr));
}

/** @ingroup bnt_ipv6
 *  Writes the IPv6 traffic class field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv6__set_traffic_class(bnt_ipv6 *ip6, __u8 tc)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_set_vtcflow)(ip6->__ctx, ip6->__off, 0x0ff00000u, (__u32)tc << 20);
#else
    __be32 old_v = 0;
    __u32 host;
    int ret;

    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be32(ip6->__ctx, ip6->__off, &old_v);
    if (ret)
        return ret;

    host = (bpf_ntohl(old_v) & 0xf00fffff) | ((__u32)tc << 20);
    return __bnt_write_be32(ip6->__ctx, ip6->__off, bpf_htonl(host));
#endif
}

/** @ingroup bnt_ipv6
 *  Writes the IPv6 flow label field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv6__set_flow_label(bnt_ipv6 *ip6, __u32 label)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_set_vtcflow)(ip6->__ctx, ip6->__off, 0x000fffffu, label);
#else
    __be32 old_v = 0;
    __u32 host;
    int ret;

    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be32(ip6->__ctx, ip6->__off, &old_v);
    if (ret)
        return ret;

    host = (bpf_ntohl(old_v) & 0xfff00000) | (label & 0x000fffff);
    return __bnt_write_be32(ip6->__ctx, ip6->__off, bpf_htonl(host));
#endif
}

/** Writes the IPv6 payload length field with no checksum update.
 *  Use when the caller handles checksums separately (e.g. full recompute). */
static __always_inline int __bnt_ipv6__set_payload_len_raw(bnt_ipv6 *ip6, __u16 payload_len)
{
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, payload_len),
                             bpf_htons(payload_len));
}

/**
 * @ingroup bnt_ipv6
 * @brief Sets the IPv6 payload length field and fixes the affected checksum.
 *
 * When the upper layer is TCP, UDP, or ICMPv6, updates its pseudo-header
 * checksum, since the new length changes the L4 segment length carried in the
 * pseudo-header.
 *
 * @param ip6         Parsed IPv6 view.
 * @param payload_len New payload length, in bytes.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TOO_DEEP the extension header chain exceeds
 *                         @c BNT_MAX_IPV6_EXT_DEPTH.
 * @retval BNT_ERR_FRAGMENT the packet is a fragment and the upper layer is
 *                          TCP, UDP, or ICMPv6, or could not be resolved.
 */
static __always_inline int bnt_ipv6__set_payload_len(bnt_ipv6 *ip6, __u16 payload_len)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv6_set_payload_len)(ip6->__ctx, ip6->__off, payload_len);
#else
    struct __bnt_ipv6_meta meta;
    BNT_CTX_TYPE *ctx;
    __be16 old = 0, v = bpf_htons(payload_len);
    __u32 ip6_off, pl_off, csum_off;
    void *data, *data_end;
    int ret;

    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ctx = ip6->__ctx;
    /*
     * Break CSE of ctx->data across the surrounding program. Without this
     * barrier clang can merge packet-pointer loads from nearby helpers and
     * later materialize them in verifier-hostile forms.
     */
#if BNT_LEGACY_KERNEL
    asm volatile("" : "+r"(ctx));
#endif
    ip6->__ctx = ctx;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (meta.is_fragment && __bnt_ipv6_l4_maybe_has_pseudo_csum(&meta))
        return BNT_ERR_FRAGMENT;

    ip6_off = ip6->__off;
    pl_off = ip6_off + offsetof(struct ipv6hdr, payload_len);
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    /* Confined: read old / write new through globals so the (possibly
     * unconstrained) ip6->__off is re-bounded inside each global. */
    (void)data;
    (void)data_end;
    ret = __BNT_OP(__bnt_read_be16)(ctx, pl_off, &old);
    if (ret)
        return ret;
    ret = __BNT_OP(__bnt_write_be16)(ctx, pl_off, v);
    if (ret)
        return ret;
#else
    /*
     * Access payload_len directly instead of routing through __bnt_data_ptr;
     * this setter already performed a fresh IPv6 metadata walk above.
     */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data + pl_off + 2 > data_end)
        return BNT_ERR_TRUNC;
    old = *((__be16 *)(data + pl_off));
    *((__be16 *)(data + pl_off)) = v;
#endif

    if (!meta.l4_off_valid)
        return BNT_OK;
    if (meta.l4_proto == IPPROTO_TCP)
        csum_off = meta.next_off + offsetof(struct tcphdr, check);
    else if (meta.l4_proto == IPPROTO_UDP)
        csum_off = meta.next_off + offsetof(struct udphdr, check);
    else if (meta.l4_proto == IPPROTO_ICMPV6)
        csum_off = meta.next_off + offsetof(struct icmp6hdr, icmp6_cksum);
    else
        return BNT_OK;

    return __bnt_l4_pseudo_csum16(ip6->__ctx, csum_off, old, v,
                                    meta.l4_proto == IPPROTO_UDP);
#endif
}

/** @ingroup bnt_ipv6
 *  Writes the IPv6 next-header field in the fixed header.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv6__set_base_nexthdr(bnt_ipv6 *ip6, __u8 nexthdr)
{
    if (!ip6)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, nexthdr), nexthdr);
}

/**
 * @ingroup bnt_tcp
 * @brief Initializes a TCP header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param off Byte offset of the TCP header.
 * @param tcp View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_tcp__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_tcp *tcp)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    tcp->__ctx = ctx;
    tcp->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_tcp
 * @brief Returns the offset of the payload following the TCP header.
 *
 * @param tcp Parsed TCP view.
 * @param out Byte offset of the payload on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC     the TCP header is truncated.
 * @retval BNT_ERR_BAD_PROTO the data offset field is smaller than the
 *                           minimum TCP header size.
 */
static __always_inline int bnt_tcp__next_off(const bnt_tcp *tcp, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_tcp_next_off)(tcp->__ctx, tcp->__off, &off);
        if (ret)
            return ret;
        return __bnt_off_ret(off, BNT_OFF_BOUND_L4, out);
    }
#else
    {
        __u32 hlen;
        int ret = __bnt_tcp_hlen(tcp, &hlen);
        if (ret)
            return ret;
        return __bnt_off_ret(tcp->__off + hlen, BNT_OFF_BOUND_L4, out);
    }
#endif
}

/** @ingroup bnt_tcp
 *  Reads the TCP source port.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_sport(const bnt_tcp *tcp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, source), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP destination port.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_dport(const bnt_tcp *tcp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, dest), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP sequence number.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_seq(const bnt_tcp *tcp, __u32 *out)
{
    __be32 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, seq), &v);
    if (ret)
        return ret;
    *out = bpf_ntohl(v);
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP acknowledgment number.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_ack_seq(const bnt_tcp *tcp, __u32 *out)
{
    __be32 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, ack_seq), &v);
    if (ret)
        return ret;
    *out = bpf_ntohl(v);
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP data offset, in 32-bit words.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p tcp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the data offset is below 5 words.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_doff(const bnt_tcp *tcp, __u32 *out)
{
    __u32 hlen;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_tcp_hlen(tcp, &hlen);
    if (ret)
        return ret;
    *out = hlen / 4;
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP flags bitmask using BNT_TCP_* bits.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_flags(const bnt_tcp *tcp, __u16 *out)
{
    __be16 word = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + 12, &word);
    if (ret)
        return ret;
    *out = bpf_ntohs(word) & 0x01ff;
    return BNT_OK;
}

static __always_inline int __bnt_tcp__is_flag_set(const bnt_tcp *tcp, __u16 flag, bool *out)
{
    __u16 flags;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = bnt_tcp__get_flags(tcp, &flags);
    if (ret)
        return ret;

    *out = (flags & flag) != 0;
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP FIN flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_fin(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_FIN, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP SYN flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_syn(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_SYN, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP RST flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_rst(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_RST, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP PSH flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_psh(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_PSH, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP ACK flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_ack(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_ACK, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP URG flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_urg(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_URG, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP ECE flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_ece(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_ECE, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP CWR flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_cwr(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_CWR, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP NS flag into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__is_ns(const bnt_tcp *tcp, bool *out)
{
    return __bnt_tcp__is_flag_set(tcp, BNT_TCP_NS, out);
}

/** @ingroup bnt_tcp
 *  Reads the TCP window size.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_window(const bnt_tcp *tcp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, window), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_check(const bnt_tcp *tcp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Reads the TCP urgent pointer.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_tcp__get_urg_ptr(const bnt_tcp *tcp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, urg_ptr), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_tcp
 *  Writes the TCP checksum directly, without incremental update.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_check(bnt_tcp *tcp, __u16 check)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), bpf_htons(check));
}

/** Writes the TCP source port without updating the checksum. */
static __always_inline int __bnt_tcp__set_sport_raw(bnt_tcp *tcp, __u16 port)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, source), bpf_htons(port));
}

/** Writes the TCP destination port without updating the checksum. */
static __always_inline int __bnt_tcp__set_dport_raw(bnt_tcp *tcp, __u16 port)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, dest), bpf_htons(port));
}

/** Writes the TCP sequence number without updating the checksum. */
static __always_inline int __bnt_tcp__set_seq_raw(bnt_tcp *tcp, __u32 seq)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, seq), bpf_htonl(seq));
}

/** Writes the TCP acknowledgment number without updating the checksum. */
static __always_inline int __bnt_tcp__set_ack_seq_raw(bnt_tcp *tcp, __u32 ack_seq)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, ack_seq), bpf_htonl(ack_seq));
}

/** Writes the TCP flags (preserving data offset and reserved bits) without updating the checksum. */
static __always_inline int __bnt_tcp__set_flags_raw(bnt_tcp *tcp, __u16 flags)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_set_flags_raw)(tcp->__ctx, tcp->__off, flags);
#else
    __be16 old = 0;
    __u16 old_h;
    int ret;

    if (!tcp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + 12, &old);
    if (ret)
        return ret;
    old_h = bpf_ntohs(old);
    return __bnt_write_be16(tcp->__ctx, tcp->__off + 12,
                             bpf_htons((old_h & 0xfe00) | (flags & 0x01ff)));
#endif
}

/** Writes the TCP window field without updating the checksum. */
static __always_inline int __bnt_tcp__set_window_raw(bnt_tcp *tcp, __u16 window)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, window), bpf_htons(window));
}

/** Writes the TCP urgent pointer field without updating the checksum. */
static __always_inline int __bnt_tcp__set_urg_ptr_raw(bnt_tcp *tcp, __u16 urg_ptr)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, urg_ptr), bpf_htons(urg_ptr));
}

/** Writes the TCP data offset field without updating the checksum. */
static __always_inline int __bnt_tcp__set_doff_raw(bnt_tcp *tcp, __u32 doff)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    if (doff < 5 || doff > 15)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_set_doff_raw)(tcp->__ctx, tcp->__off, doff);
#else
    __be16 old_word = 0;
    int ret;

    if (!tcp)
        return BNT_ERR_BAD_ARG;
    if (doff < 5 || doff > 15)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_bounds(tcp->__ctx, tcp->__off, doff * 4);
    if (ret)
        return ret;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + 12, &old_word);
    if (ret)
        return ret;
    return __bnt_write_be16(tcp->__ctx, tcp->__off + 12,
                             (old_word & bpf_htons(0x0fff)) | bpf_htons((__u16)doff << 12));
#endif
}

/**
 * @ingroup bnt_udp
 * @brief Initializes a UDP header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param off Byte offset of the UDP header.
 * @param udp View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_udp__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_udp *udp)
{
    if (!udp)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    udp->__ctx = ctx;
    udp->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_udp
 * @brief Returns the offset of the payload following the UDP header.
 *
 * @param udp Parsed UDP view.
 * @param out Byte offset of the payload on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the resulting offset exceeds the representable range.
 */
static __always_inline int bnt_udp__next_off(const bnt_udp *udp, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!udp)
        return BNT_ERR_BAD_ARG;

    /* UDP next-offset is pure arithmetic (no packet access), so it needs no
     * global; the clamp makes the result usable for inline parsing even when
     * udp->__off arrives wide from a find/parse global. */
    return __bnt_off_ret(udp->__off + sizeof(struct udphdr), BNT_OFF_BOUND_L4, out);
}

/** @ingroup bnt_udp
 *  Reads the UDP source port.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_udp__get_sport(const bnt_udp *udp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!udp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, source), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_udp
 *  Reads the UDP destination port.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_udp__get_dport(const bnt_udp *udp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!udp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, dest), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_udp
 *  Reads the UDP length field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_udp__get_len(const bnt_udp *udp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!udp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, len), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_udp
 *  Reads the UDP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_udp__get_check(const bnt_udp *udp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!udp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_udp
 *  Writes the UDP checksum directly, without incremental update.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_udp__set_check(bnt_udp *udp, __u16 check)
{
    if (!udp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), bpf_htons(check));
}

/** Writes the UDP source port without updating the checksum. */
static __always_inline int __bnt_udp__set_sport_raw(bnt_udp *udp, __u16 port)
{
    if (!udp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, source), bpf_htons(port));
}

/** Writes the UDP destination port without updating the checksum. */
static __always_inline int __bnt_udp__set_dport_raw(bnt_udp *udp, __u16 port)
{
    if (!udp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, dest), bpf_htons(port));
}

/** Writes the UDP length field without updating the checksum. */
static __always_inline int __bnt_udp__set_len_raw(bnt_udp *udp, __u16 len)
{
    if (!udp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, len), bpf_htons(len));
}

/**
 * @ingroup bnt_icmp4
 * @brief Initializes an ICMPv4 header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx  Packet context for the active bnt backend.
 * @param off  Byte offset of the ICMPv4 header.
 * @param icmp View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_icmp4__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_icmp4 *icmp)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    icmp->__ctx = ctx;
    icmp->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_icmp4
 * @brief Returns the offset of the payload following the ICMPv4 header.
 *
 * @param icmp Parsed ICMPv4 view.
 * @param out  Byte offset of the payload on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the resulting offset exceeds the representable range.
 */
static __always_inline int bnt_icmp4__next_off(const bnt_icmp4 *icmp, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_off_ret(icmp->__off + sizeof(struct bnt_icmp4_hdr),
                          BNT_OFF_BOUND_L4, out);
}

/** @ingroup bnt_icmp4
 *  Reads the ICMPv4 type field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp4__get_type(const bnt_icmp4 *icmp, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, type), out);
}

/** @ingroup bnt_icmp4
 *  Reads the ICMPv4 code field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp4__get_code(const bnt_icmp4 *icmp, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, code), out);
}

/** @ingroup bnt_icmp4
 *  Reads the ICMPv4 checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp4__get_checksum(const bnt_icmp4 *icmp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_icmp4
 *  Reads the ICMPv4 echo identifier.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp4__get_echo_id(const bnt_icmp4 *icmp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 4, &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_icmp4
 *  Reads the ICMPv4 echo sequence number.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp4__get_echo_seq(const bnt_icmp4 *icmp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 6, &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

#ifdef BNT_XDP_H
/* Shared by ICMPv4 and ICMPv6, which have the same layout here: type at 0,
 * code at 1, checksum at 2, echo id at 4, echo seq at 6. */
static __always_inline int __bnt_icmp_set_typecode(BNT_CTX_TYPE *ctx, __u32 off, __u8 value, int is_code)
{
    __u8 *p;
    __be16 old, neww;
    int ret = __bnt_data_ptr(ctx, off, 8, (void **)&p);
    if (ret)
        return ret;
    old = __BNT_PKT_LOAD(*(__be16 *)p);                         /* type | code */
    if (is_code) { p[1] = value; neww = bpf_htons((bpf_ntohs(old) & 0xff00) | value); }
    else         { p[0] = value; neww = bpf_htons(((__u16)value << 8) | (bpf_ntohs(old) & 0x00ff)); }
    __BNT_PKT_STORE(*(__be16 *)(p + 2), __bnt_csum16_update(__BNT_PKT_LOAD(*(__be16 *)(p + 2)), old, neww));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp_set_typecode_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 value, int is_code);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp_set_typecode_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 value, int is_code)
{
    return __bnt_icmp_set_typecode(ctx, off, value, is_code);
}
#endif
#endif /* !BNT_INLINE_ALL */
static __always_inline int __bnt_icmp_set_echo(BNT_CTX_TYPE *ctx, __u32 off, __u16 value, int is_seq)
{
    __u8 *p;
    __be16 old, v = bpf_htons(value);
    int ret = __bnt_data_ptr(ctx, off, 8, (void **)&p);
    if (ret)
        return ret;
    if (is_seq) { old = __BNT_PKT_LOAD(*(__be16 *)(p + 6)); __BNT_PKT_STORE(*(__be16 *)(p + 6), v); }
    else        { old = __BNT_PKT_LOAD(*(__be16 *)(p + 4)); __BNT_PKT_STORE(*(__be16 *)(p + 4), v); }
    __BNT_PKT_STORE(*(__be16 *)(p + 2), __bnt_csum16_update(__BNT_PKT_LOAD(*(__be16 *)(p + 2)), old, v));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp_set_echo_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 value, int is_seq);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp_set_echo_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 value, int is_seq)
{
    return __bnt_icmp_set_echo(ctx, off, value, is_seq);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

/**
 * @ingroup bnt_icmp4
 * @brief Sets the ICMPv4 type field and fixes the ICMPv4 checksum.
 *
 * @param icmp Parsed ICMPv4 view.
 * @param type New type value.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_type(bnt_icmp4 *icmp, __u8 type)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_typecode)(icmp->__ctx, icmp->__off, type, 0);
#else
    {
        __be16 from = 0, to;
        __u16 host;
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off, &from);
        if (ret)
            return ret;
        host = bpf_ntohs(from);
        to = bpf_htons(((__u16)type << 8) | (host & 0x00ff));
        ret = __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, type), type);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum),
                                from, to, 0);
    }
#endif
}

/**
 * @ingroup bnt_icmp4
 * @brief Sets the ICMPv4 code field and fixes the ICMPv4 checksum.
 *
 * @param icmp Parsed ICMPv4 view.
 * @param code New code value.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_code(bnt_icmp4 *icmp, __u8 code)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_typecode)(icmp->__ctx, icmp->__off, code, 1);
#else
    {
        __be16 from = 0, to;
        __u16 host;
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off, &from);
        if (ret)
            return ret;
        host = bpf_ntohs(from);
        to = bpf_htons((host & 0xff00) | code);
        ret = __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, code), code);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum),
                                from, to, 0);
    }
#endif
}

/**
 * @ingroup bnt_icmp4
 * @brief Sets the ICMPv4 echo identifier and fixes the ICMPv4 checksum.
 *
 * @param icmp Parsed ICMPv4 view.
 * @param id   New echo identifier.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_echo_id(bnt_icmp4 *icmp, __u16 id)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_echo)(icmp->__ctx, icmp->__off, id, 0);
#else
    {
        __be16 old = 0, v = bpf_htons(id);
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 4, &old);
        if (ret)
            return ret;
        ret = __bnt_write_be16(icmp->__ctx, icmp->__off + 4, v);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum),
                                old, v, 0);
    }
#endif
}

/**
 * @ingroup bnt_icmp4
 * @brief Sets the ICMPv4 echo sequence number and fixes the ICMPv4 checksum.
 *
 * @param icmp Parsed ICMPv4 view.
 * @param seq  New echo sequence number.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_echo_seq(bnt_icmp4 *icmp, __u16 seq)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_echo)(icmp->__ctx, icmp->__off, seq, 1);
#else
    {
        __be16 old = 0, v = bpf_htons(seq);
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 6, &old);
        if (ret)
            return ret;
        ret = __bnt_write_be16(icmp->__ctx, icmp->__off + 6, v);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum),
                                old, v, 0);
    }
#endif
}

/** @ingroup bnt_icmp4
 *  Writes the ICMPv4 checksum directly, without incremental update.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_checksum(bnt_icmp4 *icmp, __u16 checksum)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum),
                             bpf_htons(checksum));
}

/** Writes the ICMPv4 type byte without updating the checksum. */
static __always_inline int __bnt_icmp4__set_type_raw(bnt_icmp4 *icmp, __u8 type)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, type), type);
}

/** Writes the ICMPv4 code byte without updating the checksum. */
static __always_inline int __bnt_icmp4__set_code_raw(bnt_icmp4 *icmp, __u8 code)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct bnt_icmp4_hdr, code), code);
}

/** Writes the ICMPv4 echo identifier without updating the checksum. */
static __always_inline int __bnt_icmp4__set_echo_id_raw(bnt_icmp4 *icmp, __u16 id)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(icmp->__ctx, icmp->__off + 4, bpf_htons(id));
}

/** Writes the ICMPv4 echo sequence number without updating the checksum. */
static __always_inline int __bnt_icmp4__set_echo_seq_raw(bnt_icmp4 *icmp, __u16 seq)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(icmp->__ctx, icmp->__off + 6, bpf_htons(seq));
}

/**
 * @ingroup bnt_icmp6
 * @brief Initializes an ICMPv6 header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx  Packet context for the active bnt backend.
 * @param off  Byte offset of the ICMPv6 header.
 * @param icmp View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_icmp6__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_icmp6 *icmp)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    icmp->__ctx = ctx;
    icmp->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_icmp6
 * @brief Returns the offset of the payload following the ICMPv6 header.
 *
 * @param icmp Parsed ICMPv6 view.
 * @param out  Byte offset of the payload on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the resulting offset exceeds the representable range.
 */
static __always_inline int bnt_icmp6__next_off(const bnt_icmp6 *icmp, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_off_ret(icmp->__off + sizeof(struct icmp6hdr),
                          BNT_OFF_BOUND_L4, out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 type field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_type(const bnt_icmp6 *icmp, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_type), out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 code field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_code(const bnt_icmp6 *icmp, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_code), out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_checksum(const bnt_icmp6 *icmp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 echo identifier.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_echo_id(const bnt_icmp6 *icmp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 4, &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 echo sequence number.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_echo_seq(const bnt_icmp6 *icmp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 6, &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Router Advertisement flags byte into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_router_advert_flags(const bnt_icmp6 *icmp,
                                                               __u8 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_icmp6_ra_flags)(icmp->__ctx, icmp->__off, out);
#else
    __u8 type;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;

    ret = bnt_icmp6__get_type(icmp, &type);
    if (ret)
        return ret;
    if (type != BNT_ICMP6_ND_ROUTER_ADVERT)
        return BNT_ERR_BAD_PROTO;

    return __bnt_read_u8(icmp->__ctx, icmp->__off + 5, out);
#endif
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Router Advertisement default-router preference into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_router_advert_preference(const bnt_icmp6 *icmp,
                                                                    __u8 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 flags = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_icmp6_ra_flags)(icmp->__ctx, icmp->__off, &flags);
    if (ret)
        return ret;
    *out = (flags & BNT_ICMP6_RA_PREFERENCE_MASK) >> BNT_ICMP6_RA_PREFERENCE_SHIFT;
    return BNT_OK;
#else
    __u8 flags;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;

    ret = bnt_icmp6__get_router_advert_flags(icmp, &flags);
    if (ret)
        return ret;

    *out = (flags & BNT_ICMP6_RA_PREFERENCE_MASK) >> BNT_ICMP6_RA_PREFERENCE_SHIFT;
    return BNT_OK;
#endif
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Neighbor Advertisement flags byte into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__get_neighbor_advert_flags(const bnt_icmp6 *icmp,
                                                                 __u8 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_icmp6_na_flags)(icmp->__ctx, icmp->__off, out);
#else
    __u8 type;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;

    ret = bnt_icmp6__get_type(icmp, &type);
    if (ret)
        return ret;
    if (type != BNT_ICMP6_ND_NEIGHBOR_ADVERT)
        return BNT_ERR_BAD_PROTO;

    return __bnt_read_u8(icmp->__ctx, icmp->__off + 4, out);
#endif
}

static __always_inline int __bnt_icmp6__is_router_advert_flag_set(const bnt_icmp6 *icmp,
                                                                   __u8 flag,
                                                                   bool *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 flags = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_icmp6_ra_flags)(icmp->__ctx, icmp->__off, &flags);
    if (ret)
        return ret;
    *out = (flags & flag) != 0;
    return BNT_OK;
#else
    __u8 flags;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = bnt_icmp6__get_router_advert_flags(icmp, &flags);
    if (ret)
        return ret;

    *out = (flags & flag) != 0;
    return BNT_OK;
#endif
}

static __always_inline int __bnt_icmp6__is_neighbor_advert_flag_set(const bnt_icmp6 *icmp,
                                                                     __u8 flag,
                                                                     bool *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 flags = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_icmp6_na_flags)(icmp->__ctx, icmp->__off, &flags);
    if (ret)
        return ret;
    *out = (flags & flag) != 0;
    return BNT_OK;
#else
    __u8 flags;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = bnt_icmp6__get_neighbor_advert_flags(icmp, &flags);
    if (ret)
        return ret;

    *out = (flags & flag) != 0;
    return BNT_OK;
#endif
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Router Advertisement Managed (M) flag into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__is_router_advert_managed(const bnt_icmp6 *icmp,
                                                                bool *out)
{
    return __bnt_icmp6__is_router_advert_flag_set(icmp, BNT_ICMP6_RA_MANAGED, out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Router Advertisement Other Configuration (O) flag into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__is_router_advert_other(const bnt_icmp6 *icmp,
                                                              bool *out)
{
    return __bnt_icmp6__is_router_advert_flag_set(icmp, BNT_ICMP6_RA_OTHER, out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Router Advertisement Home Agent (H) flag into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__is_router_advert_home_agent(const bnt_icmp6 *icmp,
                                                                   bool *out)
{
    return __bnt_icmp6__is_router_advert_flag_set(icmp, BNT_ICMP6_RA_HOME_AGENT, out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Router Advertisement Proxy (P) flag into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__is_router_advert_proxy(const bnt_icmp6 *icmp,
                                                              bool *out)
{
    return __bnt_icmp6__is_router_advert_flag_set(icmp, BNT_ICMP6_RA_PROXY, out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Neighbor Advertisement Router (R) flag into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__is_neighbor_advert_router(const bnt_icmp6 *icmp,
                                                                 bool *out)
{
    return __bnt_icmp6__is_neighbor_advert_flag_set(icmp, BNT_ICMP6_NA_ROUTER, out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Neighbor Advertisement Solicited (S) flag into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__is_neighbor_advert_solicited(const bnt_icmp6 *icmp,
                                                                    bool *out)
{
    return __bnt_icmp6__is_neighbor_advert_flag_set(icmp, BNT_ICMP6_NA_SOLICITED, out);
}

/** @ingroup bnt_icmp6
 *  Reads the ICMPv6 Neighbor Advertisement Override (O) flag into @p out.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp or @p out is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     the read falls outside the packet.
 */
static __always_inline int bnt_icmp6__is_neighbor_advert_override(const bnt_icmp6 *icmp,
                                                                   bool *out)
{
    return __bnt_icmp6__is_neighbor_advert_flag_set(icmp, BNT_ICMP6_NA_OVERRIDE, out);
}

/**
 * @ingroup bnt_icmp6
 * @brief Sets the ICMPv6 type field and fixes the ICMPv6 checksum.
 *
 * @param icmp Parsed ICMPv6 view.
 * @param type New type value.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_type(bnt_icmp6 *icmp, __u8 type)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_typecode)(icmp->__ctx, icmp->__off, type, 0);
#else
    {
        __be16 from = 0, to;
        __u16 host;
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off, &from);
        if (ret)
            return ret;
        host = bpf_ntohs(from);
        to = bpf_htons(((__u16)type << 8) | (host & 0x00ff));
        ret = __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_type), type);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                                from, to, 0);
    }
#endif
}

/**
 * @ingroup bnt_icmp6
 * @brief Sets the ICMPv6 code field and fixes the ICMPv6 checksum.
 *
 * @param icmp Parsed ICMPv6 view.
 * @param code New code value.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_code(bnt_icmp6 *icmp, __u8 code)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_typecode)(icmp->__ctx, icmp->__off, code, 1);
#else
    {
        __be16 from = 0, to;
        __u16 host;
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off, &from);
        if (ret)
            return ret;
        host = bpf_ntohs(from);
        to = bpf_htons((host & 0xff00) | code);
        ret = __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_code), code);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                                from, to, 0);
    }
#endif
}

static __always_inline int __bnt_icmp6__write_router_advert_flags(bnt_icmp6 *icmp,
                                                                   __u8 flags)
{
    __be16 old = 0;
    __be16 v;
    __u16 host;
    int ret;

    if (!icmp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 4, &old);
    if (ret)
        return ret;

    host = bpf_ntohs(old);
    v = bpf_htons((host & 0xff00) | flags);
    ret = __bnt_write_be16(icmp->__ctx, icmp->__off + 4, v);
    if (ret)
        return ret;

    return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                            old, v, 0);
}

static __always_inline int __bnt_icmp6__write_neighbor_advert_flags(bnt_icmp6 *icmp,
                                                                     __u8 flags)
{
    __be16 old = 0;
    __be16 v;
    __u16 host;
    int ret;

    if (!icmp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 4, &old);
    if (ret)
        return ret;

    host = bpf_ntohs(old);
    v = bpf_htons(((__u16)flags << 8) | (host & 0x00ff));
    ret = __bnt_write_be16(icmp->__ctx, icmp->__off + 4, v);
    if (ret)
        return ret;

    return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                            old, v, 0);
}

#ifdef BNT_XDP_H
/* ICMPv6 Router and Neighbor Advertisement flags. They are in the word at
 * off + 4: low byte for RA, high byte for NA. Checks the message type, changes
 * the bit and updates the checksum at off + 2. */
static __always_inline int __bnt_icmp6_set_advert_flag(BNT_CTX_TYPE *ctx, __u32 off, __u8 flag,
                                   int enabled, int is_neighbor)
{
    __u8 *p;
    __be16 old, neww;
    __u16 h, b;
    int ret = __bnt_data_ptr(ctx, off, 8, (void **)&p);
    if (ret)
        return ret;
    if (p[0] != (is_neighbor ? BNT_ICMP6_ND_NEIGHBOR_ADVERT
                             : BNT_ICMP6_ND_ROUTER_ADVERT))
        return BNT_ERR_BAD_PROTO;
    old = __BNT_PKT_LOAD(*(__be16 *)(p + 4));
    h   = bpf_ntohs(old);
    b   = is_neighbor ? (h >> 8) : (h & 0x00ff);
    if (enabled) b |= flag;
    else         b &= (__u16)~flag;
    neww = is_neighbor ? bpf_htons((b << 8) | (h & 0x00ff))
                       : bpf_htons((h & 0xff00) | (b & 0x00ff));
    __BNT_PKT_STORE(*(__be16 *)(p + 4), neww);
    __BNT_PKT_STORE(*(__be16 *)(p + 2), __bnt_csum16_update(__BNT_PKT_LOAD(*(__be16 *)(p + 2)), old, neww));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_set_advert_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 flag,
                                   int enabled, int is_neighbor);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_icmp6_set_advert_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 flag,
                                   int enabled, int is_neighbor)
{
    return __bnt_icmp6_set_advert_flag(ctx, off, flag, enabled, is_neighbor);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

static __always_inline int __bnt_icmp6__set_router_advert_flag(bnt_icmp6 *icmp,
                                                                __u8 flag,
                                                                bool enabled)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp6_set_advert_flag)(icmp->__ctx, icmp->__off, flag, enabled, 0);
#else
    {
        __u8 flags;
        int ret;
        ret = bnt_icmp6__get_router_advert_flags(icmp, &flags);
        if (ret)
            return ret;
        if (enabled)
            flags |= flag;
        else
            flags &= ~flag;
        return __bnt_icmp6__write_router_advert_flags(icmp, flags);
    }
#endif
}

static __always_inline int __bnt_icmp6__set_neighbor_advert_flag(bnt_icmp6 *icmp,
                                                                  __u8 flag,
                                                                  bool enabled)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp6_set_advert_flag)(icmp->__ctx, icmp->__off, flag, enabled, 1);
#else
    {
        __u8 flags;
        int ret;
        ret = bnt_icmp6__get_neighbor_advert_flags(icmp, &flags);
        if (ret)
            return ret;
        if (enabled)
            flags |= flag;
        else
            flags &= ~flag;
        return __bnt_icmp6__write_neighbor_advert_flags(icmp, flags);
    }
#endif
}

/**
 * @ingroup bnt_icmp6
 * @brief Sets the ICMPv6 Router Advertisement default-router preference and fixes the ICMPv6 checksum.
 *
 * @param icmp       Parsed ICMPv6 view; its type must be Router Advertisement.
 * @param preference New preference value.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL, or @p preference is out of range.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO @p icmp is not a Router Advertisement.
 */
static __always_inline int bnt_icmp6__set_router_advert_preference(bnt_icmp6 *icmp,
                                                                    __u8 preference)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (preference > 0x3)
        return BNT_ERR_BAD_ARG;
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_icmp6_set_ra_pref)(icmp->__ctx, icmp->__off, preference);
#else
    __u8 flags;
    int ret;

    if (preference > BNT_ICMP6_RA_PREFERENCE_LOW)
        return BNT_ERR_BAD_ARG;

    ret = bnt_icmp6__get_router_advert_flags(icmp, &flags);
    if (ret)
        return ret;

    flags &= ~BNT_ICMP6_RA_PREFERENCE_MASK;
    flags |= preference << BNT_ICMP6_RA_PREFERENCE_SHIFT;
    return __bnt_icmp6__write_router_advert_flags(icmp, flags);
#endif
}

/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 Router Advertisement Managed (M) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_router_advert_managed(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_MANAGED, true);
}

/** @ingroup bnt_icmp6
 *  Clears the ICMPv6 Router Advertisement Managed (M) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__clear_router_advert_managed(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_MANAGED, false);
}

/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 Router Advertisement Other Configuration (O) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_router_advert_other(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_OTHER, true);
}

/** @ingroup bnt_icmp6
 *  Clears the ICMPv6 Router Advertisement Other Configuration (O) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__clear_router_advert_other(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_OTHER, false);
}

/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 Router Advertisement Home Agent (H) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_router_advert_home_agent(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_HOME_AGENT, true);
}

/** @ingroup bnt_icmp6
 *  Clears the ICMPv6 Router Advertisement Home Agent (H) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__clear_router_advert_home_agent(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_HOME_AGENT, false);
}

/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 Router Advertisement Proxy (P) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_router_advert_proxy(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_PROXY, true);
}

/** @ingroup bnt_icmp6
 *  Clears the ICMPv6 Router Advertisement Proxy (P) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Router Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__clear_router_advert_proxy(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_router_advert_flag(icmp, BNT_ICMP6_RA_PROXY, false);
}

/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 Neighbor Advertisement Router (R) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_neighbor_advert_router(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_neighbor_advert_flag(icmp, BNT_ICMP6_NA_ROUTER, true);
}

/** @ingroup bnt_icmp6
 *  Clears the ICMPv6 Neighbor Advertisement Router (R) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__clear_neighbor_advert_router(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_neighbor_advert_flag(icmp, BNT_ICMP6_NA_ROUTER, false);
}

/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 Neighbor Advertisement Solicited (S) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_neighbor_advert_solicited(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_neighbor_advert_flag(icmp, BNT_ICMP6_NA_SOLICITED, true);
}

/** @ingroup bnt_icmp6
 *  Clears the ICMPv6 Neighbor Advertisement Solicited (S) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__clear_neighbor_advert_solicited(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_neighbor_advert_flag(icmp, BNT_ICMP6_NA_SOLICITED, false);
}

/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 Neighbor Advertisement Override (O) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_neighbor_advert_override(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_neighbor_advert_flag(icmp, BNT_ICMP6_NA_OVERRIDE, true);
}

/** @ingroup bnt_icmp6
 *  Clears the ICMPv6 Neighbor Advertisement Override (O) flag and fixes the ICMPv6 checksum.
 *
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p icmp is NULL.
 * @retval BNT_ERR_BAD_PROTO the message is not a Neighbor Advertisement.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__clear_neighbor_advert_override(bnt_icmp6 *icmp)
{
    return __bnt_icmp6__set_neighbor_advert_flag(icmp, BNT_ICMP6_NA_OVERRIDE, false);
}

/**
 * @ingroup bnt_icmp6
 * @brief Sets the ICMPv6 echo identifier and fixes the ICMPv6 checksum.
 *
 * @param icmp Parsed ICMPv6 view.
 * @param id   New echo identifier.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_echo_id(bnt_icmp6 *icmp, __u16 id)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_echo)(icmp->__ctx, icmp->__off, id, 0);
#else
    {
        __be16 old = 0, v = bpf_htons(id);
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 4, &old);
        if (ret)
            return ret;
        ret = __bnt_write_be16(icmp->__ctx, icmp->__off + 4, v);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                                old, v, 0);
    }
#endif
}

/**
 * @ingroup bnt_icmp6
 * @brief Sets the ICMPv6 echo sequence number and fixes the ICMPv6 checksum.
 *
 * @param icmp Parsed ICMPv6 view.
 * @param seq  New echo sequence number.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_echo_seq(bnt_icmp6 *icmp, __u16 seq)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_icmp_set_echo)(icmp->__ctx, icmp->__off, seq, 1);
#else
    {
        __be16 old = 0, v = bpf_htons(seq);
        int ret;
        ret = __bnt_read_be16(icmp->__ctx, icmp->__off + 6, &old);
        if (ret)
            return ret;
        ret = __bnt_write_be16(icmp->__ctx, icmp->__off + 6, v);
        if (ret)
            return ret;
        return __bnt_l4_csum16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                                old, v, 0);
    }
#endif
}

/** @ingroup bnt_icmp6
 *  Writes the ICMPv6 checksum directly, without incremental update.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp6__set_checksum(bnt_icmp6 *icmp, __u16 checksum)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                             bpf_htons(checksum));
}

/** Writes the ICMPv6 type byte without updating the checksum. */
static __always_inline int __bnt_icmp6__set_type_raw(bnt_icmp6 *icmp, __u8 type)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_type), type);
}

/** Writes the ICMPv6 code byte without updating the checksum. */
static __always_inline int __bnt_icmp6__set_code_raw(bnt_icmp6 *icmp, __u8 code)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(icmp->__ctx, icmp->__off + offsetof(struct icmp6hdr, icmp6_code), code);
}

/** Writes the ICMPv6 echo identifier without updating the checksum. */
static __always_inline int __bnt_icmp6__set_echo_id_raw(bnt_icmp6 *icmp, __u16 id)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(icmp->__ctx, icmp->__off + 4, bpf_htons(id));
}

/** Writes the ICMPv6 echo sequence number without updating the checksum. */
static __always_inline int __bnt_icmp6__set_echo_seq_raw(bnt_icmp6 *icmp, __u16 seq)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(icmp->__ctx, icmp->__off + 6, bpf_htons(seq));
}

/**
 * @ingroup bnt_arp
 * @brief Initializes an ARP header view at the given packet offset.
 *
 * Records the position only; the header is read and bounds-checked on each
 * later access.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param off Byte offset of the ARP message.
 * @param arp View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp is NULL.
 * @retval BNT_ERR_TRUNC   @p off is past 0xffff, where no header can start.
 */
static __always_inline int bnt_arp__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_arp *arp)
{
    if (!arp)
        return BNT_ERR_BAD_ARG;
    if (off > __BNT_MAX_VIEW_OFFSET)
        return BNT_ERR_TRUNC;
    arp->__ctx = ctx;
    arp->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_arp
 * @brief Returns the offset of the payload following the ARP message.
 *
 * @param arp Parsed ARP view.
 * @param out Byte offset of the payload on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the ARP message is truncated.
 */
static __always_inline int bnt_arp__next_off(const bnt_arp *arp, __u32 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 hlen = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_arp_hlen)(arp->__ctx, arp->__off, &hlen);
    if (ret)
        return ret;
    return __bnt_off_ret(arp->__off + hlen, BNT_OFF_BOUND_L3, out);
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    return __bnt_off_ret(arp->__off + meta.hlen, BNT_OFF_BOUND_L3, out);
#endif
}

/** @ingroup bnt_arp
 *  Reports through @p out whether the ARP message is Ethernet over IPv4 with
 *  standard address sizes.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_arp__is_eth_ipv4(const bnt_arp *arp, bool *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 is = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_arp_is_eth_ipv4)(arp->__ctx, arp->__off, &is);
    if (ret)
        return ret;
    *out = is;
    return BNT_OK;
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = false;

    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;

    *out = __bnt_arp_is_eth_ipv4_meta(&meta) != 0;
    return BNT_OK;
#endif
}

/** @ingroup bnt_arp
 *  Reads the ARP hardware type.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_htype(const bnt_arp *arp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_hrd), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_arp
 *  Reads the ARP protocol type.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_ptype(const bnt_arp *arp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_pro), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_arp
 *  Reads the ARP hardware address length field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_haddr_len(const bnt_arp *arp, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_hln), out);
}

/** @ingroup bnt_arp
 *  Reads the ARP protocol address length field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_paddr_len(const bnt_arp *arp, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __bnt_read_u8(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_pln), out);
}

/** @ingroup bnt_arp
 *  Reads the ARP operation field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_oper(const bnt_arp *arp, __u16 *out)
{
    __be16 v = 0;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_op), &v);
    if (ret)
        return ret;
    *out = bpf_ntohs(v);
    return BNT_OK;
}

/** @ingroup bnt_arp
 *  Reads the ARP sender hardware address for Ethernet/IPv4 ARP packets.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp or @p out is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_sha(const bnt_arp *arp, unsigned char out[ETH_ALEN])
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    struct __bnt_mac tmp = {};
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, BNT_MAC_LEN);
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_arp_get_sha)(arp->__ctx, arp->__off, &tmp);
    if (ret)
        return ret;
    __builtin_memcpy(out, tmp.addr, BNT_MAC_LEN);
    return BNT_OK;
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, ETH_ALEN);
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        ret = __BNT_OP(__bnt_read_mac)(arp->__ctx, __bnt_arp_sha_off(arp), &tmp);
        if (ret)
            return ret;
        __builtin_memcpy(out, tmp.addr, ETH_ALEN);
        return BNT_OK;
    }
#else
    return __bnt_read(arp->__ctx, __bnt_arp_sha_off(arp), out, ETH_ALEN);
#endif
#endif
}

/** @ingroup bnt_arp
 *  Reads the ARP sender protocol address for Ethernet/IPv4 ARP packets, in
 *  network byte order.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp or @p out is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_spa(const bnt_arp *arp, __be32 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_arp_get_spa)(arp->__ctx, arp->__off, out);
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
    return __bnt_read_be32(arp->__ctx, __bnt_arp_spa_off(arp, &meta), out);
#endif
}

/** @ingroup bnt_arp
 *  Reads the ARP target hardware address for Ethernet/IPv4 ARP packets.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp or @p out is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_tha(const bnt_arp *arp, unsigned char out[ETH_ALEN])
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    struct __bnt_mac tmp = {};
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, BNT_MAC_LEN);
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_arp_get_tha)(arp->__ctx, arp->__off, &tmp);
    if (ret)
        return ret;
    __builtin_memcpy(out, tmp.addr, BNT_MAC_LEN);
    return BNT_OK;
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    __builtin_memset(out, 0, ETH_ALEN);
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        ret = __BNT_OP(__bnt_read_mac)(arp->__ctx, __bnt_arp_tha_off(arp, &meta), &tmp);
        if (ret)
            return ret;
        __builtin_memcpy(out, tmp.addr, ETH_ALEN);
        return BNT_OK;
    }
#else
    return __bnt_read(arp->__ctx, __bnt_arp_tha_off(arp, &meta), out, ETH_ALEN);
#endif
#endif
}

/** @ingroup bnt_arp
 *  Reads the ARP target protocol address for Ethernet/IPv4 ARP packets, in
 *  network byte order.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp or @p out is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the read falls outside the packet.
 */
static __always_inline int bnt_arp__get_tpa(const bnt_arp *arp, __be32 *out)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_arp_get_tpa)(arp->__ctx, arp->__off, out);
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
    return __bnt_read_be32(arp->__ctx, __bnt_arp_tpa_off(arp, &meta), out);
#endif
}

/** @ingroup bnt_arp
 *  Writes the ARP hardware type field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_htype(bnt_arp *arp, __u16 htype)
{
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_hrd),
                             bpf_htons(htype));
}

/** @ingroup bnt_arp
 *  Writes the ARP protocol type field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_ptype(bnt_arp *arp, __u16 ptype)
{
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_pro),
                             bpf_htons(ptype));
}

/** @ingroup bnt_arp
 *  Writes the ARP hardware address length field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_haddr_len(bnt_arp *arp, __u8 haddr_len)
{
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_hln), haddr_len);
}

/** @ingroup bnt_arp
 *  Writes the ARP protocol address length field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_paddr_len(bnt_arp *arp, __u8 paddr_len)
{
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_u8(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_pln), paddr_len);
}

/** @ingroup bnt_arp
 *  Writes the ARP operation field.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p arp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_oper(bnt_arp *arp, __u16 oper)
{
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __bnt_write_be16(arp->__ctx, arp->__off + offsetof(struct bnt_arp_hdr, ar_op),
                             bpf_htons(oper));
}

/** @ingroup bnt_arp
 *  Writes the ARP sender hardware address for Ethernet/IPv4 ARP packets.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp or @p mac is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_sha(bnt_arp *arp, const unsigned char mac[ETH_ALEN])
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    struct __bnt_mac tmp = {};

    if (!arp || !mac)
        return BNT_ERR_BAD_ARG;
    __builtin_memcpy(tmp.addr, mac, BNT_MAC_LEN);
    return __BNT_OP(__bnt_arp_set_sha)(arp->__ctx, arp->__off, &tmp);
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!arp || !mac)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        __builtin_memcpy(tmp.addr, mac, ETH_ALEN);
        return __BNT_OP(__bnt_write_mac)(arp->__ctx, __bnt_arp_sha_off(arp), &tmp);
    }
#else
    return __bnt_write(arp->__ctx, __bnt_arp_sha_off(arp), mac, ETH_ALEN);
#endif
#endif
}

/** @ingroup bnt_arp
 *  Writes the ARP sender protocol address for Ethernet/IPv4 ARP packets, in
 *  network byte order.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_spa(bnt_arp *arp, __be32 spa)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_arp_set_spa)(arp->__ctx, arp->__off, spa);
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
    return __bnt_write_be32(arp->__ctx, __bnt_arp_spa_off(arp, &meta), spa);
#endif
}

/** @ingroup bnt_arp
 *  Writes the ARP target hardware address for Ethernet/IPv4 ARP packets.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp or @p mac is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_tha(bnt_arp *arp, const unsigned char mac[ETH_ALEN])
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    struct __bnt_mac tmp = {};

    if (!arp || !mac)
        return BNT_ERR_BAD_ARG;
    __builtin_memcpy(tmp.addr, mac, BNT_MAC_LEN);
    return __BNT_OP(__bnt_arp_set_tha)(arp->__ctx, arp->__off, &tmp);
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!arp || !mac)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        struct __bnt_mac tmp = {};
        __builtin_memcpy(tmp.addr, mac, ETH_ALEN);
        return __BNT_OP(__bnt_write_mac)(arp->__ctx, __bnt_arp_tha_off(arp, &meta), &tmp);
    }
#else
    return __bnt_write(arp->__ctx, __bnt_arp_tha_off(arp, &meta), mac, ETH_ALEN);
#endif
#endif
}

/** @ingroup bnt_arp
 *  Writes the ARP target protocol address for Ethernet/IPv4 ARP packets, in
 *  network byte order.
 *
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p arp is NULL.
 * @retval BNT_ERR_UNSUPPORTED the ARP header is not Ethernet/IPv4 (hardware
 *                             type 1, protocol 0x0800, address lengths 6 and
 *                             4).
 * @retval BNT_ERR_TRUNC       the write falls outside the packet.
 */
static __always_inline int bnt_arp__set_tpa(bnt_arp *arp, __be32 tpa)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!arp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_arp_set_tpa)(arp->__ctx, arp->__off, tpa);
#else
    struct __bnt_arp_meta meta;
    int ret;

    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_arp_meta_dispatch(arp, &meta);
    if (ret)
        return ret;
    if (!__bnt_arp_is_eth_ipv4_meta(&meta))
        return BNT_ERR_UNSUPPORTED;
    return __bnt_write_be32(arp->__ctx, __bnt_arp_tpa_off(arp, &meta), tpa);
#endif
}

/*
 * MPLS Label Switching: parse, navigation, getters, setters.
 *
 * An MPLS Label Stack Entry (LSE) is a 32-bit big-endian word:
 *   bits 31-12: label (20 bits)
 *   bits  11-9: TC / EXP (3 bits)
 *   bit      8: S — bottom-of-stack flag
 *   bits   7-0: TTL
 */

/**
 * @ingroup bnt_mpls
 * @brief Initializes an MPLS label view at the given packet offset.
 *
 * Records the position only; the label is read and bounds-checked on each
 * later access.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param off Byte offset of the MPLS label.
 * @param m   View initialized on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m is NULL.
 * @retval BNT_ERR_TRUNC   the label falls outside the packet.
 */
static __always_inline int bnt_mpls__parse(BNT_CTX_TYPE *ctx, __u32 off, bnt_mpls *m)
{
    if (!m)
        return BNT_ERR_BAD_ARG;
    if (__bnt_bounds(ctx, off, 4))
        return BNT_ERR_TRUNC;
    m->__ctx = ctx;
    m->__off = off;
    return BNT_OK;
}

/**
 * @ingroup bnt_mpls
 * @brief Returns the offset immediately after this label.
 *
 * @param m   Parsed MPLS view.
 * @param out Byte offset following the label on success.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the resulting offset exceeds the representable range.
 */
static __always_inline int bnt_mpls__next_off(const bnt_mpls *m, __u32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!m)
        return BNT_ERR_BAD_ARG;
    return __bnt_off_ret(m->__off + 4, BNT_OFF_BOUND_L3, out);
}

static __always_inline int __bnt_mpls__read_lse(const bnt_mpls *m, __be32 *lse)
{
    *lse = 0;
    return __bnt_read_be32(m->__ctx, m->__off, lse);
}

/** @ingroup bnt_mpls
 *  Reads the 20-bit MPLS label into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_mpls__get_label(const bnt_mpls *m, __u32 *out)
{
    __be32 lse;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    *out = bpf_ntohl(lse) >> 12;
    return BNT_OK;
}

/** @ingroup bnt_mpls
 *  Reads the 3-bit TC (traffic class / EXP) field into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_mpls__get_tc(const bnt_mpls *m, __u8 *out)
{
    __be32 lse;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    *out = (__u8)((bpf_ntohl(lse) >> 9) & 0x7u);
    return BNT_OK;
}

/** @ingroup bnt_mpls
 *  Reads the 8-bit TTL field into @p out.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_mpls__get_ttl(const bnt_mpls *m, __u8 *out)
{
    __be32 lse;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    *out = (__u8)(bpf_ntohl(lse) & 0xffu);
    return BNT_OK;
}

/** @ingroup bnt_mpls
 *  Sets @p out to true if the BOS (bottom-of-stack) bit is set.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m or @p out is NULL.
 * @retval BNT_ERR_TRUNC   the read falls outside the packet.
 */
static __always_inline int bnt_mpls__is_bos(const bnt_mpls *m, bool *out)
{
    __be32 lse;
    int ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    *out = !!(bpf_ntohl(lse) & (1u << 8));
    return BNT_OK;
}

/** @ingroup bnt_mpls
 *  Writes a new 20-bit label value (preserving TC, BOS, TTL); @p label must
 *  fit in 20 bits.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m is NULL, or @p label exceeds 20 bits.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_mpls__set_label(bnt_mpls *m, __u32 label)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!m || label > 0xFFFFFu)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_mpls_set_lse)(m->__ctx, m->__off, 0xfffff000u, label << 12);
#else
    __be32 lse;
    __u32 v;
    int ret;

    if (!m || label > 0xFFFFFu)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    v = (bpf_ntohl(lse) & 0x00000FFFu) | (label << 12);
    lse = bpf_htonl(v);
    return __bnt_write_be32(m->__ctx, m->__off, lse);
#endif
}

/** @ingroup bnt_mpls
 *  Writes a new 3-bit TC value (preserving label, BOS, TTL).
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_mpls__set_tc(bnt_mpls *m, __u8 tc)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!m)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_mpls_set_lse)(m->__ctx, m->__off, 0x00000e00u, (__u32)(tc & 0x7u) << 9);
#else
    __be32 lse;
    __u32 v;
    int ret;

    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    v = (bpf_ntohl(lse) & ~0xE00u) | ((__u32)(tc & 0x7u) << 9);
    lse = bpf_htonl(v);
    return __bnt_write_be32(m->__ctx, m->__off, lse);
#endif
}

/** @ingroup bnt_mpls
 *  Writes a new TTL value (preserving label, TC, BOS).
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_mpls__set_ttl(bnt_mpls *m, __u8 ttl)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!m)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_mpls_set_lse)(m->__ctx, m->__off, 0x000000ffu, ttl);
#else
    __be32 lse;
    __u32 v;
    int ret;

    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    v = (bpf_ntohl(lse) & 0xFFFFFF00u) | (__u32)ttl;
    lse = bpf_htonl(v);
    return __bnt_write_be32(m->__ctx, m->__off, lse);
#endif
}

/** @ingroup bnt_mpls
 *  Sets or clears the BOS bit (preserving label, TC, TTL).
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p m is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_mpls__set_bos(bnt_mpls *m, bool bos)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!m)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_mpls_set_lse)(m->__ctx, m->__off, 0x00000100u, bos ? 0x100u : 0);
#else
    __be32 lse;
    __u32 v;
    int ret;

    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_mpls__read_lse(m, &lse);
    if (ret)
        return ret;
    v = bpf_ntohl(lse);
    if (bos)
        v |= (1u << 8);
    else
        v &= ~(1u << 8);
    lse = bpf_htonl(v);
    return __bnt_write_be32(m->__ctx, m->__off, lse);
#endif
}

/**
 * @ingroup bnt_eth
 * @brief Parses the MPLS label following Ethernet and any VLAN tags.
 *
 * @param eth Parsed Ethernet view.
 * @param m   Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p eth or @p m is NULL.
 * @retval BNT_ERR_TRUNC     a header on the VLAN stack or the label is truncated.
 * @retval BNT_ERR_BAD_PROTO the final EtherType is not ETH_P_MPLS_UC or
 *                           ETH_P_MPLS_MC.
 * @retval BNT_ERR_TOO_DEEP  the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) is
 *                           exhausted (see @ref limits).
 */
static __always_inline int bnt_eth__next_mpls(const bnt_eth *eth, bnt_mpls *m)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0;
    int ret;

    if (!m || !eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(eth->__ctx, eth->__off, &info);
    if (ret)
        return ret;
    if ((info & 0xffff) != ETH_P_MPLS_UC && (info & 0xffff) != ETH_P_MPLS_MC)
        return BNT_ERR_BAD_PROTO;
    return bnt_mpls__parse(eth->__ctx, eth->__off + ((info >> 16) & 0xff), m);
#else
    struct __bnt_eth_meta meta;
    int ret;

    if (!m)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_MPLS_UC && meta.proto != ETH_P_MPLS_MC)
        return BNT_ERR_BAD_PROTO;
    return bnt_mpls__parse(eth->__ctx, eth->__off + meta.hlen, m);
#endif
}

/**
 * @ingroup bnt_mpls
 * @brief Parses the next MPLS label in the stack.
 *
 * @param m    Parsed MPLS view.
 * @param next Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p m or @p next is NULL.
 * @retval BNT_ERR_TRUNC     the label falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO @p m has the BOS bit set.
 */
static __always_inline int bnt_mpls__next_mpls(const bnt_mpls *m, bnt_mpls *next)
{
    bool bos;
    int ret;

    if (!m || !next)
        return BNT_ERR_BAD_ARG;
    ret = bnt_mpls__is_bos(m, &bos);
    if (ret)
        return ret;
    if (bos)
        return BNT_ERR_BAD_PROTO;
    return bnt_mpls__parse(m->__ctx, m->__off + 4, next);
}

/**
 * @ingroup bnt_mpls
 * @brief Parses the IPv4 header following the bottom of the MPLS label stack.
 *
 * @param m   Parsed MPLS view.
 * @param ip4 Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p m or @p ip4 is NULL.
 * @retval BNT_ERR_TRUNC     the label or the IPv4 header falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO @p m does not have the BOS bit set, or the
 *                           payload is not IPv4.
 */
static __always_inline int bnt_mpls__next_ipv4(const bnt_mpls *m, bnt_ipv4 *ip4)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    int ret;

    if (!m || !ip4)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_mpls_next_ip)(m->__ctx, m->__off, 4);
    if (ret)
        return ret;
    return __bnt_header_set(ip4, m->__ctx, m->__off + 4);
#else
    bool bos;
    __u8 nibble = 0;
    __u32 off;
    int ret;

    if (!m || !ip4)
        return BNT_ERR_BAD_ARG;
    ret = bnt_mpls__is_bos(m, &bos);
    if (ret)
        return ret;
    if (!bos)
        return BNT_ERR_BAD_PROTO;
    off = m->__off + 4;
    ret = __bnt_read_u8(m->__ctx, off, &nibble);
    if (ret)
        return ret;
    if ((nibble >> 4) != 4)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(ip4, m->__ctx, off);
#endif
}

/**
 * @ingroup bnt_mpls
 * @brief Parses the IPv6 header following the bottom of the MPLS label stack.
 *
 * @param m   Parsed MPLS view.
 * @param ip6 Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p m or @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC     the label or the IPv6 header falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO @p m does not have the BOS bit set, or the
 *                           payload is not IPv6.
 */
static __always_inline int bnt_mpls__next_ipv6(const bnt_mpls *m, bnt_ipv6 *ip6)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    int ret;

    if (!m || !ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_mpls_next_ip)(m->__ctx, m->__off, 6);
    if (ret)
        return ret;
    return __bnt_header_set(ip6, m->__ctx, m->__off + 4);
#else
    bool bos;
    __u8 nibble = 0;
    __u32 off;
    int ret;

    if (!m || !ip6)
        return BNT_ERR_BAD_ARG;
    ret = bnt_mpls__is_bos(m, &bos);
    if (ret)
        return ret;
    if (!bos)
        return BNT_ERR_BAD_PROTO;
    off = m->__off + 4;
    ret = __bnt_read_u8(m->__ctx, off, &nibble);
    if (ret)
        return ret;
    if ((nibble >> 4) != 6)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(ip6, m->__ctx, off);
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Parses the inner IPv4 header of an IPv4-in-IPv4 tunnel.
 *
 * @param ip    Parsed outer IPv4 view.
 * @param inner Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p inner is NULL.
 * @retval BNT_ERR_TRUNC     the outer or inner IPv4 header is truncated.
 * @retval BNT_ERR_BAD_PROTO the outer header is malformed, or its protocol is
 *                           not IPPROTO_IPIP.
 * @retval BNT_ERR_FRAGMENT  the outer packet is a non-first fragment.
 */
static __always_inline int bnt_ipv4__next_ipv4(const bnt_ipv4 *ip, bnt_ipv4 *inner)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!inner || !ip)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv4_next_proto_off)(ip->__ctx, ip->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_IPIP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(inner, ip->__ctx, next);
#else
    struct __bnt_ipv4_meta meta;
    int ret;

    if (!inner)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv4_meta_dispatch(ip, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.protocol != IPPROTO_IPIP)
        return BNT_ERR_BAD_PROTO;

    return __bnt_header_set(inner, ip->__ctx, meta.next_off);
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Parses the inner IPv6 header of an IPv6-in-IPv4 tunnel.
 *
 * @param ip    Parsed outer IPv4 view.
 * @param inner Destination IPv6 view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p inner is NULL.
 * @retval BNT_ERR_TRUNC     the outer IPv4 header is truncated.
 * @retval BNT_ERR_BAD_PROTO the outer header is malformed, or its protocol is
 *                           not IPPROTO_IPV6.
 * @retval BNT_ERR_FRAGMENT  the outer packet is a non-first fragment.
 */
static __always_inline int bnt_ipv4__next_ipv6(const bnt_ipv4 *ip, bnt_ipv6 *inner)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!inner || !ip)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv4_next_proto_off)(ip->__ctx, ip->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_IPV6)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(inner, ip->__ctx, next);
#else
    struct __bnt_ipv4_meta meta;
    int ret;

    if (!inner)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv4_meta_dispatch(ip, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.protocol != IPPROTO_IPV6)
        return BNT_ERR_BAD_PROTO;

    return __bnt_header_set(inner, ip->__ctx, meta.next_off);
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Parses the inner IPv4 header of an IPv4-in-IPv6 tunnel.
 *
 * @param ip6   Parsed outer IPv6 view.
 * @param inner Destination IPv4 view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p inner is NULL.
 * @retval BNT_ERR_TRUNC     a header on the outer chain or the inner IPv4
 *                           header is truncated.
 * @retval BNT_ERR_BAD_PROTO the outer header is malformed, or its resolved
 *                           upper-layer protocol is not IPPROTO_IPIP.
 * @retval BNT_ERR_TOO_DEEP  the outer extension header chain exceeds
 *                           @c BNT_MAX_IPV6_EXT_DEPTH (see @ref limits).
 * @retval BNT_ERR_FRAGMENT  the outer packet is a non-first fragment.
 */
static __always_inline int bnt_ipv6__next_ipv4(const bnt_ipv6 *ip6, bnt_ipv4 *inner)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!inner || !ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv6_next_proto_off)(ip6->__ctx, ip6->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_IPIP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(inner, ip6->__ctx, next);
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!inner)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.l4_proto != IPPROTO_IPIP)
        return BNT_ERR_BAD_PROTO;

    return __bnt_header_set(inner, ip6->__ctx, meta.next_off);
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Parses the inner IPv6 header of an IPv6-in-IPv6 tunnel.
 *
 * @param ip6   Parsed outer IPv6 view.
 * @param inner Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p inner is NULL.
 * @retval BNT_ERR_TRUNC     a header on the outer chain is truncated.
 * @retval BNT_ERR_BAD_PROTO the outer header is malformed, or its resolved
 *                           upper-layer protocol is not IPPROTO_IPV6.
 * @retval BNT_ERR_TOO_DEEP  the outer extension header chain exceeds
 *                           @c BNT_MAX_IPV6_EXT_DEPTH (see @ref limits).
 * @retval BNT_ERR_FRAGMENT  the outer packet is a non-first fragment.
 */
static __always_inline int bnt_ipv6__next_ipv6(const bnt_ipv6 *ip6, bnt_ipv6 *inner)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!inner || !ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv6_next_proto_off)(ip6->__ctx, ip6->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_IPV6)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(inner, ip6->__ctx, next);
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!inner)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.l4_proto != IPPROTO_IPV6)
        return BNT_ERR_BAD_PROTO;

    return __bnt_header_set(inner, ip6->__ctx, meta.next_off);
#endif
}

/*
 * Typed next-header helpers.
 *
 * The bnt_*__next_<type>() functions check that the protocol advertised by
 * the source header matches the requested destination view, then initialize the
 * destination view at the correct offset. A protocol mismatch returns
 * BNT_ERR_BAD_PROTO. Non-first fragments return BNT_ERR_FRAGMENT because the
 * advertised L4 protocol is not present at a parsable offset in that packet.
 *
 * The bnt_*__next_header(src, dst) macros below dispatch at compile time from
 * the type pointed to by dst, so callers can write:
 *
 *     bnt_eth__next_header(&eth, &ip4);
 *     bnt_ipv4__next_header(&ip4, &tcp);
 *     bnt_ipv6__next_header(&ip6, &udp);
 */
static __always_inline int __bnt_next_header_unsupported(const void *src, const void *dst)
{
    if (!src || !dst)
        return BNT_ERR_BAD_ARG;
    return BNT_ERR_UNSUPPORTED;
}

/**
 * @ingroup bnt_eth
 * @brief Parses the IPv4 header following Ethernet and any VLAN tags.
 *
 * @param eth Parsed Ethernet view.
 * @param ip4 Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p eth or @p ip4 is NULL.
 * @retval BNT_ERR_TRUNC     a header on the VLAN stack is truncated.
 * @retval BNT_ERR_BAD_PROTO the final EtherType is not ETH_P_IP.
 * @retval BNT_ERR_TOO_DEEP  the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) is
 *                           exhausted (see @ref limits).
 */
static __always_inline int bnt_eth__next_ipv4(const bnt_eth *eth, bnt_ipv4 *ip4)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0;
    int ret;

    if (!ip4 || !eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(eth->__ctx, eth->__off, &info);
    if (ret)
        return ret;
    if ((info & 0xffff) != ETH_P_IP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(ip4, eth->__ctx, eth->__off + ((info >> 16) & 0xff));
#else
    struct __bnt_eth_meta meta;
    int ret;

    if (!ip4)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IP)
        return BNT_ERR_BAD_PROTO;

    return __bnt_header_set(ip4, eth->__ctx, eth->__off + meta.hlen);
#endif
}

/**
 * @ingroup bnt_eth
 * @brief Parses the IPv6 header following Ethernet and any VLAN tags.
 *
 * @param eth Parsed Ethernet view.
 * @param ip6 Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p eth or @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC     a header on the VLAN stack is truncated.
 * @retval BNT_ERR_BAD_PROTO the final EtherType is not ETH_P_IPV6.
 * @retval BNT_ERR_TOO_DEEP  the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) is
 *                           exhausted (see @ref limits).
 */
static __always_inline int bnt_eth__next_ipv6(const bnt_eth *eth, bnt_ipv6 *ip6)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0;
    int ret;

    if (!ip6 || !eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(eth->__ctx, eth->__off, &info);
    if (ret)
        return ret;
    if ((info & 0xffff) != ETH_P_IPV6)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(ip6, eth->__ctx, eth->__off + ((info >> 16) & 0xff));
#else
    struct __bnt_eth_meta meta;
    int ret;

    if (!ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IPV6)
        return BNT_ERR_BAD_PROTO;

    return __bnt_header_set(ip6, eth->__ctx, eth->__off + meta.hlen);
#endif
}

/**
 * @ingroup bnt_eth
 * @brief Parses the ARP header following Ethernet and any VLAN tags.
 *
 * @param eth Parsed Ethernet view.
 * @param arp Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p eth or @p arp is NULL.
 * @retval BNT_ERR_TRUNC     a header on the VLAN stack is truncated.
 * @retval BNT_ERR_BAD_PROTO the final EtherType is not ETH_P_ARP.
 * @retval BNT_ERR_TOO_DEEP  the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) is
 *                           exhausted (see @ref limits).
 */
static __always_inline int bnt_eth__next_arp(const bnt_eth *eth, bnt_arp *arp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0;
    int ret;

    if (!arp || !eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(eth->__ctx, eth->__off, &info);
    if (ret)
        return ret;
    if ((info & 0xffff) != ETH_P_ARP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(arp, eth->__ctx, eth->__off + ((info >> 16) & 0xff));
#else
    struct __bnt_eth_meta meta;
    int ret;

    if (!arp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_ARP)
        return BNT_ERR_BAD_PROTO;

    return __bnt_header_set(arp, eth->__ctx, eth->__off + meta.hlen);
#endif
}

static __always_inline int __bnt_ipv4__next_l4_off(const bnt_ipv4 *ip, __u8 protocol,
                                                    __u32 *off)
{
    struct __bnt_ipv4_meta meta;
    int ret;

    if (!off)
        return BNT_ERR_BAD_ARG;
    *off = 0;

    ret = __bnt_ipv4_meta_dispatch(ip, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.protocol != protocol)
        return BNT_ERR_BAD_PROTO;

    *off = meta.next_off;
    return BNT_OK;
}

/**
 * @ingroup bnt_ipv4
 * @brief Parses the TCP header following IPv4.
 *
 * @param ip  Parsed IPv4 view.
 * @param tcp Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p tcp is NULL.
 * @retval BNT_ERR_TRUNC     the IPv4 or TCP header is truncated.
 * @retval BNT_ERR_BAD_PROTO the IPv4 header is malformed, or its protocol is
 *                           not IPPROTO_TCP.
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv4__next_tcp(const bnt_ipv4 *ip, bnt_tcp *tcp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!tcp || !ip)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv4_next_proto_off)(ip->__ctx, ip->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_TCP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(tcp, ip->__ctx, next);
#else
    __u32 off;
    int ret;

    if (!tcp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv4__next_l4_off(ip, IPPROTO_TCP, &off);
    if (ret)
        return ret;

    return __bnt_header_set(tcp, ip->__ctx, off);
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Parses the UDP header following IPv4.
 *
 * @param ip  Parsed IPv4 view.
 * @param udp Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p udp is NULL.
 * @retval BNT_ERR_TRUNC     the IPv4 or UDP header is truncated.
 * @retval BNT_ERR_BAD_PROTO the IPv4 header is malformed, or its protocol is
 *                           not IPPROTO_UDP.
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv4__next_udp(const bnt_ipv4 *ip, bnt_udp *udp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!udp || !ip)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv4_next_proto_off)(ip->__ctx, ip->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_UDP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(udp, ip->__ctx, next);
#else
    __u32 off;
    int ret;

    if (!udp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv4__next_l4_off(ip, IPPROTO_UDP, &off);
    if (ret)
        return ret;

    return __bnt_header_set(udp, ip->__ctx, off);
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Parses the ICMPv4 header following IPv4.
 *
 * @param ip   Parsed IPv4 view.
 * @param icmp Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip or @p icmp is NULL.
 * @retval BNT_ERR_TRUNC     the IPv4 or ICMPv4 header is truncated.
 * @retval BNT_ERR_BAD_PROTO the IPv4 header is malformed, or its protocol is
 *                           not IPPROTO_ICMP.
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv4__next_icmp4(const bnt_ipv4 *ip, bnt_icmp4 *icmp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!icmp || !ip)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv4_next_proto_off)(ip->__ctx, ip->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_ICMP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(icmp, ip->__ctx, next);
#else
    __u32 off;
    int ret;

    if (!icmp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv4__next_l4_off(ip, IPPROTO_ICMP, &off);
    if (ret)
        return ret;

    return __bnt_header_set(icmp, ip->__ctx, off);
#endif
}

static __always_inline int __bnt_ipv6__next_l4_off(const bnt_ipv6 *ip6, __u8 protocol,
                                                    __u32 *off)
{
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!off)
        return BNT_ERR_BAD_ARG;
    *off = 0;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.l4_proto != protocol)
        return BNT_ERR_BAD_PROTO;

    *off = meta.next_off;
    return BNT_OK;
}

/**
 * @ingroup bnt_ipv6
 * @brief Parses the TCP header following IPv6, walking past any extension headers.
 *
 * @param ip6 Parsed IPv6 view.
 * @param tcp Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p tcp is NULL.
 * @retval BNT_ERR_TRUNC     a header on the chain or the TCP header is truncated.
 * @retval BNT_ERR_BAD_PROTO the IPv6 header is malformed, or its resolved
 *                           upper-layer protocol is not IPPROTO_TCP.
 * @retval BNT_ERR_TOO_DEEP  the extension header chain exceeds
 *                           @c BNT_MAX_IPV6_EXT_DEPTH (see @ref limits).
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv6__next_tcp(const bnt_ipv6 *ip6, bnt_tcp *tcp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!tcp || !ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv6_next_proto_off)(ip6->__ctx, ip6->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_TCP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(tcp, ip6->__ctx, next);
#else
    __u32 off;
    int ret;

    if (!tcp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv6__next_l4_off(ip6, IPPROTO_TCP, &off);
    if (ret)
        return ret;

    return __bnt_header_set(tcp, ip6->__ctx, off);
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Parses the UDP header following IPv6, walking past any extension headers.
 *
 * @param ip6 Parsed IPv6 view.
 * @param udp Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p udp is NULL.
 * @retval BNT_ERR_TRUNC     a header on the chain or the UDP header is truncated.
 * @retval BNT_ERR_BAD_PROTO the IPv6 header is malformed, or its resolved
 *                           upper-layer protocol is not IPPROTO_UDP.
 * @retval BNT_ERR_TOO_DEEP  the extension header chain exceeds
 *                           @c BNT_MAX_IPV6_EXT_DEPTH (see @ref limits).
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv6__next_udp(const bnt_ipv6 *ip6, bnt_udp *udp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!udp || !ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv6_next_proto_off)(ip6->__ctx, ip6->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_UDP)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(udp, ip6->__ctx, next);
#else
    __u32 off;
    int ret;

    if (!udp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv6__next_l4_off(ip6, IPPROTO_UDP, &off);
    if (ret)
        return ret;

    return __bnt_header_set(udp, ip6->__ctx, off);
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Parses the ICMPv6 header following IPv6, walking past any extension headers.
 *
 * @param ip6  Parsed IPv6 view.
 * @param icmp Destination view initialized on success.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p icmp is NULL.
 * @retval BNT_ERR_TRUNC     a header on the chain or the ICMPv6 header is truncated.
 * @retval BNT_ERR_BAD_PROTO the IPv6 header is malformed, or its resolved
 *                           upper-layer protocol is not IPPROTO_ICMPV6.
 * @retval BNT_ERR_TOO_DEEP  the extension header chain exceeds
 *                           @c BNT_MAX_IPV6_EXT_DEPTH (see @ref limits).
 * @retval BNT_ERR_FRAGMENT  the packet is a non-first fragment.
 */
static __always_inline int bnt_ipv6__next_icmp6(const bnt_ipv6 *ip6, bnt_icmp6 *icmp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!icmp || !ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv6_next_proto_off)(ip6->__ctx, ip6->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto != IPPROTO_ICMPV6)
        return BNT_ERR_BAD_PROTO;
    return __bnt_header_set(icmp, ip6->__ctx, next);
#else
    __u32 off;
    int ret;

    if (!icmp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ipv6__next_l4_off(ip6, IPPROTO_ICMPV6, &off);
    if (ret)
        return ret;

    return __bnt_header_set(icmp, ip6->__ctx, off);
#endif
}

#define __BNT_TERMINAL_NEXT_HEADER(src, dst)                                      \
    _Generic((dst),                                                               \
        bnt_eth *: __bnt_next_header_unsupported,                               \
        bnt_ipv4 *: __bnt_next_header_unsupported,                              \
        bnt_ipv6 *: __bnt_next_header_unsupported,                              \
        bnt_tcp *: __bnt_next_header_unsupported,                               \
        bnt_udp *: __bnt_next_header_unsupported,                               \
        bnt_icmp4 *: __bnt_next_header_unsupported,                             \
        bnt_icmp6 *: __bnt_next_header_unsupported,                             \
        bnt_arp *: __bnt_next_header_unsupported,                               \
        bnt_mpls *: __bnt_next_header_unsupported                               \
    )((src), (dst))

/** @ingroup bnt_eth
 *  Dispatches to bnt_eth__next_ipv4(), _ipv6(), _arp(), or _mpls(). */
#define bnt_eth__next_header(src, dst)                                           \
    _Generic((dst),                                                               \
        bnt_ipv4 *: bnt_eth__next_ipv4,                                         \
        bnt_ipv6 *: bnt_eth__next_ipv6,                                         \
        bnt_arp *: bnt_eth__next_arp,                                           \
        bnt_mpls *: bnt_eth__next_mpls,                                         \
        bnt_eth *: __bnt_next_header_unsupported,                               \
        bnt_tcp *: __bnt_next_header_unsupported,                               \
        bnt_udp *: __bnt_next_header_unsupported,                               \
        bnt_icmp4 *: __bnt_next_header_unsupported,                             \
        bnt_icmp6 *: __bnt_next_header_unsupported                              \
    )((src), (dst))

/** @ingroup bnt_ipv4
 *  Dispatches to bnt_ipv4__next_tcp(), _udp(), _icmp4(), _ipv4(), or _ipv6(). */
#define bnt_ipv4__next_header(src, dst)                                          \
    _Generic((dst),                                                               \
        bnt_tcp *: bnt_ipv4__next_tcp,                                          \
        bnt_udp *: bnt_ipv4__next_udp,                                          \
        bnt_icmp4 *: bnt_ipv4__next_icmp4,                                      \
        bnt_ipv4 *: bnt_ipv4__next_ipv4,                                        \
        bnt_ipv6 *: bnt_ipv4__next_ipv6,                                        \
        bnt_eth *: __bnt_next_header_unsupported,                               \
        bnt_icmp6 *: __bnt_next_header_unsupported,                             \
        bnt_arp *: __bnt_next_header_unsupported,                               \
        bnt_mpls *: __bnt_next_header_unsupported                               \
    )((src), (dst))

/** @ingroup bnt_ipv6
 *  Dispatches to bnt_ipv6__next_tcp(), _udp(), _icmp6(), _ipv4(), or _ipv6(). */
#define bnt_ipv6__next_header(src, dst)                                          \
    _Generic((dst),                                                               \
        bnt_tcp *: bnt_ipv6__next_tcp,                                          \
        bnt_udp *: bnt_ipv6__next_udp,                                          \
        bnt_icmp6 *: bnt_ipv6__next_icmp6,                                      \
        bnt_ipv4 *: bnt_ipv6__next_ipv4,                                        \
        bnt_ipv6 *: bnt_ipv6__next_ipv6,                                        \
        bnt_eth *: __bnt_next_header_unsupported,                               \
        bnt_icmp4 *: __bnt_next_header_unsupported,                             \
        bnt_arp *: __bnt_next_header_unsupported,                               \
        bnt_mpls *: __bnt_next_header_unsupported                               \
    )((src), (dst))

/** @ingroup bnt_mpls
 *  Dispatches to bnt_mpls__next_mpls(), _ipv4(), or _ipv6(). */
#define bnt_mpls__next_header(src, dst)                                          \
    _Generic((dst),                                                               \
        bnt_mpls *: bnt_mpls__next_mpls,                                        \
        bnt_ipv4 *: bnt_mpls__next_ipv4,                                        \
        bnt_ipv6 *: bnt_mpls__next_ipv6,                                        \
        bnt_eth *: __bnt_next_header_unsupported,                               \
        bnt_tcp *: __bnt_next_header_unsupported,                               \
        bnt_udp *: __bnt_next_header_unsupported,                               \
        bnt_icmp4 *: __bnt_next_header_unsupported,                             \
        bnt_icmp6 *: __bnt_next_header_unsupported,                             \
        bnt_arp *: __bnt_next_header_unsupported                                \
    )((src), (dst))

/** @ingroup bnt_tcp
 *  Terminal header types have no supported next typed header in bnt. */
#define bnt_tcp__next_header(src, dst) __BNT_TERMINAL_NEXT_HEADER(src, dst)
/** @ingroup bnt_udp
 *  Terminal header types have no supported next typed header in bnt. */
#define bnt_udp__next_header(src, dst) __BNT_TERMINAL_NEXT_HEADER(src, dst)
/** @ingroup bnt_icmp4
 *  Terminal header types have no supported next typed header in bnt. */
#define bnt_icmp4__next_header(src, dst) __BNT_TERMINAL_NEXT_HEADER(src, dst)
/** @ingroup bnt_icmp6
 *  Terminal header types have no supported next typed header in bnt. */
#define bnt_icmp6__next_header(src, dst) __BNT_TERMINAL_NEXT_HEADER(src, dst)
/** @ingroup bnt_arp
 *  Terminal header types have no supported next typed header in bnt. */
#define bnt_arp__next_header(src, dst) __BNT_TERMINAL_NEXT_HEADER(src, dst)

/*
 * High-level ctx find helpers.
 *
 * These helpers are an optional convenience layer over the explicit parser and
 * typed next-header APIs. They start at Ethernet offset 0 and walk only the
 * packet stacks currently supported by bnt.
 *
 * Supported paths:
 *   - Ethernet -> VLAN* -> MPLS                         (find_mpls, first label only)
 *   - Ethernet -> VLAN* -> IPv4                         (find_ipv4)
 *   - Ethernet -> VLAN* -> IPv6                         (find_ipv6)
 *   - Ethernet -> VLAN* -> ARP                          (find_arp)
 *   - Ethernet -> VLAN* -> IPv4/IPv6 -> TCP/UDP/ICMPv4/ICMPv6 (find_tcp/udp/icmp4/icmp6)
 *
 * No walker here looks through MPLS to an inner IP header or through an IP
 * tunnel (IPPROTO_IPIP / IPPROTO_IPV6) to the next IP level; an MPLS or
 * tunneled stack past the first header is BNT_ERR_UNSUPPORTED here. IPv6
 * extension headers within the one IP level are walked by __bnt_ipv6_meta and
 * bounded by BNT_MAX_IPV6_EXT_DEPTH.
 *
 * VLAN traversal bounded by BNT_MAX_VLAN_DEPTH. Unsupported valid stacks
 * return BNT_ERR_UNSUPPORTED. Wrong-protocol matches return BNT_ERR_BAD_PROTO.
 * Depth exhaustion returns BNT_ERR_TOO_DEEP.
 */
static __always_inline int __bnt_ctx__eth_meta(BNT_CTX_TYPE *ctx,
                                                bnt_eth *eth,
                                                struct __bnt_eth_meta *meta)
{
    int ret;

    if (!eth || !meta)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_header_set(eth, ctx, 0);
    if (ret)
        return ret;

    return __bnt_eth_meta_dispatch(eth, meta);
}

/* meta.proto is never a VLAN TPID here: __bnt_eth_meta_dispatch() already
 * turns VLAN-walk exhaustion into BNT_ERR_TOO_DEEP before returning. */
static __always_inline int __bnt_ctx__l3_mismatch(__u16 proto)
{
    if (proto == ETH_P_IP || proto == ETH_P_IPV6 || proto == ETH_P_ARP ||
        proto == ETH_P_MPLS_UC || proto == ETH_P_MPLS_MC)
        return BNT_ERR_BAD_PROTO;
    return BNT_ERR_UNSUPPORTED;
}

static __always_inline int __bnt_ctx__ipv4_l4_mismatch(__u8 protocol)
{
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP)
        return BNT_ERR_BAD_PROTO;
    return BNT_ERR_UNSUPPORTED;
}

static __always_inline int __bnt_ctx__ipv6_l4_mismatch(__u8 protocol)
{
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMPV6)
        return BNT_ERR_BAD_PROTO;
    return BNT_ERR_UNSUPPORTED;
}

static __always_inline int __bnt_ctx__ipv4_l4_off(const bnt_ipv4 *ip4, __u8 protocol,
                                                   __u32 *off)
{
    struct __bnt_ipv4_meta meta;
    int ret;

    if (!off)
        return BNT_ERR_BAD_ARG;
    *off = 0;

    ret = __bnt_ipv4_meta_dispatch(ip4, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.protocol != protocol)
        return __bnt_ctx__ipv4_l4_mismatch(meta.protocol);

    *off = meta.next_off;
    return BNT_OK;
}

static __always_inline int __bnt_ctx__ipv6_l4_off(const bnt_ipv6 *ip6, __u8 protocol,
                                                   __u32 *off)
{
    struct __bnt_ipv6_meta meta;
    int ret;

    if (!off)
        return BNT_ERR_BAD_ARG;
    *off = 0;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;
    if (meta.l4_proto != protocol)
        return __bnt_ctx__ipv6_l4_mismatch(meta.l4_proto);

    *off = meta.next_off;
    return BNT_OK;
}

static __always_inline int __bnt_ctx__validate_ipv4(const bnt_ipv4 *ip4)
{
    struct __bnt_ipv4_meta meta;

    return __bnt_ipv4_meta_dispatch(ip4, &meta);
}

static __always_inline int __bnt_ctx__validate_ipv6_base(const bnt_ipv6 *ip6)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    const struct ipv6hdr *h;
#else
    struct ipv6hdr h;
#endif
    __u8 first;
    int ret;

    if (!ip6)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    /* Bound the whole header, read only the version byte (no header copy). */
    ret = __bnt_data_ptr(ip6->__ctx, ip6->__off, sizeof(*h), (void **)&h);
    if (ret)
        return ret;
    first = *(const __u8 *)h;
#else
    ret = __bnt_read(ip6->__ctx, ip6->__off, &h, sizeof(h));
    if (ret)
        return ret;

    first = *(__u8 *)&h;
#endif
    if ((first >> 4) != 6)
        return BNT_ERR_BAD_PROTO;

    return BNT_OK;
}

static __always_inline int __bnt_ctx__validate_tcp(const bnt_tcp *tcp)
{
    __u32 next_off;

    return bnt_tcp__next_off(tcp, &next_off);
}

static __always_inline int __bnt_ctx__validate_udp(const bnt_udp *udp)
{
    __u16 len;
    int ret;

    if (!udp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_bounds(udp->__ctx, udp->__off, sizeof(struct udphdr));
    if (ret)
        return ret;

    ret = bnt_udp__get_len(udp, &len);
    if (ret)
        return ret;
    if (len < sizeof(struct udphdr))
        return BNT_ERR_BAD_PROTO;

    return BNT_OK;
}

static __always_inline int __bnt_ctx__validate_icmp4(const bnt_icmp4 *icmp)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_bounds(icmp->__ctx, icmp->__off, sizeof(struct bnt_icmp4_hdr));
}

static __always_inline int __bnt_ctx__validate_icmp6(const bnt_icmp6 *icmp)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __bnt_bounds(icmp->__ctx, icmp->__off, sizeof(struct icmp6hdr));
}

static __always_inline int __bnt_ctx__validate_arp(const bnt_arp *arp)
{
    __u32 next_off;

    return bnt_arp__next_off(arp, &next_off);
}


/* ── find_* globals ─────────────────────────────────────────────────────────
 *
 * Each global walks eth->L3->L4 and returns only the target header offset.
 * The inline wrapper then fills in (view->__ctx = ctx, view->__off = off) —
 * ctx is still PTR_TO_CTX in the caller's frame because it was never spilled
 * across a BPF call (the local copy pattern).
 */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ctx_find_ipv4(BNT_CTX_TYPE *ctx, __u32 *ip_off)
{
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    bnt_ipv4 ip4;
    int ret;

    if (!ip_off)
        return BNT_ERR_BAD_ARG;
    eth.__ctx = ctx;
    eth.__off = 0;
    ret = __bnt_api_eth_walk(ctx, 0, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IP)
        return __bnt_ctx__l3_mismatch(meta.proto);
    ip4.__ctx = ctx;
    ip4.__off = eth.__off + meta.hlen;
    {
        struct __bnt_ipv4_meta ip4meta;

        ret = __bnt_api_ipv4_meta(ctx, ip4.__off, &ip4meta);
    }
    if (ret)
        return ret;
    *ip_off = ip4.__off;
    return BNT_OK;
}
#endif

#ifdef BNT_XDP_H

__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_ipv4_g(BNT_CTX_TYPE *ctx, __u32 *ip_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_ipv4_g(BNT_CTX_TYPE *ctx, __u32 *ip_off)
{
    return __bnt_ctx_find_ipv4(ctx, ip_off);
}
#endif

static __always_inline int __bnt_ctx_find_ipv6(BNT_CTX_TYPE *ctx, __u32 *ip_off)
{
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    bnt_ipv6 ip6;
    int ret;

    if (!ip_off)
        return BNT_ERR_BAD_ARG;
    eth.__ctx = ctx;
    eth.__off = 0;
    ret = __bnt_api_eth_walk(ctx, 0, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IPV6)
        return __bnt_ctx__l3_mismatch(meta.proto);
    ip6.__ctx = ctx;
    ip6.__off = eth.__off + meta.hlen;
    ret = __bnt_ctx__validate_ipv6_base(&ip6);
    if (ret)
        return ret;
    *ip_off = ip6.__off;
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_ipv6_g(BNT_CTX_TYPE *ctx, __u32 *ip_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_ipv6_g(BNT_CTX_TYPE *ctx, __u32 *ip_off)
{
    return __bnt_ctx_find_ipv6(ctx, ip_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_ctx_find_tcp(BNT_CTX_TYPE *ctx, __u32 *tcp_off)
{
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    int ret;

    if (!tcp_off)
        return BNT_ERR_BAD_ARG;
    eth.__ctx = ctx;
    eth.__off = 0;
    ret = __bnt_api_eth_walk(ctx, 0, &meta);
    if (ret)
        return ret;

    if (meta.proto == ETH_P_IP) {
        bnt_ipv4 ip4;
        struct __bnt_ipv4_meta ip4meta;

        ip4.__ctx = ctx;
        ip4.__off = eth.__off + meta.hlen;
        ret = __bnt_api_ipv4_meta(ctx, ip4.__off, &ip4meta);
        if (ret) return ret;
        if (!ip4meta.l4_off_valid) return BNT_ERR_FRAGMENT;
        if (ip4meta.protocol != IPPROTO_TCP)
            return __bnt_ctx__ipv4_l4_mismatch(ip4meta.protocol);
        *tcp_off = ip4meta.next_off;
        return BNT_OK;
    }
    if (meta.proto == ETH_P_IPV6) {
        bnt_ipv6 ip6;
        struct __bnt_ipv6_meta ip6meta;

        ip6.__ctx = ctx;
        ip6.__off = eth.__off + meta.hlen;
        ret = __bnt_ipv6_meta(&ip6, &ip6meta);
        if (ret) return ret;
        if (!ip6meta.l4_off_valid) return BNT_ERR_FRAGMENT;
        if (ip6meta.l4_proto != IPPROTO_TCP)
            return __bnt_ctx__ipv6_l4_mismatch(ip6meta.l4_proto);
        *tcp_off = ip6meta.next_off;
        return BNT_OK;
    }
    return __bnt_ctx__l3_mismatch(meta.proto);
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_tcp_g(BNT_CTX_TYPE *ctx, __u32 *tcp_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_tcp_g(BNT_CTX_TYPE *ctx, __u32 *tcp_off)
{
    return __bnt_ctx_find_tcp(ctx, tcp_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_ctx_find_udp(BNT_CTX_TYPE *ctx, __u32 *udp_off)
{
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    int ret;

    if (!udp_off)
        return BNT_ERR_BAD_ARG;
    eth.__ctx = ctx;
    eth.__off = 0;
    ret = __bnt_api_eth_walk(ctx, 0, &meta);
    if (ret)
        return ret;

    if (meta.proto == ETH_P_IP) {
        bnt_ipv4 ip4;
        struct __bnt_ipv4_meta ip4meta;

        ip4.__ctx = ctx;
        ip4.__off = eth.__off + meta.hlen;
        ret = __bnt_api_ipv4_meta(ctx, ip4.__off, &ip4meta);
        if (ret) return ret;
        if (!ip4meta.l4_off_valid) return BNT_ERR_FRAGMENT;
        if (ip4meta.protocol != IPPROTO_UDP)
            return __bnt_ctx__ipv4_l4_mismatch(ip4meta.protocol);
        *udp_off = ip4meta.next_off;
        return BNT_OK;
    }
    if (meta.proto == ETH_P_IPV6) {
        bnt_ipv6 ip6;
        struct __bnt_ipv6_meta ip6meta;

        ip6.__ctx = ctx;
        ip6.__off = eth.__off + meta.hlen;
        ret = __bnt_ipv6_meta(&ip6, &ip6meta);
        if (ret) return ret;
        if (!ip6meta.l4_off_valid) return BNT_ERR_FRAGMENT;
        if (ip6meta.l4_proto != IPPROTO_UDP)
            return __bnt_ctx__ipv6_l4_mismatch(ip6meta.l4_proto);
        *udp_off = ip6meta.next_off;
        return BNT_OK;
    }
    return __bnt_ctx__l3_mismatch(meta.proto);
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_udp_g(BNT_CTX_TYPE *ctx, __u32 *udp_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_udp_g(BNT_CTX_TYPE *ctx, __u32 *udp_off)
{
    return __bnt_ctx_find_udp(ctx, udp_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_ctx_find_icmp4(BNT_CTX_TYPE *ctx, __u32 *icmp_off)
{
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    bnt_ipv4 ip4;
    struct __bnt_ipv4_meta ip4meta;
    int ret;

    if (!icmp_off)
        return BNT_ERR_BAD_ARG;
    eth.__ctx = ctx;
    eth.__off = 0;
    ret = __bnt_api_eth_walk(ctx, 0, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IP)
        return __bnt_ctx__l3_mismatch(meta.proto);
    ip4.__ctx = ctx;
    ip4.__off = eth.__off + meta.hlen;
    ret = __bnt_api_ipv4_meta(ctx, ip4.__off, &ip4meta);
    if (ret) return ret;
    if (!ip4meta.l4_off_valid) return BNT_ERR_FRAGMENT;
    if (ip4meta.protocol != IPPROTO_ICMP)
        return __bnt_ctx__ipv4_l4_mismatch(ip4meta.protocol);
    *icmp_off = ip4meta.next_off;
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_icmp4_g(BNT_CTX_TYPE *ctx, __u32 *icmp_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_icmp4_g(BNT_CTX_TYPE *ctx, __u32 *icmp_off)
{
    return __bnt_ctx_find_icmp4(ctx, icmp_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_ctx_find_icmp6(BNT_CTX_TYPE *ctx, __u32 *icmp_off)
{
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    bnt_ipv6 ip6;
    struct __bnt_ipv6_meta ip6meta;
    int ret;

    if (!icmp_off)
        return BNT_ERR_BAD_ARG;
    eth.__ctx = ctx;
    eth.__off = 0;
    ret = __bnt_api_eth_walk(ctx, 0, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_IPV6)
        return __bnt_ctx__l3_mismatch(meta.proto);
    ip6.__ctx = ctx;
    ip6.__off = eth.__off + meta.hlen;
    ret = __bnt_ipv6_meta(&ip6, &ip6meta);
    if (ret) return ret;
    if (!ip6meta.l4_off_valid) return BNT_ERR_FRAGMENT;
    if (ip6meta.l4_proto != IPPROTO_ICMPV6)
        return __bnt_ctx__ipv6_l4_mismatch(ip6meta.l4_proto);
    *icmp_off = ip6meta.next_off;
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_icmp6_g(BNT_CTX_TYPE *ctx, __u32 *icmp_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ctx_find_icmp6_g(BNT_CTX_TYPE *ctx, __u32 *icmp_off)
{
    return __bnt_ctx_find_icmp6(ctx, icmp_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_ipv4
 * @brief Finds the first IPv4 header reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> IPv4.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param ip4 Destination IPv4 view initialized on success.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p ip4 is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a supported L3 protocol is present but is not IPv4.
 * @retval BNT_ERR_UNSUPPORTED the stack is valid but outside this walker.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_ipv4(BNT_CTX_TYPE *ctx, bnt_ipv4 *ip4)
{
    if (!ip4)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ctx_find_ipv4)(ctx, &off);
        if (ret)
            return ret;
        ip4->__ctx = ctx;
        ip4->__off = off;
        return BNT_OK;
    }
#else
    {
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    int ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
    if (ret)
        return ret;

    if (meta.proto != ETH_P_IP)
        return __bnt_ctx__l3_mismatch(meta.proto);

    ret = __bnt_header_set(ip4, eth.__ctx, eth.__off + meta.hlen);
    if (ret)
        return ret;

    return __bnt_ctx__validate_ipv4(ip4);
    }
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Finds the first IPv6 header reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> IPv6. Validates the IPv6 base header only; extension
 * headers are walked by L4 helpers such as bnt_ctx__find_tcp(),
 * bnt_ctx__find_udp(), and bnt_ctx__find_icmp6().
 *
 * @param ctx Packet context for the active bnt backend.
 * @param ip6 Destination IPv6 view initialized on success.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a supported L3 protocol is present but is not IPv6.
 * @retval BNT_ERR_UNSUPPORTED the stack is valid but outside this walker.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_ipv6(BNT_CTX_TYPE *ctx, bnt_ipv6 *ip6)
{
    if (!ip6)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ctx_find_ipv6)(ctx, &off);
        if (ret)
            return ret;
        ip6->__ctx = ctx;
        ip6->__off = off;
        return BNT_OK;
    }
#else
    {
        struct __bnt_eth_meta meta;
        bnt_eth eth;
        int ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
        if (ret)
            return ret;

        if (meta.proto != ETH_P_IPV6)
            return __bnt_ctx__l3_mismatch(meta.proto);

        ret = __bnt_header_set(ip6, eth.__ctx, eth.__off + meta.hlen);
        if (ret)
            return ret;

        return __bnt_ctx__validate_ipv6_base(ip6);
    }
#endif
}

/**
 * @ingroup bnt_arp
 * @brief Finds the first ARP header reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> ARP.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param arp Destination ARP view initialized on success.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p arp is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a supported L3 protocol is present but is not ARP.
 * @retval BNT_ERR_UNSUPPORTED the stack is valid but outside this walker.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_arp(BNT_CTX_TYPE *ctx, bnt_arp *arp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 off = 0;
    int ret;

    if (!arp)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ctx_find_arp)(ctx, &off);
    if (ret)
        return ret;
    arp->__ctx = ctx;
    arp->__off = off;
    return BNT_OK;
#else
    struct __bnt_eth_meta meta;
    bnt_arp found;
    bnt_eth eth;
    int ret;

    if (!arp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_ARP)
        return __bnt_ctx__l3_mismatch(meta.proto);

    ret = __bnt_header_set(&found, eth.__ctx, eth.__off + meta.hlen);
    if (ret)
        return ret;
    ret = __bnt_ctx__validate_arp(&found);
    if (ret)
        return ret;
    *arp = found;
    return BNT_OK;
#endif
}

/**
 * @ingroup bnt_mpls
 * @brief Finds the first MPLS label reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> MPLS.
 *
 * @param ctx  Packet context for the active bnt backend.
 * @param mpls Destination view initialized on success (first label in the stack).
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p mpls is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a different known L3 protocol is present.
 * @retval BNT_ERR_UNSUPPORTED the stack is valid but outside this walker.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_mpls(BNT_CTX_TYPE *ctx, bnt_mpls *mpls)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0;
    int ret;

    if (!mpls)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(ctx, 0, &info);
    if (ret)
        return ret;
    if ((info & 0xffff) != ETH_P_MPLS_UC && (info & 0xffff) != ETH_P_MPLS_MC)
        return __bnt_ctx__l3_mismatch(info & 0xffff);
    return bnt_mpls__parse(ctx, (info >> 16) & 0xff, mpls);
#else
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    int ret;

    if (!mpls)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
    if (ret)
        return ret;
    if (meta.proto != ETH_P_MPLS_UC && meta.proto != ETH_P_MPLS_MC)
        return __bnt_ctx__l3_mismatch(meta.proto);

    return bnt_mpls__parse(eth.__ctx, eth.__off + meta.hlen, mpls);
#endif
}

/**
 * @ingroup bnt_tcp
 * @brief Finds the first TCP header reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> IPv4 -> TCP, and
 * Ethernet -> VLAN* -> IPv6 -> extension headers* -> TCP.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param tcp Destination TCP view initialized on success.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p tcp is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a supported stack reaches a different supported
 *                            protocol.
 * @retval BNT_ERR_UNSUPPORTED a valid L3/L4 stack is outside this walker.
 * @retval BNT_ERR_FRAGMENT   the packet is a non-first fragment.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) or
 *                            IPv6 extension walk (@c BNT_MAX_IPV6_EXT_DEPTH)
 *                            is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_tcp(BNT_CTX_TYPE *ctx, bnt_tcp *tcp)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ctx_find_tcp)(ctx, &off);
        if (ret)
            return ret;
        tcp->__ctx = ctx;
        tcp->__off = off;
        return BNT_OK;
    }
#else
    {
    struct __bnt_eth_meta meta;
    bnt_eth eth;
    int ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
    if (ret)
        return ret;

    if (meta.proto == ETH_P_IP) {
        bnt_ipv4 ip4;
        struct __bnt_ipv4_meta ip4meta;

        ret = __bnt_header_set(&ip4, eth.__ctx, eth.__off + meta.hlen);
        if (ret) return ret;
        ret = __bnt_ipv4_meta_dispatch(&ip4, &ip4meta);
        if (ret) return ret;
        if (!ip4meta.l4_off_valid)
            return BNT_ERR_FRAGMENT;
        if (ip4meta.protocol != IPPROTO_TCP)
            return __bnt_ctx__ipv4_l4_mismatch(ip4meta.protocol);
        ret = __bnt_header_set(tcp, eth.__ctx, ip4meta.next_off);
        if (ret) return ret;
        return __bnt_ctx__validate_tcp(tcp);
    }

    if (meta.proto == ETH_P_IPV6) {
        bnt_ipv6 ip6;
        struct __bnt_ipv6_meta ip6meta;

        ret = __bnt_header_set(&ip6, eth.__ctx, eth.__off + meta.hlen);
        if (ret) return ret;
        ret = __bnt_ipv6_meta(&ip6, &ip6meta);
        if (ret) return ret;
        if (!ip6meta.l4_off_valid)
            return BNT_ERR_FRAGMENT;
        if (ip6meta.l4_proto != IPPROTO_TCP)
            return __bnt_ctx__ipv6_l4_mismatch(ip6meta.l4_proto);
        ret = __bnt_header_set(tcp, eth.__ctx, ip6meta.next_off);
        if (ret) return ret;
        return __bnt_ctx__validate_tcp(tcp);
    }

    return __bnt_ctx__l3_mismatch(meta.proto);
    }
#endif
}

/**
 * @ingroup bnt_udp
 * @brief Finds the first UDP header reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> IPv4 -> UDP, and
 * Ethernet -> VLAN* -> IPv6 -> extension headers* -> UDP.
 *
 * @param ctx Packet context for the active bnt backend.
 * @param udp Destination UDP view initialized on success.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p udp is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a supported stack reaches a different supported
 *                            protocol, or the UDP length is malformed.
 * @retval BNT_ERR_UNSUPPORTED a valid L3/L4 stack is outside this walker.
 * @retval BNT_ERR_FRAGMENT   the packet is a non-first fragment.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) or
 *                            IPv6 extension walk (@c BNT_MAX_IPV6_EXT_DEPTH)
 *                            is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_udp(BNT_CTX_TYPE *ctx, bnt_udp *udp)
{
    if (!udp)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ctx_find_udp)(ctx, &off);
        if (ret)
            return ret;
        udp->__ctx = ctx;
        udp->__off = off;
        return BNT_OK;
    }
#else
    {
        struct __bnt_eth_meta meta;
        bnt_eth eth;
        int ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
        if (ret)
            return ret;

        if (meta.proto == ETH_P_IP) {
            bnt_ipv4 ip4;
            struct __bnt_ipv4_meta ip4meta;

            ret = __bnt_header_set(&ip4, eth.__ctx, eth.__off + meta.hlen);
            if (ret) return ret;
            ret = __bnt_ipv4_meta_dispatch(&ip4, &ip4meta);
            if (ret) return ret;
            if (!ip4meta.l4_off_valid)
                return BNT_ERR_FRAGMENT;
            if (ip4meta.protocol != IPPROTO_UDP)
                return __bnt_ctx__ipv4_l4_mismatch(ip4meta.protocol);
            ret = __bnt_header_set(udp, eth.__ctx, ip4meta.next_off);
            if (ret) return ret;
            return __bnt_ctx__validate_udp(udp);
        }

        if (meta.proto == ETH_P_IPV6) {
            bnt_ipv6 ip6;
            struct __bnt_ipv6_meta ip6meta;

            ret = __bnt_header_set(&ip6, eth.__ctx, eth.__off + meta.hlen);
            if (ret) return ret;
            ret = __bnt_ipv6_meta(&ip6, &ip6meta);
            if (ret) return ret;
            if (!ip6meta.l4_off_valid)
                return BNT_ERR_FRAGMENT;
            if (ip6meta.l4_proto != IPPROTO_UDP)
                return __bnt_ctx__ipv6_l4_mismatch(ip6meta.l4_proto);
            ret = __bnt_header_set(udp, eth.__ctx, ip6meta.next_off);
            if (ret) return ret;
            return __bnt_ctx__validate_udp(udp);
        }

        return __bnt_ctx__l3_mismatch(meta.proto);
    }
#endif
}

/**
 * @ingroup bnt_icmp4
 * @brief Finds the first ICMPv4 header reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> IPv4 -> ICMPv4.
 *
 * @param ctx  Packet context for the active bnt backend.
 * @param icmp Destination ICMPv4 view initialized on success.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p icmp is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a supported stack reaches a different supported
 *                            protocol.
 * @retval BNT_ERR_UNSUPPORTED a valid L3/L4 stack is outside this walker.
 * @retval BNT_ERR_FRAGMENT   the packet is a non-first fragment.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_icmp4(BNT_CTX_TYPE *ctx, bnt_icmp4 *icmp)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ctx_find_icmp4)(ctx, &off);
        if (ret)
            return ret;
        icmp->__ctx = ctx;
        icmp->__off = off;
        return BNT_OK;
    }
#else
    {
        struct __bnt_eth_meta meta;
        bnt_eth eth;
        bnt_ipv4 ip4;
        struct __bnt_ipv4_meta ip4meta;
        int ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
        if (ret)
            return ret;

        if (meta.proto != ETH_P_IP)
            return __bnt_ctx__l3_mismatch(meta.proto);

        ret = __bnt_header_set(&ip4, eth.__ctx, eth.__off + meta.hlen);
        if (ret) return ret;
        ret = __bnt_ipv4_meta_dispatch(&ip4, &ip4meta);
        if (ret) return ret;
        if (!ip4meta.l4_off_valid)
            return BNT_ERR_FRAGMENT;
        if (ip4meta.protocol != IPPROTO_ICMP)
            return __bnt_ctx__ipv4_l4_mismatch(ip4meta.protocol);
        ret = __bnt_header_set(icmp, eth.__ctx, ip4meta.next_off);
        if (ret) return ret;
        return __bnt_ctx__validate_icmp4(icmp);
    }
#endif
}

/**
 * @ingroup bnt_icmp6
 * @brief Finds the first ICMPv6 header reachable from @p ctx on bnt-supported paths.
 *
 * The walker starts at Ethernet offset 0 and currently supports
 * Ethernet -> VLAN* -> IPv6 -> extension headers* -> ICMPv6.
 *
 * @param ctx  Packet context for the active bnt backend.
 * @param icmp Destination ICMPv6 view initialized on success.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p icmp is NULL.
 * @retval BNT_ERR_TRUNC      a header on the path is truncated.
 * @retval BNT_ERR_BAD_PROTO  a supported stack reaches a different supported
 *                            protocol.
 * @retval BNT_ERR_UNSUPPORTED a valid L3/L4 stack is outside this walker.
 * @retval BNT_ERR_FRAGMENT   the packet is a non-first fragment.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) or
 *                            IPv6 extension walk (@c BNT_MAX_IPV6_EXT_DEPTH)
 *                            is exhausted (see @ref limits).
 */
static __always_inline int bnt_ctx__find_icmp6(BNT_CTX_TYPE *ctx, bnt_icmp6 *icmp)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;

#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    {
        __u32 off = 0;
        int ret = __BNT_OP(__bnt_ctx_find_icmp6)(ctx, &off);
        if (ret)
            return ret;
        icmp->__ctx = ctx;
        icmp->__off = off;
        return BNT_OK;
    }
#else
    {
        struct __bnt_eth_meta meta;
        bnt_eth eth;
        bnt_ipv6 ip6;
        struct __bnt_ipv6_meta ip6meta;
        int ret = __bnt_ctx__eth_meta(ctx, &eth, &meta);
        if (ret)
            return ret;

        if (meta.proto != ETH_P_IPV6)
            return __bnt_ctx__l3_mismatch(meta.proto);

        ret = __bnt_header_set(&ip6, eth.__ctx, eth.__off + meta.hlen);
        if (ret) return ret;
        ret = __bnt_ipv6_meta(&ip6, &ip6meta);
        if (ret) return ret;
        if (!ip6meta.l4_off_valid)
            return BNT_ERR_FRAGMENT;
        if (ip6meta.l4_proto != IPPROTO_ICMPV6)
            return __bnt_ctx__ipv6_l4_mismatch(ip6meta.l4_proto);
        ret = __bnt_header_set(icmp, eth.__ctx, ip6meta.next_off);
        if (ret) return ret;
        return __bnt_ctx__validate_icmp6(icmp);
    }
#endif
}

/**
 * @ingroup bnt_eth
 * @brief Dispatches from a parsed Ethernet view to IPv4 or IPv6 parsing.
 *
 * Initializes whichever of @p ip4 or @p ip6 matches the final EtherType; the
 * other view is left untouched.
 *
 * @param eth Parsed Ethernet view.
 * @param ip4 Initialized when the final EtherType is ETH_P_IP.
 * @param ip6 Initialized when the final EtherType is ETH_P_IPV6.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p eth is NULL, or the matching destination view
 *                            is NULL.
 * @retval BNT_ERR_TRUNC      a header on the VLAN stack is truncated.
 * @retval BNT_ERR_BAD_PROTO  the final EtherType is ETH_P_ARP.
 * @retval BNT_ERR_UNSUPPORTED the final EtherType is none of the above.
 * @retval BNT_ERR_TOO_DEEP   the bounded VLAN walk (@c BNT_MAX_VLAN_DEPTH) is
 *                            exhausted (see @ref limits).
 */
static __always_inline int bnt_eth__parse_l3(const bnt_eth *eth, bnt_ipv4 *ip4, bnt_ipv6 *ip6)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u32 info = 0, off;
    int ret;

    if (!eth)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_eth_info)(eth->__ctx, eth->__off, &info);
    if (ret)
        return ret;
    off = eth->__off + ((info >> 16) & 0xff);
    if ((info & 0xffff) == ETH_P_IP)
        return __bnt_header_set(ip4, eth->__ctx, off);
    if ((info & 0xffff) == ETH_P_IPV6)
        return __bnt_header_set(ip6, eth->__ctx, off);
    if ((info & 0xffff) == ETH_P_ARP)
        return BNT_ERR_BAD_PROTO;
    return BNT_ERR_UNSUPPORTED;
#else
    struct __bnt_eth_meta meta;
    __u32 off;
    int ret;

    ret = __bnt_eth_meta_dispatch(eth, &meta);
    if (ret)
        return ret;

    off = eth->__off + meta.hlen;
    if (meta.proto == ETH_P_IP)
        return __bnt_header_set(ip4, eth->__ctx, off);
    if (meta.proto == ETH_P_IPV6)
        return __bnt_header_set(ip6, eth->__ctx, off);
    if (meta.proto == ETH_P_ARP)
        return BNT_ERR_BAD_PROTO;

    return BNT_ERR_UNSUPPORTED;
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Dispatches from a parsed IPv4 view to TCP, UDP, or ICMPv4 parsing.
 *
 * Initializes whichever of @p tcp, @p udp, or @p icmp matches the IPv4
 * protocol field; the other views are left untouched.
 *
 * @param ip   Parsed IPv4 view.
 * @param tcp  Initialized when the protocol is IPPROTO_TCP.
 * @param udp  Initialized when the protocol is IPPROTO_UDP.
 * @param icmp Initialized when the protocol is IPPROTO_ICMP.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p ip is NULL, or the view for the protocol found
 *                            is NULL.
 * @retval BNT_ERR_TRUNC      the IPv4 header is truncated.
 * @retval BNT_ERR_BAD_PROTO  the IPv4 header is malformed.
 * @retval BNT_ERR_FRAGMENT   the packet is a non-first fragment.
 * @retval BNT_ERR_UNSUPPORTED the protocol is none of the above.
 */
static __always_inline int bnt_ipv4__parse_l4(const bnt_ipv4 *ip,
                                               bnt_tcp *tcp,
                                               bnt_udp *udp,
                                               bnt_icmp4 *icmp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!ip)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv4_next_proto_off)(ip->__ctx, ip->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto == IPPROTO_TCP)
        return __bnt_header_set(tcp, ip->__ctx, next);
    if (proto == IPPROTO_UDP)
        return __bnt_header_set(udp, ip->__ctx, next);
    if (proto == IPPROTO_ICMP)
        return __bnt_header_set(icmp, ip->__ctx, next);
    return BNT_ERR_UNSUPPORTED;
#else
    struct __bnt_ipv4_meta meta;
    int ret;

    ret = __bnt_ipv4_meta_dispatch(ip, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;

    if (meta.protocol == IPPROTO_TCP)
        return __bnt_header_set(tcp, ip->__ctx, meta.next_off);
    if (meta.protocol == IPPROTO_UDP)
        return __bnt_header_set(udp, ip->__ctx, meta.next_off);
    if (meta.protocol == IPPROTO_ICMP)
        return __bnt_header_set(icmp, ip->__ctx, meta.next_off);

    return BNT_ERR_UNSUPPORTED;
#endif
}

/**
 * @ingroup bnt_ipv6
 * @brief Dispatches from a parsed IPv6 view to TCP, UDP, or ICMPv6 parsing.
 *
 * Walks past any extension headers, then initializes whichever of @p tcp,
 * @p udp, or @p icmp matches the resolved upper-layer protocol; the other
 * views are left untouched.
 *
 * @param ip6  Parsed IPv6 view.
 * @param tcp  Initialized when the resolved protocol is IPPROTO_TCP.
 * @param udp  Initialized when the resolved protocol is IPPROTO_UDP.
 * @param icmp Initialized when the resolved protocol is IPPROTO_ICMPV6.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p ip6 is NULL, or the view for the protocol found
 *                            is NULL.
 * @retval BNT_ERR_TRUNC      a header on the chain is truncated.
 * @retval BNT_ERR_BAD_PROTO  the IPv6 header is malformed.
 * @retval BNT_ERR_TOO_DEEP   the extension header chain exceeds
 *                            @c BNT_MAX_IPV6_EXT_DEPTH (see @ref limits).
 * @retval BNT_ERR_FRAGMENT   the packet is a non-first fragment.
 * @retval BNT_ERR_UNSUPPORTED the resolved protocol is none of the above.
 */
static __always_inline int bnt_ipv6__parse_l4(const bnt_ipv6 *ip6,
                                               bnt_tcp *tcp,
                                               bnt_udp *udp,
                                               bnt_icmp6 *icmp)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    __u8 proto = 0;
    __u32 next = 0;
    int ret;

    if (!ip6)
        return BNT_ERR_BAD_ARG;
    ret = __BNT_OP(__bnt_ipv6_next_proto_off)(ip6->__ctx, ip6->__off, &proto, &next);
    if (ret)
        return ret;
    if (proto == IPPROTO_TCP)
        return __bnt_header_set(tcp, ip6->__ctx, next);
    if (proto == IPPROTO_UDP)
        return __bnt_header_set(udp, ip6->__ctx, next);
    if (proto == IPPROTO_ICMPV6)
        return __bnt_header_set(icmp, ip6->__ctx, next);
    return BNT_ERR_UNSUPPORTED;
#else
    struct __bnt_ipv6_meta meta;
    int ret;

    ret = __bnt_ipv6_meta_dispatch(ip6, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_ERR_FRAGMENT;

    if (meta.l4_proto == IPPROTO_TCP)
        return __bnt_header_set(tcp, ip6->__ctx, meta.next_off);
    if (meta.l4_proto == IPPROTO_UDP)
        return __bnt_header_set(udp, ip6->__ctx, meta.next_off);
    if (meta.l4_proto == IPPROTO_ICMPV6)
        return __bnt_header_set(icmp, ip6->__ctx, meta.next_off);

    return BNT_ERR_UNSUPPORTED;
#endif
}

/*
 * Full-checksum recompute functions.
 *
 * Use these after modifying fields that affect the checksum (including payload
 * modifications) to recompute the whole checksum from scratch. They zero the
 * checksum field before computing, so no prior state is assumed.
 *
 * IPv4 header recompute supports only IHL=5 (no options).
 *
 * Stack and instruction budget
 * ----------------------------
 * The payload loop (TCP/UDP/ICMPv6) reads BNT_CSUM_CHUNK bytes per iteration
 * from a stack buffer, contributing:
 *   - BNT_CSUM_CHUNK bytes to the caller's BPF stack frame (512-byte limit)
 *   - BNT_MAX_PAYLOAD / BNT_CSUM_CHUNK + 1 iterations to the verifier's
 *     instruction count (1 000 000-instruction limit)
 *
 * Both limits are shared with the rest of the calling program. If it exceeds
 * either, move the recompute into a separate program reached with a tail call,
 * which starts with its own stack and instruction budget.
 */

/** Recomputes the IPv4 header checksum from scratch. Requires IHL=5 (no options). */
static __always_inline int __bnt_ipv4__recompute_csum(bnt_ipv4 *ip)
{
    struct iphdr hdr;
    __s64 res;
    int ret;

    if (!ip)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_read(ip->__ctx, ip->__off, &hdr, sizeof(hdr));
    if (ret)
        return ret;
    if ((hdr.ihl & 0xf) != 5)
        return BNT_ERR_UNSUPPORTED;

    hdr.check = 0;
    res = bpf_csum_diff(NULL, 0, (__be32 *)&hdr, sizeof(hdr), 0);
    return __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, check),
                             __bnt_csum_fold((__wsum)res));
}

/** Recomputes the TCP checksum from scratch over an IPv4 pseudo-header. */
static __always_inline int __bnt_tcp__recompute_csum_v4(bnt_tcp *tcp, bnt_ipv4 *ip4)
{
    __u8 pseudo[12];
    __be16 tot_len_be = 0;
    __u8 vihl = 0;
    __u16 ip_hlen;
    __u16 tcp_len;
    __wsum acc;
    __s64 res;
    int ret;

    if (!tcp || !ip4)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_u8(ip4->__ctx, ip4->__off, &vihl);
    if (ret)
        return ret;
    ip_hlen = (__u16)(vihl & 0xf) * 4;

    ret = __bnt_read_be16(ip4->__ctx, ip4->__off + offsetof(struct iphdr, tot_len), &tot_len_be);
    if (ret)
        return ret;
    tcp_len = bpf_ntohs(tot_len_be) - ip_hlen;

    /* Zero TCP checksum before accumulating. */
    ret = __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), 0);
    if (ret)
        return ret;

    /* IPv4 pseudo-header: saddr(4) + daddr(4) + zero(1) + proto(1) + tcp_len(2). */
    __builtin_memset(pseudo, 0, sizeof(pseudo));
    ret = __bnt_read(ip4->__ctx, ip4->__off + offsetof(struct iphdr, saddr), pseudo, 8);
    if (ret)
        return ret;
    pseudo[9] = IPPROTO_TCP;
    __be16 tcp_len_be = bpf_htons(tcp_len);
    __builtin_memcpy(&pseudo[10], &tcp_len_be, 2);

    res = bpf_csum_diff(NULL, 0, (__be32 *)pseudo, 12, 0);
    acc = (__wsum)res;

    ret = __bnt_csum_range(tcp->__ctx, tcp->__off, tcp_len, acc, &acc);
    if (ret)
        return ret;

    return __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check),
                             __bnt_csum_fold(acc));
}

/** Recomputes the TCP checksum from scratch over an IPv6 pseudo-header. */
static __always_inline int __bnt_tcp__recompute_csum_v6(bnt_tcp *tcp, bnt_ipv6 *ip6)
{
    __u8 pseudo[40];
    __be16 payload_len_be = 0;
    __u16 tcp_len;
    __wsum acc;
    __s64 res;
    int ret;

    if (!tcp || !ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, payload_len),
                           &payload_len_be);
    if (ret)
        return ret;
    tcp_len = bpf_ntohs(payload_len_be);

    ret = __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), 0);
    if (ret)
        return ret;

    /* IPv6 pseudo-header: saddr(16) + daddr(16) + tcp_len(4) + zeros(3) + nexthdr(1). */
    __builtin_memset(pseudo, 0, sizeof(pseudo));
    ret = __bnt_read(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), pseudo, 32);
    if (ret)
        return ret;
    __be32 tcp_len_be32 = bpf_htonl((__u32)tcp_len);
    __builtin_memcpy(&pseudo[32], &tcp_len_be32, 4);
    pseudo[39] = IPPROTO_TCP;

    res = bpf_csum_diff(NULL, 0, (__be32 *)pseudo, 40, 0);
    acc = (__wsum)res;

    ret = __bnt_csum_range(tcp->__ctx, tcp->__off, tcp_len, acc, &acc);
    if (ret)
        return ret;

    return __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check),
                             __bnt_csum_fold(acc));
}

/** Recomputes the UDP checksum from scratch over an IPv4 pseudo-header. */
static __always_inline int __bnt_udp__recompute_csum_v4(bnt_udp *udp, bnt_ipv4 *ip4)
{
    __u8 pseudo[12];
    __be16 udp_len_be = 0;
    __u16 udp_len;
    __wsum acc;
    __s64 res;
    int ret;

    if (!udp || !ip4)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, len), &udp_len_be);
    if (ret)
        return ret;
    udp_len = bpf_ntohs(udp_len_be);

    ret = __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), 0);
    if (ret)
        return ret;

    __builtin_memset(pseudo, 0, sizeof(pseudo));
    ret = __bnt_read(ip4->__ctx, ip4->__off + offsetof(struct iphdr, saddr), pseudo, 8);
    if (ret)
        return ret;
    pseudo[9] = IPPROTO_UDP;
    __builtin_memcpy(&pseudo[10], &udp_len_be, 2);

    res = bpf_csum_diff(NULL, 0, (__be32 *)pseudo, 12, 0);
    acc = (__wsum)res;

    ret = __bnt_csum_range(udp->__ctx, udp->__off, udp_len, acc, &acc);
    if (ret)
        return ret;

    __be16 check = __bnt_csum_fold(acc);
    /* RFC 768: a zero UDP checksum must be transmitted as 0xffff. */
    if (check == 0)
        check = bpf_htons(0xffff);
    return __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), check);
}

/** Recomputes the UDP checksum from scratch over an IPv6 pseudo-header. */
static __always_inline int __bnt_udp__recompute_csum_v6(bnt_udp *udp, bnt_ipv6 *ip6)
{
    __u8 pseudo[40];
    __be16 udp_len_be = 0;
    __u16 udp_len;
    __wsum acc;
    __s64 res;
    int ret;

    if (!udp || !ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, len), &udp_len_be);
    if (ret)
        return ret;
    udp_len = bpf_ntohs(udp_len_be);

    ret = __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), 0);
    if (ret)
        return ret;

    __builtin_memset(pseudo, 0, sizeof(pseudo));
    ret = __bnt_read(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), pseudo, 32);
    if (ret)
        return ret;
    __be32 udp_len_be32 = bpf_htonl((__u32)udp_len);
    __builtin_memcpy(&pseudo[32], &udp_len_be32, 4);
    pseudo[39] = IPPROTO_UDP;

    res = bpf_csum_diff(NULL, 0, (__be32 *)pseudo, 40, 0);
    acc = (__wsum)res;

    ret = __bnt_csum_range(udp->__ctx, udp->__off, udp_len, acc, &acc);
    if (ret)
        return ret;

    __be16 check = __bnt_csum_fold(acc);
    if (check == 0)
        check = bpf_htons(0xffff);
    return __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), check);
}

/** Recomputes the ICMPv4 checksum from scratch over the given ICMP message length. */
static __always_inline int __bnt_icmp4__recompute_csum(bnt_icmp4 *icmp, __u16 icmp_len)
{
    __wsum acc = 0;
    int ret;

    if (!icmp)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_write_be16(icmp->__ctx,
                            icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum), 0);
    if (ret)
        return ret;

    ret = __bnt_csum_range(icmp->__ctx, icmp->__off, icmp_len, acc, &acc);
    if (ret)
        return ret;

    return __bnt_write_be16(icmp->__ctx,
                             icmp->__off + offsetof(struct bnt_icmp4_hdr, checksum),
                             __bnt_csum_fold(acc));
}

/** Recomputes the ICMPv6 checksum from scratch over an IPv6 pseudo-header. */
static __always_inline int __bnt_icmp6__recompute_csum(bnt_icmp6 *icmp, bnt_ipv6 *ip6,
                                                        __u16 icmp_len)
{
    __u8 pseudo[40];
    __be32 icmp_len_be32;
    __wsum acc;
    __s64 res;
    int ret;

    if (!icmp || !ip6)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_write_be16(icmp->__ctx,
                            icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum), 0);
    if (ret)
        return ret;

    __builtin_memset(pseudo, 0, sizeof(pseudo));
    ret = __bnt_read(ip6->__ctx, ip6->__off + offsetof(struct ipv6hdr, saddr), pseudo, 32);
    if (ret)
        return ret;
    icmp_len_be32 = bpf_htonl((__u32)icmp_len);
    __builtin_memcpy(&pseudo[32], &icmp_len_be32, 4);
    pseudo[39] = IPPROTO_ICMPV6;

    res = bpf_csum_diff(NULL, 0, (__be32 *)pseudo, 40, 0);
    acc = (__wsum)res;

    ret = __bnt_csum_range(icmp->__ctx, icmp->__off, icmp_len, acc, &acc);
    if (ret)
        return ret;

    return __bnt_write_be16(icmp->__ctx,
                             icmp->__off + offsetof(struct icmp6hdr, icmp6_cksum),
                             __bnt_csum_fold(acc));
}

/* ── recompute_csum globals ──────────────────────────────────────────────────
 *
 * Each global encapsulates loops + bpf_csum_diff calls so the verifier
 * processes them once in isolation (own 1M-instruction budget, 512B stack).
 * Defined AFTER the inline implementations they wrap so the inline bodies
 * are visible at the call site and can be inlined inside the global.
 */
#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_recompute_csum(BNT_CTX_TYPE *ctx, __u32 ip_off)
{
    struct iphdr *ip, hdr;
    __s64 res;
    int ret = __bnt_data_ptr(ctx, ip_off, sizeof(*ip), (void **)&ip);

    if (ret)
        return ret;
    if ((*(__u8 *)ip & 0xf) != 5)
        return BNT_ERR_UNSUPPORTED;
    __BNT_PKT_ASSIGN(hdr, *ip);
    hdr.check = 0;
    res = bpf_csum_diff(NULL, 0, (__be32 *)&hdr, sizeof(hdr), 0);
    __BNT_PKT_STORE(ip->check, __bnt_csum_fold((__wsum)res));
    return BNT_OK;
}
#endif

#ifdef BNT_XDP_H

__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv4_recompute_csum_g(BNT_CTX_TYPE *ctx, __u32 ip_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_ipv4_recompute_csum_g(BNT_CTX_TYPE *ctx, __u32 ip_off)
{
    return __bnt_ipv4_recompute_csum(ctx, ip_off);
}
#endif

/* The full L4 checksum recompute of the globals: the pseudo-header fields read
 * in place through one pointer to the IP header, the checksum field through one
 * pointer (zeroed, summed over, written), the L4 bytes through
 * __bnt_csum_range. Every bound is tested before the first write. ipv is 4,
 * 6, or 0 (ICMPv4: no pseudo-header); co is the checksum's offset in the L4
 * header. The L4 length comes from the IPv4 header (TCP), the IPv6 payload
 * length (TCP), the UDP header, or len (ICMP). */
static __always_inline int __bnt_api_l4_recompute(BNT_CTX_TYPE *ctx, __u32 l4_off, __u32 ip_off, __u16 len,
                                                  const int ipv, const __u8 proto, const __u32 co)
{
    __u8 pseudo[40] = {};
    const __u8 *ip = NULL, *l4;
    __be16 *check;
    __be16 c;
    __wsum acc = 0;
    int ret;

    if (ipv) {
        ret = __bnt_data_ptr(ctx, ip_off, ipv == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr),
                             (void **)&ip);
        if (ret)
            return ret;
    }
    ret = __bnt_data_ptr(ctx, l4_off, proto == IPPROTO_UDP ? sizeof(struct udphdr) : co + 2, (void **)&l4);
    if (ret)
        return ret;
    check = (__be16 *)(l4 + co);
    if (proto == IPPROTO_UDP)
        len = bpf_ntohs(__BNT_PKT_LOAD(((const struct udphdr *)l4)->len));
    else if (proto == IPPROTO_TCP && ipv == 4)
        len = bpf_ntohs(__BNT_PKT_LOAD(((const struct iphdr *)ip)->tot_len)) - (__u16)((ip[0] & 0xf) * 4);
    else if (proto == IPPROTO_TCP)
        len = bpf_ntohs(__BNT_PKT_LOAD(((const struct ipv6hdr *)ip)->payload_len));
    /* The length is tested before the first write. */
    if (len > BNT_MAX_PAYLOAD || l4_off + len > __bnt_len(ctx))
        return BNT_ERR_TRUNC;
    /* Zeroed before the pseudo-header is read: a view placed over the IP
     * header can make the field part of it. */
    __BNT_PKT_STORE(*check, 0);
    if (ipv == 4) {
        __be16 len_be = bpf_htons(len);

        /* saddr(4) daddr(4) zero(1) proto(1) length(2) */
        __BNT_PKT_MEMCPY(pseudo, ip + offsetof(struct iphdr, saddr), 8);
        pseudo[9] = proto;
        __builtin_memcpy(&pseudo[10], &len_be, 2);
        acc = (__wsum)bpf_csum_diff(NULL, 0, (__be32 *)pseudo, 12, 0);
    } else if (ipv == 6) {
        __be32 len_be = bpf_htonl((__u32)len);

        /* saddr(16) daddr(16) length(4) zero(3) next header(1) */
        __BNT_PKT_MEMCPY(pseudo, ip + offsetof(struct ipv6hdr, saddr), 32);
        __builtin_memcpy(&pseudo[32], &len_be, 4);
        pseudo[39] = proto;
        acc = (__wsum)bpf_csum_diff(NULL, 0, (__be32 *)pseudo, 40, 0);
    }
    ret = __bnt_csum_range(ctx, l4_off, len, acc, &acc);
    if (ret)
        return ret;
    c = __bnt_csum_fold(acc);
    if (proto == IPPROTO_UDP && c == 0)     /* RFC 768: a computed 0 is sent as 0xffff */
        c = bpf_htons(0xffff);
    __BNT_PKT_STORE(*check, c);
    return BNT_OK;
}

static __always_inline int __bnt_tcp_recompute_csum_v4(BNT_CTX_TYPE *ctx,
                                                              __u32 tcp_off, __u32 ip_off)
{
    return __bnt_api_l4_recompute(ctx, tcp_off, ip_off, 0, 4, IPPROTO_TCP, offsetof(struct tcphdr, check));
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_tcp_recompute_csum_v4_g(BNT_CTX_TYPE *ctx,
                                                              __u32 tcp_off, __u32 ip_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_tcp_recompute_csum_v4_g(BNT_CTX_TYPE *ctx,
                                                              __u32 tcp_off, __u32 ip_off)
{
    return __bnt_tcp_recompute_csum_v4(ctx, tcp_off, ip_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_tcp_recompute_csum_v6(BNT_CTX_TYPE *ctx,
                                                              __u32 tcp_off, __u32 ip_off)
{
    return __bnt_api_l4_recompute(ctx, tcp_off, ip_off, 0, 6, IPPROTO_TCP, offsetof(struct tcphdr, check));
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_tcp_recompute_csum_v6_g(BNT_CTX_TYPE *ctx,
                                                              __u32 tcp_off, __u32 ip_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_tcp_recompute_csum_v6_g(BNT_CTX_TYPE *ctx,
                                                              __u32 tcp_off, __u32 ip_off)
{
    return __bnt_tcp_recompute_csum_v6(ctx, tcp_off, ip_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_udp_recompute_csum_v4(BNT_CTX_TYPE *ctx,
                                                              __u32 udp_off, __u32 ip_off)
{
    return __bnt_api_l4_recompute(ctx, udp_off, ip_off, 0, 4, IPPROTO_UDP, offsetof(struct udphdr, check));
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_udp_recompute_csum_v4_g(BNT_CTX_TYPE *ctx,
                                                              __u32 udp_off, __u32 ip_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_udp_recompute_csum_v4_g(BNT_CTX_TYPE *ctx,
                                                              __u32 udp_off, __u32 ip_off)
{
    return __bnt_udp_recompute_csum_v4(ctx, udp_off, ip_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_udp_recompute_csum_v6(BNT_CTX_TYPE *ctx,
                                                              __u32 udp_off, __u32 ip_off)
{
    return __bnt_api_l4_recompute(ctx, udp_off, ip_off, 0, 6, IPPROTO_UDP, offsetof(struct udphdr, check));
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_udp_recompute_csum_v6_g(BNT_CTX_TYPE *ctx,
                                                              __u32 udp_off, __u32 ip_off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_udp_recompute_csum_v6_g(BNT_CTX_TYPE *ctx,
                                                              __u32 udp_off, __u32 ip_off)
{
    return __bnt_udp_recompute_csum_v6(ctx, udp_off, ip_off);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_icmp4_recompute_csum(BNT_CTX_TYPE *ctx,
                                                             __u32 icmp_off, __u16 icmp_len)
{
    return __bnt_api_l4_recompute(ctx, icmp_off, 0, icmp_len, 0, IPPROTO_ICMP, offsetof(struct bnt_icmp4_hdr, checksum));
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_icmp4_recompute_csum_g(BNT_CTX_TYPE *ctx,
                                                             __u32 icmp_off, __u16 icmp_len);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_icmp4_recompute_csum_g(BNT_CTX_TYPE *ctx,
                                                             __u32 icmp_off, __u16 icmp_len)
{
    return __bnt_icmp4_recompute_csum(ctx, icmp_off, icmp_len);
}
#endif
#endif /* !BNT_INLINE_ALL */

static __always_inline int __bnt_icmp6_recompute_csum(BNT_CTX_TYPE *ctx,
                                                             __u32 icmp_off, __u32 ip_off,
                                                             __u16 icmp_len)
{
    return __bnt_api_l4_recompute(ctx, icmp_off, ip_off, icmp_len, 6, IPPROTO_ICMPV6, offsetof(struct icmp6hdr, icmp6_cksum));
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_icmp6_recompute_csum_g(BNT_CTX_TYPE *ctx,
                                                             __u32 icmp_off, __u32 ip_off,
                                                             __u16 icmp_len);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_icmp6_recompute_csum_g(BNT_CTX_TYPE *ctx,
                                                             __u32 icmp_off, __u32 ip_off,
                                                             __u16 icmp_len)
{
    return __bnt_icmp6_recompute_csum(ctx, icmp_off, ip_off, icmp_len);
}
#endif
#endif /* !BNT_INLINE_ALL */

#endif /* !BNT_INLINE_ALL */

/* ── Unified setters (context-dispatch via __bnt_l4_csum* / __bnt_l3_csum* functions) ── */

/* TCP setters */

#ifdef BNT_XDP_H
/* Port rewrites: one global per protocol for source and destination (is_dest
 * selects the offset), with the checksum update. */
static __always_inline int __bnt_tcp_set_port(BNT_CTX_TYPE *ctx, __u32 off, __u16 port, int is_dest)
{
    struct tcphdr *tcp;
    __be16 old, v = bpf_htons(port);
    int ret = __bnt_data_ptr(ctx, off, sizeof(*tcp), (void **)&tcp);
    if (ret)
        return ret;
    if (is_dest) { old = __BNT_PKT_LOAD(tcp->dest); __BNT_PKT_STORE(tcp->dest, v); }
    else         { old = __BNT_PKT_LOAD(tcp->source); __BNT_PKT_STORE(tcp->source, v); }
    __BNT_PKT_STORE(tcp->check, __bnt_csum16_update(__BNT_PKT_LOAD(tcp->check), old, v));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_port_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 port, int is_dest);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_port_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 port, int is_dest)
{
    return __bnt_tcp_set_port(ctx, off, port, is_dest);
}
#endif
#endif /* !BNT_INLINE_ALL */
static __always_inline int __bnt_udp_set_port(BNT_CTX_TYPE *ctx, __u32 off, __u16 port, int is_dest)
{
    struct udphdr *udp;
    __be16 old, c, v = bpf_htons(port);
    int ret = __bnt_data_ptr(ctx, off, sizeof(*udp), (void **)&udp);
    if (ret)
        return ret;
    if (is_dest) { old = __BNT_PKT_LOAD(udp->dest); __BNT_PKT_STORE(udp->dest, v); }
    else         { old = __BNT_PKT_LOAD(udp->source); __BNT_PKT_STORE(udp->source, v); }
    c = __BNT_PKT_LOAD(udp->check);
    if (c != 0) {                       /* UDP checksum 0 = none */
        c = __bnt_csum16_update(c, old, v);
        if (c == 0) c = bpf_htons(0xffff);
        __BNT_PKT_STORE(udp->check, c);
    }
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_udp_set_port_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 port, int is_dest);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_udp_set_port_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 port, int is_dest)
{
    return __bnt_udp_set_port(ctx, off, port, is_dest);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP source port and fixes the TCP checksum.
 *
 * @param tcp  Parsed TCP view.
 * @param port New source port.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_sport(bnt_tcp *tcp, __u16 port)
{
    if (!tcp) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_tcp_set_port)(tcp->__ctx, tcp->__off, port, 0);
#else
    {
        __be16 old = 0, v = bpf_htons(port);
        int ret;
        ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, source), &old);
        if (ret) return ret;
        ret = __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, source), v);
        if (ret) return ret;
        return __bnt_l4_csum16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old, v, 0);
    }
#endif
}

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP destination port and fixes the TCP checksum.
 *
 * @param tcp  Parsed TCP view.
 * @param port New destination port.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_dport(bnt_tcp *tcp, __u16 port)
{
    if (!tcp) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_tcp_set_port)(tcp->__ctx, tcp->__off, port, 1);
#else
    {
        __be16 old = 0, v = bpf_htons(port);
        int ret;
        ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, dest), &old);
        if (ret) return ret;
        ret = __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, dest), v);
        if (ret) return ret;
        return __bnt_l4_csum16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old, v, 0);
    }
#endif
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_tcp_set_seq(BNT_CTX_TYPE *ctx, __u32 off, __u32 value, int is_ack)
{
    struct tcphdr *tcp;
    __be32 old, v = bpf_htonl(value);
    int ret = __bnt_data_ptr(ctx, off, sizeof(*tcp), (void **)&tcp);
    if (ret)
        return ret;
    if (is_ack) { old = __BNT_PKT_LOAD(tcp->ack_seq); __BNT_PKT_STORE(tcp->ack_seq, v); }
    else        { old = __BNT_PKT_LOAD(tcp->seq);     __BNT_PKT_STORE(tcp->seq, v); }
    __BNT_PKT_STORE(tcp->check, __bnt_csum32_update(__BNT_PKT_LOAD(tcp->check), old, v));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
/* set_seq and set_ack_seq (is_ack selects the field): the field and the
 * checksum. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_seq_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 value, int is_ack);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_seq_g(BNT_CTX_TYPE *ctx, __u32 off, __u32 value, int is_ack)
{
    return __bnt_tcp_set_seq(ctx, off, value, is_ack);
}
#endif
#endif

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP sequence number and fixes the TCP checksum.
 *
 * @param tcp Parsed TCP view.
 * @param seq New sequence number.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_seq(bnt_tcp *tcp, __u32 seq)
{
    if (!tcp) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_tcp_set_seq)(tcp->__ctx, tcp->__off, seq, 0);
#else
    {
        __be32 old = 0, v = bpf_htonl(seq);
        int ret;
        ret = __bnt_read_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, seq), &old);
        if (ret) return ret;
        ret = __bnt_write_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, seq), v);
        if (ret) return ret;
        return __bnt_l4_csum32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old, v, 0);
    }
#endif
}

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP acknowledgment number and fixes the TCP checksum.
 *
 * @param tcp     Parsed TCP view.
 * @param ack_seq New acknowledgment number.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_ack_seq(bnt_tcp *tcp, __u32 ack_seq)
{
    if (!tcp) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_tcp_set_seq)(tcp->__ctx, tcp->__off, ack_seq, 1);
#else
    {
        __be32 old = 0, v = bpf_htonl(ack_seq);
        int ret;
        ret = __bnt_read_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, ack_seq), &old);
        if (ret) return ret;
        ret = __bnt_write_be32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, ack_seq), v);
        if (ret) return ret;
        return __bnt_l4_csum32(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old, v, 0);
    }
#endif
}

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP flags bitmask using BNT_TCP_* bits and fixes the TCP checksum.
 *
 * @param tcp   Parsed TCP view.
 * @param flags New flags bitmask.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_flags(bnt_tcp *tcp, __u16 flags)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_set_flags)(tcp->__ctx, tcp->__off, flags);
#else
    __be16 old = 0, v;
    __u16 old_h;
    int ret;
    if (!tcp) return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + 12, &old);
    if (ret) return ret;
    old_h = bpf_ntohs(old);
    v = bpf_htons((old_h & 0xfe00) | (flags & 0x01ff));
    ret = __bnt_write_be16(tcp->__ctx, tcp->__off + 12, v);
    if (ret) return ret;
    return __bnt_l4_csum16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old, v, 0);
#endif
}

#ifdef BNT_XDP_H
/* Every TCP flag set and clear: the bit in the data-offset/flags word, and the
 * checksum. */
static __always_inline int __bnt_tcp_set_flag(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled)
{
    struct tcphdr *tcp;
    __be16 old, v;
    __u16 w;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*tcp), (void **)&tcp);
    if (ret)
        return ret;
    old = __BNT_PKT_LOAD(*(__be16 *)((__u8 *)tcp + 12));        /* data offset | reserved | flags */
    w   = bpf_ntohs(old);
    if (enabled) w |= flag;
    else         w &= (__u16)~flag;
    v = bpf_htons(w);
    __BNT_PKT_STORE(*(__be16 *)((__u8 *)tcp + 12), v);
    __BNT_PKT_STORE(tcp->check, __bnt_csum16_update(__BNT_PKT_LOAD(tcp->check), old, v));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_tcp_set_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled)
{
    return __bnt_tcp_set_flag(ctx, off, flag, enabled);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

static __always_inline int __bnt_tcp__set_flag(bnt_tcp *tcp, __u16 flag, bool enabled)
{
    if (!tcp)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_tcp_set_flag)(tcp->__ctx, tcp->__off, flag, enabled);
#else
    {
        __u16 flags;
        int ret;

        ret = bnt_tcp__get_flags(tcp, &flags);
        if (ret)
            return ret;

        if (enabled)
            flags |= flag;
        else
            flags &= ~flag;

        return bnt_tcp__set_flags(tcp, flags);
    }
#endif
}

/** @ingroup bnt_tcp
 *  Sets the TCP FIN flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_fin(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_FIN, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP FIN flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_fin(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_FIN, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP SYN flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_syn(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_SYN, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP SYN flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_syn(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_SYN, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP RST flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_rst(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_RST, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP RST flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_rst(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_RST, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP PSH flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_psh(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_PSH, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP PSH flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_psh(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_PSH, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP ACK flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_ack(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_ACK, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP ACK flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_ack(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_ACK, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP URG flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_urg(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_URG, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP URG flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_urg(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_URG, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP ECE flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_ece(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_ECE, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP ECE flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_ece(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_ECE, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP CWR flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_cwr(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_CWR, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP CWR flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_cwr(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_CWR, false);
}

/** @ingroup bnt_tcp
 *  Sets the TCP NS flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_ns(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_NS, true);
}

/** @ingroup bnt_tcp
 *  Clears the TCP NS flag and fixes the TCP checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__clear_ns(bnt_tcp *tcp)
{
    return __bnt_tcp__set_flag(tcp, BNT_TCP_NS, false);
}

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP window size and fixes the TCP checksum.
 *
 * @param tcp    Parsed TCP view.
 * @param window New window size.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_window(bnt_tcp *tcp, __u16 window)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_set_window)(tcp->__ctx, tcp->__off, window);
#else
    __be16 old = 0, v = bpf_htons(window);
    int ret;
    if (!tcp) return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, window), &old);
    if (ret) return ret;
    ret = __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, window), v);
    if (ret) return ret;
    return __bnt_l4_csum16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old, v, 0);
#endif
}

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP urgent pointer and fixes the TCP checksum.
 *
 * @param tcp     Parsed TCP view.
 * @param urg_ptr New urgent pointer.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_urg_ptr(bnt_tcp *tcp, __u16 urg_ptr)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_set_urg_ptr)(tcp->__ctx, tcp->__off, urg_ptr);
#else
    __be16 old = 0, v = bpf_htons(urg_ptr);
    int ret;
    if (!tcp) return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, urg_ptr), &old);
    if (ret) return ret;
    ret = __bnt_write_be16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, urg_ptr), v);
    if (ret) return ret;
    return __bnt_l4_csum16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old, v, 0);
#endif
}

/**
 * @ingroup bnt_tcp
 * @brief Sets the TCP data offset (header length in 32-bit words) and fixes the TCP checksum.
 *
 * @param tcp  Parsed TCP view.
 * @param doff New data offset; must be between 5 and 15.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL, or @p doff is out of range.
 * @retval BNT_ERR_TRUNC   the new header length falls outside the packet.
 */
static __always_inline int bnt_tcp__set_doff(bnt_tcp *tcp, __u32 doff)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!tcp)
        return BNT_ERR_BAD_ARG;
    if (doff < 5 || doff > 15)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_set_doff)(tcp->__ctx, tcp->__off, doff);
#else
    __be16 old_word = 0, new_word;
    int ret;
    if (!tcp) return BNT_ERR_BAD_ARG;
    if (doff < 5 || doff > 15)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_bounds(tcp->__ctx, tcp->__off, doff * 4);
    if (ret) return ret;
    ret = __bnt_read_be16(tcp->__ctx, tcp->__off + 12, &old_word);
    if (ret) return ret;
    new_word = (old_word & bpf_htons(0x0fff)) | bpf_htons((__u16)doff << 12);
    ret = __bnt_write_be16(tcp->__ctx, tcp->__off + 12, new_word);
    if (ret) return ret;
    return __bnt_l4_csum16(tcp->__ctx, tcp->__off + offsetof(struct tcphdr, check), old_word, new_word, 0);
#endif
}

/* UDP setters */

/**
 * @ingroup bnt_udp
 * @brief Sets the UDP source port and fixes the UDP checksum.
 *
 * Leaves the checksum at 0 (disabled) if it was already 0.
 *
 * @param udp  Parsed UDP view.
 * @param port New source port.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_udp__set_sport(bnt_udp *udp, __u16 port)
{
    if (!udp) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_udp_set_port)(udp->__ctx, udp->__off, port, 0);
#else
    {
        __be16 old = 0, v = bpf_htons(port);
        int ret;
        ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, source), &old);
        if (ret) return ret;
        ret = __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, source), v);
        if (ret) return ret;
        return __bnt_l4_csum16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), old, v, 1);
    }
#endif
}

/**
 * @ingroup bnt_udp
 * @brief Sets the UDP destination port and fixes the UDP checksum.
 *
 * Leaves the checksum at 0 (disabled) if it was already 0.
 *
 * @param udp  Parsed UDP view.
 * @param port New destination port.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_udp__set_dport(bnt_udp *udp, __u16 port)
{
    if (!udp) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_udp_set_port)(udp->__ctx, udp->__off, port, 1);
#else
    {
        __be16 old = 0, v = bpf_htons(port);
        int ret;
        ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, dest), &old);
        if (ret) return ret;
        ret = __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, dest), v);
        if (ret) return ret;
        return __bnt_l4_csum16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), old, v, 1);
    }
#endif
}

/**
 * @ingroup bnt_udp
 * @brief Sets the UDP length field and fixes the UDP checksum.
 *
 * Leaves the checksum at 0 (disabled) if it was already 0.
 *
 * @param udp Parsed UDP view.
 * @param len New length, in bytes.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_udp__set_len(bnt_udp *udp, __u16 len)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!udp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_udp_set_len)(udp->__ctx, udp->__off, len);
#else
    __be16 old = 0, v = bpf_htons(len);
    int ret;
    if (!udp) return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, len), &old);
    if (ret) return ret;
    ret = __bnt_write_be16(udp->__ctx, udp->__off + offsetof(struct udphdr, len), v);
    if (ret) return ret;
    return __bnt_l4_csum16(udp->__ctx, udp->__off + offsetof(struct udphdr, check), old, v, 1);
#endif
}

/* IPv4 setters
 *
 * For byte-sized fields (TOS, TTL, protocol, IHL), we read the full 16-bit
 * word that contains the byte, replace only the relevant byte in host order,
 * then pass the old and new word __be16 values to __bnt_l3_csum16.  This
 * is required because csum_replace2 / bpf_csum_diff both operate on 16-bit
 * words, and the correct checksum delta depends on the byte's position within
 * that word (high byte vs low byte).
 *
 * IPv4 header layout for reference:
 *   offset 0:  version|IHL (HIGH byte of word 0)  TOS (LOW byte of word 0)
 *   offset 2:  total_len   (word 1, 16-bit)
 *   offset 4:  id          (word 2, 16-bit)
 *   offset 6:  frag_off    (word 3, 16-bit)
 *   offset 8:  TTL         (HIGH byte of word 4)  protocol (LOW byte of word 4)
 *   offset 10: check       (word 5, 16-bit)
 *   offset 12: saddr       (words 6-7, 32-bit)
 *   offset 16: daddr       (words 8-9, 32-bit)
 *
 * Fields that are part of the TCP/UDP pseudo-header (saddr, daddr, protocol,
 * tot_len) update both the IP header checksum and the L4 pseudo-header
 * checksum automatically for TCP and UDP when the L4 checksum field is
 * present in this packet.
 */

static __always_inline int __bnt_ipv4_update_pseudo16(bnt_ipv4 *ip, __be16 old, __be16 v)
{
    struct __bnt_ipv4_meta meta;
    __u32 csum_off;
    int ret;

    ret = __bnt_ipv4_meta_dispatch(ip, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_OK;
    if (meta.protocol == IPPROTO_TCP)
        csum_off = meta.next_off + offsetof(struct tcphdr, check);
    else if (meta.protocol == IPPROTO_UDP)
        csum_off = meta.next_off + offsetof(struct udphdr, check);
    else
        return BNT_OK;
    return __bnt_l4_pseudo_csum16(ip->__ctx, csum_off, old, v,
                                    meta.protocol == IPPROTO_UDP);
}

static __always_inline int __bnt_ipv4_update_pseudo32(bnt_ipv4 *ip, __be32 old, __be32 v)
{
    struct __bnt_ipv4_meta meta;
    __u32 csum_off;
    int ret;

    ret = __bnt_ipv4_meta_dispatch(ip, &meta);
    if (ret)
        return ret;
    if (!meta.l4_off_valid)
        return BNT_OK;
    if (meta.protocol == IPPROTO_TCP)
        csum_off = meta.next_off + offsetof(struct tcphdr, check);
    else if (meta.protocol == IPPROTO_UDP)
        csum_off = meta.next_off + offsetof(struct udphdr, check);
    else
        return BNT_OK;
    return __bnt_l4_pseudo_csum32(ip->__ctx, csum_off, old, v,
                                    meta.protocol == IPPROTO_UDP);
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_set_tos(BNT_CTX_TYPE *ctx, __u32 off, __u8 tos)
{
    struct iphdr *ip;
    __be16 old_w, new_w;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    old_w = __BNT_PKT_LOAD(*(__be16 *)ip);                                  /* version|IHL | TOS */
    new_w = bpf_htons((bpf_ntohs(old_w) & 0xFF00) | ((__u16)tos & 0x00FF));
    ip->tos   = tos;
    __BNT_PKT_STORE(ip->check, __bnt_csum16_update(__BNT_PKT_LOAD(ip->check), old_w, new_w));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
/* The TOS byte and the header checksum. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_tos_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 tos);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_tos_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 tos)
{
    return __bnt_ipv4_set_tos(ctx, off, tos);
}
#endif
#endif

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 TOS/DSCP+ECN byte and fixes the IPv4 header checksum.
 *
 * @param ip  Parsed IPv4 view.
 * @param tos New TOS/DSCP+ECN byte.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_tos(bnt_ipv4 *ip, __u8 tos)
{
    if (!ip) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv4_set_tos)(ip->__ctx, ip->__off, tos);
#else
    {
        __be16 old_w = 0, new_w;
        __u16 h;
        int ret;
        /* word 0: version|IHL (high) | TOS (low) */
        ret = __bnt_read_be16(ip->__ctx, ip->__off + 0, &old_w);
        if (ret) return ret;
        h = bpf_ntohs(old_w);
        new_w = bpf_htons((h & 0xFF00) | ((__u16)tos & 0x00FF));
        ret = __bnt_write_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, tos), tos);
        if (ret) return ret;
        return __bnt_l3_csum16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old_w, new_w);
    }
#endif
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_set_ttl(BNT_CTX_TYPE *ctx, __u32 off, __u8 ttl)
{
    struct iphdr *ip;
    __be16 old_w, new_w;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    old_w = __BNT_PKT_LOAD(*(__be16 *)((__u8 *)ip + offsetof(struct iphdr, ttl))); /* TTL | protocol */
    new_w = bpf_htons((bpf_ntohs(old_w) & 0x00FF) | ((__u16)ttl << 8));
    ip->ttl   = ttl;
    __BNT_PKT_STORE(ip->check, __bnt_csum16_update(__BNT_PKT_LOAD(ip->check), old_w, new_w));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_ttl_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 ttl);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_ttl_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 ttl)
{
    return __bnt_ipv4_set_ttl(ctx, off, ttl);
}
#endif
#endif

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 TTL and fixes the IPv4 header checksum.
 *
 * @param ip  Parsed IPv4 view.
 * @param ttl New TTL.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_ttl(bnt_ipv4 *ip, __u8 ttl)
{
    if (!ip) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv4_set_ttl)(ip->__ctx, ip->__off, ttl);
#else
    {
        __be16 old_w = 0, new_w;
        __u16 h;
        int ret;
        /* word 4: TTL (high) | protocol (low) */
        ret = __bnt_read_be16(ip->__ctx, ip->__off + 8, &old_w);
        if (ret) return ret;
        h = bpf_ntohs(old_w);
        new_w = bpf_htons((h & 0x00FF) | ((__u16)ttl << 8));
        ret = __bnt_write_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, ttl), ttl);
        if (ret) return ret;
        return __bnt_l3_csum16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old_w, new_w);
    }
#endif
}

#ifdef BNT_XDP_H
static __always_inline int __bnt_ipv4_dec_ttl(BNT_CTX_TYPE *ctx, __u32 off, bool *expired)
{
    struct iphdr *ip;
    __be16 old_w, new_w;
    __u8 ttl;
    int ret;

    if (expired)
        *expired = false;
    ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    ttl = ip->ttl;
    if (ttl <= 1) {
        if (expired)
            *expired = true;
        return BNT_ERR_BAD_STATE;
    }
    old_w = __BNT_PKT_LOAD(*(__be16 *)((__u8 *)ip + offsetof(struct iphdr, ttl))); /* TTL | protocol */
    new_w = bpf_htons((((__u16)(ttl - 1)) << 8) | (bpf_ntohs(old_w) & 0x00FF));
    ip->ttl   = ttl - 1;
    __BNT_PKT_STORE(ip->check, __bnt_csum16_update(__BNT_PKT_LOAD(ip->check), old_w, new_w));
    return BNT_OK;
}
#endif

#if !BNT_INLINE_ALL
/* The TTL, decremented unless it is 1 or less, and the header checksum. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_dec_ttl_g(BNT_CTX_TYPE *ctx, __u32 off, bool *expired);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_dec_ttl_g(BNT_CTX_TYPE *ctx, __u32 off, bool *expired)
{
    return __bnt_ipv4_dec_ttl(ctx, off, expired);
}
#endif
#endif

/**
 * @ingroup bnt_ipv4
 * @brief Decrements the IPv4 TTL by one and fixes the IPv4 header checksum.
 *
 * Refuses to decrement a TTL that is already at or below 1.
 *
 * @param ip      Parsed IPv4 view.
 * @param expired Set to true if the TTL was already at or below 1, false
 *                otherwise. May be NULL.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip is NULL.
 * @retval BNT_ERR_TRUNC     the read or write falls outside the packet.
 * @retval BNT_ERR_BAD_STATE the TTL is already at or below 1.
 */
static __always_inline int bnt_ipv4__dec_ttl(bnt_ipv4 *ip, bool *expired)
{
    if (expired)
        *expired = false;
    if (!ip)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv4_dec_ttl)(ip->__ctx, ip->__off, expired);
#else
    {
        __u8 ttl;
        int ret;
        ret = bnt_ipv4__get_ttl(ip, &ttl);
        if (ret)
            return ret;
        if (ttl <= 1) {
            if (expired)
                *expired = true;
            return BNT_ERR_BAD_STATE;
        }
        return bnt_ipv4__set_ttl(ip, ttl - 1);
    }
#endif
}

#ifdef BNT_XDP_H
/* The protocol byte, the header checksum and the TCP/UDP checksum, whose
 * pseudo-header holds the protocol. The old protocol tells which L4 header is
 * at off + ihl * 4. */
static __always_inline int __bnt_ipv4_set_protocol(BNT_CTX_TYPE *ctx, __u32 off, __u8 protocol)
{
    struct iphdr *ip;
    __be16 *check = NULL;
    __be16 old_w, new_w;
    __u8 old_proto;
    __u32 hlen;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;

    /* The L4 checksum is found first, so a call that fails writes nothing. */
    old_proto = ip->protocol;
    hlen = (__u32)(*(__u8 *)ip & 0x0f) * 4;
    if (hlen >= sizeof(struct iphdr) && (bpf_ntohs(__BNT_PKT_LOAD(ip->frag_off)) & IP_OFFSET) == 0 &&
        (old_proto == IPPROTO_TCP || old_proto == IPPROTO_UDP)) {
        ret = __bnt_data_ptr(ctx, off + hlen + (old_proto == IPPROTO_TCP ? offsetof(struct tcphdr, check)
                                                                         : offsetof(struct udphdr, check)),
                             sizeof(*check), (void **)&check);
        if (ret)
            return ret;
    }

    old_w = __BNT_PKT_LOAD(*(__be16 *)((__u8 *)ip + offsetof(struct iphdr, ttl))); /* TTL | protocol */
    new_w = bpf_htons((bpf_ntohs(old_w) & 0xFF00) | ((__u16)protocol & 0x00FF));
    ip->protocol = protocol;
    __BNT_PKT_STORE(ip->check, __bnt_csum16_update(__BNT_PKT_LOAD(ip->check), old_w, new_w));
    if (check) {
        __be16 c = __BNT_PKT_LOAD(*check);
        int udp = old_proto == IPPROTO_UDP;

        if (!(udp && c == 0)) {
            c = __bnt_csum16_update(c, bpf_htons((__u16)old_proto), bpf_htons((__u16)protocol));
            if (udp && c == 0)
                c = bpf_htons(0xffff);
            __BNT_PKT_STORE(*check, c);
        }
    }
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_protocol_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 protocol);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_protocol_g(BNT_CTX_TYPE *ctx, __u32 off, __u8 protocol)
{
    return __bnt_ipv4_set_protocol(ctx, off, protocol);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 protocol field and fixes the affected checksums.
 *
 * Updates the IPv4 header checksum and, when the upper layer is TCP or UDP,
 * the L4 pseudo-header checksum. The L4 update is skipped on a fragment.
 *
 * @param ip       Parsed IPv4 view.
 * @param protocol New upper-layer protocol number.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_protocol(bnt_ipv4 *ip, __u8 protocol)
{
    if (!ip) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv4_set_protocol)(ip->__ctx, ip->__off, protocol);
#else
    {
        struct __bnt_ipv4_meta meta;
        __be16 old_w = 0, new_w;
        __u16 h;
        __u32 csum_off;
        int ret;
        ret = __bnt_ipv4_meta_dispatch(ip, &meta);
        if (ret) return ret;
        /* word 4: TTL (high) | protocol (low) */
        ret = __bnt_read_be16(ip->__ctx, ip->__off + 8, &old_w);
        if (ret) return ret;
        h = bpf_ntohs(old_w);
        new_w = bpf_htons((h & 0xFF00) | ((__u16)protocol & 0x00FF));
        ret = __bnt_write_u8(ip->__ctx, ip->__off + offsetof(struct iphdr, protocol), protocol);
        if (ret) return ret;
        ret = __bnt_l3_csum16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old_w, new_w);
        if (ret) return ret;
        if (!meta.l4_off_valid) return BNT_OK;
        if (meta.protocol == IPPROTO_TCP)
            csum_off = meta.next_off + offsetof(struct tcphdr, check);
        else if (meta.protocol == IPPROTO_UDP)
            csum_off = meta.next_off + offsetof(struct udphdr, check);
        else
            return BNT_OK;
        return __bnt_l4_pseudo_csum16(ip->__ctx, csum_off,
                                        bpf_htons((__u16)meta.protocol),
                                        bpf_htons((__u16)protocol),
                                        meta.protocol == IPPROTO_UDP);
    }
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 header length (IHL) and fixes the IPv4 header checksum.
 *
 * @param ip   Parsed IPv4 view.
 * @param hlen New header length in bytes; must be a multiple of 4 between
 *             20 and 60.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL, or @p hlen is out of range or not a
 *                         multiple of 4.
 * @retval BNT_ERR_TRUNC   the new header length falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_hlen(bnt_ipv4 *ip, __u32 hlen)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv4_set_hlen)(ip->__ctx, ip->__off, hlen);
#else
    __be16 old_w = 0, new_w;
    __u8 old_first, new_first;
    __u16 h;
    int ret;
    if (!ip) return BNT_ERR_BAD_ARG;
    if (hlen < sizeof(struct iphdr) || hlen > 60 || (hlen & 3) != 0)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_bounds(ip->__ctx, ip->__off, hlen);
    if (ret) return ret;
    /* word 0: version|IHL (high) | TOS (low) */
    ret = __bnt_read_be16(ip->__ctx, ip->__off + 0, &old_w);
    if (ret) return ret;
    h = bpf_ntohs(old_w);
    old_first = (__u8)(h >> 8);
    new_first = (old_first & 0xF0) | (__u8)(hlen / 4);
    new_w = bpf_htons(((__u16)new_first << 8) | (h & 0x00FF));
    ret = __bnt_write_u8(ip->__ctx, ip->__off, new_first);
    if (ret) return ret;
    return __bnt_l3_csum16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old_w, new_w);
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 identification field and fixes the IPv4 header checksum.
 *
 * @param ip Parsed IPv4 view.
 * @param id New identification value.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_id(bnt_ipv4 *ip, __u16 id)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv4_set_id)(ip->__ctx, ip->__off, id);
#else
    __be16 old = 0, v = bpf_htons(id);
    int ret;
    if (!ip) return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, id), &old);
    if (ret) return ret;
    ret = __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, id), v);
    if (ret) return ret;
    return __bnt_l3_csum16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old, v);
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 fragment offset and flags word and fixes the IPv4 header checksum.
 *
 * @param ip       Parsed IPv4 view.
 * @param frag_off New fragment offset and flags word.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_frag_off(bnt_ipv4 *ip, __u16 frag_off)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv4_set_frag_off)(ip->__ctx, ip->__off, frag_off);
#else
    __be16 old = 0, v = bpf_htons(frag_off);
    int ret;
    if (!ip) return BNT_ERR_BAD_ARG;
    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, frag_off), &old);
    if (ret) return ret;
    ret = __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, frag_off), v);
    if (ret) return ret;
    return __bnt_l3_csum16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old, v);
#endif
}

#ifdef BNT_XDP_H
/* Every IPv4 fragment-flag set and clear: the bit in the fragment-offset word,
 * and the header checksum. */
static __always_inline int __bnt_ipv4_set_frag_flag(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled)
{
    struct iphdr *ip;
    __be16 old, v;
    __u16 w;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    old = __BNT_PKT_LOAD(*(__be16 *)((__u8 *)ip + offsetof(struct iphdr, frag_off)));
    w   = bpf_ntohs(old);
    if (enabled) w |= flag;
    else         w &= (__u16)~flag;
    v = bpf_htons(w);
    __BNT_PKT_STORE(*(__be16 *)((__u8 *)ip + offsetof(struct iphdr, frag_off)), v);
    __BNT_PKT_STORE(ip->check, __bnt_csum16_update(__BNT_PKT_LOAD(ip->check), old, v));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_frag_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_frag_flag_g(BNT_CTX_TYPE *ctx, __u32 off, __u16 flag, int enabled)
{
    return __bnt_ipv4_set_frag_flag(ctx, off, flag, enabled);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

static __always_inline int __bnt_ipv4__set_frag_flag(bnt_ipv4 *ip,
                                                      __u16 flag,
                                                      bool enabled)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv4_set_frag_flag)(ip->__ctx, ip->__off, flag, enabled);
#else
    {
        __u16 frag_off;
        int ret;

        ret = bnt_ipv4__get_frag_off(ip, &frag_off);
        if (ret)
            return ret;

        if (enabled)
            frag_off |= flag;
        else
            frag_off &= ~flag;

        return bnt_ipv4__set_frag_off(ip, frag_off);
    }
#endif
}

/** @ingroup bnt_ipv4
 *  Sets the reserved (evil) bit of the IPv4 fragment flags and fixes the IPv4 header checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_reserved_fragment_flag(bnt_ipv4 *ip)
{
    return __bnt_ipv4__set_frag_flag(ip, IP_RF, true);
}

/** @ingroup bnt_ipv4
 *  Clears the reserved (evil) bit of the IPv4 fragment flags and fixes the IPv4 header checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv4__clear_reserved_fragment_flag(bnt_ipv4 *ip)
{
    return __bnt_ipv4__set_frag_flag(ip, IP_RF, false);
}

/** @ingroup bnt_ipv4
 *  Sets the IPv4 Don't Fragment (DF) flag and fixes the IPv4 header checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_dont_fragment(bnt_ipv4 *ip)
{
    return __bnt_ipv4__set_frag_flag(ip, IP_DF, true);
}

/** @ingroup bnt_ipv4
 *  Clears the IPv4 Don't Fragment (DF) flag and fixes the IPv4 header checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv4__clear_dont_fragment(bnt_ipv4 *ip)
{
    return __bnt_ipv4__set_frag_flag(ip, IP_DF, false);
}

/** @ingroup bnt_ipv4
 *  Sets the IPv4 More Fragments (MF) flag and fixes the IPv4 header checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_more_fragments(bnt_ipv4 *ip)
{
    return __bnt_ipv4__set_frag_flag(ip, IP_MF, true);
}

/** @ingroup bnt_ipv4
 *  Clears the IPv4 More Fragments (MF) flag and fixes the IPv4 header checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 */
static __always_inline int bnt_ipv4__clear_more_fragments(bnt_ipv4 *ip)
{
    return __bnt_ipv4__set_frag_flag(ip, IP_MF, false);
}

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 total length field and fixes the affected checksums.
 *
 * Updates the IPv4 header checksum and, when the upper layer is TCP or UDP,
 * the L4 pseudo-header checksum, since the new length changes the L4 segment
 * length carried in the pseudo-header.
 *
 * @param ip        Parsed IPv4 view.
 * @param total_len New total length, in bytes.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv4 header, or
 *                          @p total_len is below its length.
 * @retval BNT_ERR_FRAGMENT the packet is a fragment and the upper layer is
 *                          TCP or UDP.
 */
static __always_inline int bnt_ipv4__set_total_len(bnt_ipv4 *ip, __u16 total_len)
{
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv4_set_total_len)(ip->__ctx, ip->__off, total_len);
#else
    struct __bnt_ipv4_meta meta;
    __be16 old = 0, v = bpf_htons(total_len);
    int ret;
    if (!ip) return BNT_ERR_BAD_ARG;
    ret = __bnt_ipv4_meta_dispatch(ip, &meta);
    if (ret) return ret;
    if (meta.is_fragment && __bnt_ipv4_l4_has_pseudo_csum(meta.protocol))
        return BNT_ERR_FRAGMENT;
    ret = __bnt_read_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, tot_len), &old);
    if (ret) return ret;
    ret = __bnt_write_be16(ip->__ctx, ip->__off + offsetof(struct iphdr, tot_len), v);
    if (ret) return ret;
    ret = __bnt_l3_csum16(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old, v);
    if (ret) return ret;
    return __bnt_ipv4_update_pseudo16(ip, old, v);
#endif
}

#ifdef BNT_XDP_H
/* set_saddr and set_daddr: the address, the header checksum and the TCP/UDP
 * checksum. Every IPv4 field is read before the pointer to the L4 checksum is
 * taken. */
static __always_inline int __bnt_ipv4_set_addr(BNT_CTX_TYPE *ctx, __u32 off, __be32 addr, int is_daddr)
{
    struct iphdr *ip;
    __be16 *check = NULL;
    __be32 old;
    __u32 hlen;
    __u8 proto;
    int ret = __bnt_data_ptr(ctx, off, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;

    /* The L4 checksum is found first, so a call that fails writes nothing. */
    hlen  = (__u32)(*(__u8 *)ip & 0x0f) * 4;
    proto = ip->protocol;
    if (hlen >= sizeof(struct iphdr) && (bpf_ntohs(__BNT_PKT_LOAD(ip->frag_off)) & IP_OFFSET) == 0 &&
        (proto == IPPROTO_TCP || proto == IPPROTO_UDP)) {
        ret = __bnt_data_ptr(ctx, off + hlen + (proto == IPPROTO_TCP ? offsetof(struct tcphdr, check)
                                                                     : offsetof(struct udphdr, check)),
                             sizeof(*check), (void **)&check);
        if (ret)
            return ret;
    }

    if (is_daddr) { old = __BNT_PKT_LOAD(ip->daddr); __BNT_PKT_STORE(ip->daddr, addr); }
    else          { old = __BNT_PKT_LOAD(ip->saddr); __BNT_PKT_STORE(ip->saddr, addr); }
    __BNT_PKT_STORE(ip->check, __bnt_csum32_update(__BNT_PKT_LOAD(ip->check), old, addr));
    if (check) {
        __be16 c = __BNT_PKT_LOAD(*check);
        int udp = proto == IPPROTO_UDP;

        if (!(udp && c == 0)) {                         /* UDP checksum 0 = none */
            c = __bnt_csum32_update(c, old, addr);
            if (udp && c == 0)
                c = bpf_htons(0xffff);
            __BNT_PKT_STORE(*check, c);
        }
    }
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_addr_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 addr, int is_daddr);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv4_set_addr_g(BNT_CTX_TYPE *ctx, __u32 off, __be32 addr, int is_daddr)
{
    return __bnt_ipv4_set_addr(ctx, off, addr, is_daddr);
}
#endif
#endif /* !BNT_INLINE_ALL */
#endif

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 source address and fixes the affected checksums.
 *
 * Updates the IPv4 header checksum and, when the upper layer is TCP or UDP,
 * the L4 pseudo-header checksum. The L4 update is skipped on a fragment.
 *
 * @param ip    Parsed IPv4 view.
 * @param saddr New source address, in network byte order.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_saddr(bnt_ipv4 *ip, __be32 saddr)
{
    if (!ip) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv4_set_addr)(ip->__ctx, ip->__off, saddr, 0);
#else
    {
        __be32 old = 0;
        int ret;
        ret = __bnt_read_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, saddr), &old);
        if (ret) return ret;
        ret = __bnt_write_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, saddr), saddr);
        if (ret) return ret;
        ret = __bnt_l3_csum32(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old, saddr);
        if (ret) return ret;
        return __bnt_ipv4_update_pseudo32(ip, old, saddr);
    }
#endif
}

/**
 * @ingroup bnt_ipv4
 * @brief Sets the IPv4 destination address and fixes the affected checksums.
 *
 * Updates the IPv4 header checksum and, when the upper layer is TCP or UDP, the
 * L4 pseudo-header checksum. The L4 update is skipped on a fragment.
 *
 * @param ip    Parsed IPv4 view.
 * @param daddr New destination address, in network byte order.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_daddr(bnt_ipv4 *ip, __be32 daddr)
{
    if (!ip) return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL || defined(BNT_XDP_H)
    return __BNT_OP(__bnt_ipv4_set_addr)(ip->__ctx, ip->__off, daddr, 1);
#else
    {
        __be32 old = 0;
        int ret;
        ret = __bnt_read_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, daddr), &old);
        if (ret) return ret;
        ret = __bnt_write_be32(ip->__ctx, ip->__off + offsetof(struct iphdr, daddr), daddr);
        if (ret) return ret;
        ret = __bnt_l3_csum32(ip->__ctx, ip->__off + offsetof(struct iphdr, check), old, daddr);
        if (ret) return ret;
        return __bnt_ipv4_update_pseudo32(ip, old, daddr);
    }
#endif
}

#define __bnt_try_or_return(expr, action) do { if ((expr)) return (action); } while (0)
