/* SPDX-License-Identifier: MIT */
#ifndef BNT_XDP_H
#define BNT_XDP_H

/* gcc only: #pragma unroll is clang's (gcc ignores it, as it should), and
 * -Wmaybe-uninitialized misfires on views that a parse call fills in only on
 * success. Both are silenced inside the BONet headers only. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

/*
 * bnt_xdp.h - verifier-friendly packet parsing helpers for XDP.
 *
 * Public header views are lightweight packet cursors: they keep only the XDP
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

/* IPv6 full-checksum recompute support in XDP (disabled by default due to verifier complexity) */
#ifndef BNT_XDP_IPV6_CSUM_SUPPORT
#define BNT_XDP_IPV6_CSUM_SUPPORT 0
#endif

/*
 * Build knobs:
 *   BNT_INLINE_ALL     0 = global mode (default), 1 = fully inline.
 *   BNT_LEGACY_KERNEL  for target kernels older than 5.12, which cannot run the
 *                      global mode. Forces inline mode and turns on the barriers
 *                      below, which steer clang's codegen into shapes those
 *                      verifiers follow, at the cost of more processed_insns and
 *                      stack. It has to be set by hand: the build cannot know
 *                      the target kernel.
 *
 * Gated on BNT_LEGACY_KERNEL:
 *   1. asm volatile("" : "+r"(ctx)) in __bnt_xdp_fresh_ctx — gives the verifier
 *      an independent data/data_end pair at every bounds check (no caching of
 *      ctx->data across accesses).
 *   2. __noinline on __bnt_len — isolates (data_end - data) in a sub-prog so it
 *      returns in a register instead of being re-derived in the caller.
 *   3. volatile on the __bnt_csum_range loop counters — keeps their tnum bounds
 *      from being re-derived off the unbounded stack copy of `len`.
 *
 * Always on:
 *   4. __bnt_shift_insert / __bnt_shift_remove copy the header prefix through a
 *      stack buffer: a packet pointer at a runtime offset (data+n) has verifier
 *      range 0 and cannot be accessed directly.
 *   5. Packet-derived scalars and runtime stack-array indices are pinned after
 *      narrowing — asm volatile on derived offsets (hlen, per-segment offsets)
 *      and a mask on the SRH segment index — so the narrowed bound survives
 *      instead of being re-derived.
 *
 * In inline mode the API is fused with the caller, whose register and stack
 * pressure can still make clang spill or fold in ways these barriers do not
 * cover. Only global mode is independent of the caller.
 */
#ifndef BNT_LEGACY_KERNEL
#define BNT_LEGACY_KERNEL 0
#endif

#if BNT_LEGACY_KERNEL
#ifdef BNT_INLINE_ALL
#undef BNT_INLINE_ALL
#endif
#define BNT_INLINE_ALL 1
#endif

#ifndef BNT_INLINE_ALL
#define BNT_INLINE_ALL 0
#endif

/* An operation: its global in global mode, its body (the same code, inlined)
 * in the inline build. */
#if BNT_INLINE_ALL
#define __BNT_OP(f) f
#else
#define __BNT_OP(f) f##_g
#endif

#ifndef __BPF_HELPERS__
static __wsum (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) =
    (void *)BPF_FUNC_csum_diff;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) =
    (void *)BPF_FUNC_fib_lookup;
static long (*bpf_xdp_adjust_head)(struct xdp_md *xdp_md, int delta) =
    (void *)BPF_FUNC_xdp_adjust_head;
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline, weak))
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

static __always_inline struct xdp_md *__bnt_xdp_fresh_ctx(struct xdp_md *ctx)
{
#if BNT_LEGACY_KERNEL
    asm volatile("" : "+r"(ctx));
#endif
    return ctx;
}

static __always_inline void *__bnt_xdp_data(struct xdp_md *ctx)
{
    ctx = __bnt_xdp_fresh_ctx(ctx);
    return (void *)(long)ctx->data;
}

static __always_inline void *__bnt_xdp_data_end(struct xdp_md *ctx)
{
    ctx = __bnt_xdp_fresh_ctx(ctx);
    return (void *)(long)ctx->data_end;
}

/* Length helper, lean by default.  Under BNT_LEGACY_KERNEL it is isolated in
 * its own sub-prog (item 2: keeps the data_end-data subtraction out of the
 * caller's register allocation); otherwise it is always_inline. */
#if BNT_LEGACY_KERNEL
static __noinline __u32 __bnt_len(struct xdp_md *ctx)
#else
static __always_inline __u32 __bnt_len(struct xdp_md *ctx)
#endif
{
    ctx = __bnt_xdp_fresh_ctx(ctx);
    return ctx->data_end - ctx->data;
}

static __always_inline int __bnt_bounds_len(__u32 pkt_len, __u32 off, __u32 len)
{
    if (off > pkt_len)
        return BNT_ERR_TRUNC;
    if (len > pkt_len - off)
        return BNT_ERR_TRUNC;
    return BNT_OK;
}

static __always_inline int __bnt_bounds(struct xdp_md *ctx, __u32 off, __u32 len)
{
    return __bnt_bounds_len(__bnt_len(ctx), off, len);
}

#ifndef BNT_XDP_MAX_PACKET_OFFSET
#define BNT_XDP_MAX_PACKET_OFFSET 0xffffu
#endif

/*
 * gcc assumes the caller zero-extended a 32-bit argument and adds it to a
 * pointer as is. The verifier does not: a global's arguments are unknown 64-bit
 * scalars. BNT_ZEXT32(x) zero-extends x in place with one w = w; gcc takes a
 * 32-bit value as already extended, so the move has to be in asm. The asm also
 * hides what gcc knows about x, so the checks after it stay. clang always
 * zero-extends, so it is empty there.
 */
#if defined(__GNUC__) && !defined(__clang__)
#define BNT_ZEXT32(x) asm volatile("{mov32 %0,%0|%w0 = %w0}" : "+r"(x))
#else
#define BNT_ZEXT32(x) ((void)(x))
#endif

static __always_inline int __bnt_data_ptr(struct xdp_md *ctx, __u32 off, __u32 len, void **out)
{
    unsigned char *base;
    unsigned char *ptr;
    void *end;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = NULL;
    /* Before the checks, so gcc cannot drop them as already proven. */
    BNT_ZEXT32(off);
    if (len > BNT_XDP_MAX_PACKET_OFFSET)
        return BNT_ERR_TRUNC;
    if (off > BNT_XDP_MAX_PACKET_OFFSET - len)
        return BNT_ERR_TRUNC;

    base = __bnt_xdp_data(ctx);
    end = __bnt_xdp_data_end(ctx);
    ptr = base + off;
    if ((void *)(ptr + len) > end)
        return BNT_ERR_TRUNC;

    *out = ptr;
    return BNT_OK;
}

/* __bnt_data_ptr for an offset the caller has already bounded, pinned in a
 * register, at most BNT_XDP_MAX_PACKET_OFFSET - len: only the end test is left. */
static __always_inline int __bnt_data_ptr_in_range(struct xdp_md *ctx, __u32 off, __u32 len, void **out)
{
    unsigned char *ptr = (unsigned char *)__bnt_xdp_data(ctx) + off;

    if ((void *)(ptr + len) > __bnt_xdp_data_end(ctx))
        return BNT_ERR_TRUNC;
    *out = ptr;
    return BNT_OK;
}

static __always_inline int __bnt_read(struct xdp_md *ctx, __u32 off, void *dst, __u32 len)
{
    void *src;
    int ret;

    if (!dst)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_data_ptr(ctx, off, len, &src);
    if (ret)
        return ret;

    __builtin_memcpy(dst, src, len);
    return BNT_OK;
}

static __always_inline int __bnt_write(struct xdp_md *ctx, __u32 off, const void *src, __u32 len)
{
    void *dst;
    int ret;

    if (!src)
        return BNT_ERR_BAD_ARG;

    ret = __bnt_data_ptr(ctx, off, len, &dst);
    if (ret)
        return ret;

    __builtin_memcpy(dst, src, len);
    return BNT_OK;
}

/*
 * Packet alignment, see bnt_rw.h. Set here because the wide copies below must
 * be in place before bnt_rw.h is included.
 */
#ifndef BNT_STRICT_ALIGN
#if defined(__TARGET_ARCH_riscv) || defined(__TARGET_ARCH_loongarch) || \
    defined(__TARGET_ARCH_mips) || defined(__TARGET_ARCH_sparc)
#define BNT_STRICT_ALIGN 1
#else
#define BNT_STRICT_ALIGN 0
#endif
#endif

/*
 * Global mode ships the globals as frozen BPF assembly (bnt_asm_globals.h),
 * so their code does not depend on the compiler that builds the program. The
 * asm is in clang's syntax and was built for little-endian targets with
 * unaligned packet access; elsewhere the C definitions are used. Set
 * BNT_ASM_GLOBALS=0 to always use the C definitions.
 */
#ifndef BNT_ASM_GLOBALS
#if defined(__clang__) && !BNT_STRICT_ALIGN && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BNT_ASM_GLOBALS 1
#else
#define BNT_ASM_GLOBALS 0
#endif
#endif

#if !BNT_STRICT_ALIGN
/*
 * Global mode without BNT_STRICT_ALIGN: __bnt_read/__bnt_write copy in chunks
 * as wide as the alignment of the non-packet side's type, instead of byte by
 * byte. The packet side may be misaligned, which this configuration allows; the
 * other side keeps its type's alignment, which the verifier always enforces on
 * the stack. The chunk types are may_alias: the destination is often a struct
 * or an array of another type, and plain __u32 stores into it would let clang
 * treat it as never written.
 */
typedef __u64 __attribute__((may_alias)) __bnt_chunk64;
typedef __u32 __attribute__((may_alias)) __bnt_chunk32;
typedef __u16 __attribute__((may_alias)) __bnt_chunk16;

static __always_inline void __bnt_copy_wide(void *dst, const void *src, __u32 len, __u32 align)
{
    __u32 i = 0;

#pragma unroll
    for (; align >= 8 && i + 8 <= len; i += 8)
        *(__bnt_chunk64 *)((__u8 *)dst + i) = *(const __bnt_chunk64 *)((const __u8 *)src + i);
#pragma unroll
    for (; align >= 4 && i + 4 <= len; i += 4)
        *(__bnt_chunk32 *)((__u8 *)dst + i) = *(const __bnt_chunk32 *)((const __u8 *)src + i);
#pragma unroll
    for (; align >= 2 && i + 2 <= len; i += 2)
        *(__bnt_chunk16 *)((__u8 *)dst + i) = *(const __bnt_chunk16 *)((const __u8 *)src + i);
#pragma unroll
    for (; i < len; i++)
        ((__u8 *)dst)[i] = ((const __u8 *)src)[i];
}

static __always_inline int __bnt_read_wide(struct xdp_md *ctx, __u32 off, void *dst,
                                           __u32 len, __u32 align)
{
    void *src;
    int ret;

    if (!dst)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_data_ptr(ctx, off, len, &src);
    if (ret)
        return ret;
    __bnt_copy_wide(dst, src, len, align);
    return BNT_OK;
}

static __always_inline int __bnt_write_wide(struct xdp_md *ctx, __u32 off, const void *src,
                                            __u32 len, __u32 align)
{
    void *dst;
    int ret;

    if (!src)
        return BNT_ERR_BAD_ARG;
    ret = __bnt_data_ptr(ctx, off, len, &dst);
    if (ret)
        return ret;
    __bnt_copy_wide(dst, src, len, align);
    return BNT_OK;
}

#define __bnt_read(ctx, off, dst, len)                                         \
    __bnt_read_wide((ctx), (off), (dst), (len), __alignof__(*(dst)))
#define __bnt_write(ctx, off, src, len)                                        \
    __bnt_write_wide((ctx), (off), (src), (len), __alignof__(*(src)))
#endif

/* XDP sees raw pre-GRO packets: standard MTU 1500. */
#ifndef BNT_MAX_PAYLOAD
#define BNT_MAX_PAYLOAD 1500
#endif

/*
 * BNT_CSUM_CHUNK must be a power of 2 in the XDP path so that chunk count
 * and remainder can be derived via shift/mask, giving the BPF verifier precise
 * tnum bounds that survive stack spills across bpf_csum_diff calls.
 */
#ifndef BNT_CSUM_CHUNK
#define BNT_CSUM_CHUNK 64
#endif
/* bpf_csum_diff takes at most 512 bytes; the checksum code relies on it never
 * failing, so the chunk must stay within that. */
_Static_assert(BNT_CSUM_CHUNK >= 4 && BNT_CSUM_CHUNK <= 512 && !(BNT_CSUM_CHUNK & (BNT_CSUM_CHUNK - 1)),
               "BNT_CSUM_CHUNK must be a power of 2 between 4 and 512");

/* Define context type before including shared helpers. */
#define BNT_CTX_TYPE struct xdp_md
#include "bnt_rw.h"

/*
 * Fixed-size single-block checksum global.  Straight-line (no loop) and with a
 * compile-time constant length, so __bnt_data_ptr threads its bounds check into
 * the pointer exactly as in the read primitives: bpf_csum_diff sees a packet
 * pointer with a provable, constant range even when off arrives with a wide
 * var_off.  __bnt_csum_range drives it from a loop that carries only the
 * scalar offset and accumulator, never a packet pointer.
 */
static __always_inline int __bnt_csum_blk(struct xdp_md *ctx, __u32 off,
                                                __wsum seed, __wsum *out)
{
    void  *p;
    __s64  res;
    int    ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = seed;
    ret = __bnt_data_ptr(ctx, off, BNT_CSUM_CHUNK, &p);
    if (ret)
        return ret;
    /* bpf_csum_diff fails only on a size that is not a multiple of 4 or is
     * over 512 bytes; every call in BONet passes a constant that is neither. */
    res = bpf_csum_diff(NULL, 0, (__be32 *)p, BNT_CSUM_CHUNK, seed);
    *out = (__wsum)res;
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_csum_blk_g(struct xdp_md *ctx, __u32 off,
                                                __wsum seed, __wsum *out);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1))) int __bnt_csum_blk_g(struct xdp_md *ctx, __u32 off,
                                                __wsum seed, __wsum *out)
{
    return __bnt_csum_blk(ctx, off, seed, out);
}
#endif
#endif /* !BNT_INLINE_ALL */


/*
 * XDP __bnt_csum_range. `len` reloaded from its stack slot is unbounded even
 * after the check on it (the verifier does not carry a register's bounds back
 * to the slot), and clang may recompute n_chunks/n_words from that reload
 * instead of keeping the bounded values. Under BNT_LEGACY_KERNEL they are
 * volatile: each gets its own slot, written once from the bounded register, so
 * every loop condition sees the [0, BNT_MAX_PAYLOAD/CHUNK] bound.
 */
static __always_inline int __bnt_csum_range(struct xdp_md *ctx, __u32 off, __u32 len,
                                             __wsum seed, __wsum *out)
{
    __wsum acc = seed;
    __u32  i;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;

    if (len > BNT_MAX_PAYLOAD)
        return BNT_ERR_TRUNC;
    /* Bound off before deriving ptr (mirrors __bnt_data_ptr): once off arrives
     * unconstrained from another global's result, the bounds checks below cannot
     * recover a usable packet range without this clamp. */
    if (off > 0xffffu - len)
        return BNT_ERR_TRUNC;

    /* computed while len is still bounded; see above */
#if BNT_LEGACY_KERNEL
    volatile __u32 n_chunks = len >> __builtin_ctz(BNT_CSUM_CHUNK);
    volatile __u32 n_words  = (len & (__u32)(BNT_CSUM_CHUNK - 1)) >> 2;
#else
    __u32 n_chunks = len >> __builtin_ctz(BNT_CSUM_CHUNK);
    __u32 n_words  = (len & (__u32)(BNT_CSUM_CHUNK - 1)) >> 2;
#endif
    __u32 rem               = len & (__u32)(BNT_CSUM_CHUNK - 1);

    /*
     * Only the offset (cur) crosses the loop back-edge; each block gets its own
     * range-checked pointer. A packet pointer carried across the back-edge loses
     * its range when off has a wide var_off.
     */
    __u32 cur = off;
    int   ret;

    /* The whole range is tested once, so no block can fall outside the
     * packet and their results need no test. */
    if (off + len > __bnt_len(ctx))
        return BNT_ERR_TRUNC;
    for (i = 0; i < BNT_MAX_PAYLOAD / BNT_CSUM_CHUNK + 1; i++) {
        if (i >= n_chunks)
            break;
        __BNT_OP(__bnt_csum_blk)(ctx, cur, acc, &acc);
        cur += BNT_CSUM_CHUNK;
    }

    /*
     * The rest (under one chunk) summed in place from bounded pointers:
     * the same one's-complement sum as bpf_csum_diff, without a helper
     * call per word, whose clobbers would spill the loop counter (5.12
     * loses it when spilled as 32 bits).
     */
    rem &= 3U;
    if (n_words || rem) {
        __u64 sum = acc;
        void *end;

        if (cur > 0xff7fu)          /* a range the verifier can add to a pointer */
            return BNT_ERR_TRUNC;
        asm volatile("" : "+r"(cur));  /* BNT_PIN, defined in bnt_core.h */
        end = (void *)(long)ctx->data_end;
        if (n_words) {
            const __u32 *p;

            ret = __bnt_data_ptr_in_range(ctx, cur, 4, (void **)&p);
            if (ret)
                return ret;
            for (i = 0; i < BNT_CSUM_CHUNK / 4 - 1; i++) {   /* n_words < CHUNK / 4 */
                if (i >= n_words)
                    break;
                if ((void *)(p + 1) > end)
                    return BNT_ERR_TRUNC;
                sum += __BNT_PKT_LOAD(*p);
                p++;
            }
            cur += n_words * 4;
            asm volatile("" : "+r"(cur));
        }
        if (rem) {                  /* the last 1-3 bytes, zero-padded to a word */
            __be32 tail = 0;
            __u8  *t    = (__u8 *)&tail;
            const __u8 *p;

            if (cur > 0xff7fu)      /* bounded again: 5.12 loses n_words if spilled */
                return BNT_ERR_TRUNC;
            asm volatile("" : "+r"(cur));
            ret = __bnt_data_ptr_in_range(ctx, cur, 1, (void **)&p);
            if (ret)
                return ret;
            t[0] = p[0];
            if (rem >= 2) {
                if ((void *)(p + 2) > end)
                    return BNT_ERR_TRUNC;
                t[1] = p[1];
            }
            if (rem >= 3) {
                if ((void *)(p + 3) > end)
                    return BNT_ERR_TRUNC;
                t[2] = p[2];
            }
            sum += tail;
        }
        sum = (sum & 0xffffffffu) + (sum >> 32);
        sum = (sum & 0xffffffffu) + (sum >> 32);
        acc = (__wsum)sum;
    }

    *out = acc;
    return BNT_OK;
}

/* XDP: pure inline arithmetic, no helper call. */
static __always_inline __be16 __bnt_csum16_update(__be16 check, __be16 from, __be16 to)
{
    __u32 sum = (~(__u32)bpf_ntohs(check)) & 0xffff;
    sum += (~(__u32)bpf_ntohs(from)) & 0xffff;
    sum += (__u32)bpf_ntohs(to);
    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

static __always_inline __be16 __bnt_csum32_update(__be16 check, __be32 from, __be32 to)
{
    __u32 from_h = bpf_ntohl(from);
    __u32 to_h   = bpf_ntohl(to);
    __u32 sum = (~(__u32)bpf_ntohs(check)) & 0xffff;
    sum += (~(from_h >> 16)) & 0xffff;
    sum += (~from_h) & 0xffff;
    sum += to_h >> 16;
    sum += to_h & 0xffff;
    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

static __always_inline int __bnt_l4_csum16(struct xdp_md *ctx, __u32 off,
                                             __be16 from, __be16 to, int mangled)
{
    __be16 check, new_check;
    int ret = __bnt_read_be16(ctx, off, &check);
    if (ret) return ret;
    if (mangled && check == 0) return BNT_OK;
    new_check = __bnt_csum16_update(check, from, to);
    if (mangled && new_check == 0) new_check = bpf_htons(0xffff);
    return __bnt_write_be16(ctx, off, new_check);
}
static __always_inline int __bnt_l4_csum32(struct xdp_md *ctx, __u32 off,
                                             __be32 from, __be32 to, int mangled)
{
    __be16 check, new_check;
    int ret = __bnt_read_be16(ctx, off, &check);
    if (ret) return ret;
    if (mangled && check == 0) return BNT_OK;
    new_check = __bnt_csum32_update(check, from, to);
    if (mangled && new_check == 0) new_check = bpf_htons(0xffff);
    return __bnt_write_be16(ctx, off, new_check);
}
static __always_inline int __bnt_l4_pseudo_csum16(struct xdp_md *ctx, __u32 off,
                                                    __be16 from, __be16 to, int mangled)
{
    return __bnt_l4_csum16(ctx, off, from, to, mangled);
}
static __always_inline int __bnt_l4_pseudo_csum32(struct xdp_md *ctx, __u32 off,
                                                    __be32 from, __be32 to, int mangled)
{
    return __bnt_l4_csum32(ctx, off, from, to, mangled);
}
static __always_inline int __bnt_l3_csum16(struct xdp_md *ctx, __u32 off,
                                             __be16 from, __be16 to)
{
    __be16 check;
    int ret = __bnt_read_be16(ctx, off, &check);
    if (ret) return ret;
    return __bnt_write_be16(ctx, off, __bnt_csum16_update(check, from, to));
}
static __always_inline int __bnt_l3_csum32(struct xdp_md *ctx, __u32 off,
                                             __be32 from, __be32 to)
{
    __be16 check;
    int ret = __bnt_read_be16(ctx, off, &check);
    if (ret) return ret;
    return __bnt_write_be16(ctx, off, __bnt_csum32_update(check, from, to));
}


#include "bnt_core.h"
#undef BNT_CTX_TYPE

#define try_or_return_pass(expr)     __bnt_try_or_return(expr, XDP_PASS)
#define try_or_return_drop(expr)     __bnt_try_or_return(expr, XDP_DROP)
#define try_or_return_tx(expr)       __bnt_try_or_return(expr, XDP_TX)
#define try_or_return_redirect(expr) __bnt_try_or_return(expr, XDP_REDIRECT)
#define try_or_return_aborted(expr)  __bnt_try_or_return(expr, XDP_ABORTED)

/* Raw setters for callers that will recompute checksums from scratch. */
/** @ingroup bnt_ipv4
 *  Sets the IPv4 TOS/DSCP+ECN byte without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_tos_no_csum(bnt_ipv4 *ip, __u8 tos)
    { return __bnt_ipv4__set_tos_raw(ip, tos); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 TTL without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_ttl_no_csum(bnt_ipv4 *ip, __u8 ttl)
    { return __bnt_ipv4__set_ttl_raw(ip, ttl); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 source address without updating any checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_saddr_no_csum(bnt_ipv4 *ip, __be32 saddr)
    { return __bnt_ipv4__set_saddr_raw(ip, saddr); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 destination address without updating any checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_daddr_no_csum(bnt_ipv4 *ip, __be32 daddr)
    { return __bnt_ipv4__set_daddr_raw(ip, daddr); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 identification field without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_id_no_csum(bnt_ipv4 *ip, __u16 id)
    { return __bnt_ipv4__set_id_raw(ip, id); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 total length field without updating any checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_total_len_no_csum(bnt_ipv4 *ip, __u16 total_len)
    { return __bnt_ipv4__set_total_len_raw(ip, total_len); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 protocol field without updating any checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_protocol_no_csum(bnt_ipv4 *ip, __u8 protocol)
    { return __bnt_ipv4__set_protocol_raw(ip, protocol); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 fragment offset and flags word without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_frag_off_no_csum(bnt_ipv4 *ip, __u16 frag_off)
    { return __bnt_ipv4__set_frag_off_raw(ip, frag_off); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 IHL (header length) without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL, or @p hlen is not a multiple of 4
 *                         between 20 and 60.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_ipv4__set_hlen_no_csum(bnt_ipv4 *ip, __u32 hlen)
    { return __bnt_ipv4__set_hlen_raw(ip, hlen); }


/*
 * BNT_XDP_MAX_HEADER_PREFIX — maximum byte length of the header prefix that
 * bnt will shift when inserting or removing a header layer.
 *
 * "Prefix" means all bytes that come BEFORE the insertion/removal point and
 * must be moved to make room (or close the gap).  For a standard program this
 * is the Ethernet frame header plus any VLAN tags:
 *
 *   14 bytes  plain Ethernet
 *   18 bytes  Ethernet + 1 VLAN tag (802.1Q)
 *   22 bytes  Ethernet + 2 VLAN tags (QinQ / 802.1ad)
 *
 * When inserting a header deeper in the stack — e.g. an SRH after an outer
 * IPv6 header — the prefix also includes all the headers above the insertion
 * point.  For Ethernet + QinQ + outer IPv6 (the deepest case in this library):
 *
 *   62 bytes  Ethernet (14) + QinQ (8) + IPv6 base (40)
 *
 * It is also the loop bound of the prefix copy, so a smaller value means less
 * verifier work. The default of 64 covers Ethernet/VLAN/IPv6 stacks. Define it
 * before #include <bnt_xdp.h> to change it, e.g. 22 for Ethernet + QinQ only,
 * or 94 for Ethernet + QinQ + IPv4 + IPv6. The variable-size shift copies the
 * prefix through the stack, which bounds it at 512 bytes. A prefix longer than
 * the bound returns BNT_ERR_TOO_DEEP.
 */
#ifndef BNT_XDP_MAX_HEADER_PREFIX
#define BNT_XDP_MAX_HEADER_PREFIX 64
#endif

/*
 * Packet-header shift helpers.
 *
 * Two families:
 *
 *   __bnt_shift_insert(ctx, prefix_len, n)   — variable n, uses a stack
 *   __bnt_shift_remove(ctx, prefix_len, n)     buffer.  Called only from
 *                                                SRH paths where n (= srh_size)
 *                                                is not known at compile time.
 *
 *   __bnt_shift_insert_N(ctx, prefix_len)    — N is a compile-time constant;
 *   __bnt_shift_remove_N(ctx, prefix_len)      no buffer needed (see below).
 *                                                Used for VLAN (N=4), IPv4
 *                                                (N=20), IPv6/MPLS (N=40).
 *
 * Why the buffer is necessary for variable n:
 *   The BPF verifier only updates a packet pointer's readable range (r field)
 *   when the pointer has var_off = 0 (constant base).  Any pointer derived as
 *   data+n where n is a runtime scalar gets range=0 permanently, so all byte
 *   accesses through it are rejected regardless of bounds checks.  The stack
 *   buffer sidesteps this by keeping both loops on data+i (constant base).
 *
 * Why constant N works without a buffer:
 *   "data + MAX + N ≤ data_end" sets data.r = MAX + N.
 *   shifted = data + N  (constant addition)  →  shifted.r = MAX.
 *   The loop counter i is tracked as a precise value at each iteration, so
 *   (shifted+i).r = MAX−i ≥ 1 for all i < MAX.  No per-byte checks needed.
 *
 * These helpers are always_inline.  At BNT_INLINE_ALL=0 the shift logic is fused
 * directly into the per-operation insert/remove globals (one global per
 * operation, verified once); the standalone helpers are then used only by the
 * BNT_INLINE_ALL=1 (fully inline) wrappers.
 */
#define __BNT_SHIFT_LINKAGE static __always_inline

/*
 * Loop bound for the prefix copy of the fixed-size inserts. In global mode
 * prefix_len is not a constant, and with 32-bit compares (-mcpu=v3) each exit
 * of the copy loop narrows it to a different range; since the insert global
 * uses prefix_len after the loop, the verifier cannot merge the exits and
 * walks the rest of the global once per exit (up to BNT_XDP_MAX_HEADER_PREFIX
 * times). Comparing against a copy made by an AND, which the verifier does not
 * link to prefix_len, leaves prefix_len untouched. The AND is a no-op
 * (prefix_len <= the prefix limit). The variable-size shift uses the 32-bit
 * form below; the removes do not need it.
 */
#if BNT_INLINE_ALL
/* 32-bit, as prefix_len: with a 64-bit bound clang turns the inline copy into a memmove call */
typedef __u32 __bnt_copy_limit_t;
#define __BNT_COPY_LIMIT(x) (x)
#define __BNT_COPY_LIMIT32(x) (x)
#else
typedef __u64 __bnt_copy_limit_t;
static __always_inline __u64 __BNT_COPY_LIMIT(__u64 x)
{
    asm volatile("%0 &= 0xffff" : "+r"(x));
    return x;
}

/* The same on a 32-bit subregister, for the copy through the stack buffer:
 * with the 64-bit form clang zero-extends the bound with two shifts per loop.
 * gcc has no "w" constraint. */
static __always_inline __u32 __BNT_COPY_LIMIT32(__u32 x)
{
#ifdef __clang__
    asm volatile("%0 &= 0xffff" : "+w"(x));
#else
    asm volatile("%0 &= 0xffff" : "+r"(x));
#endif
    return x;
}
#endif

__BNT_SHIFT_LINKAGE int __bnt_shift_insert(struct xdp_md *ctx,
                                                   __u32 prefix_len, __u32 n)
{
    __u8 buf[BNT_XDP_MAX_HEADER_PREFIX] __attribute__((aligned(8)));
    void *data, *data_end;
    __u32 i;
    __u32 lim;

    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)
        return BNT_ERR_TOO_DEEP;

    data     = __bnt_xdp_data(ctx);
    data_end = __bnt_xdp_data_end(ctx);
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX > (__u8 *)data_end)
        return BNT_ERR_TRUNC;
#if BNT_STRICT_ALIGN
    /* zeroed: before 6.3 the verifier rejects reading bytes of buf the loop below did not write */
    __builtin_memset(buf, 0, sizeof(buf));
    lim = __BNT_COPY_LIMIT32(prefix_len);
    for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {
        if (i >= lim)
            break;
        buf[i] = *((__u8 *)data + i);
    }
#else
    for (i = 0; i + 8 <= BNT_XDP_MAX_HEADER_PREFIX; i += 8)
        *(__u64 *)(buf + i) = *(__u64 *)((__u8 *)data + i);
    for (; i < BNT_XDP_MAX_HEADER_PREFIX; i++)
        buf[i] = *((__u8 *)data + i);
#endif

    if (bpf_xdp_adjust_head(ctx, -(int)n))
        return BNT_ERR_WRITE;

    data     = __bnt_xdp_data(ctx);
    data_end = __bnt_xdp_data_end(ctx);
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX > (__u8 *)data_end)
        return BNT_ERR_TRUNC;
    lim = __BNT_COPY_LIMIT32(prefix_len);
    for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {
        if (i >= lim)
            break;
        *((__u8 *)data + i) = buf[i];
    }
    return BNT_OK;
}

__BNT_SHIFT_LINKAGE int __bnt_shift_remove(struct xdp_md *ctx,
                                                   __u32 prefix_len, __u32 n)
{
    __u8 buf[BNT_XDP_MAX_HEADER_PREFIX];
    void *data, *data_end;
    __u32 i;

    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)
        return BNT_ERR_TOO_DEEP;

    data     = __bnt_xdp_data(ctx);
    data_end = __bnt_xdp_data_end(ctx);
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX > (__u8 *)data_end)
        return BNT_ERR_TRUNC;
    for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {
        if (i >= prefix_len)
            break;
        buf[i] = *((__u8 *)data + i);
    }

    if (bpf_xdp_adjust_head(ctx, (int)n))
        return BNT_ERR_WRITE;

    data     = __bnt_xdp_data(ctx);
    data_end = __bnt_xdp_data_end(ctx);
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX > (__u8 *)data_end)
        return BNT_ERR_TRUNC;
    for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {
        if (i >= prefix_len)
            break;
        *((__u8 *)data + i) = buf[i];
    }
    return BNT_OK;
}

/*
 * The prefix moves back by N into the new room. Every check is done before
 * the packet grows, so a call that fails leaves it as it was. An Ethernet
 * header at offset 0 (the common case) needs only its 14 bytes and is moved
 * with three loads before three stores; any other prefix is copied byte by
 * byte from a BNT_XDP_MAX_HEADER_PREFIX window, so the frame must hold that
 * many bytes.
 */
#if BNT_STRICT_ALIGN
#define __BNT_SHIFT_INSERT_ETH(data, shifted)                                   \
    do {                                                                         \
        for (i = 0; i < ETH_HLEN; i++)                                           \
            *((__u8 *)(data) + i) = *((shifted) + i);                            \
    } while (0)
#else
#define __BNT_SHIFT_INSERT_ETH(data, shifted)                                   \
    do {                                                                         \
        __u64 a = *(__u64 *)(shifted);                                           \
        __u32 b = *(__u32 *)((shifted) + 8);                                     \
        __u16 c = *(__u16 *)((shifted) + 12);                                    \
        *(__u64 *)(data) = a;                                                    \
        *(__u32 *)((__u8 *)(data) + 8) = b;                                      \
        *(__u16 *)((__u8 *)(data) + 12) = c;                                     \
    } while (0)
#endif

#define __BNT_SHIFT_INSERT_FIXED(N)                                             \
__BNT_SHIFT_LINKAGE int __bnt_shift_insert_##N(struct xdp_md *ctx,            \
                                                  __u32 prefix_len)              \
{                                                                                 \
    void *data, *data_end;                                                       \
    __u8 *shifted;                                                                \
    __u32 i;                                                                     \
    __bnt_copy_limit_t lim;                                                      \
    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)                                \
        return BNT_ERR_TOO_DEEP;                                               \
    if ((__u8 *)(long)ctx->data + (prefix_len == ETH_HLEN ? ETH_HLEN : BNT_XDP_MAX_HEADER_PREFIX) > \
        (__u8 *)(long)ctx->data_end)                                             \
        return BNT_ERR_TRUNC;                                                  \
    if (bpf_xdp_adjust_head(ctx, -(int)(N)))                                    \
        return BNT_ERR_WRITE;                                                  \
    data     = (void *)(long)ctx->data;                                          \
    data_end = (void *)(long)ctx->data_end;                                      \
    shifted  = (__u8 *)data + (N);                                               \
    if (prefix_len == ETH_HLEN && (__u8 *)data + ETH_HLEN + (N) <= (__u8 *)data_end) { \
        __BNT_SHIFT_INSERT_ETH(data, shifted);                                   \
        return BNT_OK;                                                           \
    }                                                                            \
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX + (N) > (__u8 *)data_end)    \
        return BNT_ERR_TRUNC;                                                  \
    lim = __BNT_COPY_LIMIT(prefix_len);                                          \
    for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {                         \
        if (i >= lim)                                                            \
            break;                                                               \
        *((__u8 *)data + i) = *(shifted + i);                                   \
    }                                                                             \
    return BNT_OK;                                                              \
}

/*
 * The prefix moves forward by N. When longer than N it overlaps itself, so the
 * forward byte copy would read bytes it already overwrote: then it goes through
 * a buffer, read whole as in __bnt_shift_insert. An Ethernet header at offset 0
 * (the common remove_vlan) is moved without it: three loads before three
 * stores, or with BNT_STRICT_ALIGN a copy from the end.
 */
#if BNT_STRICT_ALIGN
#define __BNT_SHIFT_REMOVE_ETH(data, shifted, prefix_len)                       \
    ((prefix_len) == ETH_HLEN && ({                                              \
        for (i = ETH_HLEN; i-- > 0;)                                             \
            *((shifted) + i) = *((__u8 *)(data) + i);                            \
        1;                                                                       \
    }))
#define __BNT_SHIFT_REMOVE_READ(buf, data)                                      \
    do {                                                                         \
        for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++)                          \
            ((__u8 *)buf)[i] = *((__u8 *)(data) + i);                            \
    } while (0)
#else
#define __BNT_SHIFT_REMOVE_ETH(data, shifted, prefix_len)                       \
    ((prefix_len) == ETH_HLEN && ({                                              \
        __u64 a = *(__u64 *)(data);                                              \
        __u32 b = *(__u32 *)((__u8 *)(data) + 8);                                \
        __u16 c = *(__u16 *)((__u8 *)(data) + 12);                               \
        *(__u64 *)(shifted) = a;                                                 \
        *(__u32 *)((shifted) + 8) = b;                                           \
        *(__u16 *)((shifted) + 12) = c;                                          \
        1;                                                                       \
    }))
#define __BNT_SHIFT_REMOVE_READ(buf, data)                                      \
    do {                                                                         \
        for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX / 8; i++)                      \
            (buf)[i] = *((__u64 *)(data) + i);                                   \
    } while (0)
#endif

#define __BNT_SHIFT_REMOVE_FIXED(N)                                             \
__BNT_SHIFT_LINKAGE int __bnt_shift_remove_##N(struct xdp_md *ctx,            \
                                                  __u32 prefix_len)              \
{                                                                                 \
    __u64 buf[BNT_XDP_MAX_HEADER_PREFIX / 8];                                    \
    void *data, *data_end;                                                       \
    __u8 *shifted;                                                                \
    __u32 i;                                                                     \
    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)                                \
        return BNT_ERR_TOO_DEEP;                                               \
    data     = (void *)(long)ctx->data;                                          \
    data_end = (void *)(long)ctx->data_end;                                      \
    shifted  = (__u8 *)data + (N);                                               \
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX + (N) > (__u8 *)data_end)    \
        return BNT_ERR_TRUNC;                                                  \
    if (!__BNT_SHIFT_REMOVE_ETH(data, shifted, prefix_len)) {                    \
        const __u8 *src = data;                                                  \
        if (prefix_len > (N)) {                                                  \
            __BNT_SHIFT_REMOVE_READ(buf, data);                                  \
            src = (const __u8 *)buf;                                             \
        }                                                                        \
        for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {                       \
            if (i >= prefix_len)                                                 \
                break;                                                           \
            *(shifted + i) = src[i];                                             \
        }                                                                        \
    }                                                                            \
    if (bpf_xdp_adjust_head(ctx, (int)(N)))                                     \
        return BNT_ERR_WRITE;                                                  \
    return BNT_OK;                                                              \
}

__BNT_SHIFT_INSERT_FIXED(4)
__BNT_SHIFT_INSERT_FIXED(20)
__BNT_SHIFT_INSERT_FIXED(40)
__BNT_SHIFT_REMOVE_FIXED(4)
__BNT_SHIFT_REMOVE_FIXED(20)
__BNT_SHIFT_REMOVE_FIXED(40)

/** Inserts an outer VLAN header after the Ethernet source/destination fields. */
/* One-global insert: read outer EtherType + shift + write the VLAN tag and set
 * the eth EtherType to the TPID, all fused. Inserts the outer tag at a constant
 * offset (off + 14), so the post-adjust writes need no barrier (no walk widens
 * the offset). */
static __always_inline int __bnt_eth_insert_vlan(struct xdp_md *ctx, __u32 off, __u16 tpid, __u16 tci)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *p;
    __be16 proto;
    __u16 outer_ethertype;
    __u32 prefix_len, cur, i, depth = 0;
    int ret;

    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(*(__be16 *)p);
    outer_ethertype = bpf_ntohs(proto);

    /* Count existing tags so a stack already at the bound is rejected instead
     * of growing past what the bounded readers can walk back. */
    cur = off + sizeof(struct ethhdr);
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        ret = __bnt_data_ptr(ctx, cur + 2, sizeof(__be16), &p);
        if (ret)
            return ret;
        proto = __BNT_PKT_LOAD(*(__be16 *)p);
        depth++;
        cur += sizeof(struct bnt_vlan_hdr);
    }
    if (depth >= BNT_MAX_VLAN_DEPTH)
        return BNT_ERR_TOO_DEEP;

    prefix_len = off + sizeof(struct ethhdr);
    ret = __bnt_shift_insert_4(ctx, prefix_len);
    if (ret)
        return ret;

#if BNT_LEGACY_KERNEL || __clang_major__ == 18 || __clang_major__ == 19
    BNT_PIN(prefix_len);     /* clang 18,19 */
#endif
    {
        /* write the 4-byte tag as a single aligned store */
        __be32 tag = bpf_htonl(((__u32)tci << 16) | (__u32)outer_ethertype);
        ret = __bnt_data_ptr(ctx, prefix_len, sizeof(__be32), &p);
        if (ret)
            return ret;
        __BNT_PKT_STORE(*(__be32 *)p, tag);
    }

    ret = __bnt_data_ptr(ctx, prefix_len - 2, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(tpid));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_vlan_g(struct xdp_md *ctx, __u32 off, __u16 tpid, __u16 tci);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_vlan_g(struct xdp_md *ctx, __u32 off, __u16 tpid, __u16 tci)
{
    return __bnt_eth_insert_vlan(ctx, off, tpid, tci);
}
#endif
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_eth
 * @brief Inserts a VLAN tag as the outermost tag, immediately after the Ethernet
 * source/destination fields.
 *
 * @note The header prefix before the insertion point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Unless @p eth is at offset 0, the packet must hold
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; shorter, returns BNT_ERR_TRUNC. On an
 * error the packet is left unchanged.
 * Views for headers after @p eth become stale; re-parse them.
 *
 * @param eth  Parsed Ethernet view.
 * @param tpid Tag protocol identifier (e.g. @c ETH_P_8021Q), in host byte order.
 * @param tci  Tag control information, in host byte order.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 * @retval BNT_ERR_WRITE   the packet resize failed.
 * @retval BNT_ERR_TOO_DEEP the existing VLAN stack is already at
 *                          @c BNT_MAX_VLAN_DEPTH (see @ref limits), or the
 *                          header prefix before @p eth exceeds
 *                          @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_eth__insert_vlan(bnt_eth *eth, __u16 tpid, __u16 tci)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_insert_vlan)(eth->__ctx, eth->__off, tpid, tci);
}

/** Removes the outermost VLAN header after the Ethernet source/destination fields. */
/* Removes a VLAN tag: the encapsulated EtherType replaces the outer one, then
 * the 4-byte tag is shifted out. bpf_xdp_adjust_head comes last, so no write
 * follows the resize and no barrier is needed. */
static __always_inline int __bnt_eth_remove_vlan(struct xdp_md *ctx, __u32 off)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *p;
    __u16 outer_ethertype;
    __be16 encap;
    __u32 vlan_off;
    int ret;

    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    outer_ethertype = bpf_ntohs(__BNT_PKT_LOAD(*(__be16 *)p));
    if (outer_ethertype != ETH_P_8021Q && outer_ethertype != ETH_P_8021AD)
        return BNT_ERR_BAD_PROTO;

    vlan_off = off + sizeof(struct ethhdr);
    ret = __bnt_data_ptr(ctx,
                          vlan_off + offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto),
                          sizeof(__be16), &p);
    if (ret)
        return ret;
    encap = __BNT_PKT_LOAD(*(__be16 *)p);

    /* The move's own checks first: past them it cannot fail, so a call that
     * fails writes nothing. */
    if (vlan_off > BNT_XDP_MAX_HEADER_PREFIX)
        return BNT_ERR_TOO_DEEP;
    if ((__u8 *)__bnt_xdp_data(ctx) + BNT_XDP_MAX_HEADER_PREFIX + 4 > (__u8 *)__bnt_xdp_data_end(ctx))
        return BNT_ERR_TRUNC;
    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, encap);
    return __bnt_shift_remove_4(ctx, vlan_off);
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_vlan_g(struct xdp_md *ctx, __u32 off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_vlan_g(struct xdp_md *ctx, __u32 off)
{
    return __bnt_eth_remove_vlan(ctx, off);
}
#endif
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_eth
 * @brief Removes the outermost VLAN tag, restoring the EtherType it encapsulated.
 *
 * @note The header prefix before the removal point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Views for headers after @p eth become stale; re-parse them.
 *
 * @param eth Parsed Ethernet view.
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p eth is NULL.
 * @retval BNT_ERR_TRUNC     a read or write falls outside the packet.
 * @retval BNT_ERR_WRITE     the packet resize failed.
 * @retval BNT_ERR_BAD_PROTO the outer EtherType is not ETH_P_8021Q or
 *                           ETH_P_8021AD.
 * @retval BNT_ERR_TOO_DEEP  the header prefix before @p eth exceeds
 *                           @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_eth__remove_vlan(bnt_eth *eth)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_remove_vlan)(eth->__ctx, eth->__off);
}



/** Inserts a base IPv4 header immediately after Ethernet/VLAN and initializes it. */
/* One-global insert: Ethernet/VLAN walk + shift + IPv4 header write fused. The
 * header write after bpf_xdp_adjust_head needs a barrier on prefix_len (see
 * __bnt_eth_insert_ipv6_g). */
static __always_inline int __bnt_eth_insert_ipv4(struct xdp_md *ctx, __u32 off, __u8 protocol,
                             __be32 saddr, __be32 daddr)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    struct iphdr *ip;
    void *p;
    __be16 proto;
    __u32 hlen = sizeof(struct ethhdr), cur, prefix_len, i, pkt_len, total_len;
    __wsum csum;
    int ret;

    /* walk Ethernet + VLAN inline */
    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(*(__be16 *)p);
    cur = off + sizeof(struct ethhdr);
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        ret = __bnt_data_ptr(ctx, cur + 2, sizeof(__be16), &p);
        if (ret)
            return ret;
        proto = __BNT_PKT_LOAD(*(__be16 *)p);
        hlen += 4;
        cur += 4;
    }
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
        return BNT_ERR_TOO_DEEP;
    prefix_len = off + hlen;

    ret = __bnt_shift_insert_20(ctx, prefix_len);
    if (ret)
        return ret;

    /* Keeps the bounds check of __bnt_data_ptr below: clang knows prefix_len
     * <= BNT_XDP_MAX_HEADER_PREFIX and drops it, and kernels up to 6.6 lose
     * that bound across the spill around bpf_xdp_adjust_head. */
    BNT_PIN(prefix_len);
    ret = __bnt_data_ptr(ctx, prefix_len, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    pkt_len = __bnt_len(ctx);
    if (prefix_len > pkt_len)
        return BNT_ERR_TRUNC;
    total_len = pkt_len - prefix_len;
    if (total_len < sizeof(struct iphdr) || total_len > 0xffff)
        return BNT_ERR_TRUNC;
    __BNT_PKT_MEMSET0(ip, sizeof(*ip));
#if BNT_STRICT_ALIGN
    /* Byte stores through struct iphdr * carry its 4-byte alignment, which lets
     * clang merge them into one wider, misaligned store. */
    __BNT_PKT_STORE(*(__u8 *)ip, 0x45);                 /* version 4, IHL 5 */
#else
    ip->version  = 4;
    ip->ihl      = 5;
#endif
    __BNT_PKT_STORE(ip->tot_len, bpf_htons((__u16)total_len));
    __BNT_PKT_STORE(ip->frag_off, bpf_htons(IP_DF));
#if BNT_STRICT_ALIGN
    __BNT_PKT_STORE(ip->ttl, 64);
    __BNT_PKT_STORE(ip->protocol, protocol);
#else
    ip->ttl      = 64;
    ip->protocol = protocol;
#endif
    __BNT_PKT_STORE(ip->saddr, saddr);
    __BNT_PKT_STORE(ip->daddr, daddr);
    csum = bpf_csum_diff(NULL, 0, (__be32 *)ip, sizeof(*ip), 0);
    __BNT_PKT_STORE(ip->check, __bnt_csum_fold(csum));

    ret = __bnt_data_ptr(ctx, prefix_len - 2, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(ETH_P_IP));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_ipv4_g(struct xdp_md *ctx, __u32 off, __u8 protocol,
                             __be32 saddr, __be32 daddr);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_ipv4_g(struct xdp_md *ctx, __u32 off, __u8 protocol,
                             __be32 saddr, __be32 daddr)
{
    return __bnt_eth_insert_ipv4(ctx, off, protocol, saddr, daddr);
}
#endif
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_eth
 * @brief Inserts a base IPv4 header immediately after Ethernet/VLAN (outer
 * encapsulation) and initializes it.
 *
 * Sets version 4, a 20-byte header with no options, total length to cover the
 * rest of the packet, the Don't Fragment flag, TTL 64, @p protocol, @p saddr,
 * and @p daddr, with a valid header checksum. Sets the EtherType (or the
 * outermost VLAN's encapsulated protocol) to ETH_P_IP.
 *
 * @note The header prefix before the insertion point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Unless @p eth is at offset 0 with no VLAN tag (a prefix of the Ethernet
 * header alone), the packet must hold @c BNT_XDP_MAX_HEADER_PREFIX bytes;
 * shorter, returns BNT_ERR_TRUNC. On an error the packet is left unchanged.
 * Views for headers after @p eth become stale; re-parse them.
 *
 * @param eth      Parsed Ethernet view.
 * @param protocol Upper-layer protocol number.
 * @param saddr    Source address, in network byte order.
 * @param daddr    Destination address, in network byte order.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet, or the
 *                         remaining packet cannot fit a valid total length.
 * @retval BNT_ERR_WRITE   the packet resize failed.
 * @retval BNT_ERR_TOO_DEEP the VLAN walk (@c BNT_MAX_VLAN_DEPTH, see
 *                          @ref limits) is exhausted, or the header prefix
 *                          before @p eth exceeds @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_eth__insert_ipv4(bnt_eth *eth,
                                                  __u8 protocol,
                                                  __be32 saddr,
                                                  __be32 daddr)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_insert_ipv4)(eth->__ctx, eth->__off, protocol, saddr, daddr);
}

/* Every packet write after bpf_xdp_adjust_head has a barrier on its offset:
 * it makes clang recompute the offset register instead of reloading a wider
 * spilled copy, which the verifier rejects (r=0). */
static __always_inline int __bnt_eth_insert_ipv6(struct xdp_md *ctx, __u32 off, __u8 nexthdr,
                             const struct in6_addr *saddr, const struct in6_addr *daddr)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    struct ipv6hdr *ip;
    void *p;
    __be16 proto;
    __u32 hlen = sizeof(struct ethhdr), cur, prefix_len, i, pkt_len, payload_len;
    int ret;

    if (!saddr || !daddr)
        return BNT_ERR_BAD_ARG;

    /* walk Ethernet + VLAN inline (no nested global, so the op stays one call) */
    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(*(__be16 *)p);
    cur = off + sizeof(struct ethhdr);
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        ret = __bnt_data_ptr(ctx, cur + 2, sizeof(__be16), &p);
        if (ret)
            return ret;
        proto = __BNT_PKT_LOAD(*(__be16 *)p);
        hlen += 4;
        cur += 4;
    }
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
        return BNT_ERR_TOO_DEEP;
    prefix_len = off + hlen;

    /* shift the prefix forward by one IPv6 header (constant N, no stack buffer) */
    ret = __bnt_shift_insert_40(ctx, prefix_len);
    if (ret)
        return ret;

    /* write the base header; barrier re-materializes prefix_len post-adjust */
    BNT_PIN(prefix_len);     /* see __bnt_eth_insert_ipv4_g */
    ret = __bnt_data_ptr(ctx, prefix_len, sizeof(*ip), (void **)&ip);
    if (ret)
        return ret;
    pkt_len = __bnt_len(ctx);
    if (prefix_len > pkt_len)
        return BNT_ERR_TRUNC;
    payload_len = pkt_len - prefix_len - sizeof(struct ipv6hdr);
    if (payload_len > 0xffff)
        return BNT_ERR_TRUNC;
    __BNT_PKT_MEMSET0(ip, sizeof(*ip));
#if BNT_STRICT_ALIGN
    /* See __bnt_eth_insert_ipv4_g: keep the byte stores from being merged. */
    __BNT_PKT_STORE(*(__u8 *)ip, 0x60);                 /* version 6 */
    __BNT_PKT_STORE(ip->payload_len, bpf_htons((__u16)payload_len));
    __BNT_PKT_STORE(ip->nexthdr, nexthdr);
    __BNT_PKT_STORE(ip->hop_limit, 64);
#else
    ip->version     = 6;
    __BNT_PKT_STORE(ip->payload_len, bpf_htons((__u16)payload_len));
    ip->nexthdr     = nexthdr;
    ip->hop_limit   = 64;
#endif
    __BNT_PKT_MEMCPY(&ip->saddr, saddr, sizeof(ip->saddr));
    __BNT_PKT_MEMCPY(&ip->daddr, daddr, sizeof(ip->daddr));

    ret = __bnt_data_ptr(ctx, prefix_len - 2, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(ETH_P_IPV6));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_ipv6_g(struct xdp_md *ctx, __u32 off, __u8 nexthdr,
                             const struct in6_addr *saddr, const struct in6_addr *daddr);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_ipv6_g(struct xdp_md *ctx, __u32 off, __u8 nexthdr,
                             const struct in6_addr *saddr, const struct in6_addr *daddr)
{
    return __bnt_eth_insert_ipv6(ctx, off, nexthdr, saddr, daddr);
}
#endif
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_eth
 * @brief Inserts a base IPv6 header immediately after Ethernet/VLAN (outer
 * encapsulation) and initializes it.
 *
 * Sets version 6, payload length to cover the rest of the packet, @p nexthdr,
 * hop limit 64, @p saddr, and @p daddr. Sets the EtherType (or the outermost
 * VLAN's encapsulated protocol) to ETH_P_IPV6.
 *
 * @note The header prefix before the insertion point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Unless @p eth is at offset 0 with no VLAN tag (a prefix of the Ethernet
 * header alone), the packet must hold @c BNT_XDP_MAX_HEADER_PREFIX bytes;
 * shorter, returns BNT_ERR_TRUNC. On an error the packet is left unchanged.
 * Views for headers after @p eth become stale; re-parse them.
 *
 * @param eth     Parsed Ethernet view.
 * @param nexthdr Upper-layer protocol number.
 * @param saddr   Source address.
 * @param daddr   Destination address.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth, @p saddr, or @p daddr is NULL.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet, or the
 *                         remaining packet cannot fit a valid payload length.
 * @retval BNT_ERR_WRITE   the packet resize failed.
 * @retval BNT_ERR_TOO_DEEP the VLAN walk (@c BNT_MAX_VLAN_DEPTH, see
 *                          @ref limits) is exhausted, or the header prefix
 *                          before @p eth exceeds @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_eth__insert_ipv6(bnt_eth *eth,
                                                  __u8 nexthdr,
                                                  const struct in6_addr *saddr,
                                                  const struct in6_addr *daddr)
{
    if (!eth || !saddr || !daddr)
        return BNT_ERR_BAD_ARG;
    {
        /* One global for the whole op. Copy the (possibly rodata) addresses to
         * stack so the global gets writable pointer args. */
        struct in6_addr s = *saddr, d = *daddr;
        return __BNT_OP(__bnt_eth_insert_ipv6)(eth->__ctx, eth->__off, nexthdr, &s, &d);
    }
}

/** Removes a base IPv4 header immediately after Ethernet/VLAN. */
static __always_inline int __bnt_eth_remove_ipv4(struct xdp_md *ctx, __u32 off)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *p;
    __be16 proto;
    __u8 vihl, ipproto;
    __u16 new_ethertype;
    __u32 hlen = sizeof(struct ethhdr), cur, prefix_len, eproto_off, i, vlan_depth = 0;
    int ret;

    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(*(__be16 *)p);
    cur = off + sizeof(struct ethhdr);
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        ret = __bnt_data_ptr(ctx,
                              cur + offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto),
                              sizeof(__be16), &p);
        if (ret)
            return ret;
        proto = __BNT_PKT_LOAD(*(__be16 *)p);
        hlen += sizeof(struct bnt_vlan_hdr);
        cur += sizeof(struct bnt_vlan_hdr);
        vlan_depth++;
    }
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
        return BNT_ERR_TOO_DEEP;
    if (proto != bpf_htons(ETH_P_IP))
        return BNT_ERR_BAD_PROTO;

    prefix_len = off + hlen;
    /* one bounds check for the inner header; read both fields from the same
     * pointer so the verifier keeps the range (two separate __bnt_data_ptr
     * reads off the same base get fused by the compiler and lose it). The
     * bound is tested next to its use: clang otherwise reloads prefix_len from
     * the stack in between, and 5.12 loses the bounds of a spilled scalar. */
    {
        struct iphdr *ip;
        if (prefix_len > BNT_XDP_MAX_PACKET_OFFSET - sizeof(*ip))
            return BNT_ERR_TRUNC;
        BNT_PIN(prefix_len);
        ret = __bnt_data_ptr_in_range(ctx, prefix_len, sizeof(*ip), (void **)&ip);
        if (ret)
            return ret;
        vihl = *(__u8 *)ip;
        ipproto = ip->protocol;
    }
    if (vihl != 0x45)
        return BNT_ERR_UNSUPPORTED;
    if (ipproto == IPPROTO_IPIP)
        new_ethertype = ETH_P_IP;
    else if (ipproto == IPPROTO_IPV6)
        new_ethertype = ETH_P_IPV6;
    else
        return BNT_ERR_UNSUPPORTED;

    eproto_off = off + offsetof(struct ethhdr, h_proto);
    if (vlan_depth > 0)
        eproto_off = off + sizeof(struct ethhdr) +
                     (vlan_depth - 1) * sizeof(struct bnt_vlan_hdr) +
                     offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto);
    /* eproto_off depends on the VLAN walk; barrier so the bounds check and the
     * store share the register (same fix the variable-offset inserts use). */
#if BNT_LEGACY_KERNEL || (__clang_major__ >= 16 && __clang_major__ <= 19)
    BNT_PIN(eproto_off);     /* clang 16,17,18,19 */
#endif
    /* The move's own checks first: past them it cannot fail, so a call that
     * fails writes nothing. */
    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)
        return BNT_ERR_TOO_DEEP;
    if ((__u8 *)__bnt_xdp_data(ctx) + BNT_XDP_MAX_HEADER_PREFIX + 20 > (__u8 *)__bnt_xdp_data_end(ctx))
        return BNT_ERR_TRUNC;
    ret = __bnt_data_ptr(ctx, eproto_off, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(new_ethertype));
    return __bnt_shift_remove_20(ctx, prefix_len);
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_ipv4_g(struct xdp_md *ctx, __u32 off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_ipv4_g(struct xdp_md *ctx, __u32 off)
{
    return __bnt_eth_remove_ipv4(ctx, off);
}
#endif
#endif

/**
 * @ingroup bnt_eth
 * @brief Removes a base IPv4 header immediately after Ethernet/VLAN (tunnel
 * decapsulation) and restores the revealed protocol's EtherType.
 *
 * The IPv4 header must have no options and its protocol must be IPPROTO_IPIP
 * or IPPROTO_IPV6.
 *
 * @note The header prefix before the removal point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Views for headers after @p eth become stale; re-parse them.
 *
 * @param eth Parsed Ethernet view.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p eth is NULL.
 * @retval BNT_ERR_TRUNC      a read or write falls outside the packet.
 * @retval BNT_ERR_WRITE      the packet resize failed.
 * @retval BNT_ERR_BAD_PROTO  the EtherType is not ETH_P_IP.
 * @retval BNT_ERR_UNSUPPORTED the IPv4 header has options, or its protocol
 *                            is neither IPPROTO_IPIP nor IPPROTO_IPV6.
 * @retval BNT_ERR_TOO_DEEP   the VLAN walk (@c BNT_MAX_VLAN_DEPTH, see
 *                            @ref limits) is exhausted, or the header prefix
 *                            before @p eth exceeds @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_eth__remove_ipv4(bnt_eth *eth)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_remove_ipv4)(eth->__ctx, eth->__off);
}

/** Removes a base IPv6 header immediately after Ethernet/VLAN. */
static __always_inline int __bnt_eth_remove_ipv6(struct xdp_md *ctx, __u32 off)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *p;
    __be16 proto;
    __u8 ver, nexthdr;
    __u16 new_ethertype;
    __u32 hlen = sizeof(struct ethhdr), cur, prefix_len, eproto_off, i, vlan_depth = 0;
    int ret;

    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(*(__be16 *)p);
    cur = off + sizeof(struct ethhdr);
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        ret = __bnt_data_ptr(ctx,
                              cur + offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto),
                              sizeof(__be16), &p);
        if (ret)
            return ret;
        proto = __BNT_PKT_LOAD(*(__be16 *)p);
        hlen += sizeof(struct bnt_vlan_hdr);
        cur += sizeof(struct bnt_vlan_hdr);
        vlan_depth++;
    }
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
        return BNT_ERR_TOO_DEEP;
    if (proto != bpf_htons(ETH_P_IPV6))
        return BNT_ERR_BAD_PROTO;

    prefix_len = off + hlen;
    /* As in __bnt_eth_remove_ipv4_g: one pointer for both fields, bounded
     * next to its use. */
    {
        struct ipv6hdr *ip6;
        if (prefix_len > BNT_XDP_MAX_PACKET_OFFSET - sizeof(*ip6))
            return BNT_ERR_TRUNC;
        BNT_PIN(prefix_len);
        ret = __bnt_data_ptr_in_range(ctx, prefix_len, sizeof(*ip6), (void **)&ip6);
        if (ret)
            return ret;
        ver = *(__u8 *)ip6;
        nexthdr = ip6->nexthdr;
    }
    if ((ver >> 4) != 6)
        return BNT_ERR_UNSUPPORTED;
    if (nexthdr == IPPROTO_IPIP)
        new_ethertype = ETH_P_IP;
    else if (nexthdr == IPPROTO_IPV6)
        new_ethertype = ETH_P_IPV6;
    else
        return BNT_ERR_UNSUPPORTED;

    eproto_off = off + offsetof(struct ethhdr, h_proto);
    if (vlan_depth > 0)
        eproto_off = off + sizeof(struct ethhdr) +
                     (vlan_depth - 1) * sizeof(struct bnt_vlan_hdr) +
                     offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto);
    /* eproto_off depends on the VLAN walk; barrier so the bounds check and the
     * store share the register (same fix the variable-offset inserts use). */
#if BNT_LEGACY_KERNEL
    BNT_PIN(eproto_off);
#endif
    /* The move's own checks first: past them it cannot fail, so a call that
     * fails writes nothing. */
    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)
        return BNT_ERR_TOO_DEEP;
    if ((__u8 *)__bnt_xdp_data(ctx) + BNT_XDP_MAX_HEADER_PREFIX + 40 > (__u8 *)__bnt_xdp_data_end(ctx))
        return BNT_ERR_TRUNC;
    ret = __bnt_data_ptr(ctx, eproto_off, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(new_ethertype));
    return __bnt_shift_remove_40(ctx, prefix_len);
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_ipv6_g(struct xdp_md *ctx, __u32 off);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_ipv6_g(struct xdp_md *ctx, __u32 off)
{
    return __bnt_eth_remove_ipv6(ctx, off);
}
#endif
#endif

/**
 * @ingroup bnt_eth
 * @brief Removes a base IPv6 header immediately after Ethernet/VLAN (tunnel
 * decapsulation) and restores the revealed protocol's EtherType.
 *
 * The IPv6 header's next-header field must be IPPROTO_IPIP or IPPROTO_IPV6.
 *
 * @note The header prefix before the removal point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Views for headers after @p eth become stale; re-parse them.
 *
 * @param eth Parsed Ethernet view.
 * @retval BNT_OK             on success.
 * @retval BNT_ERR_BAD_ARG    @p eth is NULL.
 * @retval BNT_ERR_TRUNC      a read or write falls outside the packet.
 * @retval BNT_ERR_WRITE      the packet resize failed.
 * @retval BNT_ERR_BAD_PROTO  the EtherType is not ETH_P_IPV6.
 * @retval BNT_ERR_UNSUPPORTED the next-header field is neither IPPROTO_IPIP
 *                            nor IPPROTO_IPV6.
 * @retval BNT_ERR_TOO_DEEP   the VLAN walk (@c BNT_MAX_VLAN_DEPTH, see
 *                            @ref limits) is exhausted, or the header prefix
 *                            before @p eth exceeds @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_eth__remove_ipv6(bnt_eth *eth)
{
    if (!eth)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_remove_ipv6)(eth->__ctx, eth->__off);
}

#if BNT_XDP_IPV6_CSUM_SUPPORT
/* XDP IPv6 full-checksum recompute is disabled: keep the raw IPv6 setters out
 * of the XDP API so callers do not update pseudo-header fields without a
 * matching recompute path. TC still exposes these helpers. */
/** @ingroup bnt_ipv6
 *  Sets the IPv6 source address without updating any checksum. */
static __always_inline int bnt_ipv6__set_saddr_no_csum(bnt_ipv6 *ip6, const struct in6_addr *addr)
    { return __bnt_ipv6__set_saddr_raw(ip6, addr); }
/** @ingroup bnt_ipv6
 *  Sets the IPv6 destination address without updating any checksum. */
static __always_inline int bnt_ipv6__set_daddr_no_csum(bnt_ipv6 *ip6, const struct in6_addr *addr)
    { return __bnt_ipv6__set_daddr_raw(ip6, addr); }
/** @ingroup bnt_ipv6
 *  Sets the IPv6 payload length field without updating any checksum. */
static __always_inline int bnt_ipv6__set_payload_len_no_csum(bnt_ipv6 *ip6, __u16 payload_len)
    { return __bnt_ipv6__set_payload_len_raw(ip6, payload_len); }
#endif

/** @ingroup bnt_tcp
 *  Sets the TCP source port without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_sport_no_csum(bnt_tcp *tcp, __u16 port)
    { return __bnt_tcp__set_sport_raw(tcp, port); }
/** @ingroup bnt_tcp
 *  Sets the TCP destination port without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_dport_no_csum(bnt_tcp *tcp, __u16 port)
    { return __bnt_tcp__set_dport_raw(tcp, port); }
/** @ingroup bnt_tcp
 *  Sets the TCP sequence number without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_seq_no_csum(bnt_tcp *tcp, __u32 seq)
    { return __bnt_tcp__set_seq_raw(tcp, seq); }
/** @ingroup bnt_tcp
 *  Sets the TCP acknowledgment number without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_ack_seq_no_csum(bnt_tcp *tcp, __u32 ack_seq)
    { return __bnt_tcp__set_ack_seq_raw(tcp, ack_seq); }
/** @ingroup bnt_tcp
 *  Sets the TCP flags bitmask without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_flags_no_csum(bnt_tcp *tcp, __u16 flags)
    { return __bnt_tcp__set_flags_raw(tcp, flags); }
/** @ingroup bnt_tcp
 *  Sets the TCP window size without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_window_no_csum(bnt_tcp *tcp, __u16 window)
    { return __bnt_tcp__set_window_raw(tcp, window); }
/** @ingroup bnt_tcp
 *  Sets the TCP urgent pointer without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_urg_ptr_no_csum(bnt_tcp *tcp, __u16 urg_ptr)
    { return __bnt_tcp__set_urg_ptr_raw(tcp, urg_ptr); }
/** @ingroup bnt_tcp
 *  Sets the TCP data offset without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp is NULL, or @p doff is not between 5 and 15.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_tcp__set_doff_no_csum(bnt_tcp *tcp, __u32 doff)
    { return __bnt_tcp__set_doff_raw(tcp, doff); }

/** @ingroup bnt_udp
 *  Sets the UDP source port without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_udp__set_sport_no_csum(bnt_udp *udp, __u16 port)
    { return __bnt_udp__set_sport_raw(udp, port); }
/** @ingroup bnt_udp
 *  Sets the UDP destination port without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_udp__set_dport_no_csum(bnt_udp *udp, __u16 port)
    { return __bnt_udp__set_dport_raw(udp, port); }
/** @ingroup bnt_udp
 *  Sets the UDP length field without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_udp__set_len_no_csum(bnt_udp *udp, __u16 len)
    { return __bnt_udp__set_len_raw(udp, len); }

/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 type without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_type_no_csum(bnt_icmp4 *icmp, __u8 type)
    { return __bnt_icmp4__set_type_raw(icmp, type); }
/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 code without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_code_no_csum(bnt_icmp4 *icmp, __u8 code)
    { return __bnt_icmp4__set_code_raw(icmp, code); }
/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 echo identifier without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_echo_id_no_csum(bnt_icmp4 *icmp, __u16 id)
    { return __bnt_icmp4__set_echo_id_raw(icmp, id); }
/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 echo sequence number without updating the checksum.
 *
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   the write falls outside the packet.
 */
static __always_inline int bnt_icmp4__set_echo_seq_no_csum(bnt_icmp4 *icmp, __u16 seq)
    { return __bnt_icmp4__set_echo_seq_raw(icmp, seq); }

#if BNT_XDP_IPV6_CSUM_SUPPORT
/* ICMPv6 has no XDP full-recompute wrapper while IPv6 recompute is disabled. */
/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 type without updating the checksum. */
static __always_inline int bnt_icmp6__set_type_no_csum(bnt_icmp6 *icmp, __u8 type)
    { return __bnt_icmp6__set_type_raw(icmp, type); }
/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 code without updating the checksum. */
static __always_inline int bnt_icmp6__set_code_no_csum(bnt_icmp6 *icmp, __u8 code)
    { return __bnt_icmp6__set_code_raw(icmp, code); }
/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 echo identifier without updating the checksum. */
static __always_inline int bnt_icmp6__set_echo_id_no_csum(bnt_icmp6 *icmp, __u16 id)
    { return __bnt_icmp6__set_echo_id_raw(icmp, id); }
/** @ingroup bnt_icmp6
 *  Sets the ICMPv6 echo sequence number without updating the checksum. */
static __always_inline int bnt_icmp6__set_echo_seq_no_csum(bnt_icmp6 *icmp, __u16 seq)
    { return __bnt_icmp6__set_echo_seq_raw(icmp, seq); }
#endif

/* XDP sees packet bytes directly, so full recompute is always explicit. */
/**
 * @ingroup bnt_ipv4
 * @brief Recomputes the IPv4 header checksum from scratch.
 *
 * Covers the IPv4 header only.
 *
 * @param ip Parsed IPv4 view.
 * @retval BNT_OK              on success.
 * @retval BNT_ERR_BAD_ARG     @p ip is NULL.
 * @retval BNT_ERR_TRUNC       the header falls outside the packet.
 * @retval BNT_ERR_UNSUPPORTED the header has options (IHL is not 5).
 */
static __always_inline int bnt_ipv4__recompute_csum(bnt_ipv4 *ip)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_ipv4_recompute_csum)(ip->__ctx, ip->__off);
}
/**
 * @ingroup bnt_tcp
 * @brief Recomputes the full TCP checksum from scratch.
 *
 * @note Covers the IPv4 pseudo-header and up to @c BNT_MAX_PAYLOAD bytes of
 * TCP payload. Requires the IPv4 view for the pseudo-header.
 *
 * @param tcp Parsed TCP view.
 * @param ip4 Parsed IPv4 view of the enclosing packet.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p ip4 is NULL.
 * @retval BNT_ERR_TRUNC   the segment exceeds @c BNT_MAX_PAYLOAD bytes, or a
 *                         read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__recompute_csum4(bnt_tcp *tcp, bnt_ipv4 *ip4)
{
    if (!tcp || !ip4)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_recompute_csum_v4)(tcp->__ctx, tcp->__off, ip4->__off);
}
#if BNT_XDP_IPV6_CSUM_SUPPORT
/* Off by default (BNT_XDP_IPV6_CSUM_SUPPORT): the verifier state grows too much
 * on this path. TC always exposes recompute_csum6. */
/**
 * @ingroup bnt_tcp
 * @brief Recomputes the full TCP checksum from scratch over an IPv6 pseudo-header.
 *
 * @note Covers the IPv6 pseudo-header and up to @c BNT_MAX_PAYLOAD bytes of
 * TCP payload. Requires the IPv6 view for the pseudo-header. Available on
 * XDP only when built with @c BNT_XDP_IPV6_CSUM_SUPPORT=1.
 *
 * @param tcp Parsed TCP view.
 * @param ip6 Parsed IPv6 view of the enclosing packet.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p tcp or @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   the segment exceeds @c BNT_MAX_PAYLOAD bytes, or a
 *                         read or write falls outside the packet.
 */
static __always_inline int bnt_tcp__recompute_csum6(bnt_tcp *tcp, bnt_ipv6 *ip6)
{
    if (!tcp || !ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_tcp_recompute_csum_v6)(tcp->__ctx, tcp->__off, ip6->__off);
}
#endif
/**
 * @ingroup bnt_udp
 * @brief Recomputes the full UDP checksum from scratch.
 *
 * Always produces an active checksum, even if it was previously 0 (disabled).
 *
 * @note Covers the IPv4 pseudo-header and up to @c BNT_MAX_PAYLOAD bytes of
 * UDP payload. Requires the IPv4 view for the pseudo-header.
 *
 * @param udp Parsed UDP view.
 * @param ip4 Parsed IPv4 view of the enclosing packet.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p ip4 is NULL.
 * @retval BNT_ERR_TRUNC   the segment exceeds @c BNT_MAX_PAYLOAD bytes, or a
 *                         read or write falls outside the packet.
 */
static __always_inline int bnt_udp__recompute_csum4(bnt_udp *udp, bnt_ipv4 *ip4)
{
    if (!udp || !ip4)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_udp_recompute_csum_v4)(udp->__ctx, udp->__off, ip4->__off);
}
#if BNT_XDP_IPV6_CSUM_SUPPORT
/* See the disabled TCP/IPv6 recompute wrapper above. */
/**
 * @ingroup bnt_udp
 * @brief Recomputes the full UDP checksum from scratch over an IPv6 pseudo-header.
 *
 * Always produces an active checksum, even if it was previously 0 (disabled).
 *
 * @note Covers the IPv6 pseudo-header and up to @c BNT_MAX_PAYLOAD bytes of
 * UDP payload. Requires the IPv6 view for the pseudo-header. Available on
 * XDP only when built with @c BNT_XDP_IPV6_CSUM_SUPPORT=1.
 *
 * @param udp Parsed UDP view.
 * @param ip6 Parsed IPv6 view of the enclosing packet.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p udp or @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   the segment exceeds @c BNT_MAX_PAYLOAD bytes, or a
 *                         read or write falls outside the packet.
 */
static __always_inline int bnt_udp__recompute_csum6(bnt_udp *udp, bnt_ipv6 *ip6)
{
    if (!udp || !ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_udp_recompute_csum_v6)(udp->__ctx, udp->__off, ip6->__off);
}
#endif
/**
 * @ingroup bnt_icmp4
 * @brief Recomputes the full ICMPv4 checksum from scratch.
 *
 * ICMPv4 has no pseudo-header, so this covers only the ICMPv4 message itself.
 *
 * @note Covers up to @c BNT_MAX_PAYLOAD bytes of the ICMPv4 message.
 *
 * @param icmp     Parsed ICMPv4 view.
 * @param icmp_len Length of the ICMPv4 message (header and data), in bytes.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp is NULL.
 * @retval BNT_ERR_TRUNC   @p icmp_len exceeds @c BNT_MAX_PAYLOAD bytes, or a
 *                         read or write falls outside the packet.
 */
static __always_inline int bnt_icmp4__recompute_csum(bnt_icmp4 *icmp, __u16 icmp_len)
{
    if (!icmp)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_icmp4_recompute_csum)(icmp->__ctx, icmp->__off, icmp_len);
}
#if BNT_XDP_IPV6_CSUM_SUPPORT
/* See the disabled TCP/IPv6 recompute wrapper above. */
/**
 * @ingroup bnt_icmp6
 * @brief Recomputes the full ICMPv6 checksum from scratch.
 *
 * @note Covers the IPv6 pseudo-header and up to @c BNT_MAX_PAYLOAD bytes of
 * the ICMPv6 message. Requires the IPv6 view for the pseudo-header.
 * Available on XDP only when built with @c BNT_XDP_IPV6_CSUM_SUPPORT=1.
 *
 * @param icmp     Parsed ICMPv6 view.
 * @param ip6      Parsed IPv6 view of the enclosing packet.
 * @param icmp_len Length of the ICMPv6 message (header and data), in bytes.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p icmp or @p ip6 is NULL.
 * @retval BNT_ERR_TRUNC   @p icmp_len exceeds @c BNT_MAX_PAYLOAD bytes, or a
 *                         read or write falls outside the packet.
 */
static __always_inline int bnt_icmp6__recompute_csum(bnt_icmp6 *icmp, bnt_ipv6 *ip6,
                                                       __u16 icmp_len)
{
    if (!icmp || !ip6)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_icmp6_recompute_csum)(icmp->__ctx, icmp->__off, ip6->__off, icmp_len);
}
#endif



/* Fixed-size wrapper so a BPF global infers the full segment-buffer size (a bare
 * `struct in6_addr *` arg would be sized as a single 16-byte element). */
struct __bnt_srv6_segs { struct in6_addr s[BNT_SRV6_MAX_SEGS]; };

/* One-global SRH insert: read + shift + write (IPv6 base + SRH + segments) fused
 * into a single subprogram. Like the IPv6 1G insert, each packet write after
 * bpf_xdp_adjust_head needs a barrier on its derived offset (here: the base/SRH
 * write at `off`, and each segment write at `so`). */
static __always_inline int __bnt_ipv6_insert_srh(struct xdp_md *ctx, __u32 off,
                             struct __bnt_srv6_segs *segs, __u8 n_segs)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *base;
    struct ipv6hdr *hdr;
    struct bnt_sr_hdr *srh;
    __u8 orig_nexthdr;
    __u16 old_plen, new_plen;
    __u32 srh_size, segs_off, prefix, i;
    int ret;

    if (!segs || !n_segs || n_segs > BNT_SRV6_MAX_SEGS)
        return BNT_ERR_BAD_ARG;
    srh_size = (__u32)sizeof(struct bnt_sr_hdr) +
               (__u32)n_segs * (__u32)sizeof(struct in6_addr);

    ret = __bnt_data_ptr(ctx, off, sizeof(*hdr), (void **)&hdr);
    if (ret)
        return ret;
    if (((*(__u8 *)hdr) >> 4) != 6)
        return BNT_ERR_BAD_PROTO;
    orig_nexthdr = hdr->nexthdr;
    old_plen     = bpf_ntohs(__BNT_PKT_LOAD(hdr->payload_len));
    if ((__u32)old_plen + srh_size > 0xffffu)
        return BNT_ERR_TRUNC;
    new_plen = (__u16)(old_plen + (__u16)srh_size);

    /* shift the IPv6 base header forward to open srh_size bytes (variable n: buffer) */
    prefix = off + (__u32)sizeof(struct ipv6hdr);
    ret = __bnt_shift_insert(ctx, prefix, srh_size);
    if (ret)
        return ret;

    /* write the IPv6 base header + SRH base; barrier re-materializes off */
    BNT_PIN(off);     /* see __bnt_eth_insert_ipv4_g */
    ret = __bnt_data_ptr(ctx, off,
                          sizeof(struct ipv6hdr) + sizeof(struct bnt_sr_hdr), &base);
    if (ret)
        return ret;
    hdr = (struct ipv6hdr *)base;
    hdr->nexthdr     = NEXTHDR_ROUTING;
    __BNT_PKT_STORE(hdr->payload_len, bpf_htons(new_plen));
    srh = (struct bnt_sr_hdr *)((__u8 *)base + sizeof(struct ipv6hdr));
    __BNT_PKT_MEMSET0(srh, sizeof(*srh));
    srh->nexthdr       = orig_nexthdr;
    srh->hdrlen        = (__u8)(n_segs * 2u);
    srh->type          = 4;
    srh->segments_left = (__u8)(n_segs - 1);
    srh->first_segment = (__u8)(n_segs - 1);

    segs_off = off + (__u32)sizeof(struct ipv6hdr) + (__u32)sizeof(struct bnt_sr_hdr);
    /* clang 16/17 cannot fully unroll this loop and warn about the pragma; it
     * verifies as a bounded loop there. */
#if !defined(__clang_major__) || __clang_major__ >= 18
#pragma unroll
#endif
    for (i = 0; i < BNT_SRV6_MAX_SEGS; i++) {
        __u8 rev;
        struct in6_addr *sp;
        __u32 so;
        if (i >= (__u32)n_segs)
            break;
        rev = (__u8)(n_segs - 1 - (__u8)i);
        if (rev >= BNT_SRV6_MAX_SEGS)
            return BNT_ERR_BAD_ARG;
        /* Mask the segs[] index to [0, BNT_SRV6_MAX_SEGS) so the verifier can
         * prove the access stays inside the fixed segment buffer.  The guard
         * above already rejects rev >= MAX, so this is a no-op at runtime; it
         * exists only to keep clang-16's BPF backend from widening rev to the
         * full u8 range and losing the bound (clang-18+ propagates it). */
#if BNT_LEGACY_KERNEL || __clang_major__ >= 22
        asm volatile("" : "+r"(rev));   /* clang>=22: keep the clamp below from being elided */
#endif
        rev &= (__u8)(BNT_SRV6_MAX_SEGS - 1u);
        so = segs_off + i * (__u32)sizeof(struct in6_addr);
        BNT_PIN(so);     /* keeps the bounds check on so, as on off above */
        ret = __bnt_data_ptr(ctx, so, sizeof(struct in6_addr), (void **)&sp);
        if (ret)
            return ret;
        __BNT_PKT_MEMCPY(sp, &segs->s[rev], sizeof(struct in6_addr));
    }
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_insert_srh_g(struct xdp_md *ctx, __u32 off,
                             struct __bnt_srv6_segs *segs, __u8 n_segs);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_insert_srh_g(struct xdp_md *ctx, __u32 off,
                             struct __bnt_srv6_segs *segs, __u8 n_segs)
{
    return __bnt_ipv6_insert_srh(ctx, off, segs, n_segs);
}
#endif
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_ipv6
 * @brief Inserts an SRH immediately after an existing IPv6 base header (H.Insert).
 *
 * Segment addresses are passed in forward visitation order.
 *
 * @note The header prefix before the insertion point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Views for headers after @p ip6 become stale; re-parse them.
 *
 * @param ip6     Parsed IPv6 view.
 * @param segs    Segment list, in forward visitation order.
 * @param n_segs  Number of segments; must be between 1 and
 *                @c BNT_SRV6_MAX_SEGS (see @ref limits).
 * @retval BNT_OK            on success.
 * @retval BNT_ERR_BAD_ARG   @p ip6 or @p segs is NULL, or @p n_segs is 0 or
 *                           exceeds @c BNT_SRV6_MAX_SEGS.
 * @retval BNT_ERR_BAD_PROTO the header is not a well-formed IPv6 header.
 * @retval BNT_ERR_TRUNC     the new payload length would overflow, or the
 *                           insertion falls outside the packet.
 * @retval BNT_ERR_TOO_DEEP  the header prefix before @p ip6 exceeds
 *                           @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_ipv6__insert_srh(bnt_ipv6 *ip6,
                                                  const struct in6_addr *segs,
                                                  __u8 n_segs)
{
    if (!ip6 || !segs || !n_segs || n_segs > BNT_SRV6_MAX_SEGS)
        return BNT_ERR_BAD_ARG;

    {
        /* One global for the whole operation. Copy the (possibly rodata) segment
         * list to a writable stack buffer first (a global's pointer arg is assumed
         * writable). */
        struct __bnt_srv6_segs segbuf = {};
        __u32 i;

        for (i = 0; i < BNT_SRV6_MAX_SEGS; i++)
            if (i < n_segs)
                __builtin_memcpy(&segbuf.s[i], &segs[i], sizeof(struct in6_addr));

        return __BNT_OP(__bnt_ipv6_insert_srh)(ip6->__ctx, ip6->__off, &segbuf, n_segs);
    }
}

/** Pushes one MPLS label after Ethernet/VLAN; BOS is set automatically. */
/* One-global insert: Ethernet/VLAN walk (also yields the EtherType for the BOS
 * bit) + shift + LSE/ethertype write, fused. Barrier on prefix_len for the
 * post-adjust write (see __bnt_eth_insert_ipv6_g). */
static __always_inline int __bnt_eth_insert_mpls(struct xdp_md *ctx, __u32 off, __u32 label, __u8 tc, __u8 ttl)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *p;
    __be16 proto;
    __be32 lse;
    bool bos;
    __u32 hlen = sizeof(struct ethhdr), cur, prefix_len, i;
    int ret;

    if (label > 0xFFFFFu)
        return BNT_ERR_BAD_ARG;

    /* walk Ethernet + VLAN inline; proto also drives the BOS bit */
    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(*(__be16 *)p);
    cur = off + sizeof(struct ethhdr);
    for (i = 0; i < BNT_MAX_VLAN_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        ret = __bnt_data_ptr(ctx, cur + 2, sizeof(__be16), &p);
        if (ret)
            return ret;
        proto = __BNT_PKT_LOAD(*(__be16 *)p);
        hlen += 4;
        cur += 4;
    }
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
        return BNT_ERR_TOO_DEEP;
    /* BOS=1 when the existing EtherType is not MPLS (this label is the bottom). */
    bos = (proto != bpf_htons(ETH_P_MPLS_UC) && proto != bpf_htons(ETH_P_MPLS_MC));
    lse = bpf_htonl((label << 12) |
                     ((__u32)(tc & 0x7u) << 9) |
                     (bos ? (1u << 8) : 0u) |
                     (__u32)ttl);
    prefix_len = off + hlen;

    ret = __bnt_shift_insert_4(ctx, prefix_len);
    if (ret)
        return ret;

    BNT_PIN(prefix_len);     /* see __bnt_eth_insert_ipv4_g */
    ret = __bnt_data_ptr(ctx, prefix_len, sizeof(__be32), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be32 *)p, lse);
    ret = __bnt_data_ptr(ctx, prefix_len - 2, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(ETH_P_MPLS_UC));
    return BNT_OK;
}

#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_mpls_g(struct xdp_md *ctx, __u32 off, __u32 label, __u8 tc, __u8 ttl);
#if !BNT_ASM_GLOBALS
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_mpls_g(struct xdp_md *ctx, __u32 off, __u32 label, __u8 tc, __u8 ttl)
{
    return __bnt_eth_insert_mpls(ctx, off, label, tc, ttl);
}
#endif
#endif /* !BNT_INLINE_ALL */

/**
 * @ingroup bnt_eth
 * @brief Pushes one MPLS label as the new outermost label, immediately after
 * Ethernet/VLAN.
 *
 * Sets the BOS bit when the current EtherType is not already MPLS (this
 * becomes the bottom of a new stack); clears it when pushing onto an existing
 * MPLS stack. Sets the EtherType (or the outermost VLAN's encapsulated
 * protocol) to ETH_P_MPLS_UC.
 *
 * @note The header prefix before the insertion point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
 * Unless @p eth is at offset 0 with no VLAN tag (a prefix of the Ethernet
 * header alone), the packet must hold @c BNT_XDP_MAX_HEADER_PREFIX bytes;
 * shorter, returns BNT_ERR_TRUNC. On an error the packet is left unchanged.
 * Views for headers after @p eth become stale; re-parse them.
 *
 * @param eth   Parsed Ethernet view.
 * @param label New label value; must fit in 20 bits.
 * @param tc    Traffic class / EXP value.
 * @param ttl   TTL value.
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p eth is NULL, or @p label exceeds 20 bits.
 * @retval BNT_ERR_TRUNC   a read or write falls outside the packet.
 * @retval BNT_ERR_WRITE   the packet resize failed.
 * @retval BNT_ERR_TOO_DEEP the VLAN walk (@c BNT_MAX_VLAN_DEPTH, see
 *                          @ref limits) is exhausted, or the header prefix
 *                          before @p eth exceeds @c BNT_XDP_MAX_HEADER_PREFIX.
 */
static __always_inline int bnt_eth__insert_mpls(bnt_eth *eth,
                                                  __u32 label, __u8 tc, __u8 ttl)
{
    if (!eth || label > 0xFFFFFu)
        return BNT_ERR_BAD_ARG;
    return __BNT_OP(__bnt_eth_insert_mpls)(eth->__ctx, eth->__off, label, tc, ttl);
}

#if !BNT_INLINE_ALL && BNT_ASM_GLOBALS
#include "bnt_asm_globals.h"
#endif

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* BNT_XDP_H */
