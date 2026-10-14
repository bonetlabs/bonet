/* SPDX-License-Identifier: MIT */
#ifndef BNT_XDP_H
#define BNT_XDP_H

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
 * Verifier-hardening barriers
 *
 * BNT_LEGACY_KERNEL forces inline mode and enables an extra set of barriers that
 * steer clang's codegen into shapes the BPF verifier can follow.  They are
 * semantically transparent (no runtime behaviour change) and exist for inline
 * builds that cannot rely on the global sub-program boundary for isolation:
 * older/stricter verifiers (kernels before 5.12, where the default global mode
 * is unavailable so inline is mandatory) and aggressive compilers.  They add
 * processed_insns and stack depth, so they are off by default; in global mode
 * the sub-program boundary provides the same isolation for free.
 *
 * Gated on BNT_LEGACY_KERNEL (inline-only hardening):
 *   1. asm volatile("" : "+r"(ctx)) in __bnt_xdp_fresh_ctx — gives the verifier
 *      an independent data/data_end pair at every bounds check (no caching of
 *      ctx->data across accesses).
 *   2. __noinline on __bnt_len — isolates (data_end - data) in a sub-prog so it
 *      returns in a register instead of being re-derived in the caller.
 *   3. volatile on the __bnt_csum_range loop counters — keeps their tnum bounds
 *      from being re-derived off the unbounded stack copy of `len`.
 *
 * Always on, in EVERY mode (structural — the verifier has no alternative, so it
 * is not optional and not gated):
 *   4. __bnt_shift_insert / __bnt_shift_remove copy the header prefix through a
 *      stack buffer: a packet pointer at a runtime offset (data+n) has verifier
 *      range 0 and cannot be accessed directly.
 *   5. Packet-derived scalars and runtime stack-array indices are pinned after
 *      narrowing — asm volatile on derived offsets (hlen, per-segment offsets)
 *      and a mask on the SRH segment index — so the narrowed bound survives
 *      instead of being re-derived.
 *
 * NOTE: this barrier set is best-effort, not a completeness guarantee.  In
 * inline mode the API is fused with the (unbounded) caller, so caller-driven
 * register/stack pressure can make clang spill or fold in ways no fixed set of
 * barriers can pre-empt.  The only caller-independent guarantee is global mode.
 */
/*
 * Two build knobs:
 *   BNT_INLINE_ALL     0 = global isolation (default), 1 = fully inline.
 *   BNT_LEGACY_KERNEL  set for target kernels older than 5.12, which cannot
 *                      run the global mode.  Forces inline mode AND turns on the
 *                      inline-hardening barriers — the only configuration that
 *                      verifies on those older kernels.  Set it explicitly (the
 *                      build cannot detect the *target* kernel version); the
 *                      default stays global.
 *
 * The barriers below are gated on BNT_LEGACY_KERNEL.  Since legacy forces inline,
 * it can never coexist with global mode, so global builds are barrier-free by
 * construction — the sub-program boundary already isolates the API there.
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
    if (!ctx)
        return BNT_ERR_BAD_ARG;
    return __bnt_bounds_len(__bnt_len(ctx), off, len);
}

#ifndef BNT_XDP_MAX_PACKET_OFFSET
#define BNT_XDP_MAX_PACKET_OFFSET 0xffffu
#endif

static __always_inline int __bnt_data_ptr(struct xdp_md *ctx, __u32 off, __u32 len, void **out)
{
    unsigned char *base;
    unsigned char *ptr;
    void *end;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = NULL;
    if (!ctx)
        return BNT_ERR_BAD_ARG;
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

#if !BNT_INLINE_ALL && !BNT_STRICT_ALIGN
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

/* Define context type before including shared helpers. */
#define BNT_CTX_TYPE struct xdp_md
#include "bnt_rw.h"

#if !BNT_INLINE_ALL
/*
 * Fixed-size single-block checksum globals.  Straight-line (no loop) and with a
 * compile-time constant length, so __bnt_data_ptr threads its bounds check into
 * the pointer exactly as in the read primitives: bpf_csum_diff sees a packet
 * pointer with a provable, constant range even when off arrives with a wide
 * var_off.  __bnt_csum_range drives these from a loop that carries only the
 * scalar offset and accumulator, never a packet pointer.
 */
__attribute__((noinline, weak, nonnull(1))) int __bnt_csum_blk_g(struct xdp_md *ctx, __u32 off,
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
    res = bpf_csum_diff(NULL, 0, (__be32 *)p, BNT_CSUM_CHUNK, seed);
    if (res < 0)
        return BNT_ERR_TRUNC;
    *out = (__wsum)res;
    return BNT_OK;
}

__attribute__((noinline, weak, nonnull(1))) int __bnt_csum_word_g(struct xdp_md *ctx, __u32 off,
                                                 __wsum seed, __wsum *out)
{
    void  *p;
    __s64  res;
    int    ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = seed;
    ret = __bnt_data_ptr(ctx, off, 4, &p);
    if (ret)
        return ret;
    res = bpf_csum_diff(NULL, 0, (__be32 *)p, 4, seed);
    if (res < 0)
        return BNT_ERR_TRUNC;
    *out = (__wsum)res;
    return BNT_OK;
}

/* Reads one packet byte through a global (straight-line data_ptr). */
__attribute__((noinline, weak, nonnull(1))) int __bnt_csum_byte_g(struct xdp_md *ctx, __u32 off, __u8 *out)
{
    void *p;
    int   ret;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    ret = __bnt_data_ptr(ctx, off, 1, &p);
    if (ret)
        return ret;
    *out = *(__u8 *)p;
    return BNT_OK;
}
#endif

/*
 * XDP-specific __bnt_csum_range:
 *
 * Two compounding verifier problems require the approach below:
 *
 * (1) Stack-slot tnum loss: `len` reloaded from a stack slot is unbounded
 *     (mmmmmmmm) even after an earlier conditional check, because the
 *     verifier does not back-propagate register bounds to the originating
 *     stack slot.
 *
 * (2) Compiler re-derivation: even if n_chunks / n_words are precomputed
 *     from the bounded register, clang treats them as re-derivable from `len`
 *     (n_chunks == len >> log2(CHUNK)) and may reload `len` from its own
 *     mmmmmmmm stack slot and recompute inline, discarding the bounded slot.
 *
 * Fix: declare n_chunks and n_words as `volatile`.  volatile forces the
 * compiler to (a) materialise a dedicated stack slot for each variable,
 * (b) write it exactly once from the bounded register value, and (c) always
 * reload from that slot rather than recomputing from `len`.  The verifier
 * preserves the tnum of the initial store, so subsequent reloads carry the
 * tight [0, BNT_MAX_PAYLOAD/CHUNK] bound into every loop condition.
 */
static __always_inline int __bnt_csum_range(struct xdp_md *ctx, __u32 off, __u32 len,
                                             __wsum seed, __wsum *out)
{
    __wsum acc = seed;
    __s64  res;
    __u32  i;

    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    if (!ctx)
        return BNT_ERR_BAD_ARG;

    if (len > BNT_MAX_PAYLOAD)
        return BNT_ERR_TRUNC;
    /* Bound off before deriving ptr (mirrors __bnt_data_ptr): once off arrives
     * unconstrained from a *_meta_g result, the bounds checks below cannot
     * recover a usable packet range without this clamp. */
    if (off > 0xffffu - len)
        return BNT_ERR_TRUNC;

    /* Computed from `len` while it is still in a bounded register.
     * volatile prevents the compiler from replacing loads with a
     * re-derivation from the mmmmmmmm `len` stack slot. */
#if BNT_LEGACY_KERNEL
    volatile __u32 n_chunks = len >> __builtin_ctz(BNT_CSUM_CHUNK);
    volatile __u32 n_words  = (len & (__u32)(BNT_CSUM_CHUNK - 1)) >> 2;
#else
    __u32 n_chunks = len >> __builtin_ctz(BNT_CSUM_CHUNK);
    __u32 n_words  = (len & (__u32)(BNT_CSUM_CHUNK - 1)) >> 2;
#endif
    __u32 rem               = len & (__u32)(BNT_CSUM_CHUNK - 1);

#if !BNT_INLINE_ALL
    /*
     * Level 2: carry a scalar offset (cur) across the loop back-edge and
     * re-derive a fresh, range-checked packet pointer each iteration.  When off
     * arrives from a *_meta_g result it has a wide var_off; a packet pointer
     * advanced across a back-edge loses its range under that var_off, so
     * bpf_csum_diff would see r=0.  Re-deriving per iteration (as __bnt_data_ptr
     * does for a single access) keeps every chunk pointer provably in range.
     */
    {
        __u32 cur = off;
        int   ret;

        for (i = 0; i < BNT_MAX_PAYLOAD / BNT_CSUM_CHUNK + 1; i++) {
            if (i >= n_chunks)
                break;
            ret = __bnt_csum_blk_g(ctx, cur, acc, &acc);
            if (ret)
                return ret;
            cur += BNT_CSUM_CHUNK;
        }

        for (i = 0; i < BNT_CSUM_CHUNK / 4; i++) {
            if (i >= n_words)
                break;
            ret = __bnt_csum_word_g(ctx, cur, acc, &acc);
            if (ret)
                return ret;
            cur += 4;
        }

        rem &= 3U;
        if (rem > 0) {
            __be32 tail = 0;
            __u8  *t    = (__u8 *)&tail;

            ret = __bnt_csum_byte_g(ctx, cur, &t[0]);
            if (ret)
                return ret;
            if (rem >= 2) {
                ret = __bnt_csum_byte_g(ctx, cur + 1, &t[1]);
                if (ret)
                    return ret;
            }
            if (rem >= 3) {
                ret = __bnt_csum_byte_g(ctx, cur + 2, &t[2]);
                if (ret)
                    return ret;
            }
            res = bpf_csum_diff(NULL, 0, &tail, 4, acc);
            if (res < 0)
                return BNT_ERR_TRUNC;
            acc = (__wsum)res;
        }
    }
#else
    /*
     * Keep this hot checksum path in its compact direct-load form.  The
     * generic XDP helpers intentionally break ctx load CSE, but doing that
     * inside the csum loop increases verifier state pressure.
     */
    void *data_end = (void *)(long)ctx->data_end;
    void *ptr = (void *)(long)ctx->data + off;

    /* Process BNT_CSUM_CHUNK-byte chunks. */
#if BNT_LEGACY_KERNEL
#pragma unroll
#endif
    for (i = 0; i < BNT_MAX_PAYLOAD / BNT_CSUM_CHUNK + 1; i++) {
        if (i >= n_chunks)
            break;
        if (ptr + BNT_CSUM_CHUNK > data_end)
            return BNT_ERR_TRUNC;
        res = bpf_csum_diff(NULL, 0, (__be32 *)ptr, BNT_CSUM_CHUNK, acc);
        if (res < 0)
            return BNT_ERR_TRUNC;
        acc = (__wsum)res;
        ptr += BNT_CSUM_CHUNK;
    }

    /* Process 4-byte words of the remainder. */
#if BNT_LEGACY_KERNEL
#pragma unroll
#endif
    for (i = 0; i < BNT_CSUM_CHUNK / 4; i++) {
        if (i >= n_words)
            break;
        if (ptr + 4 > data_end)
            return BNT_ERR_TRUNC;
        res = bpf_csum_diff(NULL, 0, (__be32 *)ptr, 4, acc);
        if (res < 0)
            return BNT_ERR_TRUNC;
        acc = (__wsum)res;
        ptr += 4;
    }

    /* Tail: 0–3 bytes. rem & 3 gives the byte count. */
    rem &= 3U;
    if (rem > 0) {
        __be32 tail = 0;
        __u8  *t    = (__u8 *)&tail;
        if (ptr + 1 > data_end)
            return BNT_ERR_TRUNC;
        t[0] = *((__u8 *)ptr);
        if (rem >= 2) {
            if (ptr + 2 > data_end)
                return BNT_ERR_TRUNC;
            t[1] = *((__u8 *)ptr + 1);
        }
        if (rem >= 3) {
            if (ptr + 3 > data_end)
                return BNT_ERR_TRUNC;
            t[2] = *((__u8 *)ptr + 2);
        }
        res = bpf_csum_diff(NULL, 0, &tail, 4, acc);
        if (res < 0)
            return BNT_ERR_TRUNC;
        acc = (__wsum)res;
    }
#endif

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

/*
 * Level 2: confine the incremental checksum updaters in global BPF functions.
 * The inline versions read+write the checksum field at a caller-supplied offset;
 * once that offset arrives unconstrained from another global (e.g. a *_meta_g
 * result), the inline packet access fails range tracking.  Wrapping each updater
 * in a global verified once in isolation keeps every checksum write confined.
 * The redirect macros below route all callers (here and in bnt_core.h, included
 * afterwards) to the globals with no per-call-site changes.
 */
#if !BNT_INLINE_ALL
__attribute__((noinline, weak, nonnull(1))) int __bnt_l4_csum16_g(struct xdp_md *ctx, __u32 off,
                                                 __be16 from, __be16 to, int mangled)
{ return __bnt_l4_csum16(ctx, off, from, to, mangled); }
__attribute__((noinline, weak, nonnull(1))) int __bnt_l4_csum32_g(struct xdp_md *ctx, __u32 off,
                                                 __be32 from, __be32 to, int mangled)
{ return __bnt_l4_csum32(ctx, off, from, to, mangled); }
__attribute__((noinline, weak, nonnull(1))) int __bnt_l4_pseudo_csum16_g(struct xdp_md *ctx, __u32 off,
                                                        __be16 from, __be16 to, int mangled)
{ return __bnt_l4_pseudo_csum16(ctx, off, from, to, mangled); }
__attribute__((noinline, weak, nonnull(1))) int __bnt_l4_pseudo_csum32_g(struct xdp_md *ctx, __u32 off,
                                                        __be32 from, __be32 to, int mangled)
{ return __bnt_l4_pseudo_csum32(ctx, off, from, to, mangled); }
__attribute__((noinline, weak, nonnull(1))) int __bnt_l3_csum16_g(struct xdp_md *ctx, __u32 off,
                                                 __be16 from, __be16 to)
{ return __bnt_l3_csum16(ctx, off, from, to); }
__attribute__((noinline, weak, nonnull(1))) int __bnt_l3_csum32_g(struct xdp_md *ctx, __u32 off,
                                                 __be32 from, __be32 to)
{ return __bnt_l3_csum32(ctx, off, from, to); }
#define __bnt_l4_csum16        __bnt_l4_csum16_g
#define __bnt_l4_csum32        __bnt_l4_csum32_g
#define __bnt_l4_pseudo_csum16 __bnt_l4_pseudo_csum16_g
#define __bnt_l4_pseudo_csum32 __bnt_l4_pseudo_csum32_g
#define __bnt_l3_csum16        __bnt_l3_csum16_g
#define __bnt_l3_csum32        __bnt_l3_csum32_g
#endif

#include "bnt_core.h"
#undef BNT_CTX_TYPE

#define try_or_return_pass(expr)     __bnt_try_or_return(expr, XDP_PASS)
#define try_or_return_drop(expr)     __bnt_try_or_return(expr, XDP_DROP)
#define try_or_return_tx(expr)       __bnt_try_or_return(expr, XDP_TX)
#define try_or_return_redirect(expr) __bnt_try_or_return(expr, XDP_REDIRECT)
#define try_or_return_aborted(expr)  __bnt_try_or_return(expr, XDP_ABORTED)

/* Raw setters for callers that will recompute checksums from scratch. */
/** @ingroup bnt_ipv4
 *  Sets the IPv4 TOS/DSCP+ECN byte without updating the checksum. */
static __always_inline int bnt_ipv4__set_tos_no_csum(bnt_ipv4 *ip, __u8 tos)
    { return __bnt_ipv4__set_tos_raw(ip, tos); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 TTL without updating the checksum. */
static __always_inline int bnt_ipv4__set_ttl_no_csum(bnt_ipv4 *ip, __u8 ttl)
    { return __bnt_ipv4__set_ttl_raw(ip, ttl); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 source address without updating any checksum. */
static __always_inline int bnt_ipv4__set_saddr_no_csum(bnt_ipv4 *ip, __be32 saddr)
    { return __bnt_ipv4__set_saddr_raw(ip, saddr); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 destination address without updating any checksum. */
static __always_inline int bnt_ipv4__set_daddr_no_csum(bnt_ipv4 *ip, __be32 daddr)
    { return __bnt_ipv4__set_daddr_raw(ip, daddr); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 identification field without updating the checksum. */
static __always_inline int bnt_ipv4__set_id_no_csum(bnt_ipv4 *ip, __u16 id)
    { return __bnt_ipv4__set_id_raw(ip, id); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 total length field without updating any checksum. */
static __always_inline int bnt_ipv4__set_total_len_no_csum(bnt_ipv4 *ip, __u16 total_len)
    { return __bnt_ipv4__set_total_len_raw(ip, total_len); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 protocol field without updating any checksum. */
static __always_inline int bnt_ipv4__set_protocol_no_csum(bnt_ipv4 *ip, __u8 protocol)
    { return __bnt_ipv4__set_protocol_raw(ip, protocol); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 fragment offset and flags word without updating the checksum. */
static __always_inline int bnt_ipv4__set_frag_off_no_csum(bnt_ipv4 *ip, __u16 frag_off)
    { return __bnt_ipv4__set_frag_off_raw(ip, frag_off); }
/** @ingroup bnt_ipv4
 *  Sets the IPv4 IHL (header length) without updating the checksum. */
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
 * This value is the BPF-verifier loop bound: the verifier explores one state
 * per loop iteration, so a tighter bound directly reduces processed_insns.
 * The default of 64 is intentionally conservative and covers all standard
 * Ethernet/VLAN/IPv6 stacks without requiring any configuration.
 *
 * HOW TO TUNE:
 *   Define this macro before #include <bnt_xdp.h> to override the default.
 *
 *   Reduce it when you know your programs never exceed a shallower prefix:
 *     #define BNT_XDP_MAX_HEADER_PREFIX 14   // plain Ethernet only
 *     #define BNT_XDP_MAX_HEADER_PREFIX 22   // Ethernet + up to QinQ
 *
 *   Increase it when your programs operate on deeper stacks, for example
 *   inserting headers after an outer tunneling layer (GRE, IPIP, etc.):
 *     #define BNT_XDP_MAX_HEADER_PREFIX 94   // Ethernet + QinQ + IPv4 + IPv6
 *
 *   There is no kernel-imposed ceiling on this value other than the BPF stack
 *   limit (512 bytes) and practical packet structure.  If the runtime prefix
 *   exceeds the configured bound, bnt returns BNT_ERR_TOO_DEEP.
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

__BNT_SHIFT_LINKAGE int __bnt_shift_insert(struct xdp_md *ctx,
                                                   __u32 prefix_len, __u32 n)
{
    __u8 buf[BNT_XDP_MAX_HEADER_PREFIX];
    void *data, *data_end;
    __u32 i;

    if (!ctx)
        return BNT_ERR_BAD_ARG;
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

    if (bpf_xdp_adjust_head(ctx, -(int)n))
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

__BNT_SHIFT_LINKAGE int __bnt_shift_remove(struct xdp_md *ctx,
                                                   __u32 prefix_len, __u32 n)
{
    __u8 buf[BNT_XDP_MAX_HEADER_PREFIX];
    void *data, *data_end;
    __u32 i;

    if (!ctx)
        return BNT_ERR_BAD_ARG;
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

#define __BNT_SHIFT_INSERT_FIXED(N)                                             \
__BNT_SHIFT_LINKAGE int __bnt_shift_insert_##N(struct xdp_md *ctx,            \
                                                  __u32 prefix_len)              \
{                                                                                 \
    void *data, *data_end;                                                       \
    __u8 *shifted;                                                                \
    __u32 i;                                                                     \
    if (!ctx)                                                                    \
        return BNT_ERR_BAD_ARG;                                                \
    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)                                \
        return BNT_ERR_TOO_DEEP;                                               \
    if (bpf_xdp_adjust_head(ctx, -(int)(N)))                                    \
        return BNT_ERR_WRITE;                                                  \
    data     = (void *)(long)ctx->data;                                          \
    data_end = (void *)(long)ctx->data_end;                                      \
    shifted  = (__u8 *)data + (N);                                               \
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX + (N) > (__u8 *)data_end)    \
        return BNT_ERR_TRUNC;                                                  \
    for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {                         \
        if (i >= prefix_len)                                                     \
            break;                                                               \
        *((__u8 *)data + i) = *(shifted + i);                                   \
    }                                                                             \
    return BNT_OK;                                                              \
}

#define __BNT_SHIFT_REMOVE_FIXED(N)                                             \
__BNT_SHIFT_LINKAGE int __bnt_shift_remove_##N(struct xdp_md *ctx,            \
                                                  __u32 prefix_len)              \
{                                                                                 \
    void *data, *data_end;                                                       \
    __u8 *shifted;                                                                \
    __u32 i;                                                                     \
    if (!ctx)                                                                    \
        return BNT_ERR_BAD_ARG;                                                \
    if (prefix_len > BNT_XDP_MAX_HEADER_PREFIX)                                \
        return BNT_ERR_TOO_DEEP;                                               \
    data     = (void *)(long)ctx->data;                                          \
    data_end = (void *)(long)ctx->data_end;                                      \
    shifted  = (__u8 *)data + (N);                                               \
    if ((__u8 *)data + BNT_XDP_MAX_HEADER_PREFIX + (N) > (__u8 *)data_end)    \
        return BNT_ERR_TRUNC;                                                  \
    for (i = 0; i < BNT_XDP_MAX_HEADER_PREFIX; i++) {                         \
        if (i >= prefix_len)                                                     \
            break;                                                               \
        *(shifted + i) = *((__u8 *)data + i);                                   \
    }                                                                             \
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
#if !BNT_INLINE_ALL
/* One-global insert: read outer EtherType + shift + write the VLAN tag and set
 * the eth EtherType to the TPID, all fused. Inserts the outer tag at a constant
 * offset (off + 14), so the post-adjust writes need no barrier (no walk widens
 * the offset). */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_vlan_g(struct xdp_md *ctx, __u32 off, __u16 tpid, __u16 tci)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *p;
    __be16 proto;
    __u16 outer_proto;
    __u32 prefix_len, cur, i, depth = 0;
    int ret;

    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    proto = __BNT_PKT_LOAD(*(__be16 *)p);
    outer_proto = bpf_ntohs(proto);

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
        __be32 tag = bpf_htonl(((__u32)tci << 16) | (__u32)outer_proto);
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
#endif

/**
 * @ingroup bnt_eth
 * @brief Inserts a VLAN tag as the outermost tag, immediately after the Ethernet
 * source/destination fields.
 *
 * @note The header prefix before the insertion point must not exceed
 * @c BNT_XDP_MAX_HEADER_PREFIX bytes; beyond it, returns BNT_ERR_TOO_DEEP.
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
#if !BNT_INLINE_ALL
    return __bnt_eth_insert_vlan_g(eth->__ctx, eth->__off, tpid, tci);
#else
    {
        struct __bnt_eth_meta meta;
        __u16 outer_proto;
        __u32 prefix_len;
        int ret;
        struct bnt_vlan_hdr vlan = {};

        ret = __bnt_eth_meta(eth, &meta);
        if (ret)
            return ret;
        if (meta.vlan_depth >= BNT_MAX_VLAN_DEPTH)
            return BNT_ERR_TOO_DEEP;

        ret = bnt_eth__get_outer_proto(eth, &outer_proto);
        if (ret)
            return ret;
        prefix_len = eth->__off + sizeof(struct ethhdr);
        ret = __bnt_shift_insert_4(eth->__ctx, prefix_len);
        if (ret)
            return ret;
        ret = bnt_eth__set_outer_proto(eth, tpid);
        if (ret)
            return ret;
        vlan.h_vlan_TCI = bpf_htons(tci);
        vlan.h_vlan_encapsulated_proto = bpf_htons(outer_proto);
        return __bnt_write(eth->__ctx, prefix_len, &vlan, sizeof(vlan));
    }
#endif
}

/** Removes the outermost VLAN header after the Ethernet source/destination fields. */
#if !BNT_INLINE_ALL
/* One-global remove: read outer EtherType + encapsulated proto, rewrite the eth
 * EtherType, then shift-remove the 4-byte tag. bpf_xdp_adjust_head runs LAST (no
 * packet write follows the resize), so no post-adjust barrier is needed. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_vlan_g(struct xdp_md *ctx, __u32 off)
{
    BNT_TIGHTEN_OFFSET(off, BNT_XDP_MAX_PACKET_OFFSET);
    void *p;
    __u16 outer_proto;
    __be16 encap;
    __u32 vlan_off;
    int ret;

    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    outer_proto = bpf_ntohs(__BNT_PKT_LOAD(*(__be16 *)p));
    if (outer_proto != ETH_P_8021Q && outer_proto != ETH_P_8021AD)
        return BNT_ERR_BAD_PROTO;

    vlan_off = off + sizeof(struct ethhdr);
    ret = __bnt_data_ptr(ctx,
                          vlan_off + offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto),
                          sizeof(__be16), &p);
    if (ret)
        return ret;
    encap = __BNT_PKT_LOAD(*(__be16 *)p);

    ret = __bnt_data_ptr(ctx, off + offsetof(struct ethhdr, h_proto), sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, encap);

    return __bnt_shift_remove_4(ctx, vlan_off);
}
#endif

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
#if !BNT_INLINE_ALL
    return __bnt_eth_remove_vlan_g(eth->__ctx, eth->__off);
#else
    {
        __be16 encap;
        __u32 vlan_off;
        __u16 outer_proto;
        int ret;

        ret = bnt_eth__get_outer_proto(eth, &outer_proto);
        if (ret)
            return ret;
        if (outer_proto != ETH_P_8021Q && outer_proto != ETH_P_8021AD)
            return BNT_ERR_BAD_PROTO;

        vlan_off = eth->__off + sizeof(struct ethhdr);
        ret = __bnt_read_be16(eth->__ctx,
                               vlan_off + offsetof(struct bnt_vlan_hdr, h_vlan_encapsulated_proto),
                               &encap);
        if (ret)
            return ret;

        ret = bnt_eth__set_outer_proto(eth, bpf_ntohs(encap));
        if (ret)
            return ret;

        return __bnt_shift_remove_4(eth->__ctx, vlan_off);
    }
#endif
}



/** Inserts a base IPv4 header immediately after Ethernet/VLAN and initializes it. */
#if !BNT_INLINE_ALL
/* One-global insert: Ethernet/VLAN walk + shift + IPv4 header write fused. The
 * header write after bpf_xdp_adjust_head needs a barrier on prefix_len (see
 * __bnt_eth_insert_ipv6_g). */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_ipv4_g(struct xdp_md *ctx, __u32 off, __u8 protocol,
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

#if BNT_LEGACY_KERNEL || (__clang_major__ >= 17 && __clang_major__ <= 19) || __clang_major__ == 21
    BNT_PIN(prefix_len);     /* clang 17,18,19,21 */
#endif
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
    if ((long)csum < 0)
        return BNT_ERR_WRITE;
    __BNT_PKT_STORE(ip->check, __bnt_csum_fold(csum));

    ret = __bnt_data_ptr(ctx, prefix_len - 2, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(ETH_P_IP));
    return BNT_OK;
}
#endif

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
#if !BNT_INLINE_ALL
    return __bnt_eth_insert_ipv4_g(eth->__ctx, eth->__off, protocol, saddr, daddr);
#else
    {
        struct __bnt_eth_meta meta;
        __u32 prefix_len;
        __u32 pkt_len;
        __u32 total_len;
        __wsum csum;
        int ret;

        ret = __bnt_eth_meta(eth, &meta);
        if (ret)
            return ret;

        prefix_len = eth->__off + meta.hlen;
        ret = __bnt_shift_insert_20(eth->__ctx, prefix_len);
        if (ret)
            return ret;

        pkt_len = __bnt_len(eth->__ctx);
        if (prefix_len > pkt_len)
            return BNT_ERR_TRUNC;
        total_len = pkt_len - prefix_len;
        if (total_len < sizeof(struct iphdr) || total_len > 0xffff)
            return BNT_ERR_TRUNC;
        {
            struct iphdr h = {};
            h.version  = 4;
            h.ihl      = 5;
            h.tot_len  = bpf_htons((__u16)total_len);
            h.frag_off = bpf_htons(IP_DF);
            h.ttl      = 64;
            h.protocol = protocol;
            h.saddr    = saddr;
            h.daddr    = daddr;
            csum = bpf_csum_diff(NULL, 0, (__be32 *)&h, sizeof(h), 0);
            if ((long)csum < 0)
                return BNT_ERR_WRITE;
            h.check = __bnt_csum_fold(csum);
            ret = __bnt_write(eth->__ctx, prefix_len, &h, sizeof(h));
            if (ret)
                return ret;
        }
        return bnt_eth__set_ethertype(eth, ETH_P_IP);
    }
#endif
}

#if !BNT_INLINE_ALL
/* One-global insert: Ethernet/VLAN walk + shift + header write fused into a
 * single subprogram (1 bpf2bpf call instead of 3). Every packet write performed
 * AFTER bpf_xdp_adjust_head must be preceded by a barrier on its derived offset:
 * it forces clang to re-materialize the offset register so the verifier can keep
 * the bounds proof (without it, clang spills/reloads the offset wide across the
 * adjust and the access is rejected with r=0). NB: this relies on compiler codegen
 * and is more clang-version-sensitive than the split version. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_ipv6_g(struct xdp_md *ctx, __u32 off, __u8 nexthdr,
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
#if BNT_LEGACY_KERNEL || (__clang_major__ >= 17 && __clang_major__ <= 19) || __clang_major__ == 21
    BNT_PIN(prefix_len);     /* clang 17,18,19,21 */
#endif
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
#endif

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
#if !BNT_INLINE_ALL
    {
        /* One global for the whole op. Copy the (possibly rodata) addresses to
         * stack so the global gets writable pointer args. */
        struct in6_addr s = *saddr, d = *daddr;
        return __bnt_eth_insert_ipv6_g(eth->__ctx, eth->__off, nexthdr, &s, &d);
    }
#else
    {
        struct __bnt_eth_meta meta;
        __u32 prefix_len;
        __u32 pkt_len;
        __u32 payload_len;
        int ret;

        ret = __bnt_eth_meta(eth, &meta);
        if (ret)
            return ret;

        prefix_len = eth->__off + meta.hlen;
        ret = __bnt_shift_insert_40(eth->__ctx, prefix_len);
        if (ret)
            return ret;

        pkt_len = __bnt_len(eth->__ctx);
        if (prefix_len > pkt_len)
            return BNT_ERR_TRUNC;
        payload_len = pkt_len - prefix_len - sizeof(struct ipv6hdr);
        if (payload_len > 0xffff)
            return BNT_ERR_TRUNC;
        {
            struct ipv6hdr h = {};
            h.version     = 6;
            h.payload_len = bpf_htons((__u16)payload_len);
            h.nexthdr     = nexthdr;
            h.hop_limit   = 64;
            __builtin_memcpy(&h.saddr, saddr, sizeof(h.saddr));
            __builtin_memcpy(&h.daddr, daddr, sizeof(h.daddr));
            ret = __bnt_write(eth->__ctx, prefix_len, &h, sizeof(h));
            if (ret)
                return ret;
        }
        return bnt_eth__set_ethertype(eth, ETH_P_IPV6);
    }
#endif
}

/** Removes a base IPv4 header immediately after Ethernet/VLAN. */
#if !BNT_INLINE_ALL
/* One-global remove: Ethernet/VLAN walk + inner-header reads + EtherType rewrite
 * + shift-remove fused. bpf_xdp_adjust_head runs LAST, so no barrier is needed. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_ipv4_g(struct xdp_md *ctx, __u32 off)
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
     * reads off the same base get fused by the compiler and lose it). */
    {
        struct iphdr *ip;
        ret = __bnt_data_ptr(ctx, prefix_len, sizeof(*ip), (void **)&ip);
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
    ret = __bnt_data_ptr(ctx, eproto_off, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(new_ethertype));

    return __bnt_shift_remove_20(ctx, prefix_len);
}
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
#if !BNT_INLINE_ALL
    return __bnt_eth_remove_ipv4_g(eth->__ctx, eth->__off);
#else
    {
        struct __bnt_eth_meta meta;
        __u32 prefix_len;
        __u8 vihl, proto;
        int ret;

        ret = __bnt_eth_meta(eth, &meta);
        if (ret)
            return ret;
        if (meta.proto != ETH_P_IP)
            return BNT_ERR_BAD_PROTO;

        prefix_len = eth->__off + meta.hlen;
        ret = __bnt_read_u8(eth->__ctx, prefix_len, &vihl);     /* version | IHL */
        if (ret)
            return ret;
        if (vihl != 0x45)
            return BNT_ERR_UNSUPPORTED;
        ret = __bnt_read_u8(eth->__ctx, prefix_len + offsetof(struct iphdr, protocol), &proto);
        if (ret)
            return ret;
        if (proto == IPPROTO_IPIP)
            ret = bnt_eth__set_ethertype(eth, ETH_P_IP);
        else if (proto == IPPROTO_IPV6)
            ret = bnt_eth__set_ethertype(eth, ETH_P_IPV6);
        else
            return BNT_ERR_UNSUPPORTED;
        if (ret)
            return ret;
        return __bnt_shift_remove_20(eth->__ctx, prefix_len);
    }
#endif
}

/** Removes a base IPv6 header immediately after Ethernet/VLAN. */
#if !BNT_INLINE_ALL
/* One-global remove: Ethernet/VLAN walk + inner-header reads + EtherType rewrite
 * + shift-remove fused. bpf_xdp_adjust_head runs LAST, so no barrier is needed. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_remove_ipv6_g(struct xdp_md *ctx, __u32 off)
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
    /* one bounds check for the inner header; read both fields from the same
     * pointer so the verifier keeps the range (two separate __bnt_data_ptr
     * reads off the same base get fused by the compiler and lose it). */
    {
        struct ipv6hdr *ip6;
        ret = __bnt_data_ptr(ctx, prefix_len, sizeof(*ip6), (void **)&ip6);
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
    ret = __bnt_data_ptr(ctx, eproto_off, sizeof(__be16), &p);
    if (ret)
        return ret;
    __BNT_PKT_STORE(*(__be16 *)p, bpf_htons(new_ethertype));

    return __bnt_shift_remove_40(ctx, prefix_len);
}
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
#if !BNT_INLINE_ALL
    return __bnt_eth_remove_ipv6_g(eth->__ctx, eth->__off);
#else
    {
        struct __bnt_eth_meta meta;
        __u32 prefix_len;
        __u8 ver, nexthdr;
        int ret;

        ret = __bnt_eth_meta(eth, &meta);
        if (ret)
            return ret;
        if (meta.proto != ETH_P_IPV6)
            return BNT_ERR_BAD_PROTO;

        prefix_len = eth->__off + meta.hlen;
        ret = __bnt_read_u8(eth->__ctx, prefix_len, &ver);
        if (ret)
            return ret;
        if ((ver >> 4) != 6)
            return BNT_ERR_UNSUPPORTED;
        ret = __bnt_read_u8(eth->__ctx, prefix_len + offsetof(struct ipv6hdr, nexthdr), &nexthdr);
        if (ret)
            return ret;
        if (nexthdr == IPPROTO_IPIP)
            ret = bnt_eth__set_ethertype(eth, ETH_P_IP);
        else if (nexthdr == IPPROTO_IPV6)
            ret = bnt_eth__set_ethertype(eth, ETH_P_IPV6);
        else
            return BNT_ERR_UNSUPPORTED;
        if (ret)
            return ret;
        return __bnt_shift_remove_40(eth->__ctx, prefix_len);
    }
#endif
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
 *  Sets the TCP source port without updating the checksum. */
static __always_inline int bnt_tcp__set_source_no_csum(bnt_tcp *tcp, __u16 port)
    { return __bnt_tcp__set_source_raw(tcp, port); }
/** @ingroup bnt_tcp
 *  Sets the TCP destination port without updating the checksum. */
static __always_inline int bnt_tcp__set_dest_no_csum(bnt_tcp *tcp, __u16 port)
    { return __bnt_tcp__set_dest_raw(tcp, port); }
/** @ingroup bnt_tcp
 *  Sets the TCP sequence number without updating the checksum. */
static __always_inline int bnt_tcp__set_seq_no_csum(bnt_tcp *tcp, __u32 seq)
    { return __bnt_tcp__set_seq_raw(tcp, seq); }
/** @ingroup bnt_tcp
 *  Sets the TCP acknowledgment number without updating the checksum. */
static __always_inline int bnt_tcp__set_ack_seq_no_csum(bnt_tcp *tcp, __u32 ack_seq)
    { return __bnt_tcp__set_ack_seq_raw(tcp, ack_seq); }
/** @ingroup bnt_tcp
 *  Sets the TCP flags bitmask without updating the checksum. */
static __always_inline int bnt_tcp__set_flags_no_csum(bnt_tcp *tcp, __u16 flags)
    { return __bnt_tcp__set_flags_raw(tcp, flags); }
/** @ingroup bnt_tcp
 *  Sets the TCP window size without updating the checksum. */
static __always_inline int bnt_tcp__set_window_no_csum(bnt_tcp *tcp, __u16 window)
    { return __bnt_tcp__set_window_raw(tcp, window); }
/** @ingroup bnt_tcp
 *  Sets the TCP urgent pointer without updating the checksum. */
static __always_inline int bnt_tcp__set_urg_ptr_no_csum(bnt_tcp *tcp, __u16 urg_ptr)
    { return __bnt_tcp__set_urg_ptr_raw(tcp, urg_ptr); }
/** @ingroup bnt_tcp
 *  Sets the TCP data offset without updating the checksum. */
static __always_inline int bnt_tcp__set_doff_no_csum(bnt_tcp *tcp, __u32 doff)
    { return __bnt_tcp__set_doff_raw(tcp, doff); }

/** @ingroup bnt_udp
 *  Sets the UDP source port without updating the checksum. */
static __always_inline int bnt_udp__set_source_no_csum(bnt_udp *udp, __u16 port)
    { return __bnt_udp__set_source_raw(udp, port); }
/** @ingroup bnt_udp
 *  Sets the UDP destination port without updating the checksum. */
static __always_inline int bnt_udp__set_dest_no_csum(bnt_udp *udp, __u16 port)
    { return __bnt_udp__set_dest_raw(udp, port); }
/** @ingroup bnt_udp
 *  Sets the UDP length field without updating the checksum. */
static __always_inline int bnt_udp__set_len_no_csum(bnt_udp *udp, __u16 len)
    { return __bnt_udp__set_len_raw(udp, len); }

/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 type without updating the checksum. */
static __always_inline int bnt_icmp4__set_type_no_csum(bnt_icmp4 *icmp, __u8 type)
    { return __bnt_icmp4__set_type_raw(icmp, type); }
/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 code without updating the checksum. */
static __always_inline int bnt_icmp4__set_code_no_csum(bnt_icmp4 *icmp, __u8 code)
    { return __bnt_icmp4__set_code_raw(icmp, code); }
/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 echo identifier without updating the checksum. */
static __always_inline int bnt_icmp4__set_echo_id_no_csum(bnt_icmp4 *icmp, __u16 id)
    { return __bnt_icmp4__set_echo_id_raw(icmp, id); }
/** @ingroup bnt_icmp4
 *  Sets the ICMPv4 echo sequence number without updating the checksum. */
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
 * @retval BNT_OK          on success.
 * @retval BNT_ERR_BAD_ARG @p ip is NULL.
 * @retval BNT_ERR_TRUNC   the header falls outside the packet.
 */
static __always_inline int bnt_ipv4__recompute_csum(bnt_ipv4 *ip)
{
    if (!ip)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL
    return __bnt_ipv4_recompute_csum_g(ip->__ctx, ip->__off);
#else
    return __bnt_ipv4__recompute_csum(ip);
#endif
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
static __always_inline int bnt_tcp__recompute_csum(bnt_tcp *tcp, bnt_ipv4 *ip4)
{
    if (!tcp || !ip4)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL
    return __bnt_tcp_recompute_csum_v4_g(tcp->__ctx, tcp->__off, ip4->__off);
#else
    return __bnt_tcp__recompute_csum_v4(tcp, ip4);
#endif
}
#if BNT_XDP_IPV6_CSUM_SUPPORT
/* XDP IPv6 full recompute is intentionally disabled/commented out: verifier
 * state growth is too costly for this path. TC still exposes recompute_csum6. */
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
#if !BNT_INLINE_ALL
    return __bnt_tcp_recompute_csum_v6_g(tcp->__ctx, tcp->__off, ip6->__off);
#else
    return __bnt_tcp__recompute_csum_v6(tcp, ip6);
#endif
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
static __always_inline int bnt_udp__recompute_csum(bnt_udp *udp, bnt_ipv4 *ip4)
{
    if (!udp || !ip4)
        return BNT_ERR_BAD_ARG;
#if !BNT_INLINE_ALL
    return __bnt_udp_recompute_csum_v4_g(udp->__ctx, udp->__off, ip4->__off);
#else
    return __bnt_udp__recompute_csum_v4(udp, ip4);
#endif
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
#if !BNT_INLINE_ALL
    return __bnt_udp_recompute_csum_v6_g(udp->__ctx, udp->__off, ip6->__off);
#else
    return __bnt_udp__recompute_csum_v6(udp, ip6);
#endif
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
#if !BNT_INLINE_ALL
    return __bnt_icmp4_recompute_csum_g(icmp->__ctx, icmp->__off, icmp_len);
#else
    return __bnt_icmp4__recompute_csum(icmp, icmp_len);
#endif
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
#if !BNT_INLINE_ALL
    return __bnt_icmp6_recompute_csum_g(icmp->__ctx, icmp->__off, ip6->__off, icmp_len);
#else
    return __bnt_icmp6__recompute_csum(icmp, ip6, icmp_len);
#endif
}
#endif



#if !BNT_INLINE_ALL
/* Fixed-size wrapper so a BPF global infers the full segment-buffer size (a bare
 * `struct in6_addr *` arg would be sized as a single 16-byte element). */
struct __bnt_srv6_segs { struct in6_addr s[BNT_SRV6_MAX_SEGS]; };

/* One-global SRH insert: read + shift + write (IPv6 base + SRH + segments) fused
 * into a single subprogram. Like the IPv6 1G insert, each packet write after
 * bpf_xdp_adjust_head needs a barrier on its derived offset (here: the base/SRH
 * write at `off`, and each segment write at `so`). More clang-version-sensitive
 * than the read|shift|write split. */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_ipv6_insert_srh_g(struct xdp_md *ctx, __u32 off,
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
#if BNT_LEGACY_KERNEL || (__clang_major__ >= 16 && __clang_major__ <= 19)
    BNT_PIN(off);     /* clang 16,17,18,19 */
#endif
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
#if BNT_LEGACY_KERNEL || __clang_major__ == 18 || __clang_major__ == 19
        BNT_PIN(so);     /* clang 18,19: per-segment derived offset */
#endif
        ret = __bnt_data_ptr(ctx, so, sizeof(struct in6_addr), (void **)&sp);
        if (ret)
            return ret;
        __BNT_PKT_MEMCPY(sp, &segs->s[rev], sizeof(struct in6_addr));
    }
    return BNT_OK;
}
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

#if !BNT_INLINE_ALL
    {
        /* One global for the whole operation. Copy the (possibly rodata) segment
         * list to a writable stack buffer first (a global's pointer arg is assumed
         * writable). */
        struct __bnt_srv6_segs segbuf;
        __u32 i;

        for (i = 0; i < BNT_SRV6_MAX_SEGS; i++)
            if (i < n_segs)
                __builtin_memcpy(&segbuf.s[i], &segs[i], sizeof(struct in6_addr));

        return __bnt_ipv6_insert_srh_g(ip6->__ctx, ip6->__off, &segbuf, n_segs);
    }
#else
    {
        __u32 srh_size = (__u32)sizeof(struct bnt_sr_hdr) +
                         (__u32)n_segs * (__u32)sizeof(struct in6_addr);
        __u8 orig_nexthdr;
        __u32 srh_off, segs_off, i;
        __u16 old_plen, new_plen;
        int ret;

#if (BNT_INLINE_ALL && !BNT_LEGACY_KERNEL)
        {
            struct ipv6hdr *hdr;
            struct bnt_sr_hdr *srh;

            ret = __bnt_data_ptr(ip6->__ctx, ip6->__off, sizeof(*hdr), (void **)&hdr);
            if (ret)
                return ret;
            if (((*(__u8 *)hdr) >> 4) != 6)
                return BNT_ERR_BAD_PROTO;
            orig_nexthdr = hdr->nexthdr;
            old_plen     = bpf_ntohs(hdr->payload_len);
            if ((__u32)old_plen + srh_size > 0xffffu)
                return BNT_ERR_TRUNC;
            new_plen = (__u16)(old_plen + (__u16)srh_size);

            ret = __bnt_shift_insert(ip6->__ctx,
                                           ip6->__off + (__u32)sizeof(struct ipv6hdr),
                                           srh_size);
            if (ret)
                return ret;

            ret = __bnt_data_ptr(ip6->__ctx, ip6->__off, sizeof(*hdr), (void **)&hdr);
            if (ret)
                return ret;
            hdr->nexthdr     = NEXTHDR_ROUTING;
            hdr->payload_len = bpf_htons(new_plen);

            srh_off = ip6->__off + (__u32)sizeof(struct ipv6hdr);
            ret = __bnt_data_ptr(ip6->__ctx, srh_off, sizeof(*srh), (void **)&srh);
            if (ret)
                return ret;
            __builtin_memset(srh, 0, sizeof(*srh));
            srh->nexthdr       = orig_nexthdr;
            srh->hdrlen        = (__u8)(n_segs * 2u);
            srh->type          = 4;
            srh->segments_left = n_segs - 1;
            srh->first_segment = n_segs - 1;
        }
#else
        {
            struct ipv6hdr hdr = {};

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

            ret = __bnt_shift_insert(ip6->__ctx,
                                           ip6->__off + (__u32)sizeof(struct ipv6hdr),
                                           srh_size);
            if (ret)
                return ret;

            hdr.nexthdr     = NEXTHDR_ROUTING;
            hdr.payload_len = bpf_htons(new_plen);
            ret = __bnt_write(ip6->__ctx, ip6->__off, &hdr, sizeof(hdr));
            if (ret)
                return ret;

            srh_off = ip6->__off + (__u32)sizeof(struct ipv6hdr);
            {
                struct bnt_sr_hdr srh = {};
                srh.nexthdr       = orig_nexthdr;
                srh.hdrlen        = (__u8)(n_segs * 2u);
                srh.type          = 4;
                srh.segments_left = n_segs - 1;
                srh.first_segment = n_segs - 1;
                ret = __bnt_write(ip6->__ctx, srh_off, &srh, sizeof(srh));
                if (ret)
                    return ret;
            }
        }
#endif

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
            rev &= (__u8)(BNT_SRV6_MAX_SEGS - 1u);  /* verifier bound, see _g path */
            ret = __bnt_write(ip6->__ctx,
                               segs_off + i * (__u32)sizeof(struct in6_addr),
                               &segs[rev], sizeof(struct in6_addr));
            if (ret)
                return ret;
        }
        return BNT_OK;
    }
#endif
}

/** Pushes one MPLS label after Ethernet/VLAN; BOS is set automatically. */
#if !BNT_INLINE_ALL
/* One-global insert: Ethernet/VLAN walk (also yields the EtherType for the BOS
 * bit) + shift + LSE/ethertype write, fused. Barrier on prefix_len for the
 * post-adjust write (see __bnt_eth_insert_ipv6_g). */
__attribute__((noinline, weak, nonnull(1)))
int __bnt_eth_insert_mpls_g(struct xdp_md *ctx, __u32 off, __u32 label, __u8 tc, __u8 ttl)
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

#if BNT_LEGACY_KERNEL || (__clang_major__ >= 17 && __clang_major__ <= 19) || __clang_major__ == 21
    BNT_PIN(prefix_len);     /* clang 17,18,19,21 */
#endif
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
#endif

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
#if !BNT_INLINE_ALL
    return __bnt_eth_insert_mpls_g(eth->__ctx, eth->__off, label, tc, ttl);
#else
    {
        struct __bnt_eth_meta meta;
        __be32 lse;
        bool bos;
        __u32 prefix_len;
        int ret;

        ret = __bnt_eth_meta(eth, &meta);
        if (ret)
            return ret;

        /* BOS=1 when the existing EtherType is not MPLS (this label is the bottom). */
        bos = (meta.proto != ETH_P_MPLS_UC && meta.proto != ETH_P_MPLS_MC);
        lse = bpf_htonl((label << 12) |
                         ((__u32)(tc & 0x7u) << 9) |
                         (bos ? (1u << 8) : 0u) |
                         (__u32)ttl);

        prefix_len = eth->__off + meta.hlen;
        ret = __bnt_shift_insert_4(eth->__ctx, prefix_len);
        if (ret)
            return ret;

        ret = bnt_eth__set_ethertype(eth, ETH_P_MPLS_UC);
        if (ret)
            return ret;
        return __bnt_write(eth->__ctx, prefix_len, &lse, sizeof(lse));
    }
#endif
}

#endif /* BNT_XDP_H */
