/* SPDX-License-Identifier: MIT */
#ifndef BNT_RW_H
#define BNT_RW_H

/*
 * bnt_rw.h - typed read/write helpers and incremental checksum updaters.
 *
 * Included by bnt_xdp.h and the TC backend headers after they define:
 *   - BNT_CTX_TYPE
 *   - __bnt_read(ctx, off, dst, len)
 *   - __bnt_write(ctx, off, src, len)
 *   - bpf_csum_diff
 *   - bpf_htons / bpf_ntohs
 *   - BNT_OK / BNT_ERR_*
 *
 * Output convention: typed read helpers zero a non-NULL destination before
 * reading. Callers may safely inspect output variables on error paths, which
 * keeps BPF verifier state initialized even when a read fails early.
 */

/*
 * Packet access through a pointer at a runtime offset.
 *
 * Inside a global the packet offset is only a bounded scalar, so the verifier
 * cannot prove a multi-byte packet access aligned. Kernels that enforce
 * alignment reject such an access: those without
 * CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS (riscv, loongarch and mips in their
 * default configurations, sparc64) and any program loaded with
 * BPF_F_STRICT_ALIGNMENT. The globals route every multi-byte packet access
 * through the macros below. By default they expand to the plain access;
 * BNT_STRICT_ALIGN=1 turns each one into a byte-wise copy. bnt_xdp.h turns it
 * on automatically from the __TARGET_ARCH_* macro of the architectures above.
 *
 *   __BNT_PKT_LOAD(lv)          value of the packet lvalue lv
 *   __BNT_PKT_STORE(lv, v)      lv = v
 *   __BNT_PKT_ASSIGN(dst, src)  dst = src, either side in packet memory
 *   __BNT_PKT_MEMCPY(d, s, n)   memcpy, either side in packet memory
 *   __BNT_PKT_MEMSET0(p, n)     zero n bytes of packet memory
 */
#ifndef BNT_ASM_GLOBALS
#define BNT_ASM_GLOBALS 0    /* TC backends have no globals */
#endif
#ifndef BNT_STRICT_ALIGN
#define BNT_STRICT_ALIGN 0   /* TC backends: packet access goes through helpers */
#endif

#if BNT_STRICT_ALIGN
/* Every byte goes through a volatile pointer: clang may neither widen nor merge
 * volatile accesses, so each stays a single-byte access. A plain byte-wise
 * memcpy is not enough: clang 22 recombines it into one misaligned load. */
static __always_inline __u64 __bnt_load_bytes(const void *p, __u32 n)
{
    const volatile __u8 *b = (const volatile __u8 *)p;
    __u64 v = 0;
    __u32 i;

#pragma unroll
    for (i = 0; i < n; i++)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        v |= (__u64)b[i] << (8 * i);
#else
        v = (v << 8) | b[i];
#endif
    return v;
}

static __always_inline void __bnt_store_bytes(void *p, __u64 v, __u32 n)
{
    volatile __u8 *b = (volatile __u8 *)p;
    __u32 i;

#pragma unroll
    for (i = 0; i < n; i++)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        b[i] = (__u8)(v >> (8 * i));
#else
        b[i] = (__u8)(v >> (8 * (n - 1 - i)));
#endif
}

static __always_inline void __bnt_memcpy_bytes(void *dst, const void *src, __u32 n)
{
    volatile __u8 *d = (volatile __u8 *)dst;
    const volatile __u8 *s = (const volatile __u8 *)src;
    __u32 i;

#pragma unroll
    for (i = 0; i < n; i++)
        d[i] = s[i];
}

static __always_inline void __bnt_memset0_bytes(void *p, __u32 n)
{
    volatile __u8 *b = (volatile __u8 *)p;
    __u32 i;

#pragma unroll
    for (i = 0; i < n; i++)
        b[i] = 0;
}

#define __BNT_PKT_LOAD(lv)                                                     \
    ((__typeof__(lv))__bnt_load_bytes(&(lv), sizeof(lv)))
#define __BNT_PKT_STORE(lv, val)                                               \
    __bnt_store_bytes(&(lv), (__u64)(val), sizeof(lv))
#define __BNT_PKT_ASSIGN(dst, src)                                             \
    __bnt_memcpy_bytes(&(dst), &(src), sizeof(dst))
#define __BNT_PKT_MEMCPY(d, s, n)  __bnt_memcpy_bytes((d), (s), (n))
#define __BNT_PKT_MEMSET0(p, n)    __bnt_memset0_bytes((p), (n))
#else
#define __BNT_PKT_LOAD(lv)          (lv)
#define __BNT_PKT_STORE(lv, val)    ((lv) = (val))
#define __BNT_PKT_ASSIGN(dst, src)  ((dst) = (src))
#define __BNT_PKT_MEMCPY(d, s, n)   __builtin_memcpy((d), (s), (n))
#define __BNT_PKT_MEMSET0(p, n)     __builtin_memset((p), 0, (n))
#endif

static __always_inline int __bnt_read_u8(BNT_CTX_TYPE *ctx, __u32 off, __u8 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    return __bnt_read(ctx, off, out, sizeof(*out));
}

static __always_inline int __bnt_read_be16(BNT_CTX_TYPE *ctx, __u32 off, __be16 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    return __bnt_read(ctx, off, out, sizeof(*out));
}

static __always_inline int __bnt_read_be32(BNT_CTX_TYPE *ctx, __u32 off, __be32 *out)
{
    if (!out)
        return BNT_ERR_BAD_ARG;
    *out = 0;
    return __bnt_read(ctx, off, out, sizeof(*out));
}

static __always_inline int __bnt_write_u8(BNT_CTX_TYPE *ctx, __u32 off, __u8 v)
{
    return __bnt_write(ctx, off, &v, sizeof(v));
}

static __always_inline int __bnt_write_be16(BNT_CTX_TYPE *ctx, __u32 off, __be16 v)
{
    return __bnt_write(ctx, off, &v, sizeof(v));
}

static __always_inline int __bnt_write_be32(BNT_CTX_TYPE *ctx, __u32 off, __be32 v)
{
    return __bnt_write(ctx, off, &v, sizeof(v));
}

#define __bnt_header_set(h, ctx, off) \
    (!(h) ? BNT_ERR_BAD_ARG : ((h)->__ctx = (ctx), (h)->__off = (off), BNT_OK))


#endif /* BNT_RW_H */
