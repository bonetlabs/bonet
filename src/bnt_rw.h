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
    (!(h) || !(ctx) ? BNT_ERR_BAD_ARG : ((h)->__ctx = (ctx), (h)->__off = (off), BNT_OK))


#endif /* BNT_RW_H */
