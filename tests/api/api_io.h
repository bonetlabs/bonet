/* The data a tests/api program shares with run_api and check.py (see
 * gen_programs.py). The layout is mirrored by IO in api.py. */
#ifndef BNT_API_IO_H
#define BNT_API_IO_H

struct bnt_api_io {
    __u64 arg[4];        /* scalar arguments, by parameter index */
    __u32 off[4];        /* view offsets, by parameter index */
    __u32 nullmask;      /* bit k: parameter k is NULL */
    int ret;             /* the API's return value */
    __u32 vout[4][2];    /* each view after the call: offset, ctx set */
    __u8 buf[4][96];     /* pointer arguments, by parameter index */
} __attribute__((aligned(8)));

#endif
