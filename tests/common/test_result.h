#ifndef BNT_TEST_RESULT_H
#define BNT_TEST_RESULT_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define BNT_TEST_RESULT_MAGIC 0x50545854u
#define BNT_TEST_STATUS_OK    1
#define BNT_TEST_STATUS_FAIL  2

struct bnt_test_result_value {
    __u32 magic;
    __s32 status;
    __u64 seen;
    __u64 expected;
    __u64 detail[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bnt_test_result_value);
} bnt_test_result SEC(".maps");

static __always_inline int bnt_test_report(__s32 status, __u64 seen, __u64 expected)
{
    __u32 key = 0;
    struct bnt_test_result_value value = {};

    value.magic = BNT_TEST_RESULT_MAGIC;
    value.status = status;
    value.seen = seen;
    value.expected = expected;
    return bpf_map_update_elem(&bnt_test_result, &key, &value, BPF_ANY);
}

static __always_inline int bnt_test_ok(__u64 seen, __u64 expected)
{
    return bnt_test_report(BNT_TEST_STATUS_OK, seen, expected);
}

static __always_inline int bnt_test_fail(__u64 seen, __u64 expected)
{
    return bnt_test_report(BNT_TEST_STATUS_FAIL, seen, expected);
}

static __always_inline int bnt_test_fail_detail(__u64 seen, __u64 expected,
                                                  __u64 d0, __u64 d1, __u64 d2)
{
    __u32 key = 0;
    struct bnt_test_result_value value = {};
    value.magic    = BNT_TEST_RESULT_MAGIC;
    value.status   = BNT_TEST_STATUS_FAIL;
    value.seen     = seen;
    value.expected = expected;
    value.detail[0] = d0;
    value.detail[1] = d1;
    value.detail[2] = d2;
    return bpf_map_update_elem(&bnt_test_result, &key, &value, BPF_ANY);
}

#endif
