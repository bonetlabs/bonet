// Reference for bench_globals.py: a case program of tests/units without the
// call, storing the result as they do and returning XDP_DROP.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __u8 out[256];
    int ret;
} __attribute__((aligned(8))) bnt_res = { .ret = -999 };

SEC("xdp")
int run(struct xdp_md *ctx)
{
    (void)ctx;
    bnt_res.ret = 0;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
