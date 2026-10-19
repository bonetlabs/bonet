// Reference for bench_workloads.py: a program that only takes the action of a
// case, built once per action (REF_DROP, REF_PASS, REF_TX, REF_REDIRECT).
// Subtracting its time leaves the cost of the workload itself.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int ref(struct xdp_md *ctx)
{
#if defined(REF_REDIRECT)
    return bpf_redirect(ctx->ingress_ifindex, 0);
#elif defined(REF_TX)
    return XDP_TX;
#elif defined(REF_PASS)
    return XDP_PASS;
#else
    return XDP_DROP;
#endif
}

char LICENSE[] SEC("license") = "GPL";
