// Attached to v1 by vm_net.sh: counts and drops what bench_prog sends out of
// v0 with XDP_TX or XDP_REDIRECT, so that the veth accepts those frames and
// bench_workloads.py can check that every packet came out.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} seen SEC(".maps");

SEC("xdp")
int sink(struct xdp_md *ctx)
{
    __u32 k = 0;
    __u64 *n = bpf_map_lookup_elem(&seen, &k);

    (void)ctx;
    if (n)
        __sync_fetch_and_add(n, 1);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
