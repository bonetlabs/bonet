// Front program for bench_prog -w: put back the original packet, then tail
// call the program being timed.
//
// With BPF_F_TEST_XDP_LIVE_FRAMES the kernel resets the packet pointers before
// each iteration but reuses the pages as the previous run left them, so a
// program that rewrites the packet (a TTL, an address) would see its own
// output the next time round. bench_prog stores the packet in orig; this
// program copies it back over the frame before every run.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_PKT 256

struct pkt {
    __u32 len;
    __u8 data[MAX_PKT];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt);
} orig SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target SEC(".maps");

SEC("xdp")
int bench_wrap(struct xdp_md *ctx)
{
    __u32 k = 0, len;
    struct pkt *p = bpf_map_lookup_elem(&orig, &k);

    if (!p)
        return XDP_ABORTED;
    len = p->len;
    if (len < 1 || len > MAX_PKT)
        return XDP_ABORTED;
    if (bpf_xdp_store_bytes(ctx, 0, p->data, len))
        return XDP_ABORTED;
    bpf_tail_call(ctx, &target, 0);
    return XDP_ABORTED;
}

char LICENSE[] SEC("license") = "GPL";
