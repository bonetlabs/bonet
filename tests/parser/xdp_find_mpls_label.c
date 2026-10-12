#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bnt_xdp.h"
#include "test_result.h"

#define MPLS_LABEL_EXPECTED 100

SEC("xdp")
int xdp_find_mpls_label(struct xdp_md *ctx)
{
    bnt_mpls mpls;
    __u32 label = 0;
    int ret;

    ret = bnt_ctx__find_mpls(ctx, &mpls);
    if (ret)
        return XDP_PASS;
    ret = bnt_mpls__get_label(&mpls, &label);
    if (ret || label != MPLS_LABEL_EXPECTED)
        goto fail;

    bnt_test_ok(label, MPLS_LABEL_EXPECTED);
    return XDP_DROP;

fail:
    bnt_test_fail(label, MPLS_LABEL_EXPECTED);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
