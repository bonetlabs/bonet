#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bnt_debug.h"

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
    (void)signo;
    exiting = 1;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int bpf_object_path(const char *prog, char *buf, size_t len)
{
    int n = snprintf(buf, len, "%s.bpf.o", prog);

    return n < 0 || (size_t)n >= len ? -1 : 0;
}

static int load_and_attach(const char *ifname, const char *obj_path,
                           struct bpf_object **obj_out, int *ifindex_out)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    long open_err;
    int ifindex;
    int err;

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "unknown interface %s\n", ifname);
        return -1;
    }

    obj = bpf_object__open_file(obj_path, NULL);
    open_err = libbpf_get_error(obj);
    if (open_err) {
        fprintf(stderr, "open %s failed: %s\n", obj_path, strerror((int)-open_err));
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "load %s failed: %s\n", obj_path, strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "no BPF program found in %s\n", obj_path);
        bpf_object__close(obj);
        return -1;
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(prog),
                         XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "attach to %s failed: %s\n", ifname, strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    *obj_out = obj;
    *ifindex_out = ifindex;
    return 0;
}

static int map_fd(struct bpf_object *obj, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);

    if (!map) {
        fprintf(stderr, "map %s not found\n", name);
        return -1;
    }
    return bpf_map__fd(map);
}

static int on_eth(void *ctx, void *data, size_t size)
{
    const struct bnt_dbg_eth_event *e = data;

    (void)ctx;
    if (size < sizeof(*e))
        return 0;

    printf("eth src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x ethertype=0x%04x vlans=%u\n",
           e->src[0], e->src[1], e->src[2], e->src[3], e->src[4], e->src[5],
           e->dst[0], e->dst[1], e->dst[2], e->dst[3], e->dst[4], e->dst[5],
           e->ethertype, e->vlan_depth);
    return 0;
}

static int on_vlan(void *ctx, void *data, size_t size)
{
    const struct bnt_dbg_vlan_event *e = data;

    (void)ctx;
    if (size < sizeof(*e))
        return 0;

    printf("vlan idx=%u vid=%u pcp=%u encap=0x%04x\n",
           e->index, e->vid, e->pcp, e->encapsulated_proto);
    return 0;
}

static int on_ipv4(void *ctx, void *data, size_t size)
{
    const struct bnt_dbg_ipv4_event *e = data;
    const unsigned char *s = (const unsigned char *)&e->saddr;
    const unsigned char *d = (const unsigned char *)&e->daddr;

    (void)ctx;
    if (size < sizeof(*e))
        return 0;

    printf("ipv4 %u.%u.%u.%u -> %u.%u.%u.%u ttl=%u proto=%u len=%u\n",
           s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3],
           e->ttl, e->protocol, e->total_len);
    return 0;
}

static int on_tcp(void *ctx, void *data, size_t size)
{
    const struct bnt_dbg_tcp_event *e = data;

    (void)ctx;
    if (size < sizeof(*e))
        return 0;

    printf("tcp %u -> %u flags=0x%03x seq=%u ack=%u\n",
           e->source, e->dest, e->flags, e->seq, e->ack_seq);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct ring_buffer *rb = NULL;
    char obj_path[512];
    int ifindex = 0;
    int eth_fd;
    int vlan_fd;
    int ipv4_fd;
    int tcp_fd;
    int err = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s IFACE\n", argv[0]);
        return 2;
    }
    if (bpf_object_path(argv[0], obj_path, sizeof(obj_path))) {
        fprintf(stderr, "BPF object path is too long\n");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    bump_memlock_rlimit();

    if (load_and_attach(argv[1], obj_path, &obj, &ifindex))
        return 1;

    eth_fd = map_fd(obj, "bnt_debug_eth_events");
    vlan_fd = map_fd(obj, "bnt_debug_vlan_events");
    ipv4_fd = map_fd(obj, "bnt_debug_ipv4_events");
    tcp_fd = map_fd(obj, "bnt_debug_tcp_events");
    if (eth_fd < 0 || vlan_fd < 0 || ipv4_fd < 0 || tcp_fd < 0)
        goto out;

    rb = ring_buffer__new(eth_fd, on_eth, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }
    if (ring_buffer__add(rb, vlan_fd, on_vlan, NULL) ||
        ring_buffer__add(rb, ipv4_fd, on_ipv4, NULL) ||
        ring_buffer__add(rb, tcp_fd, on_tcp, NULL)) {
        fprintf(stderr, "ring_buffer__add failed: %s\n", strerror(errno));
        goto out;
    }

    printf("attached; polling ring buffers, Ctrl-C to stop\n");
    while (!exiting)
        ring_buffer__poll(rb, 250);
    err = 0;

out:
    ring_buffer__free(rb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    return err;
}
