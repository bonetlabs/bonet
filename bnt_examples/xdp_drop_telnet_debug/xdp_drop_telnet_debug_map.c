#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

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

static int seen(const struct bnt_dbg_event_meta *meta)
{
    return meta->packet_len != 0;
}

static void print_latest(int eth_fd, int vlan_fd, int ipv4_fd, int tcp_fd)
{
    struct bnt_dbg_eth_event eth = {};
    struct bnt_dbg_vlan_event vlan = {};
    struct bnt_dbg_ipv4_event ip4 = {};
    struct bnt_dbg_tcp_event tcp = {};
    __u32 key = 0;

    if (!bpf_map_lookup_elem(eth_fd, &key, &eth) && seen(&eth.meta)) {
        printf("eth ethertype=0x%04x vlans=%u pkt_len=%u\n",
               eth.ethertype, eth.vlan_depth, eth.meta.packet_len);
    }

    if (!bpf_map_lookup_elem(vlan_fd, &key, &vlan) && seen(&vlan.meta)) {
        printf("vlan idx=%u vid=%u encap=0x%04x\n",
               vlan.index, vlan.vid, vlan.encapsulated_proto);
    }

    if (!bpf_map_lookup_elem(ipv4_fd, &key, &ip4) && seen(&ip4.meta)) {
        const unsigned char *s = (const unsigned char *)&ip4.saddr;
        const unsigned char *d = (const unsigned char *)&ip4.daddr;

        printf("ipv4 %u.%u.%u.%u -> %u.%u.%u.%u ttl=%u len=%u\n",
               s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3],
               ip4.ttl, ip4.total_len);
    }

    if (!bpf_map_lookup_elem(tcp_fd, &key, &tcp) && seen(&tcp.meta)) {
        printf("tcp %u -> %u flags=0x%03x seq=%u ack=%u\n",
               tcp.source, tcp.dest, tcp.flags, tcp.seq, tcp.ack_seq);
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    char obj_path[512];
    int ifindex = 0;
    int eth_fd;
    int vlan_fd;
    int ipv4_fd;
    int tcp_fd;

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

    eth_fd = map_fd(obj, "bnt_debug_eth_latest");
    vlan_fd = map_fd(obj, "bnt_debug_vlan_latest");
    ipv4_fd = map_fd(obj, "bnt_debug_ipv4_latest");
    tcp_fd = map_fd(obj, "bnt_debug_tcp_latest");
    if (eth_fd < 0 || vlan_fd < 0 || ipv4_fd < 0 || tcp_fd < 0) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        bpf_object__close(obj);
        return 1;
    }

    printf("attached; polling latest maps, Ctrl-C to stop\n");
    while (!exiting) {
        print_latest(eth_fd, vlan_fd, ipv4_fd, tcp_fd);
        sleep(1);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    return 0;
}
