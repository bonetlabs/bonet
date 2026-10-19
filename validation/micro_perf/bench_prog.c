// Time one XDP program on one packet with BPF_PROG_TEST_RUN.
//
// usage: bench_prog [-n REPEAT] [-r ROUNDS] [-i IFINDEX] [-w WRAP_OBJ] OBJ PACKET_HEX [MAP KEY_HEX VALUE_HEX]...
//
// With -w (build/bench_wrap.o) the run goes through that front program, which
// copies the original packet back before tail calling OBJ: live frames reuse
// the pages as the last run left them, so without it a program that rewrites
// the packet would be timed on its own output.
//
// Loads the object and puts the given entries in its maps. Then:
// - one plain run, with the packet coming in on IFINDEX, prints
//   "CHECK <action> <packet out hex>": compare it with the expected result to
//   be sure the packet takes the path meant to be measured;
// - ROUNDS runs of REPEAT iterations with BPF_F_TEST_XDP_LIVE_FRAMES, each
//   printing "ROUND <ns per packet>". In this mode every iteration starts from
//   the original packet and the action is carried out (XDP_TX and
//   XDP_REDIRECT send the packet out), so a program that rewrites or grows the
//   packet is timed on the path it takes for a fresh packet.
// Needs root, and for XDP_TX or XDP_REDIRECT a device that accepts XDP frames
// (../exec_metrics/vm_net.sh with build/sink.o).
#include <bpf/bpf.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int quiet(enum libbpf_print_level l, const char *f, va_list a)
{
    (void)l; (void)f; (void)a;
    return 0;
}

static int unhex(const char *s, unsigned char *out, int max)
{
    int n = strlen(s) / 2;

    if (n > max)
        return -1;
    for (int i = 0; i < n; i++)
        sscanf(s + 2 * i, "%2hhx", &out[i]);
    return n;
}

int main(int argc, char **argv)
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    static unsigned char in[4096], out[4096 + 512], key[256], val[4096];
    struct xdp_md ctx = {};
    struct bpf_object *obj;
    struct bpf_program *prog;
    int repeat = 1000000, rounds = 5, opt, len, fd;
    const char *wrap = NULL;

    while ((opt = getopt(argc, argv, "n:r:i:w:")) != -1) {
        if (opt == 'n')
            repeat = atoi(optarg);
        else if (opt == 'r')
            rounds = atoi(optarg);
        else if (opt == 'i')
            ctx.ingress_ifindex = atoi(optarg);
        else if (opt == 'w')
            wrap = optarg;
    }
    argc -= optind;
    argv += optind;
    if (argc < 2 || (argc - 2) % 3) {
        fprintf(stderr, "usage: bench_prog [-n REPEAT] [-r ROUNDS] [-i IFINDEX] [-w WRAP_OBJ] OBJ PACKET_HEX [MAP KEY VALUE]...\n");
        return 2;
    }
    setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_print(quiet);
    obj = bpf_object__open_file(argv[0], NULL);
    if (!obj || bpf_object__load(obj)) {
        printf("LOADFAIL\n");
        return 1;
    }
    for (int i = 2; i < argc; i += 3) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, argv[i]);
        int kl = unhex(argv[i + 1], key, sizeof(key)), vl = unhex(argv[i + 2], val, sizeof(val));

        if (!m || bpf_map__update_elem(m, key, kl, val, vl, BPF_ANY)) {
            printf("MAPFAIL %s\n", argv[i]);
            return 1;
        }
    }
    prog = bpf_object__next_program(obj, NULL);
    fd = bpf_program__fd(prog);
    len = unhex(argv[1], in, sizeof(in));
    ctx.data_end = len;  /* the kernel wants the packet length here when a context is given */
    if (wrap) {
        static struct { __u32 len; unsigned char data[256]; } pkt;
        struct bpf_object *w = bpf_object__open_file(wrap, NULL);
        __u32 k = 0;
        int pfd;

        if (!w || bpf_object__load(w) || len > (int)sizeof(pkt.data)) {
            printf("WRAPFAIL\n");
            return 1;
        }
        pkt.len = len;
        memcpy(pkt.data, in, len);
        pfd = bpf_program__fd(prog);
        if (bpf_map__update_elem(bpf_object__find_map_by_name(w, "orig"), &k, 4, &pkt, sizeof(pkt), BPF_ANY) ||
            bpf_map__update_elem(bpf_object__find_map_by_name(w, "target"), &k, 4, &pfd, 4, BPF_ANY)) {
            printf("WRAPFAIL\n");
            return 1;
        }
        fd = bpf_program__fd(bpf_object__next_program(w, NULL));
    }

    LIBBPF_OPTS(bpf_test_run_opts, check, .data_in = in, .data_size_in = len, .data_out = out,
                .data_size_out = sizeof(out), .ctx_in = &ctx, .ctx_size_in = sizeof(ctx), .repeat = 1);
    if (bpf_prog_test_run_opts(fd, &check)) {
        printf("CHECKFAIL %s\n", strerror(errno));
        return 1;
    }
    printf("CHECK %u ", check.retval);
    for (__u32 i = 0; i < check.data_size_out; i++)
        printf("%02x", out[i]);
    printf("\n");

    for (int r = 0; r < rounds; r++) {
        LIBBPF_OPTS(bpf_test_run_opts, live, .data_in = in, .data_size_in = len, .ctx_in = &ctx,
                    .ctx_size_in = sizeof(ctx), .repeat = repeat, .flags = BPF_F_TEST_XDP_LIVE_FRAMES);
        if (bpf_prog_test_run_opts(fd, &live)) {
            printf("RUNFAIL %s\n", strerror(errno));
            return 1;
        }
        printf("ROUND %u\n", live.duration);
    }
    bpf_object__close(obj);
    return 0;
}
