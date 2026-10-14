// Run one case program with BPF_PROG_TEST_RUN and print what the global did.
//
// usage: run_case OBJ PACKET_HEX
// Output, one line: "OK <global ret> <out buffer hex> <packet after hex>",
// or "LOADFAIL <verifier line>" / "RUNFAIL <errno>" / "MAPFAIL".
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

struct bnt_case_res {
    unsigned char out[256];
    int ret;
} __attribute__((aligned(8)));

static char logbuf[1 << 20];

static int quiet(enum libbpf_print_level l, const char *f, va_list a)
{
    (void)l; (void)f; (void)a;
    return 0;
}

static void hex(const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

int main(int argc, char **argv)
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    unsigned char pkt[4096], pout[4096];
    struct bnt_case_res res;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map, *data = NULL;
    size_t plen;
    int key = 0;

    if (argc != 3) {
        fprintf(stderr, "usage: %s OBJ PACKET_HEX\n", argv[0]);
        return 2;
    }
    plen = strlen(argv[2]) / 2;
    if (plen > sizeof(pkt))
        return 2;
    for (size_t i = 0; i < plen; i++)
        sscanf(argv[2] + 2 * i, "%2hhx", &pkt[i]);

    setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_print(quiet);
    obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        printf("LOADFAIL cannot open %s\n", argv[1]);
        return 0;
    }
    prog = bpf_object__find_program_by_name(obj, "run");
    bpf_program__set_log_buf(prog, logbuf, sizeof(logbuf));
    bpf_program__set_log_level(prog, 1);
    if (bpf_object__load(obj)) {
        char *last = strrchr(logbuf, '\n');
        while (last && last > logbuf && last[1] == 0) {
            *last = 0;
            last = strrchr(logbuf, '\n');
        }
        printf("LOADFAIL %s\n", last ? last + 1 : logbuf);
        return 0;
    }
    bpf_object__for_each_map(map, obj)
        if (strstr(bpf_map__name(map), ".data"))
            data = map;

    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt, .data_size_in = plen,
                .data_out = pout, .data_size_out = sizeof(pout), .repeat = 1);
    if (bpf_prog_test_run_opts(bpf_program__fd(prog), &opts)) {
        printf("RUNFAIL %d\n", errno);
        return 0;
    }
    if (!data || bpf_map__lookup_elem(data, &key, sizeof(key), &res, sizeof(res), 0)) {
        printf("MAPFAIL\n");
        return 0;
    }
    printf("OK %d ", res.ret);
    hex(res.out, sizeof(res.out));
    printf(" ");
    hex(pout, opts.data_size_out);
    printf("\n");
    bpf_object__close(obj);
    return 0;
}
