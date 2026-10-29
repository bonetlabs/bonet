// Load one tests/api program and run it on every case read from stdin.
//
// usage: run_api OBJ [LOG] < CASES
// Each input line is "PACKET_HEX IO_HEX" (IO: struct bnt_api_io before the
// call). Prints one line per case, "OK <io after hex> <packet after hex>" or
// "RUNFAIL <errno>", or a single "LOADFAIL <last verifier line>". On a failed
// load, the whole verifier log goes to LOG when given.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "api_io.h"

static char logbuf[1 << 24];  /* kernels before 6.4 fail the load when the log fills up */
static char line[1 << 16];

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

static size_t unhex(const char *s, size_t len, unsigned char *out, size_t max)
{
    size_t n = len / 2;

    if (n > max)
        n = max;
    for (size_t i = 0; i < n; i++)
        sscanf(s + 2 * i, "%2hhx", &out[i]);
    return n;
}

int main(int argc, char **argv)
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    unsigned char pkt[4096], pout[4096];
    struct bnt_api_io io;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map, *data = NULL;
    int key = 0;

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s OBJ [LOG] < CASES\n", argv[0]);
        return 2;
    }
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
        FILE *f = argc == 3 ? fopen(argv[2], "w") : NULL;
        char *last;

        if (f) {
            fputs(logbuf, f);
            fclose(f);
        }
        last = strrchr(logbuf, '\n');
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
    if (!data) {
        printf("LOADFAIL no .data map\n");
        return 0;
    }

    while (fgets(line, sizeof(line), stdin)) {
        char *sp = strchr(line, ' ');
        size_t plen;

        if (!sp)
            continue;
        plen = unhex(line, sp - line, pkt, sizeof(pkt));
        memset(&io, 0, sizeof(io));
        unhex(sp + 1, strcspn(sp + 1, "\n"), (unsigned char *)&io, sizeof(io));
        if (bpf_map__update_elem(data, &key, sizeof(key), &io, sizeof(io), 0)) {
            printf("MAPFAIL %d\n", errno);
            continue;
        }
        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt, .data_size_in = plen,
                    .data_out = pout, .data_size_out = sizeof(pout), .repeat = 1);
        if (bpf_prog_test_run_opts(bpf_program__fd(prog), &opts)) {
            printf("RUNFAIL %d\n", errno);
            continue;
        }
        if (bpf_map__lookup_elem(data, &key, sizeof(key), &io, sizeof(io), 0)) {
            printf("MAPFAIL %d\n", errno);
            continue;
        }
        printf("OK ");
        hex((unsigned char *)&io, sizeof(io));
        printf(" ");
        hex(pout, opts.data_size_out);
        printf("\n");
        fflush(stdout);
    }
    bpf_object__close(obj);
    return 0;
}
