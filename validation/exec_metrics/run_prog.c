// Run one XDP program on one packet with BPF_PROG_TEST_RUN.
//
// usage: run_prog OBJ PACKET_HEX [MAP KEY_HEX VALUE_HEX]...
//
// Loads the object, puts the given entries in its maps, runs the program once
// and prints "OK <action> <packet out hex>", then "MAP <map> <key> <value>"
// for each entry given, as it is after the run. Needs root.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

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
    struct bpf_object *obj;
    struct bpf_program *prog;
    int len;

    if (argc < 3 || (argc - 3) % 3) {
        fprintf(stderr, "usage: %s OBJ PACKET_HEX [MAP KEY_HEX VALUE_HEX]...\n", argv[0]);
        return 2;
    }
    setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_print(quiet);
    obj = bpf_object__open_file(argv[1], NULL);
    if (!obj || bpf_object__load(obj)) {
        printf("LOADFAIL\n");
        return 1;
    }
    for (int i = 3; i < argc; i += 3) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, argv[i]);
        int kl = unhex(argv[i + 1], key, sizeof(key)), vl = unhex(argv[i + 2], val, sizeof(val));

        if (!m || bpf_map__update_elem(m, key, kl, val, vl, BPF_ANY)) {
            printf("MAPFAIL %s\n", argv[i]);
            return 1;
        }
    }
    prog = bpf_object__next_program(obj, NULL);
    len = unhex(argv[2], in, sizeof(in));
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = in, .data_size_in = len, .data_out = out,
                .data_size_out = sizeof(out), .repeat = 1);
    if (bpf_prog_test_run_opts(bpf_program__fd(prog), &opts)) {
        printf("RUNFAIL\n");
        return 1;
    }
    printf("OK %u ", opts.retval);
    for (__u32 i = 0; i < opts.data_size_out; i++)
        printf("%02x", out[i]);
    printf("\n");
    for (int i = 3; i < argc; i += 3) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, argv[i]);
        int kl = unhex(argv[i + 1], key, sizeof(key)), vl = bpf_map__value_size(m);

        if (bpf_map__lookup_elem(m, key, kl, val, vl, 0))
            continue;
        printf("MAP %s %s ", argv[i], argv[i + 1]);
        for (int k = 0; k < vl; k++)
            printf("%02x", val[k]);
        printf("\n");
    }
    bpf_object__close(obj);
    return 0;
}
