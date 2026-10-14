// Load every program of a BPF object on its own and report the verifier result.
//
// usage: load_each [--strict] OBJ...
//   --strict  load with BPF_F_STRICT_ALIGNMENT, as on kernels that enforce
//             alignment
// Prints one line per program; exits with 1 if any program fails to load.
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#define MAX_PROGS 512

static char logbuf[1 << 22];

static int quiet(enum libbpf_print_level l, const char *f, va_list a)
{
    (void)l; (void)f; (void)a;
    return 0;
}

/* Last line of the verifier log that is not a statistics line. */
static void last_error(char *out, size_t n)
{
    char *end = logbuf + strlen(logbuf), *p;

    for (;;) {
        while (end > logbuf && (end[-1] == '\n' || end[-1] == ' '))
            end--;
        p = end;
        while (p > logbuf && p[-1] != '\n')
            p--;
        if (p > logbuf && (!strncmp(p, "processed", 9) || !strncmp(p, "stack depth", 11) ||
                           !strncmp(p, "verification time", 17))) {
            end = p;
            continue;
        }
        break;
    }
    snprintf(out, n, "%.*s", (int)(end - p), p);
}

static int load_one(const char *path, const char *name, int strict)
{
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    struct bpf_program *prog, *target = NULL;
    char err[256];
    int ret;

    if (!obj) {
        printf("FAIL %s %s: cannot open: %s\n", path, name, strerror(errno));
        return 1;
    }
    bpf_object__for_each_program(prog, obj) {
        int me = strcmp(bpf_program__name(prog), name) == 0;

        bpf_program__set_autoload(prog, me);
        if (me)
            target = prog;
    }
    logbuf[0] = 0;
    bpf_program__set_log_buf(target, logbuf, sizeof(logbuf));
    bpf_program__set_log_level(target, 1);
    if (strict)
        bpf_program__set_flags(target, bpf_program__flags(target) | BPF_F_STRICT_ALIGNMENT);
    ret = bpf_object__load(obj);
    if (ret) {
        last_error(err, sizeof(err));
        printf("FAIL %s %s: %s\n", path, name, err);
    } else {
        printf("OK   %s %s\n", path, name);
    }
    bpf_object__close(obj);
    return ret != 0;
}

int main(int argc, char **argv)
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    int strict = 0, failed = 0, total = 0;

    setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_print(quiet);
    for (int i = 1; i < argc; i++) {
        struct bpf_object *obj;
        struct bpf_program *prog;
        char names[MAX_PROGS][128];
        int n = 0;

        if (!strcmp(argv[i], "--strict")) {
            strict = 1;
            continue;
        }
        obj = bpf_object__open_file(argv[i], NULL);
        if (!obj) {
            printf("FAIL %s: cannot open: %s\n", argv[i], strerror(errno));
            failed++;
            continue;
        }
        bpf_object__for_each_program(prog, obj)
            if (n < MAX_PROGS)
                snprintf(names[n++], sizeof(names[0]), "%s", bpf_program__name(prog));
        bpf_object__close(obj);
        for (int k = 0; k < n; k++) {
            failed += load_one(argv[i], names[k], strict);
            total++;
        }
    }
    printf("%d/%d loaded%s\n", total - failed, total, strict ? " (strict alignment)" : "");
    return failed ? 1 : 0;
}
