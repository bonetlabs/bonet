#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>

static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (!getenv("BNT_LOAD_DEBUG") && level > LIBBPF_WARN)
        return 0;

    return vfprintf(stderr, fmt, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        fprintf(stderr, "warning: setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
}

static int load_one(const char *path)
{
    struct bpf_object *obj;
    long open_err;
    int err;

    obj = bpf_object__open_file(path, NULL);
    open_err = libbpf_get_error(obj);
    if (open_err) {
        fprintf(stderr, "FAIL open %s: %s\n", path, strerror((int)-open_err));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "FAIL load %s: %s (%d)\n", path, strerror(-err), err);
        bpf_object__close(obj);
        return 1;
    }

    printf("OK %s\n", path);
    bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv)
{
    int failed = 0;
    int i;

    if (argc < 2) {
        fprintf(stderr, "usage: %s OBJ [OBJ...]\n", argv[0]);
        return 2;
    }

    libbpf_set_print(libbpf_log);
    bump_memlock_rlimit();

    for (i = 1; i < argc; i++)
        failed |= load_one(argv[i]);

    return failed ? 1 : 0;
}
