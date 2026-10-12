#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/libbpf.h>

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

static void read_trace_pipe(void)
{
    FILE *trace;
    char line[4096];

    trace = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (!trace) {
        fprintf(stderr, "cannot open trace_pipe: %s\n", strerror(errno));
        fprintf(stderr, "you can still read it manually with bpftool prog tracelog\n");
        while (!exiting)
            sleep(1);
        return;
    }

    while (!exiting && fgets(line, sizeof(line), trace)) {
        if (strstr(line, "bnt "))
            fputs(line, stdout);
    }

    fclose(trace);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    char obj_path[512];
    int ifindex = 0;

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

    printf("attached; reading bpf_printk output, Ctrl-C to stop\n");
    read_trace_pipe();

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    return 0;
}
