// Load every program of a BPF object on its own and print what the kernel
// reports about the global it calls, one tab-separated line per program.
//
// usage: verifier_stats [-x DIR] [-l DIR] OBJ...
//   -x DIR  also write, for each program that loads, the instructions as the
//           verifier translated them (DIR/<object>/<program>.xlated) and the
//           first instruction of each function in them (<program>.funcs, one
//           "name start" per line), and the maps it uses (<program>.maps,
//           "id name" per line), for bpfsim.Xlated and progsim.XProg
//   -l DIR  for each program that fails, write the verifier log to
//           DIR/<object>/<program>.log
//
// Columns: object, program, ok, error, and then, when the program loaded:
//   processed, max_states_per_insn, total_states, peak_states  verifier stats
//   verif_usec                    verification time
//   subprogs                      functions in the loaded program
//   stack                         stack depth of the global, from the verifier
//   xlated_insns                  instructions of the global after the
//                                 verifier's rewrites
//   jited_bytes                   machine code of the global
// The verifier stats cover the whole program: the global, the globals it
// calls and the small caller made by tests/globals/gen_programs.py.
//   prog_stack, prog_stack_sum, prog_xlated_insns, prog_jited_bytes
//                                 the same for the whole program (prog_stack:
//                                 the main function's frame; prog_stack_sum:
//                                 the frames of all its functions, as the
//                                 verifier log's "stack depth A+B+...")
// For a program that does not call a global named after it, the columns of
// the global are empty.
//
// The global is the subprogram named after the program without its leading
// "c" (c__bnt_read_u8_g calls __bnt_read_u8_g). Needs root.
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PROGS 512
#define MAX_FUNCS 64

static char logbuf[1 << 23];
static const char *xdir, *ldir;
static struct bpf_insn xinsns[1 << 16];

static int quiet(enum libbpf_print_level l, const char *f, va_list a)
{
    (void)l; (void)f; (void)a;
    return 0;
}

/* Last line of the log that is not a statistics line. */
/* mkdir -p */
static void mkdirs(const char *path)
{
    char p[4096];

    snprintf(p, sizeof(p), "%s", path);
    for (char *s = p + 1; *s; s++)
        if (*s == '/') {
            *s = 0;
            mkdir(p, 0755);
            *s = '/';
        }
    mkdir(p, 0755);
}

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
    for (char *c = out; *c; c++)
        if (*c == '\t')
            *c = ' ';
}

static void one(const char *path, const char *name)
{
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    struct bpf_program *prog, *target = NULL;
    struct bpf_prog_info info;
    struct bpf_func_info finfo[MAX_FUNCS];
    __u32 jlens[MAX_FUNCS], len = sizeof(info), nfunc, njit, depth[MAX_FUNCS] = {0};
    int processed = -1, maxst = -1, totst = -1, peakst = -1, ndepth = 0, g = -1;
    long long usec = -1;
    char err[256], *s;

    if (!obj) {
        printf("%s\t%s\t0\tcannot open\n", path, name);
        return;
    }
    bpf_object__for_each_program(prog, obj) {
        int me = strcmp(bpf_program__name(prog), name) == 0;

        bpf_program__set_autoload(prog, me);
        if (me)
            target = prog;
    }
    /* Level 4 (stats) is enough when it loads; level 1 says why when it fails. */
    logbuf[0] = 0;
    bpf_program__set_log_buf(target, logbuf, sizeof(logbuf));
    bpf_program__set_log_level(target, 4);
    if (bpf_object__load(obj)) {
        bpf_object__close(obj);
        obj = bpf_object__open_file(path, NULL);
        bpf_object__for_each_program(prog, obj) {
            int me = strcmp(bpf_program__name(prog), name) == 0;

            bpf_program__set_autoload(prog, me);
            if (me)
                target = prog;
        }
        logbuf[0] = 0;
        bpf_program__set_log_buf(target, logbuf, sizeof(logbuf));
        bpf_program__set_log_level(target, 1);
        bpf_object__load(obj);
        last_error(err, sizeof(err));
        printf("%s\t%s\t0\t%s\n", path, name, err);
        if (ldir) {
            const char *base = strrchr(path, '/') ? strrchr(path, '/') + 1 : path;
            char p[4096];
            FILE *f;

            snprintf(p, sizeof(p), "%s/%s", ldir, base);
            mkdirs(p);
            snprintf(p, sizeof(p), "%s/%s/%s.log", ldir, base, name);
            if ((f = fopen(p, "w"))) {
                fputs(logbuf, f);
                fclose(f);
            }
        }
        bpf_object__close(obj);
        return;
    }

    /* 6.18 also prints "insns processed A+B+..." before the summary line */
    if ((s = strstr(logbuf, "\nprocessed ")) && s++)
        sscanf(s, "processed %d insns (limit %*d) max_states_per_insn %d total_states %d peak_states %d",
               &processed, &maxst, &totst, &peakst);
    if ((s = strstr(logbuf, "verification time ")))
        sscanf(s, "verification time %lld", &usec);
    if ((s = strstr(logbuf, "stack depth "))) {
        s += strlen("stack depth ");
        while (ndepth < MAX_FUNCS) {
            char *e;
            unsigned long v = strtoul(s, &e, 10);

            if (e == s)
                break;
            depth[ndepth++] = v;
            if (*e != '+')
                break;
            s = e + 1;
        }
    }

    /* Ask once for the counts, then for the per-function records. */
    memset(&info, 0, sizeof(info));
    bpf_prog_get_info_by_fd(bpf_program__fd(target), &info, &len);
    nfunc = info.nr_func_info < MAX_FUNCS ? info.nr_func_info : MAX_FUNCS;
    njit = info.nr_jited_func_lens < MAX_FUNCS ? info.nr_jited_func_lens : MAX_FUNCS;
    {
        __u32 xlated = info.xlated_prog_len / 8, jited = info.jited_prog_len;
        struct btf *btf = bpf_object__btf(obj);

        memset(&info, 0, sizeof(info));
        info.nr_func_info = nfunc;
        info.func_info_rec_size = sizeof(struct bpf_func_info);
        info.func_info = (__u64)(unsigned long)finfo;
        info.nr_jited_func_lens = njit;
        info.jited_func_lens = (__u64)(unsigned long)jlens;
        len = sizeof(info);
        bpf_prog_get_info_by_fd(bpf_program__fd(target), &info, &len);

        for (__u32 i = 0; i < nfunc && btf; i++) {
            const struct btf_type *t = btf__type_by_id(btf, finfo[i].type_id);

            if (t && !strcmp(btf__name_by_offset(btf, t->name_off), name + 1))
                g = i;
        }
        if (xdir) {
            const char *base = strrchr(path, '/') ? strrchr(path, '/') + 1 : path;
            char p[4096];
            FILE *f;
            __u32 n = xlated < sizeof(xinsns) / sizeof(xinsns[0]) ? xlated : 0;

            memset(&info, 0, sizeof(info));
            info.xlated_prog_len = n * sizeof(struct bpf_insn);
            info.xlated_prog_insns = (__u64)(unsigned long)xinsns;
            len = sizeof(info);
            bpf_prog_get_info_by_fd(bpf_program__fd(target), &info, &len);
            snprintf(p, sizeof(p), "%s/%s", xdir, base);
            mkdirs(p);
            snprintf(p, sizeof(p), "%s/%s/%s.xlated", xdir, base, name);
            if ((f = fopen(p, "wb"))) {
                fwrite(xinsns, sizeof(struct bpf_insn), n, f);
                fclose(f);
            }
            {
                __u32 ids[64], nmap;
                struct bpf_prog_info mi;
                __u32 ml = sizeof(mi);

                memset(&mi, 0, sizeof(mi));
                bpf_prog_get_info_by_fd(bpf_program__fd(target), &mi, &ml);
                nmap = mi.nr_map_ids < 64 ? mi.nr_map_ids : 64;
                memset(&mi, 0, sizeof(mi));
                mi.nr_map_ids = nmap;
                mi.map_ids = (__u64)(unsigned long)ids;
                ml = sizeof(mi);
                bpf_prog_get_info_by_fd(bpf_program__fd(target), &mi, &ml);
                snprintf(p, sizeof(p), "%s/%s/%s.maps", xdir, base, name);
                if (nmap && (f = fopen(p, "w"))) {
                    for (__u32 i = 0; i < nmap; i++) {
                        struct bpf_map_info info2;
                        __u32 l2 = sizeof(info2);
                        int fd = bpf_map_get_fd_by_id(ids[i]);

                        memset(&info2, 0, sizeof(info2));
                        if (fd >= 0 && !bpf_map_get_info_by_fd(fd, &info2, &l2))
                            fprintf(f, "%u %s\n", ids[i], info2.name);
                        if (fd >= 0)
                            close(fd);
                    }
                    fclose(f);
                }
            }
            snprintf(p, sizeof(p), "%s/%s/%s.funcs", xdir, base, name);
            if ((f = fopen(p, "w"))) {
                for (__u32 i = 0; i < nfunc && btf; i++) {
                    const struct btf_type *t = btf__type_by_id(btf, finfo[i].type_id);

                    fprintf(f, "%s %u\n", t ? btf__name_by_offset(btf, t->name_off) : "?", finfo[i].insn_off);
                }
                fclose(f);
            }
        }
        printf("%s\t%s\t1\t\t%d\t%d\t%d\t%d\t%lld\t%u\t", path, name, processed, maxst, totst, peakst,
               usec, nfunc);
        if (g < 0) {
            printf("\t\t\t");  /* not a test program for one global */
        } else {
            __u32 end = (__u32)g + 1 < nfunc ? finfo[g + 1].insn_off : xlated;

            printf("%u\t%u\t%u\t", g < ndepth ? depth[g] : 0, end - finfo[g].insn_off,
                   (__u32)g < njit ? jlens[g] : 0);
        }
        {
            unsigned long sum = 0;

            for (int k = 0; k < ndepth; k++)
                sum += depth[k];
            printf("%u\t%lu\t%u\t%u\n", ndepth ? depth[0] : 0, sum, xlated, jited);
        }
    }
    bpf_object__close(obj);
}

int main(int argc, char **argv)
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

    setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_print(quiet);
    printf("object\tprogram\tok\terror\tprocessed\tmax_states_per_insn\ttotal_states\tpeak_states\t"
           "verif_usec\tsubprogs\tstack\txlated_insns\tjited_bytes\tprog_stack\tprog_stack_sum\tprog_xlated_insns\tprog_jited_bytes\n");
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-x") && i + 1 < argc) {
            xdir = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "-l") && i + 1 < argc) {
            ldir = argv[++i];
            continue;
        }
        struct bpf_object *obj = bpf_object__open_file(argv[i], NULL);
        struct bpf_program *prog;
        char names[MAX_PROGS][128];
        int n = 0;

        if (!obj) {
            printf("%s\t\t0\tcannot open\n", argv[i]);
            continue;
        }
        bpf_object__for_each_program(prog, obj)
            if (n < MAX_PROGS)
                snprintf(names[n++], sizeof(names[0]), "%s", bpf_program__name(prog));
        bpf_object__close(obj);
        for (int k = 0; k < n; k++)
            one(argv[i], names[k]);
    }
    return 0;
}
