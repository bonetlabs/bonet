# baseline

Handwritten eBPF reference programs (no `bnt` library). Each program here has an
equivalent `bnt`-based implementation of the same name in `../framework/`; the two
are compared by the benchmarks and metrics in `../` (`macro_perf`,
`softeng_perf`).

Each file is either an XDP program (`xdp_*`) or a TC program (`tc_*`).

Build (from this directory):

```bash
make            # one .o per .c
make clean
```

Check they pass the kernel verifier (from the repo root):

```bash
./verify_all.sh validation/baseline
```
