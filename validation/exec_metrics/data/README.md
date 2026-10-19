# Data

`globals-kernel7.0.csv` is the comparison behind the choice of the shipped
globals: 104 configurations × 102 cases, one row each. The columns are
described in `../README.md`.

How it was built:

- BONet: the sources of the commit that last changed this file (the globals
  are compiled from `src/` through `tests/globals` and `tests/units`).
- Kernel: 7.0.0-38-generic (Ubuntu), in a virtme-ng VM, x86-64.
- clang: Ubuntu packages 16.0.6 (23ubuntu4), 17.0.6 (23ubuntu7), 18.1.8
  (20ubuntu8), 19.1.7 (20ubuntu4), 20.1.8 (2ubuntu8), 21.1.8 (6ubuntu1),
  22.1.2 (1ubuntu1).
- gcc: Ubuntu `gcc-bpf` 16-20260315 (16.0.1, a trunk snapshot), as `gcc16`.
- llvm-mca: LLVM 20.1.8, CPU models skylake and znver3.
- Merlin: commit `442bd340878be7270a642062ca13acfdd203849b`; LLVM passes built
  against LLVM 20.1.8.

Steps:

```bash
./candidates.py results/objs            # CLANGS, GCC_BPF, MERLIN set as in ../README.md
sudo build/verifier_stats -x results/xlated results/objs/*.o > results/verifier.tsv
grep -wE '__bpf_call_base|bpf_csum_diff|bpf_xdp_adjust_head|bpf_xdp_fib_lookup' \
    /proc/kallsyms | sudo tee results/xlated/kallsyms.txt
sudo ./kernel_cases.py results/objs > results/kernel_cases.tsv
./collect.py -o results/all.csv --verifier results/verifier.tsv \
    --kernel-cases results/kernel_cases.tsv --xlated results/xlated \
    --mca skylake,znver3 $(cat results/objs/configs.txt)
```

Every global in the case programs was the code measured in the whole objects;
392 rows are globals the verifier rejects (no kernel result); on the other
10216 the kernel's result matches `tests/units/expected.json`, and the
interpreter agrees with the kernel both on the compiled code and on the code
as the verifier translated it.

The choices in `choices-kernel7.0.txt` were picked per global among the
configurations no other one beats on these metrics. With them, every global
loads and every case gives the expected result, in the asm and in the C build,
on the latest release of each mainline series from 5.12 to 7.2, on the first
release of each LTS since 5.15, and on Ubuntu 6.8.0-147 and 7.0.0-38.
