# Data

`globals-kernel7.0.csv` is the comparison behind the choice of the shipped
globals: 104 configurations × 102 cases, one row each. The columns are
described in `../README.md`.

How it was built:

- BONet: commit `f33f20f` (the globals are compiled from `src/` as of that
  commit, through `tests/globals` and `tests/units`).
- Kernel: 7.0.0-38-generic (Ubuntu), in a virtme-ng VM, x86-64.
- clang: Ubuntu packages 16.0.6, 17.0.6, 18.1.8, 19.1.7, 20.1.8, 21.1.8,
  22.1.2.
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

In this run every global in the case programs was the code measured in the
whole objects; 368 rows are globals the verifier rejects (no kernel result);
on the other 10240 the kernel's result matches `tests/units/expected.json`,
and the interpreter agrees with the kernel both on the compiled code and on
the code as the verifier translated it.

`eth_insert_ipv6` is not the best configuration of this table: that one
(`clang20-O2+merlin_llvm+merlin_bc`) is rejected by the 6.8 verifier, which
does not carry a bound checked after a spill to the spilled copy. The choice
is the configuration that loads on 6.8 (Ubuntu 6.8.0-124) with the fewest
executed loads, stores and multiplications, then the fewest executed
instructions: `clang22-O2+merlin_bc`. The other 67 choices load on 6.8.
