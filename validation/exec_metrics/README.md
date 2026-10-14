# Executed-instruction metrics

The verifier says whether a global loads and how many instructions it has, but
not how many it executes on a given packet. `bpfsim.py` is a small BPF
interpreter that runs a global straight from the compiled object and counts
what it executes, so different builds of the same global can be compared.

It uses the cases in `tests/units/cases.py`. Each case is a global, a packet and
the call arguments.

For each run it records:

- executed instructions, total and by class (ALU, packet/stack/ctx loads and
  stores, jumps, calls to globals and helpers);
- bytes passed to `bpf_csum_diff`;
- the deepest stack use along the path taken.

Everything else comes from the kernel (see `verifier_stats` below).

## Checking the interpreter

The interpreter is only useful if it does what the kernel does.
`check_interpreter.py` runs the unit-test objects and compares the results with
`tests/units/expected.json`, which was recorded on the kernel:

```bash
make -C ../../tests/units
python3 check_interpreter.py default
python3 check_interpreter.py strict
```

No root is needed. Rerun it whenever `bpfsim.py` or the cases change.

## Comparing two builds

Both objects must contain every global, as `tests/globals/build/globals.o` does
(`make -C ../../tests/globals`):

```bash
python3 compare.py old.o new.o
```

It lists the cases whose instruction count or result changed and prints a
summary. A changed result means one of the two builds is wrong.

## Building the configurations

`candidates.sh` builds the globals with each compiler and level, and with the
optimizers on top:

```bash
CLANGS="clang16:/opt/llvm16/bin/clang clang20:clang-20" \
GCC_BPF=bpf-gcc GCC_LABEL=gcc16 \
MERLIN=~/src/Merlin \
./candidates.sh results/objs
```

Leave out `GCC_BPF` or `MERLIN` to skip them. It writes one object per
configuration and `results/objs/configs.txt`.

gcc builds come in three sets of flags: none, `-fno-ivopts`, and
`-fno-ivopts -fno-cse-follow-jumps -fno-thread-jumps`. Only the last one gets
every global through the verifier, but some globals verify, and run faster,
with fewer.

### Merlin

[Merlin](https://github.com/4ar0nma0/Merlin) is not included here; clone it
somewhere and pass its path. The numbers in our results come from commit
`442bd340878be7270a642062ca13acfdd203849b`. Its bytecode optimizer needs numpy.

- `merlin_bc.py MERLIN IN.o OUT.o` runs the bytecode optimizer on each function
  once. Merlin's own driver would run it once per function on the whole
  `.text`, i.e. 68 times over the same code.
- `merlin_llvm.sh MERLIN -O2 IN.c OUT.o [flags]` compiles through Merlin's LLVM
  passes. It builds them into `build/` against the LLVM of `LLVM_CONFIG`
  (default `llvm-config-20`), with three small fixes for LLVM newer than 17.

AlignBPF assumes packet pointers are 8-byte aligned at a variable offset. That
is false, but harmless where unaligned access is cheap (the default series).
AtomicBPF finds nothing to merge in the globals.

## Kernel metrics

`verifier_stats` loads each program of an object on its own and prints what
the kernel reports about the global it calls. It needs root:

```bash
make
sudo build/verifier_stats results/objs/*.o > results/verifier.tsv
```

The columns are: whether it loaded and the verifier error; the verifier's
processed instructions, states and time; the stack depth of the global; its
size after the verifier's rewrites (instructions) and after the JIT (bytes).
The verifier counts cover the whole test program, which is the global, the
globals it calls and a small caller.

## Collecting a CSV

```bash
python3 collect.py -o results/all.csv --ref results/objs/clang20-O2.o \
    --verifier results/verifier.tsv $(cat results/objs/configs.txt)
```

Each row is one configuration and one case: the static size of the global, the
executed instructions, `sim_stack_max`, csum bytes, return value, one
`n_<class>` column per instruction class, and `same_as_ref` (whether the
result matches the `--ref` object). With `--verifier`, the kernel columns are
added with a `k_` prefix. The label before `=` is free text. `results/` and
`build/` are ignored by git.

## Limits

- `bpf_fib_lookup` is a stub that returns `BPF_FIB_LKUP_RET_FWD_DISABLED`, as
  in the test VM, so only the paths up to the lookup are measured.
- `bpf_csum_diff` folds the result to 16 bits, as kernel 7.0 does.
- `ingress_ifindex` reads as 1; `data_meta` equals `data`.
- Helper calls count as one instruction. Their cost is in the per-class
  counts and `helper_bytes`, so it can be weighted afterwards.
- `ja +0` is counted as `nop`, not as an executed instruction: the verifier
  removes it.
- K2 (https://github.com/smartnic/superopt) was tried and left out: it does
  not decode 32-bit jumps, which `-mcpu=v3` code uses everywhere, and it only
  takes r1 as input, while the globals read their arguments from r2-r5.
