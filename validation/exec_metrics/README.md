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
- the deepest stack use along the call chain.

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

## Collecting a CSV

```bash
python3 collect.py -o results/clang.csv --ref clang20.o \
    clang16=clang16.o clang20=clang20.o clang22=clang22.o
```

Each row is one configuration and one case. The columns are the static size of
the global, the executed instructions, stack, csum bytes, return value, one
`n_<class>` column per instruction class, and `same_as_ref` (whether the
result matches the `--ref` object). The label before `=` is free text, so it
can encode compiler, version, flags or optimizer. `results/` is ignored by git.

## Limits

- `bpf_fib_lookup` is a stub that returns `BPF_FIB_LKUP_RET_FWD_DISABLED`, as
  in the test VM, so only the paths up to the lookup are measured.
- `bpf_csum_diff` folds the result to 16 bits, as kernel 7.0 does.
- `ingress_ifindex` reads as 1; `data_meta` equals `data`.
- Helper calls count as one instruction. Their cost is in the per-class
  counts and `helper_bytes`, so it can be weighted afterwards.
