# Executed-instruction metrics

The verifier says whether a global loads and how many instructions it has, but
not how many it executes on a given packet. `bpfsim.py` is a small BPF
interpreter that runs a global, either from the compiled object or as the
verifier translated it, and counts what it executes, so different builds of
the same global can be compared.

It uses the cases in `tests/units/cases.py`. Each case is a global, a packet and
the call arguments.

For each run it records:

- executed instructions, total and by class (ALU, packet/stack/ctx loads and
  stores, jumps, calls to globals and helpers), for the global alone and with
  the globals it calls;
- bytes passed to `bpf_csum_diff`;
- the deepest stack use along the path taken;
- the executed instructions themselves, which `mca.py` turns into estimated
  cycles.

Everything else comes from the kernel: whether each global loads, the
verifier's numbers and the code sizes (`verifier_stats`), and the results of
each case (`kernel_cases.py`). The same works for the whole workload programs (see
[Workload programs](#workload-programs)).

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

`candidates.py` builds the globals with each compiler and level, and with the
optimizers on top:

```bash
CLANGS="clang16:/opt/llvm16/bin/clang clang20:clang-20" \
GCC_BPF=bpf-gcc GCC_LABEL=gcc16 \
MERLIN=~/src/Merlin \
./candidates.py results/objs
```

Leave out `GCC_BPF` or `MERLIN` to skip them. `ONLY="g1 g2"` builds the case programs of
those globals only, for a quick look after a change that touches a few. For each configuration it writes
`<label>.o`, with every global, and `cases/<label>/`, the programs of
`tests/units` built the same way. It checks that each global is the same code
in both and lists the exceptions in `mismatch.txt`. `configs.txt` has one
`LABEL=OBJ` per line.

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

Both tools need root.

`verifier_stats` loads each program of an object on its own and prints what
the kernel reports about the global it calls:

```bash
make
sudo build/verifier_stats -x results/xlated results/objs/*.o > results/verifier.tsv
grep -wE '__bpf_call_base|bpf_csum_diff|bpf_xdp_adjust_head|bpf_xdp_fib_lookup' \
    /proc/kallsyms | sudo tee results/xlated/kallsyms.txt
```

With `-x` it also saves each program as the verifier translated it. The
translated code calls helpers by kernel address, so the interpreter needs the
addresses of the same boot: take `kallsyms.txt` right after, without
rebooting.

`-l DIR` saves the verifier log of each program that fails, as
`DIR/<object>/<program>.log`.

The columns are: whether it loaded and the verifier error; the verifier's
processed instructions, states and time; the stack depth of the global; its
size after the verifier's rewrites (instructions) and after the JIT (bytes).
The verifier counts cover the whole test program, which is the global, the
globals it calls and a small caller.

`kernel_cases.py` runs every case program of every configuration with
`BPF_PROG_TEST_RUN`, through `tests/units/build/run_case`
(`make -C ../../tests/units`):

```bash
sudo ./kernel_cases.py results/objs > results/kernel_cases.tsv
```

## Collecting a CSV

```bash
python3 collect.py -o results/all.csv --verifier results/verifier.tsv \
    --kernel-cases results/kernel_cases.tsv --xlated results/xlated \
    --mca skylake,znver3 $(cat results/objs/configs.txt)
```

Each row is one configuration and one case. The label before `=` is free
text. The columns:

- interpreter, compiled code: `static_insns`, `exec_insns` (the global's own
  instructions), `exec_total` (with the globals it calls), `calls` (which
  globals, how many times), `sim_stack_max`, `helper_bytes`, `ret`, and one
  `n_<class>` column per instruction class, for the global alone;
- interpreter, translated code: `xl_exec_insns`, `xl_exec_total`, `xl_ld`,
  `xl_st`, `xl_mul`, `xl_same_as_kernel`;
- llvm-mca: `mca_<cpu>` and `xl_mca_<cpu>`;
- kernel: `loaded`, `k_error`, the verifier's numbers, `k_stack`,
  `k_xlated_insns`, `k_jited_bytes`, and how the case ran (`k_status`,
  `k_ret`, `k_same_as_expected` against `tests/units/expected.json`);
- `sim_same_as_kernel`: whether the interpreter agrees with the kernel on that
  configuration; `--ref OBJ` adds `same_as_ref`, the interpreter against a
  reference object.

A global is measured on its own code: the globals it calls are chosen on
their own, so they do not count for it. `results/` and `build/` are ignored by
git.

`data/` holds the CSV behind the choice of the shipped globals, with a note of
what it was built from.

## Estimated cycles

`mca.py` lowers the instructions a global executed to x86-64 the way the
kernel's x86 JIT does (same register mapping, `movzx` loads, `ror`+`movzx` for
16-bit byte swaps, `shlx`/`shrx`/`sarx` for shifts by a register, `cmp` or
`test` plus a jump for branches) and asks `llvm-mca` (LLVM 20) for the cycles
of one pass on a CPU model: ports, latencies, dispatch width and register
dependencies come from LLVM's scheduling model for that CPU. `collect.py
--mca skylake,znver3` adds `mca_<cpu>` (compiled code) and `xl_mca_<cpu>`
(translated code) columns.

It is an estimate, not a measurement. It leaves out the prologue and epilogue,
the time spent in helpers and in the globals called (the same in every build),
branch mispredictions and cache misses. llvm-mca also takes loads and stores
as not aliasing, so a spill read back at once costs its store and load but no
forwarding delay. Small changes move the estimate by a few cycles either way:
on the FIB globals the two extra loads of the translated code lower the
Skylake estimate from 133 to 123. Differences of a few cycles between builds
say nothing.

## The shipped asm

`src/bnt_asm_globals.h`, which global mode uses by default, is generated from
the choice of one configuration per global:

```bash
./gen_asm.py data/choices-kernel7.0.txt results/objs
```

`data/choices-kernel7.0.txt` has one `global: configuration` line per global.
For each one, `bpfasm.py` prints the function from that configuration's object
as clang BPF assembly (jumps to labels, calls to other globals by name, the
`ja +0` that Merlin leaves dropped), and `gen_asm.py` wraps it in a function
with the C prototype, so the BTF keeps the parameter names. The generated
header stops the build when a limit that shapes the globals is not at its
default, or for strict-alignment and big-endian builds.

`candidates.py` builds the C globals (`BNT_ASM_GLOBALS=0`), so regenerating
the candidates does not depend on the shipped asm.

`check_asm.py` checks the default build against the choices: each global's
code must be the chosen configuration's (apart from the dropped `ja +0`), and
its BTF must have global linkage and named parameters.

## Workload programs

The same interpreter runs the 14 XDP programs of `../framework` (or
`../baseline`) on the packets of `workloads.py`, the whole program with the
globals it calls. `progsim.py` loads a program from its object as libbpf
would; the forwarding cases need `bpf_fib_lookup` to succeed, so the kernel
runs them in a VM set up by `vm_net.sh`, and the interpreter returns the same
result for the same routes (`workloads.FIB`).

In the VM, as root (`make` builds `build/run_prog`):

```bash
IF=$(./vm_net.sh)
for b in asm c; do build/verifier_stats -x results/wl-xlated/$b results/wl/$b/*.o; done
grep -wE '__bpf_call_base|bpf_csum_diff|bpf_xdp_adjust_head|bpf_xdp_fib_lookup|bpf_xdp_redirect|bpf_map_lookup_elem|__htab_map_lookup_elem' \
    /proc/kallsyms > results/wl-xlated/kallsyms.txt
./workload_kernel.py asm=results/wl/asm c=results/wl/c > results/wl-kernel.tsv
echo $IF
```

Then, anywhere:

```bash
./workload_metrics.py --kernel results/wl-kernel.tsv --xlated results/wl-xlated \
    --ifindex $IF -o results/workloads.csv asm=results/wl/asm c=results/wl/c
```

Each row is a build and a case: the instructions executed by the whole
program, by its own code and by the globals; loads, stores and multiplications;
llvm-mca cycles; the same on the translated code; and whether the interpreter
matches the kernel's action, packet and map entries. The verifier's numbers for
the whole programs are in the `prog_*` columns of `verifier_stats`.

## Limits

- For the unit cases `bpf_fib_lookup` is a stub that returns
  `BPF_FIB_LKUP_RET_FWD_DISABLED`, as in the test VM, so only the paths up to
  the lookup are measured. For the workload programs it succeeds for the
  routes of `workloads.FIB` and fails otherwise.
- `bpf_csum_diff` folds the result to 16 bits, as kernel 7.0 does.
- `ingress_ifindex` reads as 1; `data_meta` equals `data`. On the translated
  code the context is `struct xdp_buff` (kernel 7.0 layout), and the reads of
  `ingress_ifindex` go through the receive queue and the device, as in the
  kernel.
- Helper calls count as one instruction. Their cost is in the per-class
  counts and `helper_bytes`, so it can be weighted afterwards.
- `ja +0` is counted as `nop`, not as an executed instruction: the verifier
  removes it.
- K2 (https://github.com/smartnic/superopt) was tried and left out: it does
  not decode 32-bit jumps, which `-mcpu=v3` code uses everywhere, and it only
  takes r1 as input, while the globals read their arguments from r2-r5.
