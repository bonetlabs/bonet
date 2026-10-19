# eBPF Validation Workspace

This directory contains the local validation workflow for comparing handwritten
eBPF programs against equivalent programs written with the `bnt` framework.

## Layout

- `baseline/`: handwritten eBPF programs.
- `framework/`: equivalent `bnt`-based eBPF programs (default `BNT_INLINE_ALL=0`).
- `framework_inlined/`: the same `bnt`-based programs built with `BNT_INLINE_ALL=1`
  (everything inlined, no global subprograms; meaningful on XDP only). It has no
  sources of its own; its Makefile compiles `framework/`'s sources with the
  inline flag.
- `exec_metrics/`: a BPF interpreter that counts the instructions each XDP
  global executes, to compare builds of the globals.
- `macro_perf/`: two-machine forwarding throughput benchmarks.
- `softeng_perf/`: software-engineering metrics, verifier-log metrics, and
  cognitive-complexity reports.

## Requirements

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y \
  python3 python3-venv python3-pip \
  make gcc clang llvm bpftool \
  libbpf-dev libelf-dev zlib1g-dev pkg-config \
  linux-tools-generic file cloc
```

`cloc` is optional but recommended for `softeng_perf/compare_metrics.py`.

## Build Validation Objects

Run these commands from `validation/`:

```bash
make -C baseline
make -C framework
make -C framework_inlined
```

Each Makefile builds one eBPF object file per benchmark program. A quick sanity
check is:

```bash
file baseline/*.o framework/*.o
```

The expected file type is `ELF ... eBPF`.

## Verification modes

The `bnt` library compiles in three modes, selected at build time:

- **globals** (default, `BNT_INLINE_ALL=0`): each packet operation is a global
  BPF subprogram, verified once in isolation.
- **fast inline** (`BNT_INLINE_ALL=1`): every operation inlined into the program.
- **legacy kernel** (`BNT_LEGACY_KERNEL=1`): inline plus extra verifier barriers
  for old/stricter verifiers; forces `BNT_INLINE_ALL=1`.

On TC `BNT_INLINE_ALL` is always forced to `1`, so only XDP differs across modes.
Build `framework/` in a specific mode by passing the flag:

```bash
make -C framework BNT_INLINE_ALL=0                                         # globals (default)
make -C framework BNT_INLINE_ALL=1                                         # fast inline
make -C framework EXTRA_CFLAGS="-DBNT_LEGACY_KERNEL=1"                     # legacy kernel
```

`framework_inlined/` is a convenience target that builds `framework/`'s sources
with `BNT_INLINE_ALL=1`, so the globals and inline objects coexist. (`macro_perf`
builds its own objects; see `macro_perf/profiles/`.)

## Software-Metrics Setup

From `validation/`, create a Python virtual environment and install
the Python packages used by the software-engineering metrics workflow:

```bash
cd softeng_perf
python3 -m venv env
source env/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

The requirements include `lizard` and the other Python packages used by the
metrics scripts.

## Quick Start

From `validation/`, build once:

```bash
make -C baseline
make -C framework
make -C framework_inlined
```

Run software-engineering metrics after completing the software-metrics setup:

```bash
cd softeng_perf

python3 cognitive.py
python3 generate_verifier_logs.py --baseline ../baseline --framework ../framework
python3 compare_metrics.py \
  --baseline ../baseline \
  --framework ../framework \
  --framework-api-prefix bnt \
  --line-counter cloc \
  --baseline-verifier-log ../baseline \
  --framework-verifier-log ../framework \
  --json results/metrics.json \
  --csv results/metrics.csv \
  --markdown results/metrics.md \
  --split-output-dir results/split
```

## Where To Look Next

- Software-engineering metrics, cognitive-complexity methodology, verifier-log
  metrics: `softeng_perf/README.md`.
- Macro throughput experiments: `macro_perf/README.md`.

## Cleanup

From `validation/`:

```bash
make -C baseline clean
make -C framework clean
make -C framework_inlined clean
```

Generated reports are ignored by git:

- `exec_metrics/results/`
- `macro_perf/results/`
- `softeng_perf/results/`
