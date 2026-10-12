# Software-Engineering Metrics

This folder contains the software-engineering metrics workflow for the paired
eBPF programs in `../baseline` and `../framework`.

It covers:

- source metrics from Lizard and optional external line counters;
- local C/eBPF cognitive complexity;
- eBPF-specific source-pattern counts;
- object-file metrics from `llvm-objdump`/`objdump`;
- Linux verifier-log metrics.

## Quick Start

Run from `validation/softeng_perf/`:

```bash
python3 -m venv env
source env/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

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

Generated reports are written below `results/`.

## Cognitive Complexity

For the one-shot cognitive-complexity comparison:

```bash
python3 cognitive.py
```

The output is printed to the terminal and saved as:

- `results/cognitive/cognitive.json`
- `results/cognitive/cognitive.csv`
- `results/cognitive/cognitive.md`

The default backend is local and reproducible. The optional official Sonar
backend is available through:

```bash
python3 cognitive.py --engine sonar
```

That mode requires a SonarQube/SonarCloud setup with C/C++/Objective-C CFamily
analysis support. Methodological details are in `COGNITIVE.md`.

## Verifier Logs

`compare_metrics.py` can extract verifier metrics from `.verifier.log` files.
Generate them first:

```bash
python3 generate_verifier_logs.py --baseline ../baseline --framework ../framework
```

By default, `generate_verifier_logs.py` runs `make clean` and `make` in both
input directories before loading the object files. Use `--no-rebuild` only when
you intentionally want to keep existing objects.

The script saves logs next to the corresponding object files, for example:

- `../baseline/tc_ipv4_dnat.verifier.log`
- `../framework/tc_ipv4_dnat.verifier.log`

If `bpftool` is missing:

```bash
sudo apt install -y linux-tools-generic
```

## Main Report

The report command compares files by stem, so these files are treated as the
same test:

- `../baseline/tc_ipv4_dnat.c`
- `../baseline/tc_ipv4_dnat.o`
- `../baseline/tc_ipv4_dnat.verifier.log`
- `../framework/tc_ipv4_dnat.c`
- `../framework/tc_ipv4_dnat.o`
- `../framework/tc_ipv4_dnat.verifier.log`

Recommended command:

```bash
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

Report structure:

- `results/metrics.json`: full machine-readable report.
- `results/metrics.csv`: flat comparison table.
- `results/metrics.md`: human-readable summary.
- `results/split/`: aggregate tables, per-test files, warnings, tool status,
  and a compact summary.

## Minimal Smoke Test

Use this when checking script flow without optional tools:

```bash
python3 compare_metrics.py \
  --baseline ../baseline \
  --framework ../framework \
  --framework-api-prefix bnt \
  --no-lizard \
  --line-counter none \
  --markdown results/metrics_minimal.md
```

## Line Counters

Recommended:

```bash
--line-counter cloc
```

Supported values:

- `cloc`: use `cloc --json`;
- `nloc`: force an installed `nloc` executable;
- `sloc`: force an installed `sloc` executable;
- `auto`: try known counters in order;
- `none`: disable external line-counter metrics.

If `--check-tools` reports `nloc` or `sloc` as missing, that is fine when the
report command uses `--line-counter cloc`.
