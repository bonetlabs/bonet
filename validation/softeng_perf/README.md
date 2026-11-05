# Software-Engineering Metrics

This folder contains the software-engineering metrics workflow for the paired
eBPF programs in `../baseline` and `../framework`.

It covers:

- cognitive complexity, with SonarSource's C analyzer (`cognitive.py`);
- source metrics from Lizard and optional external line counters;
- eBPF-specific source-pattern counts;
- object-file metrics from `llvm-objdump`/`objdump`;
- Linux verifier-log metrics.

## What the paper uses

| paper | how |
|---|---|
| Fig. 6, cognitive complexity | `python3 cognitive.py` (Sonar, below) |
| Fig. 6, lines of code | `cloc --by-file` on the `.c` files (`../figures/README.md`) |
| Table I, removed constructs | the `// [..]` tags in `../baseline/*.c`, see "Table I" below |

The figures themselves are drawn by `../figures/plot.py`.

## Quick Start

Run from `validation/softeng_perf/`:

```bash
python3 -m venv env
source env/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

python3 cognitive.py          # needs Docker, see below
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

Generated reports are written below `results/` (ignored by git).

## Cognitive Complexity

```bash
python3 cognitive.py                  # about 5 minutes, the first time longer (images)
```

It prints a table and writes `results/cognitive/cognitive.{json,csv,md}`, one
row per program pair: the cognitive complexity of the `baseline/` and the
`framework/` file (the sum over the file's functions, Sonar's
`cognitive_complexity` metric) and the change.

It needs only Docker, no account or license. What it does, and why:

1. **SonarQube Developer Edition** (`sonarqube:developer`) in a disposable
   container. The Community images have no C analyzer (they report "0 languages
   detected" on `.c` files); the commercial editions do. Without a license the
   server still starts and hands the analyzers to the scanner; it only refuses
   to store the results ("Analyses suspended. Please set a valid license").
2. **SonarScanner with clang** (`bonet-sonar-scanner`, built from
   `sonar/Dockerfile` the first time). The C analyzer runs the compiler of
   `compile_commands.json` to learn its predefined macros; the stock
   `sonar-scanner-cli` image has none and skips every file.
3. Each side is copied to a work directory under `results/`, with a
   `compile_commands.json` for `clang -target bpf` (the BONet headers come from
   `src/`), and scanned.
4. **The measures are read from the scanner's own report**
   (`.scannerwork/scanner-report`, kept with `sonar.scanner.keepReport=true`),
   not from the server: the scanner computes them before uploading, so the
   rejected upload does not matter. `read_report_metrics()` reads the two
   protobuf files it needs (`component-N.pb`, `measures-N.pb`).

`--keep-container` and `--keep-workdir` keep the server and the work directory
for inspection. `SONAR_IMAGE` and `SONAR_SCANNER_IMAGE` (or `--sonar-image`,
`--scanner-image`) change the images; a licensed server works the same way.

`--engine local` runs, without Docker, the approximate analyzer of
`compare_metrics.py`. It is close but not equal to Sonar (on the paper's
workloads it gives 11/11/9 for BONet where Sonar gives 12/12/9, and 38 instead
of 36 for the DNAT baseline of the first submission, whose numbers came from
it). Use Sonar for anything published.

Not working, do not retry: `sonarqube:community` (any version, no C), the
sonar-cxx community plugin (a different analyzer), and SonarQube for IDE in VS
Code (it only reports functions above the rule's threshold, 25 for C).

## Table I

Every line of the plain programs in `../baseline/` that exists only for the
verifier or for low-level packet handling carries a tag in a trailing comment,
e.g. `// [B P]`. Table I counts the tags of `xdp_mmlf.c`,
`xdp_static_dnat.c` and `xdp_ip6ip6_encap.c` (a line with two tags counts in
both rows):

| tag | Table I row |
|---|---|
| `CC` | context casts (`ctx->data`, `ctx->data_end`) |
| `B` | bounds checks |
| `L` | loop termination checks |
| `C` | header casts |
| `P` | pointer-arithmetic expressions |
| `E` | endian conversions |
| `CS` | checksum-update operations |
| `BW` | packet-layout writes |

```bash
grep -ho '//\s*\[[A-Z ]*\]' ../baseline/xdp_mmlf.c | tr -d '/[]' | tr ' ' '\n' | grep . | sort | uniq -c
```

A change to a baseline must keep its tags up to date.

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
