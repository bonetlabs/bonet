# Paper figures

`plot.py` draws the evaluation figures: Plain eBPF, Inlined APIs, BONet (the
default build, asm globals) and, for the PDR, the kernel. Colors and hatches
follow Fig. 1/2 of the paper; every series but BONet has a hatch, so the
figures read without color. Each figure is written as PDF and PNG to
`results/` (or `-o DIR`).

| figure | option | input |
|---|---|---|
| `pdr` | `--pdr` | `report/summary.csv` of a `macro_perf` run with `-p paper` |
| `time-per-packet` | `--runtime` | `report/summary.csv` of a `macro_perf` run with `-p runtime` |
| `verifier` | `--verifier` | directory written by `verifier_logs.sh` |
| `complexity` | `--cognitive`, `--loc` | `softeng_perf/cognitive.py`'s `cognitive.csv` and `cloc` |

Each option is independent: only the figures whose inputs are given are drawn.

```bash
R=../macro_perf/results
# verifier logs of the run's objects, on kernel 6.8 (here in a VM, as root)
vng --run vmlinuz-6.8.0-147-generic --disable-microvm --rwdir=$PWD \
    --exec "sh $PWD/verifier_logs.sh $R/<paper-run>/objs $PWD/results/verifier"
python3 ../softeng_perf/cognitive.py --output-dir results/cognitive
(cd .. && cloc --by-file --json baseline/xdp_{mmlf,static_dnat,ip6ip6_encap}.c \
    framework/xdp_{mmlf,static_dnat,ip6ip6_encap}.c) > results/loc.json

../macro_perf/.venv/bin/python plot.py \
    --pdr $R/<paper-run>/report/summary.csv \
    --runtime $R/<runtime-run>/report/summary.csv \
    --verifier results/verifier \
    --cognitive results/cognitive/cognitive.csv --loc results/loc.json
```

Notes:

- Verifier: processed instructions are the verifier's count for the whole
  program. The stack is the sum of the frames it prints (`stack depth 88+0+8`),
  which for these programs is the deepest call chain.
- Cognitive complexity: `cognitive.py` without `--engine sonar` uses its local
  analyzer, which on the sources the paper measured (before commit b0ac6c5)
  gives the paper's values. The Sonar engine needs a C analyzer, which
  `sonarqube:community` does not have.
- `hatchcolor` needs matplotlib 3.10 or later (`macro_perf/.venv` has it).
