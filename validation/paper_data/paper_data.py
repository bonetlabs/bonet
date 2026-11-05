#!/usr/bin/env python3
"""Keeps the paper's results in the repo and writes README.md, the overview of every number.

  paper_data.py                  rewrite README.md from raw/
  paper_data.py run [RUN_ID]     save a macro_perf run (default: the newest one) into raw/
  paper_data.py verifier DIR     save the numbers of the verifier logs of figures/verifier_logs.sh
  paper_data.py code             save cognitive complexity (Sonar), lines of code and Table I tags

Every command but the first also rewrites README.md. Run it with macro_perf's
venv (it imports macro_perf/report.py, which needs matplotlib).
"""
import csv
import gzip
import json
import math
import re
import shutil
import statistics
import subprocess
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALIDATION = HERE.parent
RAW = HERE / "raw"
sys.path.insert(0, str(VALIDATION / "macro_perf"))
import report  # noqa: E402  (Run, welch, t95: the same statistics as the run reports)

WL = ["MMLF", "DNAT", "ENCAP"]
OBJ = {"MMLF": "xdp_mmlf", "DNAT": "xdp_static_dnat", "ENCAP": "xdp_ip6ip6_encap"}
# the traffic of the macro runs, as a micro_perf case (exec_metrics/workloads.py)
MICRO_CASE = {"MMLF": "marked", "DNAT": "translate", "ENCAP": "encap"}
LABEL = {"plain": "Plain eBPF", "inline": "Inlined APIs", "globals-asm": "BONet",
         "globals-c": "BONet, C globals", "kernel": "Kernel"}
VARIANTS = ["inline", "globals-asm", "globals-c"]
TAGS = {"CC": "Context casts", "B": "Bounds checks", "L": "Loop termination checks",
        "C": "Header casts", "P": "Pointer-arithmetic expressions", "E": "Endian conversions",
        "CS": "Checksum-update operations", "BW": "Packet-layout writes"}
# what a run keeps: enough to recompute every number; objects, pcaps and plots are rebuilt
RUN_FILES = ["plan.json", "meta.json", "progress.json", "searches.csv", "trials.csv", "checks.csv",
             "runtime.csv", "sut-info.txt", "git.diff", "micro/workloads.tsv"]


# ---------------------------------------------------------------- saving

def save_run(run_id=None):
    results = VALIDATION / "macro_perf" / "results"
    runs = sorted(p.parent for p in results.glob("*/plan.json"))
    src = next((p for p in runs if p.name == run_id), None) if run_id else runs[-1]
    if src is None:
        sys.exit(f"no run {run_id} in {results}")
    method = json.loads((src / "plan.json").read_text()).get("method", "pdr")
    dst = RAW / method / src.name
    for name in RUN_FILES:
        if (src / name).exists():
            (dst / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src / name, dst / name)
    if (src / "log.txt").exists():
        with (src / "log.txt").open("rb") as f, gzip.open(dst / "log.txt.gz", "wb") as g:
            shutil.copyfileobj(f, g)
    print(f"saved {src.name} -> {dst.relative_to(HERE)}")


def save_verifier(logs):
    logs = Path(logs)
    rows = []
    for log in sorted(logs.glob("*.log")):
        case, obj = log.stem.rsplit("-", 1)  # <case>-<object>.log; objects have no "-"
        text = log.read_text(errors="replace")
        stat = re.findall(r"processed (\d+) insns.*?total_states (\d+) peak_states (\d+)", text)
        depth = re.findall(r"stack depth ([\d+]+)", text)
        if not stat or not depth:
            sys.exit(f"{log}: no verifier statistics (did it load?)")
        insns, total, peak = stat[-1]
        rows.append({"case": case, "object": obj, "processed_insns": insns,
                     "total_states": total, "peak_states": peak, "stack_depth": depth[-1],
                     "stack_bytes": sum(map(int, depth[-1].split("+")))})
    dst = RAW / "verifier"
    dst.mkdir(parents=True, exist_ok=True)
    write_tsv(dst / "verifier.tsv", rows)
    kernel = (logs / "uname").read_text().strip() if (logs / "uname").exists() else "unknown"
    (dst / "kernel.txt").write_text(kernel + "\n")
    print(f"saved {len(rows)} programs, kernel {kernel} -> raw/verifier")


def save_code():
    dst = RAW / "code"
    dst.mkdir(parents=True, exist_ok=True)
    cognitive = VALIDATION / "softeng_perf" / "results" / "cognitive" / "cognitive.json"
    loc = VALIDATION / "figures" / "results" / "loc.json"
    for src, hint in ((cognitive, "softeng_perf/cognitive.py"), (loc, "cloc, see figures/README.md")):
        if not src.exists():
            sys.exit(f"missing {src}: run {hint} first")
    report_json = json.loads(cognitive.read_text())
    if report_json["metadata"]["engine"] != "sonar":
        sys.exit("cognitive.json was not measured with Sonar (cognitive.py --engine sonar)")
    shutil.copy2(cognitive.with_suffix(".csv"), dst / "cognitive.csv")
    shutil.copy2(loc, dst / "loc.json")
    rows = []
    for w, obj in OBJ.items():
        text = (VALIDATION / "baseline" / f"{obj}.c").read_text()
        tags = [t for m in re.findall(r"//\s*\[([A-Z ]+)\]", text) for t in m.split()]
        rows.append({"workload": w, **{t: tags.count(t) for t in TAGS}})
    write_tsv(dst / "tags.tsv", rows)
    commit = subprocess.run(["git", "describe", "--always", "--dirty"], cwd=VALIDATION,
                            capture_output=True, text=True).stdout.strip()
    (dst / "source.txt").write_text(f"sources at {commit}, saved {datetime.now():%Y-%m-%d %H:%M}\n")
    print(f"saved code metrics of {commit} -> raw/code")


def write_tsv(path, rows):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), delimiter="\t")
        w.writeheader()
        w.writerows(rows)


def read_tsv(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


# ---------------------------------------------------------------- numbers

def ci(values):
    n = len(values)
    return report.t95(n - 1) * statistics.stdev(values) / math.sqrt(n) if n > 1 else float("nan")


def num(x, d=1):
    return "–" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:,.{d}f}"


def pct(x, half=None):
    if x is None or math.isnan(x):
        return "–"
    return f"{x:+.1f}%" + (f" ±{half:.1f}" if half is not None and not math.isnan(half) else "")


def paper_runs(method):
    """Saved runs of a method on the paper's workloads, newest first."""
    runs = [report.Run(p.parent) for p in (RAW / method).glob("*/plan.json")]
    return sorted((r for r in runs if set(WL) <= set(r.experiments)), key=lambda r: r.id, reverse=True)


def run_line(run):
    m, tb = run.meta, run.plan.get("testbed", "fabric")
    commit = m.get("git_describe") or "not recorded"
    return f"`{run.id}`, testbed {tb}, commit `{commit}`" + (f": {m['note']}" if m.get("note") else "")


def pdr_section(run):
    out = [f"Run {run_line(run)}.", "",
           "| workload | case | PDR (Mpps) | Δ pps vs plain | Δ time vs plain | × kernel |",
           "|---|---|---|---|---|---|"]
    worst = {}
    for w in WL:
        plain, kernel = run.stats(w, "plain"), run.stats(w, "kernel")
        for case in ["plain"] + VARIANTS + ["kernel"]:
            s = run.stats(w, case)
            if not s.get("n"):
                continue
            d, half = run.delta(w, case, "plain") if case != "plain" else (None, None)
            dt = 100 * (plain["mean_pps"] / s["mean_pps"] - 1) if case != "plain" else None
            kx = s["mean_pps"] / kernel["mean_pps"] if kernel.get("n") and case != "kernel" else None
            out.append(f"| {w} | {LABEL[case]} | {num(s['mean_pps'] / 1e6, 3)} ±{num(s['ci95_pps'] / 1e6, 3)} "
                       f"| {pct(d, half)} | {pct(dt)} | {num(kx, 2) + '×' if kx else '–'} |")
            if case in VARIANTS:
                worst.setdefault(case, []).append(d)
            if case in VARIANTS and kx:
                worst.setdefault("kx", []).append(kx)
    out += ["", "In the text: " + "; ".join(
        f"{LABEL[c]} within {abs(min(worst[c])):.1f}% of plain" for c in VARIANTS if c in worst)
        + (f"; the BONet variants {min(worst['kx']):.1f}–{max(worst['kx']):.1f}× the kernel" if "kx" in worst else "")
        + "."]
    return out


def runtime_section(run):
    rate = run.rates()[0]
    out = [f"Run {run_line(run)}. TRex offers {float(rate) / 1e6:g} Mpps to every case; the time is "
           "`run_time_ns / run_cnt` of the attached program (`kernel.bpf_stats_enabled`).", "",
           "| workload | case | ns per packet | Δ time vs plain | Δ pps vs plain |", "|---|---|---|---|---|"]
    for w in WL:
        base = statistics.mean(run.ns(w, "plain", rate))
        for case in ["plain"] + VARIANTS:
            v = run.ns(w, case, rate)
            if not v:
                continue
            d, half = report.welch(v, run.ns(w, "plain", rate)) if case != "plain" else (None, None)
            dp = 100 * (base / statistics.mean(v) - 1) if case != "plain" else None
            out.append(f"| {w} | {LABEL[case]} | {num(statistics.mean(v))} ±{num(ci(v))} | {pct(d, half)} | {pct(dp)} |")
    return out


def micro_section(run):
    path = run.path / "micro" / "workloads.tsv"
    if not path.exists():
        return ["No `micro/workloads.tsv` in this run."]
    rounds = {(r["build"], r["workload"], r["case"]): [float(x) for x in r["ns"].split(",")]
              for r in read_tsv(path)}
    out = [f"`BPF_PROG_TEST_RUN` with live frames on the SUT, pinned to the RX CPU (`micro_perf/bench_workloads.py`), "
           f"saved with run `{run.id}`. Net time: the workload's rounds minus those of `ref`, a program that only "
           "redirects; MMLF marked, DNAT translate, ENCAP encap (the macro traffic).", "",
           "| workload | case | net ns per packet | Δ time vs plain | Δ pps vs plain |", "|---|---|---|---|---|"]
    for w in WL:
        key = (OBJ[w], MICRO_CASE[w])
        ref = rounds[("ref", *key)]
        net = {}
        for case in ["plain"] + VARIANTS:
            if (case, *key) in rounds:
                v = rounds[(case, *key)]
                net[case] = (statistics.mean(v) - statistics.mean(ref), math.hypot(ci(v), ci(ref)))
        for case, (m, half) in net.items():
            p = net["plain"][0]
            dt = 100 * (m / p - 1) if case != "plain" else None
            dp = 100 * (p / m - 1) if case != "plain" else None
            out.append(f"| {w} | {LABEL[case]} | {num(m)} ±{num(half)} | {pct(dt)} | {pct(dp)} |")
    return out


def verifier_section():
    path = RAW / "verifier" / "verifier.tsv"
    if not path.exists():
        return ["Not saved yet: `paper_data.py verifier DIR`."]
    rows = {(r["case"], r["object"]): r for r in read_tsv(path)}
    kernel = (RAW / "verifier" / "kernel.txt").read_text().strip()
    out = [f"Kernel {kernel}; objects of a macro_perf run, loaded with `figures/verifier_logs.sh`. Stack: "
           "the sum of the frames the verifier prints (`88+0+8`), the deepest call chain here.", "",
           "| workload | case | verifier instructions | states (total/peak) | stack (B) |", "|---|---|---|---|---|"]
    for w in WL:
        for case in ["plain"] + VARIANTS:
            r = rows.get((case, OBJ[w]))
            if r:
                out.append(f"| {w} | {LABEL[case]} | {r['processed_insns']} | {r['total_states']}/{r['peak_states']} "
                           f"| {r['stack_bytes']} (`{r['stack_depth']}`) |")
    top = max(rows.values(), key=lambda r: int(r["processed_insns"]))
    deep = max(rows.values(), key=lambda r: int(r["stack_bytes"]))
    out += ["", f"Largest: {top['processed_insns']} instructions ({100 * int(top['processed_insns']) / 1e6:.2f}% "
            f"of 1M), {deep['stack_bytes']} B of stack ({100 * int(deep['stack_bytes']) / 512:.1f}% of 512 B)."]
    return out


def code_section():
    d = RAW / "code"
    if not (d / "cognitive.csv").exists():
        return ["Not saved yet: `paper_data.py code`."]
    cog = {r["test"]: r for r in csv.DictReader((d / "cognitive.csv").open())}
    loc = {Path(k).parent.name + "/" + Path(k).stem: v["code"]
           for k, v in json.loads((d / "loc.json").read_text()).items() if k.endswith(".c")}
    out = [(d / "source.txt").read_text().strip() + ". Cognitive complexity: SonarSource's C analyzer "
           "(`softeng_perf/cognitive.py`); lines of code: `cloc`.", "",
           "| workload | cognitive, plain | cognitive, BONet | change | LOC, plain | LOC, BONet | change |",
           "|---|---|---|---|---|---|---|"]
    for w in WL:
        cp, cb = float(cog[OBJ[w]]["baseline_cognitive_complexity"]), float(cog[OBJ[w]]["framework_cognitive_complexity"])
        lp, lb = loc[f"baseline/{OBJ[w]}"], loc[f"framework/{OBJ[w]}"]
        out.append(f"| {w} | {cp:g} | {cb:g} | {pct(100 * (cb / cp - 1))} | {lp} | {lb} | {pct(100 * (lb / lp - 1))} |")
    tags = {r["workload"]: r for r in read_tsv(d / "tags.tsv")}
    out += ["", "### Table I: constructs removed from the plain programs", "",
            "The `// [..]` tags of `baseline/*.c` (`softeng_perf/README.md`, \"Table I\").", "",
            "| construct | tag | " + " | ".join(WL) + " |", "|---|---|" + "---|" * len(WL)]
    out += [f"| {name} | `{t}` | " + " | ".join(tags[w][t] for w in WL) + " |" for t, name in TAGS.items()]
    return out


def readme():
    pdr, runtime = paper_runs("pdr"), paper_runs("runtime")
    lines = [
        "# Paper results",
        "",
        "Every number of the paper's evaluation, recomputed from the raw data in `raw/`. "
        "Generated by `paper_data.py`: do not edit, run it again.",
        "",
        "- Δ pps: throughput change, `PDR_variant / PDR_plain − 1` (for times, `t_plain / t_variant − 1`).",
        "- Δ time: time per packet change, `t_variant / t_plain − 1` (for PDRs, `PDR_plain / PDR_variant − 1`).",
        "- ± is the 95% confidence interval (Student t over the repetitions; Welch for differences).",
        "- Cases: Plain eBPF (`baseline/`), Inlined APIs (`framework/`, `BNT_INLINE_ALL=1`), "
        "BONet (`framework/`, asm globals: the default), BONet with C globals, the kernel's own configuration.",
        "",
        "Updating: run the experiment, then `paper_data.py run [RUN_ID]`, `paper_data.py verifier DIR` "
        "or `paper_data.py code` (see the docstring), and commit `raw/` and this file.",
        "",
    ]
    bare = [r for r in pdr if r.plan.get("testbed", "fabric") == "bare-metal"]
    if bare:
        lines += ["## Forwarding throughput (Fig. 7)", ""] + pdr_section(bare[0]) + [""]
    if runtime:
        lines += ["## Run time per packet, on the NIC", ""] + runtime_section(runtime[0]) + [""]
        lines += ["## Run time per packet, BPF_PROG_TEST_RUN", ""] + micro_section(runtime[0]) + [""]
    lines += ["## Verifier resources (Fig. 8)", ""] + verifier_section() + [""]
    lines += ["## Application code (Fig. 6, Table I)", ""] + code_section() + [""]
    fabric = [r for r in pdr if r.plan.get("testbed", "fabric") == "fabric"]
    if fabric:
        lines += ["## Earlier testbed: FABRIC", "",
                  "Two VMs with ConnectX-6 VFs. Not the data of the first submission's Fig. 7 "
                  "(that run is lost); the last FABRIC run before the move to bare metal.", ""]
        lines += pdr_section(fabric[0]) + [""]
    lines += ["## Saved runs", "", "| run | method | testbed | commit | note |", "|---|---|---|---|---|"]
    for r in sorted(pdr + runtime, key=lambda r: r.id):
        lines.append(f"| `{r.id}` | {r.method} | {r.plan.get('testbed', 'fabric')} | "
                     f"`{r.meta.get('git_describe', '–')}` | {r.meta.get('note', '')} |")
    (HERE / "README.md").write_text("\n".join(lines) + "\n")
    print(f"wrote {(HERE / 'README.md').relative_to(VALIDATION.parent)}")


def main():
    args = sys.argv[1:]
    if args[:1] == ["run"]:
        save_run(args[1] if len(args) > 1 else None)
    elif args[:1] == ["verifier"] and len(args) == 2:
        save_verifier(args[1])
    elif args[:1] == ["code"]:
        save_code()
    elif args:
        sys.exit(__doc__)
    readme()


if __name__ == "__main__":
    main()
