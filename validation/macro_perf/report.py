#!/usr/bin/env python3
"""Builds the reports from downloaded run data.

  report.py [RUN_ID]   the report of one run (default: every run), then the
                       cumulative report

Per run, results/<run>/report/:
  summary.md    run description, checks, PDR table, comparisons, figures
  summary.csv   one row per (workload, case): n, mean, std, 95% CI, deltas
  pdr.png/.pdf  Fig. 4 of the paper: mean PDR with 95% CI
  reps.png      every search, by repetition (drift, outliers)

results/REPORT.md, history.csv, history.png: every run, side by side.
"""

from __future__ import annotations

import csv
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

# Colors of the paper's Fig. 4, plus one for the asm globals.
COLORS = {
    "plain": "#4C72B0",
    "inline": "#E8A317",
    "globals-c": "#D62728",
    "globals-asm": "#7B4FA0",
    "kernel": "#55A868",
    "plain-tc": "#8DA9D4",
    "bonet-tc": "#F2C66D",
}
FALLBACK = ["#937860", "#DA8BC3", "#8C8C8C", "#64B5CD"]

# Two-sided 95% Student t quantiles.
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306,
       9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
       16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 25: 2.060, 30: 2.042,
       40: 2.021, 60: 2.000, 120: 1.980}


def t95(df: float) -> float:
    if df < 1:
        return float("nan")
    keys = sorted(T95)
    for key in keys:
        if df <= key:
            return T95[key]
    return 1.960


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})


def fmt(value: Optional[float], digits: int = 3) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "–"
    return f"{value:.{digits}f}"


def pm(delta: float, ci: Optional[float]) -> str:
    """A delta in %, with its CI when there is one."""
    if ci is None or math.isnan(ci):
        return pct(delta)
    return f"{pct(delta)} ±{fmt(ci, 1)}"


def pct(value: Optional[float]) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "–"
    return f"{value:+.1f}%"


class Run:
    def __init__(self, path: Path):
        self.path = path
        self.id = path.name
        self.plan = json.loads((path / "plan.json").read_text())
        self.meta = json.loads((path / "meta.json").read_text()) if (path / "meta.json").exists() else {}
        self.progress = json.loads((path / "progress.json").read_text()) \
            if (path / "progress.json").exists() else {}
        self.searches = read_csv(path / "searches.csv")
        self.checks = read_csv(path / "checks.csv")
        self.trials = read_csv(path / "trials.csv")
        self.cases: List[str] = list(self.plan["cases"])
        self.experiments: List[str] = [e["name"] for e in self.plan["experiments"]]
        self.baseline = self.plan.get("baseline_case") or self.cases[0]

    def label(self, case: str) -> str:
        return self.plan["cases"][case].get("label", case)

    def values(self, experiment: str, case: str) -> List[float]:
        return [float(r["pdr_pps"]) for r in self.searches
                if r["experiment"] == experiment and r["case"] == case and r["status"] == "ok"]

    def stats(self, experiment: str, case: str) -> Dict[str, Any]:
        values = self.values(experiment, case)
        n = len(values)
        failed = sum(1 for r in self.searches if r["experiment"] == experiment and
                     r["case"] == case and r["status"] != "ok")
        out: Dict[str, Any] = {"experiment": experiment, "case": case, "label": self.label(case),
                               "n": n, "failed_searches": failed}
        if not n:
            return out
        mean = statistics.mean(values)
        std = statistics.stdev(values) if n > 1 else 0.0
        half = t95(n - 1) * std / math.sqrt(n) if n > 1 else float("nan")
        out.update(mean_pps=mean, std_pps=std, ci95_pps=half, min_pps=min(values),
                   max_pps=max(values), cv_pct=100 * std / mean if mean else float("nan"))
        return out

    def delta(self, experiment: str, case: str, ref: str) -> Tuple[float, float]:
        """Mean difference case - ref in % of ref, with the Welch 95% CI half width."""
        a, b = self.values(experiment, case), self.values(experiment, ref)
        if len(a) < 1 or len(b) < 1:
            return float("nan"), float("nan")
        ma, mb = statistics.mean(a), statistics.mean(b)
        d = 100 * (ma - mb) / mb
        if len(a) < 2 or len(b) < 2:
            return d, float("nan")
        va, vb = statistics.variance(a) / len(a), statistics.variance(b) / len(b)
        se = math.sqrt(va + vb)
        if se == 0:
            return d, 0.0
        df = (va + vb) ** 2 / (va ** 2 / (len(a) - 1) + vb ** 2 / (len(b) - 1))
        return d, 100 * t95(df) * se / mb

    def status(self) -> str:
        return self.progress.get("status", "unknown")


def color(case: str, index: int) -> str:
    return COLORS.get(case, FALLBACK[index % len(FALLBACK)])


def style(ax) -> None:
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color("#888888")
    ax.tick_params(colors="#444444")
    ax.yaxis.grid(True, color="#e6e6e6", linewidth=0.8)
    ax.set_axisbelow(True)


def plot_pdr(run: Run, out: Path) -> None:
    exps, cases = run.experiments, run.cases
    width = 0.8 / len(cases)
    fig, ax = plt.subplots(figsize=(max(6.5, 2.2 * len(exps)), 3.4))
    for i, case in enumerate(cases):
        xs, ys, errs = [], [], []
        for j, exp in enumerate(exps):
            s = run.stats(exp, case)
            if not s.get("n"):
                continue
            xs.append(j - 0.4 + width * (i + 0.5))
            ys.append(s["mean_pps"] / 1e6)
            ci = s["ci95_pps"]
            errs.append(0 if math.isnan(ci) else ci / 1e6)
        bars = ax.bar(xs, ys, width * 0.92, yerr=errs, capsize=3, color=color(case, i),
                      edgecolor="#333333", linewidth=0.6, label=run.label(case),
                      error_kw={"elinewidth": 0.9, "ecolor": "#222222"})
        for bar, y, err in zip(bars, ys, errs):
            ax.text(bar.get_x() + bar.get_width() / 2, y + err + 0.02, f"{y:.2f}", ha="center",
                    va="bottom", fontsize=6.5, color="#333333", rotation=90)
    ax.set_xticks(range(len(exps)), exps)
    ax.set_ylabel("PDR (Mpps)")
    style(ax)
    top = ax.get_ylim()[1]
    ax.set_ylim(0, top * 1.12)
    ax.legend(ncol=len(cases), loc="upper center", bbox_to_anchor=(0.5, 1.2), frameon=False,
              fontsize=8, handlelength=1.2, columnspacing=1.0)
    fig.tight_layout()
    fig.savefig(out / "pdr.png", dpi=200)
    fig.savefig(out / "pdr.pdf")
    plt.close(fig)


def plot_reps(run: Run, out: Path) -> None:
    exps = run.experiments
    fig, axes = plt.subplots(1, len(exps), figsize=(3.4 * len(exps), 3.0), squeeze=False)
    for ax, exp in zip(axes[0], exps):
        for i, case in enumerate(run.cases):
            rows = sorted((int(r["rep"]), float(r["pdr_pps"]) / 1e6) for r in run.searches
                          if r["experiment"] == exp and r["case"] == case and r["status"] == "ok")
            if rows:
                ax.plot([r[0] for r in rows], [r[1] for r in rows], marker="o", markersize=4,
                        linewidth=1.2, color=color(case, i), label=run.label(case))
        ax.set_title(exp, fontsize=10)
        ax.set_xlabel("repetition")
        style(ax)
    axes[0][0].set_ylabel("PDR (Mpps)")
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, ncol=len(run.cases), loc="upper center", frameon=False, fontsize=8)
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    fig.savefig(out / "reps.png", dpi=160)
    plt.close(fig)


SUMMARY_FIELDS = ["run_id", "experiment", "case", "label", "n", "failed_searches", "mean_pps",
                  "std_pps", "ci95_pps", "cv_pct", "min_pps", "max_pps", "vs_baseline_pct",
                  "vs_baseline_ci95_pct", "vs_globals_c_pct", "vs_globals_c_ci95_pct",
                  "vs_kernel_x"]


def summary_rows(run: Run) -> List[Dict[str, Any]]:
    rows = []
    for exp in run.experiments:
        kernel = run.stats(exp, "kernel") if "kernel" in run.cases else {}
        for case in run.cases:
            s = run.stats(exp, case)
            s["run_id"] = run.id
            if s.get("n"):
                s["vs_baseline_pct"], s["vs_baseline_ci95_pct"] = run.delta(exp, case, run.baseline)
                if "globals-c" in run.cases:
                    s["vs_globals_c_pct"], s["vs_globals_c_ci95_pct"] = run.delta(exp, case, "globals-c")
                if kernel.get("n"):
                    s["vs_kernel_x"] = s["mean_pps"] / kernel["mean_pps"]
            rows.append(s)
    return rows


def duration(run: Run) -> str:
    times = [r["start"] for r in run.searches] + [r["end"] for r in run.searches]
    if not times:
        return "–"
    import datetime as dt
    first, last = dt.datetime.fromisoformat(min(times)), dt.datetime.fromisoformat(max(times))
    return f"{(last - first).total_seconds() / 3600:.1f} h"


def run_report(run: Run) -> None:
    out = run.path / "report"
    out.mkdir(exist_ok=True)
    rows = summary_rows(run)
    write_csv(out / "summary.csv", rows, SUMMARY_FIELDS)
    have_data = any(r.get("n") for r in rows)
    if have_data:
        plot_pdr(run, out)
        plot_reps(run, out)

    m, p = run.meta, run.progress
    sut_info = (run.path / "sut-info.txt").read_text().strip().splitlines() \
        if (run.path / "sut-info.txt").exists() else []
    pdr = run.plan["pdr"]
    lines = [f"# Run {run.id}", ""]
    if m.get("note"):
        lines += [m["note"], ""]
    lines += [
        f"- status: **{run.status()}**, {p.get('done', 0)}/{p.get('total', '?')} searches, "
        f"measured over {duration(run)}",
        f"- profile: `{run.plan['profile']}`; commit `{m.get('git_describe', '?')}`"
        + (" (uncommitted changes, see git.diff)" if m.get("git_dirty") else ""),
        f"- compiler: {m.get('compiler', '?')}, flags `{' '.join(m.get('profile', {}).get('build', {}).get('cflags', []))}`",
        f"- SUT: {', '.join(sut_info)}",
        f"- TRex host: {', '.join(m.get('trex_host', []))}",
        f"- method: PDR at delivery ratio {pdr['delivery_ratio']}, {pdr['frame_size']}-byte frames, "
        f"{pdr['duration_s']} s trials ({pdr['warmup_trials']} warm-up + {pdr['samples']} measured "
        f"per rate), search {pdr['start_pps']:,}–{pdr['max_pps']:,} pps to a "
        f"{pdr['window_pps']:,} pps window, {pdr['repetitions']} repetitions in shuffled order; "
        f"RX on one queue pinned to CPU {run.plan['sut']['rx_cpu']}",
        "",
    ]
    if p.get("error"):
        lines += ["## Error", "", "```", str(p["error"]).strip(), "```", ""]

    failed = [c for c in run.checks if c["verdict"] != "pass"]
    lines += ["## Checks", ""]
    if not run.checks:
        lines += ["No checks recorded.", ""]
    elif failed:
        lines += [f"**{len(failed)} of {len(run.checks)} checks failed.**", ""]
        for c in failed:
            lines += [f"- {c['experiment']}/{c['case']} rep {c['rep']}:", "", "```",
                      c["detail"].strip(), "```", ""]
    else:
        lines += [f"All {len(run.checks)} checks passed: before every search, "
                  f"{run.plan['check']['packets']} packets came back exactly as the workload's "
                  "model says, through the XDP path (or the kernel for the kernel case), with the "
                  "RX interrupts on the pinned CPU.", ""]
    progs = {}
    for c in run.checks:
        if c.get("xlated_bytes"):
            progs[(c["experiment"], c["case"])] = (c["xlated_bytes"], c["jited_bytes"], c["prog_tag"])
    if progs:
        lines += ["Attached programs (as loaded on the SUT, main program only):", "",
                  "| workload | case | xlated B | jited B | tag |", "|---|---|---:|---:|---|"]
        for (exp, case), (x, j, tag) in sorted(progs.items()):
            lines.append(f"| {exp} | {run.label(case)} | {x} | {j} | `{tag}` |")
        lines.append("")

    show_c = "globals-c" in run.cases and run.baseline != "globals-c"
    if have_data:
        lines += ["## PDR", "", "![PDR](pdr.png)", "",
                  f"| workload | case | n | mean Mpps | ±95% CI | CV | vs {run.label(run.baseline)} |"
                  + (" vs Global (C) |" if show_c else "")
                  + (" × kernel |" if "kernel" in run.cases else ""),
                  "|---|---|---:|---:|---:|---:|---:|"
                  + ("---:|" if show_c else "")
                  + ("---:|" if "kernel" in run.cases else "")]
        for r in rows:
            if not r.get("n"):
                lines.append(f"| {r['experiment']} | {r['label']} | 0 | – | – | – | – |"
                             + (" – |" if show_c else "")
                             + (" – |" if "kernel" in run.cases else ""))
                continue
            vb = "" if r["case"] == run.baseline else \
                pm(r['vs_baseline_pct'], r['vs_baseline_ci95_pct'])
            line = (f"| {r['experiment']} | {r['label']} | {r['n']} | {fmt(r['mean_pps'] / 1e6)} "
                    f"| {fmt(r['ci95_pps'] / 1e6)} | {fmt(r['cv_pct'], 1) + '%' if r['n'] > 1 else '–'} | {vb} |")
            if show_c:
                vc = "" if r["case"] == "globals-c" else \
                    pm(r.get('vs_globals_c_pct'), r.get('vs_globals_c_ci95_pct'))
                line += f" {vc} |"
            if "kernel" in run.cases:
                line += f" {fmt(r.get('vs_kernel_x'), 2)} |"
            lines.append(line)
        lines += ["", "Deltas are differences of means, with the Welch 95% confidence interval.", ""]

        if {"globals-asm", "globals-c"} <= set(run.cases):
            lines += ["## Asm globals against C globals", ""]
            for exp in run.experiments:
                d, ci = run.delta(exp, "globals-asm", "globals-c")
                if math.isnan(d):
                    lines.append(f"- {exp}: no data")
                    continue
                verdict = "one search each, no interval" if math.isnan(ci) else \
                    "no significant difference" if abs(d) <= ci else \
                    ("faster" if d > 0 else "slower")
                lines.append(f"- {exp}: {pm(d, ci)} ({verdict})")
            lines.append("")
        others = [c for c in run.cases if c not in (run.baseline, "kernel")]
        if others:
            lines += [f"## Loss against {run.label(run.baseline)}", ""]
            for case in others:
                losses = [run.delta(exp, case, run.baseline)[0] for exp in run.experiments]
                losses = [x for x in losses if not math.isnan(x)]
                if losses:
                    lines.append(f"- {run.label(case)}: worst {pct(min(losses))}, "
                                 f"per workload {', '.join(pct(x) for x in losses)}")
            lines.append("")
        lines += ["## Every search", "", "![repetitions](reps.png)", ""]

    lines += ["## Files", "",
              "- `../trials.csv`: every TRex trial (rate, tx/rx packets, delivery ratio)",
              "- `../searches.csv`: every PDR search (result, bounds, steps)",
              "- `../checks.csv`: every correctness check",
              "- `summary.csv`: the table above",
              "- `../meta.json`, `../plan.json`: configuration, commit, object hashes",
              "- `../objs/`: the objects measured; `../log.txt`: the runner's log", ""]
    (out / "summary.md").write_text("\n".join(lines))


# --------------------------------------------------------------------------
# Cumulative

HISTORY_FIELDS = ["run_id", "profile", "status", "commit", "dirty", "note"] + SUMMARY_FIELDS[1:]


def cumulative(runs: List[Run]) -> None:
    rows: List[Dict[str, Any]] = []
    for run in runs:
        for r in summary_rows(run):
            if not r.get("n"):
                continue
            r.update(profile=run.plan["profile"], status=run.status(),
                     commit=run.meta.get("git_describe", ""), dirty=run.meta.get("git_dirty", ""),
                     note=run.meta.get("note", ""))
            rows.append(r)
    write_csv(RESULTS / "history.csv", rows, HISTORY_FIELDS)

    lines = ["# macro_perf: all runs", "",
             "Generated by report.py from results/*/; one section per profile. "
             "Each run's own report is in `<run>/report/summary.md`.", ""]
    profiles = sorted({r.plan["profile"] for r in runs})
    for profile in profiles:
        pruns = [r for r in runs if r.plan["profile"] == profile]
        lines += [f"## Profile `{profile}`", "",
                  "| run | status | searches | commit | note |", "|---|---|---:|---|---|"]
        for run in pruns:
            lines.append(f"| [{run.id}]({run.id}/report/summary.md) | {run.status()} | "
                         f"{run.progress.get('done', 0)}/{run.progress.get('total', '?')} | "
                         f"`{run.meta.get('git_describe', '')}` | {run.meta.get('note', '')} |")
        lines.append("")
        with_data = [r for r in pruns if r.searches]
        if not with_data:
            continue
        last = with_data[-1]
        img = f"history-{profile}.png"
        plot_history(with_data, RESULTS / img)
        lines += [f"![history]({img})", "",
                  "Mean PDR (Mpps) per run:", ""]
        header = "| workload | case | " + " | ".join(r.id for r in with_data) + " |"
        lines += [header, "|---|---|" + "---:|" * len(with_data)]
        for exp in last.experiments:
            for case in last.cases:
                cells = []
                for run in with_data:
                    s = run.stats(exp, case) if case in run.cases and exp in run.experiments else {}
                    cells.append(("–" if not s.get("n") else fmt(s["mean_pps"] / 1e6)
                                  + ("" if math.isnan(s["ci95_pps"]) else f" ±{fmt(s['ci95_pps'] / 1e6)}")))
                lines.append(f"| {exp} | {last.label(case)} | " + " | ".join(cells) + " |")
        if {"globals-asm", "globals-c"} <= set(last.cases):
            lines += ["", "Asm globals against C globals (difference of means, Welch 95% CI):", "",
                      "| workload | " + " | ".join(r.id for r in with_data) + " |",
                      "|---|" + "---:|" * len(with_data)]
            for exp in last.experiments:
                cells = []
                for run in with_data:
                    d, ci = run.delta(exp, "globals-asm", "globals-c") \
                        if {"globals-asm", "globals-c"} <= set(run.cases) else (float("nan"),) * 2
                    cells.append("–" if math.isnan(d) else pm(d, ci))
                lines.append(f"| {exp} | " + " | ".join(cells) + " |")
        lines.append("")
    (RESULTS / "REPORT.md").write_text("\n".join(lines))


def plot_history(runs: List[Run], out: Path) -> None:
    last = runs[-1]
    exps = last.experiments
    fig, axes = plt.subplots(1, len(exps), figsize=(3.4 * len(exps), 3.0), squeeze=False)
    for ax, exp in zip(axes[0], exps):
        for i, case in enumerate(last.cases):
            xs, ys, es = [], [], []
            for k, run in enumerate(runs):
                s = run.stats(exp, case) if case in run.cases and exp in run.experiments else {}
                if s.get("n"):
                    xs.append(k)
                    ys.append(s["mean_pps"] / 1e6)
                    es.append(0 if math.isnan(s["ci95_pps"]) else s["ci95_pps"] / 1e6)
            if xs:
                ax.errorbar(xs, ys, yerr=es, marker="o", markersize=4, linewidth=1.2,
                            capsize=2, color=color(case, i), label=last.label(case))
        ax.set_title(exp, fontsize=10)
        ax.set_xticks(range(len(runs)), [str(k + 1) for k in range(len(runs))])
        ax.set_xlabel("run")
        style(ax)
    axes[0][0].set_ylabel("PDR (Mpps)")
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, ncol=len(last.cases), loc="upper center", frameon=False, fontsize=8)
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    fig.savefig(out, dpi=160)
    plt.close(fig)


def main() -> None:
    runs = [Run(p) for p in sorted(RESULTS.glob("*/plan.json")) for p in [p.parent]]
    selected = [r for r in runs if len(sys.argv) < 2 or r.id == sys.argv[1]]
    for run in selected:
        run_report(run)
        print(f"report: {run.path / 'report' / 'summary.md'}")
    cumulative(runs)
    print(f"report: {RESULTS / 'REPORT.md'}")


if __name__ == "__main__":
    main()
