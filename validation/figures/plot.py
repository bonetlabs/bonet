#!/usr/bin/env python3
"""Paper figures: plain eBPF, inlined APIs, BONet (asm globals) and kernel, in the style of Fig. 1/2.

See README.md for where each input comes from.
"""
import argparse
import csv
import json
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

WL = ["MMLF", "DNAT", "ENCAP"]
OBJ = {"MMLF": "xdp_mmlf", "DNAT": "xdp_static_dnat", "ENCAP": "xdp_ip6ip6_encap"}
CASES = {"plain": "plain", "inline": "inline", "globals-asm": "bonet", "kernel": "kernel"}

# Colors from the paper's own figures (Fig. 1/2 gray and blue, Fig. 5 green, Fig. 7 blue).
# BONet is the only solid series; the others carry a hatch, so they read without color.
TEXT, GRID, AXIS, EDGE = "#111111", "#E4E3DE", "#888780", "#4A4A46"
STYLE = {
    "plain":  dict(label="Plain eBPF",   fc="#DCDBD5", hc="#6E6D66", hatch="///"),
    "inline": dict(label="Inlined APIs", fc="#D6DEE7", hc="#3F5A75", hatch="..."),
    "bonet":  dict(label="BONet",        fc="#4C78A8", hc="#4C78A8", hatch=""),
    "kernel": dict(label="Kernel",       fc="#E0F3EE", hc="#009E73", hatch="oo"),
}
plt.rcParams.update({
    "font.family": "sans-serif", "font.sans-serif": ["Nimbus Sans", "TeX Gyre Heros", "Liberation Sans"],
    "font.size": 7, "text.color": TEXT, "axes.labelcolor": TEXT, "xtick.color": TEXT, "ytick.color": TEXT,
    "axes.edgecolor": AXIS, "axes.linewidth": 0.8, "xtick.major.size": 0, "ytick.major.size": 0,
    "ytick.major.pad": 3, "hatch.linewidth": 0.5, "pdf.fonttype": 42, "ps.fonttype": 42,
})


def summary(path):
    """macro_perf report/summary.csv: {series: ([mean per workload], [ci95 per workload])}."""
    out = {}
    for r in csv.DictReader(open(path)):
        if r["case"] in CASES:
            m, ci = ("mean_pps", "ci95_pps") if "mean_pps" in r else ("mean_ns", "ci95_ns")
            out.setdefault(CASES[r["case"]], {})[r["experiment"]] = (float(r[m]), float(r[ci]))
    return {c: ([v[w][0] for w in WL], [v[w][1] for w in WL]) for c, v in out.items()}


def verifier(logs):
    """bpftool -d prog load logs named <case>-<object>.log: processed insns and stack depth."""
    insns, stack = {}, {}
    for case, key in CASES.items():
        if key == "kernel":
            continue
        for w in WL:
            log = (logs / f"{case}-{OBJ[w]}.log").read_text()
            insns.setdefault(key, []).append(int(re.findall(r"processed (\d+) insns", log)[-1]))
            # One frame per subprogram ("88+0+8"): with globals the deepest chain is their sum here.
            depth = re.findall(r"stack depth ([\d+]+)", log)[-1]
            stack.setdefault(key, []).append(sum(map(int, depth.split("+"))))
    return insns, stack


def cognitive(path):
    """softeng_perf/cognitive.py's cognitive.csv."""
    rows = {r["test"]: r for r in csv.DictReader(open(path))}
    return {"plain": [float(rows[OBJ[w]]["baseline_cognitive_complexity"]) for w in WL],
            "bonet": [float(rows[OBJ[w]]["framework_cognitive_complexity"]) for w in WL]}


def loc(path):
    """cloc --by-file --json over baseline/ and framework/."""
    by_file = {Path(k).parent.name + "/" + Path(k).stem: v["code"]
               for k, v in json.load(open(path)).items() if k.endswith(".c")}
    return {"plain": [by_file[f"baseline/{OBJ[w]}"] for w in WL],
            "bonet": [by_file[f"framework/{OBJ[w]}"] for w in WL]}


def bars(ax, series, ylabel=None, scale=1.0, width=None):
    """series: (style key, values, ci or None); the bars of a group touch and fill 0.8 of it,
    unless width is given."""
    width = width or 0.8 / len(series)
    for j, (key, vals, ci) in enumerate(series):
        st = STYLE[key]
        x = [i + (j - (len(series) - 1) / 2) * width for i in range(len(WL))]
        y = [v / scale for v in vals]
        ax.bar(x, y, width, color=st["fc"], edgecolor=EDGE, hatch=st["hatch"], hatchcolor=st["hc"],
               lw=0.6, zorder=2)
        if ci:
            ax.errorbar(x, y, yerr=[c / scale for c in ci], fmt="none", ecolor="#333333",
                        elinewidth=0.7, capsize=1.8, capthick=0.7, zorder=3)
    ax.set_xlim(-0.5, len(WL) - 0.5)
    ax.set_xticks(range(len(WL)), WL)
    if ylabel:
        ax.set_ylabel(ylabel)
    ax.margins(y=0.08)
    ax.set_ylim(bottom=0)
    ax.grid(axis="y", color=GRID, lw=0.6, zorder=0)
    ax.set_axisbelow(True)


def legend(fig, keys):
    """Centered on the boxes (on the pair, with two), not on the figure: call it after margins()."""
    x = (min(a.get_position().x0 for a in fig.axes) + max(a.get_position().x1 for a in fig.axes)) / 2
    handles = [Patch(fc=STYLE[k]["fc"], ec=EDGE, hatch=STYLE[k]["hatch"], hatchcolor=STYLE[k]["hc"],
                     lw=0.6, label=STYLE[k]["label"]) for k in keys]
    fig.legend(handles=handles, loc="upper center", ncol=len(keys), frameon=False,
               handlelength=1.1, handleheight=1.1, handletextpad=0.5, columnspacing=1.4,
               bbox_to_anchor=(x, 1.0))


def margins(fig, bottom, top, **kw):
    """Margins in inches: every figure keeps its exact size, so at the same LaTeX width they all scale alike.
    The left one is just wide enough for the y labels of the first box, measured once drawn."""
    w, h = fig.get_size_inches()
    fig.subplots_adjust(left=0.5 / w, right=1 - 0.03 / w, bottom=bottom / h, top=1 - top / h, **kw)
    ax = fig.axes[0]
    labels = ax.get_position().x0 * w - ax.get_tightbbox(fig.canvas.get_renderer()).x0 / fig.dpi
    fig.subplots_adjust(left=(labels + 0.02) / w)


def save(fig, out, name):
    for ext in ("pdf", "png"):
        fig.savefig(out / f"{name}.{ext}", dpi=300)
    plt.close(fig)


def single(out, name, data, keys, ylabel, scale=1.0):
    fig, ax = plt.subplots(figsize=(3.5, 1.75))
    # The PDR's four bars per group set the width, so the figures drawn next to it match.
    bars(ax, [(k, *data[k]) for k in keys], ylabel, scale, width=0.2)
    margins(fig, bottom=0.2, top=0.26)
    legend(fig, keys)
    save(fig, out, name)


def pair(out, name, keys, left, right):
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 1.6))
    # The metric names each panel from above: a rotated y label would take a third of its width.
    for ax, (data, title) in zip(axes, (left, right)):
        bars(ax, [(k, data[k], None) for k in keys])
        ax.set_title(title, fontsize=7, pad=3)
    margins(fig, bottom=0.2, top=0.38, wspace=0.25)
    legend(fig, keys)
    save(fig, out, name)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pdr", type=Path, help="report/summary.csv of a macro_perf paper run")
    ap.add_argument("--runtime", type=Path, help="report/summary.csv of a macro_perf runtime run")
    ap.add_argument("--verifier", type=Path, help="directory of verifier logs (verifier_logs.sh)")
    ap.add_argument("--cognitive", type=Path, help="cognitive.csv of softeng_perf/cognitive.py")
    ap.add_argument("--loc", type=Path, help="cloc --by-file --json output")
    ap.add_argument("-o", "--out", type=Path, default=Path(__file__).parent / "results")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    if a.pdr:
        single(a.out, "pdr_wide", summary(a.pdr), ["plain", "inline", "bonet", "kernel"], "PDR (Mpps)", 1e6)
    if a.runtime:
        single(a.out, "time-per-packet", summary(a.runtime), ["plain", "inline", "bonet"],
               "Time per packet (ns)")
    if a.verifier:
        insns, stack = verifier(a.verifier)
        pair(a.out, "verifier-final-abs", ["plain", "inline", "bonet"],
             (insns, "Verifier instructions"), (stack, "Stack depth (B)"))
    if a.cognitive and a.loc:
        # Inline and global builds share the source: one BONet bar.
        pair(a.out, "cc_loc_half", ["plain", "bonet"],
             (cognitive(a.cognitive), "Cognitive complexity"), (loc(a.loc), "Lines of code"))


if __name__ == "__main__":
    main()
