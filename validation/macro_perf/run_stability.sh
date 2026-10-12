#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${1:-config.stability.yaml}"
RUNS=3

cd "${SCRIPT_DIR}"

echo "=== Stability validation: ${RUNS} runs of ${CONFIG} ==="

for i in $(seq 1 "${RUNS}"); do
    echo ""
    echo "--- Run ${i}/${RUNS} ---"
    python3 runner.py --config "${CONFIG}"
done

echo ""
echo "=== Results ==="
python3 - <<'EOF'
import json, glob, os, sys

results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
files = sorted(glob.glob(os.path.join(results_dir, "results-*.json")))
if not files:
    print("No result files found in results/")
    sys.exit(1)

# Only consider the most recent RUNS files
files = files[-3:]

rows = []
for path in files:
    with open(path) as f:
        d = json.load(f)
    for exp_name in d.get("cases", {}).get("framework", {}).keys():
        fw_entry = d["cases"].get("framework", {}).get(exp_name, {})
        bl_entry = d["cases"].get("baseline", {}).get(exp_name, {})
        if not fw_entry or not bl_entry:
            continue
        fw = fw_entry.get("pdr_pps_mean") or fw_entry.get("rx_pps_mean")
        bl = bl_entry.get("pdr_pps_mean") or bl_entry.get("rx_pps_mean")
        fw_std = fw_entry.get("pdr_pps_std") or fw_entry.get("rx_pps_std") or 0
        bl_std = bl_entry.get("pdr_pps_std") or bl_entry.get("rx_pps_std") or 0
        if fw and bl:
            delta = (fw - bl) / bl * 100
            rows.append((os.path.basename(path), exp_name, fw, fw_std, bl, bl_std, delta))

if not rows:
    print("No comparable framework/baseline entries found.")
    sys.exit(1)

col_w = max(len(r[0]) for r in rows)
print(f"{'file':<{col_w}}  {'experiment':<30}  {'framework (Mpps)':>18}  {'baseline (Mpps)':>18}  {'delta':>8}")
print("-" * (col_w + 30 + 18 + 18 + 8 + 12))
deltas_by_exp = {}
for fname, exp, fw, fw_std, bl, bl_std, delta in rows:
    print(f"{fname:<{col_w}}  {exp:<30}  {fw/1e6:>7.3f} ±{fw_std/1e6:>6.3f}  {bl/1e6:>7.3f} ±{bl_std/1e6:>6.3f}  {delta:>+7.2f}%")
    deltas_by_exp.setdefault(exp, []).append(delta)

print()
print("Summary (delta spread across runs):")
for exp, deltas in deltas_by_exp.items():
    spread = max(deltas) - min(deltas)
    print(f"  {exp}: min={min(deltas):+.2f}%  max={max(deltas):+.2f}%  spread={spread:.2f}pp")
EOF
