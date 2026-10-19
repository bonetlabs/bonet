#!/usr/bin/env python3
"""PDR benchmark runner. Runs on the TRex machine, inside a run directory
prepared by ../remote.py (plan.json, objects, this directory).

For every repetition, every (experiment, case) pair is measured once, in an
order shuffled per repetition. Before each search the SUT output is checked
against the expected packets; a wrong or missing output stops the run.

Writes, in the run directory:
  trials.csv     every TRex trial
  searches.csv   one row per PDR search
  checks.csv     one row per correctness check
  progress.json  state for `remote.py status`
"""

from __future__ import annotations

import csv
import json
import os
import random
import shlex
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import packets  # noqa: E402

RUN_DIR = Path.cwd()
PLAN: Dict[str, Any] = json.loads((RUN_DIR / "plan.json").read_text())

TRIAL_FIELDS = ["run_id", "time", "experiment", "case", "rep", "phase", "step",
                "rate_pps", "trial", "kind", "duration_s", "tx_pkts", "rx_pkts",
                "delivery_ratio", "rx_pps"]
SEARCH_FIELDS = ["run_id", "experiment", "case", "rep", "order", "start", "end", "status",
                 "pdr_pps", "upper_pps", "lower_dr", "upper_dr", "steps", "trials"]
CHECK_FIELDS = ["run_id", "time", "experiment", "case", "rep", "verdict", "sent", "captured",
                "forwarded", "matched", "model", "kernel_forwarded", "rx_cpu",
                "prog_id", "prog_tag", "xlated_bytes", "jited_bytes", "detail"]


class CheckFailed(Exception):
    pass


# --------------------------------------------------------------------------
# Output files

def append_row(name: str, fields: Sequence[str], row: Mapping[str, Any]) -> None:
    path = RUN_DIR / name
    new = not path.exists()
    with path.open("a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        if new:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in fields})


def read_rows(name: str) -> List[Dict[str, str]]:
    path = RUN_DIR / name
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


PROGRESS: Dict[str, Any] = {}


def progress(**fields: Any) -> None:
    PROGRESS.update(fields)
    PROGRESS["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    tmp = RUN_DIR / "progress.json.tmp"
    tmp.write_text(json.dumps(PROGRESS, indent=2) + "\n")
    tmp.replace(RUN_DIR / "progress.json")


def log(message: str) -> None:
    print(time.strftime("%H:%M:%S ") + message, flush=True)


# --------------------------------------------------------------------------
# SUT

def sut_env(case: str, experiment: Mapping[str, Any]) -> Dict[str, str]:
    net = PLAN["net"]
    sut = PLAN["sut"]
    hook = PLAN["cases"][case]["hook"]
    env = {
        "SUT_RX_IFACE": net["sut_rx_iface"], "SUT_TX_IFACE": net["sut_tx_iface"],
        "SUT_RX_IPV4": net["sut_rx_ipv4"], "SUT_RX_PREFIX": net["sut_rx_prefix"],
        "SUT_TX_IPV4": net["sut_tx_ipv4"], "SUT_TX_PREFIX": net["sut_tx_prefix"],
        "SUT_RX_IPV6": net["sut_rx_ipv6"], "SUT_RX_IPV6_PREFIX": net["sut_rx_ipv6_prefix"],
        "SUT_TX_IPV6": net["sut_tx_ipv6"], "SUT_TX_IPV6_PREFIX": net["sut_tx_ipv6_prefix"],
        "TG_RX_IPV4": net["tg_rx_ipv4"], "TG_RX_IPV6": net["tg_rx_ipv6"],
        "TG_RX_MAC": net["tg_rx_mac"],
        "RX_QUEUE": sut["rx_queue"], "RX_CPU": sut["rx_cpu"],
        "HOOK": hook,
        "OBJ": f"{sut['dir']}/{experiment['objects'][case]}" if hook != "kernel" else "",
        "KERNEL_SETUP": experiment.get("kernel", "") if hook == "kernel" else "",
    }
    return {key: str(value) for key, value in env.items()}


def sut(action: str, env: Optional[Mapping[str, str]] = None) -> str:
    env = dict(env or sut_env(next(iter(PLAN["cases"])), PLAN["experiments"][0]))
    assign = " ".join(f"{key}={shlex.quote(value)}" for key, value in sorted(env.items()))
    remote = f"sudo env {assign} bash {PLAN['sut']['dir']}/sut.sh {action}"
    proc = subprocess.run(["ssh", "-o", "BatchMode=yes", PLAN["sut"]["ssh"], remote],
                          capture_output=True, text=True, timeout=120)
    if proc.stderr.strip():
        for line in proc.stderr.strip().splitlines():
            log(line)
    if proc.returncode != 0:
        raise RuntimeError(f"sut.sh {action} failed ({proc.returncode})")
    return proc.stdout


def sut_counters(env: Mapping[str, str]) -> Tuple[int, List[int]]:
    forwarded = 0
    irqs: List[int] = []
    for line in sut("counters", env).splitlines():
        parts = line.split()
        if parts[0] in ("IpForwDatagrams", "Ip6OutForwDatagrams"):
            forwarded += int(parts[1])
        elif parts[0] == "rx_irqs":
            irqs = [int(value) for value in parts[1:]]
    return forwarded, irqs


# --------------------------------------------------------------------------
# TRex

def trex_api():
    sys.path.insert(0, PLAN["trex"]["api_path"])
    from trex_stl_lib import api  # type: ignore
    return api


API = None
CLIENT = None


def client():
    global API, CLIENT
    if CLIENT is None:
        API = trex_api()
        CLIENT = API.STLClient(server="127.0.0.1")
        CLIENT.connect()
    return CLIENT


def ports() -> Tuple[int, int]:
    return int(PLAN["trex"]["tx_port"]), int(PLAN["trex"]["rx_port"])


def stats_packets(stats: Mapping[Any, Any], port: int, key: str) -> int:
    entry = stats.get(port, stats.get(str(port)))
    return int(entry[key])


def trial(pcap: Path, rate_pps: float, duration: float) -> Tuple[int, int]:
    c = client()
    tx, rx = ports()
    c.reset(ports=[tx, rx])
    c.add_streams([API.STLStream(packet=API.STLPktBuilder(pkt=str(pcap)),
                                 mode=API.STLTXCont())], ports=[tx])
    c.clear_stats()
    c.start(ports=[tx], mult=f"{rate_pps:.3f}pps", duration=duration)
    c.wait_on_traffic(ports=[tx, rx])
    time.sleep(1.0)  # let the last packets and counters arrive
    stats = c.get_stats(ports=[tx, rx])
    return stats_packets(stats, tx, "opackets"), stats_packets(stats, rx, "ipackets")


def capture_burst(pcap: Path, count: int, pps: float) -> List[bytes]:
    c = client()
    tx, rx = ports()
    c.reset(ports=[tx, rx])
    c.set_service_mode(ports=[rx], enabled=True)
    try:
        cap = c.start_capture(rx_ports=[rx], limit=max(1000, 4 * count))
        c.add_streams([API.STLStream(packet=API.STLPktBuilder(pkt=str(pcap)),
                                     mode=API.STLTXSingleBurst(total_pkts=count, pps=pps))],
                      ports=[tx])
        c.start(ports=[tx])
        c.wait_on_traffic(ports=[tx])
        time.sleep(1.0)
        out: List[Dict[str, Any]] = []
        c.stop_capture(cap["id"], output=out)
    finally:
        c.set_service_mode(ports=[rx], enabled=False)
    return [bytes(pkt["binary"]) for pkt in out]


# --------------------------------------------------------------------------
# Check and search

def check(experiment: Mapping[str, Any], case: str, rep: int, env: Mapping[str, str]) -> None:
    count = int(PLAN["check"]["packets"])
    hook = PLAN["cases"][case]["hook"]
    fwd_before, irq_before = sut_counters(env)
    captured = capture_burst(PCAPS[experiment["name"]], count, float(PLAN["check"]["pps"]))
    fwd_after, irq_after = sut_counters(env)

    result = packets.compare(FRAMES[experiment["name"]], captured, experiment, PLAN["net"],
                             case, count)
    kernel_forwarded = fwd_after - fwd_before
    deltas = [after - before for before, after in zip(irq_before, irq_after)]
    rx_cpu = max(range(len(deltas)), key=lambda i: deltas[i]) if any(deltas) else -1

    problems = []
    if not result["ok"]:
        problems.append(str(result["detail"]))
    if hook == "kernel" and kernel_forwarded < count:
        problems.append(f"kernel forwarded {kernel_forwarded} of {count} packets")
    if hook != "kernel" and kernel_forwarded >= count // 2:
        problems.append(f"the kernel forwarded {kernel_forwarded} of {count} packets: "
                        f"the {hook} program passed them up instead of redirecting")
    if rx_cpu != int(PLAN["sut"]["rx_cpu"]):
        problems.append(f"RX interrupts on CPU {rx_cpu}, expected {PLAN['sut']['rx_cpu']} "
                        f"(per-CPU deltas {deltas})")

    prog: Dict[str, Any] = {}
    if hook != "kernel":
        try:
            prog = json.loads(sut("prog", env) or "{}")
        except (RuntimeError, json.JSONDecodeError):
            prog = {}
        if not prog:
            problems.append("no program attached")

    verdict = "fail" if problems else "pass"
    append_row("checks.csv", CHECK_FIELDS, {
        "run_id": PLAN["run_id"], "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "experiment": experiment["name"], "case": case, "rep": rep, "verdict": verdict,
        "sent": count, "captured": result["captured"], "forwarded": result["forwarded"],
        "matched": result["matched"], "model": result["model"],
        "kernel_forwarded": kernel_forwarded, "rx_cpu": rx_cpu,
        "prog_id": prog.get("id", ""), "prog_tag": prog.get("tag", ""),
        "xlated_bytes": prog.get("bytes_xlated", ""), "jited_bytes": prog.get("bytes_jited", ""),
        "detail": "\n".join(problems),
    })
    if problems:
        raise CheckFailed(f"{experiment['name']}/{case}: " + "\n".join(problems))
    log(f"check {experiment['name']}/{case}: {result['matched']}/{count} as expected"
        f" (model {result['model']}, kernel forwarded {kernel_forwarded}, cpu {rx_cpu})")


def prepare(experiment: Mapping[str, Any], case: str) -> Dict[str, str]:
    env = sut_env(case, experiment)
    sut("prepare", env)
    time.sleep(float(PLAN["pdr"]["settle_s"]))
    return env


def search(experiment: Mapping[str, Any], case: str, rep: int, order: int) -> None:
    cfg = dict(PLAN["pdr"])
    cfg.update(experiment.get("pdr", {}))
    threshold = float(cfg["delivery_ratio"])
    duration = float(cfg["duration_s"])
    warmup = int(cfg["warmup_trials"])
    samples = int(cfg["samples"])
    pcap = PCAPS[experiment["name"]]
    base = {"run_id": PLAN["run_id"], "experiment": experiment["name"], "case": case, "rep": rep}
    trials = 0
    start = time.strftime("%Y-%m-%dT%H:%M:%S")

    def probe(rate: float, phase: str, step: int) -> float:
        nonlocal trials
        ratios = []
        for index in range(warmup + samples):
            tx, rx = trial(pcap, rate, duration)
            trials += 1
            ratio = min(rx, tx) / tx if tx else 0.0
            kind = "warmup" if index < warmup else "sample"
            if kind == "sample":
                ratios.append(ratio)
            append_row("trials.csv", TRIAL_FIELDS, dict(base, **{
                "time": time.strftime("%Y-%m-%dT%H:%M:%S"), "phase": phase, "step": step,
                "rate_pps": f"{rate:.1f}", "trial": index, "kind": kind,
                "duration_s": duration, "tx_pkts": tx, "rx_pkts": rx,
                "delivery_ratio": f"{ratio:.6f}", "rx_pps": f"{rx / duration:.1f}"}))
        return sum(ratios) / len(ratios)

    lower, upper = float(cfg["start_pps"]), float(cfg["max_pps"])
    lower_dr, upper_dr = 0.0, 0.0
    status = "ok"
    for attempt in range(3):
        lower_dr = probe(lower, "lower", attempt)
        if lower_dr >= threshold:
            break
    steps = 0
    if lower_dr < threshold:
        status = "lower_bound_failed"
        log(f"PDR {experiment['name']}/{case} rep {rep}: {lower:.0f} pps delivers "
            f"{lower_dr:.6f} < {threshold}")
    else:
        while upper - lower > float(cfg["window_pps"]):
            steps += 1
            rate = (upper + lower) / 2.0
            ratio = probe(rate, "probe", steps)
            if ratio < threshold:
                upper, upper_dr = rate, ratio
            else:
                lower, lower_dr = rate, ratio
            log(f"  {experiment['name']}/{case} rep {rep} step {steps}: {rate:,.0f} pps "
                f"dr={ratio:.6f} -> [{lower:,.0f}, {upper:,.0f}]")
        log(f"PDR {experiment['name']}/{case} rep {rep}: {lower:,.0f} pps")
    append_row("searches.csv", SEARCH_FIELDS, dict(base, **{
        "order": order, "start": start, "end": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": status, "pdr_pps": f"{lower:.1f}" if status == "ok" else "",
        "upper_pps": f"{upper:.1f}", "lower_dr": f"{lower_dr:.6f}",
        "upper_dr": f"{upper_dr:.6f}", "steps": steps, "trials": trials}))


# --------------------------------------------------------------------------

def schedule() -> List[Tuple[int, int, Mapping[str, Any], str]]:
    """(rep, order, experiment, case) for the whole run: per repetition, the
    experiments in a shuffled order, and within each the cases shuffled
    (the old runner's randomized block design)."""
    out = []
    for rep in range(int(PLAN["pdr"]["repetitions"])):
        rng = random.Random(f"{PLAN['seed']}-{rep}")
        blocks = []
        for experiment in PLAN["experiments"]:
            cases = list(experiment["cases"])
            rng.shuffle(cases)
            blocks.append([(experiment, case) for case in cases])
        rng.shuffle(blocks)
        order = 0
        for block in blocks:
            for experiment, case in block:
                out.append((rep, order, experiment, case))
                order += 1
    return out


PCAPS: Dict[str, Path] = {}
FRAMES: Dict[str, bytes] = {}


def main() -> int:
    frame_size = int(PLAN["pdr"]["frame_size"])
    (RUN_DIR / "pcap").mkdir(exist_ok=True)
    for experiment in PLAN["experiments"]:
        frame = packets.traffic_frame(experiment, PLAN["net"], frame_size)
        path = RUN_DIR / "pcap" / f"{experiment['name']}.pcap"
        packets.write_pcap(path, [frame])
        PCAPS[experiment["name"]], FRAMES[experiment["name"]] = path, frame

    plan = schedule()
    done = {(row["experiment"], row["case"], int(row["rep"])) for row in read_rows("searches.csv")}
    todo = [item for item in plan if (item[2]["name"], item[3], item[0]) not in done]
    previous = json.loads((RUN_DIR / "progress.json").read_text()) \
        if (RUN_DIR / "progress.json").exists() else {}
    PROGRESS.update(previous)
    progress(status="running", pid=os.getpid(), total=len(plan), done=len(plan) - len(todo),
             started=previous.get("started", time.strftime("%Y-%m-%dT%H:%M:%S")),
             error=None, current=None)
    log(f"run {PLAN['run_id']}: {len(todo)} of {len(plan)} searches to do")

    if not (RUN_DIR / "sut-info.txt").exists():
        (RUN_DIR / "sut-info.txt").write_text(sut("info"))
    started = time.time()
    try:
        if len(todo) == len(plan):
            # Every case, once, before spending hours on the searches.
            progress(current="initial checks")
            for experiment in PLAN["experiments"]:
                for case in experiment["cases"]:
                    check(experiment, case, -1, prepare(experiment, case))
        for index, (rep, order, experiment, case) in enumerate(todo):
            progress(current=f"rep {rep} {experiment['name']}/{case}")
            env = prepare(experiment, case)
            check(experiment, case, rep, env)
            search(experiment, case, rep, order)
            elapsed = time.time() - started
            progress(done=len(plan) - len(todo) + index + 1,
                     eta_s=int(elapsed / (index + 1) * (len(todo) - index - 1)))
        progress(status="done", current=None, eta_s=0)
        log("run complete")
        return 0
    except CheckFailed as exc:
        progress(status="check_failed", error=str(exc))
        log(f"CHECK FAILED, stopping: {exc}")
        return 3
    except KeyboardInterrupt:
        progress(status="stopped")
        log("stopped")
        return 130
    except Exception as exc:  # recorded for `remote.py status`
        progress(status="error", error=f"{exc}\n{traceback.format_exc()}")
        log(traceback.format_exc())
        return 1
    finally:
        try:
            sut("clean")
        except Exception as exc:  # noqa: BLE001
            log(f"clean failed: {exc}")
        if CLIENT is not None:
            CLIENT.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
