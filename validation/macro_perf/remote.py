#!/usr/bin/env python3
"""Drives the PDR benchmark from this machine; nothing has to be done by hand
on the TRex or SUT machines.

  ./remote.py [-t TESTBED] setup     find the testbed (testbeds/TESTBED.yaml), install TRex and tools
  ./remote.py [-t TESTBED] topology  show the links and control path setup would use
  ./remote.py [-t TESTBED] trex start|stop|status
  ./remote.py build -p paper         build the objects of a profile (into build/)
  ./remote.py [-t TESTBED] run -p paper   build, push, check and start a run on TREX
  ./remote.py status [RUN]           progress of a run (default: the latest)
  ./remote.py fetch [RUN] [--wait]   download a run's data and rebuild the reports
  ./remote.py resume [RUN]           restart a stopped run where it left off
  ./remote.py stop [RUN]
  ./remote.py report [RUN]           rebuild the reports from downloaded data

TESTBED is a file in testbeds/ (default: $BENCH_TESTBED, else fabric). A run
remembers its testbed, so status, fetch, resume and stop need no -t.

Runs live in results/<run-id>/ here and in <home>/runs/<run-id>/ on the
machines. The run continues on TREX (in tmux) if this machine disconnects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = HERE / "results"
TESTBEDS = HERE / "testbeds"
TESTBED = os.environ.get("BENCH_TESTBED", "fabric")  # -t overrides it
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=30", "-o", "ServerAliveInterval=30"]
TREX_URL = "https://trex-tgn.cisco.com/trex/release/{version}.tar.gz"


# --------------------------------------------------------------------------
# Configuration

def load_yaml(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def merge(base: Dict[str, Any], over: Mapping[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in over.items():
        # cases and experiments replace the included ones as a whole.
        if isinstance(value, dict) and isinstance(out.get(key), dict) and key != "cases":
            out[key] = merge(out[key], value)
        else:
            out[key] = value
    return out


def load_profile(name: str) -> Dict[str, Any]:
    path = Path(name) if name.endswith(".yaml") else HERE / "profiles" / f"{name}.yaml"
    data = load_yaml(path)
    if "include" in data:
        data = merge(load_profile(str(path.parent / data.pop("include"))), data)
    data["name"] = path.stem if name.endswith(".yaml") else name
    return data


def testbed_path(name: Optional[str] = None) -> Path:
    return TESTBEDS / f"{name or TESTBED}.yaml"


def testbed(name: Optional[str] = None) -> Dict[str, Any]:
    path = testbed_path(name)
    if not path.exists():
        known = ", ".join(sorted(p.stem for p in TESTBEDS.glob("*.yaml")))
        raise SystemExit(f"no testbed {path.stem!r} (known: {known}); "
                         f"./remote.py -t {path.stem} setup creates it")
    return load_yaml(path)


def run_testbed(run_id: str) -> Dict[str, Any]:
    """The testbed a run was started on (runs from before testbeds/ were on FABRIC)."""
    plan = json.loads((RESULTS / run_id / "plan.json").read_text())
    return testbed(plan.get("testbed", "fabric"))


def net_settings(tb: Mapping[str, Any]) -> Dict[str, Any]:
    net = dict(tb["network"])
    trex_ports = tb["trex"]["ports"]
    net["tg_tx_mac"] = trex_ports[tb["trex"]["tx_port"]]["mac"]
    net["tg_rx_mac"] = trex_ports[tb["trex"]["rx_port"]]["mac"]
    return net


# --------------------------------------------------------------------------
# Remote commands

def ssh(host: str, command: str, check: bool = True, capture: bool = False,
        timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(["ssh", *SSH_OPTS, host, command], text=True,
                          capture_output=capture, timeout=timeout)
    if check and proc.returncode != 0:
        if capture:
            sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"{host}: command failed ({proc.returncode}): {command[:200]}")
    return proc


def out(host: str, command: str, timeout: Optional[int] = 120) -> str:
    return ssh(host, command, capture=True, timeout=timeout).stdout


def rsync(src: str, dst: str, *extra: str) -> None:
    cmd = ["rsync", "-a", "-e", "ssh " + " ".join(SSH_OPTS), *extra, src, dst]
    if subprocess.run(cmd).returncode != 0:
        raise SystemExit(f"rsync failed: {src} -> {dst}")


def say(message: str) -> None:
    print(f"== {message}", flush=True)


# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# setup: what the machines look like, and installing what the run needs

CONTROL_NET = ("192.168.250.1", "192.168.250.2", 30)

# Prints the facts discovery needs about one machine; the NICs listed are the
# PCI network devices other than the one with the default route.
FACTS = r'''
def=$(ip -o route get 1.1.1.1 2>/dev/null | grep -oP "dev \K\S+")
[ -n "$def" ] || def=$(ip -o -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP "dev \K\S+")
echo "user $(id -un)"; echo "home $HOME"; echo "nproc $(nproc)"
for a in $(ip -o addr show dev "$def" scope global | awk '{print $4}'); do echo "mgmt ${a%/*}"; done
for p in /sys/class/net/*/device; do
  d=$(basename "$(dirname "$p")"); [ "$d" = "$def" ] || [ ! -e "$p/numa_node" ] && continue
  ch=$(ethtool -l "$d" 2>/dev/null | awk '/Current/{c=1} c && /Combined/{print $2; exit}')
  echo "nic $d $(basename "$(readlink -f "$p")") $(cat /sys/class/net/$d/address) ${ch:-1} $(cat $p/numa_node)"
done
for n in /sys/devices/system/node/node[0-9]*; do echo "node ${n##*node} $(cat $n/cpulist)"; done
'''


def facts(host: str) -> Dict[str, Any]:
    f: Dict[str, Any] = {"mgmt": [], "nics": {}, "nodes": {}}
    for line in out(host, FACTS).splitlines():
        key, *rest = line.split()
        if key == "nic":
            name, pci, mac_addr, channels, numa = rest
            f["nics"][name] = {"iface": name, "pci": pci.split(":", 1)[1] if pci.count(":") == 2 else pci,
                               "mac": mac_addr, "channels": int(channels), "numa": max(0, int(numa))}
        elif key == "node":
            # The first range of the node's CPUs: its physical cores, before the SMT siblings.
            lo, _, hi = rest[1].split(",")[0].partition("-")
            f["nodes"][int(rest[0])] = list(range(int(lo), int(hi or lo) + 1))
        elif key == "mgmt":
            f["mgmt"].append(rest[0])
        else:
            f[key] = int(rest[0]) if key == "nproc" else rest[0]
    return f


def links(trex: str, sut: str, sut_nics: Mapping[str, Any]) -> List[Tuple[str, str]]:
    """(TREX iface, SUT iface) of every cable, from which SUT MAC answers an
    all-nodes ping on each TREX port."""
    ssh(sut, "for d in " + " ".join(sut_nics) + "; do sudo ip link set $d up; done")
    by_mac = {n["mac"]: name for name, n in sut_nics.items()}
    # 100G links take a few seconds to come up.
    script = ("for d in $(ls /sys/class/net); do [ -e /sys/class/net/$d/device ] && "
              "sudo ip link set $d up; done; sleep 8; "
              "for d in $(ls /sys/class/net); do [ -e /sys/class/net/$d/device ] || continue; "
              "ping -6 -c2 -W2 ff02::1%$d >/dev/null 2>&1; "
              "echo $d $(ip -6 neigh show dev $d | grep -oE 'lladdr [0-9a-f:]+' | awk '{print $2}'); done")
    found = []
    for line in out(trex, script).splitlines():
        iface, *macs = line.split()
        for peer in macs:
            if peer in by_mac:
                found.append((iface, by_mac[peer]))
    return found


def discover(existing: Mapping[str, Any]) -> Dict[str, Any]:
    """The testbed as found on the machines; values already in the testbed
    file are kept. With one cable, it carries the traffic both ways (the SUT
    redirects out of the port it received on)."""
    t_ssh = existing.get("trex", {}).get("ssh", "TREX")
    s_ssh = existing.get("sut", {}).get("ssh", "SUT")
    tf, sf = facts(t_ssh), facts(s_ssh)
    cables = sorted((pair for pair in links(t_ssh, s_ssh, sf["nics"]) if pair[0] in tf["nics"]),
                    key=lambda pair: tf["nics"][pair[0]]["pci"])
    if not cables:
        raise SystemExit("found no TREX-SUT link")
    (t_tx, s_rx), (t_rx, s_tx) = cables[0], cables[min(1, len(cables) - 1)]

    # The runner on TREX reaches the SUT over the management network if it
    # can, otherwise over a third link.
    control: Dict[str, Any] = {}
    for addr in sf["mgmt"]:
        target = f"[{addr}]" if ":" in addr else addr
        if ssh(t_ssh, f"timeout 5 bash -c '</dev/tcp/{target.strip('[]')}/22'",
               check=False).returncode == 0:
            control = {"sut_ip": addr}
            break
    if not control:
        if len(cables) < 3:
            raise SystemExit("TREX cannot reach the SUT's management address and there is no "
                             "third link for the control traffic")
        trex_ip, sut_ip, prefix = CONTROL_NET
        control = {"trex_iface": cables[2][0], "sut_iface": cables[2][1],
                   "trex_ip": trex_ip, "sut_ip": sut_ip, "prefix": prefix}

    # Everything on the NUMA node of the NICs. The SUT's RX queue and CPU have
    # the same number: XDP_REDIRECT transmits on the queue of the current CPU.
    socket = tf["nics"][t_tx]["numa"]
    cores = tf["nodes"][socket]
    sut_cores = sf["nodes"][sf["nics"][s_rx]["numa"]]
    rx_queue = min(sut_cores[0] + 2, sf["nics"][s_rx]["channels"] - 1)
    found = {
        "trex": {
            "ssh": t_ssh, "home": f"{tf['home']}/bonet-bench",
            "trex_dir": "/opt/trex/v3.08", "trex_version": "v3.08", "hugepages_2m": 2048,
            "ports": [{k: tf["nics"][i][k] for k in ("pci", "iface", "mac")}
                      for i in dict.fromkeys((t_tx, t_rx))],
            "tx_port": 0, "rx_port": 0 if t_tx == t_rx else 1, "socket": socket,
            "master_thread": cores[0], "latency_thread": cores[1],
            "threads": cores[2:], "port_bandwidth_gb": 100, "port_mtu": 1500,
        },
        "sut": {"ssh": s_ssh, "control": control, "user": sf["user"],
                "home": f"{sf['home']}/bonet-bench", "rx_queue": rx_queue, "rx_cpu": rx_queue},
        "network": {
            "sut_rx_iface": s_rx, "sut_rx_mac": sf["nics"][s_rx]["mac"],
            "sut_rx_ipv4": "10.8.0.2", "sut_rx_prefix": 24,
            "sut_rx_ipv6": "fd08::2", "sut_rx_ipv6_prefix": 64,
            "sut_tx_iface": s_tx, "sut_tx_mac": sf["nics"][s_tx]["mac"],
            "sut_tx_ipv4": "10.7.0.2", "sut_tx_prefix": 24,
            "sut_tx_ipv6": "fd07::2", "sut_tx_ipv6_prefix": 64,
            "tg_tx_ipv4": "10.8.0.1", "tg_tx_ipv6": "fd08::1",
            "tg_rx_ipv4": "10.7.0.1", "tg_rx_ipv6": "fd07::1",
        },
    }
    out_tb = merge(found, existing)
    if "control" in existing.get("sut", {}):
        out_tb["sut"]["control"] = existing["sut"]["control"]
    print("links (TREX -> SUT):")
    for i, (a, b) in enumerate(cables):
        role = ["traffic in" + (" and out" if len(cables) == 1 else ""), "traffic out",
                "control" if "trex_iface" in control else "unused"][min(i, 2)]
        print(f"  {a} ({tf['nics'][a]['pci']}) - {b}   {role}")
    print(f"control: TREX -> {sf['user']}@{out_tb['sut']['control']['sut_ip']}")
    return out_tb


TESTBED_HEADER = """\
# The machines the benchmark runs on: written by `./remote.py setup` from what
# it finds on TREX and SUT (the hosts named by trex.ssh and sut.ssh in
# ~/.ssh/config). Values here are kept: edit to override, and run
# `./remote.py -t <name> setup --rediscover` to look at the machines again
# (values still in the file win).
"""


def trex_cfg(tb: Mapping[str, Any]) -> str:
    t = tb["trex"]
    net = tb["network"]
    dests = [net["sut_rx_mac"], net["sut_tx_mac"]]
    ports = [t["ports"][t["tx_port"]], t["ports"][t["rx_port"]]]
    pcis = [repr(p["pci"]) for p in ports]
    if t["tx_port"] == t["rx_port"]:
        pcis[1] = "'dummy'"  # TRex wants ports in pairs; one cable sends and receives
    lines = ["- version: 2",
             f"  interfaces: [{', '.join(pcis)}]",
             f"  port_bandwidth_gb: {t['port_bandwidth_gb']}",
             f"  port_mtu: {t['port_mtu']}",
             "  port_info:"]
    for port, dest in zip(ports, dests):
        lines += [f"    - dest_mac: {dest}", f"      src_mac: {port['mac']}"]
    lines += ["  platform:",
              f"    master_thread_id: {t['master_thread']}",
              f"    latency_thread_id: {t['latency_thread']}",
              "    dual_if:",
              f"      - socket: {t.get('socket', 0)}",
              f"        threads: {list(t['threads'])}"]
    return "\n".join(lines) + "\n"


def intel_ports(t: Mapping[str, Any]) -> List[str]:
    return [p["pci"] for p in t["ports"]
            if out(t["ssh"], f"cat /sys/bus/pci/devices/0000:{p['pci']}/vendor").strip() == "0x8086"]


def cmd_setup(args: argparse.Namespace) -> None:
    path = testbed_path()
    existing = load_yaml(path) if path.exists() else {}
    if existing.get("trex", {}).get("ports") and not args.rediscover:
        # Once TRex has run, DPDK may hold the ports, and they cannot be found again.
        say(f"using {path.name} as it is (--rediscover to look at the machines again)")
        tb = existing
    else:
        if existing.get("trex", {}).get("ports") and trex_running(existing["trex"]):
            raise SystemExit("TRex is running and holds its ports: ./remote.py trex stop first")
        say("discovering the testbed")
        tb = discover(existing)
        path.write_text(TESTBED_HEADER + "\n" + yaml.safe_dump(tb, sort_keys=False, width=100))
        print(f"wrote {path}")
    t, s = tb["trex"], tb["sut"]
    apt = "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq"

    say("SUT packages")
    ssh(s["ssh"], f"sudo apt-get update -qq && {apt} iptables nftables ethtool tcpdump rsync "
                  "linux-tools-$(uname -r) linux-tools-common >/dev/null")
    say("TREX packages and mlx5 RDMA modules")
    ssh(t["ssh"], f"sudo apt-get update -qq && {apt} rdma-core ibverbs-utils tmux rsync "
                  "python3-yaml linux-modules-extra-$(uname -r) >/dev/null && "
                  "sudo modprobe -a mlx5_ib ib_uverbs")
    if intel_ports(t):
        # DPDK's ice driver reads the DDP package uncompressed; Ubuntu ships it zstd'ed.
        say("TREX Intel ports: vfio-pci and the ice DDP package")
        ssh(t["ssh"], f"{apt} linux-firmware zstd >/dev/null && "
                      "f=/lib/firmware/intel/ice/ddp/ice.pkg; "
                      "[ -e $f ] || sudo zstd -dqf $f.zst -o $f; sudo modprobe vfio-pci")

    if ssh(t["ssh"], f"test -x {t['trex_dir']}/t-rex-64", check=False).returncode != 0:
        url = TREX_URL.format(version=t["trex_version"])
        say(f"TRex {t['trex_version']}")
        parent = str(Path(t["trex_dir"]).parent)
        # trex-tgn.cisco.com leaves its intermediate CA out of the TLS chain: on
        # failure, fetch it from the address in the server certificate (it is
        # signed by a system root, so the download is still verified).
        host = url.split("/")[2]
        fetch = (f"curl -fsSL -o /tmp/trex.tgz {url} || {{ "
                 f"aia=$(echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null "
                 "| openssl x509 -noout -ext authorityInfoAccess | grep -oP 'CA Issuers - URI:\\K\\S+') && "
                 "curl -fsS \"$aia\" | openssl pkcs7 -inform der -print_certs > /tmp/trex-ca.pem && "
                 "cat /etc/ssl/certs/ca-certificates.crt /tmp/trex-ca.pem > /tmp/trex-bundle.pem && "
                 f"curl -fsSL --cacert /tmp/trex-bundle.pem -o /tmp/trex.tgz {url}; }}")
        if ssh(t["ssh"], f"{fetch} && sudo mkdir -p {parent} && "
                         f"sudo tar -C {parent} -xzf /tmp/trex.tgz && rm /tmp/trex.tgz",
               check=False).returncode != 0:
            raise SystemExit(f"downloading {url} on {t['ssh']} failed: install TRex in "
                             f"{t['trex_dir']} by hand, then run setup again")

    say("TRex config and hugepages")
    cfg = shlex.quote(trex_cfg(tb))
    node = f"/sys/devices/system/node/node{t.get('socket', 0)}/hugepages/hugepages-2048kB"
    ssh(t["ssh"], f"echo {cfg} | sudo tee /etc/trex_cfg.yaml >/dev/null && "
                  f"echo {t['hugepages_2m']} | sudo tee {node}/nr_hugepages >/dev/null")

    c = s["control"]
    if "trex_iface" in c:
        say("control link")
        ssh(t["ssh"], f"sudo ip addr replace {c['trex_ip']}/{c['prefix']} dev {c['trex_iface']}")
        ssh(s["ssh"], f"sudo ip addr replace {c['sut_ip']}/{c['prefix']} dev {c['sut_iface']}")
    say("ssh access from TREX to the SUT")
    pub = out(t["ssh"], "test -f ~/.ssh/id_ed25519 || ssh-keygen -q -t ed25519 -N '' "
                        "-f ~/.ssh/id_ed25519 -C bonet-bench; cat ~/.ssh/id_ed25519.pub").strip()
    ssh(s["ssh"], f"grep -qxF {shlex.quote(pub)} ~/.ssh/authorized_keys || "
                  f"echo {shlex.quote(pub)} >> ~/.ssh/authorized_keys")
    ssh(t["ssh"], f"ssh-keygen -F {c['sut_ip']} >/dev/null || "
                  f"ssh-keyscan -t ed25519 {c['sut_ip']} >> ~/.ssh/known_hosts 2>/dev/null; "
                  f"ssh -o BatchMode=yes {s['user']}@{c['sut_ip']} true")
    say("setup done; start TRex with ./remote.py trex start")


def cmd_topology(args: argparse.Namespace) -> None:
    path = testbed_path()
    existing = load_yaml(path) if path.exists() else {}
    if existing.get("trex", {}).get("ports") and trex_running(existing["trex"]):
        raise SystemExit("TRex is running and holds its ports: ./remote.py trex stop first")
    discover({k: {"ssh": v["ssh"]} for k, v in existing.items() if k in ("trex", "sut")})


def check_iommu(tb: Mapping[str, Any]) -> None:
    """Stops when a SUT port goes through IOMMU translation: every redirected
    packet would be mapped through it, capping all cases at the same rate."""
    net = tb["network"]
    script = "; ".join(f"g=/sys/class/net/{i}/device/iommu_group; [ -e $g ] && "
                       f"echo {i} $(basename $(readlink -f $g)) $(cat $g/type); true"
                       for i in dict.fromkeys((net["sut_rx_iface"], net["sut_tx_iface"])))
    bad = [line.split() for line in out(tb["sut"]["ssh"], script).splitlines()
           if line.split()[-1] != "identity"]
    if bad:
        raise SystemExit("SUT ports in IOMMU translation (" +
                         ", ".join(f"{i}: group {g} {t}" for i, g, t in bad) +
                         "): set them to passthrough first, see README, Testbed")


def trex_running(t: Mapping[str, Any]) -> bool:
    probe = (f"cd {t['trex_dir']}/automation/trex_control_plane/interactive && timeout 20 python3 -c "
             "'from trex_stl_lib.api import STLClient; c=STLClient(); c.connect(); "
             "print(c.get_server_version()[\"version\"]); c.disconnect()'")
    proc = ssh(t["ssh"], probe, check=False, capture=True, timeout=60)
    if proc.returncode == 0:
        print(f"TRex server up: {proc.stdout.strip()}")
        return True
    return False


def cmd_trex(args: argparse.Namespace) -> None:
    t = testbed()["trex"]
    if args.action == "stop":
        ssh(t["ssh"], "sudo tmux kill-session -t trex 2>/dev/null; sudo pkill -f '[_]t-rex-64'; true")
        return
    if args.action == "status":
        if not trex_running(t):
            print("TRex server not reachable")
            print(out(t["ssh"], "sudo tmux capture-pane -p -t trex 2>/dev/null | tail -20; true"))
        return
    if trex_running(t):
        return
    ssh(t["ssh"], "sudo tmux kill-session -t trex 2>/dev/null; true")
    for pci in intel_ports(t):
        # TRex picks vfio-pci only with iommu= on the kernel command line, and
        # its fallback (uio_pci_generic) cannot work with the IOMMU on.
        ssh(t["ssh"], f"cd {t['trex_dir']} && sudo ./dpdk_nic_bind.py -b vfio-pci 0000:{pci}")
    ssh(t["ssh"], f"sudo tmux new -d -s trex 'cd {t['trex_dir']} && "
                  "./t-rex-64 -i --no-ofed-check --cfg /etc/trex_cfg.yaml 2>&1 | tee /tmp/trex.log'")
    for _ in range(30):
        time.sleep(5)
        if trex_running(t):
            return
    print(out(t["ssh"], "tail -30 /tmp/trex.log"))
    raise SystemExit("TRex did not come up")


# --------------------------------------------------------------------------
# build

def clang_version(clang: str) -> str:
    return subprocess.run([clang, "--version"], capture_output=True, text=True,
                          check=True).stdout.splitlines()[0]


def experiment_cases(profile: Mapping[str, Any], experiment: Mapping[str, Any]) -> List[str]:
    return list(experiment.get("cases") or profile["cases"].keys())


def build(profile: Mapping[str, Any], dest: Path) -> Dict[str, Dict[str, str]]:
    """Builds every (case, program) object of the profile under dest/<case>/.
    Returns {experiment: {case: relative object path}}."""
    cfg = profile["build"]
    sysinc = f"/usr/include/{os.uname().machine}-linux-gnu"
    objects: Dict[str, Dict[str, str]] = {}
    hashes: Dict[str, str] = {}
    for experiment in profile["experiments"]:
        objects[experiment["name"]] = {}
        for case in experiment_cases(profile, experiment):
            spec = profile["cases"][case]
            if spec["hook"] == "kernel":
                continue
            name = f"{spec['hook']}_{experiment['program']}"
            src_dir = REPO / "validation" / spec["src"]
            rel = f"objs/{case}/{name}.o"
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            cmd = [cfg["clang"], *cfg["cflags"], f"-I{src_dir}", f"-I{sysinc}",
                   f"-I{REPO / 'src'}", *[f"-D{d}" for d in spec.get("defines", [])],
                   "-c", str(src_dir / f"{name}.c"), "-o", str(target)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                sys.stderr.write(proc.stderr)
                raise SystemExit(f"build failed: {case}/{name}")
            objects[experiment["name"]][case] = rel
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            hashes.setdefault(f"{name}:{digest}", case)
            if hashes[f"{name}:{digest}"] != case:
                print(f"warning: {case}/{name}.o is identical to "
                      f"{hashes[f'{name}:{digest}']}/{name}.o")
    return objects


def cmd_build(args: argparse.Namespace) -> None:
    profile = load_profile(args.profile)
    dest = HERE / "build" / profile["name"]
    shutil.rmtree(dest, ignore_errors=True)
    objects = build(profile, dest)
    for experiment, cases in objects.items():
        for case, rel in cases.items():
            print(f"{experiment:8} {case:12} {rel}")
    print(f"built with {clang_version(profile['build']['clang'])} into {dest}")


# --------------------------------------------------------------------------
# run

def git(*argv: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *argv], capture_output=True,
                          text=True).stdout.strip()


def run_ids() -> List[str]:
    if not RESULTS.exists():
        return []
    return sorted(p.name for p in RESULTS.iterdir() if (p / "plan.json").exists())


def resolve_run(run: Optional[str]) -> str:
    ids = run_ids()
    if run:
        matches = [i for i in ids if i == run or i.startswith(run)]
        if len(matches) != 1:
            raise SystemExit(f"no unique run matching {run!r}")
        return matches[0]
    if not ids:
        raise SystemExit("no runs in results/")
    return ids[-1]


def remote_dirs(tb: Mapping[str, Any], run_id: str) -> Dict[str, str]:
    return {"trex": f"{tb['trex']['home']}/runs/{run_id}",
            "sut": f"{tb['sut']['home']}/runs/{run_id}"}


def start_runner(tb: Mapping[str, Any], run_id: str) -> None:
    t = tb["trex"]
    rdir = remote_dirs(tb, run_id)["trex"]
    session = f"bench-{run_id}"
    ssh(t["ssh"], f"tmux kill-session -t {session} 2>/dev/null; "
                  f"tmux new -d -s {session} 'cd {rdir} && python3 bench/runner.py >> log.txt 2>&1'")
    print(f"runner started on {t['ssh']} in tmux session {session}")


def cmd_run(args: argparse.Namespace) -> None:
    tb = testbed()
    profile = load_profile(args.profile)
    t = tb["trex"]
    if not trex_running(t):
        raise SystemExit("TRex server is not running: ./remote.py trex start")
    check_iommu(tb)

    run_id = time.strftime("%Y%m%d-%H%M%S") + f"-{profile['name']}"
    if args.label:
        run_id += f"-{args.label}"
    local = RESULTS / run_id
    local.mkdir(parents=True)
    say(f"run {run_id}: building")
    objects = build(profile, local)

    dirs = remote_dirs(tb, run_id)
    experiments = []
    for experiment in profile["experiments"]:
        entry = dict(experiment)
        entry["cases"] = experiment_cases(profile, experiment)
        entry["objects"] = objects[experiment["name"]]
        experiments.append(entry)
    plan = {
        "run_id": run_id,
        "profile": profile["name"],
        "testbed": TESTBED,
        "seed": random.SystemRandom().randrange(1 << 30),
        "net": net_settings(tb),
        "trex": {"tx_port": t["tx_port"], "rx_port": t["rx_port"],
                 "api_path": f"{t['trex_dir']}/automation/trex_control_plane/interactive"},
        "sut": {"ssh": f"{tb['sut']['user']}@{tb['sut']['control']['sut_ip']}", "dir": dirs["sut"],
                "rx_queue": tb["sut"]["rx_queue"], "rx_cpu": tb["sut"]["rx_cpu"],
                "fixed_cpu_freq": bool(tb["sut"].get("fixed_cpu_freq", False))},
        "method": profile.get("method", "pdr"),
        # A testbed much faster or slower than the profile's range sets its own
        # (pdr:, runtime: in its file).
        "pdr": {**profile["pdr"], **tb.get("pdr", {})},
        "runtime": profile.get("runtime") and {**profile["runtime"], **tb.get("runtime", {})},
        "check": profile["check"],
        "cases": profile["cases"],
        "baseline_case": profile.get("baseline_case"),
        "experiments": experiments,
    }
    (local / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    diff = subprocess.run(["git", "-C", str(REPO), "diff", "HEAD"], capture_output=True).stdout
    hashes = {str(p.relative_to(local)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted((local / "objs").rglob("*.o"))}
    meta = {
        "run_id": run_id,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "profile": profile,
        "testbed": tb,
        "git_commit": git("rev-parse", "HEAD"),
        "git_describe": git("describe", "--always", "--dirty"),
        "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "git_diff_sha256": hashlib.sha256(diff).hexdigest() if diff else None,
        "compiler": clang_version(profile["build"]["clang"]),
        "objects_sha256": hashes,
        "trex_host": out(t["ssh"], f"uname -r; cat {t['trex_dir']}/VERSION 2>/dev/null; "
                                   "true").strip().splitlines(),
        "note": args.note or "",
    }
    (local / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    if diff:
        (local / "git.diff").write_bytes(diff)

    say("pushing")
    bench = HERE / "bench"
    ssh(t["ssh"], f"mkdir -p {dirs['trex']}")
    rsync(f"{bench}", f"{t['ssh']}:{dirs['trex']}/", "--exclude", "__pycache__")
    rsync(f"{local}/plan.json", f"{t['ssh']}:{dirs['trex']}/plan.json")
    ssh(tb["sut"]["ssh"], f"mkdir -p {dirs['sut']}")
    rsync(f"{local}/objs", f"{tb['sut']['ssh']}:{dirs['sut']}/")
    rsync(f"{bench}/sut.sh", f"{tb['sut']['ssh']}:{dirs['sut']}/sut.sh")
    start_runner(tb, run_id)
    print(f"follow with ./remote.py status {run_id}; download with ./remote.py fetch {run_id} --wait")


def remote_progress(tb: Mapping[str, Any], run_id: str) -> Dict[str, Any]:
    rdir = remote_dirs(tb, run_id)["trex"]
    text = out(tb["trex"]["ssh"], f"cat {rdir}/progress.json 2>/dev/null || echo '{{}}'")
    return json.loads(text or "{}")


def runner_alive(tb: Mapping[str, Any], run_id: str) -> bool:
    return ssh(tb["trex"]["ssh"], f"tmux has-session -t bench-{run_id} 2>/dev/null",
               check=False).returncode == 0


def cmd_status(args: argparse.Namespace) -> None:
    run_id = resolve_run(args.run)
    tb = run_testbed(run_id)
    p = remote_progress(tb, run_id)
    alive = runner_alive(tb, run_id)
    eta = p.get("eta_s")
    eta_text = f", about {eta / 3600:.1f} h left" if eta else ""
    print(f"{run_id}: {p.get('status', 'not started')} ({'running' if alive else 'no runner'}), "
          f"{p.get('done', 0)}/{p.get('total', '?')} measurements{eta_text}")
    if p.get("current"):
        print(f"  now: {p['current']}")
    if p.get("error"):
        print(f"  error: {p['error']}")
    rdir = remote_dirs(tb, run_id)["trex"]
    print(out(tb["trex"]["ssh"], f"tail -n {args.lines} {rdir}/log.txt 2>/dev/null; true"))


FETCHED = ["plan.json", "progress.json", "log.txt", "trials.csv", "searches.csv", "runtime.csv",
           "checks.csv", "sut-info.txt", "pcap"]


def fetch(tb: Mapping[str, Any], run_id: str) -> None:
    rdir = remote_dirs(tb, run_id)["trex"]
    local = RESULTS / run_id
    for name in FETCHED:
        if ssh(tb["trex"]["ssh"], f"test -e {rdir}/{name}", check=False).returncode == 0:
            rsync(f"{tb['trex']['ssh']}:{rdir}/{name}", f"{local}/")


def cmd_fetch(args: argparse.Namespace) -> None:
    run_id = resolve_run(args.run)
    tb = run_testbed(run_id)
    while True:
        fetch(tb, run_id)
        report(run_id)
        status = json.loads((RESULTS / run_id / "progress.json").read_text()).get("status") \
            if (RESULTS / run_id / "progress.json").exists() else None
        print(f"{run_id}: {status}")
        if not args.wait or status != "running":
            break
        if not runner_alive(tb, run_id):
            # it ended after this fetch: take what it wrote last
            fetch(tb, run_id)
            report(run_id)
            break
        time.sleep(args.every * 60)


def cmd_resume(args: argparse.Namespace) -> None:
    run_id = resolve_run(args.run)
    tb = run_testbed(run_id)
    if runner_alive(tb, run_id):
        raise SystemExit(f"{run_id} is still running")
    if not trex_running(tb["trex"]):
        raise SystemExit("TRex server is not running: ./remote.py trex start")
    check_iommu(tb)
    start_runner(tb, run_id)


def cmd_stop(args: argparse.Namespace) -> None:
    run_id = resolve_run(args.run)
    tb = run_testbed(run_id)
    ssh(tb["trex"]["ssh"], f"tmux send-keys -t bench-{run_id} C-c 2>/dev/null; true")
    print(f"sent interrupt to bench-{run_id}; it cleans the SUT before exiting")


def report(run_id: Optional[str]) -> None:
    python = HERE / ".venv" / "bin" / "python"
    argv = [str(python if python.exists() else sys.executable), str(HERE / "report.py")]
    if run_id:
        argv.append(run_id)
    subprocess.run(argv, check=True)


def cmd_report(args: argparse.Namespace) -> None:
    report(resolve_run(args.run) if args.run or not args.all else None)


# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-t", "--testbed", default=TESTBED,
                        help="testbeds/<name>.yaml (default: $BENCH_TESTBED, else fabric)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("setup")
    p.add_argument("--rediscover", action="store_true",
                   help="look at the machines again even if the testbed file has ports")
    p.set_defaults(func=cmd_setup)
    sub.add_parser("topology").set_defaults(func=cmd_topology)
    p = sub.add_parser("trex")
    p.add_argument("action", choices=["start", "stop", "status"])
    p.set_defaults(func=cmd_trex)
    p = sub.add_parser("build")
    p.add_argument("-p", "--profile", default="paper")
    p.set_defaults(func=cmd_build)
    p = sub.add_parser("run")
    p.add_argument("-p", "--profile", default="paper")
    p.add_argument("--label", help="suffix for the run id")
    p.add_argument("--note", help="free text stored in meta.json and shown in the report")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("status")
    p.add_argument("run", nargs="?")
    p.add_argument("-n", "--lines", type=int, default=15)
    p.set_defaults(func=cmd_status)
    p = sub.add_parser("fetch")
    p.add_argument("run", nargs="?")
    p.add_argument("--wait", action="store_true", help="keep fetching until the run ends")
    p.add_argument("--every", type=float, default=15, help="minutes between fetches (--wait)")
    p.set_defaults(func=cmd_fetch)
    p = sub.add_parser("resume")
    p.add_argument("run", nargs="?")
    p.set_defaults(func=cmd_resume)
    p = sub.add_parser("stop")
    p.add_argument("run", nargs="?")
    p.set_defaults(func=cmd_stop)
    p = sub.add_parser("report")
    p.add_argument("run", nargs="?")
    p.add_argument("--all", action="store_true", help="only rebuild the cumulative report")
    p.set_defaults(func=cmd_report)
    args = parser.parse_args()
    globals()["TESTBED"] = args.testbed
    args.func(args)


if __name__ == "__main__":
    main()
