#!/usr/bin/env python3
"""
IPv4 forwarding benchmark runner for BONet.

The runner keeps the SRPerf shape: configure the SUT for one forwarding
behavior, generate traffic with TRex, collect MRR or PDR, then move to the next
behavior. The behaviors here are BONet framework XDP, handwritten baseline
XDP, and plain kernel forwarding.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import posixpath
import random
import shlex
import socket
import statistics
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import yaml
except ImportError as exc:  # pragma: no cover - reached only on target hosts.
    print("Missing dependency: PyYAML. Install with `python3 -m pip install pyyaml`.", file=sys.stderr)
    raise SystemExit(2) from exc


VALID_CASES = ("framework", "framework-inlined", "baseline", "kernel", "framework-tc", "baseline-tc")
DEFAULT_OBJECTS = {
    "framework": "validation/framework/xdp_fib4_forward.o",
    # framework-inlined is the same library built with BNT_INLINE_ALL=1 (no global
    # subprograms). XDP-only: on TC BNT_INLINE_ALL is forced to 1 anyway, so a
    # framework-inlined-tc case would be byte-identical to framework-tc.
    "framework-inlined": "validation/framework_inlined/xdp_fib4_forward.o",
    "baseline": "validation/baseline/xdp_fib4_forward.o",
    "framework-tc": "validation/framework/tc_fib4_forward.o",
    "baseline-tc": "validation/baseline/tc_fib4_forward.o",
}


def merged_objects(config: Mapping[str, Any], experiment: Optional[Mapping[str, Any]] = None) -> Dict[str, str]:
    objects: Dict[str, str] = dict(DEFAULT_OBJECTS)
    objects.update({key: str(value) for key, value in config.get("objects", {}).items()})
    if experiment:
        objects.update({key: str(value) for key, value in experiment.get("objects", {}).items()})
    return objects


def config_for_experiment(config: Mapping[str, Any], experiment: Mapping[str, Any]) -> Dict[str, Any]:
    merged = dict(config)
    merged["objects"] = merged_objects(config, experiment)
    merged["_experiment"] = experiment
    return merged


def configured_objects(config: Mapping[str, Any], experiments: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
    objects: Dict[str, str] = {}
    for case, obj in merged_objects(config).items():
        objects[case] = obj
    for experiment in experiments:
        for case, obj in merged_objects(config, experiment).items():
            objects[f"{experiment.get('name', 'experiment')}:{case}"] = obj
    return objects

TREX_SYMBOLS: Optional[Tuple[Any, Any, Any, Any, Any]] = None


@dataclass
class TrexRun:
    requested_tx_rate: str
    tx_packets: int
    rx_packets: int
    duration: float
    warnings: Optional[Any] = None

    @property
    def delivery_ratio(self) -> float:
        if self.tx_packets <= 0:
            return 0.0
        rx_packets = min(self.rx_packets, self.tx_packets)
        return rx_packets / float(self.tx_packets)

    @property
    def rx_pps(self) -> float:
        if self.duration <= 0:
            return 0.0
        return self.rx_packets / float(self.duration)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_tx_rate": self.requested_tx_rate,
            "tx_packets": self.tx_packets,
            "rx_packets": self.rx_packets,
            "duration": self.duration,
            "delivery_ratio": self.delivery_ratio,
            "rx_pps": self.rx_pps,
            "warnings": self.warnings,
        }


def load_config(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    if not isinstance(config, dict):
        raise ValueError("Top-level YAML value must be a mapping")
    return config


def require(mapping: Mapping[str, Any], key: str, section: str) -> Any:
    value = mapping.get(key)
    if value is None or value == "":
        raise ValueError(f"Missing required config key `{section}.{key}`")
    return value


def as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(item) for item in value]


def local_path(value: str, base_dir: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return base_dir / path


def quote_cmd(cmd: Sequence[Any]) -> str:
    return " ".join(shlex.quote(str(part)) for part in cmd)


def run_cmd(cmd: Sequence[Any], dry_run: bool) -> None:
    print("+ " + quote_cmd(cmd))
    if dry_run:
        return
    subprocess.run([str(part) for part in cmd], check=True)


def run_sut_command(config: Mapping[str, Any], argv: Sequence[str], dry_run: bool, sudo: bool = False) -> None:
    sut = config.get("sut", {})
    mode = sut.get("mode", "local")

    if mode == "local":
        cmd: List[str] = []
        if sudo:
            cmd.append("sudo")
        cmd.extend(argv)
        run_cmd(cmd, dry_run)
        return

    if mode != "ssh":
        raise ValueError("`sut.mode` must be `local` or `ssh`")

    ssh_cfg = sut.get("ssh", {})
    host = require(ssh_cfg, "host", "sut.ssh")
    user = ssh_cfg.get("user")
    target = f"{user}@{host}" if user else str(host)

    remote = quote_cmd(argv)
    if sudo:
        remote = "sudo " + remote

    cmd = ["ssh"]
    if ssh_cfg.get("key"):
        cmd.extend(["-i", str(ssh_cfg["key"])])
    if ssh_cfg.get("port"):
        cmd.extend(["-p", str(ssh_cfg["port"])])
    cmd.extend([target, remote])
    run_cmd(cmd, dry_run)


def object_parent_and_name(root: str, object_path: str) -> Tuple[str, str]:
    if object_path.startswith("/"):
        return posixpath.dirname(object_path), posixpath.basename(object_path)
    full = posixpath.join(root.rstrip("/"), object_path)
    return posixpath.dirname(full), posixpath.basename(full)


def build_objects(config: Mapping[str, Any], cases: Iterable[str], experiments: Iterable[Mapping[str, Any]], dry_run: bool) -> None:
    build_cfg = config.get("build", {})
    if build_cfg.get("enabled", True) is False:
        return

    root = str(require(config.get("sut", {}), "bonet_root", "sut"))
    objects = configured_objects(config, experiments)
    built: set[str] = set()

    for key, obj in objects.items():
        case = key.rsplit(":", 1)[-1]
        if case == "kernel" or case not in cases or obj in built:
            continue
        workdir, target = object_parent_and_name(root, obj)
        run_sut_command(config, ["make", "-C", workdir, target], dry_run)
        built.add(obj)


def env_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def build_sut_env(config: Mapping[str, Any]) -> Dict[str, str]:
    sut = config.get("sut", {})
    net = config.get("network", {})
    xdp = config.get("xdp", {})

    objects = merged_objects(config)

    root = str(require(sut, "bonet_root", "sut"))
    traffic_dst_ipv4 = str(require(net, "traffic_dst_ipv4", "network"))
    traffic_dst_prefix = str(require(net, "traffic_dst_prefix", "network"))
    traffic_dst_route = str(ipaddress.ip_network(f"{traffic_dst_ipv4}/{traffic_dst_prefix}", strict=False))
    env = {
        "BONET_ROOT": root,
        "SUT_RCV_IFACE": str(require(net, "sut_rx_iface", "network")),
        "SUT_RCV_IPV4": str(require(net, "sut_rx_ipv4", "network")),
        "SUT_RCV_PLEN": str(require(net, "sut_rx_prefix", "network")),
        "SUT_RCV_MAC": env_value(net.get("sut_rx_mac", "")),
        "SUT_SND_IFACE": str(require(net, "sut_tx_iface", "network")),
        "SUT_SND_IPV4": str(require(net, "sut_tx_ipv4", "network")),
        "SUT_SND_PLEN": str(require(net, "sut_tx_prefix", "network")),
        "SUT_SND_MAC": env_value(net.get("sut_tx_mac", "")),
        "TG_RX_IPV4": str(require(net, "tg_rx_ipv4", "network")),
        "TG_RX_MAC": str(require(net, "tg_rx_mac", "network")),
        "TRAFFIC_DST_IPV4": traffic_dst_ipv4,
        "TRAFFIC_DST_PLEN": traffic_dst_prefix,
        "TRAFFIC_DST_ROUTE": traffic_dst_route,
        "FRAMEWORK_OBJ": str(objects["framework"]),
        "FRAMEWORK_INLINED_OBJ": str(objects.get("framework-inlined", "")),
        "BASELINE_OBJ": str(objects["baseline"]),
        "FRAMEWORK_TC_OBJ": str(objects.get("framework-tc", "")),
        "BASELINE_TC_OBJ": str(objects.get("baseline-tc", "")),
        "XDP_MODE": str(xdp.get("mode", "xdp")),
        "XDP_SECTION": str(xdp.get("section", "xdp")),
        "TC_SECTION": str(config.get("tc", {}).get("section", "tc")),
        "SUT_TC_SETTLE_SECONDS": str(config.get("sut", {}).get("tc_settle_seconds", 3)),
        "SUT_RCV_IRQ_MIN": env_value(net.get("sut_rx_irq_min", "")),
        "SUT_RCV_IRQ_MAX": env_value(net.get("sut_rx_irq_max", "")),
        "SUT_RCV_IRQ_CORE": env_value(net.get("sut_rx_irq_core", "")),
        "SUT_SND_IRQ_MIN": env_value(net.get("sut_tx_irq_min", "")),
        "SUT_SND_IRQ_MAX": env_value(net.get("sut_tx_irq_max", "")),
        "SUT_SND_IRQ_CORE": env_value(net.get("sut_tx_irq_core", "")),
    }
    experiment = config.get("_experiment", {})
    env["TRAFFIC_SRC_IPV4"] = env_value(net.get("traffic_src_ipv4", net.get("tg_tx_ipv4", "")))
    env["PCAP_DST_IPV4"] = env_value(str(experiment.get("pcap_dst_ipv4", traffic_dst_ipv4)))
    env["PCAP_DST_PLEN"] = env_value(str(experiment.get("pcap_dst_prefix", traffic_dst_prefix)))
    env["EXPERIMENT_NAME"] = env_value(str(experiment.get("name", "")))
    env["EXPERIMENT_IP_VERSION"] = env_value(str(experiment.get("ip_version", "4")))
    env["SUT_RCV_IPV6"] = env_value(net.get("sut_rx_ipv6", ""))
    env["SUT_RCV_IPV6_PLEN"] = env_value(str(net.get("sut_rx_ipv6_prefix", 64)))
    env["SUT_SND_IPV6"] = env_value(net.get("sut_tx_ipv6", ""))
    env["SUT_SND_IPV6_PLEN"] = env_value(str(net.get("sut_tx_ipv6_prefix", 64)))
    env["TG_RX_IPV6"] = env_value(net.get("tg_rx_ipv6", ""))
    traffic_dst_ipv6 = net.get("traffic_dst_ipv6", "")
    traffic_dst_ipv6_prefix = str(net.get("traffic_dst_ipv6_prefix", 64))
    traffic_dst_ipv6_route = ""
    if traffic_dst_ipv6:
        traffic_dst_ipv6_route = str(ipaddress.ip_network(
            f"{traffic_dst_ipv6}/{traffic_dst_ipv6_prefix}", strict=False))
    env["TRAFFIC_DST_IPV6"] = env_value(traffic_dst_ipv6)
    env["TRAFFIC_DST_IPV6_PLEN"] = env_value(traffic_dst_ipv6_prefix)
    env["TRAFFIC_DST_IPV6_ROUTE"] = env_value(traffic_dst_ipv6_route)
    env["TRAFFIC_SRC_IPV6"] = env_value(net.get("traffic_src_ipv6", net.get("tg_tx_ipv6", "")))
    env["PCAP_DST_IPV6"] = env_value(str(experiment.get("pcap_dst_ipv6", traffic_dst_ipv6)))
    env["PCAP_DST_IPV6_PLEN"] = env_value(str(experiment.get("pcap_dst_ipv6_prefix", traffic_dst_ipv6_prefix)))
    return env


def run_sut_action(config: Mapping[str, Any], action: str, case: str, dry_run: bool) -> None:
    sut = config.get("sut", {})
    root = str(require(sut, "bonet_root", "sut"))
    use_sudo = bool(sut.get("sudo", True))
    env = build_sut_env(config)
    assignments = [f"{key}={value}" for key, value in sorted(env.items())]

    if sut.get("mode", "local") == "local":
        script = posixpath.join(root.rstrip("/"), "validation/macro_perf/sut_forwarding.sh")
        cmd: List[str] = []
        if use_sudo:
            cmd.extend(["sudo", "env"])
        else:
            cmd.append("env")
        cmd.extend(assignments)
        cmd.extend(["bash", script, action, case])
        run_cmd(cmd, dry_run)
        return

    if sut.get("mode") != "ssh":
        raise ValueError("`sut.mode` must be `local` or `ssh`")

    ssh_cfg = sut.get("ssh", {})
    host = require(ssh_cfg, "host", "sut.ssh")
    user = ssh_cfg.get("user")
    target = f"{user}@{host}" if user else str(host)

    remote_env = " ".join(shlex.quote(item) for item in assignments)
    sudo = "sudo " if use_sudo else ""
    remote = (
        f"cd {shlex.quote(root)} && "
        f"{sudo}env {remote_env} bash validation/macro_perf/sut_forwarding.sh "
        f"{shlex.quote(action)} {shlex.quote(case)}"
    )

    cmd = ["ssh"]
    if ssh_cfg.get("key"):
        cmd.extend(["-i", str(ssh_cfg["key"])])
    if ssh_cfg.get("port"):
        cmd.extend(["-p", str(ssh_cfg["port"])])
    cmd.extend([target, remote])
    run_cmd(cmd, dry_run)


def mac_to_bytes(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address `{value}`")
    return bytes(int(part, 16) for part in parts)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) + data[idx + 1]
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def write_ipv6_udp_pcap(path: Path, network: Mapping[str, Any], frame_size: int, compute_udp_csum: bool = False) -> None:
    if frame_size < 62:
        raise ValueError("frame size must be at least 62 bytes for Ethernet/IPv6/UDP")

    dst_mac = mac_to_bytes(str(require(network, "sut_rx_mac", "network")))
    src_mac = mac_to_bytes(str(require(network, "tg_tx_mac", "network")))
    src_ip = socket.inet_pton(socket.AF_INET6, str(network.get("traffic_src_ipv6",
                                                                require(network, "tg_tx_ipv6", "network"))))
    dst_ip = socket.inet_pton(socket.AF_INET6, str(require(network, "traffic_dst_ipv6", "network")))

    udp_src = int(network.get("udp_src_port", 12345))
    udp_dst = int(network.get("udp_dst_port", 54321))
    hop_limit = int(network.get("traffic_ttl", 64))
    payload_len = frame_size - 14 - 40 - 8
    payload = bytes((idx % 251 for idx in range(payload_len)))

    udp_len = 8 + payload_len
    udp = struct.pack("!HHHH", udp_src, udp_dst, udp_len, 0)
    if compute_udp_csum:
        pseudo = src_ip + dst_ip + struct.pack("!I", udp_len) + b'\x00\x00\x00\x11'
        raw_csum = checksum(pseudo + udp + payload)
        udp = struct.pack("!HHHH", udp_src, udp_dst, udp_len, raw_csum if raw_csum != 0 else 0xffff)

    ip6 = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        udp_len,
        socket.IPPROTO_UDP,
        hop_limit,
        src_ip,
        dst_ip,
    )

    eth = dst_mac + src_mac + struct.pack("!H", 0x86DD)
    frame = eth + ip6 + udp + payload
    if len(frame) != frame_size:
        raise AssertionError(f"internal pcap size mismatch: {len(frame)} != {frame_size}")

    path.parent.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        handle.write(struct.pack("<IIII", now, 0, len(frame), len(frame)))
        handle.write(frame)


def write_ipv4_udp_pcap(path: Path, network: Mapping[str, Any], frame_size: int, compute_udp_csum: bool = False) -> None:
    if frame_size < 42:
        raise ValueError("frame size must be at least 42 bytes for Ethernet/IPv4/UDP")

    dst_mac = mac_to_bytes(str(require(network, "sut_rx_mac", "network")))
    src_mac = mac_to_bytes(str(require(network, "tg_tx_mac", "network")))
    src_ip = socket.inet_aton(str(network.get("traffic_src_ipv4", require(network, "tg_tx_ipv4", "network"))))
    dst_ip = socket.inet_aton(str(require(network, "traffic_dst_ipv4", "network")))

    udp_src = int(network.get("udp_src_port", 12345))
    udp_dst = int(network.get("udp_dst_port", 54321))
    ttl = int(network.get("traffic_ttl", 64))
    payload_len = frame_size - 14 - 20 - 8
    payload = bytes((idx % 251 for idx in range(payload_len)))

    udp_len = 8 + payload_len
    udp = struct.pack("!HHHH", udp_src, udp_dst, udp_len, 0)
    if compute_udp_csum:
        pseudo = src_ip + dst_ip + b'\x00\x11' + struct.pack('!H', udp_len)
        raw_csum = checksum(pseudo + udp + payload)
        udp = struct.pack("!HHHH", udp_src, udp_dst, udp_len, raw_csum if raw_csum != 0 else 0xffff)

    total_len = 20 + len(udp) + len(payload)
    ip_wo_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        int(network.get("traffic_ip_id", 1)) & 0xffff,
        0,
        ttl,
        socket.IPPROTO_UDP,
        0,
        src_ip,
        dst_ip,
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        int(network.get("traffic_ip_id", 1)) & 0xffff,
        0,
        ttl,
        socket.IPPROTO_UDP,
        checksum(ip_wo_csum),
        src_ip,
        dst_ip,
    )

    eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
    frame = eth + ip + udp + payload
    if len(frame) != frame_size:
        raise AssertionError(f"internal pcap size mismatch: {len(frame)} != {frame_size}")

    path.parent.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        handle.write(struct.pack("<IIII", now, 0, len(frame), len(frame)))
        handle.write(frame)


def ensure_trex_api(api_path: Optional[str]) -> Tuple[Any, Any, Any, Any, Any]:
    global TREX_SYMBOLS
    if TREX_SYMBOLS is not None:
        return TREX_SYMBOLS
    if api_path:
        sys.path.insert(0, api_path)
    try:
        from trex_stl_lib.api import STLClient, STLError, STLPktBuilder, STLStream, STLTXCont
    except ImportError as exc:
        raise RuntimeError(
            "Cannot import TRex STL API. Set `trex.api_path` in the YAML config."
        ) from exc
    TREX_SYMBOLS = (STLClient, STLError, STLPktBuilder, STLStream, STLTXCont)
    return TREX_SYMBOLS


def stat_value(stats: Mapping[str, Any], names: Sequence[str]) -> int:
    for name in names:
        if name in stats:
            return int(stats[name])
    raise KeyError(f"None of the expected TRex stats keys were present: {', '.join(names)}")


def port_stats(stats: Mapping[str, Any], port: int) -> Mapping[str, Any]:
    for key in (port, str(port)):
        value = stats.get(key)
        if isinstance(value, Mapping):
            return value
    raise KeyError(f"TRex stats did not include port {port}")


def run_trex_trial(trex_cfg: Mapping[str, Any], pcap: Path, rate: str) -> TrexRun:
    STLClient, STLError, STLPktBuilder, STLStream, STLTXCont = ensure_trex_api(trex_cfg.get("api_path"))

    server = str(trex_cfg.get("server", "127.0.0.1"))
    tx_port = int(trex_cfg.get("tx_port", 0))
    rx_port = int(trex_cfg.get("rx_port", 1))
    duration = float(trex_cfg.get("duration", 10))
    settle = float(trex_cfg.get("stats_settle_seconds", 1))
    all_ports = [tx_port, rx_port]

    client = STLClient(server=server)
    try:
        client.connect()
        client.reset(ports=all_ports)
        streams = [STLStream(packet=STLPktBuilder(pkt=str(pcap)), mode=STLTXCont())]
        client.add_streams(streams, ports=[tx_port])
        client.clear_stats()
        client.start(ports=[tx_port], mult=rate, duration=duration)
        client.wait_on_traffic(ports=all_ports)
        warnings = client.get_warnings()
        if settle > 0:
            time.sleep(settle)
        try:
            stats = client.get_stats(ports=all_ports)
            tx_packets = stat_value(port_stats(stats, tx_port), ("opackets", "tx_pkts", "tx_total_packets"))
            rx_packets = stat_value(port_stats(stats, rx_port), ("ipackets", "rx_pkts", "rx_total_packets"))
        except Exception:
            tx_stats = client.get_xstats(tx_port)
            rx_stats = client.get_xstats(rx_port)
            tx_packets = stat_value(
                tx_stats,
                ("tx_total_packets", "opackets", "tx_pkts", "tx_good_packets", "tx_q0_packets"),
            )
            rx_packets = stat_value(
                rx_stats,
                ("rx_total_packets", "ipackets", "rx_pkts", "rx_good_packets", "rx_q0_packets"),
            )
    except STLError as exc:
        raise RuntimeError(f"TRex run failed: {exc}") from exc
    finally:
        client.disconnect()

    return TrexRun(
        requested_tx_rate=rate,
        tx_packets=tx_packets,
        rx_packets=rx_packets,
        duration=duration,
        warnings=warnings or None,
    )


def run_rate(trex_cfg: Mapping[str, Any], pcap: Path, rate: str) -> List[TrexRun]:
    warmup = int(trex_cfg.get("warmup", 1))
    samples = int(trex_cfg.get("samples", 1))
    runs: List[TrexRun] = []

    for index in range(warmup + samples):
        result = run_trex_trial(trex_cfg, pcap, rate)
        if index >= warmup:
            runs.append(result)
    return runs


def summarize_runs(runs: Sequence[TrexRun]) -> Dict[str, Any]:
    delivery_ratios = [run.delivery_ratio for run in runs]
    rx_pps = [run.rx_pps for run in runs]
    return {
        "delivery_ratio_mean": statistics.mean(delivery_ratios) if delivery_ratios else 0.0,
        "delivery_ratio_std": statistics.stdev(delivery_ratios) if len(delivery_ratios) > 1 else 0.0,
        "rx_pps_mean": statistics.mean(rx_pps) if rx_pps else 0.0,
        "rx_pps_std": statistics.stdev(rx_pps) if len(rx_pps) > 1 else 0.0,
        "runs": [run.to_dict() for run in runs],
    }


def run_mrr(trex_cfg: Mapping[str, Any], experiment: Mapping[str, Any], pcap: Path) -> Dict[str, Any]:
    tx_rate = str(experiment.get("tx_rate", "100%"))
    repetitions = int(experiment.get("runs", 1))
    runs: List[Dict[str, Any]] = []

    for iteration in range(repetitions):
        print(f"MRR {experiment['name']} run {iteration}")
        sample_runs = run_rate(trex_cfg, pcap, tx_rate)
        runs.append(summarize_runs(sample_runs))

    values = [run["rx_pps_mean"] for run in runs]
    return {
        "rate": "mrr",
        "tx_rate": tx_rate,
        "rx_pps_mean": statistics.mean(values) if values else 0.0,
        "rx_pps_std": statistics.stdev(values) if len(values) > 1 else 0.0,
        "iterations": runs,
    }


def run_pdr(trex_cfg: Mapping[str, Any], experiment: Mapping[str, Any], pcap: Path) -> Dict[str, Any]:
    repetitions = int(experiment.get("runs", 1))
    lower_start = float(experiment.get("starting_tx_rate_pps", 100000.0))
    upper_start = float(experiment.get("max_tx_rate_pps", experiment.get("line_rate_pps", 12253000.0)))
    epsilon = float(experiment.get("ndr_window_pps", 500.0))
    threshold = float(experiment.get("delivery_ratio", 0.995))

    all_runs: List[Dict[str, Any]] = []
    for repetition in range(repetitions):
        print(f"PDR {experiment['name']} run {repetition}")
        lower = lower_start
        upper = upper_start
        upper_dr = 0.0
        iterations: List[Dict[str, Any]] = []

        lower_dr = 0.0
        for _attempt in range(3):
            lower_dr = summarize_runs(run_rate(trex_cfg, pcap, str(lower)))["delivery_ratio_mean"]
            if lower_dr >= threshold:
                break

        if lower_dr < threshold:
            raise RuntimeError(
                f"PDR lower bound {lower} pps has delivery ratio {lower_dr}, below {threshold}"
            )

        while abs(upper - lower) > epsilon:
            current = (upper + lower) / 2.0
            summary = summarize_runs(run_rate(trex_cfg, pcap, str(current)))
            current_dr = summary["delivery_ratio_mean"]

            if current_dr < threshold:
                upper = current
                upper_dr = current_dr
            else:
                lower = current
                lower_dr = current_dr

            iteration = {
                "lower_bound_pps": lower,
                "lower_bound_delivery_ratio": lower_dr,
                "upper_bound_pps": upper,
                "upper_bound_delivery_ratio": upper_dr,
                "probed_pps": current,
                "probed_delivery_ratio": current_dr,
                "threshold": threshold,
                "runs": summary["runs"],
            }
            iterations.append(iteration)
            print(
                "PDR search "
                f"[{lower:.3f}/{lower_dr:.6f}, {upper:.3f}/{upper_dr:.6f}] "
                f"probe={current:.3f} dr={current_dr:.6f} threshold={threshold:.6f}"
            )

        all_runs.append(
            {
                "lower_bound_pps": lower,
                "lower_bound_delivery_ratio": lower_dr,
                "upper_bound_pps": upper,
                "upper_bound_delivery_ratio": upper_dr,
                "iterations": iterations,
            }
        )

    values = [run["lower_bound_pps"] for run in all_runs]
    return {
        "rate": "pdr",
        "delivery_ratio": threshold,
        "pdr_pps_mean": statistics.mean(values) if values else 0.0,
        "pdr_pps_std": statistics.stdev(values) if len(values) > 1 else 0.0,
        "iterations": all_runs,
    }


def run_mrr_one(trex_cfg: Mapping[str, Any], experiment: Mapping[str, Any], pcap: Path) -> Dict[str, Any]:
    tx_rate = str(experiment.get("tx_rate", "100%"))
    return summarize_runs(run_rate(trex_cfg, pcap, tx_rate))


def run_pdr_one(trex_cfg: Mapping[str, Any], experiment: Mapping[str, Any], pcap: Path) -> Dict[str, Any]:
    lower = float(experiment.get("starting_tx_rate_pps", 100000.0))
    upper = float(experiment.get("max_tx_rate_pps", experiment.get("line_rate_pps", 12253000.0)))
    epsilon = float(experiment.get("ndr_window_pps", 500.0))
    threshold = float(experiment.get("delivery_ratio", 0.995))
    upper_dr = 0.0
    iterations: List[Dict[str, Any]] = []

    lower_dr = 0.0
    for _attempt in range(3):
        lower_dr = summarize_runs(run_rate(trex_cfg, pcap, str(lower)))["delivery_ratio_mean"]
        if lower_dr >= threshold:
            break
    if lower_dr < threshold:
        raise RuntimeError(
            f"PDR lower bound {lower} pps has delivery ratio {lower_dr}, below {threshold}"
        )

    while abs(upper - lower) > epsilon:
        current = (upper + lower) / 2.0
        summary = summarize_runs(run_rate(trex_cfg, pcap, str(current)))
        current_dr = summary["delivery_ratio_mean"]
        if current_dr < threshold:
            upper = current
            upper_dr = current_dr
        else:
            lower = current
            lower_dr = current_dr
        iterations.append({
            "lower_bound_pps": lower,
            "lower_bound_delivery_ratio": lower_dr,
            "upper_bound_pps": upper,
            "upper_bound_delivery_ratio": upper_dr,
            "probed_pps": current,
            "probed_delivery_ratio": current_dr,
            "threshold": threshold,
            "runs": summary["runs"],
        })
        print(
            "PDR search "
            f"[{lower:.3f}/{lower_dr:.6f}, {upper:.3f}/{upper_dr:.6f}] "
            f"probe={current:.3f} dr={current_dr:.6f} threshold={threshold:.6f}"
        )

    return {
        "lower_bound_pps": lower,
        "lower_bound_delivery_ratio": lower_dr,
        "upper_bound_pps": upper,
        "upper_bound_delivery_ratio": upper_dr,
        "iterations": iterations,
    }


def _make_partial_entry(experiment: Mapping[str, Any]) -> Dict[str, Any]:
    rate = str(experiment.get("rate", "mrr")).lower()
    entry: Dict[str, Any] = {"_partial": True, "rate": rate, "iterations": []}
    if rate == "mrr":
        entry["tx_rate"] = str(experiment.get("tx_rate", "100%"))
    elif rate == "pdr":
        entry["delivery_ratio"] = float(experiment.get("delivery_ratio", 0.995))
    return entry


def _finalize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    rate = entry["rate"]
    iterations = entry["iterations"]
    if rate == "mrr":
        values = [it["rx_pps_mean"] for it in iterations]
        return {
            "rate": "mrr",
            "tx_rate": entry["tx_rate"],
            "rx_pps_mean": statistics.mean(values) if values else 0.0,
            "rx_pps_std": statistics.stdev(values) if len(values) > 1 else 0.0,
            "iterations": iterations,
        }
    elif rate == "pdr":
        values = [it["lower_bound_pps"] for it in iterations]
        return {
            "rate": "pdr",
            "delivery_ratio": entry["delivery_ratio"],
            "pdr_pps_mean": statistics.mean(values) if values else 0.0,
            "pdr_pps_std": statistics.stdev(values) if len(values) > 1 else 0.0,
            "iterations": iterations,
        }
    return dict(entry)


def generate_pcaps(config: Mapping[str, Any], config_dir: Path, experiments: Sequence[Mapping[str, Any]]) -> Dict[str, Path]:
    perf_cfg = config.get("perf", {})
    pcap_dir = local_path(str(perf_cfg.get("pcap_dir", "pcap")), config_dir)
    network = config.get("network", {})
    pcaps: Dict[str, Path] = {}

    for experiment in experiments:
        name = str(require(experiment, "name", "experiments[]"))
        frame_size = int(experiment.get("frame_size", experiment.get("size", 64)))
        pcap_path = pcap_dir / f"{name}-{frame_size}.pcap"
        exp_network: Dict[str, Any] = dict(network)
        ip_version = str(experiment.get("ip_version", "4"))
        compute_csum = bool(experiment.get("traffic_udp_checksum", False))
        if ip_version == "6":
            if "pcap_dst_ipv6" in experiment:
                exp_network["traffic_dst_ipv6"] = str(experiment["pcap_dst_ipv6"])
            write_ipv6_udp_pcap(pcap_path, exp_network, frame_size, compute_csum)
        else:
            # ip_version "4" or "srv6" both use an IPv4 inner pcap
            if "pcap_dst_ipv4" in experiment:
                exp_network["traffic_dst_ipv4"] = str(experiment["pcap_dst_ipv4"])
            if "pcap_dst_prefix" in experiment:
                exp_network["traffic_dst_prefix"] = str(experiment["pcap_dst_prefix"])
            write_ipv4_udp_pcap(pcap_path, exp_network, frame_size, compute_csum)
        pcaps[name] = pcap_path
        print(f"Generated {pcap_path} ({frame_size} bytes)")
    return pcaps


def results_output_dir(config: Mapping[str, Any], config_dir: Path) -> Path:
    perf_cfg = config.get("perf", {})
    output_dir = local_path(str(perf_cfg.get("output_dir", "results")), config_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_results(config: Mapping[str, Any], config_dir: Path, payload: Mapping[str, Any]) -> Path:
    output_dir = results_output_dir(config, config_dir)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_path = output_dir / f"bonet-ipv4-forward-{timestamp}.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_path


def checkpoint_path(config: Mapping[str, Any], config_dir: Path) -> Path:
    return results_output_dir(config, config_dir) / "checkpoint.json"


def save_checkpoint(path: Path, data: Dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_checkpoint(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def filter_experiments(config: Mapping[str, Any], selected: Sequence[str]) -> List[Mapping[str, Any]]:
    experiments = config.get("experiments", [])
    if not isinstance(experiments, list) or not experiments:
        raise ValueError("Config must define a non-empty `experiments` list")
    if not selected:
        return experiments
    selected_set = set(selected)
    return [experiment for experiment in experiments if str(experiment.get("name")) in selected_set]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run BONet IPv4 forwarding benchmarks with TRex")
    parser.add_argument("--config", default="config.example.yaml", help="YAML benchmark config")
    parser.add_argument("--cases", help="Comma-separated cases: framework,baseline,kernel")
    parser.add_argument("--experiments", help="Comma-separated experiment names to run")
    parser.add_argument("--skip-build", action="store_true", help="Do not build XDP object files")
    parser.add_argument("--skip-clean", action="store_true", help="Leave SUT configuration in place at exit")
    parser.add_argument("--dry-run", action="store_true", help="Print SUT/build commands and generate pcaps only")
    parser.add_argument("--resume", action="store_true", help="Resume from a previous checkpoint in the output directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    config_dir = config_path.parent
    config = load_config(config_path)

    cases = as_list(args.cases) or as_list(config.get("cases")) or list(VALID_CASES)
    invalid_cases = [case for case in cases if case not in VALID_CASES]
    if invalid_cases:
        raise ValueError(f"Invalid cases: {', '.join(invalid_cases)}")

    experiments = filter_experiments(config, as_list(args.experiments))
    pcaps = generate_pcaps(config, config_dir, experiments)

    if not args.skip_build:
        build_objects(config, cases, experiments, args.dry_run)

    if args.dry_run:
        for case in cases:
            for experiment in experiments:
                run_sut_action(config_for_experiment(config, experiment), "prepare", case, True)
        print("Dry run completed; TRex measurements were skipped.")
        return 0

    ckpt_path = checkpoint_path(config, config_dir)
    results: Dict[str, Any] = {
        "cases": {},
        "experiments": [dict(experiment) for experiment in experiments],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if args.resume:
        existing = load_checkpoint(ckpt_path)
        if existing:
            results = existing
            # Find the last fully-complete round: a round N is complete only when
            # every (case, experiment) pair has at least N+1 stored iterations.
            complete_rounds = min(
                len((results.get("cases", {}).get(case, {}).get(str(exp["name"])) or {}).get("iterations", []))
                for case in cases
                for exp in experiments
            )
            # Discard any results beyond the last complete round so the resume
            # always starts at a clean round boundary.
            discarded = 0
            for case in cases:
                for exp in experiments:
                    name = str(exp["name"])
                    entry = (results.get("cases", {}).get(case) or {}).get(name)
                    if entry and len(entry.get("iterations", [])) > complete_rounds:
                        discarded += len(entry["iterations"]) - complete_rounds
                        entry["iterations"] = entry["iterations"][:complete_rounds]
                        for key in ("pdr_pps_mean", "pdr_pps_std", "rx_pps_mean", "rx_pps_std"):
                            entry.pop(key, None)
                        entry["_partial"] = True
            msg = f"Resuming from checkpoint: {complete_rounds} complete rounds"
            if discarded:
                msg += f", discarded {discarded} partial-round measurements"
            print(msg)
        else:
            print("No checkpoint found, starting fresh")

    trex_cfg = config.get("trex", {})
    settle = float(config.get("sut", {}).get("settle_seconds", 1))
    max_reps = max(int(exp.get("runs", 1)) for exp in experiments)

    # Ensure partial-entry placeholders exist for every case/experiment not yet completed.
    for case in cases:
        if case not in results["cases"]:
            results["cases"][case] = {}
        for experiment in experiments:
            name = str(experiment["name"])
            existing_entry = results["cases"][case].get(name)
            if existing_entry is None:
                results["cases"][case][name] = _make_partial_entry(experiment)

    try:
        for rep in range(max_reps):
            # Randomized block design: group by experiment so all variants
            # (framework/baseline/kernel) for the same program are measured in
            # close temporal proximity, reducing variance from slow-varying
            # conditions (thermal, load).  The order of blocks and the order of
            # cases within each block are both independently randomized so no
            # positional bias accumulates across repetitions.
            blocks = []
            for exp in experiments:
                if rep >= int(exp.get("runs", 1)):
                    continue
                block = [(exp, case) for case in cases]
                random.shuffle(block)
                blocks.append(block)
            random.shuffle(blocks)
            for experiment, case in (pair for block in blocks for pair in block):
                name = str(experiment["name"])
                exp_reps = int(experiment.get("runs", 1))
                entry = results["cases"][case][name]
                if not entry.get("_partial"):
                    print(f"Skipping {case}/{name} (already completed)")
                    continue
                done_reps = len(entry["iterations"])
                if done_reps > rep:
                    print(f"Skipping {case}/{name} rep {rep} (already in checkpoint)")
                    continue
                print(f"Preparing SUT case: {case} experiment: {name} rep: {rep}/{exp_reps - 1}")
                run_sut_action(config_for_experiment(config, experiment), "prepare", case, False)
                if settle > 0:
                    time.sleep(settle)
                rate = str(experiment.get("rate", "mrr")).lower()
                if rate == "mrr":
                    iteration = run_mrr_one(trex_cfg, experiment, pcaps[name])
                elif rate == "pdr":
                    iteration = run_pdr_one(trex_cfg, experiment, pcaps[name])
                else:
                    raise ValueError(f"Unsupported rate `{rate}` for experiment `{name}`")
                entry["iterations"].append(iteration)
                save_checkpoint(ckpt_path, results)
                print(f"Checkpoint saved ({case}/{name} rep {rep})")

        # Finalize: replace partial entries with aggregated results.
        for case in cases:
            for experiment in experiments:
                name = str(experiment["name"])
                entry = results["cases"][case][name]
                if entry.get("_partial"):
                    results["cases"][case][name] = _finalize_entry(entry)
    finally:
        if not args.skip_clean:
            run_sut_action(config, "clean", "kernel", False)

    output_path = write_results(config, config_dir, results)
    print(f"Results written to {output_path}")
    ckpt_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
