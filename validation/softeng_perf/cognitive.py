#!/usr/bin/env python3
"""
Cognitive complexity of the paired eBPF programs in ../baseline and ../framework.

--engine sonar (default) measures it with SonarSource's own C analyzer: it starts a
disposable SonarQube Developer Edition container, scans each side with a
sonar-scanner-cli container that also has clang (sonar/Dockerfile), and reads the
per-file cognitive_complexity from the report the scanner keeps locally. See
README.md, "Cognitive complexity", for why it works this way.

--engine local uses the approximate analyzer of compare_metrics.py, without Docker.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import json
import os
import platform
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
VALIDATION_DIR = SCRIPT_DIR.parent
REPO_ROOT = VALIDATION_DIR.parent
DEFAULT_RESULTS_DIR = SCRIPT_DIR / "results" / "cognitive"
COGNITIVE_METRIC = "cognitive_complexity"
# SonarQube Developer Edition: the cheapest edition with the C analyzer (CFamily); it runs without a
# license, it only refuses to store the results, which we read from the scanner's report instead.
DEFAULT_SONAR_IMAGE = "sonarqube:developer"
# sonar-scanner-cli plus clang, which the C analyzer runs to learn the compiler's macros (sonar/Dockerfile).
DEFAULT_SCANNER_IMAGE = "bonet-sonar-scanner"


class CognitiveError(RuntimeError):
    """Explicit runtime failure for the one-shot cognitive workflow."""


@dataclass(frozen=True)
class SourcePair:
    test: str
    filename: str
    baseline: Path
    framework: Path


@dataclass(frozen=True)
class SideSource:
    label: str
    root: Path
    files: List[Path]


@dataclass
class SonarRuntime:
    run_id: str
    host_url: str
    port: int
    sonar_image: str
    scanner_image: str
    container_name: str
    token: str
    admin_password: str
    work_root: Path
    project_keys: Dict[str, str]
    raw: Dict[str, Any]


def info(message: str, verbose: bool = True) -> None:
    if verbose:
        print(message, flush=True)


def fail(message: str) -> None:
    raise CognitiveError(message)


def redact(text: str, secrets_to_redact: Sequence[str] = ()) -> str:
    redacted = text
    for secret in secrets_to_redact:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    return redacted


def run_command(
    cmd: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    secrets_to_redact: Sequence[str] = (),
) -> Tuple[str, str]:
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        fail(f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired as exc:
        preview = redact((exc.stdout or "") + "\n" + (exc.stderr or ""), secrets_to_redact)
        fail(f"Command timed out after {timeout}s: {format_command(cmd, secrets_to_redact)}\n{preview[-3000:]}")

    if proc.returncode != 0:
        output = redact((proc.stdout or "") + "\n" + (proc.stderr or ""), secrets_to_redact)
        fail(
            "Command failed with exit code "
            f"{proc.returncode}: {format_command(cmd, secrets_to_redact)}\n{output[-5000:]}"
        )
    return proc.stdout, proc.stderr


def run_command_allow_failure(
    cmd: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    secrets_to_redact: Sequence[str] = (),
) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        stdout = redact(exc.stdout or "", secrets_to_redact)
        stderr = redact(exc.stderr or "", secrets_to_redact)
        return 124, stdout, stderr or f"Timed out after {timeout}s"
    return proc.returncode, proc.stdout, proc.stderr


def format_command(cmd: Sequence[str], secrets_to_redact: Sequence[str] = ()) -> str:
    rendered = shlex.join(list(cmd))
    return redact(rendered, secrets_to_redact)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Mapping[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def round_number(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    if float(value).is_integer():
        return int(value)
    return round(value, 3)


def pct_change(baseline: float, framework: float) -> Optional[float]:
    if baseline == 0:
        return 0.0 if framework == 0 else None
    return ((framework - baseline) / baseline) * 100.0


def comparison_row(test: str, filename: str, baseline: float, framework: float) -> Dict[str, Any]:
    delta = framework - baseline
    pct = pct_change(baseline, framework)
    return {
        "test": test,
        "file": filename,
        "baseline_cognitive_complexity": round_number(baseline),
        "framework_cognitive_complexity": round_number(framework),
        "delta_framework_minus_baseline": round_number(delta),
        "pct_change_framework_vs_baseline": round_number(pct),
    }


def aggregate_rows(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    baseline_total = sum(float(row["baseline_cognitive_complexity"]) for row in rows)
    framework_total = sum(float(row["framework_cognitive_complexity"]) for row in rows)
    delta = framework_total - baseline_total
    pct = pct_change(baseline_total, framework_total)
    improved = sum(1 for row in rows if float(row["delta_framework_minus_baseline"]) < 0)
    unchanged = sum(1 for row in rows if float(row["delta_framework_minus_baseline"]) == 0)
    regressed = sum(1 for row in rows if float(row["delta_framework_minus_baseline"]) > 0)
    return {
        "tests": len(rows),
        "baseline_total": round_number(baseline_total),
        "framework_total": round_number(framework_total),
        "delta_framework_minus_baseline": round_number(delta),
        "pct_change_framework_vs_baseline": round_number(pct),
        "baseline_mean": round_number(baseline_total / len(rows)) if rows else None,
        "framework_mean": round_number(framework_total / len(rows)) if rows else None,
        "improved_tests": improved,
        "unchanged_tests": unchanged,
        "regressed_tests": regressed,
    }


def collect_direct_c_files(root: Path) -> List[Path]:
    if not root.exists():
        fail(f"Input directory does not exist: {root}")
    if not root.is_dir():
        fail(f"Input path is not a directory: {root}")
    files = sorted(path.resolve() for path in root.glob("*.c") if path.is_file())
    if not files:
        fail(f"No application .c files found in {root}")
    return files


def pair_sources(baseline_dir: Path, framework_dir: Path) -> Tuple[SideSource, SideSource, List[SourcePair]]:
    baseline = SideSource("baseline", baseline_dir.resolve(), collect_direct_c_files(baseline_dir))
    framework = SideSource("framework", framework_dir.resolve(), collect_direct_c_files(framework_dir))

    baseline_by_name = {path.name: path for path in baseline.files}
    framework_by_name = {path.name: path for path in framework.files}
    baseline_names = set(baseline_by_name)
    framework_names = set(framework_by_name)

    missing_framework = sorted(baseline_names - framework_names)
    missing_baseline = sorted(framework_names - baseline_names)
    if missing_framework or missing_baseline:
        details: List[str] = []
        if missing_framework:
            details.append("missing in framework: " + ", ".join(missing_framework))
        if missing_baseline:
            details.append("missing in baseline: " + ", ".join(missing_baseline))
        fail("Baseline/framework .c files are not paired by filename (" + "; ".join(details) + ")")

    pairs = [
        SourcePair(
            test=Path(name).stem,
            filename=name,
            baseline=baseline_by_name[name],
            framework=framework_by_name[name],
        )
        for name in sorted(baseline_names)
    ]
    return baseline, framework, pairs


def load_local_cognitive_analyzer() -> Any:
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        import compare_metrics  # type: ignore
    except Exception as exc:
        fail(f"Cannot import softeng_perf/compare_metrics.py for --engine local: {exc}")
    return compare_metrics


def run_local_engine(pairs: Sequence[SourcePair]) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, Any]]:
    compare_metrics = load_local_cognitive_analyzer()
    raw: Dict[str, Any] = {"algorithm": getattr(compare_metrics, "COGNITIVE_COMPLEXITY_ALGORITHM", "local")}
    side_scores: Dict[str, Dict[str, float]] = {"baseline": {}, "framework": {}}

    for side in ["baseline", "framework"]:
        side_raw: Dict[str, Any] = {}
        for pair in pairs:
            path = getattr(pair, side)
            warnings: List[str] = []
            metrics, metric_raw = compare_metrics.analyze_cognitive_complexity([path], warnings)
            if warnings:
                fail(f"Local cognitive analysis failed for {path}: {'; '.join(warnings)}")
            try:
                total = float(metrics["cognitive_complexity"]["total"])
                function_count = int(metrics["cognitive_complexity"]["function_count"])
            except Exception as exc:
                fail(f"Local cognitive analysis returned an unexpected shape for {path}: {exc}")
            if function_count <= 0:
                fail(f"Local cognitive analysis found no functions in {path}")
            side_scores[side][pair.filename] = total
            side_raw[pair.filename] = metric_raw.get("cognitive_complexity", {})
        raw[side] = side_raw

    return side_scores["baseline"], side_scores["framework"], raw


def docker_available() -> None:
    if shutil.which("docker") is None:
        fail("Docker CLI is not installed or not in PATH")
    rc, out, err = run_command_allow_failure(["docker", "info"], timeout=30)
    if rc != 0:
        fail("Docker daemon is not reachable. docker info failed:\n" + (out + "\n" + err)[-3000:])


def check_port_free(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError as exc:
        fail(f"Port {host}:{port} is already in use; choose another port with --port. Details: {exc}")
    finally:
        sock.close()


def docker_pull_if_missing(image: str, verbose: bool) -> None:
    rc, _, _ = run_command_allow_failure(["docker", "image", "inspect", image], timeout=30)
    if rc == 0:
        return
    info(f"Image {image} is not local; pulling it...", verbose)
    run_command(["docker", "pull", image], timeout=1200)


def docker_build_if_missing(image: str, context: Path, verbose: bool) -> None:
    rc, _, _ = run_command_allow_failure(["docker", "image", "inspect", image], timeout=30)
    if rc == 0:
        return
    info(f"Image {image} is not local; building it from {context}...", verbose)
    run_command(["docker", "build", "-t", image, str(context)], timeout=1800)


def docker_logs(container_name: str) -> str:
    rc, out, err = run_command_allow_failure(["docker", "logs", "--tail", "200", container_name], timeout=30)
    if rc != 0:
        return (out + "\n" + err)[-4000:]
    return (out + "\n" + err)[-8000:]


def cleanup_container(container_name: str, verbose: bool) -> None:
    rc, out, err = run_command_allow_failure(["docker", "rm", "-f", container_name], timeout=60)
    if rc == 0:
        info(f"Removed SonarQube container {container_name}", verbose)
    else:
        info(f"Could not remove container {container_name}: {(out + err)[-1000:]}", verbose)


def auth_header(token: Optional[str] = None, basic: Optional[Tuple[str, str]] = None) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if token:
        raw = f"{token}:".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    elif basic:
        raw = f"{basic[0]}:{basic[1]}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return headers


def http_json(
    method: str,
    host_url: str,
    endpoint: str,
    *,
    params: Optional[Mapping[str, str]] = None,
    data: Optional[Mapping[str, str]] = None,
    token: Optional[str] = None,
    basic: Optional[Tuple[str, str]] = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    url = host_url.rstrip("/") + "/" + endpoint.lstrip("/")
    if params:
        url += "?" + urllib.parse.urlencode(params)
    body = urllib.parse.urlencode(data or {}).encode("utf-8") if data is not None else None
    headers = auth_header(token=token, basic=basic)
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
        fail(f"Sonar API {method} {endpoint} failed with HTTP {exc.code}: {details[:1000]}")
    except Exception as exc:
        fail(f"Sonar API {method} {endpoint} failed: {exc}")
    if not payload.strip():
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        fail(f"Sonar API {method} {endpoint} returned non-JSON data: {exc}: {payload[:500]}")


def wait_for_sonar(host_url: str, container_name: str, timeout: int, verbose: bool) -> None:
    deadline = time.monotonic() + timeout
    last_status = "not reachable"
    while time.monotonic() < deadline:
        rc, out, _ = run_command_allow_failure(["docker", "inspect", "-f", "{{.State.Running}}", container_name], timeout=10)
        if rc != 0:
            fail(f"SonarQube container {container_name} disappeared while starting")
        if out.strip() != "true":
            fail(f"SonarQube container {container_name} exited while starting:\n{docker_logs(container_name)}")
        try:
            payload = http_json("GET", host_url, "/api/system/status", timeout=10)
            last_status = str(payload.get("status", "unknown"))
            if last_status == "UP":
                info("SonarQube is UP", verbose)
                return
        except CognitiveError as exc:
            last_status = str(exc)
        time.sleep(5)
    fail(
        f"SonarQube did not become UP within {timeout}s; last status: {last_status}\n"
        f"Recent container logs:\n{docker_logs(container_name)}"
    )


def configure_sonar(host_url: str, run_id: str, verbose: bool) -> Tuple[str, str]:
    admin_password = "BONet-" + secrets.token_urlsafe(18)
    info("Configuring SonarQube admin password and analysis token via API", verbose)
    http_json(
        "POST",
        host_url,
        "/api/users/change_password",
        data={"login": "admin", "previousPassword": "admin", "password": admin_password},
        basic=("admin", "admin"),
    )
    payload = http_json(
        "POST",
        host_url,
        "/api/user_tokens/generate",
        data={"name": f"bonet-cognitive-{run_id}"},
        basic=("admin", admin_password),
    )
    token = payload.get("token")
    if not token:
        fail(f"Sonar token creation returned no token: {payload}")
    return admin_password, str(token)


def create_sonar_project(host_url: str, token: str, key: str, name: str) -> None:
    http_json(
        "POST",
        host_url,
        "/api/projects/create",
        data={"project": key, "name": name},
        token=token,
    )


def guess_bpf_arch() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "x86",
        "amd64": "x86",
        "aarch64": "arm64",
        "arm64": "arm64",
        "s390x": "s390",
        "ppc64le": "powerpc",
        "mips64": "mips",
        "riscv64": "riscv",
    }
    return mapping.get(machine, machine)


def system_include_subdir() -> str:
    return f"/host_usr_include/{platform.machine()}-linux-gnu"


def prepare_sonar_side_workspace(
    side: SideSource,
    pairs: Sequence[SourcePair],
    side_work: Path,
    *,
    bpf_arch: str,
    include_dirs: Sequence[str],
) -> None:
    sources_dir = side_work / "sources"
    headers_dir = side_work / "headers"
    objects_dir = side_work / "objects"
    ensure_dir(sources_dir)
    ensure_dir(headers_dir)
    ensure_dir(objects_dir)

    for header in sorted(side.root.glob("*.h")) + sorted(side.root.glob("*.hh")) + sorted(side.root.glob("*.hpp")):
        if header.is_file():
            shutil.copy2(header, headers_dir / header.name)

    compile_commands: List[Dict[str, str]] = []
    pair_paths = {getattr(pair, side.label).name: getattr(pair, side.label) for pair in pairs}
    for filename, source_path in sorted(pair_paths.items()):
        shutil.copy2(source_path, sources_dir / filename)
        container_source = f"/usr/src/sources/{filename}"
        container_object = f"/usr/src/objects/{Path(filename).stem}.o"
        command_parts = [
            "clang",
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-target",
            "bpf",
            f"-D__TARGET_ARCH_{bpf_arch}",
            "-I/usr/src/sources",
            "-I/usr/src/headers",
            "-I/host_usr_include",
            f"-I{system_include_subdir()}",
        ]
        for include_dir in include_dirs:
            command_parts.append(f"-I{include_dir}")
        command_parts.extend(["-c", container_source, "-o", container_object])
        compile_commands.append(
            {
                "directory": "/usr/src",
                "command": shlex.join(command_parts),
                "file": container_source,
            }
        )

    (side_work / "compile_commands.json").write_text(
        json.dumps(compile_commands, indent=2) + "\n",
        encoding="utf-8",
    )


def scanner_summary(output: str) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    for marker in ["ANALYSIS SUCCESSFUL", "EXECUTION FAILURE", "0 languages detected"]:
        if marker in output:
            summary[marker.lower().replace(" ", "_")] = True
    for line in output.splitlines():
        if "languages detected" in line or "files indexed" in line or "Sensor CFamily" in line:
            summary.setdefault("notable_lines", []).append(line.strip())
    return summary


def run_sonar_scanner(
    runtime: SonarRuntime,
    side: SideSource,
    project_key: str,
    expected_files: Sequence[str],
    *,
    timeout: int,
    verbose: bool,
) -> Dict[str, Any]:
    side_work = runtime.work_root / side.label
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "-w",
        "/usr/src",
        "-e",
        f"SONAR_HOST_URL={runtime.host_url}",
        "-e",
        f"SONAR_TOKEN={runtime.token}",
        # the image works in /tmp by default; keep .scannerwork where we can read it
        "-e",
        "SCANNER_WORKDIR_PATH=/usr/src/.scannerwork",
        "-v",
        f"{side_work}:/usr/src",
        "-v",
        f"{REPO_ROOT}:/repo:ro",
        "-v",
        "/usr/include:/host_usr_include:ro",
        runtime.scanner_image,
        "-Dsonar.projectKey=" + project_key,
        "-Dsonar.projectName=" + project_key,
        "-Dsonar.sources=sources",
        "-Dsonar.host.url=" + runtime.host_url,
        "-Dsonar.token=" + runtime.token,
        "-Dsonar.sourceEncoding=UTF-8",
        "-Dsonar.scm.disabled=true",
        "-Dsonar.cfamily.compile-commands=compile_commands.json",
        "-Dsonar.scanner.keepReport=true",
    ]
    info(f"Running SonarScanner for {side.label} ({len(expected_files)} files)", verbose)
    rc, out, err = run_command_allow_failure(cmd, timeout=timeout, secrets_to_redact=[runtime.token])
    combined = redact(out + "\n" + err, [runtime.token])
    raw = {
        "command": format_command(cmd, [runtime.token]),
        "returncode": rc,
        "summary": scanner_summary(combined),
        "output_tail": combined[-5000:],
    }
    if rc != 0:
        fail(f"SonarScanner failed for {side.label} with exit code {rc}:\n{combined[-5000:]}")
    if "0 languages detected" in combined:
        fail(
            f"SonarScanner completed for {side.label}, but Sonar detected 0 languages: "
            f"{runtime.sonar_image} has no C analyzer (the Community images do not; use sonarqube:developer)."
        )
    return raw


def _varint(data: bytes, i: int) -> Tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, i


def _proto_fields(data: bytes) -> Dict[int, Any]:
    """Top-level fields of one protobuf message (last value wins); enough for the scanner report."""
    fields: Dict[int, Any] = {}
    i = 0
    while i < len(data):
        key, i = _varint(data, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(data, i)
        elif wire == 2:
            size, i = _varint(data, i)
            value, i = data[i:i + size], i + size
        elif wire == 1:
            value, i = data[i:i + 8], i + 8
        elif wire == 5:
            value, i = data[i:i + 4], i + 4
        else:
            fail(f"Unsupported protobuf wire type {wire} in the scanner report")
        fields[number] = value
    return fields


def read_report_metrics(side_work: Path, label: str, expected_files: Sequence[str]) -> Dict[str, float]:
    """cognitive_complexity per file from the report the scanner kept locally.

    The server is only needed by the scanner to download the analyzers: without a license the
    Developer Edition rejects the report ("Analyses suspended"), but the measures are computed by
    the scanner and are already in .scannerwork/scanner-report (sonar.scanner.keepReport=true).
    Files: component-<ref>.pb (one Component, whose path is a string field) and
    measures-<ref>.pb (length-delimited Measure: metric_key = 1, int_value = 3 { value = 1 }).
    """
    report = side_work / ".scannerwork" / "scanner-report"
    if not report.is_dir():
        fail(f"SonarScanner kept no report for {label} in {report}")
    expected = set(expected_files)
    by_file: Dict[str, float] = {}
    for component in sorted(report.glob("component-*.pb")):
        names = [
            Path(v.decode("utf-8", errors="replace")).name
            for v in _proto_fields(component.read_bytes()).values()
            if isinstance(v, bytes)
        ]
        name = next((n for n in names if n in expected), None)
        measures = report / ("measures-" + component.stem.split("-", 1)[1] + ".pb")
        if name is None or not measures.exists():
            continue
        data, i = measures.read_bytes(), 0
        while i < len(data):
            size, i = _varint(data, i)
            measure = _proto_fields(data[i:i + size])
            i += size
            if measure.get(1) == COGNITIVE_METRIC.encode() and 3 in measure:
                by_file[name] = float(_proto_fields(measure[3]).get(1, 0))
    missing = sorted(expected - set(by_file))
    if missing:
        fail(f"Scanner report for {label} has no {COGNITIVE_METRIC} for: " + ", ".join(missing))
    return {name: by_file[name] for name in sorted(expected)}


def run_sonar_engine(args: argparse.Namespace, baseline: SideSource, framework: SideSource, pairs: Sequence[SourcePair]) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, Any]]:
    docker_available()
    check_port_free("127.0.0.1", args.port)
    docker_pull_if_missing(args.sonar_image, args.verbose)
    if args.scanner_image == DEFAULT_SCANNER_IMAGE:
        docker_build_if_missing(args.scanner_image, SCRIPT_DIR / "sonar", args.verbose)
    else:
        docker_pull_if_missing(args.scanner_image, args.verbose)

    run_id = args.run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    container_name = f"bonet-cognitive-sonar-{run_id}"
    host_url = f"http://127.0.0.1:{args.port}"
    # Under the repo, not /tmp: the containers mount it, and a snap Docker cannot see /tmp.
    ensure_dir(SCRIPT_DIR / "results")
    work_root = Path(tempfile.mkdtemp(prefix=f"sonar-work-{run_id}-", dir=SCRIPT_DIR / "results"))

    runtime = SonarRuntime(
        run_id=run_id,
        host_url=host_url,
        port=args.port,
        sonar_image=args.sonar_image,
        scanner_image=args.scanner_image,
        container_name=container_name,
        token="",
        admin_password="",
        work_root=work_root,
        project_keys={},
        raw={"work_root": str(work_root)},
    )

    try:
        info(f"Starting disposable SonarQube container {container_name} on port {args.port}", args.verbose)
        docker_run = [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "--label",
            f"bonet.cognitive.run_id={run_id}",
            "-p",
            f"127.0.0.1:{args.port}:9000",
            "-e",
            "SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true",
            "--ulimit",
            "nofile=131072:131072",
            "--ulimit",
            "nproc=8192:8192",
        ]
        if args.sonar_data_tmpfs_size:
            docker_run.extend(["--tmpfs", f"/opt/sonarqube/data:rw,size={args.sonar_data_tmpfs_size}"])
        docker_run.append(args.sonar_image)
        run_command(docker_run, timeout=120)
        wait_for_sonar(host_url, container_name, args.sonar_startup_timeout, args.verbose)
        admin_password, token = configure_sonar(host_url, run_id, args.verbose)
        runtime.admin_password = admin_password
        runtime.token = token

        expected_files = [pair.filename for pair in pairs]
        include_dirs = ["/repo/src"]
        for include_dir in args.include_dir:
            resolved = include_dir.resolve()
            try:
                rel = resolved.relative_to(REPO_ROOT)
                include_dirs.append("/repo/" + rel.as_posix())
            except ValueError:
                fail(f"Additional include directory must be inside the repository so it can be mounted read-only: {resolved}")

        project_prefix = args.project_prefix.rstrip("-")
        for side in [baseline, framework]:
            key = f"{project_prefix}-{side.label}-{run_id}".replace("_", "-")
            runtime.project_keys[side.label] = key
            create_sonar_project(host_url, token, key, key)
            prepare_sonar_side_workspace(
                side,
                pairs,
                work_root / side.label,
                bpf_arch=args.arch,
                include_dirs=include_dirs,
            )
            scanner_raw = run_sonar_scanner(
                runtime,
                side,
                key,
                expected_files,
                timeout=args.scanner_timeout,
                verbose=args.verbose,
            )
            runtime.raw[f"{side.label}_scanner"] = scanner_raw

        side_scores = {
            side.label: read_report_metrics(work_root / side.label, side.label, expected_files)
            for side in [baseline, framework]
        }

        raw = {
            "run_id": run_id,
            "host_url": host_url,
            "sonar_image": args.sonar_image,
            "scanner_image": args.scanner_image,
            "project_keys": runtime.project_keys,
            "work_root": str(work_root),
            "scanner": runtime.raw,
        }
        return side_scores["baseline"], side_scores["framework"], raw
    finally:
        if not args.keep_container:
            cleanup_container(container_name, args.verbose)
        else:
            info(f"Keeping SonarQube container {container_name}", args.verbose)
        if not args.keep_workdir:
            shutil.rmtree(work_root, ignore_errors=True)
        else:
            info(f"Keeping temporary scanner workspace {work_root}", args.verbose)


def build_report(
    args: argparse.Namespace,
    baseline: SideSource,
    framework: SideSource,
    pairs: Sequence[SourcePair],
    baseline_scores: Mapping[str, float],
    framework_scores: Mapping[str, float],
    raw: Mapping[str, Any],
) -> Dict[str, Any]:
    rows = [
        comparison_row(pair.test, pair.filename, baseline_scores[pair.filename], framework_scores[pair.filename])
        for pair in pairs
    ]
    report = {
        "metadata": {
            "script": str(Path(__file__).resolve()),
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "engine": args.engine,
            "metric": COGNITIVE_METRIC,
            "baseline_dir": str(baseline.root),
            "framework_dir": str(framework.root),
            "measured_files": [pair.filename for pair in pairs],
            "scope": "direct child .c files only; headers and library sources are not aggregated",
        },
        "aggregate": aggregate_rows(rows),
        "tests": rows,
        "raw": raw,
    }
    return report


def terminal_table(report: Mapping[str, Any]) -> str:
    rows = report["tests"]
    headers = ["test", "baseline", "framework", "delta", "% change"]
    table_rows = []
    for row in rows:
        pct = row["pct_change_framework_vs_baseline"]
        table_rows.append(
            [
                row["test"],
                str(row["baseline_cognitive_complexity"]),
                str(row["framework_cognitive_complexity"]),
                str(row["delta_framework_minus_baseline"]),
                "" if pct is None else str(pct),
            ]
        )
    agg = report["aggregate"]
    pct = agg["pct_change_framework_vs_baseline"]
    table_rows.append(
        [
            "TOTAL",
            str(agg["baseline_total"]),
            str(agg["framework_total"]),
            str(agg["delta_framework_minus_baseline"]),
            "" if pct is None else str(pct),
        ]
    )

    widths = [len(header) for header in headers]
    for row in table_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def render(row: Sequence[str]) -> str:
        return (
            row[0].ljust(widths[0])
            + "  "
            + row[1].rjust(widths[1])
            + "  "
            + row[2].rjust(widths[2])
            + "  "
            + row[3].rjust(widths[3])
            + "  "
            + row[4].rjust(widths[4])
        )

    lines = [
        "Cognitive complexity comparison",
        f"Engine: {report['metadata']['engine']}  Metric: {report['metadata']['metric']}",
        "",
        render(headers),
        render(["-" * w for w in widths]),
    ]
    lines.extend(render(row) for row in table_rows)
    lines.extend(
        [
            "",
            f"Improved tests: {agg['improved_tests']}  "
            f"Unchanged: {agg['unchanged_tests']}  Regressed: {agg['regressed_tests']}",
        ]
    )
    return "\n".join(lines)


def write_csv_report(path: Path, report: Mapping[str, Any]) -> None:
    ensure_dir(path.parent)
    fieldnames = [
        "test",
        "file",
        "baseline_cognitive_complexity",
        "framework_cognitive_complexity",
        "delta_framework_minus_baseline",
        "pct_change_framework_vs_baseline",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in report["tests"]:
            writer.writerow({key: row.get(key) for key in fieldnames})


def md_cell(value: Any) -> str:
    return "" if value is None else str(value)


def write_markdown_report(path: Path, report: Mapping[str, Any]) -> None:
    ensure_dir(path.parent)
    agg = report["aggregate"]
    lines = [
        "# Cognitive complexity comparison",
        "",
        f"- Engine: `{report['metadata']['engine']}`",
        f"- Metric: `{report['metadata']['metric']}`",
        f"- Scope: {report['metadata']['scope']}",
        "",
        "## Aggregate",
        "",
        "| Baseline total | Framework total | Delta | % change | Improved | Unchanged | Regressed |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        "| "
        + " | ".join(
            md_cell(value)
            for value in [
                agg["baseline_total"],
                agg["framework_total"],
                agg["delta_framework_minus_baseline"],
                agg["pct_change_framework_vs_baseline"],
                agg["improved_tests"],
                agg["unchanged_tests"],
                agg["regressed_tests"],
            ]
        )
        + " |",
        "",
        "## Per Test",
        "",
        "| Test | Baseline | Framework | Delta | % change |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in report["tests"]:
        lines.append(
            "| "
            + " | ".join(
                md_cell(value)
                for value in [
                    row["test"],
                    row["baseline_cognitive_complexity"],
                    row["framework_cognitive_complexity"],
                    row["delta_framework_minus_baseline"],
                    row["pct_change_framework_vs_baseline"],
                ]
            )
            + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure cognitive complexity for paired eBPF validation programs. "
            "By default this runs SonarSource's C analyzer in disposable Docker containers; "
            "--engine local uses an approximate analyzer without Docker."
        )
    )
    parser.add_argument("--baseline", type=Path, default=VALIDATION_DIR / "baseline", help="Directory containing handwritten .c programs.")
    parser.add_argument("--framework", type=Path, default=VALIDATION_DIR / "framework", help="Directory containing framework-based .c programs.")
    parser.add_argument("--engine", choices=["sonar", "local"], default="sonar", help="sonar (the paper's numbers, needs Docker) or local (a quick approximation). Default: sonar.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_RESULTS_DIR, help="Default directory for JSON/CSV/Markdown outputs.")
    parser.add_argument("--json", type=Path, help="JSON output path. Defaults to output-dir/cognitive.json.")
    parser.add_argument("--csv", type=Path, help="CSV output path. Defaults to output-dir/cognitive.csv.")
    parser.add_argument("--markdown", type=Path, help="Markdown output path. Defaults to output-dir/cognitive.md.")
    parser.add_argument("--list-tests", action="store_true", help="List paired tests and exit before analysis.")
    parser.add_argument("--quiet", action="store_true", help="Reduce progress output.")

    sonar = parser.add_argument_group("Sonar automation")
    sonar.add_argument("--port", type=int, default=9000, help="Host port for the disposable SonarQube container.")
    sonar.add_argument("--sonar-image", default=os.environ.get("SONAR_IMAGE", DEFAULT_SONAR_IMAGE), help="SonarQube Docker image; it needs the C analyzer.")
    sonar.add_argument("--scanner-image", default=os.environ.get("SONAR_SCANNER_IMAGE", DEFAULT_SCANNER_IMAGE), help="SonarScanner Docker image with clang; built from sonar/Dockerfile when missing.")
    sonar.add_argument("--sonar-startup-timeout", type=int, default=360, help="Seconds to wait for SonarQube to become UP.")
    sonar.add_argument("--scanner-timeout", type=int, default=1200, help="Seconds to wait for each SonarScanner run.")
    sonar.add_argument(
        "--sonar-data-tmpfs-size",
        default="3g",
        help="Mount disposable SonarQube data on tmpfs of this size; pass an empty string to disable.",
    )
    sonar.add_argument("--project-prefix", default="bonet-cognitive", help="Prefix for temporary Sonar project keys.")
    sonar.add_argument("--run-id", help="Stable run id for container/project names; defaults to timestamp plus random suffix.")
    sonar.add_argument("--arch", default=guess_bpf_arch(), help="BPF target arch suffix used for __TARGET_ARCH_<arch>.")
    sonar.add_argument("--include-dir", type=Path, action="append", default=[], help="Extra repository-local include directory for C analysis.")
    sonar.add_argument("--keep-container", action="store_true", help="Do not remove the disposable SonarQube container at the end.")
    sonar.add_argument("--keep-workdir", action="store_true", help="Do not remove the temporary scanner workspace.")

    args = parser.parse_args(argv)
    args.verbose = not args.quiet
    if args.json is None:
        args.json = args.output_dir / "cognitive.json"
    if args.csv is None:
        args.csv = args.output_dir / "cognitive.csv"
    if args.markdown is None:
        args.markdown = args.output_dir / "cognitive.md"
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        baseline, framework, pairs = pair_sources(args.baseline, args.framework)
        if args.list_tests:
            for pair in pairs:
                print(pair.filename)
            return 0

        info(f"Found {len(pairs)} paired application .c files", args.verbose)
        if args.engine == "sonar":
            baseline_scores, framework_scores, raw = run_sonar_engine(args, baseline, framework, pairs)
        else:
            baseline_scores, framework_scores, raw = run_local_engine(pairs)

        report = build_report(args, baseline, framework, pairs, baseline_scores, framework_scores, raw)
        print(terminal_table(report))
        write_json(args.json, report)
        write_csv_report(args.csv, report)
        write_markdown_report(args.markdown, report)
        info("", args.verbose)
        info(f"Wrote JSON:     {args.json}", args.verbose)
        info(f"Wrote CSV:      {args.csv}", args.verbose)
        info(f"Wrote Markdown: {args.markdown}", args.verbose)
        return 0
    except CognitiveError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
