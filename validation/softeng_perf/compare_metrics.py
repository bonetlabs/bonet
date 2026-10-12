#!/usr/bin/env python3
"""
Software-engineering metrics for paired eBPF validation programs.

The script compares handwritten baseline programs against framework-based
programs using source metrics, Lizard, a local C/eBPF cognitive-complexity pass,
optional external line counters, object-file metrics, verifier-log metrics, and
extra JSON inputs such as microbenchmark summaries.

Typical usage from validation/softeng_perf:

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
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# Constants and configuration
# ---------------------------------------------------------------------------

DEFAULT_SOURCE_EXTENSIONS = [".c"]
HEADER_EXTENSIONS = [".h", ".hpp", ".hh"]
DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".scannerwork",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "dist",
    "out",
    "target",
    "node_modules",
    "__pycache__",
}
DEFAULT_ARTIFACT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".scannerwork",
    "node_modules",
    "__pycache__",
}

BPF_HELPER_NAMES = {
    1: "map_lookup_elem",
    2: "map_update_elem",
    3: "map_delete_elem",
    4: "probe_read",
    5: "ktime_get_ns",
    6: "trace_printk",
    7: "get_prandom_u32",
    8: "get_smp_processor_id",
    9: "skb_store_bytes",
    10: "l3_csum_replace",
    11: "l4_csum_replace",
    12: "tail_call",
    14: "get_current_pid_tgid",
    23: "redirect",
    25: "perf_event_output",
    26: "skb_load_bytes",
    34: "xdp_adjust_head",
    51: "redirect_map",
    58: "xdp_adjust_meta",
    65: "skb_adjust_room",
    80: "skb_load_bytes_relative",
    93: "xdp_adjust_tail",
    113: "probe_read_user",
    114: "probe_read_kernel",
    115: "probe_read_user_str",
    116: "probe_read_kernel_str",
}

LOWER_IS_BETTER_HINTS = (
    "loc",
    "nloc",
    "sloc",
    "lines",
    "complexity",
    "ccn",
    "token",
    "parameter",
    "nesting",
    "instruction",
    "insn",
    "stack",
    "state",
    "verifier",
    "helper",
    "bounds",
    "pointer",
    "cast",
    "endian",
    "latency",
    "cycles",
    "branch_miss",
    "cpu",
    "error",
    "failure",
)

HIGHER_IS_BETTER_HINTS = (
    "throughput",
    "mpps",
    "pps",
    "goodput",
    "success_rate",
    "pass_rate",
)

COGNITIVE_COMPLEXITY_ALGORITHM = "local-c-ebpf-heuristic-v1"
COGNITIVE_NON_FUNCTION_NAMES = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "sizeof",
    "return",
    "SEC",
    "__attribute__",
    "__section",
    "section",
    "aligned",
}
COGNITIVE_TOKEN_RE = re.compile(r"\b[A-Za-z_]\w*\b|&&|\|\||[{}()?:;]")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ToolStatus:
    """Availability and version information for an external tool."""

    name: str
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


@dataclass
class AnalysisUnit:
    """Input bundle for either the baseline or framework side."""

    label: str
    source_paths: List[Path]
    source_files: List[Path]
    object_files: List[Path]
    verifier_logs: List[Path]
    extra_json_files: List[Path]


@dataclass
class UnitResult:
    """Collected metrics and warnings for one side of the comparison."""

    label: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


@dataclass
class SideInventory:
    """Discovered sources and artifacts for one side of a comparison."""

    label: str
    source_paths: List[Path]
    all_source_files: List[Path]
    test_source_files: List[Path]
    object_files: List[Path]
    verifier_logs: List[Path]
    extra_json_files: List[Path]
    sources_by_test: Dict[str, List[Path]]
    objects_by_test: Dict[str, List[Path]]
    verifier_logs_by_test: Dict[str, List[Path]]
    extra_json_by_test: Dict[str, List[Path]]


@dataclass
class CFunctionSpan:
    """A best-effort C function body span inside a source file."""

    name: str
    signature_start: int
    body_start: int
    body_end: int
    start_line: int
    end_line: int


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

def read_text(path: Path) -> str:
    """Read a text file in a robust way."""
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text, creating parent directories if necessary."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def is_finite_number(value: Any) -> bool:
    """Return True for finite numeric values, excluding booleans."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def to_number(value: Any) -> Optional[float]:
    """Best-effort conversion to float."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().replace(",", "")
        if cleaned.endswith("%"):
            cleaned = cleaned[:-1]
        try:
            num = float(cleaned)
            if math.isfinite(num):
                return num
        except ValueError:
            return None
    return None


def safe_div(num: float, den: float) -> Optional[float]:
    """Divide while avoiding division by zero."""
    if den == 0:
        return None
    return num / den


def pct_change(old: float, new: float) -> Optional[float]:
    """Percentage change from old to new. Positive means new is larger."""
    if old == 0:
        return None
    return ((new - old) / old) * 100.0


def improvement_pct(old: float, new: float, higher_is_better: bool) -> Optional[float]:
    """Percentage improvement using the metric's direction."""
    if old == 0:
        return None
    if higher_is_better:
        return ((new - old) / old) * 100.0
    return ((old - new) / old) * 100.0


def metric_higher_is_better(metric: str) -> bool:
    """Heuristic metric direction used only for comparison reporting."""
    lowered = metric.lower()
    if any(hint in lowered for hint in HIGHER_IS_BETTER_HINTS):
        return True
    if any(hint in lowered for hint in LOWER_IS_BETTER_HINTS):
        return False
    return False


def round_value(value: Any, digits: int = 3) -> Any:
    """Round floats for compact output."""
    if isinstance(value, float) and math.isfinite(value):
        return round(value, digits)
    return value


def flatten_dict(d: Mapping[str, Any], prefix: str = "") -> Dict[str, Any]:
    """Flatten nested dictionaries with dot-separated keys."""
    out: Dict[str, Any] = {}
    for key, value in d.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            out.update(flatten_dict(value, name))
        else:
            out[name] = value
    return out


def aggregate_numbers(values: Sequence[float]) -> Dict[str, Any]:
    """Return standard descriptive statistics for a numeric vector."""
    cleaned = [float(v) for v in values if math.isfinite(float(v))]
    if not cleaned:
        return {
            "sum": 0,
            "avg": None,
            "median": None,
            "max": None,
            "p90": None,
        }
    sorted_values = sorted(cleaned)
    p90_index = int(math.ceil(0.90 * len(sorted_values))) - 1
    p90_index = max(0, min(p90_index, len(sorted_values) - 1))
    return {
        "sum": sum(cleaned),
        "avg": statistics.mean(cleaned),
        "median": statistics.median(cleaned),
        "max": max(cleaned),
        "p90": sorted_values[p90_index],
    }


def run_command(cmd: Sequence[str], cwd: Optional[Path] = None, timeout: int = 300) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or f"timeout after {timeout}s"


def command_version(cmd: str, args: Sequence[str] = ("--version",)) -> ToolStatus:
    """Return best-effort availability/version information for a command."""
    path = shutil.which(cmd)
    if not path:
        return ToolStatus(name=cmd, available=False, error="not found in PATH")
    rc, out, err = run_command([path, *args], timeout=30)
    text = (out or err).strip().splitlines()
    version = text[0].strip() if text else None
    return ToolStatus(name=cmd, available=rc == 0, version=version, path=path, error=None if rc == 0 else err.strip())


def first_existing_command(names: Sequence[str]) -> Optional[str]:
    """Return the first command name available in PATH."""
    for name in names:
        if shutil.which(name):
            return name
    return None


# ---------------------------------------------------------------------------
# Source collection and comment stripping
# ---------------------------------------------------------------------------

def parse_extensions(args: argparse.Namespace) -> List[str]:
    """Compute the source extension set from CLI options."""
    exts = list(args.extensions or DEFAULT_SOURCE_EXTENSIONS)
    if args.include_headers:
        exts.extend(HEADER_EXTENSIONS)
    normalized = []
    for ext in exts:
        ext = ext.strip()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        normalized.append(ext.lower())
    return sorted(set(normalized))


def should_exclude(path: Path, exclude_dirs: Sequence[str], exclude_regexes: Sequence[str]) -> bool:
    """Return True when a path should be ignored."""
    parts = set(path.parts)
    if any(excluded in parts for excluded in exclude_dirs):
        return True
    text = str(path)
    return any(re.search(pattern, text) for pattern in exclude_regexes)


def collect_source_files(
    paths: Sequence[Path],
    extensions: Sequence[str],
    exclude_dirs: Sequence[str],
    exclude_regexes: Sequence[str],
) -> List[Path]:
    """Recursively collect source files with the requested extensions."""
    files: List[Path] = []
    for input_path in paths:
        if not input_path.exists():
            continue
        if input_path.is_file():
            if input_path.suffix.lower() in extensions and not should_exclude(input_path, exclude_dirs, exclude_regexes):
                files.append(input_path.resolve())
            continue
        for root, dirs, names in os.walk(input_path):
            root_path = Path(root)
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for name in names:
                candidate = root_path / name
                if candidate.suffix.lower() not in extensions:
                    continue
                if should_exclude(candidate, exclude_dirs, exclude_regexes):
                    continue
                files.append(candidate.resolve())
    return sorted(set(files))


def collect_artifact_files(
    paths: Sequence[Path],
    suffixes: Sequence[str],
    exclude_dirs: Sequence[str],
    exclude_regexes: Sequence[str],
) -> List[Path]:
    """Collect generated artifact files, accepting either files or directories."""
    normalized_suffixes = {s.lower() if s.startswith(".") else f".{s.lower()}" for s in suffixes}
    files: List[Path] = []
    for input_path in paths:
        if not input_path.exists():
            continue
        if input_path.is_file():
            if input_path.suffix.lower() in normalized_suffixes and not should_exclude(input_path, exclude_dirs, exclude_regexes):
                files.append(input_path.resolve())
            continue
        for root, dirs, names in os.walk(input_path):
            root_path = Path(root)
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for name in names:
                candidate = root_path / name
                if candidate.suffix.lower() not in normalized_suffixes:
                    continue
                if should_exclude(candidate, exclude_dirs, exclude_regexes):
                    continue
                files.append(candidate.resolve())
    return sorted(set(files))


def artifact_test_name(path: Path) -> str:
    """Infer a test name from source/object/log/report file names."""
    name = path.name
    for suffix in [".verifier.log", ".verifier.txt", ".metrics.json", ".extra.json", ".json", ".log", ".txt", ".o", ".c"]:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def group_paths_by_test_name(paths: Sequence[Path]) -> Dict[str, List[Path]]:
    """Group files by the inferred test name."""
    grouped: Dict[str, List[Path]] = {}
    for path in paths:
        grouped.setdefault(artifact_test_name(path), []).append(path)
    return {name: sorted(set(group)) for name, group in sorted(grouped.items())}


def is_ebpf_program_source(path: Path) -> bool:
    """Return True when a C source appears to contain an eBPF program section."""
    try:
        code = strip_comments_preserve_strings(read_text(path))
    except Exception:
        return False
    return bool(
        re.search(
            r"\bSEC\s*\(\s*\"(?:xdp|tc|classifier|sched_cls|sched_act|socket|tracepoint|kprobe|kretprobe|fentry|fexit)",
            code,
        )
    )


def select_test_source_files(source_files: Sequence[Path], object_files: Sequence[Path]) -> List[Path]:
    """Select eBPF test sources, excluding host helpers such as verify_load.c."""
    object_names = {artifact_test_name(path) for path in object_files}
    selected: List[Path] = []
    for path in source_files:
        name = artifact_test_name(path)
        if name in object_names or is_ebpf_program_source(path):
            selected.append(path)
    return sorted(set(selected))


def filter_grouped_paths(grouped: Mapping[str, List[Path]], names: Sequence[str]) -> List[Path]:
    """Flatten grouped paths for the requested test names."""
    wanted = set(names)
    out: List[Path] = []
    for name, paths in grouped.items():
        if name in wanted:
            out.extend(paths)
    return sorted(set(out))


def strip_comments_preserve_strings(code: str) -> str:
    """
    Remove C/C++ comments while preserving strings/chars enough for regex-based
    source metrics. This is not a C parser; it is deliberately conservative.
    """
    out: List[str] = []
    i = 0
    n = len(code)
    state = "normal"
    while i < n:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if state == "normal":
            if ch == '"':
                out.append(ch)
                state = "string"
                i += 1
            elif ch == "'":
                out.append(ch)
                state = "char"
                i += 1
            elif ch == "/" and nxt == "/":
                out.append(" ")
                i += 2
                while i < n and code[i] != "\n":
                    i += 1
            elif ch == "/" and nxt == "*":
                out.append(" ")
                i += 2
                while i + 1 < n and not (code[i] == "*" and code[i + 1] == "/"):
                    if code[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 2
            else:
                out.append(ch)
                i += 1
        elif state == "string":
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(code[i + 1])
                i += 2
            elif ch == '"':
                state = "normal"
                i += 1
            else:
                i += 1
        elif state == "char":
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(code[i + 1])
                i += 2
            elif ch == "'":
                state = "normal"
                i += 1
            else:
                i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Local cognitive complexity metrics
# ---------------------------------------------------------------------------

def mask_string_and_char_literals(code: str) -> str:
    """
    Replace string/char literal contents with spaces while preserving layout.

    The cognitive-complexity pass is deliberately lexical: preserving positions
    keeps line numbers stable, while masking literal contents avoids counting
    words or braces inside format strings.
    """
    out: List[str] = []
    i = 0
    n = len(code)
    state = "normal"
    while i < n:
        ch = code[i]
        if state == "normal":
            if ch == '"':
                out.append(ch)
                state = "string"
            elif ch == "'":
                out.append(ch)
                state = "char"
            else:
                out.append(ch)
            i += 1
        elif state == "string":
            if ch == "\\" and i + 1 < n:
                out.append(" ")
                out.append("\n" if code[i + 1] == "\n" else " ")
                i += 2
            elif ch == '"':
                out.append(ch)
                state = "normal"
                i += 1
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif state == "char":
            if ch == "\\" and i + 1 < n:
                out.append(" ")
                out.append("\n" if code[i + 1] == "\n" else " ")
                i += 2
            elif ch == "'":
                out.append(ch)
                state = "normal"
                i += 1
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
    return "".join(out)


def find_matching_forward(text: str, open_pos: int, open_char: str, close_char: str) -> Optional[int]:
    """Return the matching close delimiter position in already-masked text."""
    if open_pos < 0 or open_pos >= len(text) or text[open_pos] != open_char:
        return None
    depth = 1
    i = open_pos + 1
    while i < len(text):
        ch = text[i]
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def line_number_at(text: str, pos: int) -> int:
    """Return the 1-based line number for a character offset."""
    return text.count("\n", 0, max(0, pos)) + 1


def function_signature_start(code: str, open_brace: int) -> int:
    """Find a conservative start offset for the declaration before a body."""
    boundaries = [
        code.rfind(";", 0, open_brace),
        code.rfind("}", 0, open_brace),
        code.rfind("{", 0, open_brace),
    ]
    preprocessor_lines = list(re.finditer(r"(?m)^\s*#.*(?:\n|$)", code[:open_brace]))
    if preprocessor_lines:
        boundaries.append(preprocessor_lines[-1].end() - 1)
    return max(boundaries) + 1


def function_tail_is_allowed(tail: str) -> bool:
    """Return True for common C attributes/macros between a function signature and body."""
    if not tail:
        return True
    if "=" in tail or ";" in tail:
        return False
    return bool(re.fullmatch(r"[\sA-Za-z0-9_(),\[\]\"']*", tail))


def parse_c_function_name(signature: str) -> Optional[str]:
    """Extract a C function name from a candidate declaration."""
    candidate = "\n".join(
        line for line in signature.splitlines() if not line.lstrip().startswith("#")
    ).strip()
    if not candidate or "=" in candidate or ";" in candidate:
        return None

    matches = list(re.finditer(r"\b([A-Za-z_]\w*)\s*\(", candidate))
    for match in reversed(matches):
        name = match.group(1)
        if name in COGNITIVE_NON_FUNCTION_NAMES:
            continue
        open_paren = match.end() - 1
        close_paren = find_matching_forward(candidate, open_paren, "(", ")")
        if close_paren is None:
            continue
        tail = candidate[close_paren + 1 :].strip()
        if not function_tail_is_allowed(tail):
            continue
        prefix = candidate[: match.start()].strip()
        if not prefix or prefix.endswith("#"):
            continue
        return name
    return None


def extract_c_function_spans(code: str) -> List[CFunctionSpan]:
    """Best-effort extraction of C function definitions from masked source."""
    spans: List[CFunctionSpan] = []
    i = 0
    while i < len(code):
        open_brace = code.find("{", i)
        if open_brace < 0:
            break
        close_brace = find_matching_forward(code, open_brace, "{", "}")
        if close_brace is None:
            i = open_brace + 1
            continue

        sig_start = function_signature_start(code, open_brace)
        signature = code[sig_start:open_brace]
        name = parse_c_function_name(signature)
        if name is None:
            i = open_brace + 1
            continue
        display_start = sig_start + (len(signature) - len(signature.lstrip()))

        spans.append(
            CFunctionSpan(
                name=name,
                signature_start=sig_start,
                body_start=open_brace,
                body_end=close_brace,
                start_line=line_number_at(code, display_start),
                end_line=line_number_at(code, close_brace),
            )
        )
        i = close_brace + 1
    return spans


def tokenize_cognitive_source(code: str) -> List[Tuple[str, int]]:
    """Tokenize only the constructs needed by the local cognitive metric."""
    return [(match.group(0), match.start()) for match in COGNITIVE_TOKEN_RE.finditer(code)]


def find_matching_token(tokens: Sequence[Tuple[str, int]], open_index: int, open_value: str, close_value: str) -> Optional[int]:
    """Return the matching token index for a balanced token pair."""
    if open_index < 0 or open_index >= len(tokens) or tokens[open_index][0] != open_value:
        return None
    depth = 1
    for i in range(open_index + 1, len(tokens)):
        value = tokens[i][0]
        if value == open_value:
            depth += 1
        elif value == close_value:
            depth -= 1
            if depth == 0:
                return i
    return None


def find_condition_token_span(tokens: Sequence[Tuple[str, int]], keyword_index: int) -> Optional[Tuple[int, int]]:
    """Find the parenthesized condition following a control-flow keyword."""
    for i in range(keyword_index + 1, len(tokens)):
        value = tokens[i][0]
        if value == "(":
            close_index = find_matching_token(tokens, i, "(", ")")
            if close_index is None:
                return None
            return i, close_index
        if value in {"{", ";"}:
            return None
    return None


def find_braced_body_after(
    code: str,
    tokens: Sequence[Tuple[str, int]],
    start_index: int,
) -> Optional[Tuple[int, int]]:
    """Find the next braced body after a token index."""
    for i in range(start_index + 1, len(tokens)):
        value, pos = tokens[i]
        if value == "{":
            close_pos = find_matching_forward(code, pos, "{", "}")
            if close_pos is None:
                return None
            return pos, close_pos
        if value == ";":
            return None
    return None


def token_index_after_pos(tokens: Sequence[Tuple[str, int]], pos: int) -> Optional[int]:
    """Return the first token index whose position is greater than pos."""
    for i, (_, token_pos) in enumerate(tokens):
        if token_pos > pos:
            return i
    return None


def active_cognitive_nesting(blocks: Sequence[Tuple[int, int]], pos: int) -> int:
    """Count active control-flow blocks at a position."""
    return sum(1 for start, end in blocks if start < pos < end)


def logical_operator_sequences(expression: str) -> int:
    """Count logical operator sequences in a condition."""
    operators = re.findall(r"&&|\|\|", expression)
    sequences = 0
    previous: Optional[str] = None
    for operator in operators:
        if operator != previous:
            sequences += 1
        previous = operator
    return sequences


def analyze_function_cognitive_complexity(name: str, body: str) -> Dict[str, Any]:
    """Compute a local cognitive-complexity estimate for one C function body."""
    tokens = tokenize_cognitive_source(body)
    blocks: List[Tuple[int, int]] = []
    skip_while_positions: Set[int] = set()
    score = 0
    breakdown: Dict[str, int] = {
        "if": 0,
        "else": 0,
        "loops": 0,
        "switch": 0,
        "ternary": 0,
        "logical_operator_sequences": 0,
        "jumps": 0,
        "recursion": 0,
    }

    for i, (value, pos) in enumerate(tokens):
        nesting = active_cognitive_nesting(blocks, pos)

        if value == "else":
            next_value = tokens[i + 1][0] if i + 1 < len(tokens) else None
            if next_value == "if":
                continue
            score += 1 + nesting
            breakdown["else"] += 1
            body_span = find_braced_body_after(body, tokens, i)
            if body_span:
                blocks.append(body_span)
            continue

        if value == "if":
            condition_span = find_condition_token_span(tokens, i)
            score += 1 + nesting
            breakdown["if"] += 1
            if condition_span:
                open_index, close_index = condition_span
                expr_start = tokens[open_index][1] + 1
                expr_end = tokens[close_index][1]
                logical = logical_operator_sequences(body[expr_start:expr_end])
                score += logical
                breakdown["logical_operator_sequences"] += logical
                body_span = find_braced_body_after(body, tokens, close_index)
                if body_span:
                    blocks.append(body_span)
            continue

        if value in {"for", "while"}:
            if pos in skip_while_positions:
                continue
            condition_span = find_condition_token_span(tokens, i)
            score += 1 + nesting
            breakdown["loops"] += 1
            if condition_span:
                open_index, close_index = condition_span
                expr_start = tokens[open_index][1] + 1
                expr_end = tokens[close_index][1]
                logical = logical_operator_sequences(body[expr_start:expr_end])
                score += logical
                breakdown["logical_operator_sequences"] += logical
                body_span = find_braced_body_after(body, tokens, close_index)
                if body_span:
                    blocks.append(body_span)
            continue

        if value == "do":
            score += 1 + nesting
            breakdown["loops"] += 1
            body_span = find_braced_body_after(body, tokens, i)
            if body_span:
                blocks.append(body_span)
                after_body_index = token_index_after_pos(tokens, body_span[1])
                if after_body_index is not None and tokens[after_body_index][0] == "while":
                    skip_while_positions.add(tokens[after_body_index][1])
            continue

        if value == "switch":
            score += 1 + nesting
            breakdown["switch"] += 1
            condition_span = find_condition_token_span(tokens, i)
            if condition_span:
                body_span = find_braced_body_after(body, tokens, condition_span[1])
                if body_span:
                    blocks.append(body_span)
            continue

        if value == "?":
            score += 1 + nesting
            breakdown["ternary"] += 1
            continue

        if value == "goto":
            score += 1 + nesting
            breakdown["jumps"] += 1

    if re.search(rf"\b{re.escape(name)}\s*\(", body):
        score += 1
        breakdown["recursion"] = 1

    max_nesting = 0
    for _, pos in tokens:
        max_nesting = max(max_nesting, active_cognitive_nesting(blocks, pos))

    return {
        "cognitive_complexity": score,
        "max_nesting_estimate": max_nesting,
        "breakdown": breakdown,
    }


def analyze_cognitive_complexity(files: Sequence[Path], warnings: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Collect local C/eBPF cognitive-complexity metrics."""
    file_records: List[Dict[str, Any]] = []
    function_records: List[Dict[str, Any]] = []

    for path in files:
        try:
            source = read_text(path)
            code = mask_string_and_char_literals(strip_comments_preserve_strings(source))
        except Exception as exc:
            warnings.append(f"Local cognitive complexity failed to read {path}: {exc}")
            continue

        spans = extract_c_function_spans(code)
        file_score = 0
        for span in spans:
            body = code[span.body_start + 1 : span.body_end]
            function_metrics = analyze_function_cognitive_complexity(span.name, body)
            score = int(function_metrics["cognitive_complexity"])
            file_score += score
            function_records.append(
                {
                    "path": str(path),
                    "name": span.name,
                    "start_line": span.start_line,
                    "end_line": span.end_line,
                    **function_metrics,
                }
            )

        file_records.append(
            {
                "path": str(path),
                "function_count": len(spans),
                "cognitive_complexity": file_score,
            }
        )

    values = [r["cognitive_complexity"] for r in function_records if is_finite_number(r.get("cognitive_complexity"))]
    nesting_values = [r["max_nesting_estimate"] for r in function_records if is_finite_number(r.get("max_nesting_estimate"))]

    metrics = {
        "files": len(file_records),
        "function_count": len(function_records),
        "algorithm": COGNITIVE_COMPLEXITY_ALGORITHM,
        "total": sum(float(v) for v in values),
        "per_function": aggregate_numbers(values),
        "max_nesting_estimate": aggregate_numbers(nesting_values),
        "gt_5": sum(1 for v in values if v > 5),
        "gt_10": sum(1 for v in values if v > 10),
        "gt_15": sum(1 for v in values if v > 15),
    }

    top_functions = sorted(
        function_records,
        key=lambda r: (to_number(r.get("cognitive_complexity")) or -1, r.get("name", "")),
        reverse=True,
    )[:20]

    raw = {
        "available": True,
        "algorithm": COGNITIVE_COMPLEXITY_ALGORITHM,
        "files": file_records,
        "functions": function_records,
        "top_functions_by_cognitive_complexity": top_functions,
    }
    return {"cognitive_complexity": metrics}, {"cognitive_complexity": raw}


# ---------------------------------------------------------------------------
# Lizard metrics
# ---------------------------------------------------------------------------

def load_lizard_module(warnings: List[str]) -> Optional[Any]:
    """Import lizard if available."""
    try:
        import lizard  # type: ignore
        return lizard
    except Exception as exc:  # pragma: no cover - depends on user environment
        warnings.append(
            "Lizard Python package is not available. Install with: python3 -m pip install lizard. "
            f"Import error: {exc}"
        )
        return None


def maybe_load_lizard_extensions(enable_nesting: bool, warnings: List[str]) -> List[Any]:
    """
    Try to load optional Lizard extensions.

    Lizard extensions are not guaranteed to expose stable Python names across
    versions; failing to load them should not break the main analysis.
    """
    extensions: List[Any] = []
    if not enable_nesting:
        return extensions
    possible_modules = [
        "lizard_ext.lizardns",     # nesting statistics extension in many installs
        "lizard_ext.lizardnsl",    # alternative/older naming sometimes seen
    ]
    for module_name in possible_modules:
        try:
            module = __import__(module_name, fromlist=["*"])
            if hasattr(module, "LizardExtension"):
                extensions.append(module.LizardExtension())
                return extensions
        except Exception:
            continue
    warnings.append(
        "Requested Lizard nesting metrics, but no known nesting extension could be loaded. "
        "The script will still report standard Lizard metrics."
    )
    return extensions


def get_lizard_attr(obj: Any, names: Sequence[str]) -> Optional[Any]:
    """Return the first available attribute from an object."""
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def analyze_with_lizard(files: Sequence[Path], enable_nesting: bool, warnings: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Collect Lizard metrics using the Python API."""
    lizard = load_lizard_module(warnings)
    if lizard is None:
        return {}, {"available": False}

    extensions = maybe_load_lizard_extensions(enable_nesting, warnings)
    file_records: List[Dict[str, Any]] = []
    function_records: List[Dict[str, Any]] = []

    analyze_source_code = None
    try:
        analyze_source_code = lizard.analyze_file.analyze_source_code
    except Exception:
        analyze_source_code = None

    if analyze_source_code is None:
        warnings.append("Unable to find lizard.analyze_file.analyze_source_code in installed Lizard package.")
        return {}, {"available": False}

    for path in files:
        try:
            source = read_text(path)
            kwargs = {"extensions": extensions} if extensions else {}
            info = analyze_source_code(str(path), source, **kwargs)
        except TypeError:
            # Older Lizard versions may not support the extensions keyword.
            try:
                info = analyze_source_code(str(path), read_text(path))
            except Exception as exc:
                warnings.append(f"Lizard failed on {path}: {exc}")
                continue
        except Exception as exc:
            warnings.append(f"Lizard failed on {path}: {exc}")
            continue

        file_nloc = to_number(get_lizard_attr(info, ["nloc"])) or 0
        file_records.append({"path": str(path), "nloc": file_nloc})

        for func in getattr(info, "function_list", []) or []:
            name = get_lizard_attr(func, ["long_name", "name", "full_name"]) or "<unknown>"
            start_line = get_lizard_attr(func, ["start_line", "start_line_number", "line_number"])
            end_line = get_lizard_attr(func, ["end_line", "end_line_number"])
            func_nloc = to_number(get_lizard_attr(func, ["nloc", "length"]))
            ccn = to_number(get_lizard_attr(func, ["cyclomatic_complexity", "ccn"]))
            tokens = to_number(get_lizard_attr(func, ["token_count", "tokens"]))
            params = to_number(get_lizard_attr(func, ["parameter_count", "parameters", "num_parameters"]))
            nesting = to_number(get_lizard_attr(func, ["max_nesting_depth", "nesting_depth", "max_nesting", "NS"]))

            extra_attrs: Dict[str, Any] = {}
            for attr in dir(func):
                if attr.startswith("_"):
                    continue
                lowered = attr.lower()
                if "nest" in lowered or lowered in {"ns", "nsl"}:
                    value = get_lizard_attr(func, [attr])
                    if isinstance(value, (str, int, float)):
                        extra_attrs[attr] = value

            function_records.append(
                {
                    "path": str(path),
                    "name": str(name),
                    "start_line": start_line,
                    "end_line": end_line,
                    "nloc": func_nloc,
                    "ccn": ccn,
                    "token_count": tokens,
                    "parameter_count": params,
                    "nesting": nesting,
                    "nesting_attrs": extra_attrs,
                }
            )

    ccn_values = [r["ccn"] for r in function_records if is_finite_number(r.get("ccn"))]
    fn_nloc_values = [r["nloc"] for r in function_records if is_finite_number(r.get("nloc"))]
    token_values = [r["token_count"] for r in function_records if is_finite_number(r.get("token_count"))]
    param_values = [r["parameter_count"] for r in function_records if is_finite_number(r.get("parameter_count"))]
    nesting_values = [r["nesting"] for r in function_records if is_finite_number(r.get("nesting"))]

    lizard_metrics: Dict[str, Any] = {
        "files": len(file_records),
        "nloc": sum(float(r["nloc"]) for r in file_records),
        "function_count": len(function_records),
        "ccn": aggregate_numbers(ccn_values),
        "function_nloc": aggregate_numbers(fn_nloc_values),
        "token_count": aggregate_numbers(token_values),
        "parameter_count": aggregate_numbers(param_values),
        "ccn_gt_5": sum(1 for v in ccn_values if v > 5),
        "ccn_gt_10": sum(1 for v in ccn_values if v > 10),
        "ccn_gt_15": sum(1 for v in ccn_values if v > 15),
    }
    if nesting_values:
        lizard_metrics["nesting"] = aggregate_numbers(nesting_values)

    top_by_ccn = sorted(
        function_records,
        key=lambda r: (to_number(r.get("ccn")) or -1, to_number(r.get("nloc")) or -1),
        reverse=True,
    )[:20]

    raw = {
        "available": True,
        "files": file_records,
        "functions": function_records,
        "top_functions_by_ccn": top_by_ccn,
    }
    return {"lizard": lizard_metrics}, {"lizard": raw}


# ---------------------------------------------------------------------------
# External line counter metrics: nloc/sloc/cloc adapters
# ---------------------------------------------------------------------------

def parse_line_counter_json(text: str) -> Dict[str, Any]:
    """Parse common JSON outputs from cloc/sloc-like line counters."""
    data = json.loads(text)
    metrics: Dict[str, Any] = {}

    # cloc --json has a SUM object with code/comment/blank/nFiles.
    if isinstance(data, Mapping) and isinstance(data.get("SUM"), Mapping):
        sum_obj = data["SUM"]
        metrics.update(
            {
                "files": to_number(sum_obj.get("nFiles")) or to_number(sum_obj.get("files")),
                "blank": to_number(sum_obj.get("blank")),
                "comment": to_number(sum_obj.get("comment")),
                "code": to_number(sum_obj.get("code")),
            }
        )
        return {k: v for k, v in metrics.items() if v is not None}

    # Some sloc JSON formats are a list by language or a dict with total/source.
    if isinstance(data, Mapping):
        candidates = [data]
        for key in ("total", "summary", "SUM", "stats"):
            if isinstance(data.get(key), Mapping):
                candidates.append(data[key])
        for obj in candidates:
            for out_key, names in {
                "files": ["files", "nFiles", "file_count"],
                "total": ["total", "physical", "loc", "lines"],
                "code": ["code", "source", "sloc", "nloc"],
                "comment": ["comment", "comments"],
                "blank": ["blank", "empty"],
            }.items():
                for name in names:
                    if name in obj and to_number(obj[name]) is not None:
                        metrics[out_key] = to_number(obj[name])
                        break
        return metrics

    if isinstance(data, list):
        totals: Dict[str, float] = {}
        for item in data:
            if not isinstance(item, Mapping):
                continue
            for out_key, names in {
                "files": ["files", "nFiles", "file_count"],
                "total": ["total", "physical", "loc", "lines"],
                "code": ["code", "source", "sloc", "nloc"],
                "comment": ["comment", "comments"],
                "blank": ["blank", "empty"],
            }.items():
                for name in names:
                    num = to_number(item.get(name))
                    if num is not None:
                        totals[out_key] = totals.get(out_key, 0) + num
                        break
        return totals

    return {}


def parse_line_counter_xml(text: str) -> Dict[str, Any]:
    """Parse XML from nloc/cloc-like tools using forgiving name matching."""
    root = ET.fromstring(text)
    totals: Dict[str, float] = {}

    keyword_map = {
        "files": ["files", "filecount", "nfiles"],
        "total": ["total", "physical", "loc", "lines"],
        "code": ["code", "source", "sloc", "nloc", "logical"],
        "comment": ["comment", "comments"],
        "blank": ["blank", "empty"],
    }

    def add_named(name: str, value: Any) -> None:
        num = to_number(value)
        if num is None:
            return
        lowered = name.lower().replace("_", "").replace("-", "")
        for metric, keys in keyword_map.items():
            if lowered in keys or any(k in lowered for k in keys):
                totals[metric] = totals.get(metric, 0) + num
                return

    for elem in root.iter():
        for attr_name, attr_value in elem.attrib.items():
            add_named(attr_name, attr_value)
        if elem.text and elem.text.strip():
            add_named(elem.tag, elem.text.strip())
    return totals


def parse_line_counter_text(text: str) -> Dict[str, Any]:
    """Parse human-readable output from line counters using robust regexes."""
    metrics: Dict[str, float] = {}
    patterns = {
        "files": r"(?i)\b(?:files?|nfiles|file count)\b\D+(\d+(?:\.\d+)?)",
        "total": r"(?i)\b(?:total|physical|loc|lines)\b\D+(\d+(?:\.\d+)?)",
        "code": r"(?i)\b(?:code|source|sloc|nloc|logical)\b\D+(\d+(?:\.\d+)?)",
        "comment": r"(?i)\bcomments?\b\D+(\d+(?:\.\d+)?)",
        "blank": r"(?i)\b(?:blank|empty)\b\D+(\d+(?:\.\d+)?)",
    }
    for key, pattern in patterns.items():
        found = re.findall(pattern, text)
        if found:
            # Use the last match because many tools print per-file rows and a final total.
            num = to_number(found[-1])
            if num is not None:
                metrics[key] = num
    return metrics


def parse_line_counter_output(stdout: str, stderr: str, output_file: Optional[Path] = None) -> Dict[str, Any]:
    """Parse line-counter output from stdout/stderr or a generated report file."""
    candidates: List[str] = []
    if output_file and output_file.exists():
        candidates.append(read_text(output_file))
    candidates.extend([stdout, stderr])

    for text in candidates:
        text = text.strip()
        if not text:
            continue
        try:
            parsed = parse_line_counter_json(text)
            if parsed:
                return parsed
        except Exception:
            pass
        try:
            parsed = parse_line_counter_xml(text)
            if parsed:
                return parsed
        except Exception:
            pass
        parsed = parse_line_counter_text(text)
        if parsed:
            return parsed
    return {}


def format_command_template(template: str, paths: Sequence[Path], output_file: Path) -> List[str]:
    """
    Format a simple command template.

    Supported placeholders:
      {paths}  -> shell-free expansion into multiple argv tokens
      {output} -> output file path

    Example:
      'cloc --json {paths}'
      'nloc --xml {output} {paths}'
    """
    import shlex

    tokens = shlex.split(template)
    result: List[str] = []
    for token in tokens:
        if token == "{paths}":
            result.extend(str(p) for p in paths)
        else:
            result.append(token.replace("{output}", str(output_file)))
    return result


def run_line_counter(
    paths: Sequence[Path],
    mode: str,
    command_template: Optional[str],
    warnings: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Run nloc/sloc/cloc or a user-provided line-counter command."""
    if mode == "none":
        return {}, {"available": False, "reason": "disabled"}

    attempted: List[Dict[str, Any]] = []
    templates: List[Tuple[str, str]] = []

    if command_template:
        templates.append(("custom", command_template))
    elif mode == "nloc":
        # nloc CLI syntax varies across implementations; these are common guesses.
        templates.extend(
            [
                ("nloc", "nloc --xml {output} {paths}"),
                ("nloc", "nloc -xml {output} {paths}"),
                ("nloc", "nloc {paths}"),
            ]
        )
    elif mode == "cloc":
        templates.append(("cloc", "cloc --json {paths}"))
    elif mode == "sloc":
        templates.extend(
            [
                ("sloc", "sloc --format json {paths}"),
                ("sloc", "sloc -f json {paths}"),
                ("sloc", "sloc {paths}"),
            ]
        )
    elif mode == "auto":
        templates.extend(
            [
                ("nloc", "nloc --xml {output} {paths}"),
                ("nloc", "nloc -xml {output} {paths}"),
                ("nloc", "nloc {paths}"),
                ("cloc", "cloc --json {paths}"),
                ("sloc", "sloc --format json {paths}"),
                ("sloc", "sloc -f json {paths}"),
            ]
        )
    else:
        warnings.append(f"Unknown line-counter mode: {mode}")
        return {}, {"available": False, "reason": f"unknown mode {mode}"}

    with tempfile.TemporaryDirectory(prefix="ebpf-line-counter-") as td:
        output_file = Path(td) / "line-counter-report.xml"
        for tool_name, template in templates:
            argv = format_command_template(template, paths, output_file)
            if not argv:
                continue
            executable = shutil.which(argv[0])
            if not executable:
                attempted.append({"tool": tool_name, "template": template, "error": "not found in PATH"})
                continue
            argv[0] = executable
            rc, out, err = run_command(argv, timeout=300)
            parsed = parse_line_counter_output(out, err, output_file)
            attempted.append(
                {
                    "tool": tool_name,
                    "template": template,
                    "argv": argv,
                    "returncode": rc,
                    "stdout_preview": out[:1000],
                    "stderr_preview": err[:1000],
                    "parsed": parsed,
                }
            )
            if rc == 0 and parsed:
                metrics = {"line_counter": {"tool": tool_name, **parsed}}
                raw = {"line_counter": {"available": True, "tool": tool_name, "attempts": attempted}}
                return metrics, raw

    warnings.append(
        "No external line counter produced parseable output. "
        "Install nloc/cloc/sloc or pass --line-counter-command-template. "
        "Lizard NLOC is still reported if Lizard is installed."
    )
    return {}, {"line_counter": {"available": False, "attempts": attempted}}


def load_line_counter_report(path: Path, warnings: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Import an already generated line-counter report."""
    try:
        text = read_text(path)
        parsed = parse_line_counter_output(text, "")
        if not parsed:
            warnings.append(f"Could not parse line-counter report: {path}")
            return {}, {"line_counter": {"available": False, "report": str(path)}}
        return {"line_counter": {"tool": "imported", **parsed}}, {"line_counter": {"available": True, "report": str(path)}}
    except Exception as exc:
        warnings.append(f"Failed to read line-counter report {path}: {exc}")
        return {}, {"line_counter": {"available": False, "report": str(path), "error": str(exc)}}


# ---------------------------------------------------------------------------
# Custom eBPF source metrics
# ---------------------------------------------------------------------------

def count_regex(pattern: str, text: str, flags: int = re.MULTILINE) -> int:
    """Count regex matches."""
    return len(re.findall(pattern, text, flags=flags))


def count_regex_lines(pattern: str, text: str, flags: int = re.MULTILINE) -> int:
    """Count distinct source lines that contain at least one match."""
    return len({text[:m.start()].count('\n') for m in re.finditer(pattern, text, flags)})


def analyze_ebpf_source_patterns(files: Sequence[Path], framework_prefixes: Sequence[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Compute eBPF-specific source metrics that standard tools do not expose."""
    aggregate: Dict[str, int] = {
        "files": len(files),
        "total_lines": 0,
        "manual_bounds_checks": 0,
        "data_end_mentions": 0,
        "packet_data_mentions": 0,
        "raw_packet_pointer_arithmetic_sites": 0,
        "direct_header_casts": 0,
        "manual_offset_updates": 0,
        "endian_conversions": 0,
        "bpf_helper_calls": 0,
        "bpf_map_operations": 0,
        "tail_calls": 0,
        "skb_helper_calls": 0,
        "skb_load_store_bytes_calls": 0,
        "xdp_adjust_calls": 0,
        "debug_print_calls": 0,
        "volatile_barrier_or_inline_asm": 0,
        "likely_unlikely_annotations": 0,
        "framework_api_calls": 0,
        "sec_programs": 0,
    }
    per_file: List[Dict[str, Any]] = []

    prefix_pattern = None
    prefixes = [p for p in framework_prefixes if p]
    if prefixes:
        escaped = "|".join(re.escape(p) for p in prefixes)
        prefix_pattern = rf"\b(?:{escaped})[A-Za-z0-9_]*\s*\("

    for path in files:
        text = read_text(path)
        code = strip_comments_preserve_strings(text)
        file_metrics: Dict[str, int] = {
            "total_lines": text.count("\n") + (1 if text else 0),
            "manual_bounds_checks": count_regex(r"\bif\s*\([^;{}]*\b(?:data_end|pkt_end)\b[^;{}]*\)", code),
            "data_end_mentions": count_regex(r"\bdata_end\b|\bpkt_end\b", code),
            "packet_data_mentions": count_regex(r"\bdata\b|\bpkt\b|\bskb\b", code),
            "raw_packet_pointer_arithmetic_sites": count_regex_lines(r"\b(?:data|pkt|cursor|pos|off|offset)\b\s*(?:\+|-|\+=|-=|\[)|(?:\+|-)\s*\b(?:data|pkt|cursor|pos|off|offset)\b", code),
            "direct_header_casts": count_regex(r"\(\s*struct\s+[A-Za-z_]\w*[^)]*\)\s*\(?\s*(?:data|pkt|cursor|pos)\b", code),
            "manual_offset_updates": count_regex(r"\b(?:off|offset|cursor|pos)\s*(?:\+=|-=|=\s*[^;\n]*[+-])", code),
            "endian_conversions": count_regex(r"\b(?:bpf_)?(?:ntohs|ntohl|ntohll|htons|htonl|htonll)\s*\(", code),
            "bpf_helper_calls": count_regex(r"\bbpf_[A-Za-z0-9_]+\s*\(", code),
            "bpf_map_operations": count_regex(r"\bbpf_map_(?:lookup|update|delete|push|pop|peek)[A-Za-z0-9_]*\s*\(", code),
            "tail_calls": count_regex(r"\bbpf_tail_call\s*\(", code),
            "skb_helper_calls": count_regex(r"\bbpf_skb_[A-Za-z0-9_]+\s*\(", code),
            "skb_load_store_bytes_calls": count_regex(r"\bbpf_skb_(?:load|store)_bytes[A-Za-z0-9_]*\s*\(", code),
            "xdp_adjust_calls": count_regex(r"\bbpf_xdp_adjust_[A-Za-z0-9_]+\s*\(", code),
            "debug_print_calls": count_regex(r"\b(?:bpf_printk|bpf_trace_printk|trace_printk)\s*\(", code),
            "volatile_barrier_or_inline_asm": count_regex(r"\basm\s+volatile\b|\bbarrier\s*\(", code),
            "likely_unlikely_annotations": count_regex(r"\b(?:likely|unlikely)\s*\(", code),
            "framework_api_calls": count_regex(prefix_pattern, code) if prefix_pattern else 0,
            "sec_programs": count_regex(r"\bSEC\s*\(\s*\"(?:xdp|tc|classifier|sched_cls|socket|tracepoint|kprobe|fentry|fexit)", code),
        }
        for key, value in file_metrics.items():
            aggregate[key] = aggregate.get(key, 0) + int(value)
        per_file.append({"path": str(path), **file_metrics})

    derived: Dict[str, Any] = dict(aggregate)
    total_lines = float(aggregate.get("total_lines", 0))
    if total_lines:
        for key in [
            "manual_bounds_checks",
            "raw_packet_pointer_arithmetic_sites",
            "direct_header_casts",
            "manual_offset_updates",
            "endian_conversions",
            "bpf_helper_calls",
            "framework_api_calls",
        ]:
            derived[f"{key}_per_kloc"] = aggregate[key] / total_lines * 1000.0

    return {"ebpf_source": derived}, {"ebpf_source": {"per_file": per_file, "framework_prefixes": prefixes}}


# ---------------------------------------------------------------------------
# Object-file metrics from objdump
# ---------------------------------------------------------------------------

def disassemble_object(path: Path, objdump_cmd: Optional[str], warnings: List[str]) -> Optional[str]:
    """Disassemble one object file using llvm-objdump or objdump."""
    candidates = []
    if objdump_cmd:
        candidates.append(objdump_cmd)
    candidates.extend(["llvm-objdump", "objdump"])

    seen = set()
    for cmd in candidates:
        if cmd in seen:
            continue
        seen.add(cmd)
        executable = shutil.which(cmd) or (cmd if Path(cmd).exists() else None)
        if not executable:
            continue
        arg_sets = [
            [executable, "-d", "--no-show-raw-insn", str(path)],
            [executable, "-d", str(path)],
        ]
        for argv in arg_sets:
            rc, out, err = run_command(argv, timeout=120)
            if rc == 0 and out.strip():
                return out
        warnings.append(f"{cmd} failed to disassemble {path}: {err[:300]}")
    warnings.append(f"No objdump command could disassemble {path}")
    return None


def parse_objdump_disassembly(text: str) -> Dict[str, Any]:
    """Parse BPF-ish disassembly metrics from objdump output."""
    instruction_lines = []
    mnemonics: List[str] = []
    stack_offsets: List[int] = []
    helper_ids: Dict[str, int] = {}

    for line in text.splitlines():
        # Examples:
        #      18: r1 = r10
        #      19: r1 += -4
        #      42: call 26
        #      5c: 85 00 00 00 1a 00 00 00  call 26
        if not re.match(r"^\s*[0-9a-fA-F]+:\s+", line):
            continue
        instruction_lines.append(line)
        after_colon = line.split(":", 1)[1].strip()
        # Remove raw bytes if present: BPF raw bytes are commonly hex pairs.
        tokens = after_colon.split()
        while tokens and re.fullmatch(r"[0-9a-fA-F]{2}", tokens[0]):
            tokens.pop(0)
        mnemonic = tokens[0] if tokens else ""
        mnemonics.append(mnemonic)

        for match in re.finditer(r"(?:r10|fp)\s*[-+]\s*(\d+)", line):
            stack_offsets.append(abs(int(match.group(1))))
        for match in re.finditer(r"\[\s*(?:r10|fp)\s*-\s*(\d+)\s*\]", line):
            stack_offsets.append(abs(int(match.group(1))))

        call_match = re.search(r"\bcall\s+(-?\d+)\b", line)
        if call_match:
            helper = int(call_match.group(1))
            if helper >= 0:
                helper_name = BPF_HELPER_NAMES.get(helper, f"helper_{helper}")
                helper_ids[helper_name] = helper_ids.get(helper_name, 0) + 1

    call_count = sum(1 for m in mnemonics if m == "call")
    jump_count = sum(1 for m in mnemonics if m.startswith("j") or m in {"goto", "if"})
    exit_count = sum(1 for m in mnemonics if m == "exit")

    return {
        "instructions": len(instruction_lines),
        "calls": call_count,
        "helper_calls_estimate": sum(helper_ids.values()),
        "jumps": jump_count,
        "exits": exit_count,
        "estimated_stack_depth_bytes": max(stack_offsets) if stack_offsets else 0,
        "helper_call_breakdown": helper_ids,
    }


def analyze_object_files(files: Sequence[Path], objdump_cmd: Optional[str], warnings: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Collect object-file metrics for a list of .o files."""
    totals: Dict[str, Any] = {
        "files": 0,
        "instructions": 0,
        "calls": 0,
        "helper_calls_estimate": 0,
        "jumps": 0,
        "exits": 0,
        "estimated_stack_depth_bytes": 0,
    }
    helper_breakdown: Dict[str, int] = {}
    per_file: List[Dict[str, Any]] = []

    for path in files:
        if not path.exists():
            warnings.append(f"Object file not found: {path}")
            continue
        text = disassemble_object(path, objdump_cmd, warnings)
        if text is None:
            continue
        parsed = parse_objdump_disassembly(text)
        totals["files"] += 1
        for key in ["instructions", "calls", "helper_calls_estimate", "jumps", "exits"]:
            totals[key] += int(parsed.get(key, 0))
        totals["estimated_stack_depth_bytes"] = max(
            int(totals["estimated_stack_depth_bytes"]),
            int(parsed.get("estimated_stack_depth_bytes", 0)),
        )
        for helper, count in (parsed.get("helper_call_breakdown") or {}).items():
            helper_breakdown[helper] = helper_breakdown.get(helper, 0) + int(count)
        per_file.append({"path": str(path), **parsed})

    if helper_breakdown:
        totals["helper_call_breakdown"] = helper_breakdown
    return {"object": totals}, {"object": {"per_file": per_file}}


# ---------------------------------------------------------------------------
# Verifier-log metrics
# ---------------------------------------------------------------------------

def parse_verifier_log(text: str) -> Dict[str, Any]:
    """Extract metrics from Linux verifier logs/bpftool load output."""
    metrics: Dict[str, Any] = {
        "log_bytes": len(text.encode("utf-8", errors="replace")),
        "log_lines": len(text.splitlines()),
        "likely_failure": 0,
    }

    patterns = {
        "processed_insns": [
            r"processed\s+(\d+)\s+insns",
            r"processed_insns\s*[=:]\s*(\d+)",
        ],
        "verification_time_usec": [
            r"verification\s+time\s+(\d+)\s+usec",
            r"verification_time\s*[=:]\s*(\d+)",
        ],
        "total_states": [r"total_states\s+(\d+)", r"total_states\s*[=:]\s*(\d+)"],
        "peak_states": [r"peak_states\s+(\d+)", r"peak_states\s*[=:]\s*(\d+)"],
        "mark_read": [r"mark_read\s+(\d+)", r"mark_read\s*[=:]\s*(\d+)"],
        "max_states_per_insn": [r"max_states_per_insn\s+(\d+)", r"max_states_per_insn\s*[=:]\s*(\d+)"],
        "stack_depth_bytes": [r"stack depth\s+(\d+)", r"stack_depth\s*[=:]\s*(\d+)"],
    }

    for metric, regexes in patterns.items():
        for pattern in regexes:
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            if matches:
                metrics[metric] = int(matches[-1])
                break

    failure_patterns = [
        r"\bR\d+ invalid mem access",
        r"invalid access to packet",
        r"math between .* pointer",
        r"invalid stack",
        r"unbounded",
        r"permission denied",
        r"processed \d+ insns.*limit",
        r"BPF program is too large",
        r"verification failed",
        r"Error loading program",
    ]
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in failure_patterns):
        metrics["likely_failure"] = 1

    return metrics


def analyze_verifier_logs(files: Sequence[Path], warnings: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Collect verifier metrics from log files."""
    per_file: List[Dict[str, Any]] = []
    for path in files:
        if not path.exists():
            warnings.append(f"Verifier log not found: {path}")
            continue
        parsed = parse_verifier_log(read_text(path))
        per_file.append({"path": str(path), **parsed})

    totals: Dict[str, Any] = {"files": len(per_file)}
    for key in [
        "log_bytes",
        "log_lines",
        "processed_insns",
        "verification_time_usec",
        "total_states",
        "peak_states",
        "mark_read",
        "max_states_per_insn",
        "stack_depth_bytes",
        "likely_failure",
    ]:
        values = [to_number(row.get(key)) for row in per_file]
        values = [v for v in values if v is not None]
        if not values:
            continue
        if key in {"peak_states", "max_states_per_insn", "stack_depth_bytes"}:
            totals[key] = max(values)
        else:
            totals[key] = sum(values)

    return {"verifier": totals}, {"verifier": {"per_file": per_file}}


# ---------------------------------------------------------------------------
# Extra benchmark metrics
# ---------------------------------------------------------------------------

def merge_numeric_json(target: Dict[str, Any], source: Mapping[str, Any], prefix: str = "") -> None:
    """Merge numeric values from JSON into a flat dict."""
    for key, value in source.items():
        out_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            merge_numeric_json(target, value, out_key)
        else:
            num = to_number(value)
            if num is not None:
                target[out_key] = num
            elif isinstance(value, str):
                target[out_key] = value


def load_extra_json(files: Sequence[Path], warnings: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Import externally measured performance/usability metrics from JSON."""
    merged: Dict[str, Any] = {}
    raw_files: List[Dict[str, Any]] = []
    for path in files:
        if not path.exists():
            warnings.append(f"Extra JSON file not found: {path}")
            continue
        try:
            data = json.loads(read_text(path))
            if isinstance(data, Mapping):
                merge_numeric_json(merged, data)
            raw_files.append({"path": str(path), "data": data})
        except Exception as exc:
            warnings.append(f"Failed to parse extra JSON {path}: {exc}")
    return ({"extra": merged} if merged else {}, {"extra": {"files": raw_files}})


# ---------------------------------------------------------------------------
# Analysis orchestration
# ---------------------------------------------------------------------------

def merge_metrics(dst: Dict[str, Any], src: Mapping[str, Any]) -> None:
    """Deep-merge metric dictionaries."""
    for key, value in src.items():
        if isinstance(value, Mapping) and isinstance(dst.get(key), dict):
            merge_metrics(dst[key], value)  # type: ignore[index]
        else:
            dst[key] = value


def build_side_inventory(
    label: str,
    source_paths: Sequence[Path],
    source_files: Sequence[Path],
    object_paths: Sequence[Path],
    verifier_log_paths: Sequence[Path],
    extra_json_paths: Sequence[Path],
    exclude_dirs: Sequence[str],
    exclude_regexes: Sequence[str],
) -> SideInventory:
    """Discover test sources and generated artifacts for one comparison side."""
    resolved_source_paths = [p.resolve() for p in source_paths]

    # If explicit artifact paths are not provided, look next to the sources so
    # users can simply run make in each test directory and then point here.
    object_inputs = list(object_paths) if object_paths else list(source_paths)
    object_files = collect_artifact_files(object_inputs, [".o"], exclude_dirs, exclude_regexes)
    verifier_log_inputs = list(verifier_log_paths) if verifier_log_paths else list(source_paths)
    verifier_logs = collect_artifact_files(verifier_log_inputs, [".log", ".txt"], exclude_dirs, exclude_regexes)
    extra_json_files = collect_artifact_files(extra_json_paths, [".json"], exclude_dirs, exclude_regexes)

    test_source_files = select_test_source_files(source_files, object_files)
    sources_by_test = group_paths_by_test_name(test_source_files)
    objects_by_test = group_paths_by_test_name(object_files)
    verifier_logs_by_test = group_paths_by_test_name(verifier_logs)
    extra_json_by_test = group_paths_by_test_name(extra_json_files)

    return SideInventory(
        label=label,
        source_paths=resolved_source_paths,
        all_source_files=sorted(set(source_files)),
        test_source_files=test_source_files,
        object_files=object_files,
        verifier_logs=verifier_logs,
        extra_json_files=extra_json_files,
        sources_by_test=sources_by_test,
        objects_by_test=objects_by_test,
        verifier_logs_by_test=verifier_logs_by_test,
        extra_json_by_test=extra_json_by_test,
    )


def make_analysis_unit(
    inventory: SideInventory,
    test_names: Sequence[str],
    args: argparse.Namespace,
) -> AnalysisUnit:
    """Build an aggregate unit from selected tests in an inventory."""
    if test_names:
        source_files = filter_grouped_paths(inventory.sources_by_test, test_names)
        object_files = filter_grouped_paths(inventory.objects_by_test, test_names)
        verifier_logs = filter_grouped_paths(inventory.verifier_logs_by_test, test_names)
        extra_json_files = filter_grouped_paths(inventory.extra_json_by_test, test_names)
        source_paths = source_files or inventory.source_paths
    else:
        source_files = inventory.test_source_files or inventory.all_source_files
        object_files = inventory.object_files
        verifier_logs = inventory.verifier_logs
        extra_json_files = inventory.extra_json_files
        source_paths = source_files or inventory.source_paths

    return AnalysisUnit(
        label=inventory.label,
        source_paths=[p.resolve() for p in source_paths],
        source_files=[p.resolve() for p in source_files],
        object_files=[p.resolve() for p in object_files],
        verifier_logs=[p.resolve() for p in verifier_logs],
        extra_json_files=[p.resolve() for p in extra_json_files],
    )


def make_test_unit(inventory: SideInventory, test_name: str) -> AnalysisUnit:
    """Build a unit for a single test case."""
    source_files = inventory.sources_by_test.get(test_name, [])
    source_paths = source_files or inventory.source_paths
    return AnalysisUnit(
        label=inventory.label,
        source_paths=[p.resolve() for p in source_paths],
        source_files=[p.resolve() for p in source_files],
        object_files=[p.resolve() for p in inventory.objects_by_test.get(test_name, [])],
        verifier_logs=[p.resolve() for p in inventory.verifier_logs_by_test.get(test_name, [])],
        extra_json_files=[p.resolve() for p in inventory.extra_json_by_test.get(test_name, [])],
    )


def analyze_unit(
    unit: AnalysisUnit,
    args: argparse.Namespace,
    use_imported_line_counter_reports: bool = True,
) -> UnitResult:
    """Run all enabled analyses for a baseline/framework unit."""
    result = UnitResult(label=unit.label)

    if not unit.source_files:
        result.warnings.append(f"No source files found for {unit.label}")

    if not args.no_lizard:
        metrics, raw = analyze_with_lizard(unit.source_files, args.lizard_enable_nesting, result.warnings)
        merge_metrics(result.metrics, metrics)
        merge_metrics(result.raw, raw)

    if not args.no_cognitive_complexity:
        metrics, raw = analyze_cognitive_complexity(unit.source_files, result.warnings)
        merge_metrics(result.metrics, metrics)
        merge_metrics(result.raw, raw)

    if use_imported_line_counter_reports and unit.label == "baseline" and args.baseline_line_counter_report:
        metrics, raw = load_line_counter_report(args.baseline_line_counter_report, result.warnings)
    elif use_imported_line_counter_reports and unit.label == "framework" and args.framework_line_counter_report:
        metrics, raw = load_line_counter_report(args.framework_line_counter_report, result.warnings)
    else:
        metrics, raw = run_line_counter(
            unit.source_paths,
            args.line_counter,
            args.line_counter_command_template,
            result.warnings,
        )
    merge_metrics(result.metrics, metrics)
    merge_metrics(result.raw, raw)

    metrics, raw = analyze_ebpf_source_patterns(unit.source_files, args.framework_api_prefix)
    merge_metrics(result.metrics, metrics)
    merge_metrics(result.raw, raw)

    if unit.object_files:
        metrics, raw = analyze_object_files(unit.object_files, args.objdump, result.warnings)
        merge_metrics(result.metrics, metrics)
        merge_metrics(result.raw, raw)

    if unit.verifier_logs:
        metrics, raw = analyze_verifier_logs(unit.verifier_logs, result.warnings)
        merge_metrics(result.metrics, metrics)
        merge_metrics(result.raw, raw)

    if unit.extra_json_files:
        metrics, raw = load_extra_json(unit.extra_json_files, result.warnings)
        merge_metrics(result.metrics, metrics)
        merge_metrics(result.raw, raw)

    result.raw["inputs"] = {
        "source_paths": [str(p) for p in unit.source_paths],
        "source_files": [str(p) for p in unit.source_files],
        "object_files": [str(p) for p in unit.object_files],
        "verifier_logs": [str(p) for p in unit.verifier_logs],
        "extra_json_files": [str(p) for p in unit.extra_json_files],
    }
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_comparison(baseline: Mapping[str, Any], framework: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Build a flat comparison table from two nested metric dicts."""
    flat_base = flatten_dict(baseline)
    flat_fw = flatten_dict(framework)
    all_keys = sorted(set(flat_base) | set(flat_fw))
    rows: List[Dict[str, Any]] = []

    for key in all_keys:
        base_val = flat_base.get(key)
        fw_val = flat_fw.get(key)
        base_num = to_number(base_val)
        fw_num = to_number(fw_val)
        row: Dict[str, Any] = {
            "metric": key,
            "baseline": round_value(base_val),
            "framework": round_value(fw_val),
            "delta_framework_minus_baseline": None,
            "pct_change": None,
            "higher_is_better": metric_higher_is_better(key),
            "improvement_pct": None,
        }
        if base_num is not None and fw_num is not None:
            row["delta_framework_minus_baseline"] = round_value(fw_num - base_num)
            row["pct_change"] = round_value(pct_change(base_num, fw_num))
            row["improvement_pct"] = round_value(improvement_pct(base_num, fw_num, row["higher_is_better"]))
        rows.append(row)
    return rows


def metric_priority(metric: str) -> Tuple[int, str]:
    """Sort important paper metrics first."""
    prefixes = [
        "cognitive_complexity.total",
        "cognitive_complexity.per_function",
        "cognitive_complexity.max_nesting_estimate",
        "lizard.nloc",
        "lizard.ccn",
        "lizard.function_count",
        "lizard.token_count",
        "lizard.parameter_count",
        "lizard.nesting",
        "line_counter",
        "ebpf_source.manual_bounds_checks",
        "ebpf_source.raw_packet_pointer_arithmetic_sites",
        "ebpf_source.direct_header_casts",
        "ebpf_source.endian_conversions",
        "ebpf_source.bpf_helper_calls",
        "object.instructions",
        "object.estimated_stack_depth_bytes",
        "object.helper_calls_estimate",
        "verifier.processed_insns",
        "verifier.total_states",
        "verifier.peak_states",
        "verifier.max_states_per_insn",
        "verifier.verification_time_usec",
    ]
    for i, prefix in enumerate(prefixes):
        if metric.startswith(prefix):
            return (i, metric)
    return (len(prefixes), metric)


def format_cell(value: Any) -> str:
    """Format a value for Markdown."""
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


def scoped_comparison_rows(report: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Return aggregate and per-test comparison rows with scope metadata."""
    rows: List[Dict[str, Any]] = []
    for row in report.get("comparison", []):
        scoped = {"scope": "aggregate", "test": "", **dict(row)}
        rows.append(scoped)
    for test_name, test_report in sorted((report.get("tests") or {}).items()):
        for row in test_report.get("comparison", []):
            scoped = {"scope": "test", "test": test_name, **dict(row)}
            rows.append(scoped)
    return rows


def write_csv_report(path: Path, report: Mapping[str, Any]) -> None:
    """Write aggregate and per-test comparison tables as CSV."""
    fieldnames = [
        "scope",
        "test",
        "metric",
        "baseline",
        "framework",
        "delta_framework_minus_baseline",
        "pct_change",
        "higher_is_better",
        "improvement_pct",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in scoped_comparison_rows(report):
            writer.writerow({k: row.get(k) for k in fieldnames})


def append_comparison_table(lines: List[str], rows: Sequence[Mapping[str, Any]]) -> None:
    """Append a Markdown comparison table."""
    rows = list(rows)
    rows = sorted(rows, key=lambda r: metric_priority(str(r["metric"])))

    lines.append("| Metric | Baseline | Framework | Delta | % change | Improvement % |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in rows:
        metric = str(row["metric"])
        # Keep the Markdown report readable: include all primary metrics and all
        # metrics with numeric comparison; raw string-only metadata stays in JSON.
        if row.get("delta_framework_minus_baseline") is None and not any(
            metric.startswith(prefix)
            for prefix in [
                "cognitive_complexity.",
                "lizard.",
                "line_counter.",
                "ebpf_source.",
                "object.",
                "verifier.",
                "extra.",
            ]
        ):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    metric,
                    format_cell(row.get("baseline")),
                    format_cell(row.get("framework")),
                    format_cell(row.get("delta_framework_minus_baseline")),
                    format_cell(row.get("pct_change")),
                    format_cell(row.get("improvement_pct")),
                ]
            )
            + " |"
        )


def write_markdown_report(path: Path, report: Mapping[str, Any]) -> None:
    """Write a compact Markdown report."""
    lines: List[str] = []
    lines.append("# eBPF framework comparison metrics")
    lines.append("")
    lines.append("## Tool status")
    lines.append("")
    lines.append("| Tool | Available | Version/path | Notes |")
    lines.append("|---|---:|---|---|")
    for tool in report.get("tool_status", []):
        version_path = tool.get("version") or tool.get("path") or ""
        notes = tool.get("error") or ""
        lines.append(f"| {tool.get('name')} | {tool.get('available')} | {format_cell(version_path)} | {format_cell(notes)} |")

    lines.append("")
    lines.append("## Aggregate comparison")
    lines.append("")
    lines.append("Positive improvement means the framework is better according to the metric direction heuristic.")
    lines.append("")
    append_comparison_table(lines, report["comparison"])

    tests = report.get("tests") or {}
    if tests:
        lines.append("")
        lines.append("## Per-test comparisons")
        for test_name, test_report in sorted(tests.items()):
            lines.append("")
            lines.append(f"### {test_name}")
            lines.append("")
            append_comparison_table(lines, test_report.get("comparison", []))

    for label in ["baseline", "framework"]:
        warnings = report.get("units", {}).get(label, {}).get("warnings", [])
        if warnings:
            lines.append("")
            lines.append(f"## Warnings: {label}")
            lines.append("")
            for warning in warnings:
                lines.append(f"- {warning}")

    for test_name, test_report in sorted(tests.items()):
        for label in ["baseline", "framework"]:
            warnings = test_report.get("units", {}).get(label, {}).get("warnings", [])
            if warnings:
                lines.append("")
                lines.append(f"## Warnings: {test_name} / {label}")
                lines.append("")
                for warning in warnings:
                    lines.append(f"- {warning}")

    lines.append("")
    lines += build_macro_summary_markdown(report)
    write_text(path, "\n".join(lines))


def safe_report_filename(name: str) -> str:
    """Return a filesystem-friendly report file stem."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return cleaned.strip("._") or "report"


def write_json_file(path: Path, payload: Mapping[str, Any]) -> None:
    """Write a JSON file with the same formatting as the main report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_comparison_csv_rows(path: Path, rows: Sequence[Mapping[str, Any]], scope: str, test: str = "") -> None:
    """Write one comparison table as CSV."""
    fieldnames = [
        "scope",
        "test",
        "metric",
        "baseline",
        "framework",
        "delta_framework_minus_baseline",
        "pct_change",
        "higher_is_better",
        "improvement_pct",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            scoped = {"scope": scope, "test": test, **dict(row)}
            writer.writerow({k: scoped.get(k) for k in fieldnames})


def write_tool_status_markdown(path: Path, report: Mapping[str, Any]) -> None:
    """Write tool status as a standalone Markdown file."""
    lines = ["# Tool status", "", "| Tool | Available | Version/path | Notes |", "|---|---:|---|---|"]
    for tool in report.get("tool_status", []):
        version_path = tool.get("version") or tool.get("path") or ""
        notes = tool.get("error") or ""
        lines.append(f"| {tool.get('name')} | {tool.get('available')} | {format_cell(version_path)} | {format_cell(notes)} |")
    lines.append("")
    write_text(path, "\n".join(lines))


def write_warnings_markdown(path: Path, report: Mapping[str, Any]) -> None:
    """Write aggregate and per-test warnings as a standalone Markdown file."""
    lines = ["# Warnings", ""]
    any_warning = False
    for label in ["baseline", "framework"]:
        warnings = report.get("units", {}).get(label, {}).get("warnings", [])
        if warnings:
            any_warning = True
            lines.extend([f"## {label}", ""])
            for warning in warnings:
                lines.append(f"- {warning}")
            lines.append("")

    for test_name, test_report in sorted((report.get("tests") or {}).items()):
        for label in ["baseline", "framework"]:
            warnings = test_report.get("units", {}).get(label, {}).get("warnings", [])
            if warnings:
                any_warning = True
                lines.extend([f"## {test_name} / {label}", ""])
                for warning in warnings:
                    lines.append(f"- {warning}")
                lines.append("")

    if not any_warning:
        lines.append("No warnings.")
        lines.append("")
    write_text(path, "\n".join(lines))


# ---------------------------------------------------------------------------
# Macro-perf summary: programs and metrics of interest
# ---------------------------------------------------------------------------

MACRO_PROGRAMS: List[Tuple[str, str]] = [
    ("xdp_fib4_forward",  "tc_fib4_forward"),
    ("xdp_fib6_forward",  "tc_fib6_forward"),
    ("xdp_mmlf",          "tc_mmlf"),
    ("xdp_mmlf6",         "tc_mmlf6"),
    ("xdp_ipip_encap",    "tc_ipip_encap"),
    ("xdp_static_dnat",   "tc_static_dnat"),
    ("xdp_static_dnat6",  "tc_static_dnat6"),
    ("xdp_srv6_encap",    "tc_srv6_encap"),
]

MACRO_METRICS: List[Tuple[str, str]] = [
    ("line_counter.code",          "LOC"),
    ("cognitive_complexity.total", "Cog.Cplx"),
    ("lizard.ccn.max",             "CCN max"),
    ("object.instructions",        "BPF insns"),
    ("verifier.processed_insns",   "Verif. insns"),
    ("verifier.stack_depth_bytes", "Stack (B)"),
]


def _macro_get(test_data: Mapping[str, Any], metric_key: str):
    """Return (baseline, framework, pct_change) for a metric in a test entry."""
    for entry in test_data.get("comparison", []):
        if entry["metric"] == metric_key:
            return entry.get("baseline"), entry.get("framework"), entry.get("pct_change")
    return None, None, None


def _macro_fmt_val(v: Any) -> str:
    if v is None:
        return "N/A"
    if isinstance(v, float) and v != int(v):
        return f"{v:.1f}"
    return str(int(v)) if isinstance(v, float) else str(v)


def _macro_fmt_pct(pct: Any) -> str:
    if pct is None:
        return "N/A"
    sign = "+" if float(pct) > 0 else ""
    return f"{sign}{float(pct):.1f}%"


def _macro_fmt_delta(base: Any, fw: Any) -> str:
    try:
        d = float(fw) - float(base)
        return f"{d:+.1f}" if d != int(d) else f"{int(d):+d}"
    except (TypeError, ValueError):
        return "N/A"


def build_macro_summary_markdown(report: Mapping[str, Any]) -> List[str]:
    """Build Markdown lines for the macro-perf summary section."""
    tests = report.get("tests") or {}
    lines: List[str] = []

    lines += [
        "# Macro-perf summary",
        "",
        "Key metrics for the programs used in macro-perf experiments.",
        "Baseline = handwritten eBPF; Framework = bnt API.",
        "Delta is Framework − Baseline.",
        "",
    ]

    for metric_key, label in MACRO_METRICS:
        lines += [f"## {label}", "", f"*{metric_key}*", ""]
        lines.append("| Program | Baseline | Framework | Δ abs | Δ% |")
        lines.append("|:--------|---:|---:|---:|---:|")
        for xdp_prog, tc_prog in MACRO_PROGRAMS:
            for prog in (xdp_prog, tc_prog):
                if prog not in tests:
                    continue
                base, fw, pct = _macro_get(tests[prog], metric_key)
                lines.append(
                    f"| `{prog}` | {_macro_fmt_val(base)} | {_macro_fmt_val(fw)}"
                    f" | {_macro_fmt_delta(base, fw)} | {_macro_fmt_pct(pct)} |"
                )
            lines.append("|  |  |  |  |  |")
        lines.append("")

    return lines


def write_macro_summary_markdown(path: Path, report: Mapping[str, Any]) -> None:
    write_text(path, "\n".join(build_macro_summary_markdown(report)))


def write_aggregate_markdown(path: Path, report: Mapping[str, Any]) -> None:
    """Write only the aggregate comparison table."""
    lines = [
        "# Aggregate comparison",
        "",
        "Positive improvement means the framework is better according to the metric direction heuristic.",
        "",
    ]
    append_comparison_table(lines, report.get("comparison", []))
    lines.append("")
    write_text(path, "\n".join(lines))


def write_test_markdown(path: Path, test_name: str, test_report: Mapping[str, Any]) -> None:
    """Write one per-test comparison table."""
    lines = [f"# {test_name}", ""]
    append_comparison_table(lines, test_report.get("comparison", []))
    lines.append("")
    write_text(path, "\n".join(lines))


def write_split_reports(output_dir: Path, report: Mapping[str, Any]) -> None:
    """Write report parts into separate files for easier review."""
    output_dir.mkdir(parents=True, exist_ok=True)
    tests_dir = output_dir / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    write_tool_status_markdown(output_dir / "tool_status.md", report)
    write_warnings_markdown(output_dir / "warnings.md", report)

    aggregate_payload = {
        "metadata": report.get("metadata", {}),
        "tool_status": report.get("tool_status", []),
        "units": report.get("units", {}),
        "comparison": report.get("comparison", []),
    }
    write_aggregate_markdown(output_dir / "aggregate.md", report)
    write_comparison_csv_rows(output_dir / "aggregate.csv", report.get("comparison", []), "aggregate")
    write_json_file(output_dir / "aggregate.json", aggregate_payload)
    write_macro_summary_markdown(output_dir / "summary.md", report)

    index_lines = [
        "# Split metrics report",
        "",
        "- [Macro-perf summary](summary.md)",
        "- [Aggregate comparison](aggregate.md)",
        "- [Tool status](tool_status.md)",
        "- [Warnings](warnings.md)",
        "",
        "## Tests",
        "",
    ]

    for test_name, test_report in sorted((report.get("tests") or {}).items()):
        stem = safe_report_filename(test_name)
        md_name = f"{stem}.md"
        csv_name = f"{stem}.csv"
        json_name = f"{stem}.json"
        write_test_markdown(tests_dir / md_name, test_name, test_report)
        write_comparison_csv_rows(tests_dir / csv_name, test_report.get("comparison", []), "test", test_name)
        write_json_file(tests_dir / json_name, test_report)
        index_lines.append(f"- [{test_name}](tests/{md_name})")

    index_lines.append("")
    write_text(output_dir / "index.md", "\n".join(index_lines))


def collect_tool_status(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Collect tool availability for reproducibility metadata."""
    statuses: List[ToolStatus] = []

    # Lizard package version.
    try:
        import lizard  # type: ignore
        version = getattr(lizard, "__version__", None) or "importable"
        statuses.append(ToolStatus("python:lizard", True, str(version)))
    except Exception as exc:
        statuses.append(ToolStatus("python:lizard", False, error=str(exc)))

    statuses.append(
        ToolStatus(
            "local:cognitive_complexity",
            not args.no_cognitive_complexity,
            version=COGNITIVE_COMPLEXITY_ALGORITHM,
            path=Path(__file__).name,
            error=None if not args.no_cognitive_complexity else "disabled by --no-cognitive-complexity",
        )
    )

    for cmd in ["lizard", "nloc", "cloc", "sloc", args.objdump or "llvm-objdump", "objdump"]:
        if not cmd:
            continue
        name = Path(cmd).name
        if name in {s.name for s in statuses}:
            continue
        statuses.append(command_version(cmd))

    return [status.__dict__ for status in statuses]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Compare source, cognitive-complexity, Lizard, object, and verifier metrics for eBPF framework evaluations.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    inputs = parser.add_argument_group("inputs")
    inputs.add_argument("--baseline", nargs="+", type=Path, required=True, help="Baseline source file(s) or directory/directories.")
    inputs.add_argument("--framework", nargs="+", type=Path, required=True, help="Framework-based source file(s) or directory/directories.")
    inputs.add_argument("--baseline-obj", nargs="*", type=Path, default=[], help="Baseline compiled eBPF object files.")
    inputs.add_argument("--framework-obj", nargs="*", type=Path, default=[], help="Framework compiled eBPF object files.")
    inputs.add_argument("--baseline-verifier-log", nargs="*", type=Path, default=[], help="Baseline verifier log files.")
    inputs.add_argument("--framework-verifier-log", nargs="*", type=Path, default=[], help="Framework verifier log files.")
    inputs.add_argument("--baseline-extra-json", nargs="*", type=Path, default=[], help="Baseline extra metrics JSON files.")
    inputs.add_argument("--framework-extra-json", nargs="*", type=Path, default=[], help="Framework extra metrics JSON files.")
    inputs.add_argument("--no-per-test", action="store_true", help="Disable automatic per-test grouping by source/object stem.")

    source = parser.add_argument_group("source collection")
    source.add_argument("--extensions", nargs="*", default=DEFAULT_SOURCE_EXTENSIONS, help="Source extensions to analyze.")
    source.add_argument("--include-headers", action="store_true", help="Also include .h/.hpp/.hh files.")
    source.add_argument("--exclude-dir", action="append", default=[], help="Directory name to exclude; may be repeated.")
    source.add_argument("--exclude-regex", action="append", default=[], help="Regex path filter to exclude files; may be repeated.")
    source.add_argument(
        "--framework-api-prefix",
        nargs="*",
        default=["bnt"],
        help="Function-name prefixes treated as framework API calls, e.g. bnt ebpfx.",
    )

    lizard_group = parser.add_argument_group("Lizard")
    lizard_group.add_argument("--no-lizard", action="store_true", help="Disable Lizard metrics.")
    lizard_group.add_argument("--lizard-enable-nesting", action="store_true", help="Try to enable Lizard nesting extension metrics.")

    cognitive = parser.add_argument_group("local cognitive complexity")
    cognitive.add_argument(
        "--no-cognitive-complexity",
        action="store_true",
        help="Disable the built-in C/eBPF cognitive-complexity estimate.",
    )

    line_counter = parser.add_argument_group("external line counter")
    line_counter.add_argument(
        "--line-counter",
        choices=["auto", "nloc", "cloc", "sloc", "none"],
        default="auto",
        help="External LOC counter adapter. Lizard NLOC is separate and preferred for function metrics.",
    )
    line_counter.add_argument(
        "--line-counter-command-template",
        help="Custom command template, e.g. 'nloc --xml {output} {paths}' or 'cloc --json {paths}'.",
    )
    line_counter.add_argument("--baseline-line-counter-report", type=Path, help="Import precomputed baseline nloc/sloc/cloc report.")
    line_counter.add_argument("--framework-line-counter-report", type=Path, help="Import precomputed framework nloc/sloc/cloc report.")

    obj = parser.add_argument_group("object metrics")
    obj.add_argument("--objdump", help="objdump command; defaults to llvm-objdump then objdump.")

    outputs = parser.add_argument_group("outputs")
    outputs.add_argument("--json", type=Path, help="Write full JSON report.")
    outputs.add_argument("--csv", type=Path, help="Write flat CSV comparison.")
    outputs.add_argument("--markdown", type=Path, help="Write Markdown report.")
    outputs.add_argument(
        "--split-output-dir",
        type=Path,
        help="Write separate aggregate, per-test, warning, and tool-status files into this directory.",
    )
    outputs.add_argument("--print-json", action="store_true", help="Print JSON report to stdout.")
    outputs.add_argument("--check-tools", action="store_true", help="Print tool status and continue with the analysis.")

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)

    extensions = parse_extensions(args)
    exclude_dirs = sorted(DEFAULT_EXCLUDE_DIRS | set(args.exclude_dir or []))
    artifact_exclude_dirs = sorted(DEFAULT_ARTIFACT_EXCLUDE_DIRS | set(args.exclude_dir or []))
    exclude_regexes = args.exclude_regex or []

    baseline_files = collect_source_files(args.baseline, extensions, exclude_dirs, exclude_regexes)
    framework_files = collect_source_files(args.framework, extensions, exclude_dirs, exclude_regexes)

    baseline_inventory = build_side_inventory(
        "baseline",
        args.baseline,
        baseline_files,
        args.baseline_obj,
        args.baseline_verifier_log,
        args.baseline_extra_json,
        artifact_exclude_dirs,
        exclude_regexes,
    )
    framework_inventory = build_side_inventory(
        "framework",
        args.framework,
        framework_files,
        args.framework_obj,
        args.framework_verifier_log,
        args.framework_extra_json,
        artifact_exclude_dirs,
        exclude_regexes,
    )

    test_names: List[str] = []
    if not args.no_per_test:
        test_names = sorted(set(baseline_inventory.sources_by_test) | set(framework_inventory.sources_by_test))

    baseline_unit = make_analysis_unit(baseline_inventory, test_names, args)
    framework_unit = make_analysis_unit(framework_inventory, test_names, args)

    tool_status = collect_tool_status(args)
    if args.check_tools:
        print(json.dumps({"tool_status": tool_status}, indent=2))

    baseline_result = analyze_unit(baseline_unit, args)
    framework_result = analyze_unit(framework_unit, args)

    comparison = build_comparison(baseline_result.metrics, framework_result.metrics)

    test_reports: Dict[str, Any] = {}
    for test_name in test_names:
        baseline_test_unit = make_test_unit(baseline_inventory, test_name)
        framework_test_unit = make_test_unit(framework_inventory, test_name)
        baseline_test_result = analyze_unit(
            baseline_test_unit,
            args,
            use_imported_line_counter_reports=False,
        )
        framework_test_result = analyze_unit(
            framework_test_unit,
            args,
            use_imported_line_counter_reports=False,
        )
        test_reports[test_name] = {
            "units": {
                "baseline": {
                    "metrics": baseline_test_result.metrics,
                    "raw": baseline_test_result.raw,
                    "warnings": baseline_test_result.warnings,
                },
                "framework": {
                    "metrics": framework_test_result.metrics,
                    "raw": framework_test_result.raw,
                    "warnings": framework_test_result.warnings,
                },
            },
            "comparison": build_comparison(baseline_test_result.metrics, framework_test_result.metrics),
        }

    report: Dict[str, Any] = {
        "metadata": {
            "script": Path(__file__).name,
            "python": sys.version,
            "source_extensions": extensions,
            "exclude_dirs": exclude_dirs,
            "artifact_exclude_dirs": artifact_exclude_dirs,
            "exclude_regexes": exclude_regexes,
            "framework_api_prefix": args.framework_api_prefix,
            "cognitive_complexity_enabled": not args.no_cognitive_complexity,
            "cognitive_complexity_algorithm": COGNITIVE_COMPLEXITY_ALGORITHM,
            "per_test_enabled": not args.no_per_test,
            "test_names": test_names,
            "aggregate_scope": "selected_tests" if test_names else "all_collected_sources",
            "artifact_discovery": {
                "baseline_objects": [str(p) for p in baseline_inventory.object_files],
                "framework_objects": [str(p) for p in framework_inventory.object_files],
                "baseline_test_sources": [str(p) for p in baseline_inventory.test_source_files],
                "framework_test_sources": [str(p) for p in framework_inventory.test_source_files],
            },
        },
        "tool_status": tool_status,
        "units": {
            "baseline": {
                "metrics": baseline_result.metrics,
                "raw": baseline_result.raw,
                "warnings": baseline_result.warnings,
            },
            "framework": {
                "metrics": framework_result.metrics,
                "raw": framework_result.raw,
                "warnings": framework_result.warnings,
            },
        },
        "comparison": comparison,
        "tests": test_reports,
    }

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.csv:
        write_csv_report(args.csv, report)
    if args.markdown:
        write_markdown_report(args.markdown, report)
    if args.split_output_dir:
        write_split_reports(args.split_output_dir, report)
    if args.print_json or not any([args.json, args.csv, args.markdown, args.split_output_dir]):
        print(json.dumps(report, indent=2, sort_keys=True))

    # Non-zero only for malformed invocation/runtime crash. Missing tools are
    # warnings because this script is often run in partial environments.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
