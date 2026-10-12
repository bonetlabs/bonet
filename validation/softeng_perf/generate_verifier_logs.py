#!/usr/bin/env python3
"""
generate_verifier_logs.py

Automatically generate verifier logs for all eBPF object files using bpftool.

This script extracts the Linux verifier output for both baseline and framework
eBPF programs, saving them as .verifier.log files that can be consumed by
compare_metrics.py.

Typical usage:

  python3 generate_verifier_logs.py \
      --baseline ../baseline \
      --framework ../framework

Or pass explicit object directories:

  python3 generate_verifier_logs.py \
      --baseline ../baseline \
      --framework ../framework \
      --output-dir verifier_logs

The script will:
  1. Rebuild the baseline and framework objects from a clean state
  2. Find all .o files in the specified directories
  3. Use bpftool prog load to extract verifier logs
  4. Save logs as <basename>.verifier.log in the same directory as the .o file
     (or in --output-dir if specified)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


def format_command(argv: List[str]) -> str:
    """Return a shell-readable command for logs."""
    return " ".join(shlex.quote(part) for part in argv)


def find_bpftool() -> Optional[str]:
    """Find bpftool in PATH."""
    result = shutil.which("bpftool")
    if result:
        return result
    
    # Try common locations
    common_paths = [
        "/usr/sbin/bpftool",
        "/usr/bin/bpftool",
        "/bin/bpftool",
    ]
    for path in common_paths:
        p = Path(path)
        if p.exists():
            return str(p)
    
    return None


import re
import subprocess
import uuid
from pathlib import Path
from typing import Optional


def infer_bpf_prog_type(obj_path: Path) -> str:
    """
    Infer the BPF program type from the object filename.

    This is a best-effort heuristic for the validation programs:
    - tc_* programs are usually SCHED_CLS classifiers;
    - xdp_* programs are XDP programs.
    """
    name = obj_path.name.lower()

    if name.startswith("tc_") or "tc" in name:
        return "classifier"

    if name.startswith("xdp_") or "xdp" in name:
        return "xdp"

    # Default to XDP because most validation examples are packet-path XDP programs.
    return "xdp"


def redact_sudo_prompt(text: str) -> str:
    """
    Remove common sudo password prompt noise from captured logs.
    """
    return re.sub(r"\[sudo\] password for .*?:\s*", "", text or "")


def extract_verifier_log(
    obj_path: Path,
    bpftool_path: str,
    prog_type: Optional[str] = None,
) -> Optional[str]:
    """
    Extract verifier log from an eBPF object file using bpftool.

    Returns the verifier/debug log text, or None if extraction fails.

    Notes:
    - bpftool prog load requires a bpffs pin path. Do not use /dev/null.
    - The verifier log is usually emitted on stderr.
    - Successful loads may only print useful verifier details when verbose/debug
      output is enabled.
    - The pinned program is removed immediately after loading.
    """
    obj_path = Path(obj_path)
    prog_type = prog_type or infer_bpf_prog_type(obj_path)

    pin_dir = Path("/sys/fs/bpf/bonet_verifier_tmp")
    pin_path = pin_dir / f"{obj_path.stem}_{prog_type}_{uuid.uuid4().hex}"

    # Prefer bpftool debug mode because it tends to expose libbpf/verifier output
    # even when the program successfully verifies.
    cmd = [
        "sudo",
        bpftool_path,
        "-d",
        "prog",
        "load",
        str(obj_path),
        str(pin_path),
        "type",
        prog_type,
    ]

    try:
        subprocess.run(
            ["sudo", "mkdir", "-p", str(pin_dir)],
            capture_output=True,
            text=True,
            timeout=5,
        )

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )

        verifier_output = "\n".join(
            part for part in [result.stdout, result.stderr] if part
        )
        verifier_output = redact_sudo_prompt(verifier_output).strip()

        if verifier_output:
            return verifier_output

        logger.warning(
            "No verifier output captured from %s using program type %s "
            "(return code %s)",
            obj_path,
            prog_type,
            result.returncode,
        )
        return None

    except subprocess.TimeoutExpired:
        logger.warning("Timeout extracting verifier log from %s", obj_path)
        return None

    except Exception as e:
        logger.warning("Error extracting verifier log from %s: %s", obj_path, e)
        return None

    finally:
        # Idempotent cleanup: remove the pinned program if it was created.
        # Ignore failures because the load may have failed before pinning.
        try:
            subprocess.run(
                ["sudo", "rm", "-f", str(pin_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            pass

def extract_verifier_log_with_libbpf(obj_path: Path) -> Optional[str]:
    """
    Alternative method using a minimal C program with libbpf.
    
    This is more reliable than bpftool for getting structured verifier output.
    """
    # Create a temporary C program that loads the object and captures verifier output
    verifier_extractor = """
#include <stdio.h>
#include <sys/rlimit.h>
#include <bpf/libbpf.h>

static char log_buf[256 * 1024];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <obj_path>\\n", argv[0]);
        return 1;
    }

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    libbpf_set_print(libbpf_print_fn);
    
    struct bpf_object_open_opts opts = {
        .kernel_log_buf = log_buf,
        .kernel_log_size = sizeof(log_buf),
        .kernel_log_level = 4,
    };
    
    struct bpf_object *obj = bpf_object__open_file(argv[1], &opts);
    if (!obj) {
        fprintf(stderr, "Failed to open object\\n");
        return 1;
    }
    
    int err = bpf_object__load(obj);
    
    if (log_buf[0]) {
        fprintf(stdout, "%s", log_buf);
    }
    
    bpf_object__close(obj);
    return 0;
}
"""
    # For now, we'll use the simpler bpftool approach
    # This can be enhanced later if needed
    return None


def get_object_files(paths: List[Path]) -> List[Path]:
    """Find all .o files in the given directories."""
    obj_files = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            logger.warning(f"Path does not exist: {path}")
            continue
        
        if p.is_file() and p.suffix == ".o":
            obj_files.append(p)
        elif p.is_dir():
            obj_files.extend(sorted(p.glob("*.o")))
    
    return sorted(set(obj_files))


def rebuild_object_dirs(paths: List[Path], dry_run: bool = False) -> bool:
    """
    Run make clean and make in each input directory that has a Makefile.

    Returning False means at least one rebuild command failed.
    """
    dirs: List[Path] = []
    seen = set()

    for path in paths:
        p = Path(path)
        build_dir = p.parent if p.exists() and p.is_file() else p
        key = build_dir.resolve()
        if key in seen:
            continue
        seen.add(key)
        dirs.append(build_dir)

    for build_dir in dirs:
        if not build_dir.exists():
            logger.warning("Skipping rebuild for missing path: %s", build_dir)
            continue
        if not (build_dir / "Makefile").exists():
            logger.warning("Skipping rebuild for %s: no Makefile found", build_dir)
            continue

        for target in ["clean", None]:
            cmd = ["make", "-C", str(build_dir)]
            if target:
                cmd.append(target)

            if dry_run:
                logger.info("Would run: %s", format_command(cmd))
                continue

            logger.info("Running: %s", format_command(cmd))
            result = subprocess.run(cmd, text=True)
            if result.returncode != 0:
                logger.error("Build command failed with exit code %s: %s", result.returncode, format_command(cmd))
                return False

    return True


def generate_verifier_logs(
    obj_files: List[Path],
    bpftool_path: str,
    output_dir: Optional[Path] = None,
) -> Tuple[int, int]:
    """
    Generate verifier logs for all object files.
    
    Returns (success_count, failure_count).
    """
    success_count = 0
    failure_count = 0
    
    for obj_path in obj_files:
        output_dir_to_use = output_dir if output_dir else obj_path.parent
        log_file = output_dir_to_use / f"{obj_path.stem}.verifier.log"
        
        logger.info(f"Processing: {obj_path}")
        
        verifier_log = extract_verifier_log(obj_path, bpftool_path)
        
        if verifier_log:
            try:
                output_dir_to_use.mkdir(parents=True, exist_ok=True)
                with open(log_file, "w") as f:
                    f.write(verifier_log)
                logger.info(f"  → Saved: {log_file}")
                success_count += 1
            except Exception as e:
                logger.error(f"  ✗ Failed to write {log_file}: {e}")
                failure_count += 1
        else:
            logger.warning(f"  ✗ Could not extract verifier log")
            failure_count += 1
    
    return success_count, failure_count


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate verifier logs for eBPF object files.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Baseline directory containing .o files.",
    )
    parser.add_argument(
        "--framework",
        type=Path,
        required=True,
        help="Framework directory containing .o files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional output directory for verifier logs. If not specified, logs are saved next to .o files.",
    )
    parser.add_argument(
        "--bpftool",
        type=str,
        default=None,
        help="Path to bpftool. If not specified, searches in PATH.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without actually generating logs.",
    )
    parser.add_argument(
        "--no-rebuild",
        action="store_true",
        help="Do not run make clean and make before generating verifier logs.",
    )
    
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)

    input_paths = [args.baseline, args.framework]

    if not args.no_rebuild:
        if not rebuild_object_dirs(input_paths, args.dry_run):
            return 1

    # Collect object files after the optional rebuild.
    obj_files = get_object_files(input_paths)
    
    if not obj_files:
        logger.error("No .o files found in specified directories.")
        return 1
    
    logger.info(f"Found {len(obj_files)} object file(s)")
    
    if args.dry_run:
        for obj_path in obj_files:
            log_file = (args.output_dir or obj_path.parent) / f"{obj_path.stem}.verifier.log"
            logger.info(f"Would process: {obj_path} → {log_file}")
        return 0

    # Find bpftool
    bpftool_path = args.bpftool or find_bpftool()
    if not bpftool_path:
        logger.error("bpftool not found. Install with: sudo apt install linux-tools-generic")
        return 1

    logger.info(f"Using bpftool: {bpftool_path}")
    
    # Generate verifier logs
    success_count, failure_count = generate_verifier_logs(
        obj_files,
        bpftool_path,
        args.output_dir,
    )
    
    logger.info(f"\nResults: {success_count} succeeded, {failure_count} failed")
    
    if failure_count > 0:
        logger.warning("Some verifier logs could not be generated. This may be expected if:")
        logger.warning("  - bpftool is not running with proper permissions")
        logger.warning("  - The system does not support loading these eBPF programs")
        logger.warning("  - The object files have permission issues")
    
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
