#!/usr/bin/env python3
"""
Advanced Session Minimizer for Lafleur crash bundles.

This tool reduces a multi-script session crash (e.g., polluter -> warmup -> attack)
into a single, minimal Python script that reproduces the bug. It employs a three-stage
process:
1. Script Minimization: Identifying which scripts in the sequence are necessary.
2. Concatenation: Merging necessary scripts into one file (renaming harnesses).
3. Code Minimization: Using 'shrinkray' to reduce the final source code.
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

from lafleur.utils import FUZZING_ENV


def _make_repro_env() -> dict[str, str]:
    """Create environment for crash reproduction.

    Based on FUZZING_ENV but with verbose logging disabled for speed.
    """
    env = FUZZING_ENV.copy()
    env["PYTHON_LLTRACE"] = "0"
    env["PYTHON_OPT_DEBUG"] = "0"
    return env


def extract_grep_pattern(metadata: dict) -> str:
    """Extract a grep pattern from the crash fingerprint metadata."""
    fingerprint = metadata.get("fingerprint", "")

    if fingerprint.startswith("ASAN:"):
        return "AddressSanitizer"
    elif fingerprint.startswith("ASSERT:"):
        # Extract the assertion text (e.g., "ASSERT:foo.c:123:assertion failed" -> "assertion failed")
        parts = fingerprint.split(":", 3)
        if len(parts) >= 4:
            return parts[3]
        return "Assertion"
    elif fingerprint.startswith("PANIC:"):
        # "PANIC:Fatal Python error: message" -> "Fatal Python error"
        return "Fatal Python error"

    # Fallback to simple keywords if fingerprint is generic
    if "SIGSEGV" in fingerprint or "SIGNAL:SIG_11" in fingerprint:
        return "Segmentation fault"

    return ""  # No grep pattern, rely on exit code


def measure_execution_time(cmd: list[str], timeout: int) -> float:
    """Run a command and return its execution time in seconds."""
    start_time = time.monotonic()
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, env=_make_repro_env())
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start_time
        print(
            f"  [!] Warning: Baseline measurement timed out after {elapsed:.1f}s. "
            f"Using {timeout}s as baseline.",
        )
        return float(timeout)
    return time.monotonic() - start_time


def rename_harnesses(source: str, suffix: str) -> str:
    """
    Rename 'uop_harness_fN' to 'uop_harness_fN_{suffix}' to prevent collisions
    when concatenating multiple scripts.
    """
    # Rename definitions (with or without parameters)
    source = re.sub(
        r"def\s+(uop_harness_f\d+)\s*\(",
        rf"def \1_{suffix}(",
        source,
    )
    # Rename calls (with or without arguments)
    source = re.sub(
        r"\b(uop_harness_f\d+)\s*\(",
        rf"\1_{suffix}(",
        source,
    )
    return source


def run_session(scripts: list[Path], target_python: str, timeout: int = 10) -> tuple[int, str, str]:
    """Run a session using lafleur.driver and return (returncode, stdout, stderr)."""
    cmd = [target_python, "-m", "lafleur.driver"] + [str(s) for s in scripts]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=_make_repro_env()
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"


def check_reproduction(
    scripts: list[Path], metadata: dict, grep_pattern: str, target_python: str
) -> bool:
    """Check if the crash reproduces with the given scripts."""
    target_code = metadata.get("returncode", 0)

    # ASan often returns 1 instead of sigsegv
    is_asan = "ASAN" in metadata.get("type", "")

    ret, _, stderr = run_session(scripts, target_python)

    code_match = False
    if is_asan:
        # ASan typically exits with 1 or a specific code like 77
        code_match = ret != 0
    elif target_code < 0:
        # Signal match
        code_match = ret == target_code
    else:
        # Exact code match
        code_match = ret == target_code

    grep_match = True
    if grep_pattern:
        grep_match = grep_pattern in stderr

    return code_match and grep_match


def _load_and_validate_metadata(crash_dir: Path) -> tuple[dict, str, list[Path]]:
    """Load metadata, validate returncode, extract grep pattern, and find scripts.

    Returns (metadata, grep_pattern, script_files).
    Exits with code 1 on validation errors.
    """
    metadata_path = crash_dir / "metadata.json"
    if not metadata_path.exists():
        print("[!] Error: metadata.json not found. Cannot minimize.")
        sys.exit(1)

    try:
        metadata = json.loads(metadata_path.read_text())
    except json.JSONDecodeError:
        print("[!] Error: Invalid metadata.json.")
        sys.exit(1)

    # Validate that we have a non-zero crash return code
    target_returncode = metadata.get("returncode")
    if target_returncode is None or target_returncode == 0:
        print("[!] Error: metadata.json has no crash return code (returncode is missing or 0).")
        print("    Cannot determine crash reproduction without a non-zero exit code.")
        sys.exit(1)

    grep_pattern = extract_grep_pattern(metadata)
    print(f"[*] Target Fingerprint: {metadata.get('fingerprint')}")
    print(f"[*] Grep Pattern: '{grep_pattern}'")

    script_files = sorted([f for f in crash_dir.glob("*.py") if f.name != "combined_repro.py"])
    if not script_files:
        print("[!] No script files found in bundle.")
        sys.exit(1)

    return metadata, grep_pattern, script_files


def _minimize_scripts(
    script_files: list[Path], metadata: dict, grep_pattern: str, target_python: str
) -> list[Path]:
    """Stage 1: Identify which scripts are necessary for reproduction.

    Returns the reduced list of necessary scripts.
    """
    print(f"[*] Starting Script Minimization with {len(script_files)} scripts...")
    necessary_scripts = list(script_files)

    for script in list(necessary_scripts):
        candidate_list = [s for s in necessary_scripts if s != script]

        # Don't test empty list
        if not candidate_list:
            continue

        print(f"  [?] Testing removal of {script.name}...", end=" ", flush=True)
        if check_reproduction(candidate_list, metadata, grep_pattern, target_python):
            print("REMOVED (Crash reproduces)")
            necessary_scripts = candidate_list
        else:
            print("KEPT (Required for crash)")

    print(f"[*] Reduced to {len(necessary_scripts)} necessary scripts.")
    return necessary_scripts


def _concatenate_scripts(
    necessary_scripts: list[Path],
    crash_dir: Path,
    metadata: dict,
    grep_pattern: str,
    target_python: str,
    force_overwrite: bool,
) -> tuple[Path, bool]:
    """Stage 2: Concatenate scripts and verify reproduction.

    Returns (target_file, use_concatenation).
    """
    print("[*] Attempting to concatenate scripts...")
    combined_path = crash_dir / "combined_repro.py"
    combined_content = ""

    for script in necessary_scripts:
        content = script.read_text()
        combined_content += f"\n# --- Source: {script.name} ---\n"
        combined_content += content + "\n"

    target_file = None
    use_concatenation = False

    # Check for existing, potentially better reproduction
    if combined_path.exists() and not force_overwrite:
        current_size = len(combined_content)
        existing_size = combined_path.stat().st_size
        if existing_size < current_size:
            print(
                f"[!] Warning: Existing combined_repro.py is smaller "
                f"({existing_size} < {current_size})."
            )
            print("    Use --force-overwrite to replace it.")
            target_file = combined_path
            if check_reproduction([combined_path], metadata, grep_pattern, target_python):
                print("    Existing file reproduces crash. Using it.")
                use_concatenation = True
            else:
                print("    Existing file FAILED reproduction. Overwriting with new candidate.")
                combined_path.write_text(combined_content)
                target_file = None
        else:
            combined_path.write_text(combined_content)
    else:
        combined_path.write_text(combined_content)

    if target_file is None:
        target_file = None
        use_concatenation = False

        print("  [?] Verifying concatenated reproduction...", end=" ", flush=True)
        if check_reproduction([combined_path], metadata, grep_pattern, target_python):
            print("SUCCESS")
            target_file = combined_path
            use_concatenation = True
        else:
            print("FAILED (Concatenation broke the crash)")
            print("[!] Warning: Falling back to minimizing the LAST script in the chain.")
            target_file = necessary_scripts[-1]
            use_concatenation = False

    return target_file, use_concatenation


def _generate_bash_scripts(
    crash_dir: Path,
    target_file: Path,
    necessary_scripts: list[Path],
    metadata: dict,
    grep_pattern: str,
    target_python: str,
    use_concatenation: bool,
) -> Path:
    """Generate check_crash.sh and reproduce_minimized.sh scripts.

    Returns the path to check_crash.sh.
    """
    check_script_path = crash_dir / "check_crash.sh"

    driver_cmd = ""
    repro_cmd_display = ""
    if use_concatenation:
        driver_cmd = (
            f"{shlex.quote(target_python)} -m lafleur.driver {shlex.quote(target_file.name)}"
        )
        repro_cmd_display = driver_cmd
    else:
        cmd_parts = [shlex.quote(target_python), "-m", "lafleur.driver"]
        for s in necessary_scripts[:-1]:
            cmd_parts.append(shlex.quote(str(s.resolve())))
        cmd_parts.append(shlex.quote(target_file.name))
        driver_cmd = " ".join(cmd_parts)
        repro_parts = [shlex.quote(target_python), "-m", "lafleur.driver"]
        repro_parts.extend([shlex.quote(s.name) for s in necessary_scripts])
        repro_cmd_display = " ".join(repro_parts)

    safe_pattern = shlex.quote(grep_pattern) if grep_pattern else "''"

    # Build exit code validation logic matching check_reproduction() behavior.
    # Python signals (e.g. -11) become bash exit codes (128 + abs(signal)).
    target_returncode = metadata.get("returncode", 0)
    is_asan = "ASAN" in metadata.get("type", "")

    if is_asan:
        # ASAN exit codes vary (1, 77, etc.) — any non-zero is acceptable
        exit_check = """\
# ASAN crash: accept any non-zero exit code
if [ $EXIT_CODE -eq 0 ]; then
    exit 1
fi"""
    elif target_returncode < 0:
        # Signal crash: Python -N becomes bash 128+N
        expected_bash_code = 128 + abs(target_returncode)
        exit_check = f"""\
# Signal crash: expected bash exit code {expected_bash_code} (Python {target_returncode})
if [ $EXIT_CODE -ne {expected_bash_code} ]; then
    exit 1
fi"""
    else:
        # Exact match for other crash types
        exit_check = f"""\
# Exact exit code match
if [ $EXIT_CODE -ne {target_returncode} ]; then
    exit 1
fi"""

    check_script_content = f"""#!/bin/bash
export PYTHON_JIT=1
export PYTHON_LLTRACE=0
export ASAN_OPTIONS=detect_leaks=0

# Run the driver
OUTPUT=$({driver_cmd} 2>&1)
EXIT_CODE=$?

{exit_check}

# Verify Grep Pattern (fixed-string match, safely quoted)
GREP_PATTERN={safe_pattern}
if [ -n "$GREP_PATTERN" ] && ! echo "$OUTPUT" | grep -qF "$GREP_PATTERN"; then
    exit 1
fi

exit 0
"""
    check_script_path.write_text(check_script_content)
    check_script_path.chmod(0o755)

    # Generate reproduce_minimized.sh
    repro_script_path = crash_dir / "reproduce_minimized.sh"
    repro_script_content = f"""#!/bin/bash
# Minimal reproduction script generated by lafleur.minimize
export PYTHON_JIT=1
export PYTHON_LLTRACE=0
export ASAN_OPTIONS=detect_leaks=0

{repro_cmd_display}
"""
    repro_script_path.write_text(repro_script_content)
    repro_script_path.chmod(0o755)

    return check_script_path


def _run_shrinkray(check_script: Path, target_file: Path, dynamic_timeout: int) -> None:
    """Discover and run ShrinkRay for code minimization."""
    shrinkray_cmd = [
        "shrinkray",
        "--ui=basic",
        "--timeout",
        str(dynamic_timeout),
        "--parallelism",
        str((os.cpu_count() or 1) // 2),
        str(check_script.resolve()),
        str(target_file.resolve()),
    ]

    try:
        subprocess.run(shrinkray_cmd, check=False, env=_make_repro_env())
        print("[*] ShrinkRay finished.")
    except Exception as e:
        print(f"[!] ShrinkRay failed: {e}")


def minimize_session(crash_dir: Path, target_python: str, force_overwrite: bool) -> None:
    """Main logic to minimize a session crash."""
    print(f"[*] Minimizing crash bundle: {crash_dir}")

    metadata, grep_pattern, script_files = _load_and_validate_metadata(crash_dir)

    # Backup original scripts
    for script in script_files:
        shutil.copy(script, script.with_suffix(".py.backup"))

    # Initial Reproduction Check
    print("[*] Verifying initial crash reproduction...")
    if not check_reproduction(script_files, metadata, grep_pattern, target_python):
        print(f"[!] Error: Crash does NOT reproduce with the provided python ({target_python}).")
        print("    Check that you are using the correct JIT-enabled build.")
        sys.exit(1)

    # Stage 1: Script Minimization
    necessary_scripts = _minimize_scripts(script_files, metadata, grep_pattern, target_python)

    # Measure baseline
    print("[*] Measuring baseline execution time...")
    baseline_time = measure_execution_time(
        [target_python, "-m", "lafleur.driver"] + [str(s) for s in necessary_scripts],
        timeout=30,
    )
    print(f"  -> Baseline: {baseline_time:.2f}s")

    # Stage 2: Concatenation
    target_file, use_concatenation = _concatenate_scripts(
        necessary_scripts, crash_dir, metadata, grep_pattern, target_python, force_overwrite
    )

    # Stage 3: ShrinkRay
    shrinkray_path = shutil.which("shrinkray")
    if not shrinkray_path:
        print("[!] 'shrinkray' not found in PATH. Skipping code minimization.")
        print(f"[*] Final reproduction script(s): {[str(s.name) for s in necessary_scripts]}")
        if use_concatenation:
            print(f"[*] Combined reproduction: {target_file}")
        return

    print("[*] Starting ShrinkRay...")
    dynamic_timeout = max(10, int(baseline_time * 2.5))

    check_script = _generate_bash_scripts(
        crash_dir,
        target_file,
        necessary_scripts,
        metadata,
        grep_pattern,
        target_python,
        use_concatenation,
    )

    _run_shrinkray(check_script, target_file, dynamic_timeout)

    print("\n[=] Minimization Complete!")
    if use_concatenation:
        print(f"    Result: {target_file}")
    else:
        print(f"    Result: {target_file} (requires predecessors)")


def main():
    parser = argparse.ArgumentParser(description="Minimize a lafleur crash bundle.")
    parser.add_argument("crash_dir", type=Path, help="Path to the session crash directory")
    parser.add_argument(
        "--target-python",
        type=str,
        default=sys.executable,
        help="Path to the Python interpreter to use for reproduction (default: sys.executable)",
    )
    parser.add_argument(
        "--force-overwrite",
        action="store_true",
        help="Overwrite existing combined_repro.py even if it is smaller",
    )

    args = parser.parse_args()

    if not args.crash_dir.exists():
        print(f"Error: Directory {args.crash_dir} does not exist.")
        sys.exit(1)

    minimize_session(args.crash_dir, args.target_python, args.force_overwrite)


if __name__ == "__main__":
    main()
