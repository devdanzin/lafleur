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
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# Environment variables for reproduction
REPRO_ENV = os.environ.copy()
REPRO_ENV.update({
    "PYTHON_JIT": "1",
    "PYTHON_LLTRACE": "0",  # Disable verbose logging for speed
    "ASAN_OPTIONS": "detect_leaks=0",
})

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
    
    return "" # No grep pattern, rely on exit code

def measure_execution_time(cmd: list[str], timeout: int) -> float:
    """Run a command and return its execution time in seconds."""
    start_time = time.monotonic()
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env=REPRO_ENV
        )
    except subprocess.TimeoutExpired:
        pass
    return time.monotonic() - start_time

def rename_harnesses(source: str, suffix: str) -> str:
    """
    Rename 'uop_harness_f1' to 'uop_harness_f1_{suffix}' to prevent collisions
    when concatenating multiple scripts.
    """
    # Rename definitions
    source = re.sub(
        r"def\s+uop_harness_f1\(\):",
        f"def uop_harness_f1_{suffix}():",
        source
    )
    # Rename calls
    source = re.sub(
        r"uop_harness_f1\(\)",
        f"uop_harness_f1_{suffix}()",
        source
    )
    return source

def run_session(scripts: list[Path], timeout: int = 10) -> tuple[int, str, str]:
    """Run a session using lafleur.driver and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "lafleur.driver"] + [str(s) for s in scripts]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=REPRO_ENV
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"

def check_reproduction(scripts: list[Path], metadata: dict, grep_pattern: str) -> bool:
    """Check if the crash reproduces with the given scripts."""
    target_code = metadata.get("returncode", 0)
    
    # ASan often returns 1 instead of sigsegv
    is_asan = "ASAN" in metadata.get("type", "")
    
    ret, _, stderr = run_session(scripts)
    
    # Check exit code match
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

    # Check grep pattern match
    grep_match = True
    if grep_pattern:
        grep_match = grep_pattern in stderr

    return code_match and grep_match

def minimize_session(crash_dir: Path):
    """Main logic to minimize a session crash."""
    print(f"[*] Minimizing crash bundle: {crash_dir}")
    
    # Step 0: Preparation
    metadata_path = crash_dir / "metadata.json"
    if not metadata_path.exists():
        print("[!] Error: metadata.json not found. Cannot minimize.")
        sys.exit(1)
        
    try:
        metadata = json.loads(metadata_path.read_text())
    except json.JSONDecodeError:
        print("[!] Error: Invalid metadata.json.")
        sys.exit(1)
        
    grep_pattern = extract_grep_pattern(metadata)
    print(f"[*] Target Fingerprint: {metadata.get('fingerprint')}")
    print(f"[*] Grep Pattern: '{grep_pattern}'")
    
    script_files = sorted([f for f in crash_dir.glob("*.py") if f.name != "combined_repro.py"])
    if not script_files:
        print("[!] No script files found in bundle.")
        sys.exit(1)
        
    # Backup original scripts
    for script in script_files:
        shutil.copy(script, script.with_suffix(".py.backup"))
        
    # Step 1: Script Minimization
    print(f"[*] Starting Script Minimization with {len(script_files)} scripts...")
    necessary_scripts = list(script_files)
    
    # Iterate over a copy so we can modify necessary_scripts
    for script in list(necessary_scripts):
        candidate_list = [s for s in necessary_scripts if s != script]
        
        # Don't test empty list
        if not candidate_list:
            continue
            
        print(f"  [?] Testing removal of {script.name}...", end=" ", flush=True)
        if check_reproduction(candidate_list, metadata, grep_pattern):
            print("REMOVED (Crash reproduces)")
            necessary_scripts = candidate_list
        else:
            print("KEPT (Required for crash)")
            
    print(f"[*] Reduced to {len(necessary_scripts)} necessary scripts.")
    
    # Measure execution time
    print("[*] Measuring baseline execution time...")
    baseline_time = measure_execution_time(
        [sys.executable, "-m", "lafleur.driver"] + [str(s) for s in necessary_scripts],
        timeout=30
    )
    print(f"  -> Baseline: {baseline_time:.2f}s")
    
    # Step 2: Concatenation Attempt
    print("[*] Attempting to concatenate scripts...")
    combined_path = crash_dir / "combined_repro.py"
    combined_content = ""
    
    for i, script in enumerate(necessary_scripts):
        content = script.read_text()
        # Rename harness to avoid collisions (e.g. uop_harness_f1_0)
        content = rename_harnesses(content, str(i))
        combined_content += f"\n# --- Source: {script.name} ---\n"
        combined_content += content + "\n"
        
    combined_path.write_text(combined_content)
    
    target_file = None
    use_concatenation = False
    
    print("  [?] Verifying concatenated reproduction...", end=" ", flush=True)
    if check_reproduction([combined_path], metadata, grep_pattern):
        print("SUCCESS")
        target_file = combined_path
        use_concatenation = True
    else:
        print("FAILED (Concatenation broke the crash)")
        print("[!] Warning: Falling back to minimizing the LAST script in the chain.")
        target_file = necessary_scripts[-1]
        use_concatenation = False
        
    # Step 3: Code Minimization (ShrinkRay)
    shrinkray_path = shutil.which("shrinkray")
    if not shrinkray_path:
        print("[!] 'shrinkray' not found in PATH. Skipping code minimization.")
        print(f"[*] Final reproduction script(s): {[str(s.name) for s in necessary_scripts]}")
        if use_concatenation:
             print(f"[*] Combined reproduction: {target_file}")
        return

    print("[*] Starting ShrinkRay...")
    dynamic_timeout = max(10, int(baseline_time * 2.5))
    
    # Generate check_crash.sh
    check_script_path = crash_dir / "check_crash.sh"
    
    driver_cmd = ""
    if use_concatenation:
        driver_cmd = f"python3 -m lafleur.driver {target_file.name}"
    else:
        # If fallback, we run the full chain, but shrinkray only modifies the last one
        # We need to construct the command with absolute paths for the unmodified predecessors
        # and the relative path for the target
        cmd_parts = ["python3", "-m", "lafleur.driver"]
        for s in necessary_scripts[:-1]:
            cmd_parts.append(str(s.resolve()))
        cmd_parts.append(target_file.name)
        driver_cmd = " ".join(cmd_parts)

    check_script_content = f"#!/bin/bash
export PYTHON_JIT=1
export PYTHON_LLTRACE=0
export ASAN_OPTIONS=detect_leaks=0

# Run the driver
OUTPUT=$({driver_cmd} 2>&1)
EXIT_CODE=$?

# Verify Exit Code matches {metadata.get('returncode')}
# (Logic simplified for bash: check for non-zero if ASan/Signal)
if [ {metadata.get('returncode')} -ne 0 ] && [ $EXIT_CODE -eq 0 ]; then
    exit 1
fi

# Verify Grep Pattern
if [[ "$OUTPUT" != *"{grep_pattern}"* ]]; then
    exit 1
fi

exit 0
"
    check_script_path.write_text(check_script_content)
    check_script_path.chmod(0o755)
    
    # Run ShrinkRay
    shrinkray_cmd = [
        shrinkray_path,
        "--no-tui",
        "--timeout", str(dynamic_timeout),
        str(check_script_path.resolve()),
        str(target_file.resolve())
    ]
    
    try:
        subprocess.run(shrinkray_cmd, check=False)
        print("[*] ShrinkRay finished.")
    except Exception as e:
        print(f"[!] ShrinkRay failed: {e}")

    print("\n[=] Minimization Complete!")
    if use_concatenation:
        print(f"    Result: {target_file}")
    else:
        print(f"    Result: {target_file} (requires predecessors)")


def main():
    parser = argparse.ArgumentParser(description="Minimize a lafleur crash bundle.")
    parser.add_argument("crash_dir", type=Path, help="Path to the session crash directory")
    
    args = parser.parse_args()
    
    if not args.crash_dir.exists():
        print(f"Error: Directory {args.crash_dir} does not exist.")
        sys.exit(1)
        
    minimize_session(args.crash_dir)

if __name__ == "__main__":
    main()
