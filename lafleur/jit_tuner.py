#!/usr/bin/env python3
"""
A utility script to apply aggressive JIT settings to the CPython source code.

This tool modifies C header files in a CPython source tree to lower various
thresholds, making the JIT compiler activate more frequently and aggressively.
This is useful for creating a dedicated CPython build for fuzzing, increasing
the chances of triggering JIT-specific behavior and bugs.
"""

import re
import argparse
from pathlib import Path
from typing import Sequence

# A comprehensive dictionary of JIT parameters to tweak for fuzzing.
# Values are set to be more aggressive than the defaults.
JIT_TWEAKS = {
    # Lower backoff counters to make the JIT trigger much sooner.
    "Include/internal/pycore_backoff.h": [
        ("JUMP_BACKWARD_INITIAL_VALUE", 63),
        ("JUMP_BACKWARD_INITIAL_BACKOFF", 6),
        ("SIDE_EXIT_INITIAL_VALUE", 63),
        ("SIDE_EXIT_INITIAL_BACKOFF", 6),
    ],
    "Python/optimizer.c": [
        # Lower the branch confidence threshold to encourage more specialization.
        ("CONFIDENCE_CUTOFF", 100),
    ],
    "Include/internal/pycore_optimizer.h": [
        # Decrease the JIT cleanup threshold to run it more often.
        ("JIT_CLEANUP_THRESHOLD", 10000),
    ],
    "Include/internal/pycore_optimizer_types.h": [
        ("MAX_ABSTRACT_INTERP_SIZE", 8192),
        # Increase the maximum length of a side-exit chain.
        ("MAX_CHAIN_DEPTH", 16),
        # Decrease the max trace length to stress trace linking.
    ],
    # "Include/internal/pycore_uop.h": [
    #     ("UOP_MAX_TRACE_LENGTH", 800),
    # ],

}


def apply_jit_tweaks(
    cpython_path: Path,
    dry_run: bool = False,
    disabled_files: Sequence[str] | None = None,
    disabled_tweaks: Sequence[str] | None = None,
) -> None:
    """
    Find and replace CPython JIT parameters using regular expressions.

    Args:
        cpython_path: The root path of the CPython source code checkout.
        dry_run: If True, print changes without modifying files.
        disabled_files: A list of filenames to skip patching.
        disabled_tweaks: A list of C macro names to skip patching.
    """
    print(f"[*] Starting JIT parameter tweaks for CPython at: {cpython_path.resolve()}")

    # Ensure disabled lists are not None for 'in' checks
    disabled_files = disabled_files or []
    disabled_tweaks = disabled_tweaks or []

    if not cpython_path.is_dir():
        print(f"[!] Error: CPython source directory not found at '{cpython_path}'")
        return

    for rel_path, tweaks in JIT_TWEAKS.items():
        if rel_path in disabled_files:
            print(f"[-] Skipping file as requested by --disable-file: {rel_path}")
            continue

        file_path = cpython_path / rel_path
        if not file_path.exists():
            print(f"[-] Warning: File not found, skipping: {file_path}")
            continue

        print(f"[*] Processing file: {file_path}")
        try:
            content = file_path.read_text()
            original_content = content

            for param_name, new_value in tweaks:
                if param_name in disabled_tweaks:
                    print(f"  - Skipping tweak as requested by --disable-tweak: {param_name}")
                    continue

                # This regex captures the define, the parameter name, and the original value.
                pattern = re.compile(rf"^(#define\s+{param_name}\s+)(\d+)", re.MULTILINE)

                # Use a function for the replacement to capture the old value
                def replacer(match: re.Match) -> str:
                    prefix = match.group(1)
                    old_value = match.group(2)
                    print(f"  - Changing '{param_name}': from '{old_value}' to '{new_value}'")
                    return f"{prefix}{new_value}"

                content, num_subs = pattern.subn(replacer, content)

                if num_subs == 0:
                    print(f"  - Warning: Could not find and replace '{param_name}'")

            if content != original_content and not dry_run:
                print(f"[*] Writing changes to: {file_path}")
                file_path.write_text(content)
            elif dry_run and content != original_content:
                print(f"[*] Dry run: Changes for {file_path} were not written.")

        except Exception as e:
            print(f"[!] Error processing {file_path}: {e}")


def main() -> None:
    """Parse command-line arguments and apply JIT tweaks."""
    parser = argparse.ArgumentParser(
        description="Apply aggressive JIT settings to the CPython source code."
    )
    parser.add_argument(
        "cpython_dir",
        type=str,
        help="Path to the root of the CPython source repository.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print changes without modifying files.",
    )
    parser.add_argument(
        "--disable-file",
        action="append",
        dest="disabled_files",
        help="Disable all patches for a given file. Can be used multiple times.",
    )
    parser.add_argument(
        "--disable-tweak",
        action="append",
        dest="disabled_tweaks",
        help="Disable a specific tweak by its name (e.g., 'CONFIDENCE_CUTOFF'). Can be used multiple times.",
    )
    args = parser.parse_args()

    cpython_src_path = Path(args.cpython_dir)
    apply_jit_tweaks(cpython_src_path, args.dry_run, args.disabled_files, args.disabled_tweaks)
    print("[*] Done.")


if __name__ == "__main__":
    main()
