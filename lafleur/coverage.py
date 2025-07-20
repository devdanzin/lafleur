#!/usr/bin/env python3
"""
This module provides utilities for parsing CPython JIT trace logs.

It includes functions to extract coverage information (uops, edges, rare events)
from log files and to manage the fuzzer's persistent state file, which stores
this coverage data.
"""

import argparse
import os
import pickle
import re
import secrets
import sys
from collections import defaultdict, Counter
from pathlib import Path
from typing import Any

# Regex to find our harness markers, e.g., "[f1]", "[f12]", etc.
HARNESS_MARKER_REGEX = re.compile(r"\[(f\d+)\]")

# Regex to find standard uops in the JIT log files.
UOP_REGEX = re.compile(r"(?:ADD_TO_TRACE|OPTIMIZED): (_[A-Z0-9_]+)(?=\s|\n|$)")

# Regex to find "rare" but highly interesting JIT events.
RARE_EVENT_REGEX = re.compile(
    r"(_DEOPT|_GUARD_FAIL"
    # Low-level bailout reasons from C-code analysis
    r"|Bailing on recursive call|Bailing due to dynamic target"
    r"|Bailing because co_version != func_version|Bail, new_code == NULL"
    r"|Unsupported opcode|JUMP_BACKWARD not to top ends trace|Trace stack overflow"
    r"|No room for|Out of space in abstract interpreter"
    r"|out of space for symbolic expression type|Hit bottom in abstract interpreter"
    r"|Encountered error in abstract interpreter|Confidence too low"
    # High-level semantic events from summarize_stats.py analysis
    r"|Rare event set class|Rare event set bases|Rare event func modification"
    r"|Rare event builtin dict|Rare event watched globals modification)"
)

# Define paths for the coverage directory and the new state file.
COVERAGE_DIR = Path("coverage")
COVERAGE_STATE_FILE = COVERAGE_DIR / "coverage_state.pkl"


def _create_empty_harness_coverage() -> dict[str, Counter[str]]:
    """Create a factory for an empty harness coverage dictionary."""
    return {"uops": Counter(), "edges": Counter(), "rare_events": Counter()}


def parse_log_for_edge_coverage(log_path: Path) -> dict[str, dict[str, Counter[str]]]:
    """
    Read a JIT log file and extract hit counts for uops, edges, and rare events.

    Return a dictionary mapping each harness ID found in the log to its
    own coverage profile.
    """
    if not log_path.is_file():
        print(f"Error: Log file not found at {log_path}", file=sys.stderr)
        return {}

    # The new data structure uses Counters for hit tracking.
    coverage_by_harness: defaultdict[str, dict[str, Counter[str]]] = defaultdict(
        _create_empty_harness_coverage
    )

    current_harness_id = None
    previous_uop = None

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            harness_match = HARNESS_MARKER_REGEX.search(line)
            if harness_match:
                current_harness_id = harness_match.group(1)
                previous_uop = "_START_OF_HARNESS_"

            if not current_harness_id:
                continue

            uop_match = UOP_REGEX.search(line)
            if uop_match:
                current_uop = uop_match.group(1)
                # Increment hit count for the individual uop.
                coverage_by_harness[current_harness_id]["uops"][current_uop] += 1

                if previous_uop:
                    edge = f"{previous_uop}->{current_uop}"
                    # Increment hit count for the edge.
                    coverage_by_harness[current_harness_id]["edges"][edge] += 1
                previous_uop = current_uop

            rare_event_match = RARE_EVENT_REGEX.search(line)
            if rare_event_match:
                rare_event = rare_event_match.group(1)
                # Increment hit count for the rare event.
                coverage_by_harness[current_harness_id]["rare_events"][rare_event] += 1

    # No need to sort, as Counters handle their own structure.
    return coverage_by_harness


def load_coverage_state() -> dict[str, Any]:
    """
    Load the global and per-file coverage state from the pickle file.

    Return a default structure if the file doesn't exist or is corrupted.
    """
    if not COVERAGE_STATE_FILE.is_file():
        return {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
    try:
        with open(COVERAGE_STATE_FILE, "rb") as f:  # Open in binary read mode
            state: dict[str, Any] = pickle.load(f)
            # Ensure keys are present for backward compatibility
            state.setdefault("global_coverage", {"uops": {}, "edges": {}, "rare_events": {}})
            state.setdefault("per_file_coverage", {})
            return state
    except (pickle.UnpicklingError, IOError, EOFError) as e:
        print(
            f"Warning: Could not load coverage state file. Starting fresh. Error: {e}",
            file=sys.stderr,
        )
        return {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {},
        }


def save_coverage_state(state: dict[str, Any]) -> None:
    """Save the updated coverage state to its pickle file atomically."""
    COVERAGE_DIR.mkdir(exist_ok=True)
    # Create a unique temporary file path in the same directory.
    tmp_path = COVERAGE_STATE_FILE.with_suffix(f".pkl.tmp.{secrets.token_hex(4)}")

    try:
        with open(tmp_path, "wb") as f:  # Open in binary write mode
            pickle.dump(state, f)
        # The write was successful, now atomically rename the file.
        os.rename(tmp_path, COVERAGE_STATE_FILE)
    except (IOError, OSError, pickle.PicklingError) as e:
        print(f"[!] Error during atomic save of coverage state: {e}", file=sys.stderr)
        # If an error occurred, try to clean up the temporary file.
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError as e_unlink:
                print(
                    f"[!] Warning: Could not remove temporary state file {tmp_path}: {e_unlink}",
                    file=sys.stderr,
                )


def main() -> None:
    """Run the coverage parser as a standalone command-line tool."""
    parser = argparse.ArgumentParser(
        description="Parses JIT logs, updates global coverage state, and reports new discoveries."
    )
    parser.add_argument("log_file", type=Path, help="Path to the JIT log file to be parsed.")
    args = parser.parse_args()

    # 1. Parse the current log for per-harness coverage.
    per_harness_coverage = parse_log_for_edge_coverage(args.log_file)
    if not per_harness_coverage:
        print("No per-harness coverage found in the log file.", file=sys.stderr)
        return

    # 2. Load the persistent global coverage state.
    global_coverage_state = load_coverage_state()
    newly_discovered = False

    # 3. Iterate through the new coverage and update the global state.
    for harness_id, data in per_harness_coverage.items():
        # Update uops
        for uop, count in data["uops"].items():
            if uop not in global_coverage_state["uops"]:
                print(
                    f"[NEW UOP] Discovered new uop in harness '{harness_id}': {uop}",
                    file=sys.stderr,
                )
                newly_discovered = True
                global_coverage_state["uops"][uop] = 0
            global_coverage_state["uops"][uop] += count

        # Update edges
        for edge, count in data["edges"].items():
            if edge not in global_coverage_state["edges"]:
                print(
                    f"[NEW EDGE] Discovered new edge in harness '{harness_id}': {edge}",
                    file=sys.stderr,
                )
                newly_discovered = True
                global_coverage_state["edges"][edge] = 0
            global_coverage_state["edges"][edge] += count

        # Update rare events
        for event, count in data["rare_events"].items():
            if event not in global_coverage_state["rare_events"]:
                print(
                    f"[NEW RARE EVENT] Discovered new rare event in harness '{harness_id}': {event}",
                    file=sys.stderr,
                )
                newly_discovered = True
                global_coverage_state["rare_events"][event] = 0
            global_coverage_state["rare_events"][event] += count

    if not newly_discovered:
        print("No new coverage found in this run.", file=sys.stderr)

    # 4. Save the updated state back to the file.
    save_coverage_state(global_coverage_state)
    print(f"Global coverage state updated: {COVERAGE_STATE_FILE}", file=sys.stderr)


if __name__ == "__main__":
    main()
