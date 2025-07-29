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
from enum import Enum, auto
from pathlib import Path
from typing import Any


class JitState(Enum):
    """Represents the current operational state of the JIT compiler."""
    TRACING = auto()      # The JIT is creating a proto-trace from bytecode.
    OPTIMIZED = auto()    # The JIT has produced and is logging an optimized trace.
    EXECUTING = auto()    # Default state for general execution.


PROTO_TRACE_REGEX = re.compile(r"Created a proto-trace")
OPTIMIZED_TRACE_REGEX = re.compile(r"Optimized trace \(length (\d+)\):")

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


def _create_empty_harness_coverage() -> dict[str, int | Counter[tuple[str, str]]]:
    """Create a factory for an empty harness coverage dictionary."""
    return {"uops": Counter(), "edges": Counter(), "rare_events": Counter()}


def parse_log_for_edge_coverage(log_path: Path) -> dict[str, dict[str, Any]]:
    """
    Read a JIT log file and extract hit counts and structural metrics.

    This function operates as a state machine, tracking the JIT's current
    state (TRACING, OPTIMIZED, etc.) and associating the coverage it finds
    with that state. It also extracts trace length and side exit counts.

    Return a dictionary mapping each harness ID to its coverage profile.
    """
    if not log_path.is_file():
        print(f"Error: Log file not found at {log_path}", file=sys.stderr)
        return {}

    coverage_by_harness = defaultdict(_create_empty_harness_coverage)
    current_harness_id = None
    previous_uop = None

    # --- State machine and metrics tracking ---
    current_state = JitState.EXECUTING
    current_trace_length = 0
    current_side_exits = 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # --- State and Metric Transition Logic ---
            proto_trace_match = PROTO_TRACE_REGEX.search(line)
            opt_trace_match = OPTIMIZED_TRACE_REGEX.search(line)
            harness_match = HARNESS_MARKER_REGEX.search(line)

            if proto_trace_match:
                current_state = JitState.TRACING
            elif opt_trace_match:
                current_state = JitState.OPTIMIZED
                current_trace_length = int(opt_trace_match.group(1))
                current_side_exits = 0  # Reset for the new trace

            if harness_match:
                # Before switching harness, save the metrics for the previous one.
                if current_harness_id and current_trace_length > 0:
                    coverage_by_harness[current_harness_id]['trace_length'] = current_trace_length
                    coverage_by_harness[current_harness_id]['side_exits'] = current_side_exits

                # Reset state for the new harness.
                current_harness_id = harness_match.group(1)
                previous_uop = "_START_OF_HARNESS_"
                current_state = JitState.EXECUTING
                current_trace_length = 0
                current_side_exits = 0

            if not current_harness_id:
                continue

            # --- Coverage Parsing Logic ---
            uop_match = UOP_REGEX.search(line)
            if uop_match:
                current_uop = uop_match.group(1)

                if current_state == JitState.OPTIMIZED and current_uop in ("_DEOPT", "_EXIT_TRACE"):
                    current_side_exits += 1

                coverage_by_harness[current_harness_id]["uops"][current_uop] += 1

                if previous_uop:
                    edge_str = f"{previous_uop}->{current_uop}"
                    stateful_edge = (current_state.name, edge_str)
                    coverage_by_harness[current_harness_id]["edges"][stateful_edge] += 1

                previous_uop = current_uop

            rare_event_match = RARE_EVENT_REGEX.search(line)
            if rare_event_match:
                rare_event = rare_event_match.group(1)
                coverage_by_harness[current_harness_id]["rare_events"][rare_event] += 1

    # After the loop, save the metrics for the very last harness in the file.
    if current_harness_id and current_trace_length > 0:
        coverage_by_harness[current_harness_id]['trace_length'] = current_trace_length
        coverage_by_harness[current_harness_id]['side_exits'] = current_side_exits

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
