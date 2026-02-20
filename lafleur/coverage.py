#!/usr/bin/env python3
"""
This module provides utilities for parsing CPython JIT trace logs.

It includes functions to extract coverage information (uops, edges, rare events)
from log files and to manage the fuzzer's persistent state file, which stores
this coverage data. It also includes the CoverageManager class for managing the
fuzzer's persistent state with integer-based IDs.
"""

import argparse
import pickle
import re
import secrets
import sys
from collections import defaultdict, Counter
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, TypedDict

from lafleur.uop_names import UOP_NAMES

migrate_state_to_integers: Callable[[dict[str, Any]], dict[str, Any]] | None
try:
    from lafleur.state_tool import migrate_state_to_integers
except ImportError:
    migrate_state_to_integers = None


class JitState(Enum):
    """Represents the current operational state of the JIT compiler."""

    TRACING = auto()  # The JIT is creating a proto-trace from bytecode.
    OPTIMIZED = auto()  # The JIT has produced and is logging an optimized trace.
    EXECUTING = auto()  # Default state for general execution.


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

# Sentinel UOP used to seed the edge chain at the start of each harness.
# This creates edges like "_START_OF_HARNESS_->_LOAD_FAST", capturing
# which UOP each harness begins execution with. Not in UOP_NAMES — it
# passes through because the spurious-UOP check only applies to current_uop.
_START_OF_HARNESS = "_START_OF_HARNESS_"

# Define paths for the coverage directory and the new state file.
COVERAGE_DIR = Path("coverage")
COVERAGE_STATE_FILE = COVERAGE_DIR / "coverage_state.pkl"


def ensure_state_schema(state: dict[str, Any]) -> None:
    """Ensure all required keys exist in a coverage state dictionary.

    This is the single source of truth for the state schema. Called by
    both load_coverage_state (for freshly loaded/created states) and
    CoverageManager.__init__ (for the map subset).

    Args:
        state: Coverage state dictionary to initialize in-place.
    """
    # ID mapping tables
    state.setdefault("uop_map", {})
    state.setdefault("edge_map", {})
    state.setdefault("rare_event_map", {})
    state.setdefault("next_id_map", {"uop": 0, "edge": 0, "rare_event": 0})

    # Coverage data
    state.setdefault("global_coverage", {"uops": {}, "edges": {}, "rare_events": {}})
    state.setdefault("per_file_coverage", {})


class CoverageManager:
    """
    Encapsulates the fuzzer's coverage state and manages integer ID mappings.
    """

    def __init__(self, state: dict[str, Any]):
        self.state = state
        ensure_state_schema(state)
        self._initialize_reverse_maps()

        # Pre-compute map references to avoid per-call string formatting
        # in get_or_create_id. Maps item_type -> (forward_map, reverse_map).
        self._type_maps: dict[str, tuple[dict[str, int], dict[int, str]]] = {
            "uop": (self.state["uop_map"], self.reverse_uop_map),
            "edge": (self.state["edge_map"], self.reverse_edge_map),
            "rare_event": (self.state["rare_event_map"], self.reverse_rare_event_map),
        }

    def _initialize_reverse_maps(self) -> None:
        """Create reverse mappings from integer IDs to strings."""
        self.reverse_uop_map: dict[int, str] = {v: k for k, v in self.state["uop_map"].items()}
        self.reverse_edge_map: dict[int, str] = {v: k for k, v in self.state["edge_map"].items()}
        self.reverse_rare_event_map: dict[int, str] = {
            v: k for k, v in self.state["rare_event_map"].items()
        }

    def get_or_create_id(self, item_type: str, item_string: str) -> int:
        """Get the integer ID for a string, creating a new one if first seen.

        Args:
            item_type: One of "uop", "edge", "rare_event".
            item_string: The string representation of the coverage item.

        Returns:
            Integer ID for the item.
        """
        forward_map, reverse_map = self._type_maps[item_type]

        existing_id = forward_map.get(item_string)
        if existing_id is not None:
            return existing_id

        new_id = self.state["next_id_map"][item_type]
        forward_map[item_string] = new_id
        self.state["next_id_map"][item_type] += 1
        reverse_map[new_id] = item_string
        return new_id


class HarnessCoverage(TypedDict, total=False):
    """Type for harness coverage data."""

    uops: Counter[int]
    edges: Counter[int]
    rare_events: Counter[int]
    trace_length: int
    side_exits: int


def _create_empty_harness_coverage() -> HarnessCoverage:
    """Create a factory for an empty harness coverage dictionary (using int IDs)."""
    return {"uops": Counter(), "edges": Counter(), "rare_events": Counter()}


def parse_log_for_edge_coverage(
    log_path: Path, coverage_manager: CoverageManager
) -> dict[str, HarnessCoverage]:
    """
    Read a JIT log file and extract hit counts and structural metrics.
    Requires a CoverageManager to convert coverage items to integer IDs.

    This function operates as a state machine, tracking the JIT's current
    state (TRACING, OPTIMIZED, etc.) and associating the coverage it finds
    with that state. It also extracts trace length and side exit counts.

    Return a dictionary mapping each harness ID to its coverage profile.
    """
    if not log_path.is_file():
        print(f"Error: Log file not found at {log_path}", file=sys.stderr)
        return {}

    coverage_by_harness: defaultdict[str, HarnessCoverage] = defaultdict(
        _create_empty_harness_coverage
    )
    current_harness_id = None
    previous_uop = None

    # --- State machine and metrics tracking ---
    current_state = JitState.EXECUTING
    current_trace_length = 0
    current_side_exits = 0

    def flush_harness_metrics(harness_id: str | None, trace_length: int, side_exits: int) -> None:
        """Save trace metrics for the given harness, if any."""
        if harness_id and trace_length > 0:
            coverage_by_harness[harness_id]["trace_length"] = trace_length
            coverage_by_harness[harness_id]["side_exits"] = side_exits

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
                flush_harness_metrics(current_harness_id, current_trace_length, current_side_exits)

                # Reset state for the new harness.
                current_harness_id = harness_match.group(1)
                previous_uop = _START_OF_HARNESS
                current_state = JitState.EXECUTING
                current_trace_length = 0
                current_side_exits = 0

            if not current_harness_id:
                continue

            # --- Coverage Parsing Logic ---
            uop_match = UOP_REGEX.search(line)
            if uop_match:
                current_uop = uop_match.group(1)

                if current_uop not in UOP_NAMES:
                    # Spurious UOP detected. Discard it and break the edge chain.
                    previous_uop = None
                else:
                    # UOP is valid, proceed with coverage tracking.
                    if current_state == JitState.OPTIMIZED and current_uop in (
                        "_DEOPT",
                        "_EXIT_TRACE",
                    ):
                        current_side_exits += 1

                    uop_id = coverage_manager.get_or_create_id("uop", current_uop)
                    coverage_by_harness[current_harness_id]["uops"][uop_id] += 1

                    if previous_uop:
                        edge_str = f"{previous_uop}->{current_uop}"
                        stateful_edge_str = str((current_state.name, edge_str))
                        edge_id = coverage_manager.get_or_create_id("edge", stateful_edge_str)
                        coverage_by_harness[current_harness_id]["edges"][edge_id] += 1

                    # Only update previous_uop if the current one was valid.
                    previous_uop = current_uop

            if rare_event_match := RARE_EVENT_REGEX.search(line):
                rare_event = rare_event_match.group(1)
                event_id = coverage_manager.get_or_create_id("rare_event", rare_event)
                coverage_by_harness[current_harness_id]["rare_events"][event_id] += 1

    # After the loop, flush the last harness.
    flush_harness_metrics(current_harness_id, current_trace_length, current_side_exits)

    return dict(coverage_by_harness)


def load_coverage_state() -> dict[str, Any]:
    """Load the coverage state, auto-migrating if it's in the old format."""
    if not COVERAGE_STATE_FILE.is_file():
        state: dict[str, Any] = {}
        ensure_state_schema(state)
        return state
    try:
        with open(COVERAGE_STATE_FILE, "rb") as f:
            state = pickle.load(f)

        # Auto-migration check
        if "uop_map" not in state:
            print(
                "[*] Old format coverage state detected. Migrating to integer-based format in memory..."
            )
            if migrate_state_to_integers:
                state = migrate_state_to_integers(state)
                # The new state will be saved automatically on the next successful run.
            else:
                # This is a fallback in case the import fails.
                print(
                    "[!] Warning: Migration tool not found. Re-initializing state.", file=sys.stderr
                )
                state = {}  # Start fresh if migration isn't possible

        ensure_state_schema(state)
        return state
    except (pickle.UnpicklingError, IOError, EOFError) as e:
        print(f"Warning: Could not load coverage state file. Error: {e}", file=sys.stderr)
        state = {}
        ensure_state_schema(state)
        return state


def save_coverage_state(state: dict[str, Any]) -> None:
    """Save the updated coverage state to its pickle file atomically."""
    COVERAGE_DIR.mkdir(exist_ok=True)
    # Create a unique temporary file path in the same directory.
    tmp_path = COVERAGE_STATE_FILE.with_suffix(f".pkl.tmp.{secrets.token_hex(4)}")

    try:
        with open(tmp_path, "wb") as f:  # Open in binary write mode
            pickle.dump(state, f)
        # The write was successful, now atomically rename the file.
        tmp_path.rename(COVERAGE_STATE_FILE)
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


def merge_coverage_into_global(
    state: dict[str, Any],
    per_harness_coverage: dict,
) -> list[tuple[str, str, str]]:
    """Merge per-harness coverage into the global coverage state.

    Updates the global coverage counters with new coverage data. Returns
    a list of newly discovered items for reporting.

    Args:
        state: The full coverage state dict (with "global_coverage" key).
        per_harness_coverage: Coverage data keyed by harness ID.

    Returns:
        List of (coverage_type, item_key, harness_id) tuples for newly
        discovered items. coverage_type is one of "UOP", "EDGE", "RARE EVENT".
    """
    discoveries: list[tuple[str, str, str]] = []
    global_cov = state["global_coverage"]

    # Map from global_coverage key to the corresponding forward-map key
    # so we can build reverse maps to resolve human-readable names.
    _forward_map_keys: dict[str, str] = {
        "uops": "uop_map",
        "edges": "edge_map",
        "rare_events": "rare_event_map",
    }
    _reverse_maps: dict[str, dict[int, str]] = {
        cov_type: {v: k for k, v in state.get(fwd_key, {}).items()}
        for cov_type, fwd_key in _forward_map_keys.items()
    }

    for harness_id, data in per_harness_coverage.items():
        for cov_type in ("uops", "edges", "rare_events"):
            global_map = global_cov[cov_type]
            reverse_map = _reverse_maps[cov_type]
            for item_id, count in data.get(cov_type, {}).items():
                if item_id not in global_map:
                    # Derive the display name from cov_type:
                    # "uops" -> "UOP", "edges" -> "EDGE", "rare_events" -> "RARE EVENT"
                    display_type = cov_type.rstrip("s").upper().replace("_", " ")
                    display_name = reverse_map.get(item_id, str(item_id))
                    discoveries.append((display_type, display_name, harness_id))
                    global_map[item_id] = 0
                global_map[item_id] += count

    return discoveries


def main() -> None:
    """Run the coverage parser as a standalone command-line tool."""
    parser = argparse.ArgumentParser(
        description="Parses JIT logs, updates global coverage state, and reports new discoveries."
    )
    parser.add_argument("log_file", type=Path, help="Path to the JIT log file to be parsed.")
    args = parser.parse_args()

    global_coverage_state = load_coverage_state()

    coverage_manager = CoverageManager(global_coverage_state)
    per_harness_coverage = parse_log_for_edge_coverage(args.log_file, coverage_manager)
    if not per_harness_coverage:
        print("No per-harness coverage found in the log file.", file=sys.stderr)
        return

    discoveries = merge_coverage_into_global(global_coverage_state, per_harness_coverage)

    if discoveries:
        for cov_type, item_key, harness_id in discoveries:
            print(
                f"[NEW {cov_type}] Discovered in harness '{harness_id}': {item_key}",
                file=sys.stderr,
            )
    else:
        print("No new coverage found in this run.", file=sys.stderr)

    save_coverage_state(global_coverage_state)
    print(f"Global coverage state updated: {COVERAGE_STATE_FILE}", file=sys.stderr)


if __name__ == "__main__":
    main()
