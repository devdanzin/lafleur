#!/usr/bin/env python3
"""
A standalone command-line utility for inspecting and migrating lafleur's
binary state file (`coverage_state.pkl`).
"""

import argparse
import json
import pickle
import sys
from pathlib import Path
from typing import Any, cast


def migrate_state_to_integers(old_state: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a string-based coverage state file to the new integer-based format.
    """
    print("[*] Starting migration of coverage state to integer-based format...")
    new_state = {
        "uop_map": {},
        "edge_map": {},
        "rare_event_map": {},
        "next_id_map": {"uop": 0, "edge": 0, "rare_event": 0},
        "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
        "per_file_coverage": {},
    }

    # Helper to create mappings and get IDs
    def get_or_create_id(item_type: str, item_string: str) -> int:
        map_name = f"{item_type}_map"
        item_map = cast(dict[str, int], new_state[map_name])
        if item_string in item_map:
            return item_map[item_string]

        next_id_map = cast(dict[str, int], new_state["next_id_map"])
        new_id = next_id_map[item_type]
        item_map[item_string] = new_id
        next_id_map[item_type] += 1
        return new_id

    # 1. Migrate global_coverage
    global_cov = cast(dict[str, dict[int, int]], new_state["global_coverage"])
    for cov_type in ["uops", "edges", "rare_events"]:
        id_type = cov_type.rstrip("s")
        for item_str, count in old_state.get("global_coverage", {}).get(cov_type, {}).items():
            item_id = get_or_create_id(id_type, str(item_str))
            global_cov[cov_type][item_id] = count

    # 2. Migrate per_file_coverage
    per_file_cov = cast(dict[str, Any], new_state["per_file_coverage"])
    for filename, metadata in old_state.get("per_file_coverage", {}).items():
        new_metadata = metadata.copy()

        # a. Migrate baseline_coverage
        new_baseline = {}
        for harness, harness_data in metadata.get("baseline_coverage", {}).items():
            new_harness_data = harness_data.copy()
            for cov_type in ["uops", "edges", "rare_events"]:
                id_type = cov_type.rstrip("s")
                new_harness_data[cov_type] = {
                    get_or_create_id(id_type, str(item_str)): count
                    for item_str, count in harness_data.get(cov_type, {}).items()
                }
            new_baseline[harness] = new_harness_data
        new_metadata["baseline_coverage"] = new_baseline

        # b. Migrate lineage_coverage_profile
        new_lineage = {}
        for harness, harness_data in metadata.get("lineage_coverage_profile", {}).items():
            new_harness_data = harness_data.copy()
            for cov_type in ["uops", "edges", "rare_events"]:
                id_type = cov_type.rstrip("s")
                new_harness_data[cov_type] = {
                    get_or_create_id(id_type, str(item_str))
                    for item_str in harness_data.get(cov_type, set())
                }
            new_lineage[harness] = new_harness_data
        new_metadata["lineage_coverage_profile"] = new_lineage

        per_file_cov[filename] = new_metadata

    print("[+] Migration complete.")
    return new_state


def main() -> None:
    """Parse args to inspect, convert, or migrate the state file."""
    parser = argparse.ArgumentParser(description="Inspect or migrate lafleur's coverage state.")
    parser.add_argument("input_file", type=Path, help="Path to the coverage_state.pkl file.")
    parser.add_argument(
        "output_file",
        type=Path,
        nargs="?",
        help="Optional path to save output. If ends in .json, saves as JSON. If ends in .pkl, saves as a migrated pickle file.",
    )

    args = parser.parse_args()

    if not args.input_file.is_file():
        print(f"Error: Input file not found at {args.input_file}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input_file, "rb") as f:
            state = pickle.load(f)
    except (pickle.UnpicklingError, IOError) as e:
        print(f"Error: Could not read pickle file: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Main Logic ---
    migrated_state = state
    if "uop_map" not in state:
        migrated_state = migrate_state_to_integers(state)

    # Convert sets to lists for JSON serialization
    def set_to_list(obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        raise TypeError

    if not args.output_file:
        # Default action: print as JSON to stdout
        print(json.dumps(migrated_state, indent=2, default=set_to_list))

    elif args.output_file.suffix == ".json":
        with open(args.output_file, "w") as json_f:
            json.dump(migrated_state, json_f, indent=2, default=set_to_list)
        print(f"State saved as JSON to {args.output_file}")

    elif args.output_file.suffix == ".pkl":
        with open(args.output_file, "wb") as pkl_f:
            pickle.dump(migrated_state, pkl_f)
        print(f"Migrated state saved as pickle to {args.output_file}")


if __name__ == "__main__":
    main()
