import argparse
import glob
import json
import pickle
import random
from pathlib import Path

# Import the canonical set of UOP names from our fuzzer
from lafleur.uop_names import UOP_NAMES


def analyze_campaign(state_file: Path):
    """
    Analyzes a single campaign's coverage state file and extracts all seen UOPs.
    """
    if not state_file.is_file():
        print(f"Error: State file not found at '{state_file}'")
        return

    print(f"[*] Analyzing campaign file: {state_file.name}")

    try:
        with open(state_file, "rb") as f:
            state = pickle.load(f)
    except (pickle.UnpicklingError, EOFError, KeyError) as e:
        print(f"Error: Could not load or parse pickle file '{state_file}': {e}")
        return

    uop_map = state.get("uop_map")
    if not uop_map:
        print(f"Warning: No 'uop_map' found in '{state_file}'. Skipping.")
        return

    # The values of the reverse map are the UOP names
    seen_uops = list(uop_map.keys())

    output_path = state_file.with_suffix(f".{random.randint(1000, 9999)}.uops.json")
    with open(output_path, "w") as f:
        json.dump(seen_uops, f, indent=2)

    print(f"[+] Found {len(seen_uops)} UOPs. Report saved to '{output_path.name}'.")


def generate_report(glob_pattern: str):
    """
    Merges multiple campaign reports and compares against the canonical UOP set.
    """
    report_files = glob.glob(glob_pattern)
    if not report_files:
        print(f"Error: No report files found matching pattern: '{glob_pattern}'")
        return

    print(f"[*] Merging {len(report_files)} campaign reports...")

    all_seen_uops = set()
    for report_file in report_files:
        try:
            with open(report_file, "r") as f:
                uops = json.load(f)
                all_seen_uops.update(uops)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not read or parse '{report_file}'. Skipping. Error: {e}")
            continue

    missing_uops = sorted(list(UOP_NAMES - all_seen_uops))
    spurious_uops = sorted(list(all_seen_uops - UOP_NAMES))

    total_known = len(UOP_NAMES)
    total_seen = len(all_seen_uops)
    total_spurious = len(spurious_uops)
    coverage_percent = ((total_seen - total_spurious) / total_known) * 100

    print("\n--- UOP Coverage Report ---")
    print(f"Total Known UOPs: {total_known}")
    print(f"Total Seen UOPs:  {total_seen}")
    print(f"Total Spurious UOPs recorded:  {total_spurious}")
    print(f"Total Valid UOPs recorded:  {total_seen - total_spurious}")
    print(f"Coverage:         {coverage_percent:.2f}%")
    print("---------------------------\n")

    if not missing_uops:
        print("[+] Excellent! All known UOPs have been covered.")
    else:
        print(f"[*] Found {len(missing_uops)} Missing UOPs to Target:")
        for uop in missing_uops:
            print(f"  - {uop}")


def main():
    """Main entry point for the UOP coverage analysis tool."""
    parser = argparse.ArgumentParser(
        description="Analyze and report on UOP coverage across lafleur campaigns."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sub-command for analyzing a single campaign
    parser_analyze = subparsers.add_parser(
        "analyze", help="Analyze a single coverage_state.pickle file."
    )
    parser_analyze.add_argument(
        "state_file", type=Path, help="Path to the coverage_state.pickle file."
    )

    # Sub-command for generating a merged report
    parser_report = subparsers.add_parser(
        "report", help="Generate a merged report from multiple .uops.json files."
    )
    parser_report.add_argument(
        "glob_pattern",
        type=str,
        help='Glob pattern for the .uops.json files to merge (e.g., "campaign_results/*.uops.json").',
    )

    args = parser.parse_args()

    if args.command == "analyze":
        analyze_campaign(args.state_file)
    elif args.command == "report":
        generate_report(args.glob_pattern)


if __name__ == "__main__":
    main()
