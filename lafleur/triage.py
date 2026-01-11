"""
Crash triage CLI for managing the crash registry.

This module provides a command-line interface for importing crashes from
fuzzing campaigns and linking them to GitHub issues.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from lafleur.registry import CrashRegistry


def load_json_file(path: Path) -> dict[str, Any] | None:
    """Load a JSON file, returning None if it doesn't exist or is invalid."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def get_revision_date(revision: str) -> int | None:
    """
    Get the commit timestamp for a git revision.

    Args:
        revision: Git commit hash.

    Returns:
        Unix timestamp of the commit, or None if lookup fails.
    """
    try:
        result = subprocess.run(
            ["git", "show", "-s", "--format=%ct", revision],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    return None


def parse_iso_timestamp(timestamp_str: str) -> int | None:
    """Parse an ISO8601 timestamp to Unix timestamp."""
    if not timestamp_str:
        return None
    try:
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(timestamp_str)
        return int(dt.timestamp())
    except (ValueError, TypeError):
        return None


def discover_instances(root_dir: Path) -> list[Path]:
    """Discover lafleur instance directories under a root directory."""
    instances = []

    if not root_dir.exists():
        return instances

    # Check if root_dir itself is an instance
    if (root_dir / "logs" / "run_metadata.json").exists():
        instances.append(root_dir)
        return instances

    # Search subdirectories
    for subdir in sorted(root_dir.iterdir()):
        if subdir.is_dir() and (subdir / "logs" / "run_metadata.json").exists():
            instances.append(subdir)

    return instances


def import_campaign(args: argparse.Namespace) -> None:
    """Import crashes from a campaign directory into the registry."""
    registry = CrashRegistry(args.db)
    campaign_dir = Path(args.campaign_dir).resolve()

    if not campaign_dir.exists():
        print(f"Error: Directory not found: {campaign_dir}", file=sys.stderr)
        sys.exit(1)

    # Discover instances
    instances = discover_instances(campaign_dir)
    if not instances:
        print(f"Error: No valid instances found under {campaign_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Found {len(instances)} instance(s) to import")

    total_imported = 0
    total_skipped = 0

    for instance_path in instances:
        # Load instance metadata
        metadata_path = instance_path / "logs" / "run_metadata.json"
        metadata = load_json_file(metadata_path)

        if not metadata:
            print(f"  [!] Skipping {instance_path.name}: No valid metadata")
            continue

        instance_name = metadata.get("instance_name", instance_path.name)
        run_id = metadata.get("run_id", "unknown")

        # Get CPython revision info
        env = metadata.get("environment", {})
        cpython_revision = None
        revision_date = None

        # Try to extract revision from python_version string or other fields
        python_version = env.get("python_version", "")
        if ":" in python_version and "(" in python_version:
            # Format: "3.15.0a3+ (heads/main-dirty:e0fb2780649, ...)"
            try:
                rev_part = python_version.split(":")[1].split(",")[0]
                if len(rev_part) >= 8:
                    cpython_revision = rev_part
                    revision_date = get_revision_date(cpython_revision)
            except (IndexError, ValueError):
                pass

        # Fall back to start_time for revision_date proxy
        if revision_date is None:
            stats = load_json_file(instance_path / "fuzz_run_stats.json")
            if stats:
                start_time = stats.get("start_time")
                if start_time:
                    revision_date = parse_iso_timestamp(start_time)

        # Scan crashes directory
        crashes_dir = instance_path / "crashes"
        if not crashes_dir.exists():
            print(f"  [-] {instance_name}: No crashes directory")
            continue

        instance_imported = 0
        instance_skipped = 0

        for crash_dir in crashes_dir.iterdir():
            if not crash_dir.is_dir():
                continue

            crash_metadata_path = crash_dir / "metadata.json"
            crash_metadata = load_json_file(crash_metadata_path)

            if not crash_metadata:
                continue

            fingerprint = crash_metadata.get("fingerprint")
            if not fingerprint:
                continue

            # Get crash timestamp
            timestamp_str = crash_metadata.get("timestamp", "")
            # Convert "20260109_221500" format to ISO8601
            if timestamp_str and "_" in timestamp_str:
                try:
                    dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    timestamp_str = dt.isoformat()
                except ValueError:
                    pass

            # Add sighting to registry
            added = registry.add_sighting(
                fingerprint=fingerprint,
                run_id=run_id,
                instance_name=instance_name,
                timestamp=timestamp_str,
                cpython_revision=cpython_revision,
                revision_date=revision_date,
            )

            if added:
                instance_imported += 1
            else:
                instance_skipped += 1

        print(
            f"  [+] {instance_name}: Imported {instance_imported} sightings "
            f"({instance_skipped} duplicates skipped)"
        )
        total_imported += instance_imported
        total_skipped += instance_skipped

    print(f"\n[+] Total: {total_imported} sightings imported, {total_skipped} duplicates skipped")

    # Show summary stats
    stats = registry.get_stats()
    print(f"\n[+] Registry now contains:")
    print(f"    {stats['total_crashes']} unique crashes")
    print(f"    {stats['total_sightings']} total sightings")
    print(f"    {stats['unique_instances']} unique instances")


def record_issue_wizard(args: argparse.Namespace) -> None:
    """Interactive wizard to record a GitHub issue and link it to a crash."""
    registry = CrashRegistry(args.db)

    print("=" * 60)
    print("RECORD GITHUB ISSUE")
    print("=" * 60)

    # Get issue number
    while True:
        issue_input = input("\nIssue number (e.g., 12345): ").strip()
        if not issue_input:
            print("Issue number is required.")
            continue
        try:
            issue_number = int(issue_input)
            break
        except ValueError:
            print("Please enter a valid integer.")

    # Check if issue exists
    with registry._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reported_issues WHERE issue_number = ?", (issue_number,))
        existing = cursor.fetchone()

    if existing:
        print(f"\n[!] Issue #{issue_number} already exists: {existing['title']}")
        update = input("Update this issue? (y/N): ").strip().lower()
        if update != "y":
            # Just link to crash
            fingerprint = input("\nFingerprint to link (or Enter to skip): ").strip()
            if fingerprint:
                if registry.link_crash_to_issue(fingerprint, issue_number):
                    print(f"[+] Linked crash to issue #{issue_number}")
                else:
                    print(f"[!] Crash fingerprint not found: {fingerprint}")
            return

    # Collect issue details
    print("\n--- Issue Details ---")

    title = input("Title: ").strip()
    url = input(f"URL (default: https://github.com/python/cpython/issues/{issue_number}): ").strip()
    if not url:
        url = f"https://github.com/python/cpython/issues/{issue_number}"

    reported_by = input("Reported by (your GitHub username): ").strip()
    reported_date = input(f"Reported date (default: {datetime.now().date().isoformat()}): ").strip()
    if not reported_date:
        reported_date = datetime.now().date().isoformat()

    description = input("Brief description: ").strip()

    print("\n--- CPython Version ---")
    cpython_revision = input("CPython revision (git hash): ").strip() or None
    cpython_version = input("CPython version (e.g., 3.15.0a3): ").strip() or None
    build_info = input("Build info (e.g., --enable-experimental-jit): ").strip() or None

    print("\n--- Status ---")
    print("Issue status options: Open, Closed, Duplicate")
    issue_status = input("Issue status (default: Open): ").strip() or "Open"

    print("Crash status options: NEW, TRIAGED, REPORTED, FIXED, WONTFIX")
    crash_status = input("Crash status (default: REPORTED): ").strip() or "REPORTED"

    print("\n--- Additional Info (optional) ---")
    linked_prs = input("Linked PRs (comma-separated): ").strip() or None
    tested_oses = input("Tested OSes (e.g., Linux, macOS): ").strip() or None
    labels = input("Labels (comma-separated): ").strip() or None

    # Record the issue
    issue_data = {
        "issue_number": issue_number,
        "title": title,
        "url": url,
        "reported_date": reported_date,
        "reported_by": reported_by,
        "description": description,
        "cpython_revision": cpython_revision,
        "cpython_version": cpython_version,
        "build_info": build_info,
        "issue_status": issue_status,
        "crash_status": crash_status,
        "linked_prs": linked_prs,
        "tested_oses": tested_oses,
        "labels": labels,
    }

    registry.record_issue(issue_data)
    print(f"\n[+] Recorded issue #{issue_number}: {title}")

    # Link to crash fingerprint
    print("\n--- Link to Crash ---")
    fingerprint = input("Fingerprint to link (or Enter to skip): ").strip()

    if fingerprint:
        crash = registry.get_crash(fingerprint)
        if crash:
            registry.link_crash_to_issue(fingerprint, issue_number)
            print(f"[+] Linked crash to issue #{issue_number}")
            print(f"    Fingerprint: {fingerprint}")
            print(f"    Sightings: {crash['sighting_count']}")
        else:
            print(f"[!] Crash fingerprint not found: {fingerprint}")
            create = input("Create crash record anyway? (y/N): ").strip().lower()
            if create == "y":
                registry.add_sighting(
                    fingerprint=fingerprint,
                    run_id="manual",
                    instance_name="manual",
                    timestamp=datetime.now().isoformat(),
                )
                registry.link_crash_to_issue(fingerprint, issue_number)
                print(f"[+] Created crash record and linked to issue #{issue_number}")

    print("\n[+] Done!")


def show_status(args: argparse.Namespace) -> None:
    """Show registry status and statistics."""
    registry = CrashRegistry(args.db)
    stats = registry.get_stats()

    print("=" * 60)
    print("CRASH REGISTRY STATUS")
    print("=" * 60)
    print(f"Database: {registry.db_path}")
    print()
    print(f"Total unique crashes:  {stats['total_crashes']}")
    print(f"Total sightings:       {stats['total_sightings']}")
    print(f"Reported issues:       {stats['total_issues']}")
    print(f"Linked to issues:      {stats['linked_to_issues']}")
    print(f"Unique instances:      {stats['unique_instances']}")
    print(f"Unique runs:           {stats['unique_runs']}")
    print()

    if stats.get("by_triage_status"):
        print("By triage status:")
        for status, count in sorted(stats["by_triage_status"].items()):
            print(f"  {status}: {count}")


def list_crashes(args: argparse.Namespace) -> None:
    """List crashes, optionally filtered by status."""
    registry = CrashRegistry(args.db)
    crashes = registry.get_all_crashes(triage_status=args.status)

    if not crashes:
        print("No crashes found.")
        return

    print(f"{'Fingerprint':<45} | {'Status':<8} | {'Hits':>6} | Issue")
    print("-" * 80)

    for crash in crashes:
        fp = crash["fingerprint"][:45]
        status = crash["triage_status"]
        hits = crash["sighting_count"]
        issue = crash.get("issue_number") or "-"
        issue_title = crash.get("issue_title", "")[:20] if crash.get("issue_title") else ""

        if issue != "-" and issue_title:
            issue_str = f"#{issue} {issue_title}"
        elif issue != "-":
            issue_str = f"#{issue}"
        else:
            issue_str = "-"

        print(f"{fp:<45} | {status:<8} | {hits:>6} | {issue_str}")


def show_crash(args: argparse.Namespace) -> None:
    """Show details for a specific crash."""
    registry = CrashRegistry(args.db)
    crash = registry.get_crash(args.fingerprint)

    if not crash:
        print(f"Crash not found: {args.fingerprint}")
        return

    print("=" * 60)
    print("CRASH DETAILS")
    print("=" * 60)
    print(f"Fingerprint:    {crash['fingerprint']}")
    print(f"Triage Status:  {crash['triage_status']}")
    print(f"First Seen:     {crash['first_seen_date']}")
    print(f"Latest Seen:    {crash['latest_sighting']}")
    print(f"Total Sightings: {crash['sighting_count']}")
    print(f"Instances:      {', '.join(crash['instances'])}")

    if crash.get("notes"):
        print(f"Notes:          {crash['notes']}")

    if crash.get("issue_number"):
        print()
        print("--- Linked Issue ---")
        print(f"Issue:          #{crash['issue_number']}")
        print(f"Title:          {crash.get('issue_title', 'N/A')}")
        print(f"URL:            {crash.get('issue_url', 'N/A')}")
        print(f"Issue Status:   {crash.get('issue_status', 'N/A')}")
        print(f"Crash Status:   {crash.get('crash_status', 'N/A')}")

    # Show recent sightings
    print()
    print("--- Recent Sightings ---")
    sightings = registry.get_sightings(args.fingerprint, limit=5)
    for s in sightings:
        rev = s["cpython_revision"][:8] if s["cpython_revision"] else "N/A"
        print(f"  {s['timestamp']} | {s['instance_name']} | rev: {rev}")


def export_issues(args: argparse.Namespace) -> None:
    """Export reported issues to a JSON file."""
    registry = CrashRegistry(args.db)
    issues = registry.get_all_reported_issues()

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(issues, f, indent=4, sort_keys=True)
        print(f"[+] Exported {len(issues)} known issues to {args.output}")
    except OSError as e:
        print(f"Error writing to {args.output}: {e}", file=sys.stderr)
        sys.exit(1)


def import_issues(args: argparse.Namespace) -> None:
    """Import reported issues from a JSON file."""
    try:
        with open(args.input, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error reading {args.input}: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate structure
    if not isinstance(data, list):
        print("Error: JSON file must contain a list of issue objects", file=sys.stderr)
        sys.exit(1)

    for i, item in enumerate(data):
        if not isinstance(item, dict):
            print(f"Error: Item {i} is not a dictionary", file=sys.stderr)
            sys.exit(1)
        if "issue_number" not in item:
            print(f"Error: Item {i} missing required field 'issue_number'", file=sys.stderr)
            sys.exit(1)

    registry = CrashRegistry(args.db)
    count = registry.upsert_reported_issues(data)
    print(f"[+] Imported/Updated {count} known issues from {args.input}")


def run_interactive_triage(args: argparse.Namespace) -> None:
    """Run interactive triage loop for NEW crashes."""
    registry = CrashRegistry(args.db)
    new_crashes = registry.get_new_crashes()

    if not new_crashes:
        print("\n[+] All caught up! No crashes need triage.")
        return

    print(f"\n[+] Found {len(new_crashes)} crash(es) needing triage\n")

    try:
        for i, crash in enumerate(new_crashes, 1):
            fingerprint = crash["fingerprint"]
            first_seen = crash.get("first_seen_date", "Unknown")
            sighting_count = registry.get_sighting_count(fingerprint)

            # Display crash info
            print("-" * 64)
            print(f"CRASH [{i}/{len(new_crashes)}]: {fingerprint}")
            print(f"First Seen: {first_seen} | Total Sightings: {sighting_count}")
            print("-" * 64)

            # Get user action
            while True:
                try:
                    action = (
                        input("\nAction? [R]eport / [I]gnore / [M]ark Fixed / [S]kip / [Q]uit > ")
                        .strip()
                        .lower()
                    )
                except EOFError:
                    print("\n[!] EOF received, exiting.")
                    return

                if action in ("r", "report"):
                    # Link to issue
                    while True:
                        try:
                            issue_input = input("Issue Number: ").strip()
                            if not issue_input:
                                print("Issue number is required.")
                                continue
                            issue_num = int(issue_input)
                            break
                        except ValueError:
                            print("Please enter a valid integer.")
                        except EOFError:
                            print("\n[!] EOF received, exiting.")
                            return

                    registry.link_crash_to_issue(fingerprint, issue_num)
                    registry.set_triage_status(fingerprint, "REPORTED")
                    print(f"[+] Linked to Issue #{issue_num}")
                    break

                elif action in ("i", "ignore"):
                    registry.set_triage_status(fingerprint, "IGNORED")
                    print("[+] Marked as IGNORED (Noise)")
                    break

                elif action in ("m", "fixed"):
                    registry.set_triage_status(fingerprint, "FIXED")
                    print("[+] Marked as FIXED")
                    break

                elif action in ("s", "skip"):
                    print("[~] Skipped")
                    break

                elif action in ("q", "quit"):
                    print("\n[+] Exiting triage loop.")
                    return

                else:
                    print("Invalid action. Use R, I, M, S, or Q.")

            print()  # Blank line between crashes

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted. Exiting triage loop.")
        return

    print("[+] Triage session complete!")


def main() -> None:
    """Main entry point for the triage CLI."""
    parser = argparse.ArgumentParser(
        description="Crash registry and triage tool for lafleur.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--db",
        type=Path,
        default="crashes.db",
        help="Path to the SQLite database (default: crashes.db)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Import command
    import_parser = subparsers.add_parser(
        "import",
        help="Import crashes from a campaign directory",
    )
    import_parser.add_argument(
        "campaign_dir",
        type=str,
        help="Campaign directory containing instance subdirectories",
    )

    # Record issue command
    subparsers.add_parser(
        "record-issue",
        help="Interactive wizard to record a GitHub issue",
    )

    # Status command
    subparsers.add_parser(
        "status",
        help="Show registry statistics",
    )

    # List command
    list_parser = subparsers.add_parser(
        "list",
        help="List crashes in the registry",
    )
    list_parser.add_argument(
        "--status",
        choices=["NEW", "TRIAGED", "IGNORED"],
        help="Filter by triage status",
    )

    # Show command
    show_parser = subparsers.add_parser(
        "show",
        help="Show details for a specific crash",
    )
    show_parser.add_argument(
        "fingerprint",
        type=str,
        help="Crash fingerprint to look up",
    )

    # Export issues command
    export_parser = subparsers.add_parser(
        "export-issues",
        help="Export reported issues to a JSON file",
    )
    export_parser.add_argument(
        "output",
        type=Path,
        help="Output JSON file path",
    )

    # Import issues command
    import_issues_parser = subparsers.add_parser(
        "import-issues",
        help="Import reported issues from a JSON file",
    )
    import_issues_parser.add_argument(
        "input",
        type=Path,
        help="Input JSON file path",
    )

    # Interactive triage command
    subparsers.add_parser(
        "interactive",
        help="Interactively triage NEW crashes",
    )

    args = parser.parse_args()

    if args.command == "import":
        import_campaign(args)
    elif args.command == "record-issue":
        record_issue_wizard(args)
    elif args.command == "status":
        show_status(args)
    elif args.command == "list":
        list_crashes(args)
    elif args.command == "show":
        show_crash(args)
    elif args.command == "export-issues":
        export_issues(args)
    elif args.command == "import-issues":
        import_issues(args)
    elif args.command == "interactive":
        run_interactive_triage(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
