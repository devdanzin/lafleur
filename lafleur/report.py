"""
Text reporter for lafleur fuzzing instances.

This module provides a CLI tool to generate human-readable text summaries
of fuzzing runs by consuming metadata, stats, and crash information.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json_file(path: Path) -> dict[str, Any] | None:
    """Load a JSON file, returning None if it doesn't exist or is invalid."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def load_latest_timeseries_entry(instance_dir: Path) -> dict[str, Any] | None:
    """
    Load the latest entry from the timeseries log.

    The timeseries log contains system metrics (RSS, corpus size, disk usage)
    that aren't stored in fuzz_run_stats.json.

    Args:
        instance_dir: Path to the fuzzing instance directory.

    Returns:
        Dictionary with the latest timeseries entry, or None if not found.
    """
    logs_dir = instance_dir / "logs"
    if not logs_dir.exists():
        return None

    # Find timeseries files (there may be multiple from different runs)
    timeseries_files = sorted(logs_dir.glob("timeseries_*.jsonl"), reverse=True)
    if not timeseries_files:
        return None

    # Read the latest entry from the most recent timeseries file
    for ts_file in timeseries_files:
        try:
            # Read the last line efficiently
            with open(ts_file, "rb") as f:
                # Seek to end and work backwards to find last newline
                f.seek(0, 2)  # Go to end
                file_size = f.tell()
                if file_size == 0:
                    continue

                # Read backwards to find the last complete line
                pos = file_size - 1
                while pos > 0:
                    f.seek(pos)
                    char = f.read(1)
                    if char == b"\n" and pos < file_size - 1:
                        break
                    pos -= 1

                # Read the last line
                if pos > 0:
                    f.seek(pos + 1)
                else:
                    f.seek(0)

                last_line = f.read().decode("utf-8").strip()
                if last_line:
                    return json.loads(last_line)
        except (OSError, json.JSONDecodeError):
            continue

    return None


def parse_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parse an ISO format timestamp string into a datetime object."""
    if not timestamp_str:
        return None
    try:
        # Handle various ISO formats
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        return datetime.fromisoformat(timestamp_str)
    except (ValueError, TypeError):
        return None


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 0:
        return "N/A"

    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def format_number(value: int | float | None, suffix: str = "") -> str:
    """Format a number with thousands separators and optional suffix."""
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:,.2f}{suffix}"
    return f"{value:,}{suffix}"


def get_jit_asan_status(config_args: str | None) -> tuple[str, str]:
    """Extract JIT and ASan status from Python config args."""
    if not config_args:
        return ("Unknown", "Unknown")

    jit_status = "Enabled" if "--enable-experimental-jit" in config_args else "Disabled"
    asan_status = "Enabled" if "--with-address-sanitizer" in config_args else "Disabled"

    return (jit_status, asan_status)


def load_crash_data(instance_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """
    Load and group crash metadata by fingerprint.

    Returns a dict mapping fingerprint -> list of crash metadata dicts.
    """
    crashes_dir = instance_dir / "crashes"
    crash_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

    if not crashes_dir.exists():
        return crash_groups

    # Look for metadata.json in crash subdirectories
    for crash_dir in crashes_dir.iterdir():
        if not crash_dir.is_dir():
            continue

        metadata_path = crash_dir / "metadata.json"
        metadata = load_json_file(metadata_path)

        if metadata:
            fingerprint = metadata.get("fingerprint", "UNKNOWN")
            metadata["_crash_dir"] = str(crash_dir)
            crash_groups[fingerprint].append(metadata)

    return crash_groups


def calculate_duration(
    metadata: dict[str, Any] | None, stats: dict[str, Any] | None, instance_dir: Path
) -> tuple[float, str]:
    """
    Calculate the duration of the fuzzing run.

    Returns (duration_seconds, end_time_source) where end_time_source indicates
    how the end time was determined.
    """
    # Get start time - check multiple sources
    start_time = None
    start_time_str = None

    # First, check stats file (most reliable source)
    if stats:
        start_time_str = stats.get("start_time")

    # Then check metadata
    if not start_time_str and metadata:
        start_time_str = metadata.get("start_time")
        if not start_time_str and "configuration" in metadata:
            # Check if stored in args
            args = metadata.get("configuration", {}).get("args", {})
            start_time_str = args.get("start_time")

    # Also check stats file modification time as fallback for start
    stats_path = instance_dir / "fuzz_run_stats.json"

    if start_time_str:
        start_time = parse_timestamp(start_time_str)

    # Get end time from stats
    end_time = None
    end_source = "now"

    if stats:
        last_update_str = stats.get("last_update_time")
        if last_update_str:
            end_time = parse_timestamp(last_update_str)
            end_source = "last_update"

    # Fallback to file modification time or now
    if not end_time:
        if stats_path.exists():
            try:
                mtime = stats_path.stat().st_mtime
                end_time = datetime.fromtimestamp(mtime, tz=timezone.utc)
                end_source = "file_mtime"
            except OSError:
                pass

    if not end_time:
        end_time = datetime.now(timezone.utc)
        end_source = "now"

    # If no start time, try to use metadata file creation/modification
    if not start_time:
        metadata_path = instance_dir / "logs" / "run_metadata.json"
        if metadata_path.exists():
            try:
                # Use creation time if available, otherwise modification time
                stat = metadata_path.stat()
                ctime = getattr(stat, "st_birthtime", stat.st_mtime)
                start_time = datetime.fromtimestamp(ctime, tz=timezone.utc)
            except OSError:
                pass

    if not start_time:
        return (-1.0, "unknown")

    duration = (end_time - start_time).total_seconds()
    return (max(0.0, duration), end_source)


def truncate_string(s: str, max_len: int, suffix: str = "...") -> str:
    """Truncate a string to max_len, adding suffix if truncated."""
    if len(s) <= max_len:
        return s
    return s[: max_len - len(suffix)] + suffix


def generate_report(instance_dir: Path) -> str:
    """Generate a text report for the given instance directory."""
    lines: list[str] = []

    # Load data files
    metadata_path = instance_dir / "logs" / "run_metadata.json"
    stats_path = instance_dir / "fuzz_run_stats.json"

    metadata = load_json_file(metadata_path)
    stats = load_json_file(stats_path)
    timeseries = load_latest_timeseries_entry(instance_dir)
    crash_groups = load_crash_data(instance_dir)

    # Calculate derived metrics
    duration_seconds, duration_source = calculate_duration(metadata, stats, instance_dir)
    total_mutations = stats.get("total_mutations", 0) if stats else 0
    speed = total_mutations / duration_seconds if duration_seconds > 0 else 0.0

    # ========== HEADER ==========
    lines.append("=" * 80)
    lines.append("LAFLEUR FUZZING INSTANCE REPORT")
    lines.append("=" * 80)

    if metadata:
        instance_name = metadata.get("instance_name", "N/A")
        run_id = metadata.get("run_id", "N/A")
        env = metadata.get("environment", {})
        hostname = env.get("hostname", "N/A")
        platform_info = env.get("os", "N/A")
    else:
        instance_name = "N/A"
        run_id = "N/A"
        hostname = "N/A"
        platform_info = "N/A"

    lines.append(f"Instance Name:  {instance_name}")
    lines.append(f"Run ID:         {run_id}")
    lines.append(f"Hostname:       {hostname}")
    lines.append(f"Platform:       {truncate_string(platform_info, 60)}")
    lines.append(f"Report Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # ========== SYSTEM ==========
    lines.append("-" * 80)
    lines.append("SYSTEM")
    lines.append("-" * 80)

    if metadata:
        hardware = metadata.get("hardware", {})
        env = metadata.get("environment", {})
        config = metadata.get("configuration", {})

        cpu_physical = hardware.get("cpu_count_physical", "N/A")
        cpu_logical = hardware.get("cpu_count_logical", "N/A")
        total_ram = hardware.get("total_ram_gb", "N/A")
        python_version = env.get("python_version", "N/A")
        config_args = env.get("python_config_args", "")

        jit_status, asan_status = get_jit_asan_status(config_args)

        # Clean up Python version (remove newlines)
        if isinstance(python_version, str):
            python_version = python_version.replace("\n", " ")
            python_version = truncate_string(python_version, 60)
    else:
        cpu_physical = "N/A"
        cpu_logical = "N/A"
        total_ram = "N/A"
        python_version = "N/A"
        jit_status = "N/A"
        asan_status = "N/A"

    lines.append(f"CPU:            {cpu_physical} physical / {cpu_logical} logical cores")
    lines.append(
        f"Total RAM:      {format_number(total_ram, ' GB') if isinstance(total_ram, (int, float)) else total_ram}"
    )
    lines.append(f"Python:         {python_version}")
    lines.append(f"JIT:            {jit_status}")
    lines.append(f"ASan:           {asan_status}")
    lines.append("")

    # ========== PERFORMANCE ==========
    lines.append("-" * 80)
    lines.append("PERFORMANCE")
    lines.append("-" * 80)

    uptime_str = format_duration(duration_seconds) if duration_seconds >= 0 else "N/A"

    # Get memory and disk from timeseries (preferred) or stats
    # These metrics are recorded in the timeseries log, not fuzz_run_stats.json
    process_rss = None
    corpus_size_mb = None
    disk_usage = None
    system_load = None

    if timeseries:
        process_rss = timeseries.get("process_rss_mb")
        corpus_size_mb = timeseries.get("corpus_size_mb")
        disk_usage = timeseries.get("disk_usage_percent")
        system_load = timeseries.get("system_load_1min")

    # Fall back to stats if timeseries doesn't have these
    if stats:
        if process_rss is None:
            process_rss = stats.get("process_rss_mb")
        if corpus_size_mb is None:
            corpus_size_mb = stats.get("corpus_size_mb")
        if disk_usage is None:
            disk_usage = stats.get("disk_usage_percent")

    lines.append(f"Uptime:         {uptime_str}")
    lines.append(f"Executions:     {format_number(total_mutations)}")
    lines.append(f"Speed:          {format_number(speed, ' exec/s')}")
    lines.append(f"System Load:    {format_number(system_load) if system_load else 'N/A'}")
    lines.append(f"Memory (RSS):   {format_number(process_rss, ' MB') if process_rss else 'N/A'}")
    lines.append(
        f"Corpus Size:    {format_number(corpus_size_mb, ' MB') if corpus_size_mb else 'N/A'}"
    )
    lines.append(f"Disk Usage:     {format_number(disk_usage, '%') if disk_usage else 'N/A'}")
    lines.append("")

    # ========== COVERAGE ==========
    lines.append("-" * 80)
    lines.append("COVERAGE")
    lines.append("-" * 80)

    if stats:
        global_edges = stats.get("global_edges", 0)
        global_uops = stats.get("global_uops", 0)
        corpus_files = stats.get("corpus_size", 0)
    else:
        global_edges = 0
        global_uops = 0
        corpus_files = 0

    lines.append(f"Global Edges:   {format_number(global_edges)}")
    lines.append(f"Global Uops:    {format_number(global_uops)}")
    lines.append(f"Corpus Files:   {format_number(corpus_files)}")
    lines.append("")

    # ========== CRASH DIGEST ==========
    lines.append("-" * 80)
    lines.append("CRASH DIGEST")
    lines.append("-" * 80)

    total_crashes = sum(len(crashes) for crashes in crash_groups.values())
    unique_fingerprints = len(crash_groups)

    lines.append(f"Total Crashes:       {format_number(total_crashes)}")
    lines.append(f"Unique Fingerprints: {format_number(unique_fingerprints)}")
    lines.append("")

    if crash_groups:
        # Sort fingerprints by count (descending)
        sorted_fingerprints = sorted(crash_groups.items(), key=lambda x: len(x[1]), reverse=True)

        # Table header
        lines.append(f"{'Count':>6} | {'First Seen':<19} | {'Fingerprint':<30} | Sample Repro")
        lines.append("-" * 80)

        # Show top 10 fingerprints
        for fingerprint, crashes in sorted_fingerprints[:10]:
            count = len(crashes)

            # Find earliest timestamp
            earliest_time = None
            sample_crash_dir = None
            for crash in crashes:
                timestamp_str = crash.get("timestamp")
                if timestamp_str:
                    try:
                        # Timestamp format: "20260109_231723"
                        crash_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                        if earliest_time is None or crash_time < earliest_time:
                            earliest_time = crash_time
                            sample_crash_dir = crash.get("_crash_dir")
                    except ValueError:
                        pass

                # Keep track of a sample crash dir regardless
                if sample_crash_dir is None:
                    sample_crash_dir = crash.get("_crash_dir")

            first_seen = earliest_time.strftime("%Y-%m-%d %H:%M:%S") if earliest_time else "N/A"

            # Get reproduce.sh path
            if sample_crash_dir:
                repro_path = str(Path(sample_crash_dir) / "reproduce.sh")
                repro_path = truncate_string(repro_path, 30)
            else:
                repro_path = "N/A"

            fp_display = truncate_string(fingerprint, 30)

            lines.append(f"{count:>6} | {first_seen:<19} | {fp_display:<30} | {repro_path}")

        if len(sorted_fingerprints) > 10:
            lines.append(f"... and {len(sorted_fingerprints) - 10} more unique fingerprints")
    else:
        lines.append("No crashes recorded.")

    lines.append("")
    lines.append("=" * 80)

    return "\n".join(lines)


def main() -> None:
    """Main entry point for the text reporter CLI."""
    parser = argparse.ArgumentParser(
        description="Generate a text report for a lafleur fuzzing instance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Report for current directory
  %(prog)s /path/to/instance  # Report for specific instance
  %(prog)s . > report.txt     # Save report to file
        """,
    )
    parser.add_argument(
        "instance_dir",
        nargs="?",
        default=".",
        help="Path to the fuzzing instance directory (default: current directory)",
    )

    args = parser.parse_args()

    instance_dir = Path(args.instance_dir).resolve()

    if not instance_dir.exists():
        print(f"Error: Instance directory does not exist: {instance_dir}", file=sys.stderr)
        sys.exit(1)

    # Check if this looks like a lafleur instance
    has_stats = (instance_dir / "fuzz_run_stats.json").exists()
    has_metadata = (instance_dir / "logs" / "run_metadata.json").exists()
    has_corpus = (instance_dir / "corpus").exists()

    if not (has_stats or has_metadata or has_corpus):
        print(
            f"Warning: {instance_dir} may not be a lafleur instance directory. "
            "Missing expected files (fuzz_run_stats.json, logs/run_metadata.json, corpus/).",
            file=sys.stderr,
        )

    report = generate_report(instance_dir)
    print(report)


if __name__ == "__main__":
    main()
