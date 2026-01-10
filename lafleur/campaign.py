"""
Campaign aggregator for multi-instance lafleur analysis.

This module provides functionality to aggregate metrics across multiple
lafleur fuzzing instances, deduplicate findings, and produce fleet-wide
summaries for campaign analysis.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
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


def parse_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parse an ISO format timestamp string into a datetime object."""
    if not timestamp_str:
        return None
    try:
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


@dataclass
class CrashInfo:
    """Aggregated information about a crash fingerprint across instances."""

    count: int = 0
    finding_instances: set[str] = field(default_factory=set)
    first_found: datetime | None = None
    first_finder: str | None = None


@dataclass
class InstanceData:
    """Data loaded from a single fuzzing instance."""

    path: Path
    name: str
    metadata: dict[str, Any] | None = None
    stats: dict[str, Any] | None = None
    corpus_stats: dict[str, Any] | None = None
    status: str = "Unknown"
    speed: float = 0.0
    coverage: int = 0
    crash_count: int = 0
    corpus_size: int = 0


class CampaignAggregator:
    """
    Aggregates metrics across multiple lafleur fuzzing instances.

    Provides fleet-wide analysis including crash deduplication,
    corpus statistics, and performance metrics.
    """

    def __init__(self, instance_paths: list[Path]) -> None:
        """
        Initialize the aggregator with instance directory paths.

        Args:
            instance_paths: List of paths to instance directories.
        """
        self.instance_paths = instance_paths
        self.instances: list[InstanceData] = []
        self.global_crashes: dict[str, CrashInfo] = {}
        self.global_corpus = {
            "total_files": 0,
            "total_sterile": 0,
            "sum_depth": 0.0,
            "sum_size": 0.0,
            "file_count_for_avg": 0,
            "mutation_counter": Counter(),
        }
        self.totals = {
            "total_executions": 0,
            "total_duration_secs": 0.0,
            "total_coverage_edges": 0,
        }

    def load_instances(self) -> None:
        """Load and validate all instance directories."""
        for path in self.instance_paths:
            instance = self._load_instance(path)
            if instance:
                self.instances.append(instance)

    def _load_instance(self, path: Path) -> InstanceData | None:
        """Load data from a single instance directory."""
        metadata_path = path / "logs" / "run_metadata.json"

        # Validate instance by checking for metadata
        if not metadata_path.exists():
            print(f"[!] Skipping {path}: No run_metadata.json found", file=sys.stderr)
            return None

        metadata = load_json_file(metadata_path)
        stats = load_json_file(path / "fuzz_run_stats.json")
        corpus_stats = load_json_file(path / "corpus_stats.json")

        # Determine instance name
        name = metadata.get("instance_name", path.name) if metadata else path.name

        instance = InstanceData(
            path=path,
            name=name,
            metadata=metadata,
            stats=stats,
            corpus_stats=corpus_stats,
        )

        # Calculate derived metrics
        if stats:
            # Determine status based on last update time
            last_update = parse_timestamp(stats.get("last_update_time"))
            if last_update:
                age_seconds = (datetime.now(timezone.utc) - last_update).total_seconds()
                instance.status = "Running" if age_seconds < 300 else "Stopped"  # 5 min threshold
            else:
                instance.status = "Unknown"

            # Calculate speed
            total_mutations = stats.get("total_mutations", 0)
            start_time = parse_timestamp(stats.get("start_time"))
            end_time = parse_timestamp(stats.get("last_update_time"))

            if start_time and end_time:
                duration = (end_time - start_time).total_seconds()
                instance.speed = total_mutations / duration if duration > 0 else 0.0
            else:
                instance.speed = 0.0

            instance.coverage = stats.get("global_edges", 0)
            instance.corpus_size = stats.get("corpus_size", 0)

        return instance

    def aggregate(self) -> None:
        """Perform full aggregation across all loaded instances."""
        for instance in self.instances:
            self._aggregate_crashes(instance)
            self._aggregate_corpus(instance)
            self._aggregate_performance(instance)

    def _aggregate_crashes(self, instance: InstanceData) -> None:
        """Aggregate crash data from an instance."""
        crashes_dir = instance.path / "crashes"
        if not crashes_dir.exists():
            return

        crash_count = 0
        for crash_dir in crashes_dir.iterdir():
            if not crash_dir.is_dir():
                continue

            metadata_path = crash_dir / "metadata.json"
            metadata = load_json_file(metadata_path)
            if not metadata:
                continue

            crash_count += 1
            fingerprint = metadata.get("fingerprint", "UNKNOWN")
            timestamp_str = metadata.get("timestamp")

            # Parse timestamp (format: "20260109_221500")
            crash_time = None
            if timestamp_str:
                try:
                    crash_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                except ValueError:
                    pass

            # Update global crash info
            if fingerprint not in self.global_crashes:
                self.global_crashes[fingerprint] = CrashInfo()

            crash_info = self.global_crashes[fingerprint]
            crash_info.count += 1
            crash_info.finding_instances.add(instance.name)

            # Track first finder
            if crash_time and (
                crash_info.first_found is None or crash_time < crash_info.first_found
            ):
                crash_info.first_found = crash_time
                crash_info.first_finder = instance.name

        instance.crash_count = crash_count

    def _aggregate_corpus(self, instance: InstanceData) -> None:
        """Aggregate corpus statistics from an instance."""
        if not instance.corpus_stats:
            return

        corpus = instance.corpus_stats
        total_files = corpus.get("total_files", 0)

        self.global_corpus["total_files"] += total_files
        self.global_corpus["total_sterile"] += corpus.get("sterile_count", 0)

        # Weighted averages
        if total_files > 0:
            depth_dist = corpus.get("lineage_depth_distribution", {})
            size_dist = corpus.get("file_size_distribution", {})

            if depth_dist.get("mean"):
                self.global_corpus["sum_depth"] += depth_dist["mean"] * total_files
                self.global_corpus["file_count_for_avg"] += total_files

            if size_dist.get("mean"):
                self.global_corpus["sum_size"] += size_dist["mean"] * total_files

        # Aggregate mutation strategies
        successful_mutations = corpus.get("successful_mutations", {})
        for strategy, count in successful_mutations.items():
            self.global_corpus["mutation_counter"][strategy] += count

    def _aggregate_performance(self, instance: InstanceData) -> None:
        """Aggregate performance metrics from an instance."""
        if not instance.stats:
            return

        stats = instance.stats
        self.totals["total_executions"] += stats.get("total_mutations", 0)
        self.totals["total_coverage_edges"] += stats.get("global_edges", 0)

        # Calculate duration
        start_time = parse_timestamp(stats.get("start_time"))
        end_time = parse_timestamp(stats.get("last_update_time"))
        if start_time and end_time:
            duration = (end_time - start_time).total_seconds()
            self.totals["total_duration_secs"] += duration

    def get_fleet_speed(self) -> float:
        """Calculate aggregate fleet execution speed."""
        if self.totals["total_duration_secs"] > 0:
            return self.totals["total_executions"] / self.totals["total_duration_secs"]
        return 0.0

    def get_core_hours(self) -> float:
        """Calculate total core-hours across all instances."""
        return self.totals["total_duration_secs"] / 3600.0

    def get_global_sterile_rate(self) -> float:
        """Calculate global sterile file rate."""
        if self.global_corpus["total_files"] > 0:
            return self.global_corpus["total_sterile"] / self.global_corpus["total_files"]
        return 0.0

    def get_avg_lineage_depth(self) -> float:
        """Calculate weighted average lineage depth across fleet."""
        if self.global_corpus["file_count_for_avg"] > 0:
            return self.global_corpus["sum_depth"] / self.global_corpus["file_count_for_avg"]
        return 0.0

    def get_top_mutations(self, n: int = 5) -> list[tuple[str, int]]:
        """Get top N mutation strategies by success count."""
        return self.global_corpus["mutation_counter"].most_common(n)

    def generate_report(self) -> str:
        """Generate a text report of the campaign analysis."""
        lines: list[str] = []
        instance_count = len(self.instances)

        # ========== CAMPAIGN HEADER ==========
        lines.append("=" * 90)
        lines.append("LAFLEUR CAMPAIGN REPORT")
        lines.append("=" * 90)

        if instance_count == 0:
            lines.append("No valid instances found.")
            return "\n".join(lines)

        # List instances
        instance_names = [i.name for i in self.instances]
        if len(instance_names) <= 3:
            names_str = ", ".join(instance_names)
        else:
            names_str = f"{instance_names[0]}, ... {instance_names[-1]}"

        lines.append(f"Instances:      {instance_count} ({names_str})")
        lines.append(f"Core-Hours:     {self.get_core_hours():,.1f} hours")
        lines.append(f"Executions:     {self.totals['total_executions']:,}")
        lines.append(f"Fleet Speed:    {self.get_fleet_speed():,.2f} exec/s (aggregate)")
        lines.append(f"Report Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # ========== INSTANCE LEADERBOARD ==========
        lines.append("-" * 90)
        lines.append("INSTANCE LEADERBOARD")
        lines.append("-" * 90)

        # Sort instances by coverage (descending)
        sorted_instances = sorted(self.instances, key=lambda i: i.coverage, reverse=True)

        # Table header
        lines.append(
            f"{'Name':<25} | {'Status':<8} | {'Speed':>10} | {'Coverage':>8} | "
            f"{'Crashes':>7} | {'Corpus':>8}"
        )
        lines.append("-" * 90)

        for inst in sorted_instances:
            speed_str = f"{inst.speed:.2f}/s" if inst.speed > 0 else "N/A"
            lines.append(
                f"{inst.name:<25} | {inst.status:<8} | {speed_str:>10} | "
                f"{inst.coverage:>8,} | {inst.crash_count:>7,} | {inst.corpus_size:>8,}"
            )

        lines.append("")

        # ========== GLOBAL CRASH TABLE ==========
        lines.append("-" * 90)
        lines.append("GLOBAL CRASH TABLE")
        lines.append("-" * 90)

        if self.global_crashes:
            # Sort by instance percentage (reproducibility), then by count
            sorted_crashes = sorted(
                self.global_crashes.items(),
                key=lambda x: (len(x[1].finding_instances) / instance_count, x[1].count),
                reverse=True,
            )

            # Table header
            lines.append(
                f"{'Fingerprint':<40} | {'Hits':>6} | {'Instance %':>10} | {'First Finder':<20}"
            )
            lines.append("-" * 90)

            for fingerprint, info in sorted_crashes[:15]:  # Top 15
                instance_pct = (len(info.finding_instances) / instance_count) * 100
                first_finder = info.first_finder or "Unknown"

                # Truncate fingerprint if too long
                fp_display = fingerprint[:40] if len(fingerprint) > 40 else fingerprint

                lines.append(
                    f"{fp_display:<40} | {info.count:>6,} | {instance_pct:>9.1f}% | "
                    f"{first_finder:<20}"
                )

            if len(sorted_crashes) > 15:
                lines.append(f"... and {len(sorted_crashes) - 15} more unique fingerprints")

            lines.append("")
            lines.append(f"Total Unique Crashes: {len(self.global_crashes)}")
            lines.append(
                f"Total Crash Hits:     {sum(c.count for c in self.global_crashes.values()):,}"
            )
        else:
            lines.append("No crashes recorded across fleet.")

        lines.append("")

        # ========== FLEET CORPUS SUMMARY ==========
        lines.append("-" * 90)
        lines.append("FLEET CORPUS SUMMARY")
        lines.append("-" * 90)

        total_files = self.global_corpus["total_files"]
        total_sterile = self.global_corpus["total_sterile"]
        sterile_rate = self.get_global_sterile_rate() * 100
        avg_depth = self.get_avg_lineage_depth()

        lines.append(f"Total Files:    {total_files:,}")
        lines.append(f"Sterile Rate:   {total_sterile:,} ({sterile_rate:.2f}%)")
        lines.append(f"Avg Depth:      {avg_depth:.1f}")

        # Top mutations
        top_mutations = self.get_top_mutations(5)
        if top_mutations:
            top_str = ", ".join(f"{name} ({count:,})" for name, count in top_mutations)
            lines.append(f"Top Mutations:  {top_str}")
        else:
            lines.append("Top Mutations:  N/A")

        lines.append("")
        lines.append("=" * 90)

        return "\n".join(lines)


def discover_instances(root_dir: Path) -> list[Path]:
    """
    Discover lafleur instance directories under a root directory.

    Args:
        root_dir: Root directory to search.

    Returns:
        List of paths to valid instance directories.
    """
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


def main() -> None:
    """Main entry point for the campaign aggregator CLI."""
    parser = argparse.ArgumentParser(
        description="Aggregate and analyze multiple lafleur fuzzing instances.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s runs/                      # Analyze all instances under runs/
  %(prog)s runs/jit_run1 runs/jit_run2  # Analyze specific instances
  %(prog)s ~/fuzzing/campaign1/       # Analyze a campaign directory
        """,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="Root directory containing instances, or list of instance directories",
    )

    args = parser.parse_args()

    # Discover instances from provided paths
    all_instances: list[Path] = []

    for path in args.paths:
        path = path.resolve()
        discovered = discover_instances(path)
        if discovered:
            all_instances.extend(discovered)
        elif path.is_dir():
            # Maybe it's a direct instance path without metadata yet
            print(f"[!] Warning: No instances found under {path}", file=sys.stderr)

    if not all_instances:
        print("Error: No valid lafleur instances found.", file=sys.stderr)
        sys.exit(1)

    # Remove duplicates while preserving order
    seen = set()
    unique_instances = []
    for inst in all_instances:
        if inst not in seen:
            seen.add(inst)
            unique_instances.append(inst)

    print(f"[+] Found {len(unique_instances)} instance(s) to analyze", file=sys.stderr)

    # Create aggregator and run analysis
    aggregator = CampaignAggregator(unique_instances)
    aggregator.load_instances()
    aggregator.aggregate()

    # Generate and print report
    report = aggregator.generate_report()
    print(report)


if __name__ == "__main__":
    main()
