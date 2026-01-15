"""
Campaign aggregator for multi-instance lafleur analysis.

This module provides functionality to aggregate metrics across multiple
lafleur fuzzing instances, deduplicate findings, and produce fleet-wide
summaries for campaign analysis.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict


class GlobalCorpusData(TypedDict):
    """Type definition for global corpus aggregation data."""

    total_files: int
    total_sterile: int
    sum_depth: float
    sum_size: float
    file_count_for_avg: int
    strategy_counter: Counter[str]
    mutator_counter: Counter[str]


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
    # Registry enrichment fields
    status_label: str = "NEW"  # NEW, KNOWN, REGRESSION, NOISE
    issue_number: int | None = None
    issue_url: str | None = None
    issue_title: str | None = None


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
        self.global_corpus: GlobalCorpusData = {
            "total_files": 0,
            "total_sterile": 0,
            "sum_depth": 0.0,
            "sum_size": 0.0,
            "file_count_for_avg": 0,
            "strategy_counter": Counter(),
            "mutator_counter": Counter(),
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

        # Aggregate mutation strategies (with backwards compatibility)
        successful_strategies = corpus.get("successful_strategies", {})
        # Fall back to old field name for backwards compatibility
        if not successful_strategies:
            successful_strategies = corpus.get("successful_mutations", {})
        for strategy, count in successful_strategies.items():
            self.global_corpus["strategy_counter"][strategy] += count

        # Aggregate individual mutators
        successful_mutators = corpus.get("successful_mutators", {})
        for mutator, count in successful_mutators.items():
            self.global_corpus["mutator_counter"][mutator] += count

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

    def get_top_strategies(self, n: int = 5) -> list[tuple[str, int]]:
        """Get top N mutation strategies by success count."""
        return self.global_corpus["strategy_counter"].most_common(n)

    def get_top_mutators(self, n: int = 5) -> list[tuple[str, int]]:
        """Get top N individual mutators/transformers by success count."""
        return self.global_corpus["mutator_counter"].most_common(n)

    def enrich_crashes_from_registry(self, registry: Any) -> None:
        """
        Enrich crash data with registry context.

        Queries the registry for each crash fingerprint and computes
        status labels (NEW, KNOWN, REGRESSION, NOISE).

        Args:
            registry: CrashRegistry instance to query.
        """
        for fingerprint, crash_info in self.global_crashes.items():
            context = registry.get_crash_context(fingerprint)

            if context is None:
                # Not in registry - stays as NEW
                crash_info.status_label = "NEW"
                continue

            triage_status = context.get("triage_status", "")
            crash_status = context.get("crash_status", "")
            issue_number = context.get("issue_number")

            # Compute status label
            if crash_status == "FIXED" or triage_status == "FIXED":
                crash_info.status_label = "REGRESSION"
            elif triage_status in ("IGNORED", "WONTFIX") or crash_status == "WONTFIX":
                crash_info.status_label = "NOISE"
            elif issue_number is not None:
                crash_info.status_label = "KNOWN"
            else:
                crash_info.status_label = "NEW"

            # Store issue info for linking
            crash_info.issue_number = issue_number
            crash_info.issue_url = context.get("issue_url")
            crash_info.issue_title = context.get("title")

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
        lines.append("-" * 100)
        lines.append("GLOBAL CRASH TABLE")
        lines.append("-" * 100)

        if self.global_crashes:
            # Status priority for sorting: REGRESSION > NEW > KNOWN > NOISE
            status_priority = {"REGRESSION": 0, "NEW": 1, "KNOWN": 2, "NOISE": 3}

            # Sort by status priority, then by reproducibility, then by count
            sorted_crashes = sorted(
                self.global_crashes.items(),
                key=lambda x: (
                    status_priority.get(x[1].status_label, 1),
                    -len(x[1].finding_instances) / instance_count if instance_count else 0,
                    -x[1].count,
                ),
            )

            # Table header
            lines.append(
                f"{'Status':<12} | {'Fingerprint':<35} | {'Hits':>6} | "
                f"{'Repro %':>7} | {'Issue':<15}"
            )
            lines.append("-" * 100)

            for fingerprint, info in sorted_crashes[:15]:  # Top 15
                instance_pct = (len(info.finding_instances) / instance_count) * 100
                status = f"[{info.status_label}]"

                # Truncate fingerprint if too long
                fp_display = fingerprint[:35] if len(fingerprint) > 35 else fingerprint

                # Format issue reference
                if info.issue_number:
                    issue_str = f"#{info.issue_number}"
                else:
                    issue_str = "-"

                lines.append(
                    f"{status:<12} | {fp_display:<35} | {info.count:>6,} | "
                    f"{instance_pct:>6.1f}% | {issue_str:<15}"
                )

            if len(sorted_crashes) > 15:
                lines.append(f"... and {len(sorted_crashes) - 15} more unique fingerprints")

            # Count by status
            status_counts = Counter(info.status_label for info in self.global_crashes.values())
            lines.append("")
            lines.append(f"Total Unique Crashes: {len(self.global_crashes)}")
            lines.append(
                f"Total Crash Hits:     {sum(c.count for c in self.global_crashes.values()):,}"
            )
            if status_counts.get("REGRESSION", 0) > 0:
                lines.append(f"  REGRESSIONS: {status_counts['REGRESSION']}")
            if status_counts.get("KNOWN", 0) > 0:
                lines.append(f"  KNOWN:       {status_counts['KNOWN']}")
            if status_counts.get("NOISE", 0) > 0:
                lines.append(f"  NOISE:       {status_counts['NOISE']}")
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

        # Top strategies
        top_strategies = self.get_top_strategies(5)
        if top_strategies:
            top_str = ", ".join(f"{name} ({count:,})" for name, count in top_strategies)
            lines.append(f"Top Strategies: {top_str}")
        else:
            lines.append("Top Strategies: N/A")

        # Top mutators
        top_mutators = self.get_top_mutators(5)
        if top_mutators:
            top_str = ", ".join(f"{name} ({count:,})" for name, count in top_mutators)
            lines.append(f"Top Mutators:   {top_str}")
        else:
            lines.append("Top Mutators:   N/A")

        lines.append("")
        lines.append("=" * 90)

        return "\n".join(lines)


def generate_html_report(aggregator: CampaignAggregator) -> str:
    """
    Generate an offline HTML report with embedded CSS and JavaScript.

    Args:
        aggregator: The CampaignAggregator with loaded and aggregated data.

    Returns:
        Complete HTML document as a string.
    """
    instance_count = len(aggregator.instances)
    total_crashes = sum(c.count for c in aggregator.global_crashes.values())
    unique_crashes = len(aggregator.global_crashes)

    # Calculate max values for bar scaling
    max_speed = max((i.speed for i in aggregator.instances), default=1) or 1
    max_coverage = max((i.coverage for i in aggregator.instances), default=1) or 1
    max_hits = max((c.count for c in aggregator.global_crashes.values()), default=1) or 1

    # Sort instances by coverage (descending)
    sorted_instances = sorted(aggregator.instances, key=lambda i: i.coverage, reverse=True)

    # Status priority for sorting: REGRESSION > NEW > KNOWN > NOISE
    status_priority = {"REGRESSION": 0, "NEW": 1, "KNOWN": 2, "NOISE": 3}

    # Sort crashes by status priority, then by reproducibility, then by count
    sorted_crashes = sorted(
        aggregator.global_crashes.items(),
        key=lambda x: (
            status_priority.get(x[1].status_label, 1),
            -len(x[1].finding_instances) / instance_count if instance_count else 0,
            -x[1].count,
        ),
    )[:15]  # Top 15

    # Build instance rows
    instance_rows = []
    for inst in sorted_instances:
        name_escaped = html.escape(inst.name)
        status_class = "running" if inst.status == "Running" else "stopped"
        speed_pct = (inst.speed / max_speed) * 100 if max_speed else 0
        coverage_pct = (inst.coverage / max_coverage) * 100 if max_coverage else 0
        speed_str = f"{inst.speed:.2f}/s" if inst.speed > 0 else "N/A"

        instance_rows.append(f"""        <tr>
          <td>{name_escaped}</td>
          <td><span class="status {status_class}">{inst.status}</span></td>
          <td data-sort="{inst.speed:.4f}"><div class="bar-container"><div class="bar-fill speed" style="width:{speed_pct:.1f}%"></div><span class="bar-text">{speed_str}</span></div></td>
          <td data-sort="{inst.coverage}"><div class="bar-container"><div class="bar-fill coverage" style="width:{coverage_pct:.1f}%"></div><span class="bar-text">{inst.coverage:,}</span></div></td>
          <td data-sort="{inst.corpus_size}">{inst.corpus_size:,}</td>
          <td data-sort="{inst.crash_count}">{inst.crash_count:,}</td>
        </tr>""")

    # Build crash rows
    crash_rows = []
    for fingerprint, info in sorted_crashes:
        fp_escaped = html.escape(fingerprint[:40] if len(fingerprint) > 40 else fingerprint)
        instance_pct = (len(info.finding_instances) / instance_count * 100) if instance_count else 0
        hits_pct = (info.count / max_hits) * 100 if max_hits else 0

        # Determine row class and status badge
        status_label = info.status_label
        row_class = ""
        if status_label == "REGRESSION":
            row_class = "regression"
            badge = '<span class="badge regression">REGRESSION</span>'
        elif status_label == "NOISE":
            row_class = "noise"
            badge = '<span class="badge noise">NOISE</span>'
        elif status_label == "KNOWN":
            badge = '<span class="badge known">KNOWN</span>'
        else:
            badge = '<span class="badge new">NEW</span>'

        # Format issue link
        if info.issue_number:
            # Use provided URL or default to CPython issues tracker
            issue_url = (
                info.issue_url or f"https://github.com/python/cpython/issues/{info.issue_number}"
            )
            issue_html = (
                f'<a href="{html.escape(issue_url)}" target="_blank">#{info.issue_number}</a>'
            )
        else:
            issue_html = "-"

        crash_rows.append(f"""        <tr class="{row_class}" data-status="{status_priority.get(status_label, 1)}">
          <td>{badge}</td>
          <td title="{html.escape(fingerprint)}">{fp_escaped}</td>
          <td data-sort="{info.count}"><div class="bar-container"><div class="bar-fill hits" style="width:{hits_pct:.1f}%"></div><span class="bar-text">{info.count:,}</span></div></td>
          <td data-sort="{instance_pct:.1f}">{instance_pct:.1f}%</td>
          <td>{issue_html}</td>
        </tr>""")

    # Top strategies
    top_strategies = aggregator.get_top_strategies(5)
    strategies_html = (
        ", ".join(
            f"<span class='mutation'>{html.escape(name)}</span> ({count:,})"
            for name, count in top_strategies
        )
        if top_strategies
        else "N/A"
    )

    # Top mutators
    top_mutators = aggregator.get_top_mutators(5)
    mutators_html = (
        ", ".join(
            f"<span class='mutation'>{html.escape(name)}</span> ({count:,})"
            for name, count in top_mutators
        )
        if top_mutators
        else "N/A"
    )

    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lafleur Campaign Report</title>
  <style>
    :root {{
      --bg: #1a1a2e;
      --surface: #16213e;
      --primary: #0f3460;
      --accent: #e94560;
      --text: #eee;
      --text-dim: #888;
      --success: #4ade80;
      --warning: #fbbf24;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }}
    h1 {{ color: var(--accent); margin-bottom: 0.5rem; }}
    h2 {{ color: var(--text); margin: 2rem 0 1rem; border-bottom: 2px solid var(--primary); padding-bottom: 0.5rem; }}
    .subtitle {{ color: var(--text-dim); margin-bottom: 2rem; }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .kpi-card {{
      background: var(--surface);
      border-radius: 8px;
      padding: 1.5rem;
      border-left: 4px solid var(--accent);
    }}
    .kpi-card .label {{ color: var(--text-dim); font-size: 0.875rem; text-transform: uppercase; }}
    .kpi-card .value {{ font-size: 2rem; font-weight: bold; color: var(--text); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{ padding: 0.75rem 1rem; text-align: left; }}
    th {{
      background: var(--primary);
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }}
    th:hover {{ background: #1a4a7a; }}
    th::after {{ content: " \\2195"; opacity: 0.5; }}
    th.asc::after {{ content: " \\2191"; opacity: 1; }}
    th.desc::after {{ content: " \\2193"; opacity: 1; }}
    tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
    tr:hover {{ background: rgba(255,255,255,0.05); }}
    .status {{
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: bold;
      text-transform: uppercase;
    }}
    .status.running {{ background: var(--success); color: #000; }}
    .status.stopped {{ background: var(--text-dim); color: #000; }}
    .bar-container {{
      position: relative;
      background: rgba(255,255,255,0.1);
      border-radius: 4px;
      height: 24px;
      min-width: 100px;
    }}
    .bar-fill {{
      position: absolute;
      top: 0;
      left: 0;
      height: 100%;
      border-radius: 4px;
      opacity: 0.7;
    }}
    .bar-fill.speed {{ background: linear-gradient(90deg, #4ade80, #22c55e); }}
    .bar-fill.coverage {{ background: linear-gradient(90deg, #60a5fa, #3b82f6); }}
    .bar-fill.hits {{ background: linear-gradient(90deg, #f87171, #ef4444); }}
    .bar-text {{
      position: relative;
      z-index: 1;
      display: block;
      padding: 2px 8px;
      font-size: 0.875rem;
      font-weight: 500;
    }}
    .summary {{ background: var(--surface); padding: 1.5rem; border-radius: 8px; margin-top: 2rem; }}
    .summary p {{ margin: 0.5rem 0; }}
    .mutation {{
      background: var(--primary);
      padding: 0.125rem 0.5rem;
      border-radius: 4px;
      font-size: 0.875rem;
    }}
    .badge {{
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: bold;
      text-transform: uppercase;
    }}
    .badge.regression {{ background: #dc2626; color: #fff; }}
    .badge.noise {{ background: #6b7280; color: #fff; }}
    .badge.known {{ background: #2563eb; color: #fff; }}
    .badge.new {{ background: #16a34a; color: #fff; }}
    tr.regression {{ background: rgba(220, 38, 38, 0.15) !important; }}
    tr.regression:hover {{ background: rgba(220, 38, 38, 0.25) !important; }}
    tr.noise {{ opacity: 0.6; }}
    tr.noise:hover {{ opacity: 0.8; }}
    a {{ color: #60a5fa; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    footer {{ margin-top: 3rem; text-align: center; color: var(--text-dim); font-size: 0.875rem; }}
  </style>
</head>
<body>
  <h1>Lafleur Campaign Report</h1>
  <p class="subtitle">Generated: {report_date}</p>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="label">Core-Hours</div>
      <div class="value">{aggregator.get_core_hours():,.1f}</div>
    </div>
    <div class="kpi-card">
      <div class="label">Total Executions</div>
      <div class="value">{aggregator.totals["total_executions"]:,}</div>
    </div>
    <div class="kpi-card">
      <div class="label">Fleet Speed</div>
      <div class="value">{aggregator.get_fleet_speed():.2f}/s</div>
    </div>
    <div class="kpi-card">
      <div class="label">Unique Crashes</div>
      <div class="value">{unique_crashes}</div>
    </div>
  </div>

  <h2>Instance Leaderboard ({instance_count} instances)</h2>
  <table id="instances">
    <thead>
      <tr>
        <th>Name</th>
        <th>Status</th>
        <th>Speed</th>
        <th>Coverage</th>
        <th>Corpus</th>
        <th>Crashes</th>
      </tr>
    </thead>
    <tbody>
{chr(10).join(instance_rows)}
    </tbody>
  </table>

  <h2>Global Crash Table ({unique_crashes} unique, {total_crashes:,} hits)</h2>
  <table id="crashes">
    <thead>
      <tr>
        <th>Status</th>
        <th>Fingerprint</th>
        <th>Hits</th>
        <th>Repro %</th>
        <th>Issue</th>
      </tr>
    </thead>
    <tbody>
{chr(10).join(crash_rows)}
    </tbody>
  </table>

  <div class="summary">
    <h2 style="margin-top:0;border:none;">Fleet Corpus Summary</h2>
    <p><strong>Total Files:</strong> {aggregator.global_corpus["total_files"]:,}</p>
    <p><strong>Sterile Rate:</strong> {aggregator.get_global_sterile_rate() * 100:.2f}%</p>
    <p><strong>Avg Lineage Depth:</strong> {aggregator.get_avg_lineage_depth():.1f}</p>
    <p><strong>Top Strategies:</strong> {strategies_html}</p>
    <p><strong>Top Mutators:</strong> {mutators_html}</p>
  </div>

  <footer>Lafleur Fuzzer Campaign Analysis</footer>

  <script>
    document.querySelectorAll('th').forEach(th => {{
      th.addEventListener('click', () => {{
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const idx = Array.from(th.parentNode.children).indexOf(th);
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const asc = !th.classList.contains('asc');

        th.parentNode.querySelectorAll('th').forEach(h => h.classList.remove('asc', 'desc'));
        th.classList.add(asc ? 'asc' : 'desc');

        rows.sort((a, b) => {{
          const aCell = a.children[idx], bCell = b.children[idx];
          let aVal = aCell.dataset.sort !== undefined ? aCell.dataset.sort : aCell.textContent.trim();
          let bVal = bCell.dataset.sort !== undefined ? bCell.dataset.sort : bCell.textContent.trim();
          const aNum = parseFloat(aVal.replace(/,/g, '')), bNum = parseFloat(bVal.replace(/,/g, ''));
          if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
          return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        }});
        rows.forEach(row => tbody.appendChild(row));
      }});
    }});
  </script>
</body>
</html>"""


def discover_instances(root_dir: Path) -> list[Path]:
    """
    Discover lafleur instance directories under a root directory.

    Args:
        root_dir: Root directory to search.

    Returns:
        List of paths to valid instance directories.
    """
    instances: list[Path] = []

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
  %(prog)s runs/                        # Analyze all instances under runs/
  %(prog)s runs/ --html report.html     # Generate HTML report
  %(prog)s runs/ --registry crashes.db  # Enrich with registry data
  %(prog)s runs/jit_run1 runs/jit_run2  # Analyze specific instances
  %(prog)s ~/fuzzing/campaign1/         # Analyze a campaign directory
        """,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="Root directory containing instances, or list of instance directories",
    )
    parser.add_argument(
        "--html",
        type=Path,
        metavar="PATH",
        help="Generate HTML report and save to specified path",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        metavar="PATH",
        help="Path to crash registry database for enrichment",
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

    # Enrich crashes with registry data if provided
    if args.registry:
        if args.registry.exists():
            try:
                from lafleur.registry import CrashRegistry

                registry = CrashRegistry(args.registry)
                aggregator.enrich_crashes_from_registry(registry)
                print(f"[+] Enriched crashes from registry: {args.registry}", file=sys.stderr)
            except Exception as e:
                print(f"[!] Warning: Could not load registry: {e}", file=sys.stderr)
        else:
            print(f"[!] Warning: Registry not found: {args.registry}", file=sys.stderr)

    # Generate and print text report
    report = aggregator.generate_report()
    print(report)

    # Generate HTML report if requested
    if args.html:
        html_report = generate_html_report(aggregator)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_report)
        print(f"[+] HTML report saved to {args.html}", file=sys.stderr)


if __name__ == "__main__":
    main()
