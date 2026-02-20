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


class HealthSummary(TypedDict):
    """Type definition for per-instance health event summary."""

    total_events: int
    by_event: Counter[str]
    by_category: Counter[str]
    waste_event_count: int
    crash_profile: Counter[str]
    parent_offenders: Counter[str]


class CrashAttributionSummary(TypedDict):
    """Summary of crash attribution data from a JSONL log."""

    total_attributed_crashes: int
    unique_fingerprints: int
    avg_lineage_depth: float
    direct_strategy_counter: Counter[str]
    direct_transformer_counter: Counter[str]
    lineage_strategy_counter: Counter[str]
    lineage_transformer_counter: Counter[str]
    combined_transformer_scores: Counter[str]
    combined_strategy_scores: Counter[str]


# Constants matching the learning system multipliers
CRASH_DIRECT_WEIGHT = 5
CRASH_LINEAGE_WEIGHT = 2


WASTE_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "parent_parse_failure",
        "mutation_recursion_error",
        "unparse_recursion_error",
        "child_script_none",
        "core_code_syntax_error",
    }
)


def load_json_file(path: Path) -> dict[str, Any] | None:
    """Load a JSON file, returning None if it doesn't exist or is invalid."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def load_health_summary(health_log_path: Path) -> HealthSummary | None:
    """Load and summarize health events from a JSONL health log.

    Args:
        health_log_path: Path to the health_events.jsonl file.

    Returns:
        Aggregated health summary, or None if the file is missing or empty.
    """
    if not health_log_path.exists():
        return None

    by_event: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    crash_profile: Counter[str] = Counter()
    parent_offenders: Counter[str] = Counter()
    total_events = 0
    waste_event_count = 0

    try:
        with open(health_log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_events += 1
                event = record.get("event", "unknown")
                category = record.get("cat", "unknown")

                by_event[event] += 1
                by_category[category] += 1

                if event in WASTE_EVENT_TYPES:
                    waste_event_count += 1
                    parent_id = record.get("parent_id")
                    if parent_id:
                        parent_offenders[parent_id] += 1

                if event == "ignored_crash":
                    reason = record.get("reason", "unknown")
                    crash_profile[reason] += 1
    except OSError:
        return None

    if total_events == 0:
        return None

    return {
        "total_events": total_events,
        "by_event": by_event,
        "by_category": by_category,
        "waste_event_count": waste_event_count,
        "crash_profile": crash_profile,
        "parent_offenders": parent_offenders,
    }


def load_crash_attribution_summary(log_path: Path) -> CrashAttributionSummary | None:
    """Parse crash_attribution.jsonl and return aggregated summary.

    Args:
        log_path: Path to the crash_attribution.jsonl file.

    Returns:
        CrashAttributionSummary dict, or None if no data exists.
    """
    if not log_path.is_file():
        return None

    total_crashes = 0
    fingerprints: set[str] = set()
    total_lineage_depth = 0

    direct_strategy: Counter[str] = Counter()
    direct_transformer: Counter[str] = Counter()
    lineage_strategy: Counter[str] = Counter()
    lineage_transformer: Counter[str] = Counter()

    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_crashes += 1
                fp = entry.get("fingerprint", "")
                if fp:
                    fingerprints.add(fp)
                total_lineage_depth += entry.get("lineage_depth", 0)

                # Direct attribution
                direct = entry.get("direct", {})
                ds = direct.get("strategy", "")
                if ds:
                    direct_strategy[ds] += 1
                for t in direct.get("transformers", []):
                    direct_transformer[t] += 1

                # Lineage attribution
                for s in entry.get("lineage_strategies", []):
                    if s:
                        lineage_strategy[s] += 1
                for t in entry.get("lineage_transformers", []):
                    lineage_transformer[t] += 1

    except OSError:
        return None

    if total_crashes == 0:
        return None

    # Compute combined scores using learning system multipliers
    combined_transformer: Counter[str] = Counter()
    for t, count in direct_transformer.items():
        combined_transformer[t] += count * CRASH_DIRECT_WEIGHT
    for t, count in lineage_transformer.items():
        combined_transformer[t] += count * CRASH_LINEAGE_WEIGHT

    combined_strategy: Counter[str] = Counter()
    for s, count in direct_strategy.items():
        combined_strategy[s] += count * CRASH_DIRECT_WEIGHT
    for s, count in lineage_strategy.items():
        combined_strategy[s] += count * CRASH_LINEAGE_WEIGHT

    return CrashAttributionSummary(
        total_attributed_crashes=total_crashes,
        unique_fingerprints=len(fingerprints),
        avg_lineage_depth=total_lineage_depth / total_crashes,
        direct_strategy_counter=direct_strategy,
        direct_transformer_counter=direct_transformer,
        lineage_strategy_counter=lineage_strategy,
        lineage_transformer_counter=lineage_transformer,
        combined_transformer_scores=combined_transformer,
        combined_strategy_scores=combined_strategy,
    )


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
    health_summary: HealthSummary | None = None
    status: str = "Unknown"
    speed: float = 0.0
    coverage: int = 0
    crash_count: int = 0
    corpus_size: int = 0
    relative_dir: str = ""


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
        self.global_health: dict[str, Any] = {
            "total_events": 0,
            "waste_events": 0,
            "by_event": Counter(),
            "by_category": Counter(),
            "crash_profile": Counter(),
            "top_offenders": Counter(),
        }
        self.fleet_crash_attribution: CrashAttributionSummary | None = None

    def load_instances(self) -> None:
        """Load and validate all instance directories."""
        for path in self.instance_paths:
            instance = self._load_instance(path)
            if instance:
                self.instances.append(instance)

    def set_relative_dirs(self, campaign_root: Path) -> None:
        """Set relative directory paths for all instances."""
        for inst in self.instances:
            try:
                inst.relative_dir = str(inst.path.relative_to(campaign_root))
            except ValueError:
                # Instance path is not under campaign_root
                inst.relative_dir = str(inst.path)

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
        health_summary = load_health_summary(path / "logs" / "health_events.jsonl")

        # Determine instance name
        name = metadata.get("instance_name", path.name) if metadata else path.name

        instance = InstanceData(
            path=path,
            name=name,
            metadata=metadata,
            stats=stats,
            corpus_stats=corpus_stats,
            health_summary=health_summary,
            relative_dir=path.name,
        )

        # Calculate derived metrics
        if stats:
            # Determine status: check heartbeat file first (updates every ~60s),
            # fall back to last_update_time in stats (updates once per session).
            instance.status = self._detect_instance_status(path, stats)

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

    @staticmethod
    def _detect_instance_status(instance_path: Path, stats: dict[str, Any]) -> str:
        """Detect whether an instance is running or stopped.

        Checks the heartbeat file first (written every ~60s from the mutation
        loop), then falls back to last_update_time in fuzz_run_stats.json
        (written once per session). This avoids false "Stopped" status during
        long sessions.

        Args:
            instance_path: Root directory of the instance.
            stats: Loaded fuzz_run_stats.json contents.

        Returns:
            "Running", "Stopped", or "Unknown".
        """
        now = datetime.now(timezone.utc)
        threshold_seconds = 300  # 5 minutes

        # Primary signal: heartbeat file (written every ~60s)
        heartbeat_path = instance_path / "logs" / "heartbeat"
        try:
            heartbeat_text = heartbeat_path.read_text(encoding="utf-8").strip()
            heartbeat_time = parse_timestamp(heartbeat_text)
            if heartbeat_time:
                age = (now - heartbeat_time).total_seconds()
                return "Running" if age < threshold_seconds else "Stopped"
        except (OSError, ValueError):
            pass  # File doesn't exist or is unreadable — fall through

        # Fallback: last_update_time from stats (written once per session)
        last_update = parse_timestamp(stats.get("last_update_time"))
        if last_update:
            age = (now - last_update).total_seconds()
            return "Running" if age < threshold_seconds else "Stopped"

        return "Unknown"

    def aggregate(self) -> None:
        """Perform full aggregation across all loaded instances."""
        for instance in self.instances:
            self._aggregate_crashes(instance)
            self._aggregate_corpus(instance)
            self._aggregate_performance(instance)
            self._aggregate_health(instance)
        self._aggregate_crash_attribution()

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

            if depth_dist.get("mean") is not None:
                self.global_corpus["sum_depth"] += depth_dist["mean"] * total_files
                self.global_corpus["file_count_for_avg"] += total_files

            if size_dist.get("mean") is not None:
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

    def _aggregate_health(self, instance: InstanceData) -> None:
        """Aggregate health event data from an instance."""
        if not instance.health_summary:
            return

        hs = instance.health_summary
        self.global_health["total_events"] += hs["total_events"]
        self.global_health["waste_events"] += hs["waste_event_count"]
        self.global_health["by_event"] += hs["by_event"]
        self.global_health["by_category"] += hs["by_category"]
        self.global_health["crash_profile"] += hs["crash_profile"]

        # Prefix parent_ids with instance name for fleet-wide tracking
        for parent_id, count in hs["parent_offenders"].items():
            self.global_health["top_offenders"][f"{instance.name}:{parent_id}"] += count

    def _aggregate_crash_attribution(self) -> None:
        """Aggregate crash attribution data across all instances."""
        merged_total = 0
        merged_fingerprints: set[str] = set()
        merged_depth_sum = 0.0
        merged_direct_strategy: Counter[str] = Counter()
        merged_direct_transformer: Counter[str] = Counter()
        merged_lineage_strategy: Counter[str] = Counter()
        merged_lineage_transformer: Counter[str] = Counter()

        for instance in self.instances:
            log_path = instance.path / "logs" / "crash_attribution.jsonl"
            summary = load_crash_attribution_summary(log_path)
            if summary is None:
                continue

            merged_total += summary["total_attributed_crashes"]
            merged_depth_sum += summary["avg_lineage_depth"] * summary["total_attributed_crashes"]
            merged_direct_strategy += summary["direct_strategy_counter"]
            merged_direct_transformer += summary["direct_transformer_counter"]
            merged_lineage_strategy += summary["lineage_strategy_counter"]
            merged_lineage_transformer += summary["lineage_transformer_counter"]

            # Re-parse to get exact fingerprints for fleet-wide dedup
            try:
                with open(log_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            fp = entry.get("fingerprint", "")
                            if fp:
                                merged_fingerprints.add(fp)
                        except json.JSONDecodeError:
                            continue
            except OSError:
                pass

        if merged_total == 0:
            self.fleet_crash_attribution = None
            return

        # Compute combined scores
        combined_transformer: Counter[str] = Counter()
        for t, count in merged_direct_transformer.items():
            combined_transformer[t] += count * CRASH_DIRECT_WEIGHT
        for t, count in merged_lineage_transformer.items():
            combined_transformer[t] += count * CRASH_LINEAGE_WEIGHT

        combined_strategy: Counter[str] = Counter()
        for s, count in merged_direct_strategy.items():
            combined_strategy[s] += count * CRASH_DIRECT_WEIGHT
        for s, count in merged_lineage_strategy.items():
            combined_strategy[s] += count * CRASH_LINEAGE_WEIGHT

        self.fleet_crash_attribution = CrashAttributionSummary(
            total_attributed_crashes=merged_total,
            unique_fingerprints=len(merged_fingerprints),
            avg_lineage_depth=merged_depth_sum / merged_total,
            direct_strategy_counter=merged_direct_strategy,
            direct_transformer_counter=merged_direct_transformer,
            lineage_strategy_counter=merged_lineage_strategy,
            lineage_transformer_counter=merged_lineage_transformer,
            combined_transformer_scores=combined_transformer,
            combined_strategy_scores=combined_strategy,
        )

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

    def get_fleet_waste_rate(self) -> float:
        """Calculate fleet-wide mutation waste rate."""
        total_mutations = self.totals["total_executions"]
        if total_mutations == 0:
            return 0.0
        return self.global_health["waste_events"] / total_mutations

    def get_fleet_health_grade(self) -> tuple[str, str]:
        """Get the fleet-wide health grade based on waste rate."""
        return self.health_grade(self.get_fleet_waste_rate())

    def get_top_offenders(self, n: int = 5) -> list[tuple[str, int]]:
        """Get parent files causing the most waste events fleet-wide."""
        return self.global_health["top_offenders"].most_common(n)

    def get_crash_profile(self, n: int = 5) -> list[tuple[str, int]]:
        """Get most common ignored crash reasons fleet-wide."""
        return self.global_health["crash_profile"].most_common(n)

    @staticmethod
    def health_grade(waste_rate: float) -> tuple[str, str]:
        """Map a waste rate to a health grade.

        Returns:
            Tuple of (short_label, long_label): e.g. ("OK", "Healthy").
        """
        if waste_rate < 0.02:
            return ("OK", "Healthy")
        elif waste_rate < 0.10:
            return ("WARN", "Degraded")
        else:
            return ("BAD", "Unhealthy")

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
            f"{'Crashes':>7} | {'Corpus':>8} | {'Health':>6} | {'Dir'}"
        )
        lines.append("-" * 130)

        for inst in sorted_instances:
            speed_str = f"{inst.speed:.2f}/s" if inst.speed > 0 else "N/A"

            # Per-instance health grade
            if inst.health_summary and inst.stats:
                total_muts = inst.stats.get("total_mutations", 0)
                if total_muts > 0:
                    inst_waste = inst.health_summary["waste_event_count"] / total_muts
                else:
                    inst_waste = 0.0
                health_str, _ = self.health_grade(inst_waste)
            else:
                health_str = "N/A"

            lines.append(
                f"{inst.name:<25} | {inst.status:<8} | {speed_str:>10} | "
                f"{inst.coverage:>8,} | {inst.crash_count:>7,} | {inst.corpus_size:>8,} | "
                f"{health_str:>6} | {inst.relative_dir}"
            )

        lines.append("")

        # ========== FLEET HEALTH ==========
        lines.append("-" * 90)
        lines.append("FLEET HEALTH")
        lines.append("-" * 90)

        waste_rate = self.get_fleet_waste_rate()
        short_grade, long_grade = self.get_fleet_health_grade()
        lines.append(f"Waste Rate:     {waste_rate * 100:.2f}% ({long_grade})")
        lines.append(
            f"Health Events:  {self.global_health['total_events']:,} total, "
            f"{self.global_health['waste_events']:,} waste"
        )

        top_offenders = self.get_top_offenders(5)
        if top_offenders:
            offender_str = ", ".join(f"{name} ({count:,})" for name, count in top_offenders)
            lines.append(f"Top Offenders:  {offender_str}")

        crash_profile = self.get_crash_profile(5)
        if crash_profile:
            profile_str = ", ".join(f"{reason} ({count:,})" for reason, count in crash_profile)
            lines.append(f"Crash Profile:  {profile_str}")

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

        # ========== CRASH-PRODUCTIVE MUTATORS ==========
        if self.fleet_crash_attribution:
            ca = self.fleet_crash_attribution
            lines.append("-" * 90)
            lines.append("CRASH-PRODUCTIVE MUTATORS")
            lines.append("-" * 90)

            lines.append(
                f"Attributed Crashes: {ca['total_attributed_crashes']:,} "
                f"({ca['unique_fingerprints']:,} unique fingerprints)"
            )
            lines.append(f"Avg Lineage Depth:  {ca['avg_lineage_depth']:.1f}")
            lines.append("")

            # Top strategies by combined score
            top_strategies = ca["combined_strategy_scores"].most_common(5)
            if top_strategies:
                strat_strs = [f"{name} (score: {score:,})" for name, score in top_strategies]
                lines.append(f"Top Crash Strategies: {', '.join(strat_strs)}")
                lines.append("")

            # Top mutators by combined score — two-column layout, top 10
            top_mutators = ca["combined_transformer_scores"].most_common(10)
            if top_mutators:
                lines.append("Top Crash Mutators (by attribution score):")

                # Calculate padding for alignment
                max_name_len = max(len(name) for name, _ in top_mutators)
                pad = max(max_name_len + 2, 30)

                # Two-column layout
                half = (len(top_mutators) + 1) // 2
                for i in range(half):
                    left_name, left_score = top_mutators[i]
                    left_str = f"  {left_name} {'.' * (pad - len(left_name) - 2)} {left_score:,}"

                    if i + half < len(top_mutators):
                        right_name, right_score = top_mutators[i + half]
                        right_str = (
                            f"  {right_name} {'.' * (pad - len(right_name) - 2)} {right_score:,}"
                        )
                        lines.append(f"{left_str}    {right_str}")
                    else:
                        lines.append(left_str)

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
        dir_escaped = html.escape(inst.relative_dir)
        status_class = "running" if inst.status == "Running" else "stopped"
        speed_pct = (inst.speed / max_speed) * 100 if max_speed else 0
        coverage_pct = (inst.coverage / max_coverage) * 100 if max_coverage else 0
        speed_str = f"{inst.speed:.2f}/s" if inst.speed > 0 else "N/A"

        # Per-instance health badge
        if inst.health_summary and inst.stats:
            total_muts = inst.stats.get("total_mutations", 0)
            if total_muts > 0:
                inst_waste = inst.health_summary["waste_event_count"] / total_muts
            else:
                inst_waste = 0.0
            short_label, _ = CampaignAggregator.health_grade(inst_waste)
            health_class = f"health-{short_label.lower()}"
            health_badge = f'<span class="health-badge {health_class}">{short_label}</span>'
        else:
            health_badge = '<span class="health-badge">N/A</span>'

        instance_rows.append(f"""        <tr>
          <td>{name_escaped}</td>
          <td><span class="status {status_class}">{inst.status}</span></td>
          <td data-sort="{inst.speed:.4f}"><div class="bar-container"><div class="bar-fill speed" style="width:{speed_pct:.1f}%"></div><span class="bar-text">{speed_str}</span></div></td>
          <td data-sort="{inst.coverage}"><div class="bar-container"><div class="bar-fill coverage" style="width:{coverage_pct:.1f}%"></div><span class="bar-text">{inst.coverage:,}</span></div></td>
          <td data-sort="{inst.corpus_size}">{inst.corpus_size:,}</td>
          <td data-sort="{inst.crash_count}">{inst.crash_count:,}</td>
          <td>{health_badge}</td>
          <td>{dir_escaped}</td>
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

    # Fleet health data
    fleet_waste_rate = aggregator.get_fleet_waste_rate()
    fleet_short_grade, fleet_long_grade = aggregator.get_fleet_health_grade()
    fleet_health_color = {
        "OK": "var(--success)",
        "WARN": "var(--warning)",
        "BAD": "var(--accent)",
    }.get(fleet_short_grade, "var(--text-dim)")

    # Fleet health section content
    top_offenders = aggregator.get_top_offenders(5)
    offenders_html = (
        ", ".join(
            f"<span class='mutation'>{html.escape(name)}</span> ({count:,})"
            for name, count in top_offenders
        )
        if top_offenders
        else "None"
    )
    crash_profile = aggregator.get_crash_profile(5)
    crash_profile_html = (
        ", ".join(
            f"<span class='mutation'>{html.escape(reason)}</span> ({count:,})"
            for reason, count in crash_profile
        )
        if crash_profile
        else "None"
    )

    # Waste event breakdown
    waste_by_event = aggregator.global_health["by_event"]
    waste_breakdown_html = (
        ", ".join(f"{html.escape(evt)} ({count:,})" for evt, count in waste_by_event.most_common(5))
        if waste_by_event
        else "None"
    )

    # Crash-Productive Mutators card
    crash_attribution_html = ""
    if aggregator.fleet_crash_attribution:
        ca = aggregator.fleet_crash_attribution
        top_mutators = ca["combined_transformer_scores"].most_common(10)
        max_mut_score = top_mutators[0][1] if top_mutators else 1

        mutator_rows_html = []
        for name, score in top_mutators:
            pct = (score / max_mut_score) * 100 if max_mut_score else 0
            direct_count = ca["direct_transformer_counter"].get(name, 0)
            lineage_count = ca["lineage_transformer_counter"].get(name, 0)
            name_escaped = html.escape(name)
            mutator_rows_html.append(
                f"        <tr>\n"
                f"          <td>{name_escaped}</td>\n"
                f'          <td data-sort="{score}">'
                f'<div class="bar-container">'
                f'<div class="bar-fill speed" style="width:{pct:.1f}%"></div>'
                f'<span class="bar-text">{score:,}</span></div></td>\n'
                f"          <td>{direct_count}</td>\n"
                f"          <td>{lineage_count}</td>\n"
                f"        </tr>"
            )

        crash_attribution_html = (
            f'\n  <div class="summary">\n'
            f'    <h2 style="margin-top:0;border:none;">Crash-Productive Mutators</h2>\n'
            f"    <p><strong>Attributed Crashes:</strong> "
            f"{ca['total_attributed_crashes']:,}</p>\n"
            f"    <p><strong>Unique Fingerprints:</strong> "
            f"{ca['unique_fingerprints']:,}</p>\n"
            f"    <p><strong>Avg Lineage Depth:</strong> "
            f"{ca['avg_lineage_depth']:.1f}</p>\n"
            f"    <table>\n"
            f"      <thead><tr>"
            f"<th>Mutator</th><th>Score</th><th>Direct</th><th>Lineage</th>"
            f"</tr></thead>\n"
            f"      <tbody>\n" + "\n".join(mutator_rows_html) + "\n"
            "      </tbody>\n"
            "    </table>\n"
            "  </div>"
        )

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
    .health-badge {{
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: bold;
    }}
    .health-ok {{ background: var(--success); color: #000; }}
    .health-warn {{ background: var(--warning); color: #000; }}
    .health-bad {{ background: var(--accent); color: #fff; }}
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
    <div class="kpi-card" style="border-left-color: {fleet_health_color};">
      <div class="label">Fleet Health</div>
      <div class="value" style="color: {fleet_health_color};">{fleet_long_grade}</div>
      <div class="label">{fleet_waste_rate * 100:.2f}% waste</div>
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
        <th>Health</th>
        <th>Directory</th>
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
{crash_attribution_html}
  <div class="summary">
    <h2 style="margin-top:0;border:none;">Fleet Corpus Summary</h2>
    <p><strong>Total Files:</strong> {aggregator.global_corpus["total_files"]:,}</p>
    <p><strong>Sterile Rate:</strong> {aggregator.get_global_sterile_rate() * 100:.2f}%</p>
    <p><strong>Avg Lineage Depth:</strong> {aggregator.get_avg_lineage_depth():.1f}</p>
    <p><strong>Top Strategies:</strong> {strategies_html}</p>
    <p><strong>Top Mutators:</strong> {mutators_html}</p>
  </div>

  <div class="summary">
    <h2 style="margin-top:0;border:none;">Fleet Health</h2>
    <p><strong>Waste Rate:</strong> {fleet_waste_rate * 100:.2f}% ({fleet_long_grade})</p>
    <p><strong>Health Events:</strong> {aggregator.global_health["total_events"]:,} total, {aggregator.global_health["waste_events"]:,} waste</p>
    <p><strong>Event Breakdown:</strong> {waste_breakdown_html}</p>
    <p><strong>Top Offenders:</strong> {offenders_html}</p>
    <p><strong>Crash Profile:</strong> {crash_profile_html}</p>
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

    # Set relative directory paths from the campaign root
    campaign_root = args.paths[0].resolve()
    if campaign_root.is_file():
        campaign_root = campaign_root.parent
    aggregator.set_relative_dirs(campaign_root)

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
