"""
Scoring and coverage analysis for the lafleur fuzzer.

This module provides the ScoringManager class ("The Judge") which handles:
- Analyzing coverage results from child executions
- Parsing JIT statistics from log output
- Scoring mutations to decide interestingness
"""

import json
import sys
from dataclasses import dataclass

from lafleur.coverage import CoverageManager


@dataclass
class NewCoverageInfo:
    """A data class to hold the counts of new coverage found."""

    global_uops: int = 0
    relative_uops: int = 0
    global_edges: int = 0
    relative_edges: int = 0
    global_rare_events: int = 0
    relative_rare_events: int = 0
    total_child_edges: int = 0

    def is_interesting(self) -> bool:
        """Return True if any new coverage was found."""
        return (
            self.global_uops > 0
            or self.relative_uops > 0
            or self.global_edges > 0
            or self.relative_edges > 0
            or self.global_rare_events > 0
            or self.relative_rare_events > 0
        )


class InterestingnessScorer:
    """Calculates a score to determine if a mutated child is worth keeping."""

    MIN_INTERESTING_SCORE = 10.0

    def __init__(
        self,
        coverage_info: NewCoverageInfo,
        parent_file_size: int,
        parent_lineage_edge_count: int,
        child_file_size: int,
        is_timing_mode: bool,
        jit_avg_time_ms: float | None,
        nojit_avg_time_ms: float | None,
        nojit_cv: float | None,
        jit_stats: dict | None = None,
        parent_jit_stats: dict | None = None,
    ):
        self.info = coverage_info
        self.parent_file_size = parent_file_size
        self.parent_lineage_edge_count = parent_lineage_edge_count
        self.child_file_size = child_file_size
        self.is_timing_mode = is_timing_mode
        self.jit_avg_time_ms = jit_avg_time_ms
        self.nojit_avg_time_ms = nojit_avg_time_ms
        self.nojit_cv = nojit_cv
        self.jit_stats = jit_stats or {}
        self.parent_jit_stats = parent_jit_stats or {}

    def calculate_score(self) -> float:
        """
        Calculate a score based on new coverage, richness, density, and performance.
        """
        score = 0.0

        if self.is_timing_mode and self.jit_avg_time_ms and self.nojit_avg_time_ms:
            # Avoid division by zero for extremely fast non-JIT runs
            if self.nojit_avg_time_ms > 0:
                slowdown_ratio = self.jit_avg_time_ms / self.nojit_avg_time_ms

                # Only reward if the slowdown is statistically significant
                # relative to the noise of the baseline measurement.
                # We require the slowdown to be at least 3x the noise.
                nojit_cv = self.nojit_cv if self.nojit_cv is not None else 0.0
                dynamic_threshold = 1.0 + (3 * nojit_cv)

                print(
                    f"  [~] Timing slowdown ratio (JIT/non-JIT) is {slowdown_ratio:.3f} (minimum: {dynamic_threshold:.3f}).",
                    file=sys.stderr,
                )

                if slowdown_ratio > dynamic_threshold:
                    performance_bonus = (slowdown_ratio - 1.0) * 50.0
                    score += performance_bonus

        # --- JIT Vitals Scoring ---
        zombie_traces = self.jit_stats.get("zombie_traces", 0)
        # max_exit_count = self.jit_stats.get("max_exit_count", 0) # Superseded by density
        max_chain_depth = self.jit_stats.get("max_chain_depth", 0)
        min_code_size = self.jit_stats.get("min_code_size", 0)  # Less critical

        # Differential Scoring for Exit Density
        child_density = self.jit_stats.get("max_exit_density", 0.0)
        parent_density = self.parent_jit_stats.get("max_exit_density", 0.0)
        density_threshold = max(10.0, parent_density * 1.25)

        if child_density > density_threshold:
            print(
                f"  [+] JIT Tachycardia intensified (Density: {child_density:.2f} > {density_threshold:.2f})",
                file=sys.stderr,
            )
            score += 20.0

        if zombie_traces > 0:
            print("  [!] JIT ZOMBIE STATE DETECTED!", file=sys.stderr)
            score += 50.0

        if max_chain_depth > 3:
            print("  [+] JIT Hyper-Extension (Deep Chains) detected.", file=sys.stderr)
            score += 10.0

        if 0 < min_code_size < 5:
            # Reward tiny code sizes (stubs) which often indicate interesting edge cases
            score += 5.0

        # 1. Heavily reward new global discoveries.
        score += self.info.global_edges * 10.0
        score += self.info.global_uops * 5.0
        score += self.info.global_rare_events * 10.0

        # 2. Add smaller rewards for new relative discoveries.
        score += self.info.relative_edges * 1.0
        score += self.info.relative_uops * 0.5

        # 3. Reward for richness (% increase in total coverage).
        if self.parent_lineage_edge_count > 0:
            percent_increase = (self.info.total_child_edges / self.parent_lineage_edge_count) - 1.0
            if percent_increase > 0.1:  # Reward if > 10% richer
                score += percent_increase * 5.0  # Add up to 5 points for a 100% increase

        # 4. Penalize for low coverage density (large size increase for little gain).
        if self.info.global_edges == 0 and self.info.relative_edges > 0:
            size_increase_ratio = (self.child_file_size / (self.parent_file_size + 1)) - 1.0
            if size_increase_ratio > 0.5:  # Penalize if > 50% larger
                # This penalty can offset the small gain from relative edges
                score -= size_increase_ratio * 2.0

        return score


class ScoringManager:
    """
    Manages scoring and coverage analysis for fuzzer results.

    This class handles analyzing coverage from child executions, parsing JIT
    statistics, and deciding if mutations are interesting enough to keep.
    """

    def __init__(self, coverage_manager: CoverageManager, timing_fuzz: bool = False):
        """
        Initialize the ScoringManager.

        Args:
            coverage_manager: CoverageManager instance for accessing coverage state
            timing_fuzz: Whether timing-based fuzzing mode is enabled
        """
        self.coverage_manager = coverage_manager
        self.timing_fuzz = timing_fuzz

    def find_new_coverage(
        self,
        child_coverage: dict,
        parent_lineage_profile: dict,
        parent_id: str | None,
    ) -> NewCoverageInfo:
        """
        Count all new global and relative coverage items from a child's run.

        Args:
            child_coverage: Coverage data from the child execution
            parent_lineage_profile: Coverage profile inherited from parent lineage
            parent_id: ID of the parent file (None for seed files)

        Returns:
            NewCoverageInfo object containing detailed coverage counts
        """
        info = NewCoverageInfo()
        total_edges = 0

        for harness_id, child_data in child_coverage.items():
            lineage_harness_data = parent_lineage_profile.get(harness_id, {})

            total_edges += len(child_data.get("edges", {}))

            # Helper to get the correct reverse map for a given coverage type
            def get_reverse_map(cov_type: str) -> dict:
                return getattr(self.coverage_manager, f"reverse_{cov_type}_map")

            for cov_type in ["uops", "edges", "rare_events"]:
                lineage_set = lineage_harness_data.get(cov_type, set())
                global_coverage_map = self.coverage_manager.state["global_coverage"].get(
                    cov_type, {}
                )
                reverse_map = get_reverse_map(cov_type.rstrip("s"))

                global_counter_attr = f"global_{cov_type}"
                relative_counter_attr = f"relative_{cov_type}"

                for item_id in child_data.get(cov_type, {}):
                    item_str = reverse_map.get(item_id, f"ID_{item_id}_(unknown)")

                    if item_id not in global_coverage_map:
                        setattr(info, global_counter_attr, getattr(info, global_counter_attr) + 1)
                        print(
                            f"[NEW GLOBAL {cov_type.upper()[:-1]}] '{item_str}' in harness '{harness_id}'",
                            file=sys.stderr,
                        )
                    elif parent_id is not None and item_id not in lineage_set:
                        setattr(
                            info, relative_counter_attr, getattr(info, relative_counter_attr) + 1
                        )
                        print(
                            f"[NEW RELATIVE {cov_type.upper()[:-1]}] '{item_str}' in harness '{harness_id}'",
                            file=sys.stderr,
                        )
        info.total_child_edges = total_edges
        return info

    def parse_jit_stats(self, log_content: str) -> dict:
        """
        Parse JIT stats from the driver log output.

        The log may contain multiple [DRIVER:STATS] lines (one per script in session).
        We aggregate them to find the 'peak stress' values.
        It also parses [EKG] WATCHED: lines to find variables the JIT depends on.

        Args:
            log_content: Content of the log file

        Returns:
            Dictionary of aggregated JIT statistics
        """
        aggregated_stats: dict = {
            "max_exit_count": 0,
            "max_chain_depth": 0,
            "zombie_traces": 0,
            "min_code_size": 0,
            "max_exit_density": 0.0,
            "watched_dependencies": [],
        }
        min_code_sizes: list[int] = []
        watched_dependencies: set[str] = set()

        for line in log_content.splitlines():
            if "[DRIVER:STATS]" in line:
                try:
                    json_str = line.split("[DRIVER:STATS]", 1)[1].strip()
                    stats = json.loads(json_str)

                    aggregated_stats["max_exit_count"] = max(
                        aggregated_stats["max_exit_count"], stats.get("max_exit_count", 0)
                    )
                    aggregated_stats["max_chain_depth"] = max(
                        aggregated_stats["max_chain_depth"], stats.get("max_chain_depth", 0)
                    )
                    aggregated_stats["zombie_traces"] = max(
                        aggregated_stats["zombie_traces"], stats.get("zombie_traces", 0)
                    )
                    aggregated_stats["max_exit_density"] = max(
                        aggregated_stats["max_exit_density"], stats.get("max_exit_density", 0.0)
                    )

                    code_size = stats.get("min_code_size", 0)
                    if code_size > 0:
                        min_code_sizes.append(code_size)

                except (json.JSONDecodeError, IndexError):
                    pass
            elif line.startswith("[EKG] WATCHED:"):
                try:
                    variables = line.split("[EKG] WATCHED:", 1)[1].strip()
                    if variables:
                        for var in variables.split(","):
                            var = var.strip()
                            if var:
                                watched_dependencies.add(var)
                except IndexError:
                    pass

        if min_code_sizes:
            aggregated_stats["min_code_size"] = min(min_code_sizes)

        aggregated_stats["watched_dependencies"] = sorted(list(watched_dependencies))

        return aggregated_stats

    def score_and_decide_interestingness(
        self,
        coverage_info: NewCoverageInfo,
        parent_id: str | None,
        mutation_info: dict,
        parent_file_size: int,
        parent_lineage_edge_count: int,
        child_file_size: int,
        jit_avg_time_ms: float | None,
        nojit_avg_time_ms: float | None,
        nojit_cv: float | None,
        jit_stats: dict | None = None,
        parent_jit_stats: dict | None = None,
    ) -> bool:
        """
        Use the scorer to decide if a child is interesting.

        Args:
            coverage_info: NewCoverageInfo with coverage counts
            parent_id: ID of the parent file (None for seeds)
            mutation_info: Information about the mutation applied
            parent_file_size: Size of parent file in bytes
            parent_lineage_edge_count: Number of edges in parent's lineage
            child_file_size: Size of child file in bytes
            jit_avg_time_ms: Average JIT execution time
            nojit_avg_time_ms: Average non-JIT execution time
            nojit_cv: Coefficient of variation for non-JIT timing
            jit_stats: JIT statistics from child execution
            parent_jit_stats: JIT statistics from parent

        Returns:
            True if the child is considered interesting
        """
        # Handle the special case for seed files first.
        if parent_id is None:
            is_seed = "seed" in mutation_info.get("strategy", "")
            if coverage_info.is_interesting() or is_seed:
                return True
            else:
                print("  [~] Seed file produced no JIT coverage. Skipping.", file=sys.stderr)
                return False

        # For normal mutations, use the scoring logic.
        scorer = InterestingnessScorer(
            coverage_info,
            parent_file_size,
            parent_lineage_edge_count,
            child_file_size,
            self.timing_fuzz,
            jit_avg_time_ms,
            nojit_avg_time_ms,
            nojit_cv,
            jit_stats,
            parent_jit_stats,
        )
        score = scorer.calculate_score()

        if score >= scorer.MIN_INTERESTING_SCORE:
            valid_timings = (
                scorer.jit_avg_time_ms is not None
                and scorer.nojit_avg_time_ms is not None
                and scorer.nojit_avg_time_ms > 0
            )
            if self.timing_fuzz and valid_timings:
                # Both values are guaranteed non-None by valid_timings check
                assert scorer.jit_avg_time_ms is not None
                assert scorer.nojit_avg_time_ms is not None
                slowdown_ratio = scorer.jit_avg_time_ms / scorer.nojit_avg_time_ms
                print(
                    f"  [+] Child is interesting with score: {score:.2f} (JIT slowdown: {slowdown_ratio:.2f}x)",
                    file=sys.stderr,
                )
            else:
                print(f"  [+] Child is interesting with score: {score:.2f}", file=sys.stderr)
            return True

        print(f"  [+] Child IS NOT interesting with score: {score:.2f}", file=sys.stderr)
        return False
