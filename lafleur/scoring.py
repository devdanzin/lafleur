"""
Scoring and coverage analysis for the lafleur fuzzer.

This module provides the ScoringManager class ("The Judge") which handles:
- Analyzing coverage results from child executions
- Parsing JIT statistics from log output
- Scoring mutations to decide interestingness
- Analyzing runs for new coverage and interestingness
"""

import ast
import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from lafleur.coverage import (
    CoverageManager,
    merge_coverage_into_global,
    parse_log_for_edge_coverage,
)
from lafleur.utils import ExecutionResult

if TYPE_CHECKING:
    from lafleur.artifacts import ArtifactManager
    from lafleur.corpus_manager import CorpusManager
    from lafleur.health import HealthMonitor

# Coverage types tracked by the fuzzer
COVERAGE_TYPES = ("uops", "edges", "rare_events")

# Tachycardia (instability) tracking constants
TACHYCARDIA_DECAY_FACTOR = 0.95
MAX_DENSITY_GROWTH_FACTOR = 5.0


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

    # --- Coverage scoring weights ---
    GLOBAL_EDGE_WEIGHT = 10.0
    GLOBAL_UOP_WEIGHT = 5.0
    GLOBAL_RARE_EVENT_WEIGHT = 10.0
    RELATIVE_EDGE_WEIGHT = 1.0
    RELATIVE_UOP_WEIGHT = 0.5

    # --- Richness and density weights ---
    RICHNESS_BONUS_WEIGHT = 5.0
    RICHNESS_THRESHOLD = 0.1
    DENSITY_PENALTY_WEIGHT = 2.0
    DENSITY_PENALTY_THRESHOLD = 0.5

    # --- Timing weights ---
    TIMING_BONUS_MULTIPLIER = 50.0
    TIMING_CV_MULTIPLIER = 3.0

    # --- JIT Vitals bonuses (absolute density, fallback) ---
    TACHYCARDIA_BONUS = 20.0
    TACHYCARDIA_MIN_DENSITY = 10.0
    TACHYCARDIA_PARENT_MULTIPLIER = 1.25

    # --- JIT Vitals bonuses (delta density, session mode) ---
    TACHYCARDIA_DELTA_DENSITY_THRESHOLD = 0.135
    TACHYCARDIA_DELTA_EXITS_THRESHOLD = 20
    TACHYCARDIA_DELTA_BONUS = 20.0

    ZOMBIE_BONUS = 50.0
    CHAIN_DEPTH_BONUS = 10.0
    CHAIN_DEPTH_THRESHOLD = 3
    STUB_BONUS = 5.0
    STUB_SIZE_THRESHOLD = 5

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
                dynamic_threshold = 1.0 + (self.TIMING_CV_MULTIPLIER * nojit_cv)

                print(
                    f"  [~] Timing slowdown ratio (JIT/non-JIT) is {slowdown_ratio:.3f} (minimum: {dynamic_threshold:.3f}).",
                    file=sys.stderr,
                )

                if slowdown_ratio > dynamic_threshold:
                    performance_bonus = (slowdown_ratio - 1.0) * self.TIMING_BONUS_MULTIPLIER
                    score += performance_bonus

        # --- JIT Vitals Scoring ---
        zombie_traces = self.jit_stats.get("zombie_traces") or 0
        max_chain_depth = self.jit_stats.get("max_chain_depth") or 0
        min_code_size = self.jit_stats.get("min_code_size") or 0

        # --- Tachycardia scoring ---
        # Prefer delta metrics (child-isolated) when available from session mode.
        # Fall back to absolute metrics for non-session runs or old data.
        child_delta_density = self.jit_stats.get("child_delta_max_exit_density") or 0.0
        child_delta_exits = self.jit_stats.get("child_delta_total_exits") or 0

        if child_delta_density > 0 or child_delta_exits > 0:
            # Delta metrics available — use child-isolated measurement.
            # Both thresholds are parent-relative to prevent coasting.
            parent_delta_density = self.parent_jit_stats.get("child_delta_max_exit_density") or 0.0
            density_threshold = max(
                self.TACHYCARDIA_DELTA_DENSITY_THRESHOLD,
                parent_delta_density * self.TACHYCARDIA_PARENT_MULTIPLIER,
            )
            parent_delta_exits = self.parent_jit_stats.get("child_delta_total_exits") or 0
            exits_threshold = max(
                self.TACHYCARDIA_DELTA_EXITS_THRESHOLD,
                parent_delta_exits * self.TACHYCARDIA_PARENT_MULTIPLIER,
            )
            tachycardia_triggered = (
                child_delta_density > density_threshold or child_delta_exits > exits_threshold
            )
            if tachycardia_triggered:
                print(
                    f"  [+] JIT Tachycardia (delta): density={child_delta_density:.2f} "
                    f"(threshold={density_threshold:.2f}), "
                    f"exits={child_delta_exits} (threshold={exits_threshold:.0f})",
                    file=sys.stderr,
                )
                score += self.TACHYCARDIA_DELTA_BONUS
        else:
            # No delta metrics — fall back to absolute (original behavior).
            child_density = self.jit_stats.get("max_exit_density") or 0.0
            parent_density = self.parent_jit_stats.get("max_exit_density") or 0.0
            density_threshold = max(
                self.TACHYCARDIA_MIN_DENSITY,
                parent_density * self.TACHYCARDIA_PARENT_MULTIPLIER,
            )
            if child_density > density_threshold:
                print(
                    f"  [+] JIT Tachycardia (absolute): density={child_density:.2f} > "
                    f"{density_threshold:.2f}",
                    file=sys.stderr,
                )
                score += self.TACHYCARDIA_BONUS

        if zombie_traces > 0:
            print("  [!] JIT ZOMBIE STATE DETECTED!", file=sys.stderr)
            score += self.ZOMBIE_BONUS

        if max_chain_depth > self.CHAIN_DEPTH_THRESHOLD:
            print("  [+] JIT Hyper-Extension (Deep Chains) detected.", file=sys.stderr)
            score += self.CHAIN_DEPTH_BONUS

        if 0 < min_code_size < self.STUB_SIZE_THRESHOLD:
            score += self.STUB_BONUS

        # 1. Heavily reward new global discoveries.
        score += self.info.global_edges * self.GLOBAL_EDGE_WEIGHT
        score += self.info.global_uops * self.GLOBAL_UOP_WEIGHT
        score += self.info.global_rare_events * self.GLOBAL_RARE_EVENT_WEIGHT

        # 2. Add smaller rewards for new relative discoveries.
        score += self.info.relative_edges * self.RELATIVE_EDGE_WEIGHT
        score += self.info.relative_uops * self.RELATIVE_UOP_WEIGHT

        # 3. Reward for richness (% increase in total coverage).
        if self.parent_lineage_edge_count > 0:
            percent_increase = (self.info.total_child_edges / self.parent_lineage_edge_count) - 1.0
            if percent_increase > self.RICHNESS_THRESHOLD:
                score += percent_increase * self.RICHNESS_BONUS_WEIGHT

        # 4. Penalize for low coverage density (large size increase for little gain).
        if self.info.global_edges == 0 and self.info.relative_edges > 0:
            size_increase_ratio = (self.child_file_size / (self.parent_file_size + 1)) - 1.0
            if size_increase_ratio > self.DENSITY_PENALTY_THRESHOLD:
                score -= size_increase_ratio * self.DENSITY_PENALTY_WEIGHT

        return score


class ScoringManager:
    """
    Manages scoring and coverage analysis for fuzzer results.

    This class handles analyzing coverage from child executions, parsing JIT
    statistics, and deciding if mutations are interesting enough to keep.
    """

    def __init__(
        self,
        coverage_manager: CoverageManager,
        timing_fuzz: bool = False,
        artifact_manager: "ArtifactManager | None" = None,
        corpus_manager: "CorpusManager | None" = None,
        get_core_code_func: Callable[[str], str] | None = None,
        run_stats: dict | None = None,
        health_monitor: "HealthMonitor | None" = None,
    ):
        """
        Initialize the ScoringManager.

        Args:
            coverage_manager: CoverageManager instance for accessing coverage state
            timing_fuzz: Whether timing-based fuzzing mode is enabled
            artifact_manager: ArtifactManager for crash/divergence detection
            corpus_manager: CorpusManager for known_hashes lookup
            get_core_code_func: Function to extract core code from source
            run_stats: Run statistics dictionary for updating counters
            health_monitor: Optional HealthMonitor for adverse event tracking
        """
        self.coverage_manager = coverage_manager
        self.timing_fuzz = timing_fuzz
        self.artifact_manager = artifact_manager
        self.corpus_manager = corpus_manager
        self._get_core_code = get_core_code_func
        self.run_stats = run_stats
        self.health_monitor = health_monitor

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

        # Pre-build reverse map and counter attribute lookups
        reverse_maps = {
            "uops": self.coverage_manager.reverse_uop_map,
            "edges": self.coverage_manager.reverse_edge_map,
            "rare_events": self.coverage_manager.reverse_rare_event_map,
        }
        counter_attrs = {
            "uops": ("global_uops", "relative_uops"),
            "edges": ("global_edges", "relative_edges"),
            "rare_events": ("global_rare_events", "relative_rare_events"),
        }

        for harness_id, child_data in child_coverage.items():
            lineage_harness_data = parent_lineage_profile.get(harness_id, {})

            total_edges += len(child_data.get("edges", {}))

            for cov_type in COVERAGE_TYPES:
                lineage_set = lineage_harness_data.get(cov_type, set())
                global_coverage_map = self.coverage_manager.state["global_coverage"].get(
                    cov_type, {}
                )
                reverse_map = reverse_maps[cov_type]
                global_attr, relative_attr = counter_attrs[cov_type]

                for item_id in child_data.get(cov_type, {}):
                    item_str = reverse_map.get(item_id, f"ID_{item_id}_(unknown)")

                    if item_id not in global_coverage_map:
                        setattr(info, global_attr, getattr(info, global_attr) + 1)
                        print(
                            f"[NEW GLOBAL {cov_type.upper()[:-1]}] '{item_str}' in harness '{harness_id}'",
                            file=sys.stderr,
                        )
                    elif parent_id is not None and item_id not in lineage_set:
                        setattr(info, relative_attr, getattr(info, relative_attr) + 1)
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
            # Delta metrics from the child script (last stats line)
            "child_delta_max_exit_density": 0.0,
            "child_delta_max_exit_count": 0,
            "child_delta_total_exits": 0,
            "child_delta_new_executors": 0,
            "child_delta_new_zombies": 0,
        }
        min_code_sizes: list[int] = []
        watched_dependencies: set[str] = set()

        for line in log_content.splitlines():
            if "[DRIVER:STATS]" in line:
                try:
                    json_str = line.split("[DRIVER:STATS]", 1)[1].strip()
                    stats = json.loads(json_str)

                    aggregated_stats["max_exit_count"] = max(
                        aggregated_stats["max_exit_count"],
                        stats.get("max_exit_count") or 0,
                    )
                    aggregated_stats["max_chain_depth"] = max(
                        aggregated_stats["max_chain_depth"],
                        stats.get("max_chain_depth") or 0,
                    )
                    aggregated_stats["zombie_traces"] = max(
                        aggregated_stats["zombie_traces"],
                        stats.get("zombie_traces") or 0,
                    )
                    aggregated_stats["max_exit_density"] = max(
                        aggregated_stats["max_exit_density"],
                        stats.get("max_exit_density") or 0.0,
                    )

                    code_size = stats.get("min_code_size") or 0
                    if code_size > 0:
                        min_code_sizes.append(code_size)

                    # Delta metrics: overwrite each time (we want the LAST line = child)
                    if "delta_max_exit_density" in stats:
                        aggregated_stats["child_delta_max_exit_density"] = (
                            stats.get("delta_max_exit_density") or 0.0
                        )
                        aggregated_stats["child_delta_max_exit_count"] = (
                            stats.get("delta_max_exit_count") or 0
                        )
                        aggregated_stats["child_delta_total_exits"] = (
                            stats.get("delta_total_exits") or 0
                        )
                        aggregated_stats["child_delta_new_executors"] = (
                            stats.get("delta_new_executors") or 0
                        )
                        aggregated_stats["child_delta_new_zombies"] = (
                            stats.get("delta_new_zombies") or 0
                        )

                except (json.JSONDecodeError, IndexError) as e:
                    print(
                        f"  [!] Warning: Failed to parse JIT stats line: {e}. "
                        f"Line content: {line[:200]}",
                        file=sys.stderr,
                    )
            elif line.startswith("[EKG] WATCHED:"):
                try:
                    variables = line.split("[EKG] WATCHED:", 1)[1].strip()
                    if variables:
                        for var in variables.split(","):
                            var = var.strip()
                            if var:
                                watched_dependencies.add(var)
                except IndexError as e:
                    print(
                        f"  [!] Warning: Failed to parse EKG watched line: {e}. "
                        f"Line content: {line[:200]}",
                        file=sys.stderr,
                    )

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

    def _update_global_coverage(self, child_coverage: dict) -> None:
        """Commit the coverage from a new, interesting child to the global state."""
        merge_coverage_into_global(self.coverage_manager.state, child_coverage)

    def _calculate_coverage_hash(self, coverage_profile: dict) -> str:
        """Create a deterministic SHA256 hash of a coverage profile's edges."""
        all_edges = []
        # We only hash the edges, as they provide the most significant signal.
        # It's crucial to sort the items to ensure the hash is deterministic.
        for harness_id in sorted(coverage_profile.keys()):
            edges = sorted(coverage_profile[harness_id].get("edges", {}).keys())
            if edges:
                all_edges.append(f"{harness_id}:{','.join(str(edge) for edge in edges)}")

        canonical_string = ";".join(all_edges)
        return hashlib.sha256(canonical_string.encode("utf-8")).hexdigest()

    def _build_lineage_profile(
        self, parent_lineage_profile: dict, child_baseline_profile: dict
    ) -> dict:
        """
        Create a new lineage profile by taking the union of a parent's
        lineage and a child's own baseline coverage.
        """
        # Start with a deep copy of the parent's lineage to avoid side effects.
        lineage = copy.deepcopy(parent_lineage_profile)
        for harness_id, child_data in child_baseline_profile.items():
            # Ensure the harness entry exists in the new lineage profile.
            lineage_harness = lineage.setdefault(
                harness_id,
                {
                    "uops": set(),
                    "edges": set(),
                    "rare_events": set(),
                    "max_trace_length": 0,
                    "max_side_exits": 0,
                },
            )
            lineage_harness["uops"].update(child_data.get("uops", {}).keys())
            lineage_harness["rare_events"].update(child_data.get("rare_events", {}).keys())
            lineage_harness["edges"].update(child_data.get("edges", {}).keys())

            lineage_harness["max_trace_length"] = max(
                lineage_harness.get("max_trace_length", 0), child_data.get("trace_length", 0)
            )
            lineage_harness["max_side_exits"] = max(
                lineage_harness.get("max_side_exits", 0), child_data.get("side_exits", 0)
            )

        return lineage

    def analyze_run(
        self,
        exec_result: ExecutionResult,
        parent_lineage_profile: dict,
        parent_id: str | None,
        mutation_info: dict,
        mutation_seed: int,
        parent_file_size: int,
        parent_lineage_edge_count: int,
    ) -> dict:
        """Orchestrate the analysis of a run and return a dictionary of findings."""
        if self.artifact_manager is None or self.corpus_manager is None:
            raise RuntimeError("ScoringManager requires artifact_manager and corpus_manager")
        if self._get_core_code is None:
            raise RuntimeError("ScoringManager requires get_core_code_func")
        if self.run_stats is None:
            raise RuntimeError("ScoringManager requires run_stats")

        if exec_result.is_divergence:
            self.artifact_manager.save_divergence(
                exec_result.source_path,
                exec_result.jit_output or "",
                exec_result.nojit_output or "",
                exec_result.divergence_reason or "unknown",
            )
            self.run_stats["divergences_found"] = self.run_stats.get("divergences_found", 0) + 1
            return {"status": "DIVERGENCE"}

        log_content = ""
        try:
            log_content = exec_result.log_path.read_text()
        except IOError as e:
            print(f"  [!] Warning: Could not read log file for analysis: {e}", file=sys.stderr)

        if self.artifact_manager.check_for_crash(
            exec_result.returncode,
            log_content,
            exec_result.source_path,
            exec_result.log_path,
            exec_result.parent_path,
            exec_result.session_files,
            parent_id=parent_id,
            mutation_info=mutation_info,
        ):
            return {
                "status": "CRASH",
                "mutation_info": mutation_info or {},
                "parent_id": parent_id,
                "fingerprint": self.artifact_manager.last_crash_fingerprint,
            }

        child_coverage = parse_log_for_edge_coverage(exec_result.log_path, self.coverage_manager)

        coverage_info = self.find_new_coverage(child_coverage, parent_lineage_profile, parent_id)
        jit_stats = self.parse_jit_stats(log_content)

        # Retrieve parent JIT stats from metadata
        parent_jit_stats = {}
        if parent_id:
            parent_metadata = self.coverage_manager.state["per_file_coverage"].get(parent_id, {})
            parent_jit_stats = parent_metadata.get("discovery_mutation", {}).get("jit_stats", {})

        is_interesting = self.score_and_decide_interestingness(
            coverage_info,
            parent_id,
            mutation_info,
            parent_file_size,
            parent_lineage_edge_count,
            exec_result.source_path.stat().st_size,
            exec_result.jit_avg_time_ms,
            exec_result.nojit_avg_time_ms,
            exec_result.nojit_cv,
            jit_stats,
            parent_jit_stats,
        )

        if is_interesting:
            return self._prepare_new_coverage_result(
                exec_result,
                child_coverage,
                jit_stats,
                parent_jit_stats,
                parent_id,
                mutation_info,
                mutation_seed,
            )

        return {"status": "NO_CHANGE"}

    def _prepare_new_coverage_result(
        self,
        exec_result: ExecutionResult,
        child_coverage: dict,
        jit_stats: dict,
        parent_jit_stats: dict,
        parent_id: str | None,
        mutation_info: dict,
        mutation_seed: int,
    ) -> dict:
        """Deduplicate, commit coverage, apply density decay, and build the result dict."""
        assert self.corpus_manager is not None
        assert self._get_core_code is not None

        core_code_to_save = self._get_core_code(exec_result.source_path.read_text())

        # Validate the extracted core code is syntactically valid before saving.
        # _get_core_code() can produce broken output if boilerplate boundaries
        # are unusual, and saving unparseable files poisons the corpus — they
        # are selected repeatedly but can never be mutated.
        try:
            ast.parse(core_code_to_save)
        except SyntaxError as e:
            print(
                f"  [!] Warning: Extracted core code has SyntaxError: {e}. "
                f"Discarding to prevent corpus poisoning.",
                file=sys.stderr,
            )
            if self.health_monitor:
                self.health_monitor.record_core_code_syntax_error(
                    parent_id,
                    str(e),
                    strategy=mutation_info.get("strategy") if mutation_info else None,
                )
            return {"status": "NO_CHANGE"}

        content_hash = hashlib.sha256(core_code_to_save.encode("utf-8")).hexdigest()
        coverage_hash = self._calculate_coverage_hash(child_coverage)

        if (content_hash, coverage_hash) in self.corpus_manager.known_hashes:
            print(
                f"  [~] New coverage found, but this is a known duplicate behavior (ContentHash: {content_hash[:10]}, CoverageHash: {coverage_hash[:10]}). Skipping.",
                file=sys.stderr,
            )
            if self.health_monitor:
                self.health_monitor.record_duplicate_rejected(content_hash, coverage_hash)
            return {"status": "NO_CHANGE"}

        # This is the crucial step: if it's new and not a duplicate, we commit the coverage.
        self._update_global_coverage(child_coverage)

        # --- Dynamic Density Clamping ---
        # Prevent a single massive spike from setting an unreachable bar for the next generation.
        child_density = jit_stats.get("max_exit_density") or 0.0
        parent_density = parent_jit_stats.get("max_exit_density") or 0.0

        if parent_density > 0:
            clamped_density = min(parent_density * MAX_DENSITY_GROWTH_FACTOR, child_density)
        else:
            clamped_density = child_density

        # Also clamp delta density if present
        child_delta_density = jit_stats.get("child_delta_max_exit_density") or 0.0
        parent_delta_density = parent_jit_stats.get("child_delta_max_exit_density") or 0.0

        if parent_delta_density > 0:
            clamped_delta_density = min(
                parent_delta_density * MAX_DENSITY_GROWTH_FACTOR, child_delta_density
            )
        else:
            clamped_delta_density = child_delta_density

        # Also clamp delta exits if present
        child_delta_exits = jit_stats.get("child_delta_total_exits") or 0
        parent_delta_exits = parent_jit_stats.get("child_delta_total_exits") or 0

        if parent_delta_exits > 0:
            clamped_delta_exits = min(
                parent_delta_exits * MAX_DENSITY_GROWTH_FACTOR, child_delta_exits
            )
        else:
            clamped_delta_exits = child_delta_exits

        # --- Tachycardia Decay ---
        saved_density = clamped_density * TACHYCARDIA_DECAY_FACTOR
        saved_delta_density = clamped_delta_density * TACHYCARDIA_DECAY_FACTOR
        saved_delta_exits = clamped_delta_exits * TACHYCARDIA_DECAY_FACTOR

        if clamped_density > 0:
            print(
                f"  [~] Tachycardia decay: {clamped_density:.4f} -> {saved_density:.4f}",
                file=sys.stderr,
            )
        if clamped_delta_density > 0:
            print(
                f"  [~] Tachycardia delta decay: {clamped_delta_density:.4f} -> "
                f"{saved_delta_density:.4f}",
                file=sys.stderr,
            )
        if clamped_delta_exits > 0:
            print(
                f"  [~] Tachycardia delta exits decay: {clamped_delta_exits:.0f} -> "
                f"{saved_delta_exits:.0f}",
                file=sys.stderr,
            )

        jit_stats_for_save = jit_stats.copy()
        jit_stats_for_save["max_exit_density"] = saved_density
        jit_stats_for_save["child_delta_max_exit_density"] = saved_delta_density
        jit_stats_for_save["child_delta_total_exits"] = saved_delta_exits

        saved_mutation_info = {**mutation_info, "jit_stats": jit_stats_for_save}

        return {
            "status": "NEW_COVERAGE",
            "core_code": core_code_to_save,
            "baseline_coverage": child_coverage,
            "content_hash": content_hash,
            "coverage_hash": coverage_hash,
            "execution_time_ms": exec_result.execution_time_ms,
            "parent_id": parent_id,
            "mutation_info": saved_mutation_info,
            "mutation_seed": mutation_seed,
            "jit_avg_time_ms": exec_result.jit_avg_time_ms,
            "nojit_avg_time_ms": exec_result.nojit_avg_time_ms,
        }
