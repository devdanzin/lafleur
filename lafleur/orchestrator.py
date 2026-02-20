"""
This module contains the main LafleurOrchestrator class.

The orchestrator is the "brain" of the fuzzer, responsible for managing the
entire evolutionary feedback loop, including selecting parents from the corpus,
applying mutation strategies, executing child processes, and analyzing the
results for new and interesting JIT behavior.
"""

import argparse
import ast
import copy
import json
import math
import os
import platform
import random
import shutil
import socket
import sys
import time

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from textwrap import dedent

from lafleur.corpus_manager import CORPUS_DIR, CorpusManager
from lafleur.health import HealthMonitor
from lafleur.coverage import CoverageManager, load_coverage_state
from lafleur.analysis import CrashFingerprinter
from lafleur.artifacts import ArtifactManager, TelemetryManager
from lafleur.execution import ExecutionManager
from lafleur.scoring import ScoringManager
from lafleur.types import (
    AnalysisResult,
    CrashResult,
    DivergenceResult,
    NewCoverageResult,
)
from lafleur.learning import MutatorScoreTracker
from lafleur.mutation_controller import MutationController
from lafleur.mutators import ASTMutator
from lafleur.metadata import generate_run_metadata
from lafleur.utils import TeeLogger, load_run_stats


class FlowControl(Enum):
    """Signals returned by _handle_analysis_data to control the mutation loop."""

    NONE = auto()  # No interesting result; continue to next run
    BREAK = auto()  # Major find (new coverage or divergence); stop runs for this mutation
    CONTINUE = auto()  # Crash found; stop runs but continue mutations


# --- Paths for Fuzzer Outputs (relative to current working directory) ---
# This allows running multiple fuzzer instances from different directories.
TMP_DIR = Path("tmp_fuzz_run")
CRASHES_DIR = Path("crashes")
REGRESSIONS_DIR = Path("regressions")
TIMEOUTS_DIR = Path("timeouts")
DIVERGENCES_DIR = Path("divergences")
LOGS_DIR = Path("logs")
RUN_LOGS_DIR = LOGS_DIR / "run_logs"
HEARTBEAT_FILE = LOGS_DIR / "heartbeat"
HEARTBEAT_INTERVAL_SECONDS = 60  # Write heartbeat at most once per minute

# --- Sterility Thresholds ---
# Maximum sterile mutations in a deepening session before abandoning the lineage.
DEEPENING_STERILITY_LIMIT = 30
# Maximum sterile mutations for a corpus file before marking it permanently sterile.
CORPUS_STERILITY_LIMIT = 599


@dataclass
class ParentContext:
    """All data needed to run mutations against a parent test case."""

    parent_path: Path
    parent_id: str
    parent_score: float
    parent_metadata: dict
    parent_lineage_profile: dict
    parent_file_size: int
    parent_lineage_edge_count: int
    base_harness_node: ast.FunctionDef
    parent_core_tree: ast.Module
    setup_nodes: list[ast.stmt]
    watched_keys: list[str] | None
    num_runs: int
    max_mutations: int


@dataclass
class MutationOutcome:
    """Result of running a single mutation through all its runs."""

    flow_control: FlowControl
    found_new_coverage: bool
    new_child_filename: str | None


class LafleurOrchestrator:
    """
    Manage the main evolutionary fuzzing loop.

    Select interesting test cases from the corpus, apply mutation
    strategies, execute the mutated children, and analyze the results
    for new coverage.
    """

    MAX_LINEAGE_DEPTH = 20  # Safety bound for lineage walking

    def __init__(
        self,
        fusil_path: str,
        min_corpus_files: int = 1,
        differential_testing: bool = False,
        timeout: int = 10,
        num_runs: int = 1,
        use_dynamic_runs: bool = False,
        keep_tmp_logs: bool = False,
        timing_fuzz: bool = False,
        session_fuzz: bool = False,
        max_timeout_log_size: int = 400,
        max_crash_log_size: int = 400,
        target_python: str = sys.executable,
        deepening_probability: float = 0.2,
        run_stats: dict | None = None,
        no_ekg: bool = False,
        max_sessions: int | None = None,
        max_mutations_per_session: int | None = None,
        keep_children: bool = False,
        dry_run: bool = False,
        mutator_filter: list[str] | None = None,
        forced_strategy: str | None = None,
    ):
        """Initialize the orchestrator and the corpus manager."""
        self.differential_testing = differential_testing
        self.fusil_path = fusil_path
        self.base_runs = num_runs
        self.use_dynamic_runs = use_dynamic_runs
        self.keep_tmp_logs = keep_tmp_logs
        if not 0.0 <= deepening_probability <= 1.0:
            raise ValueError(
                f"deepening_probability must be between 0.0 and 1.0, got {deepening_probability}"
            )
        self.deepening_probability = deepening_probability
        self.max_sessions = max_sessions
        self.max_mutations_per_session = max_mutations_per_session
        self.keep_children = keep_children
        self.dry_run = dry_run
        self.forced_strategy = forced_strategy
        ast_mutator = ASTMutator()

        # --- Apply mutator pool filter (diagnostic mode) ---
        if mutator_filter is not None:
            pool_names = {t.__name__ for t in ast_mutator.transformers}
            unknown = set(mutator_filter) - pool_names
            if unknown:
                raise ValueError(
                    f"Unknown mutator(s): {', '.join(sorted(unknown))}. "
                    f"Use --list-mutators to see valid names."
                )
            ast_mutator.transformers = [
                t for t in ast_mutator.transformers if t.__name__ in mutator_filter
            ]
            print(
                f"[+] Mutator pool filtered to {len(ast_mutator.transformers)} transformer(s): "
                f"{', '.join(t.__name__ for t in ast_mutator.transformers)}"
            )

        max_timeout_log_bytes = max_timeout_log_size * 1024 * 1024
        max_crash_log_bytes = max_crash_log_size * 1024 * 1024

        coverage_state = load_coverage_state()
        self.coverage_manager = CoverageManager(coverage_state)

        self.run_stats = run_stats if run_stats is not None else load_run_stats()

        self.timing_fuzz = timing_fuzz
        self.score_tracker = MutatorScoreTracker(
            ast_mutator.transformers,
            strategies=["deterministic", "havoc", "spam", "helper_sniper", "sniper"],
        )

        self.mutation_controller = MutationController(
            ast_mutator=ast_mutator,
            score_tracker=self.score_tracker,
            differential_testing=differential_testing,
            forced_strategy=forced_strategy,
        )

        self.min_corpus_files = min_corpus_files
        self.corpus_manager = CorpusManager(
            self.coverage_manager,
            self.run_stats,
            fusil_path,
            self.mutation_controller.get_boilerplate,
            timeout,
            target_python=target_python,
        )

        # Break circular dependency: MutationController needs the corpus for splicing
        self.mutation_controller.corpus_manager = self.corpus_manager

        fingerprinter = CrashFingerprinter()

        TMP_DIR.mkdir(exist_ok=True)
        LOGS_DIR.mkdir(exist_ok=True)
        if self.keep_tmp_logs:
            RUN_LOGS_DIR.mkdir(exist_ok=True)
            print(f"[+] Retaining temporary run logs in: {RUN_LOGS_DIR}")

        self.health_monitor = HealthMonitor(log_path=LOGS_DIR / "health_events.jsonl")
        self.mutation_controller.health_monitor = self.health_monitor
        self.corpus_manager.health_monitor = self.health_monitor

        run_timestamp = self.run_stats.get("start_time", datetime.now(timezone.utc).isoformat())
        safe_timestamp = run_timestamp.replace(":", "-").replace("+", "Z")
        self.timeseries_log_path = LOGS_DIR / f"timeseries_{safe_timestamp}.jsonl"
        print(
            f"[+] Time-series analytics for this run will be saved to: {self.timeseries_log_path}"
        )

        self.artifact_manager = ArtifactManager(
            crashes_dir=CRASHES_DIR,
            timeouts_dir=TIMEOUTS_DIR,
            divergences_dir=DIVERGENCES_DIR,
            regressions_dir=REGRESSIONS_DIR,
            fingerprinter=fingerprinter,
            max_timeout_log_bytes=max_timeout_log_bytes,
            max_crash_log_bytes=max_crash_log_bytes,
            session_fuzz=session_fuzz,
            health_monitor=self.health_monitor,
        )

        self.telemetry_manager = TelemetryManager(
            run_stats=self.run_stats,
            coverage_manager=self.coverage_manager,
            corpus_manager=self.corpus_manager,
            score_tracker=self.score_tracker,
            timeseries_log_path=self.timeseries_log_path,
        )

        self.scoring_manager = ScoringManager(
            coverage_manager=self.coverage_manager,
            timing_fuzz=self.timing_fuzz,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            get_core_code_func=self.mutation_controller._get_core_code,
            run_stats=self.run_stats,
            health_monitor=self.health_monitor,
        )

        self.execution_manager = ExecutionManager(
            target_python=target_python,
            timeout=timeout,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            differential_testing=differential_testing,
            timing_fuzz=timing_fuzz,
            session_fuzz=session_fuzz,
            no_ekg=no_ekg,
        )

        if no_ekg:
            print(
                "[!] WARNING: EKG introspection disabled (--no-ekg). "
                "JIT executor metrics will not be collected.",
                file=sys.stderr,
            )

        # Verify that the target python is suitable for fuzzing before doing anything else
        self.execution_manager.verify_target_capabilities()

        # Synchronize the corpus and state at startup.
        self.corpus_manager.synchronize(
            self.scoring_manager.analyze_run, self.scoring_manager._build_lineage_profile
        )

        self.mutations_since_last_find = 0
        self.global_seed_counter = self.run_stats.get("global_seed_counter", 0)
        self._last_heartbeat_time: float = 0.0  # monotonic time of last heartbeat write

    def _write_heartbeat(self) -> None:
        """Write a lightweight heartbeat timestamp to signal the instance is alive.

        Called frequently from the mutation loop. Rate-limited to avoid
        excessive I/O — writes at most once per HEARTBEAT_INTERVAL_SECONDS.
        """
        now = time.monotonic()
        if now - self._last_heartbeat_time < HEARTBEAT_INTERVAL_SECONDS:
            return
        self._last_heartbeat_time = now
        try:
            HEARTBEAT_FILE.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
        except OSError:
            pass  # Non-critical — never crash the fuzzer for a heartbeat

    def run_evolutionary_loop(self) -> None:
        """
        Run the main evolutionary fuzzing loop.

        This method first ensures the corpus has the minimum number of files,
        then enters the infinite loop that drives the fuzzer's core logic of
        selection, mutation, execution, and analysis.
        """
        # Write initial heartbeat so a fresh instance shows "Running" immediately
        self._last_heartbeat_time = 0.0  # Force immediate write
        self._write_heartbeat()

        # --- Bootstrap the corpus if it's smaller than the minimum required size ---
        current_corpus_size = len(self.coverage_manager.state.get("per_file_coverage", {}))
        needed = self.min_corpus_files - current_corpus_size

        if needed > 0:
            print(
                f"[*] Corpus size ({current_corpus_size}) is less than minimum ({self.min_corpus_files}). Need to generate {needed} more file(s)."
            )

            if not self.corpus_manager.fusil_path_is_valid:
                print("[!] WARNING: Cannot generate new seed files.", file=sys.stderr)
                if self.fusil_path:
                    print(
                        f"    Reason: Provided --fusil-path '{self.fusil_path}' is not a valid executable file.",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "    Reason: The --fusil-path argument was not provided.", file=sys.stderr
                    )

                if current_corpus_size > 0:
                    print(
                        f"[*] Proceeding with the {current_corpus_size} existing file(s). To enforce the minimum, please provide a valid path.",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "[!!!] CRITICAL: The corpus is empty and no valid seeder is available. Halting.",
                        file=sys.stderr,
                    )
                    sys.exit(1)  # Unrecoverable state
            else:
                # Seeder is available, generate the needed files
                print("[*] Starting corpus generation phase...")
                for _ in range(needed):
                    self.corpus_manager.generate_new_seed(
                        self.scoring_manager.analyze_run,
                        self.scoring_manager._build_lineage_profile,
                    )
                print(
                    f"[+] Corpus generation complete. New size: {len(self.coverage_manager.state['per_file_coverage'])}."
                )

        print("[+] Starting Deep Fuzzer Evolutionary Loop. Press Ctrl+C to stop.")
        try:
            while True:
                if (
                    self.max_sessions is not None
                    and self.run_stats.get("total_sessions", 0) >= self.max_sessions
                ):
                    print(f"[+] Reached --max-sessions limit ({self.max_sessions}). Stopping.")
                    break

                self.run_stats["total_sessions"] = self.run_stats.get("total_sessions", 0) + 1
                session_num = self.run_stats["total_sessions"]
                print(f"\n--- Fuzzing Session #{self.run_stats['total_sessions']} ---")

                is_deepening_session = random.random() < self.deepening_probability

                # 1. Selection
                selection = self.corpus_manager.select_parent()

                # This should now only happen if min_corpus_files is 0 and corpus is empty.
                if selection is None:
                    print("[!] Corpus is empty and no minimum size was set. Halting.")
                    return
                else:
                    parent_path, parent_score = selection
                    if is_deepening_session:
                        print(
                            f"[+] Selected parent for DEEPENING session: {parent_path.name} (Score: {parent_score:.2f})"
                        )
                    else:
                        print(
                            f"[+] Selected parent for BREADTH session: {parent_path.name} (Score: {parent_score:.2f})"
                        )

                    self.execute_mutation_and_analysis_cycle(
                        parent_path, parent_score, session_num, is_deepening_session
                    )

                # Update dynamic stats after each session
                self.telemetry_manager.update_and_save_run_stats(self.global_seed_counter)
                if session_num % 10 == 0:
                    print(f"[*] Logging time-series data point at session {session_num}...")
                    self.telemetry_manager.log_timeseries_datapoint()
        finally:
            # Crash-safety: save stats even if interrupted mid-session.
            # The per-session save above handles the normal case.
            print("\n[+] Fuzzing loop terminating. Saving final stats...")
            self.telemetry_manager.update_and_save_run_stats(self.global_seed_counter)
            self.telemetry_manager.log_timeseries_datapoint()

            self.score_tracker.save_state()

    def _handle_analysis_data(
        self,
        analysis_data: AnalysisResult,
        i: int,
        parent_metadata: dict,
        nojit_cv: float | None,
        parent_id: str = "unknown",
    ) -> tuple[FlowControl, str | None]:
        """Process the result from analyze_run and update fuzzer state.

        Returns:
            A tuple of (flow_control, new_filename). new_filename is set for
            NEW_COVERAGE and DIVERGENCE statuses, None otherwise.
        """
        if isinstance(analysis_data, (DivergenceResult, NewCoverageResult)):
            mutation_info = analysis_data.mutation_info
            strategy = mutation_info.get("strategy")
            transformers = mutation_info.get("transformers", [])
            if strategy and transformers:
                hygiene_names = {cls.__name__ for cls, _ in MutationController.HYGIENE_MUTATORS}
                filtered = [t for t in transformers if t not in hygiene_names]
                if filtered:
                    self.score_tracker.record_success(strategy, filtered)

        if isinstance(analysis_data, DivergenceResult):
            self.run_stats["divergences_found"] = self.run_stats.get("divergences_found", 0) + 1
            self.mutations_since_last_find = 0
            print(
                f"  [***] SUCCESS! Mutation #{i + 1} found a correctness divergence. Moving to next parent."
            )
            return FlowControl.BREAK, "divergence"
        elif isinstance(analysis_data, CrashResult):
            self.run_stats["crashes_found"] = self.run_stats.get("crashes_found", 0) + 1

            # --- Crash attribution ---
            crash_mutation_info = analysis_data.mutation_info
            crash_strategy = crash_mutation_info.get("strategy", "")
            crash_transformers = crash_mutation_info.get("transformers", [])

            if crash_strategy or crash_transformers:
                hygiene_names = {cls.__name__ for cls, _ in MutationController.HYGIENE_MUTATORS}
                filtered_transformers = [t for t in crash_transformers if t not in hygiene_names]

                # Walk lineage from the parent
                crash_parent_id = analysis_data.parent_id
                lineage_mutations = self._walk_crash_lineage(crash_parent_id)

                # Filter hygiene from lineage too
                filtered_lineage = []
                for ancestor in lineage_mutations:
                    filtered_lineage.append(
                        {
                            "strategy": ancestor.get("strategy", ""),
                            "transformers": [
                                t
                                for t in ancestor.get("transformers", [])
                                if t not in hygiene_names
                            ],
                        }
                    )

                fingerprint = analysis_data.fingerprint or ""
                self.score_tracker.record_crash_attribution(
                    direct_strategy=crash_strategy,
                    direct_transformers=filtered_transformers,
                    lineage_mutations=filtered_lineage,
                    fingerprint=fingerprint,
                    parent_id=crash_parent_id or "",
                )

            return FlowControl.CONTINUE, None
        elif isinstance(analysis_data, NewCoverageResult):
            print(f"  [***] SUCCESS! Mutation #{i + 1} found new coverage. Moving to next parent.")
            new_filename = self.corpus_manager.add_new_file(
                core_code=analysis_data.core_code,
                baseline_coverage=analysis_data.baseline_coverage,
                content_hash=analysis_data.content_hash,
                coverage_hash=analysis_data.coverage_hash,
                execution_time_ms=analysis_data.execution_time_ms,
                parent_id=analysis_data.parent_id,
                mutation_info=analysis_data.mutation_info,
                mutation_seed=analysis_data.mutation_seed,
                build_lineage_func=self.scoring_manager._build_lineage_profile,
            )

            self._check_timing_regression(analysis_data, new_filename, nojit_cv)

            return FlowControl.BREAK, new_filename
        else:  # NoChangeResult
            parent_metadata["mutations_since_last_find"] = (
                parent_metadata.get("mutations_since_last_find", 0) + 1
            )
            if parent_metadata["mutations_since_last_find"] > CORPUS_STERILITY_LIMIT:
                if not parent_metadata.get("is_sterile", False):
                    # Fire the health event only on the False→True transition
                    parent_metadata["is_sterile"] = True
                    self.health_monitor.record_corpus_sterility(
                        parent_id=parent_id,
                        mutations_since_last_find=parent_metadata["mutations_since_last_find"],
                    )
            return FlowControl.NONE, None

    def _walk_crash_lineage(self, parent_id: str | None) -> list[dict]:
        """Walk the ancestry of a corpus file, collecting mutation info.

        Follows the parent_id chain in per_file_coverage, collecting each
        ancestor's discovery_mutation until reaching a seed file (parent_id
        is None) or the depth limit.

        Args:
            parent_id: Starting corpus filename to trace back from.

        Returns:
            List of MutationInfo dicts, ordered parent -> grandparent -> ...
        """
        per_file = self.coverage_manager.state.get("per_file_coverage", {})
        lineage: list[dict] = []
        current_id = parent_id

        for _ in range(self.MAX_LINEAGE_DEPTH):
            if current_id is None:
                break
            metadata = per_file.get(current_id)
            if metadata is None:
                break

            discovery_mutation = metadata.get("discovery_mutation")
            if discovery_mutation and isinstance(discovery_mutation, dict):
                lineage.append(discovery_mutation)

            current_id = metadata.get("parent_id")

        return lineage

    def _check_timing_regression(
        self,
        analysis_data: NewCoverageResult,
        new_filename: str,
        nojit_cv: float | None,
    ) -> None:
        """Check for JIT performance regressions and save artifacts if found."""
        if not self.timing_fuzz:
            return

        jit_time = analysis_data.jit_avg_time_ms
        nojit_time = analysis_data.nojit_avg_time_ms
        if jit_time is None or nojit_time is None or nojit_time <= 0:
            return

        slowdown_ratio = jit_time / nojit_time

        if nojit_cv is not None:
            dynamic_threshold = 1.0 + (3 * nojit_cv)
        else:
            dynamic_threshold = 1.2

        if slowdown_ratio > dynamic_threshold:
            self.artifact_manager.save_regression(CORPUS_DIR / new_filename, jit_time, nojit_time)
            self.run_stats["regressions_found"] = self.run_stats.get("regressions_found", 0) + 1

    def _cleanup_log_file(
        self, child_log_path: Path, parent_id: str, mutation_seed: int, run_num: int
    ) -> None:
        """Move or delete a temporary log file after a child run.

        Checks for plain `.log`, compressed `.log.zst`, and truncated `_truncated.log`
        variants in order. For the first one found, either moves it to `RUN_LOGS_DIR`
        (when ``keep_tmp_logs`` is set) or deletes it. If none exist the file was already
        handled by crash/timeout processing.
        """
        candidates = [
            (child_log_path, f"log_{parent_id}_seed_{mutation_seed}_run_{run_num + 1}.log"),
            (
                child_log_path.with_suffix(".log.zst"),
                f"log_{parent_id}_seed_{mutation_seed}_run_{run_num + 1}.log.zst",
            ),
            (
                child_log_path.with_name(f"{child_log_path.stem}_truncated{child_log_path.suffix}"),
                f"log_{parent_id}_seed_{mutation_seed}_run_{run_num + 1}_truncated.log",
            ),
        ]
        try:
            for candidate_path, dest_name in candidates:
                if candidate_path.exists():
                    if self.keep_tmp_logs:
                        shutil.move(candidate_path, RUN_LOGS_DIR / dest_name)
                    else:
                        candidate_path.unlink()
                    return
        except OSError as e:
            print(f"  [!] Warning: Could not process temp file: {e}", file=sys.stderr)

    def _prepare_parent_context(
        self,
        parent_path: Path,
        parent_score: float,
        is_deepening_session: bool,
    ) -> ParentContext | None:
        """Build the context needed to run mutations against a parent.

        Returns ``None`` when the parent file cannot be parsed into valid
        AST nodes (the caller should abort the current cycle).
        """
        max_mutations = self.mutation_controller._calculate_mutations(parent_score)
        if self.max_mutations_per_session is not None:
            max_mutations = self.max_mutations_per_session
        parent_id = parent_path.name
        parent_metadata = self.coverage_manager.state["per_file_coverage"].get(parent_id, {})
        parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})

        parent_file_size = parent_metadata.get("file_size_bytes", 0)

        # Calculate the total number of unique edges in the parent's lineage
        parent_lineage_edge_count = 0
        for harness_data in parent_lineage_profile.values():
            parent_lineage_edge_count += len(harness_data.get("edges", set()))

        base_harness_node, parent_core_tree, setup_nodes = (
            self.mutation_controller._get_nodes_from_parent(parent_path)
        )
        if base_harness_node is None or parent_core_tree is None:
            # Mark the parent as sterile so it's deprioritized by the scheduler.
            # Without this, unparseable files retain their score and get selected
            # repeatedly, burning cycles on parents that can never produce children.
            if parent_metadata is not None:
                parent_metadata["is_sterile"] = True
                print(
                    f"  [!] Marking {parent_id} as sterile (unparseable or missing harness).",
                    file=sys.stderr,
                )
            self.health_monitor.record_parent_parse_failure(
                parent_id, "unparseable or missing harness"
            )
            return None

        # Retrieve watched dependencies from parent metadata
        watched_keys = (
            parent_metadata.get("discovery_mutation", {})
            .get("jit_stats", {})
            .get("watched_dependencies")
        )

        # Filter out the harness itself, as we can't snipe it
        if watched_keys:
            current_harness_name = base_harness_node.name
            watched_keys = [k for k in watched_keys if k != current_harness_name]

        if self.use_dynamic_runs:
            num_runs = 2 + int(math.floor(math.log(max(1.0, parent_score / 15))))
            num_runs = min(num_runs, 10)
            session_type = "deepening" if is_deepening_session else "breadth"
            print(f"    -> Dynamic run count: {num_runs} for {parent_id} ({session_type})")
        else:
            num_runs = self.base_runs

        return ParentContext(
            parent_path=parent_path,
            parent_id=parent_id,
            parent_score=parent_score,
            parent_metadata=parent_metadata,
            parent_lineage_profile=parent_lineage_profile,
            parent_file_size=parent_file_size,
            parent_lineage_edge_count=parent_lineage_edge_count,
            base_harness_node=base_harness_node,
            parent_core_tree=parent_core_tree,
            setup_nodes=setup_nodes or [],
            watched_keys=watched_keys,
            num_runs=num_runs,
            max_mutations=max_mutations,
        )

    def _execute_single_mutation(
        self,
        ctx: ParentContext,
        mutation_seed: int,
        mutation_index: int,
        session_id: int,
        mutation_id: int,
    ) -> MutationOutcome:
        """Run a single mutation through all its repetitions and return the outcome."""
        mutated_harness_node, mutation_info = self.mutation_controller.get_mutated_harness(
            ctx.base_harness_node, mutation_seed, watched_keys=ctx.watched_keys
        )
        if not mutated_harness_node or mutation_info is None:
            return MutationOutcome(
                flow_control=FlowControl.NONE,
                found_new_coverage=False,
                new_child_filename=None,
            )

        # --- DRY RUN: generate child script but skip execution ---
        if self.dry_run:
            runtime_seed = mutation_seed + 1
            child_source = self.mutation_controller.prepare_child_script(
                ctx.parent_core_tree,
                mutated_harness_node,
                runtime_seed,
            )
            if child_source:
                child_path = TMP_DIR / f"child_{session_id}_{mutation_id}_dryrun.py"
                child_path.write_text(child_source)
                print(
                    f"    [DRY-RUN] Wrote {child_path.name} "
                    f"(strategy: {mutation_info.get('strategy', '?')})"
                )
            return MutationOutcome(
                flow_control=FlowControl.NONE,
                found_new_coverage=False,
                new_child_filename=None,
            )

        flow_control = FlowControl.NONE
        found_new_coverage = False
        new_child_filename: str | None = None

        for run_num in range(ctx.num_runs):
            child_source_path = TMP_DIR / f"child_{session_id}_{mutation_id}_{run_num + 1}.py"
            child_log_path = TMP_DIR / f"child_{session_id}_{mutation_id}_{run_num + 1}.log"

            try:
                runtime_seed = (mutation_seed + 1) * (run_num + 1)
                mutation_info["runtime_seed"] = runtime_seed

                if ctx.num_runs > 1:
                    print(f"    -> Run #{run_num + 1}/{ctx.num_runs} (RuntimeSeed: {runtime_seed})")

                child_source = self.mutation_controller.prepare_child_script(
                    ctx.parent_core_tree,
                    mutated_harness_node,
                    runtime_seed,
                )
                if not child_source:
                    self.health_monitor.record_child_script_none(
                        ctx.parent_id,
                        mutation_seed,
                        strategy=mutation_info.get("strategy") if mutation_info else None,
                    )
                    continue

                exec_result, stat_key = self.execution_manager.execute_child(
                    child_source, child_source_path, child_log_path, ctx.parent_path
                )
                if stat_key:
                    self.run_stats[stat_key] = self.run_stats.get(stat_key, 0) + 1
                if stat_key == "timeout_count":
                    self.health_monitor.record_timeout(ctx.parent_id)
                else:
                    self.health_monitor.reset_timeout_streak()
                if not exec_result:
                    continue

                analysis_data = self.scoring_manager.analyze_run(
                    exec_result,
                    ctx.parent_lineage_profile,
                    ctx.parent_id,
                    mutation_info,
                    mutation_seed,
                    ctx.parent_file_size,
                    ctx.parent_lineage_edge_count,
                )

                nojit_cv = exec_result.nojit_cv
                flow_control, returned_filename = self._handle_analysis_data(
                    analysis_data,
                    mutation_index,
                    ctx.parent_metadata,
                    nojit_cv,
                    ctx.parent_id,
                )

                if flow_control in (FlowControl.BREAK, FlowControl.CONTINUE):
                    if isinstance(analysis_data, NewCoverageResult):
                        found_new_coverage = True

                        # --- Update stats on every find ---
                        self.run_stats["new_coverage_finds"] = (
                            self.run_stats.get("new_coverage_finds", 0) + 1
                        )
                        self.run_stats["sum_of_mutations_per_find"] = (
                            self.run_stats.get("sum_of_mutations_per_find", 0)
                            + self.mutations_since_last_find
                        )
                        self.mutations_since_last_find = 0
                        ctx.parent_metadata["total_finds"] = (
                            ctx.parent_metadata.get("total_finds", 0) + 1
                        )
                        ctx.parent_metadata["mutations_since_last_find"] = 0

                        new_child_filename = returned_filename
                    break  # Break inner multi-run loop
            finally:
                if child_source_path.exists() and not self.keep_children:
                    child_source_path.unlink()
                self._cleanup_log_file(child_log_path, ctx.parent_id, mutation_seed, run_num)

        return MutationOutcome(
            flow_control=flow_control,
            found_new_coverage=found_new_coverage,
            new_child_filename=new_child_filename,
        )

    def execute_mutation_and_analysis_cycle(
        self,
        initial_parent_path: Path,
        initial_parent_score: float,
        session_id: int,
        is_deepening_session: bool,
    ) -> None:
        """Take a parent test case and run a full cycle of mutation and analysis.

        If in a deepening session, will continue to mutate successful children.
        """
        # --- Session-level state for deepening ---
        current_parent_path = initial_parent_path
        current_parent_score = initial_parent_score
        mutations_since_last_find_in_session = 0
        mutation_id = 0

        # --- This loop controls the deepening process ---
        while True:
            ctx = self._prepare_parent_context(
                current_parent_path, current_parent_score, is_deepening_session
            )
            if ctx is None:
                return  # Abort if parent is invalid

            # --- Main Mutation Loop ---
            found_new_coverage_in_cycle = False
            mutation_index = 0
            while mutation_index < ctx.max_mutations:
                mutation_index += 1
                mutation_id += 1
                self.run_stats["total_mutations"] = self.run_stats.get("total_mutations", 0) + 1
                self._write_heartbeat()
                self.mutations_since_last_find += 1
                mutations_since_last_find_in_session += 1

                if (
                    is_deepening_session
                    and mutations_since_last_find_in_session > DEEPENING_STERILITY_LIMIT
                ):
                    print(
                        "  [~] Deepening session became sterile. Returning to breadth-first search."
                    )
                    self.health_monitor.record_deepening_sterility(
                        parent_id=ctx.parent_id,
                        depth=ctx.parent_metadata.get("lineage_depth", 0),
                        mutations_attempted=mutations_since_last_find_in_session,
                    )
                    return

                self.global_seed_counter += 1
                mutation_seed = self.global_seed_counter
                print(
                    f"  \\-> Running mutation #{mutation_index} (Seed: {mutation_seed}) for {ctx.parent_id}..."
                )

                outcome = self._execute_single_mutation(
                    ctx, mutation_seed, mutation_index, session_id, mutation_id
                )

                if outcome.found_new_coverage:
                    found_new_coverage_in_cycle = True
                    mutations_since_last_find_in_session = 0

                    if is_deepening_session and outcome.new_child_filename:
                        print(
                            f"  [>>>] DEEPENING: New child {outcome.new_child_filename} becomes the new parent.",
                            file=sys.stderr,
                        )
                        current_parent_path = CORPUS_DIR / outcome.new_child_filename
                        # During deepening, inherit parent's score with a bonus
                        # rather than re-scoring the entire corpus.
                        current_parent_score = current_parent_score * 1.1

                if found_new_coverage_in_cycle and is_deepening_session:
                    break
                elif outcome.flow_control == FlowControl.BREAK:
                    return  # For breadth mode, a single find ends the entire session

            # Exit condition for the while True loop
            if not is_deepening_session or not found_new_coverage_in_cycle:
                break


def _format_run_header(
    instance_name: str,
    run_id: str,
    orchestrator_log_path: Path,
    timestamp_iso: str,
    timeout: int,
    start_stats: dict,
) -> str:
    """Format the informative header printed at the start of a fuzzing run."""
    return dedent(f"""
================================================================================
LAFLEUR FUZZER RUN
================================================================================
- Instance Name:     {instance_name}
- Run ID:            {run_id}
- Hostname:          {socket.gethostname()}
- Platform:          {platform.platform()}
- Process ID:        {os.getpid()}
- Python Version:    {sys.version.replace(chr(10), " ")}
- Working Dir:       {Path.cwd()}
- Log File:          {orchestrator_log_path}
- Start Time:        {timestamp_iso}
- Command:           {" ".join(sys.argv)}
- Script Timeout:    {timeout} seconds
--------------------------------------------------------------------------------
Initial Stats:
{json.dumps(start_stats, indent=4)}
================================================================================

""")


def _format_run_summary(
    termination_reason: str,
    run_start_time: datetime,
    start_stats: dict,
) -> str:
    """Format the summary footer printed at the end of a fuzzing run."""
    end_time = datetime.now(timezone.utc)
    duration = end_time - run_start_time
    end_stats = load_run_stats()

    mutations_this_run = end_stats.get("total_mutations", 0) - start_stats.get("total_mutations", 0)
    finds_this_run = end_stats.get("new_coverage_finds", 0) - start_stats.get(
        "new_coverage_finds", 0
    )
    crashes_this_run = end_stats.get("crashes_found", 0) - start_stats.get("crashes_found", 0)
    duration_secs = duration.total_seconds()
    exec_per_sec = mutations_this_run / duration_secs if duration_secs > 0 else 0

    header = "\n" + "=" * 80 + "\nFUZZING RUN SUMMARY\n" + "=" * 80
    body = dedent(f"""
- Termination:       {termination_reason}
- End Time:          {end_time.isoformat()}
- Total Duration:    {str(duration)}

--- Discoveries This Run ---
- New Coverage:      {finds_this_run}
- New Crashes:       {crashes_this_run}

--- Performance This Run ---
- Total Executions: {mutations_this_run}
- Execs per Second: {exec_per_sec:.2f}

--- Final Campaign Stats ---
{json.dumps(end_stats, indent=4)}
================================================================================
""")
    return header + body


def main():
    """Parse command-line arguments and run the Lafleur Fuzzer Orchestrator."""
    parser = argparse.ArgumentParser(
        description="lafleur: A feedback-driven JIT fuzzer for CPython."
    )
    parser.add_argument(
        "--fusil-path",
        type=str,
        default=None,
        help="The absolute path to the classic fusil executable (fusil-python-threaded).",
    )
    parser.add_argument(
        "--min-corpus-files",
        type=int,
        default=1,
        help="Ensure the corpus has at least N files before starting the main fuzzing loop.",
    )
    parser.add_argument(
        "--differential-testing",
        action="store_true",
        help="Enable differential testing mode to find correctness bugs.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,  # Default timeout of 10 seconds
        help="Timeout in seconds for script execution.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Run each mutated test case N times. (Default: 1)",
    )
    parser.add_argument(
        "--dynamic-runs",
        action="store_true",
        help="Dynamically vary the number of runs based on parent score, overriding --runs.",
    )
    parser.add_argument(
        "--keep-tmp-logs",
        action="store_true",
        help="Retain temporary log files for all runs in the logs/run_logs/ directory for offline analysis.",
    )
    parser.add_argument(
        "--prune-corpus",
        action="store_true",
        help="Run the corpus pruning tool to find and report redundant test cases, then exit.",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Used with --prune-corpus to actually delete the files. (Default: dry run)",
    )
    parser.add_argument(
        "--timing-fuzz",
        action="store_true",
        help="Enable JIT performance regression fuzzing mode.",
    )
    parser.add_argument(
        "--session-fuzz",
        action="store_true",
        help="Enable session fuzzing mode. Scripts run in a persistent process to preserve JIT state.",
    )
    parser.add_argument(
        "--deepening-probability",
        type=float,
        default=0.2,
        help="Probability of choosing a depth-first deepening session vs. breadth-first. (Default: 0.2)",
    )
    parser.add_argument(
        "--max-timeout-log-size",
        type=int,
        default=400,
        help="Maximum timeout log size in MB before truncation. (Default: 400)",
    )
    parser.add_argument(
        "--max-crash-log-size",
        type=int,
        default=400,
        help="Maximum crash log size in MB before truncation. (Default: 400)",
    )
    parser.add_argument(
        "--target-python",
        type=str,
        default=sys.executable,
        help="Path to the target Python executable to fuzz. Defaults to the current interpreter.",
    )
    parser.add_argument(
        "--instance-name",
        type=str,
        default=None,
        help="A human-readable name for this fuzzing instance (e.g., 'stoic-darwin'). "
        "Auto-generated if not provided.",
    )
    parser.add_argument(
        "--no-ekg",
        action="store_true",
        help="Disable ctypes-based JIT introspection in the driver. "
        "Use this for CPython builds older than 3.15 where the executor struct layout differs.",
    )
    # --- Diagnostic / bounded-run options ---
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=None,
        help="Stop after N fuzzing sessions (default: unlimited). "
        "Useful for smoke tests and diagnostics.",
    )
    parser.add_argument(
        "--max-mutations-per-session",
        type=int,
        default=None,
        help="Override dynamic mutation count: each session performs exactly N mutations "
        "(default: score-based dynamic calculation).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Global random seed for reproducible runs. Seeds the RNG before corpus selection "
        "and strategy choice. Per-mutation seeds remain deterministic relative to this.",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="Working directory for all fuzzer outputs (corpus, crashes, logs, etc.). "
        "Created if it doesn't exist. Defaults to current working directory.",
    )
    parser.add_argument(
        "--keep-children",
        action="store_true",
        help="Retain all generated child scripts in tmp_fuzz_run/, not just interesting ones. "
        "Useful for inspecting mutation output.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate mutated children but skip subprocess execution and analysis. "
        "Implies --keep-children. Children are written to tmp_fuzz_run/ for inspection.",
    )
    parser.add_argument(
        "--list-mutators",
        action="store_true",
        help="Print all available mutators with descriptions and exit.",
    )
    parser.add_argument(
        "--mutators",
        type=str,
        default=None,
        help="Comma-separated list of mutator class names to include in the pool. "
        "All others are excluded. Use --list-mutators to see available names.",
    )
    parser.add_argument(
        "--strategy",
        type=str,
        default=None,
        choices=["deterministic", "havoc", "spam", "sniper", "helper_sniper"],
        help="Force a specific mutation strategy, bypassing adaptive selection.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all log messages including individual mutator actions, per-run boilerplate, "
        "and relative coverage discoveries. Default: quiet mode (important events only).",
    )
    parser.add_argument(
        "--log-path",
        type=str,
        default=None,
        help="Path for the orchestrator log file. Default: logs/deep_fuzzer_run_{timestamp}.log",
    )
    args = parser.parse_args()

    if args.list_mutators:
        ast_mutator = ASTMutator()
        print(f"Available mutators ({len(ast_mutator.transformers)} total):\n")
        for t in sorted(ast_mutator.transformers, key=lambda x: x.__name__):
            doc = (t.__doc__ or "").strip().split("\n")[0] if t.__doc__ else "(no description)"
            print(f"  {t.__name__:45s} {doc}")
        sys.exit(0)

    if args.dry_run:
        args.keep_children = True
        if args.max_sessions is None:
            print(
                "[!] Warning: --dry-run without --max-sessions will run forever. "
                "Consider adding --max-sessions.",
                file=sys.stderr,
            )

    if args.workdir is not None:
        workdir = args.workdir.resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        os.chdir(workdir)
        print(f"[+] Working directory set to: {workdir}")

    if args.seed is not None:
        random.seed(args.seed)
        print(f"[+] Global random seed set to: {args.seed}")

    # --- Mutator pool filtering ---
    mutator_filter: list[str] | None = None
    if args.mutators is not None:
        mutator_filter = [name.strip() for name in args.mutators.split(",") if name.strip()]
        if not mutator_filter:
            print("Error: --mutators requires at least one mutator name.", file=sys.stderr)
            sys.exit(1)

    LOGS_DIR.mkdir(exist_ok=True)
    # Use a consistent timestamp for the whole run
    run_start_time = datetime.now(timezone.utc)
    timestamp_iso = run_start_time.isoformat()
    safe_timestamp = timestamp_iso.replace(":", "-").replace("+", "Z")
    if args.log_path:
        orchestrator_log_path = Path(args.log_path)
        orchestrator_log_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        orchestrator_log_path = LOGS_DIR / f"deep_fuzzer_run_{safe_timestamp}.log"

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    # This initial print goes only to the console
    verbose_label = "verbose" if args.verbose else "quiet"
    print(
        f"[+] Starting deep fuzzer ({verbose_label} mode). "
        f"Full log will be at: {orchestrator_log_path}"
    )

    tee_logger = TeeLogger(orchestrator_log_path, original_stdout, verbose=args.verbose)
    sys.stdout = tee_logger
    sys.stderr = tee_logger

    termination_reason = "Completed"  # Default reason
    start_stats = load_run_stats()  # Capture stats at the start

    # Generate and save run metadata
    run_metadata = generate_run_metadata(LOGS_DIR, args)
    run_id = run_metadata["run_id"]
    instance_name = run_metadata["instance_name"]

    try:
        print(
            _format_run_header(
                instance_name,
                run_id,
                orchestrator_log_path,
                timestamp_iso,
                args.timeout,
                start_stats,
            )
        )

        orchestrator = LafleurOrchestrator(
            fusil_path=args.fusil_path,
            min_corpus_files=args.min_corpus_files,
            differential_testing=args.differential_testing,
            timeout=args.timeout,
            num_runs=args.runs,
            use_dynamic_runs=args.dynamic_runs,
            keep_tmp_logs=args.keep_tmp_logs,
            timing_fuzz=args.timing_fuzz,
            session_fuzz=args.session_fuzz,
            max_timeout_log_size=args.max_timeout_log_size,
            max_crash_log_size=args.max_crash_log_size,
            target_python=args.target_python,
            deepening_probability=args.deepening_probability,
            run_stats=copy.deepcopy(start_stats),
            no_ekg=args.no_ekg,
            max_sessions=args.max_sessions,
            max_mutations_per_session=args.max_mutations_per_session,
            keep_children=args.keep_children,
            dry_run=args.dry_run,
            mutator_filter=mutator_filter,
            forced_strategy=args.strategy,
        )
        if args.prune_corpus:
            orchestrator.corpus_manager.prune_corpus(dry_run=not args.force)
            print("[*] Pruning complete. Exiting.")
            sys.exit(0)

        orchestrator.run_evolutionary_loop()
    except KeyboardInterrupt:
        print("\n[!] Fuzzing stopped by user.")
        termination_reason = "KeyboardInterrupt"
    except Exception as e:
        termination_reason = f"Error: {e}"
        # Use original stderr for the final error message so it's always visible.
        print(
            f"\n[!!!] An unexpected error occurred in the orchestrator: {e}", file=original_stderr
        )
        import traceback

        traceback.print_exc(file=original_stderr)
    finally:
        print(_format_run_summary(termination_reason, run_start_time, start_stats))

        # Cleanly close the log file and restore streams.
        tee_logger.close()
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        print(f"[+] Fuzzing session finished. Full log saved to: {orchestrator_log_path}")


if __name__ == "__main__":
    main()
