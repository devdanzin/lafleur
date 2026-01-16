"""
This module contains the main LafleurOrchestrator class.

The orchestrator is the "brain" of the fuzzer, responsible for managing the
entire evolutionary feedback loop, including selecting parents from the corpus,
applying mutation strategies, executing child processes, and analyzing the
results for new and interesting JIT behavior.
"""

import argparse
import json
import math
import os
import platform
import random
import shutil
import socket
import sys

from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent

from lafleur.corpus_manager import CORPUS_DIR, CorpusManager
from lafleur.coverage import CoverageManager, load_coverage_state
from lafleur.analysis import CrashFingerprinter
from lafleur.artifacts import ArtifactManager
from lafleur.execution import ExecutionManager
from lafleur.scoring import ScoringManager
from lafleur.learning import MutatorScoreTracker
from lafleur.mutation_controller import MutationController
from lafleur.mutators import ASTMutator
from lafleur.metadata import generate_run_metadata
from lafleur.utils import TeeLogger, load_run_stats

# --- Paths for Fuzzer Outputs (relative to current working directory) ---
# This allows running multiple fuzzer instances from different directories.
TMP_DIR = Path("tmp_fuzz_run")
CRASHES_DIR = Path("crashes")
REGRESSIONS_DIR = Path("regressions")
TIMEOUTS_DIR = Path("timeouts")
DIVERGENCES_DIR = Path("divergences")
LOGS_DIR = Path("logs")
RUN_LOGS_DIR = LOGS_DIR / "run_logs"


class LafleurOrchestrator:
    """
    Manage the main evolutionary fuzzing loop.

    Select interesting test cases from the corpus, apply mutation
    strategies, execute the mutated children, and analyze the results
    for new coverage.
    """

    def __init__(
        self,
        fusil_path: str,
        min_corpus_files: int = 1,
        differential_testing: bool = False,
        timeout: int = 10,
        num_runs: int = 1,
        use_dynamic_runs: bool = False,
        keep_tmp_logs: bool = False,
        prune_corpus_flag: bool = False,
        force_prune: bool = False,
        timing_fuzz: bool = False,
        session_fuzz: bool = False,
        max_timeout_log_size: int = 400,
        max_crash_log_size: int = 400,
        target_python: str = sys.executable,
    ):
        """Initialize the orchestrator and the corpus manager."""
        self.differential_testing = differential_testing
        self.fusil_path = fusil_path
        self.base_runs = num_runs
        self.use_dynamic_runs = use_dynamic_runs
        self.keep_tmp_logs = keep_tmp_logs
        self.deepening_probability = 0.2
        self.ast_mutator = ASTMutator()
        self.timeout = timeout
        self.max_timeout_log_bytes = max_timeout_log_size * 1024 * 1024
        self.max_crash_log_bytes = max_crash_log_size * 1024 * 1024

        self.target_python = target_python

        coverage_state = load_coverage_state()
        self.coverage_manager = CoverageManager(coverage_state)

        self.run_stats = load_run_stats()

        self.timing_fuzz = timing_fuzz
        self.session_fuzz = session_fuzz
        self.score_tracker = MutatorScoreTracker(self.ast_mutator.transformers)

        # Initialize the mutation controller for managing mutation strategies
        # Note: corpus_manager is set to a placeholder and updated after CorpusManager init
        self.mutation_controller = MutationController(
            ast_mutator=self.ast_mutator,
            score_tracker=self.score_tracker,
            corpus_manager=None,  # type: ignore[arg-type]  # Set after CorpusManager init
            differential_testing=differential_testing,
        )

        self.min_corpus_files = min_corpus_files
        self.corpus_manager = CorpusManager(
            self.coverage_manager,
            self.run_stats,
            fusil_path,
            self.mutation_controller.get_boilerplate,
            self.timeout,
            target_python=target_python,
        )

        # Now set the corpus_manager reference in mutation_controller
        self.mutation_controller.corpus_manager = self.corpus_manager

        self.fingerprinter = CrashFingerprinter()

        # Ensure temporary and log directories exist first (needed for timeseries path)
        TMP_DIR.mkdir(exist_ok=True)
        LOGS_DIR.mkdir(exist_ok=True)
        if self.keep_tmp_logs:
            RUN_LOGS_DIR.mkdir(exist_ok=True)
            print(f"[+] Retaining temporary run logs in: {RUN_LOGS_DIR}")

        run_timestamp = self.run_stats.get("start_time", datetime.now(timezone.utc).isoformat())
        # Sanitize timestamp for use in filename
        safe_timestamp = run_timestamp.replace(":", "-").replace("+", "Z")
        self.timeseries_log_path = LOGS_DIR / f"timeseries_{safe_timestamp}.jsonl"
        print(
            f"[+] Time-series analytics for this run will be saved to: {self.timeseries_log_path}"
        )

        # Initialize the artifact manager for handling crashes, timeouts, divergences, and stats
        self.artifact_manager = ArtifactManager(
            crashes_dir=CRASHES_DIR,
            timeouts_dir=TIMEOUTS_DIR,
            divergences_dir=DIVERGENCES_DIR,
            regressions_dir=REGRESSIONS_DIR,
            fingerprinter=self.fingerprinter,
            max_timeout_log_bytes=self.max_timeout_log_bytes,
            max_crash_log_bytes=self.max_crash_log_bytes,
            session_fuzz=self.session_fuzz,
            run_stats=self.run_stats,
            coverage_manager=self.coverage_manager,
            corpus_manager=self.corpus_manager,
            score_tracker=self.score_tracker,
            timeseries_log_path=self.timeseries_log_path,
        )

        # Initialize the scoring manager for analyzing coverage and interestingness
        self.scoring_manager = ScoringManager(
            coverage_manager=self.coverage_manager,
            timing_fuzz=self.timing_fuzz,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            get_core_code_func=self.mutation_controller._get_core_code,
            run_stats=self.run_stats,
        )

        # Initialize the execution manager for running child processes
        self.execution_manager = ExecutionManager(
            target_python=target_python,
            timeout=timeout,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            differential_testing=differential_testing,
            timing_fuzz=timing_fuzz,
            session_fuzz=session_fuzz,
        )

        # Verify that the target python is suitable for fuzzing before doing anything else
        self.execution_manager.verify_target_capabilities()

        # Synchronize the corpus and state at startup.
        self.corpus_manager.synchronize(
            self.scoring_manager.analyze_run, self.scoring_manager._build_lineage_profile
        )

        if prune_corpus_flag:
            self.corpus_manager.prune_corpus(dry_run=not force_prune)
            print("[*] Pruning complete. Exiting.")
            sys.exit(0)

        self.mutations_since_last_find = 0
        self.global_seed_counter = self.run_stats.get("global_seed_counter", 0)

    def run_evolutionary_loop(self) -> None:
        """
        Run the main evolutionary fuzzing loop.

        This method first ensures the corpus has the minimum number of files,
        then enters the infinite loop that drives the fuzzer's core logic of
        selection, mutation, execution, and analysis.
        """
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
                self.artifact_manager.update_and_save_run_stats(self.global_seed_counter)
                if session_num % 10 == 0:
                    print(f"[*] Logging time-series data point at session {session_num}...")
                    self.artifact_manager.log_timeseries_datapoint()
        finally:
            print("\n[+] Fuzzing loop terminating. Saving final stats...")
            self.artifact_manager.update_and_save_run_stats(self.global_seed_counter)
            self.artifact_manager.log_timeseries_datapoint()  # Log one final data point on exit

            self.score_tracker.save_state()

    def _handle_analysis_data(
        self, analysis_data: dict, i: int, parent_metadata: dict, nojit_cv: float | None
    ) -> str | None:
        """Process the result from analyze_run and update fuzzer state."""
        status = analysis_data.get("status")

        if status in ("DIVERGENCE", "NEW_COVERAGE"):
            mutation_info = analysis_data.get("mutation_info", {})
            strategy = mutation_info.get("strategy")
            transformers = mutation_info.get("transformers", [])
            if strategy and transformers:
                self.score_tracker.record_success(strategy, transformers)

        if status == "DIVERGENCE":
            self.run_stats["divergences_found"] = self.run_stats.get("divergences_found", 0) + 1
            self.mutations_since_last_find = 0
            print(
                f"  [***] SUCCESS! Mutation #{i + 1} found a correctness divergence. Moving to next parent."
            )
            analysis_data["new_filename"] = "divergence"  # Placeholder
            return "BREAK"  # A divergence is a major find, move to the next parent
        elif status == "CRASH":
            self.run_stats["crashes_found"] = self.run_stats.get("crashes_found", 0) + 1
            return "CONTINUE"
        elif status == "NEW_COVERAGE":
            print(f"  [***] SUCCESS! Mutation #{i + 1} found new coverage. Moving to next parent.")
            new_filename = self.corpus_manager.add_new_file(
                core_code=analysis_data["core_code"],
                baseline_coverage=analysis_data["baseline_coverage"],
                content_hash=analysis_data["content_hash"],
                coverage_hash=analysis_data["coverage_hash"],
                execution_time_ms=analysis_data["execution_time_ms"],
                parent_id=analysis_data["parent_id"],
                mutation_info=analysis_data["mutation_info"],
                mutation_seed=analysis_data["mutation_seed"],
                build_lineage_func=self.scoring_manager._build_lineage_profile,
            )

            if self.timing_fuzz:
                jit_time = analysis_data.get("jit_avg_time_ms")
                nojit_time = analysis_data.get("nojit_avg_time_ms")
                if jit_time is not None and nojit_time is not None and nojit_time > 0:
                    slowdown_ratio = jit_time / nojit_time

                    # Define the threshold, preferring the dynamic one if available.
                    if nojit_cv is not None:
                        dynamic_threshold = 1.0 + (3 * nojit_cv)  # Same as in InterestingnessScorer
                    else:
                        dynamic_threshold = 1.2  # Fallback to a 20% slowdown threshold

                    if slowdown_ratio > dynamic_threshold:
                        self.artifact_manager.save_regression(
                            CORPUS_DIR / new_filename, jit_time, nojit_time
                        )
                        self.run_stats["regressions_found"] = (
                            self.run_stats.get("regressions_found", 0) + 1
                        )

            analysis_data["new_filename"] = new_filename
            return "BREAK"
        else:  # NO_CHANGE
            parent_metadata["mutations_since_last_find"] = (
                parent_metadata.get("mutations_since_last_find", 0) + 1
            )
            if parent_metadata["mutations_since_last_find"] > 599:
                parent_metadata["is_sterile"] = True
            return None

    def execute_mutation_and_analysis_cycle(
        self,
        initial_parent_path: Path,
        initial_parent_score: float,
        session_id: int,
        is_deepening_session: bool,
    ):
        """
        Take a parent test case and run a full cycle of mutation and analysis.
        If in a deepening session, will continue to mutate successful children.
        """
        # --- Session-level state for deepening ---
        current_parent_path = initial_parent_path
        current_parent_score = initial_parent_score
        mutations_since_last_find_in_session = 0
        new_finds_this_session = 0

        mutation_id = 0

        # --- This loop controls the deepening process ---
        while True:
            max_mutations = self.mutation_controller._calculate_mutations(current_parent_score)
            parent_id = current_parent_path.name
            parent_metadata = self.coverage_manager.state["per_file_coverage"].get(parent_id, {})
            parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})

            parent_file_size = parent_metadata.get("file_size_bytes", 0)

            # Calculate the total number of unique edges in the parent's lineage
            parent_lineage_edge_count = 0
            for harness_data in parent_lineage_profile.values():
                parent_lineage_edge_count += len(harness_data.get("edges", set()))

            base_harness_node, parent_core_tree, setup_nodes = (
                self.mutation_controller._get_nodes_from_parent(current_parent_path)
            )
            if base_harness_node is None or parent_core_tree is None:
                return  # Abort if parent is invalid

            core_logic_to_mutate = base_harness_node

            # Retrieve watched dependencies from parent metadata
            watched_keys = (
                parent_metadata.get("mutation_info", {})
                .get("jit_stats", {})
                .get("watched_dependencies")
            )

            # Filter out the harness itself, as we can't snipe it
            if watched_keys:
                current_harness_name = base_harness_node.name
                watched_keys = [k for k in watched_keys if k != current_harness_name]

            if self.use_dynamic_runs:
                num_runs = 2 + int(math.floor(math.log(max(1.0, current_parent_score / 15))))
                num_runs = min(num_runs, 10)
                if not is_deepening_session:  # Only log this once per breadth session
                    print(f"    -> Dynamically set run count to {num_runs} for this parent.")
            else:
                num_runs = self.base_runs

            # --- Main Mutation Loop ---
            found_new_coverage_in_cycle = False
            mutation_index = 0
            while mutation_index < max_mutations:
                mutation_index += 1
                mutation_id += 1
                self.run_stats["total_mutations"] += 1
                self.mutations_since_last_find += 1
                mutations_since_last_find_in_session += 1

                if is_deepening_session and mutations_since_last_find_in_session > 30:
                    print(
                        "  [~] Deepening session became sterile. Returning to breadth-first search."
                    )
                    return

                self.global_seed_counter += 1
                mutation_seed = self.global_seed_counter
                print(
                    f"  \\-> Running mutation #{mutation_index} (Seed: {mutation_seed}) for {parent_id}..."
                )

                mutated_harness_node, mutation_info = self.mutation_controller.get_mutated_harness(
                    core_logic_to_mutate, mutation_seed, watched_keys=watched_keys
                )
                if not mutated_harness_node or mutation_info is None:
                    continue

                # --- Inner Multi-Run Loop ---
                flow_control: str | None = ""
                for run_num in range(num_runs):
                    child_source_path = (
                        TMP_DIR / f"child_{session_id}_{mutation_id}_{run_num + 1}.py"
                    )
                    child_log_path = TMP_DIR / f"child_{session_id}_{mutation_id}_{run_num + 1}.log"

                    try:
                        runtime_seed = (mutation_seed + 1) * (run_num + 1)
                        mutation_info["runtime_seed"] = runtime_seed

                        if num_runs > 1:
                            print(
                                f"    -> Run #{run_num + 1}/{num_runs} (RuntimeSeed: {runtime_seed})"
                            )

                        child_source = self.mutation_controller.prepare_child_script(
                            parent_core_tree,
                            mutated_harness_node,
                            runtime_seed,
                        )
                        if not child_source:
                            continue

                        exec_result, stat_key = self.execution_manager.execute_child(
                            child_source, child_source_path, child_log_path, current_parent_path
                        )
                        if stat_key:
                            self.run_stats[stat_key] = self.run_stats.get(stat_key, 0) + 1
                        if not exec_result:
                            continue

                        analysis_data = self.scoring_manager.analyze_run(
                            exec_result,
                            parent_lineage_profile,
                            parent_id,
                            mutation_info,
                            mutation_seed,
                            parent_file_size,
                            parent_lineage_edge_count,
                            self.differential_testing,
                        )

                        nojit_cv = exec_result.nojit_cv
                        flow_control = self._handle_analysis_data(
                            analysis_data, mutation_index, parent_metadata, nojit_cv
                        )

                        if flow_control == "BREAK" or flow_control == "CONTINUE":
                            if analysis_data.get("status") == "NEW_COVERAGE":
                                found_new_coverage_in_cycle = True

                                # --- Update stats and logs on every find ---
                                self.run_stats["new_coverage_finds"] += 1
                                self.run_stats["sum_of_mutations_per_find"] += (
                                    self.mutations_since_last_find
                                )
                                self.mutations_since_last_find = 0
                                parent_metadata["total_finds"] = (
                                    parent_metadata.get("total_finds", 0) + 1
                                )
                                parent_metadata["mutations_since_last_find"] = 0
                                self.artifact_manager.update_and_save_run_stats(
                                    self.global_seed_counter
                                )

                                new_finds_this_session += 1
                                if new_finds_this_session % 10 == 0:
                                    print(
                                        f"[*] Logging time-series data point after {new_finds_this_session} finds in this session."
                                    )
                                    self.artifact_manager.log_timeseries_datapoint()

                                if is_deepening_session:
                                    new_child_filename = analysis_data["new_filename"]
                                    print(
                                        f"  [>>>] DEEPENING: New child {new_child_filename} becomes the new parent.",
                                        file=sys.stderr,
                                    )
                                    current_parent_path = CORPUS_DIR / new_child_filename
                                    current_parent_score = (
                                        self.corpus_manager.scheduler.calculate_scores().get(
                                            new_child_filename, 100.0
                                        )
                                    )
                                    mutations_since_last_find_in_session = 0
                            break  # Break inner multi-run loop
                    finally:
                        # Cleanup or save temp files for this specific run
                        try:
                            if child_source_path.exists():
                                child_source_path.unlink()
                            else:
                                print(f"Error deleting {child_source_path}, file doesn't exist!")

                            compressed_log_path = child_log_path.with_suffix(".log.zst")
                            truncated_log_path = child_log_path.with_name(
                                f"{child_log_path.stem}_truncated{child_log_path.suffix}"
                            )
                            if child_log_path.exists():
                                if self.keep_tmp_logs:
                                    dest_log_path = (
                                        RUN_LOGS_DIR
                                        / f"log_{parent_id}_seed_{mutation_seed}_run_{run_num + 1}.log"
                                    )
                                    shutil.move(child_log_path, dest_log_path)
                                else:
                                    child_log_path.unlink()

                            elif compressed_log_path.exists():
                                if self.keep_tmp_logs:
                                    dest_log_path = (
                                        RUN_LOGS_DIR
                                        / f"log_{parent_id}_seed_{mutation_seed}_run_{run_num + 1}.log.zst"
                                    )
                                    shutil.move(compressed_log_path, dest_log_path)
                                else:
                                    compressed_log_path.unlink()

                            elif truncated_log_path.exists():
                                if self.keep_tmp_logs:
                                    dest_log_path = (
                                        RUN_LOGS_DIR
                                        / f"log_{parent_id}_seed_{mutation_seed}_run_{run_num + 1}_truncated.log"
                                    )
                                    shutil.move(truncated_log_path, dest_log_path)
                                else:
                                    truncated_log_path.unlink()
                            # Note: If no log file exists, it was already processed and saved
                            # by timeout/crash handling - this is expected, not an error.

                        except OSError as e:
                            print(
                                f"  [!] Warning: Could not process temp file: {e}", file=sys.stderr
                            )

                if found_new_coverage_in_cycle and is_deepening_session:
                    break
                elif flow_control == "BREAK":
                    return  # For breadth mode, a single find ends the entire session

            # Exit condition for the while True loop
            if not is_deepening_session or not found_new_coverage_in_cycle:
                break


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
    args = parser.parse_args()

    LOGS_DIR.mkdir(exist_ok=True)
    # Use a consistent timestamp for the whole run
    run_start_time = datetime.now()
    timestamp_iso = run_start_time.isoformat()
    safe_timestamp = timestamp_iso.replace(":", "-").replace("+", "Z")
    orchestrator_log_path = LOGS_DIR / f"deep_fuzzer_run_{safe_timestamp}.log"

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    # This initial print goes only to the console
    print(f"[+] Starting deep fuzzer. Full log will be at: {orchestrator_log_path}")

    tee_logger = TeeLogger(orchestrator_log_path, original_stdout)
    sys.stdout = tee_logger
    sys.stderr = tee_logger

    termination_reason = "Completed"  # Default reason
    start_stats = load_run_stats()  # Capture stats at the start

    # Generate and save run metadata
    run_metadata = generate_run_metadata(LOGS_DIR, args)
    run_id = run_metadata["run_id"]
    instance_name = run_metadata["instance_name"]

    try:
        # --- Create and Write the Informative Header ---
        header = f"""
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
- Script Timeout:    {args.timeout} seconds
--------------------------------------------------------------------------------
Initial Stats:
{json.dumps(start_stats, indent=4)}
================================================================================

"""
        print(dedent(header))
        # --- End of Header ---

        orchestrator = LafleurOrchestrator(
            fusil_path=args.fusil_path,
            min_corpus_files=args.min_corpus_files,
            differential_testing=args.differential_testing,
            timeout=args.timeout,
            num_runs=args.runs,
            use_dynamic_runs=args.dynamic_runs,
            keep_tmp_logs=args.keep_tmp_logs,
            prune_corpus_flag=args.prune_corpus,
            force_prune=args.force,
            timing_fuzz=args.timing_fuzz,
            session_fuzz=args.session_fuzz,
            max_timeout_log_size=args.max_timeout_log_size,
            max_crash_log_size=args.max_crash_log_size,
            target_python=args.target_python,
        )
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
        # --- Create and Write the Summary Footer ---
        print("\n" + "=" * 80)
        print("FUZZING RUN SUMMARY")
        print("=" * 80)

        end_time = datetime.now()
        duration = end_time - run_start_time
        end_stats = load_run_stats()

        mutations_this_run = end_stats.get("total_mutations", 0) - start_stats.get(
            "total_mutations", 0
        )
        finds_this_run = end_stats.get("new_coverage_finds", 0) - start_stats.get(
            "new_coverage_finds", 0
        )
        crashes_this_run = end_stats.get("crashes_found", 0) - start_stats.get("crashes_found", 0)
        duration_secs = duration.total_seconds()
        exec_per_sec = mutations_this_run / duration_secs if duration_secs > 0 else 0

        summary = f"""
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
"""
        print(dedent(summary))

        # Cleanly close the log file and restore streams.
        tee_logger.close()
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        print(f"[+] Fuzzing session finished. Full log saved to: {orchestrator_log_path}")


if __name__ == "__main__":
    main()
