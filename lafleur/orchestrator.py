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
import difflib
import hashlib
import json
import math
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import socket
import sys
import time
from collections import defaultdict

import psutil
from compression import zstd
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent, indent
from typing import Any

from lafleur.corpus_manager import CORPUS_DIR, CorpusManager
from lafleur.coverage import (
    CoverageManager,
    parse_log_for_edge_coverage,
    load_coverage_state,
    PROTO_TRACE_REGEX,
    OPTIMIZED_TRACE_REGEX,
)
from lafleur.analysis import CrashFingerprinter, CrashType, CrashSignature
from lafleur.learning import MutatorScoreTracker
from lafleur.mutators import (
    ASTMutator,
    EmptyBodySanitizer,
    FuzzerSetupNormalizer,
    HarnessInstrumentor,
    SlicingMutator,
    VariableRenamer,
)
from lafleur.corpus_analysis import generate_corpus_stats
from lafleur.metadata import generate_run_metadata
from lafleur.mutators.sniper import SniperMutator
from lafleur.mutators.helper_injection import HelperFunctionInjector
from lafleur.utils import ExecutionResult, TeeLogger, load_run_stats, save_run_stats

SERIALIZATION_SNIPPET = dedent("""
    # --- BEGIN INJECTED SERIALIZATION CODE ---
    import types
    import inspect
    import json

    class LafleurStateEncoder(json.JSONEncoder):
        '''A custom JSON encoder that handles complex types found in locals().'''
        def default(self, o):
            if isinstance(o, bytes):
                try:
                    # Try to decode as UTF-8, with a fallback for binary data
                    return o.decode('utf-8', errors='replace')
                except Exception:
                    return repr(o)
            elif inspect.isfunction(o):
                return f"<function: {o.__name__}>"
            elif inspect.isclass(o):
                return f"<class: {o.__name__}>"
            elif inspect.ismodule(o):
                return None  # Exclude modules entirely
            elif hasattr(o, '__class__') and hasattr(o.__class__, '__module__') and o.__class__.__module__ == '__main__':
                 return f"<instance of: {o.__class__.__name__}>"

            # For any other unknown types, use a generic repr
            try:
                return super().default(o)
            except TypeError:
                return f"<unserializable type: {type(o).__name__}>"

    # Filter out keys we don't care about before serialization
    state_dict = locals().copy()
    IGNORE_KEYS = {
        '__name__', '__doc__', '__package__', '__loader__',
        '__spec__', '__builtins__', 'LafleurStateEncoder', 'json',
        'types', 'inspect'
    }
    filtered_state = {k: v for k, v in state_dict.items() if k not in IGNORE_KEYS and not k.startswith('__')}

    # Check if the harness loop actually ran and produced a result
    if 'final_harness_locals' in filtered_state:
        print(json.dumps(filtered_state['final_harness_locals'], sort_keys=True, indent=2, cls=LafleurStateEncoder))
    # --- END INJECTED SERIALIZATION CODE ---
""")

RANDOM = random.Random()

# --- Paths for Fuzzer Outputs (relative to current working directory) ---
# This allows running multiple fuzzer instances from different directories.
TMP_DIR = Path("tmp_fuzz_run")
CRASHES_DIR = Path("crashes")
REGRESSIONS_DIR = Path("regressions")
TIMEOUTS_DIR = Path("timeouts")
DIVERGENCES_DIR = Path("divergences")
LOGS_DIR = Path("logs")
RUN_LOGS_DIR = LOGS_DIR / "run_logs"

TIMEOUT_LOG_COMPRESSION_THRESHOLD = 1_048_576  # 1 MB
DEFAULT_MAX_LOG_SIZE = 400 * 1024 * 1024  # 400 MB
TRUNCATE_HEAD_SIZE = 50 * 1024  # 50 KB
TRUNCATE_TAIL_SIZE = 300 * 1024  # 300 KB

# Session fuzzing: The Mixer strategy
MIXER_PROBABILITY = 0.3  # 30% chance to prepend polluter scripts

# Tachycardia (instability) tracking: decay factor to prevent local optima
# By decaying the saved density, persistent instability remains interesting over generations
TACHYCARDIA_DECAY_FACTOR = 0.95

CRASH_KEYWORDS = [
    "Segmentation fault",
    # "Traceback (most recent call last):",
    "JITCorrectnessError",
    "Assertion ",
    "Abort ",
    "Fatal Python error",
    "panic",
    "AddressSanitizer",
]

BOILERPLATE_START_MARKER = "# FUSIL_BOILERPLATE_START"
BOILERPLATE_END_MARKER = "# FUSIL_BOILERPLATE_END"

ENV = os.environ.copy()
ENV.update(
    {
        "PYTHON_LLTRACE": "2",
        "PYTHON_OPT_DEBUG": "4",
        "PYTHON_JIT": "1",
        "ASAN_OPTIONS": "detect_leaks=0",
    }
)


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
                dynamic_threshold = 1.0 + (3 * self.nojit_cv)

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
        self.boilerplate_code = None
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

        self.min_corpus_files = min_corpus_files
        self.corpus_manager = CorpusManager(
            self.coverage_manager,
            self.run_stats,
            fusil_path,
            self.get_boilerplate,
            self.timeout,
            target_python=target_python,
        )

        # Verify that the target python is suitable for fuzzing before doing anything else
        self.verify_target_capabilities()

        self.fingerprinter = CrashFingerprinter()

        # Synchronize the corpus and state at startup.
        self.corpus_manager.synchronize(self.analyze_run, self._build_lineage_profile)

        if prune_corpus_flag:
            self.corpus_manager.prune_corpus(dry_run=not force_prune)
            print("[*] Pruning complete. Exiting.")
            sys.exit(0)

        self.mutations_since_last_find = 0
        self.global_seed_counter = self.run_stats.get("global_seed_counter", 0)

        # Ensure temporary and corpus directories exist
        TMP_DIR.mkdir(exist_ok=True)
        CRASHES_DIR.mkdir(exist_ok=True)
        REGRESSIONS_DIR.mkdir(exist_ok=True)
        TIMEOUTS_DIR.mkdir(exist_ok=True)
        DIVERGENCES_DIR.mkdir(exist_ok=True)
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

    def get_boilerplate(self) -> str:
        """Return the cached boilerplate code."""
        return self.boilerplate_code

    def _extract_and_cache_boilerplate(self, source_code: str) -> None:
        """Parse a source file to find, extract, and cache the boilerplate code."""
        try:
            start_index = source_code.index(BOILERPLATE_START_MARKER)
            end_index = source_code.index(BOILERPLATE_END_MARKER)
            # The boilerplate includes the start marker itself.
            self.boilerplate_code = source_code[start_index:end_index]
            print("[+] Boilerplate code extracted and cached.")
        except ValueError:
            print(
                "[!] Warning: Could not find boilerplate markers in the initial seed file.",
                file=sys.stderr,
            )
            # Fallback to using an empty boilerplate
            self.boilerplate_code = ""

    def _get_core_code(self, source_code: str) -> str:
        """Strip the boilerplate from a source file to get the dynamic core."""
        try:
            end_index = source_code.index(BOILERPLATE_END_MARKER)
            # The core code starts right after the end marker and its newline.
            return source_code[end_index + len(BOILERPLATE_END_MARKER) + 1 :]
        except ValueError:
            # If no marker, assume the whole file is the core (for minimized corpus files)
            return source_code

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
                        self.analyze_run, self._build_lineage_profile
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
                self.update_and_save_run_stats()
                if session_num % 10 == 0:
                    print(f"[*] Logging time-series data point at session {session_num}...")
                    self._log_timeseries_datapoint()
        finally:
            print("\n[+] Fuzzing loop terminating. Saving final stats...")
            self.update_and_save_run_stats()
            self._log_timeseries_datapoint()  # Log one final data point on exit

            self.score_tracker.save_state()

    def update_and_save_run_stats(self) -> None:
        """Update dynamic run statistics and save them to the stats file."""
        self.run_stats["last_update_time"] = datetime.now(timezone.utc).isoformat()
        self.run_stats["corpus_size"] = len(
            self.coverage_manager.state.get("per_file_coverage", {})
        )
        global_cov = self.coverage_manager.state.get("global_coverage", {})
        self.run_stats["global_uops"] = len(global_cov.get("uops", {}))
        self.run_stats["global_edges"] = len(global_cov.get("edges", {}))
        self.run_stats["global_rare_events"] = len(global_cov.get("rare_events", {}))
        self.run_stats["global_seed_counter"] = self.global_seed_counter
        self.run_stats["corpus_file_counter"] = self.corpus_manager.corpus_file_counter

        total_finds = self.run_stats.get("new_coverage_finds", 0)
        if total_finds > 0:
            self.run_stats["average_mutations_per_find"] = (
                self.run_stats.get("sum_of_mutations_per_find", 0) / total_finds
            )

        save_run_stats(self.run_stats)

        # Generate and save corpus statistics
        try:
            corpus_stats = generate_corpus_stats(self.corpus_manager)
            corpus_stats_path = Path("corpus_stats.json")
            with open(corpus_stats_path, "w", encoding="utf-8") as f:
                json.dump(corpus_stats, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Could not save corpus stats: {e}", file=sys.stderr)

    def _run_slicing(
        self, base_ast: ast.AST, stage_name: str, len_body: int, seed: int = None
    ) -> tuple[ast.AST, dict[str, Any]]:
        """A helper to apply a mutation pipeline to a slice of a large AST."""
        print(
            f"  [~] Large AST detected ({len_body} statements), running SLICING stage...",
            file=sys.stderr,
        )

        if stage_name == "deterministic":
            # For deterministic, we must re-seed the RNG to get the same choices
            random.seed(seed)
            num_mutations = random.randint(1, 3)
            chosen_classes = random.choices(self.ast_mutator.transformers, k=num_mutations)
            pipeline = [cls() for cls in chosen_classes]

        elif stage_name == "spam":
            num_mutations = random.randint(20, 50)
            # Choose ONE transformer and create many instances of it
            chosen_class = random.choices(self.ast_mutator.transformers, k=1)[0]
            pipeline = [chosen_class() for _ in range(num_mutations)]
            print(f"    -> Slicing and Spamming with: {chosen_class.__name__}", file=sys.stderr)

        else:  # Havoc
            num_mutations = random.randint(15, 50)
            chosen_classes = random.choices(self.ast_mutator.transformers, k=num_mutations)
            pipeline = [cls() for cls in chosen_classes]

        slicer = SlicingMutator(pipeline)
        tree = slicer.visit(base_ast)
        mutation_info = {"strategy": f"slicing_{stage_name}", "transformers": ["SlicingMutator"]}
        return tree, mutation_info

    def _run_deterministic_stage(
        self, base_ast: ast.AST, seed: int, **kwargs
    ) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a single, seeded, deterministic mutation."""
        harness_node = base_ast
        len_harness = len(harness_node.body) if harness_node else 0
        if harness_node and len_harness > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "deterministic", len_harness, seed=seed)

        print(f"  [~] Running DETERMINISTIC stage ({len_harness} statements)...", file=sys.stderr)
        mutated_ast, transformers_used = self.ast_mutator.mutate_ast(base_ast, seed=seed)
        mutation_info = {
            "strategy": "deterministic",
            "transformers": [t.__name__ for t in transformers_used],
        }
        return mutated_ast, mutation_info

    def _run_havoc_stage(self, base_ast: ast.AST, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a random stack of many different mutations to the AST."""
        harness_node = base_ast
        len_harness = len(harness_node.body) if harness_node else 0
        if harness_node and len_harness > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "havoc", len_harness)

        print(f"  [~] Running HAVOC stage ({len_harness} statements)...", file=sys.stderr)
        tree = base_ast  # Start with the copied tree from the dispatcher
        num_havoc_mutations = RANDOM.randint(15, 50)
        transformers_applied = []

        transformer_names = [t.__name__ for t in self.ast_mutator.transformers]
        dynamic_weights = self.score_tracker.get_weights(transformer_names)

        for _ in range(num_havoc_mutations):
            transformer_class = random.choices(
                self.ast_mutator.transformers, weights=dynamic_weights, k=1
            )[0]
            # Record the attempt
            self.score_tracker.attempts[transformer_class.__name__] += 1
            transformers_applied.append(transformer_class.__name__)

            tree = transformer_class().visit(tree)

        ast.fix_missing_locations(tree)
        mutation_info = {"strategy": "havoc", "transformers": transformers_applied}
        return tree, mutation_info

    def _run_spam_stage(self, base_ast: ast.AST, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """Repeatedly apply the same type of mutation to the AST."""
        harness_node = base_ast
        len_harness = len(harness_node.body) if harness_node else 0
        if harness_node and len_harness > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "spam", len_harness)

        print(f"  [~] Running SPAM stage ({len_harness} statements)...", file=sys.stderr)
        tree = base_ast
        num_spam_mutations = RANDOM.randint(20, 50)

        transformer_names = [t.__name__ for t in self.ast_mutator.transformers]
        dynamic_weights = self.score_tracker.get_weights(transformer_names)

        chosen_transformer_class = random.choices(
            self.ast_mutator.transformers, weights=dynamic_weights, k=1
        )[0]
        print(f"    -> Spamming with: {chosen_transformer_class.__name__}", file=sys.stderr)

        for _ in range(num_spam_mutations):
            # Apply a new instance of the same transformer each time
            tree = chosen_transformer_class().visit(tree)

        ast.fix_missing_locations(tree)
        mutation_info = {
            "strategy": "spam",
            "transformers": [chosen_transformer_class.__name__] * num_spam_mutations,
        }
        return tree, mutation_info

    def _analyze_setup_ast(self, setup_nodes: list[ast.stmt]) -> dict[str, str]:
        """Analyze setup AST nodes to map variable names to their inferred types."""
        variable_map = {}
        for node in setup_nodes:
            # We are interested in simple, top-level assignments
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # Infer type from prefix, e.g., "int_v1" -> "int"
                    # This is robust to names that don't have a version suffix.
                    parts = var_name.split("_v")
                    inferred_type = parts[0]
                    variable_map[var_name] = inferred_type
        return variable_map

    def _run_splicing_stage(self, base_core_ast: ast.AST, **kwargs) -> ast.AST:
        """Perform a crossover by splicing the harness from a second parent."""
        print("  [~] Attempting SPLICING stage...", file=sys.stderr)

        selection = self.corpus_manager.select_parent()
        if not selection:
            return base_core_ast
        parent_b_path, _ = selection

        try:
            parent_b_source = parent_b_path.read_text()
            parent_b_core_code = self._get_core_code(parent_b_source)
            parent_b_tree = ast.parse(parent_b_core_code)
        except (IOError, SyntaxError):
            return base_core_ast

        # --- Analysis ---
        setup_nodes_a = [n for n in base_core_ast if not isinstance(n, ast.FunctionDef)]
        provided_vars_a = self._analyze_setup_ast(setup_nodes_a)

        setup_nodes_b = [n for n in parent_b_tree.body if not isinstance(n, ast.FunctionDef)]
        provided_vars_b = self._analyze_setup_ast(setup_nodes_b)

        harness_b = next((n for n in parent_b_tree.body if isinstance(n, ast.FunctionDef)), None)
        if not harness_b:
            return base_core_ast

        required_vars = {
            node.id
            for node in ast.walk(harness_b)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }

        # --- Phase 2: Remapping Logic ---
        remapping_dict = {}
        is_possible = True
        available_vars_a = defaultdict(list)
        for name, type_name in provided_vars_a.items():
            available_vars_a[type_name].append(name)

        for required_var in sorted(list(required_vars)):
            required_type = provided_vars_b.get(required_var)
            if not required_type:
                continue

            if available_vars_a.get(required_type):
                compatible_var = RANDOM.choice(available_vars_a[required_type])
                remapping_dict[required_var] = compatible_var
                available_vars_a[required_type].remove(compatible_var)
            else:
                print(
                    f"    -> Splice failed: No var of type '{required_type}' for '{required_var}'",
                    file=sys.stderr,
                )
                is_possible = False
                break

        if not is_possible:
            return base_core_ast

        print(f"    -> Remapping successful: {remapping_dict}")

        # --- Phase 3: Transformation and Assembly ---
        renamer = VariableRenamer(remapping_dict)
        remapped_harness_b = renamer.visit(copy.deepcopy(harness_b))

        # The new core AST consists of Parent A's setup and the remapped Harness B
        new_core_body = setup_nodes_a + [remapped_harness_b]
        new_core_ast = ast.Module(body=new_core_body, type_ignores=[])
        ast.fix_missing_locations(new_core_ast)

        return new_core_ast

    def _run_sniper_stage(
        self, base_ast: ast.AST, seed: int, watched_keys: list[str] | None = None, **kwargs
    ) -> tuple[ast.AST, dict[str, Any]]:
        """Apply the SniperMutator if watched keys are available."""
        if not watched_keys:
            # Fallback to havoc if no intelligence available
            return self._run_havoc_stage(base_ast, seed=seed, **kwargs)

        print(
            f"  [~] Running SNIPER stage (Targets: {', '.join(watched_keys[:3])})...",
            file=sys.stderr,
        )
        tree = copy.deepcopy(base_ast)
        mutator = SniperMutator(watched_keys)
        tree = mutator.visit(tree)
        ast.fix_missing_locations(tree)

        mutation_info = {
            "strategy": "sniper",
            "transformers": ["SniperMutator"],
            "targets": watched_keys,
        }
        return tree, mutation_info

    def _run_helper_sniper_stage(
        self, base_ast: ast.AST, seed: int, **kwargs
    ) -> tuple[ast.AST, dict[str, Any]]:
        """
        Combined strategy: Inject helpers, then attack them with Sniper.

        This strategy ensures HelperFunctionInjector and SniperMutator work together:
        1. HelperFunctionInjector creates/detects _jit_helper_* functions
        2. SniperMutator targets those helpers for invalidation attacks

        This solves the feedback problem: the combined strategy gets credit
        for any interesting behavior, allowing both mutators to evolve together.
        """
        print("  [~] Running HELPER+SNIPER stage...", file=sys.stderr)
        tree = copy.deepcopy(base_ast)

        # Stage 1: Inject helpers (or detect existing ones)
        helper_injector = HelperFunctionInjector(probability=1.0)  # Always apply in this strategy
        tree = helper_injector.visit(tree)
        ast.fix_missing_locations(tree)

        detected_helpers = helper_injector.helpers_injected
        if not detected_helpers:
            # No helpers available, fall back to havoc
            print("  [!] No helpers available, falling back to havoc", file=sys.stderr)
            return self._run_havoc_stage(base_ast, seed=seed, **kwargs)

        print(
            f"  [~] Detected {len(detected_helpers)} helper(s): {detected_helpers}", file=sys.stderr
        )

        # Stage 2: Attack the helpers with Sniper
        sniper = SniperMutator(watched_keys=detected_helpers)
        tree = sniper.visit(tree)
        ast.fix_missing_locations(tree)

        mutation_info = {
            "strategy": "helper_sniper",
            "transformers": ["HelperFunctionInjector", "SniperMutator"],
            "targets": detected_helpers,
        }
        return tree, mutation_info

    def apply_mutation_strategy(
        self, base_ast: ast.AST, seed: int, watched_keys: list[str] | None = None
    ) -> tuple[ast.AST, dict[str, Any]]:
        """
        Apply a single, seeded mutation strategy to an AST.

        Take a base AST and a seed, then probabilistically choose and
        apply one of the available mutation strategies (e.g., deterministic,
        havoc, or spam).

        Return a tuple containing the mutated AST and a dictionary of
        information about the mutation that was performed.
        """
        RANDOM.seed(seed)
        random.seed(seed)

        tree_copy = copy.deepcopy(base_ast)
        # Clean the AST of any previous fuzzer setup before applying new mutations.
        normalizer = FuzzerSetupNormalizer()
        tree_copy = normalizer.visit(tree_copy)

        strategy_candidates = [
            self._run_deterministic_stage,
            self._run_havoc_stage,
            self._run_spam_stage,
            self._run_helper_sniper_stage,  # Always available - generates own targets
        ]

        if watched_keys:
            # Add sniper strategy if we have Bloom-detected targets
            strategy_candidates.append(self._run_sniper_stage)

        strategy_names = [
            s.__name__.replace("_run_", "").replace("_stage", "") for s in strategy_candidates
        ]

        # Record an attempt for each strategy to help with exploration.
        for name in strategy_names:
            self.score_tracker.attempts[name] += 1

        dynamic_weights = self.score_tracker.get_weights(strategy_names)

        # Boost sniper weight if available (simple heuristic for now)
        if "sniper" in strategy_names:
            sniper_idx = strategy_names.index("sniper")
            # Ensure sniper has at least average weight
            avg_weight = sum(dynamic_weights) / len(dynamic_weights)
            dynamic_weights[sniper_idx] = max(dynamic_weights[sniper_idx], avg_weight * 1.5)

        chosen_strategy = random.choices(strategy_candidates, weights=dynamic_weights, k=1)[0]

        # The `seed` argument is used by the deterministic stage for its own
        # seeding, and the other stages use the globally seeded RANDOM instance.
        mutated_ast, mutation_info = chosen_strategy(
            tree_copy, seed=seed, watched_keys=watched_keys
        )

        # Always run the sanitizer last to fix any empty bodies.
        sanitizer = EmptyBodySanitizer()
        mutated_ast = sanitizer.visit(mutated_ast)
        ast.fix_missing_locations(mutated_ast)

        mutation_info["seed"] = seed
        return mutated_ast, mutation_info

    def _get_mutated_harness(
        self, original_harness_node: ast.AST, seed: int, watched_keys: list[str] | None = None
    ) -> tuple[ast.AST | None, dict | None]:
        """Apply a mutation strategy and handle transformation errors."""
        try:
            mutated_harness_node, mutation_info = self.apply_mutation_strategy(
                original_harness_node, seed=seed, watched_keys=watched_keys
            )
            mutation_info["runtime_seed"] = seed + 1
            return mutated_harness_node, mutation_info
        except RecursionError:
            print(
                "  [!] Warning: Skipping mutation due to RecursionError during AST transformation.",
                file=sys.stderr,
            )
            return None, None

    def _prepare_child_script(
        self,
        parent_core_tree: ast.Module,
        mutated_harness_node: ast.AST,
        runtime_seed: int,
    ) -> str | None:
        """Reassemble the AST and generate the final Python source code for the child."""
        try:
            gc_tuning_code = ""
            if random.random() < 0.25:
                print("    -> Prepending GC pressure to test case", file=sys.stderr)
                # This logic is the same as in GCInjector
                thresholds = [1, 10, 100, None]
                weights = [0.6, 0.1, 0.1, 0.2]
                chosen_threshold = random.choices(thresholds, weights=weights, k=1)[0]
                if chosen_threshold is None:
                    chosen_threshold = random.randint(1, 150)
                gc_tuning_code = f"import gc\ngc.set_threshold({chosen_threshold})\n"

            rng_setup_code = dedent(f"""
                import random
                fuzzer_rng = random.Random({runtime_seed})
            """)

            child_core_tree = copy.deepcopy(parent_core_tree)
            for i, node in enumerate(child_core_tree.body):
                if isinstance(node, ast.FunctionDef) and node.name == mutated_harness_node.name:
                    child_core_tree.body[i] = mutated_harness_node
                    break

            if self.differential_testing:
                instrumentor = HarnessInstrumentor()
                child_core_tree = instrumentor.visit(child_core_tree)

            mutated_core_code = ast.unparse(child_core_tree)
            return f"{self.boilerplate_code}\n{gc_tuning_code}{rng_setup_code}\n{mutated_core_code}"
        except RecursionError:
            print(
                "  [!] Warning: Skipping mutation due to RecursionError during ast.unparse.",
                file=sys.stderr,
            )
            return None

    def _run_timed_trial(
        self, source_path: Path, num_runs: int, jit_enabled: bool
    ) -> tuple[float | None, bool, float | None]:
        """
        Run a script multiple times to get a stable execution time.

        Return a tuple of (average_time_ms, did_timeout, coefficient_of_variation).
        Return None for time and CV if measurements are unstable.
        """
        timings_ms = []
        env = os.environ.copy()
        env["PYTHON_JIT"] = "1" if jit_enabled else "0"
        # Explicitly disable our noisy debug logs for timing runs
        env["PYTHON_LLTRACE"] = "0"
        env["PYTHON_OPT_DEBUG"] = "0"

        print(f"[TIMING] Running timed trial with JIT={jit_enabled}.", file=sys.stderr)

        # Run N+2 times and discard the min/max runs as outliers
        for _ in range(num_runs + 2):
            try:
                start_time = time.monotonic()
                subprocess.run(
                    [self.target_python, str(source_path)],
                    capture_output=True,  # We only care about time, not output
                    timeout=self.timeout,
                    env=env,
                    check=True,  # Raise exception on non-zero exit code
                )
                end_time = time.monotonic()
                timings_ms.append((end_time - start_time) * 1000)
            except subprocess.TimeoutExpired:
                return None, True, None  # Signal a timeout
            except subprocess.CalledProcessError:
                # The script crashed during a timing run. This is a bug, but not a
                # performance regression. We'll treat it as unstable.
                print("  [~] Child crashed during timing run, aborting.", file=sys.stderr)
                return None, False, None

        if len(timings_ms) < 3:
            return None, False, None  # Not enough data points

        timings_ms.sort()
        stable_timings = timings_ms[1:-1]  # Discard min and max outliers

        mean = statistics.mean(stable_timings)
        print(f"  [~] Mean for JIT={jit_enabled}: {mean / 1000:.3f}s.", file=sys.stderr)
        if mean == 0:
            return 0.0, False, 0.0  # Extremely fast, no variation

        stdev = statistics.stdev(stable_timings)
        cv = stdev / mean  # Coefficient of Variation

        # If variation is > 20%, the measurement is too noisy to be reliable.
        CV_THRESHOLD = 0.20
        if cv > CV_THRESHOLD:
            print(
                f"  [~] Timing measurements too noisy (CV={cv:.2f}). Discarding run.",
                file=sys.stderr,
            )
            return None, False, None

        return mean, False, cv

    def _truncate_huge_log(self, log_path: Path, original_size: int) -> Path:
        """
        Truncate a huge log file by keeping only the head and tail.
        Returns the path to the new truncated file.
        """
        truncated_path = log_path.with_name(f"{log_path.stem}_truncated{log_path.suffix}")
        try:
            with open(log_path, "rb") as src, open(truncated_path, "wb") as dst:
                # Write Head
                dst.write(src.read(TRUNCATE_HEAD_SIZE))

                # Write Marker
                mb_size = original_size / (1024 * 1024)
                msg = f"\n\n... [Log Truncated by Lafleur: Original size {mb_size:.2f} MB] ...\n\n"
                dst.write(msg.encode("utf-8", errors="replace"))

                # Write Tail
                src.seek(original_size - TRUNCATE_TAIL_SIZE)
                dst.write(src.read(TRUNCATE_TAIL_SIZE))

            log_path.unlink()  # Delete the original huge file
            return truncated_path
        except Exception as e:
            print(f"  [!] Warning: Could not truncate huge log: {e}", file=sys.stderr)
            return log_path  # Fallback to keeping the original

    def _compress_log_stream(self, log_path: Path) -> Path:
        """
        Compress a log file using streaming to avoid high memory usage.
        Returns the path to the new compressed file.
        """
        compressed_path = log_path.with_suffix(".log.zst")
        try:
            # Use zstd.open for streaming compression (Python 3.14+ feature)
            with open(log_path, "rb") as src, zstd.open(compressed_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

            log_path.unlink()  # Delete the original file
            return compressed_path
        except Exception as e:
            print(f"  [!] Warning: Could not compress log stream: {e}", file=sys.stderr)
            if compressed_path.exists():
                compressed_path.unlink()
            return log_path  # Fallback to keeping the original

    def _process_log_file(self, log_path: Path, max_size_bytes: int, label: str = "Log") -> Path:
        """
        Apply size policies to a log file: Truncate if huge, Compress if large, Keep if small.
        Returns the path to the processed file.
        """
        try:
            if not log_path.exists():
                return log_path

            log_size = log_path.stat().st_size

            # Tier 3: Huge Log -> Truncate
            if log_size > max_size_bytes:
                print(
                    f"  [*] {label} is huge ({log_size / (1024 * 1024):.1f} MB), truncating...",
                    file=sys.stderr,
                )
                return self._truncate_huge_log(log_path, log_size)

            # Tier 2: Large Log -> Compress
            elif log_size > TIMEOUT_LOG_COMPRESSION_THRESHOLD:
                print(f"  [*] {label} is large, compressing with zstd...", file=sys.stderr)
                return self._compress_log_stream(log_path)

            # Tier 1: Small Log -> Keep as is
            return log_path

        except Exception as e:
            print(f"  [!] Warning: Error processing {label.lower()}: {e}", file=sys.stderr)
            return log_path

    def _handle_timeout(
        self, child_source_path: Path, child_log_path: Path, parent_path: Path
    ) -> None:
        """Handles a standard timeout by saving the test case and processing the log."""
        self.run_stats["timeouts_found"] = self.run_stats.get("timeouts_found", 0) + 1
        print("  [!!!] TIMEOUT DETECTED! Saving test case.", file=sys.stderr)

        # Use the centralized processor with timeout-specific limits
        log_to_save = self._process_log_file(
            child_log_path, self.max_timeout_log_bytes, "Timeout log"
        )

        timeout_source_path = TIMEOUTS_DIR / f"timeout_{child_source_path.stem}_{parent_path.name}"

        # Calculate destination log path, explicitly preserving truncation marker or compression extension
        if log_to_save.name.endswith("_truncated.log"):
            timeout_log_path = timeout_source_path.with_name(
                f"{timeout_source_path.stem}_truncated.log"
            )
        elif log_to_save.name.endswith(".log.zst"):
            timeout_log_path = timeout_source_path.with_name(f"{timeout_source_path.stem}.log.zst")
        else:
            timeout_log_path = timeout_source_path.with_suffix(log_to_save.suffix)

        if log_to_save.exists():
            shutil.copy(child_source_path, timeout_source_path)
            shutil.copy(log_to_save, timeout_log_path)

            if log_to_save != child_log_path:
                log_to_save.unlink()
        return None

    def _save_regression_timeout(self, source_path: Path, parent_path: Path):
        """Saves a test case that timed out with the JIT but not without."""
        self.run_stats["regression_timeouts_found"] = (
            self.run_stats.get("regression_timeouts_found", 0) + 1
        )
        print("  [!!!] JIT-INDUCED TIMEOUT DETECTED! Saving test case.", file=sys.stderr)

        dest_dir = REGRESSIONS_DIR / "timeouts"
        dest_dir.mkdir(parents=True, exist_ok=True)

        dest_path = dest_dir / f"timeout_{source_path.stem}_{parent_path.name}.py"
        try:
            shutil.copy(source_path, dest_path)
            print(f"  [+] Regression timeout saved to {dest_path}", file=sys.stderr)
        except IOError as e:
            print(f"  [!] CRITICAL: Could not save regression timeout file: {e}", file=sys.stderr)

    def _save_jit_hang(self, source_path: Path, parent_path: Path):
        """Saves a test case that timed out with the JIT enabled but not disabled."""
        self.run_stats["jit_hangs_found"] = self.run_stats.get("jit_hangs_found", 0) + 1
        print("  [!!!] JIT-INDUCED HANG DETECTED! Saving test case.", file=sys.stderr)

        dest_dir = DIVERGENCES_DIR / "jit_hangs"
        dest_dir.mkdir(parents=True, exist_ok=True)

        dest_path = dest_dir / f"hang_{source_path.stem}_{parent_path.name}.py"
        try:
            shutil.copy(source_path, dest_path)
            print(f"  [+] JIT hang saved to {dest_path}", file=sys.stderr)
        except IOError as e:
            print(f"  [!] CRITICAL: Could not save JIT hang file: {e}", file=sys.stderr)

    def _filter_jit_stderr(self, stderr_content: str) -> str:
        """Removes known, benign JIT debug messages from stderr output."""
        lines = stderr_content.splitlines()
        # Filter out lines that are known to be part of the JIT's tracing output
        filtered_lines = [
            line
            for line in lines
            if not line.strip().startswith(
                ("Created a proto-trace", "Optimized trace", "SIDE EXIT")
            )
        ]
        return "\n".join(filtered_lines)

    def _execute_child(
        self, source_code: str, child_source_path: Path, child_log_path: Path, parent_path: Path
    ) -> ExecutionResult | None:
        """
        Execute a child script, sequentially checking for correctness divergences,
        then performance regressions, and finally gathering coverage.
        """
        jit_avg_ms = None
        nojit_avg_ms = None
        nojit_cv = None

        # --- Stage 1: Differential Correctness Fuzzing (if enabled) ---
        if self.differential_testing:
            instrumented_code = source_code + "\n" + SERIALIZATION_SNIPPET
            child_source_path.write_text(instrumented_code)

            # Run Non-JIT
            nojit_run = None
            try:
                nojit_env = ENV.copy()
                nojit_env["PYTHON_JIT"] = "0"
                # Disable debug logs for a clean stderr comparison
                nojit_env["PYTHON_LLTRACE"] = "0"
                nojit_env["PYTHON_OPT_DEBUG"] = "0"
                print("[DIFFERENTIAL] Running child with JIT=False.", file=sys.stderr)
                nojit_run = subprocess.run(
                    [self.target_python, str(child_source_path)],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=nojit_env,
                )
            except subprocess.TimeoutExpired:
                return self._handle_timeout(child_source_path, child_log_path, parent_path)

            # Run JIT
            jit_run = None
            try:
                jit_env = ENV.copy()
                jit_env["PYTHON_JIT"] = "1"
                jit_env["PYTHON_LLTRACE"] = "0"
                jit_env["PYTHON_OPT_DEBUG"] = "0"
                print("[DIFFERENTIAL] Running child with JIT=True.", file=sys.stderr)
                jit_run = subprocess.run(
                    [self.target_python, str(child_source_path)],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=jit_env,
                )
            except subprocess.TimeoutExpired:
                self._save_jit_hang(child_source_path, parent_path)
                return None

            # If both runs completed, compare their results sequentially.
            if nojit_run and jit_run:
                # 1. Check for exit code mismatch
                if jit_run.returncode != nojit_run.returncode:
                    return ExecutionResult(
                        source_path=child_source_path,
                        log_path=child_log_path,
                        returncode=0,
                        execution_time_ms=0,
                        is_divergence=True,
                        divergence_reason="exit_code_mismatch",
                        jit_output=f"Exit Code: {jit_run.returncode}",
                        nojit_output=f"Exit Code: {nojit_run.returncode}",
                        parent_path=parent_path,
                    )

                # 2. Check for stderr mismatch (after filtering)
                filtered_jit_stderr = self._filter_jit_stderr(jit_run.stderr)
                filtered_nojit_stderr = self._filter_jit_stderr(nojit_run.stderr)
                if filtered_jit_stderr != filtered_nojit_stderr:
                    return ExecutionResult(
                        source_path=child_source_path,
                        log_path=child_log_path,
                        returncode=0,
                        execution_time_ms=0,
                        is_divergence=True,
                        divergence_reason="stderr_mismatch",
                        jit_output=filtered_jit_stderr,
                        nojit_output=filtered_nojit_stderr,
                        parent_path=parent_path,
                    )

                # 3. Check for stdout mismatch
                if jit_run.stdout != nojit_run.stdout:
                    return ExecutionResult(
                        source_path=child_source_path,
                        log_path=child_log_path,
                        returncode=0,
                        execution_time_ms=0,
                        is_divergence=True,
                        divergence_reason="stdout_mismatch",
                        jit_output=jit_run.stdout,
                        nojit_output=nojit_run.stdout,
                        parent_path=parent_path,
                    )
            print("  [~] No divergences found.", file=sys.stderr)

        # --- Stage 2: Performance Timing Fuzzing (if enabled) ---
        # This runs if differential testing is off, or if it found no divergence.
        if self.timing_fuzz:
            child_source_path.write_text(source_code)  # Ensure original code is used
            num_timing_runs = 5

            nojit_avg_ms, timed_out, nojit_cv = self._run_timed_trial(
                child_source_path, num_timing_runs, jit_enabled=False
            )
            if timed_out:
                return self._handle_timeout(child_source_path, child_log_path, parent_path)

            jit_avg_ms, timed_out, _ = self._run_timed_trial(
                child_source_path, num_timing_runs, jit_enabled=True
            )
            if timed_out:
                self._save_regression_timeout(child_source_path, parent_path)
                return None

        # --- Stage 3: Normal Coverage-Gathering Run ---
        # This always runs unless a critical bug was found in a previous stage.
        try:
            print("[COVERAGE] Running child with JIT=True.", file=sys.stderr)
            # Re-write the original source to ensure we're not running instrumented code
            child_source_path.write_text(source_code)

            # Build the command based on session fuzzing mode
            session_files = None
            if getattr(self, "session_fuzz", False):
                # Session mode: run parent (warmup) then child (attack) in same process
                print("[SESSION] Using session driver for warm JIT fuzzing.", file=sys.stderr)

                # The Mixer: Prepend random corpus files to pollute JIT state
                if random.random() < MIXER_PROBABILITY:
                    # Select 1-3 random polluter scripts from corpus
                    num_polluters = random.randint(1, 3)
                    polluters = []

                    # Try to get polluters from corpus (handle empty corpus gracefully)
                    try:
                        for _ in range(num_polluters):
                            polluter_path = self.corpus_manager.get_random_parent()
                            if polluter_path:
                                polluters.append(CORPUS_DIR / polluter_path)
                    except (AttributeError, IndexError):
                        # Corpus empty or get_random_parent not available
                        pass

                    if polluters:
                        session_files = polluters + [parent_path, child_source_path]
                        print(
                            f"  [MIXER] Active: Added {len(polluters)} polluter(s) to session.",
                            file=sys.stderr,
                        )
                    else:
                        # Fallback to standard session
                        session_files = [parent_path, child_source_path]
                else:
                    # Standard session mode
                    session_files = [parent_path, child_source_path]

                cmd = [
                    self.target_python,
                    "-m",
                    "lafleur.driver",
                ] + [str(f) for f in session_files]
            else:
                # Normal mode: run child in fresh process
                cmd = [self.target_python, str(child_source_path)]

            with open(child_log_path, "w") as log_file:
                start_time = time.monotonic()
                result = subprocess.run(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.timeout,
                    env=ENV,  # Use the global ENV with debug flags for coverage
                )
                end_time = time.monotonic()

            return ExecutionResult(
                returncode=result.returncode,
                log_path=child_log_path,
                source_path=child_source_path,
                execution_time_ms=int((end_time - start_time) * 1000),
                jit_avg_time_ms=jit_avg_ms,
                nojit_avg_time_ms=nojit_avg_ms,
                nojit_cv=nojit_cv,
                parent_path=parent_path,
                session_files=session_files if getattr(self, "session_fuzz", False) else None,
            )
        except subprocess.TimeoutExpired:
            return self._handle_timeout(child_source_path, child_log_path, parent_path)
        except Exception as e:
            # Instead of letting the exception propagate, we create a "failure"
            # result so the analyzer can inspect the log and non-zero exit code.
            print(f"  [!] An OS-level error occurred during child execution: {e}", file=sys.stderr)
            # A common exit code for segfaults is -11. We'll use a high
            # number to indicate an exceptional failure that was caught.
            return ExecutionResult(
                returncode=255,  # Indicates a crash caught by the orchestrator
                log_path=child_log_path,
                source_path=child_source_path,
                execution_time_ms=0,
                parent_path=parent_path,
                session_files=session_files if getattr(self, "session_fuzz", False) else None,
            )

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
                build_lineage_func=self._build_lineage_profile,
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
                        self._save_regression(CORPUS_DIR / new_filename, jit_time, nojit_time)

            analysis_data["new_filename"] = new_filename
            return "BREAK"
        else:  # NO_CHANGE
            parent_metadata["mutations_since_last_find"] = (
                parent_metadata.get("mutations_since_last_find", 0) + 1
            )
            if parent_metadata["mutations_since_last_find"] > 599:
                parent_metadata["is_sterile"] = True
            return None

    def _get_nodes_from_parent(
        self, parent_path: Path
    ) -> tuple[ast.FunctionDef, ast.AST, list[ast.stmt]] | tuple[None, None, None]:
        """Parse a parent file and extract its setup and harness AST nodes."""
        try:
            parent_source = parent_path.read_text()
            if self.boilerplate_code is None:
                self._extract_and_cache_boilerplate(parent_source)
            parent_core_code = self._get_core_code(parent_source)
            parent_core_tree = ast.parse(parent_core_code)

            normalizer = FuzzerSetupNormalizer()
            parent_core_tree = normalizer.visit(parent_core_tree)
            ast.fix_missing_locations(parent_core_tree)

        except (IOError, SyntaxError) as e:
            print(f"[!] Error processing parent file {parent_path.name}: {e}", file=sys.stderr)
            return None, None, None

        base_harness_node = None
        setup_nodes = []
        for node in parent_core_tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("uop_harness_"):
                base_harness_node = node
            elif base_harness_node is None:
                # Collect setup nodes that appear before the harness function
                setup_nodes.append(node)
        if not base_harness_node:
            print(
                f"[-] No harness function found in {parent_path.name}. Skipping.", file=sys.stderr
            )
            return None, None, None
        return base_harness_node, parent_core_tree, setup_nodes

    def _calculate_mutations(self, parent_score: float) -> int:
        """Dynamically calculate the number of mutations based on parent score."""
        # --- Implement Dynamic Mutation Count ---
        base_mutations = 100
        # Normalize the score relative to a baseline of 100 to calculate a multiplier
        score_multiplier = parent_score / 100.0
        # Apply a gentle curve so that very high scores don't lead to extreme mutation counts
        # and very low scores don't get starved completely.
        # We use math.log to dampen the effect. Add 1 to avoid log(0).
        dynamic_multiplier = 0.5 + (math.log(max(1.0, score_multiplier * 10)) / 2)
        # Clamp the multiplier to a reasonable range (e.g., 0.25x to 3.0x)
        final_multiplier = max(0.25, min(3.0, dynamic_multiplier))
        max_mutations = int(base_mutations * final_multiplier)
        print(
            f"[+] Dynamically adjusting mutation count based on score. Base: {base_mutations}, "
            f"Multiplier: {final_multiplier:.2f}, Final Count: {max_mutations}"
        )
        return max_mutations

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
            max_mutations = self._calculate_mutations(current_parent_score)
            parent_id = current_parent_path.name
            parent_metadata = self.coverage_manager.state["per_file_coverage"].get(parent_id, {})
            parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})

            parent_file_size = parent_metadata.get("file_size_bytes", 0)

            # Calculate the total number of unique edges in the parent's lineage
            parent_lineage_edge_count = 0
            for harness_data in parent_lineage_profile.values():
                parent_lineage_edge_count += len(harness_data.get("edges", set()))

            base_harness_node, parent_core_tree, setup_nodes = self._get_nodes_from_parent(
                current_parent_path
            )
            if base_harness_node is None:
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

                mutated_harness_node, mutation_info = self._get_mutated_harness(
                    core_logic_to_mutate, mutation_seed, watched_keys=watched_keys
                )
                if not mutated_harness_node:
                    continue

                # --- Inner Multi-Run Loop ---
                flow_control = ""
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

                        child_source = self._prepare_child_script(
                            parent_core_tree,
                            mutated_harness_node,
                            runtime_seed,
                        )
                        if not child_source:
                            continue

                        exec_result = self._execute_child(
                            child_source, child_source_path, child_log_path, current_parent_path
                        )
                        if not exec_result:
                            continue

                        analysis_data = self.analyze_run(
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
                                self.update_and_save_run_stats()

                                new_finds_this_session += 1
                                if new_finds_this_session % 10 == 0:
                                    print(
                                        f"[*] Logging time-series data point after {new_finds_this_session} finds in this session."
                                    )
                                    self._log_timeseries_datapoint()

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

    def _save_session_crash(
        self, scripts: list[Path], exit_code: int, crash_signature: CrashSignature | None = None
    ) -> Path:
        """
        Save a session crash bundle containing all scripts in the sequence.

        In session fuzzing mode, crashes may depend on JIT state built by earlier
        scripts in the sequence. This method creates a crash directory containing
        all scripts with sequential prefixes, plus a reproduce.sh script.

        Args:
            scripts: List of script paths in execution order (e.g., [parent, child])
            exit_code: The exit code from the crashed execution
            crash_signature: Optional crash fingerprint metadata

        Returns:
            Path to the created crash directory
        """
        # Generate unique directory name with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        random_suffix = random.randint(1000, 9999)
        crash_dir = CRASHES_DIR / f"session_crash_{timestamp}_{random_suffix}"

        # Create the crash directory
        crash_dir.mkdir(parents=True, exist_ok=True)

        # Write metadata.json if signature is provided
        if crash_signature:
            metadata_path = crash_dir / "metadata.json"
            metadata = crash_signature.to_dict()
            metadata["timestamp"] = timestamp
            metadata_path.write_text(json.dumps(metadata, indent=2))

        # Copy scripts with sequential prefixes
        script_names = []
        for i, script_path in enumerate(scripts):
            if i == 0:
                dest_name = f"{i:02d}_warmup.py"
            elif i == len(scripts) - 1:
                dest_name = f"{i:02d}_attack.py"
            else:
                dest_name = f"{i:02d}_script.py"

            dest_path = crash_dir / dest_name
            shutil.copy2(script_path, dest_path)
            script_names.append(dest_name)

        # Create reproduce.sh script
        reproduce_script = crash_dir / "reproduce.sh"
        reproduce_content = dedent(f"""
            #!/bin/bash
            # Session crash reproducer
            # Exit code: {exit_code}
            # Generated: {timestamp}

            python3 -m lafleur.driver {" ".join(script_names)}
        """).strip()

        reproduce_script.write_text(reproduce_content)
        reproduce_script.chmod(0o755)  # Make executable

        return crash_dir

    def _check_for_crash(
        self,
        return_code: int,
        log_content: str,
        source_path: Path,
        log_path: Path,
        parent_path: Path | None = None,
        session_files: list[Path] | None = None,
    ) -> bool:
        """Check for crashes, determine the cause (Signal/Retcode/Keyword), and save artifacts."""
        crash_signature = None
        crash_reason = None

        # 1. Analyze with Fingerprinter
        if return_code != 0:
            # Ignore standard termination signals (SIGKILL=-9, SIGTERM=-15)
            # These are usually caused by timeouts or OOM killers, not JIT bugs.
            if return_code in (-9, -15):
                print(f"  [~] Ignoring signal {return_code} (SIGKILL/SIGTERM).", file=sys.stderr)
                return False

            crash_signature = self.fingerprinter.analyze(return_code, log_content)

            # Filter out crashes marked as IGNORE (OOM, allocation failures, etc.)
            if crash_signature.crash_type == CrashType.IGNORE:
                print(
                    f"  [~] Ignoring uninteresting crash: {crash_signature.fingerprint}",
                    file=sys.stderr,
                )
                return False

            # Filter out SyntaxErrors and IndentationErrors early (applies to all crash types)
            # These are just invalid mutations, not real bugs. The driver may output them in
            # a format that the fingerprinter doesn't recognize as PYTHON_UNCAUGHT.
            if "SyntaxError:" in log_content or "IndentationError:" in log_content:
                print(
                    "  [~] Ignoring SyntaxError/IndentationError from invalid mutation.",
                    file=sys.stderr,
                )
                return False

            # Filter out mundane Python errors (Exit Code 1)
            if crash_signature.crash_type == CrashType.PYTHON_UNCAUGHT:
                # If it's just a Python exception without other signals, ignore it
                return False

            crash_reason = crash_signature.fingerprint

        # 2. Check Keywords (Fallback if return code was 0 but log indicates panic)
        if not crash_reason:
            for keyword in CRASH_KEYWORDS:
                if keyword.lower() in log_content.lower():
                    # Sanitize keyword: lowercase, spaces to underscores, remove non-alphanumeric
                    safe_kw = re.sub(r"[^a-z0-9_]", "", keyword.lower().replace(" ", "_"))
                    crash_reason = f"keyword_{safe_kw}"
                    # Retroactively create a signature
                    crash_signature = CrashSignature(
                        type="KEYWORD",
                        crash_type=CrashType.UNKNOWN,
                        returncode=return_code,
                        signal_name=None,
                        fingerprint=crash_reason,
                    )
                    break

        # 3. Save Artifacts if Crash Detected
        if crash_reason:
            print(f"  [!!!] CRASH DETECTED! ({crash_reason}). Saving...", file=sys.stderr)

            # Process the log (truncate/compress) using the crash-specific limit
            log_to_save = self._process_log_file(log_path, self.max_crash_log_bytes, "Crash log")

            # Branch based on session fuzzing mode
            if getattr(self, "session_fuzz", False) and parent_path is not None:
                # Session mode: save crash bundle with all scripts
                # Use session_files if available (includes polluters), otherwise use parent+child
                scripts_to_save = session_files if session_files else [parent_path, source_path]
                num_scripts = len(scripts_to_save)
                print(
                    f"  [SESSION] Saving crash bundle with {num_scripts} script(s).",
                    file=sys.stderr,
                )
                crash_dir = self._save_session_crash(scripts_to_save, return_code, crash_signature)

                # Determine log destination name
                if log_to_save.name.endswith("_truncated.log"):
                    crash_log_name = "session_crash_truncated.log"
                elif log_to_save.name.endswith(".log.zst"):
                    crash_log_name = "session_crash.log.zst"
                else:
                    crash_log_name = "session_crash.log"

                crash_log_path = crash_dir / crash_log_name

                try:
                    shutil.copy(log_to_save, crash_log_path)
                    if log_to_save != log_path:
                        log_to_save.unlink()
                    print(f"  [!!!] Session crash bundle saved to: {crash_dir}", file=sys.stderr)
                except IOError as e:
                    print(f"  [!] Error saving session crash log: {e}", file=sys.stderr)

            else:
                # Standard mode: save single child file
                # Use sanitization for filename
                safe_reason = re.sub(r"[^a-zA-Z0-9_.-]", "_", crash_reason[:50])
                crash_base_name = f"crash_{safe_reason}_{source_path.name}"
                crash_source_path = CRASHES_DIR / crash_base_name

                # Determine destination log name, preserving extensions/markers
                if log_to_save.name.endswith("_truncated.log"):
                    crash_log_path = CRASHES_DIR / f"{Path(crash_base_name).stem}_truncated.log"
                elif log_to_save.name.endswith(".log.zst"):
                    crash_log_path = CRASHES_DIR / f"{Path(crash_base_name).stem}.log.zst"
                else:
                    crash_log_path = CRASHES_DIR / f"{Path(crash_base_name).stem}.log"

                try:
                    shutil.copy(source_path, crash_source_path)
                    shutil.copy(log_to_save, crash_log_path)

                    # Clean up the processed temp log if we created one
                    if log_to_save != log_path:
                        log_to_save.unlink()
                except IOError as e:
                    print(f"  [!] Error saving crash artifacts: {e}", file=sys.stderr)

            return True

        return False

    def _find_new_coverage(
        self,
        child_coverage: dict,
        parent_lineage_profile: dict,
        parent_id: str | None,
    ) -> NewCoverageInfo:
        """
        Count all new global and relative coverage items from a child's run.

        Return a NewCoverageInfo object containing detailed counts.
        """
        info = NewCoverageInfo()
        total_edges = 0

        for harness_id, child_data in child_coverage.items():
            lineage_harness_data = parent_lineage_profile.get(harness_id, {})

            total_edges += len(child_data.get("edges", {}))

            # Helper to get the correct reverse map for a given coverage type
            def get_reverse_map(cov_type):
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

    def _update_global_coverage(self, child_coverage: dict):
        """Commit the coverage from a new, interesting child to the global state."""
        global_coverage = self.coverage_manager.state["global_coverage"]
        for harness_id, data in child_coverage.items():
            for cov_type in ["uops", "edges", "rare_events"]:
                # The data already contains integer IDs from the parser.
                for item_id, count in data.get(cov_type, {}).items():
                    global_coverage[cov_type].setdefault(item_id, 0)
                    global_coverage[cov_type][item_id] += count

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

    def verify_target_capabilities(self) -> None:
        """
        Verify that the target Python interpreter produces the expected JIT debug output.
        Raises a RuntimeError if the JIT does not appear to be active or logging correctly.
        """
        print(
            f"[*] Verifying target interpreter capabilities: {self.target_python}...",
            file=sys.stderr,
        )

        # A minimal script to trigger the JIT
        stimulus_code = dedent("""
            def workload():
                for i in range(1000):
                    x = i + 1
            for x in range(100):
                workload()
        """)

        # Use the exact environment we rely on for coverage
        env = ENV.copy()

        try:
            # Run the stimulus
            result = subprocess.run(
                [self.target_python, "-c", stimulus_code],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )

            # Check for JIT signals in stderr
            has_proto = PROTO_TRACE_REGEX.search(f"{result.stderr}\n{result.stdout}")
            has_opt = OPTIMIZED_TRACE_REGEX.search(f"{result.stderr}\n{result.stdout}")

            if not (has_proto or has_opt):
                stderr_stdout = result.stderr + "\n" + result.stdout
                output = indent(
                    stderr_stdout[:500] + "..." if len(stderr_stdout) > 500 else stderr_stdout,
                    "    ",
                )
                # If we don't see traces, the JIT likely isn't enabled or built correctly.
                error_msg = dedent(f"""
                    [!] CRITICAL: The target interpreter '{self.target_python}' did not produce JIT debug output.

                    Lafleur requires a CPython build with the experimental JIT enabled and configured for debug logging.

                    Troubleshooting:
                    1. Ensure you built CPython with: ./configure --with-pydebug --enable-experimental-jit
                    2. Ensure you ran: make -j$(nproc)
                    3. Ensure the environment variables PYTHON_JIT=1, PYTHON_LLTRACE=4, and PYTHON_OPT_DEBUG=4 are respected.

                    Output received from target (stderr +  stdout):
                    {output}
                """)
                raise RuntimeError(error_msg)

            print(
                "  [+] Target interpreter validated successfully (JIT traces detected).",
                file=sys.stderr,
            )

        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Target interpreter '{self.target_python}' timed out during verification check."
            )
        except RuntimeError as e:
            print(e)
            sys.exit(1)

    def _parse_jit_stats(self, log_content: str) -> dict:
        """
        Parse JIT stats from the driver log output.

        The log may contain multiple [DRIVER:STATS] lines (one per script in session).
        We aggregate them to find the 'peak stress' values.
        It also parses [EKG] WATCHED: lines to find variables the JIT depends on.
        """
        aggregated_stats = {
            "max_exit_count": 0,
            "max_chain_depth": 0,
            "zombie_traces": 0,
            "min_code_size": 0,
            "max_exit_density": 0.0,
            "watched_dependencies": [],
        }
        min_code_sizes = []
        watched_dependencies = set()

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

    def _score_and_decide_interestingness(
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
        """Use the scorer to decide if a child is interesting."""

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
                scorer.jit_avg_time_ms and scorer.nojit_avg_time_ms and scorer.nojit_avg_time_ms > 0
            )
            if self.timing_fuzz and valid_timings:
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

    def analyze_run(
        self,
        exec_result: ExecutionResult,
        parent_lineage_profile: dict,
        parent_id: str | None,
        mutation_info: dict,
        mutation_seed: int,
        parent_file_size: int,
        parent_lineage_edge_count: int,
        is_differential_mode: bool = False,
    ) -> dict:
        """Orchestrate the analysis of a run and return a dictionary of findings."""

        if exec_result.is_divergence:
            self._save_divergence(
                exec_result.source_path,
                exec_result.jit_output,
                exec_result.nojit_output,
                exec_result.divergence_reason,
            )
            return {"status": "DIVERGENCE"}

        log_content = ""
        try:
            log_content = exec_result.log_path.read_text()
        except IOError as e:
            print(f"  [!] Warning: Could not read log file for analysis: {e}", file=sys.stderr)

        if self._check_for_crash(
            exec_result.returncode,
            log_content,
            exec_result.source_path,
            exec_result.log_path,
            exec_result.parent_path,
            exec_result.session_files,
        ):
            return {"status": "CRASH"}

        child_coverage = parse_log_for_edge_coverage(exec_result.log_path, self.coverage_manager)

        coverage_info = self._find_new_coverage(child_coverage, parent_lineage_profile, parent_id)
        jit_stats = self._parse_jit_stats(log_content)

        # Retrieve parent JIT stats from metadata
        parent_jit_stats = {}
        if parent_id:
            parent_metadata = self.coverage_manager.state["per_file_coverage"].get(parent_id, {})
            parent_jit_stats = parent_metadata.get("mutation_info", {}).get("jit_stats", {})

        is_interesting = self._score_and_decide_interestingness(
            coverage_info,
            parent_id,
            mutation_info,
            parent_file_size,
            parent_lineage_edge_count,
            len(exec_result.source_path.read_text().encode("utf-8")),
            exec_result.jit_avg_time_ms,
            exec_result.nojit_avg_time_ms,
            exec_result.nojit_cv,
            jit_stats,
            parent_jit_stats,
        )

        if is_interesting:
            core_code_to_save = self._get_core_code(exec_result.source_path.read_text())
            content_hash = hashlib.sha256(core_code_to_save.encode("utf-8")).hexdigest()
            coverage_hash = self._calculate_coverage_hash(child_coverage)

            if (content_hash, coverage_hash) in self.corpus_manager.known_hashes:
                print(
                    f"  [~] New coverage found, but this is a known duplicate behavior (ContentHash: {content_hash[:10]}, CoverageHash: {coverage_hash[:10]}). Skipping.",
                    file=sys.stderr,
                )
                return {"status": "NO_CHANGE"}

            # This is the crucial step: if it's new and not a duplicate, we commit the coverage.
            self._update_global_coverage(child_coverage)

            # --- Dynamic Density Clamping ---
            # Prevent a single massive spike from setting an unreachable bar for the next generation.
            child_density = jit_stats.get("max_exit_density", 0.0)
            parent_density = parent_jit_stats.get("max_exit_density", 0.0)

            if parent_density > 0:
                # Allow exponential growth (up to 5x), but clamp massive outliers.
                clamped_density = min(parent_density * 5.0, child_density)
            else:
                # First generation or no parent data: trust the child's value.
                clamped_density = child_density

            # --- Tachycardia Decay ---
            # Apply decay to the saved metric so persistent instability remains interesting.
            # This prevents the fuzzer from getting stuck in local optima where high baseline
            # densities make incremental improvements invisible.
            saved_density = clamped_density * TACHYCARDIA_DECAY_FACTOR
            if clamped_density > 0:
                print(
                    f"  [~] Tachycardia decay: {clamped_density:.4f} -> {saved_density:.4f}",
                    file=sys.stderr,
                )

            # Create a copy of stats for persistence, with the decayed density.
            jit_stats_for_save = jit_stats.copy()
            jit_stats_for_save["max_exit_density"] = saved_density

            # Inject jit_stats into mutation_info so it gets saved with the file
            mutation_info["jit_stats"] = jit_stats_for_save

            return {
                "status": "NEW_COVERAGE",
                "core_code": core_code_to_save,
                "baseline_coverage": child_coverage,
                "content_hash": content_hash,
                "coverage_hash": coverage_hash,
                "execution_time_ms": exec_result.execution_time_ms,
                "parent_id": parent_id,
                "mutation_info": mutation_info,
                "mutation_seed": mutation_seed,
                "jit_avg_time_ms": exec_result.jit_avg_time_ms,
                "nojit_avg_time_ms": exec_result.nojit_avg_time_ms,
                # jit_stats is now inside mutation_info, no need to pass separately if not used by caller
            }

        return {"status": "NO_CHANGE"}

    def _save_divergence(self, source_path: Path, jit_output: str, nojit_output: str, reason: str):
        """Saves artifacts from a JIT divergence for a given reason."""
        self.run_stats["divergences_found"] = self.run_stats.get("divergences_found", 0) + 1
        print(f"  [!!!] JIT DIVERGENCE DETECTED ({reason})! Saving test case.", file=sys.stderr)

        # Create a subdirectory for this type of divergence
        dest_dir = DIVERGENCES_DIR / reason
        dest_dir.mkdir(parents=True, exist_ok=True)

        base_filename = f"divergence_{source_path.stem}"
        dest_source_path = dest_dir / f"{base_filename}.py"

        # Create a .diff file to show the difference
        diff_path = dest_dir / f"{base_filename}.diff"

        try:
            shutil.copy(source_path, dest_source_path)

            # Use difflib to create a clear diff of the outputs
            diff = difflib.unified_diff(
                nojit_output.splitlines(keepends=True),
                jit_output.splitlines(keepends=True),
                fromfile="nojit_output",
                tofile="jit_output",
            )
            diff_path.write_text("".join(diff))

            print(f"  [+] Divergence artifacts saved to {dest_dir}", file=sys.stderr)

        except IOError as e:
            print(f"  [!] CRITICAL: Could not save divergence files: {e}", file=sys.stderr)

    def _save_regression(self, source_path: Path, jit_time: float, nojit_time: float):
        """Saves a test case that causes a significant JIT performance regression."""
        self.run_stats["regressions_found"] = self.run_stats.get("regressions_found", 0) + 1
        print("  [!!!] JIT PERFORMANCE REGRESSION DETECTED! Saving test case.", file=sys.stderr)

        REGRESSIONS_DIR.mkdir(parents=True, exist_ok=True)

        # Create a descriptive filename with the timing data
        filename = f"regression_jit_{jit_time:.0f}ms_nojit_{nojit_time:.0f}ms_{source_path.name}"
        dest_path = REGRESSIONS_DIR / filename

        try:
            shutil.copy(source_path, dest_path)
            print(f"  [+] Regression saved to {dest_path}", file=sys.stderr)
        except IOError as e:
            print(f"  [!] CRITICAL: Could not save regression file: {e}", file=sys.stderr)

    def _log_timeseries_datapoint(self) -> None:
        """Append a snapshot of the current run statistics to the time-series log."""
        # Create a snapshot of the current stats for logging.
        datapoint = self.run_stats.copy()
        datapoint["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Add system resource metrics
        try:
            datapoint["system_load_1min"] = psutil.getloadavg()[0]
        except (OSError, AttributeError):
            # getloadavg() may not be available on all platforms (e.g., Windows)
            datapoint["system_load_1min"] = None

        datapoint["process_rss_mb"] = round(psutil.Process().memory_info().rss / (1024 * 1024), 2)

        # Calculate corpus directory size
        try:
            corpus_size_bytes = sum(f.stat().st_size for f in CORPUS_DIR.rglob("*") if f.is_file())
            datapoint["corpus_size_mb"] = round(corpus_size_bytes / (1024 * 1024), 2)
        except OSError:
            datapoint["corpus_size_mb"] = None

        # Get disk usage percentage for the current working directory
        try:
            datapoint["disk_usage_percent"] = psutil.disk_usage(Path.cwd()).percent
        except OSError:
            datapoint["disk_usage_percent"] = None

        try:
            # Open in append mode and write the JSON object as a single line.
            with open(self.timeseries_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(datapoint) + "\n")
        except IOError as e:
            print(f"[!] Warning: Could not write to time-series log file: {e}", file=sys.stderr)

        self.score_tracker.save_telemetry()

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

    def debug_mutation_differences(self, original_ast: ast.AST, mutated_ast: ast.AST, seed: int):
        """Verify that mutations are producing different code."""
        original_str = ast.unparse(original_ast)
        mutated_str = ast.unparse(mutated_ast)

        if original_str == mutated_str:
            print(f"  [WARNING] Mutation with seed {seed} produced identical code!")
            return False

        # Compute hashes to see if different ASTs produce same unparsed code
        original_hash = hashlib.sha256(original_str.encode("utf-8")).hexdigest()[:10]
        mutated_hash = hashlib.sha256(mutated_str.encode("utf-8")).hexdigest()[:10]

        print(
            f"  [DEBUG] Seed {seed}: Original hash: {original_hash}, Mutated hash: {mutated_hash}"
        )

        # Show a diff summary (just line counts for brevity)
        original_lines = original_str.count("\n")
        mutated_lines = mutated_str.count("\n")
        print(f"  [DEBUG] Line count change: {original_lines} -> {mutated_lines}")

        return True

    def verify_jit_determinism(self, test_file_path: Path, num_runs: int = 5):
        """Run the same file multiple times to check if coverage is deterministic."""
        print(f"\n[*] Testing JIT determinism for {test_file_path.name}...")

        coverage_sets = []
        for run in range(num_runs):
            log_path = TMP_DIR / f"determinism_test_run_{run}.log"

            with open(log_path, "w") as log_file:
                subprocess.run(
                    [self.target_python, str(test_file_path)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.timeout,  # Use the configurable timeout here
                    env=ENV,
                )

            coverage = parse_log_for_edge_coverage(log_path, self.coverage_manager)

            # Collect all edges from all harnesses
            all_edges = set()
            for harness_data in coverage.values():
                all_edges.update(harness_data.get("edges", {}).keys())

            coverage_sets.append(all_edges)
            print(f"  Run {run + 1}: {len(all_edges)} unique edges")

        # Check if all runs produced identical coverage
        if all(s == coverage_sets[0] for s in coverage_sets):
            print("  [✓] Coverage is deterministic across all runs")
        else:
            print("  [!] Coverage is NON-DETERMINISTIC!")
            # Show which edges are inconsistent
            all_edges_union = set().union(*coverage_sets)
            for edge in all_edges_union:
                appearances = sum(1 for s in coverage_sets if edge in s)
                if appearances != num_runs:
                    print(f"    Edge '{edge}' appeared in {appearances}/{num_runs} runs")


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
