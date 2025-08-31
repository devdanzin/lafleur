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
import hashlib
import json
import math
import os
import platform
import random
import shutil
import subprocess
import socket
import sys
import time
from collections import defaultdict
from compression import zstd
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent, indent
from typing import Any

from lafleur.corpus_manager import CORPUS_DIR, CorpusManager
from lafleur.coverage import CoverageManager, parse_log_for_edge_coverage, load_coverage_state
from lafleur.learning import MutatorScoreTracker
from lafleur.mutator import (
    ASTMutator,
    EmptyBodySanitizer,
    FuzzerSetupNormalizer,
    SlicingMutator,
    VariableRenamer,
)
from lafleur.utils import ExecutionResult, TeeLogger, load_run_stats, save_run_stats

RANDOM = random.Random()

# --- Paths for Fuzzer Outputs (relative to current working directory) ---
# This allows running multiple fuzzer instances from different directories.
TMP_DIR = Path("tmp_fuzz_run")
CRASHES_DIR = Path("crashes")
TIMEOUTS_DIR = Path("timeouts")
DIVERGENCES_DIR = Path("divergences")
LOGS_DIR = Path("logs")
RUN_LOGS_DIR = LOGS_DIR / "run_logs"
TIMEOUT_LOG_COMPRESSION_THRESHOLD = 1_048_576  # 1 MB

CRASH_KEYWORDS = [
    "Segmentation fault",
    "Traceback (most recent call last):",
    "JITCorrectnessError",
    "Assertion",
    "Abort",
    "Fatal Python error",
    "panic",
    "AddressSanitizer",
]

BOILERPLATE_START_MARKER = "# FUSIL_BOILERPLATE_START"
BOILERPLATE_END_MARKER = "# FUSIL_BOILERPLATE_END"

ENV = os.environ.copy()
ENV.update(
    {
        "PYTHON_LLTRACE": "4",
        "PYTHON_OPT_DEBUG": "4",
        "PYTHON_JIT": "1",
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
    ):
        self.info = coverage_info
        self.parent_file_size = parent_file_size
        self.parent_lineage_edge_count = parent_lineage_edge_count
        self.child_file_size = child_file_size

    def calculate_score(self) -> float:
        """
        Calculate a score based on new coverage, richness, and density.
        """
        score = 0.0

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
        self.timeout = timeout  # Store the timeout value

        coverage_state = load_coverage_state()
        self.coverage_manager = CoverageManager(coverage_state)

        self.run_stats = load_run_stats()

        self.score_tracker = MutatorScoreTracker(self.ast_mutator.transformers)

        self.min_corpus_files = min_corpus_files
        self.corpus_manager = CorpusManager(
            self.coverage_manager, self.run_stats, fusil_path, self.get_boilerplate, self.timeout
        )
        # Synchronize the corpus and state at startup.
        self.corpus_manager.synchronize(self.analyze_run, self._build_lineage_profile)

        self.mutations_since_last_find = 0
        self.global_seed_counter = self.run_stats.get("global_seed_counter", 0)

        # Ensure temporary and corpus directories exist
        TMP_DIR.mkdir(exist_ok=True)
        CRASHES_DIR.mkdir(exist_ok=True)
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
        harness_node = next((n for n in base_ast.body if isinstance(n, ast.FunctionDef)), None)
        if harness_node and len(harness_node.body) > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "deterministic", len(harness_node.body), seed=seed)

        mutated_ast, transformers_used = self.ast_mutator.mutate_ast(base_ast, seed=seed)
        mutation_info = {
            "strategy": "deterministic",
            "transformers": [t.__name__ for t in transformers_used],
        }
        return mutated_ast, mutation_info

    def _run_havoc_stage(self, base_ast: ast.AST, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a random stack of many different mutations to the AST."""
        harness_node = next((n for n in base_ast.body if isinstance(n, ast.FunctionDef)), None)
        if harness_node and len(harness_node.body) > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "havoc", len(harness_node.body))

        print("  [~] Running HAVOC stage...", file=sys.stderr)
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
        harness_node = next((n for n in base_ast.body if isinstance(n, ast.FunctionDef)), None)
        if harness_node and len(harness_node.body) > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "spam", len(harness_node.body))

        print("  [~] Running SPAM stage...", file=sys.stderr)
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

    def apply_mutation_strategy(
        self, base_ast: ast.AST, seed: int
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
        ]
        strategy_names = [
            s.__name__.replace("_run_", "").replace("_stage", "") for s in strategy_candidates
        ]

        # Record an attempt for each strategy to help with exploration.
        for name in strategy_names:
            self.score_tracker.attempts[name] += 1

        dynamic_weights = self.score_tracker.get_weights(strategy_names)

        chosen_strategy = random.choices(strategy_candidates, weights=dynamic_weights, k=1)[0]

        # The `seed` argument is used by the deterministic stage for its own
        # seeding, and the other stages use the globally seeded RANDOM instance.
        mutated_ast, mutation_info = chosen_strategy(tree_copy, seed=seed)

        # Always run the sanitizer last to fix any empty bodies.
        sanitizer = EmptyBodySanitizer()
        mutated_ast = sanitizer.visit(mutated_ast)
        ast.fix_missing_locations(mutated_ast)

        mutation_info["seed"] = seed
        return mutated_ast, mutation_info

    def _get_mutated_harness(
        self, original_harness_node: ast.AST, seed: int
    ) -> tuple[ast.AST | None, dict | None]:
        """Apply a mutation strategy and handle transformation errors."""
        try:
            mutated_harness_node, mutation_info = self.apply_mutation_strategy(
                original_harness_node, seed=seed
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
        setup_code: str,
        prefix: str,
        current_seed: int,
        parent_id: str,
        runtime_seed: int,
    ) -> str | None:
        """Reassemble the AST and generate the final Python source code for the child."""
        try:
            gc_tuning_code = ""
            if random.random() < 0.25:  # 25% chance to prepend GC tuning
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

            if self.differential_testing:
                mutated_core_code = ast.unparse(mutated_harness_node.body)
                mutated_core_code += "\n    return locals().copy()"
                diff_boilerplate = self._get_differential_test_boilerplate()
                return dedent(f"""
# Fuzzer-generated differential test
# Seed: {current_seed}, Parent: {parent_id}
from gc import collect
import sys
from textwrap import indent
{self.boilerplate_code}
{diff_boilerplate}
{rng_setup_code}
{setup_code}

def jit_target_{prefix}():
{indent(mutated_core_code, "    ")}

def control_{prefix}():
{indent(mutated_core_code, "    ")}

# --- Execute the 'Twin Execution' harness ---
try:
    jit_harness(jit_target_{prefix}, 500)
    jit_result = jit_target_{prefix}()
    control_result = no_jit_harness(control_{prefix})

    if not compare_results(jit_result, control_result):
        # Use repr() to get a more detailed string representation of the dicts
        raise JITCorrectnessError(f"JIT DIVERGENCE! JIT: {{repr(jit_result)}}, Control: {{repr(control_result)}}")
except JITCorrectnessError:
    # Re-raise our specific error to be caught by the log scanner
    raise
except Exception:
    # Ignore other benign errors in the generated code
    pass
""")
            else:
                child_core_tree = copy.deepcopy(parent_core_tree)
                for i, node in enumerate(child_core_tree.body):
                    if isinstance(node, ast.FunctionDef) and node.name == mutated_harness_node.name:
                        child_core_tree.body[i] = mutated_harness_node
                        break
                mutated_core_code = ast.unparse(child_core_tree)
                return f"{self.boilerplate_code}\n{gc_tuning_code}{rng_setup_code}\n{mutated_core_code}"
        except RecursionError:
            print(
                "  [!] Warning: Skipping mutation due to RecursionError during ast.unparse.",
                file=sys.stderr,
            )
            return None

    def _execute_child(
        self, source_code: str, child_source_path: Path, child_log_path: Path, parent_path: Path
    ) -> ExecutionResult | None:
        """Write the child script to a temp file, execute it, and return results."""

        try:
            child_source_path.write_text(source_code)
            with open(child_log_path, "w") as log_file:
                start_time = time.monotonic()
                result = subprocess.run(
                    ["python3", str(child_source_path)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.timeout,  # Use the configurable timeout here
                    env=ENV,
                )
                end_time = time.monotonic()

            return ExecutionResult(
                returncode=result.returncode,
                log_path=child_log_path,
                source_path=child_source_path,
                execution_time_ms=int((end_time - start_time) * 1000),
            )
        except subprocess.TimeoutExpired:
            self.run_stats["timeouts_found"] = self.run_stats.get("timeouts_found", 0) + 1
            print("  [!!!] TIMEOUT DETECTED! Saving test case.", file=sys.stderr)
            log_to_save = child_log_path
            try:
                if child_log_path.stat().st_size > TIMEOUT_LOG_COMPRESSION_THRESHOLD:
                    print("  [*] Timeout log is large, compressing with zstd...", file=sys.stderr)
                    compressed_log_path = child_log_path.with_suffix(".log.zst")

                    log_content = child_log_path.read_bytes()
                    compressed_content = zstd.compress(log_content)
                    compressed_log_path.write_bytes(compressed_content)

                    log_to_save = compressed_log_path
                    # Clean up the original large log file
                    child_log_path.unlink()
            except Exception as e:
                print(f"  [!] Warning: Could not compress timeout log: {e}", file=sys.stderr)

            timeout_source_path = (
                TIMEOUTS_DIR / f"timeout_{child_source_path.stem}_{parent_path.name}"
            )
            timeout_log_path = timeout_source_path.with_suffix(
                log_to_save.suffix
            )  # Use the correct suffix

            if log_to_save.exists():
                shutil.copy(child_source_path, timeout_source_path)
                shutil.copy(log_to_save, timeout_log_path)

                if log_to_save != child_log_path:
                    log_to_save.unlink()
            return None
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
            )

    def _handle_analysis_data(
        self, analysis_data: dict, i: int, parent_metadata: dict
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

            setup_code = ast.unparse(setup_nodes)
            core_logic_to_mutate = base_harness_node
            prefix = base_harness_node.name.replace("uop_harness_", "")

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
                    core_logic_to_mutate, mutation_seed
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
                            setup_code,
                            prefix,
                            mutation_seed,
                            parent_id,
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

                        flow_control = self._handle_analysis_data(
                            analysis_data, mutation_index, parent_metadata
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
                            else:
                                print(
                                    f"Error processing log named {child_log_path.stem}, file doesn't exist!"
                                )

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

    def _check_for_divergence(self, log_content: str, source_path: Path, log_path: Path) -> bool:
        """Check for correctness divergences and save artifacts."""
        if "JITCorrectnessError" in log_content:
            print("  [!!!] DIVERGENCE DETECTED! Saving test case and log.", file=sys.stderr)
            divergence_path = DIVERGENCES_DIR / f"divergence_{source_path.name}"
            shutil.copy(source_path, divergence_path)
            shutil.copy(log_path, divergence_path.with_suffix(".log"))
            return True
        return False

    def _check_for_crash(
        self, return_code: int, log_content: str, source_path: Path, log_path: Path
    ) -> bool:
        """Check for crashes and save artifacts."""
        if return_code != 0:
            if "IndentationError: too many levels of indentation" in log_content:
                print(
                    "  [~] Ignoring known-uninteresting IndentationError (too deep).",
                    file=sys.stderr,
                )
                return False
            elif "SyntaxError: too many statically nested blocks" in log_content:
                print(
                    "  [~] Ignoring known-uninteresting SyntaxError (too nested).", file=sys.stderr
                )
                return False

            print(f"  [!!!] CRASH DETECTED! Exit code: {return_code}. Saving...", file=sys.stderr)
            crash_path = CRASHES_DIR / f"crash_retcode_{source_path.name}"
            shutil.copy(source_path, crash_path)
            shutil.copy(log_path, crash_path.with_suffix(".log"))
            return True
        for keyword in CRASH_KEYWORDS:
            if keyword.lower() in log_content.lower():
                print(
                    f"  [!!!] CRASH DETECTED! Found keyword '{keyword}'. Saving...", file=sys.stderr
                )
                crash_path = CRASHES_DIR / f"crash_keyword_{source_path.name}"
                shutil.copy(source_path, crash_path)
                shutil.copy(log_path, crash_path.with_suffix(".log"))
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

    def _score_and_decide_interestingness(
        self,
        coverage_info: NewCoverageInfo,
        parent_id: str | None,
        mutation_info: dict,
        parent_file_size: int,
        parent_lineage_edge_count: int,
        child_file_size: int,
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
            coverage_info, parent_file_size, parent_lineage_edge_count, child_file_size
        )
        score = scorer.calculate_score()

        if score >= scorer.MIN_INTERESTING_SCORE:
            print(f"  [+] Child IS interesting with score: {score:.2f}", file=sys.stderr)
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
        log_content = ""
        try:
            log_content = exec_result.log_path.read_text()
        except IOError as e:
            print(f"  [!] Warning: Could not read log file for analysis: {e}", file=sys.stderr)

        if is_differential_mode and self._check_for_divergence(
            log_content, exec_result.source_path, exec_result.log_path
        ):
            return {"status": "DIVERGENCE"}

        if self._check_for_crash(
            exec_result.returncode, log_content, exec_result.source_path, exec_result.log_path
        ):
            return {"status": "CRASH"}

        child_coverage = parse_log_for_edge_coverage(exec_result.log_path, self.coverage_manager)

        coverage_info = self._find_new_coverage(child_coverage, parent_lineage_profile, parent_id)

        is_interesting = self._score_and_decide_interestingness(
            coverage_info,
            parent_id,
            mutation_info,
            parent_file_size,
            parent_lineage_edge_count,
            len(exec_result.source_path.read_text().encode("utf-8")),
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
            }

        return {"status": "NO_CHANGE"}

    def _log_timeseries_datapoint(self):
        """Append a snapshot of the current run statistics to the time-series log."""
        # Create a snapshot of the current stats for logging.
        datapoint = self.run_stats.copy()
        datapoint["timestamp"] = datetime.now(timezone.utc).isoformat()

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

    def _get_differential_test_boilerplate(self) -> str:
        """Return the boilerplate code required for differential testing."""
        return dedent("""
            import math
            import types

            # Define a custom exception to distinguish our check from others.
            class JITCorrectnessError(AssertionError): pass

            # This function is called only once, so it will not be JIT-compiled.
            def no_jit_harness(func, *args, **kwargs):
                return func(*args, **kwargs)

            # This function calls its target in a loop to make it 'hot' for the JIT.
            def jit_harness(func, iterations, *args, **kwargs):
                for _ in range(iterations):
                    func(*args, **kwargs)

            # Helper for correctness testing that handles NaN, lambdas, and complex numbers.
            def compare_results(a, b):
                if isinstance(a, types.FunctionType) and a.__name__ == '<lambda>' and \\
                   isinstance(b, types.FunctionType) and b.__name__ == '<lambda>':
                    return True # Treat two lambdas as equal for our purposes

                if isinstance(a, complex) and isinstance(b, complex):
                    a_real_nan = math.isnan(a.real)
                    b_real_nan = math.isnan(b.real)
                    a_imag_nan = math.isnan(a.imag)
                    b_imag_nan = math.isnan(b.imag)
                    real_match = (a.real == b.real) or (a_real_nan and b_real_nan)
                    imag_match = (a.imag == b.imag) or (a_imag_nan and b_imag_nan)
                    return real_match and imag_match

                if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
                    return True

                # For generic objects, we can't reliably compare, so we assume they are equivalent
                # if they are not one of the well-defined types we can compare.
                if type(a).__module__ != 'builtins' or type(b).__module__ != 'builtins':
                    return True

                return a == b
        """)

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
                    ["python3", str(test_file_path)],
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

    try:
        # --- Create and Write the Informative Header ---
        header = f"""
================================================================================
LAFLEUR FUZZER RUN
================================================================================
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
