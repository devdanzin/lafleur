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
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent, indent
from typing import Any
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

from lafleur.corpus_manager import CorpusManager
from lafleur.coverage import parse_log_for_edge_coverage, load_coverage_state
from lafleur.mutator import ASTMutator, VariableRenamer
from lafleur.utils import ExecutionResult, TeeLogger, load_run_stats, save_run_stats

RANDOM = random.Random()

# --- Paths for Fuzzer Outputs (relative to current working directory) ---
# This allows running multiple fuzzer instances from different directories.
TMP_DIR = Path("tmp_fuzz_run")
CRASHES_DIR = Path("crashes")
TIMEOUTS_DIR = Path("timeouts")
DIVERGENCES_DIR = Path("divergences")
LOGS_DIR = Path("logs")
COVERAGE_DIR = Path("coverage")
COVERAGE_STATE_FILE = COVERAGE_DIR / "coverage_state.pkl"

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


class LafleurOrchestrator:
    """
    Manage the main evolutionary fuzzing loop.

    Select interesting test cases from the corpus, apply mutation
    strategies, execute the mutated children, and analyze the results
    for new coverage.
    """

    def __init__(
        self, fusil_path: str, min_corpus_files: int = 1, differential_testing: bool = False
    ):
        """Initialize the orchestrator and the corpus manager."""
        self.differential_testing = differential_testing
        self.fusil_path = fusil_path
        self.ast_mutator = ASTMutator()
        self.boilerplate_code = None

        self.coverage_state = load_coverage_state()
        self.run_stats = load_run_stats()

        self.min_corpus_files = min_corpus_files
        self.corpus_manager = CorpusManager(
            self.coverage_state, self.run_stats, fusil_path, self.get_boilerplate
        )
        # Synchronize the corpus and state at startup.
        self.corpus_manager.synchronize(self.analyze_run, self._build_lineage_profile)

        self.mutations_since_last_find = 0
        self.global_seed_counter = self.run_stats.get("global_seed_counter", 0)

        # Ensure temporary aand corpus directories exist
        TMP_DIR.mkdir(exist_ok=True)
        CRASHES_DIR.mkdir(exist_ok=True)
        TIMEOUTS_DIR.mkdir(exist_ok=True)
        DIVERGENCES_DIR.mkdir(exist_ok=True)
        LOGS_DIR.mkdir(exist_ok=True)

        run_timestamp = self.run_stats.get("start_time", datetime.now(timezone.utc).isoformat())
        # Sanitize timestamp for use in filename
        safe_timestamp = run_timestamp.replace(":", "-").replace("+", "Z")
        self.timeseries_log_path = LOGS_DIR / f"timeseries_{safe_timestamp}.jsonl"
        logger.info(  # Replaced print
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
            logger.info("[+] Boilerplate code extracted and cached.")  # Replaced print
        except ValueError:
            logger.warning(  # Replaced print
                "[!] Warning: Could not find boilerplate markers in the initial seed file."
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
        current_corpus_size = len(self.coverage_state.get("per_file_coverage", {}))
        needed = self.min_corpus_files - current_corpus_size

        if needed > 0:
            logger.info(  # Replaced print
                f"[*] Corpus size ({current_corpus_size}) is less than minimum ({self.min_corpus_files}). Need to generate {needed} more file(s)."
            )

            if not self.corpus_manager.fusil_path_is_valid:
                logger.warning("[!] WARNING: Cannot generate new seed files.")  # Replaced print
                if self.fusil_path:
                    logger.warning(  # Replaced print
                        f"    Reason: Provided --fusil-path '{self.fusil_path}' is not a valid executable file."
                    )
                else:
                    logger.warning(  # Replaced print
                        "    Reason: The --fusil-path argument was not provided."
                    )

                if current_corpus_size > 0:
                    logger.warning(  # Replaced print
                        f"[*] Proceeding with the {current_corpus_size} existing file(s). To enforce the minimum, please provide a valid path."
                    )
                else:
                    logger.critical(  # Replaced print
                        "[!!!] CRITICAL: The corpus is empty and no valid seeder is available. Halting."
                    )
                    sys.exit(1)  # Unrecoverable state
            else:
                # Seeder is available, generate the needed files
                logger.info("[*] Starting corpus generation phase...")  # Replaced print
                for _ in range(needed):
                    self.corpus_manager.generate_new_seed(
                        self.analyze_run, self._build_lineage_profile
                    )
                logger.info(  # Replaced print
                    f"[+] Corpus generation complete. New size: {len(self.coverage_state['per_file_coverage'])}."
                )

        logger.info(
            "[+] Starting Deep Fuzzer Evolutionary Loop. Press Ctrl+C to stop."
        )  # Replaced print
        try:
            while True:
                self.run_stats["total_sessions"] = self.run_stats.get("total_sessions", 0) + 1
                session_num = self.run_stats["total_sessions"]
                logger.info(
                    f"\n--- Fuzzing Session #{self.run_stats['total_sessions']} ---"
                )  # Replaced print

                # 1. Selection
                selection = self.corpus_manager.select_parent()

                # This should now only happen if min_corpus_files is 0 and corpus is empty.
                if selection is None:
                    logger.info(
                        "[!] Corpus is empty and no minimum size was set. Halting."
                    )  # Replaced print
                    return
                else:
                    parent_path, parent_score = selection
                    logger.info(  # Replaced print
                        f"[+] Selected parent for mutation: {parent_path.name} (Score: {parent_score:.2f})"
                    )
                    self.execute_mutation_and_analysis_cycle(
                        parent_path, parent_score, self.run_stats["total_sessions"]
                    )

                # Update dynamic stats after each session
                self.update_and_save_run_stats()
                if session_num % 10 == 0:
                    logger.info(
                        f"[*] Logging time-series data point at session {session_num}..."
                    )  # Replaced print
                    self._log_timeseries_datapoint()
        finally:
            logger.info("\n[+] Fuzzing loop terminating. Saving final stats...")  # Replaced print
            self.update_and_save_run_stats()
            self._log_timeseries_datapoint()  # Log one final data point on exit

    def update_and_save_run_stats(self) -> None:
        """Update dynamic run statistics and save them to the stats file."""
        self.run_stats["last_update_time"] = datetime.now(timezone.utc).isoformat()
        self.run_stats["corpus_size"] = len(self.coverage_state.get("per_file_coverage", {}))
        global_cov = self.coverage_state.get("global_coverage", {})
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

    def _run_deterministic_stage(
        self, base_ast: ast.AST, seed: int, **kwargs
    ) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a single, seeded, deterministic mutation."""
        mutated_ast, transformers_used = self.ast_mutator.mutate_ast(base_ast, seed=seed)
        mutation_info = {
            "strategy": "deterministic",
            "transformers": [t.__name__ for t in transformers_used],
        }
        return mutated_ast, mutation_info

    def _run_havoc_stage(self, base_ast: ast.AST, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a random stack of many different mutations to the AST."""
        logger.info("  [~] Running HAVOC stage...")  # Replaced print
        tree = base_ast  # Start with the copied tree from the dispatcher
        num_havoc_mutations = RANDOM.randint(15, 50)
        transformers_applied = []

        for _ in range(num_havoc_mutations):
            transformer_class = RANDOM.choice(self.ast_mutator.transformers)
            transformers_applied.append(transformer_class.__name__)
            tree = transformer_class().visit(tree)

        ast.fix_missing_locations(tree)
        mutation_info = {"strategy": "havoc", "transformers": transformers_applied}
        return tree, mutation_info

    def _run_spam_stage(self, base_ast: ast.AST, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """Repeatedly apply the same type of mutation to the AST."""
        logger.info("  [~] Running SPAM stage...")  # Replaced print
        tree = base_ast
        num_spam_mutations = RANDOM.randint(20, 50)

        # Choose one single type of mutation to spam
        chosen_transformer_class = RANDOM.choice(self.ast_mutator.transformers)
        logger.info(f"    -> Spamming with: {chosen_transformer_class.__name__}")  # Replaced print

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
        logger.info("  [~] Attempting SPLICING stage...")  # Replaced print

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
                logger.info(  # Replaced print
                    f"    -> Splice failed: No var of type '{required_type}' for '{required_var}'"
                )
                is_possible = False
                break

        if not is_possible:
            return base_core_ast

        logger.info(f"    -> Remapping successful: {remapping_dict}")  # Replaced print

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

        strategies = [
            self._run_deterministic_stage,
            self._run_havoc_stage,
            self._run_spam_stage,
            # self._run_splicing_stage,
        ]
        weights = [0.85, 0.10, 0.05]

        tree_copy = copy.deepcopy(base_ast)
        chosen_strategy = RANDOM.choices(strategies, weights=weights, k=1)[0]

        # The `seed` argument is used by the deterministic stage for its own
        # seeding, and the other stages use the globally seeded RANDOM instance.
        mutated_ast, mutation_info = chosen_strategy(tree_copy, seed=seed)
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
            return mutated_harness_node, mutation_info
        except RecursionError:
            logger.warning(  # Replaced print
                "  [!] Warning: Skipping mutation due to RecursionError during AST transformation."
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
    ) -> str | None:
        """Reassemble the AST and generate the final Python source code for the child."""
        try:
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
                return f"{self.boilerplate_code}\n{mutated_core_code}"
        except RecursionError:
            logger.warning(  # Replaced print
                "  [!] Warning: Skipping mutation due to RecursionError during ast.unparse."
            )
            return None

    def _execute_child(
        self, source_code: str, session_id: int, mutation_index: int
    ) -> ExecutionResult | None:
        """Write the child script to a temp file, execute it, and return results."""
        child_source_path = TMP_DIR / f"child_{session_id}_{mutation_index}.py"
        child_log_path = TMP_DIR / f"child_{session_id}_{mutation_index}.log"

        try:
            child_source_path.write_text(source_code)
            with open(child_log_path, "w") as log_file:
                start_time = time.monotonic()
                result = subprocess.run(
                    ["python3", str(child_source_path)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=10,
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
            logger.info("  [!!!] TIMEOUT DETECTED! Saving test case.")  # Replaced print
            timeout_path = (
                TIMEOUTS_DIR / f"timeout_{session_id}_{mutation_index}_{child_source_path.name}"
            )
            shutil.copy(child_source_path, timeout_path)
            shutil.copy(child_log_path, timeout_path.with_suffix(".log"))
            return None
        except Exception as e:
            logger.error(f"  [!] Error during child execution: {e}")  # Replaced print
            return None

    def _handle_analysis_data(
        self, analysis_data: dict, i: int, parent_metadata: dict
    ) -> str | None:
        """Process the result from analyze_run and update fuzzer state."""
        if analysis_data["status"] == "DIVERGENCE":
            self.run_stats["divergences_found"] = self.run_stats.get("divergences_found", 0) + 1
            self.mutations_since_last_find = 0
            logger.info(  # Replaced print
                f"  [***] SUCCESS! Mutation #{i + 1} found a correctness divergence. Moving to next parent."
            )
            return "BREAK"  # A divergence is a major find, move to the next parent
        elif analysis_data["status"] == "CRASH":
            self.run_stats["crashes_found"] = self.run_stats.get("crashes_found", 0) + 1
            return "CONTINUE"
        elif analysis_data["status"] == "NEW_COVERAGE":
            self.run_stats["new_coverage_finds"] += 1
            self.run_stats["sum_of_mutations_per_find"] += self.mutations_since_last_find
            self.mutations_since_last_find = 0
            logger.info(
                f"  [***] SUCCESS! Mutation #{i + 1} found new coverage. Moving to next parent."
            )  # Replaced print
            parent_metadata["total_finds"] = parent_metadata.get("total_finds", 0) + 1
            parent_metadata["mutations_since_last_find"] = 0
            self.corpus_manager.add_new_file(
                core_code=analysis_data["core_code"],
                baseline_coverage=analysis_data["baseline_coverage"],
                content_hash=analysis_data["content_hash"],
                execution_time_ms=analysis_data["execution_time_ms"],
                parent_id=analysis_data["parent_id"],
                mutation_info=analysis_data["mutation_info"],
                mutation_seed=analysis_data["mutation_seed"],
                build_lineage_func=self._build_lineage_profile,
            )
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
        except (IOError, SyntaxError) as e:
            logger.error(
                f"[!] Error processing parent file {parent_path.name}: {e}"
            )  # Replaced print
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
            logger.warning(  # Replaced print
                f"[-] No harness function found in {parent_path.name}. Skipping."
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
        logger.info(  # Replaced print
            f"[+] Dynamically adjusting mutation count based on score. Base: {base_mutations}, "
            f"Multiplier: {final_multiplier:.2f}, Final Count: {max_mutations}"
        )
        return max_mutations

    def execute_mutation_and_analysis_cycle(
        self, parent_path: Path, parent_score: float, session_id: int
    ):
        """Take a parent test case and run a full cycle of mutation and analysis."""
        max_mutations = self._calculate_mutations(parent_score)

        parent_id = parent_path.name
        parent_metadata = self.coverage_state["per_file_coverage"].get(parent_id, {})
        parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})

        base_harness_node, parent_core_tree, setup_nodes = self._get_nodes_from_parent(parent_path)
        if base_harness_node is None:
            return

        setup_code = ast.unparse(setup_nodes)
        core_logic_to_mutate = base_harness_node
        prefix = base_harness_node.name.replace("uop_harness_", "")
        # --- Main Mutation Loop ---
        for i in range(max_mutations):
            self.run_stats["total_mutations"] = self.run_stats.get("total_mutations", 0) + 1
            self.mutations_since_last_find += 1
            self.global_seed_counter += 1
            current_seed = self.global_seed_counter
            logger.info(  # Replaced print
                f"  \\-> Running mutation #{i + 1} (Seed: {current_seed}) for {parent_path.name}..."
            )

            try:
                mutated_harness_node, mutation_info = self._get_mutated_harness(
                    core_logic_to_mutate, current_seed
                )
                if not mutated_harness_node:
                    continue
                # self.debug_mutation_differences(core_logic_to_mutate, mutated_body_ast, current_seed)

            except RecursionError:
                logger.warning(  # Replaced print
                    "  [!] Warning: Skipping mutation due to RecursionError during AST transformation."
                )
                continue

            child_source_path = TMP_DIR / f"child_{session_id}_{i + 1}.py"
            child_log_path = TMP_DIR / f"child_{session_id}_{i + 1}.log"

            try:
                child_source = self._prepare_child_script(
                    parent_core_tree,
                    mutated_harness_node,
                    setup_code,
                    prefix,
                    current_seed,
                    parent_id,
                )
                if not child_source:
                    continue
            except RecursionError:
                logger.warning(  # Replaced print
                    "  [!] Warning: Skipping mutation due to RecursionError during ast.unparse."
                )
                continue
            try:
                # --- Execute and Analyze Child ---
                exec_result = self._execute_child(child_source, session_id, i + 1)
                if not exec_result:
                    continue

                analysis_data = self.analyze_run(
                    exec_result, parent_lineage_profile, parent_id, mutation_info, current_seed
                )

                # --- Handle Analysis Result ---
                flow_control = self._handle_analysis_data(analysis_data, i, parent_metadata)
                if flow_control == "BREAK":
                    break
                elif flow_control == "CONTINUE":
                    continue
            except subprocess.TimeoutExpired:
                self.run_stats["timeouts_found"] = self.run_stats.get("timeouts_found", 0) + 1
                logger.info("  [!!!] TIMEOUT DETECTED! Saving test case.")  # Replaced print
                timeout_source_path = (
                    TIMEOUTS_DIR / f"timeout_{session_id}_{i + 1}_{parent_path.name}"
                )
                timeout_log_path = timeout_source_path.with_suffix(".log")
                shutil.copy(child_source_path, timeout_source_path)
                shutil.copy(child_log_path, timeout_log_path)
                continue
            except Exception as e:
                logger.error(f"  [!] Error executing child process: {e}")  # Replaced print
                continue  # Move to the next mutation
            finally:
                try:
                    if child_source_path.exists():
                        # self.verify_jit_determinism(child_source_path, 25)
                        child_source_path.unlink()
                    if child_log_path.exists():
                        child_log_path.unlink()
                except OSError as e:
                    logger.warning(
                        f"  [!] Warning: Could not delete temp file: {e}"
                    )  # Replaced print

    def _check_for_divergence(self, log_content: str, source_path: Path, log_path: Path) -> bool:
        """Check for correctness divergences and save artifacts."""
        if "JITCorrectnessError" in log_content:
            logger.info("  [!!!] DIVERGENCE DETECTED! Saving test case and log.")  # Replaced print
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
            logger.info(
                f"  [!!!] CRASH DETECTED! Exit code: {return_code}. Saving..."
            )  # Replaced print
            crash_path = CRASHES_DIR / f"crash_retcode_{source_path.name}"
            shutil.copy(source_path, crash_path)
            shutil.copy(log_path, crash_path.with_suffix(".log"))
            return True
        for keyword in CRASH_KEYWORDS:
            if keyword.lower() in log_content.lower():
                logger.info(  # Replaced print
                    f"  [!!!] CRASH DETECTED! Found keyword '{keyword}'. Saving..."
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
        mutation_info: dict,
    ) -> bool:
        """
        Perform a read-only check to see if a child has new coverage.

        Return True if new coverage is found, False otherwise.
        """
        is_interesting = False
        # --- PASS 1: Unified Read-Only Check for Interestingness ---
        for harness_id, child_data in child_coverage.items():
            lineage_harness_data = parent_lineage_profile.get(harness_id, {})
            for cov_type in ["uops", "edges", "rare_events"]:
                lineage_set = lineage_harness_data.get(cov_type, set())
                global_set = self.coverage_state["global_coverage"].get(cov_type, {})
                for item in child_data.get(cov_type, {}):
                    if item not in global_set:
                        logger.info(  # Replaced print
                            f"[NEW GLOBAL {cov_type.upper()[:-1]}] '{item}' in harness '{harness_id}'"
                        )
                        is_interesting = True
                    elif parent_id is not None and item not in lineage_set:
                        logger.info(  # Replaced print
                            f"[NEW RELATIVE {cov_type.upper()[:-1]}] '{item}' in harness '{harness_id}'"
                        )
                        is_interesting = True
            if is_interesting and parent_id is not None:
                break

        # --- Apply special rules for SEED files ---
        if parent_id is None:
            is_generative_seed = mutation_info.get("strategy") == "generative_seed"
            if child_coverage or is_generative_seed:
                is_interesting = True
            elif not is_interesting:
                logger.info("  [~] Seed file produced no JIT coverage. Skipping.")  # Replaced print

        return is_interesting

    def _update_global_coverage(self, child_coverage: dict):
        """Commit the coverage from a new, interesting child to the global state."""
        global_coverage = self.coverage_state["global_coverage"]
        for harness_id, data in child_coverage.items():
            for cov_type in ["uops", "edges", "rare_events"]:
                global_coverage.setdefault(cov_type, {})
                for item, count in data.get(cov_type, {}).items():
                    global_coverage[cov_type].setdefault(item, 0)
                    global_coverage[cov_type][item] += count

    def analyze_run(
        self,
        exec_result: ExecutionResult,
        parent_lineage_profile: dict,
        parent_id: str | None,
        mutation_info: dict,
        mutation_seed: int,
        is_differential_mode: bool = False,
    ) -> dict:
        """Orchestrate the analysis of a run and return a dictionary of findings."""
        log_content = ""
        try:
            log_content = exec_result.log_path.read_text()
        except IOError as e:
            logger.warning(
                f"  [!] Warning: Could not read log file for analysis: {e}"
            )  # Replaced print

        if is_differential_mode and self._check_for_divergence(
            log_content, exec_result.source_path, exec_result.log_path
        ):
            return {"status": "DIVERGENCE"}

        if self._check_for_crash(
            exec_result.returncode, log_content, exec_result.source_path, exec_result.log_path
        ):
            return {"status": "CRASH"}

        child_coverage = parse_log_for_edge_coverage(exec_result.log_path)
        is_interesting = self._find_new_coverage(
            child_coverage, parent_lineage_profile, parent_id, mutation_info
        )

        if is_interesting:
            core_code_to_save = self._get_core_code(exec_result.source_path.read_text())
            content_hash = hashlib.sha256(core_code_to_save.encode("utf-8")).hexdigest()

            if content_hash in self.corpus_manager.known_hashes:
                logger.info(  # Replaced print
                    f"  [~] New coverage found, but content is a known duplicate (Hash: {content_hash[:10]}...). Skipping."
                )
                return {"status": "NO_CHANGE"}

            # This is the crucial step: if it's new and not a duplicate, we commit the coverage.
            self._update_global_coverage(child_coverage)

            return {
                "status": "NEW_COVERAGE",
                "core_code": core_code_to_save,
                "baseline_coverage": child_coverage,
                "content_hash": content_hash,
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
            logger.warning(
                f"[!] Warning: Could not write to time-series log file: {e}"
            )  # Replaced print

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
                harness_id, {"uops": set(), "edges": set(), "rare_events": set()}
            )
            for key in ["uops", "edges", "rare_events"]:
                # Get the set of items from the parent's lineage.
                lineage_set = lineage_harness.setdefault(key, set())
                # Add all the keys from the child's new coverage to the set.
                lineage_set.update(child_data.get(key, {}).keys())
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
            logger.warning(
                f"  [WARNING] Mutation with seed {seed} produced identical code!"
            )  # Replaced print
            return False

        # Compute hashes to see if different ASTs produce same unparsed code
        original_hash = hashlib.sha256(original_str.encode("utf-8")).hexdigest()[:10]
        mutated_hash = hashlib.sha256(mutated_str.encode("utf-8")).hexdigest()[:10]

        logger.debug(  # Replaced print
            f"  [DEBUG] Seed {seed}: Original hash: {original_hash}, Mutated hash: {mutated_hash}"
        )

        # Show a diff summary (just line counts for brevity)
        original_lines = original_str.count("\n")
        mutated_lines = mutated_str.count("\n")
        logger.debug(
            f"  [DEBUG] Line count change: {original_lines} -> {mutated_lines}"
        )  # Replaced print

        return True

    def verify_jit_determinism(self, test_file_path: Path, num_runs: int = 5):
        """Run the same file multiple times to check if coverage is deterministic."""
        logger.info(f"\n[*] Testing JIT determinism for {test_file_path.name}...")  # Replaced print

        coverage_sets = []
        for run in range(num_runs):
            log_path = TMP_DIR / f"determinism_test_run_{run}.log"

            with open(log_path, "w") as log_file:
                subprocess.run(
                    ["python3", str(test_file_path)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=10,
                    env=ENV,
                )

            coverage = parse_log_for_edge_coverage(log_path)

            # Collect all edges from all harnesses
            all_edges = set()
            for harness_data in coverage.values():
                all_edges.update(harness_data.get("edges", {}).keys())

            coverage_sets.append(all_edges)
            logger.info(f"  Run {run + 1}: {len(all_edges)} unique edges")  # Replaced print

        # Check if all runs produced identical coverage
        if all(s == coverage_sets[0] for s in coverage_sets):
            logger.info("  [✓] Coverage is deterministic across all runs")  # Replaced print
        else:
            logger.warning("  [!] Coverage is NON-DETERMINISTIC!")  # Replaced print
            # Show which edges are inconsistent
            all_edges_union = set().union(*coverage_sets)
            for edge in all_edges_union:
                appearances = sum(1 for s in coverage_sets if edge in s)
                if appearances != num_runs:
                    logger.warning(
                        f"    Edge '{edge}' appeared in {appearances}/{num_runs} runs"
                    )  # Replaced print


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
    args = parser.parse_args()

    LOGS_DIR.mkdir(exist_ok=True)
    # Use a consistent timestamp for the whole run
    run_start_time = datetime.now()
    timestamp_iso = run_start_time.isoformat()
    safe_timestamp = timestamp_iso.replace(":", "-").replace("+", "Z")
    orchestrator_log_path = LOGS_DIR / f"deep_fuzzer_run_{safe_timestamp}.log"

    # Configure logging at the root level for the entire application
    logging.basicConfig(
        level=logging.INFO,  # Default logging level
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(orchestrator_log_path),  # Log to file
            logging.StreamHandler(sys.stdout),  # Log to console
        ],
    )

    # This initial print goes only to the console, before TeeLogger takes over stdout
    # Removed initial print as logging is now configured to handle stdout

    termination_reason = "Completed"  # Default reason
    start_stats = load_run_stats()  # Capture stats at the start

    try:
        # --- Create and Write the Informative Header ---
        header = f"""
================================================================================
LAFLEUR FUZZER RUN
================================================================================
- Hostname:         {socket.gethostname()}
- Platform:         {platform.platform()}
- Process ID:       {os.getpid()}
- Python Version:   {sys.version.replace(chr(10), " ")}
- Working Dir:      {Path.cwd()}
- Log File:         {orchestrator_log_path}
- Start Time:       {timestamp_iso}
- Command:          {" ".join(sys.argv)}
--------------------------------------------------------------------------------
Initial Stats:
{json.dumps(start_stats, indent=4)}
================================================================================

"""
        logger.info(dedent(header))  # Replaced print with logger.info
        # --- End of Header ---

        orchestrator = LafleurOrchestrator(
            fusil_path=args.fusil_path,
            min_corpus_files=args.min_corpus_files,
            differential_testing=args.differential_testing,
        )
        orchestrator.run_evolutionary_loop()
    except KeyboardInterrupt:
        logger.info("\n[!] Fuzzing stopped by user.")  # Replaced print with logger.info
        termination_reason = "KeyboardInterrupt"
    except Exception as e:
        termination_reason = f"Error: {e}"
        logger.exception(
            "\n[!!!] An unexpected error occurred in the orchestrator: %s", e
        )  # Use logger.exception for traceback
    finally:
        # --- Create and Write the Summary Footer ---
        logger.info("\n" + "=" * 80)  # Replaced print with logger.info
        logger.info("FUZZING RUN SUMMARY")  # Replaced print with logger.info
        logger.info("=" * 80)  # Replaced print with logger.info

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
- Termination:      {termination_reason}
- End Time:         {end_time.isoformat()}
- Total Duration:   {str(duration)}

--- Discoveries This Run ---
- New Coverage:     {finds_this_run}
- New Crashes:      {crashes_this_run}

--- Performance This Run ---
- Total Executions: {mutations_this_run}
- Execs per Second: {exec_per_sec:.2f}

--- Final Campaign Stats ---
{json.dumps(end_stats, indent=4)}
================================================================================
"""
        logger.info(dedent(summary))  # Replaced print with logger.info

        # Cleanly close the log file and restore streams.
        # TeeLogger is no longer needed if logging is configured to handle stdout
        # sys.stdout and sys.stderr are managed by logging.basicConfig handlers now.
        logger.info(
            f"[+] Fuzzing session finished. Full log saved to: {orchestrator_log_path}"
        )  # Replaced print with logger.info


if __name__ == "__main__":
    main()
