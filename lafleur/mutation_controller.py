"""
Mutation strategy controller for the lafleur fuzzer.

This module provides the MutationController class ("The Alchemist") which handles:
- Applying various mutation strategies (deterministic, havoc, spam, sniper, etc.)
- Managing the mutation pipeline and AST transformations
- Preparing child scripts from mutated ASTs
- Extracting boilerplate and core code from source files
"""

import ast
import copy
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from textwrap import dedent
from typing import TYPE_CHECKING, Any, Callable, cast

from lafleur.mutators import (
    ASTMutator,
    EmptyBodySanitizer,
    FuzzerSetupNormalizer,
    HarnessInstrumentor,
    SlicingMutator,
    VariableRenamer,
)
from lafleur.mutators.sniper import SniperMutator
from lafleur.mutators.helper_injection import HelperFunctionInjector

if TYPE_CHECKING:
    from lafleur.corpus_manager import CorpusManager
    from lafleur.learning import MutatorScoreTracker

# Module-level RNG for mutation operations
RANDOM = random.Random()

# Boilerplate markers for extracting core code
BOILERPLATE_START_MARKER = "# FUSIL_BOILERPLATE_START"
BOILERPLATE_END_MARKER = "# FUSIL_BOILERPLATE_END"


class MutationController:
    """
    Controls mutation strategy selection and application.

    This class handles applying various mutation strategies to ASTs,
    managing the mutation pipeline, preparing child scripts, and
    extracting boilerplate/core code from source files.
    """

    def __init__(
        self,
        ast_mutator: "ASTMutator",
        score_tracker: "MutatorScoreTracker",
        corpus_manager: "CorpusManager",
        differential_testing: bool = False,
    ):
        """
        Initialize the MutationController.

        Args:
            ast_mutator: ASTMutator instance for applying transformations
            score_tracker: MutatorScoreTracker for adaptive strategy selection
            corpus_manager: CorpusManager for parent selection in splicing
            differential_testing: Whether differential testing mode is enabled
        """
        self.ast_mutator = ast_mutator
        self.score_tracker = score_tracker
        self.corpus_manager = corpus_manager
        self.differential_testing = differential_testing
        self.boilerplate_code: str | None = None

    def get_boilerplate(self) -> str:
        """Return the cached boilerplate code."""
        return self.boilerplate_code or ""

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

    def _get_nodes_from_parent(
        self, parent_path: Path
    ) -> tuple[ast.FunctionDef, ast.Module, list[ast.stmt]] | tuple[None, None, None]:
        """Parse a parent file and extract its setup and harness AST nodes."""
        try:
            parent_source = parent_path.read_text()
            if self.boilerplate_code is None:
                self._extract_and_cache_boilerplate(parent_source)
            parent_core_code = self._get_core_code(parent_source)
            parent_core_tree = ast.parse(parent_core_code)

            normalizer = FuzzerSetupNormalizer()
            # The normalizer preserves Module structure, so cast to maintain type
            parent_core_tree = cast(ast.Module, normalizer.visit(parent_core_tree))
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

    def _run_slicing(
        self, base_ast: ast.AST, stage_name: str, len_body: int, seed: int | None = None
    ) -> tuple[ast.AST, dict[str, Any]]:
        """A helper to apply a mutation pipeline to a slice of a large AST."""
        print(
            f"  [~] Large AST detected ({len_body} statements), running SLICING stage...",
            file=__import__("sys").stderr,
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
            print(
                f"    -> Slicing and Spamming with: {chosen_class.__name__}",
                file=__import__("sys").stderr,
            )

        else:  # Havoc
            num_mutations = random.randint(15, 50)
            chosen_classes = random.choices(self.ast_mutator.transformers, k=num_mutations)
            pipeline = [cls() for cls in chosen_classes]

        slicer = SlicingMutator(pipeline)
        tree = slicer.visit(base_ast)
        mutation_info = {"strategy": f"slicing_{stage_name}", "transformers": ["SlicingMutator"]}
        return tree, mutation_info

    def _run_deterministic_stage(
        self, base_ast: ast.AST, seed: int, **kwargs: Any
    ) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a single, seeded, deterministic mutation."""
        len_harness = (
            len(base_ast.body) if isinstance(base_ast, (ast.Module, ast.FunctionDef)) else 0
        )
        if len_harness > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "deterministic", len_harness, seed=seed)

        print(
            f"  [~] Running DETERMINISTIC stage ({len_harness} statements)...",
            file=__import__("sys").stderr,
        )
        mutated_ast, transformers_used = self.ast_mutator.mutate_ast(base_ast, seed=seed)
        mutation_info = {
            "strategy": "deterministic",
            "transformers": [t.__name__ for t in transformers_used],
        }
        return mutated_ast, mutation_info

    def _run_havoc_stage(self, base_ast: ast.AST, **kwargs: Any) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a random stack of many different mutations to the AST."""
        len_harness = (
            len(base_ast.body) if isinstance(base_ast, (ast.Module, ast.FunctionDef)) else 0
        )
        if len_harness > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "havoc", len_harness)

        print(
            f"  [~] Running HAVOC stage ({len_harness} statements)...",
            file=__import__("sys").stderr,
        )
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

    def _run_spam_stage(self, base_ast: ast.AST, **kwargs: Any) -> tuple[ast.AST, dict[str, Any]]:
        """Repeatedly apply the same type of mutation to the AST."""
        len_harness = (
            len(base_ast.body) if isinstance(base_ast, (ast.Module, ast.FunctionDef)) else 0
        )
        if len_harness > SlicingMutator.MIN_STATEMENTS_FOR_SLICE:
            return self._run_slicing(base_ast, "spam", len_harness)

        print(
            f"  [~] Running SPAM stage ({len_harness} statements)...",
            file=__import__("sys").stderr,
        )
        tree = base_ast
        num_spam_mutations = RANDOM.randint(20, 50)

        transformer_names = [t.__name__ for t in self.ast_mutator.transformers]
        dynamic_weights = self.score_tracker.get_weights(transformer_names)

        chosen_transformer_class = random.choices(
            self.ast_mutator.transformers, weights=dynamic_weights, k=1
        )[0]
        print(
            f"    -> Spamming with: {chosen_transformer_class.__name__}",
            file=__import__("sys").stderr,
        )

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

    def _run_splicing_stage(
        self, base_core_ast: ast.AST | list[ast.stmt], **kwargs: Any
    ) -> ast.AST | list[ast.stmt]:
        """Perform a crossover by splicing the harness from a second parent."""
        print("  [~] Attempting SPLICING stage...", file=__import__("sys").stderr)

        # Handle both Module and list inputs
        if isinstance(base_core_ast, ast.Module):
            base_body = base_core_ast.body
        elif isinstance(base_core_ast, list):
            base_body = base_core_ast
        else:
            return base_core_ast

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
        setup_nodes_a = [n for n in base_body if not isinstance(n, ast.FunctionDef)]
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
                    file=__import__("sys").stderr,
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
        self, base_ast: ast.AST, seed: int, watched_keys: list[str] | None = None, **kwargs: Any
    ) -> tuple[ast.AST, dict[str, Any]]:
        """Apply the SniperMutator if watched keys are available."""
        if not watched_keys:
            # Fallback to havoc if no intelligence available
            return self._run_havoc_stage(base_ast, seed=seed, **kwargs)

        print(
            f"  [~] Running SNIPER stage (Targets: {', '.join(watched_keys[:3])})...",
            file=__import__("sys").stderr,
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
        self, base_ast: ast.AST, seed: int, **kwargs: Any
    ) -> tuple[ast.AST, dict[str, Any]]:
        """
        Combined strategy: Inject helpers, then attack them with Sniper.

        This strategy ensures HelperFunctionInjector and SniperMutator work together:
        1. HelperFunctionInjector creates/detects _jit_helper_* functions
        2. SniperMutator targets those helpers for invalidation attacks

        This solves the feedback problem: the combined strategy gets credit
        for any interesting behavior, allowing both mutators to evolve together.
        """
        print("  [~] Running HELPER+SNIPER stage...", file=__import__("sys").stderr)
        tree = copy.deepcopy(base_ast)

        # Stage 1: Inject helpers (or detect existing ones)
        helper_injector = HelperFunctionInjector(probability=1.0)  # Always apply in this strategy
        tree = helper_injector.visit(tree)
        ast.fix_missing_locations(tree)

        detected_helpers = helper_injector.helpers_injected
        if not detected_helpers:
            # No helpers available, fall back to havoc
            print(
                "  [!] No helpers available, falling back to havoc", file=__import__("sys").stderr
            )
            return self._run_havoc_stage(base_ast, seed=seed, **kwargs)

        print(
            f"  [~] Detected {len(detected_helpers)} helper(s): {detected_helpers}",
            file=__import__("sys").stderr,
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

        MutationStrategy = Callable[..., tuple[ast.AST, dict[str, Any]]]
        strategy_candidates: list[MutationStrategy] = [
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

    def get_mutated_harness(
        self, original_harness_node: ast.AST, seed: int, watched_keys: list[str] | None = None
    ) -> tuple[ast.AST | None, dict[str, Any] | None]:
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
                file=__import__("sys").stderr,
            )
            return None, None

    def prepare_child_script(
        self,
        parent_core_tree: ast.Module,
        mutated_harness_node: ast.AST,
        runtime_seed: int,
    ) -> str | None:
        """Reassemble the AST and generate the final Python source code for the child."""
        try:
            gc_tuning_code = ""
            if random.random() < 0.25:
                print("    -> Prepending GC pressure to test case", file=__import__("sys").stderr)
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
            # The mutated harness should be a FunctionDef
            if not isinstance(mutated_harness_node, ast.FunctionDef):
                return None
            for i, node in enumerate(child_core_tree.body):
                if isinstance(node, ast.FunctionDef) and node.name == mutated_harness_node.name:
                    child_core_tree.body[i] = mutated_harness_node
                    break

            if self.differential_testing:
                instrumentor = HarnessInstrumentor()
                child_core_tree = instrumentor.visit(child_core_tree)

            boilerplate = self.get_boilerplate()
            mutated_core_code = ast.unparse(child_core_tree)
            return f"{boilerplate}\n{gc_tuning_code}{rng_setup_code}\n{mutated_core_code}"
        except RecursionError:
            print(
                "  [!] Warning: Skipping mutation due to RecursionError during ast.unparse.",
                file=__import__("sys").stderr,
            )
            return None
