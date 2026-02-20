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
from pathlib import Path
from textwrap import dedent
from typing import TYPE_CHECKING, Any, Callable, cast

from lafleur.mutators import (
    ASTMutator,
    EmptyBodySanitizer,
    FuzzerSetupNormalizer,
    HarnessInstrumentor,
    RedundantStatementSanitizer,
    SlicingMutator,
    _dump_unparse_diagnostics,
)
from lafleur.mutators.generic import ImportChaosMutator, ImportPrunerMutator, StatementDuplicator
from lafleur.mutators.sniper import SniperMutator
from lafleur.mutators.helper_injection import HelperFunctionInjector

if TYPE_CHECKING:
    from lafleur.corpus_manager import CorpusManager
    from lafleur.health import HealthMonitor
    from lafleur.learning import MutatorScoreTracker

# Module-level RNG for mutation operations
RANDOM = random.Random()

# Boilerplate markers for extracting core code
BOILERPLATE_START_MARKER = "# FUSIL_BOILERPLATE_START"
BOILERPLATE_END_MARKER = "# FUSIL_BOILERPLATE_END"

MutationStrategy = Callable[..., tuple[ast.AST, dict[str, Any]]]


class MutationController:
    """
    Controls mutation strategy selection and application.

    This class handles applying various mutation strategies to ASTs,
    managing the mutation pipeline, preparing child scripts, and
    extracting boilerplate/core code from source files.
    """

    HYGIENE_MUTATORS: list[tuple[type[ast.NodeTransformer], float]] = [
        (ImportChaosMutator, 0.15),
        (ImportPrunerMutator, 0.20),
        (StatementDuplicator, 0.08),
        (RedundantStatementSanitizer, 0.05),
    ]

    def __init__(
        self,
        ast_mutator: "ASTMutator",
        score_tracker: "MutatorScoreTracker",
        corpus_manager: "CorpusManager | None" = None,
        differential_testing: bool = False,
        forced_strategy: str | None = None,
    ):
        """
        Initialize the MutationController.

        Args:
            ast_mutator: ASTMutator instance for applying transformations
            score_tracker: MutatorScoreTracker for adaptive strategy selection
            corpus_manager: CorpusManager for parent selection in splicing.
                Can be None at construction and set later via the corpus_manager attribute.
            differential_testing: Whether differential testing mode is enabled
            forced_strategy: If set, bypass adaptive selection and always use this strategy
        """
        self.ast_mutator = ast_mutator
        self.score_tracker = score_tracker
        self.corpus_manager: CorpusManager | None = corpus_manager
        self.differential_testing = differential_testing
        self.forced_strategy = forced_strategy
        self.boilerplate_code: str | None = None
        self.health_monitor: HealthMonitor | None = None

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
            file=sys.stderr,
        )

        transformer_names = [t.__name__ for t in self.ast_mutator.transformers]
        dynamic_weights = self.score_tracker.get_weights(transformer_names)

        if stage_name == "deterministic":
            # For deterministic, we must re-seed the RNG to get the same choices
            RANDOM.seed(seed)
            num_mutations = RANDOM.randint(1, 3)
            chosen_classes = RANDOM.choices(
                self.ast_mutator.transformers, weights=dynamic_weights, k=num_mutations
            )
            pipeline = [cls() for cls in chosen_classes]

        elif stage_name == "spam":
            num_mutations = RANDOM.randint(20, 50)
            chosen_class = RANDOM.choices(
                self.ast_mutator.transformers, weights=dynamic_weights, k=1
            )[0]
            pipeline = [chosen_class() for _ in range(num_mutations)]
            print(
                f"    -> Slicing and Spamming with: {chosen_class.__name__}",
                file=sys.stderr,
            )

        else:  # Havoc
            num_mutations = RANDOM.randint(15, 50)
            chosen_classes = RANDOM.choices(
                self.ast_mutator.transformers, weights=dynamic_weights, k=num_mutations
            )
            pipeline = [cls() for cls in chosen_classes]

        # Record attempts for the actual transformers, not SlicingMutator
        for transformer in pipeline:
            self.score_tracker.record_attempt(type(transformer).__name__)

        slicer = SlicingMutator(pipeline)
        tree = slicer.visit(base_ast)

        # Credit the real transformers, not SlicingMutator
        transformers_applied = [type(t).__name__ for t in pipeline]
        mutation_info = {
            "strategy": stage_name,
            "transformers": transformers_applied,
            "sliced": True,
        }
        return tree, mutation_info

    def _run_deterministic_stage(
        self, base_ast: ast.AST, seed: int, **kwargs: Any
    ) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a single, seeded, deterministic mutation."""
        print("  [~] Running DETERMINISTIC stage...", file=sys.stderr)
        mutated_ast, transformers_used = self.ast_mutator.mutate_ast(base_ast, seed=seed)
        mutation_info = {
            "strategy": "deterministic",
            "transformers": [t.__name__ for t in transformers_used],
        }
        return mutated_ast, mutation_info

    def _run_havoc_stage(self, base_ast: ast.AST, **kwargs: Any) -> tuple[ast.AST, dict[str, Any]]:
        """Apply a random stack of many different mutations to the AST."""
        print("  [~] Running HAVOC stage...", file=sys.stderr)
        tree = base_ast  # Start with the copied tree from the dispatcher
        num_havoc_mutations = RANDOM.randint(15, 50)
        transformers_applied = []

        transformer_names = [t.__name__ for t in self.ast_mutator.transformers]
        dynamic_weights = self.score_tracker.get_weights(transformer_names)

        for _ in range(num_havoc_mutations):
            transformer_class = RANDOM.choices(
                self.ast_mutator.transformers, weights=dynamic_weights, k=1
            )[0]
            self.score_tracker.record_attempt(transformer_class.__name__)
            transformers_applied.append(transformer_class.__name__)

            tree = transformer_class().visit(tree)

        mutation_info = {"strategy": "havoc", "transformers": transformers_applied}
        return tree, mutation_info

    def _run_spam_stage(self, base_ast: ast.AST, **kwargs: Any) -> tuple[ast.AST, dict[str, Any]]:
        """Repeatedly apply the same type of mutation to the AST."""
        print("  [~] Running SPAM stage...", file=sys.stderr)
        tree = base_ast
        num_spam_mutations = RANDOM.randint(20, 50)

        transformer_names = [t.__name__ for t in self.ast_mutator.transformers]
        dynamic_weights = self.score_tracker.get_weights(transformer_names)

        chosen_transformer_class = RANDOM.choices(
            self.ast_mutator.transformers, weights=dynamic_weights, k=1
        )[0]
        print(
            f"    -> Spamming with: {chosen_transformer_class.__name__}",
            file=sys.stderr,
        )

        for _ in range(num_spam_mutations):
            # Apply a new instance of the same transformer each time
            tree = chosen_transformer_class().visit(tree)

        mutation_info = {
            "strategy": "spam",
            "transformers": [chosen_transformer_class.__name__] * num_spam_mutations,
        }
        return tree, mutation_info

    def _run_sniper_stage(
        self, base_ast: ast.AST, seed: int, watched_keys: list[str] | None = None, **kwargs: Any
    ) -> tuple[ast.AST, dict[str, Any]]:
        """Apply the SniperMutator if watched keys are available."""
        if not watched_keys:
            # Fallback to havoc, but track under sniper so the score tracker
            # correctly attributes the attempt to the strategy that was selected.
            result_ast, mutation_info = self._run_havoc_stage(base_ast, seed=seed, **kwargs)
            mutation_info["strategy"] = "sniper_fallback"
            return result_ast, mutation_info

        print(
            f"  [~] Running SNIPER stage (Targets: {', '.join(watched_keys[:3])})...",
            file=sys.stderr,
        )
        tree = copy.deepcopy(base_ast)
        mutator = SniperMutator(watched_keys)
        tree = mutator.visit(tree)

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
        print("  [~] Running HELPER+SNIPER stage...", file=sys.stderr)
        tree = copy.deepcopy(base_ast)

        # Stage 1: Inject helpers (or detect existing ones)
        helper_injector = HelperFunctionInjector(probability=1.0)  # Always apply in this strategy
        tree = helper_injector.visit(tree)

        detected_helpers = helper_injector.helpers_injected
        if not detected_helpers:
            # No helpers available, fall back to havoc
            print("  [!] No helpers available, falling back to havoc", file=sys.stderr)
            result_ast, mutation_info = self._run_havoc_stage(base_ast, seed=seed, **kwargs)
            mutation_info["strategy"] = "helper_sniper_fallback"
            return result_ast, mutation_info

        print(
            f"  [~] Detected {len(detected_helpers)} helper(s): {detected_helpers}",
            file=sys.stderr,
        )

        # Stage 2: Attack the helpers with Sniper
        sniper = SniperMutator(watched_keys=detected_helpers)
        tree = sniper.visit(tree)

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

        tree_copy = copy.deepcopy(base_ast)
        # Clean the AST of any previous fuzzer setup before applying new mutations.
        normalizer = FuzzerSetupNormalizer()
        tree_copy = normalizer.visit(tree_copy)

        # --- Strategy selection ---
        chosen_strategy: MutationStrategy
        if self.forced_strategy is not None:
            # Diagnostic mode: bypass adaptive selection
            strategy_map: dict[str, MutationStrategy] = {
                "deterministic": self._run_deterministic_stage,
                "havoc": self._run_havoc_stage,
                "spam": self._run_spam_stage,
                "helper_sniper": self._run_helper_sniper_stage,
                "sniper": self._run_sniper_stage,
            }
            chosen_strategy = strategy_map[self.forced_strategy]
            chosen_name = self.forced_strategy
            self.score_tracker.record_attempt(chosen_name)
        else:
            # Normal adaptive selection
            strategy_candidates: list[MutationStrategy] = [
                self._run_deterministic_stage,
                self._run_havoc_stage,
                self._run_spam_stage,
                self._run_helper_sniper_stage,
            ]

            if watched_keys:
                strategy_candidates.append(self._run_sniper_stage)

            strategy_names = [
                s.__name__.replace("_run_", "").replace("_stage", "") for s in strategy_candidates
            ]

            dynamic_weights = self.score_tracker.get_weights(strategy_names)

            if "sniper" in strategy_names:
                sniper_idx = strategy_names.index("sniper")
                avg_weight = sum(dynamic_weights) / len(dynamic_weights)
                dynamic_weights[sniper_idx] = max(dynamic_weights[sniper_idx], avg_weight * 1.5)

            chosen_strategy = RANDOM.choices(strategy_candidates, weights=dynamic_weights, k=1)[0]
            chosen_name = chosen_strategy.__name__.replace("_run_", "").replace("_stage", "")
            self.score_tracker.record_attempt(chosen_name)

        len_body = (
            len(tree_copy.body) if isinstance(tree_copy, (ast.Module, ast.FunctionDef)) else 0
        )

        if len_body > SlicingMutator.MIN_STATEMENTS_FOR_SLICE and chosen_name in (
            "deterministic",
            "havoc",
            "spam",
        ):
            mutated_ast, mutation_info = self._run_slicing(
                tree_copy, chosen_name, len_body, seed=seed
            )
        else:
            mutated_ast, mutation_info = chosen_strategy(
                tree_copy, seed=seed, watched_keys=watched_keys
            )

        # Run hygiene mutators at fixed probability (independent of learning system).
        hygiene_applied: list[str] = []
        for mutator_cls, probability in self.HYGIENE_MUTATORS:
            if RANDOM.random() < probability:
                mutated_ast = mutator_cls().visit(mutated_ast)
                hygiene_applied.append(mutator_cls.__name__)
        if hygiene_applied:
            mutation_info.setdefault("transformers", []).extend(hygiene_applied)

        # Always run the sanitizer last to fix any empty bodies.
        sanitizer = EmptyBodySanitizer()
        mutated_ast = sanitizer.visit(mutated_ast)
        # Fix missing locations for the entire tree. Individual stages do NOT
        # need to call this — it's handled here after all mutations complete.
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
                file=sys.stderr,
            )
            if self.health_monitor:
                self.health_monitor.record_mutation_recursion_error("unknown")
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
            if RANDOM.random() < 0.25:
                print("    -> Prepending GC pressure to test case", file=sys.stderr)
                # This logic is the same as in GCInjector
                thresholds = [1, 10, 100, None]
                weights = [0.6, 0.1, 0.1, 0.2]
                chosen_threshold = RANDOM.choices(thresholds, weights=weights, k=1)[0]
                if chosen_threshold is None:
                    chosen_threshold = RANDOM.randint(1, 150)
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
                file=sys.stderr,
            )
            if self.health_monitor:
                self.health_monitor.record_unparse_recursion_error("unknown")
            return None

        except (AttributeError, TypeError, ValueError) as e:
            # JIT corruption or malformed AST nodes can cause bizarre errors
            # during ast.unparse() (e.g., type objects with corrupted descriptors).
            # Capture the failing AST for CPython bug reporting and skip the mutation.
            print(
                f"  [!] Warning: Skipping mutation due to {type(e).__name__} during "
                f"ast.unparse(): {e}",
                file=sys.stderr,
            )
            try:
                _dump_unparse_diagnostics(
                    child_core_tree,
                    e,
                    source_hint="MutationController.prepare_child_script",
                )
            except UnboundLocalError:
                pass
            return None
