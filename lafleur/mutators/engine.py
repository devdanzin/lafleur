"""
This module contains the central orchestration logic for the mutation system.

It defines the `ASTMutator` class, which manages the library of available
transformers and applies randomized mutation pipelines to ASTs. It also includes
the `SlicingMutator`, a meta-mutator designed to efficiently fuzz very large
functions by operating on small, random slices of their body.
"""

from __future__ import annotations

import ast
import pickle
import random
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent

from lafleur.mutators.generic import (
    ArithmeticSpamMutator,
    AsyncConstructMutator,
    BlockTransposerMutator,
    BoundaryValuesMutator,
    ComparisonChainerMutator,
    ComparisonSwapper,
    ConstantPerturbator,
    ContainerChanger,
    DecoratorMutator,
    ExceptionGroupMutator,
    ForLoopInjector,
    GuardInjector,
    GuardRemover,
    LiteralTypeSwapMutator,
    NewUnpackingMutator,
    OperatorSwapper,
    PatternMatchingMutator,
    SliceMutator,
    StringInterpolationMutator,
    SysMonitoringMutator,
    UnpackingMutator,
    VariableSwapper,
)
from lafleur.mutators.scenarios_control import (
    ContextManagerInjector,
    CoroutineStateCorruptor,
    DeepCallMutator,
    ExceptionHandlerMaze,
    ExitStresser,
    GeneratorFrameInliningMutator,
    GuardExhaustionGenerator,
    MaxOperandMutator,
    PatternMatchingChaosMutator,
    RecursionWrappingMutator,
    TraceBreaker,
    YieldFromInjector,
)
from lafleur.mutators.scenarios_data import (
    AbstractInterpreterConfusionMutator,
    BloomFilterSaturator,
    BoundaryComparisonMutator,
    BuiltinNamespaceCorruptor,
    CodeObjectHotSwapper,
    ComprehensionBomb,
    ConstantNarrowingPoisonMutator,
    DictPolluter,
    GlobalOptimizationInvalidator,
    IterableMutator,
    LatticeSurfingMutator,
    MagicMethodMutator,
    NumericMutator,
    ReentrantSideEffectMutator,
    SliceObjectChaosMutator,
    StackCacheThrasher,
    StarCallMutator,
    TypeShadowingMutator,
    UnpackingChaosMutator,
    ZombieTraceMutator,
)
from lafleur.mutators.scenarios_runtime import (
    ClosureStompMutator,
    EvalFrameHookMutator,
    FrameManipulator,
    GCInjector,
    GlobalInvalidator,
    RareEventStressTester,
    RefcountEscapeHatchMutator,
    SideEffectInjector,
    StressPatternInjector,
    WeakRefCallbackChaos,
)
from lafleur.mutators.scenarios_types import (
    BasesRewriteMutator,
    CodeObjectSwapper,
    ComprehensiveFunctionMutator,
    DescriptorChaosGenerator,
    DynamicClassSwapper,
    FunctionPatcher,
    InlineCachePolluter,
    InlinedFrameCorruptionMutator,
    LoadAttrPolluter,
    ManyVarsInjector,
    MROShuffler,
    SuperResolutionAttacker,
    TypeInstabilityInjector,
    TypeIntrospectionMutator,
    TypeVersionInvalidator,
)
from lafleur.mutators.helper_injection import HelperFunctionInjector
# Note: SniperMutator is NOT imported here - it's only used in orchestrator._run_sniper_stage
# because it requires watched_keys parameter from Bloom introspection

UNPARSE_DIAGNOSTICS_DIR = Path("diagnostics") / "unparse_errors"


def _dump_unparse_diagnostics(
    tree: ast.AST,
    error: Exception,
    transformers_used: list[type] | None = None,
    source_hint: str | None = None,
) -> Path | None:
    """Dump rich diagnostics when ast.unparse() fails.

    Captures the failing AST (pickle + text dump), full traceback,
    transformer list, and a reproduction script for CPython bug reporting.

    Args:
        tree: The AST that failed to unparse.
        error: The exception raised by ast.unparse().
        transformers_used: Optional list of transformer classes that were applied.
        source_hint: Optional label for which call site triggered the failure.

    Returns:
        Path to the diagnostic directory, or None if the dump failed.
    """
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        dump_dir = UNPARSE_DIAGNOSTICS_DIR / f"unparse_error_{timestamp}"
        dump_dir.mkdir(parents=True, exist_ok=True)

        # 1. Pickle the failing AST for exact reproduction
        pickle_path = dump_dir / "failing_tree.pkl"
        try:
            with open(pickle_path, "wb") as f:
                pickle.dump(tree, f)
        except Exception as pkl_err:
            with open(pickle_path.with_suffix(".pkl.err"), "w", encoding="utf-8") as f:
                f.write(f"Pickle failed: {type(pkl_err).__name__}: {pkl_err}\n")

        # 2. Human-readable text dump
        info_path = dump_dir / "info.txt"
        with open(info_path, "w", encoding="utf-8") as f:
            f.write(f"Error: {type(error).__name__}: {error}\n")
            f.write(f"Timestamp: {timestamp}\n")
            if source_hint:
                f.write(f"Source: {source_hint}\n")
            if transformers_used:
                names = [t.__name__ for t in transformers_used]
                f.write(f"Transformers: {', '.join(names)}\n")
            f.write("\n")

            # Full traceback
            f.write("Traceback:\n")
            f.write(traceback.format_exc())
            f.write("\n")

            # AST dump
            f.write("=" * 60 + "\n")
            f.write("AST Dump:\n")
            try:
                f.write(ast.dump(tree, indent=2))
            except Exception as dump_err:
                f.write(f"(ast.dump also failed: {type(dump_err).__name__}: {dump_err})\n")
                try:
                    f.write(f"Tree type: {type(tree).__name__}\n")
                    if hasattr(tree, "body"):
                        f.write(f"Body length: {len(tree.body)}\n")
                        for i, node in enumerate(tree.body[:10]):
                            f.write(f"  [{i}] {type(node).__name__}\n")
                except Exception:
                    f.write("(Could not inspect tree structure)\n")

        # 3. Reproduction script
        repro_path = dump_dir / "reproduce.py"
        with open(repro_path, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env python3\n")
            f.write('"""Reproduction script for ast.unparse() failure."""\n')
            f.write("import ast\nimport pickle\nfrom pathlib import Path\n\n")
            f.write("tree = pickle.loads(Path('failing_tree.pkl').read_bytes())\n")
            f.write("try:\n")
            f.write("    result = ast.unparse(tree)\n")
            f.write("    print('No error — could not reproduce.')\n")
            f.write("except Exception as e:\n")
            f.write("    print(f'Reproduced: {type(e).__name__}: {e}')\n")

        print(
            f"  [!] Unparse diagnostics saved to: {dump_dir}",
            file=sys.stderr,
        )
        return dump_dir

    except Exception as outer_err:
        # Never let diagnostic capture crash the fuzzer
        print(
            f"  [!] Could not save unparse diagnostics: {outer_err}",
            file=sys.stderr,
        )
        return None


class SlicingMutator(ast.NodeTransformer):
    """
    A meta-mutator that applies a given mutation pipeline to only a small
    slice of a very large function body.
    """

    MIN_STATEMENTS_FOR_SLICE = 100
    SLICE_SIZE = 25

    def __init__(self, transformer_instances: list[ast.NodeTransformer]):
        self.pipeline = transformer_instances

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        body_len = len(node.body)
        if body_len < self.MIN_STATEMENTS_FOR_SLICE or not node.name.startswith("uop_harness"):
            return node

        print(f"    -> Slicing large function body of {body_len} statements.", file=sys.stderr)

        start = random.randint(0, body_len - self.SLICE_SIZE)
        end = start + self.SLICE_SIZE
        body_slice = node.body[start:end]

        temp_module = ast.Module(body=body_slice, type_ignores=[])

        for transformer in self.pipeline:
            temp_module = transformer.visit(temp_module)

        mutated_slice = temp_module.body
        node.body = node.body[:start] + mutated_slice + node.body[end:]

        ast.fix_missing_locations(node)
        return node


class ASTMutator:
    """
    An engine for structurally modifying Python code at the AST level.

    This class takes an Abstract Syntax Tree (AST) and applies a randomized
    pipeline of `ast.NodeTransformer` subclasses to it. Each transformer is
    responsible for a specific kind of mutation. The final, mutated AST is
    then unparsed back into a string of Python code.
    """

    def __init__(self) -> None:
        self.transformers: list[type[ast.NodeTransformer]] = [
            HelperFunctionInjector,  # Injects helpers for Sniper to target
            OperatorSwapper,
            ComparisonSwapper,
            ComparisonChainerMutator,
            ConstantPerturbator,
            BoundaryValuesMutator,
            LiteralTypeSwapMutator,
            GuardInjector,
            ContainerChanger,
            VariableSwapper,
            StressPatternInjector,
            TypeInstabilityInjector,
            GuardExhaustionGenerator,
            InlineCachePolluter,
            SideEffectInjector,
            # StatementDuplicator — moved to hygiene layer (MutationController.HYGIENE_MUTATORS)
            ForLoopInjector,
            GlobalInvalidator,
            LoadAttrPolluter,
            ManyVarsInjector,
            TypeIntrospectionMutator,
            MagicMethodMutator,
            NumericMutator,
            IterableMutator,
            ReentrantSideEffectMutator,
            LatticeSurfingMutator,
            BloomFilterSaturator,
            StackCacheThrasher,
            BoundaryComparisonMutator,
            AbstractInterpreterConfusionMutator,
            GlobalOptimizationInvalidator,
            CodeObjectHotSwapper,
            TypeShadowingMutator,
            ZombieTraceMutator,
            UnpackingChaosMutator,
            ClosureStompMutator,
            GCInjector,
            DictPolluter,
            FunctionPatcher,
            ComprehensiveFunctionMutator,
            TraceBreaker,
            ExitStresser,
            MaxOperandMutator,
            DeepCallMutator,
            GuardRemover,
            BlockTransposerMutator,
            UnpackingMutator,
            NewUnpackingMutator,
            DecoratorMutator,
            RecursionWrappingMutator,
            ContextManagerInjector,
            YieldFromInjector,
            DescriptorChaosGenerator,
            MROShuffler,
            BasesRewriteMutator,
            DynamicClassSwapper,
            TypeVersionInvalidator,
            FrameManipulator,
            ComprehensionBomb,
            SuperResolutionAttacker,
            CoroutineStateCorruptor,
            GeneratorFrameInliningMutator,
            WeakRefCallbackChaos,
            RefcountEscapeHatchMutator,
            EvalFrameHookMutator,
            RareEventStressTester,
            ExceptionHandlerMaze,
            BuiltinNamespaceCorruptor,
            CodeObjectSwapper,
            SliceMutator,
            PatternMatchingMutator,
            PatternMatchingChaosMutator,
            ArithmeticSpamMutator,
            StringInterpolationMutator,
            ExceptionGroupMutator,
            AsyncConstructMutator,
            SysMonitoringMutator,
            ConstantNarrowingPoisonMutator,
            InlinedFrameCorruptionMutator,
            StarCallMutator,
            SliceObjectChaosMutator,
        ]
        # Note: SniperMutator is NOT in this list - it's applied separately
        # via orchestrator._run_sniper_stage() with Bloom-detected watched_keys

    def mutate_ast(
        self,
        tree: ast.AST | list[ast.stmt],
        seed: int | None = None,
        mutations: int | None = None,
    ) -> tuple[ast.AST, list[type]]:
        """
        Apply a random pipeline of AST mutations directly to an AST object.

        This is a more efficient version of mutate() for use when the AST
        is already available, avoiding an unparse/re-parse cycle.

        Args:
            tree: The AST object to be mutated, or a list of statements.
            seed: An optional integer to seed the random number generator.
            mutations: An optional integer to specify the number of mutations.

        Return:
            A tuple containing the new, mutated AST object and a list of the
            transformer classes that were applied.
        """
        if seed is not None:
            random.seed(seed)

        # If tree is a list of statements, wrap it in a Module
        ast_tree: ast.AST
        if isinstance(tree, list):
            ast_tree = ast.Module(body=tree, type_ignores=[])
        else:
            ast_tree = tree

        # Randomly select 1 to 3 transformers to apply
        num_mutations = mutations if mutations is not None else random.randint(1, 3)
        chosen_transformers = random.choices(self.transformers, k=num_mutations)

        for transformer_class in chosen_transformers:
            transformer_instance = transformer_class()
            ast_tree = transformer_instance.visit(ast_tree)

        ast.fix_missing_locations(ast_tree)
        return ast_tree, chosen_transformers

    def mutate(
        self, code_string: str, seed: int | None = None, mutations: int | None = None
    ) -> str:
        """
        Parse code, apply a random pipeline of AST mutations, and unparse.

        This is the main public method of the mutator. It takes a string of
        Python code and applies a randomized sequence of different
        NodeTransformer subclasses to its AST, structurally altering the code.

        Args:
            code_string: The Python code to be mutated.
            seed: An optional integer to seed the random number generator for
                  a deterministic (reproducible) mutation pipeline.
            mutations: An optional integer to specify the number of mutations.

        Return:
            A string containing the new, mutated Python code.
        """
        try:
            tree = ast.parse(dedent(code_string))
        except SyntaxError:
            commented_lines = "\n# ".join(code_string.splitlines())
            return f"# Original code failed to parse:\n# {commented_lines}"

        mutated_tree, transformers_used = self.mutate_ast(tree, seed=seed, mutations=mutations)

        try:
            return ast.unparse(mutated_tree)
        except AttributeError as e:
            _dump_unparse_diagnostics(
                mutated_tree,
                e,
                transformers_used=transformers_used,
                source_hint="ASTMutator.mutate",
            )
            commented_lines = "\n# ".join(code_string.splitlines())
            return f"# AST unparsing failed. Original code was:\n# {commented_lines}"
