"""
This module contains the central orchestration logic for the mutation system.

It defines the `ASTMutator` class, which manages the library of available
transformers and applies randomized mutation pipelines to ASTs. It also includes
the `SlicingMutator`, a meta-mutator designed to efficiently fuzz very large
functions by operating on small, random slices of their body.
"""

from __future__ import annotations

import ast
import random
import sys
from textwrap import dedent

# Import mutators from submodules
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
    # StatementDuplicator,
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
    GuardExhaustionGenerator,
    RecursionWrappingMutator,
    TraceBreaker,
)
from lafleur.mutators.scenarios_data import (
    BuiltinNamespaceCorruptor,
    ComprehensionBomb,
    DictPolluter,
    IterableMutator,
    MagicMethodMutator,
    NumericMutator,
    ReentrantSideEffectMutator,
)
from lafleur.mutators.scenarios_runtime import (
    FrameManipulator,
    GCInjector,
    GlobalInvalidator,
    SideEffectInjector,
    StressPatternInjector,
    WeakRefCallbackChaos,
)
from lafleur.mutators.scenarios_types import (
    CodeObjectSwapper,
    DescriptorChaosGenerator,
    FunctionPatcher,
    InlineCachePolluter,
    LoadAttrPolluter,
    ManyVarsInjector,
    MROShuffler,
    SuperResolutionAttacker,
    TypeInstabilityInjector,
    TypeIntrospectionMutator,
)


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

    def __init__(self):
        self.transformers = [
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
            # StatementDuplicator,
            ForLoopInjector,
            GlobalInvalidator,
            LoadAttrPolluter,
            ManyVarsInjector,
            TypeIntrospectionMutator,
            MagicMethodMutator,
            NumericMutator,
            IterableMutator,
            ReentrantSideEffectMutator,
            GCInjector,
            DictPolluter,
            FunctionPatcher,
            TraceBreaker,
            ExitStresser,
            DeepCallMutator,
            GuardRemover,
            BlockTransposerMutator,
            UnpackingMutator,
            NewUnpackingMutator,
            DecoratorMutator,
            RecursionWrappingMutator,
            ContextManagerInjector,
            DescriptorChaosGenerator,
            MROShuffler,
            FrameManipulator,
            ComprehensionBomb,
            SuperResolutionAttacker,
            CoroutineStateCorruptor,
            WeakRefCallbackChaos,
            ExceptionHandlerMaze,
            BuiltinNamespaceCorruptor,
            CodeObjectSwapper,
            SliceMutator,
            PatternMatchingMutator,
            ArithmeticSpamMutator,
            StringInterpolationMutator,
            ExceptionGroupMutator,
            AsyncConstructMutator,
            SysMonitoringMutator,
        ]

    def mutate_ast(
        self, tree: ast.AST, seed: int = None, mutations: int | None = None
    ) -> tuple[ast.AST, list[type]]:
        """
        Apply a random pipeline of AST mutations directly to an AST object.

        This is a more efficient version of mutate() for use when the AST
        is already available, avoiding an unparse/re-parse cycle.

        Args:
            tree: The AST object to be mutated.
            seed: An optional integer to seed the random number generator.
            mutations: An optional integer to specify the number of mutations.

        Return:
            A tuple containing the new, mutated AST object and a list of the
            transformer classes that were applied.
        """
        if seed is not None:
            random.seed(seed)

        # Randomly select 1 to 3 transformers to apply
        num_mutations = mutations if mutations is not None else random.randint(1, 3)
        chosen_transformers = random.choices(self.transformers, k=num_mutations)

        if isinstance(tree, list):
            tree = ast.Module(body=tree, type_ignores=[])

        for transformer_class in chosen_transformers:
            transformer_instance = transformer_class()
            tree = transformer_instance.visit(tree)

        ast.fix_missing_locations(tree)
        return tree, chosen_transformers

    def mutate(self, code_string: str, seed: int = None, mutations: int | None = None) -> str:
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
            return f"# Original code failed to parse:\n# {'#'.join(code_string.splitlines())}"

        mutated_tree, _ = self.mutate_ast(tree, seed=seed, mutations=mutations)

        try:
            return ast.unparse(mutated_tree)
        except AttributeError:
            return f"# AST unparsing failed. Original code was:\n# {code_string}"
