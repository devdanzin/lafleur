"""
Helper Function Injection Mutator.

This mutator injects optimization-friendly helper functions that will be called
from hot loops, causing the JIT to add them to the Bloom filter as dependencies.
These helpers then become targets for the SniperMutator to invalidate.
"""

import ast
import random
from textwrap import dedent


class HelperFunctionInjector(ast.NodeTransformer):
    """
    Injects helper functions and calls them from loops in the harness.

    The JIT will add called functions to its Bloom filter as dependencies.
    By injecting helpers and calling them, we create controllable targets
    for invalidation attacks.
    """

    # Templates for different types of helper functions
    HELPER_TEMPLATES = [
        # Simple arithmetic (type-specialized)
        dedent("""
        def _jit_helper_add(x, y):
            '''Type-specialized addition helper.'''
            return x + y
        """),
        # Multiplication (may be inlined)
        dedent("""
        def _jit_helper_mul(x, y):
            '''Type-specialized multiplication helper.'''
            return x * y
        """),
        # Conditional (branch prediction target)
        dedent("""
        def _jit_helper_clamp(x, minimum=0, maximum=100):
            '''Clamping helper with branches.'''
            if x < minimum:
                return minimum
            elif x > maximum:
                return maximum
            return x
        """),
        # List operation (allocation tracking)
        dedent("""
        def _jit_helper_collect(x):
            '''Helper that allocates - tests allocation tracking.'''
            return [x, x * 2, x * 3]
        """),
        # Type check (type guard target)
        dedent("""
        def _jit_helper_check_int(x):
            '''Helper with type check - tests type guards.'''
            if isinstance(x, int):
                return x * 2
            return 0
        """),
    ]

    def __init__(self, probability: float = 0.3):
        """
        Initialize the helper injector.

        Args:
            probability: Chance of applying the mutation (default 30%)
        """
        self.probability = probability
        self.helpers_injected: list[str] = []
        self.current_harness: ast.FunctionDef | None = None

    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Inject helpers at module level and modify harness functions."""
        if random.random() >= self.probability:
            return node

        # Find harness functions
        harness_funcs = [
            n
            for n in node.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("uop_harness")
        ]

        if not harness_funcs:
            return node

        # Check for existing helpers to avoid duplicates
        existing_helpers = {
            n.name
            for n in node.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("_jit_helper_")
        }

        if existing_helpers:
            # Helpers already exist - reuse them instead of injecting new ones
            self.helpers_injected = list(existing_helpers)
            # Still visit harness functions to potentially inject calls
            self.generic_visit(node)
            return node

        # Select 1-3 helper templates to inject
        num_helpers = random.randint(1, min(3, len(self.HELPER_TEMPLATES)))
        selected_templates = random.sample(self.HELPER_TEMPLATES, num_helpers)

        # Parse helper functions
        helper_nodes: list[ast.FunctionDef] = []
        for template in selected_templates:
            try:
                helper_ast = ast.parse(template)
                helper_func = helper_ast.body[0]
                if isinstance(helper_func, ast.FunctionDef):
                    self.helpers_injected.append(helper_func.name)
                    helper_nodes.append(helper_func)
            except SyntaxError:
                continue

        if not helper_nodes:
            return node

        # Insert helpers before the first harness function
        first_harness_idx = node.body.index(harness_funcs[0])
        node.body = node.body[:first_harness_idx] + helper_nodes + node.body[first_harness_idx:]

        # Visit harness functions to inject calls
        self.generic_visit(node)
        ast.fix_missing_locations(node)

        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Inject helper calls into harness function loops."""
        if not node.name.startswith("uop_harness"):
            return node

        self.current_harness = node

        # Visit children to find existing loops
        self.generic_visit(node)

        # Check if we found any loops
        has_loops = self._has_loops(node)

        # If no loops found, inject a loop that calls helpers
        if not has_loops and self.helpers_injected:
            warmup_loop = self._create_warmup_loop()
            # Insert at the beginning of the function body
            node.body = [warmup_loop] + node.body
            ast.fix_missing_locations(node)

        self.current_harness = None
        return node

    def _has_loops(self, node: ast.AST) -> bool:
        """Check if the node contains any For or While loops."""
        for child in ast.walk(node):
            if isinstance(child, (ast.For, ast.While)):
                return True
        return False

    def _create_warmup_loop(self) -> ast.For:
        """
        Create a hot loop that calls the injected helpers.

        This ensures the helpers are called enough times to trigger JIT
        compilation and get added to the Bloom filter.
        """
        # Select a random helper to call in the loop
        helper_name = random.choice(self.helpers_injected)

        # Create: for _i in range(100):
        #             _result = helper_name(_i, 10)
        loop = ast.For(
            target=ast.Name(id="_jit_warmup_i", ctx=ast.Store()),
            iter=ast.Call(
                func=ast.Name(id="range", ctx=ast.Load()),
                args=[ast.Constant(value=100)],
                keywords=[],
            ),
            body=[
                ast.Assign(
                    targets=[ast.Name(id="_jit_warmup_result", ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Name(id=helper_name, ctx=ast.Load()),
                        args=[
                            ast.Name(id="_jit_warmup_i", ctx=ast.Load()),
                            ast.Constant(value=10),
                        ],
                        keywords=[],
                    ),
                )
            ],
            orelse=[],
        )

        return loop

    def visit_For(self, node: ast.For) -> ast.For:
        """Inject helper calls into existing for loops."""
        if not self.helpers_injected or not self.current_harness:
            return node

        # 50% chance to inject into this loop
        if random.random() < 0.5:
            return node

        # Select a random helper to call
        helper_name = random.choice(self.helpers_injected)

        # Create a call to the helper
        # Pattern: _result = helper_name(loop_var, 10)
        loop_var = node.target.id if isinstance(node.target, ast.Name) else "i"
        call_stmt = ast.Assign(
            targets=[ast.Name(id="_helper_result", ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id=helper_name, ctx=ast.Load()),
                args=[
                    ast.Name(id=loop_var, ctx=ast.Load()),
                    ast.Constant(value=10),
                ],
                keywords=[],
            ),
        )

        # Insert the call at the start of the loop body
        node.body = [call_stmt] + node.body
        ast.fix_missing_locations(node)

        return node

    def visit_While(self, node: ast.While) -> ast.While:
        """Inject helper calls into existing while loops."""
        if not self.helpers_injected or not self.current_harness:
            return node

        # 50% chance to inject into this loop
        if random.random() < 0.5:
            return node

        # Select a random helper to call
        helper_name = random.choice(self.helpers_injected)

        # Create a call to the helper
        call_stmt = ast.Assign(
            targets=[ast.Name(id="_helper_result", ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id=helper_name, ctx=ast.Load()),
                args=[
                    ast.Constant(value=42),
                    ast.Constant(value=10),
                ],
                keywords=[],
            ),
        )

        # Insert the call at the start of the loop body
        node.body = [call_stmt] + node.body
        ast.fix_missing_locations(node)

        return node
