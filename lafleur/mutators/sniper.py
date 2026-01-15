import ast
import random
from textwrap import dedent
from typing import TypeVar

_LoopT = TypeVar("_LoopT", ast.For, ast.While)


class SniperMutator(ast.NodeTransformer):
    """
    A mutator that targets helper functions detected in the JIT's Bloom filter.

    This works in conjunction with HelperFunctionInjector, which creates
    optimization-friendly helper functions that get called from hot loops.
    The JIT adds these helpers to its Bloom filter as dependencies.

    The Sniper then invalidates these helpers mid-execution, triggering:
    - Deoptimization when the JIT's cached assumptions break
    - Type confusion when helper signatures change
    - State corruption when helper behavior changes unexpectedly
    """

    KNOWN_BUILTINS = {
        "len",
        "range",
        "isinstance",
        "print",
        "list",
        "dict",
        "set",
        "tuple",
        "int",
        "str",
        "float",
        "bool",
        "type",
        "object",
        "id",
        "hash",
        "iter",
        "next",
        "min",
        "max",
        "sum",
        "any",
        "all",
        "sorted",
        "reversed",
        "enumerate",
        "zip",
        "map",
        "filter",
        "open",
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
        "isinstance",
        "issubclass",
        "callable",
        "chr",
        "ord",
        "hex",
        "oct",
        "bin",
    }

    def __init__(self, watched_keys: list[str] | None = None):
        """
        Initialize the Sniper with watched dependencies from Bloom filter.

        Args:
            watched_keys: List of function names detected via Bloom introspection.
                         Typically includes helper functions injected by HelperFunctionInjector.
        """
        self.watched_keys = watched_keys or []
        # Filter to only target helper functions (start with _jit_helper_)
        self.helper_targets = [k for k in self.watched_keys if k.startswith("_jit_helper_")]

    def _create_invalidation_stmt(self, key: str) -> list[ast.stmt]:
        """
        Generates AST statements to invalidate the given key.

        For helper functions, we use various attack vectors:
        - Replace with lambda (breaks inlining)
        - Replace with None (breaks CALL opcodes)
        - Swap __code__ (breaks JIT's cached code object)
        - Replace with wrong-type-returning function (breaks type guards)
        """
        if key in self.KNOWN_BUILTINS:
            # Attack builtins
            source = dedent(f"""
                import builtins
                builtins.{key} = lambda *a, **k: None
            """).strip()
        elif key.startswith("_jit_helper_"):
            # Attack helper functions with various strategies
            attack_type = random.choice(["lambda", "none", "wrong_type", "exception", "code_swap"])

            if attack_type == "lambda":
                # Replace with a do-nothing lambda
                source = f"globals()['{key}'] = lambda *a, **k: None"
            elif attack_type == "none":
                # Replace with None (will cause TypeError on call)
                source = f"globals()['{key}'] = None"
            elif attack_type == "wrong_type":
                # Replace with function that returns wrong type
                source = f"globals()['{key}'] = lambda *a, **k: 'WRONG_TYPE'"
            elif attack_type == "code_swap":
                # Swap the __code__ attribute with a different function's code
                # This breaks JIT's cached code object assumptions
                source = dedent(f"""
                    def _sniper_fake_impl(*a, **k):
                        return 999
                    if hasattr(globals()['{key}'], '__code__'):
                        globals()['{key}'].__code__ = _sniper_fake_impl.__code__
                """).strip()
            else:  # exception
                # Replace with function that raises
                source = dedent(f"""
                    def _sniper_trap(*a, **k):
                        raise RuntimeError('Sniped!')
                    globals()['{key}'] = _sniper_trap
                """).strip()
        else:
            # Generic global invalidation
            source = f"globals()['{key}'] = None"

        try:
            return ast.parse(source).body
        except SyntaxError:
            # Fallback for weird keys
            return []

    def visit_For(self, node: ast.For) -> ast.For:
        self.generic_visit(node)
        return self._snipe_loop(node)

    def visit_While(self, node: ast.While) -> ast.While:
        self.generic_visit(node)
        return self._snipe_loop(node)

    def _snipe_loop(self, node: _LoopT) -> _LoopT:
        """Injects invalidation logic into the loop body."""
        # Prioritize helper targets (injected by HelperFunctionInjector)
        # Fall back to generic watched keys if no helpers found
        targets_pool = self.helper_targets if self.helper_targets else self.watched_keys

        if not targets_pool:
            return node

        # Probabilistic application (50%)
        if random.random() < 0.5:
            return node

        # Pick 1-2 targets to invalidate (fewer than before to avoid overwhelming)
        num_keys = random.randint(1, min(2, len(targets_pool)))
        targets = random.sample(targets_pool, num_keys)

        invalidation_code = []
        for key in targets:
            stmts = self._create_invalidation_stmt(key)
            invalidation_code.extend(stmts)

        if invalidation_code:
            # Insert at the start of the loop body
            node.body = invalidation_code + node.body
            ast.fix_missing_locations(node)

        return node
