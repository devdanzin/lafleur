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
        - Executor assassination via _testinternalcapi (GH-143604)
        - Globals detachment via types.FunctionType (GH-138378)
        """
        if key in self.KNOWN_BUILTINS:
            # Attack builtins with one of two strategies
            builtin_attack = random.choice(["replace", "executor_assassinate"])
            if builtin_attack == "replace":
                source = dedent(f"""
                    import builtins
                    builtins.{key} = lambda *a, **k: None
                """).strip()
            else:  # executor_assassinate
                # Invalidate executors that depend on this builtin.
                # We look for any function in globals that might have been
                # JIT-compiled with assumptions about this builtin.
                source = dedent(f"""
                    try:
                        import _testinternalcapi
                        import builtins
                        # First replace the builtin to invalidate caches
                        _sniper_orig_builtin = getattr(builtins, '{key}', None)
                        builtins.{key} = lambda *a, **k: None
                        # Then try to invalidate executors for all visible functions
                        for _sniper_name, _sniper_obj in list(globals().items()):
                            if callable(_sniper_obj) and hasattr(_sniper_obj, '__code__'):
                                try:
                                    _testinternalcapi.invalidate_executors(_sniper_obj.__code__)
                                except (TypeError, AttributeError):
                                    pass
                        # Restore builtin
                        if _sniper_orig_builtin is not None:
                            builtins.{key} = _sniper_orig_builtin
                    except ImportError:
                        import builtins
                        builtins.{key} = lambda *a, **k: None
                """).strip()
        elif key.startswith("_jit_helper_"):
            # Attack helper functions with various strategies
            attack_type = random.choice(
                [
                    "lambda",
                    "none",
                    "wrong_type",
                    "exception",
                    "code_swap",
                    "executor_assassinate",
                    "globals_detach",
                ]
            )

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
            elif attack_type == "executor_assassinate":
                # Use _testinternalcapi to invalidate executors while trace is running.
                # This rips the JIT executor out from under the active trace,
                # targeting memory safety bugs like GH-143604.
                source = dedent(f"""
                    try:
                        import _testinternalcapi
                        _sniper_target_func = globals().get('{key}')
                        if _sniper_target_func is not None and hasattr(_sniper_target_func, '__code__'):
                            _testinternalcapi.invalidate_executors(_sniper_target_func.__code__)
                    except (ImportError, AttributeError, TypeError):
                        pass
                """).strip()
            elif attack_type == "globals_detach":
                # Execute the helper with a completely detached globals dict.
                # The JIT may have inlined assumptions about the helper's globals
                # (e.g., builtins access, global variable types). Running the same
                # code object with empty globals forces deoptimization or crashes.
                source = dedent(f"""
                    import types as _sniper_types
                    _sniper_orig = globals().get('{key}')
                    if _sniper_orig is not None and hasattr(_sniper_orig, '__code__'):
                        try:
                            _sniper_detached = _sniper_types.FunctionType(
                                _sniper_orig.__code__,
                                {{'__builtins__': __builtins__}},
                                '{key}_detached',
                            )
                            _sniper_detached()
                        except Exception:
                            pass
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
        """Injects delayed invalidation logic into the loop body.

        The invalidation is gated behind an iteration counter so the JIT
        has time to compile the hot path before it's invalidated. Without
        this delay, the sniper fires on iteration 0 and the JIT never
        traces the code we want to deoptimize.
        """
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

        invalidation_code: list[ast.stmt] = []
        for key in targets:
            stmts = self._create_invalidation_stmt(key)
            invalidation_code.extend(stmts)

        if not invalidation_code:
            return node

        # Gate invalidation behind an iteration counter.
        # The JIT needs ~50-100 iterations to compile a trace, so we delay
        # the sniper shot until after warmup to ensure we actually trigger
        # deoptimization rather than just crashing pre-JIT.
        counter_name = f"_sniper_ctr_{random.randint(1000, 9999)}"
        trigger_iteration = random.randint(50, 100)

        # Build the counter increment with lazy initialization:
        #   try:
        #       _sniper_ctr_XXXX += 1
        #   except NameError:
        #       _sniper_ctr_XXXX = 1
        counter_increment = ast.Try(
            body=[
                ast.AugAssign(
                    target=ast.Name(id=counter_name, ctx=ast.Store()),
                    op=ast.Add(),
                    value=ast.Constant(value=1),
                )
            ],
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id="NameError", ctx=ast.Load()),
                    name=None,
                    body=[
                        ast.Assign(
                            targets=[ast.Name(id=counter_name, ctx=ast.Store())],
                            value=ast.Constant(value=1),
                        )
                    ],
                )
            ],
            orelse=[],
            finalbody=[],
        )

        # Build the guarded invalidation:
        #   if _sniper_ctr_XXXX == trigger_iteration:
        #       <invalidation_code>
        guarded_invalidation = ast.If(
            test=ast.Compare(
                left=ast.Name(id=counter_name, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=trigger_iteration)],
            ),
            body=invalidation_code,
            orelse=[],
        )

        # Prepend counter + guarded invalidation, then original loop body
        node.body = [counter_increment, guarded_invalidation] + node.body
        ast.fix_missing_locations(node)

        return node
