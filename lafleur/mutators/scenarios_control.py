"""
This module contains mutation scenarios designed to stress the JIT's control
flow analysis and trace generation limits.

The strategies here focus on the "shape" of execution. This includes creating
deep call stacks to test recursion limits, injecting complex exception handling
to break traces, and generating loops with many side-exits to stress the JIT's
guard emission and bailout mechanisms.
"""

from __future__ import annotations

import ast
import random
import sys
from textwrap import dedent, indent


class TraceBreaker(ast.NodeTransformer):
    """
    Attacks the JIT's ability to form long, linear traces (superblocks)
    by injecting code that is known to be "trace-unfriendly".
    """

    def _create_dynamic_call_break(self, prefix: str) -> list[ast.stmt]:
        """Injects a call to a function whose target is not statically known."""
        print("    -> Injecting trace-breaking (dynamic call) scenario...", file=sys.stderr)
        attack_code = dedent(f"""
            # Dynamic call trace-breaking scenario
            print('[{prefix}] Running dynamic call trace break...', file=sys.stderr)
            def f1_{prefix}(): return 1
            def f2_{prefix}(): return 2
            funcs = [f1_{prefix}, f2_{prefix}]
            for i in range(200):
                # The JIT cannot easily predict the target of func_to_call().
                func_to_call = funcs[i % 2]
                try:
                    func_to_call()
                except Exception:
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_exception_break(self, prefix: str) -> list[ast.stmt]:
        """Injects a try...except...finally block into a hot loop."""
        print("    -> Injecting trace-breaking (exception) scenario...", file=sys.stderr)
        attack_code = dedent(f"""
            # Exception handling trace-breaking scenario
            print('[{prefix}] Running exception trace break...', file=sys.stderr)
            for i in range(200):
                try:
                    # The JIT tracer often bails on complex exception handling.
                    if i % 10 == 0:
                        raise ValueError("trace break")
                except ValueError:
                    pass
                finally:
                    _ = i
        """)
        return ast.parse(attack_code).body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # Low probability
            prefix = f"{node.name}_{random.randint(1000, 9999)}"

            attack_generators = [
                self._create_dynamic_call_break,
                self._create_exception_break,
            ]
            chosen_generator = random.choice(attack_generators)
            scenario_nodes = chosen_generator(prefix)

            node.body = scenario_nodes + node.body
            ast.fix_missing_locations(node)

        return node


class ExitStresser(ast.NodeTransformer):
    """
    Attacks the JIT's side-exit mechanism by injecting a loop with
    many frequently taken branches.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # Low probability
            print(f"    -> Injecting exit stress pattern into '{node.name}'", file=sys.stderr)

            p_prefix = f"es_{random.randint(1000, 9999)}"
            num_branches = random.randint(5, 12)

            # 1. Build the if/elif/else chain as a string
            branch_code = []
            for i in range(num_branches):
                # Each branch performs a slightly different, simple operation
                branch_body = random.choice(
                    [
                        f"res_{p_prefix} = i * {i}",
                        f"res_{p_prefix} = str(i)",
                        f"res_{p_prefix} = len(str(i * 2))",
                        f"res_{p_prefix} = i % {(i % 5) + 1}",
                    ]
                )

                if i == 0:
                    branch_code.append(f"if i % {num_branches} == {i}:")
                else:
                    branch_code.append(f"elif i % {num_branches} == {i}:")
                branch_code.append(f"    {branch_body}")

            # 2. Assemble the full scenario
            attack_code = dedent(f"""
                # --- Exit Stress Scenario ---
                print('[{p_prefix}] Running exit stress scenario...', file=sys.stderr)
                res_{p_prefix} = 0
                for i in range(500):
                    try:
                        # This long chain encourages the JIT to create multiple
                        # side exits from the main hot loop.
{indent(chr(10).join(branch_code), " " * 24)}
                    except Exception:
                        pass
            """)

            try:
                scenario_nodes = ast.parse(attack_code).body
                # Prepend the scenario to the function's body.
                node.body = scenario_nodes + node.body
                ast.fix_missing_locations(node)
            except SyntaxError:
                print("    -> SyntaxError parsing ExitStresser attack code!", file=sys.stderr)

        return node


class DeepCallMutator(ast.NodeTransformer):
    """
    Attacks the JIT's trace stack limit by injecting a chain of deeply
    nested function calls with a precisely targeted depth.
    """

    TRACE_STACK_SIZE = 10  # From pycore_optimizer.h

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # Low probability for this complex injection
            # 1. Choose a "tricky" depth based on the JIT's known limit.
            depth = random.choice(
                [
                    self.TRACE_STACK_SIZE - 1,
                    self.TRACE_STACK_SIZE,
                    self.TRACE_STACK_SIZE + 1,
                ]
            )
            print(
                f"    -> Injecting deep call chain of depth {depth} into '{node.name}'",
                file=sys.stderr,
            )

            p_prefix = f"dc_{random.randint(1000, 9999)}"

            # 2. Programmatically build the function chain as a string.
            func_chain_lines = [f"# Deep call chain of depth {depth}"]
            func_chain_lines.append(f"def f_0_{p_prefix}(p): return p + 1")
            for i in range(1, depth):
                func_chain_lines.append(
                    f"def f_{i}_{p_prefix}(p): return f_{i - 1}_{p_prefix}(p) + 1"
                )

            func_chain_str = "\n".join(func_chain_lines)
            top_level_func = f"f_{depth - 1}_{p_prefix}"

            # 3. Assemble the full scenario string.
            attack_code = dedent(f"""
                # --- Deep Call Scenario ---
                print('[{p_prefix}] Running deep call scenario of depth {depth}...', file=sys.stderr)
                {indent(func_chain_str, " " * 16)}

                # Execute the top of the chain in a hot loop.
                for i in range(200):
                    try:
                        # This tests the JIT's ability to handle a stack
                        # of this specific depth during tracing.
                        {top_level_func}(i)
                    except RecursionError:
                        # This is an expected and valid outcome for deep stacks.
                        break
                    except Exception:
                        pass
            """)

            try:
                scenario_nodes = ast.parse(attack_code).body
                node.body = scenario_nodes + node.body
                ast.fix_missing_locations(node)
            except SyntaxError:
                pass  # Should not happen

        return node


class RecursionWrappingMutator(ast.NodeTransformer):
    """
    Selects a block of code, wraps it in a new self-recursive nested
    function, and replaces the original block with a guarded call to it.
    """

    MIN_STATEMENTS_FOR_WRAP = 5
    BLOCK_SIZE = 3

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        body_len = len(node.body)
        if body_len < self.MIN_STATEMENTS_FOR_WRAP:
            return node

        if random.random() < 0.05:
            # 1. Select a random block of statements to wrap.
            start_index = random.randint(0, body_len - self.BLOCK_SIZE)
            original_block = node.body[start_index : start_index + self.BLOCK_SIZE]

            # 2. Create a new, uniquely named recursive function.
            recursive_func_name = f"recursive_wrapper_{random.randint(1000, 9999)}"
            print(
                f"    -> Wrapping block at index {start_index} in recursive function '{recursive_func_name}'",
                file=sys.stderr,
            )

            # 3. Create the recursive call to the function itself.
            recursive_call = ast.Expr(
                value=ast.Call(
                    func=ast.Name(id=recursive_func_name, ctx=ast.Load()), args=[], keywords=[]
                )
            )

            # 4. Create the function definition, moving the original block into it.
            recursive_func_def = ast.FunctionDef(
                name=recursive_func_name,
                args=ast.arguments(
                    args=[], posonlyargs=[], kwonlyargs=[], kw_defaults=[], defaults=[]
                ),
                body=original_block + [recursive_call],
                decorator_list=[],
            )

            # 5. Create the try/except block to make the initial call.
            initial_call_try_block = ast.Try(
                body=[
                    ast.Expr(
                        value=ast.Call(
                            func=ast.Name(id=recursive_func_name, ctx=ast.Load()),
                            args=[],
                            keywords=[],
                        )
                    )
                ],
                handlers=[
                    ast.ExceptHandler(
                        type=ast.Name(id="RecursionError", ctx=ast.Load()),
                        name=None,
                        body=[ast.Pass()],
                    )
                ],
                orelse=[],
                finalbody=[],
            )

            # 6. Replace the original block with the new function and the try block.
            node.body = (
                node.body[:start_index]
                + [recursive_func_def, initial_call_try_block]
                + node.body[start_index + self.BLOCK_SIZE :]
            )

            ast.fix_missing_locations(node)

        return node


class GuardExhaustionGenerator(ast.NodeTransformer):
    """
    Attack JIT guard tables by injecting a long chain of `isinstance` checks.

    This mutator injects a self-contained scenario into a function that
    iterates over a polymorphic list and uses a long `if/elif` chain of
    `isinstance` checks, forcing the JIT to emit numerous guards.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # Low probability of injecting
            print(f"    -> Injecting guard exhaustion pattern into '{node.name}'", file=sys.stderr)

            # 1. Create the setup code as an AST
            setup_code = dedent("""
                poly_list = [1, "a", 3.0, [], (), {}, True, b'bytes']
            """)
            setup_ast = ast.parse(setup_code).body

            # 2. Create the loop with the isinstance chain
            isinstance_chain = dedent("""
                x = poly_list[i % len(poly_list)]
                if isinstance(x, int):
                    y = 1
                elif isinstance(x, str):
                    y = 2
                elif isinstance(x, float):
                    y = 3
                elif isinstance(x, list):
                    y = 4
                elif isinstance(x, tuple):
                    y = 5
                elif isinstance(x, dict):
                    y = 6
                elif isinstance(x, bool):
                    y = 7
                else:
                    y = 8
            """)

            loop_node = ast.For(
                target=ast.Name(id="i", ctx=ast.Store()),
                iter=ast.Call(
                    func=ast.Name(id="range", ctx=ast.Load()),
                    args=[ast.Constant(value=500)],
                    keywords=[],
                ),
                body=ast.parse(isinstance_chain).body,
                orelse=[],
            )

            # 3. Prepend the setup and the loop to the function's body
            node.body = setup_ast + [loop_node] + node.body

        return node


def _create_exception_maze_classes_ast(meta_name: str, exception_name: str) -> list[ast.ClassDef]:
    """
    Builds the AST for the metaclass and custom exception used in the maze.
    """
    return ast.parse(
        dedent(f"""
    class {meta_name}(type):
        def __instancecheck__(cls, instance):
            # This makes exception matching unpredictable for the JIT.
            cls.count = getattr(cls, 'count', 0) + 1
            return cls.count % 10 == 0

    class {exception_name}(Exception, metaclass={meta_name}):
        pass
    """)
    ).body


class ExceptionHandlerMaze(ast.NodeTransformer):
    """
    Injects a nested try/except block with a custom exception whose
    matching behavior is non-deterministic, attacking JIT's control
    flow optimizations for exception handling.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"exc_{random.randint(1000, 9999)}"
            meta_name = f"MetaException_{p_prefix}"
            exception_name = f"EvilException_{p_prefix}"

            print(
                f"    -> Injecting exception handler maze with prefix '{p_prefix}'", file=sys.stderr
            )

            # 1. Get the AST for the metaclass and exception class
            class_asts = _create_exception_maze_classes_ast(meta_name, exception_name)

            # 2. Create the AST for the "maze" itself
            maze_ast = ast.parse(
                dedent(f"""
                for i in range(400):
                    x = i
                    try:
                        try:
                            # Alternate between raising our evil exception and a normal one
                            if i % 100 == 0:
                                raise {exception_name}()
                            else:
                                raise ValueError("A normal error")
                        except {exception_name}:
                            # This block will be entered unpredictably
                            x = i + 1
                    except ValueError:
                        # This block is entered predictably
                        x = i + 2
                    except Exception:
                        # Catch any other unexpected outcomes
                        pass
            """)
            ).body

            # 3. Inject the entire scenario into the harness
            injection_point = random.randint(0, len(node.body))
            full_injection = class_asts + maze_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


def _create_evil_frame_corruptor_ast(func_name: str, target_var: str) -> ast.FunctionDef:
    """
    Builds the AST for a function that uses sys._getframe() to modify a
    local variable in its caller's frame.
    """
    return ast.parse(
        dedent(f"""
    def {func_name}(value):
        try:
            # Get the frame of the caller (the coroutine)
            caller_frame = sys._getframe(1)
            # Corrupt the local variable in that frame
            caller_frame.f_locals['{target_var}'] = value
        except (ValueError, KeyError):
            pass
    """)
    ).body[0]


class CoroutineStateCorruptor(ast.NodeTransformer):
    """
    Injects an async function that has its local state corrupted
    across an await point, attacking JIT assumptions about local
    variable stability in coroutines.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"async_{random.randint(1000, 9999)}"
            corruptor_name = f"sync_corruptor_{p_prefix}"
            coroutine_name = f"evil_coro_{p_prefix}"

            print(
                f"    -> Injecting coroutine state corruption with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            # 1. Get the AST for the synchronous corrupting function
            corruptor_ast = _create_evil_frame_corruptor_ast(corruptor_name, "x")

            # 2. Create the AST for the evil coroutine, including the warm-up loop
            coroutine_ast = ast.parse(
                dedent(f"""
            async def {coroutine_name}():
                x = 0
                # Warm-up loop to make the JIT specialize the type of 'x'
                for i in range(100):
                    x = i + 1
                    await asyncio.sleep(0)
                    x = x + 1 # Resume and use x as an int

                # Corrupt 'x' before the await point
                {corruptor_name}("corrupted_string")

                await asyncio.sleep(0)

                # After resuming, the JIT's assumption about 'x' is violated
                _ = x + 1
            """)
            ).body[0]

            # 3. Create the AST to run the scenario
            trigger_ast = ast.parse(
                dedent(f"""
                try:
                    asyncio.run({coroutine_name}())
                except Exception:
                    pass
            """)
            ).body

            # 4. Inject the entire scenario
            # Ensure imports are present
            node.body.insert(0, ast.Import(names=[ast.alias(name="sys")]))
            node.body.insert(0, ast.Import(names=[ast.alias(name="asyncio")]))

            injection_point = random.randint(2, len(node.body))
            full_injection = [corruptor_ast, coroutine_ast] + trigger_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


class ContextManagerInjector(ast.NodeTransformer):
    """
    Wraps blocks of code in context managers to stress-test the JIT's handling
    of SETUP_WITH and exception propagation.

    This mutator uses three strategies:
    - Simple: contextlib.nullcontext() (clean entry/exit)
    - Resource: open(os.devnull, 'w') (real resource management)
    - Evil: Custom context manager that randomly raises in __enter__/__exit__
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Only apply with low probability
        if random.random() < 0.15:
            # Need at least 2 statements to wrap a slice
            if len(node.body) < 2:
                return node

            # Choose a random contiguous slice (2-5 statements)
            slice_size = min(random.randint(2, 5), len(node.body))
            start_idx = random.randint(0, len(node.body) - slice_size)
            end_idx = start_idx + slice_size

            # Extract the slice to wrap
            statements_to_wrap = node.body[start_idx:end_idx]

            # Choose strategy
            strategy = random.choice(["simple", "resource", "evil"])
            uid = random.randint(1000, 9999)

            if strategy == "simple":
                print(
                    f"    -> Injecting context manager (nullcontext) wrapping {slice_size} statements",
                    file=sys.stderr,
                )
                # Strategy A: contextlib.nullcontext()
                # Ensure import
                import_node = ast.Import(names=[ast.alias(name="contextlib")])
                if import_node not in node.body:
                    node.body.insert(0, import_node)

                # Create with statement
                context_expr = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="contextlib", ctx=ast.Load()),
                        attr="nullcontext",
                        ctx=ast.Load(),
                    ),
                    args=[],
                    keywords=[],
                )
                with_node = ast.With(
                    items=[ast.withitem(context_expr=context_expr, optional_vars=None)],
                    body=statements_to_wrap,
                )

            elif strategy == "resource":
                print(
                    f"    -> Injecting context manager (os.devnull) wrapping {slice_size} statements",
                    file=sys.stderr,
                )
                # Strategy B: open(os.devnull, 'w')
                # Ensure import
                import_node = ast.Import(names=[ast.alias(name="os")])
                if import_node not in node.body:
                    node.body.insert(0, import_node)

                # Create with statement
                context_expr = ast.Call(
                    func=ast.Name(id="open", ctx=ast.Load()),
                    args=[
                        ast.Attribute(
                            value=ast.Name(id="os", ctx=ast.Load()),
                            attr="devnull",
                            ctx=ast.Load(),
                        ),
                        ast.Constant(value="w"),
                    ],
                    keywords=[],
                )
                # Store in variable to avoid issues
                with_node = ast.With(
                    items=[
                        ast.withitem(
                            context_expr=context_expr,
                            optional_vars=ast.Name(id=f"_ctx_{uid}", ctx=ast.Store()),
                        )
                    ],
                    body=statements_to_wrap,
                )

            else:  # strategy == "evil"
                print(
                    f"    -> Injecting context manager (EvilContext) wrapping {slice_size} statements",
                    file=sys.stderr,
                )
                # Strategy C: Custom EvilContext class
                evil_class_code = dedent(f"""
                    class EvilContext_{uid}:
                        '''Context manager that randomly raises in __enter__/__exit__'''
                        def __enter__(self):
                            # Randomly raise to stress exception handling
                            if fuzzer_rng.random() < 0.3:
                                raise RuntimeError("Evil __enter__")
                            return self

                        def __exit__(self, exc_type, exc_val, exc_tb):
                            # Either raise or swallow exceptions
                            if fuzzer_rng.random() < 0.3:
                                raise RuntimeError("Evil __exit__")
                            elif fuzzer_rng.random() < 0.5:
                                return True  # Swallow exceptions
                            return False
                """)
                evil_class_ast = ast.parse(evil_class_code).body[0]

                # Insert class definition at top of function (after any imports)
                insert_idx = 0
                for i, stmt in enumerate(node.body):
                    if not isinstance(stmt, (ast.Import, ast.ImportFrom)):
                        insert_idx = i
                        break
                node.body.insert(insert_idx, evil_class_ast)

                # Create with statement wrapped in try/except
                context_expr = ast.Call(
                    func=ast.Name(id=f"EvilContext_{uid}", ctx=ast.Load()),
                    args=[],
                    keywords=[],
                )

                with_body_wrapped = ast.With(
                    items=[ast.withitem(context_expr=context_expr, optional_vars=None)],
                    body=statements_to_wrap,
                )

                # Wrap the entire with statement in try/except to handle evil behavior
                with_node = ast.Try(
                    body=[with_body_wrapped],
                    handlers=[
                        ast.ExceptHandler(
                            type=ast.Name(id="Exception", ctx=ast.Load()),
                            name=None,
                            body=[ast.Pass()],
                        )
                    ],
                    orelse=[],
                    finalbody=[],
                )

            # Replace the slice with the wrapped version
            # Adjust start_idx if we inserted imports/class
            actual_start_idx = start_idx
            if strategy == "simple" or strategy == "resource":
                actual_start_idx += 1  # Account for import
            elif strategy == "evil":
                # Account for class definition
                for i, stmt in enumerate(node.body[:start_idx + 1]):
                    if isinstance(stmt, ast.ClassDef):
                        actual_start_idx += 1

            node.body[actual_start_idx : actual_start_idx + slice_size] = [with_node]
            ast.fix_missing_locations(node)

        return node


class YieldFromInjector(ast.NodeTransformer):
    """
    Targets the JIT's handling of generator suspension, `yield from` delegation,
    and stack unwinding during cleanup (`try/finally`).

    This mutator creates nested generator functions with `yield from` to stress:
    - Generator suspension/resumption mechanics
    - Stack unwinding during cleanup (finally blocks)
    - Delegation chains (yield from)
    - Recursive generator patterns
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # Low probability
            gen_name = f"_yield_from_gen_{random.randint(1000, 9999)}"
            use_recursive = random.random() < 0.2  # 20% chance for recursive version

            if use_recursive:
                print(
                    f"    -> Injecting recursive yield-from generator '{gen_name}'",
                    file=sys.stderr,
                )
                # Create recursive generator
                gen_func = self._create_recursive_generator(gen_name)
            else:
                print(f"    -> Injecting yield-from generator '{gen_name}'", file=sys.stderr)
                # Create simple generator
                gen_func = self._create_simple_generator(gen_name)

            # Create driver code to consume the generator
            driver_call = ast.Expr(
                value=ast.Call(
                    func=ast.Name(id="list", ctx=ast.Load()),
                    args=[
                        ast.Call(
                            func=ast.Name(id=gen_name, ctx=ast.Load()),
                            args=[ast.Constant(value=0)] if use_recursive else [],
                            keywords=[],
                        )
                    ],
                    keywords=[],
                )
            )

            # Prepend generator definition and append driver call
            node.body = [gen_func] + node.body + [driver_call]
            ast.fix_missing_locations(node)

        return node

    def _create_simple_generator(self, gen_name: str) -> ast.FunctionDef:
        """
        Create a simple generator with yield from and try/finally.

        def _yield_from_gen():
            try:
                yield from range(10)
            finally:
                pass
        """
        try_body = [
            ast.Expr(
                value=ast.YieldFrom(
                    value=ast.Call(
                        func=ast.Name(id="range", ctx=ast.Load()),
                        args=[ast.Constant(value=10)],
                        keywords=[],
                    )
                )
            )
        ]

        finally_body = [ast.Pass()]

        try_finally = ast.Try(
            body=try_body, handlers=[], orelse=[], finalbody=finally_body
        )

        return ast.FunctionDef(
            name=gen_name,
            args=ast.arguments(
                args=[], posonlyargs=[], kwonlyargs=[], kw_defaults=[], defaults=[]
            ),
            body=[try_finally],
            decorator_list=[],
        )

    def _create_recursive_generator(self, gen_name: str) -> ast.FunctionDef:
        """
        Create a recursive generator with yield from and try/finally.

        def _yield_from_gen(depth=0):
            if depth > 5:
                return
            try:
                yield from _yield_from_gen(depth + 1)
            finally:
                pass
        """
        # Create the if statement: if depth > 5: return
        depth_check = ast.If(
            test=ast.Compare(
                left=ast.Name(id="depth", ctx=ast.Load()),
                ops=[ast.Gt()],
                comparators=[ast.Constant(value=5)],
            ),
            body=[ast.Return(value=None)],
            orelse=[],
        )

        # Create the recursive call: yield from _yield_from_gen(depth + 1)
        recursive_yield = ast.Expr(
            value=ast.YieldFrom(
                value=ast.Call(
                    func=ast.Name(id=gen_name, ctx=ast.Load()),
                    args=[
                        ast.BinOp(
                            left=ast.Name(id="depth", ctx=ast.Load()),
                            op=ast.Add(),
                            right=ast.Constant(value=1),
                        )
                    ],
                    keywords=[],
                )
            )
        )

        # Wrap in try/finally
        try_finally = ast.Try(
            body=[recursive_yield], handlers=[], orelse=[], finalbody=[ast.Pass()]
        )

        # Create the function with depth parameter
        return ast.FunctionDef(
            name=gen_name,
            args=ast.arguments(
                args=[ast.arg(arg="depth", annotation=None)],
                posonlyargs=[],
                kwonlyargs=[],
                kw_defaults=[],
                defaults=[ast.Constant(value=0)],
            ),
            body=[depth_check, try_finally],
            decorator_list=[],
        )
