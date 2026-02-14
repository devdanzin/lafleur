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
from typing import cast


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
            prefix = f"ge_{random.randint(1000, 9999)}"
            print(f"    -> Injecting guard exhaustion pattern into '{node.name}'", file=sys.stderr)

            # 1. Create the setup code as an AST
            setup_code = dedent(f"""
                poly_list_{prefix} = [1, "a", 3.0, [], (), {{}}, True, b'bytes']
            """)
            setup_ast = ast.parse(setup_code).body

            # 2. Create the loop with the isinstance chain
            isinstance_chain = dedent(f"""
                x_{prefix} = poly_list_{prefix}[i_{prefix} % len(poly_list_{prefix})]
                if isinstance(x_{prefix}, int):
                    y_{prefix} = 1
                elif isinstance(x_{prefix}, str):
                    y_{prefix} = 2
                elif isinstance(x_{prefix}, float):
                    y_{prefix} = 3
                elif isinstance(x_{prefix}, list):
                    y_{prefix} = 4
                elif isinstance(x_{prefix}, tuple):
                    y_{prefix} = 5
                elif isinstance(x_{prefix}, dict):
                    y_{prefix} = 6
                elif isinstance(x_{prefix}, bool):
                    y_{prefix} = 7
                else:
                    y_{prefix} = 8
            """)

            loop_node = ast.For(
                target=ast.Name(id=f"i_{prefix}", ctx=ast.Store()),
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
            ast.fix_missing_locations(node)

        return node


def _create_exception_maze_classes_ast(meta_name: str, exception_name: str) -> list[ast.ClassDef]:
    """
    Builds the AST for the metaclass and custom exception used in the maze.
    """
    return cast(
        list[ast.ClassDef],
        ast.parse(
            dedent(f"""
    class {meta_name}(type):
        def __instancecheck__(cls, instance):
            # This makes exception matching unpredictable for the JIT.
            cls.count = getattr(cls, 'count', 0) + 1
            return cls.count % 10 == 0

    class {exception_name}(Exception, metaclass={meta_name}):
        pass
    """)
        ).body,
    )


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
    return cast(
        ast.FunctionDef,
        ast.parse(
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
        ).body[0],
    )


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
                # Always insert import (AST nodes use identity comparison, not equality)
                import_node = ast.Import(names=[ast.alias(name="contextlib")])
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
                with_node: ast.stmt = ast.With(
                    items=[ast.withitem(context_expr=context_expr, optional_vars=None)],
                    body=statements_to_wrap,
                )

            elif strategy == "resource":
                print(
                    f"    -> Injecting context manager (os.devnull) wrapping {slice_size} statements",
                    file=sys.stderr,
                )
                # Strategy B: open(os.devnull, 'w')
                # Always insert import (AST nodes use identity comparison, not equality)
                import_node = ast.Import(names=[ast.alias(name="os")])
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
            # Adjust start_idx because we inserted exactly one node before the slice
            actual_start_idx = start_idx
            if strategy == "simple" or strategy == "resource":
                actual_start_idx += 1  # Account for import inserted at index 0
            elif strategy == "evil":
                # Account for class inserted at insert_idx
                if insert_idx <= start_idx:
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
        try_body: list[ast.stmt] = [
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

        finally_body: list[ast.stmt] = [ast.Pass()]

        try_finally = ast.Try(body=try_body, handlers=[], orelse=[], finalbody=finally_body)

        return ast.FunctionDef(
            name=gen_name,
            args=ast.arguments(args=[], posonlyargs=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
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


class MaxOperandMutator(ast.NodeTransformer):
    """
    Stress the JIT's Copy-and-Patch encoding logic.

    This mutator verifies that the JIT correctly patches "holes" when operand
    values exceed standard 1-byte limits (forcing EXTENDED_ARG in Python bytecode).

    Two strategies:
    - Strategy A: Locals Saturation (force LOAD_FAST index > 255)
    - Strategy B: Jump Stretching (force jump offset > 255 bytes)
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.2:  # 20% chance
            # Randomly choose between Strategy A and B
            strategy = random.choice(["locals", "jumps"])

            if strategy == "locals":
                self._apply_locals_saturation(node)
            else:
                self._apply_jump_stretching(node)

            ast.fix_missing_locations(node)

        return node

    def _apply_locals_saturation(self, node: ast.FunctionDef):
        """
        Strategy A: Force LOAD_FAST index > 255 by creating 300 variables.
        """
        print(
            f"    -> Applying Locals Saturation strategy to '{node.name}' (300 variables)",
            file=sys.stderr,
        )

        # Generate 300 assignments: _jit_op_0 = 0, _jit_op_1 = 0, ..., _jit_op_299 = 0
        padding_stmts = []
        for i in range(300):
            var_name = f"_jit_op_{i}"
            assign = ast.Assign(
                targets=[ast.Name(id=var_name, ctx=ast.Store())],
                value=ast.Constant(value=0),
            )
            padding_stmts.append(assign)

        # Append a statement reading the last variable: _ = _jit_op_299
        read_last = ast.Assign(
            targets=[ast.Name(id="_", ctx=ast.Store())],
            value=ast.Name(id="_jit_op_299", ctx=ast.Load()),
        )
        padding_stmts.append(read_last)

        # Prepend to function body
        node.body = padding_stmts + node.body

    def _apply_jump_stretching(self, node: ast.FunctionDef):
        """
        Strategy B: Force jump offset > 255 bytes by creating a large padding block.
        """
        print(
            f"    -> Applying Jump Stretching strategy to '{node.name}' (200 statements)",
            file=sys.stderr,
        )

        # Create a padding block of 200 statements
        padding_block: list[ast.stmt] = []
        for i in range(200):
            assign = ast.Assign(
                targets=[ast.Name(id="_pad_jump", ctx=ast.Store())],
                value=ast.Constant(value=1),
            )
            padding_block.append(assign)

        # Wrap in an if statement: if getattr(object, '__doc__', True): <padding_block>
        # This is technically always true but harder to analyze statically
        if_node = ast.If(
            test=ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[
                    ast.Name(id="object", ctx=ast.Load()),
                    ast.Constant(value="__doc__"),
                    ast.Constant(value=True),
                ],
                keywords=[],
            ),
            body=padding_block,
            orelse=[],
        )

        # Prepend to function body
        node.body = [if_node] + node.body


class PatternMatchingChaosMutator(ast.NodeTransformer):
    """
    Attack JIT optimizations for structural pattern matching (PEP 634).

    The JIT compiles match statements into specialized bytecode sequences
    (MATCH_MAPPING, MATCH_SEQUENCE, MATCH_CLASS, MATCH_KEYS, GET_LEN).
    This mutator generates chaotic patterns that stress-test these opcodes:

    1. **Guard Side Effects**: Guards that mutate the subject during matching
    2. **Overlapping Patterns**: Or patterns and nested structures forcing backtracking
    3. **Dynamic __match_args__**: Custom classes with mutable match protocol
    4. **Control Flow Conversion**: Transforms if/for into match statements
    5. **Type-Switching Subject**: Subject that changes type mid-match
    6. **Nested Match Statements**: Match inside match for deep recursion
    """

    HELPER_CLASS_NAME = "_JitMatchChaos"

    def __init__(self) -> None:
        super().__init__()
        self.helper_injected = False
        self._inside_harness = False

    def _create_chaos_match_class(self) -> list[ast.stmt]:
        """Create the _JitMatchChaos helper class with dynamic __match_args__."""
        class_code = dedent(f"""
            class {self.HELPER_CLASS_NAME}:
                '''Class with chaotic pattern matching behavior.'''
                _access_count = 0
                _match_args_variants = [
                    ('x',),
                    ('x', 'y'),
                    ('y', 'x'),
                    ('x', 'y', 'z'),
                    (),
                ]

                def __init__(self, x=1, y=2, z=3):
                    self.x = x
                    self.y = y
                    self.z = z
                    self._local_count = 0

                @property
                def __match_args__(self):
                    '''Return different match args on each access to confuse JIT.'''
                    {self.HELPER_CLASS_NAME}._access_count += 1
                    idx = {self.HELPER_CLASS_NAME}._access_count % len(
                        {self.HELPER_CLASS_NAME}._match_args_variants
                    )
                    return {self.HELPER_CLASS_NAME}._match_args_variants[idx]

                def __getattr__(self, name):
                    '''Trigger type changes when JIT inspects attributes.'''
                    self._local_count += 1
                    if self._local_count > 50:
                        # After warmup, return wrong types to trigger deopt
                        if name == 'x':
                            return "string_instead_of_int"
                        elif name == 'y':
                            return [1, 2, 3]  # List instead of int
                    return object.__getattribute__(self, name)

                def __eq__(self, other):
                    '''Non-deterministic equality for pattern guards.'''
                    {self.HELPER_CLASS_NAME}._access_count += 1
                    return {self.HELPER_CLASS_NAME}._access_count % 3 != 0
        """)
        return ast.parse(class_code).body

    def _create_guard_side_effect_function(self, prefix: str) -> list[ast.stmt]:
        """Create a function that mutates its argument when called in a guard."""
        func_code = dedent(f"""
            def _jit_mutate_subject_{prefix}(subject):
                '''Guard function that mutates the subject during matching.'''
                if isinstance(subject, list):
                    if len(subject) > 0:
                        subject.append(None)  # Grow list during match
                    return True
                elif isinstance(subject, dict):
                    subject['_mutated'] = True  # Add key during match
                    return True
                elif hasattr(subject, '__dict__'):
                    subject.__dict__['_chaos'] = 42  # Mutate object
                return True
        """)
        return ast.parse(func_code).body

    def _create_type_switching_subject(self, prefix: str) -> list[ast.stmt]:
        """Create a subject class that changes type behavior after warmup."""
        class_code = dedent(f"""
            class _TypeSwitcher_{prefix}:
                '''Subject that changes its sequence/mapping behavior.'''
                _check_count = 0

                def __init__(self, data):
                    self._data = data

                def __len__(self):
                    _TypeSwitcher_{prefix}._check_count += 1
                    if _TypeSwitcher_{prefix}._check_count > 100:
                        raise TypeError("Length no longer available")
                    return len(self._data)

                def __getitem__(self, key):
                    _TypeSwitcher_{prefix}._check_count += 1
                    if _TypeSwitcher_{prefix}._check_count > 100:
                        # Switch from sequence to mapping behavior
                        if isinstance(key, int):
                            raise KeyError(key)
                    return self._data[key]

                def __iter__(self):
                    _TypeSwitcher_{prefix}._check_count += 1
                    if _TypeSwitcher_{prefix}._check_count > 100:
                        # Yield different number of items after warmup
                        yield from self._data
                        yield "extra_chaos"
                    else:
                        yield from self._data

                def keys(self):
                    return self._data.keys() if hasattr(self._data, 'keys') else []
        """)
        return ast.parse(class_code).body

    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Inject helper classes at module level."""
        # Check if helper already exists
        for stmt in node.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == self.HELPER_CLASS_NAME:
                self.helper_injected = True
                break

        # Inject helper class with low probability
        if not self.helper_injected and random.random() < 0.15:
            print(
                f"    -> Injecting {self.HELPER_CLASS_NAME} helper class for pattern matching chaos",
                file=sys.stderr,
            )
            helper_classes = self._create_chaos_match_class()
            node.body = helper_classes + node.body
            self.helper_injected = True
            ast.fix_missing_locations(node)

        self.generic_visit(node)
        return node

    def visit_Match(self, node: ast.Match) -> ast.Match:
        """Transform existing match statements with chaotic patterns."""
        self.generic_visit(node)

        if random.random() < 0.3:  # 30% chance to transform
            action = random.choice(["guard", "complexity", "nested"])

            if action == "guard":
                self._inject_guard_side_effects(node)
            elif action == "complexity":
                self._add_pattern_complexity(node)
            else:
                self._add_nested_match(node)

            ast.fix_missing_locations(node)

        return node

    def _inject_guard_side_effects(self, node: ast.Match) -> None:
        """Add guards that mutate the subject during matching."""
        print("    -> Injecting guard side effects into match statement", file=sys.stderr)

        for case in node.cases:
            if case.guard is None and random.random() < 0.5:
                # Add a guard that mutates the subject
                # guard: _subject_ref.append(None) or True
                case.guard = ast.BoolOp(
                    op=ast.Or(),
                    values=[
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id="_chaos_side_effect", ctx=ast.Load()),
                                attr="append",
                                ctx=ast.Load(),
                            ),
                            args=[ast.Constant(value=None)],
                            keywords=[],
                        )
                        if random.random() < 0.3
                        else ast.Constant(value=True),
                        ast.Compare(
                            left=ast.Call(
                                func=ast.Name(id="len", ctx=ast.Load()),
                                args=[node.subject],
                                keywords=[],
                            ),
                            ops=[ast.GtE()],
                            comparators=[ast.Constant(value=0)],
                        ),
                    ],
                )

    def _add_pattern_complexity(self, node: ast.Match) -> None:
        """Add Or patterns and nested structures."""
        print("    -> Adding pattern complexity to match statement", file=sys.stderr)

        for case in node.cases:
            if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None:
                # Skip wildcard patterns
                continue

            # Wrap pattern in MatchOr with alternative patterns
            if random.random() < 0.4:
                original_pattern = case.pattern
                # Create alternative patterns
                alternatives = [
                    original_pattern,
                    ast.MatchSequence(patterns=[ast.MatchAs(pattern=None, name=None)]),
                    ast.MatchMapping(keys=[], patterns=[], rest=None),
                ]
                case.pattern = ast.MatchOr(patterns=alternatives[:2])

    def _add_nested_match(self, node: ast.Match) -> None:
        """Add nested match statements inside case bodies."""
        print("    -> Adding nested match statement", file=sys.stderr)

        for case in node.cases:
            if len(case.body) > 0 and random.random() < 0.3:
                # Create a nested match on a captured variable
                inner_match_code = dedent("""
                    match _inner_subject:
                        case []: _nested_result = 0
                        case [x]: _nested_result = 1
                        case [x, y]: _nested_result = 2
                        case _: _nested_result = -1
                """)
                try:
                    inner_match = ast.parse(inner_match_code).body[0]
                    # Insert assignment and nested match
                    case.body.insert(
                        0,
                        ast.Assign(
                            targets=[ast.Name(id="_inner_subject", ctx=ast.Store())],
                            value=ast.List(elts=[ast.Constant(value=1)], ctx=ast.Load()),
                        ),
                    )
                    case.body.insert(1, inner_match)
                except SyntaxError:
                    pass

    def visit_If(self, node: ast.If) -> ast.stmt:
        """Convert isinstance checks to match statements."""
        self.generic_visit(node)

        if not self._inside_harness:
            return node

        # Check if this is an isinstance check we can convert
        if random.random() < 0.15 and self._is_isinstance_check(node.test):
            converted = self._convert_isinstance_to_match(node)
            if converted:
                print("    -> Converting isinstance check to match statement", file=sys.stderr)
                return converted

        return node

    def _is_isinstance_check(self, test: ast.expr) -> bool:
        """Check if expression is isinstance(x, SomeType)."""
        if isinstance(test, ast.Call):
            if isinstance(test.func, ast.Name) and test.func.id == "isinstance":
                return len(test.args) >= 2
        return False

    def _convert_isinstance_to_match(self, node: ast.If) -> ast.Match | None:
        """Convert if isinstance(x, Type) to match x: case Type()."""
        try:
            call = node.test
            if not isinstance(call, ast.Call):
                return None

            subject = call.args[0]
            type_check = call.args[1]

            # Create the match statement
            match_pattern: ast.pattern
            if isinstance(type_check, ast.Name):
                match_pattern = ast.MatchClass(
                    cls=type_check,
                    patterns=[],
                    kwd_attrs=[],
                    kwd_patterns=[],
                )
            elif isinstance(type_check, ast.Tuple):
                # isinstance(x, (int, str)) -> case int() | str()
                patterns = []
                for elt in type_check.elts:
                    if isinstance(elt, ast.Name):
                        patterns.append(
                            ast.MatchClass(
                                cls=elt,
                                patterns=[],
                                kwd_attrs=[],
                                kwd_patterns=[],
                            )
                        )
                if not patterns:
                    return None
                match_pattern = (
                    ast.MatchOr(patterns=cast(list[ast.pattern], patterns))
                    if len(patterns) > 1
                    else patterns[0]
                )
            else:
                return None

            # Build match cases
            cases = [
                ast.match_case(
                    pattern=match_pattern,
                    guard=None,
                    body=node.body,
                ),
            ]

            # Add else case if present
            if node.orelse:
                cases.append(
                    ast.match_case(
                        pattern=ast.MatchAs(pattern=None, name=None),
                        guard=None,
                        body=node.orelse,
                    )
                )

            match_node = ast.Match(subject=subject, cases=cases)
            ast.fix_missing_locations(match_node)
            return match_node

        except (AttributeError, IndexError):
            return None

    def visit_For(self, node: ast.For) -> ast.stmt:
        """Convert simple for loops with tuple unpacking to match-based iteration."""
        self.generic_visit(node)

        if not self._inside_harness:
            return node

        # Only convert tuple unpacking: for x, y in items
        if random.random() < 0.1 and isinstance(node.target, ast.Tuple):
            converted = self._convert_for_to_match(node)
            if converted:
                print("    -> Converting for loop to match-based iteration", file=sys.stderr)
                return converted

        return node

    def _convert_for_to_match(self, node: ast.For) -> ast.For | None:
        """Convert for x, y in items to for item in items: match item."""
        try:
            # Create new simple target
            item_var = "_match_item"

            # Create match statement for the loop body
            # Extract variable names from tuple (we know target is Tuple from visit_For check)
            target_tuple = cast(ast.Tuple, node.target)
            var_patterns: list[ast.pattern] = []
            for elt in target_tuple.elts:
                if isinstance(elt, ast.Name):
                    var_patterns.append(ast.MatchAs(pattern=None, name=elt.id))
                else:
                    var_patterns.append(ast.MatchAs(pattern=None, name=None))

            match_node = ast.Match(
                subject=ast.Name(id=item_var, ctx=ast.Load()),
                cases=[
                    ast.match_case(
                        pattern=ast.MatchSequence(patterns=var_patterns),
                        guard=None,
                        body=node.body,
                    ),
                    # Fallback case for wrong structure
                    ast.match_case(
                        pattern=ast.MatchAs(pattern=None, name=None),
                        guard=None,
                        body=[ast.Pass()],
                    ),
                ],
            )

            # Create new for loop
            new_for = ast.For(
                target=ast.Name(id=item_var, ctx=ast.Store()),
                iter=node.iter,
                body=[match_node],
                orelse=node.orelse,
            )

            ast.fix_missing_locations(new_for)
            return new_for

        except (AttributeError, IndexError):
            return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Inject chaotic match scenarios into harness functions."""
        is_harness = node.name.startswith("uop_harness")
        if is_harness:
            self._inside_harness = True
        self.generic_visit(node)
        if is_harness:
            self._inside_harness = False

        if not is_harness:
            return node

        if random.random() < 0.15:  # 15% chance
            scenario = random.choice(
                [
                    "chaos_class_match",
                    "type_switcher",
                    "walrus_guard",
                    "exhaustive_patterns",
                ]
            )

            prefix = f"pm_{random.randint(1000, 9999)}"

            if scenario == "chaos_class_match" and self.helper_injected:
                self._inject_chaos_class_match(node, prefix)
            elif scenario == "type_switcher":
                self._inject_type_switcher_scenario(node, prefix)
            elif scenario == "walrus_guard":
                self._inject_walrus_guard_scenario(node, prefix)
            else:
                self._inject_exhaustive_patterns(node, prefix)

            ast.fix_missing_locations(node)

        return node

    def _inject_chaos_class_match(self, node: ast.FunctionDef, prefix: str) -> None:
        """Inject match using the chaos class with dynamic __match_args__."""
        print(
            f"    -> Injecting chaos class match scenario with prefix '{prefix}'",
            file=sys.stderr,
        )

        scenario_code = dedent(f"""
            # Chaos class match scenario - dynamic __match_args__
            for _i_{prefix} in range(200):
                _obj_{prefix} = {self.HELPER_CLASS_NAME}(_i_{prefix}, _i_{prefix} * 2, _i_{prefix} * 3)
                try:
                    match _obj_{prefix}:
                        case {self.HELPER_CLASS_NAME}(a):
                            _result_{prefix} = a
                        case {self.HELPER_CLASS_NAME}(a, b):
                            _result_{prefix} = a + b
                        case {self.HELPER_CLASS_NAME}(a, b, c):
                            _result_{prefix} = a + b + c
                        case _:
                            _result_{prefix} = -1
                except Exception:
                    pass
        """)

        try:
            scenario_nodes = ast.parse(scenario_code).body
            node.body = scenario_nodes + node.body
        except SyntaxError:
            pass

    def _inject_type_switcher_scenario(self, node: ast.FunctionDef, prefix: str) -> None:
        """Inject match using type-switching subject."""
        print(
            f"    -> Injecting type-switcher match scenario with prefix '{prefix}'",
            file=sys.stderr,
        )

        # First inject the helper class
        helper_code = self._create_type_switching_subject(prefix)
        node.body = helper_code + node.body

        scenario_code = dedent(f"""
            # Type-switching subject scenario
            _data_{prefix} = [1, 2, 3]
            _switcher_{prefix} = _TypeSwitcher_{prefix}(_data_{prefix})
            for _i_{prefix} in range(150):
                try:
                    match _switcher_{prefix}:
                        case []: _result_{prefix} = "empty"
                        case [x]: _result_{prefix} = f"one: {{x}}"
                        case [x, y]: _result_{prefix} = f"two: {{x}}, {{y}}"
                        case [x, y, *rest]: _result_{prefix} = f"many: {{len(rest)}}"
                        case _: _result_{prefix} = "unknown"
                except Exception:
                    _result_{prefix} = "error"
        """)

        try:
            scenario_nodes = ast.parse(scenario_code).body
            # Insert after the class definition
            insert_idx = len(helper_code)
            node.body[insert_idx:insert_idx] = scenario_nodes
        except SyntaxError:
            pass

    def _inject_walrus_guard_scenario(self, node: ast.FunctionDef, prefix: str) -> None:
        """Inject match with walrus operator (:=) in guards for side effects."""
        print(
            f"    -> Injecting walrus guard match scenario with prefix '{prefix}'",
            file=sys.stderr,
        )

        scenario_code = dedent(f"""
            # Walrus operator in guards - captures and modifies during match
            _counter_{prefix} = [0]  # Mutable counter
            _data_{prefix} = [[1, 2], [3, 4, 5], [6], [], [7, 8, 9, 10]]
            for _item_{prefix} in _data_{prefix} * 50:
                try:
                    match _item_{prefix}:
                        case [x, y] if (_counter_{prefix}.__setitem__(0, _counter_{prefix}[0] + 1) or True):
                            _result_{prefix} = x + y
                        case [x, y, z] if ((_n_{prefix} := len(_item_{prefix})) > 2):
                            _result_{prefix} = x + y + z + _n_{prefix}
                        case [single] if (_counter_{prefix}[0] % 10 == 0):
                            _result_{prefix} = single * 2
                        case [] if (_counter_{prefix}[0] > 100):
                            _result_{prefix} = -999
                        case _:
                            _result_{prefix} = 0
                except Exception:
                    pass
        """)

        try:
            scenario_nodes = ast.parse(scenario_code).body
            node.body = scenario_nodes + node.body
        except SyntaxError:
            pass

    def _inject_exhaustive_patterns(self, node: ast.FunctionDef, prefix: str) -> None:
        """Inject match with many overlapping patterns to stress backtracking."""
        print(
            f"    -> Injecting exhaustive patterns scenario with prefix '{prefix}'",
            file=sys.stderr,
        )

        scenario_code = dedent(f"""
            # Exhaustive overlapping patterns - stress backtracking
            _subjects_{prefix} = [
                [1, 2, 3],
                (1, 2),
                {{'a': 1, 'b': 2}},
                {{'x': [1, 2], 'y': (3, 4)}},
                [[1], [2, 3]],
                1,
                "string",
                None,
            ]
            for _i_{prefix} in range(100):
                _subj_{prefix} = _subjects_{prefix}[_i_{prefix} % len(_subjects_{prefix})]
                try:
                    match _subj_{prefix}:
                        # Deeply nested patterns
                        case {{'x': [a, b], 'y': (c, d)}}:
                            _result_{prefix} = a + b + c + d
                        case {{'x': [*items], 'y': _}}:
                            _result_{prefix} = sum(items) if items else 0
                        # Or patterns with different structures
                        case [1, 2, 3] | (1, 2, 3):
                            _result_{prefix} = 6
                        case [a, b] | (a, b):
                            _result_{prefix} = a + b if isinstance(a, int) else 0
                        # Sequence with rest
                        case [first, *middle, last]:
                            _result_{prefix} = first + last
                        # Mapping with rest
                        case {{'a': x, **rest}}:
                            _result_{prefix} = x + len(rest)
                        # Class patterns
                        case int(x) if x > 0:
                            _result_{prefix} = x * 2
                        case str(s) if len(s) > 0:
                            _result_{prefix} = len(s)
                        case None:
                            _result_{prefix} = 0
                        case _:
                            _result_{prefix} = -1
                except Exception:
                    _result_{prefix} = -999
        """)

        try:
            scenario_nodes = ast.parse(scenario_code).body
            node.body = scenario_nodes + node.body
        except SyntaxError:
            pass
