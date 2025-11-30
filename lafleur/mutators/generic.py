"""
This module provides a suite of generic, structural mutation strategies.

These mutators are general-purpose and do not rely on specific JIT behaviors.
They perform fundamental AST transformations such as swapping operators,
perturbing constants, changing container types, and injecting basic control
flow structures like loops and guards.
"""

from __future__ import annotations

import ast
import builtins
import copy
import random
import sys
from textwrap import dedent

from lafleur.mutators.utils import is_simple_statement


class OperatorSwapper(ast.NodeTransformer):
    """Swap binary operators like `+` with `*`, avoiding overly large numbers."""

    # A rich suite of plausible substitutions for arithmetic and bitwise operators.
    OP_MAP = {
        # Arithmetic Operators, without Pow because it generates huge numbers
        ast.Add: [ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod],
        ast.Sub: [ast.Add, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod],
        ast.Mult: [ast.Add, ast.Sub, ast.Div, ast.FloorDiv],
        ast.Div: [ast.Mult, ast.Add, ast.Sub, ast.FloorDiv],
        ast.FloorDiv: [ast.Div, ast.Mult, ast.Add, ast.Sub, ast.Mod],
        ast.Mod: [ast.FloorDiv, ast.Add, ast.Sub],
        # Bitwise Operators, without LShift because it generates huge numbers
        ast.LShift: [ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor],
        ast.RShift: [ast.BitAnd, ast.BitOr, ast.BitXor],
        ast.BitAnd: [ast.BitOr, ast.BitXor, ast.RShift],
        ast.BitOr: [ast.BitAnd, ast.BitXor, ast.RShift],
        ast.BitXor: [ast.BitAnd, ast.BitOr, ast.RShift],
    }

    def visit_BinOp(self, node: ast.AST) -> ast.AST:
        op_type = type(node.op)
        if op_type in self.OP_MAP and random.random() < 0.3:
            new_op_class = random.choice(self.OP_MAP[op_type])
            node.op = new_op_class()
        return node


class ComparisonSwapper(ast.NodeTransformer):
    """Swap comparison operators like `<` with `>=`."""

    OP_MAP = {
        ast.Lt: ast.GtE,
        ast.GtE: ast.Lt,
        ast.Gt: ast.LtE,
        ast.LtE: ast.Gt,
        ast.Eq: ast.NotEq,
        ast.NotEq: ast.Eq,
        ast.Is: ast.IsNot,
        ast.IsNot: ast.Is,
    }

    def visit_Compare(self, node: ast.AST) -> ast.AST:
        if random.random() < 0.5:
            new_ops = [self.OP_MAP.get(type(op), type(op))() for op in node.ops]
            node.ops = new_ops
        return node


class ConstantPerturbator(ast.NodeTransformer):
    """Slightly modify numeric and string constants."""

    def visit_Constant(self, node: ast.AST) -> ast.AST:
        if isinstance(node.value, int) and random.random() < 0.3:
            node.value += random.choice([-1, 1, 2])
        elif isinstance(node.value, str) and node.value and random.random() < 0.3:
            pos = random.randint(0, len(node.value) - 1)
            char_val = ord(node.value[pos])
            new_char = chr(char_val + random.choice([-1, 1]))
            node.value = node.value[:pos] + new_char + node.value[pos + 1 :]
        return node


class BoundaryValuesMutator(ast.NodeTransformer):
    """
    Replaces numeric constants with interesting boundary values to stress
    JIT specializations for numbers.
    """

    BOUNDARY_VALUES = [
        # Integers
        "0",
        "-1",
        "2**31 - 1",  # Max signed 32-bit int
        "2**31",  # Signed 32-bit int overflow
        "-2**31",  # Min signed 32-bit int
        "-2**31 - 1",  # Signed 32-bit int underflow
        "2**63 - 1",  # Max signed 64-bit int
        "2**63",  # Signed 64-bit int overflow
        "-2**63",  # Min signed 64-bit int
        "-2**63 - 1",  # Signed 64-bit int underflow
        "2 ** 1024",  # Large positive int
        "-2 ** 1024",  # Large negative int
        "sys.maxsize",
        "sys.maxsize - 1",
        "sys.maxsize + 1",
        "-sys.maxsize",
        "-sys.maxsize + 1",
        "-sys.maxsize - 1",
        # Floats
        "0.0",
        "-0.0",
        "float('inf')",
        "float('-inf')",
        "float('nan')",
        "sys.float_info.max",
        "sys.float_info.min",
        "sys.float_info.epsilon",
        "float(10**15000)",
        "-float(10**15000)",
        "-sys.float_info.max",
        "-sys.float_info.epsilon",
        "sys.float_info.min / 2",
        "-sys.float_info.min / 2",
        "float('0.0000001')",
        "-float('0.0000001')",
        # Complex numbers
        "complex(sys.maxsize, sys.maxsize)",
        "complex(float('inf'), float('nan'))",
        "complex(sys.float_info.max, sys.float_info.epsilon)",
        "1j",
        "-1j",
    ]

    def _safe_unparse(self, node: ast.AST) -> str:
        """
        A helper to unparse an AST node to a string, with a fallback
        for integers that are too large to be converted.
        """
        try:
            return ast.unparse(node)
        except ValueError as e:
            if "int" in str(e) and "too large" in str(e):
                return "(an extremely large integer)"
            # Re-raise other unexpected ValueErrors
            raise

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, (int, float, complex)):
            return node

        if random.random() < 0.2:
            new_value_str = random.choice(self.BOUNDARY_VALUES)
            original_value_str = self._safe_unparse(node)
            print(
                f"    -> Mutating constant '{original_value_str}' to boundary value '{new_value_str}'",
                file=sys.stderr,
            )
            try:
                new_node = ast.parse(new_value_str, mode="eval").body
                return new_node
            except (SyntaxError, ValueError):
                return node
        return node


class GuardInjector(ast.NodeTransformer):
    """Wrap a random statement in a seeded, reproducible 'if' block."""

    def visit(self, node: ast.AST) -> ast.AST | None:
        node = super().visit(node)

        # If a child visitor removed the node, propagate the deletion.
        if node is None:
            return ast.Pass()

        if isinstance(node, ast.stmt) and not isinstance(node, ast.FunctionDef):
            # The test uses our fuzzer-provided, seeded RNG instance.
            test = ast.Compare(
                left=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="fuzzer_rng", ctx=ast.Load()),
                        attr="random",
                        ctx=ast.Load(),
                    ),
                    args=[],
                    keywords=[],
                ),
                ops=[ast.Lt()],
                comparators=[ast.Constant(value=0.1)],  # Low probability
            )
            return ast.If(test=test, body=[node], orelse=[])
        return node


class ContainerChanger(ast.NodeTransformer):
    """Change container types, e.g., from a list to a tuple or set."""

    def visit_List(self, node: ast.AST) -> ast.AST:
        if random.random() < 0.5:
            return ast.Set(elts=node.elts)
        elif random.random() < 0.5:
            return ast.Tuple(elts=node.elts, ctx=node.ctx)
        return node

    def visit_ListComp(self, node: ast.AST) -> ast.AST:
        if random.random() < 0.5:
            return ast.SetComp(elt=node.elt, generators=node.generators)
        return node


class VariableSwapper(ast.NodeTransformer):
    """Swap occurrences of two variable names within a scope."""

    _static_protected_names = frozenset(
        {
            "print",
            "random",
            "next",
            "isinstance",
            "sys",
            "operator",
            "range",
            "len",
            "object",
            "Exception",
            "BaseException",
            "collect",
        }
    )

    _exception_names = {
        name
        for name, obj in builtins.__dict__.items()
        if isinstance(obj, type) and issubclass(obj, BaseException)
    }

    PROTECTED_NAMES = _static_protected_names.union(_exception_names)

    def __init__(self):
        self.var_map = {}

    def visit_Module(self, node: ast.AST) -> ast.AST:
        # Scan for all names used in the module
        all_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

        # Filter out the protected names to get our list of swappable candidates
        swappable_names = sorted(list(all_names - self.PROTECTED_NAMES))

        if len(swappable_names) >= 2:
            # Only choose from the safe, swappable names
            a, b = random.sample(swappable_names, 2)
            self.var_map = {a: b, b: a}

        self.generic_visit(node)
        return node

    def visit_Name(self, node: ast.AST) -> ast.AST:
        node.id = self.var_map.get(node.id, node.id)
        return node


class StatementDuplicator(ast.NodeTransformer):
    """Duplicate a statement."""

    def visit(self, node: ast.AST) -> ast.AST:
        node = super().visit(node)
        if (
            isinstance(node, ast.stmt)
            and not isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module))
            and random.random() < 0.1
        ):
            return [node, copy.deepcopy(node)]
        return node


class VariableRenamer(ast.NodeTransformer):
    """
    Rename variables based on a provided mapping.

    This is used by the splicing strategy to make a donor harness compatible
    with a recipient's setup code.
    """

    def __init__(self, remapping_dict: dict[str, str]):
        self.remapping_dict = remapping_dict

    def visit_Name(self, node: ast.Name) -> ast.Name:
        """Rename a variable if it is present in the remapping dictionary."""
        if node.id in self.remapping_dict:
            node.id = self.remapping_dict[node.id]
        return node


class ForLoopInjector(ast.NodeTransformer):
    """
    A mutator that finds simple statements and wraps them in a for loop
    to make them "hot" for the JIT.
    """

    def _try_inject_loop(self, node: ast.stmt | None) -> ast.stmt | ast.For | None:
        # If the node was removed by a child visitor, return None.
        if node is None:
            return ast.Pass()

        if random.random() < 0.05 and is_simple_statement(node):
            print("    -> Injecting for loop around a statement.", file=sys.stderr)

            loop_var_name = f"i_loop_{random.randint(1000, 9999)}"

            # Choose between range(), a list, or a tuple
            iterable_type = random.choice(["range", "list", "tuple"])

            if iterable_type == "range":
                iterator_node = ast.Call(
                    func=ast.Name(id="range", ctx=ast.Load()),
                    args=[ast.Constant(value=random.randint(50, 200))],
                    keywords=[],
                )
            else:  # list or tuple
                elements = [ast.Constant(value=i) for i in range(random.randint(5, 20))]
                if iterable_type == "list":
                    iterator_node = ast.List(elts=elements, ctx=ast.Load())
                else:  # tuple
                    iterator_node = ast.Tuple(elts=elements, ctx=ast.Load())

            # Create the new For node, with the original statement as its body
            for_node = ast.For(
                target=ast.Name(id=loop_var_name, ctx=ast.Store()),
                iter=iterator_node,
                body=[node],
                orelse=[],
            )
            return for_node
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.stmt | None:
        # The call to generic_visit might return None if a child visitor
        # removes the node. We must respect this.
        node = self.generic_visit(node)
        return self._try_inject_loop(node)

    def visit_Expr(self, node: ast.Expr) -> ast.stmt | None:
        node = self.generic_visit(node)
        if node and isinstance(node.value, ast.Call):
            return self._try_inject_loop(node)
        return node


class GuardRemover(ast.NodeTransformer):
    """
    Finds conditional blocks injected by GuardInjector and replaces them
    with their body, effectively removing the guard.
    """

    def is_rng_check(self, node: ast.AST) -> bool:
        """Check if an AST node is our specific `fuzzer_rng.random()` call."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "random"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "fuzzer_rng"
        )

    def visit_If(self, node: ast.If) -> ast.AST:
        # First, visit children to allow nested removals.
        self.generic_visit(node)

        # Check if the test condition is `fuzzer_rng.random() < ...`
        if isinstance(node.test, ast.Compare) and self.is_rng_check(node.test.left):
            if random.random() < 0.25:
                print("    -> Removing fuzzer-injected guard.", file=sys.stderr)

                # If the body is not empty, unwrap it.
                # If the body IS empty (because a child visitor removed its contents),
                # replace the entire 'if' with a 'pass' to maintain valid syntax.
                return node.body if node.body else ast.Pass()

        return node


class BlockTransposerMutator(ast.NodeTransformer):
    """
    Selects a random, contiguous block of statements from a function
    body and moves it to a new random location within the same body.
    """

    MIN_STATEMENTS_FOR_TRANSPOSE = 6
    BLOCK_SIZE = 3

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        body_len = len(node.body)
        if body_len < self.MIN_STATEMENTS_FOR_TRANSPOSE:
            return node

        if random.random() < 0.05:
            # 1. Select a random block of statements to move.
            # We ensure the block doesn't exceed the list bounds.
            start_index = random.randint(0, body_len - self.BLOCK_SIZE)
            block = node.body[start_index : start_index + self.BLOCK_SIZE]

            # 2. Remove the block from its original position.
            del node.body[start_index : start_index + self.BLOCK_SIZE]

            # 3. Choose a new, random insertion point in the now-shorter list.
            new_len = len(node.body)
            insert_index = random.randint(0, new_len)

            print(
                f"    -> Transposing block from index {start_index} to {insert_index}",
                file=sys.stderr,
            )

            # 4. Insert the block at the new location.
            node.body[insert_index:insert_index] = block

            ast.fix_missing_locations(node)

        return node


class UnpackingMutator(ast.NodeTransformer):
    """
    Finds simple assignments and rewrites them to use complex tuple unpacking,
    including a starred expression.
    """

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        self.generic_visit(node)

        # We only want to mutate simple assignments, e.g., `x = ...`
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return node

        if random.random() < 0.01:
            original_var = node.targets[0]
            print(f"    -> Applying unpacking mutation to '{original_var.id}'", file=sys.stderr)

            # 1. Create a new, complex unpacking target
            # e.g., (var1, *, var2, original_var)
            num_new_vars = random.randint(2, 30)
            new_vars = [f"unpack_var_{random.randint(10000, 99999)}" for _ in range(num_new_vars)]

            new_target_tuple = ast.Tuple(
                elts=[
                    ast.Name(id=new_vars[0], ctx=ast.Store()),
                    ast.Starred(value=ast.Name(id=new_vars[1], ctx=ast.Store()), ctx=ast.Store()),
                    original_var,
                ]
                + [ast.Name(id=new_vars[x], ctx=ast.Store()) for x in range(2, num_new_vars)],
                ctx=ast.Store(),
            )

            # 2. Create a new value list that can be unpacked by the target
            # The list must have at least 2 elements for this target.
            num_elements = random.randint(num_new_vars, num_new_vars + 30)
            new_value_list = ast.List(
                elts=[
                    ast.Constant(value=random.choice([1, "eggs", None, True, 3.14, b"spam"]))
                    for _ in range(num_elements)
                ],
                ctx=ast.Load(),
            )

            # 3. Replace the original assignment node
            node.targets = [new_target_tuple]
            node.value = new_value_list
            ast.fix_missing_locations(node)

        return node


def _create_logging_decorator_ast(decorator_name: str) -> ast.FunctionDef:
    """
    Programmatically create the AST for a simple logging decorator.

    Equivalent to:
    def logging_decorator(func):
        def wrapper(*args, **kwargs):
            print(f"Calling {func.__name__}")
            return func(*args, **kwargs)
        return wrapper
    """
    func_name_str = ast.Constant(value="Calling {func.__name__}")

    decorator_def = ast.FunctionDef(
        name=decorator_name,
        args=ast.arguments(
            args=[ast.arg(arg="func")], posonlyargs=[], kwonlyargs=[], kw_defaults=[], defaults=[]
        ),
        body=[
            ast.FunctionDef(
                name="wrapper",
                args=ast.arguments(
                    args=[],
                    posonlyargs=[],
                    vararg=ast.arg(arg="args"),
                    kwarg=ast.arg(arg="kwargs"),
                    kw_defaults=[],
                    defaults=[],
                ),
                body=[
                    ast.Expr(
                        value=ast.Call(
                            func=ast.Name(id="print", ctx=ast.Load()),
                            args=[
                                ast.Call(
                                    func=ast.Attribute(
                                        value=func_name_str, attr="format", ctx=ast.Load()
                                    ),
                                    args=[],
                                    keywords=[
                                        ast.keyword(
                                            arg="func", value=ast.Name(id="func", ctx=ast.Load())
                                        )
                                    ],
                                )
                            ],
                            keywords=[],
                        )
                    ),
                    ast.Return(
                        value=ast.Call(
                            func=ast.Name(id="func", ctx=ast.Load()),
                            args=[
                                ast.Starred(
                                    value=ast.Name(id="args", ctx=ast.Load()), ctx=ast.Load()
                                )
                            ],
                            keywords=[
                                ast.keyword(arg=None, value=ast.Name(id="kwargs", ctx=ast.Load()))
                            ],
                        )
                    ),
                ],
                decorator_list=[],
            ),
            ast.Return(value=ast.Name(id="wrapper", ctx=ast.Load())),
        ],
        decorator_list=[],
    )
    return decorator_def


class DecoratorMutator(ast.NodeTransformer):
    """
    Finds a nested function definition and wraps it with a simple,
    dynamically-injected decorator.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        # We only want to mutate our main harness function
        if not node.name.startswith("uop_harness"):
            return node

        # Find a nested function to decorate
        nested_func_target = None
        for sub_node in node.body:
            if isinstance(sub_node, ast.FunctionDef):
                nested_func_target = sub_node
                break

        if nested_func_target and random.random() < 0.2:  # 20% chance
            decorator_name = f"fuzzer_decorator_{random.randint(1000, 9999)}"
            print(
                f"    -> Decorating nested function '{nested_func_target.name}' with '@{decorator_name}'",
                file=sys.stderr,
            )

            # 1. Create the decorator function's AST
            decorator_ast = _create_logging_decorator_ast(decorator_name)

            # 2. Inject the decorator's definition at the top of the harness body
            node.body.insert(0, decorator_ast)

            # 3. Apply the decorator to the nested function
            nested_func_target.decorator_list.append(ast.Name(id=decorator_name, ctx=ast.Load()))

            ast.fix_missing_locations(node)

        return node


class SliceMutator(ast.NodeTransformer):
    """
    Finds list or tuple variables and injects slicing operations (read,
    write, delete, or read-from-variable) to target slice-related uops.
    """

    def _create_random_slice(self) -> ast.Slice:
        """Helper to generate an ast.Slice with random values."""
        slice_parts = [
            None,
            ast.Constant(value=random.randint(-5, 5)),
            ast.Constant(value=random.randint(-5, 5)),
        ]
        lower = random.choice(slice_parts)
        upper = random.choice(slice_parts)
        # Step cannot be zero
        step_val = random.choice([-2, -1, 1, 2, None])
        step = ast.Constant(value=step_val) if step_val is not None else None

        return ast.Slice(lower=lower, upper=upper, step=step)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        # Find all list and tuple variables in the current scope
        list_vars = []
        sequence_vars = []
        for sub_node in node.body:
            if (
                isinstance(sub_node, ast.Assign)
                and len(sub_node.targets) == 1
                and isinstance(sub_node.targets[0], ast.Name)
            ):
                var_name = sub_node.targets[0].id
                if isinstance(sub_node.value, ast.List):
                    list_vars.append(var_name)
                    sequence_vars.append(var_name)
                elif isinstance(sub_node.value, ast.Tuple):
                    sequence_vars.append(var_name)

        if not sequence_vars:
            return node

        if random.random() < 0.25:  # 25% chance to apply
            target_var = random.choice(sequence_vars)
            operation_choices = ["read", "read_slice_obj"]
            if target_var in list_vars:
                # Write and delete are only valid for lists
                operation_choices.extend(["write", "delete"])

            operation = random.choice(operation_choices)

            new_node = None
            nodes_to_inject = []

            # Create a read operation: new_var = target_var[...]
            if operation == "read":
                print(f"    -> Injecting slice read on '{target_var}'", file=sys.stderr)
                random_slice = self._create_random_slice()
                new_node = ast.parse(
                    f"slice_var_{random.randint(1000, 9999)} = {target_var}[{ast.unparse(random_slice)}]"
                ).body[0]
                nodes_to_inject = [new_node]

            # Create a write operation: target_var[...] = [1, 2, 3]
            elif operation == "write":
                print(f"    -> Injecting slice write on '{target_var}'", file=sys.stderr)
                random_slice = self._create_random_slice()
                new_node = ast.parse(f"{target_var}[{ast.unparse(random_slice)}] = [1, 2, 3]").body[
                    0
                ]
                nodes_to_inject = [new_node]

            # Create a delete operation: del target_var[...]
            elif operation == "delete":
                print(f"    -> Injecting slice delete on '{target_var}'", file=sys.stderr)
                random_slice = self._create_random_slice()
                new_node = ast.parse(f"del {target_var}[{ast.unparse(random_slice)}]").body[0]
                nodes_to_inject = [new_node]

            elif operation == "read_slice_obj":
                print(f"    -> Injecting slice object read on '{target_var}'", file=sys.stderr)
                slice_var_name = f"slice_obj_{random.randint(1000, 9999)}"
                start = random.choice(["None", str(random.randint(-5, 5))])
                stop = random.choice(["None", str(random.randint(-5, 5))])

                # This injects a variable assignment and a hot loop that uses it.
                scenario_str = dedent(f"""
                            {slice_var_name} = slice({start}, {stop})
                            try:
                                for _ in range(50):
                                    _ = {target_var}[{slice_var_name}]
                            except Exception:
                                pass
                            """)
                nodes_to_inject = ast.parse(scenario_str).body
            # --- END NEW ---

            if nodes_to_inject:
                injection_point = random.randint(0, len(node.body))
                node.body[injection_point:injection_point] = nodes_to_inject
                ast.fix_missing_locations(node)

        return node
