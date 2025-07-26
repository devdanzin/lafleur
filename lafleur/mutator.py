"""
This module provides the AST-based structural mutation engine for the lafleur fuzzer.

It contains the `ASTMutator` class and its library of `NodeTransformer`
subclasses. Its purpose is to take an Abstract Syntax Tree (AST) and
apply a randomized pipeline of transformations to structurally alter the code.
The transformations include swapping operators, perturbing constants, and
injecting complex, JIT-specific stress patterns.
"""

from __future__ import annotations

import ast
import builtins
import random
import copy
import sys
from textwrap import dedent, indent


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


class GuardInjector(ast.NodeTransformer):
    """Wrap a random statement in a seeded, reproducible 'if' block."""

    def visit(self, node: ast.AST) -> ast.AST:
        # First, visit children to avoid infinite recursion
        node = super().visit(node)
        # Only wrap statement nodes
        if isinstance(node, ast.stmt) and not isinstance(node, ast.FunctionDef):
            # The test uses our fuzzer-provided, seeded RNG instance.
            test = ast.Compare(
                left=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='fuzzer_rng', ctx=ast.Load()),
                        attr='random',
                        ctx=ast.Load()
                    ),
                    args=[],
                    keywords=[]
                ),
                ops=[ast.Lt()],
                comparators=[ast.Constant(value=0.1)] # Low probability
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


# ==============================================================================
# Stress Pattern Injection Engine
# ==============================================================================

# Note: These functions are adapted from ASTPatternGenerator and made generic.


def _create_type_corruption_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to corrupt the type of a variable (e.g., `x = 'string'`)."""
    corruption_value = random.choice(
        [
            ast.Constant(value="corrupted by string"),
            ast.Constant(value=None),
            ast.Constant(value=123.456),
        ]
    )
    return [ast.Assign(targets=[ast.Name(id=target_var, ctx=ast.Store())], value=corruption_value)]


def _create_uop_attribute_deletion_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to delete an attribute (e.g., `del obj.x`)."""
    attr_to_delete = random.choice(["value", "x", "y"])
    return [
        ast.Delete(
            targets=[
                ast.Attribute(
                    value=ast.Name(id=target_var, ctx=ast.Load()),
                    attr=attr_to_delete,
                    ctx=ast.Del(),
                )
            ]
        )
    ]


def _create_method_patch_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to monkey-patch a method on a class."""
    method_to_patch = random.choice(["get_value", "meth", "__repr__"])
    lambda_payload = ast.Lambda(
        args=ast.arguments(
            posonlyargs=[],
            args=[],
            vararg=ast.arg(arg="a"),
            kwarg=ast.arg(arg="kw"),
            kw_defaults=[],
            defaults=[],
        ),
        body=ast.Constant(value="patched!"),
    )
    return [
        ast.Assign(
            targets=[
                ast.Attribute(
                    value=ast.Attribute(
                        value=ast.Name(id=target_var, ctx=ast.Load()),
                        attr="__class__",
                        ctx=ast.Load(),
                    ),
                    attr=method_to_patch,
                    ctx=ast.Store(),
                )
            ],
            value=lambda_payload,
        )
    ]


def _create_dict_swap_node(var1_name: str, var2_name: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to swap the __dict__ of two objects."""
    return [
        ast.Assign(
            targets=[
                ast.Tuple(
                    elts=[
                        ast.Attribute(
                            value=ast.Name(id=var1_name, ctx=ast.Load()),
                            attr="__dict__",
                            ctx=ast.Store(),
                        ),
                        ast.Attribute(
                            value=ast.Name(id=var2_name, ctx=ast.Load()),
                            attr="__dict__",
                            ctx=ast.Store(),
                        ),
                    ],
                    ctx=ast.Store(),
                )
            ],
            value=ast.Tuple(
                elts=[
                    ast.Attribute(
                        value=ast.Name(id=var2_name, ctx=ast.Load()),
                        attr="__dict__",
                        ctx=ast.Load(),
                    ),
                    ast.Attribute(
                        value=ast.Name(id=var1_name, ctx=ast.Load()),
                        attr="__dict__",
                        ctx=ast.Load(),
                    ),
                ],
                ctx=ast.Load(),
            ),
        )
    ]


def _create_class_reassignment_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate AST nodes to define a new class and reassign `obj.__class__`."""
    new_class_name = f"SwappedClass_{random.randint(1000, 9999)}"
    class_def_node = ast.ClassDef(
        name=new_class_name, bases=[], keywords=[], body=[ast.Pass()], decorator_list=[]
    )
    assign_node = ast.Assign(
        targets=[
            ast.Attribute(
                value=ast.Name(id=target_var, ctx=ast.Load()), attr="__class__", ctx=ast.Store()
            )
        ],
        value=ast.Name(id=new_class_name, ctx=ast.Load()),
    )
    return [class_def_node, assign_node]


class StressPatternInjector(ast.NodeTransformer):
    """
    Inject a hand-crafted "evil" stress pattern into a function's body.

    This mutator randomly selects from a variety of known-bad patterns, such
    as type corruption or attribute deletion, and injects the corresponding
    AST nodes into the harness function.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # First, visit children to allow them to be transformed.
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Probabilistically decide whether to inject a pattern into this function.
        if random.random() < 0.15:  # 15% chance
            # 1. Find all variables that are assigned to in this function's scope.
            local_vars = {
                n.id
                for n in ast.walk(node)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
            }
            if not local_vars:
                return node  # No variables to target.

            target_var = random.choice(list(local_vars))

            # 2. Choose an evil action to perform.
            # Note: _create_dict_swap_node requires two variables.
            single_target_actions = [
                _create_type_corruption_node,
                _create_uop_attribute_deletion_node,
                _create_method_patch_node,
                _create_class_reassignment_node,
            ]
            if len(local_vars) >= 2:
                action = random.choice(single_target_actions + [_create_dict_swap_node])
            else:
                action = random.choice(single_target_actions)

            print(
                f"    -> Injecting stress pattern '{action.__name__}' targeting '{target_var}'",
                file=sys.stderr,
            )

            # 3. Generate the evil snippet's AST nodes.
            if action == _create_dict_swap_node:
                var1, var2 = random.sample(list(local_vars), 2)
                snippet_nodes = action(var1_name=var1, var2_name=var2)
            else:
                snippet_nodes = action(target_var=target_var)

            # 4. Insert the snippet at a random point in the function body.
            if node.body:
                insert_pos = random.randint(0, len(node.body))
                node.body[insert_pos:insert_pos] = snippet_nodes

        return node


class TypeInstabilityInjector(ast.NodeTransformer):
    """
    Attack the JIT's type speculation by changing a variable's type in a hot loop.

    It finds a variable used in a `for` loop, then injects a trigger
    (e.g., `if i == N:`) that reassigns the variable to an incompatible type.
    The original operations are wrapped in a `try...except` block to handle
    the resulting `TypeError` and allow the fuzzer to continue.
    """

    def visit_For(self, node: ast.For) -> ast.For:
        # First, visit children to process any nested loops.
        self.generic_visit(node)

        if random.random() > 0.1:
            return node

        # We need a loop variable to key the corruption off of.
        if not isinstance(node.target, ast.Name):
            return node

        # Find a variable assigned to within the loop to be our target.
        assigned_vars = {
            n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
        }
        if not assigned_vars:
            return node  # No variables to corrupt.

        target_var_name = random.choice(list(assigned_vars))
        loop_var_name = node.target.id

        print(
            f"    -> Injecting type instability pattern targeting '{target_var_name}' in loop",
            file=sys.stderr,
        )

        # 1. Create the poison assignment: target_var = "corrupted"
        poison_assignment = ast.Assign(
            targets=[ast.Name(id=target_var_name, ctx=ast.Store())],
            value=ast.Constant(value="corrupted by type instability"),
        )
        # 2. Create the trigger: if i == N: ...
        trigger_if = ast.If(
            test=ast.Compare(
                left=ast.Name(id=loop_var_name, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=random.randint(100, 400))],
            ),
            body=[poison_assignment],
            orelse=[],
        )

        # 3. Create the recovery assignment: target_var = i
        recovery_assignment = ast.Assign(
            targets=[ast.Name(id=target_var_name, ctx=ast.Store())],
            value=ast.Name(id=loop_var_name, ctx=ast.Load()),
        )

        # 4. Wrap the entire original loop body in a try...except... block
        new_body = [trigger_if] + node.body
        try_block = ast.Try(
            body=new_body,
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id="TypeError", ctx=ast.Load()),
                    name=None,
                    body=[recovery_assignment],
                )
            ],
            orelse=[],
            finalbody=[],
        )

        node.body = [try_block]
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


class InlineCachePolluter(ast.NodeTransformer):
    """
    Attack JIT inline caches by injecting a megamorphic call site.

    This mutator injects a scenario that defines several classes with a
    method of the same name, then calls that method on instances of each
    class inside a hot loop. This stresses the JIT's call-site caching.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # Low probability of injecting
            print(
                f"    -> Injecting inline cache pollution pattern into '{node.name}'",
                file=sys.stderr,
            )

            # 1. Create the class definitions and instance list as an AST
            p_prefix = f"p_{random.randint(1000, 9999)}"
            setup_code = dedent(f"""
                class Polluter_A_{p_prefix}:
                    def do_it(self): return 1
                class Polluter_B_{p_prefix}:
                    def do_it(self): return 'foo'
                class Polluter_C_{p_prefix}:
                    def do_it(self): return None
                class Polluter_D_{p_prefix}:
                    def do_it(self): return [1, 2]

                polluters = [Polluter_A_{p_prefix}(), Polluter_B_{p_prefix}(), Polluter_C_{p_prefix}(), Polluter_D_{p_prefix}()]
            """)
            setup_ast = ast.parse(setup_code).body

            # 2. Create the loop that makes the polymorphic calls
            call_loop_code = dedent("""
                p = polluters[i % len(polluters)]
                try:
                    p.do_it()
                except Exception:
                    pass
            """)
            loop_node = ast.For(
                target=ast.Name(id="i", ctx=ast.Store()),
                iter=ast.Call(
                    func=ast.Name(id="range", ctx=ast.Load()),
                    args=[ast.Constant(value=500)],
                    keywords=[],
                ),
                body=ast.parse(call_loop_code).body,
                orelse=[],
            )

            # 3. Prepend the setup and the loop to the function's body
            node.body = setup_ast + [loop_node] + node.body

        return node


class SideEffectInjector(ast.NodeTransformer):
    """
    Inject a scenario that uses a `__del__` side effect to attack state stability.

    This mutator injects a `FrameModifier` class whose `__del__` method can
    maliciously alter the state of a function's local variables. It then
    instantiates and deletes this class inside a hot loop to trigger the
    side effect at a predictable time, testing the JIT's deoptimization
    pathways.
    """

    def _get_frame_modifier_class_ast(self, prefix, target_path_str, payload_str):
        """Builds the AST for the FrameModifier class."""
        class_name = f"FrameModifier_{prefix}"
        template = dedent(f"""
            class {class_name}:
                def __del__(self):
                    try:
                        # Attempt to get the frame of our harness function
                        frame = sys._getframe(1)
                        # The malicious payload assignment
                        exec('{target_path_str} = {payload_str}', frame.f_globals, frame.f_locals)
                    except Exception:
                        pass
        """)
        return ast.parse(template).body[0]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Low probability of this complex and invasive mutation
        if random.random() > 0.15:
            return node

        # --- 1. Find potential targets in the function's AST ---
        local_vars = {
            n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
        }
        # For simplicity, we'll just look for a local variable to target for now.
        # A more advanced version could find instance and class attributes.
        if not local_vars:
            return node

        print(f"    -> Injecting __del__ side-effect pattern into '{node.name}'", file=sys.stderr)

        # --- 2. Choose a target and a payload ---
        prefix = f"{node.name}_{random.randint(1000, 9999)}"
        target_var = random.choice(list(local_vars))
        payload = random.choice(['"corrupted_by_del"', "None", "123.456"])

        # --- 3. Build the components of the scenario ---

        # a) The FrameModifier class definition
        fm_class_ast = self._get_frame_modifier_class_ast(prefix, target_var, payload)

        # b) The instantiation of the FrameModifier
        fm_instance_name = f"fm_{prefix}"
        fm_instantiation_ast = ast.Assign(
            targets=[ast.Name(id=fm_instance_name, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id=fm_class_ast.name, ctx=ast.Load()), args=[], keywords=[]
            ),
        )

        # c) The hot loop containing the attack
        loop_var = f"i_{prefix}"
        trigger_iteration = random.randint(300, 450)

        # Code to use the variable before corruption
        use_before_str = f"_ = {target_var} * 2"
        # Code to use the variable after corruption
        use_after_str = f"_ = {target_var} * 2"

        loop_body_template = dedent(f"""
            # Use the variable to warm up the JIT
            try:
                {use_before_str}
            except Exception:
                pass

            # The trigger
            if {loop_var} == {trigger_iteration}:
                print('[{prefix}] Triggering __del__ side effect for {target_var}...', file=sys.stderr)
                del {fm_instance_name}
                # gc.collect() is not available here, but the del is often sufficient

            # Use the variable again, potentially hitting a corrupted state
            try:
                {use_after_str}
            except TypeError:
                # If we get a TypeError, reset the variable so the loop can continue
                {target_var} = {loop_var}
        """)

        hot_loop_ast = ast.For(
            target=ast.Name(id=loop_var, ctx=ast.Store()),
            iter=ast.Call(
                func=ast.Name(id="range", ctx=ast.Load()),
                args=[ast.Constant(value=500)],
                keywords=[],
            ),
            body=ast.parse(loop_body_template).body,
            orelse=[],
        )

        # 4. Inject the entire scenario at the top of the function body
        node.body = [fm_class_ast, fm_instantiation_ast, hot_loop_ast] + node.body
        ast.fix_missing_locations(node)
        return node


def _is_simple_statement(node: ast.stmt) -> bool:
    """
    Walk a statement's AST to check for nodes unsafe to wrap in a loop.

    Return `False` if the statement contains `return`, `break`, `continue`,
    or `del`.
    """
    for sub_node in ast.walk(node):
        if isinstance(sub_node, (ast.Return, ast.Break, ast.Continue, ast.Delete)):
            return False
    return True


class ForLoopInjector(ast.NodeTransformer):
    """
    Find a simple statement and wrap it in a `for` loop to make it "hot".
    """

    def _try_inject_loop(self, node: ast.stmt) -> ast.stmt | ast.For:
        # Low probability for this mutation
        if random.random() < 0.05 and _is_simple_statement(node):
            print("    -> Injecting for loop around a statement.", file=sys.stderr)

            # Choose a random iterable for the loop
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

    def visit_Assign(self, node: ast.Assign) -> ast.stmt:
        self.generic_visit(node)
        return self._try_inject_loop(node)

    def visit_Expr(self, node: ast.Expr) -> ast.stmt:
        self.generic_visit(node)
        # We only want to loop simple expressions, not complex ones that define classes etc.
        if isinstance(node.value, ast.Call):
            return self._try_inject_loop(node)
        return node


class GlobalInvalidator(ast.NodeTransformer):
    """
    Attack the JIT's global versioning caches by modifying `globals()`.

    This mutator injects a statement that adds a new key to the `globals()`
    dictionary, forcing an invalidation of JIT caches that depend on it.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # First, visit children to allow them to be transformed.
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Low probability for this mutation
        if random.random() < 0.1:
            if not node.body:  # Don't inject into an empty function
                return node

            print(
                f"    -> Injecting global invalidation pattern into '{node.name}'", file=sys.stderr
            )

            # 1. Create the AST for: globals()['fuzzer_...'] = None
            key_name = f"fuzzer_invalidation_key_{random.randint(1000, 99999)}"

            invalidation_node = ast.Assign(
                targets=[
                    ast.Subscript(
                        value=ast.Call(
                            func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[]
                        ),
                        slice=ast.Constant(value=key_name),
                        ctx=ast.Store(),
                    )
                ],
                value=ast.Constant(value=None),
            )

            # 2. Insert the statement at a random point in the function body.
            insert_pos = random.randint(0, len(node.body))
            node.body.insert(insert_pos, invalidation_node)
            ast.fix_missing_locations(node)

        return node


class LoadAttrPolluter(ast.NodeTransformer):
    """
    Attack JIT `LOAD_ATTR` caches by injecting a polymorphic access site.

    This mutator injects a scenario with several classes that define the same
    attribute name in different ways (data, property, slot). It then accesses
    this attribute in a hot loop on instances of each class.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Low probability for this complex injection
        if random.random() < 0.1:
            print(
                f"    -> Injecting LOAD_ATTR cache pollution pattern into '{node.name}'",
                file=sys.stderr,
            )

            p_prefix = f"la_{random.randint(1000, 9999)}"

            # 1. Define the entire scenario as a Python code string.
            # This is easier and cleaner than building each class with AST calls.
            scenario_code = dedent(f"""
                # --- LOAD_ATTR Cache Pollution Scenario ---
                print('[{p_prefix}] Running LOAD_ATTR cache pollution scenario...', file=sys.stderr)

                # a) Define classes with conflicting 'payload' attributes.
                class ShapeA_{p_prefix}:
                    payload = 123
                class ShapeB_{p_prefix}:
                    @property
                    def payload(self):
                        return 'property_payload'
                class ShapeC_{p_prefix}:
                    def payload(self):
                        return id(self)
                class ShapeD_{p_prefix}:
                    __slots__ = ['payload']
                    def __init__(self):
                        self.payload = 'slot_payload'

                # b) Create a list of instances to iterate over.
                shapes_{p_prefix} = [ShapeA_{p_prefix}(), ShapeB_{p_prefix}(), ShapeC_{p_prefix}(), ShapeD_{p_prefix}()]

                # c) In a hot loop, polymorphically access the 'payload' attribute.
                for i in range(500):
                    obj = shapes_{p_prefix}[i % len(shapes_{p_prefix})]
                    try:
                        # This polymorphic access forces the JIT to constantly check
                        # the object's type and the version of its attribute cache.
                        payload_val = obj.payload
                        # If the payload is a method, call it to make the access meaningful.
                        if callable(payload_val):
                            payload_val()
                    except Exception:
                        pass
            """)

            # 2. Parse the string into a list of AST nodes.
            try:
                scenario_nodes = ast.parse(scenario_code).body
            except SyntaxError:
                return node  # Should not happen with a fixed template

            # 3. Prepend the entire scenario to the function's body.
            node.body = scenario_nodes + node.body
            ast.fix_missing_locations(node)

        return node


class ManyVarsInjector(ast.NodeTransformer):
    """
    Inject many local variable declarations to stress `EXTENDED_ARG` handling.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Low probability for this mutation as it adds a lot of code.
        if random.random() < 0.05:
            print(f"    -> Injecting many local variables into '{node.name}'", file=sys.stderr)

            num_vars_to_add = 260  # More than 256 to force EXTENDED_ARG
            p_prefix = f"mv_{random.randint(1000, 9999)}"

            new_var_nodes = []
            for i in range(num_vars_to_add):
                var_name = f"{p_prefix}_{i}"
                assign_node = ast.Assign(
                    targets=[ast.Name(id=var_name, ctx=ast.Store())], value=ast.Constant(value=i)
                )
                new_var_nodes.append(assign_node)

            # Prepend the new variable declarations to the function's body.
            node.body = new_var_nodes + node.body
            ast.fix_missing_locations(node)

        return node


class TypeIntrospectionMutator(ast.NodeTransformer):
    """
    Attack JIT optimizations for introspection built-ins like `isinstance`.

    This mutator injects self-contained stress-testing scenarios into functions
    that use `isinstance` or `hasattr`, leaving the original code intact.
    The scenarios are designed to violate JIT assumptions about type stability.
    """

    def _create_isinstance_polymorphic_attack(self, original_call: ast.Call) -> list[ast.stmt]:
        """
        Generate a self-contained loop where a variable is rapidly
        reassigned to objects of different types before an isinstance call.
        """
        print("    -> Injecting isinstance (polymorphic) attack...", file=sys.stderr)
        type_to_check_node = original_call.args[1]
        type_to_check_str = ast.unparse(type_to_check_node)

        # This attack is now fully self-contained.
        attack_code = dedent(f"""
            # Polymorphic isinstance attack injected by fuzzer
            _poly_list = [1, "a", 3.0, [], (), {{}}, True, b'bytes']
            for i_poly_isinstance in range(300):
                poly_variable = _poly_list[i_poly_isinstance % len(_poly_list)]
                try:
                    # The JIT must guard this call against the changing type
                    isinstance(poly_variable, {type_to_check_str})
                except Exception:
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_isinstance_invalidation_attack(self, original_call: ast.Call) -> list[ast.stmt]:
        """
        Generate a train-then-invalidate scenario where an object's
        __class__ is changed after a hot loop.
        """
        print("    -> Injecting isinstance (invalidation) attack...", file=sys.stderr)
        type_to_check_node = original_call.args[1]
        type_to_check_str = ast.unparse(type_to_check_node)

        p_prefix = f"inv_{random.randint(1000, 9999)}"
        # The attack is self-contained and uses its own classes.
        attack_code = dedent(f"""
            # Invalidation attack for isinstance injected by fuzzer
            try:
                class OriginalClass_{p_prefix}: pass
                class SwappedClass_{p_prefix}: pass

                x_{p_prefix} = OriginalClass_{p_prefix}()

                # 1. Train the JIT to assume isinstance is always True
                for _ in range(500):
                    isinstance(x_{p_prefix}, OriginalClass_{p_prefix})

                # 2. Invalidate the assumption by swapping the class
                x_{p_prefix}.__class__ = SwappedClass_{p_prefix}

                # 3. Final check to see if JIT deoptimizes correctly
                isinstance(x_{p_prefix}, OriginalClass_{p_prefix})
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_hasattr_invalidation_attack(self, original_call: ast.Call) -> list[ast.stmt]:
        """
        Generate a loop that repeatedly adds and removes an attribute
        from an object's type to stress hasattr caches.
        """
        print("    -> Injecting hasattr (invalidation) attack...", file=sys.stderr)
        if not isinstance(original_call.args[0], ast.Name):
            return []  # Can't easily determine the object to attack

        target_obj_name = original_call.args[0].id

        # Use a random attribute name for the attack
        attr_name_str = f"fuzzer_attr_{random.randint(1000, 9999)}"

        attack_code = dedent(f"""
            # hasattr invalidation attack injected by fuzzer
            for i_hasattr in range(300):
                try:
                    target_obj_for_hasattr = {target_obj_name}
                    target_type = type(target_obj_for_hasattr)
                    if i_hasattr % 2 == 0:
                        setattr(target_type, "{attr_name_str}", "fuzzer_added_value")
                    else:
                        if hasattr(target_type, "{attr_name_str}"):
                            delattr(target_type, "{attr_name_str}")

                    hasattr(target_obj_for_hasattr, "{attr_name_str}")
                except Exception:
                    pass
        """)
        return ast.parse(attack_code).body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # First, visit children to allow them to be transformed.
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Low probability for this invasive set of mutations
        if random.random() > 0.15:
            return node

        # Find all calls to our target builtins within this function
        isinstance_calls = []
        hasattr_calls = []
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Call) and isinstance(sub_node.func, ast.Name):
                if sub_node.func.id == "isinstance" and len(sub_node.args) == 2:
                    isinstance_calls.append(sub_node)
                elif sub_node.func.id == "hasattr" and len(sub_node.args) == 2:
                    hasattr_calls.append(sub_node)

        nodes_to_inject = []
        # Choose one target type to inject, if any were found
        if isinstance_calls and hasattr_calls:
            target_type = random.choice(["isinstance", "hasattr"])
        elif isinstance_calls:
            target_type = "isinstance"
        elif hasattr_calls:
            target_type = "hasattr"
        else:
            return node  # No targets found

        # Generate the attack scenario based on the chosen target type
        if target_type == "isinstance":
            target_call = random.choice(isinstance_calls)
            # Randomly choose between the two different isinstance attacks
            if random.random() < 0.5:
                nodes_to_inject = self._create_isinstance_polymorphic_attack(target_call)
            else:
                nodes_to_inject = self._create_isinstance_invalidation_attack(target_call)
        elif target_type == "hasattr":
            target_call = random.choice(hasattr_calls)
            nodes_to_inject = self._create_hasattr_invalidation_attack(target_call)

        # Prepend the new scenario to the top of the function body
        if nodes_to_inject:
            node.body = nodes_to_inject + node.body
            ast.fix_missing_locations(node)

        return node


def _create_len_attack(prefix: str) -> list[ast.stmt]:
    """Generate a self-contained scenario to attack len()."""
    var_name = f"len_obj_{prefix}"
    class_def_str = genStatefulLenObject(var_name)
    attack_code = dedent(f"""
# len() attack injected by fuzzer
{class_def_str}
{var_name} = StatefulLen_{var_name}()
for i_len in range(100):
    try:
        len({var_name})
    except Exception:
        pass
    """)
    return ast.parse(attack_code).body


def _create_hash_attack(prefix: str) -> list[ast.stmt]:
    """Generate a self-contained scenario to attack hash()."""
    var_name = f"hash_obj_{prefix}"
    class_def_str = genUnstableHashObject(var_name)
    attack_code = dedent(f"""
# hash() attack injected by fuzzer
{class_def_str}
{var_name} = UnstableHash_{var_name}()
d = {{}}
for i_hash in range(100):
    try:
        # Using the object as a dict key repeatedly triggers __hash__
        d[{var_name}] = i_hash
    except Exception:
        # Expected if hash changes for existing key
        pass
    """)
    return ast.parse(attack_code).body


def _create_pow_attack(prefix: str) -> list[ast.stmt]:
    """Generate calls to pow() with tricky arguments."""
    attack_code = dedent("""
        # pow() attack injected by fuzzer
        try:
            # This pair produces a float from integers
            pow(10, -2)
        except Exception:
            pass
        try:
            # This pair produces a complex number from an integer and float
            pow(-10, 0.5)
        except Exception:
            pass
    """)
    return ast.parse(attack_code).body


class MagicMethodMutator(ast.NodeTransformer):
    """
    Attack JIT data model assumptions by stressing magic methods.

    This mutator injects scenarios that use "evil objects" with misbehaving
    magic methods (e.g., `__len__`, `__hash__`) or replaces iterables in
    `for` loops with stateful, malicious ones.
    """

    def _mutate_for_loop_iter(self, node: ast.FunctionDef) -> bool:
        """Find a for loop and replaces its iterable with a stateful one."""
        for i, stmt in enumerate(node.body):
            if isinstance(stmt, ast.For):
                print(f"    -> Mutating for loop iterator in '{node.name}'", file=sys.stderr)
                p_prefix = f"iter_{random.randint(1000, 9999)}"
                # 1. Get the evil class definition
                class_def_str = genStatefulIterObject(p_prefix)
                class_def_node = ast.parse(class_def_str).body[0]
                # 2. Prepend the class definition to the function
                node.body.insert(0, class_def_node)
                # 3. Replace the loop's iterable
                stmt.iter = ast.Call(
                    func=ast.Name(id=class_def_node.name, ctx=ast.Load()), args=[], keywords=[]
                )
                return True  # Indicate that a mutation was performed
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.15:  # Low probability for these attacks
            attack_functions = [
                _create_len_attack,
                _create_hash_attack,
                _create_pow_attack,
                self._mutate_for_loop_iter,  # This one is different
            ]
            chosen_attack = random.choice(attack_functions)

            nodes_to_inject = []
            if chosen_attack == self._mutate_for_loop_iter:
                # This attack modifies the function in-place, so we call it differently
                if self._mutate_for_loop_iter(node):
                    ast.fix_missing_locations(node)
            else:
                print(
                    f"    -> Injecting data model attack '{chosen_attack.__name__}' into '{node.name}'",
                    file=sys.stderr,
                )
                prefix = f"{node.name}_{random.randint(1000, 9999)}"
                nodes_to_inject = chosen_attack(prefix)

            if nodes_to_inject:
                node.body = nodes_to_inject + node.body
                ast.fix_missing_locations(node)

        return node


class NumericMutator(ast.NodeTransformer):
    """
    Attack JIT optimizations for numeric built-ins.

    This mutator uses two strategies: it may safely replace arguments in
    calls to functions like `pow` and `chr` with tricky values, or it may
    inject a self-contained scenario to attack `abs()` with a stateful object.
    """

    # --- Strategy 1: Safe Argument Replacement ---

    def _mutate_pow_args(self, node: ast.Call) -> ast.Call:
        """Replace arguments to pow() with pairs known to produce different types."""
        print("    -> Mutating pow() arguments", file=sys.stderr)
        tricky_pairs = [
            (10, -2),  # Returns float
            (-10, 0.5),  # Returns complex
            (2, 128),  # Tests overflow on some platforms
        ]
        chosen_pair = random.choice(tricky_pairs)
        node.args = [ast.Constant(value=chosen_pair[0]), ast.Constant(value=chosen_pair[1])]
        node.keywords = []  # Clear keywords to be safe
        return node

    def _mutate_chr_args(self, node: ast.Call) -> ast.Call:
        """Replace the argument to chr() with values that test error handling."""
        print("    -> Mutating chr() arguments", file=sys.stderr)
        tricky_values = [-1, 1114112, 0xD800]  # ValueError, ValueError, TypeError
        node.args = [ast.Constant(value=random.choice(tricky_values))]
        node.keywords = []
        return node

    def _mutate_ord_args(self, node: ast.Call) -> ast.Call:
        """Replace the argument to ord() with values that test error handling."""
        print("    -> Mutating ord() arguments", file=sys.stderr)
        tricky_values = ["", "ab", b"c"]  # TypeError, TypeError, TypeError
        node.args = [ast.Constant(value=random.choice(tricky_values))]
        node.keywords = []
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if not isinstance(node.func, ast.Name):
            return node

        mutator_map = {
            "pow": self._mutate_pow_args,
            "chr": self._mutate_chr_args,
            "ord": self._mutate_ord_args,
        }

        mutator_func = mutator_map.get(node.func.id)
        if mutator_func and random.random() < 0.1:
            return mutator_func(node)

        return node

    # --- Strategy 2: Self-Contained Scenario Injection ---

    def _create_abs_attack_scenario(self, prefix: str) -> list[ast.stmt]:
        """Generate a scenario that attacks abs() with a stateful object."""
        attack_code = dedent(f"""
            # abs() attack injected by fuzzer
            print('[{prefix}] Running abs() attack scenario...', file=sys.stderr)
            class StatefulAbs_{prefix}:
                def __init__(self):
                    self.count = 0
                def __abs__(self):
                    self.count += 1
                    if self.count > 50:
                        # Change the return type mid-loop
                        return 123.45
                    return 123

            evil_abs_obj = StatefulAbs_{prefix}()
            for _ in range(100):
                try:
                    abs(evil_abs_obj)
                except Exception:
                    pass
        """)
        return ast.parse(attack_code).body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Low probability for this injection
        if random.random() < 0.05:
            print(f"    -> Injecting numeric attack scenario into '{node.name}'", file=sys.stderr)

            # For now, we only have one scenario, but this can be expanded.
            attack_generators = [self._create_abs_attack_scenario]
            chosen_generator = random.choice(attack_generators)

            prefix = f"{node.name}_{random.randint(1000, 9999)}"
            nodes_to_inject = chosen_generator(prefix)

            # Prepend the scenario to the function's body
            node.body = nodes_to_inject + node.body
            ast.fix_missing_locations(node)

        return node


class IterableMutator(ast.NodeTransformer):
    """
    Attack JIT assumptions about iterables and collection-based built-ins.

    This mutator injects scenarios that use misbehaving iterators with
    functions like `tuple()`, `all()`, and `min()`, or it may replace the
    iterable in an existing `for` loop with a stateful one.
    """

    def _create_tuple_attack(self, prefix: str) -> list[ast.stmt]:
        """Generate a scenario attacking tuple() with an unstable-type iterator."""
        print("    -> Injecting tuple() attack scenario...", file=sys.stderr)
        # For this attack, we can reuse the StatefulIterObject
        class_def_str = genStatefulIterObject(prefix)
        attack_code = dedent(f"""
# tuple() attack injected by fuzzer
print('[{prefix}] Running tuple() attack scenario...', file=sys.stderr)
{class_def_str}
evil_iterable = StatefulIter_{prefix}()
try:
    # The JIT may make assumptions about the types from the iterator
    # which are then violated on later iterations.
    for _ in range(100):
        tuple(evil_iterable)
except Exception:
    pass
        """)
        return ast.parse(attack_code).body

    def _create_all_any_attack(self, prefix: str) -> list[ast.stmt]:
        """Generate a scenario attacking all()/any() short-circuiting."""
        print("    -> Injecting all()/any() attack scenario...", file=sys.stderr)
        attack_code = dedent(f"""
            # all()/any() short-circuit attack injected by fuzzer
            print('[{prefix}] Running all()/any() attack scenario...', file=sys.stderr)
            side_effect_counter_{prefix} = 0
            class SideEffectIterator_{prefix}:
                def __init__(self, iterable):
                    self._iterator = iter(iterable)
                def __iter__(self):
                    return self
                def __next__(self):
                    nonlocal side_effect_counter_{prefix}
                    side_effect_counter_{prefix} += 1
                    return next(self._iterator)

            # This iterable should cause all() to short-circuit after 3 items
            iterable_to_test = [True, True, False, True, True]
            try:
                all(SideEffectIterator_{prefix}(iterable_to_test))
                # The JIT might incorrectly run the whole loop. A correct run
                # will result in the counter being 3.
                if side_effect_counter_{prefix} != 3:
                    # This is not a JIT bug per se, but indicates non-standard behavior.
                    print(f"[{prefix}] Side effect counter has unexpected value: {{side_effect_counter_{prefix}}}", file=sys.stderr)
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_min_max_attack(self, prefix: str) -> list[ast.stmt]:
        """Generate a scenario attacking min()/max() with incompatible types."""
        print("    -> Injecting min()/max() attack scenario...", file=sys.stderr)
        attack_code = dedent(f"""
            # min()/max() type-confusion attack injected by fuzzer
            print('[{prefix}] Running min()/max() attack scenario...', file=sys.stderr)
            class IncompatibleTypeIterator_{prefix}:
                def __init__(self):
                    self.count = 0
                def __iter__(self):
                    self.count = 0
                    return self
                def __next__(self):
                    self.count += 1
                    if self.count < 5:
                        return self.count * 10
                    elif self.count == 5:
                        # After yielding numbers, suddenly yield an incompatible type
                        return "a_string"
                    else:
                        raise StopIteration

            iterator_instance = IncompatibleTypeIterator_{prefix}()
            try:
                # The JIT may specialize for integers and then fail on the string.
                max(iterator_instance)
            except TypeError:
                # A TypeError is the expected outcome.
                pass
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _mutate_for_loop_iter(self, func_node: ast.FunctionDef) -> bool:
        """Find a for loop and replaces its iterable with a stateful one."""
        # Find the first for loop in the function body
        for_node = None
        for stmt in func_node.body:
            if isinstance(stmt, ast.For):
                for_node = stmt
                break

        if for_node:
            print(f"    -> Mutating for loop iterator in '{func_node.name}'", file=sys.stderr)
            prefix = f"iter_{random.randint(1000, 9999)}"
            class_def_str = genStatefulIterObject(prefix)
            class_def_node = ast.parse(class_def_str).body[0]
            # Prepend the class definition to the function
            func_node.body.insert(0, class_def_node)
            # Replace the loop's iterable
            for_node.iter = ast.Call(
                func=ast.Name(id=class_def_node.name, ctx=ast.Load()), args=[], keywords=[]
            )
            return True  # Indicate that a mutation was performed
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.15:  # Low probability for these attacks
            attack_functions = [
                _create_len_attack,
                _create_hash_attack,
                _create_pow_attack,
                self._create_tuple_attack,
                self._create_all_any_attack,
                self._create_min_max_attack,
                self._mutate_for_loop_iter,
            ]
            chosen_attack = random.choice(attack_functions)

            nodes_to_inject = []
            if chosen_attack == self._mutate_for_loop_iter:
                # This attack modifies the function in-place
                if self._mutate_for_loop_iter(node):
                    ast.fix_missing_locations(node)
            else:
                # These attacks inject a new, self-contained scenario
                prefix = f"{node.name}_{random.randint(1000, 9999)}"
                nodes_to_inject = chosen_attack(prefix)

            if nodes_to_inject:
                node.body = nodes_to_inject + node.body
                ast.fix_missing_locations(node)

        return node


class GCInjector(ast.NodeTransformer):
    """
    Injects a call to gc.set_threshold() with a randomized, low value
    at the beginning of a function to increase GC pressure.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        # Only apply to our main harness functions
        if not node.name.startswith("uop_harness"):
            return node

        # High probability for this mutation, as it's a general stressor
        if random.random() < 0.25:
            print(f"    -> Injecting GC pressure into '{node.name}'", file=sys.stderr)

            # 1. Choose a threshold value using a weighted distribution
            thresholds = [1, 10, 100, None]
            weights = [0.6, 0.1, 0.1, 0.2]
            chosen_threshold = random.choices(thresholds, weights=weights, k=1)[0]

            # If 'None' is chosen, pick a random value
            if chosen_threshold is None:
                chosen_threshold = random.randint(1, 150)

            # 2. Create the AST nodes for 'import gc' and 'gc.set_threshold(...)'
            import_node = ast.Import(names=[ast.alias(name='gc')])

            set_threshold_node = ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='gc', ctx=ast.Load()),
                        attr='set_threshold',
                        ctx=ast.Load()
                    ),
                    args=[ast.Constant(value=chosen_threshold)],
                    keywords=[]
                )
            )

            # 3. Prepend the new nodes to the function's body
            node.body.insert(0, set_threshold_node)
            node.body.insert(0, import_node)
            ast.fix_missing_locations(node)

        return node


class DictPolluter(ast.NodeTransformer):
    """
    Attacks JIT dictionary caches (dk_version) by injecting loops that
    repeatedly add and delete keys from dictionaries.
    """

    def _create_global_pollution_scenario(self, prefix: str) -> list[ast.stmt]:
        """Generates a scenario that pollutes the globals() dictionary."""
        print("    -> Injecting globals() pollution scenario...", file=sys.stderr)
        key_name = f"fuzzer_polluter_key_{prefix}"

        attack_code = dedent(f"""
            # Global dictionary pollution attack
            print('[{prefix}] Running globals() pollution scenario...', file=sys.stderr)
            for i_pollute in range(200):
                try:
                    # Repeatedly add and delete the key to churn the dict version
                    if i_pollute % 2 == 0:
                        globals()['{key_name}'] = i_pollute
                    elif '{key_name}' in globals():
                        del globals()['{key_name}']
                except Exception:
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_local_pollution_scenario(self, prefix: str) -> list[ast.stmt]:
        """Generates a scenario that creates and pollutes a local dictionary."""
        print("    -> Injecting local dict pollution scenario...", file=sys.stderr)
        dict_name = f"polluter_dict_{prefix}"
        key_name = f"fuzzer_local_key_{prefix}"

        attack_code = dedent(f"""
            # Local dictionary pollution attack
            print('[{prefix}] Running local dict pollution scenario...', file=sys.stderr)
            {dict_name} = {{'initial_key': 0}}
            for i_pollute in range(200):
                try:
                    # Repeatedly add and delete the key to churn the dict version
                    if i_pollute % 2 == 0:
                        {dict_name}['{key_name}'] = i_pollute
                    elif '{key_name}' in {dict_name}:
                        del {dict_name}['{key_name}']
                except Exception:
                    pass
        """)
        return ast.parse(attack_code).body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # Low probability for this invasive mutation
            prefix = f"{node.name}_{random.randint(1000, 9999)}"

            # Choose which pollution strategy to use
            if random.random() < 0.5:
                scenario_nodes = self._create_global_pollution_scenario(prefix)
            else:
                scenario_nodes = self._create_local_pollution_scenario(prefix)

            # Prepend the scenario to the function's body
            node.body = scenario_nodes + node.body
            ast.fix_missing_locations(node)

        return node


class FunctionPatcher(ast.NodeTransformer):
    """
    Attacks JIT function versioning and inlining caches.

    This mutator injects a scenario that defines a simple nested function,
    calls it in a hot loop to get it JIT-compiled, and then overwrites the
    function object with a new one to invalidate the JIT's assumptions.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Low probability for this complex injection
        if random.random() < 0.1:
            print(f"    -> Injecting function patching scenario into '{node.name}'", file=sys.stderr)

            p_prefix = f"fp_{random.randint(1000, 9999)}"

            # This template string contains the entire self-contained attack.
            attack_preamble = dedent(f"""
                # --- Function Patching Scenario ---
                print('[{p_prefix}] Running function patching scenario...', file=sys.stderr)

                # 1. Define a simple "victim" function inside the harness.
                def victim_func_{p_prefix}(a=0, b=1, c=2):
                    return a + b + c

                # 2. Train the JIT by calling the victim in a hot loop.
                #    The JIT may decide to inline this function.
                try:
                    for _ in range(500):
                        res = victim_func_{p_prefix}()
                except Exception:
                    pass

            """)

            attack_1 = dedent(f"""
                # 3. Invalidate the JIT's assumptions by redefining the function.
                print('[{p_prefix}] Patching victim_func_{p_prefix} with lambda...', file=sys.stderr)
                victim_func_{p_prefix} = lambda: "patched!"

                # 4. Call the function again to check for a crash.
                try:
                    res = victim_func_{p_prefix}()
                except Exception:
                    pass
            """)

            attack_2 = dedent(f"""
                # 3. Invalidate the JIT's assumptions by redefining the function's defaults.
                print('[{p_prefix}] Patching victim_func_{p_prefix} with different values...', file=sys.stderr)
                victim_func_{p_prefix}.__defaults__ = (2**10, 2**15, 2**32)

                # 4. Call the function again to check for a crash.
                try:
                    res = victim_func_{p_prefix}()
                except Exception:
                    pass
            """)

            attack_3 = dedent(f"""
                # 3. Invalidate the JIT's assumptions by redefining the function's defaults types.
                print('[{p_prefix}] Patching victim_func_{p_prefix} with diffent types...', file=sys.stderr)
                victim_func_{p_prefix}.__defaults__ = ("a", "b", "c")

                # 4. Call the function again to check for a crash.
                try:
                    res = victim_func_{p_prefix}()
                except Exception:
                    pass
            """)

            attack_4 = dedent(f"""
                # 3. Invalidate the JIT's assumptions by redefining the function's defaults with incompatible types.
                print('[{p_prefix}] Patching victim_func_{p_prefix} with incompatible types...', file=sys.stderr)
                victim_func_{p_prefix}.__defaults__ = ("a", "b", -2**31-1)

                # 4. Call the function again to check for a crash.
                try:
                    res = victim_func_{p_prefix}()
                except Exception:
                    pass
            """)

            chosen_attack = random.choice((attack_1, attack_2, attack_3, attack_4))
            attack_code = attack_preamble + chosen_attack
            try:
                scenario_nodes = ast.parse(attack_code).body
                # Prepend the scenario to the function's body.
                node.body = scenario_nodes + node.body
                ast.fix_missing_locations(node)
            except SyntaxError:
                pass  # Should not happen with a fixed template

        return node


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
                branch_body = random.choice([
                    f"res_{p_prefix} = i * {i}",
                    f"res_{p_prefix} = str(i)",
                    f"res_{p_prefix} = len(str(i * 2))",
                    f"res_{p_prefix} = i % {(i % 5) + 1}",
                ])

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
                        {indent(chr(10).join(branch_code), ' ' * 8)}
                    except Exception:
                        pass
            """)

            try:
                scenario_nodes = ast.parse(attack_code).body
                # Prepend the scenario to the function's body.
                node.body = scenario_nodes + node.body
                ast.fix_missing_locations(node)
            except SyntaxError:
                pass  # Should not happen with a fixed template

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
            ConstantPerturbator,
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
            GCInjector,
            DictPolluter,
            FunctionPatcher,
            TraceBreaker,
            ExitStresser,
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


def genLyingEqualityObject(var_name: str) -> str:
    """
    Generate a class that lies about equality.
    __eq__ and __ne__ both always return True after a while.
    """
    class_name = f"LyingEquality_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            eq_count = 0
            ne_count = 0
            def __eq__(self, other):
                self.eq_count += 1
                if self.eq_count < 70:
                    if not self.eq_count % 20:
                        print("[EVIL] LyingEquality __eq__ called, returning True", file=sys.stderr)
                    return True
            def __ne__(self, other):
                self.ne_count += 1
                if self.ne_count < 70:
                    if not self.ne_count % 20:
                        print("[EVIL] LyingEquality __ne__ called, returning True", file=sys.stderr)
                    return True
        {var_name} = {class_name}()
    """)
    return setup_code


def genStatefulLenObject(var_name: str) -> str:
    """Generate the source code for a class whose `__len__` is stateful."""
    class_name = f"StatefulLen_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self.len_count = 0
            def __len__(self):
                _len = 0 if self.len_count < 70 else 99
                if not self.len_count % 20:
                    print(f"[EVIL] StatefulLen __len__ called, returning {{_len}}", file=sys.stderr)
                self.len_count += 1
                return _len
        {var_name} = {class_name}()
    """)
    return setup_code


def genUnstableHashObject(var_name: str) -> str:
    """Generate the source code for a class whose `__hash__` is not constant."""
    class_name = f"UnstableHash_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            hash_count = 0
            def __hash__(self):
                # Violates the rule that hash must be constant for the object's lifetime.
                self.hash_count += 1
                new_hash = 5 if self.hash_count < 70 else randint(0, 2**64 - 1)
                if not self.hash_count % 20:
                    print(f"[EVIL] UnstableHash __hash__ called, returning {{new_hash}}", file=sys.stderr)
                return new_hash
        {var_name} = {class_name}()
    """)
    return setup_code


def genStatefulStrReprObject(var_name: str) -> str:
    """
    Generate a class with stateful __str__ and __repr__ methods.
    __repr__ will eventually return a non-string type to cause a TypeError.
    """
    class_name = f"StatefulStrRepr_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self._str_count = 0
                self._repr_count = 0
                self._str_options = ['a', 'b', 'c']
            def __str__(self):
                val = "a" if self._str_count < 67 else b'a'
                if not self._str_count % 20:
                    print(f"[EVIL] StatefulStrRepr __str__ called, returning '{{val}}'", file=sys.stderr)
                self._str_count += 1
                return val
            def __repr__(self):
                self._repr_count += 1
                if self._repr_count > 70:
                    if not self._repr_count % 20:
                        print("[EVIL] StatefulStrRepr __repr__ called, returning NON-STRING type 123", file=sys.stderr)
                    return 123  # Violates contract, should raise TypeError
                val = f"<StatefulRepr run #{{self._repr_count}}>"
                if not self._repr_count % 20:
                    print(f"[EVIL] StatefulStrRepr __repr__ called, returning '{{val}}'", file=sys.stderr)
                return val
        {var_name} = {class_name}()
    """)
    return setup_code


def genStatefulGetitemObject(var_name: str) -> str:
    """Generate the source code for a class whose `__iter__` returns different iterators."""
    class_name = f"StatefulGetitem_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self._getitem_count = 0
            def __getitem__(self, key):
                self._getitem_count += 1
                if self._getitem_count > 67:
                    if not self._getitem_count % 20:
                        print(f"[EVIL] StatefulGetitem __getitem__ returning float", file=sys.stderr)
                    return 99.9
                if not self._getitem_count % 20:
                    print(f"[EVIL] StatefulGetitem __getitem__ returning int", file=sys.stderr)
                return 5
        {var_name} = {class_name}()
    """)
    return setup_code


def genStatefulGetattrObject(var_name: str) -> str:
    """
    Generate a class whose __getattr__ returns different values based on call count.
    """
    class_name = f"StatefulGetattr_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self._getattr_count = 0
            def __getattr__(self, name):
                self._getattr_count += 1
                if self._getattr_count > 67:
                    if not self._getattr_count % 20:
                        print(f"[EVIL] StatefulGetattr __getattr__ for '{{name}}' returning 'evil_attribute'", file=sys.stderr)
                    return b'evil_attribute'
                if not self._getattr_count % 20:
                    print(f"[EVIL] StatefulGetattr __getattr__ for '{{name}}' returning 'normal_attribute'", file=sys.stderr)
                return 'normal_attribute'
        {var_name} = {class_name}()
    """)
    return setup_code


def genStatefulBoolObject(var_name: str) -> str:
    """
    Generate a class whose __bool__ result flips after a few calls.
    """
    class_name = f"StatefulBool_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self._bool_count = 0
            def __bool__(self):
                self._bool_count += 1
                if self._bool_count > 70:
                    if not self._bool_count % 20:
                        print("[EVIL] StatefulBool __bool__ flipping to False", file=sys.stderr)
                    return False
                if not self._bool_count % 20:
                    print("[EVIL] StatefulBool __bool__ returning True", file=sys.stderr)
                return True
        {var_name} = {class_name}()
    """)
    return setup_code


def genStatefulIterObject(var_name: str) -> str:
    """
    Generate a class whose __iter__ returns different iterators.
    """
    class_name = f"StatefulIter_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self._iter_count = 0
                self._iterable = [1, 2, 3]
            def __iter__(self):
                if not self._iter_count % 20:
                    print(f"[EVIL] StatefulIter __iter__ yielding from {{self._iterable!r}}", file=sys.stderr)
                self._iter_count += 1
                if self._iter_count > 67:
                    return iter((None,))
                return iter(self._iterable)
        {var_name} = {class_name}()
    """)
    return setup_code


def genStatefulIndexObject(var_name: str) -> str:
    """
    Generate a class whose __index__ returns different integer values.
    """
    class_name = f"StatefulIndex_{var_name}"
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self._index_count = 0
            def __index__(self):
                self._index_count += 1
                if self._index_count > 70:
                    if not self._index_count % 20:
                        print("[EVIL] StatefulIndex __index__ returning 99", file=sys.stderr)
                    return 99 # A different, potentially out-of-bounds index
                if not self._index_count % 20:
                    print("[EVIL] StatefulIndex __index__ returning 0", file=sys.stderr)
                return 0
        {var_name} = {class_name}()
    """)
    return setup_code


def genSimpleObject(var_name: str) -> str:
    class_name = f"C_{var_name}"  # We can use var_name because it will be unique
    setup_code = dedent(f"""
        class {class_name}:
            def __init__(self):
                self.x = 1
                self.y = 'y'
                self.value = "value"
            def get_value(self):
                return self.value
            def __getitem__(self, item):
                return 5
        {var_name} = {class_name}()
    """)
    return setup_code
