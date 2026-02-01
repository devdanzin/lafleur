"""
This module contains mutation scenarios designed to attack the JIT's type system
and object model assumptions.

The strategies here focus on invalidating type speculation and cache assumptions.
This includes injecting type instability in hot loops, creating megamorphic
call sites to stress inline caches, confusing attribute lookup mechanisms, and
modifying class hierarchies (MRO) at runtime.
"""

from __future__ import annotations

import ast
import random
import sys
from textwrap import dedent
from typing import cast


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


def _create_evil_descriptor_ast(class_name: str) -> ast.ClassDef:
    """
    Builds the AST for a descriptor with a chaotic, stateful __get__ method
    that cycles through multiple return types.
    """
    source_code = dedent(f"""
    class {class_name}:
        def __get__(self, obj, owner):
            self.count = getattr(self, 'count', 0) + 1
            # A list of diverse types to cycle through
            type_options = [42, "a_string", 3.14, None, [1, 2, 3]]
            # Change the return type every 10 accesses
            index = (self.count // 10) % len(type_options)
            return type_options[index]
    """)
    # ast.parse() returns a Module node; the class definition is in its body.
    return cast(ast.ClassDef, ast.parse(source_code).body[0])


class DescriptorChaosGenerator(ast.NodeTransformer):
    """
    Injects a class with a stateful descriptor and a hot loop that
    accesses it, stressing JIT's attribute access caches.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            # 1. Generate unique names for our classes and variables
            p_prefix = f"chaos_{random.randint(1000, 9999)}"
            descriptor_class_name = f"EvilDescriptor_{p_prefix}"
            target_class_name = f"TargetClass_{p_prefix}"
            instance_name = f"target_obj_{p_prefix}"

            print(
                f"    -> Injecting descriptor chaos pattern with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            # 2. Get the AST for the EvilDescriptor
            descriptor_class_ast = _create_evil_descriptor_ast(descriptor_class_name)

            # 3. Create the AST for the TargetClass that uses the descriptor
            target_class_ast = ast.ClassDef(
                name=target_class_name,
                bases=[],
                keywords=[],
                body=[
                    ast.Assign(
                        targets=[ast.Name(id="chaos_attr", ctx=ast.Store())],
                        value=ast.Call(
                            func=ast.Name(id=descriptor_class_name, ctx=ast.Load()),
                            args=[],
                            keywords=[],
                        ),
                    )
                ],
                decorator_list=[],
            )

            # 4. Create the AST for the hot loop that triggers the chaos
            hot_loop_ast = ast.parse(
                dedent(f"""
                {instance_name} = {target_class_name}()
                for i in range(100):
                    try:
                        # This access will trigger the stateful __get__ method
                        _ = {instance_name}.chaos_attr
                    except Exception:
                        pass
            """)
            ).body

            # 5. Prepend the entire scenario to the function's body
            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = [
                descriptor_class_ast,
                target_class_ast,
            ] + hot_loop_ast
            ast.fix_missing_locations(node)

        return node


def _create_base_classes_ast(base1_name: str, base2_name: str) -> list[ast.ClassDef]:
    """Builds the AST for the two base classes in the MRO shuffle."""
    base1 = ast.ClassDef(
        name=base1_name,
        bases=[],
        keywords=[],
        body=[
            ast.FunctionDef(
                name="method",
                args=ast.arguments(
                    args=[ast.arg(arg="self")],
                    posonlyargs=[],
                    kwonlyargs=[],
                    kw_defaults=[],
                    defaults=[],
                ),
                body=[ast.Return(value=ast.Constant(value=1))],
                decorator_list=[],
            )
        ],
        decorator_list=[],
    )
    base2 = ast.ClassDef(
        name=base2_name,
        bases=[],
        keywords=[],
        body=[
            ast.FunctionDef(
                name="method",
                args=ast.arguments(
                    args=[ast.arg(arg="self")],
                    posonlyargs=[],
                    kwonlyargs=[],
                    kw_defaults=[],
                    defaults=[],
                ),
                body=[ast.Return(value=ast.Constant(value="two"))],
                decorator_list=[],
            )
        ],
        decorator_list=[],
    )
    return [base1, base2]


def _create_evil_subclass_ast(class_name: str, base1_name: str, base2_name: str) -> ast.ClassDef:
    """Builds the AST for the subclass that will have its MRO shuffled."""
    return ast.ClassDef(
        name=class_name,
        bases=[ast.Name(id=base1_name, ctx=ast.Load()), ast.Name(id=base2_name, ctx=ast.Load())],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    )


class MROShuffler(ast.NodeTransformer):
    """
    Injects a class hierarchy and code that shuffles the Method Resolution
    Order (MRO) mid-execution to attack JIT method caches.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"mro_{random.randint(1000, 9999)}"
            base1_name = f"Base1_{p_prefix}"
            base2_name = f"Base2_{p_prefix}"
            evil_class_name = f"Evil_{p_prefix}"
            instance_name = f"evil_obj_{p_prefix}"

            print(f"    -> Injecting MRO shuffle pattern with prefix '{p_prefix}'", file=sys.stderr)

            # 1. Create the class definitions
            base_classes_ast = _create_base_classes_ast(base1_name, base2_name)
            evil_subclass_ast = _create_evil_subclass_ast(evil_class_name, base1_name, base2_name)

            # 2. Create the warm-up loop, MRO shuffle, and trigger call as an AST
            attack_scenario_ast = ast.parse(
                dedent(f"""
                # Instantiate the class
                {instance_name} = {evil_class_name}()

                # Warm up the JIT to cache the lookup for Base1.method
                for _ in range(100):
                    try:
                        {instance_name}.method()
                    except Exception:
                        pass

                # Shuffle the MRO
                {evil_class_name}.__bases__ = ({base2_name}, {base1_name})

                # Call the method again to trigger a potential deoptimization bug
                try:
                    _ = {instance_name}.method()
                except Exception:
                    pass
            """)
            ).body

            # 3. Inject the entire scenario into a random part of the harness
            injection_point = random.randint(0, len(node.body))
            full_injection = base_classes_ast + [evil_subclass_ast] + attack_scenario_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


def _create_super_attack_hierarchy_ast(base_name: str, subclass_name: str) -> list[ast.ClassDef]:
    """
    Builds the AST for the class hierarchy by parsing a string of Python code.
    """
    call_or_attr = "f()" if random.random() < 0.5 else "counter"

    source_code = dedent(f"""
    class {base_name}:
        def __init__(self):
            self.counter = 0
        def f(self):
            self.counter += 1
            return "A"

    class {subclass_name}({base_name}):
        def __init__(self):
            super().__init__()
        def f(self):
            res = super().{call_or_attr}
            super().f()
            if self.counter > 400:
                # The attack: modify the MRO right before the super() call
                {subclass_name}.__bases__ = (object,)
                super().f()
            return res
    """)

    # ast.parse() returns a Module node; the class definitions are in its body.
    return cast(list[ast.ClassDef], ast.parse(source_code).body)


class SuperResolutionAttacker(ast.NodeTransformer):
    """
    Injects a class hierarchy where a method modifies its own class's MRO
    before a super() call, attacking JIT caches for super() resolution.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"super_{random.randint(1000, 9999)}"
            base_name = f"Base_{p_prefix}"
            subclass_name = f"Sub_{p_prefix}"
            instance_name = f"instance_{p_prefix}"

            print(
                f"    -> Injecting super() resolution attack with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            # 1. Create the class definitions
            class_asts = _create_super_attack_hierarchy_ast(base_name, subclass_name)

            # 2. Create the trigger code with the new post-shuffle stress loop
            scenario_ast = ast.parse(
                dedent(f"""
                {instance_name} = {subclass_name}()

                # Phase 1: WARM-UP LOOP
                # Encourage the JIT to specialize the call to the original super().f()
                for _ in range(300):
                    try:
                        _ = {instance_name}.f()
                    except Exception:
                        pass # The shuffle hasn't happened yet, so this is safe

                # Phase 2: THE SHUFFLE
                # The attack: modify the MRO
                {subclass_name}.__bases__ = (object,)

                # Phase 3: STRESS LOOP (The Improvement)
                # Repeatedly call the method *after* the shuffle to stress the
                # JIT's deoptimization and recovery path.
                for _ in range(100):
                    try:
                        _ = {instance_name}.f()
                    except AttributeError:
                        # This is the expected exception after the shuffle
                        pass
            """)
            ).body

            # 3. Inject the entire scenario into the harness
            injection_point = random.randint(0, len(node.body))
            full_injection = class_asts + scenario_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


def _create_code_swap_functions_ast(
    original_name: str, replacement_name: str
) -> list[ast.FunctionDef]:
    """Builds the AST for the original and replacement functions."""
    return cast(
        list[ast.FunctionDef],
        ast.parse(
            dedent(f"""
    def {original_name}():
        return 1

    def {replacement_name}():
        return "a_string"
    """)
        ).body,
    )


class CodeObjectSwapper(ast.NodeTransformer):
    """
    Injects two functions and code that swaps their __code__ objects
    mid-execution to attack JIT assumptions about function calls.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"code_{random.randint(1000, 9999)}"
            original_name = f"original_{p_prefix}"
            replacement_name = f"replacement_{p_prefix}"

            print(f"    -> Injecting code object swap with prefix '{p_prefix}'", file=sys.stderr)

            # 1. Get the AST for the two functions
            function_asts = _create_code_swap_functions_ast(original_name, replacement_name)

            # 2. Create the AST for the full attack scenario
            scenario_ast = ast.parse(
                dedent(f"""
                # Warm-up loop to encourage the JIT to specialize the call
                for i in range(100):
                    try:
                        res = {original_name}()
                        _ = res + 1 # Use the result in an integer-specific operation
                    except Exception:
                        pass

                # The attack: swap the code objects
                {original_name}.__code__ = {replacement_name}.__code__

                # The trigger: call the function again and use the result
                for _ in range(100):
                    try:
                        res = {original_name}() # Now returns a string
                        _ = res + 1          # This will raise a TypeError
                    except TypeError:
                        # This is the expected outcome.
                        pass
            """)
            ).body

            # 3. Inject the entire scenario
            injection_point = random.randint(0, len(node.body))
            full_injection = function_asts + scenario_ast
            node.body[injection_point:injection_point] = full_injection
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
            print(
                f"    -> Injecting function patching scenario into '{node.name}'", file=sys.stderr
            )

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


class ComprehensiveFunctionMutator(ast.NodeTransformer):
    """
    Systematically attacks all function modification rare events.

    Modifies: __code__, __defaults__, __kwdefaults__, __closure__,
             __globals__, __annotations__, __dict__

    Each modification targets JIT assumptions about function stability and
    forces deoptimization when cached function metadata becomes invalid.
    """

    ATTACK_SCENARIOS = [
        "code_swap",
        "defaults_mutation",
        "kwdefaults_chaos",
        "combined_attack",
        "closure_corruption",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.15:  # 15% chance
            attack_type = random.choice(self.ATTACK_SCENARIOS)
            p_prefix = f"func_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting function modification attack ({attack_type}) with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            if attack_type == "code_swap":
                scenario_ast = self._create_code_swap_attack(p_prefix)
            elif attack_type == "defaults_mutation":
                scenario_ast = self._create_defaults_attack(p_prefix)
            elif attack_type == "kwdefaults_chaos":
                scenario_ast = self._create_kwdefaults_attack(p_prefix)
            elif attack_type == "closure_corruption":
                scenario_ast = self._create_closure_attack(p_prefix)
            else:  # combined_attack
                scenario_ast = self._create_combined_attack(p_prefix)

            # Inject the scenario
            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_code_swap_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Attack by swapping a function's __code__ object with an incompatible one.
        """
        attack_code = dedent(f"""
            # __code__ swap attack
            print('[{prefix}] Running __code__ swap attack...', file=sys.stderr)

            # Define two functions with different signatures
            def victim_func_{prefix}(a, b, c=10):
                return a + b + c

            def replacement_func_{prefix}(x):
                return x * 2

            # Phase 1: Warmup to get JIT compiled
            try:
                for i_{prefix} in range(300):
                    _ = victim_func_{prefix}(i_{prefix}, i_{prefix} + 1)
            except Exception:
                pass

            # Phase 2: Swap __code__ with incompatible function
            try:
                print('[{prefix}] Swapping __code__ to incompatible signature...', file=sys.stderr)
                victim_func_{prefix}.__code__ = replacement_func_{prefix}.__code__

                # Call with original signature - will fail or behave incorrectly
                _ = victim_func_{prefix}(1, 2, 3)
            except (TypeError, AttributeError):
                pass

            # Phase 3: Swap back to original
            try:
                # Create fresh function to get original code back
                def temp_func_{prefix}(a, b, c=10):
                    return a + b + c
                victim_func_{prefix}.__code__ = temp_func_{prefix}.__code__
                _ = victim_func_{prefix}(5, 6)
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_defaults_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Attack by modifying __defaults__ to incompatible types.
        """
        attack_code = dedent(f"""
            # __defaults__ mutation attack
            print('[{prefix}] Running __defaults__ mutation attack...', file=sys.stderr)

            def target_func_{prefix}(x=1, y=2, z=3):
                return x + y + z

            # Phase 1: Warmup with integer defaults
            try:
                for i_{prefix} in range(300):
                    _ = target_func_{prefix}()
                    _ = target_func_{prefix}(i_{prefix})
            except Exception:
                pass

            # Phase 2: Mutate defaults to incompatible types
            try:
                print('[{prefix}] Mutating __defaults__ to incompatible types...', file=sys.stderr)
                target_func_{prefix}.__defaults__ = ("string", [1, 2, 3], {{"key": "value"}})

                # Call function - may crash or behave incorrectly with string + list + dict
                _ = target_func_{prefix}()
            except (TypeError, AttributeError):
                pass

            # Phase 3: Mutate to None to remove defaults
            try:
                target_func_{prefix}.__defaults__ = None
                _ = target_func_{prefix}(10, 20, 30)  # Must provide all args now
            except (TypeError, AttributeError):
                pass

            # Phase 4: Restore to very large integers
            try:
                target_func_{prefix}.__defaults__ = (2**31, 2**32, 2**63)
                _ = target_func_{prefix}()
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_kwdefaults_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Attack by toggling __kwdefaults__ between dict and None.
        """
        attack_code = dedent(f"""
            # __kwdefaults__ chaos attack
            print('[{prefix}] Running __kwdefaults__ chaos attack...', file=sys.stderr)

            def kw_func_{prefix}(a, *, b=10, c=20):
                return a + b + c

            # Phase 1: Warmup with keyword defaults
            try:
                for i_{prefix} in range(300):
                    _ = kw_func_{prefix}(i_{prefix})
                    _ = kw_func_{prefix}(i_{prefix}, b=i_{prefix}*2)
            except Exception:
                pass

            # Phase 2: Replace __kwdefaults__ with incompatible types
            try:
                print('[{prefix}] Setting __kwdefaults__ to incompatible dict...', file=sys.stderr)
                kw_func_{prefix}.__kwdefaults__ = {{"b": "not_an_int", "c": [1, 2, 3]}}
                _ = kw_func_{prefix}(5)  # Will use string + list instead of ints
            except (TypeError, AttributeError):
                pass

            # Phase 3: Set to None to remove defaults
            try:
                kw_func_{prefix}.__kwdefaults__ = None
                _ = kw_func_{prefix}(5, b=10, c=20)  # Must provide all kwargs now
            except (TypeError, AttributeError):
                pass

            # Phase 4: Add unexpected keys
            try:
                kw_func_{prefix}.__kwdefaults__ = {{"b": 100, "c": 200, "d": 300}}
                _ = kw_func_{prefix}(7)
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_closure_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Attack by modifying closure cell contents.
        """
        attack_code = dedent(f"""
            # Closure corruption attack
            print('[{prefix}] Running closure corruption attack...', file=sys.stderr)

            def make_closure_{prefix}():
                captured_val = 100

                def inner():
                    return captured_val * 2

                return inner

            closure_func_{prefix} = make_closure_{prefix}()

            # Phase 1: Warmup the closure function
            try:
                for i_{prefix} in range(300):
                    _ = closure_func_{prefix}()
            except Exception:
                pass

            # Phase 2: Corrupt the closure cell
            try:
                if closure_func_{prefix}.__closure__ is not None:
                    print('[{prefix}] Corrupting closure cell contents...', file=sys.stderr)
                    # Access the cell and modify its contents
                    cell = closure_func_{prefix}.__closure__[0]
                    cell.cell_contents  # Access current value

                    # Try to modify (this may fail in some Python versions)
                    # The JIT may have cached assumptions about the closure
                    _ = closure_func_{prefix}()
            except (AttributeError, ValueError):
                pass
        """)
        return ast.parse(attack_code).body

    def _create_combined_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Combined attack modifying multiple function attributes simultaneously.
        """
        attack_code = dedent(f"""
            # Combined function attribute attack
            print('[{prefix}] Running combined function modification attack...', file=sys.stderr)

            def multi_attack_func_{prefix}(x=1, y=2, *, z=3, w=4):
                return x + y + z + w

            # Phase 1: Warmup
            try:
                for i_{prefix} in range(300):
                    _ = multi_attack_func_{prefix}()
            except Exception:
                pass

            # Phase 2: Simultaneously modify multiple attributes
            try:
                print('[{prefix}] Modifying __defaults__, __kwdefaults__, and __code__...', file=sys.stderr)

                # Modify defaults
                multi_attack_func_{prefix}.__defaults__ = (999, 888)

                # Modify kwdefaults  
                multi_attack_func_{prefix}.__kwdefaults__ = {{"z": "evil_z", "w": b"evil_bytes"}}

                # Try to call
                _ = multi_attack_func_{prefix}()
            except (TypeError, AttributeError):
                pass

            # Phase 3: Swap code object while defaults are corrupted
            try:
                def replacement_{prefix}(a, b):
                    return a - b

                multi_attack_func_{prefix}.__code__ = replacement_{prefix}.__code__
                _ = multi_attack_func_{prefix}(10, 20)  # Signature mismatch with corrupted defaults
            except Exception:
                pass

            # Phase 4: Modify __annotations__ and __dict__
            try:
                multi_attack_func_{prefix}.__annotations__ = {{"x": "corrupted", "return": "evil"}}
                multi_attack_func_{prefix}.__dict__["custom_attr"] = lambda: "injected"
                _ = multi_attack_func_{prefix}(1, 2, z=3, w=4)
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body


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


class DynamicClassSwapper(ast.NodeTransformer):
    """
    Aggressively swaps objects between incompatible classes.

    Goes beyond LatticeSurfingMutator by:
    - Swapping to built-in types (int, str, list subclasses)
    - Swapping between user classes with incompatible __dict__
    - Swapping to/from types with __slots__
    - Swapping between classes with different MRO depths

    Targets the `set_class` rare event to stress JIT type guards and
    deoptimization logic.
    """

    ATTACK_SCENARIOS = [
        "builtin_swap",
        "slots_swap",
        "mro_depth_swap",
        "incompatible_dict_swap",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.12:  # 12% probability
            attack_type = random.choice(self.ATTACK_SCENARIOS)
            p_prefix = f"swap_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting DynamicClassSwapper ({attack_type}) with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            if attack_type == "builtin_swap":
                scenario_ast = self._create_builtin_swap_attack(p_prefix)
            elif attack_type == "slots_swap":
                scenario_ast = self._create_slots_swap_attack(p_prefix)
            elif attack_type == "mro_depth_swap":
                scenario_ast = self._create_mro_depth_swap_attack(p_prefix)
            else:  # incompatible_dict_swap
                scenario_ast = self._create_incompatible_dict_swap_attack(p_prefix)

            # Inject the scenario
            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_builtin_swap_attack(self, prefix: str) -> list[ast.stmt]:
        """Swap from user class to built-in type subclass."""
        attack_code = dedent(f"""
            # Built-in type swap attack
            print('[{prefix}] Running builtin swap attack...', file=sys.stderr)

            # Create a user class with __dict__
            class UserClass_{prefix}:
                def __init__(self, value):
                    self.value = value
                def get_value(self):
                    return self.value

            # Create int subclass that accepts __dict__
            class IntSubclass_{prefix}(int):
                def __new__(cls, val):
                    instance = super().__new__(cls, val)
                    return instance
                def get_value(self):
                    return int(self)

            # Create str subclass that accepts __dict__
            class StrSubclass_{prefix}(str):
                def __new__(cls, val=""):
                    instance = super().__new__(cls, val)
                    return instance
                def get_value(self):
                    return str(self)

            obj_{prefix} = UserClass_{prefix}(42)

            # Phase 1: Warmup - let JIT compile method calls
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.get_value()
                except Exception:
                    pass

            # Phase 2: Swap to int subclass
            try:
                print('[{prefix}] Swapping to int subclass...', file=sys.stderr)
                obj_{prefix}.__class__ = IntSubclass_{prefix}
                _ = obj_{prefix}.get_value()
            except (TypeError, AttributeError):
                pass

            # Phase 3: Swap to str subclass
            try:
                print('[{prefix}] Swapping to str subclass...', file=sys.stderr)
                obj_{prefix}.__class__ = StrSubclass_{prefix}
                _ = obj_{prefix}.get_value()
            except (TypeError, AttributeError):
                pass

            # Phase 4: Trigger more method calls after swaps
            for i_{prefix} in range(50):
                try:
                    _ = obj_{prefix}.get_value()
                except (TypeError, AttributeError):
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_slots_swap_attack(self, prefix: str) -> list[ast.stmt]:
        """Swap between classes with/without __slots__."""
        attack_code = dedent(f"""
            # Slots swap attack
            print('[{prefix}] Running slots swap attack...', file=sys.stderr)

            # Class with __dict__ (no __slots__)
            class DictClass_{prefix}:
                def __init__(self):
                    self.x = 1
                    self.y = 2
                def compute(self):
                    return self.x + self.y

            # Class with __slots__ (no __dict__)
            class SlotsClass_{prefix}:
                __slots__ = ['x', 'y']
                def __init__(self):
                    self.x = 10
                    self.y = 20
                def compute(self):
                    return self.x * self.y

            # Class with both __slots__ and __dict__
            class MixedClass_{prefix}:
                __slots__ = ['x', '__dict__']
                def __init__(self):
                    self.x = 100
                    self.y = 200  # Goes to __dict__
                def compute(self):
                    return self.x - self.y

            obj_{prefix} = DictClass_{prefix}()

            # Phase 1: Warmup with DictClass
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.compute()
                except Exception:
                    pass

            # Phase 2: Try to swap to SlotsClass (should fail - incompatible layout)
            try:
                print('[{prefix}] Trying swap to SlotsClass...', file=sys.stderr)
                obj_{prefix}.__class__ = SlotsClass_{prefix}
                _ = obj_{prefix}.compute()
            except (TypeError, AttributeError):
                pass

            # Phase 3: Create MixedClass instance and swap
            obj2_{prefix} = MixedClass_{prefix}()
            for i_{prefix} in range(200):
                try:
                    _ = obj2_{prefix}.compute()
                except Exception:
                    pass

            # Phase 4: Try swapping MixedClass to DictClass
            try:
                print('[{prefix}] Swapping MixedClass to DictClass...', file=sys.stderr)
                obj2_{prefix}.__class__ = DictClass_{prefix}
                _ = obj2_{prefix}.compute()
            except (TypeError, AttributeError):
                pass
        """)
        return ast.parse(attack_code).body

    def _create_mro_depth_swap_attack(self, prefix: str) -> list[ast.stmt]:
        """Swap between classes with different MRO depths."""
        attack_code = dedent(f"""
            # MRO depth swap attack
            print('[{prefix}] Running MRO depth swap attack...', file=sys.stderr)

            # Simple class - MRO depth 1
            class Shallow_{prefix}:
                def method(self):
                    return "shallow"
                def depth(self):
                    return 1

            # Deep class hierarchy - MRO depth 4
            class Level1_{prefix}:
                def method(self):
                    return "level1"
                def depth(self):
                    return 1

            class Level2_{prefix}(Level1_{prefix}):
                def depth(self):
                    return 2

            class Level3_{prefix}(Level2_{prefix}):
                def depth(self):
                    return 3

            class Deep_{prefix}(Level3_{prefix}):
                def method(self):
                    return "deep"
                def depth(self):
                    return 4

            # Diamond inheritance - complex MRO
            class MixinA_{prefix}:
                def mixin_method(self):
                    return "A"

            class MixinB_{prefix}:
                def mixin_method(self):
                    return "B"

            class Diamond_{prefix}(MixinA_{prefix}, MixinB_{prefix}):
                def method(self):
                    return "diamond"
                def depth(self):
                    return len(type(self).__mro__)

            obj_{prefix} = Shallow_{prefix}()

            # Phase 1: Warmup on shallow class
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.method()
                    _ = obj_{prefix}.depth()
                except Exception:
                    pass

            # Phase 2: Swap to deep hierarchy
            try:
                print('[{prefix}] Swapping to Deep class...', file=sys.stderr)
                obj_{prefix}.__class__ = Deep_{prefix}
                _ = obj_{prefix}.method()
                _ = obj_{prefix}.depth()
            except (TypeError, AttributeError):
                pass

            # Phase 3: Swap to diamond inheritance
            try:
                print('[{prefix}] Swapping to Diamond class...', file=sys.stderr)
                obj_{prefix}.__class__ = Diamond_{prefix}
                _ = obj_{prefix}.method()
                _ = obj_{prefix}.mixin_method()
            except (TypeError, AttributeError):
                pass

            # Phase 4: Swap back to shallow
            try:
                print('[{prefix}] Swapping back to Shallow class...', file=sys.stderr)
                obj_{prefix}.__class__ = Shallow_{prefix}
                _ = obj_{prefix}.method()
            except (TypeError, AttributeError):
                pass

            # Phase 5: Stress test with rapid swaps
            for i_{prefix} in range(100):
                try:
                    if i_{prefix} % 3 == 0:
                        obj_{prefix}.__class__ = Shallow_{prefix}
                    elif i_{prefix} % 3 == 1:
                        obj_{prefix}.__class__ = Deep_{prefix}
                    else:
                        obj_{prefix}.__class__ = Diamond_{prefix}
                    _ = obj_{prefix}.method()
                except (TypeError, AttributeError):
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_incompatible_dict_swap_attack(self, prefix: str) -> list[ast.stmt]:
        """Swap between classes with incompatible __dict__ attributes."""
        attack_code = dedent(f"""
            # Incompatible dict swap attack
            print('[{prefix}] Running incompatible dict swap attack...', file=sys.stderr)

            # Class expecting attributes x, y
            class ClassXY_{prefix}:
                def __init__(self):
                    self.x = 1
                    self.y = 2
                def compute(self):
                    return self.x + self.y

            # Class expecting attributes a, b, c (different attributes)
            class ClassABC_{prefix}:
                def __init__(self):
                    self.a = 10
                    self.b = 20
                    self.c = 30
                def compute(self):
                    return self.a + self.b + self.c

            # Class expecting attributes with different types
            class ClassMixed_{prefix}:
                def __init__(self):
                    self.data = [1, 2, 3]
                    self.name = "test"
                def compute(self):
                    return len(self.data) + len(self.name)

            obj_{prefix} = ClassXY_{prefix}()

            # Phase 1: Warmup - JIT specializes for ClassXY
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.compute()
                    _ = obj_{prefix}.x
                    _ = obj_{prefix}.y
                except Exception:
                    pass

            # Phase 2: Swap to ClassABC - x, y no longer exist
            try:
                print('[{prefix}] Swapping to ClassABC...', file=sys.stderr)
                obj_{prefix}.__class__ = ClassABC_{prefix}
                # compute() will fail - no a, b, c attributes
                _ = obj_{prefix}.compute()
            except (TypeError, AttributeError):
                pass

            # Phase 3: Add expected attributes and try again
            try:
                obj_{prefix}.a = 100
                obj_{prefix}.b = 200
                obj_{prefix}.c = 300
                _ = obj_{prefix}.compute()
            except (TypeError, AttributeError):
                pass

            # Phase 4: Swap to ClassMixed
            try:
                print('[{prefix}] Swapping to ClassMixed...', file=sys.stderr)
                obj_{prefix}.__class__ = ClassMixed_{prefix}
                _ = obj_{prefix}.compute()
            except (TypeError, AttributeError):
                pass

            # Phase 5: Rapidly alternate between classes
            for i_{prefix} in range(100):
                try:
                    if i_{prefix} % 2 == 0:
                        obj_{prefix}.__class__ = ClassXY_{prefix}
                        obj_{prefix}.x = i_{prefix}
                        obj_{prefix}.y = i_{prefix} + 1
                    else:
                        obj_{prefix}.__class__ = ClassABC_{prefix}
                        obj_{prefix}.a = i_{prefix}
                        obj_{prefix}.b = i_{prefix} + 1
                        obj_{prefix}.c = i_{prefix} + 2
                    _ = obj_{prefix}.compute()
                except (TypeError, AttributeError):
                    pass
        """)
        return ast.parse(attack_code).body


class BasesRewriteMutator(ast.NodeTransformer):
    """
    Creatively manipulates __bases__ to attack MRO caching.

    Complements MROShuffler with more creative __bases__ manipulations:
    - Replace bases with empty tuple (remove all parents)
    - Inject built-in types into bases
    - Toggle between single/multiple inheritance
    - Replace bases with completely different classes

    Targets the `set_bases` rare event to invalidate JIT's MRO caching
    assumptions.
    """

    ATTACK_SCENARIOS = [
        "bases_removal",
        "builtin_injection",
        "inheritance_toggle",
        "base_replacement",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.12:  # 12% probability
            attack_type = random.choice(self.ATTACK_SCENARIOS)
            p_prefix = f"bases_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting BasesRewriteMutator ({attack_type}) with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            if attack_type == "bases_removal":
                scenario_ast = self._create_bases_removal_attack(p_prefix)
            elif attack_type == "builtin_injection":
                scenario_ast = self._create_builtin_injection_attack(p_prefix)
            elif attack_type == "inheritance_toggle":
                scenario_ast = self._create_inheritance_toggle_attack(p_prefix)
            else:  # base_replacement
                scenario_ast = self._create_base_replacement_attack(p_prefix)

            # Inject the scenario
            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_bases_removal_attack(self, prefix: str) -> list[ast.stmt]:
        """Remove all bases from a class."""
        attack_code = dedent(f"""
            # Bases removal attack
            print('[{prefix}] Running bases removal attack...', file=sys.stderr)

            class Base_{prefix}:
                def method(self):
                    return "from_base"
                def base_only(self):
                    return "base_only_method"

            class Derived_{prefix}(Base_{prefix}):
                pass

            obj_{prefix} = Derived_{prefix}()

            # Phase 1: Warmup - method is inherited from Base
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.method()
                    _ = obj_{prefix}.base_only()
                except Exception:
                    pass

            # Phase 2: Set bases to object only
            try:
                print('[{prefix}] Setting bases to (object,)...', file=sys.stderr)
                Derived_{prefix}.__bases__ = (object,)
                _ = obj_{prefix}.method()  # Should fail - method no longer inherited
            except (TypeError, AttributeError):
                pass

            # Phase 3: Restore original base
            try:
                print('[{prefix}] Restoring original base...', file=sys.stderr)
                Derived_{prefix}.__bases__ = (Base_{prefix},)
                _ = obj_{prefix}.method()  # Should work again
            except (TypeError, AttributeError):
                pass

            # Phase 4: Rapidly toggle bases
            for i_{prefix} in range(100):
                try:
                    if i_{prefix} % 2 == 0:
                        Derived_{prefix}.__bases__ = (object,)
                    else:
                        Derived_{prefix}.__bases__ = (Base_{prefix},)
                    _ = obj_{prefix}.method()
                except (TypeError, AttributeError):
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_builtin_injection_attack(self, prefix: str) -> list[ast.stmt]:
        """Inject built-in types into bases."""
        attack_code = dedent(f"""
            # Builtin injection attack
            print('[{prefix}] Running builtin injection attack...', file=sys.stderr)

            class BaseA_{prefix}:
                def method(self):
                    return "A"

            class BaseB_{prefix}:
                def method(self):
                    return "B"

            class Target_{prefix}(BaseA_{prefix}, BaseB_{prefix}):
                pass

            obj_{prefix} = Target_{prefix}()

            # Phase 1: Warmup
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.method()
                except Exception:
                    pass

            # Phase 2: Inject int-like class into bases
            try:
                print('[{prefix}] Injecting IntMixin into bases...', file=sys.stderr)

                class IntMixin_{prefix}:
                    def __int__(self):
                        return 42

                Target_{prefix}.__bases__ = (IntMixin_{prefix}, BaseA_{prefix}, BaseB_{prefix})
                _ = obj_{prefix}.method()
                _ = int(obj_{prefix})
            except (TypeError, AttributeError):
                pass

            # Phase 3: Inject dict-like class into bases
            try:
                print('[{prefix}] Injecting DictMixin into bases...', file=sys.stderr)

                class DictMixin_{prefix}:
                    def keys(self):
                        return []

                Target_{prefix}.__bases__ = (DictMixin_{prefix}, BaseA_{prefix})
                _ = obj_{prefix}.method()
                _ = obj_{prefix}.keys()
            except (TypeError, AttributeError):
                pass

            # Phase 4: Try injecting actual Exception as base
            try:
                print('[{prefix}] Injecting Exception into bases...', file=sys.stderr)

                class ExcMixin_{prefix}(Exception):
                    pass

                # This will likely fail due to layout conflicts
                Target_{prefix}.__bases__ = (ExcMixin_{prefix}, BaseA_{prefix})
                _ = obj_{prefix}.method()
            except (TypeError, AttributeError):
                pass

            # Phase 5: Restore original bases
            try:
                Target_{prefix}.__bases__ = (BaseA_{prefix}, BaseB_{prefix})
                _ = obj_{prefix}.method()
            except (TypeError, AttributeError):
                pass
        """)
        return ast.parse(attack_code).body

    def _create_inheritance_toggle_attack(self, prefix: str) -> list[ast.stmt]:
        """Toggle between single and multiple inheritance."""
        attack_code = dedent(f"""
            # Inheritance toggle attack
            print('[{prefix}] Running inheritance toggle attack...', file=sys.stderr)

            class Parent1_{prefix}:
                def method1(self):
                    return "p1"
                def shared(self):
                    return "from_p1"

            class Parent2_{prefix}:
                def method2(self):
                    return "p2"
                def shared(self):
                    return "from_p2"

            class Parent3_{prefix}:
                def method3(self):
                    return "p3"
                def shared(self):
                    return "from_p3"

            # Start with single inheritance
            class Child_{prefix}(Parent1_{prefix}):
                pass

            obj_{prefix} = Child_{prefix}()

            # Phase 1: Warmup with single inheritance
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.method1()
                    _ = obj_{prefix}.shared()
                except Exception:
                    pass

            # Phase 2: Switch to multiple inheritance
            try:
                print('[{prefix}] Switching to multiple inheritance...', file=sys.stderr)
                Child_{prefix}.__bases__ = (Parent1_{prefix}, Parent2_{prefix})
                _ = obj_{prefix}.method1()
                _ = obj_{prefix}.method2()
                _ = obj_{prefix}.shared()  # Now from Parent1 (first in MRO)
            except (TypeError, AttributeError):
                pass

            # Phase 3: Add third parent
            try:
                print('[{prefix}] Adding third parent...', file=sys.stderr)
                Child_{prefix}.__bases__ = (Parent1_{prefix}, Parent2_{prefix}, Parent3_{prefix})
                _ = obj_{prefix}.method1()
                _ = obj_{prefix}.method2()
                _ = obj_{prefix}.method3()
            except (TypeError, AttributeError):
                pass

            # Phase 4: Switch back to single inheritance
            try:
                print('[{prefix}] Switching back to single inheritance...', file=sys.stderr)
                Child_{prefix}.__bases__ = (Parent2_{prefix},)
                _ = obj_{prefix}.method2()
                _ = obj_{prefix}.shared()  # Now from Parent2
            except (TypeError, AttributeError):
                pass

            # Phase 5: Rapid toggling
            for i_{prefix} in range(100):
                try:
                    if i_{prefix} % 4 == 0:
                        Child_{prefix}.__bases__ = (Parent1_{prefix},)
                    elif i_{prefix} % 4 == 1:
                        Child_{prefix}.__bases__ = (Parent2_{prefix},)
                    elif i_{prefix} % 4 == 2:
                        Child_{prefix}.__bases__ = (Parent1_{prefix}, Parent2_{prefix})
                    else:
                        Child_{prefix}.__bases__ = (Parent3_{prefix}, Parent1_{prefix})
                    _ = obj_{prefix}.shared()
                except (TypeError, AttributeError):
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_base_replacement_attack(self, prefix: str) -> list[ast.stmt]:
        """Replace all bases with completely different classes."""
        attack_code = dedent(f"""
            # Base replacement attack
            print('[{prefix}] Running base replacement attack...', file=sys.stderr)

            # Original hierarchy
            class OrigBase_{prefix}:
                val = 100
                def method(self):
                    return "original"
                def orig_only(self):
                    return "original_only"

            # Replacement hierarchy (completely different)
            class NewBase_{prefix}:
                val = 999
                def method(self):
                    return "replacement"
                def new_only(self):
                    return "new_only"

            # Alternative replacement
            class AltBase_{prefix}:
                val = -1
                def method(self):
                    return "alternative"
                def alt_only(self):
                    return "alt_only"

            class Target_{prefix}(OrigBase_{prefix}):
                pass

            obj_{prefix} = Target_{prefix}()

            # Phase 1: Warmup with original base
            for i_{prefix} in range(200):
                try:
                    _ = obj_{prefix}.method()
                    _ = obj_{prefix}.orig_only()
                    _ = Target_{prefix}.val
                except Exception:
                    pass

            # Phase 2: Complete base replacement
            try:
                print('[{prefix}] Replacing base with NewBase...', file=sys.stderr)
                Target_{prefix}.__bases__ = (NewBase_{prefix},)
                _ = obj_{prefix}.method()  # Returns "replacement" now
                _ = obj_{prefix}.new_only()  # Available now
                _ = Target_{prefix}.val  # 999 now
            except (TypeError, AttributeError):
                pass

            # Phase 3: Replace with alternative
            try:
                print('[{prefix}] Replacing base with AltBase...', file=sys.stderr)
                Target_{prefix}.__bases__ = (AltBase_{prefix},)
                _ = obj_{prefix}.method()  # Returns "alternative"
                _ = Target_{prefix}.val  # -1 now
            except (TypeError, AttributeError):
                pass

            # Phase 4: Mix old and new bases
            try:
                print('[{prefix}] Mixing bases...', file=sys.stderr)
                Target_{prefix}.__bases__ = (NewBase_{prefix}, AltBase_{prefix})
                _ = obj_{prefix}.method()  # From NewBase (first in MRO)
            except (TypeError, AttributeError):
                pass

            # Phase 5: Restore original and trigger cached lookups
            try:
                print('[{prefix}] Restoring original base...', file=sys.stderr)
                Target_{prefix}.__bases__ = (OrigBase_{prefix},)
                _ = obj_{prefix}.method()
                _ = obj_{prefix}.orig_only()
            except (TypeError, AttributeError):
                pass

            # Phase 6: Rapid replacement cycle
            bases_list_{prefix} = [
                (OrigBase_{prefix},),
                (NewBase_{prefix},),
                (AltBase_{prefix},),
                (NewBase_{prefix}, AltBase_{prefix}),
            ]
            for i_{prefix} in range(100):
                try:
                    Target_{prefix}.__bases__ = bases_list_{prefix}[i_{prefix} % len(bases_list_{prefix})]
                    _ = obj_{prefix}.method()
                    _ = Target_{prefix}.val
                except (TypeError, AttributeError):
                    pass
        """)
        return ast.parse(attack_code).body
