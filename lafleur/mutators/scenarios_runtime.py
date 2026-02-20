"""
This module contains mutation scenarios designed to manipulate the global
Python runtime environment.

The strategies here focus on state and memory management. This includes
injecting garbage collection pressure, modifying global state to invalidate
versioning caches, using frame introspection to corrupt local variables
from outside their scope, and triggering side effects via object finalizers.
"""

from __future__ import annotations

import ast
import random
import sys
from textwrap import dedent
from typing import cast


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

            # 2. Create and inject the AST nodes
            gc_nodes = ast.parse(f"import gc\ngc.set_threshold({chosen_threshold})").body
            node.body[0:0] = gc_nodes  # Prepend
            ast.fix_missing_locations(node)

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


def _create_evil_frame_modifier_ast(func_name: str, target_var: str) -> ast.FunctionDef:
    """
    Builds the AST for a function that uses sys._getframe() to modify a
    local variable in its caller's frame.
    """
    return cast(
        ast.FunctionDef,
        ast.parse(
            dedent(f"""
    def {func_name}():
        try:
            # Get the frame of the caller (the uop_harness)
            caller_frame = sys._getframe(1)
            # Corrupt the local variable in that frame
            caller_frame.f_locals['{target_var}'] = "corrupted_by_frame_manipulation"
        except (ValueError, KeyError):
            # Fail gracefully if frame inspection is not possible
            pass
    """)
        ).body[0],
    )


class FrameManipulator(ast.NodeTransformer):
    """
    Injects a function that uses sys._getframe() to maliciously modify the
    local variables of its caller, attacking JIT assumptions about local state.

    Note on CPython Internals:
    In CPython, modifications to a frame's `f_locals` dictionary do not
    reliably propagate back to the function's optimized "fast locals"
    (the C array holding local variables). This discrepancy is an intentional
    performance optimization in the interpreter.

    For our fuzzing purposes, this inconsistency is a feature, not a bug.
    It creates a scenario where the JIT's view of a variable's state might
    diverge from the state that other Python code sees, which is a potent
    source of potential bugs.

    Note on Complementary Mutators:
    This mutator is complementary to `SideEffectInjector`, which also
    corrupts local variables via frame introspection. The key difference
    is the corruption trigger:
    - FrameManipulator: corruption via a synchronous function call in a
      hot loop (tests JIT handling of frame manipulation during normal
      call flow)
    - SideEffectInjector: corruption via a __del__ finalizer triggered
      by object deletion (tests JIT handling of asynchronous GC-driven
      state changes)
    Both may be applied in the same pipeline, testing different
    deoptimization pathways.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or len(node.body) < 3:
            return node

        if random.random() < 0.15:  # 15% chance
            # 1. Select a target variable to corrupt.
            # We'll look for simple names that are stored.
            candidates = [
                n.id
                for n in ast.walk(node)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
            ]
            if not candidates:
                return node

            target_var = random.choice(candidates)

            p_prefix = f"frame_{random.randint(1000, 9999)}"
            evil_func_name = f"evil_modifier_{p_prefix}"

            print(
                f"    -> Injecting frame manipulator pattern targeting '{target_var}'",
                file=sys.stderr,
            )

            # 2. Get the AST for the evil function.
            evil_func_ast = _create_evil_frame_modifier_ast(evil_func_name, target_var)

            # 3. Create the AST for the hot loop and the guarded usage.
            attack_scenario_ast = ast.parse(
                dedent(f"""
                # This loop triggers the corruption
                for _ in range(50):
                    {evil_func_name}()

                # This usage will fail if the JIT's type assumption isn't invalidated
                try:
                    _ = {target_var} + 1
                except (TypeError, NameError):
                    pass
            """)
            ).body

            # 4. Inject the evil function and the attack scenario into the harness.
            injection_point = random.randint(0, len(node.body))
            full_injection = [evil_func_ast] + attack_scenario_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


def _create_gc_callback_ast(func_name: str) -> ast.FunctionDef:
    """Builds the AST for the weakref callback function."""
    return cast(
        ast.FunctionDef,
        ast.parse(
            dedent(f"""
    def {func_name}(ref, var_name):
        # This function is triggered by the GC when the weakref's
        # target is collected. It modifies a global variable.
        globals()[var_name] = "modified_by_gc"
    """)
        ).body[0],
    )


def _create_target_object_ast(class_name: str) -> ast.ClassDef:
    """Builds the AST for a simple, empty class to be garbage collected."""
    return cast(
        ast.ClassDef,
        ast.parse(
            dedent(f"""
    class {class_name}:
        pass
    """)
        ).body[0],
    )


class WeakRefCallbackChaos(ast.NodeTransformer):
    """
    Injects a scenario that uses a weakref callback to modify a global
    variable during garbage collection, attacking JIT assumptions about
    the stability of globals.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"gc_{random.randint(1000, 9999)}"
            class_name = f"TargetObject_{p_prefix}"
            callback_name = f"evil_callback_{p_prefix}"
            instance_name = f"target_obj_{p_prefix}"
            var_name = f"gc_var_{p_prefix}"

            print(
                f"    -> Injecting weakref callback chaos with prefix '{p_prefix}'", file=sys.stderr
            )

            # 1. Get the AST for the callback and target class
            callback_ast = _create_gc_callback_ast(callback_name)
            class_ast = _create_target_object_ast(class_name)

            # 2. Create the AST for the full attack scenario
            scenario_ast = ast.parse(
                dedent(f"""
                # Setup the global variable and weakref
                global {var_name}
                {var_name} = 100
                {instance_name} = {class_name}()
                callback = lambda ref: {callback_name}(ref, '{var_name}')
                weak_ref = weakref.ref({instance_name}, callback)

                # Warm-up loop to encourage the JIT to specialize the global var's type
                for i in range(100):
                    _ = {var_name} + i

                del {instance_name}
                for _ in range(3):
                    gc.collect()
                    gc.collect()

                # Use the (now corrupted) global variable
                try:
                    _ = {var_name} + 1
                except TypeError:
                    pass
            """)
            ).body

            # 3. Inject the entire scenario (unchanged)
            node.body.insert(0, ast.parse("import gc").body[0])
            node.body.insert(0, ast.parse("import weakref").body[0])

            injection_point = random.randint(2, len(node.body))
            full_injection = [callback_ast, class_ast] + scenario_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


def _create_type_corruption_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to corrupt the type of a variable (e.g., `x = 'string'`)."""
    corruption_value = random.choice(["'corrupted by string'", "None", "123.456"])
    return ast.parse(f"{target_var} = {corruption_value}").body


def _create_uop_attribute_deletion_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to delete an attribute (e.g., `del obj.x`)."""
    attr_to_delete = random.choice(["value", "x", "y"])
    return ast.parse(f"del {target_var}.{attr_to_delete}").body


def _create_method_patch_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to monkey-patch a method on a class."""
    method_to_patch = random.choice(["get_value", "meth", "__repr__"])
    return ast.parse(f"{target_var}.__class__.{method_to_patch} = lambda *a, **kw: 'patched!'").body


def _create_dict_swap_node(var1_name: str, var2_name: str, **kwargs) -> list[ast.stmt]:
    """Generate an AST node to swap the __dict__ of two objects."""
    return ast.parse(
        f"{var1_name}.__dict__, {var2_name}.__dict__ = {var2_name}.__dict__, {var1_name}.__dict__"
    ).body


def _create_class_reassignment_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generate AST nodes to define a new class and reassign `obj.__class__`."""
    uid = random.randint(1000, 9999)
    return ast.parse(
        dedent(f"""
        class SwappedClass_{uid}:
            pass
        {target_var}.__class__ = SwappedClass_{uid}
    """)
    ).body


class SideEffectInjector(ast.NodeTransformer):
    """
    Inject a scenario that uses a `__del__` side effect to attack state stability.

    This mutator injects a `FrameModifier` class whose `__del__` method can
    maliciously alter the state of a function's local variables. It then
    instantiates and deletes this class inside a hot loop to trigger the
    side effect at a predictable time, testing the JIT's deoptimization
    pathways.

    Note: This mutator is complementary to `FrameManipulator`, which also
    corrupts local variables via frame introspection but through synchronous
    function calls rather than __del__ finalizers. See FrameManipulator's
    docstring for details on the distinction.
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

        if random.random() < 0.15:  # 15% chance
            # --- 1. Find potential targets in the function's AST ---
            local_vars = {
                n.id
                for n in ast.walk(node)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
            }
            # For simplicity, we'll just look for a local variable to target for now.
            # A more advanced version could find instance and class attributes.
            if not local_vars:
                return node

            print(
                f"    -> Injecting __del__ side-effect pattern into '{node.name}'",
                file=sys.stderr,
            )

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
                except (TypeError, NameError):
                    # TypeError: corruption changed the type (intended behavior)
                    # NameError/UnboundLocalError: variable not yet assigned (injection before definition)
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
                snippet_nodes = _create_dict_swap_node(var1_name=var1, var2_name=var2)
            else:
                snippet_nodes = action(target_var=target_var)  # type: ignore[call-arg]

            # 4. Wrap in try/except and insert at a random point.
            # Operations like del x.value or x.__class__ = NewClass will
            # raise AttributeError/TypeError on simple types (int, str).
            # Wrapping ensures the harness continues executing so the JIT
            # can still observe the rest of the function.
            if node.body:
                try_node = ast.parse(
                    dedent("""
                    try:
                        pass
                    except Exception:
                        pass
                """)
                ).body[0]
                assert isinstance(try_node, ast.Try)
                try_node.body = snippet_nodes
                insert_pos = random.randint(0, len(node.body))
                node.body.insert(insert_pos, try_node)

        return node


def _create_closure_stomper() -> ast.FunctionDef:
    """
    Creates a helper function `_jit_stomp_closure` that randomly corrupts
    the closure cells of a given target function.
    """
    return cast(
        ast.FunctionDef,
        ast.parse(
            dedent("""
    def _jit_stomp_closure(target_func):
        try:
            if not hasattr(target_func, "__closure__") or not target_func.__closure__:
                return
            
            # We need to import random locally to ensure it's available
            import random
            
            for cell in target_func.__closure__:
                try:
                    # Randomly replace cell contents with chaotic values
                    val = random.choice([None, "CHAOS_STR", 999999, 0.0, [], {}, object()])
                    cell.cell_contents = val
                except Exception:
                    # Ignore read-only cells or other errors
                    pass
        except Exception:
            pass
    """)
        ).body[0],
    )


class ClosureStompMutator(ast.NodeTransformer):
    """
    Injects a runtime attack that directly modifies `func.__closure__[i].cell_contents`,
    potentially invalidating type/value assumptions made by the JIT for nested functions.

    This mutator:
    1. Injects a `_jit_stomp_closure` helper function.
    2. Inserts a call to this helper immediately after a function definition.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef | list[ast.stmt]:
        # First visit children
        self.generic_visit(node)

        # Do not stomp the harness function itself.
        # This prevents the root node of the mutation (the harness) from being replaced
        # by a list, which causes crashes in the MutationController pipeline.
        if node.name.startswith("uop_harness"):
            return node

        # Prevent recursive stomping of the helper function itself
        if node.name == "_jit_stomp_closure":
            return node

        # Apply with low probability to avoid excessive noise
        if random.random() > 0.15:
            return node

        print(f"    -> Injecting closure stomper for '{node.name}'", file=sys.stderr)

        # 1. Create the helper function AST
        helper_ast = _create_closure_stomper()

        # 2. Create the call to the helper: _jit_stomp_closure(node.name)
        call_ast = ast.Expr(
            value=ast.Call(
                func=ast.Name(id="_jit_stomp_closure", ctx=ast.Load()),
                args=[ast.Name(id=node.name, ctx=ast.Load())],
                keywords=[],
            )
        )

        # 3. Return the sequence: [node, helper, call]
        # This defines the original function, then the helper, then calls the helper on the function.
        # Note: We define the helper *at the site of use*. This might lead to redefinitions if used
        # multiple times, but that's safe in Python.
        return [node, helper_ast, call_ast]


class EvalFrameHookMutator(ast.NodeTransformer):
    """
    Attacks JIT assumptions by installing/removing custom eval frame hooks.

    This targets the set_eval_frame_func rare event by:
    - Installing a custom frame evaluation function mid-execution
    - Recording frame evaluations with _testinternalcapi.set_eval_frame_record
    - Swapping between default and custom eval frames in hot loops
    - Forcing deoptimization when frame eval assumptions change
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            attack_type = random.choice(
                ["frame_record_toggle", "custom_eval_install", "eval_default_cycle"]
            )

            p_prefix = f"eval_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting eval frame hook attack ({attack_type}) with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            if attack_type == "frame_record_toggle":
                scenario_ast = self._create_frame_record_attack(p_prefix)
            elif attack_type == "custom_eval_install":
                scenario_ast = self._create_custom_eval_attack(p_prefix)
            else:  # eval_default_cycle
                scenario_ast = self._create_eval_cycle_attack(p_prefix)

            # Import _testinternalcapi at the top of the function
            import_node = ast.parse("from test.support import import_helper").body[0]
            helper_import = ast.parse(
                "_testinternalcapi = import_helper.import_module('_testinternalcapi')"
            ).body[0]

            # Inject the imports and scenario
            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = [import_node, helper_import] + scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_frame_record_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Create attack that uses set_eval_frame_record to track frame evaluations,
        then toggles it on/off to force invalidation.
        """
        attack_code = dedent(f"""
            # Eval frame record attack - toggling frame recording
            print('[{prefix}] Running eval frame record attack...', file=sys.stderr)

            frame_list_{prefix} = []

            # Phase 1: Warmup without recording
            for i_{prefix} in range(100):
                try:
                    _ = i_{prefix} * 2 + 1
                except Exception:
                    pass

            # Phase 2: Install frame recording (triggers set_eval_frame_func)
            try:
                _testinternalcapi.set_eval_frame_record(frame_list_{prefix})

                # Execute code while recording frames
                for i_{prefix} in range(50):
                    _ = i_{prefix} * 3 + 2

                # Phase 3: Remove frame recording (triggers set_eval_frame_func again)
                _testinternalcapi.set_eval_frame_default()

                # Phase 4: Continue execution after hook removal
                for i_{prefix} in range(50):
                    _ = i_{prefix} * 4 + 3

            except (AttributeError, RuntimeError):
                # Gracefully handle if _testinternalcapi is not available
                pass
        """)
        return ast.parse(attack_code).body

    def _create_custom_eval_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Create attack that installs a custom eval function mid-execution.
        """
        attack_code = dedent(f"""
            # Custom eval frame attack - install custom evaluator
            print('[{prefix}] Running custom eval frame attack...', file=sys.stderr)

            # Phase 1: Warmup loop to get JIT compiled
            warmup_result_{prefix} = 0
            for i_{prefix} in range(200):
                warmup_result_{prefix} += i_{prefix}

            # Phase 2: Install frame recording to change eval behavior
            frame_log_{prefix} = []
            try:
                _testinternalcapi.set_eval_frame_record(frame_log_{prefix})

                # Execute the same pattern - JIT should deoptimize
                attack_result_{prefix} = 0
                for i_{prefix} in range(100):
                    attack_result_{prefix} += i_{prefix}

                # Restore default
                _testinternalcapi.set_eval_frame_default()

                # Verify results
                if frame_log_{prefix}:
                    print(f'[{prefix}] Captured {{len(frame_log_{prefix})}} frame evaluations', file=sys.stderr)

            except (AttributeError, RuntimeError):
                pass
        """)
        return ast.parse(attack_code).body

    def _create_eval_cycle_attack(self, prefix: str) -> list[ast.stmt]:
        """
        Create attack that rapidly cycles between default and custom eval.
        """
        attack_code = dedent(f"""
            # Eval frame cycling attack - rapid toggle
            print('[{prefix}] Running eval frame cycling attack...', file=sys.stderr)

            try:
                cycle_result_{prefix} = 0
                frame_buffer_{prefix} = []

                # Rapidly cycle between eval modes to stress deoptimization
                for cycle_{prefix} in range(20):
                    # Install custom eval
                    _testinternalcapi.set_eval_frame_record(frame_buffer_{prefix})

                    # Do some work
                    for i_{prefix} in range(10):
                        cycle_result_{prefix} += i_{prefix}

                    # Restore default eval
                    _testinternalcapi.set_eval_frame_default()

                    # Do more work
                    for i_{prefix} in range(10):
                        cycle_result_{prefix} -= i_{prefix} // 2

                # Final restoration
                _testinternalcapi.set_eval_frame_default()

            except (AttributeError, RuntimeError):
                pass
        """)
        return ast.parse(attack_code).body


class RareEventStressTester(ast.NodeTransformer):
    """
    Meta-mutator that combines multiple rare event triggers in a single scenario.

    This mutator chains together multiple JIT rare events (set_class, set_bases,
    set_eval_frame_func, builtin_dict, func_modification) to stress the JIT's
    ability to handle multiple invalidations in sequence.

    The goal is to trigger complex deoptimization paths where multiple caches
    become invalid simultaneously or in rapid succession.
    """

    # All rare event types we can trigger
    RARE_EVENTS = [
        "set_class",
        "set_bases",
        "set_eval_frame",
        "builtin_dict",
        "func_modification",
    ]

    # Combination patterns for multi-event attacks
    EVENT_COMBINATIONS = [
        ["set_class", "set_bases"],  # MRO-related events
        ["builtin_dict", "func_modification"],  # Namespace/function events
        ["set_eval_frame", "func_modification"],  # Execution model events
        ["set_class", "builtin_dict", "func_modification"],  # Mixed
        ["set_class", "set_bases", "set_eval_frame"],  # Type + eval events
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Inject rare event stress test into functions."""
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if not node.body:
            return node

        if random.random() < 0.08:  # 8% chance (meta-mutator, lower probability)
            p_prefix = f"rarestress_{random.randint(1000, 9999)}"

            # Choose attack pattern: single event or combination
            if random.random() < 0.4:  # 40% chance for single event
                event = random.choice(self.RARE_EVENTS)
                print(
                    f"    -> Injecting single rare event stress test ({event}) into '{node.name}'",
                    file=sys.stderr,
                )
                stress_nodes = self._create_single_event_attack(p_prefix, event)
            else:  # 60% chance for combination
                events = random.choice(self.EVENT_COMBINATIONS)
                print(
                    f"    -> Injecting rare event combination ({', '.join(events)}) "
                    f"into '{node.name}'",
                    file=sys.stderr,
                )
                stress_nodes = self._create_combination_attack(p_prefix, events)

            # Inject at the beginning of the function body
            node.body = stress_nodes + node.body
            ast.fix_missing_locations(node)

        return node

    def _create_single_event_attack(self, prefix: str, event: str) -> list[ast.stmt]:
        """Create a single rare event trigger attack."""
        if event == "set_class":
            return self._create_set_class_attack(prefix)
        elif event == "set_bases":
            return self._create_set_bases_attack(prefix)
        elif event == "set_eval_frame":
            return self._create_set_eval_frame_attack(prefix)
        elif event == "builtin_dict":
            return self._create_builtin_dict_attack(prefix)
        elif event == "func_modification":
            return self._create_func_modification_attack(prefix)
        else:
            return []

    def _create_combination_attack(self, prefix: str, events: list[str]) -> list[ast.stmt]:
        """Create an attack that triggers multiple rare events in sequence."""
        attack_code = dedent(f"""
            # Rare event combination attack: {", ".join(events)}
            print('[{prefix}] Starting rare event combination attack...', file=sys.stderr)
            import sys
            import builtins
        """)

        # Phase 1: Warmup to establish JIT traces
        attack_code += dedent(f"""
            # Phase 1: Warmup to establish JIT traces
            warmup_result_{prefix} = 0
            for warm_{prefix} in range(200):
                warmup_result_{prefix} += warm_{prefix}
        """)

        # Phase 2: Create objects/classes we'll mutate
        attack_code += dedent(f"""
            # Phase 2: Create mutable targets
            class Target_{prefix}:
                value = 42
                def method(self):
                    return self.value

            class AltBase_{prefix}:
                alt_value = 999

            target_obj_{prefix} = Target_{prefix}()
        """)

        # Phase 3: Sequential rare event triggers
        attack_code += dedent(f"""
            # Phase 3: Sequential rare event triggers
            print('[{prefix}] Triggering rare events...', file=sys.stderr)
        """)

        for i, event in enumerate(events):
            if event == "set_class":
                attack_code += dedent(f"""
            # Event {i + 1}: set_class
            print('[{prefix}] Triggering set_class...', file=sys.stderr)
            class NewClass_{prefix}_{i}:
                value = 100 + {i}
            try:
                target_obj_{prefix}.__class__ = NewClass_{prefix}_{i}
                _ = target_obj_{prefix}.value
            except Exception:
                pass
                """)
            elif event == "set_bases":
                attack_code += dedent(f"""
            # Event {i + 1}: set_bases
            print('[{prefix}] Triggering set_bases...', file=sys.stderr)
            try:
                Target_{prefix}.__bases__ = (AltBase_{prefix},)
            except Exception:
                pass
                """)
            elif event == "set_eval_frame":
                attack_code += dedent(f"""
            # Event {i + 1}: set_eval_frame
            print('[{prefix}] Triggering set_eval_frame...', file=sys.stderr)
            def dummy_trace_{prefix}_{i}(frame, event, arg):
                return None
            try:
                sys.settrace(dummy_trace_{prefix}_{i})
                for trace_iter_{prefix}_{i} in range(10):
                    _ = trace_iter_{prefix}_{i} * 2
                sys.settrace(None)
            except Exception:
                pass
                """)
            elif event == "builtin_dict":
                attack_code += dedent(f"""
            # Event {i + 1}: builtin_dict
            print('[{prefix}] Triggering builtin_dict...', file=sys.stderr)
            try:
                builtins.__dict__['RARE_TEST_{prefix}_{i}'] = {i + 100}
                _ = builtins.len([1, 2, 3])
                del builtins.__dict__['RARE_TEST_{prefix}_{i}']
            except Exception:
                pass
                """)
            elif event == "func_modification":
                attack_code += dedent(f"""
            # Event {i + 1}: func_modification
            print('[{prefix}] Triggering func_modification...', file=sys.stderr)
            def target_func_{prefix}_{i}(x):
                return x + 1
            try:
                # Warm up the function
                for func_warm_{prefix}_{i} in range(50):
                    _ = target_func_{prefix}_{i}(func_warm_{prefix}_{i})
                # Modify __code__
                def replacement_func_{prefix}_{i}(x):
                    return x * 2
                target_func_{prefix}_{i}.__code__ = replacement_func_{prefix}_{i}.__code__
                # Use modified function
                _ = target_func_{prefix}_{i}(10)
            except Exception:
                pass
                """)

        # Phase 3.5: Cleanup persistent state
        if "set_eval_frame" in events:
            attack_code += dedent("""
            # Cleanup: Remove any installed trace functions
            try:
                sys.settrace(None)
            except Exception:
                pass
            """)

        if "builtin_dict" in events:
            attack_code += dedent(f"""
            # Cleanup: Remove any injected builtin keys
            try:
                for _cleanup_key_{prefix} in list(builtins.__dict__.keys()):
                    if _cleanup_key_{prefix}.startswith('RARE_TEST_{prefix}'):
                        del builtins.__dict__[_cleanup_key_{prefix}]
            except Exception:
                pass
            """)

        # Add final verification
        attack_code += dedent(f"""
            # Phase 4: Verification - use objects after rare events
            print('[{prefix}] Verification phase...', file=sys.stderr)
            try:
                verify_result_{prefix} = 0
                for verify_{prefix} in range(50):
                    verify_result_{prefix} += verify_{prefix}
            except Exception:
                pass

            print(f'[{prefix}] Rare event combination complete', file=sys.stderr)
        """)

        return ast.parse(attack_code).body

    def _create_set_class_attack(self, prefix: str) -> list[ast.stmt]:
        """Create a focused set_class rare event attack."""
        attack_code = dedent(f"""
            # Single rare event attack: set_class
            print('[{prefix}] Running set_class stress test...', file=sys.stderr)

            class OriginalClass_{prefix}:
                value = 1
                def compute(self):
                    return self.value * 2

            class AlternateClass_{prefix}:
                value = 100
                def compute(self):
                    return self.value + 10

            obj_{prefix} = OriginalClass_{prefix}()

            # Phase 1: Warmup
            for warm_{prefix} in range(200):
                _ = obj_{prefix}.compute()
                _ = obj_{prefix}.value

            # Phase 2: Rapid class swapping
            for swap_{prefix} in range(50):
                try:
                    if swap_{prefix} % 2 == 0:
                        obj_{prefix}.__class__ = AlternateClass_{prefix}
                    else:
                        obj_{prefix}.__class__ = OriginalClass_{prefix}
                    _ = obj_{prefix}.compute()
                except Exception:
                    pass

            # Restore
            try:
                obj_{prefix}.__class__ = OriginalClass_{prefix}
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_set_bases_attack(self, prefix: str) -> list[ast.stmt]:
        """Create a focused set_bases rare event attack."""
        attack_code = dedent(f"""
            # Single rare event attack: set_bases
            print('[{prefix}] Running set_bases stress test...', file=sys.stderr)

            class BaseA_{prefix}:
                value_a = 10

            class BaseB_{prefix}:
                value_b = 20

            class Target_{prefix}(BaseA_{prefix}):
                pass

            obj_{prefix} = Target_{prefix}()

            # Phase 1: Warmup
            for warm_{prefix} in range(200):
                _ = obj_{prefix}.value_a

            # Phase 2: Base swapping
            for swap_{prefix} in range(30):
                try:
                    if swap_{prefix} % 2 == 0:
                        Target_{prefix}.__bases__ = (BaseB_{prefix},)
                    else:
                        Target_{prefix}.__bases__ = (BaseA_{prefix},)
                except Exception:
                    pass

            # Restore
            try:
                Target_{prefix}.__bases__ = (BaseA_{prefix},)
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_set_eval_frame_attack(self, prefix: str) -> list[ast.stmt]:
        """Create a focused set_eval_frame rare event attack."""
        attack_code = dedent(f"""
            # Single rare event attack: set_eval_frame
            print('[{prefix}] Running set_eval_frame stress test...', file=sys.stderr)
            import sys

            def trace_func_{prefix}(frame, event, arg):
                return trace_func_{prefix}

            # Phase 1: Warmup without trace
            result_{prefix} = 0
            for warm_{prefix} in range(200):
                result_{prefix} += warm_{prefix}

            # Phase 2: Rapid trace toggling
            for toggle_{prefix} in range(30):
                try:
                    # Install trace
                    sys.settrace(trace_func_{prefix})

                    # Do work
                    for work_{prefix} in range(10):
                        result_{prefix} += work_{prefix}

                    # Remove trace
                    sys.settrace(None)

                    # More work
                    for more_work_{prefix} in range(10):
                        result_{prefix} -= more_work_{prefix}
                except Exception:
                    pass

            # Ensure trace is cleared
            try:
                sys.settrace(None)
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_builtin_dict_attack(self, prefix: str) -> list[ast.stmt]:
        """Create a focused builtin_dict rare event attack."""
        attack_code = dedent(f"""
            # Single rare event attack: builtin_dict
            print('[{prefix}] Running builtin_dict stress test...', file=sys.stderr)
            import builtins

            # Phase 1: Warmup using builtins
            for warm_{prefix} in range(200):
                _ = len([warm_{prefix}])
                _ = isinstance(warm_{prefix}, int)

            # Phase 2: Rapid builtin dict modifications
            for mod_{prefix} in range(50):
                try:
                    key_{prefix} = f'RARE_BUILTIN_{{mod_{prefix}}}'
                    builtins.__dict__[key_{prefix}] = mod_{prefix}
                    # Use some builtins
                    _ = len([1, 2, 3])
                    _ = isinstance(1, int)
                    # Remove key
                    del builtins.__dict__[key_{prefix}]
                except Exception:
                    pass
        """)
        return ast.parse(attack_code).body

    def _create_func_modification_attack(self, prefix: str) -> list[ast.stmt]:
        """Create a focused func_modification rare event attack."""
        attack_code = dedent(f"""
            # Single rare event attack: func_modification
            print('[{prefix}] Running func_modification stress test...', file=sys.stderr)

            def target_func_{prefix}(x):
                return x + 1

            def alt_func_{prefix}(x):
                return x * 2

            def another_func_{prefix}(x):
                return x - 1

            # Phase 1: Warmup target function
            for warm_{prefix} in range(200):
                _ = target_func_{prefix}(warm_{prefix})

            # Phase 2: Rapid __code__ swapping
            funcs_{prefix} = [target_func_{prefix}, alt_func_{prefix}, another_func_{prefix}]
            codes_{prefix} = [f.__code__ for f in funcs_{prefix}]

            for swap_{prefix} in range(50):
                try:
                    target_func_{prefix}.__code__ = codes_{prefix}[swap_{prefix} % len(codes_{prefix})]
                    _ = target_func_{prefix}(10)
                except Exception:
                    pass

            # Restore original code
            try:
                target_func_{prefix}.__code__ = codes_{prefix}[0]
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body


class RefcountEscapeHatchMutator(ast.NodeTransformer):
    """
    Stress the JIT's refcount elimination optimization.

    The JIT replaces _POP_TOP (decref) with _POP_TOP_NOP (no-op) when it
    proves a value is borrowed or immortal. This mutator creates scenarios
    where values appear to have stable refcounts during tracing but become
    the sole reference at runtime, targeting the boundary where skipping
    a decref would cause use-after-free.

    Attack vectors:
    1. del_last_ref: STORE_FAST where the old value's only other reference
       is dropped by a __del__ callback, making the optimized-away decref
       the one that should have freed the object.
    2. weakref_surprise: LOAD_ATTR on an object whose only strong ref is
       via a container that gets cleared by a weakref callback during GC,
       leaving the JIT's "borrowed" reference dangling.
    3. descriptor_refcount_drain: Attribute access triggers a descriptor
       whose __get__ drops references to the owner object, making the
       JIT's assumption about the owner's refcount incorrect.
    4. reentrant_container_clear: CONTAINS_OP / STORE_SUBSCR on a container
       whose __contains__/__setitem__ clears the container itself,
       potentially freeing the value the JIT skipped decref on.
    5. store_fast_resurrection: STORE_FAST to a local where the old value's
       __del__ assigns itself back to a global (resurrection), but the JIT
       already decided to skip the decref.
    6. custom_add_side_effect: BINARY_OP on objects whose __add__ has side
       effects that drop references to the operands, breaking the JIT's
       refcount assumptions about _BINARY_OP.
    7. to_bool_ref_escape: TO_BOOL on objects whose __bool__ drops the last
       reference to the object being tested, via container mutation.
    8. module_attr_volatile: LOAD_ATTR_MODULE where the module attribute
       is replaced between accesses, testing whether the JIT's cached
       borrowed reference becomes stale.
    """

    ATTACK_SCENARIOS = [
        "del_last_ref",
        "weakref_surprise",
        "descriptor_refcount_drain",
        "reentrant_container_clear",
        "store_fast_resurrection",
        "custom_add_side_effect",
        "to_bool_ref_escape",
        "module_attr_volatile",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.10:  # 10% chance
            attack = random.choice(self.ATTACK_SCENARIOS)
            p_prefix = f"rcesc_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting refcount escape hatch attack ({attack}) "
                f"with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            scenario_ast = getattr(self, f"_create_{attack}")(p_prefix)

            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_del_last_ref(self, prefix: str) -> list[ast.stmt]:
        """
        STORE_FAST where __del__ on the old value drops the last external ref.

        The JIT sees `x = new_val` and decides the old x is a constant
        (or has known refcount > 1), so it skips the decref. But the old
        x's __del__ drops a reference held elsewhere, and the JIT's
        skipped decref was actually the last real one.
        """
        code = dedent(f"""
            _ref_holder_{prefix} = []

            class _Toxic_{prefix}:
                def __init__(self, val):
                    self.val = val
                    _ref_holder_{prefix}.append(self)

                def __del__(self):
                    # Drop the external reference on destruction
                    try:
                        _ref_holder_{prefix}.clear()
                    except Exception:
                        pass

                def __add__(self, other):
                    return _Toxic_{prefix}(self.val + other)

            # Phase 1: Warm up — JIT traces STORE_FAST, sees _Toxic has refcount > 1
            # (one in local, one in _ref_holder)
            _x_{prefix} = _Toxic_{prefix}(0)
            for _i_{prefix} in range(200):
                # STORE_FAST: old _x_{prefix} replaced. JIT may skip decref
                # because it saw refcount > 1 during tracing.
                _x_{prefix} = _Toxic_{prefix}(_i_{prefix})

            # Phase 2: Clear the holder so the local is the ONLY reference
            _ref_holder_{prefix}.clear()
            _x_{prefix} = _Toxic_{prefix}(999)

            # Phase 3: Continue the hot loop — now STORE_FAST's decref skip is wrong
            for _j_{prefix} in range(100):
                _x_{prefix} = _Toxic_{prefix}(_j_{prefix})

            # Phase 4: Force GC to find any leaked objects
            import gc
            gc.collect()
        """)
        return ast.parse(code).body

    def _create_weakref_surprise(self, prefix: str) -> list[ast.stmt]:
        """
        LOAD_ATTR where a weakref callback drops the owner's strong reference.

        The JIT traces LOAD_ATTR_INSTANCE_VALUE and decides _POP_TOP_NOP
        is safe because the object is alive. A weakref callback fires
        (from GC of an unrelated object) and clears the container holding
        the strong reference, leaving the JIT's borrowed ref dangling.
        """
        code = dedent(f"""
            import weakref
            import gc

            class _Owner_{prefix}:
                __slots__ = ('x', 'y')
                def __init__(self, x, y):
                    self.x = x
                    self.y = y

            # Container holding the only strong reference
            _container_{prefix} = {{}}

            def _evil_callback_{prefix}(ref):
                # When the weak referent dies, clear the container
                _container_{prefix}.clear()

            # Create owner and stash it
            _owner_{prefix} = _Owner_{prefix}(42, 3.14)
            _container_{prefix}['obj'] = _owner_{prefix}

            # Create a weak reference to a DIFFERENT object with evil callback
            class _Trigger_{prefix}:
                pass

            _trigger_{prefix} = _Trigger_{prefix}()
            _wref_{prefix} = weakref.ref(_trigger_{prefix}, _evil_callback_{prefix})

            # Phase 1: Warm up — JIT traces LOAD_ATTR_SLOT, marks _POP_TOP_NOP
            for _i_{prefix} in range(200):
                _val_{prefix} = _owner_{prefix}.x + _owner_{prefix}.y

            # Phase 2: Kill trigger to fire callback (clears container)
            del _trigger_{prefix}
            gc.collect()

            # Phase 3: Try to use the owner — container no longer holds strong ref
            # The only ref is the local variable _owner_{prefix}
            try:
                for _j_{prefix} in range(50):
                    _val_{prefix} = _owner_{prefix}.x + _owner_{prefix}.y
            except (AttributeError, ReferenceError):
                pass
        """)
        return ast.parse(code).body

    def _create_descriptor_refcount_drain(self, prefix: str) -> list[ast.stmt]:
        """
        Property/descriptor whose __get__ drops references to the owner.

        The JIT traces LOAD_ATTR and decides the owner's refcount is stable.
        The descriptor's __get__ deletes the owner from a container, making
        the next access use a potentially-freed object.
        """
        code = dedent(f"""
            _instances_{prefix} = {{}}

            class _DrainDescriptor_{prefix}:
                def __get__(self, obj, objtype=None):
                    if obj is None:
                        return self
                    # Side effect: remove owner from global dict
                    _instances_{prefix}.pop(id(obj), None)
                    return 42

                def __set__(self, obj, value):
                    pass

            class _Victim_{prefix}:
                drain = _DrainDescriptor_{prefix}()

                def __init__(self, val):
                    self.val = val
                    _instances_{prefix}[id(self)] = self

            # Phase 1: Warm up — JIT traces .drain access, sees _POP_TOP_NOP safe
            _v_{prefix} = _Victim_{prefix}(100)
            _instances_{prefix}[id(_v_{prefix})] = _v_{prefix}
            for _i_{prefix} in range(200):
                _r_{prefix} = _v_{prefix}.drain
                _r_{prefix} = _v_{prefix}.val  # Uses val after drain dropped ref

            # Phase 2: Create many victims and access drain in hot loop
            for _j_{prefix} in range(50):
                _v2_{prefix} = _Victim_{prefix}(_j_{prefix})
                try:
                    for _k_{prefix} in range(20):
                        _ = _v2_{prefix}.drain
                        _ = _v2_{prefix}.val
                except (AttributeError, TypeError):
                    pass
        """)
        return ast.parse(code).body

    def _create_reentrant_container_clear(self, prefix: str) -> list[ast.stmt]:
        """
        CONTAINS_OP/STORE_SUBSCR on containers with self-clearing dunders.

        The JIT sees `x in container` and eliminates the refcount on x
        (since it's still on the stack). But __contains__ clears the
        container and may trigger cascading destruction.
        """
        code = dedent(f"""
            class _ClearingDict_{prefix}(dict):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self._clear_count = 0

                def __contains__(self, key):
                    self._clear_count += 1
                    result = super().__contains__(key)
                    # Every 50th check, clear everything
                    if self._clear_count % 50 == 0:
                        saved = dict(self)  # save before clearing
                        self.clear()
                        self.update(saved)  # restore
                    return result

                def __setitem__(self, key, value):
                    super().__setitem__(key, value)
                    # Every 30th set, rebuild the dict
                    if len(self) > 30:
                        items = list(self.items())[-10:]
                        self.clear()
                        for k, v in items:
                            super().__setitem__(k, v)

            class _ClearingList_{prefix}(list):
                def __contains__(self, item):
                    result = super().__contains__(item)
                    # Periodically clear and rebuild
                    if len(self) > 20:
                        saved = list(self)[-5:]
                        self.clear()
                        self.extend(saved)
                    return result

            # Phase 1: Warm up — JIT traces CONTAINS_OP_DICT, marks _POP_TOP_NOP
            _cd_{prefix} = _ClearingDict_{prefix}({{i: i * 2 for i in range(20)}})
            for _i_{prefix} in range(200):
                _ = _i_{prefix} % 20 in _cd_{prefix}

            # Phase 2: Heavy containment checks triggering clears
            for _j_{prefix} in range(300):
                _ = _j_{prefix} % 100 in _cd_{prefix}
                _cd_{prefix}[_j_{prefix} % 100] = _j_{prefix}

            # Phase 3: Same for CONTAINS_OP (list)
            _cl_{prefix} = _ClearingList_{prefix}(list(range(30)))
            for _k_{prefix} in range(200):
                _ = _k_{prefix} % 30 in _cl_{prefix}

            # Phase 4: STORE_SUBSCR_LIST_INT with clearing
            _sl_{prefix} = _ClearingList_{prefix}(list(range(20)))
            for _m_{prefix} in range(200):
                try:
                    _sl_{prefix}[_m_{prefix} % len(_sl_{prefix})] = _m_{prefix}
                except (IndexError, ZeroDivisionError):
                    _sl_{prefix} = _ClearingList_{prefix}(list(range(20)))
        """)
        return ast.parse(code).body

    def _create_store_fast_resurrection(self, prefix: str) -> list[ast.stmt]:
        """
        STORE_FAST where the old value's __del__ resurrects it.

        The JIT eliminates the decref on STORE_FAST because it "knows"
        the old value has another reference. The old value's __del__
        resurrects the object by assigning it to a global.
        """
        code = dedent(f"""
            import gc

            _graveyard_{prefix} = []

            class _Undead_{prefix}:
                def __init__(self, val):
                    self.val = val
                    self.alive = True

                def __del__(self):
                    # Resurrect: add self back to a global list
                    if self.alive:
                        self.alive = False
                        _graveyard_{prefix}.append(self)

                def __add__(self, other):
                    return _Undead_{prefix}(self.val + other)

            # Phase 1: Warm up — JIT traces STORE_FAST, learns refcount pattern
            _u_{prefix} = _Undead_{prefix}(0)
            for _i_{prefix} in range(200):
                _u_{prefix} = _Undead_{prefix}(_i_{prefix})

            # Phase 2: Force GC to process __del__ calls
            gc.collect()

            # Phase 3: Use resurrected objects — these were "freed" by JIT
            for _dead_{prefix} in _graveyard_{prefix}:
                try:
                    _ = _dead_{prefix}.val + 1
                except (TypeError, AttributeError):
                    pass

            # Phase 4: Continue hot loop with interleaved GC
            _graveyard_{prefix}.clear()
            for _j_{prefix} in range(100):
                _u_{prefix} = _Undead_{prefix}(_j_{prefix})
                if _j_{prefix} % 20 == 0:
                    gc.collect()

            # Phase 5: Final resurrection check
            gc.collect()
            gc.collect()
            for _dead2_{prefix} in _graveyard_{prefix}:
                try:
                    _ = _dead2_{prefix}.val + 1
                except (TypeError, AttributeError):
                    pass
        """)
        return ast.parse(code).body

    def _create_custom_add_side_effect(self, prefix: str) -> list[ast.stmt]:
        """
        BINARY_OP on objects whose __add__ drops references to operands.

        Since commit 4e10fa99, the JIT eliminates refcounts for generic
        _BINARY_OP (custom __add__). This attack creates objects whose
        __add__ has side effects that weaken the operand references.
        """
        code = dedent(f"""
            _side_effect_log_{prefix} = []

            class _EvilAdder_{prefix}:
                _instances = []

                def __init__(self, val):
                    self.val = val
                    _EvilAdder_{prefix}._instances.append(self)

                def __add__(self, other):
                    # Side effect: clear the class-level instance list
                    # This drops references to ALL EvilAdder instances
                    if len(_EvilAdder_{prefix}._instances) > 50:
                        _EvilAdder_{prefix}._instances.clear()
                    result = _EvilAdder_{prefix}(self.val + other.val)
                    _side_effect_log_{prefix}.append(result.val)
                    return result

            # Phase 1: Warm up — JIT traces _BINARY_OP, marks _POP_TOP_NOP
            _a_{prefix} = _EvilAdder_{prefix}(1)
            _b_{prefix} = _EvilAdder_{prefix}(2)
            for _i_{prefix} in range(200):
                _res_{prefix} = _a_{prefix} + _b_{prefix}

            # Phase 2: Heavy add operations that trigger instance clearing
            for _j_{prefix} in range(200):
                _c_{prefix} = _EvilAdder_{prefix}(_j_{prefix})
                _d_{prefix} = _EvilAdder_{prefix}(_j_{prefix} + 1)
                try:
                    _res_{prefix} = _c_{prefix} + _d_{prefix}
                except (TypeError, AttributeError):
                    pass

            # Phase 3: Chain of adds (right-associative to stress stack)
            _chain_{prefix} = _EvilAdder_{prefix}(0)
            for _k_{prefix} in range(100):
                try:
                    _chain_{prefix} = _chain_{prefix} + _EvilAdder_{prefix}(1)
                except (TypeError, AttributeError):
                    _chain_{prefix} = _EvilAdder_{prefix}(0)
        """)
        return ast.parse(code).body

    def _create_to_bool_ref_escape(self, prefix: str) -> list[ast.stmt]:
        """
        TO_BOOL on objects whose __bool__ mutates external state.

        The JIT eliminates refcounts for TO_BOOL_INT, TO_BOOL_LIST,
        TO_BOOL_STR, and TO_BOOL_ALWAYS_TRUE. This creates objects
        whose __bool__ drops references via container mutation.
        """
        code = dedent(f"""
            _bool_refs_{prefix} = {{}}

            class _ToxicBool_{prefix}:
                def __init__(self, val, key):
                    self.val = val
                    self.key = key
                    _bool_refs_{prefix}[key] = self

                def __bool__(self):
                    # Side effect: remove self from global dict
                    _bool_refs_{prefix}.pop(self.key, None)
                    return bool(self.val)

            # Phase 1: Warm up with regular TO_BOOL_ALWAYS_TRUE pattern
            # (class instances are always truthy unless __bool__ returns False)
            _tb_{prefix} = _ToxicBool_{prefix}(1, "main")
            _count_{prefix} = 0
            for _i_{prefix} in range(200):
                if _tb_{prefix}:  # TO_BOOL_ALWAYS_TRUE, refcount eliminated
                    _count_{prefix} += 1

            # Phase 2: Create many objects and test truthiness in hot loop
            for _j_{prefix} in range(100):
                _obj_{prefix} = _ToxicBool_{prefix}(_j_{prefix}, f"obj_{{_j_{prefix}}}")
                try:
                    if _obj_{prefix}:  # __bool__ removes from dict
                        _count_{prefix} += 1
                except (KeyError, RuntimeError):
                    pass

            # Phase 3: TO_BOOL_INT pattern — int subclass with evil __bool__
            class _ToxicInt_{prefix}(int):
                def __bool__(self):
                    # Clear the refs dict during TO_BOOL_INT
                    if len(_bool_refs_{prefix}) > 10:
                        _bool_refs_{prefix}.clear()
                    return int.__bool__(self)

            for _k_{prefix} in range(200):
                _ti_{prefix} = _ToxicInt_{prefix}(_k_{prefix})
                _bool_refs_{prefix}[f"int_{{_k_{prefix}}}"] = _ti_{prefix}
                if _ti_{prefix}:  # TO_BOOL_INT with side-effecting __bool__
                    _count_{prefix} += 1

            # Phase 4: TO_BOOL_LIST pattern — list subclass
            class _ToxicList_{prefix}(list):
                def __bool__(self):
                    # self.clear() during truthiness check
                    result = len(self) > 0
                    if len(self) > 5:
                        self.clear()
                    return result

            _tl_{prefix} = _ToxicList_{prefix}(range(20))
            for _m_{prefix} in range(200):
                if _tl_{prefix}:  # TO_BOOL_LIST with self-clearing
                    _tl_{prefix}.append(_m_{prefix})
        """)
        return ast.parse(code).body

    def _create_module_attr_volatile(self, prefix: str) -> list[ast.stmt]:
        """
        LOAD_ATTR_MODULE where the module attribute changes between accesses.

        Since commit 6e55337f, the JIT eliminates refcounts for
        LOAD_ATTR_MODULE. This creates a module-like object whose
        attributes are volatile, testing the JIT's cached reference.
        """
        code = dedent(f"""
            import types
            import math

            # Phase 1: Warm up — JIT traces LOAD_ATTR_MODULE on math.pi
            _sum_{prefix} = 0.0
            for _i_{prefix} in range(200):
                _val_{prefix} = math.pi
                if _val_{prefix}:
                    _sum_{prefix} += 1.0

            # Phase 2: Replace math.pi mid-loop
            _orig_pi_{prefix} = math.pi
            for _j_{prefix} in range(200):
                _val_{prefix} = math.pi  # LOAD_ATTR_MODULE, refcount eliminated
                if _j_{prefix} == 100:
                    # Swap pi to a completely different type
                    math.pi = "not_a_float"
                try:
                    _sum_{prefix} += float(_val_{prefix})
                except (TypeError, ValueError):
                    pass
            math.pi = _orig_pi_{prefix}  # Restore

            # Phase 3: Create a fake module with volatile attributes
            _mod_{prefix} = types.ModuleType(f"_volatile_mod_{prefix}")
            _mod_{prefix}.value = 42
            _mod_{prefix}.counter = 0

            import sys
            sys.modules[f"_volatile_mod_{prefix}"] = _mod_{prefix}

            for _k_{prefix} in range(200):
                try:
                    _v_{prefix} = _mod_{prefix}.value
                    _mod_{prefix}.counter += 1
                    # Every 50 iterations, change the attribute type
                    if _mod_{prefix}.counter % 50 == 0:
                        _mod_{prefix}.value = str(_mod_{prefix}.value)
                    elif _mod_{prefix}.counter % 50 == 25:
                        _mod_{prefix}.value = float(_v_{prefix}) if isinstance(_v_{prefix}, (int, str)) else 42
                except (TypeError, ValueError, AttributeError):
                    _mod_{prefix}.value = 42

            # Cleanup
            sys.modules.pop(f"_volatile_mod_{prefix}", None)
        """)
        return ast.parse(code).body
