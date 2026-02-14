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

            # 2. Create the AST nodes for 'import gc' and 'gc.set_threshold(...)'
            import_node = ast.Import(names=[ast.alias(name="gc")])

            set_threshold_node = ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="gc", ctx=ast.Load()),
                        attr="set_threshold",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value=chosen_threshold)],
                    keywords=[],
                )
            )

            # 3. Prepend the new nodes to the function's body
            node.body.insert(0, set_threshold_node)
            node.body.insert(0, import_node)
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
                except TypeError:
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
            node.body.insert(0, ast.Import(names=[ast.alias(name="gc")]))
            node.body.insert(0, ast.Import(names=[ast.alias(name="weakref")]))

            injection_point = random.randint(2, len(node.body))
            full_injection = [callback_ast, class_ast] + scenario_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


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

            # 4. Insert the snippet at a random point in the function body.
            if node.body:
                insert_pos = random.randint(0, len(node.body))
                node.body[insert_pos:insert_pos] = snippet_nodes

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
