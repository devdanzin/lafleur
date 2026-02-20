"""
This module contains mutation scenarios designed to attack Python's data model
contracts and built-in functions.

The strategies here focus on the behavior of data. This includes injecting
"evil" objects that violate magic method protocols (e.g., unstable hashes,
lying equality), corrupting built-in namespaces, and creating scenarios that
misuse collection primitives like iterators and slices.
"""

from __future__ import annotations

import ast
import random
import sys
from textwrap import dedent, indent
from typing import Any, Callable, cast

from lafleur.mutators.utils import (
    genStatefulIterObject,
    genStatefulLenObject,
    genUnstableHashObject,
)


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
    """Generate calls to pow() with tricky arguments.

    Note: The prefix parameter is accepted but unused because this attack
    generates only bare pow() calls with no variables or classes that need
    namespacing. The parameter is kept to maintain a uniform Callable[[str],
    list[ast.stmt]] interface with _create_len_attack and _create_hash_attack.
    """
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


def _mutate_for_loop_iter(func_node: ast.FunctionDef) -> bool:
    """Find the first for loop in a function and replace its iterable with a stateful one.

    This is a shared helper used by MagicMethodMutator and IterableMutator.
    Returns True if a mutation was performed, False otherwise.
    """
    for i, stmt in enumerate(func_node.body):
        if isinstance(stmt, ast.For):
            print(f"    -> Mutating for loop iterator in '{func_node.name}'", file=sys.stderr)
            prefix = f"iter_{random.randint(1000, 9999)}"
            class_def_str = genStatefulIterObject(prefix)
            class_def_node = cast(ast.ClassDef, ast.parse(class_def_str).body[0])
            func_node.body.insert(0, class_def_node)
            # Adjust index since we inserted a class def at position 0
            stmt_index = i + 1
            stmt.iter = ast.Call(
                func=ast.Name(id=class_def_node.name, ctx=ast.Load()),
                args=[],
                keywords=[],
            )
            # Wrap the modified for loop in try/except to handle type
            # mismatches when the original loop did tuple unpacking or
            # expected specific types from the original iterable.
            wrapped_for = ast.Try(
                body=[stmt],
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
            func_node.body[stmt_index] = wrapped_for
            return True
    return False


class MagicMethodMutator(ast.NodeTransformer):
    """
    Attack JIT data model assumptions by stressing magic methods.

    This mutator injects scenarios that use "evil objects" with misbehaving
    magic methods (e.g., `__len__`, `__hash__`) or replaces iterables in
    `for` loops with stateful, malicious ones.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.15:  # Low probability for these attacks
            attack_functions: list[Callable[..., Any]] = [
                _create_len_attack,
                _create_hash_attack,
                _create_pow_attack,
                _mutate_for_loop_iter,
            ]
            chosen_attack = random.choice(attack_functions)

            nodes_to_inject: list[ast.stmt] = []
            if chosen_attack == _mutate_for_loop_iter:
                # This attack modifies the function in-place, so we call it differently
                if _mutate_for_loop_iter(node):
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
        tricky_values: list[str | bytes] = ["", "ab", b"c"]  # TypeError, TypeError, TypeError
        node.args = [ast.Constant(value=random.choice(tricky_values))]
        node.keywords = []
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

        # Strategy 1: Mutate arguments to numeric builtins within this harness
        mutator_map = {
            "pow": self._mutate_pow_args,
            "chr": self._mutate_chr_args,
            "ord": self._mutate_ord_args,
        }
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in mutator_map
                and random.random() < 0.1
            ):
                mutator_map[child.func.id](child)

        # Strategy 2: Inject abs() attack scenario
        if random.random() < 0.05:
            print(f"    -> Injecting numeric attack scenario into '{node.name}'", file=sys.stderr)

            attack_generators = [self._create_abs_attack_scenario]
            chosen_generator = random.choice(attack_generators)

            prefix = f"{node.name}_{random.randint(1000, 9999)}"
            nodes_to_inject = chosen_generator(prefix)

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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.15:  # Low probability for these attacks
            attack_functions: list[Callable[..., Any]] = [
                _create_len_attack,
                _create_hash_attack,
                _create_pow_attack,
                self._create_tuple_attack,
                self._create_all_any_attack,
                self._create_min_max_attack,
                _mutate_for_loop_iter,
            ]
            chosen_attack = random.choice(attack_functions)

            nodes_to_inject: list[ast.stmt] = []
            if chosen_attack == _mutate_for_loop_iter:
                # This attack modifies the function in-place
                if _mutate_for_loop_iter(node):
                    ast.fix_missing_locations(node)
            else:
                # These attacks inject a new, self-contained scenario
                prefix = f"{node.name}_{random.randint(1000, 9999)}"
                nodes_to_inject = chosen_attack(prefix)

            if nodes_to_inject:
                node.body = nodes_to_inject + node.body
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


class BuiltinNamespaceCorruptor(ast.NodeTransformer):
    """
    Temporarily replaces a built-in function with a malicious version to
    attack JIT specializations for builtins. Ensures restoration via a
    try...finally block.

    Enhanced with test_optimizer.py-inspired attacks:
    - Direct __builtins__["KEY"] style modifications
    - ModuleType vs dict representation handling
    - High-frequency builtin corruption
    """

    ATTACK_SCENARIOS = [
        {
            "builtin": "len",
            "warm_up": "for i in range(50): _ = len([0]*i); _ = len('x'*i)",
            "malicious_lambda": 'lambda x: "evil_string"',
            "trigger": "_ = len([])",
        },
        {
            "builtin": "range",
            "warm_up": "for i in range(50): _ = list(range(i)); _ = sum(range(i))",
            "malicious_lambda": "lambda x: [x, x, x]",
            "trigger": "_ = list(range(10))",
        },
        {
            "builtin": "isinstance",
            "warm_up": "for i in range(50): _ = isinstance(i, int); _ = isinstance('s', str)",
            "setup": dedent("""
                {original_var_name} = builtins.isinstance
                def evil_isinstance(obj, cls):
                    # This function closes over the original and inverts the logic
                    return not {original_var_name}(obj, cls)
            """),
            "malicious_assignment": "builtins.isinstance = evil_isinstance",
            "trigger": "_ = isinstance(1, int)",
        },
        {
            "builtin": "sum",
            "warm_up": "for i in range(50): _ = sum(range(i)); _ = sum([i, i, i])",
            "malicious_lambda": "lambda x: float('inf')",
            "trigger": "_ = sum([1, 2, 3])",
        },
    ]

    # Enhanced attack types (test_optimizer.py inspired)
    ENHANCED_ATTACKS = [
        "direct_dict_modification",
        "builtins_type_toggle",
        "highfreq_builtin_corruption",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"builtin_{random.randint(1000, 9999)}"

            # 30% chance to use enhanced attacks
            if random.random() < 0.3:
                attack_type = random.choice(self.ENHANCED_ATTACKS)
                print(
                    f"    -> Injecting enhanced builtin corruption ({attack_type}) "
                    f"with prefix '{p_prefix}'",
                    file=sys.stderr,
                )

                if attack_type == "direct_dict_modification":
                    scenario_ast = self._create_direct_dict_attack(p_prefix)
                elif attack_type == "builtins_type_toggle":
                    scenario_ast = self._create_builtins_type_toggle_attack(p_prefix)
                else:  # highfreq_builtin_corruption
                    scenario_ast = self._create_highfreq_builtin_attack(p_prefix)

                # Inject imports and scenario
                imports = ast.parse("import builtins\nimport types").body
                injection_point = random.randint(0, len(node.body))
                node.body[injection_point:injection_point] = imports + scenario_ast
                ast.fix_missing_locations(node)
            else:
                # Original attack logic
                attack = random.choice(self.ATTACK_SCENARIOS)
                builtin_name = attack["builtin"]
                original_var_name = f"original_{builtin_name}_{p_prefix}"

                print(f"    -> Injecting builtin corruption for '{builtin_name}'", file=sys.stderr)

                if "malicious_lambda" in attack:
                    # Simple case: build from a lambda
                    scenario_str = dedent(f"""
                        {original_var_name} = builtins.{builtin_name}
                        try:
                            {attack["warm_up"]}
                            builtins.{builtin_name} = {attack["malicious_lambda"]}
                            {attack["trigger"]}
                        except Exception:
                            pass
                        finally:
                            builtins.{builtin_name} = {original_var_name}
                    """)
                else:
                    # Complex case: build from setup and assignment strings
                    setup_code = attack["setup"].format(original_var_name=original_var_name)
                    scenario_str = dedent(f"""
{indent(setup_code, prefix=" " * 20)}
                        try:
                            {attack["warm_up"]}
                            {attack["malicious_assignment"]}
                            {attack["trigger"]}
                        except Exception:
                            pass
                        finally:
                            builtins.{builtin_name} = {original_var_name}
                    """)

                scenario_ast = ast.parse(scenario_str).body

                # Inject the scenario
                node.body.insert(0, ast.Import(names=[ast.alias(name="builtins")]))
                injection_point = random.randint(1, len(node.body))
                node.body[injection_point:injection_point] = scenario_ast
                ast.fix_missing_locations(node)

        return node

    def _create_direct_dict_attack(self, prefix: str) -> list[ast.stmt]:
        """Direct dictionary-style builtin modification (test_optimizer.py style)."""
        attack_code = dedent(f"""
            # Direct __builtins__ dict modification (test_optimizer.py style)
            print('[{prefix}] Running direct dict builtin attack...', file=sys.stderr)

            # Handle both dict and module representations
            if isinstance(__builtins__, types.ModuleType):
                builtins_dict_{prefix} = __builtins__.__dict__
            else:
                builtins_dict_{prefix} = __builtins__

            # Phase 1: Warmup with standard len calls
            try:
                for i_{prefix} in range(200):
                    _ = len([i_{prefix}])
                    _ = isinstance(i_{prefix}, int)
            except Exception:
                pass

            # Phase 2: Direct dict modification (triggers builtin_dict rare event)
            try:
                print('[{prefix}] Modifying builtins dict directly...', file=sys.stderr)
                builtins_dict_{prefix}["FUZZER_FOO_{prefix}"] = 42
                builtins_dict_{prefix}["FUZZER_BAR_{prefix}"] = lambda x: "evil"

                # Use the builtins after modification
                for i_{prefix} in range(50):
                    _ = len([i_{prefix}])
                    _ = isinstance(i_{prefix}, int)

                # Clean up
                del builtins_dict_{prefix}["FUZZER_FOO_{prefix}"]
                del builtins_dict_{prefix}["FUZZER_BAR_{prefix}"]

            except Exception:
                pass

            # Phase 3: Rapid add/delete cycle
            try:
                for i_{prefix} in range(100):
                    key_{prefix} = f"FUZZER_RAPID_{{i_{prefix}}}"
                    builtins_dict_{prefix}[key_{prefix}] = i_{prefix}
                    _ = len([i_{prefix}])
                    del builtins_dict_{prefix}[key_{prefix}]
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_builtins_type_toggle_attack(self, prefix: str) -> list[ast.stmt]:
        """Toggle between __builtins__ as module vs dict."""
        attack_code = dedent(f"""
            # Builtins type toggle attack
            print('[{prefix}] Running builtins type toggle...', file=sys.stderr)

            # Detect current type
            is_module_{prefix} = isinstance(__builtins__, types.ModuleType)
            print(f'[{prefix}] __builtins__ is module: {{is_module_{prefix}}}', file=sys.stderr)

            # Phase 1: Warmup
            try:
                for i_{prefix} in range(200):
                    _ = len([i_{prefix}])
                    _ = isinstance(1, int)
                    _ = type(i_{prefix})
            except Exception:
                pass

            # Phase 2: Access as different types
            try:
                if is_module_{prefix}:
                    # Access as dict via __dict__
                    print('[{prefix}] Accessing via module.__dict__...', file=sys.stderr)
                    dict_view_{prefix} = __builtins__.__dict__
                    dict_view_{prefix}["FUZZER_KEY_{prefix}"] = "evil_module"

                    # Use builtins after modification
                    for i_{prefix} in range(50):
                        _ = len([i_{prefix}])

                    del dict_view_{prefix}["FUZZER_KEY_{prefix}"]
                else:
                    # Already a dict, access directly
                    print('[{prefix}] Accessing as dict directly...', file=sys.stderr)
                    __builtins__["FUZZER_KEY_{prefix}"] = "evil_dict"

                    # Use builtins after modification
                    for i_{prefix} in range(50):
                        _ = len([i_{prefix}])

                    del __builtins__["FUZZER_KEY_{prefix}"]
            except Exception:
                pass

            # Phase 3: Stress test with type checking
            try:
                for i_{prefix} in range(100):
                    # Check type repeatedly to stress any caching
                    _ = isinstance(__builtins__, types.ModuleType)
                    _ = type(__builtins__)
                    _ = len([i_{prefix}])
            except Exception:
                pass
        """)
        return ast.parse(attack_code).body

    def _create_highfreq_builtin_attack(self, prefix: str) -> list[ast.stmt]:
        """Corrupt frequently-accessed builtins simultaneously."""
        attack_code = dedent(f"""
            # High-frequency builtin corruption
            print('[{prefix}] Corrupting frequently-used builtins...', file=sys.stderr)

            # Save originals
            original_len_{prefix} = builtins.len
            original_isinstance_{prefix} = builtins.isinstance
            original_type_{prefix} = builtins.type

            try:
                # Phase 1: Warmup with normal builtins
                for i_{prefix} in range(200):
                    _ = len([i_{prefix}])
                    _ = isinstance(i_{prefix}, int)
                    _ = type(i_{prefix})

                # Phase 2: Corrupt multiple builtins simultaneously
                print('[{prefix}] Corrupting len, isinstance, type...', file=sys.stderr)
                builtins.len = lambda x: 999
                builtins.isinstance = lambda obj, cls: False  # Always False!
                builtins.type = lambda x: "corrupted_type"

                # Phase 3: Attempt to use corrupted builtins
                for i_{prefix} in range(50):
                    try:
                        _ = len([i_{prefix}])
                        _ = isinstance(i_{prefix}, int)
                        _ = type(i_{prefix})
                    except Exception:
                        pass

                # Phase 4: Restore and corrupt again (rapid cycle)
                for cycle_{prefix} in range(20):
                    # Restore
                    builtins.len = original_len_{prefix}
                    builtins.isinstance = original_isinstance_{prefix}
                    builtins.type = original_type_{prefix}

                    _ = len([1, 2, 3])
                    _ = isinstance(1, int)

                    # Corrupt again
                    builtins.len = lambda x: -1
                    builtins.isinstance = lambda obj, cls: True  # Always True!

                    _ = len([1, 2, 3])
                    _ = isinstance("string", int)

            finally:
                # Always restore
                builtins.len = original_len_{prefix}
                builtins.isinstance = original_isinstance_{prefix}
                builtins.type = original_type_{prefix}
        """)
        return ast.parse(attack_code).body


def _create_chaotic_iterator_ast(class_name: str) -> ast.ClassDef:
    """
    Builds the AST for a custom iterator that can return an
    unexpected type, clear itself, or extend itself mid-iteration.
    """
    source_code = dedent(f"""
    class {class_name}:
        def __init__(self, items):
            self._items = list(items)
            self._index = 0

        def __iter__(self):
            return self

        def __next__(self):
            # Multiple, independent chances to cause chaos on each step
            if fuzzer_rng.random() < 0.05:
                self._items.clear()  # Prematurely end the iteration

            if fuzzer_rng.random() < 0.05:
                self._items.extend([999, 'chaos', None])  # Unexpectedly prolong the iteration

            if fuzzer_rng.random() < 0.1:
                return "unexpected_type_from_iterator"  # Corrupt the yielded value

            if self._index >= len(self._items):
                raise StopIteration

            item = self._items[self._index]
            self._index += 1
            return item
    """)
    return cast(ast.ClassDef, ast.parse(source_code).body[0])


class ComprehensionBomb(ast.NodeTransformer):
    """
    Injects a nested list comprehension that iterates over a custom iterator
    which has side effects, attacking JIT optimizations for iterators.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            p_prefix = f"comp_{random.randint(1000, 9999)}"
            class_name = f"ChaoticIterator_{p_prefix}"
            iter_name = f"evil_iter_{p_prefix}"

            print(f"    -> Injecting comprehension bomb with prefix '{p_prefix}'", file=sys.stderr)

            # 1. Get the AST for the ChaoticIterator class
            class_ast = _create_chaotic_iterator_ast(class_name)

            # 2. Create the AST for the setup and the comprehension bomb
            bomb_ast = ast.parse(
                dedent(f"""
                # Instantiate the iterator
                {iter_name} = {class_name}(range(200))
                try:
                    # The __next__ method of the iterator will be called for every
                    # item access, potentially returning a non-integer,
                    # which would cause a TypeError in the 'x + y' expression.
                    _ = [x + y for x in {iter_name} for y in {iter_name} if ({iter_name}._items.append(x) or True)]
                except Exception:
                    pass
            """)
            ).body

            # 3. Inject the entire scenario into the harness
            injection_point = random.randint(0, len(node.body))
            full_injection = [class_ast] + bomb_ast
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


class ReentrantSideEffectMutator(ast.NodeTransformer):
    """
    Create "rug pull" attacks that clear containers during access.

    This mutator injects a RugPuller object that clears or modifies a mutable
    container while that container is being accessed (e.g., inside __index__,
    __hash__, or __eq__). This targets re-entrancy bugs and use-after-free
    vulnerabilities in the JIT.
    """

    # Target types we can attack
    SEQUENCE_TYPES = {"list", "bytearray"}
    MAPPING_TYPES = {"dict", "set"}
    STDLIB_SEQUENCE_TYPES = {"array", "deque"}  # Require special handling

    def _find_target_variable(self, node: ast.FunctionDef) -> tuple[str, str] | None:
        """
        Scan function body for variables assigned to target types.

        Returns (variable_name, type_name) or None if not found.
        """
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                # Check if RHS is a Call to a builtin collection
                if isinstance(stmt.value, ast.Call):
                    func_node = stmt.value.func

                    # Handle direct calls like list(), dict(), set()
                    if isinstance(func_node, ast.Name):
                        type_name = func_node.id
                        if type_name in self.SEQUENCE_TYPES or type_name in self.MAPPING_TYPES:
                            target_name = (
                                stmt.targets[0].id
                                if isinstance(stmt.targets[0], ast.Name)
                                else None
                            )
                            if target_name:
                                return (target_name, type_name)

                    # Handle attribute calls like array.array(), collections.deque()
                    elif isinstance(func_node, ast.Attribute):
                        attr_name = func_node.attr
                        if attr_name in self.STDLIB_SEQUENCE_TYPES:
                            target_name = (
                                stmt.targets[0].id
                                if isinstance(stmt.targets[0], ast.Name)
                                else None
                            )
                            if target_name:
                                return (target_name, attr_name)

                # Check if RHS is a List, Dict, or Set literal
                if isinstance(stmt.value, (ast.List, ast.Dict, ast.Set)):
                    target_name = (
                        stmt.targets[0].id if isinstance(stmt.targets[0], ast.Name) else None
                    )
                    if target_name:
                        if isinstance(stmt.value, ast.List):
                            return (target_name, "list")
                        elif isinstance(stmt.value, ast.Dict):
                            return (target_name, "dict")
                        elif isinstance(stmt.value, ast.Set):
                            return (target_name, "set")

        return None

    def _create_rug_puller_class(self, var_name: str, type_name: str, prefix: str) -> ast.ClassDef:
        """Create the RugPuller class based on the target type."""
        class_name = f"RugPuller_{prefix}"

        if type_name in self.SEQUENCE_TYPES or type_name in self.STDLIB_SEQUENCE_TYPES:
            # For sequences: implement __index__ that clears and returns 0
            code = dedent(f"""
                class {class_name}:
                    '''Evil object that clears the target during __index__'''
                    def __index__(self):
                        # Rug pull: clear the container while it's being indexed
                        {var_name}.clear()
                        return 0
            """)
        else:  # Mappings/Sets
            # For mappings/sets: implement __hash__ and __eq__ that clear
            code = dedent(f"""
                class {class_name}:
                    '''Evil object that clears the target during __hash__'''
                    def __hash__(self):
                        # Rug pull: clear the container during hashing
                        {var_name}.clear()
                        return 42

                    def __eq__(self, other):
                        return True
            """)

        return cast(ast.ClassDef, ast.parse(code).body[0])

    def _create_trigger_statement(
        self, var_name: str, type_name: str, class_name: str
    ) -> list[ast.stmt]:
        """Create the trigger statement wrapped in try/except."""
        if type_name == "set":
            # For sets, use 'in' operator
            trigger_code = dedent(f"""
                try:
                    _ = {class_name}() in {var_name}
                except (IndexError, KeyError, RuntimeError, ValueError, NameError):
                    pass  # Expected errors from rug pull or insertion before definition
            """)
        else:
            # For sequences and dicts, use [] operator
            trigger_code = dedent(f"""
                try:
                    _ = {var_name}[{class_name}()]
                except (IndexError, KeyError, RuntimeError, ValueError, NameError):
                    pass  # Expected errors from rug pull or insertion before definition
            """)

        return ast.parse(trigger_code).body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.10:  # 10% chance
            # Try to find a target variable
            target_info = self._find_target_variable(node)

            if target_info is None:
                # No suitable variable found, inject one
                var_name = "fuzzer_list"
                type_name = "list"
                # Inject a list variable at the start
                init_code = f"{var_name} = [1, 2, 3, 4, 5]"
                init_node = ast.parse(init_code).body[0]
                node.body.insert(0, init_node)
                print(
                    f"    -> Injecting new list variable '{var_name}' for rug pull attack",
                    file=sys.stderr,
                )
            else:
                var_name, type_name = target_info
                print(
                    f"    -> Targeting existing variable '{var_name}' ({type_name}) for rug pull attack",
                    file=sys.stderr,
                )

            # Create unique prefix
            prefix = f"{random.randint(1000, 9999)}"
            class_name = f"RugPuller_{prefix}"

            # Create the RugPuller class
            rug_puller_class = self._create_rug_puller_class(var_name, type_name, prefix)

            # Create the trigger statement
            trigger_stmts = self._create_trigger_statement(var_name, type_name, class_name)

            # Inject into the function
            injection_point = random.randint(0, len(node.body))
            full_injection = [rug_puller_class] + trigger_stmts
            node.body[injection_point:injection_point] = full_injection
            ast.fix_missing_locations(node)

        return node


class LatticeSurfingMutator(ast.NodeTransformer):
    """
    Attack the JIT's Abstract Interpretation Lattice.

    This mutator exploits CPython JIT's _GUARD_TYPE_VERSION assumptions by
    injecting objects that dynamically flip their __class__ during execution.
    The "Surfer" classes change their type when magic methods are called,
    stress-testing type guards and deoptimization logic.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.1:  # 10% chance
            # Find variables assigned constant integers or booleans
            targets = self._find_constant_assignments(node)

            if not targets:
                return node

            # Limit to 1-2 variables to keep code coherent
            num_to_mutate = min(random.randint(1, 2), len(targets))
            chosen_targets = random.sample(targets, num_to_mutate)

            print(
                f"    -> Injecting Lattice Surfing into {num_to_mutate} variable(s): "
                f"{', '.join(t[0] for t in chosen_targets)}",
                file=sys.stderr,
            )

            # Inject the Surfer classes at the beginning
            surfer_classes = self._create_surfer_classes()
            node.body = surfer_classes + node.body

            # Replace the assignments
            for var_name, value in chosen_targets:
                self._replace_assignment(node, var_name, value)

            ast.fix_missing_locations(node)

        return node

    def _find_constant_assignments(self, node: ast.FunctionDef) -> list[tuple[str, int | bool]]:
        """Find variables assigned constant integers or booleans."""
        targets = []

        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                # Check for simple assignment: x = 42 or flag = True
                if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    var_name = stmt.targets[0].id
                    if isinstance(stmt.value, ast.Constant):
                        val = stmt.value.value
                        if isinstance(val, int):  # bool is subclass of int
                            targets.append((var_name, val))

        return targets

    def _create_surfer_classes(self) -> list[ast.stmt]:
        """Create the _SurferA and _SurferB classes."""
        surfer_code = dedent("""
            class _SurferA:
                def __init__(self, val):
                    self.val = val
                def __bool__(self):
                    self.__class__ = _SurferB  # The Lattice Surf
                    return True
                def __int__(self):
                    self.__class__ = _SurferB
                    return int(self.val)
                def __index__(self):  # For list indexing
                    self.__class__ = _SurferB
                    return int(self.val)
                def __add__(self, other):
                    self.__class__ = _SurferB
                    return self.val + other
                def __radd__(self, other):
                    self.__class__ = _SurferB
                    return other + self.val
                def __sub__(self, other):
                    self.__class__ = _SurferB
                    return self.val - other
                def __rsub__(self, other):
                    self.__class__ = _SurferB
                    return other - self.val
                def __mul__(self, other):
                    self.__class__ = _SurferB
                    return self.val * other
                def __rmul__(self, other):
                    self.__class__ = _SurferB
                    return other * self.val
                def __mod__(self, other):
                    self.__class__ = _SurferB
                    return self.val % other
                def __lt__(self, other):
                    self.__class__ = _SurferB
                    return self.val < other
                def __le__(self, other):
                    self.__class__ = _SurferB
                    return self.val <= other
                def __gt__(self, other):
                    self.__class__ = _SurferB
                    return self.val > other
                def __ge__(self, other):
                    self.__class__ = _SurferB
                    return self.val >= other
                def __eq__(self, other):
                    self.__class__ = _SurferB
                    return self.val == other
                def __ne__(self, other):
                    self.__class__ = _SurferB
                    return self.val != other
                def __hash__(self):
                    self.__class__ = _SurferB
                    return hash(self.val)
                def __repr__(self):
                    self.__class__ = _SurferB
                    return repr(self.val)

            class _SurferB:
                def __init__(self, val):
                    self.val = val
                def __bool__(self):
                    self.__class__ = _SurferA
                    return False
                def __int__(self):
                    self.__class__ = _SurferA
                    return int(self.val)
                def __index__(self):
                    self.__class__ = _SurferA
                    return int(self.val)
                def __add__(self, other):
                    self.__class__ = _SurferA
                    return self.val + other
                def __radd__(self, other):
                    self.__class__ = _SurferA
                    return other + self.val
                def __sub__(self, other):
                    self.__class__ = _SurferA
                    return self.val - other
                def __rsub__(self, other):
                    self.__class__ = _SurferA
                    return other - self.val
                def __mul__(self, other):
                    self.__class__ = _SurferA
                    return self.val * other
                def __rmul__(self, other):
                    self.__class__ = _SurferA
                    return other * self.val
                def __mod__(self, other):
                    self.__class__ = _SurferA
                    return self.val % other
                def __lt__(self, other):
                    self.__class__ = _SurferA
                    return self.val < other
                def __le__(self, other):
                    self.__class__ = _SurferA
                    return self.val <= other
                def __gt__(self, other):
                    self.__class__ = _SurferA
                    return self.val > other
                def __ge__(self, other):
                    self.__class__ = _SurferA
                    return self.val >= other
                def __eq__(self, other):
                    self.__class__ = _SurferA
                    return self.val == other
                def __ne__(self, other):
                    self.__class__ = _SurferA
                    return self.val != other
                def __hash__(self):
                    self.__class__ = _SurferA
                    return hash(self.val)
                def __repr__(self):
                    self.__class__ = _SurferA
                    return repr(self.val)
        """)
        return ast.parse(surfer_code).body

    def _replace_assignment(self, node: ast.FunctionDef, var_name: str, value: int | bool):
        """Replace assignment 'var_name = value' with 'var_name = _SurferA(value)'."""
        for i, stmt in enumerate(node.body):
            if isinstance(stmt, ast.Assign):
                if (
                    len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id == var_name
                ):
                    # Replace with _SurferA(value) call
                    stmt.value = ast.Call(
                        func=ast.Name(id="_SurferA", ctx=ast.Load()),
                        args=[ast.Constant(value=value)],
                        keywords=[],
                    )
                    break


class BloomFilterSaturator(ast.NodeTransformer):
    """
    Attack the JIT's global variable tracking bloom filter.

    This mutator exploits CPython JIT's _GUARD_GLOBALS_VERSION by saturating
    the global modification tracking. The JIT stops watching globals after
    approximately 4096 mutations. We rapidly reach this limit ("Saturate") and
    then modify a watched global to trigger potential stale-cache bugs.

    Enhanced with:
    - Probe-based saturation detection
    - Strategic global modifications when saturated
    - Multi-phase attack patterns
    """

    # Enhanced attack types
    ENHANCED_ATTACKS = [
        "saturation_probe",
        "strategic_global_mod",
        "multi_phase_attack",
    ]

    def __init__(self):
        super().__init__()
        self.module_vars_added = False

    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Inject module-level bloom filter tracking variables."""
        if random.random() < 0.2:  # 20% chance
            print("    -> Injecting bloom filter saturation variables", file=sys.stderr)

            # Inject initialization at the top of the module
            init_code = dedent("""
                _bloom_target = 0
                _bloom_noise_idx = 0
            """)
            init_nodes = ast.parse(init_code).body

            # Prepend to module
            node.body = init_nodes + node.body
            ast.fix_missing_locations(node)

            # Track that we added the module-level variables
            self.module_vars_added = True

        # Now visit children (functions will see module_vars_added = True if it was set)
        self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Inject bloom filter saturation logic into functions."""
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        # Only inject if we added the module-level variables
        if not self.module_vars_added:
            return node

        if random.random() < 0.2:  # 20% chance
            p_prefix = f"bloom_{random.randint(1000, 9999)}"

            # 35% chance to use enhanced attacks
            if random.random() < 0.35:
                attack_type = random.choice(self.ENHANCED_ATTACKS)
                print(
                    f"    -> Injecting enhanced bloom filter attack ({attack_type}) "
                    f"into '{node.name}'",
                    file=sys.stderr,
                )

                if attack_type == "saturation_probe":
                    saturation_nodes = self._create_saturation_probe_attack(p_prefix)
                elif attack_type == "strategic_global_mod":
                    saturation_nodes = self._create_strategic_global_attack(p_prefix)
                else:  # multi_phase_attack
                    saturation_nodes = self._create_multi_phase_attack(p_prefix)

                # Inject at the beginning of the function body
                node.body = saturation_nodes + node.body
                ast.fix_missing_locations(node)
            else:
                # Original attack logic
                print(
                    f"    -> Injecting bloom filter saturation into '{node.name}'",
                    file=sys.stderr,
                )

                # Create the saturate-and-switch code
                saturation_code = dedent("""
                    global _bloom_target, _bloom_noise_idx
                    if _bloom_target % 2 == 0: pass  # Bait: dependency on value

                    # Noise: Thrash the globals dict
                    for _ in range(150):
                        _bloom_noise_idx += 1
                        globals()[f'_bloom_noise_{_bloom_noise_idx}'] = _bloom_noise_idx

                    # Switch: Invalidate the dependency
                    _bloom_target += 1
                """)
                saturation_nodes = ast.parse(saturation_code).body

                # Inject at the beginning of the function body
                node.body = saturation_nodes + node.body
                ast.fix_missing_locations(node)

        return node

    def _create_saturation_probe_attack(self, prefix: str) -> list[ast.stmt]:
        """Probe the bloom filter's state to detect saturation."""
        attack_code = dedent(f"""
            # Bloom filter saturation probe attack
            print('[{prefix}] Probing bloom filter saturation...', file=sys.stderr)

            global _bloom_target, _bloom_noise_idx

            # Phase 1: Warmup - establish baseline behavior
            for warm_{prefix} in range(100):
                if _bloom_target % 2 == 0:
                    pass  # Create dependency

            # Phase 2: Probe for saturation
            # The bloom filter has ~4096 slots. Create probe keys and check behavior.
            saturation_detected_{prefix} = False
            probe_count_{prefix} = 0

            for probe_{prefix} in range(200):
                # Create a unique probe key
                probe_key_{prefix} = f'_bloom_probe_{{probe_{prefix}}}_{{id(object())}}'

                # Check if this "new" key triggers false positive by testing assignment
                try:
                    globals()[probe_key_{prefix}] = probe_{prefix}
                    probe_count_{prefix} += 1

                    # If we've added many probes without JIT issues, filter might be saturated
                    if probe_count_{prefix} > 150:
                        saturation_detected_{prefix} = True
                        print(f'[{prefix}] Bloom filter appears saturated after {{probe_count_{prefix}}} probes', file=sys.stderr)
                        break
                except Exception:
                    pass

            # Phase 3: If saturated, stress test
            if saturation_detected_{prefix}:
                print('[{prefix}] Exploiting saturated bloom filter...', file=sys.stderr)
                # Rapid modifications to stressed filter
                for stress_{prefix} in range(100):
                    _bloom_noise_idx += 1
                    globals()[f'_bloom_saturated_{{stress_{prefix}}}'] = stress_{prefix}
                    # Check target value during stress
                    _ = _bloom_target

            # Switch target value
            _bloom_target += 1
        """)
        return ast.parse(attack_code).body

    def _create_strategic_global_attack(self, prefix: str) -> list[ast.stmt]:
        """Strategically modify globals when filter is stressed."""
        attack_code = dedent(f"""
            # Strategic global modification attack
            print('[{prefix}] Running strategic global modification...', file=sys.stderr)

            global _bloom_target, _bloom_noise_idx

            # Phase 1: Warmup with watched global access
            original_target_{prefix} = _bloom_target
            for warm_{prefix} in range(200):
                _ = _bloom_target  # Access the watched global
                _ = _bloom_noise_idx

            # Phase 2: Saturate the bloom filter
            print('[{prefix}] Saturating bloom filter...', file=sys.stderr)
            for sat_{prefix} in range(500):
                _bloom_noise_idx += 1
                globals()[f'_bloom_strategic_{{sat_{prefix}}}'] = sat_{prefix}

            # Phase 3: Strategic modifications to critical globals
            print('[{prefix}] Modifying critical globals post-saturation...', file=sys.stderr)

            # Modify multiple globals in rapid succession
            critical_globals_{prefix} = ['_bloom_target', '_bloom_noise_idx']
            for crit_{prefix} in critical_globals_{prefix}:
                try:
                    old_val_{prefix} = globals().get(crit_{prefix}, 0)
                    globals()[crit_{prefix}] = old_val_{prefix} + 1
                    # Immediately read back
                    _ = globals()[crit_{prefix}]
                except Exception:
                    pass

            # Phase 4: Add new "important" globals and modify them
            for new_{prefix} in range(50):
                key_{prefix} = f'_critical_global_{{new_{prefix}}}'
                globals()[key_{prefix}] = new_{prefix}
                # Modify immediately
                globals()[key_{prefix}] = new_{prefix} * 2
                # Delete
                try:
                    del globals()[key_{prefix}]
                except KeyError:
                    pass

            # Access target after all modifications
            _ = _bloom_target
        """)
        return ast.parse(attack_code).body

    def _create_multi_phase_attack(self, prefix: str) -> list[ast.stmt]:
        """Multi-phase attack: warmup, saturation, exploitation, verification."""
        attack_code = dedent(f"""
            # Multi-phase bloom filter attack
            print('[{prefix}] Starting multi-phase bloom filter attack...', file=sys.stderr)

            global _bloom_target, _bloom_noise_idx

            # === PHASE 1: WARMUP ===
            print('[{prefix}] Phase 1: Warmup...', file=sys.stderr)
            warmup_result_{prefix} = 0
            for warm_{prefix} in range(300):
                # Establish JIT traces with global access
                if _bloom_target % 2 == 0:
                    warmup_result_{prefix} += 1
                else:
                    warmup_result_{prefix} -= 1
                _ = _bloom_noise_idx

            # === PHASE 2: SATURATION ===
            print('[{prefix}] Phase 2: Saturating...', file=sys.stderr)
            # Create many unique globals rapidly to fill the bloom filter
            for sat_{prefix} in range(1000):
                key_{prefix} = f'_bloom_sat_{{sat_{prefix}}}'
                globals()[key_{prefix}] = sat_{prefix}
                _bloom_noise_idx += 1

            # === PHASE 3: EXPLOITATION ===
            print('[{prefix}] Phase 3: Exploitation...', file=sys.stderr)

            # Store original value
            orig_target_{prefix} = _bloom_target

            # Rapid toggle of the watched global
            for exploit_{prefix} in range(100):
                _bloom_target = exploit_{prefix}
                # Force re-read
                if _bloom_target != exploit_{prefix}:
                    print(f'[{prefix}] Stale read detected!', file=sys.stderr)
                # Add more noise
                globals()[f'_exploit_noise_{{exploit_{prefix}}}'] = exploit_{prefix}

            # === PHASE 4: VERIFICATION ===
            print('[{prefix}] Phase 4: Verification...', file=sys.stderr)

            # Verify we can still read globals correctly
            final_target_{prefix} = _bloom_target
            final_noise_{prefix} = _bloom_noise_idx

            # One more warmup to trigger potential issues
            for verify_{prefix} in range(50):
                _ = _bloom_target
                _ = _bloom_noise_idx
                if _bloom_target % 3 == 0:
                    _bloom_target += 1

            print(f'[{prefix}] Attack complete. Target: {{_bloom_target}}, Noise idx: {{_bloom_noise_idx}}', file=sys.stderr)
        """)
        return ast.parse(attack_code).body


class StackCacheThrasher(ast.NodeTransformer):
    """
    Stress the JIT's Stack Cache and Register Allocator.

    The JIT caches the top 3 stack items in registers. By creating
    right-associative expressions with depth > 3, we force the JIT to emit
    _SPILL and _RELOAD instructions, testing stack pointer consistency.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.3:  # 30% chance
            print(
                f"    -> Injecting stack cache thrashing into '{node.name}'",
                file=sys.stderr,
            )

            # Step A: Initialize 8 local variables
            init_stmts = []
            for i in range(8):
                var_name = f"_st_{i}"
                assign = ast.Assign(
                    targets=[ast.Name(id=var_name, ctx=ast.Store())],
                    value=ast.Constant(value=i),
                )
                init_stmts.append(assign)

            # Step B: Create right-associative expression
            # _ = _st_0 + (_st_1 - (_st_2 * (_st_3 | (_st_4 & (_st_5 ^ (_st_6 + _st_7))))))

            # Build from innermost to outermost
            # Level 7 (innermost): _st_6 + _st_7
            expr = ast.BinOp(
                left=ast.Name(id="_st_6", ctx=ast.Load()),
                op=ast.Add(),
                right=ast.Name(id="_st_7", ctx=ast.Load()),
            )

            # Level 6: _st_5 ^ (...)
            expr = ast.BinOp(
                left=ast.Name(id="_st_5", ctx=ast.Load()),
                op=ast.BitXor(),
                right=expr,
            )

            # Level 5: _st_4 & (...)
            expr = ast.BinOp(
                left=ast.Name(id="_st_4", ctx=ast.Load()),
                op=ast.BitAnd(),
                right=expr,
            )

            # Level 4: _st_3 | (...)
            expr = ast.BinOp(
                left=ast.Name(id="_st_3", ctx=ast.Load()),
                op=ast.BitOr(),
                right=expr,
            )

            # Level 3: _st_2 * (...)
            expr = ast.BinOp(
                left=ast.Name(id="_st_2", ctx=ast.Load()),
                op=ast.Mult(),
                right=expr,
            )

            # Level 2: _st_1 - (...)
            expr = ast.BinOp(
                left=ast.Name(id="_st_1", ctx=ast.Load()),
                op=ast.Sub(),
                right=expr,
            )

            # Level 1 (outermost): _st_0 + (...)
            expr = ast.BinOp(
                left=ast.Name(id="_st_0", ctx=ast.Load()),
                op=ast.Add(),
                right=expr,
            )

            # Assign to _ (throwaway)
            thrash_stmt = ast.Assign(
                targets=[ast.Name(id="_", ctx=ast.Store())],
                value=expr,
            )

            # Inject: initializations at the beginning, thrashing statement in the middle/end
            injection_point = len(node.body) // 2 if len(node.body) > 1 else len(node.body)
            node.body = (
                init_stmts
                + node.body[:injection_point]
                + [thrash_stmt]
                + node.body[injection_point:]
            )

            ast.fix_missing_locations(node)

        return node


class BoundaryComparisonMutator(ast.NodeTransformer):
    """
    Stress the JIT's platform-specific assembly optimizers.

    The JIT's assembly optimizers (Tools/jit/_optimizers.py) rewrite branch
    instructions. By generating edge-case comparisons (NaNs, signed zeros),
    we force CPU flags into unusual states (like Parity Flag set) that might
    be mishandled by incorrect branch inversion logic.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.2:  # 20% chance
            print(
                f"    -> Injecting boundary comparisons into '{node.name}'",
                file=sys.stderr,
            )

            # Step A: Initialize edge-case floats
            init_stmts = [
                # NaN value
                ast.Assign(
                    targets=[ast.Name(id="_bnd_nan", ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Name(id="float", ctx=ast.Load()),
                        args=[ast.Constant(value="nan")],
                        keywords=[],
                    ),
                ),
                # Infinity
                ast.Assign(
                    targets=[ast.Name(id="_bnd_inf", ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Name(id="float", ctx=ast.Load()),
                        args=[ast.Constant(value="inf")],
                        keywords=[],
                    ),
                ),
                # Negative zero
                ast.Assign(
                    targets=[ast.Name(id="_bnd_nzero", ctx=ast.Store())],
                    value=ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=0.0)),
                ),
                # Positive zero
                ast.Assign(
                    targets=[ast.Name(id="_bnd_zero", ctx=ast.Store())],
                    value=ast.Constant(value=0.0),
                ),
                # Dummy counter
                ast.Assign(
                    targets=[ast.Name(id="_bnd_dummy", ctx=ast.Store())],
                    value=ast.Constant(value=0),
                ),
            ]

            # Step B: Create comparison blocks
            comparison_stmts = []

            # Comparison operators to test
            operators = [
                ast.Eq(),  # ==
                ast.NotEq(),  # !=
                ast.Lt(),  # <
                ast.Gt(),  # >
            ]

            # Combinations to test
            combinations = [
                ("_bnd_nan", "_bnd_nan"),  # NaN vs NaN
                ("_bnd_nan", "_bnd_inf"),  # NaN vs Inf
                ("_bnd_zero", "_bnd_nzero"),  # 0.0 vs -0.0
            ]

            # Generate If statements for each operator/combination pair
            for op in operators:
                for left_var, right_var in combinations:
                    # Create comparison: if left_var op right_var:
                    if_stmt = ast.If(
                        test=ast.Compare(
                            left=ast.Name(id=left_var, ctx=ast.Load()),
                            ops=[op],
                            comparators=[ast.Name(id=right_var, ctx=ast.Load())],
                        ),
                        body=[
                            # _bnd_dummy += 1
                            ast.AugAssign(
                                target=ast.Name(id="_bnd_dummy", ctx=ast.Store()),
                                op=ast.Add(),
                                value=ast.Constant(value=1),
                            )
                        ],
                        orelse=[],
                    )
                    comparison_stmts.append(if_stmt)

            # Inject: initializations + comparisons in the middle of function
            injection_point = len(node.body) // 2 if len(node.body) > 1 else len(node.body)
            node.body = (
                init_stmts
                + node.body[:injection_point]
                + comparison_stmts
                + node.body[injection_point:]
            )

            ast.fix_missing_locations(node)

        return node


class AbstractInterpreterConfusionMutator(ast.NodeTransformer):
    """
    Stress-test the JIT's specialized micro-ops with exception-raising indices.

    The JIT has specialized micro-ops like _BINARY_OP_SUBSCR_LIST_INT that expect
    simple index operations. By wrapping indices with _ChameleonInt (an int subclass
    that can raise exceptions during __index__() or __hash__()), we verify that the
    JIT correctly handles exceptions from within index conversion and unwinds properly.
    """

    def __init__(self):
        super().__init__()
        self.chameleon_class_injected = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        if not node.name.startswith("uop_harness"):
            return node

        # Inject the _ChameleonInt class at the top of the function
        chameleon_class_code = dedent("""
            class _ChameleonInt(int):
                def __index__(self):
                    # 10% chance to fail
                    if (self % 10) == 7:
                        raise ValueError("Chameleon Fail")
                    return int(self)
                def __hash__(self):
                    # 10% chance to fail
                    if (self % 10) == 8:
                        raise TypeError("Chameleon Hash Fail")
                    return super().__hash__()
        """)

        chameleon_class = ast.parse(chameleon_class_code).body
        self.chameleon_class_injected = True

        print(
            f"    -> Injecting _ChameleonInt into '{node.name}'",
            file=sys.stderr,
        )

        # Prepend the class definition
        node.body = chameleon_class + node.body

        # Now visit the rest of the function to modify subscripts
        self.generic_visit(node)

        ast.fix_missing_locations(node)
        return node

    def visit_Subscript(self, node: ast.Subscript) -> ast.Subscript:
        # Only modify if we've injected the chameleon class
        if not self.chameleon_class_injected:
            return node

        # Only wrap simple indices (Constant or Name)
        if isinstance(node.slice, (ast.Constant, ast.Name)):
            # 30% chance to wrap
            if random.random() < 0.3:
                # Wrap the index with _ChameleonInt(index)
                node.slice = ast.Call(
                    func=ast.Name(id="_ChameleonInt", ctx=ast.Load()),
                    args=[node.slice],
                    keywords=[],
                )

        return node


class GlobalOptimizationInvalidator(ast.NodeTransformer):
    """
    Attack the JIT's global-to-constant promotion optimization.

    The JIT often optimizes global variables (like `range`) into hardcoded
    pointers if they don't change. This mutator attacks that assumption
    through three vectors:

    1. evil_global_swap: Train the JIT to trust a global, then swap it
       for a different object inside a hot loop, forcing deoptimization.
    2. namespace_swap: Use types.FunctionType(func.__code__, alt_globals)
       to execute JIT-compiled code with entirely different globals (GH-138378).
    3. globals_dict_mutate: Directly mutate func.__globals__ in-place after
       JIT warmup, potentially corrupting cached dict pointers.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.2:  # 20% chance
            p_prefix = f"goi_{random.randint(1000, 9999)}"
            attack = random.choice(
                [
                    "evil_global_swap",
                    "namespace_swap",
                    "globals_dict_mutate",
                ]
            )

            print(
                f"    -> Injecting global optimization invalidation ({attack}) "
                f"with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            if attack == "evil_global_swap":
                scenario_ast = self._create_evil_global_swap(p_prefix)
            elif attack == "namespace_swap":
                scenario_ast = self._create_namespace_swap(p_prefix)
            else:  # globals_dict_mutate
                scenario_ast = self._create_globals_dict_mutate(p_prefix)

            if scenario_ast:
                # Inject at the middle of the function body
                injection_point = len(node.body) // 2 if len(node.body) > 1 else len(node.body)
                node.body = node.body[:injection_point] + scenario_ast + node.body[injection_point:]
                ast.fix_missing_locations(node)

        return node

    def _create_evil_global_swap(self, p_prefix: str) -> list[ast.stmt]:
        """
        Original attack: train JIT on a global, swap it for _EvilGlobal mid-loop.
        """
        evil_class_code = dedent(f"""
            class _EvilGlobal_{p_prefix}:
                def __init__(self, *args): pass
                def __call__(self, *args): return 42
        """)

        invalidation_code = dedent(f"""
            global _jit_target_{p_prefix}
            _jit_target_{p_prefix} = range
            try:
                for _jit_i_{p_prefix} in range(2000):
                    _jit_x_{p_prefix} = _jit_target_{p_prefix}(1)
                    if _jit_i_{p_prefix} == 1000:
                        globals()['_jit_target_{p_prefix}'] = _EvilGlobal_{p_prefix}()
            except (TypeError, ValueError, AttributeError):
                pass
            finally:
                globals()['_jit_target_{p_prefix}'] = range
        """)

        try:
            return ast.parse(evil_class_code).body + ast.parse(invalidation_code).body
        except SyntaxError:
            return []

    def _create_namespace_swap(self, p_prefix: str) -> list[ast.stmt]:
        """
        Execute JIT-compiled code with a completely different globals dict.

        Creates a function, warms it in a hot loop so the JIT compiles it,
        then uses types.FunctionType(func.__code__, alt_globals) to execute
        the same code object with different global variable types.
        This forces the JIT to deoptimize or crash when its cached
        global-to-constant promotions become invalid (GH-138378).
        """
        code = dedent(f"""
            import types as _types_{p_prefix}

            # Define a function that uses globals heavily
            _goi_multiplier_{p_prefix} = 3
            _goi_offset_{p_prefix} = 10

            def _goi_victim_{p_prefix}(x):
                # JIT will promote _goi_multiplier and _goi_offset to constants
                return x * _goi_multiplier_{p_prefix} + _goi_offset_{p_prefix}

            # Phase 1: Warm up — JIT traces and promotes globals to constants
            try:
                for _goi_i_{p_prefix} in range(2000):
                    _goi_victim_{p_prefix}(_goi_i_{p_prefix})
            except Exception:
                pass

            # Phase 2: Create alternate globals with different types
            _alt_globals_{p_prefix} = {{
                '__builtins__': __builtins__,
                '_goi_multiplier_{p_prefix}': "not_an_int",  # str instead of int
                '_goi_offset_{p_prefix}': [1, 2, 3],  # list instead of int
            }}

            # Phase 3: Execute same code object with swapped namespace
            try:
                _goi_swapped_{p_prefix} = _types_{p_prefix}.FunctionType(
                    _goi_victim_{p_prefix}.__code__,
                    _alt_globals_{p_prefix},
                    '_goi_victim_{p_prefix}_swapped',
                )
                for _goi_j_{p_prefix} in range(500):
                    _goi_swapped_{p_prefix}(_goi_j_{p_prefix})
            except Exception:
                pass

            # Phase 4: Go back to original — JIT may have stale trace
            try:
                for _goi_k_{p_prefix} in range(500):
                    _goi_victim_{p_prefix}(_goi_k_{p_prefix})
            except Exception:
                pass
        """)
        try:
            return ast.parse(code).body
        except SyntaxError:
            return []

    def _create_globals_dict_mutate(self, p_prefix: str) -> list[ast.stmt]:
        """
        Directly mutate a function's __globals__ dict after JIT warmup.

        Unlike namespace_swap (which creates a new function object), this
        modifies the globals dict in-place. The JIT may have cached pointers
        into the dict's internal storage, so mutation can corrupt those pointers.
        """
        code = dedent(f"""
            _goi_scale_{p_prefix} = 5

            def _goi_target_{p_prefix}(x):
                return x * _goi_scale_{p_prefix}

            # Phase 1: Warm up
            try:
                for _goi_i_{p_prefix} in range(2000):
                    _goi_target_{p_prefix}(_goi_i_{p_prefix})
            except Exception:
                pass

            # Phase 2: Mutate the function's own __globals__ in-place
            try:
                _goi_target_{p_prefix}.__globals__['_goi_scale_{p_prefix}'] = "type_changed"
                for _goi_j_{p_prefix} in range(500):
                    _goi_target_{p_prefix}(_goi_j_{p_prefix})
            except Exception:
                pass

            # Phase 3: Restore and call again
            try:
                _goi_target_{p_prefix}.__globals__['_goi_scale_{p_prefix}'] = 5
                for _goi_k_{p_prefix} in range(500):
                    _goi_target_{p_prefix}(_goi_k_{p_prefix})
            except Exception:
                pass
        """)
        try:
            return ast.parse(code).body
        except SyntaxError:
            return []


class CodeObjectHotSwapper(ast.NodeTransformer):
    """
    Target the _RETURN_GENERATOR opcode and JIT deoptimization.

    We compile a hot path that creates generators, then swap the underlying
    __code__ object of the function, and try to create the generator again.
    This tests if the JIT holds onto stale Code Objects.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.2:  # 20% chance
            print(
                f"    -> Injecting code object hot swap into '{node.name}'",
                file=sys.stderr,
            )

            # Step 1: Inject the generator functions
            generators_code = dedent("""
                def _gen_A():
                    yield 1
                    yield 2

                def _gen_B():
                    yield 100
                    yield 200
                    yield 300
            """)
            generators = ast.parse(generators_code).body

            # Step 2: Build the warmup, swap, and trigger
            swap_code = dedent("""
                # Warmup: Create generators in a hot loop
                for _swap_i in range(1000):
                    _swap_g = _gen_A()
                    next(_swap_g)

                # The Swap: Replace code object mid-execution
                try:
                    _gen_A.__code__ = _gen_B.__code__

                    # The Trigger: Create generator with swapped code
                    _swap_g = _gen_A()
                    _swap_result = next(_swap_g)  # Should yield 100, not 1
                except (ValueError, TypeError, AttributeError):
                    # Swapping code objects can raise errors if closures differ
                    pass
            """)
            swap_logic = ast.parse(swap_code).body

            # Inject at the middle of the function body
            injection_point = len(node.body) // 2 if len(node.body) > 1 else len(node.body)
            node.body = (
                generators + node.body[:injection_point] + swap_logic + node.body[injection_point:]
            )

            ast.fix_missing_locations(node)

        return node


class TypeShadowingMutator(ast.NodeTransformer):
    """
    Attack the _GUARD_TYPE_VERSION optimization via frame local manipulation.

    We train the JIT on a float variable, then use sys._getframe().f_locals
    to change its type behind the scenes (bypassing standard bytecodes),
    and immediately trigger the type-specialized operation again. This tests
    if the JIT correctly guards against type changes via f_locals writes.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.2:  # 20% chance
            p_prefix = f"shadow_{random.randint(1000, 9999)}"
            print(
                f"    -> Injecting type shadowing attack with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            # Build the type shadowing scenario
            shadow_code = dedent(f"""
                # Import sys locally to ensure availability
                _shadow_sys_{p_prefix} = __import__('sys')

                # Setup: Initialize as float for JIT specialization
                _shadow_x_{p_prefix} = 3.14

                for _shadow_i_{p_prefix} in range(2000):
                    # 1. Train the JIT: x is a float
                    _shadow_tmp_{p_prefix} = _shadow_x_{p_prefix} + 1.0

                    # 2. The Attack: Swap type via f_locals (bypasses bytecodes)
                    if _shadow_i_{p_prefix} == 1500:
                        _shadow_sys_{p_prefix}._getframe().f_locals['_shadow_x_{p_prefix}'] = "EVIL_STRING"

                    # 3. The Trigger: Execute specialized operation again
                    # If JIT doesn't see the f_locals write, it might run float_add on string
                    try:
                        _shadow_tmp_{p_prefix} = _shadow_x_{p_prefix} + 1.0
                    except TypeError:
                        # Catch successful deopt/error, restore for next iterations
                        _shadow_x_{p_prefix} = 3.14
            """)
            shadow_logic = ast.parse(shadow_code).body

            # Inject at the middle of the function body
            injection_point = len(node.body) // 2 if len(node.body) > 1 else len(node.body)
            node.body = node.body[:injection_point] + shadow_logic + node.body[injection_point:]

            ast.fix_missing_locations(node)

        return node


class ZombieTraceMutator(ast.NodeTransformer):
    """
    Stress the JIT's executor lifecycle management (pycore_optimizer.h).

    We rapidly create and destroy JIT traces by defining hot functions in a loop,
    calling them to trigger Tier 2 compilation, then letting them go out of scope.
    This targets potential bugs in the pending_deletion linked list logic for
    _PyExecutorObject cleanup.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.2:  # 20% chance
            p_prefix = f"zombie_{random.randint(1000, 9999)}"
            print(
                f"    -> Injecting zombie trace churn with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            # Define the zombie churn helper function
            churn_code = dedent(f"""
                def _zombie_churn_{p_prefix}():
                    # Loop to rapidly create and destroy JIT state
                    for _zombie_iter_{p_prefix} in range(50):
                        # Define a victim function with a hot loop
                        def _zombie_victim_{p_prefix}():
                            _zombie_x_{p_prefix} = 0
                            for _zombie_i_{p_prefix} in range(1000):
                                _zombie_x_{p_prefix} += 1
                            return _zombie_x_{p_prefix}

                        # Call it to trigger JIT compilation
                        _zombie_victim_{p_prefix}()
                        # _zombie_victim goes out of scope; Executor marked pending_deletion
            """)
            churn_func = ast.parse(churn_code).body

            # Call the churn function
            call_code = f"_zombie_churn_{p_prefix}()"
            call_stmt = ast.parse(call_code).body

            # Inject: churn function definition + call at start of function body
            node.body = churn_func + call_stmt + node.body

            ast.fix_missing_locations(node)

        return node


class UnpackingChaosMutator(ast.NodeTransformer):
    """
    Attack JIT optimizations for UNPACK_SEQUENCE and UNPACK_EX operations.

    The JIT specializes unpacking based on observed iterator behavior during tracing.
    This mutator wraps iterables in a chaotic iterator that changes behavior after
    JIT warmup:
    - 'grow' mode: yields extra items after trigger_count iterations
    - 'shrink' mode: stops iteration early after trigger_count iterations
    - 'type_switch' mode: yields a different type after trigger_count iterations

    The iterator also lies about its length via __length_hint__ to confuse
    pre-allocation optimizations.
    """

    HELPER_CLASS_NAME = "_JitChaosIterator"

    def __init__(self):
        super().__init__()
        self.helper_injected = False

    def _create_chaos_iterator_class(self) -> ast.ClassDef:
        """Create the _JitChaosIterator helper class AST."""
        class_code = dedent(f"""
            class {self.HELPER_CLASS_NAME}:
                '''Iterator that changes behavior after trigger_count iterations.'''
                def __init__(self, iterable, mode='grow', trigger_count=50):
                    self._items = list(iterable)
                    self._mode = mode
                    self._trigger_count = trigger_count
                    self._call_count = 0
                    self._index = 0

                def __iter__(self):
                    self._call_count += 1
                    self._index = 0
                    return self

                def __next__(self):
                    triggered = self._call_count > self._trigger_count

                    if self._index >= len(self._items):
                        # After exhausting items, maybe yield extra in 'grow' mode
                        if triggered and self._mode == 'grow' and self._index == len(self._items):
                            self._index += 1
                            return None  # Extra unexpected item
                        raise StopIteration

                    # In 'shrink' mode, stop early after trigger
                    if triggered and self._mode == 'shrink' and self._index >= len(self._items) // 2:
                        raise StopIteration

                    item = self._items[self._index]
                    self._index += 1

                    # In 'type_switch' mode, return wrong type after trigger
                    if triggered and self._mode == 'type_switch' and self._index == len(self._items):
                        return "unexpected_string_type"

                    return item

                def __length_hint__(self):
                    # Lie about length to confuse pre-allocation
                    if self._call_count > self._trigger_count:
                        return max(0, len(self._items) - 1)  # Underreport
                    return len(self._items) + 1  # Overreport initially
        """)
        return cast(ast.ClassDef, ast.parse(class_code).body[0])

    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Inject the helper class at module level if needed."""
        # Check if helper already exists
        for stmt in node.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == self.HELPER_CLASS_NAME:
                self.helper_injected = True
                break

        # Inject helper class at module level with low probability
        if not self.helper_injected and random.random() < 0.15:
            print(
                f"    -> Injecting {self.HELPER_CLASS_NAME} helper class",
                file=sys.stderr,
            )
            helper_class = self._create_chaos_iterator_class()
            node.body.insert(0, helper_class)
            self.helper_injected = True
            ast.fix_missing_locations(node)

        # Continue visiting children
        self.generic_visit(node)
        return node

    def _wrap_in_chaos_iterator(self, value_node: ast.expr) -> ast.Call:
        """Wrap a value node in _JitChaosIterator call."""
        mode = random.choice(["grow", "shrink", "type_switch"])
        trigger = random.randint(30, 100)

        return ast.Call(
            func=ast.Name(id=self.HELPER_CLASS_NAME, ctx=ast.Load()),
            args=[value_node],
            keywords=[
                ast.keyword(arg="mode", value=ast.Constant(value=mode)),
                ast.keyword(arg="trigger_count", value=ast.Constant(value=trigger)),
            ],
        )

    def _is_unpacking_target(self, target: ast.expr) -> bool:
        """Check if target is a tuple/list unpacking pattern."""
        return isinstance(target, (ast.Tuple, ast.List))

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        """Transform unpacking assignments: a, b = iterable -> a, b = _JitChaosIterator(iterable)."""
        if not self.helper_injected:
            return node

        # Check if any target is an unpacking pattern
        has_unpacking = any(self._is_unpacking_target(t) for t in node.targets)

        if has_unpacking and random.random() < 0.2:
            print(
                "    -> Wrapping unpacking assignment with chaos iterator",
                file=sys.stderr,
            )
            node.value = self._wrap_in_chaos_iterator(node.value)
            ast.fix_missing_locations(node)

        return node

    def visit_For(self, node: ast.For) -> ast.For:
        """Transform for loop unpacking: for a, b in seq -> for a, b in _JitChaosIterator(seq)."""
        self.generic_visit(node)

        if not self.helper_injected:
            return node

        # Check if target is an unpacking pattern (for x, y in ...)
        if self._is_unpacking_target(node.target) and random.random() < 0.2:
            print(
                "    -> Wrapping for loop iterator with chaos iterator",
                file=sys.stderr,
            )
            node.iter = self._wrap_in_chaos_iterator(node.iter)
            ast.fix_missing_locations(node)

        return node


class ConstantNarrowingPoisonMutator(ast.NodeTransformer):
    """
    Attack the JIT's constant narrowing optimization.

    After `if v == 1:`, the optimizer narrows `v` to the constant `1`
    and folds subsequent operations. This mutator creates scenarios where
    the narrowing assumption is violated.

    Attack vectors:
    1. lying_eq: Custom __eq__ that returns True for non-matching values,
       tricking the optimizer into narrowing to a wrong constant.
    2. int_subclass_extra_state: Int subclass where `x == 1` is True
       (inherited __eq__), but `x` has additional attributes the optimizer
       doesn't track.
    3. float_nan_paradox: Exploit NaN != NaN. The `!=` comparison's
       else-branch implies equality, but NaN is never equal to itself.
    4. str_identity_vs_equality: Exploit interning differences.
       `v == "hello"` can succeed for non-interned copies, but the
       optimizer may assume identity (same pointer).
    5. mutable_constant: Objects that compare equal to a constant but
       mutate between the comparison and the folded operation.
    6. hash_collision_confusion: Objects with __hash__/__eq__ that make
       dict lookups believe they're a constant when they're not.
    """

    ATTACK_SCENARIOS = [
        "lying_eq",
        "int_subclass_extra_state",
        "float_nan_paradox",
        "str_identity_vs_equality",
        "mutable_constant",
        "hash_collision_confusion",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.12:  # 12% chance
            attack = random.choice(self.ATTACK_SCENARIOS)
            p_prefix = f"cnarrow_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting constant narrowing poison ({attack}) with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            scenario_ast = getattr(self, f"_create_{attack}")(p_prefix)

            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_lying_eq(self, prefix: str) -> list[ast.stmt]:
        """
        Custom __eq__ that returns True for non-matching values.

        The optimizer sees `v == 1` return True and narrows v to constant 1.
        But v is actually a LyingInt with value 999. Subsequent operations
        folded under the assumption v==1 produce wrong results.
        """
        code = dedent(f"""
            class _LyingInt_{prefix}:
                def __init__(self, real_val):
                    self.real_val = real_val

                def __eq__(self, other):
                    # Always claim equality with small ints
                    if isinstance(other, int) and -5 <= other <= 256:
                        return True
                    return self.real_val == other

                def __hash__(self):
                    return hash(1)  # Consistent with lying __eq__

                def __add__(self, other):
                    return self.real_val + other

                def __radd__(self, other):
                    return other + self.real_val

                def __mul__(self, other):
                    return self.real_val * other

                def __bool__(self):
                    return bool(self.real_val)

            def _get_val_{prefix}():
                return _LyingInt_{prefix}(999)

            # Phase 1: Warm up — JIT traces comparison, narrows to constant 1
            _v_{prefix} = _get_val_{prefix}()
            _hits_{prefix} = 0
            for _i_{prefix} in range(200):
                if _v_{prefix} == 1:
                    # Optimizer thinks v is 1, folds v + 1 to 2
                    # But v.real_val is 999, so v + 1 should be 1000
                    _hits_{prefix} += _v_{prefix} + 1

            # Phase 2: Vary the comparison constant
            for _c_{prefix} in [0, 1, 2, 42, 100, 255, 256]:
                _v2_{prefix} = _get_val_{prefix}()
                try:
                    for _j_{prefix} in range(100):
                        if _v2_{prefix} == _c_{prefix}:
                            _ = _v2_{prefix} + _c_{prefix}
                            _ = _v2_{prefix} * 2
                except TypeError:
                    pass

            # Phase 3: Chain narrowing — nested comparisons
            _v3_{prefix} = _get_val_{prefix}()
            for _k_{prefix} in range(200):
                if _v3_{prefix} == 1:
                    if _v3_{prefix} == 1:
                        # Double narrowing — optimizer may fold both
                        try:
                            _ = _v3_{prefix} + _v3_{prefix}
                        except TypeError:
                            pass
        """)
        return ast.parse(code).body

    def _create_int_subclass_extra_state(self, prefix: str) -> list[ast.stmt]:
        """
        Int subclass that compares equal to constants but has extra state.

        x == 1 is True (inherited from int), but x carries additional
        attributes. The optimizer narrows to constant 1, losing the extra
        state. Operations that depend on the extra state break.
        """
        code = dedent(f"""
            class _RichInt_{prefix}(int):
                def __new__(cls, val, tag="default"):
                    obj = super().__new__(cls, val)
                    obj.tag = tag
                    obj.access_count = 0
                    return obj

                def __add__(self, other):
                    self.access_count += 1
                    result = super().__add__(other)
                    if isinstance(result, int) and not isinstance(result, _RichInt_{prefix}):
                        return _RichInt_{prefix}(result, self.tag)
                    return result

                def __mul__(self, other):
                    self.access_count += 1
                    return _RichInt_{prefix}(super().__mul__(other), self.tag)

            def _get_rich_{prefix}():
                return _RichInt_{prefix}(1, "secret")

            # Phase 1: Warm up — optimizer narrows to constant 1
            _rv_{prefix} = _get_rich_{prefix}()
            _total_{prefix} = 0
            for _i_{prefix} in range(200):
                if _rv_{prefix} == 1:
                    # Optimizer thinks rv is constant 1, may fold rv + 1 = 2
                    # But rv is _RichInt with tag and access_count
                    _total_{prefix} = _rv_{prefix} + 1

            # Phase 2: Test that extra state survives narrowing
            _rv2_{prefix} = _get_rich_{prefix}()
            for _j_{prefix} in range(200):
                if _rv2_{prefix} == 1:
                    _ = _rv2_{prefix} * 2
                    # After narrowing, does the result still have .tag?
                    try:
                        _result_{prefix} = _rv2_{prefix} + _j_{prefix}
                        _t_{prefix} = _result_{prefix}.tag  # Would fail if folded to plain int
                    except AttributeError:
                        pass

            # Phase 3: != narrowing path
            _rv3_{prefix} = _get_rich_{prefix}()
            for _k_{prefix} in range(200):
                if _rv3_{prefix} != 1:
                    pass  # Should never enter — int value IS 1
                else:
                    # Optimizer narrows to constant 1 in else branch
                    try:
                        _ = _rv3_{prefix} + _rv3_{prefix}
                    except TypeError:
                        pass
        """)
        return ast.parse(code).body

    def _create_float_nan_paradox(self, prefix: str) -> list[ast.stmt]:
        """
        Exploit NaN != NaN paradox in constant narrowing.

        After `if v != NaN:`, the else-branch implies v == NaN, so the
        optimizer may narrow v to NaN. But NaN is never equal to itself,
        so the else branch is unreachable — the optimizer might still
        reason about it. Also test: `if v == float('inf'):`.
        """
        code = dedent(f"""
            _nan_{prefix} = float('nan')
            _inf_{prefix} = float('inf')
            _neginf_{prefix} = float('-inf')

            def _get_nan_{prefix}():
                return float('nan')

            def _get_special_{prefix}(i):
                # Return different special floats to confuse narrowing
                if i % 4 == 0:
                    return float('nan')
                elif i % 4 == 1:
                    return float('inf')
                elif i % 4 == 2:
                    return float('-inf')
                else:
                    return 0.0

            # Phase 1: NaN equality — always False, but optimizer may still narrow
            _vn_{prefix} = _get_nan_{prefix}()
            _hits_{prefix} = 0
            for _i_{prefix} in range(200):
                if _vn_{prefix} == _nan_{prefix}:
                    # Unreachable for NaN, but optimizer may fold here
                    _hits_{prefix} += _vn_{prefix} + 1.0

            # Phase 2: NaN inequality — always True
            for _j_{prefix} in range(200):
                if _vn_{prefix} != _nan_{prefix}:
                    # Always taken. v is still NaN though.
                    try:
                        _ = _vn_{prefix} + 1.0  # NaN + 1.0 = NaN
                        _ = _vn_{prefix} == _vn_{prefix}  # NaN == NaN is False
                    except TypeError:
                        pass
                else:
                    # Optimizer might narrow v to _nan here (else of !=)
                    try:
                        _ = _vn_{prefix} * 2.0
                    except TypeError:
                        pass

            # Phase 3: Inf equality — v == inf, then use in comparisons
            _vi_{prefix} = _inf_{prefix}
            for _k_{prefix} in range(200):
                if _vi_{prefix} == _inf_{prefix}:
                    # Optimizer narrows to inf constant
                    # inf + 1 = inf, inf * 0 = nan — edge cases
                    _ = _vi_{prefix} + 1.0
                    _ = _vi_{prefix} * 0.0  # Should be NaN, not 0

            # Phase 4: -0.0 vs 0.0 — equal by ==, different by identity
            _z1_{prefix} = 0.0
            _z2_{prefix} = -0.0
            for _m_{prefix} in range(200):
                if _z1_{prefix} == _z2_{prefix}:
                    # True: 0.0 == -0.0
                    # But copysign(1, 0.0) != copysign(1, -0.0)
                    import math
                    try:
                        _ = math.copysign(1, _z1_{prefix})  # 1.0
                        _ = math.copysign(1, _z2_{prefix})  # -1.0
                    except (TypeError, ValueError):
                        pass
        """)
        return ast.parse(code).body

    def _create_str_identity_vs_equality(self, prefix: str) -> list[ast.stmt]:
        """
        Exploit string interning differences in constant narrowing.

        `v == "hello"` succeeds for both interned and non-interned copies.
        The optimizer may assume identity (same pointer) after narrowing,
        which would be wrong for non-interned strings.
        """
        code = dedent(f"""
            def _make_noninterned_{prefix}(s):
                # Force a non-interned copy
                return "".join(list(s))

            def _get_hello_{prefix}():
                return _make_noninterned_{prefix}("hello")

            # Phase 1: Warm up — optimizer narrows v to "hello" constant
            _sv_{prefix} = _get_hello_{prefix}()
            _count_{prefix} = 0
            for _i_{prefix} in range(200):
                if _sv_{prefix} == "hello":
                    # Optimizer may assume v IS the interned "hello"
                    # But it's a different object (non-interned)
                    _count_{prefix} += 1
                    _ = _sv_{prefix} + " world"

            # Phase 2: Test with string subclass
            class _RichStr_{prefix}(str):
                def __new__(cls, val, tag="default"):
                    obj = super().__new__(cls, val)
                    obj.tag = tag
                    return obj

            _rs_{prefix} = _RichStr_{prefix}("hello", "secret")
            for _j_{prefix} in range(200):
                if _rs_{prefix} == "hello":
                    # True (inherited __eq__), but rs has extra .tag
                    try:
                        _ = _rs_{prefix} + " world"
                        _ = _rs_{prefix}.tag
                    except AttributeError:
                        pass

            # Phase 3: != path with non-interned strings
            _sv2_{prefix} = _get_hello_{prefix}()
            for _k_{prefix} in range(200):
                if _sv2_{prefix} != "hello":
                    pass  # Should never enter
                else:
                    _ = _sv2_{prefix} + " post_narrow"
        """)
        return ast.parse(code).body

    def _create_mutable_constant(self, prefix: str) -> list[ast.stmt]:
        """
        Objects that compare equal to a constant but mutate between
        comparison and the folded operation.

        The optimizer narrows v to constant after comparison. Between
        the narrowing point and the folded operation, a side effect
        changes v's actual value.
        """
        code = dedent(f"""
            class _Shifty_{prefix}:
                '''Value that changes every time it's compared.'''
                def __init__(self, val):
                    self._val = val
                    self._cmp_count = 0

                def __eq__(self, other):
                    self._cmp_count += 1
                    result = self._val == other
                    # After comparison, shift the value
                    if self._cmp_count % 3 == 0:
                        self._val = self._val + 1 if isinstance(self._val, int) else self._val
                    return result

                def __hash__(self):
                    return hash(self._val)

                def __add__(self, other):
                    return self._val + other

                def __mul__(self, other):
                    return self._val * other

                def __bool__(self):
                    return bool(self._val)

            def _get_shifty_{prefix}():
                return _Shifty_{prefix}(1)

            # Phase 1: Comparison where value shifts between check and use
            _sh_{prefix} = _get_shifty_{prefix}()
            _total_{prefix} = 0
            for _i_{prefix} in range(300):
                if _sh_{prefix} == 1:
                    # After ==, optimizer narrows to 1
                    # But _Shifty may have shifted _val to 2
                    _total_{prefix} += _sh_{prefix} + 1

            # Phase 2: Double comparison — first narrows, second may see shifted value
            _sh2_{prefix} = _get_shifty_{prefix}()
            for _j_{prefix} in range(200):
                if _sh2_{prefix} == 1:
                    if _sh2_{prefix} == 1:
                        # Second comparison's __eq__ shifts value again
                        _ = _sh2_{prefix} * 2
        """)
        return ast.parse(code).body

    def _create_hash_collision_confusion(self, prefix: str) -> list[ast.stmt]:
        """
        Hash/eq that makes objects indistinguishable from constants.

        Create objects where hash(obj) == hash(1) and obj == 1, but
        the object carries mutable state. Use in dict lookups where the
        optimizer may constant-fold based on narrowing.
        """
        code = dedent(f"""
            class _Impostor_{prefix}:
                '''Pretends to be integer 1 for all equality/hash purposes.'''
                def __init__(self):
                    self.mutations = 0
                    self.identity = id(self)

                def __eq__(self, other):
                    if other == 1 or isinstance(other, _Impostor_{prefix}):
                        return True
                    return NotImplemented

                def __hash__(self):
                    return hash(1)

                def __add__(self, other):
                    self.mutations += 1
                    return self.mutations + (other if isinstance(other, int) else 0)

                def __int__(self):
                    return 1

                def __index__(self):
                    return 1

            # Phase 1: Use impostor as dict key — should collide with 1
            _d_{prefix} = {{1: "original"}}
            _imp_{prefix} = _Impostor_{prefix}()
            for _i_{prefix} in range(200):
                # Optimizer may narrow dict key lookup based on comparison
                _v_{prefix} = _d_{prefix}.get(_imp_{prefix}, "missing")
                _d_{prefix}[_imp_{prefix}] = _i_{prefix}

            # Phase 2: Impostor in `is` comparison (should fail — not same object)
            for _j_{prefix} in range(200):
                if _imp_{prefix} == 1:
                    # Optimizer narrows to constant 1
                    # But `_imp is 1` should be False
                    _ = _imp_{prefix} + 1  # Returns mutations count, not 2
                    try:
                        _idx_{prefix} = [10, 20, 30][_imp_{prefix}]  # Uses __index__
                    except (IndexError, TypeError):
                        pass

            # Phase 3: Impostor in set operations
            _s_{prefix} = {{1, 2, 3}}
            for _k_{prefix} in range(200):
                _ = _imp_{prefix} in _s_{prefix}  # True via hash/eq
                _s_{prefix}.add(_imp_{prefix})     # Should replace 1?
                _s_{prefix}.discard(_imp_{prefix}) # Should remove 1?
                _s_{prefix}.add(1)                 # Re-add
        """)
        return ast.parse(code).body


class StarCallMutator(ast.NodeTransformer):
    """
    Attack the JIT's CALL_FUNCTION_EX specialization (_PY_FRAME_EX).

    Since Jan 2025, `f(*args, **kwargs)` calls are JIT-specialized with
    optimized frames. This mutator transforms function calls into star-
    unpacking patterns and introduces instability in the unpacked containers
    to stress the specialization.

    Attack vectors:
    1. args_type_instability: The *args container alternates between tuple,
       list, and custom iterables across loop iterations.
    2. kwargs_mutation: The **kwargs dict is mutated (keys added/removed)
       between calls in the same hot loop.
    3. varargs_overflow: Star-call with progressively more arguments,
       eventually exceeding the function's expected arity.
    4. custom_mapping_kwargs: Use a custom Mapping subclass for **kwargs
       that has side effects in __getitem__/__iter__.
    5. mixed_star_explicit: Combine *args with explicit keyword arguments
       that override kwargs entries, testing conflict resolution in the
       specialized path.
    6. nested_star_delegation: f(*args) where f itself does g(*args),
       creating a chain of specialized CALL_FUNCTION_EX frames.
    """

    ATTACK_SCENARIOS = [
        "args_type_instability",
        "kwargs_mutation",
        "varargs_overflow",
        "custom_mapping_kwargs",
        "mixed_star_explicit",
        "nested_star_delegation",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.12:  # 12% chance
            attack = random.choice(self.ATTACK_SCENARIOS)
            p_prefix = f"starcall_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting star call attack ({attack}) with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            scenario_ast = getattr(self, f"_create_{attack}")(p_prefix)

            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_args_type_instability(self, prefix: str) -> list[ast.stmt]:
        """
        Star-call where *args container alternates between types.

        The JIT specializes _PY_FRAME_EX expecting a tuple for args.
        Switching to list or custom iterable may break the specialization.
        """
        code = dedent(f"""
            def _target_{prefix}(*args, **kwargs):
                total = 0
                for a in args:
                    total += a if isinstance(a, (int, float)) else 0
                return total

            # Phase 1: Warm up with tuples — JIT specializes for tuple args
            for _i_{prefix} in range(200):
                _args_{prefix} = (1, 2, 3)
                _kwargs_{prefix} = {{}}
                _target_{prefix}(*_args_{prefix}, **_kwargs_{prefix})

            # Phase 2: Switch to list args
            for _j_{prefix} in range(100):
                _args_{prefix} = [1, 2, 3]
                _kwargs_{prefix} = {{}}
                _target_{prefix}(*_args_{prefix}, **_kwargs_{prefix})

            # Phase 3: Alternate rapidly
            for _k_{prefix} in range(200):
                if _k_{prefix} % 3 == 0:
                    _args_{prefix} = (1, 2, 3)
                elif _k_{prefix} % 3 == 1:
                    _args_{prefix} = [4, 5, 6]
                else:
                    _args_{prefix} = range(1, 4)  # range object
                try:
                    _target_{prefix}(*_args_{prefix})
                except TypeError:
                    pass

            # Phase 4: Custom iterable with __length_hint__ that lies
            class _LyingArgs_{prefix}:
                def __init__(self, items):
                    self._items = items
                def __iter__(self):
                    return iter(self._items)
                def __length_hint__(self):
                    return 1  # Lie about length

            for _m_{prefix} in range(100):
                _la_{prefix} = _LyingArgs_{prefix}([1, 2, 3, 4, 5])
                try:
                    _target_{prefix}(*_la_{prefix})
                except TypeError:
                    pass
        """)
        return ast.parse(code).body

    def _create_kwargs_mutation(self, prefix: str) -> list[ast.stmt]:
        """Mutate **kwargs dict between calls in hot loop."""
        code = dedent(f"""
            def _kw_target_{prefix}(**kwargs):
                return sum(v for v in kwargs.values() if isinstance(v, (int, float)))

            _kw_{prefix} = {{"a": 1, "b": 2, "c": 3}}

            # Phase 1: Warm up with stable kwargs
            for _i_{prefix} in range(200):
                _kw_target_{prefix}(**_kw_{prefix})

            # Phase 2: Mutate kwargs between calls
            for _j_{prefix} in range(200):
                if _j_{prefix} % 10 == 0:
                    _kw_{prefix}[f"extra_{{_j_{prefix}}}"] = _j_{prefix}
                if _j_{prefix} % 15 == 0:
                    _kw_{prefix}.pop("a", None)
                    _kw_{prefix}["a"] = _j_{prefix}  # Re-add with different value
                if _j_{prefix} % 20 == 0:
                    _kw_{prefix}[f"extra_{{_j_{prefix} - 10}}"] = "string_val"
                try:
                    _kw_target_{prefix}(**_kw_{prefix})
                except TypeError:
                    pass

            # Phase 3: Empty kwargs, then full
            for _k_{prefix} in range(100):
                if _k_{prefix} % 2 == 0:
                    _kw_target_{prefix}(**{{}})
                else:
                    _kw_target_{prefix}(**{{"x": 1, "y": 2, "z": 3, "w": 4}})
        """)
        return ast.parse(code).body

    def _create_varargs_overflow(self, prefix: str) -> list[ast.stmt]:
        """Star-call with progressively more arguments, exceeding arity."""
        code = dedent(f"""
            def _fixed_{prefix}(a, b, c):
                return a + b + c

            def _with_defaults_{prefix}(a, b=2, c=3):
                return a + b + c

            # Phase 1: Warm up with correct arity
            for _i_{prefix} in range(200):
                _args_{prefix} = (1, 2, 3)
                _fixed_{prefix}(*_args_{prefix})

            # Phase 2: Wrong arity — too few, too many
            for _j_{prefix} in range(100):
                _nargs_{prefix} = (_j_{prefix} % 5) + 1
                _args_{prefix} = tuple(range(_nargs_{prefix}))
                try:
                    _fixed_{prefix}(*_args_{prefix})
                except TypeError:
                    pass

            # Phase 3: Overflow with defaults
            for _k_{prefix} in range(200):
                _nargs_{prefix} = (_k_{prefix} % 6)
                _args_{prefix} = tuple(range(_nargs_{prefix}))
                try:
                    _with_defaults_{prefix}(*_args_{prefix})
                except TypeError:
                    pass

            # Phase 4: Star-call with mixed args and kwargs
            for _m_{prefix} in range(200):
                _args_{prefix} = (1,)
                _kwargs_{prefix} = {{"b": 2}}
                if _m_{prefix} % 3 == 0:
                    _kwargs_{prefix}["c"] = 3
                if _m_{prefix} % 5 == 0:
                    _kwargs_{prefix}["d"] = 4  # Extra kwarg — TypeError
                try:
                    _fixed_{prefix}(*_args_{prefix}, **_kwargs_{prefix})
                except TypeError:
                    pass
        """)
        return ast.parse(code).body

    def _create_custom_mapping_kwargs(self, prefix: str) -> list[ast.stmt]:
        """Custom Mapping for **kwargs with side effects in __getitem__/__iter__."""
        code = dedent(f"""
            from collections.abc import Mapping

            class _EvilKwargs_{prefix}(Mapping):
                def __init__(self, data):
                    self._data = dict(data)
                    self._access_count = 0

                def __getitem__(self, key):
                    self._access_count += 1
                    # Every 20th access, change a value
                    if self._access_count % 20 == 0:
                        for k in list(self._data):
                            self._data[k] = str(self._data[k])
                    return self._data[key]

                def __iter__(self):
                    # Return keys in reverse order sometimes
                    if self._access_count % 3 == 0:
                        return reversed(list(self._data.keys()))
                    return iter(self._data)

                def __len__(self):
                    return len(self._data)

                def keys(self):
                    return self._data.keys()

            def _km_target_{prefix}(**kwargs):
                return sum(v for v in kwargs.values() if isinstance(v, (int, float)))

            # Phase 1: Warm up with regular dict
            for _i_{prefix} in range(200):
                _km_target_{prefix}(**{{"a": 1, "b": 2}})

            # Phase 2: Use evil mapping
            _ek_{prefix} = _EvilKwargs_{prefix}({{"a": 1, "b": 2, "c": 3}})
            for _j_{prefix} in range(200):
                try:
                    _km_target_{prefix}(**_ek_{prefix})
                except (TypeError, ValueError):
                    pass
        """)
        return ast.parse(code).body

    def _create_mixed_star_explicit(self, prefix: str) -> list[ast.stmt]:
        """Combine *args with explicit keywords that override **kwargs entries."""
        code = dedent(f"""
            def _mx_target_{prefix}(a, b, c, d=4):
                return a + b + c + d

            # Phase 1: Warm up — *args + **kwargs, no conflict
            for _i_{prefix} in range(200):
                _args_{prefix} = (1, 2)
                _kwargs_{prefix} = {{"c": 3, "d": 4}}
                _mx_target_{prefix}(*_args_{prefix}, **_kwargs_{prefix})

            # Phase 2: **kwargs conflicts with explicit keyword
            for _j_{prefix} in range(200):
                _args_{prefix} = (1,)
                _kwargs_{prefix} = {{"b": 2, "c": 3}}
                try:
                    # Explicit d=10 plus **kwargs with d would be error
                    if _j_{prefix} % 2 == 0:
                        _mx_target_{prefix}(*_args_{prefix}, **_kwargs_{prefix}, d=10)
                    else:
                        _kwargs_{prefix}["d"] = 99
                        _mx_target_{prefix}(*_args_{prefix}, **_kwargs_{prefix})
                except TypeError:
                    pass

            # Phase 3: Args cover some positionals, kwargs cover rest + overlap
            for _k_{prefix} in range(200):
                _n_{prefix} = _k_{prefix} % 4
                _args_{prefix} = tuple(range(_n_{prefix}))
                _keys_{prefix} = ["a", "b", "c", "d"]
                _kwargs_{prefix} = {{k: _k_{prefix} for k in _keys_{prefix}[_n_{prefix}:]}}
                # Sometimes add overlapping key
                if _k_{prefix} % 7 == 0 and _n_{prefix} > 0:
                    _kwargs_{prefix}[_keys_{prefix}[0]] = 999  # Overlap with positional
                try:
                    _mx_target_{prefix}(*_args_{prefix}, **_kwargs_{prefix})
                except TypeError:
                    pass
        """)
        return ast.parse(code).body

    def _create_nested_star_delegation(self, prefix: str) -> list[ast.stmt]:
        """f(*args) calls g(*args) — chain of CALL_FUNCTION_EX frames."""
        code = dedent(f"""
            def _inner_{prefix}(*args, **kwargs):
                total = 0
                for a in args:
                    total += a if isinstance(a, (int, float)) else 0
                for v in kwargs.values():
                    total += v if isinstance(v, (int, float)) else 0
                return total

            def _middle_{prefix}(*args, **kwargs):
                # Forward everything — nested CALL_FUNCTION_EX
                return _inner_{prefix}(*args, **kwargs)

            def _outer_{prefix}(*args, **kwargs):
                # Double nesting
                return _middle_{prefix}(*args, **kwargs)

            # Phase 1: Warm up the full chain
            for _i_{prefix} in range(200):
                _outer_{prefix}(1, 2, 3, x=4, y=5)

            # Phase 2: Vary args at each level
            for _j_{prefix} in range(200):
                _nargs_{prefix} = (_j_{prefix} % 6) + 1
                _args_{prefix} = tuple(range(_nargs_{prefix}))
                _kwargs_{prefix} = {{f"k{{_j_{prefix} % 3}}": _j_{prefix}}}
                try:
                    _outer_{prefix}(*_args_{prefix}, **_kwargs_{prefix})
                except TypeError:
                    pass

            # Phase 3: Swap inner function mid-loop
            _orig_inner_{prefix} = _inner_{prefix}

            def _replacement_inner_{prefix}(*args, **kwargs):
                return "not_a_number"

            for _k_{prefix} in range(200):
                if _k_{prefix} == 100:
                    # Monkey-patch inner — middle's *args forwarding now
                    # goes to a function with different return type
                    globals()[f"_inner_{prefix}"] = _replacement_inner_{prefix}
                try:
                    _outer_{prefix}(1, 2, 3)
                except TypeError:
                    pass

            # Restore
            globals()[f"_inner_{prefix}"] = _orig_inner_{prefix}
        """)
        return ast.parse(code).body


class SliceObjectChaosMutator(ast.NodeTransformer):
    """
    Attack the JIT's slice type tracking and guard elimination.

    Since Feb 2025, the optimizer eliminates redundant _GUARD_TOS_SLICE
    when it knows the TOS is a slice, and optimizes _BINARY_OP_SUBSCR_LIST_SLICE.
    This mutator creates scenarios where slice objects become non-slice
    at runtime, or where slice behavior changes mid-loop.

    Attack vectors:
    1. slice_to_int_swap: Alternate between slice objects and integer indices
       in the same subscript position to confuse type tracking.
    2. slice_subclass: Use slice subclasses with dynamic start/stop/step
       attributes or overridden __index__ methods.
    3. guard_elimination_violation: After the first guarded slice access,
       replace the slice variable with a non-slice object for the second
       (unguarded) access.
    4. mutating_slice: Slice-like objects whose start/stop/step change
       between the guard check and the actual subscript operation.
    5. slice_in_container_ops: Use slices in contexts where the optimizer
       tracks their type — list slicing, tuple slicing, string slicing —
       then corrupt them.
    6. nested_slice: `x[s1][s2]` where the optimizer tracks both slice
       objects; corrupt one after the first is guarded.
    """

    ATTACK_SCENARIOS = [
        "slice_to_int_swap",
        "slice_subclass",
        "guard_elimination_violation",
        "mutating_slice",
        "slice_in_container_ops",
        "nested_slice",
    ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.12:  # 12% chance
            attack = random.choice(self.ATTACK_SCENARIOS)
            p_prefix = f"slchaos_{random.randint(1000, 9999)}"

            print(
                f"    -> Injecting slice object chaos ({attack}) with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            scenario_ast = getattr(self, f"_create_{attack}")(p_prefix)

            injection_point = random.randint(0, len(node.body))
            node.body[injection_point:injection_point] = scenario_ast
            ast.fix_missing_locations(node)

        return node

    def _create_slice_to_int_swap(self, prefix: str) -> list[ast.stmt]:
        """Alternate between slice and int in the same subscript position."""
        code = dedent(f"""
            _lst_{prefix} = list(range(20))

            # Phase 1: Warm up with slice — JIT tracks _GUARD_TOS_SLICE
            _sl_{prefix} = slice(0, 5)
            for _i_{prefix} in range(200):
                _r_{prefix} = _lst_{prefix}[_sl_{prefix}]

            # Phase 2: Replace slice var with integer
            _sl_{prefix} = 3  # Now an int, not a slice
            for _j_{prefix} in range(100):
                try:
                    _r_{prefix} = _lst_{prefix}[_sl_{prefix}]  # Guard skipped?
                except TypeError:
                    pass

            # Phase 3: Rapid alternation
            for _k_{prefix} in range(300):
                if _k_{prefix} % 2 == 0:
                    _idx_{prefix} = slice(0, 3)
                else:
                    _idx_{prefix} = _k_{prefix} % len(_lst_{prefix})
                try:
                    _r_{prefix} = _lst_{prefix}[_idx_{prefix}]
                except (TypeError, IndexError):
                    pass

            # Phase 4: Alternate between slice and tuple (neither int nor slice)
            for _m_{prefix} in range(200):
                if _m_{prefix} % 3 == 0:
                    _idx_{prefix} = slice(1, 4)
                elif _m_{prefix} % 3 == 1:
                    _idx_{prefix} = 2
                else:
                    _idx_{prefix} = (1, 2)  # Tuple index — different path
                try:
                    _r_{prefix} = _lst_{prefix}[_idx_{prefix}]
                except (TypeError, IndexError):
                    pass
        """)
        return ast.parse(code).body

    def _create_slice_subclass(self, prefix: str) -> list[ast.stmt]:
        """
        Slice-like objects that the guard might accept as slices.

        Note: slice itself cannot be subclassed in CPython, so we create
        objects that behave like slices via __index__ on start/stop/step.
        """
        code = dedent(f"""
            class _DynamicIndex_{prefix}:
                '''Index that changes value on each access.'''
                def __init__(self, start_val):
                    self._val = start_val
                    self._access_count = 0

                def __index__(self):
                    self._access_count += 1
                    result = self._val
                    # Shift value every 10 accesses
                    if self._access_count % 10 == 0:
                        self._val += 1
                    return result

            _lst_{prefix} = list(range(100))

            # Phase 1: Warm up with normal slice
            _sl_{prefix} = slice(0, 5)
            for _i_{prefix} in range(200):
                _r_{prefix} = _lst_{prefix}[_sl_{prefix}]

            # Phase 2: Slice with dynamic indices
            _start_{prefix} = _DynamicIndex_{prefix}(0)
            _stop_{prefix} = _DynamicIndex_{prefix}(10)
            for _j_{prefix} in range(300):
                _sl_{prefix} = slice(_start_{prefix}, _stop_{prefix})
                try:
                    _r_{prefix} = _lst_{prefix}[_sl_{prefix}]
                except (TypeError, ValueError, IndexError):
                    pass

            # Phase 3: Slice with step that changes
            _step_{prefix} = _DynamicIndex_{prefix}(1)
            for _k_{prefix} in range(200):
                _sl_{prefix} = slice(0, 20, _step_{prefix})
                try:
                    _r_{prefix} = _lst_{prefix}[_sl_{prefix}]
                except (TypeError, ValueError, IndexError):
                    pass

            # Phase 4: Slice with None/negative indices
            for _m_{prefix} in range(200):
                _start_val_{prefix} = None if _m_{prefix} % 3 == 0 else _m_{prefix} % 10
                _stop_val_{prefix} = None if _m_{prefix} % 5 == 0 else -(_m_{prefix} % 5)
                _sl_{prefix} = slice(_start_val_{prefix}, _stop_val_{prefix})
                try:
                    _r_{prefix} = _lst_{prefix}[_sl_{prefix}]
                except (TypeError, IndexError):
                    pass
        """)
        return ast.parse(code).body

    def _create_guard_elimination_violation(self, prefix: str) -> list[ast.stmt]:
        """
        Reproduce the test pattern from test_remove_guard_for_known_type_slice.

        First access is guarded, second skips guard. Replace the slice
        variable between accesses.
        """
        code = dedent(f"""
            _lst_{prefix} = list(range(50))

            def _double_access_{prefix}(lst, idx):
                # First access: guarded _GUARD_TOS_SLICE
                r1 = lst[idx]
                # Second access: guard eliminated — optimizer trusts idx is slice
                r2 = lst[idx]
                return r1, r2

            # Phase 1: Warm up with slice — both accesses optimized
            _sl_{prefix} = slice(0, 5)
            for _i_{prefix} in range(200):
                _double_access_{prefix}(_lst_{prefix}, _sl_{prefix})

            # Phase 2: Call with a non-slice — second access skipped guard
            for _j_{prefix} in range(100):
                try:
                    _double_access_{prefix}(_lst_{prefix}, _j_{prefix} % 10)
                except (TypeError, IndexError):
                    pass

            # Phase 3: Alternate slice/non-slice rapidly
            for _k_{prefix} in range(300):
                if _k_{prefix} % 2 == 0:
                    _idx_{prefix} = slice(1, 3)
                else:
                    _idx_{prefix} = _k_{prefix} % len(_lst_{prefix})
                try:
                    _double_access_{prefix}(_lst_{prefix}, _idx_{prefix})
                except (TypeError, IndexError):
                    pass
        """)
        return ast.parse(code).body

    def _create_mutating_slice(self, prefix: str) -> list[ast.stmt]:
        """
        Slice objects created from mutable state that changes between
        construction and use.
        """
        code = dedent(f"""
            _lst_{prefix} = list(range(100))
            _state_{prefix} = {{"start": 0, "stop": 10}}

            def _make_slice_{prefix}():
                return slice(_state_{prefix}["start"], _state_{prefix}["stop"])

            # Phase 1: Warm up with stable state
            for _i_{prefix} in range(200):
                _sl_{prefix} = _make_slice_{prefix}()
                _r_{prefix} = _lst_{prefix}[_sl_{prefix}]

            # Phase 2: Mutate state between slice creation and use
            for _j_{prefix} in range(300):
                _sl_{prefix} = _make_slice_{prefix}()
                # Mutate state AFTER creating slice but BEFORE using it
                _state_{prefix}["start"] = (_j_{prefix} % 20)
                _state_{prefix}["stop"] = ((_j_{prefix} % 20) + 10)
                # The slice was created with OLD values but state now differs
                try:
                    _r_{prefix} = _lst_{prefix}[_sl_{prefix}]
                except (IndexError, TypeError):
                    pass

            # Phase 3: Create slice, use once (guarded), mutate, use again (unguarded)
            for _k_{prefix} in range(200):
                _sl_{prefix} = slice(0, 5)
                _r1_{prefix} = _lst_{prefix}[_sl_{prefix}]  # Guarded
                # "Mutate" by rebinding to a different slice
                if _k_{prefix} % 3 == 0:
                    _sl_{prefix} = slice(5, 10)  # Different slice
                elif _k_{prefix} % 3 == 1:
                    _sl_{prefix} = 3  # Not a slice at all!
                _r2_{prefix} = _lst_{prefix}[_sl_{prefix}] if isinstance(_sl_{prefix}, (slice, int)) else None
        """)
        return ast.parse(code).body

    def _create_slice_in_container_ops(self, prefix: str) -> list[ast.stmt]:
        """
        Slices across different container types — list, tuple, string, bytes.
        The optimizer may specialize differently for each.
        """
        code = dedent(f"""
            _list_{prefix} = list(range(50))
            _tuple_{prefix} = tuple(range(50))
            _string_{prefix} = "abcdefghijklmnopqrstuvwxyz" * 2
            _bytes_{prefix} = bytes(range(50))

            _sl_{prefix} = slice(5, 15)

            # Phase 1: Warm up list slicing
            for _i_{prefix} in range(200):
                _r_{prefix} = _list_{prefix}[_sl_{prefix}]

            # Phase 2: Switch to tuple — same slice, different container type
            for _j_{prefix} in range(200):
                _r_{prefix} = _tuple_{prefix}[_sl_{prefix}]

            # Phase 3: Switch to string
            for _k_{prefix} in range(200):
                _r_{prefix} = _string_{prefix}[_sl_{prefix}]

            # Phase 4: Rapid container rotation with same slice
            _containers_{prefix} = [_list_{prefix}, _tuple_{prefix}, _string_{prefix}, _bytes_{prefix}]
            for _m_{prefix} in range(400):
                _c_{prefix} = _containers_{prefix}[_m_{prefix} % 4]
                _r_{prefix} = _c_{prefix}[_sl_{prefix}]

            # Phase 5: STORE_SLICE — list only
            for _n_{prefix} in range(200):
                _list_{prefix}[_sl_{prefix}] = [99] * 10  # STORE_SLICE
                if _n_{prefix} % 20 == 0:
                    _list_{prefix} = list(range(50))  # Reset
        """)
        return ast.parse(code).body

    def _create_nested_slice(self, prefix: str) -> list[ast.stmt]:
        """Nested slicing: x[s1][s2] where optimizer tracks both slice types."""
        code = dedent(f"""
            _lst_{prefix} = [list(range(20)) for _ in range(20)]

            _s1_{prefix} = slice(2, 8)
            _s2_{prefix} = slice(0, 3)

            # Phase 1: Warm up nested slicing
            for _i_{prefix} in range(200):
                _sub_{prefix} = _lst_{prefix}[_s1_{prefix}]  # Guarded: list of lists
                _r_{prefix} = _sub_{prefix}[_s2_{prefix}]    # Guarded: sublist

            # Phase 2: Corrupt s2 after s1 is guarded
            for _j_{prefix} in range(200):
                _sub_{prefix} = _lst_{prefix}[_s1_{prefix}]
                if _j_{prefix} % 3 == 0:
                    _s2_{prefix} = slice(1, 4)  # Different slice
                elif _j_{prefix} % 3 == 1:
                    _s2_{prefix} = 2  # Not a slice
                else:
                    _s2_{prefix} = slice(0, 3)  # Original
                try:
                    _r_{prefix} = _sub_{prefix}[_s2_{prefix}]
                except (TypeError, IndexError):
                    pass

            # Phase 3: Flat list with chained slice
            _flat_{prefix} = list(range(100))
            for _k_{prefix} in range(200):
                _r_{prefix} = _flat_{prefix}[slice(10, 50)][slice(0, 5)]
                # Now same but with variable that changes
                if _k_{prefix} % 2 == 0:
                    _inner_{prefix} = slice(0, 5)
                else:
                    _inner_{prefix} = 3
                try:
                    _r_{prefix} = _flat_{prefix}[slice(10, 50)][_inner_{prefix}]
                except (TypeError, IndexError):
                    pass
        """)
        return ast.parse(code).body
