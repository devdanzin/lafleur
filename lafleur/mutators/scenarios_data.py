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
                class_def_node = cast(ast.ClassDef, ast.parse(class_def_str).body[0])
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
            attack_functions: list[Callable[..., Any]] = [
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
            class_def_node = cast(ast.ClassDef, ast.parse(class_def_str).body[0])
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
            attack_functions: list[Callable[..., Any]] = [
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
                except (IndexError, KeyError, RuntimeError, ValueError):
                    pass  # Expected errors from rug pull
            """)
        else:
            # For sequences and dicts, use [] operator
            trigger_code = dedent(f"""
                try:
                    _ = {var_name}[{class_name}()]
                except (IndexError, KeyError, RuntimeError, ValueError):
                    pass  # Expected errors from rug pull
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

            class _SurferB:  # Mirror image
                def __init__(self, val):
                    self.val = val
                def __bool__(self):
                    self.__class__ = _SurferA
                    return False  # Return opposite boolean to confuse control flow
                def __int__(self):
                    self.__class__ = _SurferA
                    return int(self.val)
                def __index__(self):
                    self.__class__ = _SurferA
                    return int(self.val)
                def __add__(self, other):
                    self.__class__ = _SurferA
                    return self.val + other
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
    Exploit the JIT's "Global-to-Constant Promotion".

    The JIT often optimizes global variables (like `range`) into hardcoded
    pointers if they don't change. We train the JIT to trust a global, then
    swap it for a different object inside the hot loop, forcing a complex
    deoptimization path.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness"):
            return node

        if random.random() < 0.2:  # 20% chance
            p_prefix = f"goi_{random.randint(1000, 9999)}"
            print(
                f"    -> Injecting global optimization invalidation with prefix '{p_prefix}'",
                file=sys.stderr,
            )

            # Step 1: Inject the _EvilGlobal class definition
            evil_class_code = dedent(f"""
                class _EvilGlobal_{p_prefix}:
                    def __init__(self, *args): pass
                    def __call__(self, *args): return 42
            """)
            evil_class = ast.parse(evil_class_code).body

            # Step 2: Build the invalidation loop
            # This follows the pattern from test_promote_globals_to_constants
            invalidation_code = dedent(f"""
                global _jit_target_{p_prefix}
                _jit_target_{p_prefix} = range
                try:
                    for _jit_i_{p_prefix} in range(2000):
                        # The Hot Operation: Call the global
                        _jit_x_{p_prefix} = _jit_target_{p_prefix}(1)

                        # The Switch: Mid-loop invalidation
                        if _jit_i_{p_prefix} == 1000:
                            globals()['_jit_target_{p_prefix}'] = _EvilGlobal_{p_prefix}()
                except (TypeError, ValueError, AttributeError):
                    # Catch Python-level errors (we only care about C-level crashes)
                    pass
                finally:
                    # Cleanup: Restore it so we don't break the rest of the script
                    globals()['_jit_target_{p_prefix}'] = range
            """)
            invalidation_loop = ast.parse(invalidation_code).body

            # Inject at the middle of the function body
            injection_point = len(node.body) // 2 if len(node.body) > 1 else len(node.body)
            node.body = (
                evil_class
                + node.body[:injection_point]
                + invalidation_loop
                + node.body[injection_point:]
            )

            ast.fix_missing_locations(node)

        return node


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
