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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)

        if not node.name.startswith("uop_harness") or not node.body:
            return node

        if random.random() < 0.15:  # 15% chance
            attack = random.choice(self.ATTACK_SCENARIOS)
            builtin_name = attack["builtin"]

            p_prefix = f"builtin_{random.randint(1000, 9999)}"
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
    return ast.parse(source_code).body[0]


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
                        if (
                            type_name in self.SEQUENCE_TYPES
                            or type_name in self.MAPPING_TYPES
                        ):
                            target_name = stmt.targets[0].id if isinstance(stmt.targets[0], ast.Name) else None
                            if target_name:
                                return (target_name, type_name)

                    # Handle attribute calls like array.array(), collections.deque()
                    elif isinstance(func_node, ast.Attribute):
                        attr_name = func_node.attr
                        if attr_name in self.STDLIB_SEQUENCE_TYPES:
                            target_name = stmt.targets[0].id if isinstance(stmt.targets[0], ast.Name) else None
                            if target_name:
                                return (target_name, attr_name)

                # Check if RHS is a List, Dict, or Set literal
                if isinstance(stmt.value, (ast.List, ast.Dict, ast.Set)):
                    target_name = stmt.targets[0].id if isinstance(stmt.targets[0], ast.Name) else None
                    if target_name:
                        if isinstance(stmt.value, ast.List):
                            return (target_name, "list")
                        elif isinstance(stmt.value, ast.Dict):
                            return (target_name, "dict")
                        elif isinstance(stmt.value, ast.Set):
                            return (target_name, "set")

        return None

    def _create_rug_puller_class(
        self, var_name: str, type_name: str, prefix: str
    ) -> ast.ClassDef:
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

        return ast.parse(code).body[0]

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
