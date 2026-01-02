"""
This module provides shared utilities, sanitizers, and helper functions for
the mutation system.

It includes AST sanitizers to ensure generated code is syntactically valid
(e.g., preventing empty bodies), instrumentation tools for differential
testing, and a library of generator functions for creating "evil" objects
with stateful or contract-violating behaviors used by various scenarios.
"""

from __future__ import annotations

import ast
import random
import sys
from textwrap import dedent


class FuzzerSetupNormalizer(ast.NodeTransformer):
    """
    Removes fuzzer-injected setup code (GC tuning, RNG seeding)
    to prevent it from accumulating across mutation cycles.
    """

    def visit_Import(self, node: ast.Import) -> ast.AST | None:
        # Remove 'import gc' and 'import random' statements
        node.names = [alias for alias in node.names if alias.name not in ("gc", "random")]
        return node if node.names else None

    def visit_Assign(self, node: ast.Assign) -> ast.AST | None:
        # Remove 'fuzzer_rng = random.Random(...)'
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == "fuzzer_rng":
                return None
        self.generic_visit(node)
        return node

    def visit_Expr(self, node: ast.Expr) -> ast.AST | None:
        # Remove 'gc.set_threshold(...)'
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "set_threshold"
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "gc"
        ):
            return None
        self.generic_visit(node)
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        """
        Find calls to the global `random()` and replace them with our
        seeded `fuzzer_rng.random()`.
        """
        # First, visit children of the call, like its arguments.
        self.generic_visit(node)

        # Check if this is a call to the global 'random' function.
        if isinstance(node.func, ast.Name) and node.func.id == "random":
            print("    -> Normalizing call to random() to use fuzzer_rng.", file=sys.stderr)
            # Transform the function call from `random()` to `fuzzer_rng.random()`
            node.func = ast.Attribute(
                value=ast.Name(id="fuzzer_rng", ctx=ast.Load()), attr="random", ctx=ast.Load()
            )
            ast.fix_missing_locations(node)

        return node


class EmptyBodySanitizer(ast.NodeTransformer):
    """
    A final-pass transformer to ensure no control flow statements have empty
    bodies, which would cause an IndentationError.
    """

    def visit(self, node: ast.AST) -> ast.AST:
        # First, let any children be visited and potentially modified.
        self.generic_visit(node)

        # This check covers If, For, While, With, FunctionDef, ClassDef, etc.
        if hasattr(node, "body") and isinstance(node.body, list) and not node.body:
            print("    -> Sanitizing empty body with a 'pass' statement.", file=sys.stderr)
            node.body = [ast.Pass()]
            ast.fix_missing_locations(node)

        return node


class RedundantStatementSanitizer(ast.NodeTransformer):
    """
    Removes consecutive, identical statements probabilistically to control
    file size bloat caused by mutators like StatementDuplicator.

    This preserves some "warming loop" behavior (useful for JIT stressing)
    while preventing infinite growth across mutation cycles.
    """

    def __init__(self, removal_probability: float = 0.9):
        """
        Initialize the sanitizer.

        Args:
            removal_probability: Probability of removing a duplicate statement (default 0.9)
        """
        self.removal_probability = removal_probability

    def _deduplicate_list(self, statements: list[ast.stmt]) -> list[ast.stmt]:
        """
        Remove consecutive identical statements probabilistically.

        Args:
            statements: List of AST statement nodes

        Returns:
            Deduplicated list of statements
        """
        if not statements:
            return statements

        new_list = []
        for node in statements:
            # If the list is empty, always add the first node
            if not new_list:
                new_list.append(node)
                continue

            # Compare with the last added node
            last_node_dump = ast.dump(new_list[-1])
            current_node_dump = ast.dump(node)

            if last_node_dump == current_node_dump:
                # Identical: remove with removal_probability
                if random.random() < self.removal_probability:
                    # Skip (remove) - random value < removal_probability
                    pass
                else:
                    # Keep it - random value >= removal_probability
                    new_list.append(node)
            else:
                # Different: always add
                new_list.append(node)

        return new_list

    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Process Module body."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Process FunctionDef body."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        """Process AsyncFunctionDef body."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        return node

    def visit_For(self, node: ast.For) -> ast.For:
        """Process For body and orelse."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        node.orelse = self._deduplicate_list(node.orelse)
        return node

    def visit_AsyncFor(self, node: ast.AsyncFor) -> ast.AsyncFor:
        """Process AsyncFor body and orelse."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        node.orelse = self._deduplicate_list(node.orelse)
        return node

    def visit_While(self, node: ast.While) -> ast.While:
        """Process While body and orelse."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        node.orelse = self._deduplicate_list(node.orelse)
        return node

    def visit_If(self, node: ast.If) -> ast.If:
        """Process If body and orelse."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        node.orelse = self._deduplicate_list(node.orelse)
        return node

    def visit_With(self, node: ast.With) -> ast.With:
        """Process With body."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        return node

    def visit_AsyncWith(self, node: ast.AsyncWith) -> ast.AsyncWith:
        """Process AsyncWith body."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        return node

    def visit_Try(self, node: ast.Try) -> ast.Try:
        """Process Try body, orelse, and finalbody."""
        self.generic_visit(node)
        node.body = self._deduplicate_list(node.body)
        node.orelse = self._deduplicate_list(node.orelse)
        node.finalbody = self._deduplicate_list(node.finalbody)
        return node


class HarnessInstrumentor(ast.NodeTransformer):
    """
    A special transformer that instruments a fuzzed AST for differential testing.
    It is NOT a mutator and should not be added to the main transformer list.

    This instrumentor does two things:
    1. Modifies the `uop_harness_f...` function to return its `locals()`.
    2. Modifies the main loop to capture this return value in a variable.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        # Find the main harness function and append the return statement
        if node.name.startswith("uop_harness_f"):
            if node.body and isinstance(node.body[-1], ast.Return):
                return node

            return_node = ast.parse("return locals().copy()").body[0]
            node.body.append(return_node)
            ast.fix_missing_locations(node)
        return node

    def visit_For(self, node: ast.For) -> ast.For:
        self.generic_visit(node)
        # Find the main execution loop, which calls the harness
        if (
            isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Name)
            and node.iter.func.id == "range"
        ):
            # Look for the try block that calls the harness
            for i, sub_node in enumerate(node.body):
                if (
                    isinstance(sub_node, ast.Try)
                    and sub_node.body
                    and isinstance(sub_node.body[0], ast.Expr)
                    and isinstance(sub_node.body[0].value, ast.Call)
                    and isinstance(sub_node.body[0].value.func, ast.Name)
                    and sub_node.body[0].value.func.id.startswith("uop_harness_f")
                ):
                    # original call is in an Expr node: `uop_harness_f1()`
                    # We need to change it to an Assign node: `final_harness_locals = uop_harness_f1()`
                    call_node = sub_node.body[0].value
                    assign_node = ast.Assign(
                        targets=[ast.Name(id="final_harness_locals", ctx=ast.Store())],
                        value=call_node,
                    )
                    # Replace the old Expr node with our new Assign node
                    sub_node.body[0] = assign_node
                    ast.fix_missing_locations(node)
                    break
        return node


def is_simple_statement(node: ast.stmt) -> bool:
    """
    Walk a statement's AST to check for nodes unsafe to wrap in a loop.

    Return `False` if the statement contains `return`, `break`, `continue`,
    or `del`.
    """
    for sub_node in ast.walk(node):
        if isinstance(sub_node, (ast.Return, ast.Break, ast.Continue, ast.Delete)):
            return False
    return True


# ==============================================================================
# Evil Object Generators
# ==============================================================================


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
                new_hash = 5 if self.hash_count < 70 else fuzzer_rng.randint(0, 2**64 - 1)
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
