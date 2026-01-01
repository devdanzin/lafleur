#!/usr/bin/env python3
"""
Tests for utility transformers.

This module contains unit tests for utility transformers defined in
lafleur/mutators/utils.py
"""

import ast
import unittest
from textwrap import dedent

from lafleur.mutators.utils import (
    EmptyBodySanitizer,
    FuzzerSetupNormalizer,
    HarnessInstrumentor,
    genLyingEqualityObject,
    genSimpleObject,
    genStatefulBoolObject,
    genStatefulGetattrObject,
    genStatefulGetitemObject,
    genStatefulIndexObject,
    genStatefulIterObject,
    genStatefulLenObject,
    genStatefulStrReprObject,
    genUnstableHashObject,
    is_simple_statement,
)


class TestEvilObjectGenerators(unittest.TestCase):
    """Test evil object generator functions."""

    def test_genLyingEqualityObject(self):
        """Test lying equality object generation."""
        code = genLyingEqualityObject("test_eq")
        self.assertIn("class LyingEquality_test_eq:", code)
        self.assertIn("def __eq__", code)
        self.assertIn("def __ne__", code)
        self.assertIn("test_eq = LyingEquality_test_eq()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulLenObject(self):
        """Test stateful len object generation."""
        code = genStatefulLenObject("test_len")
        self.assertIn("class StatefulLen_test_len:", code)
        self.assertIn("def __len__", code)
        self.assertIn("test_len = StatefulLen_test_len()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genUnstableHashObject(self):
        """Test unstable hash object generation."""
        code = genUnstableHashObject("test_hash")
        self.assertIn("class UnstableHash_test_hash:", code)
        self.assertIn("def __hash__", code)
        self.assertIn("fuzzer_rng.randint", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genSimpleObject(self):
        """Test simple object generation."""
        code = genSimpleObject("test_obj")
        self.assertIn("class C_test_obj:", code)
        self.assertIn("self.x = 1", code)
        self.assertIn("self.y = 'y'", code)
        self.assertIn("def get_value", code)

    def test_genStatefulStrReprObject(self):
        """Test stateful str/repr object generation."""
        code = genStatefulStrReprObject("test_str_repr")
        self.assertIn("class StatefulStrRepr_test_str_repr:", code)
        self.assertIn("def __str__", code)
        self.assertIn("def __repr__", code)
        self.assertIn("return 123", code)  # The TypeError-inducing return
        self.assertIn("test_str_repr = StatefulStrRepr_test_str_repr()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulGetitemObject(self):
        """Test stateful getitem object generation."""
        code = genStatefulGetitemObject("test_getitem")
        self.assertIn("class StatefulGetitem_test_getitem:", code)
        self.assertIn("def __getitem__", code)
        self.assertIn("return 99.9", code)  # Float return
        self.assertIn("return 5", code)  # Int return
        self.assertIn("test_getitem = StatefulGetitem_test_getitem()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulGetattrObject(self):
        """Test stateful getattr object generation."""
        code = genStatefulGetattrObject("test_getattr")
        self.assertIn("class StatefulGetattr_test_getattr:", code)
        self.assertIn("def __getattr__", code)
        self.assertIn("return b'evil_attribute'", code)
        self.assertIn("return 'normal_attribute'", code)
        self.assertIn("test_getattr = StatefulGetattr_test_getattr()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulBoolObject(self):
        """Test stateful bool object generation."""
        code = genStatefulBoolObject("test_bool")
        self.assertIn("class StatefulBool_test_bool:", code)
        self.assertIn("def __bool__", code)
        self.assertIn("return False", code)
        self.assertIn("return True", code)
        self.assertIn("test_bool = StatefulBool_test_bool()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulIterObject(self):
        """Test stateful iter object generation."""
        code = genStatefulIterObject("test_iter")
        self.assertIn("class StatefulIter_test_iter:", code)
        self.assertIn("def __iter__", code)
        self.assertIn("self._iterable = [1, 2, 3]", code)
        self.assertIn("return iter((None,))", code)
        self.assertIn("test_iter = StatefulIter_test_iter()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulIndexObject(self):
        """Test stateful index object generation."""
        code = genStatefulIndexObject("test_index")
        self.assertIn("class StatefulIndex_test_index:", code)
        self.assertIn("def __index__", code)
        self.assertIn("return 99", code)  # Out-of-bounds index
        self.assertIn("return 0", code)  # Normal index
        self.assertIn("test_index = StatefulIndex_test_index()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)


class TestFuzzerSetupNormalizer(unittest.TestCase):
    """Test FuzzerSetupNormalizer transformer."""

    def test_fuzzer_setup_normalizer_import(self):
        """Test FuzzerSetupNormalizer removing imports."""
        code = dedent("""
            import gc
            import random
            import os
        """)
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)

        # Should have removed gc and random imports
        self.assertEqual(len(mutated.body), 1)
        self.assertEqual(mutated.body[0].names[0].name, "os")

    def test_fuzzer_setup_normalizer_assign(self):
        """Test FuzzerSetupNormalizer removing fuzzer_rng assignment."""
        code = dedent("""
            fuzzer_rng = random.Random(42)
            x = 1
        """)
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)

        # Should have removed fuzzer_rng assignment
        self.assertEqual(len(mutated.body), 1)
        self.assertEqual(mutated.body[0].targets[0].id, "x")

    def test_fuzzer_setup_normalizer_gc_call(self):
        """Test FuzzerSetupNormalizer removing gc.set_threshold."""
        code = dedent("""
            gc.set_threshold(1)
            print("hello")
        """)
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)

        # Should have removed gc.set_threshold call
        self.assertEqual(len(mutated.body), 1)
        self.assertIsInstance(mutated.body[0].value, ast.Call)
        self.assertEqual(mutated.body[0].value.func.id, "print")

    def test_fuzzer_setup_normalizer_random_call(self):
        """Test FuzzerSetupNormalizer converting random() to fuzzer_rng.random()."""
        code = "x = random()"
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)

        # Should have converted to fuzzer_rng.random()
        call = mutated.body[0].value
        self.assertIsInstance(call.func, ast.Attribute)
        self.assertEqual(call.func.value.id, "fuzzer_rng")
        self.assertEqual(call.func.attr, "random")


class TestEmptyBodySanitizer(unittest.TestCase):
    """Test EmptyBodySanitizer transformer."""

    def test_empty_body_sanitizer_if(self):
        """Test EmptyBodySanitizer adding pass to empty if."""
        code = "if True: pass"
        tree = ast.parse(code)
        # Manually remove the pass to create empty body
        tree.body[0].body = []

        sanitizer = EmptyBodySanitizer()
        mutated = sanitizer.visit(tree)

        # Should have added pass
        self.assertEqual(len(mutated.body[0].body), 1)
        self.assertIsInstance(mutated.body[0].body[0], ast.Pass)

    def test_empty_body_sanitizer_function(self):
        """Test EmptyBodySanitizer adding pass to empty function."""
        code = "def f(): pass"
        tree = ast.parse(code)
        # Manually remove the pass
        tree.body[0].body = []

        sanitizer = EmptyBodySanitizer()
        mutated = sanitizer.visit(tree)

        # Should have added pass
        self.assertEqual(len(mutated.body[0].body), 1)
        self.assertIsInstance(mutated.body[0].body[0], ast.Pass)

    def test_empty_body_sanitizer_for(self):
        """Test EmptyBodySanitizer adding pass to empty for loop."""
        code = "for i in range(10): pass"
        tree = ast.parse(code)
        # Manually remove the pass
        tree.body[0].body = []

        sanitizer = EmptyBodySanitizer()
        mutated = sanitizer.visit(tree)

        # Should have added pass
        self.assertEqual(len(mutated.body[0].body), 1)
        self.assertIsInstance(mutated.body[0].body[0], ast.Pass)

    def test_empty_body_after_mutation(self):
        """Test sanitizing empty bodies after mutation."""
        # Create a scenario where mutation might create empty body
        code = dedent("""
            def f():
                if True:
                    x = 1
        """)

        tree = ast.parse(code)

        # Simulate a mutation that removes the assignment
        tree.body[0].body[0].body = []

        # Apply sanitizer
        sanitizer = EmptyBodySanitizer()
        sanitized = sanitizer.visit(tree)

        # Should have added pass
        if_body = sanitized.body[0].body[0].body
        self.assertEqual(len(if_body), 1)
        self.assertIsInstance(if_body[0], ast.Pass)


class TestHarnessInstrumentor(unittest.TestCase):
    """Test HarnessInstrumentor transformer."""

    def test_adds_return_locals_to_harness_function(self):
        """Test that return locals() is added to harness functions."""
        code = dedent("""
            def uop_harness_f1():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        result = ast.unparse(mutated)
        # Should have added return locals().copy()
        self.assertIn("return locals().copy()", result)

    def test_preserves_existing_return_statement(self):
        """Test that existing return statements are preserved."""
        code = dedent("""
            def uop_harness_f1():
                x = 1
                return x
        """)
        tree = ast.parse(code)
        original_body_len = len(tree.body[0].body)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        func = mutated.body[0]
        # Should not add another return statement
        self.assertEqual(len(func.body), original_body_len)
        self.assertIsInstance(func.body[-1], ast.Return)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not instrumented."""
        code = dedent("""
            def normal_function():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        result = ast.unparse(mutated)
        # Should be unchanged
        self.assertEqual(original, result)
        self.assertNotIn("return locals", result)

    def test_instruments_main_execution_loop(self):
        """Test that the main execution loop is instrumented."""
        code = dedent("""
            def uop_harness_f1():
                x = 1

            for _ in range(100):
                try:
                    uop_harness_f1()
                except Exception:
                    pass
        """)
        tree = ast.parse(code)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        result = ast.unparse(mutated)
        # Should capture return value in final_harness_locals
        self.assertIn("final_harness_locals = uop_harness_f1()", result)

    def test_handles_nested_try_blocks(self):
        """Test handling of nested try blocks."""
        code = dedent("""
            def uop_harness_f1():
                x = 1

            for _ in range(100):
                try:
                    uop_harness_f1()
                except Exception:
                    pass
        """)
        tree = ast.parse(code)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        # Should be parseable
        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_f1():
                x = 1
                y = 2
                z = x + y

            for _ in range(100):
                try:
                    uop_harness_f1()
                except Exception:
                    pass
        """)
        tree = ast.parse(code)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_handles_multiple_harness_functions(self):
        """Test handling of multiple harness functions."""
        code = dedent("""
            def uop_harness_f1():
                x = 1

            def uop_harness_f2():
                y = 2
        """)
        tree = ast.parse(code)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        result = ast.unparse(mutated)
        # Both should have return statements added
        self.assertEqual(result.count("return locals().copy()"), 2)

    def test_only_modifies_harness_functions_starting_with_uop_harness_f(self):
        """Test that only functions starting with 'uop_harness_f' are modified."""
        code = dedent("""
            def uop_harness_test():
                x = 1

            def uop_harness_f1():
                y = 2
        """)
        tree = ast.parse(code)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        result = ast.unparse(mutated)
        # Only uop_harness_f1 should have return locals()
        self.assertEqual(result.count("return locals().copy()"), 1)
        self.assertIn("def uop_harness_f1():", result)

    def test_handles_empty_function_body(self):
        """Test handling of functions with only pass."""
        code = dedent("""
            def uop_harness_f1():
                pass
        """)
        tree = ast.parse(code)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        result = ast.unparse(mutated)
        # Should add return statement
        self.assertIn("return locals().copy()", result)

    def test_preserves_function_with_multiple_statements(self):
        """Test that all original statements are preserved."""
        code = dedent("""
            def uop_harness_f1():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)
        original_statements = len(tree.body[0].body)

        instrumentor = HarnessInstrumentor()
        mutated = instrumentor.visit(tree)

        func = mutated.body[0]
        # Should have original + 1 return statement
        self.assertEqual(len(func.body), original_statements + 1)


class TestIsSimpleStatement(unittest.TestCase):
    """Test is_simple_statement helper function."""

    def test_simple_assignment_is_simple(self):
        """Test that simple assignments are considered simple."""
        node = ast.parse("x = 1").body[0]
        self.assertTrue(is_simple_statement(node))

    def test_statement_with_return_is_not_simple(self):
        """Test that statements with return are not simple."""
        # Parse a function to get a return statement
        func = ast.parse("def f():\n    return x").body[0]
        return_node = func.body[0]
        self.assertFalse(is_simple_statement(return_node))

    def test_statement_with_break_is_not_simple(self):
        """Test that statements with break are not simple."""
        loop = ast.parse("for i in range(10):\n    break").body[0]
        break_node = loop.body[0]
        self.assertFalse(is_simple_statement(break_node))

    def test_statement_with_continue_is_not_simple(self):
        """Test that statements with continue are not simple."""
        loop = ast.parse("for i in range(10):\n    continue").body[0]
        continue_node = loop.body[0]
        self.assertFalse(is_simple_statement(continue_node))

    def test_statement_with_del_is_not_simple(self):
        """Test that statements with del are not simple."""
        node = ast.parse("del x").body[0]
        self.assertFalse(is_simple_statement(node))

    def test_function_call_is_simple(self):
        """Test that function calls are simple."""
        node = ast.parse("print(x)").body[0]
        self.assertTrue(is_simple_statement(node))

    def test_augmented_assignment_is_simple(self):
        """Test that augmented assignments are simple."""
        node = ast.parse("x += 1").body[0]
        self.assertTrue(is_simple_statement(node))

    def test_nested_assignment_is_simple(self):
        """Test that nested assignments without unsafe nodes are simple."""
        node = ast.parse("x = y = z = 1").body[0]
        self.assertTrue(is_simple_statement(node))

    def test_if_statement_without_unsafe_nodes_is_simple(self):
        """Test that if statements without unsafe nodes are simple."""
        node = ast.parse("if True:\n    x = 1").body[0]
        self.assertTrue(is_simple_statement(node))

    def test_if_statement_with_return_is_not_simple(self):
        """Test that if statements with return are not simple."""
        node = ast.parse("if True:\n    return x").body[0]
        self.assertFalse(is_simple_statement(node))

    def test_loop_without_break_is_simple(self):
        """Test that loops without break/continue are simple."""
        node = ast.parse("for i in range(10):\n    x = i").body[0]
        self.assertTrue(is_simple_statement(node))

    def test_complex_expression_is_simple(self):
        """Test that complex expressions are simple."""
        node = ast.parse("x = [i**2 for i in range(10) if i % 2 == 0]").body[0]
        self.assertTrue(is_simple_statement(node))


if __name__ == "__main__":
    unittest.main(verbosity=2)
