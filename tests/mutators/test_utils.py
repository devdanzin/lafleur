#!/usr/bin/env python3
"""
Tests for utility transformers.

This module contains unit tests for utility transformers defined in
lafleur/mutators/utils.py
"""

import ast
import unittest
from textwrap import dedent

from lafleur.mutators.utils import HarnessInstrumentor, is_simple_statement


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
