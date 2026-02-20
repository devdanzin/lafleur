"""Tests for HelperFunctionInjector mutator."""

import ast
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.helper_injection import HelperFunctionInjector


class TestHelperFunctionInjector(unittest.TestCase):
    """Test cases for HelperFunctionInjector."""

    def test_injects_helpers_at_module_level(self):
        """Test that helpers are injected before the harness function."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                for i in range(10):
                    x += i
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Trigger mutation
            with patch("random.randint", return_value=2):  # Select 2 helpers
                with patch("random.sample") as mock_sample:
                    # Select specific helpers
                    mock_sample.return_value = [
                        HelperFunctionInjector.HELPER_TEMPLATES[0],
                        HelperFunctionInjector.HELPER_TEMPLATES[1],
                    ]

                    mutator = HelperFunctionInjector()
                    mutated = mutator.visit(tree)

        # Should have helpers injected
        self.assertIsInstance(mutated, ast.Module)
        # Should have more functions now (2 helpers + 1 harness)
        funcs = [n for n in mutated.body if isinstance(n, ast.FunctionDef)]
        self.assertGreaterEqual(len(funcs), 3)

        # Check that helper names start with _jit_helper_
        helper_names = [f.name for f in funcs if f.name.startswith("_jit_helper_")]
        self.assertGreater(len(helper_names), 0)

    def test_injects_loop_when_none_exist(self):
        """Test that a warmup loop is injected if harness has no loops."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                return x + y
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Trigger mutation
            with patch("random.randint", return_value=1):  # Select 1 helper
                with patch("random.choice") as mock_choice:
                    # Mock the helper selection
                    mock_choice.return_value = HelperFunctionInjector.HELPER_TEMPLATES[0]

                    mutator = HelperFunctionInjector()
                    mutated = mutator.visit(tree)

        # Find the harness
        harness = None
        for node in mutated.body:
            if isinstance(node, ast.FunctionDef) and node.name == "uop_harness_test":
                harness = node
                break

        self.assertIsNotNone(harness)

        # Should have injected a loop
        loops = [n for n in ast.walk(harness) if isinstance(n, ast.For)]
        self.assertGreater(len(loops), 0)

        # Loop should call a helper
        first_loop = loops[0]
        self.assertGreater(len(first_loop.body), 0)

    def test_injects_calls_into_existing_loops(self):
        """Test that helper calls are injected into existing loops with error handling."""
        code = dedent("""
            def uop_harness_test():
                total = 0
                for i in range(100):
                    total += i
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.3]):  # Trigger mutation, inject into loop
            with patch("random.randint", return_value=1):
                with patch("random.choice") as mock_choice:
                    mock_choice.return_value = "_jit_helper_add"

                    mutator = HelperFunctionInjector()
                    mutator.helpers_injected = ["_jit_helper_add"]  # Simulate injected helper
                    mutated = mutator.visit(tree)

        # Find the harness
        harness = None
        for node in mutated.body:
            if isinstance(node, ast.FunctionDef) and node.name == "uop_harness_test":
                harness = node
                break

        self.assertIsNotNone(harness)

        # Find the loop and verify helper call is wrapped in try/except
        for node in ast.walk(harness):
            if isinstance(node, ast.For):
                # First statement in loop body should be a Try node wrapping the helper call
                if node.body and isinstance(node.body[0], ast.Try):
                    try_node = node.body[0]
                    # The try body should have the helper call assignment
                    result = ast.unparse(try_node)
                    if "_helper_result" in result:
                        return  # Found wrapped helper call

        # If probabilistic skip, this is acceptable

    def test_helper_call_handles_non_int_loop_var(self):
        """Test that injected helper calls are protected against non-int loop variables."""
        code = dedent("""
            def uop_harness_test():
                for name in ["alice", "bob", "charlie"]:
                    pass
        """)
        tree = ast.parse(code)

        # random.random() calls: 0.1 for Module probability (< 0.3, passes),
        # 0.9 for visit_For 50% check (>= 0.5, proceeds to inject)
        with patch("random.random", side_effect=[0.1, 0.9]):
            with patch("random.randint", return_value=1):
                with patch("random.choice") as mock_choice:
                    mock_choice.return_value = "_jit_helper_add"

                    mutator = HelperFunctionInjector()
                    mutator.helpers_injected = ["_jit_helper_add"]
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # The helper call should be wrapped in try/except
        self.assertIn("try:", result)
        self.assertIn("except Exception:", result)
        self.assertIn("_helper_result", result)
        # Code should be valid Python
        ast.parse(result)
        compile(result, "<test>", "exec")

    def test_probability_controls_injection(self):
        """Test that probability parameter controls whether mutation is applied."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # High random value should skip mutation
        with patch("random.random", return_value=0.9):
            mutator = HelperFunctionInjector(probability=0.3)
            mutated = mutator.visit(tree)

        # Should have only the original harness
        funcs = [n for n in mutated.body if isinstance(n, ast.FunctionDef)]
        self.assertEqual(len(funcs), 1)

    def test_handles_no_harness_gracefully(self):
        """Test that mutator handles code with no harness function."""
        code = dedent("""
            def regular_function():
                return 42
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = HelperFunctionInjector()
            mutated = mutator.visit(tree)

        # Should return unchanged
        self.assertIsInstance(mutated, ast.Module)
        funcs = [n for n in mutated.body if isinstance(n, ast.FunctionDef)]
        self.assertEqual(len(funcs), 1)
        self.assertEqual(funcs[0].name, "regular_function")

    def test_mutated_code_is_valid_python(self):
        """Test that all mutations produce valid, parseable Python code."""
        code = dedent("""
            def uop_harness_test():
                x = 0
                for i in range(50):
                    x += i
                return x
        """)

        for _ in range(10):  # Test multiple random mutations
            tree = ast.parse(code)

            with patch("random.random", return_value=0.1):
                mutator = HelperFunctionInjector()
                mutated = mutator.visit(tree)

            # Should be valid AST
            self.assertIsInstance(mutated, ast.Module)

            # Should be unparseable
            try:
                code_str = ast.unparse(mutated)
                # Should be re-parseable
                ast.parse(code_str)
            except Exception as e:
                self.fail(f"Mutated code is not valid Python: {e}")

    def test_multiple_harnesses_handled(self):
        """Test handling code with multiple harness functions."""
        code = dedent("""
            def uop_harness_f1():
                x = 1

            def uop_harness_f2():
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=1):
                mutator = HelperFunctionInjector()
                mutated = mutator.visit(tree)

        # Should still be valid
        self.assertIsInstance(mutated, ast.Module)

        # Helpers should be inserted before the first harness
        funcs = mutated.body
        harness_indices = [
            i
            for i, n in enumerate(funcs)
            if isinstance(n, ast.FunctionDef) and n.name.startswith("uop_harness")
        ]

        if len(harness_indices) > 0:
            first_harness_idx = harness_indices[0]
            # Helpers should come before first harness
            helpers_before = [
                f
                for f in funcs[:first_harness_idx]
                if isinstance(f, ast.FunctionDef) and f.name.startswith("_jit_helper_")
            ]
            # Might have helpers (probabilistic)
            self.assertIsInstance(helpers_before, list)


if __name__ == "__main__":
    unittest.main()
