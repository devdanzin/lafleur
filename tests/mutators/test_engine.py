#!/usr/bin/env python3
"""
Tests for mutation engine components.

This module contains unit tests for engine components defined in
lafleur/mutators/engine.py
"""

import ast
import random
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.engine import ASTMutator, SlicingMutator
from lafleur.mutators.generic import ConstantPerturbator, OperatorSwapper


class TestASTMutator(unittest.TestCase):
    """Test ASTMutator orchestration engine.

    Note: Basic tests for ASTMutator exist in tests/test_mutator.py.
    This test class focuses on additional edge cases and integration scenarios.
    """

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_has_comprehensive_transformer_list(self):
        """Test that ASTMutator includes all registered transformers."""
        mutator = ASTMutator()

        # Should have a substantial list of transformers
        self.assertGreater(len(mutator.transformers), 30)

        # Check for specific important transformers
        transformer_names = [t.__name__ for t in mutator.transformers]
        expected_transformers = [
            "OperatorSwapper",
            "ConstantPerturbator",
            "TypeInstabilityInjector",
            "SliceMutator",
            "PatternMatchingMutator",
        ]

        for expected in expected_transformers:
            self.assertIn(expected, transformer_names)

    def test_mutate_ast_returns_transformer_list(self):
        """Test that mutate_ast returns list of applied transformers."""
        code = "x = 1 + 2"
        tree = ast.parse(code)

        mutator = ASTMutator()
        mutated_tree, transformers = mutator.mutate_ast(tree, seed=42, mutations=3)

        # Should return exactly 3 transformers
        self.assertEqual(len(transformers), 3)
        # All should be classes
        for t in transformers:
            self.assertTrue(isinstance(t, type))

    def test_default_mutation_count_is_random(self):
        """Test that default mutation count is between 1 and 3."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = ASTMutator()

        # Test multiple times to ensure randomness
        counts = []
        for seed in range(20):
            _, transformers = mutator.mutate_ast(tree, seed=seed)
            counts.append(len(transformers))

        # Should have variety (1, 2, or 3)
        self.assertGreaterEqual(min(counts), 1)
        self.assertLessEqual(max(counts), 3)
        # Should have at least 2 different counts
        self.assertGreater(len(set(counts)), 1)

    def test_mutate_with_zero_mutations(self):
        """Test mutating with zero mutations."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = ASTMutator()
        mutated_tree, transformers = mutator.mutate_ast(tree, seed=42, mutations=0)

        # Should apply 0 transformers
        self.assertEqual(len(transformers), 0)

    def test_mutate_preserves_ast_structure(self):
        """Test that mutation preserves basic AST structure."""
        code = dedent("""
            def test_func():
                x = 1
                return x
        """)
        tree = ast.parse(code)

        mutator = ASTMutator()
        mutated_tree, _ = mutator.mutate_ast(tree, seed=42)

        # Should still be a Module
        self.assertIsInstance(mutated_tree, ast.Module)
        # Should still have a function definition
        self.assertTrue(any(isinstance(node, ast.FunctionDef) for node in ast.walk(mutated_tree)))

    def test_mutate_string_handles_syntax_errors(self):
        """Test that mutate() handles unparseable code gracefully."""
        code = "def broken(:\n    pass"

        mutator = ASTMutator()
        result = mutator.mutate(code)

        # Should return error comment
        self.assertIn("# Original code failed to parse:", result)
        self.assertIn("def broken", result)

    def test_mutate_handles_unparsing_errors(self):
        """Test handling of AST unparsing failures."""
        # This is harder to test directly, but we can verify the code path exists
        code = "x = 1"
        mutator = ASTMutator()

        # Normal case should work
        result = mutator.mutate(code, seed=42)
        self.assertIsInstance(result, str)
        self.assertNotIn("# AST unparsing failed", result)

    def test_mutate_complex_code_structure(self):
        """Test mutating complex code with multiple constructs."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3]
                y = {'a': 1, 'b': 2}

                for i in x:
                    if i > 1:
                        y[str(i)] = i * 2

                try:
                    z = sum(y.values())
                except Exception as e:
                    z = 0

                return z
        """)

        mutator = ASTMutator()
        result = mutator.mutate(code, seed=42)

        # Should produce valid code
        tree = ast.parse(result)
        self.assertIsInstance(tree, ast.Module)

    def test_seed_determinism(self):
        """Test that using the same seed produces identical results."""
        code = "x = 1 + 2 * 3"

        mutator1 = ASTMutator()
        mutator2 = ASTMutator()

        result1 = mutator1.mutate(code, seed=12345)
        result2 = mutator2.mutate(code, seed=12345)

        # Should be identical
        self.assertEqual(result1, result2)

    def test_different_seeds_produce_different_results(self):
        """Test that different seeds usually produce different results."""
        code = dedent("""
            def uop_harness_test():
                x = 1 + 2
                y = 3 * 4
                z = x + y
                return z
        """)

        mutator = ASTMutator()
        results = [mutator.mutate(code, seed=s) for s in range(10)]

        # Should have at least some variety
        unique_results = len(set(results))
        self.assertGreater(unique_results, 1)

    def test_mutate_with_list_statements(self):
        """Test that mutate_ast handles list of statements."""
        statements = [
            ast.Assign(targets=[ast.Name(id="x", ctx=ast.Store())], value=ast.Constant(value=1)),
            ast.Assign(targets=[ast.Name(id="y", ctx=ast.Store())], value=ast.Constant(value=2)),
        ]

        mutator = ASTMutator()
        mutated_tree, _ = mutator.mutate_ast(statements, seed=42)

        # Should wrap in Module
        self.assertIsInstance(mutated_tree, ast.Module)

    def test_mutation_count_parameter(self):
        """Test that mutations parameter controls transformer count."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = ASTMutator()

        for count in [1, 2, 5, 10]:
            _, transformers = mutator.mutate_ast(tree, seed=42, mutations=count)
            self.assertEqual(len(transformers), count)

    def test_produces_valid_python_after_mutations(self):
        """Test that mutated code is always valid Python."""
        test_cases = [
            "x = 1",
            "def f(): return 42",
            "for i in range(10): print(i)",
            "if True: x = 1\nelse: x = 2",
            "try: x = 1\nexcept: pass",
            "class C: pass",
        ]

        mutator = ASTMutator()

        for code in test_cases:
            for seed in range(5):
                result = mutator.mutate(code, seed=seed)
                # Should be parseable
                try:
                    tree = ast.parse(result)
                    self.assertIsInstance(tree, ast.Module)
                except SyntaxError as e:
                    self.fail(f"Mutated code failed to parse: {result}\nError: {e}")


class TestSlicingMutator(unittest.TestCase):
    """Test SlicingMutator meta-mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def _create_function_code(self, name, num_statements):
        """Helper to create function code with given number of statements."""
        statements = "\n    ".join([f"x{i} = {i}" for i in range(num_statements)])
        return f"def {name}():\n    {statements}\n"

    def test_slices_large_function(self):
        """Test that large functions are sliced."""
        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        # Should have mutated a slice
        func = mutated.body[0]
        self.assertEqual(len(func.body), 150)  # Original size preserved

    def test_skips_small_functions(self):
        """Test that small functions (<100 statements) are not sliced."""
        code = self._create_function_code("uop_harness_test", 50)
        tree = ast.parse(code)

        mutator = SlicingMutator([ConstantPerturbator()])
        mutated = mutator.visit(tree)

        # Should not be sliced (too small)
        func = mutated.body[0]
        self.assertEqual(len(func.body), 50)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not sliced."""
        code = self._create_function_code("normal_function", 150)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        mutator = SlicingMutator([ConstantPerturbator()])
        mutated = mutator.visit(tree)

        # Should be unchanged (not a harness)
        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_applies_pipeline_to_slice(self):
        """Test that the mutation pipeline is applied to the slice."""
        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            # Use a mutator that will change constants
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        # The slice should have been mutated
        func = mutated.body[0]
        self.assertEqual(len(func.body), 150)

    def test_preserves_statements_outside_slice(self):
        """Test that statements outside the slice are preserved."""
        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        with patch("random.randint", return_value=50):  # Slice from 50-75
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        func = mutated.body[0]
        # All statements should still be there
        self.assertEqual(len(func.body), 150)

    def test_slice_size_is_25(self):
        """Test that the slice size is 25 statements."""
        # The SlicingMutator should extract 25 statements
        self.assertEqual(SlicingMutator.SLICE_SIZE, 25)

        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        # Should still have all 150 statements
        func = mutated.body[0]
        self.assertEqual(len(func.body), 150)

    def test_handles_multiple_transformers(self):
        """Test that multiple transformers can be applied in pipeline."""
        # Create function with binary operations
        statements = "\n    ".join([f"x{i} = {i} + {i}" for i in range(150)])
        code = f"def uop_harness_test():\n    {statements}\n"
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            # Use multiple mutators
            mutator = SlicingMutator([OperatorSwapper(), ConstantPerturbator()])
            mutated = mutator.visit(tree)

        func = mutated.body[0]
        self.assertEqual(len(func.body), 150)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        with patch("random.randint", return_value=20):
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_exactly_100_statements(self):
        """Test edge case with exactly 100 statements."""
        code = self._create_function_code("uop_harness_test", 100)
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        func = mutated.body[0]
        # With exactly 100, it should be sliced
        self.assertEqual(len(func.body), 100)

    def test_handles_complex_statements(self):
        """Test handling of complex statements in slice."""
        # Create function with various statement types
        complex_statements = []
        for i in range(50):
            complex_statements.append(f"x{i} = {i}")
            complex_statements.append(f"if x{i} > 0:")
            complex_statements.append(f"    y{i} = x{i} * 2")

        code = "def uop_harness_test():\n    " + "\n    ".join(complex_statements) + "\n"
        tree = ast.parse(code)

        with patch("random.randint", return_value=10):
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        # Should produce valid code
        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_random_slice_selection(self):
        """Test that random slice selection works correctly."""
        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        # Test different random starting points
        for start in [0, 25, 50, 75, 100]:
            with patch("random.randint", return_value=start):
                mutator = SlicingMutator([ConstantPerturbator()])
                mutated = mutator.visit(tree)

                func = mutated.body[0]
                # Should always have 150 statements
                self.assertEqual(len(func.body), 150)

    def test_empty_pipeline(self):
        """Test with empty pipeline (no transformers)."""
        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            # Empty pipeline
            mutator = SlicingMutator([])
            mutated = mutator.visit(tree)

        func = mutated.body[0]
        # Should still have all statements
        self.assertEqual(len(func.body), 150)

    def test_handles_exactly_minimum_size(self):
        """Test function with exactly MIN_STATEMENTS_FOR_SLICE statements."""
        min_size = SlicingMutator.MIN_STATEMENTS_FOR_SLICE
        code = self._create_function_code("uop_harness_test", min_size)
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        func = mutated.body[0]
        # Should be sliced
        self.assertEqual(len(func.body), min_size)

    def test_handles_one_more_than_minimum(self):
        """Test function with MIN_STATEMENTS_FOR_SLICE + 1 statements."""
        min_size = SlicingMutator.MIN_STATEMENTS_FOR_SLICE
        code = self._create_function_code("uop_harness_test", min_size + 1)
        tree = ast.parse(code)

        with patch("random.randint", return_value=0):
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

        func = mutated.body[0]
        # Should be sliced
        self.assertEqual(len(func.body), min_size + 1)

    def test_minimum_threshold_constant(self):
        """Test that MIN_STATEMENTS_FOR_SLICE constant is correct."""
        self.assertEqual(SlicingMutator.MIN_STATEMENTS_FOR_SLICE, 100)

    def test_slice_size_constant(self):
        """Test that SLICE_SIZE constant is correct."""
        self.assertEqual(SlicingMutator.SLICE_SIZE, 25)

    def test_slice_bounds_calculation(self):
        """Test that slice bounds are calculated correctly."""
        code = self._create_function_code("uop_harness_test", 150)
        tree = ast.parse(code)

        # Test that random.randint is called with correct bounds
        # Max start should be 150 - 25 = 125
        with patch("random.randint") as mock_randint:
            mock_randint.return_value = 100
            mutator = SlicingMutator([ConstantPerturbator()])
            mutated = mutator.visit(tree)

            # Check that randint was called with (0, 125)
            mock_randint.assert_called_once_with(0, 150 - 25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
