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
from lafleur.mutators.utils import (
    EmptyBodySanitizer,
    FuzzerSetupNormalizer,
    genStatefulBoolObject,
    genStatefulIndexObject,
)


class TestASTMutator(unittest.TestCase):
    """Test ASTMutator orchestration engine."""

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

    def test_mutate_simple_code(self):
        """Test mutating simple code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                return x + y
        """)

        mutator = ASTMutator()
        mutated_code = mutator.mutate(code, seed=42)

        # Should return valid Python code
        self.assertIsInstance(mutated_code, str)
        # Should be parseable
        tree = ast.parse(mutated_code)
        self.assertIsInstance(tree, ast.Module)

    def test_mutate_ast_directly(self):
        """Test mutating AST directly."""
        code = "x = 1 + 2"
        tree = ast.parse(code)

        mutator = ASTMutator()
        mutated_tree, transformers = mutator.mutate_ast(tree, seed=42)

        # Should return mutated AST and list of transformers
        self.assertIsInstance(mutated_tree, ast.Module)
        self.assertIsInstance(transformers, list)
        self.assertGreater(len(transformers), 0)

        # Should be unparseable
        mutated_code = ast.unparse(mutated_tree)
        self.assertIsInstance(mutated_code, str)

    def test_mutate_with_specific_count(self):
        """Test mutating with specific mutation count."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = ASTMutator()
        _, transformers = mutator.mutate_ast(tree, seed=42, mutations=5)

        # Should apply exactly 5 mutations
        self.assertEqual(len(transformers), 5)

    def test_mutate_with_seed(self):
        """Test that same seed produces same mutations."""
        code = dedent("""
            def uop_harness_test():
                x = 1 + 2
                y = x * 3
                for i in range(10):
                    z = i + y
        """)

        mutator = ASTMutator()
        result1 = mutator.mutate(code, seed=123)
        result2 = mutator.mutate(code, seed=123)

        # Same seed should produce same result
        self.assertEqual(result1, result2)

        # Different seed should produce different result (with high probability)
        result3 = mutator.mutate(code, seed=456)
        # If they're still the same, try more seeds
        if result1 == result3:
            result3 = mutator.mutate(code, seed=789)
        self.assertNotEqual(result1, result3)

    def test_mutate_invalid_syntax(self):
        """Test mutating code with invalid syntax."""
        code = "this is not valid python"

        mutator = ASTMutator()
        result = mutator.mutate(code)

        # Should return error comment
        self.assertIn("# Original code failed to parse:", result)

    def test_mutate_list_as_tree(self):
        """Test mutating when tree is a list."""
        statements = [
            ast.Assign(targets=[ast.Name(id="x", ctx=ast.Store())], value=ast.Constant(value=1)),
            ast.Assign(targets=[ast.Name(id="y", ctx=ast.Store())], value=ast.Constant(value=2)),
        ]

        mutator = ASTMutator()
        mutated_tree, _ = mutator.mutate_ast(statements, seed=42)

        # Should wrap in Module
        self.assertIsInstance(mutated_tree, ast.Module)
        self.assertGreaterEqual(len(mutated_tree.body), 2)

    def test_all_mutators_available(self):
        """Test that all mutators are available in ASTMutator."""
        mutator = ASTMutator()

        # Check some key mutators are present
        mutator_names = [m.__name__ for m in mutator.transformers]

        self.assertIn("OperatorSwapper", mutator_names)
        self.assertIn("GCInjector", mutator_names)
        self.assertIn("TypeInstabilityInjector", mutator_names)
        self.assertIn("GuardRemover", mutator_names)

        # Should have many mutators
        self.assertGreater(len(mutator.transformers), 20)

    def test_mutator_with_complex_ast(self):
        """Test mutator with complex nested AST."""
        code = dedent("""
            def uop_harness_test():
                class Inner:
                    def method(self):
                        for i in range(10):
                            if i > 5:
                                try:
                                    x = 1 / i
                                except ZeroDivisionError:
                                    pass
                                finally:
                                    y = 2
                return Inner()
        """)

        mutator = ASTMutator()
        mutated_code = mutator.mutate(code, seed=42)

        # Should handle complex nested structure
        self.assertIsInstance(mutated_code, str)
        tree = ast.parse(mutated_code)
        self.assertIsInstance(tree, ast.Module)

    def test_multiple_mutations_pipeline(self):
        """Test applying multiple mutations in sequence."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                for i in range(10):
                    result = x + y * i
                return result
        """)

        mutator = ASTMutator()

        # Apply mutations multiple times
        mutated = code
        for i in range(3):
            mutated = mutator.mutate(mutated, seed=i)
            # Each iteration should produce valid code
            tree = ast.parse(mutated)
            self.assertIsInstance(tree, ast.Module)

    def test_normalizer_then_mutate(self):
        """Test normalizing then mutating."""
        code = dedent("""
            import gc
            import random

            fuzzer_rng = random.Random(42)
            gc.set_threshold(1)

            def uop_harness_test():
                if random() > 10:
                    return x
        """)

        # First parse
        tree = ast.parse(code)

        # Apply normalizer
        normalizer = FuzzerSetupNormalizer()
        normalized = normalizer.visit(tree)

        # Check normalization worked
        normalized_code = ast.unparse(normalized)
        self.assertIn("fuzzer_rng.random()", normalized_code)

        # Then mutate with a seed that won't apply GCInjector
        mutator = ASTMutator()
        with patch("random.seed"):
            with patch("random.randint", return_value=1):
                with patch("random.choices", return_value=[OperatorSwapper]):
                    mutated, _ = mutator.mutate_ast(normalized, seed=42)

        final_code = ast.unparse(mutated)
        # Should still have the normalized random call
        self.assertIn("fuzzer_rng.random", final_code)

    def test_complex_evil_object_scenario(self):
        """Test combining multiple evil object generators."""
        # Generate a scenario using multiple evil objects
        code = dedent(f"""
            {genStatefulBoolObject("bool_obj")}
            {genStatefulIndexObject("idx_obj")}

            def uop_harness_test():
                data = [1, 2, 3, 4, 5]
                if bool_obj:
                    result = data[idx_obj]
                return result
        """)

        # Parse and mutate
        mutator = ASTMutator()
        mutated = mutator.mutate(code, seed=42)

        # Should produce valid code
        tree = ast.parse(mutated)
        self.assertIsInstance(tree, ast.Module)


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
