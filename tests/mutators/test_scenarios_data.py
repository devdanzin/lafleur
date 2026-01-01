#!/usr/bin/env python3
"""
Tests for data structure mutators.

This module contains unit tests for data structure mutators defined in
lafleur/mutators/scenarios_data.py
"""

import ast
import random
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.scenarios_data import BuiltinNamespaceCorruptor, ComprehensionBomb


class TestBuiltinNamespaceCorruptor(unittest.TestCase):
    """Test BuiltinNamespaceCorruptor mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_builtin_corruption_scenario(self):
        """Test that builtin corruption is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.choice") as mock_choice:
                # Mock to return a specific attack scenario
                mock_choice.return_value = {
                    "builtin": "len",
                    "warm_up": "for i in range(50): _ = len([0]*i); _ = len('x'*i)",
                    "malicious_lambda": 'lambda x: "evil_string"',
                    "trigger": "_ = len([])",
                }
                mutator = BuiltinNamespaceCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have builtin corruption
        self.assertIn("builtins.len", result)
        self.assertIn("original_len_", result)
        self.assertIn("lambda x:", result)

    def test_includes_try_finally_for_restoration(self):
        """Test that try/finally ensures builtin restoration."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/finally structure
        self.assertIn("try:", result)
        self.assertIn("finally:", result)
        # Should restore the original builtin
        self.assertIn("builtins.", result)

    def test_imports_builtins_module(self):
        """Test that builtins module is imported."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should import builtins
        self.assertIn("import builtins", result)

    def test_includes_warmup_and_trigger(self):
        """Test that warmup and trigger code is included."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have warmup loop
        self.assertIn("for i in range(50):", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.15 threshold
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_handles_isinstance_attack_scenario(self):
        """Test the isinstance attack scenario with custom setup."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice") as mock_choice:
                # Mock to return isinstance scenario
                mock_choice.return_value = {
                    "builtin": "isinstance",
                    "warm_up": "for i in range(50): _ = isinstance(i, int); _ = isinstance('s', str)",
                    "setup": dedent("""
                        {original_var_name} = builtins.isinstance
                        def evil_isinstance(obj, cls):
                            return not {original_var_name}(obj, cls)
                    """),
                    "malicious_assignment": "builtins.isinstance = evil_isinstance",
                    "trigger": "_ = isinstance(1, int)",
                }
                mutator = BuiltinNamespaceCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have evil_isinstance function
        self.assertIn("evil_isinstance", result)
        self.assertIn("builtins.isinstance", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_preserves_original_function_body(self):
        """Test that original function statements are preserved."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = x + y
        """)
        tree = ast.parse(code)
        original_statements = ["x = 1", "y = 2", "z = x + y"]

        with patch("random.random", return_value=0.1):
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Original statements should still be present
        for stmt in original_statements:
            self.assertIn(stmt, result)

    def test_handles_empty_function_body(self):
        """Test handling of functions with only pass."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BuiltinNamespaceCorruptor()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_variable_names(self):
        """Test that unique variable names are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                mutator = BuiltinNamespaceCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("5000", result)
        self.assertIn("original_", result)

    def test_supports_multiple_attack_scenarios(self):
        """Test that different attack scenarios can be selected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)

        # Test that all scenarios in ATTACK_SCENARIOS are valid
        mutator = BuiltinNamespaceCorruptor()
        self.assertGreater(len(mutator.ATTACK_SCENARIOS), 0)

        # Each scenario should have required keys
        for scenario in mutator.ATTACK_SCENARIOS:
            self.assertIn("builtin", scenario)
            self.assertIn("warm_up", scenario)
            self.assertIn("trigger", scenario)
            # Should have either malicious_lambda or setup+malicious_assignment
            has_lambda = "malicious_lambda" in scenario
            has_setup = "setup" in scenario and "malicious_assignment" in scenario
            self.assertTrue(has_lambda or has_setup)


class TestComprehensionBomb(unittest.TestCase):
    """Test ComprehensionBomb mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_chaotic_iterator_class(self):
        """Test that ChaoticIterator class is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", return_value=3000):
                mutator = ComprehensionBomb()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have ChaoticIterator class
        self.assertIn("class ChaoticIterator_comp_3000", result)
        self.assertIn("def __init__", result)
        self.assertIn("def __iter__", result)
        self.assertIn("def __next__", result)

    def test_creates_nested_comprehension(self):
        """Test that nested list comprehension is created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = ComprehensionBomb()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have nested comprehension
        self.assertIn("for x in", result)
        self.assertIn("for y in", result)
        self.assertIn("x + y", result)

    def test_includes_iterator_instantiation(self):
        """Test that iterator is instantiated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                mutator = ComprehensionBomb()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should instantiate the iterator
        self.assertIn("evil_iter_comp_5000", result)
        self.assertIn("ChaoticIterator_comp_5000(range(200))", result)

    def test_wraps_comprehension_in_try_except(self):
        """Test that comprehension is wrapped in try/except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ComprehensionBomb()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except wrapper
        self.assertIn("try:", result)
        self.assertIn("except Exception:", result)
        self.assertIn("pass", result)

    def test_chaotic_iterator_has_side_effects(self):
        """Test that ChaoticIterator includes side effect code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ComprehensionBomb()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have side effect code in __next__
        self.assertIn("fuzzer_rng.random()", result)
        self.assertIn("_items.clear()", result)
        self.assertIn("_items.extend", result)
        self.assertIn("unexpected_type_from_iterator", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = ComprehensionBomb()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.15 threshold
            mutator = ComprehensionBomb()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ComprehensionBomb()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_class_and_variable_names(self):
        """Test that unique names are generated for class and variables."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = ComprehensionBomb()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("comp_7000", result)
        self.assertIn("ChaoticIterator_comp_7000", result)
        self.assertIn("evil_iter_comp_7000", result)

    def test_preserves_original_function_body(self):
        """Test that original function statements are preserved."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = x + y
        """)
        tree = ast.parse(code)
        original_statements = ["x = 1", "y = 2", "z = x + y"]

        with patch("random.random", return_value=0.1):
            mutator = ComprehensionBomb()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Original statements should still be present
        for stmt in original_statements:
            self.assertIn(stmt, result)

    def test_handles_empty_function_body(self):
        """Test handling of functions with only pass."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ComprehensionBomb()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_injects_at_random_position(self):
        """Test that injection occurs at random position in function body."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
        """)
        tree = ast.parse(code)

        # Test with different injection points
        for pos in [0, 1, 2]:
            with patch("random.random", return_value=0.1):
                with patch("random.randint", side_effect=[8000, pos]):
                    mutator = ComprehensionBomb()
                    mutated = mutator.visit(tree)

            # Should produce valid code regardless of position
            result = ast.unparse(mutated)
            reparsed = ast.parse(result)
            self.assertIsInstance(reparsed, ast.Module)

    def test_comprehension_uses_iterator_multiple_times(self):
        """Test that comprehension uses the iterator in nested loops."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=9000):
                mutator = ComprehensionBomb()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # The iterator should be used multiple times in the nested comprehension
        iterator_name = "evil_iter_comp_9000"
        # Count occurrences (should be at least 2 for nested loops)
        self.assertGreaterEqual(result.count(iterator_name), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
