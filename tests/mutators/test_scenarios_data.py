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

from lafleur.mutators.scenarios_data import (
    BuiltinNamespaceCorruptor,
    ComprehensionBomb,
    DictPolluter,
    IterableMutator,
    MagicMethodMutator,
    NumericMutator,
    _create_hash_attack,
    _create_len_attack,
    _create_pow_attack,
)


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


class TestHelperFunctions(unittest.TestCase):
    """Test helper functions used by mutators."""

    def test_create_len_attack(self):
        """Test len attack generation."""
        nodes = _create_len_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain StatefulLen class
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("StatefulLen", code)
        self.assertIn("for i_len", code)

    def test_create_hash_attack(self):
        """Test hash attack generation."""
        nodes = _create_hash_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain UnstableHash class
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("UnstableHash", code)
        self.assertIn("d = {}", code)

    def test_create_pow_attack(self):
        """Test pow attack generation."""
        nodes = _create_pow_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain pow calls
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("pow(10, -2)", code)
        self.assertIn("pow(-10, 0.5)", code)


class TestAttackFunctions(unittest.TestCase):
    """Test attack generation functions."""

    def test_create_len_attack(self):
        """Test len attack generation."""
        nodes = _create_len_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain StatefulLen class
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("StatefulLen", code)
        self.assertIn("for i_len", code)

    def test_create_hash_attack(self):
        """Test hash attack generation."""
        nodes = _create_hash_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain UnstableHash class
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("UnstableHash", code)
        self.assertIn("d = {}", code)

    def test_create_pow_attack(self):
        """Test pow attack generation."""
        nodes = _create_pow_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain pow calls
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("pow(10, -2)", code)
        self.assertIn("pow(-10, 0.5)", code)


class TestAdvancedMutators(unittest.TestCase):
    """Test advanced mutator classes."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_dict_polluter_global(self):
        """Test DictPolluter with global pollution."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.3]):
            mutator = DictPolluter()
            mutated = mutator.visit(tree)

        # Should have injected global dict pollution
        func = mutated.body[0]
        self.assertGreater(len(func.body), 1)


class TestMagicMethodMutators(unittest.TestCase):
    """Test magic method and numeric mutators."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_magic_method_mutator_len_attack(self):
        """Test MagicMethodMutator with len attack."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value=_create_len_attack):
                mutator = MagicMethodMutator()
                mutated = mutator.visit(tree)

        # Should have injected len attack
        func = mutated.body[0]
        # Look for StatefulLen class
        has_stateful_len = any(
            isinstance(stmt, ast.ClassDef) and "StatefulLen" in stmt.name for stmt in func.body
        )
        self.assertTrue(has_stateful_len)

    def test_numeric_mutator_pow_args(self):
        """Test NumericMutator mutating pow arguments."""
        code = "result = pow(2, 3)"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=(10, -2)):
                mutator = NumericMutator()
                mutated = mutator.visit(tree)

        # Check pow arguments were changed
        call = mutated.body[0].value
        self.assertEqual(call.args[0].value, 10)
        self.assertEqual(call.args[1].value, -2)

    def test_numeric_mutator_chr_args(self):
        """Test NumericMutator mutating chr arguments."""
        code = "c = chr(65)"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=-1):
                mutator = NumericMutator()
                mutated = mutator.visit(tree)

        # Check chr argument was changed
        call = mutated.body[0].value
        self.assertEqual(call.args[0].value, -1)

    def test_iterable_mutator_tuple_attack(self):
        """Test IterableMutator with tuple attack."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            # Make it choose _create_tuple_attack
            def mock_choice(choices):
                for choice in choices:
                    if hasattr(choice, "__name__") and "tuple" in choice.__name__:
                        return choice
                return choices[0]

            with patch("random.choice", side_effect=mock_choice):
                mutator = IterableMutator()
                mutated = mutator.visit(tree)

        # Should have injected tuple attack scenario
        func = mutated.body[0]
        code_str = ast.unparse(func)
        self.assertIn("tuple", code_str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
