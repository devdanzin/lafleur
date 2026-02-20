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
    AbstractInterpreterConfusionMutator,
    BloomFilterSaturator,
    BoundaryComparisonMutator,
    BuiltinNamespaceCorruptor,
    CodeObjectHotSwapper,
    ComprehensionBomb,
    ConstantNarrowingPoisonMutator,
    DictPolluter,
    GlobalOptimizationInvalidator,
    IterableMutator,
    LatticeSurfingMutator,
    MagicMethodMutator,
    NumericMutator,
    ReentrantSideEffectMutator,
    SliceObjectChaosMutator,
    StackCacheThrasher,
    StarCallMutator,
    TypeShadowingMutator,
    UnpackingChaosMutator,
    ZombieTraceMutator,
    _create_hash_attack,
    _create_len_attack,
    _create_pow_attack,
    _mutate_for_loop_iter,
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

        # First random < 0.15 triggers, second random > 0.3 uses original attack
        with patch("random.random", side_effect=[0.1, 0.5]):
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

        # First random < 0.15 triggers, second random > 0.3 uses original attack
        with patch("random.random", side_effect=[0.1, 0.5]):
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

        # First random < 0.15 triggers, second random > 0.3 uses original attack
        with patch("random.random", side_effect=[0.1, 0.5]):
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
        compile(result, "<test>", "exec")

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
        compile(result, "<test>", "exec")

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
        dedent("""
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

    def test_has_enhanced_attacks_list(self):
        """Test that ENHANCED_ATTACKS list is defined."""
        mutator = BuiltinNamespaceCorruptor()
        self.assertTrue(hasattr(mutator, "ENHANCED_ATTACKS"))
        self.assertGreater(len(mutator.ENHANCED_ATTACKS), 0)
        expected_attacks = [
            "direct_dict_modification",
            "builtins_type_toggle",
            "highfreq_builtin_corruption",
        ]
        for attack in expected_attacks:
            self.assertIn(attack, mutator.ENHANCED_ATTACKS)

    def test_enhanced_attack_direct_dict_modification(self):
        """Test that direct_dict_modification attack is injected correctly."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):  # trigger, use enhanced
            with patch(
                "random.choice",
                side_effect=lambda x: "direct_dict_modification"
                if x == BuiltinNamespaceCorruptor.ENHANCED_ATTACKS
                else x[0],
            ):
                with patch("random.randint", return_value=5000):
                    mutator = BuiltinNamespaceCorruptor()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have direct dict modification markers
        self.assertIn("builtins_dict_builtin_5000", result)
        self.assertIn("FUZZER_FOO_builtin_5000", result)
        self.assertIn("FUZZER_BAR_builtin_5000", result)
        # Should have types import for ModuleType check
        self.assertIn("import types", result)
        self.assertIn("types.ModuleType", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_enhanced_attack_builtins_type_toggle(self):
        """Test that builtins_type_toggle attack is injected correctly."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):  # trigger, use enhanced
            with patch(
                "random.choice",
                side_effect=lambda x: "builtins_type_toggle"
                if x == BuiltinNamespaceCorruptor.ENHANCED_ATTACKS
                else x[0],
            ):
                with patch("random.randint", return_value=6000):
                    mutator = BuiltinNamespaceCorruptor()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have type toggle markers
        self.assertIn("is_module_builtin_6000", result)
        self.assertIn("FUZZER_KEY_builtin_6000", result)
        self.assertIn("types.ModuleType", result)
        # Should detect current type
        self.assertIn("isinstance(__builtins__, types.ModuleType)", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_enhanced_attack_highfreq_builtin_corruption(self):
        """Test that highfreq_builtin_corruption attack is injected correctly."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):  # trigger, use enhanced
            with patch(
                "random.choice",
                side_effect=lambda x: "highfreq_builtin_corruption"
                if x == BuiltinNamespaceCorruptor.ENHANCED_ATTACKS
                else x[0],
            ):
                with patch("random.randint", return_value=7000):
                    mutator = BuiltinNamespaceCorruptor()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should save originals for len, isinstance, type
        self.assertIn("original_len_builtin_7000", result)
        self.assertIn("original_isinstance_builtin_7000", result)
        self.assertIn("original_type_builtin_7000", result)
        # Should corrupt multiple builtins
        self.assertIn("builtins.len = lambda", result)
        self.assertIn("builtins.isinstance = lambda", result)
        self.assertIn("builtins.type = lambda", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_enhanced_attack_restores_builtins(self):
        """Test that enhanced attacks restore builtins in finally block."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):
            with patch(
                "random.choice",
                side_effect=lambda x: "highfreq_builtin_corruption"
                if x == BuiltinNamespaceCorruptor.ENHANCED_ATTACKS
                else x[0],
            ):
                with patch("random.randint", return_value=8000):
                    mutator = BuiltinNamespaceCorruptor()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have finally block restoring builtins
        self.assertIn("finally:", result)
        self.assertIn("builtins.len = original_len_builtin_8000", result)
        self.assertIn("builtins.isinstance = original_isinstance_builtin_8000", result)
        self.assertIn("builtins.type = original_type_builtin_8000", result)

    def test_enhanced_attacks_produce_valid_code(self):
        """Test that all enhanced attack types produce valid, parseable code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = x + y
        """)

        for attack_type in BuiltinNamespaceCorruptor.ENHANCED_ATTACKS:
            tree = ast.parse(code)
            with patch("random.random", side_effect=[0.1, 0.1]):
                with patch(
                    "random.choice",
                    side_effect=lambda x, at=attack_type: at
                    if x == BuiltinNamespaceCorruptor.ENHANCED_ATTACKS
                    else x[0],
                ):
                    with patch("random.randint", return_value=9000):
                        mutator = BuiltinNamespaceCorruptor()
                        mutated = mutator.visit(tree)

            result = ast.unparse(mutated)
            # All attack types should produce valid code
            reparsed = ast.parse(result)
            self.assertIsInstance(reparsed, ast.Module)

    def test_enhanced_attack_probability(self):
        """Test that enhanced attacks have 30% selection probability."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # random.random() returns 0.4 (> 0.3) so should use original attack
        with patch("random.random", side_effect=[0.1, 0.4]):  # trigger=0.1, enhanced=0.4
            with patch("random.randint", return_value=1000):
                mutator = BuiltinNamespaceCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should use original attack format (has original_len or original_range etc)
        has_original = any(f"original_{b}" in result for b in ["len", "range", "isinstance", "sum"])
        self.assertTrue(has_original)
        # Should NOT have enhanced attack markers
        self.assertNotIn("builtins_dict_", result)
        self.assertNotIn("is_module_", result)


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
        # Should have new backing store mutation operations
        self.assertIn("_items.insert(", result)
        self.assertIn("_items.pop(", result)

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
        compile(result, "<test>", "exec")

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
        compile(result, "<test>", "exec")

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


class TestMutateForLoopIter(unittest.TestCase):
    """Test the shared _mutate_for_loop_iter helper."""

    def test_mutate_for_loop_iter_shared_function(self):
        """Test the shared _mutate_for_loop_iter helper wraps in try/except."""
        code = dedent("""
            def uop_harness_test():
                for i in range(10):
                    x = i + 1
        """)
        tree = ast.parse(code)
        func_node = tree.body[0]

        with patch("random.randint", return_value=4242):
            result = _mutate_for_loop_iter(func_node)

        self.assertTrue(result)
        code_str = ast.unparse(func_node)
        self.assertIn("StatefulIter_iter_4242", code_str)
        # The for loop should be wrapped in try/except
        try_nodes = [n for n in func_node.body if isinstance(n, ast.Try)]
        self.assertGreater(len(try_nodes), 0, "For loop should be wrapped in try/except")

    def test_mutate_for_loop_iter_no_loop(self):
        """Test that _mutate_for_loop_iter returns False with no for loop."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        func_node = tree.body[0]

        result = _mutate_for_loop_iter(func_node)
        self.assertFalse(result)


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
        """Test NumericMutator mutating pow arguments inside harness."""
        code = dedent("""
            def uop_harness_test():
                result = pow(2, 3)
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=(10, -2)):
                mutator = NumericMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("pow(10, -2)", result)

    def test_numeric_mutator_chr_args(self):
        """Test NumericMutator mutating chr arguments inside harness."""
        code = dedent("""
            def uop_harness_test():
                c = chr(65)
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=-1):
                mutator = NumericMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("chr(-1)", result)

    def test_numeric_mutator_skips_non_harness_calls(self):
        """Test NumericMutator doesn't mutate calls in non-harness functions."""
        code = dedent("""
            def helper():
                return chr(65)

            def uop_harness_test():
                x = helper()
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=-1):
                mutator = NumericMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Helper's chr(65) should be untouched
        self.assertIn("chr(65)", result)

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


class TestReentrantSideEffectMutator(unittest.TestCase):
    """Test ReentrantSideEffectMutator ("rug pull" attacks)."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_rug_pull_attack_on_list(self):
        """Test rug pull attack on a list (sequence type)."""
        code = dedent("""
            def uop_harness_test():
                my_list = [1, 2, 3, 4, 5]
                x = my_list[0]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):  # Trigger mutation
            with patch("random.randint", return_value=1234):  # Fixed prefix
                mutator = ReentrantSideEffectMutator()
                mutated = mutator.visit(tree)

        # Verify structure
        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should have RugPuller class
        self.assertIn("RugPuller_1234", code_str)

        # Should have __index__ method (for sequences)
        self.assertIn("__index__", code_str)

        # Should clear the target list
        self.assertIn("my_list.clear()", code_str)

        # Should have try/except wrapper catching NameError
        self.assertIn("try:", code_str)
        self.assertIn("except", code_str)
        self.assertIn("NameError", code_str)

        # Should have trigger statement using []
        self.assertIn("my_list[RugPuller_1234()]", code_str)

    def test_rug_pull_attack_on_set(self):
        """Test rug pull attack on a set (mapping type)."""
        code = dedent("""
            def uop_harness_test():
                my_set = {1, 2, 3}
                x = 1 in my_set
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):  # Trigger mutation
            with patch("random.randint", return_value=5678):  # Fixed prefix
                mutator = ReentrantSideEffectMutator()
                mutated = mutator.visit(tree)

        # Verify structure
        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should have RugPuller class
        self.assertIn("RugPuller_5678", code_str)

        # Should have __hash__ method (for sets)
        self.assertIn("__hash__", code_str)

        # Should have __eq__ method
        self.assertIn("__eq__", code_str)

        # Should clear the target set
        self.assertIn("my_set.clear()", code_str)

        # Should have try/except wrapper catching NameError
        self.assertIn("try:", code_str)
        self.assertIn("except", code_str)
        self.assertIn("NameError", code_str)

        # Should use 'in' operator for sets
        self.assertIn("in my_set", code_str)

    def test_rug_pull_attack_on_dict(self):
        """Test rug pull attack on a dict."""
        code = dedent("""
            def uop_harness_test():
                my_dict = {"a": 1, "b": 2}
                x = my_dict["a"]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", return_value=9999):
                mutator = ReentrantSideEffectMutator()
                mutated = mutator.visit(tree)

        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should have RugPuller class with __hash__
        self.assertIn("RugPuller_9999", code_str)
        self.assertIn("__hash__", code_str)
        self.assertIn("my_dict.clear()", code_str)

        # Should use [] operator for dicts
        self.assertIn("my_dict[RugPuller_9999()]", code_str)

    def test_rug_pull_injects_variable_when_none_found(self):
        """Test that mutator injects a list when no suitable variable is found."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", return_value=4321):
                mutator = ReentrantSideEffectMutator()
                mutated = mutator.visit(tree)

        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should have injected fuzzer_list variable
        self.assertIn("fuzzer_list = [1, 2, 3, 4, 5]", code_str)

        # Should target the injected list
        self.assertIn("fuzzer_list.clear()", code_str)
        self.assertIn("fuzzer_list[RugPuller_4321()]", code_str)

    def test_rug_pull_handles_no_mutation(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                my_list = [1, 2, 3]
        """)
        tree = ast.parse(code)
        ast.unparse(tree)

        with patch("random.random", return_value=0.5):  # Above threshold (0.10)
            mutator = ReentrantSideEffectMutator()
            mutated = mutator.visit(tree)

        # Should not have modified the code
        mutated_code = ast.unparse(mutated)
        # The code should be essentially the same (minor formatting differences may occur)
        self.assertNotIn("RugPuller", mutated_code)


class TestLatticeSurfingMutator(unittest.TestCase):
    """Test LatticeSurfingMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_surfer_classes(self):
        """Test that _SurferA and _SurferB classes are injected."""
        code = dedent("""
            def uop_harness_test():
                x = 42
                y = True
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):  # Below 0.1 threshold
            with patch("random.randint", return_value=1):  # Mutate 1 variable
                with patch("random.sample") as mock_sample:
                    # Make it choose the first variable
                    mock_sample.side_effect = lambda targets, k: targets[:k]
                    mutator = LatticeSurfingMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have injected the Surfer classes
        self.assertIn("class _SurferA:", result)
        self.assertIn("class _SurferB:", result)

    def test_replaces_int_assignment(self):
        """Test that integer assignment is replaced with _SurferA(value)."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", return_value=1):
                with patch("random.sample") as mock_sample:
                    mock_sample.side_effect = lambda targets, k: targets[:k]
                    mutator = LatticeSurfingMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should replace x = 42 with x = _SurferA(42)
        self.assertIn("x = _SurferA(42)", result)
        self.assertNotIn("x = 42", result)  # Original assignment should be gone

    def test_replaces_bool_assignment(self):
        """Test that boolean assignment is replaced with _SurferA(value)."""
        code = dedent("""
            def uop_harness_test():
                flag = True
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", return_value=1):
                with patch("random.sample") as mock_sample:
                    mock_sample.side_effect = lambda targets, k: targets[:k]
                    mutator = LatticeSurfingMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should replace flag = True with flag = _SurferA(True)
        self.assertIn("flag = _SurferA(True)", result)

    def test_surfer_class_flip_flop(self):
        """Test that Surfer classes flip between _SurferA and _SurferB."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", return_value=1):
                with patch("random.sample") as mock_sample:
                    mock_sample.side_effect = lambda targets, k: targets[:k]
                    mutator = LatticeSurfingMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # _SurferA should flip to _SurferB in magic methods
        self.assertIn("self.__class__ = _SurferB", result)
        # _SurferB should flip to _SurferA in magic methods
        self.assertIn("self.__class__ = _SurferA", result)
        # Should have comparison and arithmetic dunder methods
        self.assertIn("__lt__", result)
        self.assertIn("__eq__", result)
        self.assertIn("__sub__", result)
        self.assertIn("__mul__", result)
        self.assertIn("__hash__", result)

    def test_limits_mutation_to_1_or_2_variables(self):
        """Test that only 1-2 variables are mutated."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", return_value=2):  # Mutate 2 variables
                with patch("random.sample") as mock_sample:
                    # Choose first 2
                    mock_sample.side_effect = lambda targets, k: targets[:k]
                    mutator = LatticeSurfingMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have exactly 2 _SurferA() calls
        surfer_count = result.count("_SurferA(")
        self.assertEqual(surfer_count, 2)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)
        ast.unparse(tree)

        with patch("random.random", return_value=0.5):  # Above 0.1 threshold
            mutator = LatticeSurfingMutator()
            mutated = mutator.visit(tree)

        mutated_code = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_SurferA", mutated_code)
        self.assertNotIn("_SurferB", mutated_code)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 42
                y = True
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", return_value=1):
                with patch("random.sample") as mock_sample:
                    mock_sample.side_effect = lambda targets, k: targets[:k]
                    mutator = LatticeSurfingMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")


class TestBloomFilterSaturator(unittest.TestCase):
    """Test BloomFilterSaturator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_module_level_variables(self):
        """Test that module-level bloom filter variables are injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.2 threshold
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have injected the module-level variables
        self.assertIn("_bloom_target = 0", result)
        self.assertIn("_bloom_noise_idx = 0", result)

    def test_injects_saturation_logic_in_function(self):
        """Test that bloom filter saturation logic is injected into functions."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # First random < 0.2 triggers module vars, second < 0.2 triggers function,
        # third > 0.35 uses original attack
        with patch("random.random", side_effect=[0.1, 0.1, 0.5]):
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have global declaration
        self.assertIn("global _bloom_target, _bloom_noise_idx", result)
        # Should have the bait (conditional check)
        self.assertIn("if _bloom_target % 2 == 0:", result)
        # Should have the noise loop
        self.assertIn("for _ in range(150):", result)
        self.assertIn("_bloom_noise_idx += 1", result)
        self.assertIn("globals()[f'_bloom_noise_{_bloom_noise_idx}']", result)
        # Should have the switch
        self.assertIn("_bloom_target += 1", result)

    def test_bait_trains_jit_dependency(self):
        """Test that the bait creates a dependency on _bloom_target."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # Use original attack (third random > 0.35)
        with patch("random.random", side_effect=[0.1, 0.1, 0.5]):
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # The bait should check _bloom_target value
        self.assertIn("_bloom_target % 2 == 0", result)
        self.assertIn("pass", result)  # The bait does nothing, just creates dependency

    def test_noise_thrashes_globals_dict(self):
        """Test that the noise loop writes to globals() multiple times."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # Use original attack (third random > 0.35)
        with patch("random.random", side_effect=[0.1, 0.1, 0.5]):
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have a loop that writes to globals()
        self.assertIn("for _ in range(150):", result)
        # Should use globals() with dynamic keys
        self.assertIn("globals()", result)
        self.assertIn("_bloom_noise_", result)

    def test_switch_modifies_watched_variable(self):
        """Test that the switch modifies _bloom_target after saturation."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # Use original attack (third random > 0.35)
        with patch("random.random", side_effect=[0.1, 0.1, 0.5]):
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should modify _bloom_target after the noise
        self.assertIn("_bloom_target += 1", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.2 threshold
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_bloom_target", result)
        self.assertNotIn("_bloom_noise_idx", result)
        self.assertNotIn("globals()", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_has_enhanced_attacks_list(self):
        """Test that ENHANCED_ATTACKS list is defined."""
        mutator = BloomFilterSaturator()
        self.assertTrue(hasattr(mutator, "ENHANCED_ATTACKS"))
        self.assertGreater(len(mutator.ENHANCED_ATTACKS), 0)
        expected_attacks = [
            "saturation_probe",
            "strategic_global_mod",
            "multi_phase_attack",
        ]
        for attack in expected_attacks:
            self.assertIn(attack, mutator.ENHANCED_ATTACKS)

    def test_enhanced_attack_saturation_probe(self):
        """Test that saturation_probe attack is injected correctly."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # Trigger module vars (0.1), trigger function (0.1), use enhanced (0.1 < 0.35)
        with patch("random.random", side_effect=[0.1, 0.1, 0.1]):
            with patch(
                "random.choice",
                side_effect=lambda x: "saturation_probe"
                if x == BloomFilterSaturator.ENHANCED_ATTACKS
                else x[0],
            ):
                with patch("random.randint", return_value=5000):
                    mutator = BloomFilterSaturator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have saturation probe markers
        self.assertIn("bloom_5000", result)
        self.assertIn("Probing bloom filter saturation", result)
        self.assertIn("saturation_detected_bloom_5000", result)
        self.assertIn("probe_count_bloom_5000", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_enhanced_attack_strategic_global_mod(self):
        """Test that strategic_global_mod attack is injected correctly."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1, 0.1]):
            with patch(
                "random.choice",
                side_effect=lambda x: "strategic_global_mod"
                if x == BloomFilterSaturator.ENHANCED_ATTACKS
                else x[0],
            ):
                with patch("random.randint", return_value=6000):
                    mutator = BloomFilterSaturator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have strategic global modification markers
        self.assertIn("bloom_6000", result)
        self.assertIn("Running strategic global modification", result)
        self.assertIn("critical_globals_bloom_6000", result)
        self.assertIn("_critical_global_", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_enhanced_attack_multi_phase(self):
        """Test that multi_phase_attack is injected correctly."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1, 0.1]):
            with patch(
                "random.choice",
                side_effect=lambda x: "multi_phase_attack"
                if x == BloomFilterSaturator.ENHANCED_ATTACKS
                else x[0],
            ):
                with patch("random.randint", return_value=7000):
                    mutator = BloomFilterSaturator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have multi-phase attack markers
        self.assertIn("bloom_7000", result)
        self.assertIn("Phase 1: Warmup", result)
        self.assertIn("Phase 2: Saturating", result)
        self.assertIn("Phase 3: Exploitation", result)
        self.assertIn("Phase 4: Verification", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_enhanced_attacks_produce_valid_code(self):
        """Test that all enhanced attack types produce valid, parseable code."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
                y = 2
        """)

        for attack_type in BloomFilterSaturator.ENHANCED_ATTACKS:
            tree = ast.parse(code)
            with patch("random.random", side_effect=[0.1, 0.1, 0.1]):
                with patch(
                    "random.choice",
                    side_effect=lambda x, at=attack_type: at
                    if x == BloomFilterSaturator.ENHANCED_ATTACKS
                    else x[0],
                ):
                    with patch("random.randint", return_value=9000):
                        mutator = BloomFilterSaturator()
                        mutated = mutator.visit(tree)

            result = ast.unparse(mutated)
            # All attack types should produce valid code
            reparsed = ast.parse(result)
            self.assertIsInstance(reparsed, ast.Module)

    def test_enhanced_attack_probability(self):
        """Test that enhanced attacks have 35% selection probability."""
        code = dedent("""
            _bloom_target = 0
            _bloom_noise_idx = 0
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # third random.random() > 0.35 so uses original attack
        with patch("random.random", side_effect=[0.1, 0.1, 0.5]):
            mutator = BloomFilterSaturator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should use original attack format
        self.assertIn("for _ in range(150):", result)
        # Should NOT have enhanced attack markers
        self.assertNotIn("saturation_detected_", result)
        self.assertNotIn("Phase 1: Warmup", result)
        self.assertNotIn("critical_globals_", result)


class TestStackCacheThrasher(unittest.TestCase):
    """Test StackCacheThrasher mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_8_variables(self):
        """Test that 8 stack variables are injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.3 threshold
            mutator = StackCacheThrasher()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have 8 _st_ variables
        self.assertIn("_st_0 = 0", result)
        self.assertIn("_st_1 = 1", result)
        self.assertIn("_st_7 = 7", result)

    def test_creates_right_associative_expression(self):
        """Test that a right-associative expression is created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StackCacheThrasher()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have the nested expression with all variables
        self.assertIn("_st_0", result)
        self.assertIn("_st_7", result)
        # Should have various operators
        self.assertIn("+", result)
        self.assertIn("-", result)
        self.assertIn("*", result)
        self.assertIn("|", result)
        self.assertIn("&", result)
        self.assertIn("^", result)

    def test_expression_assigned_to_throwaway(self):
        """Test that the expression is assigned to _."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StackCacheThrasher()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should assign to _
        self.assertIn("_ =", result)

    def test_nested_binop_structure(self):
        """Test that the expression has deeply nested BinOp structure."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StackCacheThrasher()
            mutated = mutator.visit(tree)

        # Find the assignment to _
        func = mutated.body[0]
        # Find the thrashing statement (should be somewhere in the body)
        thrash_stmt = None
        for stmt in func.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                if stmt.targets[0].id == "_":
                    thrash_stmt = stmt
                    break

        self.assertIsNotNone(thrash_stmt)
        # The value should be a BinOp
        self.assertIsInstance(thrash_stmt.value, ast.BinOp)

        # Walk down the right side to verify nesting depth
        depth = 0
        current = thrash_stmt.value
        while isinstance(current, ast.BinOp):
            depth += 1
            current = current.right

        # Should have at least 7 levels of nesting
        self.assertGreaterEqual(depth, 7)

    def test_forces_stack_depth_greater_than_3(self):
        """Test that the expression forces stack depth > 3."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StackCacheThrasher()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # The expression should use all 8 variables, which forces deep evaluation
        # All 8 variables should be present
        for i in range(8):
            self.assertIn(f"_st_{i}", result)

        # The expression should be assigned to _
        self.assertIn("_ = _st_0 +", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.3 threshold
            mutator = StackCacheThrasher()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_st_", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StackCacheThrasher()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")


class TestBoundaryComparisonMutator(unittest.TestCase):
    """Test BoundaryComparisonMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_edge_case_floats(self):
        """Test that edge-case float values are injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.2 threshold
            mutator = BoundaryComparisonMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have NaN, Inf, -0.0, 0.0, and dummy counter
        self.assertIn("_bnd_nan = float('nan')", result)
        self.assertIn("_bnd_inf = float('inf')", result)
        self.assertIn("_bnd_nzero = -0.0", result)
        self.assertIn("_bnd_zero = 0.0", result)
        self.assertIn("_bnd_dummy = 0", result)

    def test_creates_comparison_blocks(self):
        """Test that comparison If statements are created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BoundaryComparisonMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have comparisons with edge-case values
        self.assertIn("if _bnd_nan == _bnd_nan:", result)
        self.assertIn("if _bnd_nan != _bnd_inf:", result)
        self.assertIn("if _bnd_zero < _bnd_nzero:", result)
        self.assertIn("_bnd_dummy += 1", result)

    def test_uses_all_comparison_operators(self):
        """Test that Eq, NotEq, Lt, and Gt operators are used."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BoundaryComparisonMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have all operators in comparisons
        self.assertIn("==", result)
        self.assertIn("!=", result)
        self.assertIn("<", result)
        self.assertIn(">", result)

    def test_has_side_effect_in_if_body(self):
        """Test that If blocks contain _bnd_dummy += 1."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BoundaryComparisonMutator()
            mutated = mutator.visit(tree)

        # Find the If statements
        func = mutated.body[0]
        if_stmts = [stmt for stmt in func.body if isinstance(stmt, ast.If)]

        # Should have multiple If statements
        self.assertGreater(len(if_stmts), 0)

        # Each If should have AugAssign in body
        for if_stmt in if_stmts:
            self.assertEqual(len(if_stmt.body), 1)
            self.assertIsInstance(if_stmt.body[0], ast.AugAssign)
            self.assertEqual(if_stmt.body[0].target.id, "_bnd_dummy")

    def test_tests_all_combinations(self):
        """Test that all three combinations are tested for each operator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BoundaryComparisonMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have all three combinations
        # NaN vs NaN
        self.assertIn("_bnd_nan == _bnd_nan", result)
        # NaN vs Inf
        self.assertIn("_bnd_nan", result)
        self.assertIn("_bnd_inf", result)
        # 0.0 vs -0.0
        self.assertIn("_bnd_zero", result)
        self.assertIn("_bnd_nzero", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.2 threshold
            mutator = BoundaryComparisonMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_bnd_", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BoundaryComparisonMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")


class TestAbstractInterpreterConfusionMutator(unittest.TestCase):
    """Test AbstractInterpreterConfusionMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_chameleon_class(self):
        """Test that _ChameleonInt class is injected."""
        code = dedent("""
            def uop_harness_test():
                l = [1, 2, 3]
                x = l[0]
        """)
        tree = ast.parse(code)

        mutator = AbstractInterpreterConfusionMutator()
        mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have _ChameleonInt class definition
        self.assertIn("class _ChameleonInt(int):", result)
        self.assertIn("def __index__(self):", result)
        self.assertIn("def __hash__(self):", result)
        self.assertIn("raise ValueError('Chameleon Fail')", result)
        self.assertIn("raise TypeError('Chameleon Hash Fail')", result)

    def test_wraps_constant_indices(self):
        """Test that constant indices are wrapped with _ChameleonInt."""
        code = dedent("""
            def uop_harness_test():
                l = [1, 2, 3]
                x = l[0]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.3 threshold
            mutator = AbstractInterpreterConfusionMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should wrap the index
        self.assertIn("l[_ChameleonInt(0)]", result)

    def test_wraps_name_indices(self):
        """Test that Name indices are wrapped with _ChameleonInt."""
        code = dedent("""
            def uop_harness_test():
                l = [1, 2, 3]
                i = 0
                x = l[i]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.3 threshold
            mutator = AbstractInterpreterConfusionMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should wrap the index
        self.assertIn("l[_ChameleonInt(i)]", result)

    def test_no_wrapping_when_random_check_fails(self):
        """Test that indices are not wrapped when random check fails."""
        code = dedent("""
            def uop_harness_test():
                l = [1, 2, 3]
                x = l[0]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.3 threshold
            mutator = AbstractInterpreterConfusionMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still have the class but not wrap the index
        self.assertIn("class _ChameleonInt(int):", result)
        # Index should not be wrapped
        self.assertIn("l[0]", result)
        self.assertNotIn("l[_ChameleonInt(0)]", result)

    def test_chameleon_class_has_correct_behavior(self):
        """Test that _ChameleonInt class has __index__ and __hash__ methods."""
        code = dedent("""
            def uop_harness_test():
                l = [1, 2, 3]
                x = l[0]
        """)
        tree = ast.parse(code)

        mutator = AbstractInterpreterConfusionMutator()
        mutated = mutator.visit(tree)

        # Find the class definition
        func = mutated.body[0]
        chameleon_class = None
        for stmt in func.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == "_ChameleonInt":
                chameleon_class = stmt
                break

        self.assertIsNotNone(chameleon_class)
        # Check that it has the correct methods
        method_names = [m.name for m in chameleon_class.body if isinstance(m, ast.FunctionDef)]
        self.assertIn("__index__", method_names)
        self.assertIn("__hash__", method_names)

    def test_only_wraps_simple_indices(self):
        """Test that only simple indices (Constant, Name) are wrapped."""
        code = dedent("""
            def uop_harness_test():
                l = [1, 2, 3]
                x = l[0]
                y = l[1:2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.3 threshold
            mutator = AbstractInterpreterConfusionMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should wrap constant index
        self.assertIn("_ChameleonInt(0)", result)
        # Should NOT wrap slice
        self.assertIn("l[1:2]", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                l = [1, 2, 3]
                x = l[0]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = AbstractInterpreterConfusionMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")


class TestGlobalOptimizationInvalidator(unittest.TestCase):
    """Test GlobalOptimizationInvalidator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_evil_global_class(self):
        """Test that _EvilGlobal class is injected with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.2 threshold
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="evil_global_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have _EvilGlobal class definition with prefix
        self.assertIn("class _EvilGlobal_goi_5000:", result)
        self.assertIn("def __init__(self, *args):", result)
        self.assertIn("def __call__(self, *args):", result)
        self.assertIn("return 42", result)

    def test_injects_global_declaration(self):
        """Test that global _jit_target is declared with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="evil_global_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have global declaration with prefix
        self.assertIn("global _jit_target_goi_5000", result)

    def test_injects_hot_loop(self):
        """Test that the hot loop is injected with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="evil_global_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have the hot loop with prefix
        self.assertIn("for _jit_i_goi_5000 in range(2000):", result)
        self.assertIn("_jit_x_goi_5000 = _jit_target_goi_5000(1)", result)

    def test_injects_mid_loop_invalidation(self):
        """Test that global is swapped mid-loop with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="evil_global_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should swap at iteration 1000 with prefixed names
        self.assertIn("if _jit_i_goi_5000 == 1000:", result)
        self.assertIn("globals()['_jit_target_goi_5000'] = _EvilGlobal_goi_5000()", result)

    def test_restores_global_after_loop(self):
        """Test that global is restored after the loop with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="evil_global_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have finally block restoring range with prefix
        self.assertIn("finally:", result)
        self.assertIn("globals()['_jit_target_goi_5000'] = range", result)

    def test_has_try_except_wrapper(self):
        """Test that loop is wrapped in try-except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="evil_global_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try-except
        self.assertIn("try:", result)
        self.assertIn("except (TypeError, ValueError, AttributeError):", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.2 threshold
            mutator = GlobalOptimizationInvalidator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_EvilGlobal", result)
        self.assertNotIn("_jit_target", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="evil_global_swap"):
                mutator = GlobalOptimizationInvalidator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_namespace_swap_attack(self):
        """Test that namespace_swap attack injects FunctionType-based swap."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="namespace_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should use types.FunctionType for namespace swap
        self.assertIn("FunctionType", result)
        # Should define a victim function
        self.assertIn("_goi_victim_goi_5000", result)
        # Should have alternate globals with wrong types
        self.assertIn("not_an_int", result)
        # Should have warmup loop
        self.assertIn("range(2000)", result)
        # Should produce valid, parseable code
        ast.parse(result)
        compile(result, "<test>", "exec")

    def test_globals_dict_mutate_attack(self):
        """Test that globals_dict_mutate attack modifies __globals__ in-place."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="globals_dict_mutate"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should mutate __globals__ in-place
        self.assertIn("__globals__", result)
        # Should have a target function
        self.assertIn("_goi_target_goi_5000", result)
        # Should change type mid-execution
        self.assertIn("type_changed", result)
        # Should have warmup loop
        self.assertIn("range(2000)", result)
        # Should produce valid, parseable code
        ast.parse(result)
        compile(result, "<test>", "exec")

    def test_evil_global_swap_still_works(self):
        """Test that the original evil_global_swap attack still works after refactoring."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                with patch("random.choice", return_value="evil_global_swap"):
                    mutator = GlobalOptimizationInvalidator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # All original assertions should still hold
        self.assertIn("class _EvilGlobal_goi_5000:", result)
        self.assertIn("global _jit_target_goi_5000", result)
        self.assertIn("for _jit_i_goi_5000 in range(2000):", result)
        self.assertIn("if _jit_i_goi_5000 == 1000:", result)
        self.assertIn("globals()['_jit_target_goi_5000'] = _EvilGlobal_goi_5000()", result)
        self.assertIn("finally:", result)
        self.assertIn("globals()['_jit_target_goi_5000'] = range", result)

    def test_all_attack_vectors_produce_valid_code(self):
        """Test that all attack vectors produce parseable Python."""
        attack_vectors = ["evil_global_swap", "namespace_swap", "globals_dict_mutate"]

        for attack in attack_vectors:
            with self.subTest(attack=attack):
                code = dedent("""
                    def uop_harness_test():
                        x = 1
                """)
                tree = ast.parse(code)

                with patch("random.random", return_value=0.1):
                    with patch("random.randint", return_value=5000):
                        with patch("random.choice", return_value=attack):
                            mutator = GlobalOptimizationInvalidator()
                            mutated = mutator.visit(tree)

                result = ast.unparse(mutated)
                # Must parse without error
                ast.parse(result)
                compile(result, "<test>", "exec")


class TestCodeObjectHotSwapper(unittest.TestCase):
    """Test CodeObjectHotSwapper mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_generator_functions(self):
        """Test that _gen_A and _gen_B generator functions are injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.2 threshold
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have both generator functions
        self.assertIn("def _gen_A():", result)
        self.assertIn("def _gen_B():", result)
        # Generators should have yields
        self.assertIn("yield 1", result)
        self.assertIn("yield 100", result)

    def test_injects_warmup_loop(self):
        """Test that the warmup loop is injected to train the JIT."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have warmup loop
        self.assertIn("for _swap_i in range(1000):", result)
        self.assertIn("_swap_g = _gen_A()", result)
        self.assertIn("next(_swap_g)", result)

    def test_injects_code_object_swap(self):
        """Test that the __code__ attribute swap is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should swap code objects
        self.assertIn("_gen_A.__code__ = _gen_B.__code__", result)

    def test_creates_generator_after_swap(self):
        """Test that a generator is created after the swap to trigger deopt."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # After swap, should create a new generator and call next
        self.assertIn("_swap_result = next(_swap_g)", result)

    def test_has_try_except_wrapper(self):
        """Test that swap code is wrapped in try-except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try-except
        self.assertIn("try:", result)
        self.assertIn("except (ValueError, TypeError, AttributeError):", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.2 threshold
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_gen_A", result)
        self.assertNotIn("_gen_B", result)
        self.assertNotIn("__code__", result)

    def test_ignores_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def regular_function():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_gen_A", result)
        self.assertNotIn("__code__", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectHotSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")


class TestTypeShadowingMutator(unittest.TestCase):
    """Test TypeShadowingMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_sys_getframe_call(self):
        """Test that sys._getframe().f_locals is injected with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.2 threshold
            with patch("random.randint", return_value=7000):
                mutator = TypeShadowingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have sys._getframe().f_locals with prefix
        self.assertIn("_getframe", result)
        self.assertIn("f_locals", result)

    def test_injects_float_variable_setup(self):
        """Test that float variable is set up for JIT training with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = TypeShadowingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have float setup with prefix
        self.assertIn("_shadow_x_shadow_7000 = 3.14", result)
        self.assertIn("_shadow_x_shadow_7000 + 1.0", result)

    def test_injects_warmup_loop(self):
        """Test that the warmup loop is injected with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = TypeShadowingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have hot loop with prefix
        self.assertIn("for _shadow_i_shadow_7000 in range(2000):", result)

    def test_injects_type_swap_at_iteration_1500(self):
        """Test that type is swapped at iteration 1500 with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = TypeShadowingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should swap at iteration 1500 with prefix
        self.assertIn("if _shadow_i_shadow_7000 == 1500:", result)
        self.assertIn("EVIL_STRING", result)

    def test_injects_sys_import(self):
        """Test that sys is imported locally via __import__ with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = TypeShadowingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should import sys locally with prefix
        self.assertIn("_shadow_sys_shadow_7000 = __import__('sys')", result)

    def test_has_try_except_wrapper(self):
        """Test that type operation is wrapped in try-except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = TypeShadowingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try-except for TypeError
        self.assertIn("try:", result)
        self.assertIn("except TypeError:", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.2 threshold
            mutator = TypeShadowingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_shadow_x_shadow_", result)
        self.assertNotIn("_getframe", result)

    def test_ignores_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def regular_function():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = TypeShadowingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_shadow_x_shadow_", result)
        self.assertNotIn("_getframe", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = TypeShadowingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")


class TestZombieTraceMutator(unittest.TestCase):
    """Test ZombieTraceMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_zombie_churn_function(self):
        """Test that _zombie_churn function is injected with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.2 threshold
            with patch("random.randint", return_value=6000):
                mutator = ZombieTraceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have the churn function definition with prefix
        self.assertIn("def _zombie_churn_zombie_6000():", result)

    def test_injects_zombie_churn_call(self):
        """Test that _zombie_churn() is called with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = ZombieTraceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should call the churn function with prefix
        self.assertIn("_zombie_churn_zombie_6000()", result)

    def test_injects_loop_creating_victims(self):
        """Test that the loop creating victim functions is injected with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = ZombieTraceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have the victim creation loop with prefix
        self.assertIn("for _zombie_iter_zombie_6000 in range(50):", result)

    def test_injects_victim_function(self):
        """Test that _zombie_victim function is injected with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = ZombieTraceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have the victim function definition with prefix
        self.assertIn("def _zombie_victim_zombie_6000():", result)

    def test_victim_has_hot_loop(self):
        """Test that victim function has a hot loop to trigger JIT with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = ZombieTraceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have hot loop in victim with prefix
        self.assertIn("for _zombie_i_zombie_6000 in range(1000):", result)
        self.assertIn("_zombie_x_zombie_6000 += 1", result)

    def test_victim_is_called(self):
        """Test that victim function is called to trigger JIT compilation with prefix."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = ZombieTraceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should call the victim function with prefix
        self.assertIn("_zombie_victim_zombie_6000()", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.2 threshold
            mutator = ZombieTraceMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_zombie_churn", result)
        self.assertNotIn("_zombie_victim", result)

    def test_ignores_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def regular_function():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ZombieTraceMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_zombie_churn", result)
        self.assertNotIn("_zombie_victim", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ZombieTraceMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")


class TestUnpackingChaosMutator(unittest.TestCase):
    """Test UnpackingChaosMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_helper_class_at_module_level(self):
        """Test that _JitChaosIterator helper class is injected at module level."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have _JitChaosIterator class
        self.assertIn("class _JitChaosIterator:", result)
        self.assertIn("def __init__(self, iterable, mode='grow', trigger_count=50):", result)
        self.assertIn("def __iter__(self):", result)
        self.assertIn("def __next__(self):", result)
        self.assertIn("def __length_hint__(self):", result)

    def test_helper_class_has_grow_mode(self):
        """Test that helper class implements grow mode."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have grow mode logic
        self.assertIn("mode == 'grow'", result)
        self.assertIn("return None", result)  # Extra item in grow mode

    def test_helper_class_has_shrink_mode(self):
        """Test that helper class implements shrink mode."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have shrink mode logic
        self.assertIn("mode == 'shrink'", result)

    def test_helper_class_has_type_switch_mode(self):
        """Test that helper class implements type_switch mode."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have type_switch mode logic
        self.assertIn("mode == 'type_switch'", result)
        self.assertIn("unexpected_string_type", result)

    def test_helper_class_lies_about_length(self):
        """Test that __length_hint__ returns misleading values."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have __length_hint__ with misleading logic
        self.assertIn("__length_hint__", result)
        self.assertIn("len(self._items) - 1", result)  # Underreport
        self.assertIn("len(self._items) + 1", result)  # Overreport

    def test_transforms_unpacking_assignment(self):
        """Test that unpacking assignment is wrapped with chaos iterator."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        # Force helper injection and assignment transformation
        with patch("random.random", side_effect=[0.1, 0.1]):  # First for module, second for assign
            with patch("random.choice", return_value="grow"):
                with patch("random.randint", return_value=50):
                    mutator = UnpackingChaosMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should wrap the assignment value
        self.assertIn("_JitChaosIterator([1, 2]", result)

    def test_transforms_for_loop_unpacking(self):
        """Test that for loop with unpacking is wrapped."""
        code = dedent("""
            def test_func():
                for x, y in [(1, 2), (3, 4)]:
                    pass
        """)
        tree = ast.parse(code)

        # Force helper injection and for loop transformation
        with patch("random.random", side_effect=[0.1, 0.1]):  # First for module, second for loop
            with patch("random.choice", return_value="shrink"):
                with patch("random.randint", return_value=75):
                    mutator = UnpackingChaosMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should wrap the iterator
        self.assertIn("_JitChaosIterator([(1, 2), (3, 4)]", result)

    def test_no_transformation_without_helper_injection(self):
        """Test that assignments are not wrapped if helper wasn't injected."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        # High probability prevents helper injection
        with patch("random.random", return_value=0.9):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should NOT have chaos iterator
        self.assertNotIn("_JitChaosIterator", result)
        # Original code preserved
        self.assertIn("a, b = [1, 2]", result)

    def test_ignores_simple_assignments(self):
        """Test that simple (non-unpacking) assignments are not transformed."""
        code = dedent("""
            def test_func():
                x = 42
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should NOT wrap simple assignment
        self.assertNotIn("_JitChaosIterator(42)", result)
        self.assertIn("x = 42", result)

    def test_ignores_for_loops_without_unpacking(self):
        """Test that for loops without unpacking are not transformed."""
        code = dedent("""
            def test_func():
                for x in range(10):
                    pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should NOT wrap simple for loop
        self.assertNotIn("_JitChaosIterator(range(10))", result)
        self.assertIn("for x in range(10):", result)

    def test_handles_list_unpacking_target(self):
        """Test that list unpacking targets are recognized."""
        code = dedent("""
            def test_func():
                [a, b, c] = [1, 2, 3]
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):
            with patch("random.choice", return_value="grow"):
                with patch("random.randint", return_value=50):
                    mutator = UnpackingChaosMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should wrap the assignment
        self.assertIn("_JitChaosIterator", result)

    def test_skips_existing_helper_class(self):
        """Test that helper is not re-injected if already present."""
        code = dedent("""
            class _JitChaosIterator:
                pass
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should only have one _JitChaosIterator class definition
        self.assertEqual(result.count("class _JitChaosIterator:"), 1)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
                for x, y in [(1, 2)]:
                    pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)
        compile(result, "<test>", "exec")

    def test_mode_and_trigger_are_configurable(self):
        """Test that mode and trigger_count are passed to the wrapper."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):
            with patch("random.choice", return_value="type_switch"):
                with patch("random.randint", return_value=99):
                    mutator = UnpackingChaosMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have the configured mode and trigger
        self.assertIn("mode='type_switch'", result)
        self.assertIn("trigger_count=99", result)

    def test_helper_tracks_call_count(self):
        """Test that helper class tracks iteration call count."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should track call count
        self.assertIn("self._call_count", result)
        self.assertIn("self._call_count += 1", result)
        self.assertIn("self._call_count > self._trigger_count", result)

    def test_backing_store_mutate_mode(self):
        """Test that backing_store_mutate mode includes clear/extend/insert/pop."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # The class definition should include backing_store_mutate logic
        self.assertIn("backing_store_mutate", result)
        self.assertIn("_items.clear()", result)
        self.assertIn("_items.extend(", result)
        self.assertIn("_items.insert(", result)
        self.assertIn("_items.pop(", result)

    def test_exception_storm_mode(self):
        """Test that exception_storm mode raises different exception types."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = UnpackingChaosMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # The class definition should include exception_storm logic
        self.assertIn("exception_storm", result)
        self.assertIn("TypeError", result)
        self.assertIn("ValueError", result)

    def test_backing_store_mutate_can_be_selected(self):
        """Test that backing_store_mutate mode can be selected for wrapping."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):
            with patch("random.choice", return_value="backing_store_mutate"):
                with patch("random.randint", return_value=50):
                    mutator = UnpackingChaosMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_JitChaosIterator([1, 2]", result)
        self.assertIn("mode='backing_store_mutate'", result)

    def test_exception_storm_can_be_selected(self):
        """Test that exception_storm mode can be selected for wrapping."""
        code = dedent("""
            def test_func():
                a, b = [1, 2]
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.1]):
            with patch("random.choice", return_value="exception_storm"):
                with patch("random.randint", return_value=50):
                    mutator = UnpackingChaosMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_JitChaosIterator([1, 2]", result)
        self.assertIn("mode='exception_storm'", result)


class TestConstantNarrowingPoisonMutator(unittest.TestCase):
    """Test ConstantNarrowingPoisonMutator mutator."""

    def setUp(self):
        random.seed(42)

    def test_injects_lying_eq(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="lying_eq"):
                with patch("random.randint", return_value=5000):
                    mutator = ConstantNarrowingPoisonMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_LyingInt_cnarrow_5000", result)
        self.assertIn("__eq__", result)

    def test_injects_int_subclass_extra_state(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="int_subclass_extra_state"):
                with patch("random.randint", return_value=6000):
                    mutator = ConstantNarrowingPoisonMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_RichInt_cnarrow_6000", result)
        self.assertIn("tag", result)

    def test_injects_float_nan_paradox(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="float_nan_paradox"):
                with patch("random.randint", return_value=7000):
                    mutator = ConstantNarrowingPoisonMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("nan", result)
        self.assertIn("inf", result)
        self.assertIn("copysign", result)

    def test_injects_mutable_constant(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="mutable_constant"):
                with patch("random.randint", return_value=8000):
                    mutator = ConstantNarrowingPoisonMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_Shifty_cnarrow_8000", result)
        self.assertIn("_cmp_count", result)

    def test_all_attacks_produce_valid_code(self):
        for attack in ConstantNarrowingPoisonMutator.ATTACK_SCENARIOS:
            with self.subTest(attack=attack):
                code = dedent("""
                    def uop_harness_test():
                        x = 1
                """)
                tree = ast.parse(code)
                with patch("random.random", return_value=0.05):
                    with patch("random.choice", return_value=attack):
                        with patch("random.randint", return_value=4000):
                            mutator = ConstantNarrowingPoisonMutator()
                            mutated = mutator.visit(tree)
                result = ast.unparse(mutated)
                ast.parse(result)
                compile(result, "<test>", "exec")

    def test_skips_non_harness(self):
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)
        with patch("random.random", return_value=0.05):
            mutator = ConstantNarrowingPoisonMutator()
            mutated = mutator.visit(tree)
        self.assertEqual(original, ast.unparse(mutated))

    def test_respects_probability(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)
        with patch("random.random", return_value=0.9):
            mutator = ConstantNarrowingPoisonMutator()
            mutated = mutator.visit(tree)
        self.assertEqual(original, ast.unparse(mutated))


class TestStarCallMutator(unittest.TestCase):
    """Test StarCallMutator mutator."""

    def setUp(self):
        random.seed(42)

    def test_injects_args_type_instability(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="args_type_instability"):
                with patch("random.randint", return_value=5000):
                    mutator = StarCallMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_target_starcall_5000", result)
        self.assertIn("*_args_starcall_5000", result)

    def test_injects_custom_mapping_kwargs(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="custom_mapping_kwargs"):
                with patch("random.randint", return_value=6000):
                    mutator = StarCallMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_EvilKwargs_starcall_6000", result)
        self.assertIn("Mapping", result)

    def test_injects_nested_star_delegation(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="nested_star_delegation"):
                with patch("random.randint", return_value=7000):
                    mutator = StarCallMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_inner_starcall_7000", result)
        self.assertIn("_middle_starcall_7000", result)
        self.assertIn("_outer_starcall_7000", result)

    def test_all_attacks_produce_valid_code(self):
        for attack in StarCallMutator.ATTACK_SCENARIOS:
            with self.subTest(attack=attack):
                code = dedent("""
                    def uop_harness_test():
                        x = 1
                """)
                tree = ast.parse(code)
                with patch("random.random", return_value=0.05):
                    with patch("random.choice", return_value=attack):
                        with patch("random.randint", return_value=4000):
                            mutator = StarCallMutator()
                            mutated = mutator.visit(tree)
                result = ast.unparse(mutated)
                ast.parse(result)
                compile(result, "<test>", "exec")

    def test_skips_non_harness(self):
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)
        with patch("random.random", return_value=0.05):
            mutator = StarCallMutator()
            mutated = mutator.visit(tree)
        self.assertEqual(original, ast.unparse(mutated))

    def test_respects_probability(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)
        with patch("random.random", return_value=0.9):
            mutator = StarCallMutator()
            mutated = mutator.visit(tree)
        self.assertEqual(original, ast.unparse(mutated))


class TestSliceObjectChaosMutator(unittest.TestCase):
    """Test SliceObjectChaosMutator mutator."""

    def setUp(self):
        random.seed(42)

    def test_injects_slice_to_int_swap(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="slice_to_int_swap"):
                with patch("random.randint", return_value=5000):
                    mutator = SliceObjectChaosMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("slice(", result)
        self.assertIn("_lst_slchaos_5000", result)

    def test_injects_guard_elimination_violation(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="guard_elimination_violation"):
                with patch("random.randint", return_value=6000):
                    mutator = SliceObjectChaosMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_double_access_slchaos_6000", result)

    def test_injects_nested_slice(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="nested_slice"):
                with patch("random.randint", return_value=7000):
                    mutator = SliceObjectChaosMutator()
                    mutated = mutator.visit(tree)
        result = ast.unparse(mutated)
        self.assertIn("_s1_slchaos_7000", result)
        self.assertIn("_s2_slchaos_7000", result)

    def test_all_attacks_produce_valid_code(self):
        for attack in SliceObjectChaosMutator.ATTACK_SCENARIOS:
            with self.subTest(attack=attack):
                code = dedent("""
                    def uop_harness_test():
                        x = 1
                """)
                tree = ast.parse(code)
                with patch("random.random", return_value=0.05):
                    with patch("random.choice", return_value=attack):
                        with patch("random.randint", return_value=4000):
                            mutator = SliceObjectChaosMutator()
                            mutated = mutator.visit(tree)
                result = ast.unparse(mutated)
                ast.parse(result)
                compile(result, "<test>", "exec")

    def test_skips_non_harness(self):
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)
        with patch("random.random", return_value=0.05):
            mutator = SliceObjectChaosMutator()
            mutated = mutator.visit(tree)
        self.assertEqual(original, ast.unparse(mutated))

    def test_respects_probability(self):
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)
        with patch("random.random", return_value=0.9):
            mutator = SliceObjectChaosMutator()
            mutated = mutator.visit(tree)
        self.assertEqual(original, ast.unparse(mutated))


if __name__ == "__main__":
    unittest.main(verbosity=2)
