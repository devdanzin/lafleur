#!/usr/bin/env python3
"""
Tests for type system mutators.

This module contains unit tests for type system mutators defined in
lafleur/mutators/scenarios_types.py
"""

import ast
import random
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.scenarios_types import (
    CodeObjectSwapper,
    DescriptorChaosGenerator,
    FunctionPatcher,
    InlineCachePolluter,
    LoadAttrPolluter,
    MROShuffler,
    ManyVarsInjector,
    SuperResolutionAttacker,
    TypeInstabilityInjector,
    TypeIntrospectionMutator,
)
from lafleur.mutators.utils import FuzzerSetupNormalizer


class TestTypeInstabilityInjector(unittest.TestCase):
    """Test TypeInstabilityInjector mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_type_instability_injector(self):
        """Test TypeInstabilityInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                for i in range(100):
                    x = i * 2
                    y = x + 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", side_effect=lambda x: x[0] if isinstance(x, list) else x):
                mutator = TypeInstabilityInjector()
                mutated = mutator.visit(tree)

        # Should have wrapped loop body in try/except
        func = mutated.body[0]
        loop = func.body[0]
        self.assertIsInstance(loop.body[0], ast.Try)

    def test_type_instability_with_no_loop_var(self):
        """Test TypeInstabilityInjector with tuple target."""
        code = dedent("""
            def uop_harness_test():
                for a, b in [(1, 2)]:
                    x = a + b
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = TypeInstabilityInjector()
            mutated = mutator.visit(tree)

        # Should not crash, should return unchanged
        self.assertIsInstance(mutated, ast.Module)


class TestInlineCachePolluter(unittest.TestCase):
    """Test InlineCachePolluter mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_inline_cache_polluter(self):
        """Test InlineCachePolluter mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = InlineCachePolluter()
            mutated = mutator.visit(tree)

        # Should have injected polluter classes
        func = mutated.body[0]
        # Check for class definitions
        has_class = any(isinstance(stmt, ast.ClassDef) for stmt in func.body)
        self.assertTrue(has_class)


class TestLoadAttrPolluter(unittest.TestCase):
    """Test LoadAttrPolluter mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_load_attr_polluter(self):
        """Test LoadAttrPolluter mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = LoadAttrPolluter()
            mutated = mutator.visit(tree)

        # Should have injected LOAD_ATTR pollution scenario
        func = mutated.body[0]
        # Look for ShapeA/B/C/D classes
        class_names = [stmt.name for stmt in func.body if isinstance(stmt, ast.ClassDef)]
        shape_classes = [name for name in class_names if "ShapeA_" in name or "ShapeB_" in name]
        self.assertGreater(len(shape_classes), 0)

        # Should have loop accessing payload attribute
        code_str = ast.unparse(func)
        self.assertIn("payload", code_str)
        self.assertIn("obj.payload", code_str)


class TestManyVarsInjector(unittest.TestCase):
    """Test ManyVarsInjector mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_many_vars_injector(self):
        """Test ManyVarsInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.03):
            with patch("random.randint", return_value=1234):
                mutator = ManyVarsInjector()
                mutated = mutator.visit(tree)

        # Should have injected many variables
        func = mutated.body[0]
        # Count variable assignments
        var_assigns = [stmt for stmt in func.body if isinstance(stmt, ast.Assign)]
        # Should have at least 260 new variables plus the original
        self.assertGreater(len(var_assigns), 260)

        # Check variable naming pattern
        code_str = ast.unparse(func)
        self.assertIn("mv_1234_0", code_str)
        self.assertIn("mv_1234_259", code_str)

    def test_many_vars_with_existing_vars(self):
        """Test ManyVarsInjector with existing variables."""
        code = dedent("""
            def uop_harness_test():
                existing_var_1 = 10
                existing_var_2 = 20
                return existing_var_1 + existing_var_2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.03):
            mutator = ManyVarsInjector()
            mutated = mutator.visit(tree)

        # Should preserve existing variables and add new ones
        func = mutated.body[0]
        # First assignments should be the many new variables
        # Last statements should be the original code
        self.assertEqual(func.body[-2].targets[0].id, "existing_var_2")
        self.assertIsInstance(func.body[-1], ast.Return)


class TestTypeIntrospectionMutator(unittest.TestCase):
    """Test TypeIntrospectionMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_type_introspection_mutator(self):
        """Test TypeIntrospectionMutator mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                if isinstance(x, int):
                    y = 2
                if hasattr(x, 'foo'):
                    z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", side_effect=lambda x: x[0] if isinstance(x, list) else x):
                mutator = TypeIntrospectionMutator()
                mutated = mutator.visit(tree)

        # Should have injected attack scenario
        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should contain either isinstance or hasattr attack
        has_isinstance_attack = "isinstance attack" in code_str or "poly_isinstance" in code_str
        has_hasattr_attack = "hasattr" in code_str and "fuzzer_attr" in code_str
        self.assertTrue(has_isinstance_attack or has_hasattr_attack)

    def test_type_introspection_with_normalizer(self):
        """Test TypeIntrospectionMutator with FuzzerSetupNormalizer."""
        code = dedent("""
            import random

            def uop_harness_test():
                if random() > 0.1:
                    if isinstance(x, float):
                        return True
        """)

        # First normalize
        tree = ast.parse(code)
        normalizer = FuzzerSetupNormalizer()
        normalized = normalizer.visit(tree)

        # Verify normalization
        code_before_mutation = ast.unparse(normalized)
        self.assertIn("fuzzer_rng.random()", code_before_mutation)

        # The test was checking for fuzzer_rng.random after mutation,
        # but the mutator prepends attack code. The original normalized
        # code is still there, just later in the function.
        with patch("random.random", return_value=0.1):
            mutator = TypeIntrospectionMutator()
            mutated = mutator.visit(normalized)

        code_str = ast.unparse(mutated)
        # The normalized call is still there, just after the attack
        self.assertIn("fuzzer_rng.random()", code_str)

    def test_type_introspection_polymorphic_output(self):
        """Test TypeIntrospectionMutator polymorphic attack output."""
        code = dedent("""
            def uop_harness_test():
                if isinstance(x, str):
                    pass
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.3]):  # Force polymorphic attack
            mutator = TypeIntrospectionMutator()
            mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        # Should contain polymorphic list and isinstance with str
        self.assertIn("_poly_list = [1, 'a', 3.0, [], (), {}, True, b'bytes']", output)
        self.assertIn("isinstance(poly_variable, str)", output)


class TestFunctionPatcher(unittest.TestCase):
    """Test FunctionPatcher mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_function_patcher(self):
        """Test FunctionPatcher mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", side_effect=lambda x: x[0]):
                mutator = FunctionPatcher()
                mutated = mutator.visit(tree)

        # Should have injected function patching scenario
        func = mutated.body[0]
        # Look for victim_func definition
        has_victim_func = any(
            isinstance(stmt, ast.FunctionDef) and "victim_func" in stmt.name for stmt in func.body
        )
        self.assertTrue(has_victim_func)


class TestDescriptorChaosGenerator(unittest.TestCase):
    """Test DescriptorChaosGenerator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_evil_descriptor_class(self):
        """Test that EvilDescriptor class is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", return_value=1000):
                mutator = DescriptorChaosGenerator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have EvilDescriptor class
        self.assertIn("class EvilDescriptor_chaos_1000", result)
        self.assertIn("def __get__", result)
        self.assertIn("self.count", result)

    def test_descriptor_cycles_through_types(self):
        """Test that descriptor __get__ cycles through different return types."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=2000):
                mutator = DescriptorChaosGenerator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have multiple return types in descriptor
        self.assertIn("type_options = [42, 'a_string', 3.14, None, [1, 2, 3]]", result)
        self.assertIn("return type_options[index]", result)

    def test_creates_target_class_with_descriptor(self):
        """Test that TargetClass is created with descriptor attribute."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=3000):
                mutator = DescriptorChaosGenerator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have TargetClass with descriptor
        self.assertIn("class TargetClass_chaos_3000", result)
        self.assertIn("chaos_attr = EvilDescriptor_chaos_3000()", result)

    def test_includes_hot_loop_for_descriptor_access(self):
        """Test that hot loop accesses descriptor repeatedly."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = DescriptorChaosGenerator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have hot loop accessing descriptor
        self.assertIn("for i in range(100):", result)
        self.assertIn("target_obj_chaos_4000.chaos_attr", result)

    def test_wraps_access_in_try_except(self):
        """Test that descriptor accesses are wrapped in try/except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = DescriptorChaosGenerator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except wrapper
        self.assertIn("try:", result)
        self.assertIn("except Exception:", result)
        self.assertIn("pass", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = DescriptorChaosGenerator()
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
            mutator = DescriptorChaosGenerator()
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
            mutator = DescriptorChaosGenerator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_class_names(self):
        """Test that unique class names are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = DescriptorChaosGenerator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("chaos_7000", result)
        self.assertIn("EvilDescriptor_chaos_7000", result)
        self.assertIn("TargetClass_chaos_7000", result)

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
            mutator = DescriptorChaosGenerator()
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
            mutator = DescriptorChaosGenerator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestMROShuffler(unittest.TestCase):
    """Test MROShuffler mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_creates_base_classes_with_conflicting_methods(self):
        """Test that two base classes with conflicting methods are created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", return_value=1000):
                mutator = MROShuffler()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have two base classes
        self.assertIn("class Base1_mro_1000", result)
        self.assertIn("class Base2_mro_1000", result)
        # Both should have method
        self.assertGreaterEqual(result.count("def method"), 2)

    def test_base_classes_return_different_values(self):
        """Test that base classes return different values from same method."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=2000):
                mutator = MROShuffler()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Base1 returns integer, Base2 returns string
        self.assertIn("return 1", result)
        self.assertIn("return 'two'", result)

    def test_creates_subclass_inheriting_both_bases(self):
        """Test that subclass inherits from both base classes."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=3000):
                mutator = MROShuffler()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have subclass with both bases
        self.assertIn("class Evil_mro_3000(Base1_mro_3000, Base2_mro_3000)", result)

    def test_includes_warmup_loop(self):
        """Test that warmup loop is included to stabilize type."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = MROShuffler()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have warmup loop
        self.assertIn("for _ in range(100):", result)
        self.assertIn("evil_obj_mro_4000.method()", result)

    def test_shuffles_bases_tuple(self):
        """Test that __bases__ is shuffled to reverse MRO."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                mutator = MROShuffler()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should shuffle __bases__
        self.assertIn("Evil_mro_5000.__bases__", result)
        self.assertIn("= (Base2_mro_5000, Base1_mro_5000)", result)

    def test_triggers_method_call_after_shuffle(self):
        """Test that method is called after MRO shuffle."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = MROShuffler()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should call method after shuffle
        self.assertIn("_ = evil_obj_mro_6000.method()", result)

    def test_wraps_in_try_except(self):
        """Test that scenario is wrapped in try/except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = MROShuffler()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except wrapper
        self.assertIn("try:", result)
        self.assertIn("except Exception:", result)
        self.assertIn("pass", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = MROShuffler()
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
            mutator = MROShuffler()
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
            mutator = MROShuffler()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_class_names(self):
        """Test that unique class names are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=8000):
                mutator = MROShuffler()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("mro_8000", result)
        self.assertIn("Base1_mro_8000", result)
        self.assertIn("Base2_mro_8000", result)
        self.assertIn("Evil_mro_8000", result)

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
            mutator = MROShuffler()
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
            mutator = MROShuffler()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestSuperResolutionAttacker(unittest.TestCase):
    """Test SuperResolutionAttacker mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_creates_hierarchy_with_super_calls(self):
        """Test that class hierarchy with super() calls is created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", return_value=1000):
                mutator = SuperResolutionAttacker()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have class hierarchy
        self.assertIn("class Base_super_1000", result)
        self.assertIn("class Sub_super_1000", result)
        # Should have super() calls
        self.assertIn("super()", result)

    def test_method_modifies_mro_internally(self):
        """Test that method modifies its own class's MRO."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=2000):
                mutator = SuperResolutionAttacker()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should modify __bases__ inside method
        self.assertIn("Sub_super_2000.__bases__", result)
        self.assertIn("= (object,)", result)

    def test_includes_three_phase_attack(self):
        """Test that three-phase attack is present (warmup, shuffle, stress)."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=3000):
                mutator = SuperResolutionAttacker()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Phase 1: Warmup
        self.assertIn("for _ in range(300):", result)
        # Phase 2: Shuffle
        self.assertIn("Sub_super_3000.__bases__ = (object,)", result)
        # Phase 3: Stress loop
        self.assertIn("for _ in range(100):", result)

    def test_calls_super_before_and_after_shuffle(self):
        """Test that super() is called in the method."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = SuperResolutionAttacker()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Method should call super() multiple times
        self.assertGreaterEqual(result.count("super()"), 2)

    def test_includes_stress_loop(self):
        """Test that stress loop repeatedly calls method."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                mutator = SuperResolutionAttacker()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have stress loop calling method
        self.assertIn("for _ in range(100):", result)
        self.assertIn("instance_super_5000.f()", result)

    def test_wraps_in_try_except(self):
        """Test that scenario is wrapped in try/except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = SuperResolutionAttacker()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except wrapper
        self.assertIn("try:", result)
        self.assertIn("except", result)
        self.assertIn("pass", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = SuperResolutionAttacker()
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
            mutator = SuperResolutionAttacker()
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
            mutator = SuperResolutionAttacker()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_class_names(self):
        """Test that unique class names are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=9000):
                mutator = SuperResolutionAttacker()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("super_9000", result)
        self.assertIn("Base_super_9000", result)
        self.assertIn("Sub_super_9000", result)

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
            mutator = SuperResolutionAttacker()
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
            mutator = SuperResolutionAttacker()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestCodeObjectSwapper(unittest.TestCase):
    """Test CodeObjectSwapper mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_creates_two_functions_with_different_returns(self):
        """Test that two functions with different return types are created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", return_value=1000):
                mutator = CodeObjectSwapper()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have two functions
        self.assertIn("def original_code_1000():", result)
        self.assertIn("def replacement_code_1000():", result)
        # Should have different return types
        self.assertIn("return 1", result)
        self.assertIn("return 'a_string'", result)

    def test_includes_warmup_loop(self):
        """Test that warmup loop specializes on integer return."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=2000):
                mutator = CodeObjectSwapper()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have warmup loop
        self.assertIn("for i in range(100):", result)
        self.assertIn("res = original_code_2000()", result)

    def test_swaps_code_objects(self):
        """Test that __code__ objects are swapped."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=3000):
                mutator = CodeObjectSwapper()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should swap __code__ attributes
        self.assertIn("original_code_3000.__code__", result)
        self.assertIn("replacement_code_3000.__code__", result)

    def test_triggers_call_after_swap(self):
        """Test that function is called after code swap."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = CodeObjectSwapper()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should call function after swap
        self.assertIn("res = original_code_4000()", result)
        # Should have trigger loop
        self.assertIn("for _ in range(100):", result)

    def test_wraps_in_try_except(self):
        """Test that scenario is wrapped in try/except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except wrapper
        self.assertIn("try:", result)
        self.assertIn("except", result)
        self.assertIn("pass", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = CodeObjectSwapper()
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
            mutator = CodeObjectSwapper()
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
            mutator = CodeObjectSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_function_names(self):
        """Test that unique function names are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = CodeObjectSwapper()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("code_7000", result)
        self.assertIn("original_code_7000", result)
        self.assertIn("replacement_code_7000", result)

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
            mutator = CodeObjectSwapper()
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
            mutator = CodeObjectSwapper()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


if __name__ == "__main__":
    unittest.main(verbosity=2)
