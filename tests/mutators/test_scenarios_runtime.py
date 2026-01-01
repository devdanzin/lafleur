#!/usr/bin/env python3
"""
Tests for runtime manipulation mutators.

This module contains unit tests for runtime manipulation mutators defined in
lafleur/mutators/scenarios_runtime.py
"""

import ast
import random
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.scenarios_runtime import (
    FrameManipulator,
    GCInjector,
    GlobalInvalidator,
    SideEffectInjector,
    StressPatternInjector,
    WeakRefCallbackChaos,
    _create_class_reassignment_node,
    _create_dict_swap_node,
    _create_method_patch_node,
    _create_type_corruption_node,
    _create_uop_attribute_deletion_node,
)


class TestHelperFunctions(unittest.TestCase):
    """Test helper functions used by mutators."""

    def test_create_type_corruption_node(self):
        """Test type corruption node generation."""
        nodes = _create_type_corruption_node("test_var")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Assign)
        self.assertEqual(nodes[0].targets[0].id, "test_var")
        # Value should be one of the corruption values
        self.assertIsInstance(nodes[0].value, ast.Constant)

    def test_create_uop_attribute_deletion_node(self):
        """Test attribute deletion node generation."""
        nodes = _create_uop_attribute_deletion_node("test_obj")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Delete)
        self.assertIsInstance(nodes[0].targets[0], ast.Attribute)
        self.assertEqual(nodes[0].targets[0].value.id, "test_obj")

    def test_create_method_patch_node(self):
        """Test method patching node generation."""
        nodes = _create_method_patch_node("test_obj")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Assign)
        self.assertIsInstance(nodes[0].value, ast.Lambda)

    def test_create_dict_swap_node(self):
        """Test dict swap node generation."""
        nodes = _create_dict_swap_node("obj1", "obj2")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Assign)
        # Check it's a tuple assignment
        self.assertIsInstance(nodes[0].targets[0], ast.Tuple)
        self.assertEqual(len(nodes[0].targets[0].elts), 2)

    def test_create_class_reassignment_node(self):
        """Test class reassignment node generation."""
        nodes = _create_class_reassignment_node("test_obj")
        self.assertEqual(len(nodes), 2)
        self.assertIsInstance(nodes[0], ast.ClassDef)
        self.assertIsInstance(nodes[1], ast.Assign)


class TestStressPatternInjector(unittest.TestCase):
    """Test StressPatternInjector mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_stress_pattern_injector(self):
        """Test StressPatternInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                return x + y
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", side_effect=lambda x: x[0]):
                mutator = StressPatternInjector()
                mutated = mutator.visit(tree)

        # Should have injected stress pattern
        func = mutated.body[0]
        self.assertIsInstance(func, ast.FunctionDef)
        # Body should have more statements
        self.assertGreater(len(func.body), 3)

    def test_stress_pattern_injector_no_vars(self):
        """Test StressPatternInjector with no local variables."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StressPatternInjector()
            mutated = mutator.visit(tree)

        # Should handle gracefully
        self.assertIsInstance(mutated, ast.Module)


class TestSideEffectInjector(unittest.TestCase):
    """Test SideEffectInjector mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_side_effect_injector(self):
        """Test SideEffectInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", side_effect=lambda x: x[0] if isinstance(x, list) else x):
                mutator = SideEffectInjector()
                mutated = mutator.visit(tree)

        # Should have injected __del__ side effect
        func = mutated.body[0]
        # Look for FrameModifier class
        has_frame_modifier = any(
            isinstance(stmt, ast.ClassDef) and "FrameModifier" in stmt.name for stmt in func.body
        )
        self.assertTrue(has_frame_modifier)


class TestGlobalInvalidator(unittest.TestCase):
    """Test GlobalInvalidator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_global_invalidator(self):
        """Test GlobalInvalidator mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", side_effect=[0, 12345]):
                mutator = GlobalInvalidator()
                mutated = mutator.visit(tree)

        # Should have injected globals() assignment
        func = mutated.body[0]
        # Look for globals() call
        has_globals = any(
            isinstance(stmt, ast.Assign)
            and isinstance(stmt.targets[0], ast.Subscript)
            and isinstance(stmt.targets[0].value, ast.Call)
            and isinstance(stmt.targets[0].value.func, ast.Name)
            and stmt.targets[0].value.func.id == "globals"
            for stmt in func.body
        )
        self.assertTrue(has_globals)


class TestGCInjector(unittest.TestCase):
    """Test GCInjector mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_gc_injector(self):
        """Test GCInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choices", return_value=[1]):
                mutator = GCInjector()
                mutated = mutator.visit(tree)

        # Should have injected import gc and gc.set_threshold
        func = mutated.body[0]
        self.assertIsInstance(func.body[0], ast.Import)
        self.assertEqual(func.body[0].names[0].name, "gc")
        self.assertIsInstance(func.body[1], ast.Expr)

    def test_gc_injector_output(self):
        """Test GCInjector produces correct code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choices", return_value=[10]):
                mutator = GCInjector()
                mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        self.assertIn("import gc", output)
        self.assertIn("gc.set_threshold(10)", output)


class TestFrameManipulator(unittest.TestCase):
    """Test FrameManipulator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_evil_frame_modifier_function(self):
        """Test that evil frame modifier function is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.choice", return_value="x"):
                with patch("random.randint", return_value=5000):
                    mutator = FrameManipulator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have evil modifier function
        self.assertIn("evil_modifier_frame_5000", result)
        self.assertIn("def evil_modifier_frame_5000():", result)

    def test_uses_sys_getframe_for_manipulation(self):
        """Test that sys._getframe is used for frame manipulation."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="x"):
                mutator = FrameManipulator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should use sys._getframe(1) to get caller frame
        self.assertIn("sys._getframe(1)", result)
        self.assertIn("caller_frame", result)
        self.assertIn("f_locals", result)

    def test_targets_specific_variable(self):
        """Test that a specific variable is targeted for corruption."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="y"):
                mutator = FrameManipulator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should target variable 'y'
        self.assertIn("'y'", result)
        self.assertIn("corrupted_by_frame_manipulation", result)

    def test_includes_hot_loop_to_trigger_corruption(self):
        """Test that a hot loop triggers the frame corruption."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="x"):
                with patch("random.randint", return_value=6000):
                    mutator = FrameManipulator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have hot loop calling evil function
        self.assertIn("for _ in range(50):", result)
        self.assertIn("evil_modifier_frame_6000()", result)

    def test_includes_guarded_usage_after_corruption(self):
        """Test that corrupted variable is used with error handling."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="x"):
                mutator = FrameManipulator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should try to use corrupted variable
        self.assertIn("try:", result)
        self.assertIn("_ = x + 1", result)
        self.assertIn("except TypeError:", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = FrameManipulator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_skips_functions_with_too_few_statements(self):
        """Test that functions with <3 statements are skipped."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = FrameManipulator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be unchanged (too few statements)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.15 threshold
            mutator = FrameManipulator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_handles_functions_without_variables(self):
        """Test handling of functions without assignable variables."""
        code = dedent("""
            def uop_harness_test():
                pass
                pass
                pass
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = FrameManipulator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be unchanged (no variables to target)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = FrameManipulator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_function_names(self):
        """Test that unique function names are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="x"):
                with patch("random.randint", return_value=7000):
                    mutator = FrameManipulator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("frame_7000", result)
        self.assertIn("evil_modifier_frame_7000", result)

    def test_preserves_original_function_body(self):
        """Test that original function statements are preserved."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)
        original_statements = ["x = 1", "y = 2", "z = 3"]

        with patch("random.random", return_value=0.1):
            mutator = FrameManipulator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Original statements should still be present
        for stmt in original_statements:
            self.assertIn(stmt, result)

    def test_error_handling_in_frame_modifier(self):
        """Test that frame modifier has error handling."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = FrameManipulator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except in the evil function
        self.assertIn("except (ValueError, KeyError):", result)


class TestWeakRefCallbackChaos(unittest.TestCase):
    """Test WeakRefCallbackChaos mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_weakref_callback_scenario(self):
        """Test that weakref callback scenario is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", return_value=8000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have weakref callback setup
        self.assertIn("evil_callback_gc_8000", result)
        self.assertIn("TargetObject_gc_8000", result)

    def test_imports_required_modules(self):
        """Test that gc and weakref modules are imported."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = WeakRefCallbackChaos()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should import required modules
        self.assertIn("import gc", result)
        self.assertIn("import weakref", result)

    def test_creates_target_object_class(self):
        """Test that target object class is created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=9000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have target object class
        self.assertIn("class TargetObject_gc_9000", result)
        self.assertIn("pass", result)

    def test_creates_callback_function(self):
        """Test that callback function is created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=1000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have callback function
        self.assertIn("def evil_callback_gc_1000", result)
        self.assertIn("globals()", result)
        self.assertIn("modified_by_gc", result)

    def test_creates_global_variable_and_weakref(self):
        """Test that global variable and weakref are created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=2000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should create global variable
        self.assertIn("gc_var_gc_2000 = 100", result)
        # Should create weakref with callback
        self.assertIn("weakref.ref", result)
        self.assertIn("target_obj_gc_2000", result)

    def test_includes_warmup_loop(self):
        """Test that warmup loop is included to encourage JIT specialization."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=3000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have warmup loop
        self.assertIn("for i in range(100):", result)
        self.assertIn("gc_var_gc_3000 + i", result)

    def test_deletes_object_and_triggers_gc(self):
        """Test that object is deleted and gc is triggered."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should delete object
        self.assertIn("del target_obj_gc_4000", result)
        # Should trigger gc multiple times
        self.assertIn("gc.collect()", result)
        self.assertIn("for _ in range(3):", result)

    def test_includes_guarded_usage_after_gc(self):
        """Test that corrupted global is used with error handling."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should try to use corrupted global
        self.assertIn("try:", result)
        self.assertIn("gc_var_gc_5000 + 1", result)
        self.assertIn("except TypeError:", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = WeakRefCallbackChaos()
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
            mutator = WeakRefCallbackChaos()
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
            mutator = WeakRefCallbackChaos()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_variable_and_class_names(self):
        """Test that unique names are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("gc_6000", result)
        self.assertIn("TargetObject_gc_6000", result)
        self.assertIn("evil_callback_gc_6000", result)
        self.assertIn("target_obj_gc_6000", result)
        self.assertIn("gc_var_gc_6000", result)

    def test_preserves_original_function_body(self):
        """Test that original function statements are preserved."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)
        original_statements = ["x = 1", "y = 2"]

        with patch("random.random", return_value=0.1):
            mutator = WeakRefCallbackChaos()
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
            mutator = WeakRefCallbackChaos()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_callback_uses_lambda_wrapper(self):
        """Test that callback is wrapped in lambda for var_name closure."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = WeakRefCallbackChaos()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should use lambda to wrap callback
        self.assertIn("lambda ref:", result)
        self.assertIn("evil_callback_gc_7000(ref, 'gc_var_gc_7000')", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
