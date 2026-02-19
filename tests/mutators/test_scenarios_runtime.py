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
    ClosureStompMutator,
    EvalFrameHookMutator,
    FrameManipulator,
    GCInjector,
    GlobalInvalidator,
    RareEventStressTester,
    RefcountEscapeHatchMutator,
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
        """Test StressPatternInjector wraps snippets in try/except."""
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

        # Should have injected stress pattern wrapped in try/except
        func = mutated.body[0]
        self.assertIsInstance(func, ast.FunctionDef)
        # Find the Try node in the function body
        try_nodes = [n for n in func.body if isinstance(n, ast.Try)]
        self.assertGreater(len(try_nodes), 0, "Stress pattern should be wrapped in try/except")

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

    def test_side_effect_injector_catches_name_error(self):
        """Test that the hot loop handles UnboundLocalError from early injection."""
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

        result = ast.unparse(mutated)
        # The except clause should catch NameError (for UnboundLocalError)
        self.assertIn("NameError", result)


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
        self.assertIn("except (TypeError, NameError):", result)

    def test_frame_manipulator_catches_name_error(self):
        """Test that the attack scenario handles UnboundLocalError."""
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
        self.assertIn("except (TypeError, NameError)", result)

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
        """Test that global variable and weakref are created with global declaration."""
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
        # Should declare the variable as global
        self.assertIn("global gc_var_gc_2000", result)
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


class TestClosureStompMutator(unittest.TestCase):
    """Test ClosureStompMutator."""

    def setUp(self):
        """Set random seed."""
        random.seed(42)

    def test_closure_stomp_injection(self):
        """Test that the closure stomper is injected."""
        code = dedent("""
            def outer():
                x = 1
                def inner():
                    return x
        """)
        tree = ast.parse(code)

        # Force mutation (threshold is <= 0.15)
        with patch("random.random", return_value=0.1):
            mutator = ClosureStompMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)

        # Should have helper function
        self.assertIn("def _jit_stomp_closure(target_func):", result)
        # Should have call to helper
        self.assertIn("_jit_stomp_closure(outer)", result)
        # Should contain chaos values
        self.assertIn("CHAOS_STR", result)

    def test_closure_stomp_probability(self):
        """Test that mutation respects probability."""
        code = dedent("""
            def outer():
                pass
        """)
        tree = ast.parse(code)

        # Force NO mutation (threshold is > 0.15)
        with patch("random.random", return_value=0.2):
            mutator = ClosureStompMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertNotIn("_jit_stomp_closure", result)

    def test_closure_stomp_valid_python(self):
        """Test that generated code is valid Python."""
        code = dedent("""
            def outer():
                x = 1
                def inner():
                    return x
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ClosureStompMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        ast.parse(result)  # Should not raise SyntaxError

    def test_closure_stomp_multiple_functions(self):
        """Test injection for multiple functions."""
        code = dedent("""
            def f1():
                pass
            def f2():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ClosureStompMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_jit_stomp_closure(f1)", result)
        self.assertIn("_jit_stomp_closure(f2)", result)

    def test_closure_stomp_harness_skip(self):
        """Test that the harness function itself is skipped (returns FunctionDef, not list)."""
        code = dedent("""
            def uop_harness_test():
                def inner():
                    pass
        """)
        # Parse and get the FunctionDef node directly, mimicking MutationController
        tree = ast.parse(code).body[0]
        self.assertIsInstance(tree, ast.FunctionDef)

        with patch("random.random", return_value=0.1):
            mutator = ClosureStompMutator()
            mutated_node = mutator.visit(tree)

        # The root result must remain a FunctionDef
        self.assertIsInstance(mutated_node, ast.FunctionDef)
        self.assertEqual(mutated_node.name, "uop_harness_test")

        # But the inner function SHOULD be mutated (check body)
        inner_func_found = False
        stomp_found = False
        for node in mutated_node.body:
            if isinstance(node, ast.FunctionDef) and node.name == "inner":
                inner_func_found = True
            if isinstance(node, ast.Expr) and "jit_stomp_closure" in ast.unparse(node):
                stomp_found = True

        self.assertTrue(inner_func_found)
        self.assertTrue(stomp_found)

    def test_closure_stomp_skips_helper(self):
        """Test that the helper function itself is not recursively stomped."""
        code = dedent("""
            def _jit_stomp_closure(target_func):
                pass
        """)
        tree = ast.parse(code)

        # Force mutation if logic were not skipping
        with patch("random.random", return_value=0.1):
            mutator = ClosureStompMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should NOT contain a recursive call to _jit_stomp_closure(_jit_stomp_closure)
        # If it mutated, it would look like:
        # def _jit_stomp_closure(...): ...
        # def _jit_stomp_closure(...): ... # redefined
        # _jit_stomp_closure(_jit_stomp_closure)

        # We check by counting occurrences of the function name or call
        # Or simpler: checking that the result is identical to input (modulo formatting)
        # But AST roundtrip changes formatting.

        # Check that we don't have the call pattern
        self.assertNotIn("_jit_stomp_closure(_jit_stomp_closure)", result)

        # Also ensure we didn't inject the body of the helper again
        # The helper body has "CHAOS_STR"
        if "CHAOS_STR" not in code:
            self.assertNotIn("CHAOS_STR", result)


class TestEvalFrameHookMutator(unittest.TestCase):
    """Test EvalFrameHookMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_eval_frame_attack(self):
        """Test that eval frame attack is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.choice", return_value="frame_record_toggle"):
                mutator = EvalFrameHookMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have eval frame attack code
        self.assertIn("_testinternalcapi", result)
        self.assertIn("set_eval_frame", result)

    def test_imports_required_modules(self):
        """Test that required modules are imported."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = EvalFrameHookMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should import test.support.import_helper
        self.assertIn("import_helper", result)
        self.assertIn("_testinternalcapi", result)

    def test_frame_record_toggle_attack(self):
        """Test frame_record_toggle attack scenario."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="frame_record_toggle"):
                mutator = EvalFrameHookMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have frame recording setup
        self.assertIn("set_eval_frame_record", result)
        self.assertIn("set_eval_frame_default", result)
        self.assertIn("frame_list_", result)

    def test_custom_eval_install_attack(self):
        """Test custom_eval_install attack scenario."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="custom_eval_install"):
                mutator = EvalFrameHookMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have custom eval installation
        self.assertIn("set_eval_frame_record", result)
        self.assertIn("set_eval_frame_default", result)
        self.assertIn("warmup_result_", result)

    def test_eval_default_cycle_attack(self):
        """Test eval_default_cycle attack scenario."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="eval_default_cycle"):
                mutator = EvalFrameHookMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have cycling attack
        self.assertIn("set_eval_frame_record", result)
        self.assertIn("set_eval_frame_default", result)
        self.assertIn("cycle_", result)

    def test_includes_warmup_loop(self):
        """Test that warmup loop is included."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = EvalFrameHookMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have warmup/execution loops
        self.assertIn("for", result)
        self.assertIn("range(", result)

    def test_includes_try_except_wrapper(self):
        """Test that try/except wrapper is included for safety."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = EvalFrameHookMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except for AttributeError and RuntimeError
        self.assertIn("try:", result)
        self.assertIn("except", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = EvalFrameHookMutator()
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
            mutator = EvalFrameHookMutator()
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
            mutator = EvalFrameHookMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_prefixes(self):
        """Test that unique prefixes are generated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7777):
                mutator = EvalFrameHookMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("eval_7777", result)

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
            mutator = EvalFrameHookMutator()
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
            mutator = EvalFrameHookMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_different_attack_types(self):
        """Test that all three attack types can be generated."""
        attack_types = ["frame_record_toggle", "custom_eval_install", "eval_default_cycle"]

        for attack_type in attack_types:
            with self.subTest(attack_type=attack_type):
                code = dedent("""
                    def uop_harness_test():
                        x = 1
                """)
                tree = ast.parse(code)

                with patch("random.random", return_value=0.1):
                    with patch("random.choice", return_value=attack_type):
                        mutator = EvalFrameHookMutator()
                        mutated = mutator.visit(tree)

                result = ast.unparse(mutated)
                # Should have attack-specific code
                self.assertIn("set_eval_frame", result)


class TestRareEventStressTester(unittest.TestCase):
    """Test RareEventStressTester meta-mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_has_rare_events_list(self):
        """Test that RARE_EVENTS list is defined."""
        mutator = RareEventStressTester()
        self.assertTrue(hasattr(mutator, "RARE_EVENTS"))
        self.assertGreater(len(mutator.RARE_EVENTS), 0)
        expected_events = [
            "set_class",
            "set_bases",
            "set_eval_frame",
            "builtin_dict",
            "func_modification",
        ]
        for event in expected_events:
            self.assertIn(event, mutator.RARE_EVENTS)

    def test_has_event_combinations(self):
        """Test that EVENT_COMBINATIONS list is defined."""
        mutator = RareEventStressTester()
        self.assertTrue(hasattr(mutator, "EVENT_COMBINATIONS"))
        self.assertGreater(len(mutator.EVENT_COMBINATIONS), 0)
        # Each combination should have at least 2 events
        for combo in mutator.EVENT_COMBINATIONS:
            self.assertGreaterEqual(len(combo), 2)

    def test_single_event_set_class(self):
        """Test single event attack: set_class."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # 0.05 < 0.08 triggers, 0.1 < 0.4 for single event
        with patch("random.random", side_effect=[0.05, 0.1]):
            with patch("random.choice", return_value="set_class"):
                with patch("random.randint", return_value=5000):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have set_class attack markers
        self.assertIn("rarestress_5000", result)
        self.assertIn("set_class stress test", result)
        self.assertIn("OriginalClass_rarestress_5000", result)
        self.assertIn("AlternateClass_rarestress_5000", result)
        self.assertIn("__class__", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_single_event_set_bases(self):
        """Test single event attack: set_bases."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.1]):
            with patch("random.choice", return_value="set_bases"):
                with patch("random.randint", return_value=6000):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have set_bases attack markers
        self.assertIn("rarestress_6000", result)
        self.assertIn("set_bases stress test", result)
        self.assertIn("BaseA_rarestress_6000", result)
        self.assertIn("BaseB_rarestress_6000", result)
        self.assertIn("__bases__", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_single_event_set_eval_frame(self):
        """Test single event attack: set_eval_frame."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.1]):
            with patch("random.choice", return_value="set_eval_frame"):
                with patch("random.randint", return_value=7000):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have set_eval_frame attack markers
        self.assertIn("rarestress_7000", result)
        self.assertIn("set_eval_frame stress test", result)
        self.assertIn("sys.settrace", result)
        self.assertIn("trace_func_rarestress_7000", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_single_event_builtin_dict(self):
        """Test single event attack: builtin_dict."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.1]):
            with patch("random.choice", return_value="builtin_dict"):
                with patch("random.randint", return_value=8000):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have builtin_dict attack markers
        self.assertIn("rarestress_8000", result)
        self.assertIn("builtin_dict stress test", result)
        self.assertIn("import builtins", result)
        self.assertIn("builtins.__dict__", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_single_event_func_modification(self):
        """Test single event attack: func_modification."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.1]):
            with patch("random.choice", return_value="func_modification"):
                with patch("random.randint", return_value=9000):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have func_modification attack markers
        self.assertIn("rarestress_9000", result)
        self.assertIn("func_modification stress test", result)
        self.assertIn("target_func_rarestress_9000", result)
        self.assertIn("__code__", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_combination_attack(self):
        """Test combination attack with multiple events."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # 0.05 < 0.08 triggers, 0.5 > 0.4 for combination
        with patch("random.random", side_effect=[0.05, 0.5]):
            with patch("random.choice", return_value=["set_class", "set_bases"]):
                with patch("random.randint", return_value=1234):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have combination attack markers
        self.assertIn("rarestress_1234", result)
        self.assertIn("Starting rare event combination attack", result)
        self.assertIn("Triggering set_class", result)
        self.assertIn("Triggering set_bases", result)
        self.assertIn("Verification phase", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_combination_attack_three_events(self):
        """Test combination attack with three events."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):
            with patch(
                "random.choice",
                return_value=["set_class", "builtin_dict", "func_modification"],
            ):
                with patch("random.randint", return_value=4321):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have all three event triggers
        self.assertIn("Triggering set_class", result)
        self.assertIn("Triggering builtin_dict", result)
        self.assertIn("Triggering func_modification", result)
        # Verify code is valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_no_mutation_when_random_fails(self):
        """Test that no mutation occurs when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.5):  # > 0.08 threshold
            mutator = RareEventStressTester()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.05):  # Would trigger
            mutator = RareEventStressTester()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_skips_empty_functions(self):
        """Test that empty functions are not mutated."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)
        # Remove the pass statement to create truly empty body
        tree.body[0].body = []

        with patch("random.random", return_value=0.05):  # Would trigger
            mutator = RareEventStressTester()
            mutated = mutator.visit(tree)

        # Should have been skipped due to empty body
        self.assertEqual(len(mutated.body[0].body), 0)

    def test_all_single_events_produce_valid_code(self):
        """Test that all single event types produce valid code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)

        for event in RareEventStressTester.RARE_EVENTS:
            with self.subTest(event=event):
                tree = ast.parse(code)
                with patch("random.random", side_effect=[0.05, 0.1]):
                    with patch("random.choice", return_value=event):
                        with patch("random.randint", return_value=1000):
                            mutator = RareEventStressTester()
                            mutated = mutator.visit(tree)

                result = ast.unparse(mutated)
                reparsed = ast.parse(result)
                self.assertIsInstance(reparsed, ast.Module)

    def test_all_combinations_produce_valid_code(self):
        """Test that all event combinations produce valid code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)

        for combo in RareEventStressTester.EVENT_COMBINATIONS:
            with self.subTest(combo=combo):
                tree = ast.parse(code)
                with patch("random.random", side_effect=[0.05, 0.5]):
                    with patch("random.choice", return_value=combo):
                        with patch("random.randint", return_value=2000):
                            mutator = RareEventStressTester()
                            mutated = mutator.visit(tree)

                result = ast.unparse(mutated)
                reparsed = ast.parse(result)
                self.assertIsInstance(reparsed, ast.Module)

    def test_combination_attack_cleans_up_trace(self):
        """Test that combination attacks with set_eval_frame include trace cleanup."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):
            with patch("random.choice", return_value=["set_eval_frame", "func_modification"]):
                with patch("random.randint", return_value=3333):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have trace cleanup
        self.assertIn("sys.settrace(None)", result)
        # The settrace(None) for cleanup should appear AFTER the event triggers
        trigger_idx = result.index("Triggering set_eval_frame")
        cleanup_idx = result.rindex("settrace(None)")
        self.assertGreater(cleanup_idx, trigger_idx)

    def test_combination_attack_cleans_up_builtins(self):
        """Test that combination attacks with builtin_dict include builtins cleanup."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):
            with patch("random.choice", return_value=["set_class", "builtin_dict"]):
                with patch("random.randint", return_value=4444):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have builtins cleanup
        self.assertIn("RARE_TEST_rarestress_4444", result)
        # Should have cleanup loop that removes injected keys
        self.assertIn("_cleanup_key_rarestress_4444", result)
        # Verify code is valid
        ast.parse(result)

    def test_combination_no_unnecessary_cleanup(self):
        """Test that combinations without persistent events skip cleanup."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):
            with patch("random.choice", return_value=["set_class", "set_bases"]):
                with patch("random.randint", return_value=5555):
                    mutator = RareEventStressTester()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should NOT have trace or builtins cleanup
        self.assertNotIn("_cleanup_key_", result)
        # settrace(None) should not appear as a cleanup step
        # (it may appear inside event code, but not as a standalone cleanup)
        # Verify code is valid
        ast.parse(result)


class TestRefcountEscapeHatchMutator(unittest.TestCase):
    """Test RefcountEscapeHatchMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_del_last_ref(self):
        """Test __del__ last reference attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="del_last_ref"):
                with patch("random.randint", return_value=5000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_Toxic_rcesc_5000", result)
        self.assertIn("_ref_holder_rcesc_5000", result)
        self.assertIn("__del__", result)

    def test_injects_weakref_surprise(self):
        """Test weakref callback surprise attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="weakref_surprise"):
                with patch("random.randint", return_value=6000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_Owner_rcesc_6000", result)
        self.assertIn("weakref.ref", result)
        self.assertIn("_evil_callback_rcesc_6000", result)

    def test_injects_descriptor_refcount_drain(self):
        """Test descriptor refcount drain attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="descriptor_refcount_drain"):
                with patch("random.randint", return_value=7000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_DrainDescriptor_rcesc_7000", result)
        self.assertIn("_Victim_rcesc_7000", result)
        self.assertIn("__get__", result)

    def test_injects_reentrant_container_clear(self):
        """Test reentrant container clear attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="reentrant_container_clear"):
                with patch("random.randint", return_value=8000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_ClearingDict_rcesc_8000", result)
        self.assertIn("_ClearingList_rcesc_8000", result)
        self.assertIn("__contains__", result)

    def test_injects_store_fast_resurrection(self):
        """Test store-fast resurrection via __del__ attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="store_fast_resurrection"):
                with patch("random.randint", return_value=9000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_Undead_rcesc_9000", result)
        self.assertIn("_graveyard_rcesc_9000", result)
        self.assertIn("__del__", result)
        self.assertIn("gc.collect()", result)

    def test_injects_custom_add_side_effect(self):
        """Test custom __add__ with side effects attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="custom_add_side_effect"):
                with patch("random.randint", return_value=1000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_EvilAdder_rcesc_1000", result)
        self.assertIn("__add__", result)
        self.assertIn("_instances", result)

    def test_injects_to_bool_ref_escape(self):
        """Test TO_BOOL with ref-dropping __bool__ attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="to_bool_ref_escape"):
                with patch("random.randint", return_value=2000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("_ToxicBool_rcesc_2000", result)
        self.assertIn("_ToxicInt_rcesc_2000", result)
        self.assertIn("_ToxicList_rcesc_2000", result)
        self.assertIn("__bool__", result)

    def test_injects_module_attr_volatile(self):
        """Test module attribute volatility attack vector."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="module_attr_volatile"):
                with patch("random.randint", return_value=3000):
                    mutator = RefcountEscapeHatchMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("math.pi", result)
        self.assertIn("not_a_float", result)
        self.assertIn("types.ModuleType", result)

    def test_all_attack_scenarios_produce_valid_code(self):
        """Test that all attack scenarios produce parseable Python."""
        for attack in RefcountEscapeHatchMutator.ATTACK_SCENARIOS:
            with self.subTest(attack=attack):
                code = dedent("""
                    def uop_harness_test():
                        x = 1
                        y = 2
                """)
                tree = ast.parse(code)

                with patch("random.random", return_value=0.05):
                    with patch("random.choice", return_value=attack):
                        with patch("random.randint", return_value=4000):
                            mutator = RefcountEscapeHatchMutator()
                            mutated = mutator.visit(tree)

                result = ast.unparse(mutated)
                reparsed = ast.parse(result)
                self.assertIsInstance(reparsed, ast.Module)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.05):
            mutator = RefcountEscapeHatchMutator()
            mutated = mutator.visit(tree)

        self.assertEqual(original, ast.unparse(mutated))

    def test_respects_probability_threshold(self):
        """Test that mutation doesn't occur above probability threshold."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):
            mutator = RefcountEscapeHatchMutator()
            mutated = mutator.visit(tree)

        self.assertEqual(original, ast.unparse(mutated))

    def test_preserves_original_function_body(self):
        """Test that original function statements are preserved."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = x + y
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value="del_last_ref"):
                mutator = RefcountEscapeHatchMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("x = 1", result)
        self.assertIn("y = 2", result)
        self.assertIn("z = x + y", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
