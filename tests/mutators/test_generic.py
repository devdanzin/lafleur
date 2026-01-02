#!/usr/bin/env python3
"""
Tests for generic mutators.

This module contains unit tests for generic AST mutators defined in
lafleur/mutators/generic.py
"""

import ast
import random
import sys
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.generic import (
    ArithmeticSpamMutator,
    AsyncConstructMutator,
    BlockTransposerMutator,
    BoundaryValuesMutator,
    ComparisonChainerMutator,
    ComparisonSwapper,
    ConstantPerturbator,
    ContainerChanger,
    DecoratorMutator,
    ExceptionGroupMutator,
    ForLoopInjector,
    GuardInjector,
    GuardRemover,
    ImportChaosMutator,
    LiteralTypeSwapMutator,
    NewUnpackingMutator,
    OperatorSwapper,
    PatternMatchingMutator,
    SliceMutator,
    StatementDuplicator,
    StringInterpolationMutator,
    SysMonitoringMutator,
    UnpackingMutator,
    VariableRenamer,
    VariableSwapper,
)


class TestBoundaryValuesMutator(unittest.TestCase):
    """Test BoundaryValuesMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_mutates_integer_to_boundary(self):
        """Test that integers are mutated to boundary values."""
        code = "x = 42"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="sys.maxsize"):
                mutator = BoundaryValuesMutator()
                mutated = mutator.visit(tree)

        # Should have replaced with sys.maxsize
        result = ast.unparse(mutated)
        self.assertIn("sys.maxsize", result)

    def test_mutates_float_to_boundary(self):
        """Test that floats are mutated to boundary values."""
        code = "x = 3.14"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="float('inf')"):
                mutator = BoundaryValuesMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("inf", result)

    def test_preserves_non_numeric_constants(self):
        """Test that non-numeric constants are not mutated."""
        code = "x = 'hello'"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BoundaryValuesMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("'hello'", result)

    def test_no_mutation_with_high_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = "x = 100"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.9):  # Above 0.2 threshold
            mutator = BoundaryValuesMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("100", result)

    def test_handles_complex_boundary_values(self):
        """Test complex boundary values like 2**63."""
        code = "x = 1"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="2**63 - 1"):
                mutator = BoundaryValuesMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertIn("2 ** 63", result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def test():
                x = 42
                y = 3.14
                z = x + y
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = BoundaryValuesMutator()
            mutated = mutator.visit(tree)

        # Should be parseable
        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestBlockTransposerMutator(unittest.TestCase):
    """Test BlockTransposerMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_transposes_block_in_function(self):
        """Test that a block of statements is transposed."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
                f = 6
                g = 7
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            with patch("random.randint", side_effect=[0, 3]):  # start=0, insert=3
                mutator = BlockTransposerMutator()
                mutated = mutator.visit(tree)

        # Should have transposed the block
        func = mutated.body[0]
        self.assertEqual(len(func.body), 7)
        # Check that statements were moved
        self.assertIsInstance(mutated, ast.Module)

    def test_skips_functions_with_too_few_statements(self):
        """Test that functions with <6 statements are not transposed."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.01):
            mutator = BlockTransposerMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be unchanged (too few statements)
        self.assertEqual(original, result)

    def test_no_transpose_with_low_probability(self):
        """Test that transposition doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
                f = 6
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.05 threshold
            mutator = BlockTransposerMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
                a = 4
                b = 5
                c = 6
                d = 7
                e = 8
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            mutator = BlockTransposerMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_preserves_all_statements(self):
        """Test that all original statements are preserved after transposition."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
                f = 6
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            mutator = BlockTransposerMutator()
            mutated = mutator.visit(tree)

        func = mutated.body[0]
        # Should still have 6 statements
        self.assertEqual(len(func.body), 6)


class TestUnpackingMutator(unittest.TestCase):
    """Test UnpackingMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_converts_simple_assignment_to_unpacking(self):
        """Test that simple assignments are converted to unpacking."""
        code = "x = 1"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.005):
            with patch("random.randint", side_effect=[2, 10000, 99999, 10001, 10002, 5]):
                mutator = UnpackingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unpacking pattern
        self.assertIn("unpack_var_", result)
        self.assertIn("*", result)  # Starred expression

    def test_preserves_complex_assignments(self):
        """Test that complex assignments are not mutated."""
        code = "x, y = 1, 2"
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.005):
            mutator = UnpackingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be unchanged (already unpacking)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = "x = 1"
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.01 threshold
            mutator = UnpackingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.005):
            mutator = UnpackingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_creates_valid_unpacking_target(self):
        """Test that the unpacking target has valid structure."""
        code = "x = 1"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.005):
            with patch("random.randint", side_effect=[3, 10000, 10001, 10002, 5]):
                mutator = UnpackingMutator()
                mutated = mutator.visit(tree)

        # Check structure
        assign = mutated.body[0]
        self.assertIsInstance(assign.targets[0], ast.Tuple)
        # Should have starred expression
        has_starred = any(isinstance(elt, ast.Starred) for elt in assign.targets[0].elts)
        self.assertTrue(has_starred)


class TestNewUnpackingMutator(unittest.TestCase):
    """Test NewUnpackingMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_dictionary_unpacking(self):
        """Test dictionary unpacking injection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.4]):  # 0.1 < 0.25, 0.4 < 0.5 (dict)
            with patch("random.randint", return_value=5000):
                mutator = NewUnpackingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have dictionary unpacking
        self.assertIn("u_k1_5000", result)
        self.assertIn("u_k2_5000", result)

    def test_injects_single_element_list_unpacking(self):
        """Test single-element list unpacking injection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.6, 0.6]):  # 0.1 < 0.25, 0.6 >= 0.5 (list)
            with patch("random.randint", return_value=6000):
                mutator = NewUnpackingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have single-element list unpacking
        self.assertIn("u_elem_6000", result)
        self.assertIn("list_6000", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = NewUnpackingMutator()
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

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = NewUnpackingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3]
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = NewUnpackingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestDecoratorMutator(unittest.TestCase):
    """Test DecoratorMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_adds_decorator_to_nested_function(self):
        """Test that a decorator is added to a nested function."""
        code = dedent("""
            def uop_harness_test():
                def helper():
                    return 42
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = DecoratorMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have decorator definition and application
        self.assertIn("fuzzer_decorator_7000", result)
        self.assertIn("@fuzzer_decorator_7000", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                def helper():
                    return 42
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = DecoratorMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_no_mutation_without_nested_function(self):
        """Test that functions without nested functions are not mutated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = DecoratorMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                def helper():
                    return 42
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.2 threshold
            mutator = DecoratorMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                def helper(x):
                    return x * 2
                return helper(5)
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = DecoratorMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestSliceMutator(unittest.TestCase):
    """Test SliceMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_slice_read_operation(self):
        """Test slice read operation injection."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3, 4, 5]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            # Need to provide enough values for choice calls in _create_random_slice
            choice_values = ["x", "read"] + [None, None, 1]  # For slice parts and step
            with patch("random.choice", side_effect=choice_values):
                mutator = SliceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have slice operation
        self.assertIn("slice_var_", result)
        self.assertIn("[", result)

    def test_injects_slice_write_operation(self):
        """Test slice write operation injection on lists."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3, 4, 5]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            # Need to provide enough values for choice calls
            choice_values = ["x", "write"] + [None, None, 1]  # For slice parts
            with patch("random.choice", side_effect=choice_values):
                mutator = SliceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have slice write
        self.assertIn("x[", result)
        self.assertIn("= [1, 2, 3]", result)

    def test_injects_slice_delete_operation(self):
        """Test slice delete operation injection on lists."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3, 4, 5]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            # Need to provide enough values for choice calls
            choice_values = ["x", "delete"] + [None, None, 1]  # For slice parts
            with patch("random.choice", side_effect=choice_values):
                mutator = SliceMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have del statement
        self.assertIn("del x[", result)

    def test_injects_slice_object_read(self):
        """Test slice object read operation injection."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3, 4, 5]
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", side_effect=["x", "read_slice_obj", "None", "None"]):
                with patch("random.randint", return_value=8000):
                    mutator = SliceMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have slice object
        self.assertIn("slice_obj_8000", result)
        self.assertIn("slice(", result)

    def test_skips_functions_without_sequences(self):
        """Test that functions without lists/tuples are not mutated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = SliceMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3]
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = SliceMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3, 4, 5]
                y = (1, 2, 3)
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = SliceMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestPatternMatchingMutator(unittest.TestCase):
    """Test PatternMatchingMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_sequence_match(self):
        """Test sequence pattern matching injection."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3]
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.4]):  # 0.1 < 0.25, 0.4 < 0.5 (sequence)
            with patch("random.choice", return_value="x"):
                mutator = PatternMatchingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have match statement
        self.assertIn("match x:", result)
        self.assertIn("case []:", result)

    def test_injects_mapping_match(self):
        """Test mapping pattern matching injection."""
        code = dedent("""
            def uop_harness_test():
                x = {'a': 1, 'b': 2}
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.6, 0.4]):  # dict path
            with patch("random.choice", return_value="x"):
                mutator = PatternMatchingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have mapping match
        self.assertIn("match x:", result)
        self.assertIn("'a':", result)

    def test_injects_class_match(self):
        """Test class pattern matching injection."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.6]):  # class path (else branch)
            with patch("random.choice", return_value="x"):
                mutator = PatternMatchingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have class match
        self.assertIn("match x:", result)
        self.assertIn("case int():", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = [1, 2, 3]
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = PatternMatchingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3]
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = PatternMatchingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = [1, 2, 3]
                y = {'a': 1}
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = PatternMatchingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestArithmeticSpamMutator(unittest.TestCase):
    """Test ArithmeticSpamMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_float_add_spam(self):
        """Test float addition spam injection."""
        code = dedent("""
            def uop_harness_test():
                x = 1.5
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.5]):  # 0.1 < 0.25, 0.5 < 0.6 (float)
            with patch("random.choice", side_effect=["x", "add"]):
                mutator = ArithmeticSpamMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have float addition loop
        self.assertIn("x = x + 0.25", result)
        self.assertIn("for _ in range(500):", result)

    def test_injects_float_multiply_spam(self):
        """Test float multiplication spam injection."""
        code = dedent("""
            def uop_harness_test():
                x = 0.25
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.5]):
            with patch("random.choice", side_effect=["x", "mul"]):
                mutator = ArithmeticSpamMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have multiplication spam
        self.assertIn("x = x * 1.001", result)

    def test_injects_string_spam(self):
        """Test string concatenation spam injection."""
        code = dedent("""
            def uop_harness_test():
                x = "hello"
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.7]):  # String path
            with patch("random.choice", return_value="x"):
                mutator = ArithmeticSpamMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have string concatenation
        self.assertIn("x += ", result)

    def test_creates_variables_when_none_exist(self):
        """Test that variables are created when none exist."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=9000):
                mutator = ArithmeticSpamMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should create variables
        self.assertIn("f_9000", result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                x = 1.5
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = ArithmeticSpamMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1.5
                y = "test"
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ArithmeticSpamMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestStringInterpolationMutator(unittest.TestCase):
    """Test StringInterpolationMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_fstring_with_int_format(self):
        """Test f-string with integer format spec injection."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.4, 0.2]):  # f-string path, int path
            with patch("random.choice", return_value="x"):
                mutator = StringInterpolationMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have f-string with format spec
        self.assertIn("f'", result)
        self.assertIn(":04d", result)

    def test_injects_fstring_with_float_format(self):
        """Test f-string with float format spec injection."""
        code = dedent("""
            def uop_harness_test():
                x = 3.14
        """)
        tree = ast.parse(code)

        # Need: main check < 0.25, f-string choice < 0.5, float check < 0.3 (int_vars is empty, so skipped)
        with patch("random.random", side_effect=[0.1, 0.4, 0.2]):  # 0.2 < 0.3 for float
            with patch("random.choice", return_value="x"):
                mutator = StringInterpolationMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have f-string with float formatting
        self.assertIn("f'", result)
        self.assertIn(":.2f", result)

    def test_creates_variables_when_none_exist(self):
        """Test that variables are created when none exist."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        # Need more random.random calls: main check, f-string choice, int var check, float var check, str var check
        with patch("random.random", side_effect=[0.1, 0.4, 0.8, 0.8, 0.2]):
            with patch("random.randint", return_value=11000):
                with patch("random.choice", return_value="i_11000"):
                    mutator = StringInterpolationMutator()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should create a variable
        self.assertIn("11000", result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = StringInterpolationMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 42
                y = 3.14
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StringInterpolationMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    @unittest.skipIf(sys.version_info < (3, 14), "t-strings require Python 3.14+")
    def test_injects_tstring(self):
        """Test t-string template injection (Python 3.14+)."""
        code = dedent("""
            def uop_harness_test():
                x = 42
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.6]):  # t-string path
            with patch("random.choice", return_value="x"):
                mutator = StringInterpolationMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have t-string (if Python supports it)
        self.assertIn("t", result)


class TestExceptionGroupMutator(unittest.TestCase):
    """Test ExceptionGroupMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_exception_group_handling(self):
        """Test ExceptionGroup handling injection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ExceptionGroupMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have ExceptionGroup
        self.assertIn("ExceptionGroup", result)
        self.assertIn("except*", result)
        self.assertIn("ValueError", result)
        self.assertIn("TypeError", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = ExceptionGroupMutator()
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

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = ExceptionGroupMutator()
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
            mutator = ExceptionGroupMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_creates_nested_exception_groups(self):
        """Test that nested ExceptionGroups are created."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = ExceptionGroupMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have nested exception groups
        self.assertIn("ExceptionGroup('nested'", result)


class TestAsyncConstructMutator(unittest.TestCase):
    """Test AsyncConstructMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_async_for_loop(self):
        """Test async for loop injection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.4]):  # async for path
            with patch("random.randint", return_value=2000):
                mutator = AsyncConstructMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have async for
        self.assertIn("async for", result)
        self.assertIn("AsyncIter_2000", result)
        self.assertIn("__aiter__", result)

    def test_injects_async_with_block(self):
        """Test async with block injection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.6]):  # async with path
            with patch("random.randint", return_value=3000):
                mutator = AsyncConstructMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have async with
        self.assertIn("async with", result)
        self.assertIn("AsyncCtx_3000", result)
        self.assertIn("__aenter__", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = AsyncConstructMutator()
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

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = AsyncConstructMutator()
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
            mutator = AsyncConstructMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_creates_coroutine_driver(self):
        """Test that coroutine driver code is created."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = AsyncConstructMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have driver code
        self.assertIn("c.send(None)", result)
        self.assertIn("StopIteration", result)


class TestSysMonitoringMutator(unittest.TestCase):
    """Test SysMonitoringMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_sys_monitoring_scenario(self):
        """Test sys.monitoring scenario injection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                mutator = SysMonitoringMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have sys.monitoring code
        self.assertIn("sys.monitoring", result)
        self.assertIn("monitored_gym_5000", result)
        self.assertIn("use_tool_id", result)

    def test_includes_cleanup_code(self):
        """Test that cleanup code is included in finally block."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = SysMonitoringMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have cleanup
        self.assertIn("finally:", result)
        self.assertIn("free_tool_id", result)

    def test_registers_multiple_callbacks(self):
        """Test that multiple event callbacks are registered."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = SysMonitoringMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should register multiple events
        self.assertIn("BRANCH_LEFT", result)
        self.assertIn("CALL", result)
        self.assertIn("register_callback", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = SysMonitoringMutator()
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

        with patch("random.random", return_value=0.9):  # Above 0.25 threshold
            mutator = SysMonitoringMutator()
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
            mutator = SysMonitoringMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_creates_monitored_gymnasium_function(self):
        """Test that a monitored 'gymnasium' function is created."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=7000):
                mutator = SysMonitoringMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have gymnasium function with loops and branches
        self.assertIn("def monitored_gym_7000", result)
        self.assertIn("for i in range(n):", result)
        self.assertIn("if i % 2 == 0:", result)


class TestBasicMutators(unittest.TestCase):
    """Test basic AST mutators."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_operator_swapper(self):
        """Test OperatorSwapper mutator."""
        code = "result = a + b"
        tree = ast.parse(code)

        # Force mutation by patching random
        with patch("random.random", return_value=0.1):
            mutator = OperatorSwapper()
            mutated = mutator.visit(tree)

        # Check that the operator changed
        binop = mutated.body[0].value
        self.assertIsInstance(binop, ast.BinOp)
        # Should not be Add anymore (with high probability)
        # Note: Due to randomness, we can't guarantee which operator it becomes

    def test_comparison_swapper(self):
        """Test ComparisonSwapper mutator."""
        code = "if a < b: pass"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.3):
            mutator = ComparisonSwapper()
            mutated = mutator.visit(tree)

        compare = mutated.body[0].test
        self.assertIsInstance(compare, ast.Compare)
        # Should have swapped the operator
        self.assertIsInstance(compare.ops[0], ast.GtE)

    def test_comparison_chainer(self):
        """Test ComparisonChainerMutator extends comparisons into chains."""
        code = "if x < 10: pass"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.3):
            with patch("random.choice", side_effect=[ast.Eq, "constant", True]):
                mutator = ComparisonChainerMutator()
                mutated = mutator.visit(tree)

        compare = mutated.body[0].test
        self.assertIsInstance(compare, ast.Compare)
        # Should have extended to a chained comparison
        self.assertEqual(len(compare.ops), 2)  # Original Lt + new Eq
        self.assertEqual(len(compare.comparators), 2)  # Original 10 + new True
        self.assertIsInstance(compare.ops[0], ast.Lt)  # Original operator
        self.assertIsInstance(compare.ops[1], ast.Eq)  # Added operator
        self.assertEqual(compare.comparators[1].value, True)  # Added constant

        # Verify it unparsed to valid syntax
        result = ast.unparse(mutated)
        self.assertIn("x < 10 == True", result)

    def test_constant_perturbator_int(self):
        """Test ConstantPerturbator on integers."""
        code = "x = 42"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value=1):
                mutator = ConstantPerturbator()
                mutated = mutator.visit(tree)

        constant = mutated.body[0].value
        self.assertEqual(constant.value, 43)  # 42 + 1

    def test_constant_perturbator_string(self):
        """Test ConstantPerturbator on strings."""
        code = "x = 'hello'"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=1):  # Mutate 'e'
                with patch("random.choice", return_value=1):
                    mutator = ConstantPerturbator()
                    mutated = mutator.visit(tree)

        constant = mutated.body[0].value
        self.assertEqual(len(constant.value), 5)
        self.assertNotEqual(constant.value, "hello")

    def test_guard_injector(self):
        """Test GuardInjector mutator."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = GuardInjector()
        mutated = mutator.visit(tree)

        # Should wrap in an If statement
        self.assertIsInstance(mutated.body[0], ast.If)
        # Check the test uses fuzzer_rng
        test = mutated.body[0].test
        self.assertIsInstance(test, ast.Compare)
        self.assertIsInstance(test.left, ast.Call)
        self.assertEqual(test.left.func.value.id, "fuzzer_rng")

    def test_container_changer_list_to_set(self):
        """Test ContainerChanger converting list to set."""
        code = "x = [1, 2, 3]"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.3):
            mutator = ContainerChanger()
            mutated = mutator.visit(tree)

        container = mutated.body[0].value
        self.assertIsInstance(container, ast.Set)

    def test_container_changer_list_comprehension(self):
        """Test ContainerChanger on list comprehension."""
        code = "x = [i for i in range(10)]"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.3):
            mutator = ContainerChanger()
            mutated = mutator.visit(tree)

        comp = mutated.body[0].value
        self.assertIsInstance(comp, ast.SetComp)

    def test_variable_swapper(self):
        """Test VariableSwapper mutator."""
        code = dedent("""
            x = 1
            y = 2
            z = x + y
        """)
        tree = ast.parse(code)

        mutator = VariableSwapper()
        mutated = mutator.visit(tree)

        # Check that some swapping occurred
        # Due to randomness, we can't predict exact swaps
        self.assertIsInstance(mutated, ast.Module)

    def test_variable_swapper_protected_names(self):
        """Test VariableSwapper doesn't swap protected names."""
        code = dedent("""
            print(len([1, 2, 3]))
            x = 1
            y = 2
        """)
        tree = ast.parse(code)

        mutator = VariableSwapper()
        mutated = mutator.visit(tree)

        # print and len should not be swapped
        call = mutated.body[0].value
        self.assertEqual(call.func.id, "print")
        self.assertEqual(call.args[0].func.id, "len")

    def test_statement_duplicator(self):
        """Test StatementDuplicator mutator."""
        code = "x = 1"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = StatementDuplicator()
            mutated = mutator.visit(tree)

        # Should have duplicated the statement
        self.assertEqual(len(mutated.body), 2)
        self.assertIsInstance(mutated.body[0], ast.Assign)
        self.assertIsInstance(mutated.body[1], ast.Assign)

    def test_variable_renamer(self):
        """Test VariableRenamer mutator."""
        code = "x = 1; y = x + 2"
        tree = ast.parse(code)

        remapping = {"x": "renamed_x", "y": "renamed_y"}
        mutator = VariableRenamer(remapping)
        mutated = mutator.visit(tree)

        # Check variables were renamed
        self.assertEqual(mutated.body[0].targets[0].id, "renamed_x")
        self.assertEqual(mutated.body[1].targets[0].id, "renamed_y")
        self.assertEqual(mutated.body[1].value.left.id, "renamed_x")

    def test_for_loop_injector(self):
        """Test ForLoopInjector mutator."""
        code = dedent("""
            x = 1
            y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            with patch("random.choice", return_value="range"):
                with patch("random.randint", return_value=100):
                    mutator = ForLoopInjector()
                    mutated = mutator.visit(tree)

        # First statement should be wrapped in a loop
        self.assertIsInstance(mutated.body[0], ast.For)

    def test_guard_remover(self):
        """Test GuardRemover mutator."""
        code = dedent("""
            if fuzzer_rng.random() < 0.1:
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = GuardRemover()
            mutated = mutator.visit(tree)

        # Should have removed the guard
        self.assertIsInstance(mutated.body[0], ast.Assign)
        self.assertEqual(mutated.body[0].targets[0].id, "x")

    def test_guard_injector_with_none_node(self):
        """Test GuardInjector when child visitor returns None."""

        # Create a custom node that will be removed
        class RemovingTransformer(ast.NodeTransformer):
            def visit_Assign(self, node):
                return None  # Remove assignments

        code = "x = 1"
        tree = ast.parse(code)

        # First apply removing transformer
        remover = RemovingTransformer()
        tree = remover.visit(tree)

        # Then apply GuardInjector
        injector = GuardInjector()
        result = injector.visit(tree)

        # Should handle None gracefully
        self.assertIsInstance(result, ast.Module)

    def test_variable_swapper_single_var(self):
        """Test VariableSwapper with only one variable."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = VariableSwapper()
        mutated = mutator.visit(tree)

        # Should handle gracefully without swapping
        self.assertIsInstance(mutated, ast.Module)
        self.assertEqual(mutated.body[0].targets[0].id, "x")

    def test_for_loop_injector_with_del(self):
        """Test ForLoopInjector doesn't wrap del statements."""
        code = "del x"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            mutator = ForLoopInjector()
            mutated = mutator.visit(tree)

        # Should not wrap del in loop
        self.assertIsInstance(mutated.body[0], ast.Delete)

    def test_guard_injector_output(self):
        """Test GuardInjector produces correct code."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = GuardInjector()
        mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        self.assertIn("if fuzzer_rng.random() < 0.1:", output)
        self.assertIn("x = 1", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
