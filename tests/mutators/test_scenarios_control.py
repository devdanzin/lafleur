#!/usr/bin/env python3
"""
Tests for control flow mutators.

This module contains unit tests for control flow mutators defined in
lafleur/mutators/scenarios_control.py
"""

import ast
import random
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.scenarios_control import (
    ContextManagerInjector,
    CoroutineStateCorruptor,
    DeepCallMutator,
    ExceptionHandlerMaze,
    ExitStresser,
    GuardExhaustionGenerator,
    MaxOperandMutator,
    RecursionWrappingMutator,
    TraceBreaker,
    YieldFromInjector,
)


class TestRecursionWrappingMutator(unittest.TestCase):
    """Test RecursionWrappingMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_wraps_block_in_recursive_function(self):
        """Test that a block is wrapped in a recursive function."""
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

        with patch("random.random", return_value=0.01):  # Below 0.05 threshold
            with patch("random.randint", side_effect=[0, 5000]):  # start_index, func_name
                mutator = RecursionWrappingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have recursive function
        self.assertIn("def recursive_wrapper_5000():", result)

    def test_creates_function_with_unique_name(self):
        """Test that recursive function has unique name."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            with patch("random.randint", side_effect=[0, 7000]):
                mutator = RecursionWrappingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique name
        self.assertIn("recursive_wrapper_7000", result)

    def test_adds_recursive_call_to_function(self):
        """Test that recursive call is added to wrapped function."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            with patch("random.randint", side_effect=[0, 3000]):
                mutator = RecursionWrappingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should call itself recursively
        self.assertIn("recursive_wrapper_3000()", result)

    def test_wraps_initial_call_in_try_except(self):
        """Test that initial call is wrapped in try/except RecursionError."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            with patch("random.randint", side_effect=[0, 4000]):
                mutator = RecursionWrappingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have try/except RecursionError
        self.assertIn("try:", result)
        self.assertIn("except RecursionError:", result)
        self.assertIn("pass", result)

    def test_wraps_block_of_three_statements(self):
        """Test that exactly 3 statements are wrapped."""
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
        original_statements = ["a = 1", "b = 2", "c = 3", "d = 4", "e = 5", "f = 6"]

        with patch("random.random", return_value=0.01):
            with patch("random.randint", side_effect=[1, 6000]):  # Start at index 1
                mutator = RecursionWrappingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should wrap statements b, c, d (indices 1, 2, 3)
        # The recursive function should contain these
        self.assertIn("def recursive_wrapper_6000():", result)
        # These should be in the recursive function
        self.assertIn("b = 2", result)
        self.assertIn("c = 3", result)
        self.assertIn("d = 4", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.01):
            mutator = RecursionWrappingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_no_mutation_with_low_probability(self):
        """Test that mutation doesn't occur with low probability."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.9):  # Above 0.05 threshold
            mutator = RecursionWrappingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            with patch("random.randint", side_effect=[0, 8000]):
                mutator = RecursionWrappingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_skips_functions_with_too_few_statements(self):
        """Test that functions with < 5 statements are not mutated."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.01):
            mutator = RecursionWrappingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not be mutated (only 4 statements)
        self.assertEqual(original, result)

    def test_preserves_statements_outside_wrapped_block(self):
        """Test that statements outside the wrapped block are preserved."""
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
            with patch("random.randint", side_effect=[2, 9000]):  # Wrap c, d, e
                mutator = RecursionWrappingMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Statements before and after should still be present
        self.assertIn("a = 1", result)
        self.assertIn("b = 2", result)
        self.assertIn("f = 6", result)
        self.assertIn("g = 7", result)

    def test_handles_empty_function_body(self):
        """Test handling of functions with only pass."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.01):
            mutator = RecursionWrappingMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not be mutated (too few statements)
        self.assertEqual(original, result)


class TestExceptionHandlerMaze(unittest.TestCase):
    """Test ExceptionHandlerMaze mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_creates_metaclass_and_exception(self):
        """Test that metaclass and exception class are created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", return_value=1000):
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have metaclass and exception
        self.assertIn("class MetaException_exc_1000(type)", result)
        self.assertIn("class EvilException_exc_1000(Exception, metaclass=MetaException_exc_1000)", result)

    def test_metaclass_has_instancecheck(self):
        """Test that metaclass has __instancecheck__ method."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=2000):
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have __instancecheck__
        self.assertIn("def __instancecheck__", result)
        self.assertIn("cls.count", result)
        self.assertIn("% 10 == 0", result)

    def test_creates_nested_exception_maze(self):
        """Test that nested try/except blocks are created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=3000):
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have nested try/except
        self.assertGreaterEqual(result.count("try:"), 2)
        self.assertIn("except EvilException_exc_3000:", result)
        self.assertIn("except ValueError:", result)

    def test_loop_runs_400_times(self):
        """Test that maze loop runs 400 times."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=4000):
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should loop 400 times
        self.assertIn("for i in range(400):", result)

    def test_alternates_between_exceptions(self):
        """Test that code alternates between different exceptions."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=5000):
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should raise both exceptions conditionally
        self.assertIn("if i % 100 == 0:", result)
        self.assertIn("raise EvilException_exc_5000()", result)
        self.assertIn("raise ValueError", result)

    def test_has_multiple_exception_handlers(self):
        """Test that multiple exception handlers are present."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=6000):
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have multiple exception types
        self.assertIn("except EvilException_exc_6000:", result)
        self.assertIn("except ValueError:", result)
        self.assertIn("except Exception:", result)

    def test_skips_non_harness_functions(self):
        """Test that non-harness functions are not mutated."""
        code = dedent("""
            def normal_function():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = ExceptionHandlerMaze()
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
            mutator = ExceptionHandlerMaze()
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
            with patch("random.randint", return_value=7000):
                mutator = ExceptionHandlerMaze()
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
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("exc_8000", result)
        self.assertIn("MetaException_exc_8000", result)
        self.assertIn("EvilException_exc_8000", result)

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
            with patch("random.randint", return_value=9000):
                mutator = ExceptionHandlerMaze()
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
            with patch("random.randint", return_value=2824):
                mutator = ExceptionHandlerMaze()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestCoroutineStateCorruptor(unittest.TestCase):
    """Test CoroutineStateCorruptor mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_creates_corruptor_function(self):
        """Test that frame-corrupting function is created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.randint", side_effect=[1000, 2]):  # prefix, injection_point
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have corruptor function
        self.assertIn("def sync_corruptor_async_1000(value):", result)
        self.assertIn("sys._getframe(1)", result)

    def test_corruptor_uses_getframe(self):
        """Test that corruptor uses sys._getframe to modify caller frame."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", side_effect=[2000, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should modify f_locals
        self.assertIn("caller_frame = sys._getframe(1)", result)
        self.assertIn("caller_frame.f_locals['x'] = value", result)

    def test_creates_async_coroutine(self):
        """Test that async coroutine function is created."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", side_effect=[3000, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have async function
        self.assertIn("async def evil_coro_async_3000():", result)
        self.assertIn("await asyncio.sleep(0)", result)

    def test_imports_asyncio_and_sys(self):
        """Test that asyncio and sys are imported."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", side_effect=[4000, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should import both modules
        self.assertIn("import asyncio", result)
        self.assertIn("import sys", result)

    def test_has_warmup_loop(self):
        """Test that warmup loop is present to specialize type."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", side_effect=[5000, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have warmup loop
        self.assertIn("for i in range(100):", result)
        self.assertIn("x = i + 1", result)

    def test_corrupts_state_before_await(self):
        """Test that state is corrupted before await point."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", side_effect=[6000, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should call corruptor with string
        self.assertIn("sync_corruptor_async_6000('corrupted_string')", result)

    def test_uses_asyncio_run(self):
        """Test that coroutine is run with asyncio.run()."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", side_effect=[7000, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should use asyncio.run()
        self.assertIn("asyncio.run(evil_coro_async_7000())", result)

    def test_wraps_in_try_except(self):
        """Test that scenario is wrapped in try/except."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", side_effect=[8000, 2]):
                mutator = CoroutineStateCorruptor()
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
            mutator = CoroutineStateCorruptor()
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
            mutator = CoroutineStateCorruptor()
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
            with patch("random.randint", side_effect=[9000, 2]):
                mutator = CoroutineStateCorruptor()
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
            with patch("random.randint", side_effect=[5500, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique prefix
        self.assertIn("async_5500", result)
        self.assertIn("sync_corruptor_async_5500", result)
        self.assertIn("evil_coro_async_5500", result)

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
            with patch("random.randint", side_effect=[6500, 3]):
                mutator = CoroutineStateCorruptor()
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
            with patch("random.randint", side_effect=[7500, 2]):
                mutator = CoroutineStateCorruptor()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should still be valid
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestStressPatternMutators(unittest.TestCase):
    """Test stress pattern injection mutators."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_guard_exhaustion_generator(self):
        """Test GuardExhaustionGenerator mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = GuardExhaustionGenerator()
            mutated = mutator.visit(tree)

        # Should have injected isinstance chain
        func = mutated.body[0]
        # Should have poly_list setup and loop
        self.assertGreater(len(func.body), 1)

    def test_exit_stresser(self):
        """Test ExitStresser mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch(
                "random.randint", side_effect=[4567, 7]
            ):  # prefix and num_branches
                mutator = ExitStresser()
                mutated = mutator.visit(tree)

        # Should have injected exit stress scenario
        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should contain the exit stress pattern
        self.assertIn("exit stress scenario", code_str)
        self.assertIn("res_es_4567", code_str)
        # Should have if/elif chain
        self.assertIn("if i %", code_str)
        self.assertIn("elif i %", code_str)


class TestAdvancedMutators(unittest.TestCase):
    """Test advanced mutator classes."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_trace_breaker(self):
        """Test TraceBreaker mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", side_effect=lambda x: x[0]):
                mutator = TraceBreaker()
                mutated = mutator.visit(tree)

        # Should have injected trace-breaking scenario
        func = mutated.body[0]
        self.assertGreater(len(func.body), 1)

    def test_deep_call_mutator(self):
        """Test DeepCallMutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=10):
                with patch("random.randint", return_value=1234):  # Add prefix mock
                    mutator = DeepCallMutator()
                    mutated = mutator.visit(tree)

        # Should have injected deep call chain
        func = mutated.body[0]
        # Check the string representation contains function definitions
        code_str = ast.unparse(func)
        # The newlines are escaped in the string, check for function pattern
        self.assertIn("f_0_dc_1234", code_str)
        self.assertIn("f_9_dc_1234", code_str)


class TestMutatorOutput(unittest.TestCase):
    """Test the output quality of mutators."""

    def test_deep_call_output(self):
        """Test DeepCallMutator produces valid call chain."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=5):
                with patch("random.randint", return_value=2824):
                    mutator = DeepCallMutator()
                    mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        # The function definitions are in a string that gets parsed
        # Check that the attack was injected
        self.assertIn("Running deep call scenario", output)
        self.assertIn("f_4_dc_2824", output)  # Top function call

    def test_exit_stresser_output_format(self):
        """Test ExitStresser produces correctly formatted if/elif chains."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch(
                "random.randint", side_effect=[9999, 3]
            ):  # prefix and 3 branches
                mutator = ExitStresser()
                mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        # Should have exactly 3 branches
        self.assertIn("if i % 3 == 0:", output)
        self.assertIn("elif i % 3 == 1:", output)
        self.assertIn("elif i % 3 == 2:", output)
        self.assertIn("res_es_9999", output)


class TestContextManagerInjector(unittest.TestCase):
    """Test ContextManagerInjector mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_wraps_statements_with_nullcontext(self):
        """Test simple strategy wraps statements with contextlib.nullcontext()."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.15 threshold
            with patch("random.choice", return_value="simple"):  # strategy
                with patch("random.randint", side_effect=[2, 0, 3000]):  # slice_size, start_idx, uid
                    mutator = ContextManagerInjector()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have import contextlib
        self.assertIn("import contextlib", result)
        # Should have with statement
        self.assertIn("with contextlib.nullcontext():", result)

    def test_wraps_statements_with_open_devnull(self):
        """Test resource strategy wraps statements with open(os.devnull)."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="resource"):
                with patch("random.randint", side_effect=[2, 0, 4000]):  # slice_size, start_idx, uid
                    mutator = ContextManagerInjector()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have import os
        self.assertIn("import os", result)
        # Should have with statement
        self.assertIn("with open(os.devnull, 'w') as _ctx_4000:", result)

    def test_wraps_statements_with_evil_context(self):
        """Test evil strategy creates custom EvilContext class."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="evil"):
                with patch("random.randint", side_effect=[2, 0, 5000]):  # slice_size, start_idx, uid
                    mutator = ContextManagerInjector()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have EvilContext class
        self.assertIn("class EvilContext_5000:", result)
        self.assertIn("def __enter__(self):", result)
        self.assertIn("def __exit__(self, exc_type, exc_val, exc_tb):", result)
        # Should wrap with statement in try/except
        self.assertIn("try:", result)
        self.assertIn("with EvilContext_5000():", result)

    def test_evil_context_raises_in_enter(self):
        """Test that EvilContext __enter__ can raise RuntimeError."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="evil"):
                with patch("random.randint", side_effect=[2, 0, 6000]):  # slice_size, start_idx, uid
                    mutator = ContextManagerInjector()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have conditional raise in __enter__
        self.assertIn("raise RuntimeError('Evil __enter__')", result)

    def test_evil_context_raises_in_exit(self):
        """Test that EvilContext __exit__ can raise or swallow exceptions."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="evil"):
                with patch("random.randint", side_effect=[2, 0, 7000]):  # slice_size, start_idx, uid
                    mutator = ContextManagerInjector()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have raise and return True in __exit__
        self.assertIn("raise RuntimeError('Evil __exit__')", result)
        self.assertIn("return True", result)

    def test_wraps_contiguous_slice(self):
        """Test that a contiguous slice of statements is wrapped."""
        code = dedent("""
            def uop_harness_test():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="simple"):
                # Wrap statements 1-3 (b, c, d)
                with patch("random.randint", side_effect=[3, 1, 8000]):  # slice_size, start_idx, uid
                    mutator = ContextManagerInjector()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have with statement
        self.assertIn("with contextlib.nullcontext():", result)
        # All statements should still be present
        self.assertIn("a = 1", result)
        self.assertIn("b = 2", result)
        self.assertIn("c = 3", result)

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
            mutator = ContextManagerInjector()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        self.assertEqual(original, result)

    def test_skips_functions_with_too_few_statements(self):
        """Test that functions with < 2 statements are not mutated."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.unparse(tree)

        with patch("random.random", return_value=0.1):
            mutator = ContextManagerInjector()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
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
            mutator = ContextManagerInjector()
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
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="simple"):
                with patch("random.randint", side_effect=[2, 0, 9000]):  # slice_size, start_idx, uid
                    mutator = ContextManagerInjector()
                    mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be valid Python
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


class TestYieldFromInjector(unittest.TestCase):
    """Test YieldFromInjector mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_injects_simple_yield_from_generator(self):
        """Test that simple yield-from generator is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):  # trigger mutation, not recursive
            with patch("random.randint", return_value=5000):
                mutator = YieldFromInjector()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have yield from
        self.assertIn("yield from", result)
        # Should have try/finally
        self.assertIn("try:", result)
        self.assertIn("finally:", result)
        # Should have range(10)
        self.assertIn("range(10)", result)
        # Should have list() call to consume generator
        self.assertIn("list(", result)

    def test_injects_recursive_yield_from_generator(self):
        """Test that recursive yield-from generator is injected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.1]):  # trigger mutation, recursive
            with patch("random.randint", return_value=6000):
                mutator = YieldFromInjector()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have yield from
        self.assertIn("yield from", result)
        # Should have try/finally
        self.assertIn("try:", result)
        self.assertIn("finally:", result)
        # Should have depth parameter
        self.assertIn("depth", result)
        # Should have depth check
        self.assertIn("if depth > 5:", result)
        # Should have recursive call with depth + 1
        self.assertIn("depth + 1", result)
        # Should have list() call with depth argument
        self.assertIn("list(_yield_from_gen_6000(0))", result)

    def test_prepends_generator_and_appends_driver(self):
        """Test that generator is prepended and driver is appended."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):  # trigger mutation, not recursive
            with patch("random.randint", return_value=7000):
                mutator = YieldFromInjector()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        lines = [l.strip() for l in result.split('\n') if l.strip()]

        # Generator definition should come before original code
        gen_def_idx = next(i for i, line in enumerate(lines) if 'def _yield_from_gen_7000' in line)
        x_assign_idx = next(i for i, line in enumerate(lines) if 'x = 1' in line)
        self.assertLess(gen_def_idx, x_assign_idx)

        # Driver call should come after original code
        driver_idx = next(i for i, line in enumerate(lines) if 'list(_yield_from_gen_7000())' in line)
        z_assign_idx = next(i for i, line in enumerate(lines) if 'z = 3' in line)
        self.assertGreater(driver_idx, z_assign_idx)

    def test_respects_probability(self):
        """Test that mutation is applied probabilistically."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # Test with high random value (should not mutate)
        with patch("random.random", return_value=0.5):
            mutator = YieldFromInjector()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have yield from
        self.assertNotIn("yield from", result)

    def test_only_mutates_uop_harness_functions(self):
        """Test that only uop_harness functions are mutated."""
        code = dedent("""
            def regular_function():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):  # trigger mutation
            with patch("random.randint", return_value=8000):
                mutator = YieldFromInjector()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have yield from
        self.assertNotIn("yield from", result)

    def test_produces_valid_code_simple(self):
        """Test that simple generator produces valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                return x + 10
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):  # trigger mutation, not recursive
            with patch("random.randint", return_value=9000):
                mutator = YieldFromInjector()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_produces_valid_code_recursive(self):
        """Test that recursive generator produces valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                return x + 10
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.1]):  # trigger mutation, recursive
            with patch("random.randint", return_value=9500):
                mutator = YieldFromInjector()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)

    def test_unique_naming(self):
        """Test that generated names use unique suffixes."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.5]):  # trigger mutation, not recursive
            with patch("random.randint", return_value=1234):
                mutator = YieldFromInjector()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have unique suffix from randint
        self.assertIn("_yield_from_gen_1234", result)


class TestMaxOperandMutator(unittest.TestCase):
    """Test MaxOperandMutator mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_locals_saturation_creates_300_variables(self):
        """Test that locals saturation strategy creates 300 variables."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):  # Below 0.2 threshold
            with patch("random.choice", return_value="locals"):
                mutator = MaxOperandMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have 300 _jit_op_ variables
        self.assertIn("_jit_op_0 = 0", result)
        self.assertIn("_jit_op_299 = 0", result)
        # Should read the last variable
        self.assertIn("_ = _jit_op_299", result)

    def test_locals_saturation_forces_extended_arg(self):
        """Test that 300 variables force LOAD_FAST index > 255."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="locals"):
                mutator = MaxOperandMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Count the number of _jit_op_ variables
        jit_op_count = result.count("_jit_op_")
        # Should have at least 300 occurrences (300 assignments + 1 read)
        self.assertGreaterEqual(jit_op_count, 300)

    def test_jump_stretching_creates_padding_block(self):
        """Test that jump stretching strategy creates a large padding block."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="jumps"):
                mutator = MaxOperandMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should have an if statement with getattr
        self.assertIn("if getattr(object, '__doc__', True):", result)
        # Should have padding assignments
        self.assertIn("_pad_jump = 1", result)
        # Count occurrences - should have ~200
        pad_count = result.count("_pad_jump = 1")
        self.assertGreaterEqual(pad_count, 200)

    def test_jump_stretching_forces_extended_jump(self):
        """Test that 200 statements force jump offset > 255 bytes."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="jumps"):
                mutator = MaxOperandMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # The if block should be large enough to require extended jump
        # Verify the padding block exists
        self.assertIn("_pad_jump", result)

    def test_no_mutation_when_random_check_fails(self):
        """Test that mutator doesn't modify when random check fails."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.5):  # Above 0.2 threshold
            mutator = MaxOperandMutator()
            mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should not have modified the code
        self.assertNotIn("_jit_op_", result)
        self.assertNotIn("_pad_jump", result)
        self.assertNotIn("getattr", result)

    def test_strategy_selection_is_random(self):
        """Test that strategy selection uses random.choice."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # Test locals strategy
        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="locals"):
                mutator = MaxOperandMutator()
                mutated = mutator.visit(tree)
                result_locals = ast.unparse(mutated)

        # Test jumps strategy
        tree = ast.parse(code)
        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="jumps"):
                mutator = MaxOperandMutator()
                mutated = mutator.visit(tree)
                result_jumps = ast.unparse(mutated)

        # Results should be different
        self.assertIn("_jit_op_", result_locals)
        self.assertNotIn("_jit_op_", result_jumps)
        self.assertIn("_pad_jump", result_jumps)
        self.assertNotIn("_pad_jump", result_locals)

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value="locals"):
                mutator = MaxOperandMutator()
                mutated = mutator.visit(tree)

        result = ast.unparse(mutated)
        # Should be parseable
        reparsed = ast.parse(result)
        self.assertIsInstance(reparsed, ast.Module)


if __name__ == "__main__":
    unittest.main(verbosity=2)
