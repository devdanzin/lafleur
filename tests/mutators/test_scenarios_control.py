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
    CoroutineStateCorruptor,
    DeepCallMutator,
    ExceptionHandlerMaze,
    ExitStresser,
    GuardExhaustionGenerator,
    RecursionWrappingMutator,
    TraceBreaker,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
