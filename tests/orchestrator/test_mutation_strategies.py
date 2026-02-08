#!/usr/bin/env python3
"""
Tests for mutation strategy methods in lafleur/mutation_controller.py.

This module contains unit tests for mutation strategy selection and execution
methods in the MutationController class.
"""

import ast
import io
import unittest
from collections import defaultdict
from textwrap import dedent
from unittest.mock import MagicMock, patch

from lafleur.mutation_controller import MutationController


class TestApplyMutationStrategy(unittest.TestCase):
    """Test apply_mutation_strategy method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)

        # Mock ast_mutator
        self.controller.ast_mutator = MagicMock()
        self.controller.ast_mutator.transformers = [MagicMock, MagicMock]

        # Mock score_tracker
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.attempts = defaultdict(int)
        self.controller.score_tracker.get_weights.return_value = [1.0, 1.0, 1.0, 1.0]

        # Create default mock strategy methods with __name__ attributes
        # These can be overridden in individual tests
        dummy_tree = ast.parse("x = 1")
        self.mock_det = MagicMock(return_value=(dummy_tree, {"strategy": "deterministic"}))
        self.mock_det.__name__ = "_run_deterministic_stage"
        self.mock_havoc = MagicMock(return_value=(dummy_tree, {"strategy": "havoc"}))
        self.mock_havoc.__name__ = "_run_havoc_stage"
        self.mock_spam = MagicMock(return_value=(dummy_tree, {"strategy": "spam"}))
        self.mock_spam.__name__ = "_run_spam_stage"

    def test_seeds_random_generators(self):
        """Test that RNG is seeded correctly."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        with patch("lafleur.mutation_controller.RANDOM.seed") as mock_random_seed:
            with patch("lafleur.mutation_controller.random.seed") as mock_rand_seed:
                self.controller.apply_mutation_strategy(tree, seed=12345)

                mock_random_seed.assert_called_with(12345)
                mock_rand_seed.assert_called_with(12345)

    def test_normalizes_ast_before_mutation(self):
        """Test that FuzzerSetupNormalizer is applied."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        with patch("lafleur.mutation_controller.FuzzerSetupNormalizer") as mock_normalizer:
            mock_instance = MagicMock()
            mock_normalizer.return_value = mock_instance
            mock_instance.visit.return_value = tree

            self.controller.apply_mutation_strategy(tree, seed=42)

            mock_normalizer.assert_called_once()
            mock_instance.visit.assert_called_once()

    def test_chooses_strategy_with_dynamic_weights(self):
        """Test that strategy is chosen using dynamic weights."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam
        self.controller.score_tracker.get_weights.return_value = [10.0, 1.0, 1.0]

        with patch("lafleur.mutation_controller.random.choices") as mock_choices:
            mock_choices.return_value = [self.mock_det]

            self.controller.apply_mutation_strategy(tree, seed=42)

            # Verify weights were requested and used
            self.controller.score_tracker.get_weights.assert_called()
            call_args = mock_choices.call_args
            self.assertEqual(call_args[1]["weights"], [10.0, 1.0, 1.0])

    def test_records_strategy_attempts(self):
        """Test that strategy attempts are recorded."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        # Use the default mocks from setUp
        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        self.controller.apply_mutation_strategy(tree, seed=42)

        # All three strategies should have attempts recorded
        self.assertIn("deterministic", self.controller.score_tracker.attempts)
        self.assertIn("havoc", self.controller.score_tracker.attempts)
        self.assertIn("spam", self.controller.score_tracker.attempts)

    def test_sanitizes_ast_after_mutation(self):
        """Test that EmptyBodySanitizer is applied after mutation."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        with patch("lafleur.mutation_controller.EmptyBodySanitizer") as mock_sanitizer:
            mock_instance = MagicMock()
            mock_sanitizer.return_value = mock_instance
            mock_instance.visit.return_value = tree

            self.controller.apply_mutation_strategy(tree, seed=42)

            mock_sanitizer.assert_called_once()
            mock_instance.visit.assert_called_once()

    def test_adds_seed_to_mutation_info(self):
        """Test that seed is added to mutation info."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        _, mutation_info = self.controller.apply_mutation_strategy(tree, seed=12345)

        self.assertEqual(mutation_info["seed"], 12345)

    def test_returns_mutated_ast_and_info(self):
        """Test that method returns AST and mutation info."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        result_ast, result_info = self.controller.apply_mutation_strategy(tree, seed=42)

        self.assertIsInstance(result_ast, ast.AST)
        self.assertIsInstance(result_info, dict)
        self.assertIn("strategy", result_info)


class TestRunDeterministicStage(unittest.TestCase):
    """Test _run_deterministic_stage method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()
        self.controller.ast_mutator.transformers = [MagicMock]

    def test_small_ast_uses_mutate_ast(self):
        """Test that small ASTs use ast_mutator.mutate_ast."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.ast_mutator.mutate_ast.return_value = (tree, [MagicMock])

        with patch("sys.stderr", new_callable=io.StringIO):
            result_ast, mutation_info = self.controller._run_deterministic_stage(tree, seed=42)

        self.controller.ast_mutator.mutate_ast.assert_called_once_with(tree, seed=42)
        self.assertEqual(mutation_info["strategy"], "deterministic")

    def test_large_ast_uses_slicing(self):
        """Test that large ASTs (>100 statements) use slicing."""
        # Create AST with >100 statements
        statements = [
            ast.Assign(targets=[ast.Name(id=f"x{i}")], value=ast.Constant(value=i))
            for i in range(101)
        ]
        tree = ast.Module(body=statements, type_ignores=[])

        with patch.object(self.controller, "_run_slicing") as mock_slice:
            mock_slice.return_value = (tree, {"strategy": "slicing_deterministic"})

            with patch("sys.stderr", new_callable=io.StringIO):
                result_ast, mutation_info = self.controller._run_deterministic_stage(tree, seed=42)

            mock_slice.assert_called_once()
            call_args = mock_slice.call_args[0]
            self.assertEqual(call_args[1], "deterministic")  # stage_name
            self.assertEqual(call_args[2], 101)  # len_body

    def test_mutation_info_includes_transformers(self):
        """Test that mutation info includes transformer names."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        mock_transformer = MagicMock()
        mock_transformer.__name__ = "TestTransformer"
        self.controller.ast_mutator.mutate_ast.return_value = (tree, [mock_transformer])

        with patch("sys.stderr", new_callable=io.StringIO):
            _, mutation_info = self.controller._run_deterministic_stage(tree, seed=42)

        self.assertEqual(mutation_info["transformers"], ["TestTransformer"])

    def test_logs_stage_execution(self):
        """Test that deterministic stage logs to stderr."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.ast_mutator.mutate_ast.return_value = (tree, [MagicMock])

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            self.controller._run_deterministic_stage(tree, seed=42)

            self.assertIn("DETERMINISTIC", mock_stderr.getvalue())


class TestRunHavocStage(unittest.TestCase):
    """Test _run_havoc_stage method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()

        # Create mock transformers
        self.mock_transformer = MagicMock()
        self.mock_transformer.__name__ = "MockTransformer"
        self.mock_transformer.return_value.visit = MagicMock(side_effect=lambda x: x)
        self.controller.ast_mutator.transformers = [self.mock_transformer]

        # Mock score_tracker
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.attempts = defaultdict(int)
        self.controller.score_tracker.get_weights.return_value = [1.0]

    def test_small_ast_applies_multiple_mutations(self):
        """Test that havoc applies 15-50 mutations."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=20):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_havoc_stage(tree)

        # Should have applied 20 transformations
        self.assertEqual(len(mutation_info["transformers"]), 20)

    def test_large_ast_uses_slicing(self):
        """Test that large ASTs use slicing."""
        statements = [
            ast.Assign(targets=[ast.Name(id=f"x{i}")], value=ast.Constant(value=i))
            for i in range(101)
        ]
        tree = ast.Module(body=statements, type_ignores=[])

        with patch.object(self.controller, "_run_slicing") as mock_slice:
            mock_slice.return_value = (tree, {"strategy": "slicing_havoc"})

            with patch("sys.stderr", new_callable=io.StringIO):
                result_ast, mutation_info = self.controller._run_havoc_stage(tree)

            mock_slice.assert_called_once()
            self.assertEqual(mock_slice.call_args[0][1], "havoc")

    def test_uses_dynamic_weights(self):
        """Test that havoc uses dynamic weights for selection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.score_tracker.get_weights.return_value = [5.0]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch("lafleur.mutation_controller.random.choices") as mock_choices:
                mock_choices.return_value = [self.mock_transformer]

                with patch("sys.stderr", new_callable=io.StringIO):
                    self.controller._run_havoc_stage(tree)

                # Verify weights were used
                call_args = mock_choices.call_args
                self.assertEqual(call_args[1]["weights"], [5.0])

    def test_records_transformer_attempts(self):
        """Test that transformer attempts are recorded."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=3):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.controller._run_havoc_stage(tree)

        # Should have 3 attempts recorded
        self.assertEqual(self.controller.score_tracker.attempts["MockTransformer"], 3)

    def test_mutation_info_includes_strategy(self):
        """Test that mutation info includes havoc strategy."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_havoc_stage(tree)

        self.assertEqual(mutation_info["strategy"], "havoc")

    def test_logs_stage_execution(self):
        """Test that havoc stage logs to stderr."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    self.controller._run_havoc_stage(tree)

                    self.assertIn("HAVOC", mock_stderr.getvalue())


class TestRunSpamStage(unittest.TestCase):
    """Test _run_spam_stage method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()

        # Create mock transformer
        self.mock_transformer = MagicMock()
        self.mock_transformer.__name__ = "SpamTransformer"
        self.mock_transformer.return_value.visit = MagicMock(side_effect=lambda x: x)
        self.controller.ast_mutator.transformers = [self.mock_transformer]

        # Mock score_tracker
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.get_weights.return_value = [1.0]

    def test_small_ast_applies_same_mutation_repeatedly(self):
        """Test that spam applies the same mutation 20-50 times."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=25):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_spam_stage(tree)

        # Should have 25 of the same transformer
        self.assertEqual(len(mutation_info["transformers"]), 25)
        self.assertTrue(all(t == "SpamTransformer" for t in mutation_info["transformers"]))

    def test_large_ast_uses_slicing(self):
        """Test that large ASTs use slicing."""
        statements = [
            ast.Assign(targets=[ast.Name(id=f"x{i}")], value=ast.Constant(value=i))
            for i in range(101)
        ]
        tree = ast.Module(body=statements, type_ignores=[])

        with patch.object(self.controller, "_run_slicing") as mock_slice:
            mock_slice.return_value = (tree, {"strategy": "slicing_spam"})

            with patch("sys.stderr", new_callable=io.StringIO):
                result_ast, mutation_info = self.controller._run_spam_stage(tree)

            mock_slice.assert_called_once()
            self.assertEqual(mock_slice.call_args[0][1], "spam")

    def test_chooses_one_transformer_with_weights(self):
        """Test that spam chooses ONE transformer using weights."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.score_tracker.get_weights.return_value = [10.0]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch("lafleur.mutation_controller.random.choices") as mock_choices:
                mock_choices.return_value = [self.mock_transformer]

                with patch("sys.stderr", new_callable=io.StringIO):
                    self.controller._run_spam_stage(tree)

                # Should be called once to choose the transformer
                mock_choices.assert_called_once()
                self.assertEqual(mock_choices.call_args[1]["weights"], [10.0])
                self.assertEqual(mock_choices.call_args[1]["k"], 1)

    def test_logs_chosen_transformer(self):
        """Test that spam logs the chosen transformer."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    self.controller._run_spam_stage(tree)

                    output = mock_stderr.getvalue()
                    self.assertIn("SPAM", output)
                    self.assertIn("SpamTransformer", output)

    def test_mutation_info_includes_strategy(self):
        """Test that mutation info includes spam strategy."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_spam_stage(tree)

        self.assertEqual(mutation_info["strategy"], "spam")


class TestRunSlicing(unittest.TestCase):
    """Test _run_slicing method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()

        # Create mock transformers
        self.mock_transformer = MagicMock()
        self.mock_transformer.__name__ = "SliceMutator"
        self.controller.ast_mutator.transformers = [self.mock_transformer]

    def test_deterministic_stage_seeds_rng(self):
        """Test that deterministic slicing re-seeds RNG."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.random.seed") as mock_seed:
            with patch("lafleur.mutation_controller.random.randint", return_value=2):
                with patch(
                    "lafleur.mutation_controller.random.choices",
                    return_value=[self.mock_transformer],
                ):
                    with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                        mock_slicer.return_value.visit.return_value = tree

                        with patch("sys.stderr", new_callable=io.StringIO):
                            self.controller._run_slicing(tree, "deterministic", 101, seed=12345)

                        mock_seed.assert_called_with(12345)

    def test_deterministic_uses_1_to_3_mutations(self):
        """Test that deterministic slicing uses 1-3 mutations."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.random.randint", return_value=2) as mock_randint:
            with patch(
                "lafleur.mutation_controller.random.choices",
                return_value=[self.mock_transformer, self.mock_transformer],
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree

                    with patch("sys.stderr", new_callable=io.StringIO):
                        _, mutation_info = self.controller._run_slicing(
                            tree, "deterministic", 101, seed=42
                        )

                    # Verify randint was called with (1, 3)
                    mock_randint.assert_called_with(1, 3)

    def test_spam_uses_20_to_50_of_same_mutation(self):
        """Test that spam slicing uses 20-50 of the same mutation."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.random.randint", return_value=30):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_instance = MagicMock()
                    mock_slicer.return_value = mock_instance
                    mock_instance.visit.return_value = tree

                    with patch("sys.stderr", new_callable=io.StringIO):
                        _, mutation_info = self.controller._run_slicing(tree, "spam", 101)

                    # Verify SlicingMutator was created with a pipeline of 30 instances
                    pipeline = mock_slicer.call_args[0][0]
                    self.assertEqual(len(pipeline), 30)

    def test_havoc_uses_15_to_50_mutations(self):
        """Test that havoc slicing uses 15-50 mutations."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.random.randint", return_value=25):
            with patch("lafleur.mutation_controller.random.choices") as mock_choices:
                mock_choices.return_value = [self.mock_transformer] * 25

                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_instance = MagicMock()
                    mock_slicer.return_value = mock_instance
                    mock_instance.visit.return_value = tree

                    with patch("sys.stderr", new_callable=io.StringIO):
                        _, mutation_info = self.controller._run_slicing(tree, "havoc", 101)

                    # Verify choices was called with k=25
                    self.assertEqual(mock_choices.call_args[1]["k"], 25)

    def test_returns_slicing_mutator_result(self):
        """Test that slicing returns SlicingMutator result."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.random.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree

                    with patch("sys.stderr", new_callable=io.StringIO):
                        result_ast, mutation_info = self.controller._run_slicing(tree, "havoc", 101)

                    self.assertEqual(mutation_info["strategy"], "slicing_havoc")
                    self.assertEqual(mutation_info["transformers"], ["SlicingMutator"])

    def test_logs_large_ast_detection(self):
        """Test that slicing logs large AST detection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.random.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.random.choices", return_value=[self.mock_transformer]
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree

                    with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                        self.controller._run_slicing(tree, "havoc", 150)

                        output = mock_stderr.getvalue()
                        self.assertIn("Large AST detected", output)
                        self.assertIn("150 statements", output)


class TestRunSplicingStage(unittest.TestCase):
    """Test _run_splicing_stage method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)

        # Mock corpus_manager
        self.controller.corpus_manager = MagicMock()

        # Mock _get_core_code function
        self.controller._get_core_code = MagicMock()

    def test_returns_original_if_no_parent_selected(self):
        """Test that original AST is returned if no parent selected."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.corpus_manager.select_parent.return_value = None

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.controller._run_splicing_stage(tree.body)

        self.assertEqual(result, tree.body)

    def test_returns_original_on_io_error(self):
        """Test that original AST is returned on IO error."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        mock_path = MagicMock()
        mock_path.read_text.side_effect = IOError("File not found")
        self.controller.corpus_manager.select_parent.return_value = (mock_path, "id")

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.controller._run_splicing_stage(tree.body)

        self.assertEqual(result, tree.body)

    def test_returns_original_on_syntax_error(self):
        """Test that original AST is returned on syntax error."""
        code = dedent("""
            int_v1 = 5
            def uop_harness_test():
                x = int_v1
        """)
        tree = ast.parse(code)

        mock_path = MagicMock()
        mock_path.read_text.return_value = "invalid python syntax @#$"
        self.controller.corpus_manager.select_parent.return_value = (mock_path, "id")

        self.controller._get_core_code.return_value = "invalid python syntax @#$"

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.controller._run_splicing_stage(tree.body)

        self.assertEqual(result, tree.body)

    def test_returns_original_if_no_harness_in_parent_b(self):
        """Test that original is returned if parent B has no harness."""
        code_a = dedent("""
            int_v1 = 5
            def uop_harness_test():
                x = int_v1
        """)
        tree_a = ast.parse(code_a)

        code_b = dedent("""
            int_v1 = 10
        """)

        mock_path = MagicMock()
        mock_path.read_text.return_value = code_b
        self.controller.corpus_manager.select_parent.return_value = (mock_path, "id")

        self.controller._get_core_code.return_value = code_b

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.controller._run_splicing_stage(tree_a.body)

        self.assertEqual(result, tree_a.body)

    def test_returns_original_if_type_mismatch(self):
        """Test that original is returned if variable types don't match."""
        code_a = dedent("""
            str_v1 = "hello"
            def uop_harness_test():
                pass
        """)
        tree_a = ast.parse(code_a)

        code_b = dedent("""
            int_v1 = 5
            def uop_harness_b():
                x = int_v1
        """)

        mock_path = MagicMock()
        mock_path.read_text.return_value = code_b
        self.controller.corpus_manager.select_parent.return_value = (mock_path, "id")

        self.controller._get_core_code.return_value = code_b

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.controller._run_splicing_stage(tree_a.body)

            self.assertIn("Splice failed", mock_stderr.getvalue())

        self.assertEqual(result, tree_a.body)

    def test_successful_splice_with_variable_remapping(self):
        """Test successful splicing with variable remapping."""
        code_a = dedent("""
            int_v1 = 5
            int_v2 = 10
            def uop_harness_test():
                pass
        """)
        tree_a = ast.parse(code_a)

        code_b = dedent("""
            int_v1 = 7
            def uop_harness_b():
                x = int_v1
        """)

        mock_path = MagicMock()
        mock_path.read_text.return_value = code_b
        self.controller.corpus_manager.select_parent.return_value = (mock_path, "id")

        self.controller._get_core_code.return_value = code_b

        with patch("lafleur.mutation_controller.RANDOM.choice", return_value="int_v1"):
            result = self.controller._run_splicing_stage(tree_a.body)

        # Result should be an ast.Module (successful splice returns a new Module)
        self.assertIsInstance(result, ast.Module)
        # Verify the result has both setup nodes and a function
        self.assertTrue(len(result.body) > 0)

    def test_logs_splicing_attempt(self):
        """Test that splicing attempt is logged."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.corpus_manager.select_parent.return_value = None

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            self.controller._run_splicing_stage(tree.body)

            self.assertIn("SPLICING", mock_stderr.getvalue())


class TestSplicingWithoutCorpusManager(unittest.TestCase):
    """Test _run_splicing_stage when corpus_manager is None."""

    def setUp(self):
        """Set up MutationController with no corpus_manager."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.corpus_manager = None

    def test_returns_original_ast_when_corpus_manager_is_none(self):
        """Splicing returns the original AST unchanged when corpus_manager is None."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.controller._run_splicing_stage(tree.body)

        self.assertEqual(result, tree.body)
        self.assertIn("Splicing unavailable", mock_stderr.getvalue())

    def test_splicing_works_after_corpus_manager_set(self):
        """Splicing works normally after corpus_manager is set post-construction."""
        self.controller.corpus_manager = MagicMock()
        self.controller.corpus_manager.select_parent.return_value = None
        self.controller._get_core_code = MagicMock()

        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.controller._run_splicing_stage(tree.body)

        # With select_parent returning None, it returns the original
        self.assertEqual(result, tree.body)
        # But corpus_manager.select_parent was called (guard passed)
        self.controller.corpus_manager.select_parent.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
