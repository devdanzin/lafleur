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

        # Mock score_tracker with record_attempt wired to real attempts dict
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.attempts = defaultdict(int)
        self.controller.score_tracker.record_attempt.side_effect = (
            lambda name: self.controller.score_tracker.attempts.__setitem__(
                name, self.controller.score_tracker.attempts[name] + 1
            )
        )
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

    def test_seeds_random_generator(self):
        """Test that the dedicated RNG is seeded correctly."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        with patch("lafleur.mutation_controller.RANDOM.seed") as mock_random_seed:
            self.controller.apply_mutation_strategy(tree, seed=12345)

            mock_random_seed.assert_called_with(12345)

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

        with patch("lafleur.mutation_controller.RANDOM.choices") as mock_choices:
            mock_choices.return_value = [self.mock_det]

            self.controller.apply_mutation_strategy(tree, seed=42)

            # Verify weights were requested and used
            self.controller.score_tracker.get_weights.assert_called()
            call_args = mock_choices.call_args
            self.assertEqual(call_args[1]["weights"], [10.0, 1.0, 1.0])

    def test_records_only_chosen_strategy_attempt(self):
        """Test that only the chosen strategy has its attempt recorded."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        with patch("lafleur.mutation_controller.RANDOM.choices") as mock_choices:
            mock_choices.return_value = [self.mock_havoc]
            self.controller.apply_mutation_strategy(tree, seed=42)

        # Only the chosen strategy should have an attempt recorded
        self.assertEqual(self.controller.score_tracker.attempts["havoc"], 1)
        self.assertEqual(self.controller.score_tracker.attempts["deterministic"], 0)
        self.assertEqual(self.controller.score_tracker.attempts["spam"], 0)

    def test_attempt_counts_accumulate_for_chosen_strategies(self):
        """Test that attempts only accumulate for actually chosen strategies."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        # Call twice, choosing havoc both times
        with patch("lafleur.mutation_controller.RANDOM.choices") as mock_choices:
            mock_choices.return_value = [self.mock_havoc]
            self.controller.apply_mutation_strategy(tree, seed=42)
            self.controller.apply_mutation_strategy(tree, seed=43)

        self.assertEqual(self.controller.score_tracker.attempts["havoc"], 2)
        self.assertEqual(self.controller.score_tracker.attempts["deterministic"], 0)
        self.assertEqual(self.controller.score_tracker.attempts["spam"], 0)

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

    def test_reproducibility_with_same_seed(self):
        """Calling apply_mutation_strategy twice with the same seed produces identical ASTs."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = x + 2
        """)
        tree = ast.parse(code)

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        result1, info1 = self.controller.apply_mutation_strategy(tree, seed=99999)
        result2, info2 = self.controller.apply_mutation_strategy(tree, seed=99999)

        self.assertEqual(ast.dump(result1), ast.dump(result2))
        self.assertEqual(info1["strategy"], info2["strategy"])

    def test_large_ast_routes_through_slicing(self):
        """Large ASTs are routed through _run_slicing instead of the chosen strategy."""
        statements = [
            ast.Assign(targets=[ast.Name(id=f"x{i}")], value=ast.Constant(value=i))
            for i in range(101)
        ]
        tree = ast.Module(body=statements, type_ignores=[])

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam

        with patch.object(self.controller, "_run_slicing") as mock_slice:
            mock_slice.return_value = (tree, {"strategy": "slicing_havoc"})
            self.controller.apply_mutation_strategy(tree, seed=42)

            mock_slice.assert_called_once()
            # The stage name should match the chosen strategy
            call_args = mock_slice.call_args
            self.assertIn(call_args[0][1], ("deterministic", "havoc", "spam"))
            self.assertEqual(call_args[0][2], 101)


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

        # Mock score_tracker with record_attempt wired to real attempts dict
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.attempts = defaultdict(int)
        self.controller.score_tracker.record_attempt.side_effect = (
            lambda name: self.controller.score_tracker.attempts.__setitem__(
                name, self.controller.score_tracker.attempts[name] + 1
            )
        )
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
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_havoc_stage(tree)

        # Should have applied 20 transformations
        self.assertEqual(len(mutation_info["transformers"]), 20)

    def test_uses_dynamic_weights(self):
        """Test that havoc uses dynamic weights for selection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.score_tracker.get_weights.return_value = [5.0]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch("lafleur.mutation_controller.RANDOM.choices") as mock_choices:
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
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
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
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
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
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
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
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_spam_stage(tree)

        # Should have 25 of the same transformer
        self.assertEqual(len(mutation_info["transformers"]), 25)
        self.assertTrue(all(t == "SpamTransformer" for t in mutation_info["transformers"]))

    def test_chooses_one_transformer_with_weights(self):
        """Test that spam chooses ONE transformer using weights."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        self.controller.score_tracker.get_weights.return_value = [10.0]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch("lafleur.mutation_controller.RANDOM.choices") as mock_choices:
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
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
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
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_spam_stage(tree)

        self.assertEqual(mutation_info["strategy"], "spam")


class TestRunSniperStage(unittest.TestCase):
    """Test _run_sniper_stage method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()

        # Create mock transformer for havoc fallback
        self.mock_transformer = MagicMock()
        self.mock_transformer.__name__ = "MockTransformer"
        self.mock_transformer.return_value.visit = MagicMock(side_effect=lambda x: x)
        self.controller.ast_mutator.transformers = [self.mock_transformer]

        # Mock score_tracker with record_attempt wired to real attempts dict
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.attempts = defaultdict(int)
        self.controller.score_tracker.record_attempt.side_effect = (
            lambda name: self.controller.score_tracker.attempts.__setitem__(
                name, self.controller.score_tracker.attempts[name] + 1
            )
        )
        self.controller.score_tracker.get_weights.return_value = [1.0]

        self.tree = ast.parse(
            dedent("""
            def uop_harness_test():
                x = 1
        """)
        )

    def test_fallback_strategy_is_sniper_fallback_not_havoc(self):
        """When watched_keys is empty, strategy should be 'sniper_fallback', not 'havoc'."""
        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices",
                return_value=[self.mock_transformer],
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_sniper_stage(
                        self.tree, seed=42, watched_keys=[]
                    )

        self.assertEqual(mutation_info["strategy"], "sniper_fallback")

    def test_fallback_with_none_watched_keys(self):
        """When watched_keys is None, strategy should be 'sniper_fallback'."""
        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices",
                return_value=[self.mock_transformer],
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_sniper_stage(
                        self.tree, seed=42, watched_keys=None
                    )

        self.assertEqual(mutation_info["strategy"], "sniper_fallback")

    def test_normal_path_strategy_is_sniper(self):
        """When watched_keys are provided, strategy should be 'sniper'."""
        with patch("sys.stderr", new_callable=io.StringIO):
            _, mutation_info = self.controller._run_sniper_stage(
                self.tree, seed=42, watched_keys=["LOAD_ATTR", "STORE_FAST"]
            )

        self.assertEqual(mutation_info["strategy"], "sniper")


class TestRunHelperSniperStage(unittest.TestCase):
    """Test _run_helper_sniper_stage method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()

        # Create mock transformer for havoc fallback
        self.mock_transformer = MagicMock()
        self.mock_transformer.__name__ = "MockTransformer"
        self.mock_transformer.return_value.visit = MagicMock(side_effect=lambda x: x)
        self.controller.ast_mutator.transformers = [self.mock_transformer]

        # Mock score_tracker with record_attempt wired to real attempts dict
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.attempts = defaultdict(int)
        self.controller.score_tracker.record_attempt.side_effect = (
            lambda name: self.controller.score_tracker.attempts.__setitem__(
                name, self.controller.score_tracker.attempts[name] + 1
            )
        )
        self.controller.score_tracker.get_weights.return_value = [1.0]

        self.tree = ast.parse(
            dedent("""
            def uop_harness_test():
                x = 1
        """)
        )

    def test_fallback_strategy_is_helper_sniper_fallback(self):
        """When no helpers detected, strategy should be 'helper_sniper_fallback'."""
        with patch("lafleur.mutation_controller.HelperFunctionInjector") as mock_injector_cls:
            mock_injector = MagicMock()
            mock_injector_cls.return_value = mock_injector
            mock_injector.visit.return_value = self.tree
            mock_injector.helpers_injected = []  # No helpers detected

            with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
                with patch(
                    "lafleur.mutation_controller.RANDOM.choices",
                    return_value=[self.mock_transformer],
                ):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        _, mutation_info = self.controller._run_helper_sniper_stage(
                            self.tree, seed=42
                        )

        self.assertEqual(mutation_info["strategy"], "helper_sniper_fallback")

    def test_normal_path_strategy_is_helper_sniper(self):
        """When helpers are detected, strategy should be 'helper_sniper'."""
        with patch("lafleur.mutation_controller.HelperFunctionInjector") as mock_injector_cls:
            mock_injector = MagicMock()
            mock_injector_cls.return_value = mock_injector
            mock_injector.visit.return_value = self.tree
            mock_injector.helpers_injected = ["_jit_helper_foo"]

            with patch("lafleur.mutation_controller.SniperMutator") as mock_sniper_cls:
                mock_sniper = MagicMock()
                mock_sniper_cls.return_value = mock_sniper
                mock_sniper.visit.return_value = self.tree

                with patch("sys.stderr", new_callable=io.StringIO):
                    _, mutation_info = self.controller._run_helper_sniper_stage(self.tree, seed=42)

        self.assertEqual(mutation_info["strategy"], "helper_sniper")


class TestRunSlicing(unittest.TestCase):
    """Test _run_slicing method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.get_weights.return_value = [1.0]

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

        with patch("lafleur.mutation_controller.RANDOM.seed") as mock_seed:
            with patch("lafleur.mutation_controller.RANDOM.randint", return_value=2):
                with patch(
                    "lafleur.mutation_controller.RANDOM.choices",
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

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=2) as mock_randint:
            with patch(
                "lafleur.mutation_controller.RANDOM.choices",
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

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=30):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
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

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=25):
            with patch("lafleur.mutation_controller.RANDOM.choices") as mock_choices:
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

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree

                    with patch("sys.stderr", new_callable=io.StringIO):
                        result_ast, mutation_info = self.controller._run_slicing(tree, "havoc", 101)

                    self.assertEqual(mutation_info["strategy"], "havoc")
                    self.assertNotIn("SlicingMutator", mutation_info["transformers"])
                    self.assertTrue(mutation_info["sliced"])

    def test_logs_large_ast_detection(self):
        """Test that slicing logs large AST detection."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=1):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices", return_value=[self.mock_transformer]
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree

                    with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                        self.controller._run_slicing(tree, "havoc", 150)

                        output = mock_stderr.getvalue()
                        self.assertIn("Large AST detected", output)
                        self.assertIn("150 statements", output)

    def test_slicing_records_actual_transformers(self):
        """Slicing records real transformer names, not SlicingMutator."""
        tree = ast.parse("def uop_harness_test():\n    x = 1")

        # Use real classes so type(cls()).__name__ works correctly
        OperatorSwapper = type("OperatorSwapper", (), {"visit": lambda self, n: n})
        GuardInjector = type("GuardInjector", (), {"visit": lambda self, n: n})
        self.controller.ast_mutator.transformers = [OperatorSwapper, GuardInjector]
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.get_weights.return_value = [1.0, 1.0]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=2):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices",
                return_value=[OperatorSwapper, GuardInjector],
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree
                    with patch("sys.stderr", new_callable=io.StringIO):
                        _, info = self.controller._run_slicing(tree, "havoc", 101)

        self.assertEqual(info["strategy"], "havoc")
        self.assertEqual(info["transformers"], ["OperatorSwapper", "GuardInjector"])
        self.assertNotIn("SlicingMutator", info["transformers"])
        self.assertTrue(info["sliced"])

    def test_slicing_records_attempts_for_transformers(self):
        """Slicing records attempts for each pipeline transformer."""
        tree = ast.parse("def uop_harness_test():\n    x = 1")

        OperatorSwapper = type("OperatorSwapper", (), {"visit": lambda self, n: n})
        self.controller.ast_mutator.transformers = [OperatorSwapper]
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.get_weights.return_value = [1.0]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=3):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices",
                return_value=[OperatorSwapper, OperatorSwapper, OperatorSwapper],
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.controller._run_slicing(tree, "havoc", 101)

        # Should have called record_attempt 3 times for OperatorSwapper
        attempt_calls = [
            c[0][0] for c in self.controller.score_tracker.record_attempt.call_args_list
        ]
        self.assertEqual(attempt_calls, ["OperatorSwapper"] * 3)

    def test_slicing_strategy_matches_parent_strategy(self):
        """Strategy name is the original (havoc/spam/deterministic), not slicing_*."""
        tree = ast.parse("def uop_harness_test():\n    x = 1")
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.get_weights.return_value = [1.0]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=2):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices",
                return_value=[self.mock_transformer],
            ):
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree
                    with patch("sys.stderr", new_callable=io.StringIO):
                        for stage in ("deterministic", "havoc", "spam"):
                            _, info = self.controller._run_slicing(tree, stage, 101, seed=42)
                            self.assertEqual(
                                info["strategy"],
                                stage,
                                f"Strategy should be '{stage}', not 'slicing_{stage}'",
                            )
                            self.assertTrue(info["sliced"])

    def test_slicing_uses_dynamic_weights(self):
        """Slicing uses learned weights for transformer selection."""
        tree = ast.parse("def uop_harness_test():\n    x = 1")
        self.controller.score_tracker = MagicMock()
        custom_weights = [0.8, 0.2]
        self.controller.score_tracker.get_weights.return_value = custom_weights

        mock_t1 = MagicMock()
        mock_t1.__name__ = "T1"
        mock_t2 = MagicMock()
        mock_t2.__name__ = "T2"
        self.controller.ast_mutator.transformers = [mock_t1, mock_t2]

        with patch("lafleur.mutation_controller.RANDOM.randint", return_value=2):
            with patch(
                "lafleur.mutation_controller.RANDOM.choices", return_value=[mock_t1]
            ) as mock_choices:
                with patch("lafleur.mutation_controller.SlicingMutator") as mock_slicer:
                    mock_slicer.return_value.visit.return_value = tree
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.controller._run_slicing(tree, "havoc", 101)

            # Verify weights were passed to choices
            mock_choices.assert_called_with([mock_t1, mock_t2], weights=custom_weights, k=2)


class TestHygienePass(unittest.TestCase):
    """Test the hygiene mutator pass in apply_mutation_strategy."""

    def setUp(self):
        """Set up a MutationController with mocked dependencies."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.ast_mutator = MagicMock()
        self.controller.ast_mutator.transformers = [MagicMock, MagicMock]
        self.controller.score_tracker = MagicMock()
        self.controller.score_tracker.attempts = defaultdict(int)
        self.controller.score_tracker.record_attempt.side_effect = (
            lambda name: self.controller.score_tracker.attempts.__setitem__(
                name, self.controller.score_tracker.attempts[name] + 1
            )
        )
        self.controller.score_tracker.get_weights.return_value = [1.0, 1.0, 1.0, 1.0]
        self.controller.corpus_manager = None
        self.controller.differential_testing = False
        self.controller.health_monitor = None

        # Set up mock strategy methods
        self.dummy_tree = ast.parse("x = 1")
        self.mock_det = MagicMock(
            return_value=(self.dummy_tree, {"strategy": "deterministic", "transformers": ["Op"]})
        )
        self.mock_det.__name__ = "_run_deterministic_stage"
        self.mock_havoc = MagicMock(
            return_value=(self.dummy_tree, {"strategy": "havoc", "transformers": ["Op"]})
        )
        self.mock_havoc.__name__ = "_run_havoc_stage"
        self.mock_spam = MagicMock(
            return_value=(self.dummy_tree, {"strategy": "spam", "transformers": ["Op"]})
        )
        self.mock_spam.__name__ = "_run_spam_stage"
        self.mock_helper = MagicMock(
            return_value=(self.dummy_tree, {"strategy": "helper_sniper", "transformers": ["Op"]})
        )
        self.mock_helper.__name__ = "_run_helper_sniper_stage"

        self.controller._run_deterministic_stage = self.mock_det
        self.controller._run_havoc_stage = self.mock_havoc
        self.controller._run_spam_stage = self.mock_spam
        self.controller._run_helper_sniper_stage = self.mock_helper

    def _run_strategy(self, hygiene_random_values):
        """Run apply_mutation_strategy with controlled hygiene RANDOM.random() calls."""
        tree = ast.parse("x = 1")

        with patch("lafleur.mutation_controller.RANDOM") as mock_rng:
            # RANDOM.seed is called, no-op
            mock_rng.seed = MagicMock()
            # RANDOM.choices selects strategy: pick deterministic
            mock_rng.choices.return_value = [self.mock_det]
            # RANDOM.random is called once per hygiene mutator
            mock_rng.random.side_effect = hygiene_random_values
            _, info = self.controller.apply_mutation_strategy(tree, seed=42)
        return info

    def test_hygiene_mutators_applied_when_random_below_threshold(self):
        """Test that hygiene mutators run when RANDOM.random() < probability."""
        # 3 hygiene mutators with probabilities 0.15, 0.20, 0.25
        # Provide values below all thresholds so all fire
        info = self._run_strategy([0.01, 0.01, 0.01])
        transformers = info.get("transformers", [])
        self.assertIn("ImportChaosMutator", transformers)
        self.assertIn("ImportPrunerMutator", transformers)
        self.assertIn("RedundantStatementSanitizer", transformers)

    def test_hygiene_mutators_skipped_when_random_above_threshold(self):
        """Test that hygiene mutators are skipped when random is high."""
        info = self._run_strategy([0.99, 0.99, 0.99])
        transformers = info.get("transformers", [])
        for cls, _ in MutationController.HYGIENE_MUTATORS:
            self.assertNotIn(cls.__name__, transformers)

    def test_hygiene_mutators_partial_application(self):
        """Test that only some hygiene mutators fire based on probability."""
        # First below 0.15, second above 0.20, third below 0.25
        info = self._run_strategy([0.10, 0.50, 0.10])
        transformers = info.get("transformers", [])
        self.assertIn("ImportChaosMutator", transformers)
        self.assertNotIn("ImportPrunerMutator", transformers)
        self.assertIn("RedundantStatementSanitizer", transformers)

    def test_hygiene_class_constant_has_expected_entries(self):
        """Test HYGIENE_MUTATORS constant has exactly the expected mutators."""
        names = [cls.__name__ for cls, _ in MutationController.HYGIENE_MUTATORS]
        self.assertEqual(
            names, ["ImportChaosMutator", "ImportPrunerMutator", "RedundantStatementSanitizer"]
        )


class TestRecordSuccessHygieneFiltering(unittest.TestCase):
    """Test that hygiene mutators are filtered from record_success calls."""

    def test_hygiene_names_filtered_from_record_success(self):
        """Verify hygiene mutator names are stripped before record_success."""
        from lafleur.orchestrator import LafleurOrchestrator

        orch = LafleurOrchestrator.__new__(LafleurOrchestrator)
        orch.run_stats = {}
        orch.mutations_since_last_find = 0
        orch.score_tracker = MagicMock()

        analysis_data = {
            "status": "DIVERGENCE",
            "mutation_info": {
                "strategy": "havoc",
                "transformers": [
                    "OperatorSwapper",
                    "ImportChaosMutator",
                    "ImportPrunerMutator",
                    "RedundantStatementSanitizer",
                ],
            },
        }

        orch._handle_analysis_data(analysis_data, i=0, parent_metadata={}, nojit_cv=None)

        orch.score_tracker.record_success.assert_called_once_with("havoc", ["OperatorSwapper"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
