#!/usr/bin/env python3
"""
Tests for scoring components in lafleur/scoring.py.

This module contains unit tests for NewCoverageInfo and InterestingnessScorer
classes that determine which mutations are worth keeping.
"""

import unittest
from unittest.mock import MagicMock, Mock, patch

from lafleur.scoring import NewCoverageInfo, InterestingnessScorer, ScoringManager


class TestNewCoverageInfo(unittest.TestCase):
    """Test NewCoverageInfo dataclass."""

    def test_is_interesting_with_no_coverage(self):
        """Test that empty coverage returns False."""
        info = NewCoverageInfo()
        self.assertFalse(info.is_interesting())

    def test_is_interesting_with_global_uops(self):
        """Test that global uops make it interesting."""
        info = NewCoverageInfo(global_uops=1)
        self.assertTrue(info.is_interesting())

    def test_is_interesting_with_global_edges(self):
        """Test that global edges make it interesting."""
        info = NewCoverageInfo(global_edges=1)
        self.assertTrue(info.is_interesting())

    def test_is_interesting_with_global_rare_events(self):
        """Test that rare events make it interesting."""
        info = NewCoverageInfo(global_rare_events=1)
        self.assertTrue(info.is_interesting())

    def test_is_interesting_with_relative_uops(self):
        """Test that relative uops make it interesting."""
        info = NewCoverageInfo(relative_uops=1)
        self.assertTrue(info.is_interesting())

    def test_is_interesting_with_relative_edges(self):
        """Test that relative edges make it interesting."""
        info = NewCoverageInfo(relative_edges=1)
        self.assertTrue(info.is_interesting())

    def test_is_interesting_with_relative_rare_events(self):
        """Test that relative rare events make it interesting."""
        info = NewCoverageInfo(relative_rare_events=1)
        self.assertTrue(info.is_interesting())

    def test_is_interesting_with_multiple_metrics(self):
        """Test that combined metrics work."""
        info = NewCoverageInfo(
            global_uops=2, relative_edges=3, global_rare_events=1, total_child_edges=100
        )
        self.assertTrue(info.is_interesting())


class TestInterestingnessScorer(unittest.TestCase):
    """Test InterestingnessScorer class."""

    def test_score_with_no_coverage(self):
        """Test that zero coverage equals zero score."""
        info = NewCoverageInfo()
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        self.assertEqual(scorer.calculate_score(), 0.0)

    def test_score_global_edges_heavily_weighted(self):
        """Test that global edges are worth 10 points each."""
        info = NewCoverageInfo(global_edges=3)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        self.assertEqual(scorer.calculate_score(), 30.0)

    def test_score_global_uops_weighted(self):
        """Test that global uops are worth 5 points each."""
        info = NewCoverageInfo(global_uops=4)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        self.assertEqual(scorer.calculate_score(), 20.0)

    def test_score_global_rare_events_heavily_weighted(self):
        """Test that rare events are worth 10 points each."""
        info = NewCoverageInfo(global_rare_events=2)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        self.assertEqual(scorer.calculate_score(), 20.0)

    def test_score_relative_edges_lightly_weighted(self):
        """Test that relative edges are worth 1 point each."""
        info = NewCoverageInfo(relative_edges=5)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        self.assertEqual(scorer.calculate_score(), 5.0)

    def test_score_richness_bonus(self):
        """Test richness bonus for >10% coverage increase."""
        # 50 parent edges -> 60 child edges = 20% increase
        info = NewCoverageInfo(relative_edges=5, total_child_edges=60)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        score = scorer.calculate_score()
        # 5 (relative edges) + 0.2 * 5.0 (richness bonus) = 6.0
        self.assertAlmostEqual(score, 6.0, places=5)

    def test_score_density_penalty(self):
        """Test penalty for large size with little gain."""
        # 100 bytes -> 202 bytes = 100% increase (after +1), only relative coverage
        info = NewCoverageInfo(relative_edges=2)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=202,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        score = scorer.calculate_score()
        # size_increase_ratio = (202 / 101) - 1.0 = 1.0
        # penalty = 1.0 * 2.0 = 2.0
        # score = 2.0 (relative edges) - 2.0 (penalty) = 0.0
        self.assertAlmostEqual(score, 0.0, places=5)

    def test_score_no_density_penalty_with_global_coverage(self):
        """Test that density penalty doesn't apply when global coverage exists."""
        # Large size increase but with global edges
        info = NewCoverageInfo(global_edges=2, relative_edges=2)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=200,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        score = scorer.calculate_score()
        # 20.0 (global edges) + 2.0 (relative edges) = 22.0 (no penalty)
        self.assertEqual(score, 22.0)

    def test_score_timing_mode_with_slowdown(self):
        """Test performance bonus calculation in timing mode."""
        info = NewCoverageInfo()
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=True,
            jit_avg_time_ms=100.0,
            nojit_avg_time_ms=10.0,
            nojit_cv=0.1,  # 10% coefficient of variation
        )
        score = scorer.calculate_score()
        # Slowdown ratio = 100/10 = 10.0
        # Dynamic threshold = 1.0 + (3 * 0.1) = 1.3
        # Performance bonus = (10.0 - 1.0) * 50.0 = 450.0
        self.assertAlmostEqual(score, 450.0, places=5)

    def test_score_timing_mode_below_threshold(self):
        """Test that no bonus is given when below threshold."""
        info = NewCoverageInfo()
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=True,
            jit_avg_time_ms=10.0,
            nojit_avg_time_ms=10.0,
            nojit_cv=0.1,
        )
        score = scorer.calculate_score()
        # Slowdown ratio = 1.0, threshold = 1.3, no bonus
        self.assertEqual(score, 0.0)

    def test_score_timing_mode_high_cv(self):
        """Test dynamic threshold with high coefficient of variation."""
        info = NewCoverageInfo()
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=True,
            jit_avg_time_ms=30.0,
            nojit_avg_time_ms=10.0,
            nojit_cv=0.5,  # 50% coefficient of variation
        )
        score = scorer.calculate_score()
        # Slowdown ratio = 3.0
        # Dynamic threshold = 1.0 + (3 * 0.5) = 2.5
        # Slowdown exceeds threshold, so bonus = (3.0 - 1.0) * 50.0 = 100.0
        self.assertAlmostEqual(score, 100.0, places=5)

    def test_score_combined_all_factors(self):
        """Test that all scoring factors combine correctly."""
        # Parent: 100 edges, 100 bytes
        # Child: 125 edges (25% increase), 110 bytes (10% increase)
        # Coverage: 2 global edges, 3 relative edges, 1 global uop
        info = NewCoverageInfo(
            global_edges=2, global_uops=1, relative_edges=3, total_child_edges=125
        )
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=100,
            child_file_size=110,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        score = scorer.calculate_score()
        # Global edges: 2 * 10 = 20
        # Global uops: 1 * 5 = 5
        # Relative edges: 3 * 1 = 3
        # Richness bonus: (125/100 - 1.0) * 5.0 = 0.25 * 5.0 = 1.25
        # Total: 20 + 5 + 3 + 1.25 = 29.25
        self.assertAlmostEqual(score, 29.25, places=5)

    def test_score_zero_division_protection(self):
        """Test that zero nojit time doesn't cause division errors."""
        info = NewCoverageInfo()
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=50,
            child_file_size=100,
            is_timing_mode=True,
            jit_avg_time_ms=10.0,
            nojit_avg_time_ms=0.0,  # Zero time
            nojit_cv=0.1,
        )
        score = scorer.calculate_score()
        # Should not crash, should return 0
        self.assertEqual(score, 0.0)

    def test_score_zero_parent_edges_no_crash(self):
        """Zero parent_lineage_edge_count must not cause ZeroDivisionError."""
        info = NewCoverageInfo(global_edges=1, total_child_edges=10)
        scorer = InterestingnessScorer(
            coverage_info=info,
            parent_file_size=100,
            parent_lineage_edge_count=0,  # Initial seed — no parent edges
            child_file_size=100,
            is_timing_mode=False,
            jit_avg_time_ms=None,
            nojit_avg_time_ms=None,
            nojit_cv=None,
        )
        score = scorer.calculate_score()
        # Should get global edge score (10.0) without richness bonus (skipped due to 0 parent edges)
        self.assertEqual(score, 10.0)

    def test_min_interesting_score_constant(self):
        """Test that MIN_INTERESTING_SCORE is set to 10.0."""
        self.assertEqual(InterestingnessScorer.MIN_INTERESTING_SCORE, 10.0)


class TestAnalyzeRunMutationInfo(unittest.TestCase):
    """Test that analyze_run does not mutate the caller's mutation_info dict."""

    def setUp(self):
        self.coverage_manager = MagicMock()
        self.coverage_manager.state = {"per_file_coverage": {}}
        self.artifact_manager = MagicMock()
        self.artifact_manager.check_for_crash.return_value = False
        self.corpus_manager = MagicMock()
        self.corpus_manager.known_hashes = set()

        self.scoring_manager = ScoringManager(
            coverage_manager=self.coverage_manager,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            get_core_code_func=lambda code: code,
            run_stats={"divergences_found": 0},
        )

    @patch("lafleur.scoring.parse_log_for_edge_coverage")
    def test_mutation_info_not_mutated_on_new_coverage(self, mock_parse_coverage):
        """Verify that the caller's mutation_info dict is not modified."""
        mock_parse_coverage.return_value = {"edges": {1}, "uops": set(), "rare_events": set()}

        # Make find_new_coverage return interesting results
        self.scoring_manager.find_new_coverage = Mock(
            return_value=NewCoverageInfo(global_edges=5, total_child_edges=10)
        )
        self.scoring_manager.parse_jit_stats = Mock(
            return_value={
                "max_exit_count": 0,
                "max_chain_depth": 0,
                "zombie_traces": 0,
                "min_code_size": 0,
                "max_exit_density": 0.0,
                "watched_dependencies": [],
            }
        )
        self.scoring_manager._update_global_coverage = Mock()
        self.scoring_manager._calculate_coverage_hash = Mock(return_value="abc123")

        exec_result = MagicMock()
        exec_result.is_divergence = False
        exec_result.log_path = MagicMock()
        exec_result.log_path.read_text.return_value = "log content"
        exec_result.source_path = MagicMock()
        exec_result.source_path.stat.return_value.st_size = 150
        exec_result.source_path.read_text.return_value = "print('hello')"
        exec_result.returncode = 0
        exec_result.execution_time_ms = 100
        exec_result.jit_avg_time_ms = 50.0
        exec_result.nojit_avg_time_ms = 60.0
        exec_result.nojit_cv = 0.1

        original_mutation_info = {"mutator": "test_mutator", "stage": "havoc"}
        caller_mutation_info = original_mutation_info.copy()

        result = self.scoring_manager.analyze_run(
            exec_result=exec_result,
            parent_lineage_profile={},
            parent_id=None,
            mutation_info=caller_mutation_info,
            mutation_seed=42,
            parent_file_size=100,
            parent_lineage_edge_count=50,
        )

        # The returned mutation_info should contain jit_stats
        self.assertIn("jit_stats", result["mutation_info"])
        # But the caller's dict should be unchanged
        self.assertEqual(caller_mutation_info, original_mutation_info)
        self.assertNotIn("jit_stats", caller_mutation_info)


class TestPrepareNewCoverageResult(unittest.TestCase):
    """Test the extracted _prepare_new_coverage_result method."""

    def setUp(self):
        self.coverage_manager = MagicMock()
        self.corpus_manager = MagicMock()
        self.corpus_manager.known_hashes = set()

        self.scoring_manager = ScoringManager(
            coverage_manager=self.coverage_manager,
            corpus_manager=self.corpus_manager,
            get_core_code_func=lambda code: code,
            run_stats={},
        )
        self.scoring_manager._update_global_coverage = Mock()
        self.scoring_manager._calculate_coverage_hash = Mock(return_value="covhash")

        self.exec_result = MagicMock()
        self.exec_result.source_path.read_text.return_value = "print('hello')"
        self.exec_result.execution_time_ms = 100
        self.exec_result.jit_avg_time_ms = 50.0
        self.exec_result.nojit_avg_time_ms = 60.0

    def test_returns_new_coverage_result(self):
        """Test normal path returns NEW_COVERAGE with all expected keys."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={"max_exit_density": 0.0},
            parent_jit_stats={},
            parent_id="parent.py",
            mutation_info={"mutator": "test"},
            mutation_seed=42,
        )

        self.assertEqual(result["status"], "NEW_COVERAGE")
        self.assertIn("core_code", result)
        self.assertIn("content_hash", result)
        self.assertIn("coverage_hash", result)
        self.assertEqual(result["parent_id"], "parent.py")
        self.assertEqual(result["mutation_seed"], 42)
        self.scoring_manager._update_global_coverage.assert_called_once()

    def test_duplicate_returns_no_change(self):
        """Test that known duplicate hashes return NO_CHANGE."""
        # Pre-populate known_hashes with what will be computed
        content_hash = __import__("hashlib").sha256(b"print('hello')").hexdigest()
        self.corpus_manager.known_hashes = {(content_hash, "covhash")}

        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={"max_exit_density": 0.0},
            parent_jit_stats={},
            parent_id=None,
            mutation_info={"mutator": "test"},
            mutation_seed=0,
        )

        self.assertEqual(result["status"], "NO_CHANGE")
        self.scoring_manager._update_global_coverage.assert_not_called()

    def test_density_clamping_applied(self):
        """Test that density clamping limits child density relative to parent."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={"max_exit_density": 1000.0},
            parent_jit_stats={"max_exit_density": 10.0},
            parent_id=None,
            mutation_info={},
            mutation_seed=0,
        )

        # Clamped: min(10.0 * 5.0, 1000.0) = 50.0, then decay: 50.0 * 0.95 = 47.5
        saved_density = result["mutation_info"]["jit_stats"]["max_exit_density"]
        self.assertAlmostEqual(saved_density, 47.5)

    def test_delta_density_clamped_to_parent_growth_factor(self):
        """Test delta density is clamped relative to parent's delta density."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={
                "max_exit_density": 0.0,
                "child_delta_max_exit_density": 100.0,
            },
            parent_jit_stats={
                "max_exit_density": 0.0,
                "child_delta_max_exit_density": 1.0,
            },
            parent_id=None,
            mutation_info={},
            mutation_seed=0,
        )

        # Clamped: min(1.0 * 5.0, 100.0) = 5.0, then decay: 5.0 * 0.95 = 4.75
        saved = result["mutation_info"]["jit_stats"]["child_delta_max_exit_density"]
        self.assertAlmostEqual(saved, 4.75)

    def test_delta_density_no_parent_trusts_child(self):
        """Test that with no parent delta, child value is trusted (no clamping)."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={
                "max_exit_density": 0.0,
                "child_delta_max_exit_density": 3.0,
            },
            parent_jit_stats={
                "max_exit_density": 0.0,
                "child_delta_max_exit_density": 0.0,
            },
            parent_id=None,
            mutation_info={},
            mutation_seed=0,
        )

        # No parent delta → no clamping. Decay: 3.0 * 0.95 = 2.85
        saved = result["mutation_info"]["jit_stats"]["child_delta_max_exit_density"]
        self.assertAlmostEqual(saved, 2.85)

    def test_delta_density_decay_applied(self):
        """Test that delta density is decayed by TACHYCARDIA_DECAY_FACTOR."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={
                "max_exit_density": 0.0,
                "child_delta_max_exit_density": 2.0,
            },
            parent_jit_stats={},
            parent_id=None,
            mutation_info={},
            mutation_seed=0,
        )

        # 2.0 * 0.95 = 1.9
        saved = result["mutation_info"]["jit_stats"]["child_delta_max_exit_density"]
        self.assertAlmostEqual(saved, 1.9)

    def test_delta_exits_clamped_to_parent_growth_factor(self):
        """Test delta exits clamped to parent * 5.0, then decayed by 0.95."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={
                "max_exit_density": 0.0,
                "child_delta_total_exits": 200,
            },
            parent_jit_stats={
                "max_exit_density": 0.0,
                "child_delta_total_exits": 10,
            },
            parent_id=None,
            mutation_info={},
            mutation_seed=0,
        )

        # Clamped: min(10 * 5.0, 200) = 50, then decay: 50 * 0.95 = 47.5
        saved = result["mutation_info"]["jit_stats"]["child_delta_total_exits"]
        self.assertAlmostEqual(saved, 47.5)

    def test_delta_exits_no_parent_trusts_child(self):
        """Test that with no parent delta exits, child value is trusted."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={
                "max_exit_density": 0.0,
                "child_delta_total_exits": 30,
            },
            parent_jit_stats={
                "max_exit_density": 0.0,
                "child_delta_total_exits": 0,
            },
            parent_id=None,
            mutation_info={},
            mutation_seed=0,
        )

        # No parent delta exits → no clamping. Decay: 30 * 0.95 = 28.5
        saved = result["mutation_info"]["jit_stats"]["child_delta_total_exits"]
        self.assertAlmostEqual(saved, 28.5)

    def test_delta_exits_decay_applied(self):
        """Test that the 0.95 decay factor is applied to delta exits."""
        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={
                "max_exit_density": 0.0,
                "child_delta_total_exits": 100,
            },
            parent_jit_stats={},
            parent_id=None,
            mutation_info={},
            mutation_seed=0,
        )

        # 100 * 0.95 = 95.0
        saved = result["mutation_info"]["jit_stats"]["child_delta_total_exits"]
        self.assertAlmostEqual(saved, 95.0)

    def test_syntax_error_in_core_code_returns_no_change(self):
        """SyntaxError in extracted core code returns NO_CHANGE to prevent corpus poisoning."""
        # Make _get_core_code return unparseable code
        self.scoring_manager._get_core_code = lambda code: "def broken(:\n    pass"

        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={"max_exit_density": 0.0},
            parent_jit_stats={},
            parent_id="parent.py",
            mutation_info={"mutator": "test"},
            mutation_seed=42,
        )

        self.assertEqual(result["status"], "NO_CHANGE")
        # Coverage should NOT be committed
        self.scoring_manager._update_global_coverage.assert_not_called()

    def test_valid_core_code_proceeds_normally(self):
        """Valid core code passes validation and returns NEW_COVERAGE."""
        self.exec_result.source_path.read_text.return_value = "x = 1"

        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={"max_exit_density": 0.0},
            parent_jit_stats={},
            parent_id="parent.py",
            mutation_info={"mutator": "test"},
            mutation_seed=42,
        )

        self.assertEqual(result["status"], "NEW_COVERAGE")

    def test_original_mutation_info_not_modified_with_delta(self):
        """Confirm mutation_info is still not mutated after delta changes."""
        original = {"mutator": "test", "stage": "havoc"}
        caller_copy = original.copy()

        result = self.scoring_manager._prepare_new_coverage_result(
            exec_result=self.exec_result,
            child_coverage={"edges": {1}},
            jit_stats={
                "max_exit_density": 0.0,
                "child_delta_max_exit_density": 1.0,
            },
            parent_jit_stats={},
            parent_id=None,
            mutation_info=caller_copy,
            mutation_seed=0,
        )

        self.assertEqual(caller_copy, original)
        self.assertNotIn("jit_stats", caller_copy)
        self.assertIn("jit_stats", result["mutation_info"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
