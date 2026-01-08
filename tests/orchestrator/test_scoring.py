#!/usr/bin/env python3
"""
Tests for scoring components in lafleur/orchestrator.py.

This module contains unit tests for NewCoverageInfo and InterestingnessScorer
classes that determine which mutations are worth keeping.
"""

import unittest

from lafleur.orchestrator import NewCoverageInfo, InterestingnessScorer


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

    def test_min_interesting_score_constant(self):
        """Test that MIN_INTERESTING_SCORE is set to 10.0."""
        self.assertEqual(InterestingnessScorer.MIN_INTERESTING_SCORE, 10.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
