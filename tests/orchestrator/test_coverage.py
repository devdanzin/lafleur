#!/usr/bin/env python3
"""
Tests for coverage analysis methods.

This module contains unit tests for coverage-related functionality:
- ScoringManager methods (find_new_coverage, score_and_decide_interestingness) in lafleur/scoring.py
- Orchestrator methods (update_global_coverage, calculate_coverage_hash) in lafleur/orchestrator.py
"""

import hashlib
import io
import unittest
from unittest.mock import MagicMock, patch

from lafleur.orchestrator import LafleurOrchestrator
from lafleur.scoring import ScoringManager, NewCoverageInfo


class TestFindNewCoverage(unittest.TestCase):
    """Test ScoringManager.find_new_coverage method."""

    def setUp(self):
        """Set up ScoringManager with mock coverage manager."""
        # Mock coverage manager with state
        self.coverage_manager = MagicMock()
        self.coverage_manager.state = {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}}
        }

        # Mock reverse maps for coverage ID lookups
        self.coverage_manager.reverse_uop_map = {100: "_BINARY_OP", 101: "_LOAD_FAST"}
        self.coverage_manager.reverse_edge_map = {200: "edge_1->2", 201: "edge_2->3"}
        self.coverage_manager.reverse_rare_event_map = {
            300: "_DEOPT",
            301: "_GUARD_FAIL",
        }

        self.scoring_manager = ScoringManager(self.coverage_manager, timing_fuzz=False)

    def test_find_new_coverage_empty_child(self):
        """Test that empty child coverage returns empty NewCoverageInfo."""
        child_coverage = {}
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        self.assertFalse(info.is_interesting())
        self.assertEqual(info.total_child_edges, 0)

    def test_find_new_coverage_global_discovery(self):
        """Test that new global coverage is detected."""
        child_coverage = {"harness1": {"uops": {100: 5}, "edges": {200: 3}, "rare_events": {}}}
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        self.assertEqual(info.global_uops, 1)
        self.assertEqual(info.global_edges, 1)
        self.assertEqual(info.global_rare_events, 0)
        self.assertIn("NEW GLOBAL UOP", mock_stderr.getvalue())
        self.assertIn("NEW GLOBAL EDGE", mock_stderr.getvalue())

    def test_find_new_coverage_relative_discovery(self):
        """Test relative coverage (global exists, not in lineage)."""
        # Item 100 exists globally but not in parent lineage
        self.coverage_manager.state["global_coverage"]["uops"][100] = 10

        child_coverage = {"harness1": {"uops": {100: 5}, "edges": {}, "rare_events": {}}}
        parent_lineage_profile = {
            "harness1": {
                "uops": set(),  # Empty lineage
                "edges": set(),
                "rare_events": set(),
            }
        }

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        self.assertEqual(info.global_uops, 0)
        self.assertEqual(info.relative_uops, 1)
        self.assertIn("NEW RELATIVE UOP", mock_stderr.getvalue())

    def test_find_new_coverage_rare_events(self):
        """Test rare event discovery."""
        child_coverage = {"harness1": {"uops": {}, "edges": {}, "rare_events": {300: 2, 301: 1}}}
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        self.assertEqual(info.global_rare_events, 2)

    def test_find_new_coverage_multiple_harnesses(self):
        """Test coverage across multiple harnesses."""
        child_coverage = {
            "harness1": {"uops": {100: 3}, "edges": {200: 2}, "rare_events": {}},
            "harness2": {"uops": {101: 5}, "edges": {201: 1}, "rare_events": {300: 1}},
        }
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        self.assertEqual(info.global_uops, 2)
        self.assertEqual(info.global_edges, 2)
        self.assertEqual(info.global_rare_events, 1)

    def test_find_new_coverage_total_edges_counting(self):
        """Test correct total edge count."""
        child_coverage = {
            "harness1": {"uops": {}, "edges": {200: 1, 201: 1, 202: 1}, "rare_events": {}},
            "harness2": {"uops": {}, "edges": {203: 1, 204: 1}, "rare_events": {}},
        }
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        self.assertEqual(info.total_child_edges, 5)

    def test_find_new_coverage_seed_parent(self):
        """Test seed file (parent_id=None)."""
        child_coverage = {"harness1": {"uops": {100: 5}, "edges": {}, "rare_events": {}}}
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id=None
            )

        # Seeds should only get global coverage, no relative
        self.assertEqual(info.global_uops, 1)
        self.assertEqual(info.relative_uops, 0)

    def test_find_new_coverage_unknown_id(self):
        """Test handling of unknown coverage IDs."""
        child_coverage = {
            "harness1": {
                "uops": {999: 1},  # Unknown ID
                "edges": {},
                "rare_events": {},
            }
        }
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        self.assertEqual(info.global_uops, 1)
        self.assertIn("ID_999_(unknown)", mock_stderr.getvalue())

    def test_find_new_coverage_no_relative_when_in_lineage(self):
        """Test that items in lineage are not counted as relative."""
        self.coverage_manager.state["global_coverage"]["uops"][100] = 10

        child_coverage = {"harness1": {"uops": {100: 5}, "edges": {}, "rare_events": {}}}
        parent_lineage_profile = {
            "harness1": {
                "uops": {100},  # Already in lineage
                "edges": set(),
                "rare_events": set(),
            }
        }

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

        # Should not count as relative since it's in the lineage
        self.assertEqual(info.relative_uops, 0)


class TestUpdateGlobalCoverage(unittest.TestCase):
    """Test _update_global_coverage method."""

    def setUp(self):
        """Set up minimal orchestrator instance."""
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.coverage_manager = MagicMock()
        self.orchestrator.coverage_manager.state = {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}}
        }

    def test_update_global_coverage_new_items(self):
        """Test adding new coverage items."""
        child_coverage = {
            "harness1": {"uops": {100: 5}, "edges": {200: 3}, "rare_events": {300: 1}}
        }

        self.orchestrator._update_global_coverage(child_coverage)

        global_cov = self.orchestrator.coverage_manager.state["global_coverage"]
        self.assertEqual(global_cov["uops"][100], 5)
        self.assertEqual(global_cov["edges"][200], 3)
        self.assertEqual(global_cov["rare_events"][300], 1)

    def test_update_global_coverage_increment_existing(self):
        """Test incrementing existing coverage counts."""
        # Pre-populate global coverage
        global_cov = self.orchestrator.coverage_manager.state["global_coverage"]
        global_cov["uops"][100] = 10
        global_cov["edges"][200] = 5

        child_coverage = {"harness1": {"uops": {100: 5}, "edges": {200: 3}, "rare_events": {}}}

        self.orchestrator._update_global_coverage(child_coverage)

        self.assertEqual(global_cov["uops"][100], 15)
        self.assertEqual(global_cov["edges"][200], 8)

    def test_update_global_coverage_multiple_harnesses(self):
        """Test update from multiple harnesses."""
        child_coverage = {
            "harness1": {"uops": {100: 3}, "edges": {}, "rare_events": {}},
            "harness2": {"uops": {101: 5}, "edges": {201: 2}, "rare_events": {}},
        }

        self.orchestrator._update_global_coverage(child_coverage)

        global_cov = self.orchestrator.coverage_manager.state["global_coverage"]
        self.assertEqual(global_cov["uops"][100], 3)
        self.assertEqual(global_cov["uops"][101], 5)
        self.assertEqual(global_cov["edges"][201], 2)

    def test_update_global_coverage_empty_child(self):
        """Test handling of empty child coverage."""
        child_coverage = {}

        self.orchestrator._update_global_coverage(child_coverage)

        global_cov = self.orchestrator.coverage_manager.state["global_coverage"]
        self.assertEqual(len(global_cov["uops"]), 0)
        self.assertEqual(len(global_cov["edges"]), 0)


class TestCalculateCoverageHash(unittest.TestCase):
    """Test _calculate_coverage_hash method."""

    def setUp(self):
        """Set up minimal orchestrator instance."""
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)

    def test_coverage_hash_deterministic(self):
        """Test that same coverage produces same hash."""
        coverage_profile = {"harness1": {"edges": {100: 1, 101: 2}}}

        hash1 = self.orchestrator._calculate_coverage_hash(coverage_profile)
        hash2 = self.orchestrator._calculate_coverage_hash(coverage_profile)

        self.assertEqual(hash1, hash2)

    def test_coverage_hash_order_independent(self):
        """Test that edge order doesn't affect hash."""
        coverage1 = {"harness1": {"edges": {100: 1, 101: 2, 102: 3}}}
        coverage2 = {"harness1": {"edges": {102: 3, 100: 1, 101: 2}}}

        hash1 = self.orchestrator._calculate_coverage_hash(coverage1)
        hash2 = self.orchestrator._calculate_coverage_hash(coverage2)

        self.assertEqual(hash1, hash2)

    def test_coverage_hash_different_coverage(self):
        """Test that different coverage produces different hash."""
        coverage1 = {"harness1": {"edges": {100: 1}}}
        coverage2 = {"harness1": {"edges": {101: 1}}}

        hash1 = self.orchestrator._calculate_coverage_hash(coverage1)
        hash2 = self.orchestrator._calculate_coverage_hash(coverage2)

        self.assertNotEqual(hash1, hash2)

    def test_coverage_hash_empty_profile(self):
        """Test handling of empty profile."""
        coverage_profile = {}

        hash_value = self.orchestrator._calculate_coverage_hash(coverage_profile)

        # Should produce hash of empty string
        expected_hash = hashlib.sha256("".encode("utf-8")).hexdigest()
        self.assertEqual(hash_value, expected_hash)

    def test_coverage_hash_ignores_non_edge_data(self):
        """Test that only edges are included in hash."""
        coverage1 = {"harness1": {"edges": {100: 1}}}
        coverage2 = {
            "harness1": {
                "edges": {100: 1},
                "uops": {200: 5},  # Should be ignored
                "rare_events": {300: 1},  # Should be ignored
            }
        }

        hash1 = self.orchestrator._calculate_coverage_hash(coverage1)
        hash2 = self.orchestrator._calculate_coverage_hash(coverage2)

        self.assertEqual(hash1, hash2)


class TestScoreAndDecideInterestingness(unittest.TestCase):
    """Test ScoringManager.score_and_decide_interestingness method."""

    def setUp(self):
        """Set up ScoringManager with mock coverage manager."""
        self.coverage_manager = MagicMock()
        self.scoring_manager = ScoringManager(self.coverage_manager, timing_fuzz=False)

    def test_decide_interesting_seed_with_coverage(self):
        """Test that seed with coverage is interesting."""
        coverage_info = NewCoverageInfo(global_uops=1)
        mutation_info = {"strategy": "seed_strategy"}

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id=None,  # Seed
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        self.assertTrue(result)

    def test_decide_not_interesting_seed_without_coverage(self):
        """Test that seed without coverage is not interesting."""
        coverage_info = NewCoverageInfo()
        mutation_info = {"strategy": "other_strategy"}

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id=None,  # Seed
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        self.assertFalse(result)
        self.assertIn("no JIT coverage", mock_stderr.getvalue())

    def test_decide_interesting_above_threshold(self):
        """Test that score >= 10 is interesting."""
        # 2 global edges = 20 points
        coverage_info = NewCoverageInfo(global_edges=2)
        mutation_info = {"strategy": "havoc"}

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id="parent1",
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        self.assertTrue(result)
        self.assertIn("interesting with score", mock_stderr.getvalue())

    def test_decide_not_interesting_below_threshold(self):
        """Test that score < 10 is not interesting."""
        # 1 relative edge = 1 point
        coverage_info = NewCoverageInfo(relative_edges=1)
        mutation_info = {"strategy": "havoc"}

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id="parent1",
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        self.assertFalse(result)
        self.assertIn("IS NOT interesting", mock_stderr.getvalue())

    def test_decide_interesting_timing_mode(self):
        """Test that timing bonus can make it interesting."""
        self.scoring_manager = ScoringManager(self.coverage_manager, timing_fuzz=True)
        coverage_info = NewCoverageInfo()
        mutation_info = {"strategy": "havoc"}

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id="parent1",
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=100.0,  # 10x slowdown
                nojit_avg_time_ms=10.0,
                nojit_cv=0.1,
            )

        self.assertTrue(result)
        self.assertIn("JIT slowdown", mock_stderr.getvalue())

    def test_decide_edge_case_exactly_threshold(self):
        """Test score exactly at threshold (10.0)."""
        # 1 global edge = 10 points (exactly at threshold)
        coverage_info = NewCoverageInfo(global_edges=1)
        mutation_info = {"strategy": "havoc"}

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id="parent1",
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        self.assertTrue(result)

    def test_decide_logs_score(self):
        """Test that score is logged to stderr."""
        coverage_info = NewCoverageInfo(global_edges=1)
        mutation_info = {"strategy": "havoc"}

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id="parent1",
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        output = mock_stderr.getvalue()
        self.assertIn("10.00", output)  # Score should be logged

    def test_decide_no_timing_bonus_when_disabled(self):
        """Test that no timing bonus is given when timing_fuzz=False."""
        self.scoring_manager = ScoringManager(self.coverage_manager, timing_fuzz=False)
        coverage_info = NewCoverageInfo()
        mutation_info = {"strategy": "havoc"}

        with patch("sys.stderr", new_callable=io.StringIO):
            result = self.scoring_manager.score_and_decide_interestingness(
                coverage_info,
                parent_id="parent1",
                mutation_info=mutation_info,
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=100.0,  # Would be 10x slowdown
                nojit_avg_time_ms=10.0,
                nojit_cv=0.1,
            )

        # No timing bonus, score = 0, should not be interesting
        self.assertFalse(result)


class TestCoverageWorkflow(unittest.TestCase):
    """Integration tests for coverage workflow."""

    def setUp(self):
        """Set up minimal orchestrator instance and ScoringManager."""
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)

        # Mock coverage manager
        self.orchestrator.coverage_manager = MagicMock()
        self.orchestrator.coverage_manager.state = {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}}
        }
        self.orchestrator.coverage_manager.reverse_uop_map = {100: "_BINARY_OP"}
        self.orchestrator.coverage_manager.reverse_edge_map = {200: "edge_1->2"}
        self.orchestrator.coverage_manager.reverse_rare_event_map = {300: "_DEOPT"}

        # Create ScoringManager with the same mock coverage_manager
        self.scoring_manager = ScoringManager(
            self.orchestrator.coverage_manager, timing_fuzz=False
        )

    def test_workflow_new_global_coverage(self):
        """Test complete workflow with new global coverage."""
        child_coverage = {"harness1": {"uops": {100: 5}, "edges": {200: 3}, "rare_events": {}}}
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO):
            # Find coverage
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

            # Update global
            self.orchestrator._update_global_coverage(child_coverage)

            # Calculate hash
            coverage_hash = self.orchestrator._calculate_coverage_hash(child_coverage)

            # Decide interestingness
            is_interesting = self.scoring_manager.score_and_decide_interestingness(
                info,
                parent_id="parent1",
                mutation_info={"strategy": "havoc"},
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        # Verify workflow
        self.assertEqual(info.global_uops, 1)
        self.assertEqual(info.global_edges, 1)
        self.assertEqual(
            self.orchestrator.coverage_manager.state["global_coverage"]["uops"][100], 5
        )
        self.assertTrue(is_interesting)
        self.assertIsInstance(coverage_hash, str)
        self.assertEqual(len(coverage_hash), 64)  # SHA256 hash length

    def test_workflow_relative_coverage_only(self):
        """Test workflow with only relative coverage."""
        # Pre-populate global coverage
        self.orchestrator.coverage_manager.state["global_coverage"]["edges"][200] = 10

        child_coverage = {"harness1": {"uops": {}, "edges": {200: 3}, "rare_events": {}}}
        parent_lineage_profile = {
            "harness1": {
                "uops": set(),
                "edges": set(),  # Not in lineage
                "rare_events": set(),
            }
        }

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

            is_interesting = self.scoring_manager.score_and_decide_interestingness(
                info,
                parent_id="parent1",
                mutation_info={"strategy": "havoc"},
                parent_file_size=100,
                parent_lineage_edge_count=50,
                child_file_size=100,
                jit_avg_time_ms=None,
                nojit_avg_time_ms=None,
                nojit_cv=None,
            )

        # Only relative coverage
        self.assertEqual(info.global_edges, 0)
        self.assertEqual(info.relative_edges, 1)
        # Score = 1 (relative edge), below threshold of 10
        self.assertFalse(is_interesting)

    def test_workflow_handles_multiple_harnesses(self):
        """Test workflow with multiple harnesses."""
        child_coverage = {
            "harness1": {"uops": {100: 3}, "edges": {200: 2}, "rare_events": {}},
            "harness2": {"uops": {}, "edges": {}, "rare_events": {300: 1}},
        }
        parent_lineage_profile = {}

        with patch("sys.stderr", new_callable=io.StringIO):
            info = self.scoring_manager.find_new_coverage(
                child_coverage, parent_lineage_profile, parent_id="parent1"
            )

            self.orchestrator._update_global_coverage(child_coverage)

            coverage_hash = self.orchestrator._calculate_coverage_hash(child_coverage)

        # Verify multi-harness handling
        self.assertEqual(info.global_uops, 1)
        self.assertEqual(info.global_edges, 1)
        self.assertEqual(info.global_rare_events, 1)

        global_cov = self.orchestrator.coverage_manager.state["global_coverage"]
        self.assertEqual(global_cov["uops"][100], 3)
        self.assertEqual(global_cov["rare_events"][300], 1)

        # Hash should include both harnesses
        self.assertIsInstance(coverage_hash, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
