#!/usr/bin/env python3
"""
Unit tests for lafleur/corpus_manager.py
"""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from lafleur.corpus_manager import CorpusManager, CorpusScheduler
from lafleur.coverage import CoverageManager


class TestCorpusScheduler(unittest.TestCase):
    """Test the CorpusScheduler class."""

    def setUp(self):
        """Create a mock CoverageManager for testing."""
        self.state = {
            "global_coverage": {
                "edges": {},  # Will be populated per test
                "uops": {},
                "rare_events": {},
            },
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)

    def test_rarity_score_higher_for_rare_edges(self):
        """Test that files with rare edges get higher scores."""
        # Set up global coverage: edge 0 is common (hit 100 times), edge 1 is rare (hit 1 time)
        self.state["global_coverage"]["edges"] = {
            0: 100,  # Common edge
            1: 1,  # Rare edge
        }

        # File A has only the common edge
        file_a_metadata = {
            "baseline_coverage": {
                "f1": {"edges": [0], "uops": [], "rare_events": []},
            },
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        # File B has the rare edge
        file_b_metadata = {
            "baseline_coverage": {
                "f1": {"edges": [1], "uops": [], "rare_events": []},
            },
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        # Add files to state
        self.state["per_file_coverage"]["file_a.py"] = file_a_metadata
        self.state["per_file_coverage"]["file_b.py"] = file_b_metadata

        # Calculate scores
        scheduler = CorpusScheduler(self.coverage_manager)
        scores = scheduler.calculate_scores()

        # File B should have a higher score due to the rare edge
        # Rarity score for edge 0: 1/(100+1) ≈ 0.0099
        # Rarity score for edge 1: 1/(1+1) = 0.5
        # These get multiplied by 50.0 in the scoring function
        self.assertGreater(scores["file_b.py"], scores["file_a.py"])

    def test_sterile_file_penalty(self):
        """Test that sterile files receive the 0.1x penalty."""
        import copy

        # Create two identical files except for sterility
        base_metadata = {
            "baseline_coverage": {
                "f1": {"edges": [0], "uops": [], "rare_events": []},
            },
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        # Non-sterile file
        fertile_metadata = copy.deepcopy(base_metadata)
        fertile_metadata["is_sterile"] = False

        # Sterile file
        sterile_metadata = copy.deepcopy(base_metadata)
        sterile_metadata["is_sterile"] = True

        # Add to state
        self.state["per_file_coverage"]["fertile.py"] = fertile_metadata
        self.state["per_file_coverage"]["sterile.py"] = sterile_metadata

        # Calculate scores
        scheduler = CorpusScheduler(self.coverage_manager)
        scores = scheduler.calculate_scores()

        # Sterile file should have ~10% of fertile file's score
        # Allow for slight variation due to rarity scoring
        expected_ratio = 0.1
        actual_ratio = scores["sterile.py"] / scores["fertile.py"]
        self.assertAlmostEqual(actual_ratio, expected_ratio, places=1)

    def test_performance_penalty(self):
        """Test that slow and large files are penalized."""
        # Fast, small file
        fast_metadata = {
            "baseline_coverage": {"f1": {"edges": [], "uops": [], "rare_events": []}},
            "execution_time_ms": 10,  # Fast
            "file_size_bytes": 100,  # Small
            "total_finds": 0,
            "lineage_depth": 1,
        }

        # Slow, large file
        slow_metadata = {
            "baseline_coverage": {"f1": {"edges": [], "uops": [], "rare_events": []}},
            "execution_time_ms": 1000,  # Slow
            "file_size_bytes": 10000,  # Large
            "total_finds": 0,
            "lineage_depth": 1,
        }

        self.state["per_file_coverage"]["fast.py"] = fast_metadata
        self.state["per_file_coverage"]["slow.py"] = slow_metadata

        scheduler = CorpusScheduler(self.coverage_manager)
        scores = scheduler.calculate_scores()

        # Fast file should score higher
        self.assertGreater(scores["fast.py"], scores["slow.py"])

    def test_fertility_bonus(self):
        """Test that files with more finds get higher scores."""
        base_metadata = {
            "baseline_coverage": {"f1": {"edges": [], "uops": [], "rare_events": []}},
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "lineage_depth": 1,
        }

        # File with no finds
        barren_metadata = base_metadata.copy()
        barren_metadata["total_finds"] = 0

        # File with many finds
        fertile_metadata = base_metadata.copy()
        fertile_metadata["total_finds"] = 10

        self.state["per_file_coverage"]["barren.py"] = barren_metadata
        self.state["per_file_coverage"]["fertile.py"] = fertile_metadata

        scheduler = CorpusScheduler(self.coverage_manager)
        scores = scheduler.calculate_scores()

        # Fertile file should score higher
        self.assertGreater(scores["fertile.py"], scores["barren.py"])

    def test_trace_quality_metrics(self):
        """Test that trace length and side exits contribute to score."""
        # File with short trace and no side exits
        short_trace = {
            "baseline_coverage": {
                "f1": {
                    "edges": [],
                    "uops": [],
                    "rare_events": [],
                    "trace_length": 10,
                    "side_exits": 0,
                }
            },
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        # File with long trace and many side exits
        long_trace = {
            "baseline_coverage": {
                "f1": {
                    "edges": [],
                    "uops": [],
                    "rare_events": [],
                    "trace_length": 100,
                    "side_exits": 10,
                }
            },
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        self.state["per_file_coverage"]["short.py"] = short_trace
        self.state["per_file_coverage"]["long.py"] = long_trace

        scheduler = CorpusScheduler(self.coverage_manager)
        scores = scheduler.calculate_scores()

        # File with longer trace and more exits should score higher
        self.assertGreater(scores["long.py"], scores["short.py"])


class TestCorpusManager(unittest.TestCase):
    """Test the CorpusManager class."""

    def setUp(self):
        """Create a mock CorpusManager for testing."""
        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        # Create CorpusManager with mocked dependencies
        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            self.corpus_manager = CorpusManager(
                coverage_state=self.coverage_manager,
                run_stats=self.run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

    def test_is_subsumed_by_superset_and_smaller(self):
        """Test that file A is subsumed by B if B has superset coverage and is smaller."""
        # File A metadata
        file_a_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1}, "uops": [], "rare_events": []}},
            "file_size_bytes": 1000,
            "execution_time_ms": 100,
        }

        # File B metadata - superset of edges and smaller
        file_b_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}, "uops": [], "rare_events": []}},
            "file_size_bytes": 500,  # Smaller
            "execution_time_ms": 50,  # Faster
        }

        # File A should be subsumed by B
        result = self.corpus_manager._is_subsumed_by(file_a_meta, file_b_meta)
        self.assertTrue(result)

    def test_is_subsumed_by_superset_but_larger(self):
        """Test that file A is NOT subsumed by B if B is larger/slower despite superset."""
        # File A metadata
        file_a_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1}, "uops": [], "rare_events": []}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        # File B metadata - superset but larger and slower
        file_b_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}, "uops": [], "rare_events": []}},
            "file_size_bytes": 2000,  # Larger
            "execution_time_ms": 200,  # Slower
        }

        # File A should NOT be subsumed (B is not more efficient)
        result = self.corpus_manager._is_subsumed_by(file_a_meta, file_b_meta)
        self.assertFalse(result)

    def test_is_subsumed_by_not_proper_subset(self):
        """Test that files with equal or disjoint coverage are not subsumed."""
        # File A and B have same coverage
        file_a_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}, "uops": [], "rare_events": []}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        file_b_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}, "uops": [], "rare_events": []}},
            "file_size_bytes": 400,
            "execution_time_ms": 40,
        }

        # Not a proper subset (they're equal)
        result = self.corpus_manager._is_subsumed_by(file_a_meta, file_b_meta)
        self.assertFalse(result)

    def test_is_subsumed_by_empty_edges(self):
        """Test that files with empty edge sets are never subsumed."""
        file_a_meta = {
            "lineage_coverage_profile": {"f1": {"edges": set(), "uops": [], "rare_events": []}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        file_b_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}, "uops": [], "rare_events": []}},
            "file_size_bytes": 100,
            "execution_time_ms": 10,
        }

        # Empty edge set should not be subsumed
        result = self.corpus_manager._is_subsumed_by(file_a_meta, file_b_meta)
        self.assertFalse(result)

    def test_is_subsumed_by_partial_overlap(self):
        """Test that partial overlap (not subset) is not subsumption."""
        file_a_meta = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 5}, "uops": [], "rare_events": []}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        file_b_meta = {
            "lineage_coverage_profile": {
                "f1": {"edges": {0, 1, 2, 3}, "uops": [], "rare_events": []}
            },
            "file_size_bytes": 400,
            "execution_time_ms": 40,
        }

        # A has edge 5 which B doesn't have, so not a subset
        result = self.corpus_manager._is_subsumed_by(file_a_meta, file_b_meta)
        self.assertFalse(result)

    @patch("lafleur.corpus_manager.save_coverage_state")
    @patch("lafleur.corpus_manager.CORPUS_DIR")
    def test_synchronize_removes_missing_files(self, mock_corpus_dir, mock_save):
        """Test that synchronize removes files from state that are missing from disk."""
        # Mock the corpus directory
        Mock(spec=Path)
        mock_corpus_dir.exists.return_value = True

        # Create mock path objects for the files
        file1 = Mock(spec=Path)
        file1.name = "file1.py"
        file2 = Mock(spec=Path)
        file2.name = "file2.py"

        mock_corpus_dir.glob.return_value = [file1, file2]

        # State has files that don't exist on disk
        self.state["per_file_coverage"] = {
            "file1.py": {},
            "file2.py": {},
            "file3.py": {},  # This one is missing from disk
            "file4.py": {},  # This one too
        }

        # Mock the orchestrator functions
        mock_analyze = Mock()
        mock_build_lineage = Mock()

        # Mock _get_files_to_analyze to return empty set (no new files to analyze)
        with patch.object(self.corpus_manager, "_get_files_to_analyze", return_value=set()):
            # Run synchronize
            self.corpus_manager.synchronize(mock_analyze, mock_build_lineage)

        # Files 3 and 4 should be removed from state
        self.assertIn("file1.py", self.state["per_file_coverage"])
        self.assertIn("file2.py", self.state["per_file_coverage"])
        self.assertNotIn("file3.py", self.state["per_file_coverage"])
        self.assertNotIn("file4.py", self.state["per_file_coverage"])

    def test_get_edge_set_from_profile(self):
        """Test the helper method that extracts edge sets from lineage profiles."""
        profile = {
            "f1": {"edges": {0, 1, 2}, "uops": [], "rare_events": []},
            "f2": {"edges": {2, 3, 4}, "uops": [], "rare_events": []},
            "f3": {"edges": {5}, "uops": [], "rare_events": []},
        }

        edges = self.corpus_manager._get_edge_set_from_profile(profile)

        # Should be the union of all edges
        expected = {0, 1, 2, 3, 4, 5}
        self.assertEqual(edges, expected)

    def test_get_edge_set_from_empty_profile(self):
        """Test edge extraction from empty profile."""
        profile = {}
        edges = self.corpus_manager._get_edge_set_from_profile(profile)
        self.assertEqual(edges, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
