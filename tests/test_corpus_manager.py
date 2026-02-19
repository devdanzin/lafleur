#!/usr/bin/env python3
"""
Unit tests for lafleur/corpus_manager.py
"""

import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

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


class TestCorpusSchedulerCaching(unittest.TestCase):
    """Tests for CorpusScheduler score caching."""

    def setUp(self):
        self.state = {
            "global_coverage": {"edges": {0: 1}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {
                "test1.py": {
                    "baseline_coverage": {"f1": {"edges": [0]}},
                    "execution_time_ms": 50,
                    "file_size_bytes": 500,
                    "total_finds": 0,
                    "lineage_depth": 1,
                },
            },
        }
        self.coverage_manager = CoverageManager(self.state)

    def test_cache_starts_empty(self):
        """A fresh CorpusScheduler should have no cached scores."""
        scheduler = CorpusScheduler(self.coverage_manager)
        self.assertIsNone(scheduler._cached_scores)

    def test_calculate_scores_returns_cached_results(self):
        """Second call to calculate_scores should return the same dict object."""
        scheduler = CorpusScheduler(self.coverage_manager)
        first = scheduler.calculate_scores()
        second = scheduler.calculate_scores()
        self.assertIs(first, second)

    def test_invalidate_clears_cache(self):
        """invalidate_scores should force a fresh recomputation."""
        scheduler = CorpusScheduler(self.coverage_manager)
        first = scheduler.calculate_scores()
        scheduler.invalidate_scores()
        second = scheduler.calculate_scores()
        self.assertIsNot(first, second)
        self.assertEqual(first, second)

    def test_add_new_file_invalidates_cache(self):
        """add_new_file should clear the score cache."""
        run_stats = {"corpus_file_counter": 0}
        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            corpus_manager = CorpusManager(
                coverage_state=self.coverage_manager,
                run_stats=run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

        # Populate the cache
        with patch("lafleur.corpus_manager.CORPUS_DIR") as mock_dir:
            mock_dir.__truediv__ = lambda self, x: Path("/mock") / x
            corpus_manager.select_parent()

        self.assertIsNotNone(corpus_manager.scheduler._cached_scores)

        # add_new_file should invalidate
        tmp = tempfile.mkdtemp()
        with (
            patch("lafleur.corpus_manager.CORPUS_DIR", Path(tmp)),
            patch("lafleur.corpus_manager.save_coverage_state"),
        ):
            corpus_manager.add_new_file(
                core_code="x = 1",
                baseline_coverage={},
                execution_time_ms=10,
                parent_id=None,
                mutation_info={"strategy": "test"},
                mutation_seed=0,
                content_hash="abc",
                coverage_hash="def",
                build_lineage_func=lambda old, new: {},
            )

        self.assertIsNone(corpus_manager.scheduler._cached_scores)

    def test_select_parent_uses_cached_scores(self):
        """Second select_parent call should use cached scores, not recompute."""
        scheduler = CorpusScheduler(self.coverage_manager)
        rarity_call_count = 0
        original_rarity = scheduler._calculate_rarity_score

        def counting_rarity(metadata):
            nonlocal rarity_call_count
            rarity_call_count += 1
            return original_rarity(metadata)

        scheduler._calculate_rarity_score = counting_rarity

        run_stats = {"corpus_file_counter": 0}
        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            corpus_manager = CorpusManager(
                coverage_state=self.coverage_manager,
                run_stats=run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )
        corpus_manager.scheduler = scheduler

        with patch("lafleur.corpus_manager.CORPUS_DIR") as mock_dir:
            mock_dir.__truediv__ = lambda self, x: Path("/mock") / x
            corpus_manager.select_parent()
            first_count = rarity_call_count
            corpus_manager.select_parent()

        # Rarity should only be computed on first call (1 file = 1 call)
        self.assertEqual(first_count, 1)
        self.assertEqual(rarity_call_count, 1)


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


class TestCorpusManagerSelectParent(unittest.TestCase):
    """Tests for select_parent method."""

    def setUp(self):
        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            self.corpus_manager = CorpusManager(
                coverage_state=self.coverage_manager,
                run_stats=self.run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

    def test_returns_none_when_corpus_empty(self):
        """Test that select_parent returns None for empty corpus."""
        result = self.corpus_manager.select_parent()
        self.assertIsNone(result)

    def test_returns_file_when_corpus_has_files(self):
        """Test selecting parent from non-empty corpus."""
        self.state["per_file_coverage"]["test1.py"] = {
            "baseline_coverage": {},
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        with patch("lafleur.corpus_manager.CORPUS_DIR") as mock_dir:
            mock_dir.__truediv__ = lambda self, x: Path("/mock") / x
            result = self.corpus_manager.select_parent()

        self.assertIsNotNone(result)
        self.assertEqual(result[0].name, "test1.py")

    def test_handles_zero_weights(self):
        """Test fallback when all weights are zero."""
        # Create files with negative scores (will be clamped to 1.0 min)
        self.state["per_file_coverage"]["test1.py"] = {
            "baseline_coverage": {},
            "execution_time_ms": 100000,  # Very slow
            "file_size_bytes": 100000,  # Very large
            "total_finds": 0,
            "lineage_depth": 1,
            "is_sterile": True,
        }

        with patch("lafleur.corpus_manager.CORPUS_DIR") as mock_dir:
            mock_dir.__truediv__ = lambda self, x: Path("/mock") / x
            result = self.corpus_manager.select_parent()

        self.assertIsNotNone(result)


class TestCorpusManagerPruneCorpus(unittest.TestCase):
    """Tests for prune_corpus method."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR", self.temp_path / "corpus"):
            with patch("lafleur.corpus_manager.TMP_DIR", self.temp_path / "tmp"):
                self.corpus_manager = CorpusManager(
                    coverage_state=self.coverage_manager,
                    run_stats=self.run_stats,
                    fusil_path="",
                    get_boilerplate_func=lambda: "",
                    execution_timeout=10,
                )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_prune_corpus_dry_run_no_files_removed(self):
        """Test that dry run doesn't remove files."""
        # Create file that could be pruned
        self.state["per_file_coverage"]["test1.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1}}},
            "file_size_bytes": 1000,
            "execution_time_ms": 100,
        }
        self.state["per_file_coverage"]["test2.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        self.corpus_manager.prune_corpus(dry_run=True)

        # Both files should still be in state
        self.assertIn("test1.py", self.state["per_file_coverage"])
        self.assertIn("test2.py", self.state["per_file_coverage"])

    def test_dry_run_does_not_mutate_metadata(self):
        """Dry run should not add subsumed_children_count to metadata."""
        self.state["per_file_coverage"]["test1.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1}}},
            "file_size_bytes": 1000,
            "execution_time_ms": 100,
        }
        self.state["per_file_coverage"]["test2.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        self.corpus_manager.prune_corpus(dry_run=True)

        # No metadata should have been mutated
        self.assertNotIn("subsumed_children_count", self.state["per_file_coverage"]["test2.py"])

    def test_prune_corpus_finds_no_prunable(self):
        """Test when no files are prunable."""
        # Files with disjoint coverage
        self.state["per_file_coverage"]["test1.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }
        self.state["per_file_coverage"]["test2.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {2, 3}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        self.corpus_manager.prune_corpus(dry_run=True)

        # No files should be marked for pruning
        self.assertEqual(len(self.state["per_file_coverage"]), 2)

    @patch("lafleur.corpus_manager.save_coverage_state")
    def test_prune_corpus_removes_subsumed_files(self, mock_save):
        """Test that subsumed files are removed in non-dry-run mode."""
        corpus_dir = self.temp_path / "corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)

        # Create test files
        (corpus_dir / "test1.py").write_text("# test1")
        (corpus_dir / "test2.py").write_text("# test2")

        # test1 is subsumed by test2
        self.state["per_file_coverage"]["test1.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1}}},
            "file_size_bytes": 1000,
            "execution_time_ms": 100,
        }
        self.state["per_file_coverage"]["test2.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {0, 1, 2}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        with patch("lafleur.corpus_manager.CORPUS_DIR", corpus_dir):
            self.corpus_manager.prune_corpus(dry_run=False)

        # test1 should be removed
        self.assertNotIn("test1.py", self.state["per_file_coverage"])
        self.assertIn("test2.py", self.state["per_file_coverage"])
        self.assertFalse((corpus_dir / "test1.py").exists())


class TestBuildEdgeIndex(unittest.TestCase):
    """Tests for _build_edge_index helper."""

    def setUp(self):
        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            self.corpus_manager = CorpusManager(
                coverage_state=self.coverage_manager,
                run_stats=self.run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

    def test_empty_corpus(self):
        """Empty input returns empty dicts."""
        file_edges, edge_to_files = self.corpus_manager._build_edge_index({})
        self.assertEqual(file_edges, {})
        self.assertEqual(dict(edge_to_files), {})

    def test_single_file(self):
        """One file with edges {1, 2, 3}."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}}},
        }
        file_edges, edge_to_files = self.corpus_manager._build_edge_index(all_files)
        self.assertEqual(file_edges["a.py"], {1, 2, 3})
        for edge in (1, 2, 3):
            self.assertIn("a.py", edge_to_files[edge])

    def test_shared_edges(self):
        """Two files sharing edge 1."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 3}}}},
        }
        file_edges, edge_to_files = self.corpus_manager._build_edge_index(all_files)
        self.assertEqual(edge_to_files[1], {"a.py", "b.py"})
        self.assertEqual(edge_to_files[2], {"a.py"})
        self.assertEqual(edge_to_files[3], {"b.py"})

    def test_disjoint_edges(self):
        """Two files with no shared edges."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {3, 4}}}},
        }
        file_edges, edge_to_files = self.corpus_manager._build_edge_index(all_files)
        self.assertEqual(edge_to_files[1], {"a.py"})
        self.assertEqual(edge_to_files[3], {"b.py"})


class TestFindSubsumerCandidates(unittest.TestCase):
    """Tests for _find_subsumer_candidates helper."""

    def setUp(self):
        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            self.corpus_manager = CorpusManager(
                coverage_state=self.coverage_manager,
                run_stats=self.run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

    def _make_index(self, all_files):
        """Helper to build edge index from file metadata."""
        return self.corpus_manager._build_edge_index(all_files)

    def test_returns_proper_supersets(self):
        """Only files with strictly more edges should be returned."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}}},
            "c.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
        }
        file_edges, edge_to_files = self._make_index(all_files)
        candidates = self.corpus_manager._find_subsumer_candidates(
            "a.py", file_edges["a.py"], file_edges, edge_to_files, set()
        )
        self.assertEqual(candidates, {"b.py"})

    def test_excludes_self(self):
        """File A should not appear in its own candidate set."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}}},
        }
        file_edges, edge_to_files = self._make_index(all_files)
        candidates = self.corpus_manager._find_subsumer_candidates(
            "a.py", file_edges["a.py"], file_edges, edge_to_files, set()
        )
        self.assertNotIn("a.py", candidates)

    def test_excludes_pruned_files(self):
        """Files already marked for pruning should be excluded."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}}},
        }
        file_edges, edge_to_files = self._make_index(all_files)
        candidates = self.corpus_manager._find_subsumer_candidates(
            "a.py", file_edges["a.py"], file_edges, edge_to_files, {"b.py"}
        )
        self.assertEqual(candidates, set())

    def test_empty_edges(self):
        """File with no edges returns empty set."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}}},
        }
        file_edges, edge_to_files = self._make_index(all_files)
        candidates = self.corpus_manager._find_subsumer_candidates(
            "a.py", file_edges["a.py"], file_edges, edge_to_files, set()
        )
        self.assertEqual(candidates, set())

    def test_no_common_supersets(self):
        """Files with disjoint edges return empty set."""
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {3, 4, 5}}}},
        }
        file_edges, edge_to_files = self._make_index(all_files)
        candidates = self.corpus_manager._find_subsumer_candidates(
            "a.py", file_edges["a.py"], file_edges, edge_to_files, set()
        )
        self.assertEqual(candidates, set())

    def test_rarest_edge_first(self):
        """Correctness with edges of varying frequency."""
        # Edge 1 is common (in many files), edge 2 is rare (in few files)
        all_files = {
            "a.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2}}}},
            "b.py": {"lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}}},
        }
        # Add many files that have edge 1 but not edge 2
        for i in range(20):
            all_files[f"noise_{i}.py"] = {
                "lineage_coverage_profile": {"f1": {"edges": {1, 100 + i}}}
            }
        file_edges, edge_to_files = self._make_index(all_files)
        candidates = self.corpus_manager._find_subsumer_candidates(
            "a.py", file_edges["a.py"], file_edges, edge_to_files, set()
        )
        self.assertEqual(candidates, {"b.py"})


class TestPruneCorpusScalability(unittest.TestCase):
    """Tests for the inverted-index-based prune_corpus."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR", self.temp_path / "corpus"):
            with patch("lafleur.corpus_manager.TMP_DIR", self.temp_path / "tmp"):
                self.corpus_manager = CorpusManager(
                    coverage_state=self.coverage_manager,
                    run_stats=self.run_stats,
                    fusil_path="",
                    get_boilerplate_func=lambda: "",
                    execution_timeout=10,
                )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_prune_identifies_subsumed_files(self):
        """A is subsumed by B (proper superset + Pareto dominant). C is disjoint."""
        self.state["per_file_coverage"]["a.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2}}},
            "file_size_bytes": 1000,
            "execution_time_ms": 100,
        }
        self.state["per_file_coverage"]["b.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }
        self.state["per_file_coverage"]["c.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {4, 5}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        self.corpus_manager.prune_corpus(dry_run=True)

        # All still present (dry run), but A would be pruned
        self.assertIn("a.py", self.state["per_file_coverage"])
        self.assertIn("b.py", self.state["per_file_coverage"])
        self.assertIn("c.py", self.state["per_file_coverage"])

    def test_prune_respects_pareto_dominance(self):
        """B has more edges but is slower — A should NOT be pruned."""
        self.state["per_file_coverage"]["a.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }
        self.state["per_file_coverage"]["b.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}},
            "file_size_bytes": 400,
            "execution_time_ms": 60,
        }

        self.corpus_manager.prune_corpus(dry_run=True)
        self.assertEqual(len(self.state["per_file_coverage"]), 2)

    def test_prune_equal_metrics_not_subsumed(self):
        """B has more edges but identical metrics — A should NOT be pruned."""
        self.state["per_file_coverage"]["a.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }
        self.state["per_file_coverage"]["b.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        self.corpus_manager.prune_corpus(dry_run=True)
        self.assertEqual(len(self.state["per_file_coverage"]), 2)

    def test_prune_empty_edges_never_pruned(self):
        """Files with no edges should never be pruned."""
        self.state["per_file_coverage"]["empty.py"] = {
            "lineage_coverage_profile": {},
            "file_size_bytes": 100,
            "execution_time_ms": 10,
        }
        self.state["per_file_coverage"]["full.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}},
            "file_size_bytes": 50,
            "execution_time_ms": 5,
        }

        self.corpus_manager.prune_corpus(dry_run=True)
        self.assertIn("empty.py", self.state["per_file_coverage"])

    def test_prune_dry_run_does_not_delete(self):
        """Dry run should not remove files or mutate metadata."""
        corpus_dir = self.temp_path / "corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        (corpus_dir / "a.py").write_text("# a")
        (corpus_dir / "b.py").write_text("# b")

        self.state["per_file_coverage"]["a.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2}}},
            "file_size_bytes": 1000,
            "execution_time_ms": 100,
        }
        self.state["per_file_coverage"]["b.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        with patch("lafleur.corpus_manager.CORPUS_DIR", corpus_dir):
            self.corpus_manager.prune_corpus(dry_run=True)

        self.assertTrue((corpus_dir / "a.py").exists())
        self.assertIn("a.py", self.state["per_file_coverage"])
        self.assertNotIn("subsumed_children_count", self.state["per_file_coverage"]["b.py"])

    @patch("lafleur.corpus_manager.save_coverage_state")
    def test_prune_actually_deletes_in_non_dry_run(self, mock_save):
        """Non-dry-run should delete files, update state, and invalidate cache."""
        corpus_dir = self.temp_path / "corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        (corpus_dir / "a.py").write_text("# a")
        (corpus_dir / "b.py").write_text("# b")

        self.state["per_file_coverage"]["a.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2}}},
            "file_size_bytes": 1000,
            "execution_time_ms": 100,
        }
        self.state["per_file_coverage"]["b.py"] = {
            "lineage_coverage_profile": {"f1": {"edges": {1, 2, 3}}},
            "file_size_bytes": 500,
            "execution_time_ms": 50,
        }

        # Pre-populate the cache
        self.corpus_manager.scheduler._cached_scores = {"a.py": 50.0, "b.py": 80.0}

        with patch("lafleur.corpus_manager.CORPUS_DIR", corpus_dir):
            self.corpus_manager.prune_corpus(dry_run=False)

        self.assertFalse((corpus_dir / "a.py").exists())
        self.assertNotIn("a.py", self.state["per_file_coverage"])
        self.assertIn("b.py", self.state["per_file_coverage"])
        mock_save.assert_called_once()
        self.assertIsNone(self.corpus_manager.scheduler._cached_scores)

    def test_prune_progress_logging(self):
        """Progress message should appear for large corpora."""
        # Create 2001 files with empty edges (quickly skipped)
        for i in range(2001):
            self.state["per_file_coverage"][f"file_{i}.py"] = {
                "lineage_coverage_profile": {},
                "file_size_bytes": 100,
                "execution_time_ms": 10,
            }

        from io import StringIO

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            self.corpus_manager.prune_corpus(dry_run=True)

        self.assertIn("Pruning progress: 2000/2001", mock_out.getvalue())

    @patch("lafleur.corpus_manager.save_coverage_state")
    def test_prune_handles_large_corpus(self, mock_save):
        """100 subsumed files among 500 should all be identified."""
        corpus_dir = self.temp_path / "corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)

        # Create 400 "base" files with unique disjoint edge sets
        for i in range(400):
            base_edge = i * 10
            self.state["per_file_coverage"][f"base_{i}.py"] = {
                "lineage_coverage_profile": {
                    "f1": {"edges": {base_edge, base_edge + 1, base_edge + 2}}
                },
                "file_size_bytes": 500,
                "execution_time_ms": 50,
            }
            (corpus_dir / f"base_{i}.py").write_text(f"# base {i}")

        # Create 100 "subsumed" files: each has a subset of a base file's edges
        for i in range(100):
            base_edge = i * 10
            self.state["per_file_coverage"][f"sub_{i}.py"] = {
                "lineage_coverage_profile": {"f1": {"edges": {base_edge, base_edge + 1}}},
                "file_size_bytes": 1000,
                "execution_time_ms": 100,
            }
            (corpus_dir / f"sub_{i}.py").write_text(f"# sub {i}")

        with patch("lafleur.corpus_manager.CORPUS_DIR", corpus_dir):
            self.corpus_manager.prune_corpus(dry_run=False)

        # All 100 subsumed files should be gone
        remaining = set(self.state["per_file_coverage"].keys())
        for i in range(100):
            self.assertNotIn(f"sub_{i}.py", remaining)
        # All 400 base files should remain
        for i in range(400):
            self.assertIn(f"base_{i}.py", remaining)


class TestCorpusManagerGetFilesToAnalyze(unittest.TestCase):
    """Tests for _get_files_to_analyze method."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR", self.temp_path):
            with patch("lafleur.corpus_manager.TMP_DIR", self.temp_path / "tmp"):
                self.corpus_manager = CorpusManager(
                    coverage_state=self.coverage_manager,
                    run_stats=self.run_stats,
                    fusil_path="",
                    get_boilerplate_func=lambda: "",
                    execution_timeout=10,
                )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_identifies_new_files(self):
        """Test identifying new files not in state."""
        import hashlib

        # Create both files on disk
        (self.temp_path / "file1.py").write_text("# file1")
        (self.temp_path / "file2.py").write_text("# file2")

        disk_files = {"file1.py", "file2.py"}
        state_files = {"file1.py"}

        # Set the content hash for file1 so it won't be detected as modified
        file1_hash = hashlib.sha256("# file1".encode()).hexdigest()
        self.state["per_file_coverage"]["file1.py"] = {"content_hash": file1_hash}

        with patch("lafleur.corpus_manager.CORPUS_DIR", self.temp_path):
            with patch("sys.stdout", StringIO()):  # Suppress print messages
                result = self.corpus_manager._get_files_to_analyze(disk_files, state_files)

        # file2 is new (not in state), file1 has matching hash so not detected
        self.assertIn("file2.py", result)
        self.assertNotIn("file1.py", result)

    def test_identifies_modified_files(self):
        """Test identifying files with changed content."""
        # Create file with specific content
        (self.temp_path / "file1.py").write_text("# original")

        import hashlib

        original_hash = hashlib.sha256("# modified".encode()).hexdigest()

        self.state["per_file_coverage"]["file1.py"] = {
            "content_hash": original_hash  # Different from current content
        }

        disk_files = {"file1.py"}
        state_files = {"file1.py"}

        with patch("lafleur.corpus_manager.CORPUS_DIR", self.temp_path):
            result = self.corpus_manager._get_files_to_analyze(disk_files, state_files)

        self.assertIn("file1.py", result)


class TestCorpusManagerFusilValidation(unittest.TestCase):
    """Tests for fusil path validation."""

    def test_invalid_fusil_path(self):
        """Test that invalid fusil path is detected."""
        state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        coverage_manager = CoverageManager(state)
        run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            corpus_manager = CorpusManager(
                coverage_state=coverage_manager,
                run_stats=run_stats,
                fusil_path="/nonexistent/fusil",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

        self.assertFalse(corpus_manager.fusil_path_is_valid)

    def test_empty_fusil_path(self):
        """Test that empty fusil path is handled."""
        state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        coverage_manager = CoverageManager(state)
        run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            corpus_manager = CorpusManager(
                coverage_state=coverage_manager,
                run_stats=run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

        self.assertFalse(corpus_manager.fusil_path_is_valid)


class TestGenerateNewSeed(unittest.TestCase):
    """Tests for generate_new_seed timing."""

    def setUp(self):
        state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        coverage_manager = CoverageManager(state)
        run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            self.corpus_manager = CorpusManager(
                coverage_state=coverage_manager,
                run_stats=run_stats,
                fusil_path="/fake/fusil",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

    @patch("lafleur.corpus_manager.subprocess.run")
    @patch("lafleur.corpus_manager.time.monotonic")
    def test_execution_time_measured(self, mock_monotonic, mock_run):
        """Execution time should be calculated from monotonic clock, not zero."""
        # monotonic() returns 1.0 before, 1.25 after → 250 ms
        mock_monotonic.side_effect = [1.0, 1.25]

        mock_result = Mock(returncode=0)
        mock_run.return_value = mock_result

        mock_analyze = Mock(return_value={"status": "NO_NEW_COVERAGE"})
        mock_lineage = Mock()

        with patch("builtins.open", mock_open()):
            self.corpus_manager.generate_new_seed(mock_analyze, mock_lineage)

        # Verify analyze was called with execution_time_ms=250 (not zero)
        mock_analyze.assert_called_once()
        exec_result = mock_analyze.call_args.kwargs["exec_result"]
        self.assertEqual(exec_result.execution_time_ms, 250)


class TestCorpusSchedulerEdgeCases(unittest.TestCase):
    """Edge case tests for CorpusScheduler."""

    def setUp(self):
        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)

    def test_calculate_scores_empty_corpus(self):
        """Test score calculation with empty corpus."""
        scheduler = CorpusScheduler(self.coverage_manager)
        scores = scheduler.calculate_scores()
        self.assertEqual(scores, {})

    def test_score_clamped_to_minimum(self):
        """Test that scores are clamped to minimum of 1.0."""
        # Create file with very negative factors
        self.state["per_file_coverage"]["slow.py"] = {
            "baseline_coverage": {},
            "execution_time_ms": 100000,  # Very slow
            "file_size_bytes": 100000,  # Very large
            "total_finds": 0,
            "lineage_depth": 0,
            "is_sterile": True,
        }

        scheduler = CorpusScheduler(self.coverage_manager)
        scores = scheduler.calculate_scores()

        # Score should be clamped to at least 1.0
        self.assertGreaterEqual(scores["slow.py"], 1.0)


class TestSelectParentSterileFiltering(unittest.TestCase):
    """Test that select_parent skips sterile files."""

    def setUp(self):
        self.state = {
            "global_coverage": {"edges": {}, "uops": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        self.coverage_manager = CoverageManager(self.state)
        self.run_stats = {"corpus_file_counter": 0}

        with patch("lafleur.corpus_manager.CORPUS_DIR"), patch("lafleur.corpus_manager.TMP_DIR"):
            self.corpus_manager = CorpusManager(
                coverage_state=self.coverage_manager,
                run_stats=self.run_stats,
                fusil_path="",
                get_boilerplate_func=lambda: "",
                execution_timeout=10,
            )

    def test_skips_sterile_files(self):
        """Sterile files are excluded from parent selection."""
        self.state["per_file_coverage"]["sterile.py"] = {
            "is_sterile": True,
            "baseline_coverage": {},
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }
        self.state["per_file_coverage"]["fertile.py"] = {
            "is_sterile": False,
            "baseline_coverage": {},
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        with patch("lafleur.corpus_manager.CORPUS_DIR", Path("/mock")):
            # Run selection many times — should never pick sterile.py
            selections = set()
            for _ in range(20):
                result = self.corpus_manager.select_parent()
                if result:
                    selections.add(result[0].name)

            self.assertIn("fertile.py", selections)
            self.assertNotIn("sterile.py", selections)

    def test_falls_back_to_all_if_everything_sterile(self):
        """If all files are sterile, falls back to selecting from all files."""
        self.state["per_file_coverage"]["only.py"] = {
            "is_sterile": True,
            "baseline_coverage": {},
            "execution_time_ms": 50,
            "file_size_bytes": 500,
            "total_finds": 0,
            "lineage_depth": 1,
        }

        with patch("lafleur.corpus_manager.CORPUS_DIR", Path("/mock")):
            result = self.corpus_manager.select_parent()

        # Should still return something rather than None
        self.assertIsNotNone(result)

    def test_returns_none_when_corpus_empty(self):
        """Returns None when corpus is completely empty."""
        result = self.corpus_manager.select_parent()
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
