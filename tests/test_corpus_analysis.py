"""Tests for lafleur.corpus_analysis module."""

import unittest
from unittest.mock import MagicMock

from lafleur.corpus_analysis import calculate_distribution, generate_corpus_stats


class TestCalculateDistribution(unittest.TestCase):
    """Tests for the calculate_distribution helper."""

    def test_empty_list(self):
        result = calculate_distribution([])
        self.assertIsNone(result["min"])
        self.assertIsNone(result["max"])
        self.assertIsNone(result["mean"])
        self.assertIsNone(result["median"])

    def test_single_value(self):
        result = calculate_distribution([42])
        self.assertEqual(result["min"], 42)
        self.assertEqual(result["max"], 42)
        self.assertEqual(result["mean"], 42.0)
        self.assertEqual(result["median"], 42.0)

    def test_multiple_values(self):
        result = calculate_distribution([1, 2, 3, 4, 5])
        self.assertEqual(result["min"], 1)
        self.assertEqual(result["max"], 5)
        self.assertEqual(result["mean"], 3.0)
        self.assertEqual(result["median"], 3.0)

    def test_floats(self):
        result = calculate_distribution([1.5, 2.5, 3.5])
        self.assertEqual(result["min"], 1.5)
        self.assertEqual(result["max"], 3.5)
        self.assertEqual(result["mean"], 2.5)
        self.assertEqual(result["median"], 2.5)

    def test_even_count_median(self):
        result = calculate_distribution([1, 3])
        self.assertEqual(result["median"], 2.0)


class TestGenerateCorpusStats(unittest.TestCase):
    """Tests for the generate_corpus_stats function."""

    def _make_corpus_manager(self, per_file_coverage):
        cm = MagicMock()
        cm.coverage_state.state = {"per_file_coverage": per_file_coverage}
        return cm

    def test_empty_corpus(self):
        cm = self._make_corpus_manager({})
        stats = generate_corpus_stats(cm)

        self.assertEqual(stats["total_files"], 0)
        self.assertEqual(stats["sterile_count"], 0)
        self.assertEqual(stats["sterile_rate"], 0.0)
        self.assertEqual(stats["root_count"], 0)
        self.assertEqual(stats["leaf_count"], 0)
        self.assertEqual(stats["max_depth"], 0)
        self.assertEqual(stats["successful_strategies"], {})
        self.assertEqual(stats["successful_mutators"], {})

    def test_single_root_file(self):
        cm = self._make_corpus_manager(
            {
                "seed_0.py": {
                    "parent_id": None,
                    "lineage_depth": 0,
                    "file_size_bytes": 100,
                    "execution_time_ms": 50.0,
                }
            }
        )
        stats = generate_corpus_stats(cm)

        self.assertEqual(stats["total_files"], 1)
        self.assertEqual(stats["root_count"], 1)
        self.assertEqual(stats["leaf_count"], 1)
        self.assertEqual(stats["max_depth"], 0)
        self.assertEqual(stats["file_size_distribution"]["min"], 100)

    def test_sterile_files_counted(self):
        cm = self._make_corpus_manager(
            {
                "f1.py": {"parent_id": None, "lineage_depth": 0, "is_sterile": True},
                "f2.py": {"parent_id": None, "lineage_depth": 0, "is_sterile": False},
                "f3.py": {"parent_id": None, "lineage_depth": 0, "is_sterile": True},
            }
        )
        stats = generate_corpus_stats(cm)

        self.assertEqual(stats["sterile_count"], 2)
        self.assertEqual(stats["sterile_rate"], round(2 / 3, 4))
        self.assertEqual(stats["viable_count"], 1)

    def test_pruned_files_excluded(self):
        cm = self._make_corpus_manager(
            {
                "live.py": {"parent_id": None, "lineage_depth": 0},
                "pruned.py": {"parent_id": None, "lineage_depth": 0, "is_pruned": True},
            }
        )
        stats = generate_corpus_stats(cm)

        # total_files counts all entries (including pruned) because it's len(per_file_coverage)
        self.assertEqual(stats["total_files"], 2)
        # But pruned files are excluded from leaf/root calculations via the loop
        self.assertEqual(stats["root_count"], 1)

    def test_tree_topology(self):
        cm = self._make_corpus_manager(
            {
                "seed.py": {"parent_id": None, "lineage_depth": 0},
                "child1.py": {"parent_id": "seed.py", "lineage_depth": 1},
                "child2.py": {"parent_id": "seed.py", "lineage_depth": 1},
                "grandchild.py": {"parent_id": "child1.py", "lineage_depth": 2},
            }
        )
        stats = generate_corpus_stats(cm)

        self.assertEqual(stats["root_count"], 1)
        self.assertEqual(stats["max_depth"], 2)
        # Leaves: child2.py and grandchild.py (never appear as parent_id)
        self.assertEqual(stats["leaf_count"], 2)

    def test_mutation_tracking(self):
        cm = self._make_corpus_manager(
            {
                "f1.py": {
                    "parent_id": None,
                    "lineage_depth": 0,
                    "discovery_mutation": {
                        "strategy": "havoc",
                        "transformers": ["OperatorSwapper", "ConstantPerturbator"],
                    },
                },
                "f2.py": {
                    "parent_id": "f1.py",
                    "lineage_depth": 1,
                    "discovery_mutation": {
                        "strategy": "havoc",
                        "transformers": ["OperatorSwapper"],
                    },
                },
                "f3.py": {
                    "parent_id": "f1.py",
                    "lineage_depth": 1,
                    "discovery_mutation": {
                        "strategy": "deterministic",
                        "transformers": ["ComparisonSwapper"],
                    },
                },
            }
        )
        stats = generate_corpus_stats(cm)

        self.assertEqual(stats["successful_strategies"]["havoc"], 2)
        self.assertEqual(stats["successful_strategies"]["deterministic"], 1)
        self.assertEqual(stats["successful_mutators"]["OperatorSwapper"], 2)
        self.assertEqual(stats["successful_mutators"]["ConstantPerturbator"], 1)
        self.assertEqual(stats["successful_mutators"]["ComparisonSwapper"], 1)

    def test_distributions_populated(self):
        cm = self._make_corpus_manager(
            {
                "f1.py": {
                    "parent_id": None,
                    "lineage_depth": 0,
                    "file_size_bytes": 200,
                    "execution_time_ms": 10.0,
                    "mutations_since_last_find": 5,
                },
                "f2.py": {
                    "parent_id": "f1.py",
                    "lineage_depth": 1,
                    "file_size_bytes": 400,
                    "execution_time_ms": 20.0,
                    "mutations_since_last_find": 15,
                },
            }
        )
        stats = generate_corpus_stats(cm)

        self.assertEqual(stats["file_size_distribution"]["min"], 200)
        self.assertEqual(stats["file_size_distribution"]["max"], 400)
        self.assertEqual(stats["execution_time_distribution"]["mean"], 15.0)
        self.assertEqual(stats["lineage_depth_distribution"]["max"], 1)
        self.assertEqual(stats["mutations_since_find_distribution"]["min"], 5)
