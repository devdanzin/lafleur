#!/usr/bin/env python3
"""
Tests for main evolutionary loop in lafleur/orchestrator.py.

This module contains unit tests for the core fuzzing loop, mutation cycle
execution, and statistics management.
"""

import io
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.orchestrator import LafleurOrchestrator


class TestCalculateMutations(unittest.TestCase):
    """Test _calculate_mutations method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)

    def test_base_mutations_with_score_100(self):
        """Test that score of 100 gives base mutations."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.orchestrator._calculate_mutations(100.0)

            # Score of 100 should give close to base (100)
            # Multiplier = 0.5 + log(100 * 10 / 100) / 2 = 0.5 + log(10) / 2 ≈ 0.5 + 1.15 = 1.65
            # But let's just verify it's reasonable
            self.assertGreater(mutations, 50)
            self.assertLess(mutations, 300)

    def test_low_score_clamped_to_minimum(self):
        """Test that very low scores result in minimum multiplier."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.orchestrator._calculate_mutations(1.0)

            # Score of 1.0:
            # score_multiplier = 1.0 / 100.0 = 0.01
            # dynamic_multiplier = 0.5 + log(max(1.0, 0.1)) / 2 = 0.5 + log(1.0) / 2 = 0.5
            # final_multiplier = max(0.25, min(3.0, 0.5)) = 0.5
            # max_mutations = int(100 * 0.5) = 50
            self.assertEqual(mutations, 50)

    def test_high_score_clamped_to_maximum(self):
        """Test that very high scores are clamped to 3.0x multiplier."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.orchestrator._calculate_mutations(10000.0)

            # Very high score should clamp to 3.0x, so 100 * 3.0 = 300
            self.assertEqual(mutations, 300)

    def test_medium_score_calculates_dynamic_multiplier(self):
        """Test that medium scores use logarithmic scaling."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.orchestrator._calculate_mutations(50.0)

            # Score of 50:
            # score_multiplier = 50 / 100 = 0.5
            # dynamic_multiplier = 0.5 + log(0.5 * 10) / 2 = 0.5 + log(5) / 2 ≈ 0.5 + 0.805 = 1.305
            # final = 100 * 1.305 = 130.5 -> 130
            self.assertGreaterEqual(mutations, 100)
            self.assertLessEqual(mutations, 150)

    def test_prints_dynamic_adjustment_message(self):
        """Test that dynamic adjustment is logged."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            self.orchestrator._calculate_mutations(75.0)

            stdout_output = mock_stdout.getvalue()
            self.assertIn("Dynamically adjusting mutation count", stdout_output)
            self.assertIn("Base: 100", stdout_output)


class TestUpdateAndSaveRunStats(unittest.TestCase):
    """Test update_and_save_run_stats method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {}
        self.orchestrator.coverage_manager = MagicMock()
        self.orchestrator.coverage_manager.state = {
            "per_file_coverage": {
                "file1.py": {},
                "file2.py": {},
                "file3.py": {},
            },
            "global_coverage": {
                "uops": {1: 5, 2: 10},
                "edges": {3: 15, 4: 20, 5: 25},
                "rare_events": {6: 1},
            },
        }
        self.orchestrator.global_seed_counter = 42
        self.orchestrator.corpus_manager = MagicMock()
        self.orchestrator.corpus_manager.corpus_file_counter = 123

    def test_updates_timestamp(self):
        """Test that last_update_time is set to current time."""
        with patch("lafleur.orchestrator.save_run_stats"):
            before = datetime.now(timezone.utc)
            self.orchestrator.update_and_save_run_stats()
            after = datetime.now(timezone.utc)

            timestamp = datetime.fromisoformat(self.orchestrator.run_stats["last_update_time"])
            self.assertGreaterEqual(timestamp, before)
            self.assertLessEqual(timestamp, after)

    def test_updates_corpus_size(self):
        """Test that corpus_size reflects per_file_coverage count."""
        with patch("lafleur.orchestrator.save_run_stats"):
            self.orchestrator.update_and_save_run_stats()

            self.assertEqual(self.orchestrator.run_stats["corpus_size"], 3)

    def test_updates_global_coverage_counts(self):
        """Test that global coverage metrics are counted."""
        with patch("lafleur.orchestrator.save_run_stats"):
            self.orchestrator.update_and_save_run_stats()

            self.assertEqual(self.orchestrator.run_stats["global_uops"], 2)
            self.assertEqual(self.orchestrator.run_stats["global_edges"], 3)
            self.assertEqual(self.orchestrator.run_stats["global_rare_events"], 1)

    def test_updates_seed_counters(self):
        """Test that global_seed_counter and corpus_file_counter are updated."""
        with patch("lafleur.orchestrator.save_run_stats"):
            self.orchestrator.update_and_save_run_stats()

            self.assertEqual(self.orchestrator.run_stats["global_seed_counter"], 42)
            self.assertEqual(self.orchestrator.run_stats["corpus_file_counter"], 123)

    def test_calculates_average_mutations_per_find(self):
        """Test that average_mutations_per_find is calculated when finds > 0."""
        self.orchestrator.run_stats["new_coverage_finds"] = 10
        self.orchestrator.run_stats["sum_of_mutations_per_find"] = 250

        with patch("lafleur.orchestrator.save_run_stats"):
            self.orchestrator.update_and_save_run_stats()

            self.assertEqual(self.orchestrator.run_stats["average_mutations_per_find"], 25.0)

    def test_no_average_when_no_finds(self):
        """Test that average_mutations_per_find is not set when no finds."""
        self.orchestrator.run_stats["new_coverage_finds"] = 0

        with patch("lafleur.orchestrator.save_run_stats"):
            self.orchestrator.update_and_save_run_stats()

            self.assertNotIn("average_mutations_per_find", self.orchestrator.run_stats)

    def test_calls_save_run_stats(self):
        """Test that save_run_stats is called with updated stats."""
        with patch("lafleur.orchestrator.save_run_stats") as mock_save:
            self.orchestrator.update_and_save_run_stats()

            mock_save.assert_called_once_with(self.orchestrator.run_stats)


class TestRunEvolutionaryLoop(unittest.TestCase):
    """Test run_evolutionary_loop method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {}
        self.orchestrator.coverage_manager = MagicMock()
        self.orchestrator.coverage_manager.state = {"per_file_coverage": {}}
        self.orchestrator.corpus_manager = MagicMock()
        self.orchestrator.corpus_manager.corpus_file_counter = 0
        self.orchestrator.min_corpus_files = 5
        self.orchestrator.fusil_path = None
        self.orchestrator.deepening_probability = 0.3
        self.orchestrator.score_tracker = MagicMock()
        self.orchestrator.global_seed_counter = 0
        self.orchestrator.analyze_run = MagicMock()
        self.orchestrator._build_lineage_profile = MagicMock()
        self.orchestrator._log_timeseries_datapoint = MagicMock()

    def test_bootstraps_corpus_when_below_minimum(self):
        """Test that corpus generation is triggered when size < min."""
        # Start with 2 files, need 3 more
        self.orchestrator.coverage_manager.state = {
            "per_file_coverage": {"file1.py": {}, "file2.py": {}}
        }
        self.orchestrator.corpus_manager.fusil_path_is_valid = True
        self.orchestrator.corpus_manager.generate_new_seed = MagicMock()

        # Mock to break the infinite loop after bootstrap
        with patch.object(self.orchestrator, "execute_mutation_and_analysis_cycle"):
            with patch("sys.stderr", new_callable=io.StringIO):
                with patch("lafleur.orchestrator.save_run_stats"):
                    with patch.object(
                        self.orchestrator.corpus_manager, "select_parent", return_value=None
                    ):
                        self.orchestrator.run_evolutionary_loop()

                        # Should generate 3 files
                        self.assertEqual(
                            self.orchestrator.corpus_manager.generate_new_seed.call_count, 3
                        )

    def test_warns_when_fusil_path_invalid(self):
        """Test that warning is printed when fusil path is invalid."""
        self.orchestrator.coverage_manager.state = {"per_file_coverage": {}}
        self.orchestrator.corpus_manager.fusil_path_is_valid = False
        self.orchestrator.fusil_path = "/invalid/path/to/fusil"
        self.orchestrator.corpus_manager.select_parent = MagicMock(return_value=None)

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with patch("lafleur.orchestrator.save_run_stats"):
                with patch("sys.exit") as mock_exit:
                    self.orchestrator.run_evolutionary_loop()

                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("WARNING: Cannot generate new seed files", stderr_output)
                    self.assertIn("/invalid/path/to/fusil", stderr_output)
                    mock_exit.assert_called_once_with(1)

    def test_exits_when_corpus_empty_and_no_seeder(self):
        """Test that sys.exit is called when corpus is empty with no seeder."""
        self.orchestrator.coverage_manager.state = {"per_file_coverage": {}}
        self.orchestrator.corpus_manager.fusil_path_is_valid = False
        self.orchestrator.corpus_manager.select_parent = MagicMock(return_value=None)

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with patch("lafleur.orchestrator.save_run_stats"):
                with patch("sys.exit") as mock_exit:
                    self.orchestrator.run_evolutionary_loop()

                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("CRITICAL: The corpus is empty", stderr_output)
                    mock_exit.assert_called_once_with(1)

    # def test_proceeds_with_existing_files_when_seeder_unavailable(self):
    #     """Test that loop proceeds when corpus has files but below minimum."""
    #     # Skipped: requires full integration test setup
    #     pass

    # NOTE: The following tests are commented out because they test the infinite
    # run_evolutionary_loop which requires complex integration test setup.
    # The core loop logic is tested through the component tests above.

    # def test_increments_session_counter(self):
    #     """Test that total_sessions counter is incremented."""
    #     # Skipped: requires full integration test setup
    #     pass

    # def test_calls_execute_mutation_cycle(self):
    #     """Test that execute_mutation_and_analysis_cycle is called."""
    #     # Skipped: requires full integration test setup
    #     pass

    # def test_deepening_session_selected_probabilistically(self):
    #     """Test that deepening session is selected based on probability."""
    #     # Skipped: requires full integration test setup
    #     pass

    # def test_breadth_session_selected_probabilistically(self):
    #     """Test that breadth session is selected when random >= probability."""
    #     # Skipped: requires full integration test setup
    #     pass

    # def test_updates_stats_after_each_session(self):
    #     """Test that stats are updated after each session."""
    #     # Skipped: requires full integration test setup
    #     pass

    # def test_logs_timeseries_every_10_sessions(self):
    #     """Test that timeseries data point is logged every 10 sessions."""
    #     # Skipped: requires full integration test setup
    #     pass

    # def test_saves_state_on_keyboard_interrupt(self):
    #     """Test that final stats are saved on KeyboardInterrupt."""
    #     # Skipped: requires full integration test setup
    #     pass

    def test_returns_when_corpus_empty_after_bootstrap(self):
        """Test that loop returns when select_parent returns None."""
        # Corpus has enough files to skip bootstrap, but selection returns None
        self.orchestrator.coverage_manager.state = {
            "per_file_coverage": {f"file{i}.py": {} for i in range(10)}
        }

        with patch.object(self.orchestrator.corpus_manager, "select_parent", return_value=None):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                self.orchestrator.run_evolutionary_loop()

                stdout_output = mock_stdout.getvalue()
                self.assertIn("Corpus is empty and no minimum size was set", stdout_output)


class TestExecuteMutationAndAnalysisCycle(unittest.TestCase):
    """Test execute_mutation_and_analysis_cycle method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {"total_mutations": 0}
        self.orchestrator.coverage_manager = MagicMock()
        self.orchestrator.coverage_manager.state = {
            "per_file_coverage": {
                "parent_test.py": {
                    "lineage_coverage_profile": {},
                    "file_size_bytes": 1000,
                }
            }
        }
        self.orchestrator.mutations_since_last_find = 0
        self.orchestrator.global_seed_counter = 100
        self.orchestrator.use_dynamic_runs = False
        self.orchestrator.base_runs = 3
        self.orchestrator.corpus_manager = MagicMock()
        self.orchestrator.execution_manager = MagicMock()
        self.orchestrator.mutation_controller = MagicMock()

    def test_calculates_max_mutations(self):
        """Test that _calculate_mutations is called."""
        parent_path = Path("/corpus/parent_test.py")
        parent_score = 150.0

        with patch.object(self.orchestrator, "_calculate_mutations", return_value=200) as mock_calc:
            with patch.object(
                self.orchestrator, "_get_nodes_from_parent", return_value=(None, None, [])
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.orchestrator.execute_mutation_and_analysis_cycle(
                        parent_path, parent_score, 1, False
                    )

                    mock_calc.assert_called_once_with(150.0)

    def test_returns_early_when_parent_invalid(self):
        """Test that cycle returns when _get_nodes_from_parent fails."""
        parent_path = Path("/corpus/parent_test.py")

        with patch.object(self.orchestrator, "_calculate_mutations", return_value=100):
            with patch.object(
                self.orchestrator, "_get_nodes_from_parent", return_value=(None, None, [])
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    result = self.orchestrator.execute_mutation_and_analysis_cycle(
                        parent_path, 100.0, 1, False
                    )

                    # Should return early (None)
                    self.assertIsNone(result)

    def test_increments_mutation_counters(self):
        """Test that mutation counters are incremented."""
        parent_path = Path("/corpus/parent_test.py")
        mock_harness = MagicMock()
        mock_harness.name = "uop_harness_test"
        mock_tree = MagicMock()

        with patch.object(self.orchestrator, "_calculate_mutations", return_value=2):
            with patch.object(
                self.orchestrator,
                "_get_nodes_from_parent",
                return_value=(mock_harness, mock_tree, []),
            ):
                with patch.object(
                    self.orchestrator.mutation_controller,
                    "get_mutated_harness",
                    return_value=(None, {}),
                ):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.orchestrator.execute_mutation_and_analysis_cycle(
                            parent_path, 100.0, 1, False
                        )

                        # Should increment total_mutations by 2
                        self.assertEqual(self.orchestrator.run_stats["total_mutations"], 2)
                        self.assertEqual(self.orchestrator.mutations_since_last_find, 2)

    def test_stops_deepening_when_sterile(self):
        """Test that deepening session stops after 30 sterile mutations."""
        parent_path = Path("/corpus/parent_test.py")
        mock_harness = MagicMock()
        mock_harness.name = "uop_harness_test"
        mock_tree = MagicMock()

        with patch.object(self.orchestrator, "_calculate_mutations", return_value=100):
            with patch.object(
                self.orchestrator,
                "_get_nodes_from_parent",
                return_value=(mock_harness, mock_tree, []),
            ):
                with patch.object(
                    self.orchestrator.mutation_controller,
                    "get_mutated_harness",
                    return_value=(None, {}),
                ):
                    with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                        self.orchestrator.execute_mutation_and_analysis_cycle(
                            parent_path, 100.0, 1, is_deepening_session=True
                        )

                        stdout_output = mock_stdout.getvalue()
                        self.assertIn("Deepening session became sterile", stdout_output)
                        # Should stop after 31 mutations (30 sterile + 1 triggers the check)
                        self.assertLessEqual(self.orchestrator.run_stats["total_mutations"], 31)

    def test_uses_dynamic_runs_when_enabled(self):
        """Test that run count is calculated dynamically when use_dynamic_runs=True."""
        self.orchestrator.use_dynamic_runs = True
        parent_path = Path("/corpus/parent_test.py")
        parent_score = 200.0
        mock_harness = MagicMock()
        mock_harness.name = "uop_harness_test"
        mock_tree = MagicMock()

        with patch.object(self.orchestrator, "_calculate_mutations", return_value=1):
            with patch.object(
                self.orchestrator,
                "_get_nodes_from_parent",
                return_value=(mock_harness, mock_tree, []),
            ):
                with patch.object(
                    self.orchestrator.mutation_controller,
                    "get_mutated_harness",
                    return_value=(mock_harness, {}),
                ):
                    with patch.object(
                        self.orchestrator.mutation_controller,
                        "prepare_child_script",
                        return_value=None,
                    ):
                        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                            self.orchestrator.execute_mutation_and_analysis_cycle(
                                parent_path, parent_score, 1, False
                            )

                            stdout_output = mock_stdout.getvalue()
                            self.assertIn("Dynamically set run count", stdout_output)

    def test_uses_base_runs_when_dynamic_disabled(self):
        """Test that base_runs is used when use_dynamic_runs=False."""
        self.orchestrator.use_dynamic_runs = False
        self.orchestrator.base_runs = 5
        parent_path = Path("/corpus/parent_test.py")
        mock_harness = MagicMock()
        mock_harness.name = "uop_harness_test"

        # Configure execution_manager.execute_child to return (None, None) tuple
        self.orchestrator.execution_manager.execute_child.return_value = (None, None)

        with patch.object(self.orchestrator, "_calculate_mutations", return_value=1):
            with patch.object(
                self.orchestrator,
                "_get_nodes_from_parent",
                return_value=(mock_harness, MagicMock(), []),
            ):
                with patch.object(
                    self.orchestrator.mutation_controller,
                    "get_mutated_harness",
                    return_value=(mock_harness, {}),
                ):
                    with patch.object(
                        self.orchestrator.mutation_controller,
                        "prepare_child_script",
                        return_value="code",
                    ):
                        with patch("sys.stderr", new_callable=io.StringIO):
                            self.orchestrator.execute_mutation_and_analysis_cycle(
                                parent_path, 100.0, 1, False
                            )

                            # Should attempt 5 runs (base_runs), but execute_child returns (None, None)
                            # so analyze_run won't be called
                            # The loop will run 5 times per mutation
                            self.assertEqual(
                                self.orchestrator.execution_manager.execute_child.call_count, 5
                            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
