#!/usr/bin/env python3
"""
Tests for main evolutionary loop in lafleur/orchestrator.py.

This module contains unit tests for the core fuzzing loop, mutation cycle
execution, and statistics management.
"""

import io
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.mutation_controller import MutationController
from lafleur.orchestrator import FlowControl, LafleurOrchestrator


class TestCalculateMutations(unittest.TestCase):
    """Test MutationController._calculate_mutations method."""

    def setUp(self):
        self.controller = MutationController.__new__(MutationController)

    def test_base_mutations_with_score_100(self):
        """Test that score of 100 gives base mutations."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.controller._calculate_mutations(100.0)

            # Score of 100 should give close to base (100)
            # Multiplier = 0.5 + log(100 * 10 / 100) / 2 = 0.5 + log(10) / 2 ≈ 0.5 + 1.15 = 1.65
            # But let's just verify it's reasonable
            self.assertGreater(mutations, 50)
            self.assertLess(mutations, 300)

    def test_low_score_clamped_to_minimum(self):
        """Test that very low scores result in minimum multiplier."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.controller._calculate_mutations(1.0)

            # Score of 1.0:
            # score_multiplier = 1.0 / 100.0 = 0.01
            # dynamic_multiplier = 0.5 + log(max(1.0, 0.1)) / 2 = 0.5 + log(1.0) / 2 = 0.5
            # final_multiplier = max(0.25, min(3.0, 0.5)) = 0.5
            # max_mutations = int(100 * 0.5) = 50
            self.assertEqual(mutations, 50)

    def test_high_score_clamped_to_maximum(self):
        """Test that very high scores are clamped to 3.0x multiplier."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.controller._calculate_mutations(10000.0)

            # Very high score should clamp to 3.0x, so 100 * 3.0 = 300
            self.assertEqual(mutations, 300)

    def test_medium_score_calculates_dynamic_multiplier(self):
        """Test that medium scores use logarithmic scaling."""
        with patch("sys.stdout", new_callable=io.StringIO):
            mutations = self.controller._calculate_mutations(50.0)

            # Score of 50:
            # score_multiplier = 50 / 100 = 0.5
            # dynamic_multiplier = 0.5 + log(0.5 * 10) / 2 = 0.5 + log(5) / 2 ≈ 0.5 + 0.805 = 1.305
            # final = 100 * 1.305 = 130.5 -> 130
            self.assertGreaterEqual(mutations, 100)
            self.assertLessEqual(mutations, 150)

    def test_prints_dynamic_adjustment_message(self):
        """Test that dynamic adjustment is logged."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            self.controller._calculate_mutations(75.0)

            stdout_output = mock_stdout.getvalue()
            self.assertIn("Dynamically adjusting mutation count", stdout_output)
            self.assertIn("Base: 100", stdout_output)


class TestUpdateAndSaveRunStats(unittest.TestCase):
    """Test ArtifactManager.update_and_save_run_stats method."""

    def setUp(self):
        from lafleur.artifacts import ArtifactManager

        self.run_stats = {}
        self.coverage_manager = MagicMock()
        self.coverage_manager.state = {
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
        self.corpus_manager = MagicMock()
        self.corpus_manager.corpus_file_counter = 123

        # Create ArtifactManager with required dependencies
        self.artifact_manager = ArtifactManager.__new__(ArtifactManager)
        self.artifact_manager.run_stats = self.run_stats
        self.artifact_manager.coverage_manager = self.coverage_manager
        self.artifact_manager.corpus_manager = self.corpus_manager

    def test_updates_timestamp(self):
        """Test that last_update_time is set to current time."""
        with patch("lafleur.artifacts.save_run_stats"):
            with patch("lafleur.artifacts.generate_corpus_stats"):
                before = datetime.now(timezone.utc)
                self.artifact_manager.update_and_save_run_stats(global_seed_counter=42)
                after = datetime.now(timezone.utc)

                timestamp = datetime.fromisoformat(self.run_stats["last_update_time"])
                self.assertGreaterEqual(timestamp, before)
                self.assertLessEqual(timestamp, after)

    def test_updates_corpus_size(self):
        """Test that corpus_size reflects per_file_coverage count."""
        with patch("lafleur.artifacts.save_run_stats"):
            with patch("lafleur.artifacts.generate_corpus_stats"):
                self.artifact_manager.update_and_save_run_stats(global_seed_counter=42)

                self.assertEqual(self.run_stats["corpus_size"], 3)

    def test_updates_global_coverage_counts(self):
        """Test that global coverage metrics are counted."""
        with patch("lafleur.artifacts.save_run_stats"):
            with patch("lafleur.artifacts.generate_corpus_stats"):
                self.artifact_manager.update_and_save_run_stats(global_seed_counter=42)

                self.assertEqual(self.run_stats["global_uops"], 2)
                self.assertEqual(self.run_stats["global_edges"], 3)
                self.assertEqual(self.run_stats["global_rare_events"], 1)

    def test_updates_seed_counters(self):
        """Test that global_seed_counter and corpus_file_counter are updated."""
        with patch("lafleur.artifacts.save_run_stats"):
            with patch("lafleur.artifacts.generate_corpus_stats"):
                self.artifact_manager.update_and_save_run_stats(global_seed_counter=42)

                self.assertEqual(self.run_stats["global_seed_counter"], 42)
                self.assertEqual(self.run_stats["corpus_file_counter"], 123)

    def test_calculates_average_mutations_per_find(self):
        """Test that average_mutations_per_find is calculated when finds > 0."""
        self.run_stats["new_coverage_finds"] = 10
        self.run_stats["sum_of_mutations_per_find"] = 250

        with patch("lafleur.artifacts.save_run_stats"):
            with patch("lafleur.artifacts.generate_corpus_stats"):
                self.artifact_manager.update_and_save_run_stats(global_seed_counter=42)

                self.assertEqual(self.run_stats["average_mutations_per_find"], 25.0)

    def test_no_average_when_no_finds(self):
        """Test that average_mutations_per_find is not set when no finds."""
        self.run_stats["new_coverage_finds"] = 0

        with patch("lafleur.artifacts.save_run_stats"):
            with patch("lafleur.artifacts.generate_corpus_stats"):
                self.artifact_manager.update_and_save_run_stats(global_seed_counter=42)

                self.assertNotIn("average_mutations_per_find", self.run_stats)

    def test_calls_save_run_stats(self):
        """Test that save_run_stats is called with updated stats."""
        with patch("lafleur.artifacts.save_run_stats") as mock_save:
            with patch("lafleur.artifacts.generate_corpus_stats"):
                self.artifact_manager.update_and_save_run_stats(global_seed_counter=42)

                mock_save.assert_called_once_with(self.run_stats)


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
        self.orchestrator.artifact_manager = MagicMock()
        self.orchestrator.scoring_manager = MagicMock()

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

        with patch.object(
            self.orchestrator.mutation_controller, "_calculate_mutations", return_value=200
        ) as mock_calc:
            with patch.object(
                self.orchestrator.mutation_controller,
                "_get_nodes_from_parent",
                return_value=(None, None, []),
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.orchestrator.execute_mutation_and_analysis_cycle(
                        parent_path, parent_score, 1, False
                    )

                    mock_calc.assert_called_once_with(150.0)

    def test_returns_early_when_parent_invalid(self):
        """Test that cycle returns when _get_nodes_from_parent fails."""
        parent_path = Path("/corpus/parent_test.py")

        with patch.object(
            self.orchestrator.mutation_controller, "_calculate_mutations", return_value=100
        ):
            with patch.object(
                self.orchestrator.mutation_controller,
                "_get_nodes_from_parent",
                return_value=(None, None, []),
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

        with patch.object(
            self.orchestrator.mutation_controller, "_calculate_mutations", return_value=2
        ):
            with patch.object(
                self.orchestrator.mutation_controller,
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

        with patch.object(
            self.orchestrator.mutation_controller, "_calculate_mutations", return_value=100
        ):
            with patch.object(
                self.orchestrator.mutation_controller,
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

        with patch.object(
            self.orchestrator.mutation_controller, "_calculate_mutations", return_value=1
        ):
            with patch.object(
                self.orchestrator.mutation_controller,
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

        with patch.object(
            self.orchestrator.mutation_controller, "_calculate_mutations", return_value=1
        ):
            with patch.object(
                self.orchestrator.mutation_controller,
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

    def test_no_false_alarm_when_child_source_missing(self):
        """No output to stdout/stderr when child_source_path doesn't exist during cleanup."""
        self.orchestrator.keep_tmp_logs = False
        parent_path = Path("/corpus/parent_test.py")
        mock_harness = MagicMock()
        mock_harness.name = "uop_harness_test"

        # prepare_child_script returns None → no source file written
        with patch.object(
            self.orchestrator.mutation_controller, "_calculate_mutations", return_value=1
        ):
            with patch.object(
                self.orchestrator.mutation_controller,
                "_get_nodes_from_parent",
                return_value=(mock_harness, MagicMock(), []),
            ):
                with patch.object(
                    self.orchestrator.mutation_controller,
                    "get_mutated_harness",
                    return_value=(mock_harness, {"strategy": "havoc"}),
                ):
                    with patch.object(
                        self.orchestrator.mutation_controller,
                        "prepare_child_script",
                        return_value=None,
                    ):
                        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                                self.orchestrator.execute_mutation_and_analysis_cycle(
                                    parent_path, 100.0, 1, False
                                )

                                stdout_output = mock_stdout.getvalue()
                                stderr_output = mock_stderr.getvalue()
                                self.assertNotIn("Error deleting", stdout_output)
                                self.assertNotIn("Error deleting", stderr_output)


class TestRunStatsKeyErrorWithEmptyStats(unittest.TestCase):
    """Test that run_stats bare += doesn't raise KeyError on empty stats."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        # Completely empty run_stats — no pre-seeded keys
        self.orchestrator.run_stats = {}
        self.orchestrator.coverage_manager = MagicMock()
        self.orchestrator.coverage_manager.state = {
            "per_file_coverage": {
                "parent_test.py": {
                    "lineage_coverage_profile": {},
                    "file_size_bytes": 1000,
                }
            }
        }
        self.orchestrator.mutations_since_last_find = 5
        self.orchestrator.global_seed_counter = 100
        self.orchestrator.use_dynamic_runs = False
        self.orchestrator.base_runs = 1
        self.orchestrator.keep_tmp_logs = False
        self.orchestrator.corpus_manager = MagicMock()
        self.orchestrator.corpus_manager.add_new_file.return_value = "new_child.py"
        self.orchestrator.corpus_manager.scheduler = MagicMock()
        self.orchestrator.corpus_manager.scheduler.calculate_scores.return_value = {}
        self.orchestrator.execution_manager = MagicMock()
        self.orchestrator.mutation_controller = MagicMock()
        self.orchestrator.scoring_manager = MagicMock()
        self.orchestrator.artifact_manager = MagicMock()
        self.orchestrator.score_tracker = MagicMock()
        self.orchestrator.timing_fuzz = False
        self.orchestrator.differential_testing = False

    def test_no_keyerror_on_empty_run_stats_with_new_coverage(self):
        """Empty run_stats must not raise KeyError when NEW_COVERAGE is found."""
        parent_path = Path("/corpus/parent_test.py")
        mock_harness = MagicMock()
        mock_harness.name = "uop_harness_test"
        mock_tree = MagicMock()

        mock_exec_result = MagicMock()
        mock_exec_result.nojit_cv = None

        analysis_data = {
            "status": "NEW_COVERAGE",
            "core_code": "x = 1",
            "baseline_coverage": {},
            "content_hash": "abc123",
            "coverage_hash": "def456",
            "execution_time_ms": 100,
            "parent_id": "parent_test.py",
            "mutation_info": {"strategy": "havoc", "transformers": ["t1"]},
            "mutation_seed": 101,
        }

        self.orchestrator.mutation_controller._calculate_mutations.return_value = 1
        self.orchestrator.mutation_controller._get_nodes_from_parent.return_value = (
            mock_harness,
            mock_tree,
            [],
        )
        self.orchestrator.mutation_controller.get_mutated_harness.return_value = (
            mock_harness,
            {"strategy": "havoc", "transformers": ["t1"]},
        )
        self.orchestrator.mutation_controller.prepare_child_script.return_value = "code"
        self.orchestrator.execution_manager.execute_child.return_value = (mock_exec_result, None)
        self.orchestrator.scoring_manager.analyze_run.return_value = analysis_data

        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO):
                # This must not raise KeyError
                self.orchestrator.execute_mutation_and_analysis_cycle(parent_path, 100.0, 1, False)

        # Verify counters were set correctly
        self.assertEqual(self.orchestrator.run_stats["total_mutations"], 1)
        self.assertEqual(self.orchestrator.run_stats["new_coverage_finds"], 1)
        self.assertEqual(self.orchestrator.run_stats["sum_of_mutations_per_find"], 6)


class TestHandleAnalysisDataFlowControl(unittest.TestCase):
    """Test that _handle_analysis_data returns the correct FlowControl member."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {}
        self.orchestrator.mutations_since_last_find = 0
        self.orchestrator.corpus_manager = MagicMock()
        self.orchestrator.corpus_manager.add_new_file.return_value = "new_child.py"
        self.orchestrator.scoring_manager = MagicMock()
        self.orchestrator.artifact_manager = MagicMock()
        self.orchestrator.score_tracker = MagicMock()
        self.orchestrator.timing_fuzz = False
        self.parent_metadata = {}

    def test_divergence_returns_break(self):
        """DIVERGENCE status returns FlowControl.BREAK."""
        data = {"status": "DIVERGENCE", "mutation_info": {}}
        with patch("sys.stdout", new_callable=io.StringIO):
            result = self.orchestrator._handle_analysis_data(data, 0, self.parent_metadata, None)
        self.assertEqual(result, FlowControl.BREAK)

    def test_crash_returns_continue(self):
        """CRASH status returns FlowControl.CONTINUE."""
        data = {"status": "CRASH", "mutation_info": {}}
        result = self.orchestrator._handle_analysis_data(data, 0, self.parent_metadata, None)
        self.assertEqual(result, FlowControl.CONTINUE)

    def test_new_coverage_returns_break(self):
        """NEW_COVERAGE status returns FlowControl.BREAK."""
        data = {
            "status": "NEW_COVERAGE",
            "mutation_info": {},
            "core_code": "x = 1",
            "baseline_coverage": {},
            "content_hash": "abc",
            "coverage_hash": "def",
            "execution_time_ms": 100,
            "parent_id": "parent.py",
            "mutation_seed": 42,
        }
        with patch("sys.stdout", new_callable=io.StringIO):
            result = self.orchestrator._handle_analysis_data(data, 0, self.parent_metadata, None)
        self.assertEqual(result, FlowControl.BREAK)

    def test_no_change_returns_none(self):
        """NO_CHANGE status returns FlowControl.NONE."""
        data = {"status": "NO_CHANGE", "mutation_info": {}}
        result = self.orchestrator._handle_analysis_data(data, 0, self.parent_metadata, None)
        self.assertEqual(result, FlowControl.NONE)


class TestCleanupLogFile(unittest.TestCase):
    """Test _cleanup_log_file helper method."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.run_logs_dir = self.tmp_dir / "run_logs"
        self.run_logs_dir.mkdir()

        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.keep_tmp_logs = False

        self.child_log_path = self.tmp_dir / "child_1_1_1.log"
        self.parent_id = "parent_test.py"
        self.mutation_seed = 42
        self.run_num = 0

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def test_plain_log_moved_when_keep_tmp_logs(self):
        """Plain .log file is moved to RUN_LOGS_DIR when keep_tmp_logs=True."""
        self.orchestrator.keep_tmp_logs = True
        self.child_log_path.write_text("log content")

        with patch("lafleur.orchestrator.RUN_LOGS_DIR", self.run_logs_dir):
            self.orchestrator._cleanup_log_file(
                self.child_log_path, self.parent_id, self.mutation_seed, self.run_num
            )

        self.assertFalse(self.child_log_path.exists())
        expected_dest = self.run_logs_dir / "log_parent_test.py_seed_42_run_1.log"
        self.assertTrue(expected_dest.exists())
        self.assertEqual(expected_dest.read_text(), "log content")

    def test_plain_log_deleted_when_not_keep(self):
        """Plain .log file is deleted when keep_tmp_logs=False."""
        self.child_log_path.write_text("log content")

        self.orchestrator._cleanup_log_file(
            self.child_log_path, self.parent_id, self.mutation_seed, self.run_num
        )

        self.assertFalse(self.child_log_path.exists())

    def test_compressed_log_handled_when_plain_absent(self):
        """Compressed .log.zst file is handled when plain .log doesn't exist."""
        compressed_path = self.child_log_path.with_suffix(".log.zst")
        compressed_path.write_text("compressed content")

        self.orchestrator.keep_tmp_logs = True
        with patch("lafleur.orchestrator.RUN_LOGS_DIR", self.run_logs_dir):
            self.orchestrator._cleanup_log_file(
                self.child_log_path, self.parent_id, self.mutation_seed, self.run_num
            )

        self.assertFalse(compressed_path.exists())
        expected_dest = self.run_logs_dir / "log_parent_test.py_seed_42_run_1.log.zst"
        self.assertTrue(expected_dest.exists())

    def test_truncated_log_handled_when_others_absent(self):
        """Truncated log file is handled when neither .log nor .log.zst exist."""
        truncated_path = self.child_log_path.with_name(
            f"{self.child_log_path.stem}_truncated{self.child_log_path.suffix}"
        )
        truncated_path.write_text("truncated content")

        self.orchestrator.keep_tmp_logs = True
        with patch("lafleur.orchestrator.RUN_LOGS_DIR", self.run_logs_dir):
            self.orchestrator._cleanup_log_file(
                self.child_log_path, self.parent_id, self.mutation_seed, self.run_num
            )

        self.assertFalse(truncated_path.exists())
        expected_dest = self.run_logs_dir / "log_parent_test.py_seed_42_run_1_truncated.log"
        self.assertTrue(expected_dest.exists())

    def test_no_error_when_no_log_exists(self):
        """No error raised when no log file exists at all."""
        # Don't create any files — should silently return
        self.orchestrator._cleanup_log_file(
            self.child_log_path, self.parent_id, self.mutation_seed, self.run_num
        )

    def test_oserror_caught_and_warned(self):
        """OSError is caught and prints a warning to stderr."""
        self.child_log_path.write_text("log content")

        with patch("lafleur.orchestrator.RUN_LOGS_DIR", self.run_logs_dir):
            # Make unlink raise OSError
            with patch.object(Path, "unlink", side_effect=OSError("disk full")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    self.orchestrator._cleanup_log_file(
                        self.child_log_path, self.parent_id, self.mutation_seed, self.run_num
                    )

                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("Warning: Could not process temp file", stderr_output)
                    self.assertIn("disk full", stderr_output)


class TestMain(unittest.TestCase):
    """Test main CLI entry point."""

    @patch("lafleur.orchestrator.LafleurOrchestrator")
    @patch("lafleur.orchestrator.generate_run_metadata")
    @patch("lafleur.orchestrator.load_run_stats")
    @patch("lafleur.orchestrator.TeeLogger")
    def test_main_basic_invocation(self, mock_tee, mock_stats, mock_metadata, mock_orch_class):
        """Test basic main() invocation."""
        from lafleur.orchestrator import main

        mock_stats.return_value = {"total_mutations": 0}
        mock_metadata.return_value = {"run_id": "test-123", "instance_name": "test"}
        mock_tee_instance = MagicMock()
        mock_tee.return_value = mock_tee_instance

        mock_orch = MagicMock()
        mock_orch_class.return_value = mock_orch

        with patch("sys.argv", ["orchestrator", "--fusil-path", "/fake/fusil"]):
            with patch("lafleur.orchestrator.LOGS_DIR") as mock_logs:
                mock_logs.mkdir = MagicMock()
                main()

        mock_orch.run_evolutionary_loop.assert_called_once()

    @patch("lafleur.orchestrator.LafleurOrchestrator")
    @patch("lafleur.orchestrator.generate_run_metadata")
    @patch("lafleur.orchestrator.load_run_stats")
    @patch("lafleur.orchestrator.TeeLogger")
    def test_main_handles_keyboard_interrupt(
        self, mock_tee, mock_stats, mock_metadata, mock_orch_class
    ):
        """Test that KeyboardInterrupt is handled gracefully."""
        from lafleur.orchestrator import main

        mock_stats.return_value = {"total_mutations": 0}
        mock_metadata.return_value = {"run_id": "test-123", "instance_name": "test"}

        # Create a mock TeeLogger that writes to our captured output
        mock_tee_instance = MagicMock()
        captured_writes = []
        mock_tee_instance.write = lambda x: captured_writes.append(x)
        mock_tee.return_value = mock_tee_instance

        mock_orch = MagicMock()
        mock_orch.run_evolutionary_loop.side_effect = KeyboardInterrupt()
        mock_orch_class.return_value = mock_orch

        with patch("sys.argv", ["orchestrator", "--fusil-path", "/fake/fusil"]):
            with patch("lafleur.orchestrator.LOGS_DIR") as mock_logs:
                mock_logs.mkdir = MagicMock()
                # Also patch Path / operator for logs directory
                mock_logs.__truediv__ = lambda self, x: Path("/fake/logs") / x
                main()

        # Check that "stopped by user" was in any of the writes
        all_output = "".join(str(w) for w in captured_writes)
        self.assertIn("stopped by user", all_output)

    @patch("lafleur.orchestrator.LafleurOrchestrator")
    @patch("lafleur.orchestrator.generate_run_metadata")
    @patch("lafleur.orchestrator.load_run_stats")
    @patch("lafleur.orchestrator.TeeLogger")
    def test_main_handles_exception(self, mock_tee, mock_stats, mock_metadata, mock_orch_class):
        """Test that unexpected exceptions are handled."""
        from lafleur.orchestrator import main

        mock_stats.return_value = {"total_mutations": 0}
        mock_metadata.return_value = {"run_id": "test-123", "instance_name": "test"}
        mock_tee_instance = MagicMock()
        mock_tee.return_value = mock_tee_instance

        mock_orch = MagicMock()
        mock_orch.run_evolutionary_loop.side_effect = RuntimeError("Test error")
        mock_orch_class.return_value = mock_orch

        with patch("sys.argv", ["orchestrator", "--fusil-path", "/fake/fusil"]):
            with patch("lafleur.orchestrator.LOGS_DIR") as mock_logs:
                mock_logs.mkdir = MagicMock()
                with patch("sys.stdout", io.StringIO()):
                    with patch("sys.stderr", io.StringIO()):
                        # Should not raise
                        main()


if __name__ == "__main__":
    unittest.main(verbosity=2)
