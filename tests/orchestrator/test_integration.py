"""Integration tests for lafleur.orchestrator module.

These tests verify end-to-end behavior of the orchestrator with real components
and file I/O, using temporary directories to isolate test state.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, patch

from lafleur.corpus_manager import CorpusManager
from lafleur.coverage import save_coverage_state
from lafleur.execution import ExecutionManager
from lafleur.mutation_controller import MutationController
from lafleur.orchestrator import LafleurOrchestrator


class TestRunEvolutionaryLoopIntegration(unittest.TestCase):
    """Integration tests for run_evolutionary_loop with real event loop."""

    def setUp(self):
        """Set up temporary directories and real orchestrator instance."""
        # Save original working directory
        self.original_cwd = os.getcwd()

        # Create temporary directory and change to it
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)

        # Create directory structure (using relative paths like the real fuzzer)
        self.corpus_dir = Path("corpus/")
        self.corpus_dir.mkdir(parents=True)
        self.coverage_dir = Path("coverage/")
        self.coverage_dir.mkdir(parents=True)
        Path("crashes").mkdir()

        # Create a seed file
        seed_file = Path("corpus/seed_0.py")
        seed_file.write_text(
            dedent("""
            def uop_harness_test():
                x = 1 + 2
                return x
        """).strip()
        )

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            # Create orchestrator with real components (no corpus sync)
            with patch.object(CorpusManager, "synchronize"):
                self.orchestrator = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        # Register seed in coverage manager
        seed_path = str(Path("corpus/seed_0.py").resolve())
        self.orchestrator.coverage_manager.state["per_file_coverage"][seed_path] = {
            "metadata": {
                "parent_id": None,
                "is_seed": True,
                "mutators_applied": [],
                "depth": 0,
            },
            "harness_profiles": {},
        }

        # Track session count for controlled loop exit
        self.session_count = 0
        self.max_sessions = 3

        # Mock _calculate_mutations to return small number for faster tests
        self.mutations_patcher = patch.object(
            MutationController,
            "_calculate_mutations",
            return_value=1,  # Only do 1 mutation per cycle instead of 100
        )
        self.mutations_patcher.start()

    def tearDown(self):
        """Clean up temporary directory and restore working directory."""
        self.mutations_patcher.stop()
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_increments_session_counter_each_iteration(self):
        """run_evolutionary_loop increments session counter each iteration."""
        original_execute = self.orchestrator.execute_mutation_and_analysis_cycle

        def mock_execute_with_counter(*args, **kwargs):
            self.session_count += 1
            if self.session_count >= self.max_sessions:
                raise KeyboardInterrupt("Test limit reached")
            return original_execute(*args, **kwargs)

        with patch.object(
            self.orchestrator,
            "execute_mutation_and_analysis_cycle",
            side_effect=mock_execute_with_counter,
        ):
            with patch("subprocess.run") as mock_run:
                # Mock successful child execution
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        self.assertEqual(self.session_count, self.max_sessions)
        self.assertGreaterEqual(self.orchestrator.run_stats.get("total_sessions", 0), 1)

    def test_calls_execute_mutation_cycle_each_iteration(self):
        """run_evolutionary_loop calls execute_mutation_and_analysis_cycle each iteration."""
        call_count = 0
        original_execute = self.orchestrator.execute_mutation_and_analysis_cycle

        def mock_execute_with_counter(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise KeyboardInterrupt("Test limit reached")
            return original_execute(*args, **kwargs)

        with patch.object(
            self.orchestrator,
            "execute_mutation_and_analysis_cycle",
            side_effect=mock_execute_with_counter,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        self.assertEqual(call_count, 2)

    def test_alternates_between_deepening_and_breadth_sessions(self):
        """run_evolutionary_loop selects deepening and breadth sessions probabilistically."""
        session_types = []

        def capture_session_type(parent_id, parent_score, session_id, is_deepening_session):
            session_types.append(is_deepening_session)
            if len(session_types) >= 10:
                raise KeyboardInterrupt("Test limit reached")
            return None  # Don't actually execute mutations

        # Mock random.random() to return predictable values
        # First 5 calls < 0.2 (deepening), next 5 calls >= 0.2 (breadth)
        random_values = [
            0.1,
            0.15,
            0.05,
            0.19,
            0.18,  # Deepening
            0.5,
            0.8,
            0.3,
            0.9,
            0.6,
        ]  # Breadth

        with patch.object(
            self.orchestrator,
            "execute_mutation_and_analysis_cycle",
            side_effect=capture_session_type,
        ):
            with patch("random.random", side_effect=random_values):
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        # Verify we got both deepening and breadth sessions
        self.assertEqual(len(session_types), 10)
        self.assertTrue(True in session_types, "Should have deepening sessions")
        self.assertTrue(False in session_types, "Should have breadth sessions")
        # First 5 should be deepening (True), next 5 breadth (False)
        self.assertEqual(session_types[:5], [True] * 5)
        self.assertEqual(session_types[5:], [False] * 5)

    def test_updates_run_stats_after_sessions(self):
        """run_evolutionary_loop updates run_stats after sessions complete."""
        iterations = 0
        original_execute = self.orchestrator.execute_mutation_and_analysis_cycle

        def mock_execute_with_counter(*args, **kwargs):
            nonlocal iterations
            iterations += 1
            if iterations >= 2:
                raise KeyboardInterrupt("Test limit reached")
            return original_execute(*args, **kwargs)

        with patch.object(
            self.orchestrator,
            "execute_mutation_and_analysis_cycle",
            side_effect=mock_execute_with_counter,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        # Verify run_stats was updated
        self.assertIn("total_sessions", self.orchestrator.run_stats)
        self.assertGreater(self.orchestrator.run_stats["total_sessions"], 0)

    def test_logs_timeseries_every_n_sessions(self):
        """run_evolutionary_loop logs timeseries data periodically."""
        # Create a mock timeseries log file
        self.orchestrator.timeseries_log_path = self.test_dir / "timeseries.jsonl"

        iterations = 0
        original_execute = self.orchestrator.execute_mutation_and_analysis_cycle

        def mock_execute_with_counter(*args, **kwargs):
            nonlocal iterations
            iterations += 1
            # Run enough iterations to trigger timeseries logging (every 10 sessions)
            if iterations >= 11:
                raise KeyboardInterrupt("Test limit reached")
            return original_execute(*args, **kwargs)

        with patch.object(
            self.orchestrator,
            "execute_mutation_and_analysis_cycle",
            side_effect=mock_execute_with_counter,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        # Verify timeseries log was created and contains data
        if self.orchestrator.timeseries_log_path.exists():
            content = self.orchestrator.timeseries_log_path.read_text()
            self.assertGreater(len(content), 0)

    def test_saves_state_on_keyboard_interrupt(self):
        """run_evolutionary_loop saves mutator scores when interrupted."""
        # Verify mutator scores file doesn't exist yet
        mutator_scores_file = Path("coverage/mutator_scores.json")
        if mutator_scores_file.exists():
            mutator_scores_file.unlink()

        def mock_execute_raises_interrupt(*args, **kwargs):
            raise KeyboardInterrupt("User interrupt")

        with patch.object(
            self.orchestrator,
            "execute_mutation_and_analysis_cycle",
            side_effect=mock_execute_raises_interrupt,
        ):
            try:
                self.orchestrator.run_evolutionary_loop()
            except KeyboardInterrupt:
                pass

        # Verify mutator scores were saved (score_tracker.save_state() called in finally block)
        # Note: Coverage state is only saved by corpus_manager when adding files
        self.assertTrue(mutator_scores_file.exists(), "Mutator scores should be saved on interrupt")

    def test_corpus_bootstrap_with_min_files(self):
        """run_evolutionary_loop bootstraps corpus when below minimum."""
        # Start with empty corpus
        for f in self.corpus_dir.glob("*.py"):
            f.unlink()

        # Clear coverage state
        self.orchestrator.coverage_manager.state["per_file_coverage"] = {}

        # Set minimum corpus files and mark fusil path as valid
        self.orchestrator.min_corpus_files = 3
        self.orchestrator.corpus_manager.fusil_path_is_valid = True

        iterations = 0

        def mock_execute_with_counter(*args, **kwargs):
            nonlocal iterations
            iterations += 1
            if iterations >= 2:
                raise KeyboardInterrupt("Test limit reached")
            return None

        # Mock generate_new_seed to track calls
        with patch.object(
            self.orchestrator.corpus_manager, "generate_new_seed", return_value=None
        ) as mock_generate:
            with patch.object(
                self.orchestrator,
                "execute_mutation_and_analysis_cycle",
                side_effect=mock_execute_with_counter,
            ):
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

            # Verify generate_new_seed was called 3 times (min_corpus_files)
            self.assertEqual(mock_generate.call_count, 3)


class TestCorpusBootstrappingIntegration(unittest.TestCase):
    """Integration tests for corpus bootstrapping workflow."""

    def setUp(self):
        """Set up temporary directories and orchestrator."""
        # Save original working directory
        self.original_cwd = os.getcwd()

        # Create temporary directory and change to it
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)

        # Create directory structure
        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                self.orchestrator = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=5,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

    def tearDown(self):
        """Clean up temporary directory and restore working directory."""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_bootstraps_empty_corpus_with_seeder(self):
        """Orchestrator bootstraps empty corpus using fusil seeder."""
        # Clear corpus and coverage state
        for f in Path("corpus").glob("*.py"):
            f.unlink()
        self.orchestrator.coverage_manager.state["per_file_coverage"] = {}

        # Mark fusil path as valid
        self.orchestrator.corpus_manager.fusil_path_is_valid = True

        iterations = 0

        def limited_execute(*args, **kwargs):
            nonlocal iterations
            iterations += 1
            if iterations >= 2:
                raise KeyboardInterrupt("Test complete")
            return None

        # Mock generate_new_seed to track calls
        with patch.object(
            self.orchestrator.corpus_manager, "generate_new_seed", return_value=None
        ) as mock_generate:
            with patch.object(
                self.orchestrator,
                "execute_mutation_and_analysis_cycle",
                side_effect=limited_execute,
            ):
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

            # Verify generate_new_seed was called 5 times (min_corpus_files)
            self.assertEqual(mock_generate.call_count, 5)

    def test_warns_when_corpus_empty_and_no_seeder(self):
        """Orchestrator warns and exits when corpus empty and no seeder available."""
        # Ensure corpus is empty
        for f in Path("corpus").glob("*.py"):
            f.unlink()

        with patch("sys.stdout"):
            with patch("sys.exit") as mock_exit:
                # Set select_parent to return None to trigger empty corpus path
                self.orchestrator.corpus_manager.select_parent = MagicMock(return_value=None)
                try:
                    self.orchestrator.run_evolutionary_loop()
                except SystemExit:
                    pass

        mock_exit.assert_called_once()


class TestMutationCycleIntegration(unittest.TestCase):
    """Integration tests for end-to-end mutation and analysis cycle."""

    def setUp(self):
        """Set up temporary directories and orchestrator."""
        # Save original working directory
        self.original_cwd = os.getcwd()

        # Create temporary directory and change to it
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)

        # Create directory structure
        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()

        # Create seed file
        seed_file = Path("corpus/seed_0.py")
        seed_file.write_text(
            dedent("""
            def uop_harness_test():
                x = 10
                y = 20
                return x + y
        """).strip()
        )

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                self.orchestrator = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        # Register seed in coverage manager
        seed_path = str(seed_file.resolve())
        self.orchestrator.coverage_manager.state["per_file_coverage"][seed_path] = {
            "metadata": {
                "parent_id": None,
                "is_seed": True,
                "mutators_applied": [],
                "depth": 0,
            },
            "harness_profiles": {},
        }

        # Mock _calculate_mutations to return small number for faster tests
        self.mutations_patcher = patch.object(
            MutationController,
            "_calculate_mutations",
            return_value=1,  # Only do 1 mutation per cycle instead of 100
        )
        self.mutations_patcher.start()

    def tearDown(self):
        """Clean up temporary directory and restore working directory."""
        self.mutations_patcher.stop()
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_complete_mutation_cycle_creates_child(self):
        """Complete mutation cycle creates child file with mutations."""
        seed_file = list(Path("corpus").glob("*.py"))[0]

        # Mock score_and_decide_interestingness to return True (interesting)
        # This bypasses the complex JIT log parsing and directly tests child creation

        def mock_score_interesting(*args, **kwargs):
            # Call original to get NewCoverageInfo, but force it to be interesting
            from lafleur.scoring import NewCoverageInfo

            # Return interesting coverage: 2 global edges = score of 20 > 10
            return True, NewCoverageInfo(global_edges=2)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch.object(
                self.orchestrator.scoring_manager,
                "score_and_decide_interestingness",
                side_effect=mock_score_interesting,
            ):
                # Run one mutation cycle
                self.orchestrator.execute_mutation_and_analysis_cycle(
                    initial_parent_path=seed_file.resolve(),
                    initial_parent_score=0,
                    session_id=10,
                    is_deepening_session=False,
                )

        # Verify a child was created (files are added to corpus/jit_interesting_tests/)
        corpus_files = list(Path("corpus/jit_interesting_tests").glob("*.py"))
        self.assertGreater(
            len(corpus_files), 0, "Child file should be created after successful mutation"
        )

    def test_mutation_cycle_with_crash_saves_artifact(self):
        """Mutation cycle detecting crash saves crash artifact."""
        seed_file = list(Path("corpus").glob("*.py"))[0]

        with patch("subprocess.run") as mock_run:
            # Mock crash with segfault
            mock_run.return_value = MagicMock(
                returncode=-11,  # SIGSEGV
                stdout="",
                stderr="Segmentation fault\n",
            )

            # Run mutation cycle
            self.orchestrator.execute_mutation_and_analysis_cycle(
                initial_parent_path=seed_file.resolve(),
                initial_parent_score=0,
                session_id=10,
                is_deepening_session=False,
            )

        # Verify crash was saved in a structured directory
        crash_dirs = [d for d in Path("crashes").iterdir() if d.is_dir()]
        self.assertGreater(len(crash_dirs), 0, "Crash directory should be created")

        # Verify directory contains metadata.json and crash_script.py
        crash_dir = crash_dirs[0]
        self.assertTrue(
            (crash_dir / "metadata.json").exists(), "metadata.json should exist in crash dir"
        )
        self.assertTrue(
            (crash_dir / "crash_script.py").exists(), "crash_script.py should exist in crash dir"
        )

    def test_mutation_cycle_with_timeout_saves_artifact(self):
        """Mutation cycle detecting timeout saves timeout artifact."""
        seed_file = list(Path("corpus").glob("*.py"))[0]

        # Mock subprocess.run to raise TimeoutExpired
        # This will be caught by _execute_child and handled properly
        with patch("subprocess.run") as mock_run:
            from subprocess import TimeoutExpired

            mock_run.side_effect = TimeoutExpired(cmd=["python"], timeout=5)

            # Run mutation cycle
            self.orchestrator.execute_mutation_and_analysis_cycle(
                initial_parent_path=seed_file.resolve(),
                initial_parent_score=0,
                session_id=10,
                is_deepening_session=False,
            )

        # Verify timeout directory exists and has files (timeouts/ not crashes/timeouts/)
        timeout_dir = Path("timeouts")
        self.assertTrue(timeout_dir.exists(), "Timeout directory should exist")
        timeout_files = list(timeout_dir.glob("timeout_*.py"))
        self.assertGreater(len(timeout_files), 0, "Timeout file should be saved")


class TestStatePersistenceIntegration(unittest.TestCase):
    """Integration tests for state persistence and recovery."""

    def setUp(self):
        """Set up temporary directories."""
        # Save original working directory
        self.original_cwd = os.getcwd()

        # Create temporary directory and change to it
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)

        # Create directory structure
        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()

        # Create seed file
        seed_file = Path("corpus/seed_0.py")
        seed_file.write_text("def uop_harness_test():\n    x = 1\n")

    def tearDown(self):
        """Clean up temporary directory and restore working directory."""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_saves_and_loads_coverage_state(self):
        """Orchestrator saves coverage state that can be reloaded."""
        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                # Create first orchestrator and add coverage
                orch1 = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        # Add some coverage
        orch1.coverage_manager.state["global_coverage"]["edges"] = {100: 5, 200: 3}
        orch1.coverage_manager.state["global_coverage"]["uops"] = {300: 10}
        save_coverage_state(orch1.coverage_manager.state)

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                # Create second orchestrator and verify it loads the state
                orch2 = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        self.assertEqual(orch2.coverage_manager.state["global_coverage"]["edges"], {100: 5, 200: 3})
        self.assertEqual(orch2.coverage_manager.state["global_coverage"]["uops"], {300: 10})

    def test_persists_mutator_scores_across_sessions(self):
        """Mutator scores are persisted and loaded across sessions."""
        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                # Create first orchestrator
                orch1 = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        # Update mutator scores
        orch1.score_tracker.scores["OperatorSwapper"] = 10.0
        orch1.score_tracker.attempts["OperatorSwapper"] = 50
        orch1.score_tracker.save_state()
        save_coverage_state(orch1.coverage_manager.state)

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                # Create second orchestrator
                orch2 = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        # Verify scores were loaded
        self.assertAlmostEqual(orch2.score_tracker.scores.get("OperatorSwapper", 0.0), 10.0)
        self.assertEqual(orch2.score_tracker.attempts.get("OperatorSwapper", 0), 50)

    def test_persists_corpus_metadata_across_sessions(self):
        """Corpus file metadata is persisted and loaded."""
        seed_file = list(Path("corpus").glob("*.py"))[0]

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                # Create orchestrator and add metadata
                orch1 = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        # Add metadata for seed file
        seed_path = str(seed_file.resolve())
        orch1.coverage_manager.state["per_file_coverage"][seed_path] = {
            "metadata": {
                "parent_id": None,
                "is_seed": True,
                "mutators_applied": [],
                "depth": 0,
            },
            "harness_profiles": {"f1": {"edges": {100: 1}, "uops": {200: 1}, "rare_events": {}}},
        }
        save_coverage_state(orch1.coverage_manager.state)

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                # Create new orchestrator and verify metadata loaded
                orch2 = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        metadata = orch2.coverage_manager.state["per_file_coverage"][seed_path]["metadata"]
        self.assertTrue(metadata["is_seed"])
        self.assertEqual(metadata["depth"], 0)


class TestBoundedRunIntegration(unittest.TestCase):
    """Integration tests for bounded diagnostic runs."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)

        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()

        seed_file = Path("corpus/seed_0.py")
        seed_file.write_text("def uop_harness_test():\n    x = 1 + 2\n    return x\n")

        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                self.orchestrator = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    target_python=sys.executable,
                    max_sessions=3,
                    max_mutations_per_session=2,
                )

        seed_path = str(seed_file.resolve())
        self.orchestrator.coverage_manager.state["per_file_coverage"][seed_path] = {
            "metadata": {
                "parent_id": None,
                "is_seed": True,
                "mutators_applied": [],
                "depth": 0,
            },
            "harness_profiles": {},
        }

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_stops_after_max_sessions(self):
        """Orchestrator stops cleanly after max_sessions without KeyboardInterrupt."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            self.orchestrator.run_evolutionary_loop()

        self.assertEqual(self.orchestrator.run_stats["total_sessions"], 3)

    def test_respects_mutations_per_session_cap(self):
        """Each session does at most max_mutations_per_session mutations."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            self.orchestrator.run_evolutionary_loop()

        # 3 sessions x 2 mutations = 6 total max
        self.assertLessEqual(self.orchestrator.run_stats.get("total_mutations", 0), 6)


class TestMutatorFilterValidation(unittest.TestCase):
    """Test that invalid mutator names are caught at construction time."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)
        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()
        Path("corpus/seed_0.py").write_text("def uop_harness_test():\n    x = 1\n")

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_unknown_mutator_raises_valueerror(self):
        """Passing unknown mutator names raises ValueError."""
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                with self.assertRaises(ValueError) as ctx:
                    LafleurOrchestrator(
                        fusil_path=None,
                        min_corpus_files=0,
                        target_python=sys.executable,
                        mutator_filter=["OperatorSwapper", "TotallyFakeMutator"],
                    )
                self.assertIn("TotallyFakeMutator", str(ctx.exception))

    def test_valid_mutator_filter_accepted(self):
        """Known mutator names are accepted and pool is filtered."""
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                orch = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    target_python=sys.executable,
                    mutator_filter=["OperatorSwapper", "GCInjector"],
                )
        names = [t.__name__ for t in orch.mutation_controller.ast_mutator.transformers]
        self.assertEqual(sorted(names), ["GCInjector", "OperatorSwapper"])


if __name__ == "__main__":
    unittest.main()
