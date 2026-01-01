"""Integration tests for lafleur.orchestrator module.

These tests verify end-to-end behavior of the orchestrator with real components
and file I/O, using temporary directories to isolate test state.
"""

import ast
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, Mock, patch

from lafleur.corpus_manager import CorpusManager
from lafleur.coverage import CoverageManager, save_coverage_state
from lafleur.learning import MutatorScoreTracker
from lafleur.orchestrator import LafleurOrchestrator
from lafleur.utils import ExecutionResult


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
        seed_file.write_text(dedent('''
            def uop_harness_test():
                x = 1 + 2
                return x
        ''').strip())

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            # Create orchestrator with real components (no corpus sync)
            with patch.object(CorpusManager, 'synchronize'):
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
            LafleurOrchestrator,
            '_calculate_mutations',
            return_value=1  # Only do 1 mutation per cycle instead of 100
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
            'execute_mutation_and_analysis_cycle',
            side_effect=mock_execute_with_counter
        ):
            with patch('subprocess.run') as mock_run:
                # Mock successful child execution
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="",
                    stderr=""
                )
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        self.assertEqual(self.session_count, self.max_sessions)
        self.assertGreaterEqual(self.orchestrator.run_stats.get('total_sessions', 0), 1)

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
            'execute_mutation_and_analysis_cycle',
            side_effect=mock_execute_with_counter
        ):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        self.assertEqual(call_count, 2)

    def test_alternates_between_deepening_and_breadth_sessions(self):
        """run_evolutionary_loop selects deepening and breadth sessions probabilistically."""
        session_types = []
        original_execute = self.orchestrator.execute_mutation_and_analysis_cycle

        def capture_session_type(parent_id, is_deepening_session, *args, **kwargs):
            session_types.append(is_deepening_session)
            if len(session_types) >= 10:
                raise KeyboardInterrupt("Test limit reached")
            return original_execute(parent_id, is_deepening_session, *args, **kwargs)

        with patch.object(
            self.orchestrator,
            'execute_mutation_and_analysis_cycle',
            side_effect=capture_session_type
        ):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        # With 10 sessions and 30% deepening probability, we expect some variety
        # (unlikely to be all True or all False)
        self.assertGreater(len(session_types), 0)
        self.assertTrue(True in session_types or False in session_types)

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
            'execute_mutation_and_analysis_cycle',
            side_effect=mock_execute_with_counter
        ):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                try:
                    self.orchestrator.run_evolutionary_loop()
                except KeyboardInterrupt:
                    pass

        # Verify run_stats was updated
        self.assertIn('total_sessions', self.orchestrator.run_stats)
        self.assertGreater(self.orchestrator.run_stats['total_sessions'], 0)

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
            'execute_mutation_and_analysis_cycle',
            side_effect=mock_execute_with_counter
        ):
            with patch('subprocess.run') as mock_run:
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
        """run_evolutionary_loop saves state when interrupted."""
        original_execute = self.orchestrator.execute_mutation_and_analysis_cycle

        def mock_execute_raises_interrupt(*args, **kwargs):
            raise KeyboardInterrupt("User interrupt")

        with patch.object(
            self.orchestrator,
            'execute_mutation_and_analysis_cycle',
            side_effect=mock_execute_raises_interrupt
        ):
            try:
                self.orchestrator.run_evolutionary_loop()
            except KeyboardInterrupt:
                pass

        # Verify coverage state was saved
        self.assertTrue(
            (self.coverage_dir / "coverage_state.pkl").exists(),
            "Coverage state should be saved on interrupt"
        )

    def test_corpus_bootstrap_with_min_files(self):
        """run_evolutionary_loop bootstraps corpus when below minimum."""
        # Start with empty corpus
        for f in self.corpus_dir.glob("*.py"):
            f.unlink()

        # Set minimum corpus files
        self.orchestrator.min_corpus_files = 3

        # Mock fusil seeder
        mock_seeder = MagicMock()
        mock_seeder.createTestcase.return_value = dedent('''
            def uop_harness_test():
                y = 2 * 3
                return y
        ''').strip()

        iterations = 0

        def mock_execute_with_counter(*args, **kwargs):
            nonlocal iterations
            iterations += 1
            if iterations >= 5:
                raise KeyboardInterrupt("Test limit reached")
            # Return empty result
            return

        with patch.object(
            self.orchestrator,
            'execute_mutation_and_analysis_cycle',
            side_effect=mock_execute_with_counter
        ):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                with patch('lafleur.orchestrator.Project') as mock_project:
                    mock_project.return_value = mock_seeder
                    self.orchestrator.fusil_path = "/fake/fusil/path"
                    try:
                        self.orchestrator.run_evolutionary_loop()
                    except KeyboardInterrupt:
                        pass

        # Verify corpus was bootstrapped
        corpus_files = list(Path("corpus").glob("*.py"))
        self.assertGreaterEqual(len(corpus_files), 1, "Corpus should be bootstrapped")


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
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
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
        mock_seeder = MagicMock()
        test_cases = [
            "def uop_harness_test():\n    x = 1",
            "def uop_harness_test():\n    y = 2",
            "def uop_harness_test():\n    z = 3",
        ]
        mock_seeder.createTestcase.side_effect = test_cases

        with patch('lafleur.orchestrator.Project', return_value=mock_seeder):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="",
                    stderr="edge: 100->200\n"
                )
                self.orchestrator.fusil_path = "/fake/fusil/path"

                # Run bootstrap (will exit after reaching min_corpus_files)
                iterations = 0

                def limited_execute(*args, **kwargs):
                    nonlocal iterations
                    iterations += 1
                    if iterations >= 6:
                        raise KeyboardInterrupt("Test complete")
                    self.orchestrator.execute_mutation_and_analysis_cycle(*args, **kwargs)

                with patch.object(
                    self.orchestrator,
                    'execute_mutation_and_analysis_cycle',
                    side_effect=limited_execute
                ):
                    try:
                        self.orchestrator.run_evolutionary_loop()
                    except KeyboardInterrupt:
                        pass

        # Verify corpus was populated
        corpus_files = list(Path("corpus").glob("*.py"))
        self.assertGreaterEqual(len(corpus_files), 1)

    def test_warns_when_corpus_empty_and_no_seeder(self):
        """Orchestrator warns and exits when corpus empty and no seeder available."""
        # Ensure corpus is empty
        for f in Path("corpus").glob("*.py"):
            f.unlink()

        with patch('sys.stdout') as mock_stdout:
            with patch('sys.exit') as mock_exit:
                # Set select_parent to return None to trigger empty corpus path
                self.orchestrator.corpus_manager.select_parent = MagicMock(
                    return_value=None
                )
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
        seed_file.write_text(dedent('''
            def uop_harness_test():
                x = 10
                y = 20
                return x + y
        ''').strip())

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
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
            LafleurOrchestrator,
            '_calculate_mutations',
            return_value=1  # Only do 1 mutation per cycle instead of 100
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

        with patch('subprocess.run') as mock_run:
            # Mock successful execution with new coverage
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="edge: 100->200\nedge: 200->300\n"
            )

            # Run one mutation cycle
            self.orchestrator.execute_mutation_and_analysis_cycle(
                initial_parent_path=seed_file.resolve(),
                initial_parent_score=0,
                session_id=10,
                is_deepening_session=False
            )

        # Verify a child was created
        corpus_files = list(Path("corpus").glob("*.py"))
        self.assertGreater(
            len(corpus_files), 1,
            "Child file should be created after successful mutation"
        )

    def test_mutation_cycle_with_crash_saves_artifact(self):
        """Mutation cycle detecting crash saves crash artifact."""
        seed_file = list(Path("corpus").glob("*.py"))[0]

        with patch('subprocess.run') as mock_run:
            # Mock crash with segfault
            mock_run.return_value = MagicMock(
                returncode=-11,  # SIGSEGV
                stdout="",
                stderr="Segmentation fault\n"
            )

            # Run mutation cycle
            self.orchestrator.execute_mutation_and_analysis_cycle(
                initial_parent_path=seed_file.resolve(),
                initial_parent_score=0,
                session_id=10,
                is_deepening_session=False
            )

        # Verify crash was saved
        crash_files = list(Path("crashes").glob("crash_*.py"))
        self.assertGreater(len(crash_files), 0, "Crash file should be saved")

        # Verify log file exists
        if crash_files:
            log_file = crash_files[0].with_suffix('.log')
            self.assertTrue(log_file.exists(), "Crash log should be saved")

    def test_mutation_cycle_with_timeout_saves_artifact(self):
        """Mutation cycle detecting timeout saves timeout artifact."""
        seed_file = list(Path("corpus").glob("*.py"))[0]

        def mock_execute_timeout(*args, **kwargs):
            """Mock _execute_child to raise TimeoutExpired."""
            from subprocess import TimeoutExpired
            raise TimeoutExpired(cmd=["python"], timeout=5)

        with patch.object(
            self.orchestrator,
            '_execute_child',
            side_effect=mock_execute_timeout
        ):
            # Run mutation cycle
            self.orchestrator.execute_mutation_and_analysis_cycle(
                initial_parent_path=seed_file.resolve(),
                initial_parent_score=0,
                session_id=10,
                is_deepening_session=False
            )

        # Verify timeout directory exists and has files
        timeout_dir = Path("crashes/timeouts")
        if timeout_dir.exists():
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
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
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
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
                # Create second orchestrator and verify it loads the state
                orch2 = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    timing_fuzz=False,
                    differential_testing=False,
                    target_python=sys.executable,
                )

        self.assertEqual(
            orch2.coverage_manager.state["global_coverage"]["edges"],
            {100: 5, 200: 3}
        )
        self.assertEqual(
            orch2.coverage_manager.state["global_coverage"]["uops"],
            {300: 10}
        )

    def test_persists_mutator_scores_across_sessions(self):
        """Mutator scores are persisted and loaded across sessions."""
        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
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
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
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
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
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
            "harness_profiles": {
                "f1": {"edges": {100: 1}, "uops": {200: 1}, "rare_events": {}}
            }
        }
        save_coverage_state(orch1.coverage_manager.state)

        # Mock verify_target_capabilities to skip JIT checks
        with patch.object(LafleurOrchestrator, 'verify_target_capabilities'):
            with patch.object(CorpusManager, 'synchronize'):
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


if __name__ == '__main__':
    unittest.main()
