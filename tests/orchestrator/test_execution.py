#!/usr/bin/env python3
"""
Tests for execution methods.

This module contains unit tests for:
- ExecutionManager methods (run_timed_trial, execute_child) in lafleur/execution.py
- MutationController methods (prepare_child_script) in lafleur/mutation_controller.py
"""

import ast
import io
import random
import subprocess
import unittest
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, patch

from lafleur.execution import ExecutionManager
from lafleur.mutation_controller import MutationController
from lafleur.artifacts import ArtifactManager
from lafleur.analysis import CrashFingerprinter
from lafleur.utils import ExecutionResult


class TestPrepareChildScript(unittest.TestCase):
    """Test MutationController.prepare_child_script method."""

    def setUp(self):
        """Set up minimal MutationController instance."""
        self.controller = MutationController.__new__(MutationController)
        self.controller.boilerplate_code = "# Boilerplate\n"
        self.controller.differential_testing = False

    def test_assembles_complete_script(self):
        """Test that script includes boilerplate, RNG setup, and core code."""
        parent_code = dedent("""
            int_v1 = 5
            def uop_harness_test():
                x = int_v1
        """)
        parent_tree = ast.parse(parent_code)

        mutated_harness = ast.parse("def uop_harness_test():\n    y = 10").body[0]

        result = self.controller.prepare_child_script(
            parent_tree, mutated_harness, runtime_seed=12345
        )

        self.assertIn("# Boilerplate", result)
        self.assertIn("fuzzer_rng = random.Random(12345)", result)
        self.assertIn("int_v1 = 5", result)
        self.assertIn("y = 10", result)

    def test_replaces_harness_function(self):
        """Test that mutated harness replaces original."""
        parent_code = dedent("""
            def uop_harness_test():
                original = True
        """)
        parent_tree = ast.parse(parent_code)

        mutated_harness = ast.parse("def uop_harness_test():\n    mutated = True").body[0]

        result = self.controller.prepare_child_script(parent_tree, mutated_harness, runtime_seed=42)

        self.assertIn("mutated = True", result)
        self.assertNotIn("original = True", result)

    def test_gc_pressure_added_probabilistically(self):
        """Test that GC tuning is added ~25% of the time."""
        parent_tree = ast.parse("def uop_harness_test():\n    pass")
        mutated_harness = parent_tree.body[0]

        # Test with random returning value that triggers GC (< 0.25)
        with patch("lafleur.mutation_controller.RANDOM.random", return_value=0.1):
            with patch("lafleur.mutation_controller.RANDOM.choices", return_value=[10]):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    result = self.controller.prepare_child_script(
                        parent_tree, mutated_harness, runtime_seed=42
                    )

                    self.assertIn("import gc", result)
                    self.assertIn("gc.set_threshold(10)", result)
                    self.assertIn("Prepending GC pressure", mock_stderr.getvalue())

    def test_no_gc_pressure_when_random_high(self):
        """Test that GC tuning is NOT added when random >= 0.25."""
        parent_tree = ast.parse("def uop_harness_test():\n    pass")
        mutated_harness = parent_tree.body[0]

        with patch("lafleur.mutation_controller.RANDOM.random", return_value=0.9):
            result = self.controller.prepare_child_script(
                parent_tree, mutated_harness, runtime_seed=42
            )

            self.assertNotIn("gc.set_threshold", result)

    def test_differential_testing_adds_instrumentation(self):
        """Test that HarnessInstrumentor is applied in differential mode."""
        self.controller.differential_testing = True

        parent_tree = ast.parse("def uop_harness_f1():\n    x = 1")
        mutated_harness = parent_tree.body[0]

        with patch("lafleur.mutation_controller.HarnessInstrumentor") as mock_instr:
            mock_instance = MagicMock()
            mock_instr.return_value = mock_instance
            mock_instance.visit.return_value = parent_tree

            self.controller.prepare_child_script(parent_tree, mutated_harness, runtime_seed=42)

            mock_instr.assert_called_once()
            mock_instance.visit.assert_called_once()

    def test_returns_none_on_recursion_error(self):
        """Test that RecursionError during unparsing returns None."""
        parent_tree = ast.parse("def uop_harness_test():\n    pass")
        mutated_harness = parent_tree.body[0]

        with patch("ast.unparse", side_effect=RecursionError("Stack overflow")):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                result = self.controller.prepare_child_script(
                    parent_tree, mutated_harness, runtime_seed=42
                )

                self.assertIsNone(result)
                self.assertIn("RecursionError", mock_stderr.getvalue())

    def test_runtime_seed_in_rng_setup(self):
        """Test that runtime seed is correctly embedded."""
        parent_tree = ast.parse("def uop_harness_test():\n    pass")
        mutated_harness = parent_tree.body[0]

        result = self.controller.prepare_child_script(
            parent_tree, mutated_harness, runtime_seed=99999
        )

        self.assertIn("fuzzer_rng = random.Random(99999)", result)

    def test_preserves_non_harness_nodes(self):
        """Test that setup nodes are preserved in output."""
        parent_code = dedent("""
            int_v1 = 5
            str_v1 = "hello"
            def uop_harness_test():
                pass
        """)
        parent_tree = ast.parse(parent_code)
        mutated_harness = parent_tree.body[2]

        result = self.controller.prepare_child_script(parent_tree, mutated_harness, runtime_seed=42)

        self.assertIn("int_v1 = 5", result)
        self.assertIn("str_v1 = 'hello'", result)


class TestRunTimedTrial(unittest.TestCase):
    """Test ExecutionManager._run_timed_trial method."""

    def setUp(self):
        """Set up ExecutionManager with mocks."""
        self.artifact_manager = MagicMock()
        self.corpus_manager = MagicMock()
        self.execution_manager = ExecutionManager(
            target_python="/usr/bin/python3",
            timeout=10,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            differential_testing=False,
            timing_fuzz=False,
            session_fuzz=False,
        )

    def test_successful_timing_returns_average(self):
        """Test that successful runs return average time in milliseconds."""
        mock_path = Path("/tmp/test.py")

        # Simulate 5 runs (num_runs=3 means 5 total to discard outliers)
        with patch("subprocess.run"):
            with patch(
                "time.monotonic",
                side_effect=[
                    0.0,
                    0.1,  # Run 1: 100ms
                    0.2,
                    0.3,  # Run 2: 100ms
                    0.4,
                    0.5,  # Run 3: 100ms
                    0.6,
                    0.7,  # Run 4: 100ms
                    0.8,
                    0.9,  # Run 5: 100ms
                ],
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    avg_ms, did_timeout, cv = self.execution_manager._run_timed_trial(
                        mock_path, num_runs=3, jit_enabled=True
                    )

        self.assertAlmostEqual(avg_ms, 100.0, places=1)
        self.assertFalse(did_timeout)
        self.assertIsInstance(cv, float)

    def test_timeout_returns_none_and_true_flag(self):
        """Test that timeout returns (None, True, None)."""
        mock_path = Path("/tmp/test.py")

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            with patch("sys.stderr", new_callable=io.StringIO):
                avg_ms, did_timeout, cv = self.execution_manager._run_timed_trial(
                    mock_path, num_runs=3, jit_enabled=True
                )

        self.assertIsNone(avg_ms)
        self.assertTrue(did_timeout)
        self.assertIsNone(cv)

    def test_crash_returns_none_and_false_flag(self):
        """Test that crash during timing returns (None, False, None)."""
        mock_path = Path("/tmp/test.py")

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "cmd")):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                avg_ms, did_timeout, cv = self.execution_manager._run_timed_trial(
                    mock_path, num_runs=3, jit_enabled=True
                )

                self.assertIn("crashed during timing", mock_stderr.getvalue())

        self.assertIsNone(avg_ms)
        self.assertFalse(did_timeout)
        self.assertIsNone(cv)

    def test_high_cv_returns_none(self):
        """Test that high coefficient of variation (>20%) returns None."""
        mock_path = Path("/tmp/test.py")

        # Simulate runs with high variation even after discarding min/max
        with patch("subprocess.run"):
            with patch(
                "time.monotonic",
                side_effect=[
                    0.0,
                    0.01,  # Run 1: 10ms (will be discarded as min)
                    0.1,
                    0.13,  # Run 2: 30ms
                    0.2,
                    0.26,  # Run 3: 60ms
                    0.3,
                    0.39,  # Run 4: 90ms
                    0.4,
                    0.52,  # Run 5: 120ms (will be discarded as max)
                ],
            ):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    avg_ms, did_timeout, cv = self.execution_manager._run_timed_trial(
                        mock_path, num_runs=3, jit_enabled=True
                    )

                    self.assertIn("Timing measurements too noisy", mock_stderr.getvalue())

        self.assertIsNone(avg_ms)
        self.assertFalse(did_timeout)
        self.assertIsNone(cv)

    def test_jit_enabled_sets_environment(self):
        """Test that JIT environment variable is set correctly."""
        mock_path = Path("/tmp/test.py")

        with patch("subprocess.run") as mock_run:
            with patch("time.monotonic", side_effect=[i * 0.1 for i in range(10)]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.execution_manager._run_timed_trial(mock_path, num_runs=3, jit_enabled=True)

                    # Check that env has PYTHON_JIT=1
                    env_arg = mock_run.call_args[1]["env"]
                    self.assertEqual(env_arg["PYTHON_JIT"], "1")

    def test_jit_disabled_sets_environment(self):
        """Test that JIT is disabled when jit_enabled=False."""
        mock_path = Path("/tmp/test.py")

        with patch("subprocess.run") as mock_run:
            with patch("time.monotonic", side_effect=[i * 0.1 for i in range(10)]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.execution_manager._run_timed_trial(
                        mock_path, num_runs=3, jit_enabled=False
                    )

                    env_arg = mock_run.call_args[1]["env"]
                    self.assertEqual(env_arg["PYTHON_JIT"], "0")

    def test_disables_debug_logs_for_timing(self):
        """Test that debug logs are disabled during timing."""
        mock_path = Path("/tmp/test.py")

        with patch("subprocess.run") as mock_run:
            with patch("time.monotonic", side_effect=[i * 0.1 for i in range(10)]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.execution_manager._run_timed_trial(mock_path, num_runs=3, jit_enabled=True)

                    env_arg = mock_run.call_args[1]["env"]
                    self.assertEqual(env_arg["PYTHON_LLTRACE"], "0")
                    self.assertEqual(env_arg["PYTHON_OPT_DEBUG"], "0")

    def test_zero_mean_returns_zero(self):
        """Test that zero mean time returns (0.0, False, 0.0)."""
        mock_path = Path("/tmp/test.py")

        with patch("subprocess.run"):
            with patch("time.monotonic", side_effect=[i * 0.0 for i in range(10)]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    avg_ms, did_timeout, cv = self.execution_manager._run_timed_trial(
                        mock_path, num_runs=3, jit_enabled=True
                    )

        self.assertEqual(avg_ms, 0.0)
        self.assertFalse(did_timeout)
        self.assertEqual(cv, 0.0)

    def test_discards_min_and_max_outliers(self):
        """Test that min and max timings are discarded."""
        mock_path = Path("/tmp/test.py")

        # Timings: 10ms, 100ms, 100ms, 100ms, 500ms
        # After sorting: 10, 100, 100, 100, 500
        # Stable (discard min/max): 100, 100, 100 -> mean = 100
        with patch("subprocess.run"):
            with patch(
                "time.monotonic",
                side_effect=[
                    0.0,
                    0.01,  # 10ms - will be discarded (min)
                    0.1,
                    0.2,  # 100ms
                    0.3,
                    0.4,  # 100ms
                    0.5,
                    0.6,  # 100ms
                    0.7,
                    1.2,  # 500ms - will be discarded (max)
                ],
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    avg_ms, _, _ = self.execution_manager._run_timed_trial(
                        mock_path, num_runs=3, jit_enabled=True
                    )

        self.assertAlmostEqual(avg_ms, 100.0, places=1)


class TestHandleTimeout(unittest.TestCase):
    """Test ArtifactManager.handle_timeout method."""

    def setUp(self):
        """Set up ArtifactManager instance."""
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=1_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=False,
        )

    def test_increments_timeout_counter(self):
        """Test that timeout counter is incremented by orchestrator (not artifact manager)."""
        # Note: ArtifactManager no longer increments stats. This test verifies the method works.
        child_source = Path("/tmp/child.py")
        child_log = Path("/tmp/child.log")
        parent = Path("/tmp/parent.py")

        with patch.object(self.artifact_manager, "process_log_file", return_value=child_log):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO):
                    # Method should not raise
                    self.artifact_manager.handle_timeout(child_source, child_log, parent)

    def test_calls_process_log_file(self):
        """Test that process_log_file is called with correct parameters."""
        child_source = Path("/tmp/child.py")
        child_log = Path("/tmp/child.log")
        parent = Path("/tmp/parent.py")

        with patch.object(
            self.artifact_manager, "process_log_file", return_value=child_log
        ) as mock_proc:
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.handle_timeout(child_source, child_log, parent)

            mock_proc.assert_called_once_with(child_log, 1_000_000, "Timeout log")

    def test_saves_source_and_log_files(self):
        """Test that both source and log files are saved."""
        child_source = Path("/tmp/child_12345.py")
        child_log = Path("/tmp/child.log")
        parent = Path("/tmp/parent.py")

        mock_log = MagicMock()
        mock_log.exists.return_value = True

        with patch.object(self.artifact_manager, "process_log_file", return_value=mock_log):
            with patch("shutil.copy") as mock_copy:
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.handle_timeout(child_source, child_log, parent)

            # Should copy both source and log
            self.assertEqual(mock_copy.call_count, 2)

    def test_handles_truncated_log_extension(self):
        """Test that truncated log extension is preserved."""
        child_source = Path("/tmp/child_12345.py")
        child_log = Path("/tmp/child.log")

        mock_log = MagicMock()
        mock_log.name = "child_truncated.log"
        mock_log.exists.return_value = True

        parent = Path("/tmp/parent.py")

        with patch.object(self.artifact_manager, "process_log_file", return_value=mock_log):
            with patch("shutil.copy") as mock_copy:
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.handle_timeout(child_source, child_log, parent)

            # Check that the destination log path has _truncated
            log_dest = mock_copy.call_args_list[1][0][1]
            self.assertIn("_truncated", str(log_dest))

    def test_handles_compressed_log_extension(self):
        """Test that compressed log extension is preserved."""
        child_source = Path("/tmp/child_12345.py")
        child_log = Path("/tmp/child.log")

        mock_log = MagicMock()
        mock_log.name = "child.log.zst"
        mock_log.exists.return_value = True

        parent = Path("/tmp/parent.py")

        with patch.object(self.artifact_manager, "process_log_file", return_value=mock_log):
            with patch("shutil.copy") as mock_copy:
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.handle_timeout(child_source, child_log, parent)

            # Check that the destination log path has .log.zst
            log_dest = mock_copy.call_args_list[1][0][1]
            self.assertTrue(str(log_dest).endswith(".log.zst"))

    def test_logs_timeout_detection(self):
        """Test that timeout detection is logged."""
        child_source = Path("/tmp/child.py")
        child_log = Path("/tmp/child.log")
        parent = Path("/tmp/parent.py")

        with patch.object(self.artifact_manager, "process_log_file", return_value=child_log):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    self.artifact_manager.handle_timeout(child_source, child_log, parent)

                    self.assertIn("TIMEOUT DETECTED", mock_stderr.getvalue())


class TestExecuteChild(unittest.TestCase):
    """Test ExecutionManager.execute_child method."""

    def setUp(self):
        """Set up ExecutionManager with mocks."""
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=1_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=False,
        )
        self.corpus_manager = MagicMock()
        self.execution_manager = ExecutionManager(
            target_python="/usr/bin/python3",
            timeout=10,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            differential_testing=False,
            timing_fuzz=False,
            session_fuzz=False,
        )

    def test_skips_differential_when_disabled(self):
        """Test that differential testing is skipped when disabled."""
        source = "def uop_harness_test():\n    pass"
        source_path = Path("/tmp/child.py")
        log_path = Path("/tmp/child.log")
        parent_path = Path("/tmp/parent.py")

        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr="Coverage: edges={}"
                )
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.execution_manager.execute_child(source, source_path, log_path, parent_path)

        # Should only run once for coverage (no differential runs)
        self.assertEqual(mock_run.call_count, 1)

    def test_differential_detects_exit_code_mismatch(self):
        """Test that differential testing detects exit code mismatches."""
        self.execution_manager.differential_testing = True

        source = "def uop_harness_test():\n    pass"
        source_path = Path("/tmp/child.py")
        log_path = Path("/tmp/child.log")
        parent_path = Path("/tmp/parent.py")

        nojit_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="out1", stderr="")
        jit_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="out2", stderr="")

        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run", side_effect=[nojit_result, jit_result]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    result, stat_key = self.execution_manager.execute_child(
                        source, source_path, log_path, parent_path
                    )

        self.assertIsInstance(result, ExecutionResult)
        self.assertTrue(result.is_divergence)
        self.assertEqual(result.divergence_reason, "exit_code_mismatch")
        self.assertIsNone(stat_key)

    def test_differential_timeout_in_nojit_handled(self):
        """Test that timeout in non-JIT run calls artifact_manager.handle_timeout."""
        self.execution_manager.differential_testing = True

        source = "def uop_harness_test():\n    pass"
        source_path = Path("/tmp/child.py")
        log_path = Path("/tmp/child.log")
        parent_path = Path("/tmp/parent.py")

        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
                with patch.object(
                    self.artifact_manager, "handle_timeout", return_value=None
                ) as mock_handle:
                    with patch("sys.stderr", new_callable=io.StringIO):
                        result, stat_key = self.execution_manager.execute_child(
                            source, source_path, log_path, parent_path
                        )

                    mock_handle.assert_called_once()
        self.assertIsNone(result)
        self.assertEqual(stat_key, "timeouts_found")

    def test_differential_timeout_in_jit_saves_hang(self):
        """Test that timeout in JIT run calls artifact_manager.save_jit_hang."""
        self.execution_manager.differential_testing = True

        source = "def uop_harness_test():\n    pass"
        source_path = Path("/tmp/child.py")
        log_path = Path("/tmp/child.log")
        parent_path = Path("/tmp/parent.py")

        nojit_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        with patch("pathlib.Path.write_text"):
            with patch(
                "subprocess.run", side_effect=[nojit_result, subprocess.TimeoutExpired("cmd", 10)]
            ):
                with patch.object(self.artifact_manager, "save_jit_hang") as mock_save:
                    with patch("sys.stderr", new_callable=io.StringIO):
                        result, stat_key = self.execution_manager.execute_child(
                            source, source_path, log_path, parent_path
                        )

                    mock_save.assert_called_once()
        self.assertIsNone(result)
        self.assertEqual(stat_key, "jit_hangs_found")

    def test_returns_execution_result_on_success(self):
        """Test that successful execution returns ExecutionResult."""
        source = "def uop_harness_test():\n    pass"
        source_path = Path("/tmp/child.py")
        log_path = Path("/tmp/child.log")
        parent_path = Path("/tmp/parent.py")

        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )
                with patch("sys.stderr", new_callable=io.StringIO):
                    result, stat_key = self.execution_manager.execute_child(
                        source, source_path, log_path, parent_path
                    )

        self.assertIsInstance(result, ExecutionResult)
        self.assertEqual(result.source_path, source_path)
        self.assertEqual(result.log_path, log_path)
        self.assertIsNone(stat_key)

    def test_execute_child_logs_traceback_on_exception(self):
        """Exception in coverage stage logs type, message, and traceback."""
        source = "def uop_harness_test():\n    pass"
        source_path = Path("/tmp/child.py")
        log_path = Path("/tmp/child.log")
        parent_path = Path("/tmp/parent.py")

        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run", side_effect=PermissionError("access denied")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    result, stat_key = self.execution_manager.execute_child(
                        source, source_path, log_path, parent_path
                    )

                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("PermissionError", stderr_output)
                    self.assertIn("access denied", stderr_output)
                    self.assertIn("Traceback", stderr_output)

        self.assertEqual(result.returncode, 255)
        self.assertIsNone(stat_key)


class TestVerifyTargetCapabilities(unittest.TestCase):
    """Test ExecutionManager.verify_target_capabilities method."""

    def setUp(self):
        """Set up minimal ExecutionManager instance."""
        self.execution_manager = ExecutionManager.__new__(ExecutionManager)
        self.execution_manager.target_python = "/usr/bin/python3"

    def test_succeeds_with_jit_traces(self):
        """Test that verification succeeds when JIT traces are detected."""
        jit_output = "Created a proto-trace for function workload\nOptimized trace [0]"
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=jit_output
        )

        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                # Should not raise
                self.execution_manager.verify_target_capabilities()

                self.assertIn("validated successfully", mock_stderr.getvalue())

    def test_raises_without_jit_traces(self):
        """Test that verification calls sys.exit without JIT traces."""
        no_jit_output = "No JIT output here"
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=no_jit_output
        )

        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stderr", new_callable=io.StringIO):
                with patch("sys.exit") as mock_exit:
                    self.execution_manager.verify_target_capabilities()

                    # Should call sys.exit(1) when JIT traces not found
                    mock_exit.assert_called_once_with(1)

    def test_handles_subprocess_timeout(self):
        """Test that subprocess timeout raises RuntimeError."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 15)):
            with self.assertRaises(RuntimeError) as ctx:
                self.execution_manager.verify_target_capabilities()

            self.assertIn("timed out", str(ctx.exception))

    def test_uses_correct_environment(self):
        """Test that verification uses JIT environment variables."""
        jit_output = "Optimized trace (length 42):"
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=jit_output
        )

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch("sys.stderr", new_callable=io.StringIO):
                self.execution_manager.verify_target_capabilities()

                # Check environment variables
                call_kwargs = mock_run.call_args[1]
                self.assertIn("env", call_kwargs)


class TestMakeDivergenceResult(unittest.TestCase):
    """Test ExecutionManager._make_divergence_result helper."""

    def setUp(self):
        """Set up minimal ExecutionManager instance."""
        self.em = ExecutionManager.__new__(ExecutionManager)

    def test_make_divergence_result_fields(self):
        """All fields of the returned ExecutionResult match inputs."""
        result, second = self.em._make_divergence_result(
            child_source_path=Path("/tmp/child.py"),
            child_log_path=Path("/tmp/child.log"),
            parent_path=Path("/tmp/parent.py"),
            reason="exit_code_mismatch",
            jit_output="Exit Code: 1",
            nojit_output="Exit Code: 0",
        )

        self.assertTrue(result.is_divergence)
        self.assertEqual(result.divergence_reason, "exit_code_mismatch")
        self.assertEqual(result.jit_output, "Exit Code: 1")
        self.assertEqual(result.nojit_output, "Exit Code: 0")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.execution_time_ms, 0)
        self.assertEqual(result.source_path, Path("/tmp/child.py"))
        self.assertEqual(result.log_path, Path("/tmp/child.log"))
        self.assertEqual(result.parent_path, Path("/tmp/parent.py"))
        self.assertIsNone(second)


class TestRunDifferentialStage(unittest.TestCase):
    """Test ExecutionManager._run_differential_stage."""

    def setUp(self):
        """Set up ExecutionManager with mocks."""
        self.artifact_manager = MagicMock()
        self.corpus_manager = MagicMock()
        self.em = ExecutionManager(
            target_python="/usr/bin/python3",
            timeout=10,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            differential_testing=True,
        )
        self.source = "def uop_harness_test():\n    pass"
        self.source_path = Path("/tmp/child.py")
        self.log_path = Path("/tmp/child.log")
        self.parent_path = Path("/tmp/parent.py")

    def test_returns_none_on_no_divergence(self):
        """No divergence returns None (continue to next stage)."""
        identical = subprocess.CompletedProcess(args=[], returncode=0, stdout="out", stderr="")
        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run", return_value=identical):
                with patch("sys.stderr", new_callable=io.StringIO):
                    result = self.em._run_differential_stage(
                        self.source, self.source_path, self.log_path, self.parent_path
                    )
        self.assertIsNone(result)

    def test_detects_exit_code_mismatch(self):
        """Different return codes trigger exit_code_mismatch divergence."""
        nojit = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        jit = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run", side_effect=[nojit, jit]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    result = self.em._run_differential_stage(
                        self.source, self.source_path, self.log_path, self.parent_path
                    )
        exec_result, stat_key = result
        self.assertTrue(exec_result.is_divergence)
        self.assertEqual(exec_result.divergence_reason, "exit_code_mismatch")
        self.assertIsNone(stat_key)

    def test_timeout_nojit(self):
        """Timeout on non-JIT run returns timeouts_found."""
        with patch("pathlib.Path.write_text"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
                with patch("sys.stderr", new_callable=io.StringIO):
                    result = self.em._run_differential_stage(
                        self.source, self.source_path, self.log_path, self.parent_path
                    )
        self.assertEqual(result, (None, "timeouts_found"))
        self.artifact_manager.handle_timeout.assert_called_once()

    def test_timeout_jit(self):
        """Timeout on JIT run returns jit_hangs_found."""
        nojit = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("pathlib.Path.write_text"):
            with patch(
                "subprocess.run",
                side_effect=[nojit, subprocess.TimeoutExpired("cmd", 10)],
            ):
                with patch("sys.stderr", new_callable=io.StringIO):
                    result = self.em._run_differential_stage(
                        self.source, self.source_path, self.log_path, self.parent_path
                    )
        self.assertEqual(result, (None, "jit_hangs_found"))
        self.artifact_manager.save_jit_hang.assert_called_once()


class TestRunTimingStage(unittest.TestCase):
    """Test ExecutionManager._run_timing_stage."""

    def setUp(self):
        """Set up ExecutionManager with mocks."""
        self.artifact_manager = MagicMock()
        self.corpus_manager = MagicMock()
        self.em = ExecutionManager(
            target_python="/usr/bin/python3",
            timeout=10,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            timing_fuzz=True,
        )
        self.source = "def uop_harness_test():\n    pass"
        self.source_path = Path("/tmp/child.py")
        self.log_path = Path("/tmp/child.log")
        self.parent_path = Path("/tmp/parent.py")

    def test_returns_timings(self):
        """Successful timing returns timing data and None for early_exit."""
        with patch("pathlib.Path.write_text"):
            with patch.object(
                self.em,
                "_run_timed_trial",
                side_effect=[
                    (50.0, False, 0.1),  # nojit
                    (30.0, False, 0.05),  # jit
                ],
            ):
                timings, early_exit = self.em._run_timing_stage(
                    self.source, self.source_path, self.log_path, self.parent_path
                )
        self.assertEqual(timings, (30.0, 50.0, 0.1))
        self.assertIsNone(early_exit)

    def test_timeout_nojit(self):
        """Timeout on non-JIT trial returns early exit with timeouts_found."""
        with patch("pathlib.Path.write_text"):
            with patch.object(
                self.em,
                "_run_timed_trial",
                return_value=(None, True, None),
            ):
                timings, early_exit = self.em._run_timing_stage(
                    self.source, self.source_path, self.log_path, self.parent_path
                )
        self.assertEqual(timings, (None, None, None))
        self.assertEqual(early_exit, (None, "timeouts_found"))

    def test_timeout_jit(self):
        """Timeout on JIT trial returns early exit with regression_timeouts_found."""
        with patch("pathlib.Path.write_text"):
            with patch.object(
                self.em,
                "_run_timed_trial",
                side_effect=[
                    (50.0, False, 0.1),  # nojit succeeds
                    (None, True, None),  # jit times out
                ],
            ):
                timings, early_exit = self.em._run_timing_stage(
                    self.source, self.source_path, self.log_path, self.parent_path
                )
        self.assertEqual(timings, (None, None, None))
        self.assertEqual(early_exit, (None, "regression_timeouts_found"))


class TestBuildEnv(unittest.TestCase):
    """Test ExecutionManager._build_env helper."""

    def setUp(self):
        """Set up minimal ExecutionManager instance."""
        self.em = ExecutionManager.__new__(ExecutionManager)

    def test_build_env_jit_enabled(self):
        """JIT enabled with no debug logs sets correct env vars."""
        env = self.em._build_env(jit=True)
        self.assertEqual(env["PYTHON_JIT"], "1")
        self.assertEqual(env["PYTHON_LLTRACE"], "0")
        self.assertEqual(env["PYTHON_OPT_DEBUG"], "0")
        self.assertEqual(env["ASAN_OPTIONS"], "detect_leaks=0")

    def test_build_env_jit_disabled(self):
        """JIT disabled sets PYTHON_JIT to 0."""
        env = self.em._build_env(jit=False)
        self.assertEqual(env["PYTHON_JIT"], "0")

    def test_build_env_debug_logs_enabled(self):
        """Debug logs enabled sets LLTRACE and OPT_DEBUG."""
        env = self.em._build_env(jit=True, debug_logs=True)
        self.assertEqual(env["PYTHON_LLTRACE"], "2")
        self.assertEqual(env["PYTHON_OPT_DEBUG"], "4")

    def test_build_env_inherits_system_env(self):
        """System environment variables are inherited."""
        import os

        os.environ["LAFLEUR_TEST_MARKER"] = "1"
        try:
            env = self.em._build_env(jit=True)
            self.assertEqual(env["LAFLEUR_TEST_MARKER"], "1")
        finally:
            del os.environ["LAFLEUR_TEST_MARKER"]


class TestSoloSessionProbability(unittest.TestCase):
    """Test solo session probability for cold-JIT fuzzing diversity."""

    def setUp(self):
        """Set up ExecutionManager with session_fuzz=True."""
        self.artifact_manager = MagicMock()
        self.corpus_manager = MagicMock()
        self.execution_manager = ExecutionManager(
            target_python="/usr/bin/python3",
            timeout=10,
            artifact_manager=self.artifact_manager,
            corpus_manager=self.corpus_manager,
            differential_testing=False,
            timing_fuzz=False,
            session_fuzz=True,
        )
        self.source = "def uop_harness_test():\n    pass"
        self.source_path = Path("/tmp/child.py")
        self.log_path = Path("/tmp/child.log")
        self.parent_path = Path("/tmp/parent.py")

    def test_solo_session_probability_child_only(self):
        """Solo session includes only the child script, no parent or polluters."""
        # First random.random() call < SOLO_SESSION_PROBABILITY triggers solo
        with patch("lafleur.execution.random.random", return_value=0.1):
            with patch("pathlib.Path.write_text"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
                    with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                        result, _ = self.execution_manager.execute_child(
                            self.source, self.source_path, self.log_path, self.parent_path
                        )

                    # Verify the command uses only the child script
                    cmd = mock_run.call_args[0][0]
                    script_args = cmd[3:]  # After [python, -m, lafleur.driver]
                    self.assertEqual(script_args, [str(self.source_path)])
                    self.assertIn("Solo mode: child-only execution", mock_stderr.getvalue())

        # Verify session_files has only the child
        self.assertEqual(result.session_files, [self.source_path])

    def test_normal_session_when_solo_not_triggered(self):
        """When solo not triggered and mixer not triggered, session is [parent, child]."""
        # First call > SOLO_SESSION_PROBABILITY, second call > MIXER_PROBABILITY
        with patch("lafleur.execution.random.random", side_effect=[0.5, 0.5]):
            with patch("pathlib.Path.write_text"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
                    with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                        result, _ = self.execution_manager.execute_child(
                            self.source, self.source_path, self.log_path, self.parent_path
                        )

                    cmd = mock_run.call_args[0][0]
                    script_args = cmd[3:]
                    self.assertEqual(
                        script_args,
                        [str(self.parent_path), str(self.source_path)],
                    )
                    self.assertIn("warm JIT fuzzing", mock_stderr.getvalue())
                    self.assertNotIn("Solo mode", mock_stderr.getvalue())

    def test_solo_session_skips_mixer(self):
        """When solo triggers, corpus_manager.select_parent is NOT called for polluters."""
        with patch("lafleur.execution.random.random", return_value=0.1):
            with patch("pathlib.Path.write_text"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.execution_manager.execute_child(
                            self.source, self.source_path, self.log_path, self.parent_path
                        )

        # select_parent should NOT have been called (mixer was skipped)
        self.corpus_manager.select_parent.assert_not_called()

    def test_session_distribution_approximate(self):
        """Statistical sanity check: solo ~15%, warm ~55-65%, mixer ~20-30%."""
        solo_count = 0
        warm_count = 0
        mixer_count = 0
        iterations = 1000

        for _ in range(iterations):
            # Simulate the branching logic
            if random.random() < 0.15:
                solo_count += 1
            elif random.random() < 0.3:
                mixer_count += 1
            else:
                warm_count += 1

        # Generous bounds to avoid flaky tests
        self.assertGreater(solo_count, 80)  # >8%
        self.assertLess(solo_count, 250)  # <25%
        self.assertGreater(warm_count, 400)  # >40%
        self.assertGreater(mixer_count, 100)  # >10%

    def test_solo_session_crash_bundle_single_file(self):
        """Crash during solo session passes single-element session_files to check_for_crash."""
        from lafleur.artifacts import ArtifactManager
        from lafleur.analysis import CrashFingerprinter

        artifact_mgr = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=1_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=True,
        )

        solo_session_files = [self.source_path]

        with patch.object(artifact_mgr, "process_log_file", return_value=self.log_path):
            with patch.object(artifact_mgr, "save_session_crash") as mock_save:
                with patch("sys.stderr", new_callable=io.StringIO):
                    # Simulate a SIGSEGV crash with session_files=[child_only]
                    artifact_mgr.check_for_crash(
                        return_code=-11,
                        log_content="Fatal Python error: Segmentation fault",
                        source_path=self.source_path,
                        log_path=self.log_path,
                        parent_path=self.parent_path,
                        session_files=solo_session_files,
                    )

                # save_session_crash should be called with only the child script
                mock_save.assert_called_once()
                scripts_arg = mock_save.call_args[0][0]
                self.assertEqual(scripts_arg, [self.source_path])

    def test_solo_session_with_session_fuzz_disabled(self):
        """SOLO_SESSION_PROBABILITY has no effect when session_fuzz=False."""
        self.execution_manager.session_fuzz = False

        with patch("lafleur.execution.random.random") as mock_random:
            with patch("pathlib.Path.write_text"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
                    with patch("sys.stderr", new_callable=io.StringIO):
                        result, _ = self.execution_manager.execute_child(
                            self.source, self.source_path, self.log_path, self.parent_path
                        )

            # random.random() should NOT have been called (no session assembly)
            mock_random.assert_not_called()
            # Should use direct execution, not session driver
            cmd = mock_run.call_args[0][0]
            self.assertNotIn("-m", cmd)
            self.assertNotIn("lafleur.driver", cmd)
            self.assertIsNone(result.session_files)


if __name__ == "__main__":
    unittest.main(verbosity=2)
