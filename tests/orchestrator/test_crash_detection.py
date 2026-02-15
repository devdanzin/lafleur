#!/usr/bin/env python3
"""
Tests for crash detection and artifact saving in lafleur.

This module contains unit tests for ArtifactManager methods that detect crashes,
and save various types of findings (divergences, regressions, hangs).
Also tests _filter_jit_stderr on ExecutionManager.
"""

import io
import signal
import unittest
from pathlib import Path
from unittest.mock import patch, mock_open
from lafleur.artifacts import ArtifactManager
from lafleur.analysis import CrashFingerprinter
from lafleur.execution import ExecutionManager


class TestCheckForCrash(unittest.TestCase):
    """Test ArtifactManager.check_for_crash method."""

    def setUp(self):
        self.fingerprinter = CrashFingerprinter()
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=self.fingerprinter,
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=False,
        )

    def test_no_crash_with_zero_returncode(self):
        """Test that return code 0 with no keywords returns False."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Normal output\nNo errors here"

        result = self.artifact_manager.check_for_crash(0, log_content, source_path, log_path)

        self.assertFalse(result)

    def test_ignores_indentation_error(self):
        """Test that IndentationError is ignored as known-uninteresting."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "IndentationError: too many levels of indentation"

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.artifact_manager.check_for_crash(1, log_content, source_path, log_path)

            self.assertFalse(result)
            self.assertIn(
                "Ignoring SyntaxError/IndentationError from invalid mutation",
                mock_stderr.getvalue(),
            )

    def test_ignores_syntax_error_nested_blocks(self):
        """Test that nested blocks SyntaxError is ignored."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "SyntaxError: too many statically nested blocks"

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            result = self.artifact_manager.check_for_crash(1, log_content, source_path, log_path)

            self.assertFalse(result)
            self.assertIn(
                "Ignoring SyntaxError/IndentationError from invalid mutation",
                mock_stderr.getvalue(),
            )

    def test_detects_signal_crash(self):
        """Test that negative return code is interpreted as signal."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Some output"

        # Mock the process_log_file to return the same path
        with patch.object(self.artifact_manager, "process_log_file", return_value=log_path):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    # SIGSEGV = -11
                    result = self.artifact_manager.check_for_crash(
                        -signal.SIGSEGV, log_content, source_path, log_path
                    )

                    self.assertTrue(result)
                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("CRASH DETECTED", stderr_output)
                    self.assertIn("SIGNAL:SIGSEGV", stderr_output)

    def test_detects_returncode_crash(self):
        """Test that positive return code is interpreted as error code."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Some error occurred"

        with patch.object(self.artifact_manager, "process_log_file", return_value=log_path):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    result = self.artifact_manager.check_for_crash(
                        42, log_content, source_path, log_path
                    )

                    self.assertTrue(result)
                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("CRASH DETECTED", stderr_output)
                    self.assertIn("EXIT:42", stderr_output)

    def test_detects_keyword_segfault(self):
        """Test that 'Segmentation fault' keyword triggers crash detection."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Program crashed with Segmentation fault (core dumped)"

        with patch.object(self.artifact_manager, "process_log_file", return_value=log_path):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    result = self.artifact_manager.check_for_crash(
                        0, log_content, source_path, log_path
                    )

                    self.assertTrue(result)
                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("CRASH DETECTED", stderr_output)
                    self.assertIn("keyword_segmentation_fault", stderr_output)

    def test_calls_process_log_file(self):
        """Test that process_log_file is called with crash log limit."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Assertion failed!"

        mock_processed_log = Path("/tmp/child_test_truncated.log")
        with patch.object(
            self.artifact_manager, "process_log_file", return_value=mock_processed_log
        ) as mock_process:
            with patch.object(self.artifact_manager, "_safe_copy", return_value=True):
                with patch("pathlib.Path.unlink"):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.artifact_manager.check_for_crash(0, log_content, source_path, log_path)

                        mock_process.assert_called_once_with(
                            log_path, self.artifact_manager.max_crash_log_bytes, "Crash log"
                        )

    def test_saves_crash_artifacts(self):
        """Test that source and log files are copied to crashes/ directory."""
        source_path = Path("/tmp/child_abc123.py")
        log_path = Path("/tmp/child_abc123.log")
        log_content = "Abort trap!"

        with patch.object(self.artifact_manager, "process_log_file", return_value=log_path):
            with patch("shutil.copy") as mock_copy:
                with patch("sys.stderr", new_callable=io.StringIO):
                    result = self.artifact_manager.check_for_crash(
                        0, log_content, source_path, log_path
                    )

                    self.assertTrue(result)
                    # Should copy both source and log
                    self.assertEqual(mock_copy.call_count, 2)

    def test_session_crash_saving(self):
        """Test that session fuzzing crashes save the full bundle of scripts."""
        # Create artifact manager with session fuzzing enabled
        session_artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=self.fingerprinter,
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=True,
        )

        source_path = Path("/tmp/01_child.py")
        parent_path = Path("/tmp/00_parent.py")
        log_path = Path("/tmp/crash.log")

        # Mock session files (e.g. parent + child)
        session_files = [parent_path, source_path]

        with (
            patch("pathlib.Path.mkdir"),
            patch("shutil.copy"),
            patch("shutil.copy2"),
            patch("builtins.open", mock_open()),
            patch("sys.stderr"),
        ):
            # Mock save_session_crash to verify it gets called
            with patch.object(session_artifact_manager, "save_session_crash") as mock_save_bundle:
                mock_save_bundle.return_value = Path("/tmp/crashes/session_crash_123")

                # Trigger a crash (return code -11 = SIGSEGV)
                session_artifact_manager.check_for_crash(
                    -11,
                    "Segmentation fault",
                    source_path,
                    log_path,
                    parent_path=parent_path,
                    session_files=session_files,
                )

                # Verify the bundle saver was called with the correct list
                mock_save_bundle.assert_called_once_with(
                    session_files,
                    -11,
                    self.fingerprinter.analyze(-11, "Segmentation fault"),
                )

    def test_crash_with_segfault_returns_true(self):
        """Test that a standard SIGSEGV returns True."""
        source_path = Path("/tmp/child.py")
        log_path = Path("/tmp/child.log")
        log_content = "Segmentation  fault (core dumped)"

        with patch("shutil.copy"), patch("sys.stderr"):
            # Return code -11 is SIGSEGV
            result = self.artifact_manager.check_for_crash(-11, log_content, source_path, log_path)
            self.assertTrue(result)

    def test_preserves_truncated_log_extension(self):
        """Test that _truncated.log extension is preserved in crash filename."""
        source_path = Path("/tmp/child_abc123.py")
        log_path = Path("/tmp/child_abc123.log")
        log_content = "Assertion error"

        truncated_log = Path("/tmp/child_abc123_truncated.log")
        with patch.object(self.artifact_manager, "process_log_file", return_value=truncated_log):
            with patch("shutil.copy") as mock_copy:
                with patch("pathlib.Path.unlink"):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.artifact_manager.check_for_crash(0, log_content, source_path, log_path)

                        # Check that the log was copied with _truncated.log extension
                        calls = [str(call[0][1]) for call in mock_copy.call_args_list]
                        self.assertTrue(
                            any("_truncated.log" in call for call in calls),
                            f"Expected _truncated.log in calls: {calls}",
                        )

    def test_preserves_compressed_log_extension(self):
        """Test that .log.zst extension is preserved in crash filename."""
        source_path = Path("/tmp/child_abc123.py")
        log_path = Path("/tmp/child_abc123.log")
        log_content = "JITCorrectnessError: Bad trace"

        compressed_log = Path("/tmp/child_abc123.log.zst")
        with patch.object(self.artifact_manager, "process_log_file", return_value=compressed_log):
            with patch("shutil.copy") as mock_copy:
                with patch("pathlib.Path.unlink"):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.artifact_manager.check_for_crash(0, log_content, source_path, log_path)

                        # Check that the log was copied with .log.zst extension
                        calls = [str(call[0][1]) for call in mock_copy.call_args_list]
                        self.assertTrue(
                            any(".log.zst" in call for call in calls),
                            f"Expected .log.zst in calls: {calls}",
                        )

    def test_handles_io_error_gracefully(self):
        """Test that IOError during file copy is handled gracefully."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Abort "

        with patch.object(self.artifact_manager, "process_log_file", return_value=log_path):
            with patch("shutil.copy", side_effect=IOError("Permission denied")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    result = self.artifact_manager.check_for_crash(
                        0, log_content, source_path, log_path
                    )

                    # Should still return True (crash detected)
                    self.assertTrue(result)
                    # Should log the error via _safe_copy
                    self.assertIn("CRITICAL: Could not save", mock_stderr.getvalue())


class TestFilterJitStderr(unittest.TestCase):
    """Test ExecutionManager._filter_jit_stderr method."""

    def setUp(self):
        # Create ExecutionManager with minimal dependencies
        self.execution_manager = ExecutionManager.__new__(ExecutionManager)

    def test_filters_proto_trace_lines(self):
        """Test that proto-trace lines are removed."""
        stderr = "Normal output\nCreated a proto-trace for function foo\nMore output"

        result = self.execution_manager._filter_jit_stderr(stderr)

        self.assertNotIn("Created a proto-trace", result)
        self.assertIn("Normal output", result)
        self.assertIn("More output", result)

    def test_filters_optimized_trace_lines(self):
        """Test that optimized trace lines are removed."""
        stderr = "Before\nOptimized trace (length 42): foo\nAfter"

        result = self.execution_manager._filter_jit_stderr(stderr)

        self.assertNotIn("Optimized trace", result)
        self.assertIn("Before", result)
        self.assertIn("After", result)

    def test_filters_side_exit_lines(self):
        """Test that SIDE EXIT lines are removed."""
        stderr = "Start\nSIDE EXIT: Deoptimizing\nEnd"

        result = self.execution_manager._filter_jit_stderr(stderr)

        self.assertNotIn("SIDE EXIT", result)
        self.assertIn("Start", result)
        self.assertIn("End", result)

    def test_preserves_non_jit_output(self):
        """Test that non-JIT stderr content is preserved."""
        stderr = "ValueError: invalid value\nTypeError: bad type\nRuntimeError: oops"

        result = self.execution_manager._filter_jit_stderr(stderr)

        self.assertEqual(result, stderr)


class TestSaveDivergence(unittest.TestCase):
    """Test ArtifactManager.save_divergence method."""

    def setUp(self):
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=False,
        )

    def test_increments_divergences_counter(self):
        """Test that divergences_found counter is incremented by orchestrator."""
        # Note: The ArtifactManager no longer increments stats.
        # This test now just verifies the method runs without error.
        source_path = Path("/tmp/child_test.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy"):
                with patch("pathlib.Path.write_text"):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        # Method should not raise
                        self.artifact_manager.save_divergence(
                            source_path, "jit out", "nojit out", "exit_code_mismatch"
                        )

    def test_creates_subdirectory_for_reason(self):
        """Test that divergence subdirectory is created for the reason."""
        source_path = Path("/tmp/child_test.py")

        with patch("pathlib.Path.mkdir") as mock_mkdir:
            with patch("shutil.copy"):
                with patch("pathlib.Path.write_text"):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.artifact_manager.save_divergence(
                            source_path, "jit", "nojit", "stderr_mismatch"
                        )

                        # Should create divergences/stderr_mismatch/
                        mock_mkdir.assert_called_once()
                        args = mock_mkdir.call_args
                        self.assertTrue(args[1].get("parents"))
                        self.assertTrue(args[1].get("exist_ok"))

    def test_saves_source_file(self):
        """Test that source file is copied to divergence directory."""
        source_path = Path("/tmp/child_abc123.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy") as mock_copy:
                with patch("pathlib.Path.write_text"):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.artifact_manager.save_divergence(
                            source_path, "jit", "nojit", "stdout_mismatch"
                        )

                        mock_copy.assert_called_once()
                        # Check that source is copied
                        self.assertEqual(mock_copy.call_args[0][0], source_path)

    def test_creates_diff_file(self):
        """Test that diff file is created comparing outputs."""
        source_path = Path("/tmp/child_test.py")
        jit_output = "Result: 42"
        nojit_output = "Result: 43"

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy"):
                with patch("pathlib.Path.write_text") as mock_write:
                    with patch("sys.stderr", new_callable=io.StringIO):
                        self.artifact_manager.save_divergence(
                            source_path, jit_output, nojit_output, "stdout_mismatch"
                        )

                        # Should write a diff file
                        mock_write.assert_called_once()
                        # Diff should contain the outputs
                        diff_content = mock_write.call_args[0][0]
                        self.assertIn("nojit_output", diff_content)
                        self.assertIn("jit_output", diff_content)

    def test_handles_io_error(self):
        """Test that IOError is handled gracefully."""
        source_path = Path("/tmp/child_test.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy", side_effect=IOError("Disk full")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    self.artifact_manager.save_divergence(
                        source_path, "jit", "nojit", "exit_code_mismatch"
                    )

                    self.assertIn("CRITICAL: Could not save divergence", mock_stderr.getvalue())


class TestSaveRegression(unittest.TestCase):
    """Test ArtifactManager.save_regression method."""

    def setUp(self):
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=False,
        )

    def test_increments_regressions_counter(self):
        """Test that regressions_found counter is incremented by orchestrator."""
        # Note: The ArtifactManager no longer increments stats.
        # This test now just verifies the method runs without error.
        source_path = Path("/tmp/child_test.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO):
                    # Method should not raise
                    self.artifact_manager.save_regression(source_path, 100.5, 10.2)

    def test_saves_with_timing_in_filename(self):
        """Test that filename includes JIT and non-JIT timings."""
        source_path = Path("/tmp/child_abc123.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy") as mock_copy:
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.save_regression(source_path, 150.7, 25.3)

                    # Check filename includes timing data
                    dest_path = str(mock_copy.call_args[0][1])
                    self.assertIn("regression_jit_151ms", dest_path)
                    self.assertIn("nojit_25ms", dest_path)

    def test_creates_regressions_directory(self):
        """Test that regressions/ directory is created."""
        # The directory is created in __init__, not in save_regression
        # So we just verify the method works
        source_path = Path("/tmp/child_test.py")

        with patch("shutil.copy"):
            with patch("sys.stderr", new_callable=io.StringIO):
                self.artifact_manager.save_regression(source_path, 100.0, 10.0)

    def test_handles_io_error(self):
        """Test that IOError during copy is handled."""
        source_path = Path("/tmp/child_test.py")

        with patch("shutil.copy", side_effect=IOError("No space")):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                self.artifact_manager.save_regression(source_path, 50.0, 5.0)

                self.assertIn("CRITICAL: Could not save regression", mock_stderr.getvalue())


class TestSaveJitHang(unittest.TestCase):
    """Test ArtifactManager.save_jit_hang method."""

    def setUp(self):
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=False,
        )

    def test_increments_jit_hangs_counter(self):
        """Test that jit_hangs_found counter is incremented by orchestrator."""
        # Note: The ArtifactManager no longer increments stats.
        # This test now just verifies the method runs without error.
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO):
                    # Method should not raise
                    self.artifact_manager.save_jit_hang(source_path, parent_path)

    def test_creates_jit_hangs_subdirectory(self):
        """Test that divergences/jit_hangs/ subdirectory is created."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch("pathlib.Path.mkdir") as mock_mkdir:
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.save_jit_hang(source_path, parent_path)

                    mock_mkdir.assert_called_once()
                    args = mock_mkdir.call_args
                    self.assertTrue(args[1].get("parents"))
                    self.assertTrue(args[1].get("exist_ok"))

    def test_saves_source_with_parent_name(self):
        """Test that source is saved with parent name in filename."""
        source_path = Path("/tmp/child_abc123.py")
        parent_path = Path("/corpus/parent_def456.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy") as mock_copy:
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.save_jit_hang(source_path, parent_path)

                    dest_path = str(mock_copy.call_args[0][1])
                    self.assertIn("hang_child_abc123_parent_def456.py", dest_path)

    def test_handles_io_error(self):
        """Test that IOError is handled gracefully."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy", side_effect=IOError("Permission denied")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    self.artifact_manager.save_jit_hang(source_path, parent_path)

                    self.assertIn("CRITICAL: Could not save JIT hang", mock_stderr.getvalue())


class TestSaveRegressionTimeout(unittest.TestCase):
    """Test ArtifactManager.save_regression_timeout method."""

    def setUp(self):
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=False,
        )

    def test_increments_regression_timeouts_counter(self):
        """Test that regression_timeouts_found counter is incremented by orchestrator."""
        # Note: The ArtifactManager no longer increments stats.
        # This test now just verifies the method runs without error.
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO):
                    # Method should not raise
                    self.artifact_manager.save_regression_timeout(source_path, parent_path)

    def test_creates_timeouts_subdirectory(self):
        """Test that regressions/timeouts/ subdirectory is created."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch("pathlib.Path.mkdir") as mock_mkdir:
            with patch("shutil.copy"):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.save_regression_timeout(source_path, parent_path)

                    mock_mkdir.assert_called_once()
                    args = mock_mkdir.call_args
                    self.assertTrue(args[1].get("parents"))
                    self.assertTrue(args[1].get("exist_ok"))

    def test_saves_source_with_parent_name(self):
        """Test that source is saved with parent name in filename."""
        source_path = Path("/tmp/child_abc123.py")
        parent_path = Path("/corpus/parent_def456.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy") as mock_copy:
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.artifact_manager.save_regression_timeout(source_path, parent_path)

                    dest_path = str(mock_copy.call_args[0][1])
                    self.assertIn("timeout_child_abc123_parent_def456.py", dest_path)

    def test_handles_io_error(self):
        """Test that IOError is handled gracefully."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch("pathlib.Path.mkdir"):
            with patch("shutil.copy", side_effect=IOError("No space")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    self.artifact_manager.save_regression_timeout(source_path, parent_path)

                    self.assertIn(
                        "CRITICAL: Could not save Regression timeout source file",
                        mock_stderr.getvalue(),
                    )


class TestSaveSessionCrashLabels(unittest.TestCase):
    """Test script labeling in ArtifactManager.save_session_crash."""

    def setUp(self):
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
            session_fuzz=True,
        )

    def test_solo_session_labels_attack(self):
        """Single-script session labels the child as attack, not warmup."""
        scripts = [Path("/tmp/child.py")]
        with (
            patch("pathlib.Path.mkdir"),
            patch("shutil.copy2") as mock_copy2,
            patch("pathlib.Path.write_text"),
            patch("pathlib.Path.chmod"),
        ):
            self.artifact_manager.save_session_crash(scripts, -11)

            dest = mock_copy2.call_args[0][1]
            self.assertEqual(dest.name, "00_attack.py")

    def test_two_scripts_labels_correctly(self):
        """Two-script session: warmup + attack."""
        scripts = [Path("/tmp/parent.py"), Path("/tmp/child.py")]
        with (
            patch("pathlib.Path.mkdir"),
            patch("shutil.copy2") as mock_copy2,
            patch("pathlib.Path.write_text"),
            patch("pathlib.Path.chmod"),
        ):
            self.artifact_manager.save_session_crash(scripts, -11)

            calls = mock_copy2.call_args_list
            self.assertEqual(calls[0][0][1].name, "00_warmup.py")
            self.assertEqual(calls[1][0][1].name, "01_attack.py")

    def test_three_scripts_labels_correctly(self):
        """Three-script session: warmup + script + attack."""
        scripts = [Path("/tmp/parent.py"), Path("/tmp/mixer.py"), Path("/tmp/child.py")]
        with (
            patch("pathlib.Path.mkdir"),
            patch("shutil.copy2") as mock_copy2,
            patch("pathlib.Path.write_text"),
            patch("pathlib.Path.chmod"),
        ):
            self.artifact_manager.save_session_crash(scripts, -11)

            calls = mock_copy2.call_args_list
            self.assertEqual(calls[0][0][1].name, "00_warmup.py")
            self.assertEqual(calls[1][0][1].name, "01_script.py")
            self.assertEqual(calls[2][0][1].name, "02_attack.py")


class TestSafeCopy(unittest.TestCase):
    """Test ArtifactManager._safe_copy helper."""

    def setUp(self):
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
        )

    def test_returns_true_on_success(self):
        """Test that _safe_copy returns True when copy succeeds."""
        with patch("shutil.copy"):
            result = self.artifact_manager._safe_copy(
                Path("/tmp/src.py"), Path("/tmp/dst.py"), "test file"
            )
            self.assertTrue(result)

    def test_returns_false_on_ioerror(self):
        """Test that _safe_copy returns False and logs on IOError."""
        with patch("shutil.copy", side_effect=IOError("Disk full")):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                result = self.artifact_manager._safe_copy(
                    Path("/tmp/src.py"), Path("/tmp/dst.py"), "test file"
                )
                self.assertFalse(result)
                self.assertIn("Could not save test file", mock_stderr.getvalue())

    def test_preserve_metadata_uses_copy2(self):
        """Test that preserve_metadata=True uses shutil.copy2."""
        with patch("shutil.copy2") as mock_copy2:
            self.artifact_manager._safe_copy(
                Path("/tmp/src.py"),
                Path("/tmp/dst.py"),
                "test file",
                preserve_metadata=True,
            )
            mock_copy2.assert_called_once()

    def test_returns_false_for_non_path_src(self):
        """Non-path src (e.g. MagicMock) is rejected before reaching shutil."""
        from unittest.mock import MagicMock

        with patch("shutil.copy") as mock_copy:
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                result = self.artifact_manager._safe_copy(
                    MagicMock(), Path("/tmp/dst.py"), "test file"
                )
                self.assertFalse(result)
                self.assertIn("invalid src type", mock_stderr.getvalue())
                mock_copy.assert_not_called()

    def test_returns_false_for_non_path_dst(self):
        """Non-path dst (e.g. MagicMock) is rejected before reaching shutil."""
        from unittest.mock import MagicMock

        with patch("shutil.copy") as mock_copy:
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                result = self.artifact_manager._safe_copy(
                    Path("/tmp/src.py"), MagicMock(), "test file"
                )
                self.assertFalse(result)
                self.assertIn("invalid dst type", mock_stderr.getvalue())
                mock_copy.assert_not_called()


class TestGetLogSuffix(unittest.TestCase):
    """Test ArtifactManager._get_log_suffix helper."""

    def test_truncated_log(self):
        """Test that _truncated.log suffix is detected."""
        result = ArtifactManager._get_log_suffix(Path("/tmp/child_test_truncated.log"))
        self.assertEqual(result, "_truncated.log")

    def test_compressed_log(self):
        """Test that .log.zst suffix is detected."""
        result = ArtifactManager._get_log_suffix(Path("/tmp/child_test.log.zst"))
        self.assertEqual(result, ".log.zst")

    def test_plain_log(self):
        """Test that plain .log suffix is returned as default."""
        result = ArtifactManager._get_log_suffix(Path("/tmp/child_test.log"))
        self.assertEqual(result, ".log")


class TestSaveTimeoutArtifact(unittest.TestCase):
    """Test ArtifactManager._save_timeout_artifact helper."""

    def setUp(self):
        self.artifact_manager = ArtifactManager(
            crashes_dir=Path("/tmp/crashes"),
            timeouts_dir=Path("/tmp/timeouts"),
            divergences_dir=Path("/tmp/divergences"),
            regressions_dir=Path("/tmp/regressions"),
            fingerprinter=CrashFingerprinter(),
            max_timeout_log_bytes=10_000_000,
            max_crash_log_bytes=10_000_000,
        )

    def test_saves_source_without_log(self):
        """Test that source is saved when no log_path is provided."""
        with (
            patch("pathlib.Path.mkdir"),
            patch("shutil.copy") as mock_copy,
            patch("sys.stderr", new_callable=io.StringIO) as mock_stderr,
        ):
            self.artifact_manager._save_timeout_artifact(
                Path("/tmp/child.py"),
                Path("/corpus/parent.py"),
                Path("/tmp/dest"),
                "Test timeout",
            )
            mock_copy.assert_called_once()
            self.assertIn("Test timeout saved to", mock_stderr.getvalue())

    def test_saves_source_and_log(self):
        """Test that both source and log are saved when log_path is provided."""
        log_path = Path("/tmp/child.log")
        with (
            patch("pathlib.Path.mkdir"),
            patch("shutil.copy") as mock_copy,
            patch.object(
                self.artifact_manager,
                "process_log_file",
                return_value=log_path,
            ),
            patch("pathlib.Path.exists", return_value=True),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.artifact_manager._save_timeout_artifact(
                Path("/tmp/child.py"),
                Path("/corpus/parent.py"),
                Path("/tmp/dest"),
                "Test timeout",
                log_path=log_path,
            )
            # Two copies: source + log
            self.assertEqual(mock_copy.call_count, 2)


if __name__ == "__main__":
    unittest.main()
