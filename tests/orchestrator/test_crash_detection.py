#!/usr/bin/env python3
"""
Tests for crash detection and artifact saving in lafleur/orchestrator.py.

This module contains unit tests for methods that detect crashes, filter JIT
output, and save various types of findings (divergences, regressions, hangs).
"""

import io
import signal
import shutil
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from lafleur.orchestrator import LafleurOrchestrator
from lafleur.analysis import CrashFingerprinter


class TestCheckForCrash(unittest.TestCase):
    """Test _check_for_crash method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.max_crash_log_bytes = 10_000_000
        self.orchestrator.fingerprinter = CrashFingerprinter()

    def test_no_crash_with_zero_returncode(self):
        """Test that return code 0 with no keywords returns False."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Normal output\nNo errors here"

        result = self.orchestrator._check_for_crash(0, log_content, source_path, log_path)

        self.assertFalse(result)

    def test_ignores_indentation_error(self):
        """Test that IndentationError is ignored as known-uninteresting."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "IndentationError: too many levels of indentation"

        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            result = self.orchestrator._check_for_crash(1, log_content, source_path, log_path)

            self.assertFalse(result)
            self.assertIn("Ignoring known-uninteresting IndentationError", mock_stderr.getvalue())

    def test_ignores_syntax_error_nested_blocks(self):
        """Test that nested blocks SyntaxError is ignored."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "SyntaxError: too many statically nested blocks"

        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            result = self.orchestrator._check_for_crash(1, log_content, source_path, log_path)

            self.assertFalse(result)
            self.assertIn("Ignoring known-uninteresting SyntaxError", mock_stderr.getvalue())

    def test_detects_signal_crash(self):
        """Test that negative return code is interpreted as signal."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Some output"

        # Mock the _process_log_file to return the same path
        with patch.object(self.orchestrator, '_process_log_file', return_value=log_path):
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    # SIGSEGV = -11
                    result = self.orchestrator._check_for_crash(
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

        with patch.object(self.orchestrator, '_process_log_file', return_value=log_path):
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    result = self.orchestrator._check_for_crash(
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

        with patch.object(self.orchestrator, '_process_log_file', return_value=log_path):
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    result = self.orchestrator._check_for_crash(
                        0, log_content, source_path, log_path
                    )

                    self.assertTrue(result)
                    stderr_output = mock_stderr.getvalue()
                    self.assertIn("CRASH DETECTED", stderr_output)
                    self.assertIn("keyword_segmentation_fault", stderr_output)

    def test_detects_keyword_traceback(self):
        """Test that 'Traceback' keyword triggers crash detection."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Traceback (most recent call last):\n  File 'test.py', line 1"

        with patch.object(self.orchestrator, '_process_log_file', return_value=log_path):
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    result = self.orchestrator._check_for_crash(
                        0, log_content, source_path, log_path
                    )

                    self.assertTrue(result)

    def test_calls_process_log_file(self):
        """Test that _process_log_file is called with crash log limit."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Assertion failed!"

        mock_processed_log = Path("/tmp/child_test_truncated.log")
        with patch.object(
            self.orchestrator, '_process_log_file', return_value=mock_processed_log
        ) as mock_process:
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._check_for_crash(0, log_content, source_path, log_path)

                    mock_process.assert_called_once_with(
                        log_path, self.orchestrator.max_crash_log_bytes, "Crash log"
                    )

    def test_saves_crash_artifacts(self):
        """Test that source and log files are copied to crashes/ directory."""
        source_path = Path("/tmp/child_abc123.py")
        log_path = Path("/tmp/child_abc123.log")
        log_content = "Abort trap!"

        with patch.object(self.orchestrator, '_process_log_file', return_value=log_path):
            with patch('shutil.copy') as mock_copy:
                with patch('sys.stderr', new_callable=io.StringIO):
                    result = self.orchestrator._check_for_crash(
                        0, log_content, source_path, log_path
                    )

                    self.assertTrue(result)
                    # Should copy both source and log
                    self.assertEqual(mock_copy.call_count, 2)

    def test_preserves_truncated_log_extension(self):
        """Test that _truncated.log extension is preserved in crash filename."""
        source_path = Path("/tmp/child_abc123.py")
        log_path = Path("/tmp/child_abc123.log")
        log_content = "Assertion error"

        truncated_log = Path("/tmp/child_abc123_truncated.log")
        with patch.object(self.orchestrator, '_process_log_file', return_value=truncated_log):
            with patch('shutil.copy') as mock_copy:
                with patch('pathlib.Path.unlink'):
                    with patch('sys.stderr', new_callable=io.StringIO):
                        self.orchestrator._check_for_crash(0, log_content, source_path, log_path)

                        # Check that the log was copied with _truncated.log extension
                        calls = [str(call[0][1]) for call in mock_copy.call_args_list]
                        self.assertTrue(
                            any("_truncated.log" in call for call in calls),
                            f"Expected _truncated.log in calls: {calls}"
                        )

    def test_preserves_compressed_log_extension(self):
        """Test that .log.zst extension is preserved in crash filename."""
        source_path = Path("/tmp/child_abc123.py")
        log_path = Path("/tmp/child_abc123.log")
        log_content = "JITCorrectnessError: Bad trace"

        compressed_log = Path("/tmp/child_abc123.log.zst")
        with patch.object(self.orchestrator, '_process_log_file', return_value=compressed_log):
            with patch('shutil.copy') as mock_copy:
                with patch('pathlib.Path.unlink'):
                    with patch('sys.stderr', new_callable=io.StringIO):
                        self.orchestrator._check_for_crash(0, log_content, source_path, log_path)

                        # Check that the log was copied with .log.zst extension
                        calls = [str(call[0][1]) for call in mock_copy.call_args_list]
                        self.assertTrue(
                            any(".log.zst" in call for call in calls),
                            f"Expected .log.zst in calls: {calls}"
                        )

    def test_handles_io_error_gracefully(self):
        """Test that IOError during file copy is handled gracefully."""
        source_path = Path("/tmp/child_test.py")
        log_path = Path("/tmp/child_test.log")
        log_content = "Abort!"

        with patch.object(self.orchestrator, '_process_log_file', return_value=log_path):
            with patch('shutil.copy', side_effect=IOError("Permission denied")):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    result = self.orchestrator._check_for_crash(
                        0, log_content, source_path, log_path
                    )

                    # Should still return True (crash detected)
                    self.assertTrue(result)
                    # Should log the error
                    self.assertIn("Error saving crash artifacts", mock_stderr.getvalue())


class TestFilterJitStderr(unittest.TestCase):
    """Test _filter_jit_stderr method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)

    def test_filters_proto_trace_lines(self):
        """Test that proto-trace lines are removed."""
        stderr = "Normal output\nCreated a proto-trace for function foo\nMore output"

        result = self.orchestrator._filter_jit_stderr(stderr)

        self.assertNotIn("Created a proto-trace", result)
        self.assertIn("Normal output", result)
        self.assertIn("More output", result)

    def test_filters_optimized_trace_lines(self):
        """Test that optimized trace lines are removed."""
        stderr = "Before\nOptimized trace (length 42): foo\nAfter"

        result = self.orchestrator._filter_jit_stderr(stderr)

        self.assertNotIn("Optimized trace", result)
        self.assertIn("Before", result)
        self.assertIn("After", result)

    def test_filters_side_exit_lines(self):
        """Test that SIDE EXIT lines are removed."""
        stderr = "Start\nSIDE EXIT: Deoptimizing\nEnd"

        result = self.orchestrator._filter_jit_stderr(stderr)

        self.assertNotIn("SIDE EXIT", result)
        self.assertIn("Start", result)
        self.assertIn("End", result)

    def test_preserves_non_jit_output(self):
        """Test that non-JIT stderr content is preserved."""
        stderr = "ValueError: invalid value\nTypeError: bad type\nRuntimeError: oops"

        result = self.orchestrator._filter_jit_stderr(stderr)

        self.assertEqual(result, stderr)


class TestSaveDivergence(unittest.TestCase):
    """Test _save_divergence method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {}

    def test_increments_divergences_counter(self):
        """Test that divergences_found counter is incremented."""
        source_path = Path("/tmp/child_test.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy'):
                with patch('pathlib.Path.write_text'):
                    with patch('sys.stderr', new_callable=io.StringIO):
                        self.orchestrator._save_divergence(
                            source_path, "jit out", "nojit out", "exit_code_mismatch"
                        )

                        self.assertEqual(self.orchestrator.run_stats["divergences_found"], 1)

    def test_creates_subdirectory_for_reason(self):
        """Test that divergence subdirectory is created for the reason."""
        source_path = Path("/tmp/child_test.py")

        with patch('pathlib.Path.mkdir') as mock_mkdir:
            with patch('shutil.copy'):
                with patch('pathlib.Path.write_text'):
                    with patch('sys.stderr', new_callable=io.StringIO):
                        self.orchestrator._save_divergence(
                            source_path, "jit", "nojit", "stderr_mismatch"
                        )

                        # Should create divergences/stderr_mismatch/
                        mock_mkdir.assert_called_once()
                        args = mock_mkdir.call_args
                        self.assertTrue(args[1].get('parents'))
                        self.assertTrue(args[1].get('exist_ok'))

    def test_saves_source_file(self):
        """Test that source file is copied to divergence directory."""
        source_path = Path("/tmp/child_abc123.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy') as mock_copy:
                with patch('pathlib.Path.write_text'):
                    with patch('sys.stderr', new_callable=io.StringIO):
                        self.orchestrator._save_divergence(
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

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy'):
                with patch('pathlib.Path.write_text') as mock_write:
                    with patch('sys.stderr', new_callable=io.StringIO):
                        self.orchestrator._save_divergence(
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

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy', side_effect=IOError("Disk full")):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    self.orchestrator._save_divergence(
                        source_path, "jit", "nojit", "exit_code_mismatch"
                    )

                    self.assertIn("CRITICAL: Could not save divergence", mock_stderr.getvalue())


class TestSaveRegression(unittest.TestCase):
    """Test _save_regression method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {}

    def test_increments_regressions_counter(self):
        """Test that regressions_found counter is incremented."""
        source_path = Path("/tmp/child_test.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_regression(source_path, 100.5, 10.2)

                    self.assertEqual(self.orchestrator.run_stats["regressions_found"], 1)

    def test_saves_with_timing_in_filename(self):
        """Test that filename includes JIT and non-JIT timings."""
        source_path = Path("/tmp/child_abc123.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy') as mock_copy:
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_regression(source_path, 150.7, 25.3)

                    # Check filename includes timing data
                    dest_path = str(mock_copy.call_args[0][1])
                    self.assertIn("regression_jit_151ms", dest_path)
                    self.assertIn("nojit_25ms", dest_path)

    def test_creates_regressions_directory(self):
        """Test that regressions/ directory is created."""
        source_path = Path("/tmp/child_test.py")

        with patch('pathlib.Path.mkdir') as mock_mkdir:
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_regression(source_path, 100.0, 10.0)

                    mock_mkdir.assert_called_once()
                    args = mock_mkdir.call_args
                    self.assertTrue(args[1].get('parents'))
                    self.assertTrue(args[1].get('exist_ok'))

    def test_handles_io_error(self):
        """Test that IOError during copy is handled."""
        source_path = Path("/tmp/child_test.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy', side_effect=IOError("No space")):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    self.orchestrator._save_regression(source_path, 50.0, 5.0)

                    self.assertIn("CRITICAL: Could not save regression", mock_stderr.getvalue())


class TestSaveJitHang(unittest.TestCase):
    """Test _save_jit_hang method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {}

    def test_increments_jit_hangs_counter(self):
        """Test that jit_hangs_found counter is incremented."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_jit_hang(source_path, parent_path)

                    self.assertEqual(self.orchestrator.run_stats["jit_hangs_found"], 1)

    def test_creates_jit_hangs_subdirectory(self):
        """Test that divergences/jit_hangs/ subdirectory is created."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch('pathlib.Path.mkdir') as mock_mkdir:
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_jit_hang(source_path, parent_path)

                    mock_mkdir.assert_called_once()
                    args = mock_mkdir.call_args
                    self.assertTrue(args[1].get('parents'))
                    self.assertTrue(args[1].get('exist_ok'))

    def test_saves_source_with_parent_name(self):
        """Test that source is saved with parent name in filename."""
        source_path = Path("/tmp/child_abc123.py")
        parent_path = Path("/corpus/parent_def456.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy') as mock_copy:
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_jit_hang(source_path, parent_path)

                    dest_path = str(mock_copy.call_args[0][1])
                    self.assertIn("hang_child_abc123_parent_def456.py", dest_path)

    def test_handles_io_error(self):
        """Test that IOError is handled gracefully."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy', side_effect=IOError("Permission denied")):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    self.orchestrator._save_jit_hang(source_path, parent_path)

                    self.assertIn("CRITICAL: Could not save JIT hang", mock_stderr.getvalue())


class TestSaveRegressionTimeout(unittest.TestCase):
    """Test _save_regression_timeout method."""

    def setUp(self):
        self.orchestrator = LafleurOrchestrator.__new__(LafleurOrchestrator)
        self.orchestrator.run_stats = {}

    def test_increments_regression_timeouts_counter(self):
        """Test that regression_timeouts_found counter is incremented."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_regression_timeout(source_path, parent_path)

                    self.assertEqual(
                        self.orchestrator.run_stats["regression_timeouts_found"], 1
                    )

    def test_creates_timeouts_subdirectory(self):
        """Test that regressions/timeouts/ subdirectory is created."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch('pathlib.Path.mkdir') as mock_mkdir:
            with patch('shutil.copy'):
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_regression_timeout(source_path, parent_path)

                    mock_mkdir.assert_called_once()
                    args = mock_mkdir.call_args
                    self.assertTrue(args[1].get('parents'))
                    self.assertTrue(args[1].get('exist_ok'))

    def test_saves_source_with_parent_name(self):
        """Test that filename includes parent name."""
        source_path = Path("/tmp/child_xyz789.py")
        parent_path = Path("/corpus/parent_abc123.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy') as mock_copy:
                with patch('sys.stderr', new_callable=io.StringIO):
                    self.orchestrator._save_regression_timeout(source_path, parent_path)

                    dest_path = str(mock_copy.call_args[0][1])
                    self.assertIn("timeout_child_xyz789_parent_abc123.py", dest_path)

    def test_handles_io_error(self):
        """Test that IOError during save is handled."""
        source_path = Path("/tmp/child_test.py")
        parent_path = Path("/corpus/parent.py")

        with patch('pathlib.Path.mkdir'):
            with patch('shutil.copy', side_effect=IOError("Disk error")):
                with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                    self.orchestrator._save_regression_timeout(source_path, parent_path)

                    self.assertIn(
                        "CRITICAL: Could not save regression timeout", mock_stderr.getvalue()
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
