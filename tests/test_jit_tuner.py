"""
Tests for the jit_tuner module (lafleur/jit_tuner.py).

This module tests the JIT parameter tweaking utility for CPython builds.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lafleur.jit_tuner import apply_jit_tweaks, main, JIT_TWEAKS


class TestApplyJitTweaks(unittest.TestCase):
    """Tests for apply_jit_tweaks function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cpython_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_skips_nonexistent_directory(self):
        """Test that invalid directory is handled gracefully."""
        # Should not raise, just print error
        apply_jit_tweaks(Path("/nonexistent/cpython"), dry_run=True)

    def test_skips_disabled_files(self):
        """Test that disabled files are skipped."""
        # Create a file that would normally be processed
        header_dir = self.cpython_path / "Include" / "internal"
        header_dir.mkdir(parents=True)
        header_file = header_dir / "pycore_backoff.h"
        header_file.write_text("#define JUMP_BACKWARD_INITIAL_VALUE 1\n")

        # Disable this file
        apply_jit_tweaks(
            self.cpython_path,
            dry_run=True,
            disabled_files=["Include/internal/pycore_backoff.h"],
        )

        # File should not be modified
        content = header_file.read_text()
        self.assertIn("JUMP_BACKWARD_INITIAL_VALUE 1", content)

    def test_skips_disabled_tweaks(self):
        """Test that disabled tweaks are skipped."""
        header_dir = self.cpython_path / "Include" / "internal"
        header_dir.mkdir(parents=True)
        header_file = header_dir / "pycore_backoff.h"
        header_file.write_text(
            "#define JUMP_BACKWARD_INITIAL_VALUE 1\n#define SIDE_EXIT_INITIAL_VALUE 1\n"
        )

        # Disable one specific tweak
        apply_jit_tweaks(
            self.cpython_path,
            dry_run=False,
            disabled_tweaks=["JUMP_BACKWARD_INITIAL_VALUE"],
        )

        content = header_file.read_text()
        # JUMP_BACKWARD_INITIAL_VALUE should still be 1
        self.assertIn("JUMP_BACKWARD_INITIAL_VALUE 1", content)
        # But SIDE_EXIT_INITIAL_VALUE should be changed
        self.assertIn("SIDE_EXIT_INITIAL_VALUE 63", content)

    def test_applies_tweaks_to_valid_files(self):
        """Test that tweaks are applied to valid files."""
        header_dir = self.cpython_path / "Include" / "internal"
        header_dir.mkdir(parents=True)
        header_file = header_dir / "pycore_backoff.h"
        original_content = (
            "#define JUMP_BACKWARD_INITIAL_VALUE 1\n#define JUMP_BACKWARD_INITIAL_BACKOFF 1\n"
        )
        header_file.write_text(original_content)

        apply_jit_tweaks(self.cpython_path, dry_run=False)

        content = header_file.read_text()
        # Values should be changed to the fuzzing-friendly values
        self.assertIn("JUMP_BACKWARD_INITIAL_VALUE 63", content)
        self.assertIn("JUMP_BACKWARD_INITIAL_BACKOFF 6", content)

    def test_dry_run_does_not_modify_files(self):
        """Test that dry_run mode doesn't modify files."""
        header_dir = self.cpython_path / "Include" / "internal"
        header_dir.mkdir(parents=True)
        header_file = header_dir / "pycore_backoff.h"
        original_content = "#define JUMP_BACKWARD_INITIAL_VALUE 1\n"
        header_file.write_text(original_content)

        apply_jit_tweaks(self.cpython_path, dry_run=True)

        content = header_file.read_text()
        # File should not be modified in dry run
        self.assertEqual(content, original_content)

    def test_handles_missing_files_gracefully(self):
        """Test that missing files are skipped gracefully."""
        # Create only the directory structure but not the files
        header_dir = self.cpython_path / "Include" / "internal"
        header_dir.mkdir(parents=True)

        # Should not raise, just print warnings
        apply_jit_tweaks(self.cpython_path, dry_run=True)

    def test_handles_file_read_error(self):
        """Test handling of file read errors."""
        header_dir = self.cpython_path / "Include" / "internal"
        header_dir.mkdir(parents=True)
        header_file = header_dir / "pycore_backoff.h"
        header_file.write_text("#define TEST 1\n")

        # Make file unreadable
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            # Should not raise
            apply_jit_tweaks(self.cpython_path, dry_run=True)

    def test_handles_pattern_not_found(self):
        """Test handling when pattern is not found in file."""
        header_dir = self.cpython_path / "Include" / "internal"
        header_dir.mkdir(parents=True)
        header_file = header_dir / "pycore_backoff.h"
        # Write content without the expected patterns
        header_file.write_text("#define SOME_OTHER_VALUE 123\n")

        # Should not raise, just print warnings
        apply_jit_tweaks(self.cpython_path, dry_run=True)

    def test_processes_optimizer_c(self):
        """Test processing Python/optimizer.c file."""
        opt_dir = self.cpython_path / "Python"
        opt_dir.mkdir(parents=True)
        opt_file = opt_dir / "optimizer.c"
        opt_file.write_text("#define CONFIDENCE_CUTOFF 999\n")

        apply_jit_tweaks(self.cpython_path, dry_run=False)

        content = opt_file.read_text()
        self.assertIn("CONFIDENCE_CUTOFF 100", content)


class TestMain(unittest.TestCase):
    """Tests for the main CLI entry point."""

    @patch("lafleur.jit_tuner.apply_jit_tweaks")
    def test_main_basic_invocation(self, mock_apply):
        """Test basic CLI invocation."""
        with patch("sys.argv", ["jit-tweak", "/path/to/cpython"]):
            main()

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args
        self.assertEqual(call_args[0][0], Path("/path/to/cpython"))
        self.assertFalse(call_args[0][1])  # dry_run = False

    @patch("lafleur.jit_tuner.apply_jit_tweaks")
    def test_main_dry_run(self, mock_apply):
        """Test CLI with --dry-run flag."""
        with patch("sys.argv", ["jit-tweak", "/path/to/cpython", "--dry-run"]):
            main()

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args
        self.assertTrue(call_args[0][1])  # dry_run = True

    @patch("lafleur.jit_tuner.apply_jit_tweaks")
    def test_main_disable_file(self, mock_apply):
        """Test CLI with --disable-file flag."""
        with patch(
            "sys.argv",
            [
                "jit-tweak",
                "/path/to/cpython",
                "--disable-file",
                "Include/internal/pycore_backoff.h",
            ],
        ):
            main()

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args
        self.assertIn("Include/internal/pycore_backoff.h", call_args[0][2])

    @patch("lafleur.jit_tuner.apply_jit_tweaks")
    def test_main_disable_tweak(self, mock_apply):
        """Test CLI with --disable-tweak flag."""
        with patch(
            "sys.argv",
            [
                "jit-tweak",
                "/path/to/cpython",
                "--disable-tweak",
                "CONFIDENCE_CUTOFF",
            ],
        ):
            main()

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args
        self.assertIn("CONFIDENCE_CUTOFF", call_args[0][3])

    @patch("lafleur.jit_tuner.apply_jit_tweaks")
    def test_main_multiple_disable_flags(self, mock_apply):
        """Test CLI with multiple disable flags."""
        with patch(
            "sys.argv",
            [
                "jit-tweak",
                "/path/to/cpython",
                "--disable-file",
                "file1.h",
                "--disable-file",
                "file2.h",
                "--disable-tweak",
                "TWEAK1",
                "--disable-tweak",
                "TWEAK2",
            ],
        ):
            main()

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args
        self.assertEqual(len(call_args[0][2]), 2)  # Two disabled files
        self.assertEqual(len(call_args[0][3]), 2)  # Two disabled tweaks


class TestJitTweaksConstant(unittest.TestCase):
    """Tests for JIT_TWEAKS constant."""

    def test_jit_tweaks_has_expected_files(self):
        """Test that JIT_TWEAKS contains expected file paths."""
        self.assertIn("Include/internal/pycore_backoff.h", JIT_TWEAKS)
        self.assertIn("Python/optimizer.c", JIT_TWEAKS)

    def test_jit_tweaks_has_valid_structure(self):
        """Test that JIT_TWEAKS has valid structure."""
        for file_path, tweaks in JIT_TWEAKS.items():
            self.assertIsInstance(file_path, str)
            self.assertIsInstance(tweaks, list)
            for tweak in tweaks:
                self.assertIsInstance(tweak, tuple)
                self.assertEqual(len(tweak), 2)
                param_name, value = tweak
                self.assertIsInstance(param_name, str)
                self.assertIsInstance(value, int)


if __name__ == "__main__":
    unittest.main()
