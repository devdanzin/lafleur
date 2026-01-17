"""
Tests for CLI entry points (main functions) of coverage, driver, and minimize modules.

This module tests the main() functions which are often undertested because they
involve argument parsing and subprocess orchestration.
"""

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from lafleur.coverage import (
    load_coverage_state,
    save_coverage_state,
    main as coverage_main,
)


class TestCoverageMain(unittest.TestCase):
    """Tests for lafleur.coverage.main() entry point."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_main_with_valid_log_file(self):
        """Test main() with a valid log file containing coverage data."""
        # Create a sample log file
        log_file = self.temp_path / "test.log"
        log_content = """
[f1] STRATEGY: Testing
ADD_TO_TRACE: _LOAD_FAST
ADD_TO_TRACE: _STORE_FAST
Optimized trace (length 50):
  OPTIMIZED: _LOAD_CONST
  OPTIMIZED: _BINARY_OP_ADD_INT
"""
        log_file.write_text(log_content)

        # Mock load_coverage_state to return the structure main() expects
        mock_state = {
            "uops": {},
            "edges": {},
            "rare_events": {},
            "uop_map": {},
            "edge_map": {},
            "rare_event_map": {},
            "next_id_map": {"uop": 0, "edge": 0, "rare_event": 0},
        }

        with patch("sys.argv", ["coverage.py", str(log_file)]):
            with patch("lafleur.coverage.load_coverage_state", return_value=mock_state):
                with patch("lafleur.coverage.save_coverage_state"):
                    with patch("lafleur.coverage.COVERAGE_DIR", self.temp_path):
                        captured_stderr = StringIO()
                        with patch("sys.stderr", captured_stderr):
                            coverage_main()

        # Check that coverage was processed
        output = captured_stderr.getvalue()
        self.assertIn("coverage state", output.lower())

    def test_main_with_empty_log_file(self):
        """Test main() with a log file that has no harness markers."""
        # Create an empty log file (no harness markers)
        log_file = self.temp_path / "empty.log"
        log_file.write_text("Some random log content without markers")

        with patch("sys.argv", ["coverage.py", str(log_file)]):
            with patch("lafleur.coverage.COVERAGE_STATE_FILE", self.temp_path / "state.pkl"):
                captured_stderr = StringIO()
                with patch("sys.stderr", captured_stderr):
                    coverage_main()

        # Should report no coverage found
        output = captured_stderr.getvalue()
        self.assertIn("No per-harness coverage", output)

    def test_main_with_nonexistent_log_file(self):
        """Test main() with a non-existent log file."""
        with patch("sys.argv", ["coverage.py", "/nonexistent/log.log"]):
            with patch("lafleur.coverage.COVERAGE_STATE_FILE", self.temp_path / "state.pkl"):
                captured_stderr = StringIO()
                with patch("sys.stderr", captured_stderr):
                    coverage_main()

        # Should report file not found error
        output = captured_stderr.getvalue()
        self.assertIn("not found", output.lower())

    def test_main_discovers_new_uops(self):
        """Test that main() reports newly discovered UOPs."""
        log_file = self.temp_path / "new_uops.log"
        log_content = """
[f1] STRATEGY: Testing
ADD_TO_TRACE: _LOAD_FAST
ADD_TO_TRACE: _STORE_FAST
"""
        log_file.write_text(log_content)

        # Mock load_coverage_state to return the structure main() expects
        mock_state = {
            "uops": {},
            "edges": {},
            "rare_events": {},
            "uop_map": {},
            "edge_map": {},
            "rare_event_map": {},
            "next_id_map": {"uop": 0, "edge": 0, "rare_event": 0},
        }

        with patch("sys.argv", ["coverage.py", str(log_file)]):
            with patch("lafleur.coverage.load_coverage_state", return_value=mock_state):
                with patch("lafleur.coverage.save_coverage_state"):
                    with patch("lafleur.coverage.COVERAGE_DIR", self.temp_path):
                        captured_stderr = StringIO()
                        with patch("sys.stderr", captured_stderr):
                            coverage_main()

        output = captured_stderr.getvalue()
        # New UOPs should be reported (state file doesn't exist yet)
        # The current implementation tracks new coverage
        self.assertIn("coverage state", output.lower())

    def test_main_discovers_rare_events(self):
        """Test that main() reports rare events."""
        log_file = self.temp_path / "rare.log"
        log_content = """
[f1] STRATEGY: Testing
ADD_TO_TRACE: _LOAD_FAST
_DEOPT instruction found
Bailing on recursive call
"""
        log_file.write_text(log_content)

        # Mock load_coverage_state to return the structure main() expects
        mock_state = {
            "uops": {},
            "edges": {},
            "rare_events": {},
            "uop_map": {},
            "edge_map": {},
            "rare_event_map": {},
            "next_id_map": {"uop": 0, "edge": 0, "rare_event": 0},
        }

        with patch("sys.argv", ["coverage.py", str(log_file)]):
            with patch("lafleur.coverage.load_coverage_state", return_value=mock_state):
                with patch("lafleur.coverage.save_coverage_state"):
                    with patch("lafleur.coverage.COVERAGE_DIR", self.temp_path):
                        captured_stderr = StringIO()
                        with patch("sys.stderr", captured_stderr):
                            coverage_main()

        output = captured_stderr.getvalue()
        self.assertIn("coverage state", output.lower())


class TestCoverageSaveLoad(unittest.TestCase):
    """Tests for coverage state persistence functions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_coverage_state_returns_default_when_file_missing(self):
        """Test that loading from non-existent file returns defaults."""
        with patch("lafleur.coverage.COVERAGE_STATE_FILE", self.temp_path / "nonexistent.pkl"):
            state = load_coverage_state()

        self.assertIn("global_coverage", state)
        self.assertIn("per_file_coverage", state)

    def test_save_and_load_coverage_state(self):
        """Test roundtrip save and load of coverage state."""
        state_file = self.temp_path / "coverage_state.pkl"

        # Create state with data
        original_state = {
            "global_coverage": {"uops": {1: 10}, "edges": {2: 5}, "rare_events": {}},
            "per_file_coverage": {"file1.py": {"content_hash": "abc123"}},
            "uop_map": {"_LOAD_FAST": 0},
            "edge_map": {},
            "rare_event_map": {},
            "next_id_map": {"uop": 1, "edge": 0, "rare_event": 0},
        }

        with patch("lafleur.coverage.COVERAGE_STATE_FILE", state_file):
            with patch("lafleur.coverage.COVERAGE_DIR", self.temp_path):
                save_coverage_state(original_state)
                loaded_state = load_coverage_state()

        self.assertEqual(loaded_state["global_coverage"]["uops"], {1: 10})
        self.assertEqual(loaded_state["uop_map"]["_LOAD_FAST"], 0)

    def test_save_coverage_state_creates_directory(self):
        """Test that save creates the coverage directory if missing."""
        coverage_dir = self.temp_path / "coverage"
        state_file = coverage_dir / "coverage_state.pkl"

        self.assertFalse(coverage_dir.exists())

        with patch("lafleur.coverage.COVERAGE_STATE_FILE", state_file):
            with patch("lafleur.coverage.COVERAGE_DIR", coverage_dir):
                save_coverage_state({"global_coverage": {}, "per_file_coverage": {}})

        self.assertTrue(coverage_dir.exists())

    def test_load_coverage_state_handles_corrupted_file(self):
        """Test that loading a corrupted pickle returns defaults."""
        state_file = self.temp_path / "corrupted.pkl"
        state_file.write_bytes(b"not a valid pickle file !!!")

        with patch("lafleur.coverage.COVERAGE_STATE_FILE", state_file):
            captured_stderr = StringIO()
            with patch("sys.stderr", captured_stderr):
                state = load_coverage_state()

        self.assertIn("global_coverage", state)
        self.assertIn("per_file_coverage", state)
        self.assertIn("Warning", captured_stderr.getvalue())


class TestDriverMain(unittest.TestCase):
    """Tests for lafleur.driver.main() entry point."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_main_parses_arguments(self):
        """Test that main() correctly parses arguments."""
        script = self.temp_path / "test.py"
        script.write_text("x = 1")

        with patch("sys.argv", ["driver.py", str(script)]):
            from lafleur.driver import main as driver_main

            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                result = driver_main()

        self.assertEqual(result, 0)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:START]", output)
        self.assertIn("[DRIVER:STATS]", output)

    def test_main_with_verbose_flag(self):
        """Test that main() handles --verbose flag."""
        script = self.temp_path / "test.py"
        script.write_text("x = 1")

        with patch("sys.argv", ["driver.py", "--verbose", str(script)]):
            from lafleur.driver import main as driver_main

            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                result = driver_main()

        self.assertEqual(result, 0)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:INFO]", output)

    def test_main_with_multiple_scripts(self):
        """Test that main() handles multiple script arguments."""
        script1 = self.temp_path / "a.py"
        script1.write_text("x = 1")
        script2 = self.temp_path / "b.py"
        script2.write_text("y = x + 1")

        with patch("sys.argv", ["driver.py", str(script1), str(script2)]):
            from lafleur.driver import main as driver_main

            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                result = driver_main()

        self.assertEqual(result, 0)
        output = captured_stdout.getvalue()
        self.assertIn("a.py", output)
        self.assertIn("b.py", output)


class TestMinimizeMain(unittest.TestCase):
    """Tests for lafleur.minimize.main() entry point."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_main_with_nonexistent_directory(self):
        """Test main() exits with error for non-existent directory."""
        with patch("sys.argv", ["minimize.py", "/nonexistent/crash_dir"]):
            from lafleur.minimize import main as minimize_main

            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                with self.assertRaises(SystemExit) as ctx:
                    minimize_main()

            self.assertEqual(ctx.exception.code, 1)

    def test_main_with_missing_metadata(self):
        """Test main() exits with error when metadata.json is missing."""
        crash_dir = self.temp_path / "crash"
        crash_dir.mkdir()
        # No metadata.json created

        with patch("sys.argv", ["minimize.py", str(crash_dir)]):
            from lafleur.minimize import main as minimize_main

            with self.assertRaises(SystemExit) as ctx:
                minimize_main()

            self.assertEqual(ctx.exception.code, 1)

    def test_main_with_invalid_metadata(self):
        """Test main() exits with error when metadata.json is invalid."""
        crash_dir = self.temp_path / "crash"
        crash_dir.mkdir()
        (crash_dir / "metadata.json").write_text("not valid json {{{")

        with patch("sys.argv", ["minimize.py", str(crash_dir)]):
            from lafleur.minimize import main as minimize_main

            with self.assertRaises(SystemExit) as ctx:
                minimize_main()

            self.assertEqual(ctx.exception.code, 1)

    def test_main_with_no_scripts(self):
        """Test main() exits with error when no Python scripts found."""
        crash_dir = self.temp_path / "crash"
        crash_dir.mkdir()
        (crash_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "ASSERT:test", "returncode": -11})
        )
        # No .py files created

        with patch("sys.argv", ["minimize.py", str(crash_dir)]):
            from lafleur.minimize import main as minimize_main

            with self.assertRaises(SystemExit) as ctx:
                minimize_main()

            self.assertEqual(ctx.exception.code, 1)

    def test_main_with_target_python_arg(self):
        """Test main() handles --target-python argument."""
        crash_dir = self.temp_path / "crash"
        crash_dir.mkdir()
        (crash_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "ASSERT:test", "returncode": -11})
        )
        (crash_dir / "script.py").write_text("x = 1")

        with patch(
            "sys.argv", ["minimize.py", str(crash_dir), "--target-python", "/usr/bin/python3"]
        ):
            with patch("lafleur.minimize.minimize_session") as mock_minimize:
                from lafleur.minimize import main as minimize_main

                # Mock to prevent actual execution
                mock_minimize.side_effect = SystemExit(0)

                try:
                    minimize_main()
                except SystemExit:
                    pass

                # Verify target-python was passed
                mock_minimize.assert_called_once()
                args = mock_minimize.call_args
                self.assertEqual(args[0][1], "/usr/bin/python3")

    def test_main_with_force_overwrite_arg(self):
        """Test main() handles --force-overwrite argument."""
        crash_dir = self.temp_path / "crash"
        crash_dir.mkdir()
        (crash_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "ASSERT:test", "returncode": -11})
        )
        (crash_dir / "script.py").write_text("x = 1")

        with patch("sys.argv", ["minimize.py", str(crash_dir), "--force-overwrite"]):
            with patch("lafleur.minimize.minimize_session") as mock_minimize:
                from lafleur.minimize import main as minimize_main

                mock_minimize.side_effect = SystemExit(0)

                try:
                    minimize_main()
                except SystemExit:
                    pass

                # Verify force_overwrite was passed as True
                args = mock_minimize.call_args
                self.assertTrue(args[0][2])  # force_overwrite is third arg


if __name__ == "__main__":
    unittest.main()
