"""
Tests for internal driver functions and error handling paths.

This module tests run_session error handling, JIT stats collection with
degraded mode, and other edge cases that are hard to hit via subprocess.
"""

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from lafleur.driver import run_session, get_jit_stats


class TestRunSessionErrorHandling(unittest.TestCase):
    """Tests for run_session error handling paths."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_run_session_syntax_error(self):
        """Test run_session handles SyntaxError gracefully."""
        # Create a script with invalid syntax
        bad_script = self.temp_path / "bad_syntax.py"
        bad_script.write_text("def foo(:\n    pass")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(bad_script)])

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("SyntaxError", output)
        self.assertIn("[DRIVER:STATS]", output)

        # Parse stats JSON to verify structure
        for line in output.splitlines():
            if line.startswith("[DRIVER:STATS]"):
                json_str = line.replace("[DRIVER:STATS] ", "")
                stats = json.loads(json_str)
                self.assertEqual(stats["status"], "syntax_error")

    def test_run_session_runtime_error(self):
        """Test run_session handles RuntimeError gracefully."""
        # Create a script that raises RuntimeError
        error_script = self.temp_path / "runtime_error.py"
        error_script.write_text("raise RuntimeError('Test runtime error')")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(error_script)])

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("RuntimeError", output)
        self.assertIn("Test runtime error", output)
        self.assertIn("[DRIVER:STATS]", output)

        # Parse stats JSON to verify structure
        for line in output.splitlines():
            if line.startswith("[DRIVER:STATS]"):
                json_str = line.replace("[DRIVER:STATS] ", "")
                stats = json.loads(json_str)
                self.assertEqual(stats["status"], "error")
                self.assertEqual(stats["type"], "RuntimeError")

    def test_run_session_file_not_found(self):
        """Test run_session handles non-existent files."""
        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session(["/nonexistent/script.py"])

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("File not found", output)

    def test_run_session_continues_after_error(self):
        """Test run_session continues executing remaining scripts after an error."""
        # First script raises error
        error_script = self.temp_path / "error.py"
        error_script.write_text("raise ValueError('First script error')")

        # Second script succeeds
        success_script = self.temp_path / "success.py"
        success_script.write_text("x = 42")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(error_script), str(success_script)])

        self.assertEqual(result, 1)  # Errors occurred
        output = captured_stdout.getvalue()

        # Both scripts should have been started
        self.assertIn("error.py", output)
        self.assertIn("success.py", output)

        # Count DRIVER:START occurrences
        start_count = output.count("[DRIVER:START]")
        self.assertEqual(start_count, 2)

    def test_run_session_attribute_error(self):
        """Test run_session handles AttributeError gracefully."""
        error_script = self.temp_path / "attr_error.py"
        error_script.write_text("None.nonexistent_method()")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(error_script)])

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("AttributeError", output)

    def test_run_session_import_error(self):
        """Test run_session handles ImportError gracefully."""
        error_script = self.temp_path / "import_error.py"
        error_script.write_text("import nonexistent_module_xyz123")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(error_script)])

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        # Could be ImportError or ModuleNotFoundError
        self.assertTrue("ImportError" in output or "ModuleNotFoundError" in output)

    def test_run_session_type_error(self):
        """Test run_session handles TypeError gracefully."""
        error_script = self.temp_path / "type_error.py"
        error_script.write_text("'string' + 42")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(error_script)])

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("TypeError", output)

    def test_run_session_zero_division_error(self):
        """Test run_session handles ZeroDivisionError gracefully."""
        error_script = self.temp_path / "zero_div.py"
        error_script.write_text("x = 1 / 0")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(error_script)])

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("ZeroDivisionError", output)

    def test_run_session_success_returns_zero(self):
        """Test run_session returns 0 for successful execution."""
        good_script = self.temp_path / "good.py"
        good_script.write_text("x = 1\ny = 2\nz = x + y")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(good_script)])

        self.assertEqual(result, 0)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:STATS]", output)

        # Parse stats JSON to verify success
        for line in output.splitlines():
            if line.startswith("[DRIVER:STATS]"):
                json_str = line.replace("[DRIVER:STATS] ", "")
                stats = json.loads(json_str)
                self.assertEqual(stats["status"], "success")

    def test_run_session_shared_globals(self):
        """Test that scripts share globals as expected."""
        script1 = self.temp_path / "a.py"
        script1.write_text("shared_var = 100")

        script2 = self.temp_path / "b.py"
        script2.write_text("assert shared_var == 100")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(script1), str(script2)])

        self.assertEqual(result, 0)


class TestGetJitStats(unittest.TestCase):
    """Tests for get_jit_stats function."""

    def test_get_jit_stats_without_opcode(self):
        """Test get_jit_stats when _opcode is not available."""
        with patch("lafleur.driver.HAS_OPCODE", False):
            stats = get_jit_stats({})

        self.assertEqual(stats["executors"], 0)
        self.assertEqual(stats["functions_scanned"], 0)
        self.assertFalse(stats["jit_available"])

    def test_get_jit_stats_with_empty_namespace(self):
        """Test get_jit_stats with empty namespace."""
        with patch("lafleur.driver.HAS_OPCODE", True):
            # Mock _opcode to avoid actual JIT introspection
            with patch("lafleur.driver._opcode.get_executor", side_effect=ValueError):
                stats = get_jit_stats({})

        self.assertEqual(stats["executors"], 0)
        self.assertEqual(stats["functions_scanned"], 0)
        self.assertTrue(stats["jit_available"])

    def test_get_jit_stats_with_function(self):
        """Test get_jit_stats with a function in namespace."""

        def sample_function():
            total = 0
            for i in range(10):
                total += i
            return total

        namespace = {"sample_function": sample_function}

        with patch("lafleur.driver.HAS_OPCODE", True):
            with patch("lafleur.driver._opcode.get_executor", return_value=None):
                stats = get_jit_stats(namespace)

        self.assertGreaterEqual(stats["functions_scanned"], 1)
        self.assertTrue(stats["jit_available"])

    def test_get_jit_stats_skips_private_names(self):
        """Test that get_jit_stats skips names starting with underscore."""

        def _private_function():
            pass

        namespace = {"_private_function": _private_function}

        with patch("lafleur.driver.HAS_OPCODE", True):
            with patch("lafleur.driver._opcode.get_executor", return_value=None):
                stats = get_jit_stats(namespace)

        # Private function should be skipped
        self.assertEqual(stats["functions_scanned"], 0)

    def test_get_jit_stats_handles_class_methods(self):
        """Test that get_jit_stats inspects class methods."""

        class SampleClass:
            def method(self):
                pass

        namespace = {"SampleClass": SampleClass}

        with patch("lafleur.driver.HAS_OPCODE", True):
            with patch("lafleur.driver._opcode.get_executor", return_value=None):
                stats = get_jit_stats(namespace)

        self.assertGreaterEqual(stats["functions_scanned"], 1)


class TestRunSessionSystemExit(unittest.TestCase):
    """Tests for run_session handling of SystemExit."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_run_session_propagates_system_exit(self):
        """Test that SystemExit is propagated, not caught."""
        exit_script = self.temp_path / "exit.py"
        exit_script.write_text("import sys; sys.exit(42)")

        with self.assertRaises(SystemExit) as ctx:
            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                run_session([str(exit_script)])

        self.assertEqual(ctx.exception.code, 42)


class TestRunSessionKeyboardInterrupt(unittest.TestCase):
    """Tests for run_session handling of KeyboardInterrupt."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_run_session_propagates_keyboard_interrupt(self):
        """Test that KeyboardInterrupt is propagated, not caught."""
        interrupt_script = self.temp_path / "interrupt.py"
        interrupt_script.write_text("raise KeyboardInterrupt()")

        with self.assertRaises(KeyboardInterrupt):
            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                run_session([str(interrupt_script)])


class TestDriverVerboseMode(unittest.TestCase):
    """Tests for driver verbose mode."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verbose_prints_jit_status(self):
        """Test that verbose mode prints JIT introspection availability."""
        script = self.temp_path / "test.py"
        script.write_text("x = 1")

        with patch("sys.argv", ["driver.py", "--verbose", str(script)]):
            from lafleur.driver import main as driver_main

            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                driver_main()

        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:INFO]", output)
        self.assertIn("JIT introspection available", output)

    def test_verbose_prints_scripts_list(self):
        """Test that verbose mode prints the scripts list."""
        script1 = self.temp_path / "a.py"
        script1.write_text("x = 1")
        script2 = self.temp_path / "b.py"
        script2.write_text("y = 2")

        with patch("sys.argv", ["driver.py", "-v", str(script1), str(script2)]):
            from lafleur.driver import main as driver_main

            captured_stdout = StringIO()
            with patch("sys.stdout", captured_stdout):
                driver_main()

        output = captured_stdout.getvalue()
        self.assertIn("Scripts to execute", output)


if __name__ == "__main__":
    unittest.main()
