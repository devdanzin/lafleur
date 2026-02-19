"""
Tests for internal driver functions and error handling paths.

This module tests run_session error handling, JIT stats collection with
degraded mode, and other edge cases that are hard to hit via subprocess.
"""

import ctypes
import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.driver import (
    get_jit_stats,
    run_session,
    snapshot_executor_state,
    walk_code_objects,
)


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
        self.assertEqual(stats["valid_traces"], 0)
        self.assertEqual(stats["warm_traces"], 0)

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

    def test_run_session_catches_system_exit_and_continues(self):
        """Test that SystemExit is caught and subsequent scripts still run."""
        exit_script = self.temp_path / "exit.py"
        exit_script.write_text("import sys; sys.exit(42)")

        success_script = self.temp_path / "success.py"
        success_script.write_text("x = 1")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(exit_script), str(success_script)])

        # Should return 1 (errors occurred) but NOT raise SystemExit
        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()

        # Both scripts should have been started
        start_count = output.count("[DRIVER:START]")
        self.assertEqual(start_count, 2)

        # SystemExit should be logged as an error
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("SystemExit", output)

        # The exit stats should include the exit code
        self.assertIn('"status": "exit"', output)
        self.assertIn('"code": 42', output)

        # Second script should succeed
        self.assertIn("success.py", output)

    def test_run_session_system_exit_zero(self):
        """Test that sys.exit(0) is also caught, not propagated."""
        exit_script = self.temp_path / "exit_zero.py"
        exit_script.write_text("import sys; sys.exit(0)")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(exit_script)])

        # Even exit(0) should be caught — the driver manages its own exit code
        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn('"status": "exit"', output)


class TestRunSessionStateIsolation(unittest.TestCase):
    """Tests for run_session state isolation between scripts."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sys_path_restored_between_scripts(self):
        """Test that sys.path modifications don't leak between scripts."""
        polluter = self.temp_path / "polluter.py"
        polluter.write_text("import sys; sys.path.append('/fake/path/12345')")

        checker = self.temp_path / "checker.py"
        checker.write_text(
            "import sys\n"
            "assert '/fake/path/12345' not in sys.path, "
            "'sys.path pollution leaked from previous script'"
        )

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(polluter), str(checker)])

        # Both should succeed — sys.path should be restored between scripts
        self.assertEqual(result, 0)

    def test_sys_modules_cleaned_between_scripts(self):
        """Test that new sys.modules entries don't leak between scripts."""
        # First script adds a fake module to sys.modules
        polluter = self.temp_path / "polluter.py"
        polluter.write_text("import sys; sys.modules['_fake_test_module_xyz'] = None")

        checker = self.temp_path / "checker.py"
        checker.write_text(
            "import sys\n"
            "assert '_fake_test_module_xyz' not in sys.modules, "
            "'sys.modules pollution leaked from previous script'"
        )

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(polluter), str(checker)])

        # Both should succeed — new module entries should be cleaned
        self.assertEqual(result, 0)

    def test_sys_argv_restored_between_scripts(self):
        """Test that sys.argv is restored between scripts (existing behavior)."""
        script1 = self.temp_path / "script1.py"
        script1.write_text("import sys; sys.argv.append('POLLUTED')")

        script2 = self.temp_path / "script2.py"
        script2.write_text(
            "import sys\n"
            "assert 'POLLUTED' not in sys.argv, "
            "'sys.argv pollution leaked from previous script'"
        )

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(script1), str(script2)])

        self.assertEqual(result, 0)


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


def _make_mock_executor_ptr(
    exit_count=0, code_size=10, pending_deletion=0, valid=1, warm=1, chain_depth=0
):
    """Create a mock executor pointer with configurable fields."""
    mock_ptr = MagicMock()
    mock_vm_data = MagicMock()
    type(mock_vm_data).pending_deletion = unittest.mock.PropertyMock(return_value=pending_deletion)
    type(mock_vm_data).valid = unittest.mock.PropertyMock(return_value=valid)
    type(mock_vm_data).warm = unittest.mock.PropertyMock(return_value=warm)
    type(mock_vm_data).chain_depth = unittest.mock.PropertyMock(return_value=chain_depth)
    mock_ptr.contents.vm_data = mock_vm_data
    type(mock_ptr.contents).exit_count = unittest.mock.PropertyMock(return_value=exit_count)
    type(mock_ptr.contents).code_size = unittest.mock.PropertyMock(return_value=code_size)
    # Provide a minimal bloom filter so scan_watched_variables doesn't crash
    mock_bloom = MagicMock()
    mock_bloom.bits = (ctypes.c_uint32 * 8)(*[0] * 8)
    mock_vm_data.bloom = mock_bloom
    return mock_ptr


class TestWalkCodeObjects(unittest.TestCase):
    """Tests for the module-level walk_code_objects function."""

    def test_walk_yields_nested(self):
        """Verify both outer and inner code objects are yielded."""

        def outer():
            def inner():
                pass

        code_objs = list(walk_code_objects(outer.__code__))
        # Should yield at least 2: outer and inner
        self.assertGreaterEqual(len(code_objs), 2)
        self.assertIn(outer.__code__, code_objs)

    def test_walk_no_infinite_recursion(self):
        """Verify the visited set prevents infinite loops."""

        def simple():
            pass

        # Call twice — should complete both times
        list(walk_code_objects(simple.__code__))
        result = list(walk_code_objects(simple.__code__))
        self.assertGreaterEqual(len(result), 1)

    def test_walk_shared_visited_prevents_duplicates(self):
        """Passing the same code object with a shared visited set yields no duplicates."""

        def func():
            pass

        visited: set = set()
        first = list(walk_code_objects(func.__code__, visited))
        second = list(walk_code_objects(func.__code__, visited))
        self.assertGreaterEqual(len(first), 1)
        self.assertEqual(len(second), 0)


class TestSnapshotExecutorState(unittest.TestCase):
    """Tests for snapshot_executor_state function."""

    def test_snapshot_empty_namespace(self):
        """Empty namespace returns empty snapshot."""
        result = snapshot_executor_state({})
        self.assertEqual(result, {})

    def test_snapshot_without_opcode(self):
        """Returns empty dict when _opcode is unavailable."""
        with patch("lafleur.driver.HAS_OPCODE", False):
            result = snapshot_executor_state({"func": lambda: None})
        self.assertEqual(result, {})

    def test_snapshot_skips_private_names(self):
        """Private names (starting with _) should be skipped."""

        def _private_func():
            pass

        mock_ptr = _make_mock_executor_ptr(exit_count=42)
        mock_executor = MagicMock()

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast", return_value=mock_ptr),
        ):
            mock_opcode.get_executor.return_value = mock_executor
            result = snapshot_executor_state({"_private_func": _private_func})

        self.assertEqual(result, {})

    def test_snapshot_returns_dict_of_tuples(self):
        """Verify snapshot captures (code_id, offset) -> exit_count."""

        def dummy_func():
            pass

        mock_ptr = _make_mock_executor_ptr(exit_count=42)
        mock_executor = MagicMock()

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast", return_value=mock_ptr),
        ):
            # Return executor only for the first offset, None for the rest
            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 5000
            result = snapshot_executor_state({"func": dummy_func})

        self.assertGreater(len(result), 0)
        # All keys should be (int, int) tuples, all values should be 42
        for key, value in result.items():
            self.assertIsInstance(key, tuple)
            self.assertEqual(len(key), 2)
            self.assertEqual(value, 42)

    def test_snapshot_handles_classes(self):
        """Verify class methods are scanned."""

        class MyClass:
            def method(self):
                pass

        mock_ptr = _make_mock_executor_ptr(exit_count=10)
        mock_executor = MagicMock()

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast", return_value=mock_ptr),
        ):
            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 5000
            result = snapshot_executor_state({"MyClass": MyClass})

        self.assertGreater(len(result), 0)


class TestGetJitStatsDelta(unittest.TestCase):
    """Tests for get_jit_stats delta metrics with baseline."""

    def test_without_baseline_no_delta_fields(self):
        """Calling without baseline should NOT include delta fields."""

        def dummy():
            pass

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
        ):
            mock_opcode.get_executor.return_value = None
            stats = get_jit_stats({"func": dummy})

        self.assertNotIn("delta_max_exit_density", stats)
        self.assertNotIn("delta_total_exits", stats)
        self.assertNotIn("delta_new_executors", stats)
        self.assertNotIn("delta_new_zombies", stats)

    def test_with_empty_baseline_all_executors_are_new(self):
        """Empty baseline means all found executors are new."""

        def dummy():
            pass

        mock_ptr = _make_mock_executor_ptr(exit_count=10, code_size=5)
        mock_executor = MagicMock()

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast", return_value=mock_ptr),
            patch("sys.stdout", new_callable=StringIO),
        ):
            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 5000
            stats = get_jit_stats({"func": dummy}, baseline={})

        self.assertEqual(stats["delta_new_executors"], 1)
        self.assertEqual(stats["delta_total_exits"], 10)
        self.assertAlmostEqual(stats["delta_max_exit_density"], 2.0)
        self.assertEqual(stats["delta_max_exit_count"], 10)

    def test_with_matching_baseline_computes_delta(self):
        """Pre-existing executor: delta = current - baseline."""

        def dummy():
            pass

        mock_ptr = _make_mock_executor_ptr(exit_count=15, code_size=5)
        mock_executor = MagicMock()

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast", return_value=mock_ptr),
            patch("sys.stdout", new_callable=StringIO),
        ):
            # We need to figure out which (code_id, offset) will be used
            # The code_id is id(code) for the code object from walk_code_objects
            # and offset is the first bytecode offset where get_executor returns non-None
            code_obj = dummy.__code__
            # The first code object yielded by walk_code_objects will be dummy.__code__
            # The first offset is 0
            baseline = {(id(code_obj), 0): 5}

            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 5000
            stats = get_jit_stats({"func": dummy}, baseline=baseline)

        # delta = 15 - 5 = 10
        self.assertEqual(stats["delta_total_exits"], 10)
        self.assertAlmostEqual(stats["delta_max_exit_density"], 2.0)  # 10/5
        self.assertEqual(stats["delta_new_executors"], 0)

    def test_baseline_no_increase_no_delta(self):
        """When exit count hasn't increased, delta should be zero."""

        def dummy():
            pass

        mock_ptr = _make_mock_executor_ptr(exit_count=15, code_size=5)
        mock_executor = MagicMock()

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast", return_value=mock_ptr),
            patch("sys.stdout", new_callable=StringIO),
        ):
            code_obj = dummy.__code__
            baseline = {(id(code_obj), 0): 15}  # Same as current

            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 5000
            stats = get_jit_stats({"func": dummy}, baseline=baseline)

        self.assertEqual(stats["delta_total_exits"], 0)
        self.assertAlmostEqual(stats["delta_max_exit_density"], 0.0)

    def test_delta_new_zombies(self):
        """New executor with pending_deletion should count as delta_new_zombies."""

        def dummy():
            pass

        mock_ptr = _make_mock_executor_ptr(exit_count=5, code_size=10, pending_deletion=1)
        mock_executor = MagicMock()

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast", return_value=mock_ptr),
            patch("sys.stdout", new_callable=StringIO),
        ):
            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 5000
            stats = get_jit_stats({"func": dummy}, baseline={})

        self.assertEqual(stats["delta_new_zombies"], 1)
        self.assertEqual(stats["delta_new_executors"], 1)


class TestRunSessionDeltaStats(unittest.TestCase):
    """Integration test for run_session emitting delta stats."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_run_session_emits_delta_stats(self):
        """Verify run_session passes baseline to get_jit_stats for each script."""
        script_a = self.temp_path / "a.py"
        script_a.write_text(
            "def hot():\n"
            "    total = 0\n"
            "    for i in range(100):\n"
            "        total += i\n"
            "    return total\n"
            "hot()\n"
        )

        script_b = self.temp_path / "b.py"
        script_b.write_text("hot()\n")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            run_session([str(script_a), str(script_b)])

        output = captured_stdout.getvalue()
        stats_lines = [line for line in output.splitlines() if line.startswith("[DRIVER:STATS]")]
        self.assertEqual(len(stats_lines), 2)

        stats_a = json.loads(stats_lines[0].split("[DRIVER:STATS] ", 1)[1])
        stats_b = json.loads(stats_lines[1].split("[DRIVER:STATS] ", 1)[1])

        # Both should have success status
        self.assertEqual(stats_a["status"], "success")
        self.assertEqual(stats_b["status"], "success")

        # If JIT is available, delta fields should be present
        if "delta_max_exit_density" in stats_a:
            self.assertIsInstance(stats_a["delta_max_exit_density"], (int, float))
            self.assertIsInstance(stats_a["delta_total_exits"], int)
        if "delta_max_exit_density" in stats_b:
            self.assertIsInstance(stats_b["delta_max_exit_density"], (int, float))
            self.assertIsInstance(stats_b["delta_total_exits"], int)


class TestRunSessionNoEkg(unittest.TestCase):
    """Tests for run_session with no_ekg=True."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_run_session_no_ekg_skips_introspection(self):
        """Test that no_ekg=True skips introspection and emits ekg_disabled stats."""
        script = self.temp_path / "simple.py"
        script.write_text("x = 42")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(script)], no_ekg=True)

        self.assertEqual(result, 0)
        output = captured_stdout.getvalue()

        # Parse stats and verify ekg_disabled flag
        for line in output.splitlines():
            if line.startswith("[DRIVER:STATS]"):
                json_str = line.replace("[DRIVER:STATS] ", "")
                stats = json.loads(json_str)
                self.assertEqual(stats["status"], "success")
                self.assertTrue(stats["ekg_disabled"])
                # Should NOT have JIT introspection fields
                self.assertNotIn("executors", stats)
                self.assertNotIn("zombie_traces", stats)

    def test_run_session_no_ekg_error_handling(self):
        """Test that no_ekg=True still handles errors gracefully."""
        error_script = self.temp_path / "error.py"
        error_script.write_text("raise ValueError('test error')")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(error_script)], no_ekg=True)

        self.assertEqual(result, 1)
        output = captured_stdout.getvalue()
        self.assertIn("[DRIVER:ERROR]", output)
        self.assertIn("ValueError", output)

    def test_run_session_no_ekg_shared_globals_still_work(self):
        """Test that shared globals work correctly with no_ekg=True."""
        script1 = self.temp_path / "a.py"
        script1.write_text("shared_var = 999")

        script2 = self.temp_path / "b.py"
        script2.write_text("assert shared_var == 999")

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            result = run_session([str(script1), str(script2)], no_ekg=True)

        self.assertEqual(result, 0)

        output = captured_stdout.getvalue()
        stats_lines = [line for line in output.splitlines() if line.startswith("[DRIVER:STATS]")]
        self.assertEqual(len(stats_lines), 2)

        for line in stats_lines:
            stats = json.loads(line.split("[DRIVER:STATS] ", 1)[1])
            self.assertTrue(stats["ekg_disabled"])


if __name__ == "__main__":
    unittest.main()
