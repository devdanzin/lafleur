#!/usr/bin/env python3
"""
Tests for the session fuzzing driver.

This module contains unit tests for the session fuzzing driver defined in
lafleur/driver.py
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent


class TestSessionFuzzingDriver(unittest.TestCase):
    """Test the session fuzzing driver."""

    def setUp(self):
        """Create a temporary directory for test scripts."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_script(self, name: str, content: str) -> Path:
        """Create a test script in the temp directory."""
        path = Path(self.temp_dir) / name
        path.write_text(dedent(content))
        return path

    def _run_driver(self, *script_paths: Path, expect_success: bool = True) -> tuple[str, str, int]:
        """Run the driver on the given scripts."""
        cmd = [sys.executable, "-m", "lafleur.driver"] + [str(p) for p in script_paths]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if expect_success and result.returncode != 0:
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
        return result.stdout, result.stderr, result.returncode

    def test_shared_state_between_scripts(self):
        """Test that scripts share state - b.py should see x from a.py."""
        a_script = self._create_script("a.py", "x = 1")
        b_script = self._create_script("b.py", "assert x == 1, 'x should be 1 from a.py'")

        stdout, stderr, returncode = self._run_driver(a_script, b_script)

        # Both scripts should succeed
        self.assertEqual(returncode, 0)
        # Verify both scripts were started
        self.assertIn("[DRIVER:START]", stdout)
        self.assertIn("a.py", stdout)
        self.assertIn("b.py", stdout)

    def test_driver_start_tag(self):
        """Test that [DRIVER:START] tag is emitted before each script."""
        a_script = self._create_script("a.py", "x = 1")

        stdout, stderr, returncode = self._run_driver(a_script)

        self.assertEqual(returncode, 0)
        self.assertIn(f"[DRIVER:START] {a_script}", stdout)

    def test_driver_stats_tag(self):
        """Test that [DRIVER:STATS] tag is emitted after each script."""
        a_script = self._create_script("a.py", "x = 1")

        stdout, stderr, returncode = self._run_driver(a_script)

        self.assertEqual(returncode, 0)
        self.assertIn("[DRIVER:STATS]", stdout)

        # Parse the stats JSON
        for line in stdout.splitlines():
            if line.startswith("[DRIVER:STATS]"):
                json_str = line.replace("[DRIVER:STATS] ", "")
                stats = json.loads(json_str)
                self.assertIn("file", stats)
                self.assertIn("status", stats)
                self.assertEqual(stats["file"], "a.py")
                self.assertEqual(stats["status"], "success")

    def test_error_handling_continues_session(self):
        """Test that errors in one script don't stop subsequent scripts."""
        a_script = self._create_script("a.py", "raise ValueError('test error')")
        b_script = self._create_script("b.py", "y = 2")

        stdout, stderr, returncode = self._run_driver(a_script, b_script, expect_success=False)

        # Should return non-zero due to error
        self.assertEqual(returncode, 1)
        # But both scripts should have been started
        self.assertIn(f"[DRIVER:START] {a_script}", stdout)
        self.assertIn(f"[DRIVER:START] {b_script}", stdout)
        # Error should be reported
        self.assertIn("[DRIVER:ERROR]", stdout)
        self.assertIn("ValueError", stdout)

    def test_syntax_error_handling(self):
        """Test that syntax errors are handled gracefully."""
        a_script = self._create_script("a.py", "this is not valid python syntax +++")

        stdout, stderr, returncode = self._run_driver(a_script, expect_success=False)

        self.assertEqual(returncode, 1)
        self.assertIn("[DRIVER:ERROR]", stdout)
        self.assertIn("SyntaxError", stdout)

    def test_file_not_found(self):
        """Test handling of non-existent files."""
        fake_path = Path(self.temp_dir) / "nonexistent.py"

        stdout, stderr, returncode = self._run_driver(fake_path, expect_success=False)

        self.assertEqual(returncode, 1)
        self.assertIn("[DRIVER:ERROR]", stdout)
        self.assertIn("File not found", stdout)

    def test_function_definition_shared(self):
        """Test that function definitions are shared between scripts."""
        a_script = self._create_script(
            "a.py",
            """
            def greet(name):
                return f"Hello, {name}!"
            """,
        )
        b_script = self._create_script(
            "b.py",
            """
            result = greet("World")
            assert result == "Hello, World!", f"Got {result}"
            """,
        )

        stdout, stderr, returncode = self._run_driver(a_script, b_script)

        self.assertEqual(returncode, 0)

    def test_class_definition_shared(self):
        """Test that class definitions are shared between scripts."""
        a_script = self._create_script(
            "a.py",
            """
            class Counter:
                def __init__(self):
                    self.count = 0
                def increment(self):
                    self.count += 1
            """,
        )
        b_script = self._create_script(
            "b.py",
            """
            c = Counter()
            c.increment()
            c.increment()
            assert c.count == 2
            """,
        )

        stdout, stderr, returncode = self._run_driver(a_script, b_script)

        self.assertEqual(returncode, 0)

    def test_multiple_scripts_accumulate_state(self):
        """Test that state accumulates across multiple scripts."""
        a_script = self._create_script("a.py", "total = 10")
        b_script = self._create_script("b.py", "total += 5")
        c_script = self._create_script("c.py", "assert total == 15")

        stdout, stderr, returncode = self._run_driver(a_script, b_script, c_script)

        self.assertEqual(returncode, 0)

    def test_jit_stats_structure(self):
        """Test that JIT stats have the expected structure."""
        a_script = self._create_script(
            "a.py",
            """
            def hot_function():
                total = 0
                for i in range(1000):
                    total += i
                return total

            hot_function()
            """,
        )

        stdout, stderr, returncode = self._run_driver(a_script)

        self.assertEqual(returncode, 0)

        # Find and parse stats
        for line in stdout.splitlines():
            if line.startswith("[DRIVER:STATS]"):
                json_str = line.replace("[DRIVER:STATS] ", "")
                stats = json.loads(json_str)
                # Check required fields
                self.assertIn("file", stats)
                self.assertIn("status", stats)
                # May or may not have JIT fields depending on Python build
                if "jit_available" in stats:
                    self.assertIn("executors", stats)
                    self.assertIn("functions_scanned", stats)


if __name__ == "__main__":
    unittest.main(verbosity=2)
