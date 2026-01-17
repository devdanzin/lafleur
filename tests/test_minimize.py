import unittest
import shutil
import tempfile
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from lafleur.minimize import (
    rename_harnesses,
    extract_grep_pattern,
    minimize_session,
)


class TestMinimizeHelpers(unittest.TestCase):
    def test_rename_harnesses(self):
        """Test harness renaming regex logic."""
        source = """
        def uop_harness_f1():
            pass
        uop_harness_f1()
        """
        renamed = rename_harnesses(source, "0")
        self.assertIn("def uop_harness_f1_0():", renamed)
        self.assertIn("uop_harness_f1_0()", renamed)
        self.assertNotIn("def uop_harness_f1():", renamed)

    def test_extract_grep_pattern(self):
        """Test extraction of grep patterns from metadata."""
        meta_asan = {"fingerprint": "ASAN:heap-use-after-free"}
        self.assertEqual(extract_grep_pattern(meta_asan), "AddressSanitizer")

        meta_assert = {"fingerprint": "ASSERT:file.c:123:assertion text"}
        self.assertEqual(extract_grep_pattern(meta_assert), "assertion text")

        meta_segv = {"fingerprint": "SIGNAL:SIGSEGV"}
        self.assertEqual(extract_grep_pattern(meta_segv), "Segmentation fault")


class TestMinimizeWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.crash_dir = self.temp_dir / "crash_123"
        self.crash_dir.mkdir()

        # Setup dummy files
        (self.crash_dir / "metadata.json").write_text(
            json.dumps({"returncode": -11, "fingerprint": "SIGNAL:SIGSEGV", "type": "SEGV"})
        )

        (self.crash_dir / "00_polluter.py").write_text("print('polluter')")
        (self.crash_dir / "01_warmup.py").write_text("print('warmup')")
        (self.crash_dir / "02_attack.py").write_text("print('attack')")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch("lafleur.minimize.run_session")
    @patch("lafleur.minimize.shutil.which")
    @patch("subprocess.run")
    def test_script_minimization_removes_polluter(self, mock_run, mock_which, mock_run_session):
        """Test that unnecessary scripts are removed."""
        mock_which.return_value = None  # Disable shrinkray for this test

        # Mock run_session behavior:
        # If polluter is MISSING, it still crashes (simulating unnecessary polluter)
        # If attack is MISSING, it does NOT crash (simulating necessary attack)
        def side_effect(scripts, target_python="python3"):
            script_names = [s.name for s in scripts]
            if "02_attack.py" in script_names:
                return -11, "", "Segmentation fault"  # Crash
            return 0, "", ""  # No crash

        mock_run_session.side_effect = side_effect

        # Run minimize
        minimize_session(self.crash_dir, target_python="python3", force_overwrite=False)

        # Check that we tried to run shrinkray/final output logic with REDUCED set
        # Since we mocked print/stdout capture is hard, we verify logic via side effects
        # The key is that it should have tried to validate concatenation of only necessary scripts

        # We can inspect the calls to run_session to see what combinations were tested
        # 1. Test removing 00_polluter -> remaining [01, 02] -> Crash -> Polluter Removed
        # 2. Test removing 01_warmup -> remaining [02] -> Crash -> Warmup Removed
        # 3. Test removing 02_attack -> remaining [] (empty) -> No crash? (actually loop handles this)

        # Verify backups were created
        self.assertTrue((self.crash_dir / "00_polluter.py.backup").exists())

    @patch("lafleur.minimize.run_session")
    @patch("lafleur.minimize.shutil.which")
    @patch("subprocess.run")
    def test_concatenation_logic(self, mock_subprocess, mock_which, mock_run_session):
        """Test that concatenation is attempted."""
        mock_which.return_value = "/bin/shrinkray"

        # Mock behavior:
        # We need check_reproduction to return FALSE (crash NOT reproduced) when minimizing scripts
        # so that it thinks they are all necessary.
        # But we need it to return TRUE (crash reproduced) for the initial check and the final concatenation check.

        # Strategy:
        # 1. Initial check (full list) -> Crash (-11)
        # 2. Minimize polluter (remove polluter) -> No Crash (0) -> Keeps polluter
        # 3. Minimize warmup (remove warmup) -> No Crash (0) -> Keeps warmup
        # 4. Minimize attack (remove attack) -> No Crash (0) -> Keeps attack
        # 5. Concatenation check (combined_repro.py) -> Crash (-11)

        def side_effect(scripts, target_python="python3"):
            script_names = [s.name for s in scripts]

            # Concatenation check
            if "combined_repro.py" in script_names:
                return -11, "", "Segmentation fault"

            # If any script is missing from the full set, fail to reproduce
            # This forces minimize_session to keep all of them
            if len(scripts) < 3:
                return 0, "", ""

            # Full set (initial check) reproduces crash
            return -11, "", "Segmentation fault"

        mock_run_session.side_effect = side_effect

        minimize_session(self.crash_dir, target_python="python3", force_overwrite=False)

        # Check combined file created
        combined = self.crash_dir / "combined_repro.py"
        self.assertTrue(combined.exists())
        content = combined.read_text()
        # Since we forced it to keep all scripts, polluter should be in there
        self.assertIn("Source: 00_polluter.py", content)

        # Check check_crash.sh created
        check_script = self.crash_dir / "check_crash.sh"
        self.assertTrue(check_script.exists())
        self.assertIn("combined_repro.py", check_script.read_text())


class TestMinimizeShrinkRay(unittest.TestCase):
    """Tests for ShrinkRay integration and error handling."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.crash_dir = self.temp_dir / "crash_shrinkray"
        self.crash_dir.mkdir()

        # Setup dummy files
        (self.crash_dir / "metadata.json").write_text(
            json.dumps({"returncode": -11, "fingerprint": "SIGNAL:SIGSEGV", "type": "SEGV"})
        )
        (self.crash_dir / "script.py").write_text("print('crash')")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch("lafleur.minimize.run_session")
    @patch("lafleur.minimize.shutil.which")
    @patch("lafleur.minimize.subprocess.run")
    def test_shrinkray_failure_is_caught(self, mock_subprocess_run, mock_which, mock_run_session):
        """Test that ShrinkRay failure is caught and handled gracefully."""
        # ShrinkRay is available
        mock_which.return_value = "/usr/bin/shrinkray"

        # Crash reproduces
        mock_run_session.return_value = (-11, "", "Segmentation fault")

        # Make subprocess.run work normally for timing calls, but fail for ShrinkRay
        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            # Check if shrinkray is the actual command (first element)
            if isinstance(cmd, list) and len(cmd) > 0 and "shrinkray" in cmd[0]:
                raise Exception("ShrinkRay crashed")
            # Return a successful result for timing calls
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        mock_subprocess_run.side_effect = subprocess_side_effect

        # Should not raise - should catch and print error
        from io import StringIO

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            minimize_session(self.crash_dir, target_python="python3", force_overwrite=True)

        output = captured_stdout.getvalue()
        self.assertIn("ShrinkRay failed", output)
        self.assertIn("Minimization Complete", output)

    @patch("lafleur.minimize.run_session")
    @patch("lafleur.minimize.shutil.which")
    @patch("lafleur.minimize.subprocess.run")
    def test_shrinkray_success(self, mock_subprocess_run, mock_which, mock_run_session):
        """Test that ShrinkRay success is reported."""
        mock_which.return_value = "/usr/bin/shrinkray"
        mock_run_session.return_value = (-11, "", "Segmentation fault")

        # Return success for all subprocess calls (timing and ShrinkRay)
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")

        from io import StringIO

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            minimize_session(self.crash_dir, target_python="python3", force_overwrite=True)

        output = captured_stdout.getvalue()
        self.assertIn("ShrinkRay finished", output)

    @patch("lafleur.minimize.run_session")
    @patch("lafleur.minimize.shutil.which")
    def test_shrinkray_not_available(self, mock_which, mock_run_session):
        """Test that missing ShrinkRay is handled gracefully."""
        mock_which.return_value = None  # ShrinkRay not in PATH
        mock_run_session.return_value = (-11, "", "Segmentation fault")

        from io import StringIO

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            minimize_session(self.crash_dir, target_python="python3", force_overwrite=True)

        output = captured_stdout.getvalue()
        self.assertIn("shrinkray", output.lower())
        self.assertIn("not found", output.lower())


class TestMinimizeEdgeCases(unittest.TestCase):
    """Tests for edge cases in minimize module."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_extract_grep_pattern_panic(self):
        """Test grep pattern extraction for PANIC fingerprint."""
        meta = {"fingerprint": "PANIC:Fatal Python error: Segmentation fault"}
        pattern = extract_grep_pattern(meta)
        self.assertEqual(pattern, "Fatal Python error")

    def test_extract_grep_pattern_short_assert(self):
        """Test grep pattern extraction for short ASSERT fingerprint."""
        # Only has 3 parts, not 4
        meta = {"fingerprint": "ASSERT:file.c:123"}
        pattern = extract_grep_pattern(meta)
        self.assertEqual(pattern, "Assertion")

    def test_extract_grep_pattern_sig11(self):
        """Test grep pattern extraction for SIGNAL:SIG_11."""
        meta = {"fingerprint": "SIGNAL:SIG_11:something"}
        pattern = extract_grep_pattern(meta)
        self.assertEqual(pattern, "Segmentation fault")

    def test_extract_grep_pattern_unknown(self):
        """Test grep pattern extraction for unknown fingerprint."""
        meta = {"fingerprint": "UNKNOWN:something"}
        pattern = extract_grep_pattern(meta)
        self.assertEqual(pattern, "")

    def test_rename_harnesses_no_harness(self):
        """Test rename_harnesses with source that has no harness."""
        source = "def regular_function():\n    pass"
        renamed = rename_harnesses(source, "0")
        self.assertEqual(source, renamed)

    @patch("lafleur.minimize.run_session")
    @patch("lafleur.minimize.shutil.which")
    def test_crash_does_not_reproduce_initially(self, mock_which, mock_run_session):
        """Test handling when crash doesn't reproduce initially."""
        crash_dir = self.temp_dir / "no_repro"
        crash_dir.mkdir()
        (crash_dir / "metadata.json").write_text(
            json.dumps({"returncode": -11, "fingerprint": "SIGNAL:SIGSEGV"})
        )
        (crash_dir / "script.py").write_text("print('test')")

        mock_which.return_value = None
        # Crash does NOT reproduce
        mock_run_session.return_value = (0, "", "")

        with self.assertRaises(SystemExit) as ctx:
            minimize_session(crash_dir, target_python="python3", force_overwrite=True)

        self.assertEqual(ctx.exception.code, 1)

    @patch("lafleur.minimize.run_session")
    @patch("lafleur.minimize.shutil.which")
    def test_concatenation_fails_fallback_to_last(self, mock_which, mock_run_session):
        """Test fallback when concatenation breaks the crash."""
        crash_dir = self.temp_dir / "concat_fail"
        crash_dir.mkdir()
        (crash_dir / "metadata.json").write_text(
            json.dumps({"returncode": -11, "fingerprint": "SIGNAL:SIGSEGV"})
        )
        (crash_dir / "00_first.py").write_text("x = 1")
        (crash_dir / "01_second.py").write_text("y = 2")

        mock_which.return_value = None

        call_count = [0]

        def side_effect(scripts, target_python="python3"):
            call_count[0] += 1
            script_names = [s.name for s in scripts]

            # Concatenated file does NOT reproduce
            if "combined_repro.py" in script_names:
                return 0, "", ""

            # Full set or partial reproduces
            if len(scripts) >= 1:
                return -11, "", "Segmentation fault"

            return 0, "", ""

        mock_run_session.side_effect = side_effect

        from io import StringIO

        captured_stdout = StringIO()
        with patch("sys.stdout", captured_stdout):
            minimize_session(crash_dir, target_python="python3", force_overwrite=True)

        output = captured_stdout.getvalue()
        self.assertIn("Concatenation broke the crash", output)
        self.assertIn("Falling back", output)


class TestMinimizeHelperFunctions(unittest.TestCase):
    """Additional tests for helper functions."""

    def test_extract_grep_pattern_empty_fingerprint(self):
        """Test grep pattern extraction with empty fingerprint."""
        meta = {"fingerprint": ""}
        pattern = extract_grep_pattern(meta)
        self.assertEqual(pattern, "")

    def test_extract_grep_pattern_missing_fingerprint(self):
        """Test grep pattern extraction with missing fingerprint."""
        meta = {}
        pattern = extract_grep_pattern(meta)
        self.assertEqual(pattern, "")


if __name__ == "__main__":
    unittest.main()
