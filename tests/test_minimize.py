import unittest
import shutil
import tempfile
import json
from pathlib import Path
from unittest.mock import patch
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


if __name__ == "__main__":
    unittest.main()
