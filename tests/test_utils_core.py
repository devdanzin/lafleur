"""
Tests for the utils module (lafleur/utils.py).

This module tests utility functions including run stats loading/saving,
TeeLogger, and ExecutionResult.
"""

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.utils import (
    _default_run_stats,
    load_run_stats,
    save_run_stats,
    TeeLogger,
    ExecutionResult,
)


class TestLoadRunStats(unittest.TestCase):
    """Tests for load_run_stats function."""

    def test_returns_default_when_file_not_exists(self):
        """Test that default structure is returned when file doesn't exist."""
        with patch.object(Path, "is_file", return_value=False):
            stats = load_run_stats()

        self.assertIn("start_time", stats)
        self.assertIn("total_sessions", stats)
        self.assertEqual(stats["total_mutations"], 0)
        self.assertEqual(stats["corpus_size"], 0)
        self.assertEqual(stats["crashes_found"], 0)

    def test_loads_existing_stats(self):
        """Test loading existing stats file."""
        existing_stats = {
            "start_time": "2025-01-01T00:00:00",
            "total_sessions": 5,
            "total_mutations": 100,
            "corpus_size": 50,
            "crashes_found": 2,
            "timeouts_found": 1,
            "divergences_found": 0,
            "new_coverage_finds": 10,
            "sum_of_mutations_per_find": 50,
            "average_mutations_per_find": 5.0,
            "global_seed_counter": 100,
            "corpus_file_counter": 50,
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            stats_file = Path(tmp_dir) / "fuzz_run_stats.json"
            stats_file.write_text(json.dumps(existing_stats))

            with patch("lafleur.utils.RUN_STATS_FILE", stats_file):
                stats = load_run_stats()

        self.assertEqual(stats["total_sessions"], 5)
        self.assertEqual(stats["total_mutations"], 100)

    def test_corrupted_json_returns_default(self):
        """Test that corrupted JSON returns default stats without RecursionError."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            stats_file = Path(tmp_dir) / "fuzz_run_stats.json"
            stats_file.write_text("{bad json}")

            with patch("lafleur.utils.RUN_STATS_FILE", stats_file):
                stats = load_run_stats()

        self.assertIn("start_time", stats)
        self.assertEqual(stats["total_sessions"], 0)
        self.assertEqual(stats["total_mutations"], 0)
        self.assertEqual(stats["crashes_found"], 0)

    def test_corrupted_file_prints_warning(self):
        """Test that a corrupted file prints a warning to stderr."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            stats_file = Path(tmp_dir) / "fuzz_run_stats.json"
            stats_file.write_text("{bad json}")

            with patch("lafleur.utils.RUN_STATS_FILE", stats_file):
                with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                    load_run_stats()

            self.assertIn("Warning", mock_stderr.getvalue())
            self.assertIn("Starting fresh", mock_stderr.getvalue())

    def test_adds_missing_fields_to_old_stats(self):
        """Test that missing fields are added to older stats files."""
        old_stats = {
            "start_time": "2025-01-01T00:00:00",
            "total_sessions": 5,
            "total_mutations": 100,
            # Missing newer fields
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            stats_file = Path(tmp_dir) / "fuzz_run_stats.json"
            stats_file.write_text(json.dumps(old_stats))

            with patch("lafleur.utils.RUN_STATS_FILE", stats_file):
                stats = load_run_stats()

        # Should have default values for missing fields
        self.assertEqual(stats["sum_of_mutations_per_find"], 0)
        self.assertEqual(stats["average_mutations_per_find"], 0.0)
        self.assertEqual(stats["global_seed_counter"], 0)
        self.assertEqual(stats["corpus_file_counter"], 0)
        self.assertEqual(stats["divergences_found"], 0)

    def test_old_stats_preserve_existing_values(self):
        """Test that existing values are NOT overwritten by defaults."""
        old_stats = {
            "start_time": "2025-01-01T00:00:00",
            "total_sessions": 42,
            "total_mutations": 999,
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            stats_file = Path(tmp_dir) / "fuzz_run_stats.json"
            stats_file.write_text(json.dumps(old_stats))

            with patch("lafleur.utils.RUN_STATS_FILE", stats_file):
                stats = load_run_stats()

        # Existing values preserved
        self.assertEqual(stats["total_sessions"], 42)
        self.assertEqual(stats["total_mutations"], 999)
        self.assertEqual(stats["start_time"], "2025-01-01T00:00:00")
        # Missing fields filled in
        self.assertEqual(stats["crashes_found"], 0)


class TestDefaultRunStats(unittest.TestCase):
    """Tests for _default_run_stats helper."""

    def test_has_all_expected_fields(self):
        """Test that _default_run_stats contains all expected keys."""
        defaults = _default_run_stats()
        expected_keys = {
            "start_time",
            "last_update_time",
            "total_sessions",
            "total_mutations",
            "corpus_size",
            "crashes_found",
            "timeouts_found",
            "divergences_found",
            "new_coverage_finds",
            "sum_of_mutations_per_find",
            "average_mutations_per_find",
            "global_seed_counter",
            "corpus_file_counter",
        }
        self.assertEqual(set(defaults.keys()), expected_keys)

    def test_start_time_is_recent_iso_timestamp(self):
        """Test that start_time is a valid, recent ISO timestamp."""
        from datetime import datetime, timezone

        defaults = _default_run_stats()
        ts = datetime.fromisoformat(defaults["start_time"])
        now = datetime.now(timezone.utc)
        self.assertLess((now - ts).total_seconds(), 5)


class TestSaveRunStats(unittest.TestCase):
    """Tests for save_run_stats function."""

    def test_saves_stats_to_file(self):
        """Test saving stats to file."""
        stats = {
            "start_time": "2025-01-01T00:00:00",
            "total_sessions": 10,
            "total_mutations": 200,
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            stats_file = Path(tmp_dir) / "fuzz_run_stats.json"

            with patch("lafleur.utils.RUN_STATS_FILE", stats_file):
                save_run_stats(stats)

            # Verify file was written correctly
            saved_data = json.loads(stats_file.read_text())
            self.assertEqual(saved_data["total_sessions"], 10)
            self.assertEqual(saved_data["total_mutations"], 200)

    def test_sorts_keys_in_output(self):
        """Test that keys are sorted in output."""
        stats = {
            "z_field": 1,
            "a_field": 2,
            "m_field": 3,
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            stats_file = Path(tmp_dir) / "fuzz_run_stats.json"

            with patch("lafleur.utils.RUN_STATS_FILE", stats_file):
                save_run_stats(stats)

            content = stats_file.read_text()
            # Keys should appear in sorted order
            a_pos = content.index("a_field")
            m_pos = content.index("m_field")
            z_pos = content.index("z_field")
            self.assertLess(a_pos, m_pos)
            self.assertLess(m_pos, z_pos)

    def test_save_handles_write_error(self):
        """Test that IOError during save is caught and warned."""
        with patch("builtins.open", side_effect=IOError("disk full")):
            with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                save_run_stats({"total_sessions": 1})

        self.assertIn("Warning", mock_stderr.getvalue())
        self.assertIn("disk full", mock_stderr.getvalue())

    def test_save_handles_permission_error(self):
        """Test that PermissionError during save is caught and warned."""
        with patch("builtins.open", side_effect=PermissionError("access denied")):
            with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                save_run_stats({"total_sessions": 1})

        self.assertIn("Warning", mock_stderr.getvalue())
        self.assertIn("access denied", mock_stderr.getvalue())


class TestTeeLogger(unittest.TestCase):
    """Tests for TeeLogger class."""

    def test_writes_to_both_streams(self):
        """Test that write goes to both file and stream."""
        original_stream = StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, original_stream)

            logger.write("Hello, World!")

            # Check original stream
            self.assertIn("Hello, World!", original_stream.getvalue())

            # Check log file
            logger.close()
            self.assertIn("Hello, World!", log_path.read_text())

    def test_flushes_both_streams(self):
        """Test that flush is called on both streams."""
        original_stream = MagicMock()

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, original_stream)

            logger.flush()

            original_stream.flush.assert_called()
            logger.close()

    def test_close_closes_log_file(self):
        """Test that close method closes the log file."""
        original_stream = StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, original_stream)

            logger.write("test")
            logger.close()

            # File should be closed
            self.assertTrue(logger.log_file.closed)

    def test_write_flushes_immediately(self):
        """Test that each write flushes immediately."""
        original_stream = StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, original_stream)

            logger.write("Message 1\n")
            logger.write("Message 2\n")

            # Both messages should be immediately available in original stream
            output = original_stream.getvalue()
            self.assertIn("Message 1", output)
            self.assertIn("Message 2", output)

            logger.close()

    def test_encoding_delegates_to_stream(self):
        """Test that encoding property delegates to the original stream."""
        mock_stream = MagicMock()
        mock_stream.encoding = "utf-8"

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, mock_stream)

            self.assertEqual(logger.encoding, "utf-8")
            logger.close()

    def test_encoding_defaults_to_utf8(self):
        """Test that encoding defaults to utf-8 when stream has no encoding."""
        mock_stream = MagicMock(spec=[])  # No attributes at all

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, mock_stream)

            self.assertEqual(logger.encoding, "utf-8")
            logger.close()

    def test_isatty_false_for_stringio(self):
        """Test that isatty returns False for StringIO."""
        original_stream = StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, original_stream)

            self.assertFalse(logger.isatty())
            logger.close()

    def test_isatty_delegates_to_tty_stream(self):
        """Test that isatty delegates True when stream is a TTY."""
        mock_stream = MagicMock()
        mock_stream.isatty.return_value = True

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, mock_stream)

            self.assertTrue(logger.isatty())
            logger.close()

    def test_fileno_raises_for_stringio(self):
        """Test that fileno raises OSError for StringIO."""
        original_stream = StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, original_stream)

            with self.assertRaises(OSError):
                logger.fileno()
            logger.close()

    def test_fileno_delegates_to_stream(self):
        """Test that fileno delegates to the original stream."""
        mock_stream = MagicMock()
        mock_stream.fileno.return_value = 1

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, mock_stream)

            self.assertEqual(logger.fileno(), 1)
            logger.close()


class TestExecutionResult(unittest.TestCase):
    """Tests for ExecutionResult dataclass."""

    def test_basic_construction(self):
        """Test basic construction with required fields."""
        result = ExecutionResult(
            returncode=0,
            log_path=Path("/tmp/log.txt"),
            source_path=Path("/tmp/source.py"),
            execution_time_ms=100,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.log_path, Path("/tmp/log.txt"))
        self.assertEqual(result.source_path, Path("/tmp/source.py"))
        self.assertEqual(result.execution_time_ms, 100)

    def test_default_values(self):
        """Test default values for optional fields."""
        result = ExecutionResult(
            returncode=0,
            log_path=Path("/tmp/log.txt"),
            source_path=Path("/tmp/source.py"),
            execution_time_ms=100,
        )

        self.assertFalse(result.is_divergence)
        self.assertIsNone(result.divergence_reason)
        self.assertIsNone(result.jit_output)
        self.assertIsNone(result.nojit_output)
        self.assertIsNone(result.jit_avg_time_ms)
        self.assertIsNone(result.nojit_avg_time_ms)
        self.assertIsNone(result.nojit_cv)
        self.assertIsNone(result.parent_path)
        self.assertIsNone(result.session_files)

    def test_divergence_fields(self):
        """Test divergence-related fields."""
        result = ExecutionResult(
            returncode=0,
            log_path=Path("/tmp/log.txt"),
            source_path=Path("/tmp/source.py"),
            execution_time_ms=100,
            is_divergence=True,
            divergence_reason="Output mismatch",
            jit_output="result_jit",
            nojit_output="result_nojit",
        )

        self.assertTrue(result.is_divergence)
        self.assertEqual(result.divergence_reason, "Output mismatch")
        self.assertEqual(result.jit_output, "result_jit")
        self.assertEqual(result.nojit_output, "result_nojit")

    def test_timing_fields(self):
        """Test timing-related fields."""
        result = ExecutionResult(
            returncode=0,
            log_path=Path("/tmp/log.txt"),
            source_path=Path("/tmp/source.py"),
            execution_time_ms=100,
            jit_avg_time_ms=50.5,
            nojit_avg_time_ms=80.3,
            nojit_cv=0.15,
        )

        self.assertEqual(result.jit_avg_time_ms, 50.5)
        self.assertEqual(result.nojit_avg_time_ms, 80.3)
        self.assertEqual(result.nojit_cv, 0.15)

    def test_parent_and_session_files(self):
        """Test parent_path and session_files fields."""
        result = ExecutionResult(
            returncode=0,
            log_path=Path("/tmp/log.txt"),
            source_path=Path("/tmp/source.py"),
            execution_time_ms=100,
            parent_path=Path("/corpus/parent.py"),
            session_files=[Path("/tmp/file1.py"), Path("/tmp/file2.py")],
        )

        self.assertEqual(result.parent_path, Path("/corpus/parent.py"))
        self.assertEqual(len(result.session_files), 2)


if __name__ == "__main__":
    unittest.main()
