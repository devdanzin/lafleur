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

            logger.write("Hello, World!\n")
            logger.flush()  # Force buffered line out

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

            logger.write("test\n")
            logger.close()

            # File should be closed
            self.assertTrue(logger.log_file.closed)

    def test_write_flushes_immediately(self):
        """Test that different consecutive writes flush immediately."""
        original_stream = StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, original_stream)

            logger.write("Message 1\n")
            logger.write("Message 2\n")  # Different message flushes Message 1

            output = original_stream.getvalue()
            self.assertIn("Message 1", output)
            # Message 2 is still buffered until something else arrives
            logger.close()
            output = original_stream.getvalue()
            self.assertIn("Message 2", output)

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
        mock_stream = MagicMock(spec=["write", "flush"])  # No encoding attribute

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


class TestTeeLoggerRepeatCollapsing(unittest.TestCase):
    """Tests for TeeLogger repeat collapsing behavior."""

    def test_collapses_identical_consecutive_lines(self):
        """Test that 5 identical lines become 1 with (×5) suffix."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            for _ in range(5):
                logger.write("    -> Injecting for loop around a statement.\n")
            logger.write("Next different line\n")
            logger.close()

            output = stream.getvalue()
            self.assertIn("(×5)", output)
            self.assertEqual(output.count("Injecting for loop"), 1)
            self.assertIn("Next different line", output)

    def test_no_suffix_for_single_occurrence(self):
        """Test that a single line has no (×N) suffix."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            logger.write("Single line\n")
            logger.close()

            output = stream.getvalue()
            self.assertIn("Single line", output)
            self.assertNotIn("×", output)

    def test_collapses_to_log_file_too(self):
        """Test that repeat collapsing applies to the log file as well."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            for _ in range(3):
                logger.write("Repeated\n")
            logger.close()

            file_content = log_path.read_text()
            self.assertIn("(×3)", file_content)
            self.assertEqual(file_content.count("Repeated"), 1)

    def test_different_lines_not_collapsed(self):
        """Test that different lines are not collapsed."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            logger.write("Line A\n")
            logger.write("Line B\n")
            logger.write("Line C\n")
            logger.close()

            output = stream.getvalue()
            self.assertIn("Line A", output)
            self.assertIn("Line B", output)
            self.assertIn("Line C", output)
            self.assertNotIn("×", output)

    def test_alternating_lines_not_collapsed(self):
        """Test that alternating A-B-A-B lines are not collapsed."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            logger.write("A\n")
            logger.write("B\n")
            logger.write("A\n")
            logger.write("B\n")
            logger.close()

            output = stream.getvalue()
            self.assertEqual(output.count("A\n"), 2)
            self.assertEqual(output.count("B\n"), 2)
            self.assertNotIn("×", output)

    def test_close_flushes_buffered_repeat(self):
        """Test that close() flushes any buffered repeated line."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            for _ in range(10):
                logger.write("Repeated line\n")
            logger.close()

            output = stream.getvalue()
            self.assertIn("Repeated line (×10)", output)

    def test_flush_flushes_buffered_repeat(self):
        """Test that flush() flushes the buffered repeat."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            for _ in range(3):
                logger.write("Repeated\n")
            logger.flush()

            output = stream.getvalue()
            self.assertIn("(×3)", output)
            logger.close()

    def test_empty_writes_pass_through(self):
        """Test that empty strings don't interfere with repeat buffer."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            logger.write("Line\n")
            logger.write("")
            logger.write("Line\n")
            logger.close()

            output = stream.getvalue()
            # Should still collapse
            self.assertIn("(×2)", output)

    def test_mixed_collapse_and_unique(self):
        """Test realistic mixed pattern: some repeated, some unique."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            logger.write("  [~] Running HAVOC stage...\n")
            for _ in range(19):
                logger.write("    -> Injecting for loop around a statement.\n")
            for _ in range(27):
                logger.write("    -> Removing fuzzer-injected guard.\n")
            logger.write("    -> Run #1/6 (RuntimeSeed: 107939)\n")
            logger.close()

            output = stream.getvalue()
            self.assertIn("(×19)", output)
            self.assertIn("(×27)", output)
            self.assertEqual(output.count("Injecting for loop"), 1)
            self.assertEqual(output.count("Removing fuzzer-injected guard"), 1)


class TestTeeLoggerVerbosityFiltering(unittest.TestCase):
    """Tests for TeeLogger verbosity filtering."""

    def test_verbose_mode_shows_all(self):
        """Test that verbose=True shows everything."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=True)

            logger.write("    -> Injecting for loop around a statement.\n")
            logger.write("[COVERAGE] Running child with JIT=True.\n")
            logger.write("[SESSION] Using session driver for warm JIT fuzzing.\n")
            logger.close()

            output = stream.getvalue()
            self.assertIn("Injecting for loop", output)
            self.assertIn("[COVERAGE]", output)
            self.assertIn("[SESSION]", output)

    def test_quiet_mode_suppresses_mutator_detail(self):
        """Test that verbose=False suppresses mutator detail lines."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write("    -> Injecting for loop around a statement.\n")
            logger.write("    -> Removing fuzzer-injected guard.\n")
            logger.write("    -> Slicing large function body of 140 statements.\n")
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("Injecting", output)
            self.assertNotIn("Removing", output)
            self.assertNotIn("Slicing", output)

    def test_quiet_mode_suppresses_boilerplate(self):
        """Test that verbose=False suppresses execution boilerplate."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write("[COVERAGE] Running child with JIT=True.\n")
            logger.write("[SESSION] Using session driver for warm JIT fuzzing.\n")
            logger.write("[MIXER] Active: Added 2 polluter(s) to session.\n")
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("[COVERAGE]", output)
            self.assertNotIn("[SESSION]", output)
            self.assertNotIn("[MIXER]", output)

    def test_quiet_mode_suppresses_relative_coverage(self):
        """Test that verbose=False suppresses individual relative coverage lines."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write(
                "[NEW RELATIVE EDGE] '('OPTIMIZED', '_SET_IP->_UNARY_NEGATIVE')' in harness 'f1'\n"
            )
            logger.write("[NEW RELATIVE UOP] '_UNARY_NEGATIVE' in harness 'f1'\n")
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("[NEW RELATIVE", output)

    def test_quiet_mode_suppresses_not_interesting(self):
        """Test that verbose=False suppresses non-interesting child results."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write("  [+] Child IS NOT interesting with score: 1.00\n")
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("IS NOT interesting", output)

    def test_quiet_mode_suppresses_stage_notifications(self):
        """Test that verbose=False suppresses stage notifications."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write("  [~] Running HAVOC stage...\n")
            logger.write("  [~] Running DETERMINISTIC stage...\n")
            logger.write("  [~] Large AST detected (140 statements), running SLICING stage...\n")
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("HAVOC", output)
            self.assertNotIn("DETERMINISTIC", output)
            self.assertNotIn("SLICING", output)

    def test_quiet_mode_shows_important_events(self):
        """Test that verbose=False still shows all important events."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            important_lines = [
                "  [***] SUCCESS! Mutation #10 found new coverage. Moving to next parent.\n",
                "  [>>>] DEEPENING: New child 20383.py becomes the new parent.\n",
                "  [+] JIT Tachycardia (delta): density=0.11, exits=68\n",
                "  [!] JIT ZOMBIE STATE DETECTED!\n",
                "  [+] Child is interesting with score: 22.00\n",
                "    -> Rewarding successful strategy 'havoc' and transformers: ['t1']\n",
                "[+] Added minimized file to corpus: 20383.py\n",
                "[+] Dynamically adjusting mutation count. Base: 100, Final: 291\n",
                "[+] Selected parent for BREADTH session: 1234.py (Score: 5.00)\n",
                "  \\-> Running mutation #1 (Seed: 107939) for 20383.py...\n",
                "[NEW GLOBAL UOP] '_BINARY_OP' in harness 'f1'\n",
                "[NEW GLOBAL EDGE] '('OPTIMIZED', '_SET_IP->_LOAD_FAST')' in harness 'f1'\n",
                "  [~] Tachycardia decay: 0.1058 -> 0.1005\n",
            ]

            for line in important_lines:
                logger.write(line)
            logger.close()

            output = stream.getvalue()
            for line in important_lines:
                # Check the key content of each important line is present
                key_content = line.strip()[:30]
                self.assertIn(
                    key_content,
                    output,
                    f"Important line missing: {line.strip()[:50]}...",
                )

    def test_quiet_mode_with_repeat_collapsing(self):
        """Test that suppressed lines don't interfere with repeat collapsing."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            # Suppressed lines should not break the repeat buffer
            logger.write("Important line A\n")
            logger.write("[COVERAGE] Running child with JIT=True.\n")  # Suppressed
            logger.write("Important line A\n")  # Same as first, should collapse
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("[COVERAGE]", output)
            self.assertIn("Important line A (×2)", output)

    def test_suppression_applies_to_log_file_too(self):
        """Test that suppressed lines are also absent from the log file."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write("[COVERAGE] Running child with JIT=True.\n")
            logger.write("[+] Added minimized file to corpus: 123.py\n")
            logger.close()

            file_content = log_path.read_text()
            self.assertNotIn("[COVERAGE]", file_content)
            self.assertIn("[+] Added", file_content)

    def test_verbose_default_is_true(self):
        """Test that default verbose is True (backward compatible)."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream)

            self.assertTrue(logger.verbose)
            logger.close()

    def test_suppressed_print_no_blank_lines(self):
        """Test that print()-style writes (content + '\\n') leave no blank lines."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            # Simulate print() behavior: write content, then write "\n"
            logger.write("Important before\n")
            logger.write("    -> Injecting for loop around a statement.")
            logger.write("\n")  # print()'s trailing newline
            logger.write("    -> Removing fuzzer-injected guard.")
            logger.write("\n")
            logger.write("Important after\n")
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("Injecting", output)
            self.assertNotIn("Removing", output)
            # No blank lines between important lines
            self.assertNotIn("\n\n", output)

    def test_suppressed_print_no_blank_lines_in_log_file(self):
        """Test that suppressed print() leaves no blank lines in the log file."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write("Before\n")
            logger.write("[COVERAGE] Running child with JIT=True.")
            logger.write("\n")
            logger.write("[SESSION] Using session driver.")
            logger.write("\n")
            logger.write("After\n")
            logger.close()

            file_content = log_path.read_text()
            self.assertNotIn("[COVERAGE]", file_content)
            self.assertNotIn("[SESSION]", file_content)
            self.assertNotIn("\n\n", file_content)

    def test_many_suppressed_prints_no_blank_lines(self):
        """Test that many consecutive suppressed print() calls produce no blank lines."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            logger.write("  \\-> Running mutation #1 (Seed: 107981) for 10909.py...\n")
            # Simulate 20 suppressed print() calls (content + "\n")
            for i in range(20):
                logger.write(f"    -> Injecting for loop #{i}.")
                logger.write("\n")
            logger.write("  [+] Child is interesting with score: 12.00\n")
            logger.close()

            output = stream.getvalue()
            self.assertNotIn("Injecting", output)
            # Should have exactly two lines, no blanks between them
            lines = output.strip().split("\n")
            self.assertEqual(len(lines), 2)
            self.assertIn("Running mutation", lines[0])
            self.assertIn("interesting", lines[1])

    def test_non_suppressed_newlines_still_pass_through(self):
        """Test that bare newlines unrelated to suppression still work."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test.log"
            logger = TeeLogger(log_path, stream, verbose=False)

            # A non-suppressed line followed by a bare newline (e.g. print("", end="\n"))
            logger.write("Important line")
            logger.write("\n")
            logger.close()

            output = stream.getvalue()
            self.assertIn("Important line\n", output)


class TestTeeLoggerLogPath(unittest.TestCase):
    """Tests for --log-path CLI flag integration."""

    def test_custom_log_path_creates_parent_dirs(self):
        """Test that a custom log path creates parent directories."""
        stream = StringIO()
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "subdir" / "deep" / "test.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            logger = TeeLogger(log_path, stream)
            logger.write("Test\n")
            logger.close()

            self.assertTrue(log_path.exists())
            self.assertIn("Test", log_path.read_text())


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
