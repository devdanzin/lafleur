"""Tests for the HealthMonitor observability layer."""

import json
import tempfile
import unittest
from pathlib import Path

from lafleur.health import (
    CONSECUTIVE_TIMEOUT_THRESHOLD,
    FILE_SIZE_WARNING_THRESHOLD,
    HealthMonitor,
    extract_error_excerpt,
)


class TestHealthMonitorInit(unittest.TestCase):
    """Test HealthMonitor initialization."""

    def test_creates_with_log_path(self):
        """HealthMonitor accepts a log path and initializes empty counters."""
        monitor = HealthMonitor(log_path=Path("/tmp/test_health.jsonl"))
        self.assertEqual(monitor.counters, {})
        self.assertIsNone(monitor._timeout_parent)
        self.assertEqual(monitor._timeout_streak, 0)


class TestHealthMonitorWriteEvent(unittest.TestCase):
    """Test the internal _write_event method."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_writes_valid_jsonl(self):
        """Events are written as valid JSONL with expected fields."""
        self.monitor._write_event("test_cat", "test_event", key1="val1")

        lines = self.log_path.read_text().strip().split("\n")
        self.assertEqual(len(lines), 1)

        record = json.loads(lines[0])
        self.assertIn("ts", record)
        self.assertEqual(record["cat"], "test_cat")
        self.assertEqual(record["event"], "test_event")
        self.assertEqual(record["key1"], "val1")

    def test_appends_multiple_events(self):
        """Multiple events are appended, not overwritten."""
        self.monitor._write_event("cat1", "event1")
        self.monitor._write_event("cat2", "event2")

        lines = self.log_path.read_text().strip().split("\n")
        self.assertEqual(len(lines), 2)

    def test_increments_counters(self):
        """Each event increments the correct counter."""
        self.monitor._write_event("cat", "evt")
        self.monitor._write_event("cat", "evt")
        self.monitor._write_event("cat", "other")

        self.assertEqual(self.monitor.counters["cat.evt"], 2)
        self.assertEqual(self.monitor.counters["cat.other"], 1)

    def test_survives_oserror(self):
        """OSError during write is silently swallowed."""
        monitor = HealthMonitor(log_path=Path("/nonexistent/dir/health.jsonl"))
        # Should not raise
        monitor._write_event("cat", "evt")
        # Counter should still increment (it's in-memory, independent of I/O)
        self.assertEqual(monitor.counters["cat.evt"], 1)


class TestMutationPipelineEvents(unittest.TestCase):
    """Test mutation pipeline event recording."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_record_parent_parse_failure(self):
        """Parent parse failure is recorded with parent_id and error."""
        self.monitor.record_parent_parse_failure("42.py", "SyntaxError: unexpected EOF")

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["cat"], "mutation_pipeline")
        self.assertEqual(record["event"], "parent_parse_failure")
        self.assertEqual(record["parent_id"], "42.py")
        self.assertIn("SyntaxError", record["error"])

    def test_record_mutation_recursion_error(self):
        """Mutation RecursionError is recorded."""
        self.monitor.record_mutation_recursion_error("55.py")

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "mutation_recursion_error")
        self.assertEqual(record["parent_id"], "55.py")

    def test_record_unparse_recursion_error(self):
        """Unparse RecursionError is recorded."""
        self.monitor.record_unparse_recursion_error("66.py")

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "unparse_recursion_error")

    def test_record_child_script_none(self):
        """Child script None is recorded with mutation seed."""
        self.monitor.record_child_script_none("77.py", 12345)

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "child_script_none")
        self.assertEqual(record["mutation_seed"], 12345)

    def test_record_core_code_syntax_error(self):
        """Core code SyntaxError is recorded."""
        self.monitor.record_core_code_syntax_error("88.py", "unexpected indent")

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "core_code_syntax_error")
        self.assertEqual(record["parent_id"], "88.py")

    def test_record_core_code_syntax_error_seed(self):
        """Core code SyntaxError with None parent defaults to 'seed'."""
        self.monitor.record_core_code_syntax_error(None, "error")

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["parent_id"], "seed")


class TestExecutionEvents(unittest.TestCase):
    """Test execution event recording."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_timeout_streak_fires_at_threshold(self):
        """consecutive_timeouts event fires at CONSECUTIVE_TIMEOUT_THRESHOLD."""
        for _ in range(CONSECUTIVE_TIMEOUT_THRESHOLD - 1):
            self.monitor.record_timeout("42.py")

        # Should not have written yet
        self.assertFalse(self.log_path.exists())

        # This one hits the threshold
        self.monitor.record_timeout("42.py")

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "consecutive_timeouts")
        self.assertEqual(record["parent_id"], "42.py")
        self.assertEqual(record["count"], CONSECUTIVE_TIMEOUT_THRESHOLD)

    def test_timeout_streak_resets_on_different_parent(self):
        """Switching parents resets the timeout streak."""
        for _ in range(CONSECUTIVE_TIMEOUT_THRESHOLD - 1):
            self.monitor.record_timeout("42.py")

        # Switch parent — resets streak
        self.monitor.record_timeout("99.py")

        # No event should have been written
        self.assertFalse(self.log_path.exists())

    def test_timeout_streak_resets_on_explicit_reset(self):
        """reset_timeout_streak clears the streak."""
        for _ in range(CONSECUTIVE_TIMEOUT_THRESHOLD - 1):
            self.monitor.record_timeout("42.py")

        self.monitor.reset_timeout_streak()
        self.monitor.record_timeout("42.py")

        # Should not fire — streak was reset
        self.assertFalse(self.log_path.exists())

    def test_record_ignored_crash(self):
        """Ignored crash is recorded with reason and returncode."""
        self.monitor.record_ignored_crash("SyntaxError", 1)

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "ignored_crash")
        self.assertEqual(record["reason"], "SyntaxError")
        self.assertEqual(record["returncode"], 1)

    def test_record_deepening_sterility(self):
        """Deepening sterility is recorded with depth and mutation count."""
        self.monitor.record_deepening_sterility("55.py", depth=4, mutations_attempted=30)

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "deepening_sterility")
        self.assertEqual(record["depth"], 4)
        self.assertEqual(record["mutations_attempted"], 30)


class TestCorpusHealthEvents(unittest.TestCase):
    """Test corpus health event recording."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_record_file_size_warning(self):
        """File size warning is recorded with file_id and size."""
        self.monitor.record_file_size_warning("123.py", 131072)

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "file_size_warning")
        self.assertEqual(record["file_id"], "123.py")
        self.assertEqual(record["size_bytes"], 131072)

    def test_record_duplicate_rejected(self):
        """Duplicate rejection is recorded with truncated hashes."""
        self.monitor.record_duplicate_rejected("abcdef1234567890", "1234567890abcdef")

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "duplicate_rejected")
        self.assertEqual(record["content_hash"], "abcdef1234")
        self.assertEqual(record["coverage_hash"], "1234567890")

    def test_record_corpus_sterility(self):
        """Corpus sterility is recorded with parent_id and mutation count."""
        self.monitor.record_corpus_sterility("33.py", 600)

        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["event"], "corpus_sterility_reached")
        self.assertEqual(record["parent_id"], "33.py")
        self.assertEqual(record["mutations_since_last_find"], 600)


class TestGetSummary(unittest.TestCase):
    """Test get_summary method."""

    def test_returns_copy_of_counters(self):
        """get_summary returns a dict copy, not the internal reference."""
        monitor = HealthMonitor(log_path=Path("/tmp/test.jsonl"))
        monitor.counters["test.event"] = 5

        summary = monitor.get_summary()
        self.assertEqual(summary["test.event"], 5)

        # Modifying the returned dict should not affect internals
        summary["test.event"] = 99
        self.assertEqual(monitor.counters["test.event"], 5)

    def test_empty_summary(self):
        """Empty monitor returns empty summary."""
        monitor = HealthMonitor(log_path=Path("/tmp/test.jsonl"))
        self.assertEqual(monitor.get_summary(), {})


class TestExtractErrorExcerpt(unittest.TestCase):
    """Test extract_error_excerpt helper."""

    def test_extracts_python_error_line(self):
        """Finds the last Error: line in log content."""
        log = "line1\nline2\nTypeError: unsupported operand\nmore output"
        result = extract_error_excerpt(log)
        self.assertIn("TypeError", result)

    def test_falls_back_to_last_line(self):
        """Falls back to last non-empty line when no Error: pattern found."""
        log = "some output\nfinal line here"
        result = extract_error_excerpt(log)
        self.assertEqual(result, "final line here")

    def test_returns_none_for_empty(self):
        """Returns None for empty or whitespace-only content."""
        self.assertIsNone(extract_error_excerpt(""))
        self.assertIsNone(extract_error_excerpt("   \n   "))

    def test_truncates_long_lines(self):
        """Excerpt is truncated to max_length."""
        log = "ValueError: " + "x" * 300
        result = extract_error_excerpt(log, max_length=50)
        self.assertEqual(len(result), 50)

    def test_handles_none_input(self):
        """Handles None gracefully."""
        self.assertIsNone(extract_error_excerpt(None))


class TestIgnoredCrashEnriched(unittest.TestCase):
    """Test enriched ignored_crash events."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_includes_parent_id(self):
        """parent_id is included when provided."""
        self.monitor.record_ignored_crash("PYTHON:TypeError", 1, parent_id="42.py")
        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["parent_id"], "42.py")

    def test_includes_strategy(self):
        """strategy is included when provided."""
        self.monitor.record_ignored_crash("PYTHON:TypeError", 1, strategy="havoc")
        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["strategy"], "havoc")

    def test_includes_error_excerpt(self):
        """error_excerpt is included when provided."""
        self.monitor.record_ignored_crash(
            "PYTHON:unknown", 1, error_excerpt="NameError: name 'x' is not defined"
        )
        record = json.loads(self.log_path.read_text().strip())
        self.assertIn("NameError", record["error_excerpt"])

    def test_omits_none_fields(self):
        """None fields are not written to the event."""
        self.monitor.record_ignored_crash("SyntaxError", 1)
        record = json.loads(self.log_path.read_text().strip())
        self.assertNotIn("parent_id", record)
        self.assertNotIn("strategy", record)
        self.assertNotIn("error_excerpt", record)


class TestChildScriptNoneEnriched(unittest.TestCase):
    """Test enriched child_script_none events."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_includes_strategy(self):
        """strategy is included when provided."""
        self.monitor.record_child_script_none("42.py", 100, strategy="sniper")
        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["strategy"], "sniper")

    def test_omits_strategy_when_none(self):
        """strategy is omitted when not provided."""
        self.monitor.record_child_script_none("42.py", 100)
        record = json.loads(self.log_path.read_text().strip())
        self.assertNotIn("strategy", record)


class TestCoreSyntaxErrorEnriched(unittest.TestCase):
    """Test enriched core_code_syntax_error events."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_includes_strategy(self):
        """strategy is included when provided."""
        self.monitor.record_core_code_syntax_error("42.py", "bad indent", strategy="havoc")
        record = json.loads(self.log_path.read_text().strip())
        self.assertEqual(record["strategy"], "havoc")

    def test_omits_strategy_when_none(self):
        """strategy is omitted when not provided."""
        self.monitor.record_core_code_syntax_error("42.py", "bad indent")
        record = json.loads(self.log_path.read_text().strip())
        self.assertNotIn("strategy", record)


class TestCorpusSterilityOnce(unittest.TestCase):
    """Test that corpus_sterility_reached fires only once."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.tmp_dir) / "health_events.jsonl"
        self.monitor = HealthMonitor(log_path=self.log_path)

    def test_fires_once_not_repeatedly(self):
        """Verifying at the health monitor level that repeated calls produce repeated events.

        The once-only behavior is enforced in the orchestrator by checking
        is_sterile before calling record_corpus_sterility. This test verifies
        the monitor itself doesn't deduplicate (it shouldn't — that's the
        orchestrator's job).
        """
        self.monitor.record_corpus_sterility("42.py", 600)
        self.monitor.record_corpus_sterility("42.py", 601)

        lines = self.log_path.read_text().strip().split("\n")
        # Both calls should write (the monitor is stateless about sterility)
        self.assertEqual(len(lines), 2)


class TestFileConstants(unittest.TestCase):
    """Test module-level constants have sensible values."""

    def test_timeout_threshold_is_positive(self):
        self.assertGreater(CONSECUTIVE_TIMEOUT_THRESHOLD, 0)

    def test_file_size_threshold_is_positive(self):
        self.assertGreater(FILE_SIZE_WARNING_THRESHOLD, 0)
