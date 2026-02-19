"""
Tests for the report module (lafleur/report.py).

This module tests the single-instance text report generator.
"""

import json
import tempfile
import unittest
from pathlib import Path

from lafleur.report import (
    generate_report,
    load_json_file,
    format_duration,
    format_number,
    get_jit_asan_status,
    truncate_string,
    load_crash_data,
)


class TestReportHelpers(unittest.TestCase):
    """Tests for helper functions in the report module."""

    def test_format_duration_seconds(self):
        """Test formatting small durations."""
        self.assertEqual(format_duration(30), "30s")
        self.assertEqual(format_duration(0), "0s")

    def test_format_duration_minutes(self):
        """Test formatting minute-scale durations."""
        self.assertEqual(format_duration(90), "1m 30s")
        self.assertEqual(format_duration(120), "2m")

    def test_format_duration_hours(self):
        """Test formatting hour-scale durations."""
        self.assertEqual(format_duration(3600), "1h")
        self.assertEqual(format_duration(3661), "1h 1m 1s")

    def test_format_duration_days(self):
        """Test formatting day-scale durations."""
        self.assertEqual(format_duration(86400), "1d")
        self.assertEqual(format_duration(90061), "1d 1h 1m 1s")

    def test_format_duration_negative(self):
        """Test formatting negative duration."""
        self.assertEqual(format_duration(-1), "N/A")

    def test_format_number_integer(self):
        """Test formatting integers."""
        self.assertEqual(format_number(1000), "1,000")
        self.assertEqual(format_number(1000000), "1,000,000")

    def test_format_number_float(self):
        """Test formatting floats."""
        self.assertEqual(format_number(1234.56), "1,234.56")
        self.assertEqual(format_number(0.5), "0.50")

    def test_format_number_with_suffix(self):
        """Test formatting with suffix."""
        self.assertEqual(format_number(100, " MB"), "100 MB")
        self.assertEqual(format_number(3.14, "%"), "3.14%")

    def test_format_number_none(self):
        """Test formatting None."""
        self.assertEqual(format_number(None), "N/A")

    def test_get_jit_asan_status_both_enabled(self):
        """Test detecting JIT and ASan enabled."""
        config = "--with-pydebug --enable-experimental-jit --with-address-sanitizer"
        jit, asan = get_jit_asan_status(config)
        self.assertEqual(jit, "Enabled")
        self.assertEqual(asan, "Enabled")

    def test_get_jit_asan_status_disabled(self):
        """Test detecting JIT and ASan disabled."""
        config = "--with-pydebug"
        jit, asan = get_jit_asan_status(config)
        self.assertEqual(jit, "Disabled")
        self.assertEqual(asan, "Disabled")

    def test_get_jit_asan_status_none(self):
        """Test with None config."""
        jit, asan = get_jit_asan_status(None)
        self.assertEqual(jit, "Unknown")
        self.assertEqual(asan, "Unknown")

    def test_truncate_string_short(self):
        """Test truncating short strings (no change)."""
        self.assertEqual(truncate_string("hello", 10), "hello")

    def test_truncate_string_long(self):
        """Test truncating long strings."""
        self.assertEqual(truncate_string("hello world", 8), "hello...")

    def test_truncate_string_exact(self):
        """Test truncating exact length."""
        self.assertEqual(truncate_string("hello", 5), "hello")


class TestLoadJsonFile(unittest.TestCase):
    """Tests for JSON file loading."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_valid_json(self):
        """Test loading valid JSON file."""
        path = self.root / "test.json"
        path.write_text('{"key": "value"}', encoding="utf-8")

        data = load_json_file(path)
        self.assertEqual(data, {"key": "value"})

    def test_load_nonexistent_file(self):
        """Test loading non-existent file."""
        path = self.root / "nonexistent.json"
        data = load_json_file(path)
        self.assertIsNone(data)

    def test_load_invalid_json(self):
        """Test loading invalid JSON file."""
        path = self.root / "invalid.json"
        path.write_text("not valid json", encoding="utf-8")

        data = load_json_file(path)
        self.assertIsNone(data)


class TestLoadCrashData(unittest.TestCase):
    """Tests for crash data loading."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_no_crashes_dir(self):
        """Test loading from instance without crashes directory."""
        data = load_crash_data(self.root)
        self.assertEqual(data, {})

    def test_load_empty_crashes_dir(self):
        """Test loading from empty crashes directory."""
        crashes_dir = self.root / "crashes"
        crashes_dir.mkdir()

        data = load_crash_data(self.root)
        self.assertEqual(data, {})

    def test_load_crashes_with_metadata(self):
        """Test loading crashes with metadata files."""
        crashes_dir = self.root / "crashes"

        # Create crash 1
        crash1_dir = crashes_dir / "crash_1"
        crash1_dir.mkdir(parents=True)
        (crash1_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "ASSERT:test1", "timestamp": "20250101_120000"})
        )

        # Create crash 2 with same fingerprint
        crash2_dir = crashes_dir / "crash_2"
        crash2_dir.mkdir(parents=True)
        (crash2_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "ASSERT:test1", "timestamp": "20250101_130000"})
        )

        # Create crash 3 with different fingerprint
        crash3_dir = crashes_dir / "crash_3"
        crash3_dir.mkdir(parents=True)
        (crash3_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "SEGV:other", "timestamp": "20250101_140000"})
        )

        data = load_crash_data(self.root)

        # Should have 2 unique fingerprints
        self.assertEqual(len(data), 2)
        # ASSERT:test1 should have 2 crashes
        self.assertEqual(len(data["ASSERT:test1"]), 2)
        # SEGV:other should have 1 crash
        self.assertEqual(len(data["SEGV:other"]), 1)


class TestGenerateReport(unittest.TestCase):
    """Tests for the main report generation function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_minimal_instance(self):
        """Create a minimal valid instance directory."""
        # Create logs directory with metadata
        logs_dir = self.root / "logs"
        logs_dir.mkdir()

        metadata = {
            "instance_name": "test_instance",
            "run_id": "run_123",
            "environment": {
                "hostname": "test-host",
                "os": "Linux",
                "python_version": "3.14.0",
                "python_config_args": "--enable-experimental-jit",
            },
            "hardware": {
                "cpu_count_physical": 4,
                "cpu_count_logical": 8,
                "total_ram_gb": 16.0,
            },
        }
        (logs_dir / "run_metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

        # Create stats file
        stats = {
            "total_mutations": 1000,
            "global_edges": 500,
            "global_uops": 100,
            "corpus_size": 50,
            "crashes_found": 2,
            "start_time": "2025-01-01T10:00:00Z",
            "last_update_time": "2025-01-01T11:00:00Z",
        }
        (self.root / "fuzz_run_stats.json").write_text(json.dumps(stats), encoding="utf-8")

    def test_generate_report_minimal(self):
        """Test generating report for minimal instance."""
        self._create_minimal_instance()

        report = generate_report(self.root)

        # Check header
        self.assertIn("LAFLEUR FUZZING INSTANCE REPORT", report)
        self.assertIn("test_instance", report)
        self.assertIn("run_123", report)

        # Check system section
        self.assertIn("SYSTEM", report)
        self.assertIn("4 physical", report)
        self.assertIn("JIT:", report)
        self.assertIn("Enabled", report)

        # Check performance section
        self.assertIn("PERFORMANCE", report)
        self.assertIn("Executions:", report)
        self.assertIn("1,000", report)

        # Check coverage section
        self.assertIn("COVERAGE", report)
        self.assertIn("Global Edges:", report)
        self.assertIn("500", report)

    def test_generate_report_empty_directory(self):
        """Test generating report for empty directory."""
        # Should not crash, just show N/A values
        report = generate_report(self.root)

        self.assertIn("LAFLEUR FUZZING INSTANCE REPORT", report)
        self.assertIn("N/A", report)

    def test_generate_report_missing_stats(self):
        """Test generating report when stats file is missing."""
        # Create only metadata
        logs_dir = self.root / "logs"
        logs_dir.mkdir()
        (logs_dir / "run_metadata.json").write_text(
            json.dumps({"instance_name": "test"}), encoding="utf-8"
        )

        report = generate_report(self.root)

        # Should still generate report
        self.assertIn("LAFLEUR FUZZING INSTANCE REPORT", report)
        self.assertIn("Executions:", report)

    def test_generate_report_with_crashes(self):
        """Test generating report with crash data."""
        self._create_minimal_instance()

        # Add crashes
        crashes_dir = self.root / "crashes"
        crash_dir = crashes_dir / "crash_1"
        crash_dir.mkdir(parents=True)
        (crash_dir / "metadata.json").write_text(
            json.dumps(
                {
                    "fingerprint": "ASSERT:test_crash",
                    "timestamp": "20250101_103000",
                }
            )
        )

        report = generate_report(self.root)

        self.assertIn("CRASH DIGEST", report)
        self.assertIn("Total Crashes:", report)
        self.assertIn("ASSERT:test_crash", report)

    def test_generate_report_with_corpus_stats(self):
        """Test generating report with corpus statistics."""
        self._create_minimal_instance()

        # Add corpus stats
        corpus_stats = {
            "root_count": 10,
            "leaf_count": 30,
            "max_depth": 5,
            "sterile_count": 5,
            "sterile_rate": 0.1,
            "viable_count": 45,
            "successful_strategies": {"default": 20, "aggressive": 10},
            "successful_mutators": {"OperatorSwapper": 15, "ConstantPerturbator": 10},
        }
        (self.root / "corpus_stats.json").write_text(json.dumps(corpus_stats), encoding="utf-8")

        report = generate_report(self.root)

        self.assertIn("CORPUS EVOLUTION", report)
        self.assertIn("Tree Topology:", report)
        self.assertIn("Roots: 10", report)
        self.assertIn("Top Strategies:", report)
        self.assertIn("Top Mutators:", report)

    def test_generate_report_handles_malformed_metadata(self):
        """Test that report handles malformed metadata gracefully."""
        logs_dir = self.root / "logs"
        logs_dir.mkdir()
        # Write invalid JSON
        (logs_dir / "run_metadata.json").write_text("not json", encoding="utf-8")

        # Should not crash
        report = generate_report(self.root)
        self.assertIn("LAFLEUR FUZZING INSTANCE REPORT", report)

    def _write_health_events(self, events):
        """Write health events to the instance's health log."""
        logs_dir = self.root / "logs"
        logs_dir.mkdir(exist_ok=True)
        health_path = logs_dir / "health_events.jsonl"
        health_path.write_text(
            "\n".join(json.dumps(e) for e in events),
            encoding="utf-8",
        )

    def test_generate_report_with_health_events(self):
        """Test that HEALTH section appears with health events."""
        self._create_minimal_instance()
        self._write_health_events(
            [
                {
                    "ts": "2026-01-01T00:00:00Z",
                    "cat": "mutation_pipeline",
                    "event": "parent_parse_failure",
                    "parent_id": "42.py",
                },
                {
                    "ts": "2026-01-01T00:00:01Z",
                    "cat": "mutation_pipeline",
                    "event": "parent_parse_failure",
                    "parent_id": "42.py",
                },
                {
                    "ts": "2026-01-01T00:00:02Z",
                    "cat": "execution",
                    "event": "ignored_crash",
                    "reason": "PYTHON:TypeError",
                },
                {
                    "ts": "2026-01-01T00:00:03Z",
                    "cat": "execution",
                    "event": "ignored_crash",
                    "reason": "PYTHON:TypeError",
                },
                {
                    "ts": "2026-01-01T00:00:04Z",
                    "cat": "execution",
                    "event": "ignored_crash",
                    "reason": "SyntaxError",
                },
            ]
        )

        report = generate_report(self.root)

        # Section header
        self.assertIn("HEALTH", report)

        # Grade and waste rate (2 waste events / 1000 total = 0.20%)
        self.assertIn("Healthy", report)

        # Event breakdown
        self.assertIn("parent parse failure", report)

        # Top offender
        self.assertIn("42.py", report)

        # Crash profile
        self.assertIn("PYTHON:TypeError", report)

    def test_generate_report_no_health_log(self):
        """Test HEALTH section with no health log shows placeholder."""
        self._create_minimal_instance()

        report = generate_report(self.root)

        self.assertIn("HEALTH", report)
        self.assertIn("No health events recorded", report)

    def test_generate_report_empty_health_log(self):
        """Test HEALTH section with empty health log shows placeholder."""
        self._create_minimal_instance()
        self._write_health_events([])

        report = generate_report(self.root)

        self.assertIn("HEALTH", report)
        self.assertIn("No health events recorded", report)

    def test_health_section_shows_waste_rate(self):
        """Test that waste rate is calculated and displayed."""
        self._create_minimal_instance()
        # Create 100 waste events against 1000 total_mutations = 10%
        events = [
            {
                "ts": "...",
                "cat": "mutation_pipeline",
                "event": "child_script_none",
                "parent_id": f"{i}.py",
            }
            for i in range(100)
        ]
        self._write_health_events(events)

        report = generate_report(self.root)

        self.assertIn("Unhealthy", report)
        self.assertIn("10.00%", report)

    def test_health_degraded_grade(self):
        """Test that degraded grade appears at 2-10% waste."""
        self._create_minimal_instance()
        # 50 waste events / 1000 total = 5%
        events = [
            {
                "ts": "...",
                "cat": "mutation_pipeline",
                "event": "child_script_none",
                "parent_id": "x.py",
            }
            for _ in range(50)
        ]
        self._write_health_events(events)

        report = generate_report(self.root)

        self.assertIn("Degraded", report)


if __name__ == "__main__":
    unittest.main()
