import unittest
import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch, MagicMock

from lafleur.campaign import (
    CampaignAggregator,
    generate_html_report,
    load_json_file,
    parse_timestamp,
    format_duration,
    discover_instances,
    main,
    CrashInfo,
)


class TestLoadJsonFile(unittest.TestCase):
    """Tests for load_json_file helper function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_loads_valid_json(self):
        """Test loading valid JSON file."""
        json_path = self.temp_path / "test.json"
        data = {"key": "value", "number": 42}
        json_path.write_text(json.dumps(data))

        result = load_json_file(json_path)
        self.assertEqual(result, data)

    def test_returns_none_for_nonexistent_file(self):
        """Test returning None for non-existent file."""
        result = load_json_file(self.temp_path / "nonexistent.json")
        self.assertIsNone(result)

    def test_returns_none_for_invalid_json(self):
        """Test returning None for invalid JSON."""
        json_path = self.temp_path / "invalid.json"
        json_path.write_text("not valid json {{{")

        result = load_json_file(json_path)
        self.assertIsNone(result)


class TestParseTimestamp(unittest.TestCase):
    """Tests for parse_timestamp helper function."""

    def test_parses_iso_timestamp(self):
        """Test parsing standard ISO timestamp."""
        result = parse_timestamp("2025-01-01T12:00:00+00:00")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2025)

    def test_parses_z_suffix(self):
        """Test parsing timestamp with Z suffix."""
        result = parse_timestamp("2025-01-01T12:00:00Z")
        self.assertIsNotNone(result)

    def test_returns_none_for_empty_string(self):
        """Test returning None for empty string."""
        result = parse_timestamp("")
        self.assertIsNone(result)

    def test_returns_none_for_none(self):
        """Test returning None for None input."""
        result = parse_timestamp(None)
        self.assertIsNone(result)

    def test_returns_none_for_invalid_format(self):
        """Test returning None for invalid format."""
        result = parse_timestamp("not a timestamp")
        self.assertIsNone(result)


class TestFormatDuration(unittest.TestCase):
    """Tests for format_duration helper function."""

    def test_formats_seconds(self):
        """Test formatting seconds only."""
        result = format_duration(45)
        self.assertEqual(result, "45s")

    def test_formats_minutes_and_seconds(self):
        """Test formatting minutes and seconds."""
        result = format_duration(125)
        self.assertEqual(result, "2m 5s")

    def test_formats_hours(self):
        """Test formatting hours."""
        result = format_duration(7325)
        self.assertEqual(result, "2h 2m 5s")

    def test_formats_days(self):
        """Test formatting days."""
        result = format_duration(90061)
        self.assertEqual(result, "1d 1h 1m 1s")

    def test_formats_zero(self):
        """Test formatting zero duration."""
        result = format_duration(0)
        self.assertEqual(result, "0s")

    def test_handles_negative(self):
        """Test handling negative duration."""
        result = format_duration(-10)
        self.assertEqual(result, "N/A")


class TestDiscoverInstances(unittest.TestCase):
    """Tests for discover_instances function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_returns_empty_for_nonexistent(self):
        """Test returning empty for non-existent directory."""
        result = discover_instances(self.root / "nonexistent")
        self.assertEqual(result, [])

    def test_discovers_root_as_instance(self):
        """Test discovering root directory as an instance."""
        logs_dir = self.root / "logs"
        logs_dir.mkdir()
        (logs_dir / "run_metadata.json").write_text("{}")

        result = discover_instances(self.root)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.root)

    def test_discovers_subdirectories(self):
        """Test discovering instance subdirectories."""
        for name in ["run1", "run2"]:
            inst_dir = self.root / name
            logs_dir = inst_dir / "logs"
            logs_dir.mkdir(parents=True)
            (logs_dir / "run_metadata.json").write_text("{}")

        result = discover_instances(self.root)
        self.assertEqual(len(result), 2)


class TestCrashInfo(unittest.TestCase):
    """Tests for CrashInfo dataclass."""

    def test_default_values(self):
        """Test default values."""
        info = CrashInfo()
        self.assertEqual(info.count, 0)
        self.assertEqual(info.finding_instances, set())
        self.assertIsNone(info.first_found)
        self.assertEqual(info.status_label, "NEW")


class TestCampaignAggregator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.runs_dir = self.root / "runs"
        self.runs_dir.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_run(self, name, stats):
        """Helper to create a fake run directory with stats."""
        run_dir = self.runs_dir / name
        run_dir.mkdir()

        # Create run_stats.json (Implementation looks for fuzz_run_stats.json)
        (run_dir / "fuzz_run_stats.json").write_text(json.dumps(stats), encoding="utf-8")

        # Create metadata (needed for table)
        meta = {
            "run_id": name,
            "host": "test-host",
            "python_version": "3.14.0",
            "instance_name": name,
        }
        logs_dir = run_dir / "logs"
        logs_dir.mkdir()
        (logs_dir / "run_metadata.json").write_text(json.dumps(meta), encoding="utf-8")

        # Create empty corpus stats to avoid load errors
        (run_dir / "corpus_stats.json").write_text(json.dumps({}), encoding="utf-8")

        return run_dir

    def test_aggregation_logic(self):
        """Test that metrics are summed correctly across runs."""
        # Run 1: 10 execs, 1 crash
        self._create_run(
            "run1",
            {
                "total_mutations": 10,
                "global_edges": 100,
                "crashes_found": 1,
                "new_coverage_finds": 5,
                "start_time": "2025-01-01T10:00:00Z",
                "last_update_time": "2025-01-01T10:00:10Z",  # 10 seconds
            },
        )

        # Run 2: 20 execs, 0 crashes
        self._create_run(
            "run2",
            {
                "total_mutations": 20,
                "global_edges": 150,
                "crashes_found": 0,
                "new_coverage_finds": 2,
                "start_time": "2025-01-01T10:00:00Z",
                "last_update_time": "2025-01-01T10:00:10Z",  # 10 seconds
            },
        )

        # Initialize with list of paths
        aggregator = CampaignAggregator([self.runs_dir / "run1", self.runs_dir / "run2"])
        aggregator.load_instances()
        aggregator.aggregate()

        # Generate report (Method is generate_report, not generate_text_report)
        report = aggregator.generate_report()

        # Check totals
        self.assertIn("Executions:     30", report)  # 10 + 20
        # Check rates
        self.assertIn("Fleet Speed:", report)

    def test_html_generation(self):
        """Test that HTML report is generated without error."""
        self._create_run("run1", {"total_mutations": 10})

        aggregator = CampaignAggregator([self.runs_dir / "run1"])
        aggregator.load_instances()
        aggregator.aggregate()

        output_path = self.root / "report.html"

        # generate_html_report is a module-level function, not a class method
        content = generate_html_report(aggregator)
        output_path.write_text(content, encoding="utf-8")

        self.assertTrue(output_path.exists())
        self.assertIn('<html lang="en">', content)
        self.assertIn("Lafleur Campaign", content)

    def test_empty_instances(self):
        """Test report with no valid instances."""
        aggregator = CampaignAggregator([])
        aggregator.load_instances()
        aggregator.aggregate()

        report = aggregator.generate_report()
        self.assertIn("No valid instances found", report)

    def test_get_fleet_speed_zero_duration(self):
        """Test fleet speed calculation with zero duration."""
        aggregator = CampaignAggregator([])
        aggregator.totals["total_duration_secs"] = 0
        aggregator.totals["total_executions"] = 100

        speed = aggregator.get_fleet_speed()
        self.assertEqual(speed, 0.0)

    def test_get_core_hours(self):
        """Test core hours calculation."""
        aggregator = CampaignAggregator([])
        aggregator.totals["total_duration_secs"] = 7200  # 2 hours

        hours = aggregator.get_core_hours()
        self.assertEqual(hours, 2.0)

    def test_get_global_sterile_rate_zero_files(self):
        """Test sterile rate with zero files."""
        aggregator = CampaignAggregator([])
        aggregator.global_corpus["total_files"] = 0

        rate = aggregator.get_global_sterile_rate()
        self.assertEqual(rate, 0.0)

    def test_get_avg_lineage_depth_zero_files(self):
        """Test average depth with zero files."""
        aggregator = CampaignAggregator([])
        aggregator.global_corpus["file_count_for_avg"] = 0

        depth = aggregator.get_avg_lineage_depth()
        self.assertEqual(depth, 0.0)

    def test_get_top_strategies(self):
        """Test getting top strategies."""
        aggregator = CampaignAggregator([])
        aggregator.global_corpus["strategy_counter"]["sniper"] = 10
        aggregator.global_corpus["strategy_counter"]["generic"] = 5

        top = aggregator.get_top_strategies(2)
        self.assertEqual(top[0], ("sniper", 10))
        self.assertEqual(top[1], ("generic", 5))

    def test_get_top_mutators(self):
        """Test getting top mutators."""
        aggregator = CampaignAggregator([])
        aggregator.global_corpus["mutator_counter"]["OperatorSwapper"] = 20
        aggregator.global_corpus["mutator_counter"]["ConstantPerturbator"] = 15

        top = aggregator.get_top_mutators(2)
        self.assertEqual(top[0], ("OperatorSwapper", 20))

    def test_skips_invalid_instance(self):
        """Test that instances without metadata are skipped."""
        # Create instance without metadata
        invalid_dir = self.runs_dir / "invalid"
        invalid_dir.mkdir()

        aggregator = CampaignAggregator([invalid_dir])
        aggregator.load_instances()

        self.assertEqual(len(aggregator.instances), 0)

    def test_aggregate_crashes_with_invalid_timestamp(self):
        """Test crash aggregation with invalid timestamp."""
        run_dir = self._create_run("run1", {"total_mutations": 10})

        # Create crash with invalid timestamp
        crash_dir = run_dir / "crashes" / "crash1"
        crash_dir.mkdir(parents=True)
        (crash_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "ASSERT:test", "timestamp": "invalid"})
        )

        aggregator = CampaignAggregator([run_dir])
        aggregator.load_instances()
        aggregator.aggregate()

        self.assertEqual(len(aggregator.global_crashes), 1)

    def test_aggregate_corpus_with_distributions(self):
        """Test corpus aggregation with distribution data."""
        run_dir = self._create_run("run1", {"total_mutations": 10})
        (run_dir / "corpus_stats.json").write_text(
            json.dumps(
                {
                    "total_files": 100,
                    "sterile_count": 10,
                    "lineage_depth_distribution": {"mean": 5.0},
                    "file_size_distribution": {"mean": 1000.0},
                    "successful_strategies": {"sniper": 5},
                    "successful_mutators": {"OperatorSwapper": 10},
                }
            )
        )

        aggregator = CampaignAggregator([run_dir])
        aggregator.load_instances()
        aggregator.aggregate()

        self.assertEqual(aggregator.global_corpus["total_files"], 100)
        self.assertEqual(aggregator.global_corpus["total_sterile"], 10)

    def test_enrich_crashes_from_registry(self):
        """Test enriching crashes with registry data."""
        run_dir = self._create_run("run1", {"total_mutations": 10})

        # Create crash
        crash_dir = run_dir / "crashes" / "crash1"
        crash_dir.mkdir(parents=True)
        (crash_dir / "metadata.json").write_text(json.dumps({"fingerprint": "ASSERT:test"}))

        aggregator = CampaignAggregator([run_dir])
        aggregator.load_instances()
        aggregator.aggregate()

        # Mock registry
        mock_registry = MagicMock()
        mock_registry.get_crash_context.return_value = {
            "triage_status": "REPORTED",
            "crash_status": "FIXED",
            "issue_number": 123,
            "issue_url": "https://example.com/123",
            "title": "Test Bug",
        }

        aggregator.enrich_crashes_from_registry(mock_registry)

        crash_info = aggregator.global_crashes["ASSERT:test"]
        self.assertEqual(crash_info.status_label, "REGRESSION")
        self.assertEqual(crash_info.issue_number, 123)

    def test_enrich_crashes_known_status(self):
        """Test enriching crashes with KNOWN status."""
        aggregator = CampaignAggregator([])
        aggregator.global_crashes["ASSERT:test"] = CrashInfo()

        mock_registry = MagicMock()
        mock_registry.get_crash_context.return_value = {
            "triage_status": "TRIAGED",
            "issue_number": 456,
        }

        aggregator.enrich_crashes_from_registry(mock_registry)
        self.assertEqual(aggregator.global_crashes["ASSERT:test"].status_label, "KNOWN")

    def test_enrich_crashes_noise_status(self):
        """Test enriching crashes with NOISE status."""
        aggregator = CampaignAggregator([])
        aggregator.global_crashes["ASSERT:test"] = CrashInfo()

        mock_registry = MagicMock()
        mock_registry.get_crash_context.return_value = {
            "triage_status": "IGNORED",
        }

        aggregator.enrich_crashes_from_registry(mock_registry)
        self.assertEqual(aggregator.global_crashes["ASSERT:test"].status_label, "NOISE")

    def test_report_with_many_instances(self):
        """Test report generation with more than 3 instances."""
        for i in range(5):
            self._create_run(f"run{i}", {"total_mutations": 10})

        aggregator = CampaignAggregator([self.runs_dir / f"run{i}" for i in range(5)])
        aggregator.load_instances()
        aggregator.aggregate()

        report = aggregator.generate_report()
        self.assertIn("...", report)  # Truncated instance list

    def test_report_with_crashes(self):
        """Test report generation with crashes."""
        run_dir = self._create_run("run1", {"total_mutations": 10})

        # Create multiple crashes
        for i in range(20):
            crash_dir = run_dir / "crashes" / f"crash{i}"
            crash_dir.mkdir(parents=True)
            (crash_dir / "metadata.json").write_text(
                json.dumps({"fingerprint": f"ASSERT:test{i}", "timestamp": "20250101_120000"})
            )

        aggregator = CampaignAggregator([run_dir])
        aggregator.load_instances()
        aggregator.aggregate()

        report = aggregator.generate_report()
        self.assertIn("GLOBAL CRASH TABLE", report)
        self.assertIn("and 5 more unique fingerprints", report)  # 20 - 15 = 5


class TestMain(unittest.TestCase):
    """Tests for main CLI entry point."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exits_with_no_instances(self):
        """Test exit when no instances found."""
        empty_dir = self.root / "empty"
        empty_dir.mkdir()

        with patch("sys.argv", ["campaign", str(empty_dir)]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 1)

    def test_runs_with_valid_instance(self):
        """Test successful run with valid instance."""
        inst_dir = self.root / "instance"
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "run_metadata.json").write_text(json.dumps({"instance_name": "test"}))
        (inst_dir / "fuzz_run_stats.json").write_text(json.dumps({"total_mutations": 10}))
        (inst_dir / "corpus_stats.json").write_text("{}")

        captured_output = StringIO()
        with patch("sys.argv", ["campaign", str(self.root)]):
            with patch("sys.stdout", captured_output):
                main()

        output = captured_output.getvalue()
        self.assertIn("LAFLEUR CAMPAIGN REPORT", output)

    def test_generates_html_report(self):
        """Test HTML report generation."""
        inst_dir = self.root / "instance"
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "run_metadata.json").write_text(json.dumps({"instance_name": "test"}))
        (inst_dir / "fuzz_run_stats.json").write_text(json.dumps({"total_mutations": 10}))
        (inst_dir / "corpus_stats.json").write_text("{}")

        html_path = self.root / "report.html"

        with patch("sys.argv", ["campaign", str(self.root), "--html", str(html_path)]):
            main()

        self.assertTrue(html_path.exists())

    def test_warns_on_missing_registry(self):
        """Test warning when registry file not found."""
        inst_dir = self.root / "instance"
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "run_metadata.json").write_text(json.dumps({"instance_name": "test"}))
        (inst_dir / "fuzz_run_stats.json").write_text(json.dumps({"total_mutations": 10}))
        (inst_dir / "corpus_stats.json").write_text("{}")

        captured_stderr = StringIO()
        with patch("sys.argv", ["campaign", str(self.root), "--registry", "nonexistent.db"]):
            with patch("sys.stderr", captured_stderr):
                main()

        stderr_output = captured_stderr.getvalue()
        self.assertIn("Registry not found", stderr_output)
