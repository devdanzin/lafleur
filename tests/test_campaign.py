import unittest
import json
import tempfile
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch, MagicMock

from lafleur.campaign import (
    CampaignAggregator,
    InstanceData,
    generate_html_report,
    load_json_file,
    load_health_summary,
    load_crash_attribution_summary,
    parse_timestamp,
    format_duration,
    discover_instances,
    main,
    CrashInfo,
    HealthSummary,
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


class TestInstanceData(unittest.TestCase):
    """Tests for InstanceData dataclass."""

    def test_relative_dir_defaults_to_empty(self):
        """Test that relative_dir defaults to empty string."""
        inst = InstanceData(path=Path("/tmp/run1"), name="run1")
        self.assertEqual(inst.relative_dir, "")


class TestSetRelativeDirs(unittest.TestCase):
    """Tests for CampaignAggregator.set_relative_dirs."""

    def test_computes_relative_paths(self):
        """Test that relative paths are computed from campaign root."""
        aggregator = CampaignAggregator([])
        aggregator.instances = [
            InstanceData(path=Path("/campaign/runs/run1"), name="run1"),
            InstanceData(path=Path("/campaign/runs/run2"), name="run2"),
        ]
        aggregator.set_relative_dirs(Path("/campaign"))

        self.assertEqual(aggregator.instances[0].relative_dir, "runs/run1")
        self.assertEqual(aggregator.instances[1].relative_dir, "runs/run2")

    def test_falls_back_to_absolute_when_not_under_root(self):
        """Test fallback to absolute path when instance is not under root."""
        aggregator = CampaignAggregator([])
        aggregator.instances = [
            InstanceData(path=Path("/other/location/run1"), name="run1"),
        ]
        aggregator.set_relative_dirs(Path("/campaign"))

        self.assertEqual(aggregator.instances[0].relative_dir, "/other/location/run1")


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
        # Check Dir column in leaderboard
        self.assertIn("| Dir", report)

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
        self.assertIn("<th>Directory</th>", content)

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

    def test_aggregate_corpus_zero_mean_depth_included(self):
        """Test that a mean depth of 0.0 is included in weighted averages."""
        run_dir = self._create_run("run1", {"total_mutations": 10})
        (run_dir / "corpus_stats.json").write_text(
            json.dumps(
                {
                    "total_files": 50,
                    "lineage_depth_distribution": {"mean": 0.0},
                    "file_size_distribution": {"mean": 0.0},
                }
            )
        )

        aggregator = CampaignAggregator([run_dir])
        aggregator.load_instances()
        aggregator.aggregate()

        # 0.0 * 50 == 0, but file_count_for_avg must still be incremented
        self.assertEqual(aggregator.global_corpus["file_count_for_avg"], 50)
        self.assertAlmostEqual(aggregator.global_corpus["sum_depth"], 0.0)
        self.assertAlmostEqual(aggregator.global_corpus["sum_size"], 0.0)

    def test_aggregate_corpus_mixed_zero_nonzero_depth(self):
        """Test weighted average with one zero-mean and one nonzero-mean instance."""
        run1 = self._create_run("run1", {"total_mutations": 10})
        (run1 / "corpus_stats.json").write_text(
            json.dumps(
                {
                    "total_files": 100,
                    "lineage_depth_distribution": {"mean": 0.0},
                    "file_size_distribution": {"mean": 500.0},
                }
            )
        )
        run2 = self._create_run("run2", {"total_mutations": 20})
        (run2 / "corpus_stats.json").write_text(
            json.dumps(
                {
                    "total_files": 100,
                    "lineage_depth_distribution": {"mean": 4.0},
                    "file_size_distribution": {"mean": 1500.0},
                }
            )
        )

        aggregator = CampaignAggregator([run1, run2])
        aggregator.load_instances()
        aggregator.aggregate()

        # file_count_for_avg = 100 + 100 = 200
        self.assertEqual(aggregator.global_corpus["file_count_for_avg"], 200)
        # sum_depth = 0*100 + 4*100 = 400, avg = 2.0
        self.assertAlmostEqual(aggregator.global_corpus["sum_depth"], 400.0)
        # sum_size = 500*100 + 1500*100 = 200000
        self.assertAlmostEqual(aggregator.global_corpus["sum_size"], 200000.0)

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


class TestDetectInstanceStatus(unittest.TestCase):
    """Test CampaignAggregator._detect_instance_status."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.inst_path = Path(self.temp_dir.name)
        self.logs_dir = self.inst_path / "logs"
        self.logs_dir.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_running_from_fresh_heartbeat(self):
        """Instance is 'Running' when heartbeat is recent."""
        heartbeat_path = self.logs_dir / "heartbeat"
        heartbeat_path.write_text(datetime.now(timezone.utc).isoformat())

        stats = {"last_update_time": "2020-01-01T00:00:00+00:00"}  # ancient
        status = CampaignAggregator._detect_instance_status(self.inst_path, stats)
        self.assertEqual(status, "Running")

    def test_stopped_from_stale_heartbeat(self):
        """Instance is 'Stopped' when heartbeat is older than threshold."""
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        heartbeat_path = self.logs_dir / "heartbeat"
        heartbeat_path.write_text(old_time.isoformat())

        stats = {"last_update_time": old_time.isoformat()}
        status = CampaignAggregator._detect_instance_status(self.inst_path, stats)
        self.assertEqual(status, "Stopped")

    def test_falls_back_to_stats_when_no_heartbeat(self):
        """Falls back to last_update_time when heartbeat file doesn't exist."""
        recent_time = datetime.now(timezone.utc).isoformat()
        stats = {"last_update_time": recent_time}
        status = CampaignAggregator._detect_instance_status(self.inst_path, stats)
        self.assertEqual(status, "Running")

    def test_unknown_when_no_heartbeat_and_no_last_update(self):
        """Returns 'Unknown' when neither heartbeat nor last_update_time exist."""
        stats = {}
        status = CampaignAggregator._detect_instance_status(self.inst_path, stats)
        self.assertEqual(status, "Unknown")

    def test_heartbeat_takes_priority_over_stale_stats(self):
        """Recent heartbeat overrides stale last_update_time."""
        heartbeat_path = self.logs_dir / "heartbeat"
        heartbeat_path.write_text(datetime.now(timezone.utc).isoformat())

        # Stats say ancient, but heartbeat says now — should be Running
        stats = {"last_update_time": "2020-01-01T00:00:00+00:00"}
        status = CampaignAggregator._detect_instance_status(self.inst_path, stats)
        self.assertEqual(status, "Running")

    def test_handles_corrupt_heartbeat_file(self):
        """Corrupt heartbeat file falls through to stats gracefully."""
        heartbeat_path = self.logs_dir / "heartbeat"
        heartbeat_path.write_text("not a timestamp")

        recent_time = datetime.now(timezone.utc).isoformat()
        stats = {"last_update_time": recent_time}
        status = CampaignAggregator._detect_instance_status(self.inst_path, stats)
        self.assertEqual(status, "Running")


class TestLoadHealthSummary(unittest.TestCase):
    """Tests for load_health_summary function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_events(self, events: list[dict]) -> Path:
        """Write a list of event dicts as JSONL."""
        path = self.temp_path / "health_events.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        return path

    def test_returns_none_for_missing_file(self):
        """Returns None when the health log file does not exist."""
        result = load_health_summary(self.temp_path / "nonexistent.jsonl")
        self.assertIsNone(result)

    def test_returns_none_for_empty_file(self):
        """Returns None when the health log file is empty."""
        path = self.temp_path / "health_events.jsonl"
        path.write_text("")
        result = load_health_summary(path)
        self.assertIsNone(result)

    def test_counts_total_events(self):
        """Counts all events correctly."""
        events = [
            {"cat": "mutation_pipeline", "event": "child_script_none"},
            {"cat": "execution", "event": "consecutive_timeouts"},
            {"cat": "corpus_health", "event": "duplicate_rejected"},
        ]
        result = load_health_summary(self._write_events(events))
        self.assertIsNotNone(result)
        self.assertEqual(result["total_events"], 3)

    def test_counts_waste_events(self):
        """Counts only waste event types."""
        events = [
            {"cat": "mutation_pipeline", "event": "parent_parse_failure"},
            {"cat": "mutation_pipeline", "event": "child_script_none"},
            {"cat": "execution", "event": "consecutive_timeouts"},  # Not waste
            {"cat": "mutation_pipeline", "event": "mutation_recursion_error"},
        ]
        result = load_health_summary(self._write_events(events))
        self.assertEqual(result["waste_event_count"], 3)

    def test_counts_by_event_and_category(self):
        """Groups events by event type and category."""
        events = [
            {"cat": "mutation_pipeline", "event": "child_script_none"},
            {"cat": "mutation_pipeline", "event": "child_script_none"},
            {"cat": "execution", "event": "ignored_crash", "reason": "SIGKILL"},
        ]
        result = load_health_summary(self._write_events(events))
        self.assertEqual(result["by_event"]["child_script_none"], 2)
        self.assertEqual(result["by_event"]["ignored_crash"], 1)
        self.assertEqual(result["by_category"]["mutation_pipeline"], 2)
        self.assertEqual(result["by_category"]["execution"], 1)

    def test_builds_crash_profile(self):
        """Tracks ignored crash reasons."""
        events = [
            {"cat": "execution", "event": "ignored_crash", "reason": "SIGKILL"},
            {"cat": "execution", "event": "ignored_crash", "reason": "SIGKILL"},
            {"cat": "execution", "event": "ignored_crash", "reason": "PYTHON_UNCAUGHT"},
        ]
        result = load_health_summary(self._write_events(events))
        self.assertEqual(result["crash_profile"]["SIGKILL"], 2)
        self.assertEqual(result["crash_profile"]["PYTHON_UNCAUGHT"], 1)

    def test_tracks_parent_offenders(self):
        """Tracks parent_ids that cause waste events."""
        events = [
            {"cat": "mutation_pipeline", "event": "child_script_none", "parent_id": "file_a.py"},
            {"cat": "mutation_pipeline", "event": "child_script_none", "parent_id": "file_a.py"},
            {"cat": "mutation_pipeline", "event": "parent_parse_failure", "parent_id": "file_b.py"},
            {"cat": "execution", "event": "ignored_crash", "reason": "X"},  # Not waste
        ]
        result = load_health_summary(self._write_events(events))
        self.assertEqual(result["parent_offenders"]["file_a.py"], 2)
        self.assertEqual(result["parent_offenders"]["file_b.py"], 1)

    def test_skips_invalid_json_lines(self):
        """Gracefully skips malformed JSONL lines."""
        path = self.temp_path / "health_events.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"cat": "execution", "event": "consecutive_timeouts"}) + "\n")
            f.write("not valid json\n")
            f.write(
                json.dumps({"cat": "execution", "event": "ignored_crash", "reason": "X"}) + "\n"
            )
        result = load_health_summary(path)
        self.assertEqual(result["total_events"], 2)


class TestFleetHealthAggregation(unittest.TestCase):
    """Tests for fleet health aggregation on CampaignAggregator."""

    def _make_summary(
        self,
        total_events: int = 10,
        waste: int = 1,
        by_event: dict | None = None,
        by_category: dict | None = None,
        crash_profile: dict | None = None,
        parent_offenders: dict | None = None,
    ) -> HealthSummary:
        from collections import Counter

        return {
            "total_events": total_events,
            "by_event": Counter(by_event or {}),
            "by_category": Counter(by_category or {}),
            "waste_event_count": waste,
            "crash_profile": Counter(crash_profile or {}),
            "parent_offenders": Counter(parent_offenders or {}),
        }

    def test_aggregate_health_sums_totals(self):
        """Total events and waste are summed across instances."""
        agg = CampaignAggregator([])
        agg.instances = [
            InstanceData(
                path=Path("/r/run1"),
                name="run1",
                health_summary=self._make_summary(total_events=10, waste=2),
            ),
            InstanceData(
                path=Path("/r/run2"),
                name="run2",
                health_summary=self._make_summary(total_events=5, waste=1),
            ),
        ]
        agg.aggregate()
        self.assertEqual(agg.global_health["total_events"], 15)
        self.assertEqual(agg.global_health["waste_events"], 3)

    def test_aggregate_health_merges_counters(self):
        """Event and category counters are merged across instances."""
        agg = CampaignAggregator([])
        agg.instances = [
            InstanceData(
                path=Path("/r/run1"),
                name="run1",
                health_summary=self._make_summary(
                    by_event={"child_script_none": 3},
                    by_category={"mutation_pipeline": 3},
                ),
            ),
            InstanceData(
                path=Path("/r/run2"),
                name="run2",
                health_summary=self._make_summary(
                    by_event={"child_script_none": 2, "ignored_crash": 1},
                    by_category={"mutation_pipeline": 2, "execution": 1},
                ),
            ),
        ]
        agg.aggregate()
        self.assertEqual(agg.global_health["by_event"]["child_script_none"], 5)
        self.assertEqual(agg.global_health["by_event"]["ignored_crash"], 1)
        self.assertEqual(agg.global_health["by_category"]["mutation_pipeline"], 5)

    def test_aggregate_health_prefixes_offenders(self):
        """Parent offenders are prefixed with instance name."""
        agg = CampaignAggregator([])
        agg.instances = [
            InstanceData(
                path=Path("/r/run1"),
                name="run1",
                health_summary=self._make_summary(parent_offenders={"file_a.py": 5}),
            ),
            InstanceData(
                path=Path("/r/run2"),
                name="run2",
                health_summary=self._make_summary(parent_offenders={"file_a.py": 3}),
            ),
        ]
        agg.aggregate()
        self.assertEqual(agg.global_health["top_offenders"]["run1:file_a.py"], 5)
        self.assertEqual(agg.global_health["top_offenders"]["run2:file_a.py"], 3)

    def test_aggregate_health_merges_crash_profile(self):
        """Crash profile reasons are merged across instances."""
        agg = CampaignAggregator([])
        agg.instances = [
            InstanceData(
                path=Path("/r/run1"),
                name="run1",
                health_summary=self._make_summary(crash_profile={"SIGKILL": 2}),
            ),
            InstanceData(
                path=Path("/r/run2"),
                name="run2",
                health_summary=self._make_summary(crash_profile={"SIGKILL": 1, "UNCAUGHT": 3}),
            ),
        ]
        agg.aggregate()
        self.assertEqual(agg.global_health["crash_profile"]["SIGKILL"], 3)
        self.assertEqual(agg.global_health["crash_profile"]["UNCAUGHT"], 3)

    def test_aggregate_health_skips_none_summary(self):
        """Instances without health_summary are silently skipped."""
        agg = CampaignAggregator([])
        agg.instances = [
            InstanceData(path=Path("/r/run1"), name="run1", health_summary=None),
            InstanceData(
                path=Path("/r/run2"),
                name="run2",
                health_summary=self._make_summary(total_events=7, waste=2),
            ),
        ]
        agg.aggregate()
        self.assertEqual(agg.global_health["total_events"], 7)
        self.assertEqual(agg.global_health["waste_events"], 2)

    def test_get_fleet_waste_rate(self):
        """Fleet waste rate is waste_events / total_executions."""
        agg = CampaignAggregator([])
        agg.totals["total_executions"] = 1000
        agg.global_health["waste_events"] = 50
        self.assertAlmostEqual(agg.get_fleet_waste_rate(), 0.05)

    def test_get_fleet_waste_rate_zero_executions(self):
        """Returns 0.0 when no executions have been performed."""
        agg = CampaignAggregator([])
        agg.totals["total_executions"] = 0
        self.assertEqual(agg.get_fleet_waste_rate(), 0.0)

    def test_get_top_offenders(self):
        """Returns top N offenders by count."""
        agg = CampaignAggregator([])
        agg.global_health["top_offenders"]["run1:a.py"] = 10
        agg.global_health["top_offenders"]["run2:b.py"] = 5
        agg.global_health["top_offenders"]["run1:c.py"] = 1
        top = agg.get_top_offenders(2)
        self.assertEqual(len(top), 2)
        self.assertEqual(top[0], ("run1:a.py", 10))


class TestHealthGrade(unittest.TestCase):
    """Tests for CampaignAggregator.health_grade static method."""

    def test_healthy_below_two_percent(self):
        """Waste rate below 2% is Healthy/OK."""
        short, long = CampaignAggregator.health_grade(0.01)
        self.assertEqual(short, "OK")
        self.assertEqual(long, "Healthy")

    def test_degraded_between_two_and_ten_percent(self):
        """Waste rate between 2% and 10% is Degraded/WARN."""
        short, long = CampaignAggregator.health_grade(0.05)
        self.assertEqual(short, "WARN")
        self.assertEqual(long, "Degraded")

    def test_unhealthy_above_ten_percent(self):
        """Waste rate above 10% is Unhealthy/BAD."""
        short, long = CampaignAggregator.health_grade(0.15)
        self.assertEqual(short, "BAD")
        self.assertEqual(long, "Unhealthy")


class TestLoadCrashAttributionSummary(unittest.TestCase):
    """Test crash attribution JSONL parsing."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.log_path = self.root / "crash_attribution.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_entries(self, entries):
        self.log_path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")

    def test_returns_none_for_missing_file(self):
        result = load_crash_attribution_summary(self.root / "nonexistent.jsonl")
        self.assertIsNone(result)

    def test_returns_none_for_empty_file(self):
        self.log_path.write_text("", encoding="utf-8")
        result = load_crash_attribution_summary(self.log_path)
        self.assertIsNone(result)

    def test_parses_single_entry(self):
        self._write_entries(
            [
                {
                    "fingerprint": "ASSERT:test",
                    "parent_id": "42.py",
                    "direct": {"strategy": "havoc", "transformers": ["T1", "T2"]},
                    "lineage_depth": 3,
                    "lineage_strategies": ["spam", "deterministic"],
                    "lineage_transformers": ["T3", "T4"],
                }
            ]
        )

        result = load_crash_attribution_summary(self.log_path)

        self.assertIsNotNone(result)
        self.assertEqual(result["total_attributed_crashes"], 1)
        self.assertEqual(result["unique_fingerprints"], 1)
        self.assertAlmostEqual(result["avg_lineage_depth"], 3.0)

        # Direct: T1 and T2 each get 5 points
        self.assertEqual(result["combined_transformer_scores"]["T1"], 5)
        self.assertEqual(result["combined_transformer_scores"]["T2"], 5)
        # Lineage: T3 and T4 each get 2 points
        self.assertEqual(result["combined_transformer_scores"]["T3"], 2)
        self.assertEqual(result["combined_transformer_scores"]["T4"], 2)
        # Strategy: havoc gets 5 (direct), spam and deterministic get 2 each (lineage)
        self.assertEqual(result["combined_strategy_scores"]["havoc"], 5)
        self.assertEqual(result["combined_strategy_scores"]["spam"], 2)

    def test_parses_multiple_entries(self):
        self._write_entries(
            [
                {
                    "fingerprint": "ASSERT:crash1",
                    "direct": {"strategy": "havoc", "transformers": ["T1"]},
                    "lineage_depth": 2,
                    "lineage_strategies": ["spam"],
                    "lineage_transformers": ["T2"],
                },
                {
                    "fingerprint": "ASSERT:crash2",
                    "direct": {"strategy": "havoc", "transformers": ["T1"]},
                    "lineage_depth": 4,
                    "lineage_strategies": ["havoc", "deterministic"],
                    "lineage_transformers": ["T1", "T3"],
                },
            ]
        )

        result = load_crash_attribution_summary(self.log_path)

        self.assertEqual(result["total_attributed_crashes"], 2)
        self.assertEqual(result["unique_fingerprints"], 2)
        self.assertAlmostEqual(result["avg_lineage_depth"], 3.0)

        # T1: 2 direct (2*5=10) + 1 lineage (1*2=2) = 12
        self.assertEqual(result["combined_transformer_scores"]["T1"], 12)
        # havoc: 2 direct (2*5=10) + 1 lineage (1*2=2) = 12
        self.assertEqual(result["combined_strategy_scores"]["havoc"], 12)

    def test_deduplicates_fingerprints(self):
        self._write_entries(
            [
                {
                    "fingerprint": "ASSERT:same",
                    "direct": {"strategy": "havoc", "transformers": []},
                    "lineage_depth": 1,
                    "lineage_strategies": [],
                    "lineage_transformers": [],
                },
                {
                    "fingerprint": "ASSERT:same",
                    "direct": {"strategy": "spam", "transformers": []},
                    "lineage_depth": 2,
                    "lineage_strategies": [],
                    "lineage_transformers": [],
                },
            ]
        )

        result = load_crash_attribution_summary(self.log_path)

        self.assertEqual(result["total_attributed_crashes"], 2)
        self.assertEqual(result["unique_fingerprints"], 1)  # Same fingerprint

    def test_skips_malformed_lines(self):
        self.log_path.write_text(
            "not json\n"
            + json.dumps(
                {
                    "fingerprint": "ASSERT:ok",
                    "direct": {"strategy": "havoc", "transformers": ["T1"]},
                    "lineage_depth": 0,
                    "lineage_strategies": [],
                    "lineage_transformers": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )

        result = load_crash_attribution_summary(self.log_path)

        self.assertEqual(result["total_attributed_crashes"], 1)


class TestCampaignCrashAttributionAggregation(unittest.TestCase):
    """Test fleet-level crash attribution aggregation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.runs_dir = self.root / "runs"
        self.runs_dir.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_instance(self, name, stats=None, attribution_entries=None):
        """Create an instance dir with optional crash attribution log."""
        inst_dir = self.runs_dir / name
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)

        metadata = {"instance_name": name, "run_id": f"run-{name}"}
        (logs_dir / "run_metadata.json").write_text(json.dumps(metadata))

        if stats:
            (inst_dir / "fuzz_run_stats.json").write_text(json.dumps(stats))

        if attribution_entries:
            log_path = logs_dir / "crash_attribution.jsonl"
            log_path.write_text(
                "\n".join(json.dumps(e) for e in attribution_entries),
                encoding="utf-8",
            )

        return inst_dir

    def test_aggregates_across_instances(self):
        inst1 = self._create_instance(
            "inst1",
            {"total_mutations": 100},
            [
                {
                    "fingerprint": "ASSERT:crash1",
                    "direct": {"strategy": "havoc", "transformers": ["T1"]},
                    "lineage_depth": 2,
                    "lineage_strategies": [],
                    "lineage_transformers": [],
                },
            ],
        )
        inst2 = self._create_instance(
            "inst2",
            {"total_mutations": 200},
            [
                {
                    "fingerprint": "ASSERT:crash2",
                    "direct": {"strategy": "spam", "transformers": ["T2"]},
                    "lineage_depth": 4,
                    "lineage_strategies": ["havoc"],
                    "lineage_transformers": ["T1"],
                },
            ],
        )

        aggregator = CampaignAggregator([inst1, inst2])
        aggregator.load_instances()
        aggregator.aggregate()

        ca = aggregator.fleet_crash_attribution
        self.assertIsNotNone(ca)
        self.assertEqual(ca["total_attributed_crashes"], 2)
        self.assertEqual(ca["unique_fingerprints"], 2)
        # T1: 1 direct (5) + 1 lineage (2) = 7
        self.assertEqual(ca["combined_transformer_scores"]["T1"], 7)
        # T2: 1 direct (5) = 5
        self.assertEqual(ca["combined_transformer_scores"]["T2"], 5)

    def test_no_attribution_data(self):
        inst = self._create_instance("inst1", {"total_mutations": 100})

        aggregator = CampaignAggregator([inst])
        aggregator.load_instances()
        aggregator.aggregate()

        self.assertIsNone(aggregator.fleet_crash_attribution)

    def test_report_includes_section(self):
        inst = self._create_instance(
            "inst1",
            {
                "total_mutations": 100,
                "start_time": "2025-01-01T00:00:00Z",
                "last_update_time": "2025-01-01T01:00:00Z",
            },
            [
                {
                    "fingerprint": "ASSERT:test",
                    "direct": {"strategy": "havoc", "transformers": ["TypeInstabilityInjector"]},
                    "lineage_depth": 3,
                    "lineage_strategies": ["spam"],
                    "lineage_transformers": ["OperatorSwapper"],
                },
            ],
        )

        aggregator = CampaignAggregator([inst])
        aggregator.load_instances()
        aggregator.aggregate()

        report = aggregator.generate_report()
        self.assertIn("CRASH-PRODUCTIVE MUTATORS", report)
        self.assertIn("TypeInstabilityInjector", report)
        self.assertIn("Attributed Crashes:", report)

    def test_report_omits_section_when_no_data(self):
        inst = self._create_instance("inst1", {"total_mutations": 100})

        aggregator = CampaignAggregator([inst])
        aggregator.load_instances()
        aggregator.aggregate()

        report = aggregator.generate_report()
        self.assertNotIn("CRASH-PRODUCTIVE MUTATORS", report)

    def test_html_report_includes_section(self):
        inst = self._create_instance(
            "inst1",
            {
                "total_mutations": 100,
                "start_time": "2025-01-01T00:00:00Z",
                "last_update_time": "2025-01-01T01:00:00Z",
            },
            [
                {
                    "fingerprint": "ASSERT:test",
                    "direct": {"strategy": "havoc", "transformers": ["T1"]},
                    "lineage_depth": 1,
                    "lineage_strategies": [],
                    "lineage_transformers": [],
                },
            ],
        )

        aggregator = CampaignAggregator([inst])
        aggregator.load_instances()
        aggregator.aggregate()

        html_content = generate_html_report(aggregator)
        self.assertIn("Crash-Productive Mutators", html_content)
        self.assertIn("Attributed Crashes", html_content)
