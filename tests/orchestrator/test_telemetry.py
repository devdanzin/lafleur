"""Tests for TelemetryManager extracted from ArtifactManager."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.artifacts import TelemetryManager


class TestUpdateAndSaveRunStats(unittest.TestCase):
    """Test update_and_save_run_stats method."""

    def setUp(self):
        self.run_stats = {}
        self.coverage_manager = MagicMock()
        self.coverage_manager.state = {
            "per_file_coverage": {
                "file1.py": {},
                "file2.py": {},
                "file3.py": {},
            },
            "global_coverage": {
                "uops": {1: 5, 2: 10},
                "edges": {3: 15, 4: 20, 5: 25},
                "rare_events": {6: 1},
            },
        }
        self.corpus_manager = MagicMock()
        self.corpus_manager.corpus_file_counter = 123

        self.telemetry_manager = TelemetryManager(
            run_stats=self.run_stats,
            coverage_manager=self.coverage_manager,
            corpus_manager=self.corpus_manager,
            score_tracker=MagicMock(),
            timeseries_log_path=Path("/tmp/timeseries.jsonl"),
        )

    def test_update_and_save_run_stats_updates_fields(self):
        """Verify all expected fields are set in run_stats after update."""
        with patch("lafleur.artifacts.save_run_stats"):
            with patch("lafleur.artifacts.generate_corpus_stats"):
                self.telemetry_manager.update_and_save_run_stats(global_seed_counter=42)

        self.assertIn("last_update_time", self.run_stats)
        self.assertEqual(self.run_stats["corpus_size"], 3)
        self.assertEqual(self.run_stats["global_uops"], 2)
        self.assertEqual(self.run_stats["global_edges"], 3)
        self.assertEqual(self.run_stats["global_rare_events"], 1)
        self.assertEqual(self.run_stats["global_seed_counter"], 42)
        self.assertEqual(self.run_stats["corpus_file_counter"], 123)

    def test_update_and_save_run_stats_calls_save(self):
        """Verify save_run_stats and generate_corpus_stats are called."""
        with patch("lafleur.artifacts.save_run_stats") as mock_save:
            with patch("lafleur.artifacts.generate_corpus_stats") as mock_corpus_stats:
                self.telemetry_manager.update_and_save_run_stats(global_seed_counter=42)

                mock_save.assert_called_once_with(self.run_stats)
                mock_corpus_stats.assert_called_once_with(self.corpus_manager)


class TestLogTimeseries(unittest.TestCase):
    """Test log_timeseries_datapoint method."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = Path(self.tmpdir) / "timeseries.jsonl"

        self.run_stats = {"total_mutations": 10, "crashes_found": 1}
        self.coverage_manager = MagicMock()
        self.coverage_manager.state = {"per_file_coverage": {"f1.py": {}}}
        self.corpus_manager = MagicMock()
        self.score_tracker = MagicMock()

        self.telemetry_manager = TelemetryManager(
            run_stats=self.run_stats,
            coverage_manager=self.coverage_manager,
            corpus_manager=self.corpus_manager,
            score_tracker=self.score_tracker,
            timeseries_log_path=self.log_path,
        )

    def test_log_timeseries_datapoint_writes_jsonl(self):
        """Verify a valid JSONL line is written to the log file."""
        with (
            patch("lafleur.artifacts.psutil.getloadavg", return_value=(1.5, 1.0, 0.5)),
            patch("lafleur.artifacts.psutil.Process") as mock_proc,
            patch("lafleur.artifacts.psutil.disk_usage") as mock_disk,
            patch("lafleur.artifacts.CORPUS_DIR", new=Path(self.tmpdir)),
        ):
            mock_proc.return_value.memory_info.return_value.rss = 100 * 1024 * 1024
            mock_disk.return_value.percent = 42.0

            self.telemetry_manager.log_timeseries_datapoint()

        lines = self.log_path.read_text().strip().split("\n")
        self.assertEqual(len(lines), 1)

        datapoint = json.loads(lines[0])
        self.assertIn("timestamp", datapoint)
        self.assertEqual(datapoint["total_mutations"], 10)
        self.assertEqual(datapoint["crashes_found"], 1)
        self.assertEqual(datapoint["system_load_1min"], 1.5)
        self.assertAlmostEqual(datapoint["process_rss_mb"], 100.0)
        self.assertEqual(datapoint["disk_usage_percent"], 42.0)

    def test_log_timeseries_datapoint_calls_save_telemetry(self):
        """Verify score_tracker.save_telemetry() is called."""
        with (
            patch("lafleur.artifacts.psutil.getloadavg", return_value=(1.0, 1.0, 1.0)),
            patch("lafleur.artifacts.psutil.Process") as mock_proc,
            patch("lafleur.artifacts.psutil.disk_usage") as mock_disk,
            patch("lafleur.artifacts.CORPUS_DIR", new=Path(self.tmpdir)),
        ):
            mock_proc.return_value.memory_info.return_value.rss = 50 * 1024 * 1024
            mock_disk.return_value.percent = 10.0

            self.telemetry_manager.log_timeseries_datapoint()

        self.score_tracker.save_telemetry.assert_called_once()


class TestCorpusSizeCache(unittest.TestCase):
    """Test _get_corpus_size_mb caching behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create some fake corpus files
        (Path(self.tmpdir) / "file1.py").write_text("x = 1")
        (Path(self.tmpdir) / "file2.py").write_text("y = 2")

        self.coverage_manager = MagicMock()
        self.coverage_manager.state = {
            "per_file_coverage": {"file1.py": {}, "file2.py": {}},
        }

        self.telemetry_manager = TelemetryManager(
            run_stats={},
            coverage_manager=self.coverage_manager,
            corpus_manager=MagicMock(),
            score_tracker=MagicMock(),
            timeseries_log_path=Path("/tmp/ts.jsonl"),
        )

    def test_corpus_size_cache_avoids_rescan(self):
        """Verify second call with same file count uses cached value."""
        with patch("lafleur.artifacts.CORPUS_DIR", new=Path(self.tmpdir)):
            result1 = self.telemetry_manager._get_corpus_size_mb()
            self.assertIsNotNone(result1)

            # Modify a file on disk — cache should NOT notice
            (Path(self.tmpdir) / "file1.py").write_text("x = 1" * 1000)

            result2 = self.telemetry_manager._get_corpus_size_mb()
            # Same cached value, not the new larger size
            self.assertEqual(result1, result2)

    def test_corpus_size_cache_invalidates_on_file_count_change(self):
        """Verify cache is invalidated when per_file_coverage count changes."""
        with patch("lafleur.artifacts.CORPUS_DIR", new=Path(self.tmpdir)):
            self.telemetry_manager._get_corpus_size_mb()
            cached_bytes_1 = self.telemetry_manager._cached_corpus_size_bytes

            # Simulate a new large file added to corpus
            (Path(self.tmpdir) / "file3.py").write_text("z = 3\n" * 100_000)
            self.coverage_manager.state["per_file_coverage"]["file3.py"] = {}

            self.telemetry_manager._get_corpus_size_mb()
            cached_bytes_2 = self.telemetry_manager._cached_corpus_size_bytes
            # Cache should have been invalidated and rescanned with more bytes
            self.assertGreater(cached_bytes_2, cached_bytes_1)

    def test_corpus_size_cache_returns_none_on_error(self):
        """Verify None is returned when rglob raises OSError."""
        mock_dir = MagicMock()
        mock_dir.rglob.side_effect = OSError("Permission denied")
        with patch("lafleur.artifacts.CORPUS_DIR", new=mock_dir):
            result = self.telemetry_manager._get_corpus_size_mb()
            self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
