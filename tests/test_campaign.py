import unittest
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from lafleur.campaign import CampaignAggregator, generate_html_report


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
            "instance_name": name
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
        self._create_run("run1", {
            "total_mutations": 10,
            "global_edges": 100,
            "crashes_found": 1,
            "new_coverage_finds": 5,
            "start_time": "2025-01-01T10:00:00Z",
            "last_update_time": "2025-01-01T10:00:10Z"  # 10 seconds
        })

        # Run 2: 20 execs, 0 crashes
        self._create_run("run2", {
            "total_mutations": 20,
            "global_edges": 150,
            "crashes_found": 0,
            "new_coverage_finds": 2,
            "start_time": "2025-01-01T10:00:00Z",
            "last_update_time": "2025-01-01T10:00:10Z"  # 10 seconds
        })

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
