import unittest
import json
from unittest.mock import patch
from lafleur.orchestrator import LafleurOrchestrator


class TestJITParsing(unittest.TestCase):
    def setUp(self):
        # We need to mock the orchestrator's init to avoid FS operations
        with (
            patch("lafleur.orchestrator.load_coverage_state"),
            patch("lafleur.orchestrator.load_run_stats"),
            patch("lafleur.orchestrator.CoverageManager"),
            patch("lafleur.orchestrator.CorpusManager"),
            patch("lafleur.orchestrator.MutatorScoreTracker"),
            patch("pathlib.Path.mkdir"),
        ):
            self.orch = LafleurOrchestrator(fusil_path="dummy")

    def test_parse_jit_stats_single_entry(self):
        """Test parsing a single stats entry."""
        stats = {
            "max_exit_count": 10,
            "max_chain_depth": 2,
            "zombie_traces": 0,
            "min_code_size": 100,
        }
        log_content = f"Some log\n[DRIVER:STATS] {json.dumps(stats)}\nEnd log"

        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)

        self.assertEqual(parsed["max_exit_count"], 10)
        self.assertEqual(parsed["max_chain_depth"], 2)
        self.assertEqual(parsed["zombie_traces"], 0)
        self.assertEqual(parsed["min_code_size"], 100)

    def test_parse_jit_stats_aggregation(self):
        """Test aggregation of multiple stats entries (session mode)."""
        stats1 = {
            "max_exit_count": 10,
            "max_chain_depth": 5,
            "zombie_traces": 0,
            "min_code_size": 100,
        }
        stats2 = {
            "max_exit_count": 50,  # Higher
            "max_chain_depth": 2,
            "zombie_traces": 1,  # Higher
            "min_code_size": 20,  # Lower (better)
        }

        log_content = (
            f"[DRIVER:STATS] {json.dumps(stats1)}\n"
            f"Debug info...\n"
            f"[DRIVER:STATS] {json.dumps(stats2)}"
        )

        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)

        self.assertEqual(parsed["max_exit_count"], 50)  # Max
        self.assertEqual(parsed["max_chain_depth"], 5)  # Max
        self.assertEqual(parsed["zombie_traces"], 1)  # Max
        self.assertEqual(parsed["min_code_size"], 20)  # Min

    def test_parse_jit_stats_empty(self):
        """Test parsing logs with no stats."""
        log_content = "Just some debug info\nNo stats here"
        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)

        self.assertEqual(parsed["max_exit_count"], 0)
        self.assertEqual(parsed["min_code_size"], 0)

    def test_parse_jit_stats_malformed(self):
        """Test graceful handling of malformed JSON."""
        log_content = "[DRIVER:STATS] {invalid_json"
        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)

        # Should return defaults, not crash
        self.assertEqual(parsed["max_exit_count"], 0)

    def test_parse_jit_stats_malformed_json(self):
        """Test that malformed JSON in driver stats is ignored gracefully."""
        # The JSON is cut off mid-stream
        log_content = """
        [DRIVER:START] script.py
        [DRIVER:STATS] {"max_exit_count": 100, "max_chain_depth": 
        [DRIVER:ERROR] Process killed
        """

        # Should not raise JSONDecodeError
        stats = self.orch.scoring_manager.parse_jit_stats(log_content)

        # Should return safe defaults
        self.assertEqual(stats["max_exit_count"], 0)
        self.assertEqual(stats["zombie_traces"], 0)


if __name__ == "__main__":
    unittest.main()
