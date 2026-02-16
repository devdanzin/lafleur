import io
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

    def test_parse_jit_stats_malformed_json_warns_stderr(self):
        """Test that malformed JSON in driver stats logs a warning to stderr."""
        valid_stats = {"max_exit_count": 42, "max_chain_depth": 3, "zombie_traces": 1}
        log_content = (
            f"[DRIVER:STATS] {{not valid json}}\n[DRIVER:STATS] {json.dumps(valid_stats)}\n"
        )

        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            parsed = self.orch.scoring_manager.parse_jit_stats(log_content)

        # Warning should appear on stderr
        warning_output = stderr_capture.getvalue()
        self.assertIn("[!] Warning: Failed to parse JIT stats line:", warning_output)
        self.assertIn("{not valid json}", warning_output)

        # Valid line should still be parsed
        self.assertEqual(parsed["max_exit_count"], 42)
        self.assertEqual(parsed["zombie_traces"], 1)

    def test_parse_jit_stats_ekg_parsing(self):
        """Test that valid EKG watched lines are parsed correctly."""
        log_content = "[EKG] WATCHED: var1, var2\n[EKG] WATCHED: var3\n"

        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        self.assertEqual(sorted(parsed["watched_dependencies"]), ["var1", "var2", "var3"])

    def test_parse_jit_stats_ekg_empty_watched(self):
        """Test that EKG watched line with empty content is handled gracefully."""
        log_content = "[EKG] WATCHED:\n[EKG] WATCHED: valid_var\n"

        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        self.assertEqual(parsed["watched_dependencies"], ["valid_var"])

    def test_parse_jit_stats_extracts_delta_metrics(self):
        """Test that delta metrics are extracted from the LAST stats line."""
        stats1 = {
            "max_exit_count": 10,
            "delta_max_exit_density": 1.0,
            "delta_total_exits": 5,
            "delta_new_executors": 2,
            "delta_new_zombies": 0,
        }
        stats2 = {
            "max_exit_count": 20,
            "delta_max_exit_density": 3.0,
            "delta_total_exits": 25,
            "delta_max_exit_count": 15,
            "delta_new_executors": 1,
            "delta_new_zombies": 1,
        }
        log_content = f"[DRIVER:STATS] {json.dumps(stats1)}\n[DRIVER:STATS] {json.dumps(stats2)}\n"

        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        # Last line's values should win (overwrite, not max)
        self.assertAlmostEqual(parsed["child_delta_max_exit_density"], 3.0)
        self.assertEqual(parsed["child_delta_total_exits"], 25)
        self.assertEqual(parsed["child_delta_max_exit_count"], 15)
        self.assertEqual(parsed["child_delta_new_executors"], 1)
        self.assertEqual(parsed["child_delta_new_zombies"], 1)

    def test_parse_jit_stats_no_delta_fields_defaults_to_zero(self):
        """Test that missing delta fields default to zero."""
        stats = {"max_exit_count": 10, "max_chain_depth": 2}
        log_content = f"[DRIVER:STATS] {json.dumps(stats)}\n"

        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        self.assertAlmostEqual(parsed["child_delta_max_exit_density"], 0.0)
        self.assertEqual(parsed["child_delta_total_exits"], 0)
        self.assertEqual(parsed["child_delta_new_executors"], 0)
        self.assertEqual(parsed["child_delta_new_zombies"], 0)

    def test_parse_jit_stats_delta_overwrites_not_maxes(self):
        """Test that delta metrics use last-wins, not max."""
        stats1 = {"delta_max_exit_density": 5.0, "delta_total_exits": 50}
        stats2 = {"delta_max_exit_density": 2.0, "delta_total_exits": 10}
        stats3 = {"delta_max_exit_density": 3.0, "delta_total_exits": 20}
        log_content = (
            f"[DRIVER:STATS] {json.dumps(stats1)}\n"
            f"[DRIVER:STATS] {json.dumps(stats2)}\n"
            f"[DRIVER:STATS] {json.dumps(stats3)}\n"
        )

        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        # Last line wins (3.0), NOT max (5.0)
        self.assertAlmostEqual(parsed["child_delta_max_exit_density"], 3.0)
        self.assertEqual(parsed["child_delta_total_exits"], 20)


    def test_parse_jit_stats_null_min_code_size(self):
        """None value for min_code_size should not crash."""
        stats = {"min_code_size": None, "max_exit_count": 5}
        log_content = f"[DRIVER:STATS] {json.dumps(stats)}\n"
        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        self.assertEqual(parsed["min_code_size"], 0)
        self.assertEqual(parsed["max_exit_count"], 5)

    def test_parse_jit_stats_null_values_throughout(self):
        """All fields set to None should not crash and should default to zero."""
        stats = {
            "max_exit_count": None,
            "max_chain_depth": None,
            "zombie_traces": None,
            "min_code_size": None,
            "max_exit_density": None,
        }
        log_content = f"[DRIVER:STATS] {json.dumps(stats)}\n"
        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        self.assertEqual(parsed["max_exit_count"], 0)
        self.assertEqual(parsed["max_chain_depth"], 0)
        self.assertEqual(parsed["zombie_traces"], 0)
        self.assertEqual(parsed["min_code_size"], 0)
        self.assertAlmostEqual(parsed["max_exit_density"], 0.0)

    def test_parse_jit_stats_null_delta_values(self):
        """None values in delta fields should not crash."""
        stats = {
            "delta_max_exit_density": None,
            "delta_max_exit_count": None,
            "delta_total_exits": None,
            "delta_new_executors": None,
            "delta_new_zombies": None,
        }
        log_content = f"[DRIVER:STATS] {json.dumps(stats)}\n"
        parsed = self.orch.scoring_manager.parse_jit_stats(log_content)
        self.assertAlmostEqual(parsed["child_delta_max_exit_density"], 0.0)
        self.assertEqual(parsed["child_delta_max_exit_count"], 0)
        self.assertEqual(parsed["child_delta_total_exits"], 0)
        self.assertEqual(parsed["child_delta_new_executors"], 0)
        self.assertEqual(parsed["child_delta_new_zombies"], 0)


if __name__ == "__main__":
    unittest.main()
