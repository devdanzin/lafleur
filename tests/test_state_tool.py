"""
Tests for the state_tool module (lafleur/state_tool.py).

This module tests the coverage state file inspection and migration tool.
"""

import json
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from io import StringIO

from lafleur.state_tool import migrate_state_to_integers, main


class TestMigrateStateToIntegers(unittest.TestCase):
    """Tests for migrate_state_to_integers function."""

    def test_migrates_empty_state(self):
        """Test migration of empty state."""
        old_state = {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {},
        }

        new_state = migrate_state_to_integers(old_state)

        self.assertIn("uop_map", new_state)
        self.assertIn("edge_map", new_state)
        self.assertIn("rare_event_map", new_state)
        self.assertIn("next_id_map", new_state)
        self.assertIn("global_coverage", new_state)
        self.assertIn("per_file_coverage", new_state)

    def test_migrates_global_coverage(self):
        """Test migration of global coverage data."""
        old_state = {
            "global_coverage": {
                "uops": {"_LOAD_FAST": 10, "_STORE_FAST": 5},
                "edges": {"_LOAD_FAST->_STORE_FAST": 3},
                "rare_events": {"deopt": 1},
            },
            "per_file_coverage": {},
        }

        new_state = migrate_state_to_integers(old_state)

        # Check that mappings were created
        self.assertIn("_LOAD_FAST", new_state["uop_map"])
        self.assertIn("_STORE_FAST", new_state["uop_map"])
        self.assertIn("_LOAD_FAST->_STORE_FAST", new_state["edge_map"])
        self.assertIn("deopt", new_state["rare_event_map"])

        # Check that counts are preserved using integer IDs
        uop_id = new_state["uop_map"]["_LOAD_FAST"]
        self.assertEqual(new_state["global_coverage"]["uops"][uop_id], 10)

    def test_migrates_per_file_coverage(self):
        """Test migration of per-file coverage data."""
        old_state = {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {
                "test.py": {
                    "baseline_coverage": {
                        "harness1": {
                            "uops": {"_LOAD_FAST": 5},
                            "edges": {"_LOAD_FAST->_STORE_FAST": 2},
                            "rare_events": {},
                        }
                    },
                    "lineage_coverage_profile": {
                        "harness1": {
                            "uops": {"_LOAD_FAST"},
                            "edges": {"_LOAD_FAST->_STORE_FAST"},
                            "rare_events": set(),
                        }
                    },
                }
            },
        }

        new_state = migrate_state_to_integers(old_state)

        # Check that per-file data is migrated
        self.assertIn("test.py", new_state["per_file_coverage"])
        file_meta = new_state["per_file_coverage"]["test.py"]

        # Baseline coverage should use integer IDs
        baseline = file_meta["baseline_coverage"]["harness1"]
        uop_id = new_state["uop_map"]["_LOAD_FAST"]
        self.assertIn(uop_id, baseline["uops"])

    def test_increments_next_id_correctly(self):
        """Test that next_id_map is incremented correctly."""
        old_state = {
            "global_coverage": {
                "uops": {"uop1": 1, "uop2": 2, "uop3": 3},
                "edges": {"edge1": 1},
                "rare_events": {},
            },
            "per_file_coverage": {},
        }

        new_state = migrate_state_to_integers(old_state)

        # Should have assigned 3 uop IDs
        self.assertEqual(new_state["next_id_map"]["uop"], 3)
        # Should have assigned 1 edge ID
        self.assertEqual(new_state["next_id_map"]["edge"], 1)
        # No rare events assigned
        self.assertEqual(new_state["next_id_map"]["rare_event"], 0)


class TestMain(unittest.TestCase):
    """Tests for the main CLI entry point."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_handles_nonexistent_input_file(self):
        """Test error handling for non-existent input file."""
        with patch("sys.argv", ["state-tool", "/nonexistent/file.pkl"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 1)

    def test_handles_invalid_pickle_file(self):
        """Test error handling for corrupt pickle file."""
        input_file = self.temp_path / "corrupt.pkl"
        input_file.write_text("not a pickle file")

        with patch("sys.argv", ["state-tool", str(input_file)]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 1)

    def test_prints_json_to_stdout_by_default(self):
        """Test that state is printed as JSON to stdout by default."""
        input_file = self.temp_path / "state.pkl"
        state = {
            "uop_map": {"_LOAD_FAST": 0},
            "edge_map": {},
            "rare_event_map": {},
            "next_id_map": {"uop": 1, "edge": 0, "rare_event": 0},
            "global_coverage": {"uops": {0: 5}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        with open(input_file, "wb") as f:
            pickle.dump(state, f)

        captured_output = StringIO()
        with patch("sys.argv", ["state-tool", str(input_file)]):
            with patch("sys.stdout", captured_output):
                main()

        output = captured_output.getvalue()
        parsed = json.loads(output)
        self.assertIn("uop_map", parsed)

    def test_saves_as_json_when_output_is_json(self):
        """Test saving output as JSON file."""
        input_file = self.temp_path / "state.pkl"
        output_file = self.temp_path / "output.json"

        state = {
            "uop_map": {"_LOAD_FAST": 0},
            "edge_map": {},
            "rare_event_map": {},
            "next_id_map": {"uop": 1, "edge": 0, "rare_event": 0},
            "global_coverage": {"uops": {0: 5}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        with open(input_file, "wb") as f:
            pickle.dump(state, f)

        with patch("sys.argv", ["state-tool", str(input_file), str(output_file)]):
            main()

        self.assertTrue(output_file.exists())
        with open(output_file) as f:
            saved = json.load(f)
        self.assertIn("uop_map", saved)

    def test_saves_as_pickle_when_output_is_pkl(self):
        """Test saving migrated output as pickle file."""
        input_file = self.temp_path / "state.pkl"
        output_file = self.temp_path / "output.pkl"

        # Old format state (no uop_map) to trigger migration
        old_state = {
            "global_coverage": {"uops": {"_LOAD_FAST": 5}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {},
        }
        with open(input_file, "wb") as f:
            pickle.dump(old_state, f)

        with patch("sys.argv", ["state-tool", str(input_file), str(output_file)]):
            main()

        self.assertTrue(output_file.exists())
        with open(output_file, "rb") as f:
            saved = pickle.load(f)
        # Should have been migrated
        self.assertIn("uop_map", saved)

    def test_migrates_old_format_state(self):
        """Test that old format state is automatically migrated."""
        input_file = self.temp_path / "old_state.pkl"
        output_file = self.temp_path / "migrated.json"

        # Old format without uop_map
        old_state = {
            "global_coverage": {
                "uops": {"_LOAD_FAST": 10},
                "edges": {"_LOAD_FAST->_STORE_FAST": 5},
                "rare_events": {},
            },
            "per_file_coverage": {},
        }
        with open(input_file, "wb") as f:
            pickle.dump(old_state, f)

        with patch("sys.argv", ["state-tool", str(input_file), str(output_file)]):
            main()

        # Read the output file
        with open(output_file) as f:
            parsed = json.load(f)

        # Should have migrated format
        self.assertIn("uop_map", parsed)
        self.assertIn("_LOAD_FAST", parsed["uop_map"])

    def test_handles_sets_in_state(self):
        """Test that sets are converted to lists for JSON serialization."""
        input_file = self.temp_path / "state.pkl"

        state = {
            "uop_map": {},
            "edge_map": {},
            "rare_event_map": {},
            "next_id_map": {"uop": 0, "edge": 0, "rare_event": 0},
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {
                "test.py": {
                    "lineage_coverage_profile": {
                        "harness1": {
                            "uops": {1, 2, 3},  # Set
                            "edges": set(),
                            "rare_events": set(),
                        }
                    }
                }
            },
        }
        with open(input_file, "wb") as f:
            pickle.dump(state, f)

        captured_output = StringIO()
        with patch("sys.argv", ["state-tool", str(input_file)]):
            with patch("sys.stdout", captured_output):
                main()

        # Should not raise TypeError for set serialization
        output = captured_output.getvalue()
        parsed = json.loads(output)
        # Sets should be converted to sorted lists
        uops = parsed["per_file_coverage"]["test.py"]["lineage_coverage_profile"]["harness1"][
            "uops"
        ]
        self.assertIsInstance(uops, list)
        self.assertEqual(sorted(uops), [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
