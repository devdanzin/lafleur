#!/usr/bin/env python3
"""
Unit tests for lafleur/coverage.py
"""

import tempfile
import unittest
from pathlib import Path

from lafleur.coverage import (
    HARNESS_MARKER_REGEX,
    RARE_EVENT_REGEX,
    UOP_REGEX,
    CoverageManager,
    ensure_state_schema,
    parse_log_for_edge_coverage,
)


class TestRegexes(unittest.TestCase):
    """Test the regex patterns used for log parsing."""

    def test_uop_regex_matches_standard_uops(self):
        """Test that UOP_REGEX matches standard UOP patterns."""
        # Test ADD_TO_TRACE format
        line = "  63 ADD_TO_TRACE: _SET_IP (0, target=2255)"
        match = UOP_REGEX.search(line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "_SET_IP")

        # Test OPTIMIZED format
        line = "OPTIMIZED: _LOAD_FAST_BORROW"
        match = UOP_REGEX.search(line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "_LOAD_FAST_BORROW")

    def test_uop_regex_no_match_on_invalid_input(self):
        """Test that UOP_REGEX doesn't match invalid patterns."""
        invalid_lines = [
            "This is just text",
            "INVALID_UOP",
            "ADD_TO_TRACE: not_an_uop",  # Missing underscore prefix
        ]
        for line in invalid_lines:
            match = UOP_REGEX.search(line)
            self.assertIsNone(match, f"Regex should not match: {line}")

    def test_harness_marker_regex_matches_markers(self):
        """Test that HARNESS_MARKER_REGEX matches harness markers."""
        test_cases = [
            ("[f1]", "f1"),
            ("[f12]", "f12"),
            ("[f999]", "f999"),
            ("Some text [f5] more text", "f5"),
        ]
        for line, expected_id in test_cases:
            match = HARNESS_MARKER_REGEX.search(line)
            self.assertIsNotNone(match, f"Should match: {line}")
            self.assertEqual(match.group(1), expected_id)

    def test_harness_marker_regex_no_match_on_invalid(self):
        """Test that HARNESS_MARKER_REGEX doesn't match invalid patterns."""
        invalid_lines = [
            "[f]",  # No number
            "[1]",  # Missing 'f'
            "[fx]",  # Letter instead of number
            "f1",  # Missing brackets
        ]
        for line in invalid_lines:
            match = HARNESS_MARKER_REGEX.search(line)
            self.assertIsNone(match, f"Regex should not match: {line}")

    def test_rare_event_regex_matches_events(self):
        """Test that RARE_EVENT_REGEX matches various rare events."""
        rare_events = [
            ("_DEOPT instruction found", "_DEOPT"),
            ("_GUARD_FAIL detected", "_GUARD_FAIL"),
            ("Bailing on recursive call", "Bailing on recursive call"),
            ("Unsupported opcode encountered", "Unsupported opcode"),
            ("Confidence too low", "Confidence too low"),
            ("Rare event set class modified", "Rare event set class"),
        ]
        for line, expected_match in rare_events:
            match = RARE_EVENT_REGEX.search(line)
            self.assertIsNotNone(match, f"Should match: {line}")
            self.assertEqual(match.group(1), expected_match)

    def test_rare_event_regex_no_match_on_normal_text(self):
        """Test that RARE_EVENT_REGEX doesn't match normal log lines."""
        normal_lines = [
            "Standard execution line",
            "ADD_TO_TRACE: _LOAD_FAST",
            "Normal function call",
        ]
        for line in normal_lines:
            match = RARE_EVENT_REGEX.search(line)
            self.assertIsNone(match, f"Regex should not match: {line}")


class TestCoverageManager(unittest.TestCase):
    """Test the CoverageManager class."""

    def setUp(self):
        """Create a fresh CoverageManager for each test."""
        self.state = {}
        self.manager = CoverageManager(self.state)

    def test_get_or_create_id_assigns_new_ids(self):
        """Test that get_or_create_id assigns new IDs for new strings."""
        # First call should create ID 0
        uop_id1 = self.manager.get_or_create_id("uop", "_LOAD_FAST")
        self.assertEqual(uop_id1, 0)

        # Second call with different string should create ID 1
        uop_id2 = self.manager.get_or_create_id("uop", "_STORE_FAST")
        self.assertEqual(uop_id2, 1)

        # Third call with new string should create ID 2
        uop_id3 = self.manager.get_or_create_id("uop", "_BINARY_OP_ADD_INT")
        self.assertEqual(uop_id3, 2)

    def test_get_or_create_id_returns_existing_ids(self):
        """Test that get_or_create_id returns existing IDs for known strings."""
        # Create an ID
        original_id = self.manager.get_or_create_id("uop", "_LOAD_FAST")

        # Request the same string again
        reused_id = self.manager.get_or_create_id("uop", "_LOAD_FAST")

        # Should get the same ID
        self.assertEqual(original_id, reused_id)

    def test_reverse_maps_are_updated(self):
        """Test that reverse maps are updated when new IDs are created."""
        # Create some IDs
        uop_id1 = self.manager.get_or_create_id("uop", "_LOAD_FAST")
        uop_id2 = self.manager.get_or_create_id("uop", "_STORE_FAST")
        edge_id1 = self.manager.get_or_create_id("edge", "_LOAD_FAST->_STORE_FAST")

        # Check reverse maps
        self.assertEqual(self.manager.reverse_uop_map[uop_id1], "_LOAD_FAST")
        self.assertEqual(self.manager.reverse_uop_map[uop_id2], "_STORE_FAST")
        self.assertEqual(self.manager.reverse_edge_map[edge_id1], "_LOAD_FAST->_STORE_FAST")

    def test_different_types_have_independent_id_counters(self):
        """Test that different item types have independent ID sequences."""
        uop_id = self.manager.get_or_create_id("uop", "_LOAD_FAST")
        edge_id = self.manager.get_or_create_id("edge", "_LOAD_FAST->_STORE_FAST")
        event_id = self.manager.get_or_create_id("rare_event", "_DEOPT")

        # All should get ID 0 since they're in different namespaces
        self.assertEqual(uop_id, 0)
        self.assertEqual(edge_id, 0)
        self.assertEqual(event_id, 0)

    def test_state_is_properly_initialized(self):
        """Test that state is properly initialized with default structures."""
        self.assertIn("uop_map", self.state)
        self.assertIn("edge_map", self.state)
        self.assertIn("rare_event_map", self.state)
        self.assertIn("next_id_map", self.state)

        self.assertIsInstance(self.state["uop_map"], dict)
        self.assertIsInstance(self.state["edge_map"], dict)
        self.assertIsInstance(self.state["rare_event_map"], dict)
        self.assertEqual(self.state["next_id_map"]["uop"], 0)
        self.assertEqual(self.state["next_id_map"]["edge"], 0)
        self.assertEqual(self.state["next_id_map"]["rare_event"], 0)


class TestParseLogForEdgeCoverage(unittest.TestCase):
    """Test the parse_log_for_edge_coverage function."""

    def setUp(self):
        """Set up a fresh CoverageManager for each test."""
        self.state = {}
        self.manager = CoverageManager(self.state)

    def test_parse_log_with_proto_trace_and_optimized_trace(self):
        """Test parsing a log with both proto-trace and optimized trace sections."""
        # Create a sample log with state transitions
        log_content = """
[f1] STRATEGY: Testing
Created a proto-trace for function test
  ADD_TO_TRACE: _LOAD_FAST (0, target=100)
  ADD_TO_TRACE: _STORE_FAST (1, target=200)
Optimized trace (length 50):
  OPTIMIZED: _LOAD_CONST
  OPTIMIZED: _BINARY_OP_ADD_INT
"""
        # Write to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write(log_content)
            log_path = Path(f.name)

        try:
            # Parse the log
            coverage = parse_log_for_edge_coverage(log_path, self.manager)

            # Should have coverage for harness f1
            self.assertIn("f1", coverage)
            harness_data = coverage["f1"]

            # Check that UOPs were tracked
            self.assertGreater(len(harness_data["uops"]), 0)

            # Check that edges were tracked
            self.assertGreater(len(harness_data["edges"]), 0)

            # Check that trace_length was extracted
            self.assertEqual(harness_data["trace_length"], 50)

            # Check that edges have correct states
            # Need to verify state machine logic by checking edge strings
            edges_with_states = []
            for edge_id in harness_data["edges"]:
                edge_str = self.manager.reverse_edge_map[edge_id]
                edges_with_states.append(edge_str)

            # Should have edges from both TRACING and OPTIMIZED states
            tracing_edges = [e for e in edges_with_states if "'TRACING'" in e]
            optimized_edges = [e for e in edges_with_states if "'OPTIMIZED'" in e]

            self.assertGreater(len(tracing_edges), 0, "Should have TRACING state edges")
            self.assertGreater(len(optimized_edges), 0, "Should have OPTIMIZED state edges")

        finally:
            # Clean up
            log_path.unlink()

    def test_parse_log_with_rare_events(self):
        """Test that rare events are correctly extracted."""
        log_content = """
[f1] STRATEGY: Testing
ADD_TO_TRACE: _LOAD_FAST
Bailing on recursive call
ADD_TO_TRACE: _STORE_FAST
_DEOPT instruction encountered
Confidence too low for optimization
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write(log_content)
            log_path = Path(f.name)

        try:
            coverage = parse_log_for_edge_coverage(log_path, self.manager)
            harness_data = coverage["f1"]

            # Should have captured rare events
            self.assertGreater(len(harness_data["rare_events"]), 0)

            # Get the actual rare event strings
            rare_events = []
            for event_id in harness_data["rare_events"]:
                rare_events.append(self.manager.reverse_rare_event_map[event_id])

            # Check specific events were captured
            self.assertIn("Bailing on recursive call", rare_events)
            self.assertIn("_DEOPT", rare_events)
            self.assertIn("Confidence too low", rare_events)

        finally:
            log_path.unlink()

    def test_parse_log_with_spurious_uop(self):
        """Test that unknown/spurious UOPs break the edge chain."""
        log_content = """
[f1] STRATEGY: Testing
ADD_TO_TRACE: _LOAD_FAST
ADD_TO_TRACE: _SPURIOUS_UNKNOWN_UOP
ADD_TO_TRACE: _STORE_FAST
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write(log_content)
            log_path = Path(f.name)

        try:
            coverage = parse_log_for_edge_coverage(log_path, self.manager)
            harness_data = coverage["f1"]

            # Should have UOPs for LOAD_FAST and STORE_FAST but not the spurious one
            uop_names = [self.manager.reverse_uop_map[uid] for uid in harness_data["uops"]]
            self.assertIn("_LOAD_FAST", uop_names)
            self.assertIn("_STORE_FAST", uop_names)
            self.assertNotIn("_SPURIOUS_UNKNOWN_UOP", uop_names)

            # The edge chain should be broken - there should NOT be an edge
            # from _LOAD_FAST to _SPURIOUS_UNKNOWN_UOP or from _SPURIOUS_UNKNOWN_UOP to _STORE_FAST
            edge_strs = [self.manager.reverse_edge_map[eid] for eid in harness_data["edges"]]
            has_spurious_edge = any("_SPURIOUS_UNKNOWN_UOP" in e for e in edge_strs)
            self.assertFalse(has_spurious_edge, "Spurious UOP should break the edge chain")

        finally:
            log_path.unlink()

    def test_parse_log_tracks_side_exits(self):
        """Test that side exits are correctly tracked in OPTIMIZED state."""
        log_content = """
[f1] STRATEGY: Testing
Optimized trace (length 100):
  OPTIMIZED: _LOAD_CONST
  OPTIMIZED: _DEOPT
  OPTIMIZED: _BINARY_OP_ADD_INT
  OPTIMIZED: _EXIT_TRACE
  OPTIMIZED: _LOAD_FAST
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write(log_content)
            log_path = Path(f.name)

        try:
            coverage = parse_log_for_edge_coverage(log_path, self.manager)
            harness_data = coverage["f1"]

            # Should have tracked 2 side exits (_DEOPT and _EXIT_TRACE)
            self.assertEqual(harness_data["side_exits"], 2)

        finally:
            log_path.unlink()

    def test_parse_log_with_multiple_harnesses(self):
        """Test parsing a log with multiple harness sections."""
        log_content = """
[f1] STRATEGY: Testing
ADD_TO_TRACE: _LOAD_FAST
ADD_TO_TRACE: _STORE_FAST
[f2] STRATEGY: Another test
ADD_TO_TRACE: _LOAD_CONST
ADD_TO_TRACE: _BINARY_OP_ADD_INT
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write(log_content)
            log_path = Path(f.name)

        try:
            coverage = parse_log_for_edge_coverage(log_path, self.manager)

            # Should have coverage for both harnesses
            self.assertIn("f1", coverage)
            self.assertIn("f2", coverage)

            # Each should have their own UOPs
            self.assertGreater(len(coverage["f1"]["uops"]), 0)
            self.assertGreater(len(coverage["f2"]["uops"]), 0)

        finally:
            log_path.unlink()

    def test_parse_nonexistent_log_returns_empty_dict(self):
        """Test that parsing a nonexistent log file returns empty dict."""
        fake_path = Path("/tmp/nonexistent_log_file_12345.log")
        coverage = parse_log_for_edge_coverage(fake_path, self.manager)
        self.assertEqual(coverage, {})


class TestEnsureStateSchema(unittest.TestCase):
    """Test the ensure_state_schema function."""

    def test_ensure_state_schema_empty_dict(self):
        """Test that all required keys are created on an empty dict."""
        state: dict = {}
        ensure_state_schema(state)

        self.assertIn("uop_map", state)
        self.assertIn("edge_map", state)
        self.assertIn("rare_event_map", state)
        self.assertIn("next_id_map", state)
        self.assertIn("global_coverage", state)
        self.assertIn("per_file_coverage", state)
        self.assertEqual(state["next_id_map"], {"uop": 0, "edge": 0, "rare_event": 0})
        self.assertEqual(state["global_coverage"], {"uops": {}, "edges": {}, "rare_events": {}})

    def test_ensure_state_schema_preserves_existing(self):
        """Test that existing values are not overwritten."""
        state = {"uop_map": {"_LOAD_FAST": 0}, "per_file_coverage": {"f1.py": {}}}
        ensure_state_schema(state)

        self.assertEqual(state["uop_map"], {"_LOAD_FAST": 0})
        self.assertEqual(state["per_file_coverage"], {"f1.py": {}})

    def test_ensure_state_schema_idempotent(self):
        """Test that calling twice produces no changes on the second call."""
        state: dict = {}
        ensure_state_schema(state)
        snapshot = {k: v for k, v in state.items()}
        ensure_state_schema(state)

        self.assertEqual(state, snapshot)


if __name__ == "__main__":
    unittest.main(verbosity=2)
