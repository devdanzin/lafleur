#!/usr/bin/env python3
"""
Unit tests for lafleur/learning.py
"""

import json
import unittest
from unittest.mock import mock_open, patch

from lafleur.learning import MutatorScoreTracker


class TestMutatorScoreTracker(unittest.TestCase):
    """Test the MutatorScoreTracker class."""

    def setUp(self):
        """Create a fresh tracker for each test."""

        # Create mock transformer classes
        class MockTransformer1:
            pass

        class MockTransformer2:
            pass

        class MockTransformer3:
            pass

        self.transformers = [MockTransformer1, MockTransformer2, MockTransformer3]
        self.tracker = MutatorScoreTracker(
            all_transformers=self.transformers, decay_factor=0.995, min_attempts=10
        )

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_record_success_increments_scores(self, mock_file_path):
        """Test that record_success increments scores for strategy and transformers."""
        mock_file_path.is_file.return_value = False

        # Record a success
        self.tracker.record_success("havoc", ["MockTransformer1", "MockTransformer2"])

        # Check that scores were incremented
        self.assertEqual(self.tracker.scores["havoc"], 0.995)  # 1.0 * 0.995
        self.assertEqual(self.tracker.scores["MockTransformer1"], 0.995)
        self.assertEqual(self.tracker.scores["MockTransformer2"], 0.995)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_record_success_applies_decay_to_all_scores(self, mock_file_path):
        """Test that record_success applies decay to ALL scores, not just the updated ones."""
        mock_file_path.is_file.return_value = False

        # Set up some initial scores
        self.tracker.scores["havoc"] = 10.0
        self.tracker.scores["spam"] = 5.0
        self.tracker.scores["MockTransformer1"] = 8.0

        # Record a success for a different strategy
        self.tracker.record_success("deterministic", ["MockTransformer2"])

        # Check that:
        # 1. The successful items got incremented THEN decayed
        self.assertEqual(self.tracker.scores["deterministic"], 0.995)  # (0 + 1.0) * 0.995 = 0.995
        self.assertEqual(self.tracker.scores["MockTransformer2"], 0.995)

        # 2. ALL other scores got decayed
        self.assertEqual(self.tracker.scores["havoc"], 10.0 * 0.995)
        self.assertEqual(self.tracker.scores["spam"], 5.0 * 0.995)
        self.assertEqual(self.tracker.scores["MockTransformer1"], 8.0 * 0.995)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_get_weights_with_min_attempts_not_met(self, mock_file_path):
        """Test that candidates with < min_attempts get default weight of 1.0."""
        mock_file_path.is_file.return_value = False

        # Set up scores but not enough attempts
        self.tracker.scores["havoc"] = 50.0
        self.tracker.attempts["havoc"] = 5  # Less than min_attempts (10)

        # Get weights with epsilon=0 to disable exploration
        weights = self.tracker.get_weights(["havoc", "spam"], epsilon=0.0)

        # Both should get 1.0 since they haven't met min_attempts
        self.assertEqual(weights[0], 1.0)  # havoc
        self.assertEqual(weights[1], 1.0)  # spam

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_get_weights_with_min_attempts_met(self, mock_file_path):
        """Test that candidates with >= min_attempts use their scores."""
        mock_file_path.is_file.return_value = False

        # Set up scores with enough attempts
        self.tracker.scores["havoc"] = 10.0
        self.tracker.attempts["havoc"] = 15  # More than min_attempts

        self.tracker.scores["spam"] = 2.0
        self.tracker.attempts["spam"] = 12

        # Get weights with epsilon=0 to disable exploration
        weights = self.tracker.get_weights(["havoc", "spam"], epsilon=0.0)

        # Should use actual scores
        self.assertEqual(weights[0], 10.0)  # havoc score
        self.assertEqual(weights[1], 2.0)  # spam score

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_get_weights_enforces_floor(self, mock_file_path):
        """Test that weights have a floor of 0.05."""
        mock_file_path.is_file.return_value = False

        # Set up a very low score
        self.tracker.scores["havoc"] = 0.01
        self.tracker.attempts["havoc"] = 15  # Enough attempts

        # Get weights with epsilon=0
        weights = self.tracker.get_weights(["havoc"], epsilon=0.0)

        # Should be floored at 0.05
        self.assertEqual(weights[0], 0.05)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    @patch("random.random")
    def test_get_weights_epsilon_greedy_exploration(self, mock_random, mock_file_path):
        """Test epsilon-greedy exploration returns uniform weights."""
        mock_file_path.is_file.return_value = False

        # Set up scores
        self.tracker.scores["havoc"] = 100.0
        self.tracker.attempts["havoc"] = 20

        # Mock random to trigger exploration (epsilon = 0.1)
        mock_random.return_value = 0.05  # Less than epsilon

        weights = self.tracker.get_weights(["havoc", "spam", "deterministic"], epsilon=0.1)

        # Should return uniform weights (all 1.0) during exploration
        self.assertEqual(weights, [1.0, 1.0, 1.0])

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    @patch("random.random")
    def test_get_weights_epsilon_greedy_exploitation(self, mock_random, mock_file_path):
        """Test epsilon-greedy exploitation uses scores."""
        mock_file_path.is_file.return_value = False

        # Set up scores
        self.tracker.scores["havoc"] = 10.0
        self.tracker.attempts["havoc"] = 20

        # Mock random to trigger exploitation
        mock_random.return_value = 0.5  # Greater than epsilon (0.1)

        weights = self.tracker.get_weights(["havoc"], epsilon=0.1)

        # Should use actual score
        self.assertEqual(weights[0], 10.0)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_load_state_from_file(self, mock_file_path):
        """Test loading state from a saved file."""
        # Create sample state data
        saved_state = {
            "scores": {"havoc": 25.5, "spam": 10.2, "MockTransformer1": 15.0},
            "attempts": {"havoc": 50, "spam": 30},
        }

        # Mock the file path to exist
        mock_file_path.is_file.return_value = True

        # Mock the file open and json.load
        with patch("builtins.open", mock_open(read_data=json.dumps(saved_state))):
            with patch("json.load", return_value=saved_state):
                tracker = MutatorScoreTracker(self.transformers, decay_factor=0.995)

                # Verify loaded state
                self.assertEqual(tracker.scores["havoc"], 25.5)
                self.assertEqual(tracker.scores["spam"], 10.2)
                self.assertEqual(tracker.scores["MockTransformer1"], 15.0)
                self.assertEqual(tracker.attempts["havoc"], 50)
                self.assertEqual(tracker.attempts["spam"], 30)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_save_state_to_file(self, mock_file_path):
        """Test saving state to a file."""
        mock_file_path.is_file.return_value = False

        # Set up some state
        self.tracker.scores["havoc"] = 42.5
        self.tracker.scores["spam"] = 17.3
        self.tracker.attempts["havoc"] = 100

        # Mock the file operations
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            with patch("json.dump") as mock_json_dump:
                self.tracker.save_state()

                # Verify json.dump was called with correct data
                mock_json_dump.assert_called_once()
                saved_data = mock_json_dump.call_args[0][0]

                self.assertEqual(saved_data["scores"]["havoc"], 42.5)
                self.assertEqual(saved_data["scores"]["spam"], 17.3)
                self.assertEqual(saved_data["attempts"]["havoc"], 100)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_decay_factor_applied_correctly(self, mock_file_path):
        """Test that the decay factor is applied as expected."""
        mock_file_path.is_file.return_value = False

        # Create tracker with specific decay factor
        tracker = MutatorScoreTracker(self.transformers, decay_factor=0.9)

        # Set up initial scores
        tracker.scores["havoc"] = 10.0
        tracker.scores["spam"] = 20.0

        # Record a success
        tracker.record_success("deterministic", [])

        # Check decay was applied
        self.assertEqual(tracker.scores["havoc"], 10.0 * 0.9)
        self.assertEqual(tracker.scores["spam"], 20.0 * 0.9)
        self.assertEqual(tracker.scores["deterministic"], 1.0 * 0.9)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_multiple_successes_compound_decay(self, mock_file_path):
        """Test that multiple successes compound the decay effect."""
        mock_file_path.is_file.return_value = False

        # Set initial score
        self.tracker.scores["havoc"] = 100.0

        # Record multiple successes for a different strategy
        self.tracker.record_success("spam", [])
        self.tracker.record_success("spam", [])

        # havoc score should be decayed twice
        expected = 100.0 * (0.995**2)
        self.assertAlmostEqual(self.tracker.scores["havoc"], expected, places=5)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_strategies_and_transformers_initialized(self, mock_file_path):
        """Test that strategies and transformers are properly initialized."""
        mock_file_path.is_file.return_value = False

        tracker = MutatorScoreTracker(self.transformers)

        # Should have the three standard strategies
        self.assertEqual(tracker.strategies, ["deterministic", "havoc", "spam"])

        # Should have transformer names
        self.assertIn("MockTransformer1", tracker.all_transformers)
        self.assertIn("MockTransformer2", tracker.all_transformers)
        self.assertIn("MockTransformer3", tracker.all_transformers)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_load_state_handles_corrupted_file(self, mock_file_path):
        """Test that corrupted state file is handled gracefully."""
        mock_file_path.is_file.return_value = True

        with patch("builtins.open", mock_open(read_data="{ corrupted json")):
            tracker = MutatorScoreTracker(self.transformers, decay_factor=0.995)

        # Should have fresh/empty state, not crash
        self.assertEqual(dict(tracker.scores), {})
        self.assertEqual(dict(tracker.attempts), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
