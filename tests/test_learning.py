#!/usr/bin/env python3
"""
Unit tests for lafleur/learning.py
"""

import io
import json
import unittest
from unittest.mock import MagicMock, mock_open, patch

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

        # Check that scores were incremented (no decay on success)
        self.assertEqual(self.tracker.scores["havoc"], 1.0)
        self.assertEqual(self.tracker.scores["MockTransformer1"], 1.0)
        self.assertEqual(self.tracker.scores["MockTransformer2"], 1.0)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_record_success_does_not_decay(self, mock_file_path):
        """Test that record_success does not apply decay (decay is attempt-based)."""
        mock_file_path.is_file.return_value = False

        # Set up some initial scores
        self.tracker.scores["havoc"] = 10.0
        self.tracker.scores["spam"] = 5.0

        # Record a success for a different strategy
        self.tracker.record_success("deterministic", ["MockTransformer2"])

        # Successful items got incremented, no decay
        self.assertEqual(self.tracker.scores["deterministic"], 1.0)
        self.assertEqual(self.tracker.scores["MockTransformer2"], 1.0)

        # Other scores remain unchanged (no decay on success)
        self.assertEqual(self.tracker.scores["havoc"], 10.0)
        self.assertEqual(self.tracker.scores["spam"], 5.0)

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
            "attempt_counter": 17,
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
                self.assertEqual(tracker._attempt_counter, 17)

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

                # Verify parent directory is created
                mock_file_path.parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)

                # Verify json.dump was called with correct data
                mock_json_dump.assert_called_once()
                saved_data = mock_json_dump.call_args[0][0]

                self.assertEqual(saved_data["scores"]["havoc"], 42.5)
                self.assertEqual(saved_data["scores"]["spam"], 17.3)
                self.assertEqual(saved_data["attempts"]["havoc"], 100)
                self.assertEqual(saved_data["attempt_counter"], 0)

    @patch("lafleur.learning.MUTATOR_TELEMETRY_LOG")
    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_save_telemetry_creates_parent_dirs(self, mock_scores_file, mock_telemetry_log):
        """Test that save_telemetry creates parent directories before writing."""
        mock_scores_file.is_file.return_value = False

        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            self.tracker.save_telemetry()

        mock_telemetry_log.parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_record_attempt_increments_and_triggers_decay(self, mock_file_path):
        """Test that record_attempt increments attempts and triggers decay at interval."""
        mock_file_path.is_file.return_value = False

        tracker = MutatorScoreTracker(self.transformers, decay_factor=0.9)
        tracker.scores["havoc"] = 10.0
        tracker.scores["spam"] = 20.0

        # Record 49 attempts — no decay yet
        for _ in range(49):
            tracker.record_attempt("deterministic")
        self.assertEqual(tracker.scores["havoc"], 10.0)
        self.assertEqual(tracker.scores["spam"], 20.0)

        # 50th attempt triggers decay
        tracker.record_attempt("deterministic")
        self.assertAlmostEqual(tracker.scores["havoc"], 10.0 * 0.9)
        self.assertAlmostEqual(tracker.scores["spam"], 20.0 * 0.9)
        self.assertEqual(tracker.attempts["deterministic"], 50)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_record_attempt_compound_decay(self, mock_file_path):
        """Test that multiple decay intervals compound the decay effect."""
        mock_file_path.is_file.return_value = False

        self.tracker.scores["havoc"] = 100.0

        # Record 100 attempts = 2 decay intervals
        for _ in range(100):
            self.tracker.record_attempt("spam")

        expected = 100.0 * (0.995**2)
        self.assertAlmostEqual(self.tracker.scores["havoc"], expected, places=5)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_strategies_and_transformers_initialized(self, mock_file_path):
        """Test that strategies and transformers are properly initialized."""
        mock_file_path.is_file.return_value = False

        tracker = MutatorScoreTracker(self.transformers)

        # Should have the three default strategies
        self.assertEqual(tracker.strategies, ["deterministic", "havoc", "spam"])

        # Should have transformer names
        self.assertIn("MockTransformer1", tracker.all_transformers)
        self.assertIn("MockTransformer2", tracker.all_transformers)
        self.assertIn("MockTransformer3", tracker.all_transformers)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_custom_strategies(self, mock_file_path):
        """Test that custom strategies can be passed to the constructor."""
        mock_file_path.is_file.return_value = False

        custom = ["deterministic", "havoc", "spam", "helper_sniper", "sniper"]
        tracker = MutatorScoreTracker(self.transformers, strategies=custom)

        self.assertEqual(tracker.strategies, custom)

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def test_load_state_handles_corrupted_file(self, mock_file_path):
        """Test that corrupted state file is handled gracefully."""
        mock_file_path.is_file.return_value = True

        with patch("builtins.open", mock_open(read_data="{ corrupted json")):
            tracker = MutatorScoreTracker(self.transformers, decay_factor=0.995)

        # Should have fresh/empty state, not crash
        self.assertEqual(dict(tracker.scores), {})
        self.assertEqual(dict(tracker.attempts), {})


class TestRecordCrashAttribution(unittest.TestCase):
    """Test crash attribution reward system."""

    @patch("lafleur.learning.MUTATOR_SCORES_FILE")
    def setUp(self, mock_file_path):
        mock_file_path.is_file.return_value = False
        self.transformers = [MagicMock(__name__="T1"), MagicMock(__name__="T2")]
        self.tracker = MutatorScoreTracker(self.transformers)

    def test_direct_reward_applied(self):
        """Direct strategy and transformers receive CRASH_DIRECT_MULTIPLIER reward."""
        with patch("lafleur.learning.CRASH_ATTRIBUTION_LOG"):
            with patch("builtins.open", mock_open()):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.tracker.record_crash_attribution(
                        direct_strategy="havoc",
                        direct_transformers=["TypeInstabilityInjector", "OperatorSwapper"],
                        lineage_mutations=[],
                    )

        expected_reward = self.tracker.REWARD_INCREMENT * self.tracker.CRASH_DIRECT_MULTIPLIER
        self.assertEqual(self.tracker.scores["havoc"], expected_reward)
        self.assertEqual(self.tracker.scores["TypeInstabilityInjector"], expected_reward)
        self.assertEqual(self.tracker.scores["OperatorSwapper"], expected_reward)

    def test_lineage_reward_applied(self):
        """Ancestor mutations receive CRASH_LINEAGE_MULTIPLIER reward."""
        lineage = [
            {"strategy": "deterministic", "transformers": ["ConstantPerturbator"]},
            {"strategy": "spam", "transformers": ["ForLoopInjector", "ForLoopInjector"]},
        ]
        with patch("lafleur.learning.CRASH_ATTRIBUTION_LOG"):
            with patch("builtins.open", mock_open()):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.tracker.record_crash_attribution(
                        direct_strategy="havoc",
                        direct_transformers=["T1"],
                        lineage_mutations=lineage,
                    )

        lineage_reward = self.tracker.REWARD_INCREMENT * self.tracker.CRASH_LINEAGE_MULTIPLIER
        self.assertEqual(self.tracker.scores["deterministic"], lineage_reward)
        self.assertEqual(self.tracker.scores["ConstantPerturbator"], lineage_reward)
        self.assertEqual(self.tracker.scores["spam"], lineage_reward)
        # ForLoopInjector appears twice in lineage — should get 2x lineage reward
        self.assertEqual(self.tracker.scores["ForLoopInjector"], lineage_reward * 2)

    def test_direct_and_lineage_rewards_stack(self):
        """A strategy appearing in both direct and lineage gets both rewards."""
        lineage = [
            {"strategy": "havoc", "transformers": ["T1"]},
        ]
        with patch("lafleur.learning.CRASH_ATTRIBUTION_LOG"):
            with patch("builtins.open", mock_open()):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.tracker.record_crash_attribution(
                        direct_strategy="havoc",
                        direct_transformers=["T1"],
                        lineage_mutations=lineage,
                    )

        direct_reward = self.tracker.REWARD_INCREMENT * self.tracker.CRASH_DIRECT_MULTIPLIER
        lineage_reward = self.tracker.REWARD_INCREMENT * self.tracker.CRASH_LINEAGE_MULTIPLIER
        self.assertEqual(self.tracker.scores["havoc"], direct_reward + lineage_reward)
        self.assertEqual(self.tracker.scores["T1"], direct_reward + lineage_reward)

    def test_empty_strategy_skipped(self):
        """Empty direct_strategy doesn't add score to empty string key."""
        with patch("lafleur.learning.CRASH_ATTRIBUTION_LOG"):
            with patch("builtins.open", mock_open()):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.tracker.record_crash_attribution(
                        direct_strategy="",
                        direct_transformers=[],
                        lineage_mutations=[],
                    )

        self.assertEqual(self.tracker.scores[""], 0.0)

    def test_log_entry_written(self):
        """Crash attribution JSONL log is written."""
        mock_file = mock_open()
        with patch("lafleur.learning.CRASH_ATTRIBUTION_LOG") as mock_log_path:
            mock_log_path.parent.mkdir = MagicMock()
            with patch("builtins.open", mock_file):
                with patch("sys.stderr", new_callable=io.StringIO):
                    self.tracker.record_crash_attribution(
                        direct_strategy="havoc",
                        direct_transformers=["T1"],
                        lineage_mutations=[{"strategy": "spam", "transformers": ["T2"]}],
                        fingerprint="ASSERT:test",
                        parent_id="42.py",
                    )

        # Verify file was written to
        mock_file.assert_called()
        written = mock_file().write.call_args[0][0]
        entry = json.loads(written.strip())
        self.assertEqual(entry["fingerprint"], "ASSERT:test")
        self.assertEqual(entry["parent_id"], "42.py")
        self.assertEqual(entry["direct"]["strategy"], "havoc")
        self.assertEqual(entry["direct"]["transformers"], ["T1"])
        self.assertEqual(entry["lineage_depth"], 1)
        self.assertEqual(entry["lineage_strategies"], ["spam"])
        self.assertEqual(entry["lineage_transformers"], ["T2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
