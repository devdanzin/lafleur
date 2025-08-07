import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Define paths for the new state and log files
MUTATOR_SCORES_FILE = Path("coverage/mutator_scores.json")
MUTATOR_TELEMETRY_LOG = Path("logs/mutator_effectiveness.jsonl")


class MutatorScoreTracker:
    """Tracks the effectiveness of mutators and strategies to guide selection."""

    def __init__(self, all_transformers: list[type], decay_factor: float = 0.995, min_attempts: int = 10):
        self.all_transformers = [t.__name__ for t in all_transformers]
        self.strategies = ["deterministic", "havoc", "spam"]
        self.decay_factor = decay_factor
        self.min_attempts = min_attempts

        # Initialize scores and attempts from a saved state or fresh.
        self.scores = defaultdict(float)
        self.attempts = defaultdict(int)
        self.load_state()

    def load_state(self):
        """Load the last known scores and attempts from a file."""
        if MUTATOR_SCORES_FILE.is_file():
            print("[+] Loading mutator scores from previous run.")
            with open(MUTATOR_SCORES_FILE, "r") as f:
                data = json.load(f)
                self.scores = defaultdict(float, data.get("scores", {}))
                self.attempts = defaultdict(int, data.get("attempts", {}))

    def save_state(self):
        """Save the current scores and attempts to a file."""
        data = {"scores": dict(self.scores), "attempts": dict(self.attempts)}
        with open(MUTATOR_SCORES_FILE, "w") as f:
            json.dump(data, f, indent=2)

    def record_success(self, strategy_name: str, transformer_names: list[str]):
        """
        Update scores for a successful mutation and apply decay.
        """
        print(f"    -> Rewarding successful strategy '{strategy_name}' and transformers: {transformer_names}", file=sys.stderr)

        # Increment scores for the successful items
        self.scores[strategy_name] += 1.0
        for t_name in transformer_names:
            self.scores[t_name] += 1.0

        # Apply decay to all scores to favor recent successes
        for key in list(self.scores.keys()):
            self.scores[key] *= self.decay_factor

    def get_weights(self, candidates: list[str], epsilon: float = 0.1) -> list[float]:
        """
        Return a list of weights for a given list of candidates
        using an epsilon-greedy strategy with a grace period and a weight floor.
        """
        # Epsilon-greedy: with epsilon probability, explore randomly.
        if random.random() < epsilon:
            return [1.0] * len(candidates)  # Uniform weights for exploration

        # Otherwise, exploit known high-scoring candidates.
        weights = []
        for candidate in candidates:
            if self.attempts.get(candidate, 0) < self.min_attempts:
                weights.append(1.0)  # Use a neutral, baseline weight.
            else:
                # Ensure even low-scoring mutators have a chance.
                score = self.scores.get(candidate, 0.0)
                weights.append(max(0.05, score))

        return weights

    def save_telemetry(self):
        """Save a snapshot of the current effectiveness metrics to a log."""
        success_rates = {
            name: self.scores[name] / max(1, self.attempts.get(name, 1))
            for name in self.strategies + self.all_transformers
        }
        datapoint = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scores": dict(self.scores),
            "attempts": dict(self.attempts),
            "success_rates": success_rates,
        }
        with open(MUTATOR_TELEMETRY_LOG, "a") as f:
            f.write(json.dumps(datapoint) + "\n")
