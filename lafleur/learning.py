"""
Adaptive learning engine for the lafleur fuzzer.

Houses the MutatorScoreTracker, which evaluates the effectiveness of
mutation strategies and individual transformers over time. Scores are
incremented on each successful discovery and decayed periodically based
on attempt count (every DECAY_INTERVAL attempts), so that recently
successful mutators are favored while inactive ones gradually lose weight.

Selection uses an epsilon-greedy policy: with probability epsilon the
fuzzer explores uniformly, otherwise it exploits the learned weights.
A grace period (min_attempts) ensures new or rarely-used candidates
receive a neutral baseline weight until enough data is collected.
"""

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
    """Tracks the effectiveness of mutators and strategies to guide selection.

    Scoring model:
        - Each discovery adds REWARD_INCREMENT to the responsible strategy
          and transformer scores via record_success().
        - Every DECAY_INTERVAL attempts (recorded via record_attempt()),
          all scores are multiplied by decay_factor, favoring recent successes.
        - get_weights() returns per-candidate weights for random.choices():
          candidates below min_attempts get a neutral 1.0, others get their
          score (floored at WEIGHT_FLOOR). With probability epsilon, uniform
          weights are returned instead for exploration.

    State is persisted to MUTATOR_SCORES_FILE between sessions.
    """

    # Tuning constants for the adaptive learning algorithm
    REWARD_INCREMENT = 1.0  # Score added per success
    WEIGHT_FLOOR = 0.05  # Minimum weight to ensure all mutators get some chance
    DEFAULT_EPSILON = 0.1  # Probability of random exploration vs exploitation
    DECAY_INTERVAL = 50  # Apply decay every N attempts

    DEFAULT_STRATEGIES = ["deterministic", "havoc", "spam"]

    def __init__(
        self,
        all_transformers: list[type],
        decay_factor: float = 0.995,
        min_attempts: int = 10,
        strategies: list[str] | None = None,
    ):
        self.all_transformers = [t.__name__ for t in all_transformers]
        self.strategies = strategies if strategies is not None else list(self.DEFAULT_STRATEGIES)
        self.decay_factor = decay_factor
        self.min_attempts = min_attempts

        # Initialize scores and attempts from a saved state or fresh.
        self.scores: defaultdict[str, float] = defaultdict(float)
        self.attempts: defaultdict[str, int] = defaultdict(int)
        self._attempt_counter = 0
        self.load_state()

    def load_state(self):
        """Load the last known scores and attempts from a file."""
        if MUTATOR_SCORES_FILE.is_file():
            try:
                with open(MUTATOR_SCORES_FILE, "r") as f:
                    data = json.load(f)
                self.scores = defaultdict(float, data.get("scores", {}))
                self.attempts = defaultdict(int, data.get("attempts", {}))
                self._attempt_counter = data.get("attempt_counter", 0)
                print("[+] Loading mutator scores from previous run.")
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                print(
                    f"[!] Warning: Corrupted mutator scores file, starting fresh: {e}",
                    file=sys.stderr,
                )
                self.scores = defaultdict(float)
                self.attempts = defaultdict(int)

    def save_state(self):
        """Save the current scores and attempts to a file."""
        MUTATOR_SCORES_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "scores": dict(self.scores),
            "attempts": dict(self.attempts),
            "attempt_counter": self._attempt_counter,
        }
        with open(MUTATOR_SCORES_FILE, "w") as f:
            json.dump(data, f, indent=2)

    def record_attempt(self, name: str) -> None:
        """Record an attempt for a strategy or transformer, applying periodic decay."""
        self.attempts[name] += 1
        self._attempt_counter += 1
        if self._attempt_counter >= self.DECAY_INTERVAL:
            self._attempt_counter = 0
            for key in list(self.scores.keys()):
                self.scores[key] *= self.decay_factor

    def record_success(self, strategy_name: str, transformer_names: list[str]):
        """Update scores for a successful mutation."""
        print(
            f"    -> Rewarding successful strategy '{strategy_name}' and transformers: {transformer_names}",
            file=sys.stderr,
        )

        # Increment scores for the successful items
        self.scores[strategy_name] += self.REWARD_INCREMENT
        for t_name in transformer_names:
            self.scores[t_name] += self.REWARD_INCREMENT

    def get_weights(self, candidates: list[str], epsilon: float | None = None) -> list[float]:
        """
        Return a list of weights for a given list of candidates
        using an epsilon-greedy strategy with a grace period and a weight floor.
        """
        if epsilon is None:
            epsilon = self.DEFAULT_EPSILON

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
                weights.append(max(self.WEIGHT_FLOOR, score))

        return weights

    def save_telemetry(self):
        """Save a snapshot of the current effectiveness metrics to a log."""
        MUTATOR_TELEMETRY_LOG.parent.mkdir(parents=True, exist_ok=True)
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
