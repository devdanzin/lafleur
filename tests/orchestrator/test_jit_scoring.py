import unittest
from lafleur.scoring import InterestingnessScorer, NewCoverageInfo


class TestJITScoring(unittest.TestCase):
    def setUp(self):
        # Base coverage info with no new coverage
        self.base_coverage = NewCoverageInfo()

        # Standard scorer args
        self.scorer_args = {
            "coverage_info": self.base_coverage,
            "parent_file_size": 100,
            "parent_lineage_edge_count": 50,
            "child_file_size": 110,
            "is_timing_mode": False,
            "jit_avg_time_ms": None,
            "nojit_avg_time_ms": None,
            "nojit_cv": None,
        }

    def test_zombie_bonus(self):
        """Test that zombie traces trigger a large bonus."""
        jit_stats = {"zombie_traces": 1}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 50.0)

    def test_tachycardia_bonus(self):
        """Test that high exit density triggers a bonus (replacing raw exit counts)."""
        # 15.0 > 12.5 (default parent 10.0 * 1.25) if we pass parent stats,
        # but here parent defaults to empty, so threshold is 10.0.
        jit_stats = {"max_exit_density": 15.0}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 20.0)

    def test_chain_bonus(self):
        """Test that deep chains trigger a bonus."""
        jit_stats = {"max_chain_depth": 4}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 10.0)

        # Check boundary
        jit_stats = {"max_chain_depth": 3}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 0.0)

    def test_stub_bonus(self):
        """Test that small code sizes trigger a bonus."""
        jit_stats = {"min_code_size": 4}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 5.0)

        # Check boundary
        jit_stats = {"min_code_size": 5}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 0.0)

        # Zero code size (invalid/none) should be ignored
        jit_stats = {"min_code_size": 0}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 0.0)

    def test_stacked_bonuses(self):
        """Test that multiple bonuses stack correctly."""
        jit_stats = {
            "zombie_traces": 1,  # +50
            "max_exit_density": 100.0,  # +20
            "max_chain_depth": 5,  # +10
            "min_code_size": 3,  # +5
        }
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 85.0)


class TestDeltaTachycardiaScoring(unittest.TestCase):
    """Tests for delta-based tachycardia scoring."""

    def setUp(self):
        self.base_coverage = NewCoverageInfo()
        self.scorer_args = {
            "coverage_info": self.base_coverage,
            "parent_file_size": 100,
            "parent_lineage_edge_count": 50,
            "child_file_size": 110,
            "is_timing_mode": False,
            "jit_avg_time_ms": None,
            "nojit_avg_time_ms": None,
            "nojit_cv": None,
        }

    def test_delta_density_above_threshold_triggers_bonus(self):
        """Density 1.0 > 0.5 threshold should trigger bonus."""
        jit_stats = {"child_delta_max_exit_density": 1.0, "child_delta_total_exits": 5}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 20.0)

    def test_delta_exits_above_threshold_triggers_bonus(self):
        """Exits 30 > 20 threshold should trigger bonus even with low density."""
        jit_stats = {"child_delta_max_exit_density": 0.1, "child_delta_total_exits": 30}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 20.0)

    def test_delta_below_both_thresholds_no_bonus(self):
        """Both below thresholds — no tachycardia bonus."""
        jit_stats = {"child_delta_max_exit_density": 0.2, "child_delta_total_exits": 10}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 0.0)

    def test_delta_metrics_take_priority_over_absolute(self):
        """Delta path is taken when delta fields are present, even if absolute is high."""
        jit_stats = {
            "max_exit_density": 50.0,  # Would trigger absolute path
            "child_delta_max_exit_density": 0.1,  # Below delta threshold
            "child_delta_total_exits": 5,  # Below delta threshold
        }
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        # Delta path taken, both below threshold → no bonus
        self.assertEqual(score, 0.0)

    def test_fallback_to_absolute_when_no_delta_metrics(self):
        """Without delta fields, fall back to absolute scoring."""
        jit_stats = {"max_exit_density": 15.0}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        # Absolute: 15.0 > 10.0 threshold → bonus
        self.assertEqual(score, 20.0)

    def test_fallback_to_absolute_when_delta_metrics_all_zero(self):
        """Zero deltas → fallback to absolute."""
        jit_stats = {
            "max_exit_density": 15.0,
            "child_delta_max_exit_density": 0.0,
            "child_delta_total_exits": 0,
        }
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        # Both deltas are 0, so fallback to absolute (15.0 > 10.0)
        self.assertEqual(score, 20.0)


if __name__ == "__main__":
    unittest.main()
