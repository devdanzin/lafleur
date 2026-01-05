import unittest
from lafleur.orchestrator import InterestingnessScorer, NewCoverageInfo


class TestDifferentialJITScoring(unittest.TestCase):
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

    def test_density_bonus_applied(self):
        """Test that a bonus is awarded when density significantly exceeds parent's."""
        parent_stats = {"max_exit_density": 10.0}
        child_stats = {"max_exit_density": 15.0}  # 15 > 12.5 (10 * 1.25)

        scorer = InterestingnessScorer(
            jit_stats=child_stats, parent_jit_stats=parent_stats, **self.scorer_args
        )
        score = scorer.calculate_score()
        self.assertEqual(score, 20.0)

    def test_density_bonus_not_applied(self):
        """Test that no bonus is awarded if density increase is small."""
        parent_stats = {"max_exit_density": 10.0}
        child_stats = {"max_exit_density": 11.0}  # 11 < 12.5

        scorer = InterestingnessScorer(
            jit_stats=child_stats, parent_jit_stats=parent_stats, **self.scorer_args
        )
        score = scorer.calculate_score()
        self.assertEqual(score, 0.0)

    def test_density_bonus_min_threshold(self):
        """Test that minimum threshold of 10.0 applies when parent density is low."""
        parent_stats = {"max_exit_density": 2.0}
        child_stats = {"max_exit_density": 9.0}  # 9 < 10 (min threshold)

        scorer = InterestingnessScorer(
            jit_stats=child_stats, parent_jit_stats=parent_stats, **self.scorer_args
        )
        score = scorer.calculate_score()
        self.assertEqual(score, 0.0)

        child_stats_high = {"max_exit_density": 11.0}  # 11 > 10
        scorer_high = InterestingnessScorer(
            jit_stats=child_stats_high, parent_jit_stats=parent_stats, **self.scorer_args
        )
        score_high = scorer_high.calculate_score()
        self.assertEqual(score_high, 20.0)

    def test_zombie_bonus_persistence(self):
        """Test that zombie bonus still works."""
        child_stats = {"zombie_traces": 1}
        scorer = InterestingnessScorer(jit_stats=child_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 50.0)


if __name__ == "__main__":
    unittest.main()
