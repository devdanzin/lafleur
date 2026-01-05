import unittest
from lafleur.orchestrator import InterestingnessScorer, NewCoverageInfo


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
        """Test that high exit counts trigger a bonus."""
        jit_stats = {"max_exit_count": 51}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 20.0)

        # Check boundary
        jit_stats = {"max_exit_count": 50}
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 0.0)

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
            "max_exit_count": 100,  # +20
            "max_chain_depth": 5,  # +10
            "min_code_size": 3,  # +5
        }
        scorer = InterestingnessScorer(jit_stats=jit_stats, **self.scorer_args)
        score = scorer.calculate_score()
        self.assertEqual(score, 85.0)


if __name__ == "__main__":
    unittest.main()
