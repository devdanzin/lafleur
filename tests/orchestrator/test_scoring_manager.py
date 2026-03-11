"""Tests for ScoringManager.find_new_coverage and score_and_decide_interestingness."""

import unittest
from unittest.mock import MagicMock

from lafleur.scoring import NewCoverageInfo, ScoringContext, ScoringManager


def _make_scoring_manager(
    *,
    global_coverage: dict | None = None,
    reverse_uop_map: dict | None = None,
    reverse_edge_map: dict | None = None,
    reverse_rare_event_map: dict | None = None,
    timing_fuzz: bool = False,
) -> ScoringManager:
    """Create a ScoringManager with a mocked CoverageManager."""
    cm = MagicMock()
    cm.state = {
        "global_coverage": global_coverage or {"uops": {}, "edges": {}, "rare_events": {}},
        "per_file_coverage": {},
    }
    cm.reverse_uop_map = reverse_uop_map or {}
    cm.reverse_edge_map = reverse_edge_map or {}
    cm.reverse_rare_event_map = reverse_rare_event_map or {}

    return ScoringManager(
        coverage_manager=cm,
        timing_fuzz=timing_fuzz,
        run_stats={},
    )


class TestFindNewCoverage(unittest.TestCase):
    """Tests for ScoringManager.find_new_coverage."""

    def test_empty_child_coverage(self):
        """Empty child coverage returns zero counts."""
        sm = _make_scoring_manager()
        info = sm.find_new_coverage({}, {}, parent_id="parent.py")
        self.assertFalse(info.is_interesting())
        self.assertEqual(info.total_child_edges, 0)

    def test_new_global_edge(self):
        """An edge ID not in global coverage is counted as global."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {}, "rare_events": {}},
            reverse_edge_map={42: "edge_42"},
        )
        child_cov = {"harness_0": {"edges": {42: 1}, "uops": {}, "rare_events": {}}}
        info = sm.find_new_coverage(child_cov, {}, parent_id="parent.py")
        self.assertEqual(info.global_edges, 1)
        self.assertTrue(info.is_interesting())

    def test_known_global_edge_new_relative(self):
        """An edge in global but not in parent lineage is counted as relative."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {42: 5}, "rare_events": {}},
            reverse_edge_map={42: "edge_42"},
        )
        child_cov = {"harness_0": {"edges": {42: 1}, "uops": {}, "rare_events": {}}}
        # Parent lineage has no edges for this harness
        info = sm.find_new_coverage(child_cov, {}, parent_id="parent.py")
        self.assertEqual(info.global_edges, 0)
        self.assertEqual(info.relative_edges, 1)

    def test_known_global_edge_already_in_lineage(self):
        """An edge in both global and parent lineage is not counted."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {42: 5}, "rare_events": {}},
            reverse_edge_map={42: "edge_42"},
        )
        child_cov = {"harness_0": {"edges": {42: 1}, "uops": {}, "rare_events": {}}}
        parent_lineage = {"harness_0": {"edges": {42}, "uops": set(), "rare_events": set()}}
        info = sm.find_new_coverage(child_cov, parent_lineage, parent_id="parent.py")
        self.assertEqual(info.global_edges, 0)
        self.assertEqual(info.relative_edges, 0)

    def test_seed_file_no_relative(self):
        """With parent_id=None (seed), no relative coverage is counted."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {42: 5}, "rare_events": {}},
            reverse_edge_map={42: "edge_42"},
        )
        child_cov = {"harness_0": {"edges": {42: 1}, "uops": {}, "rare_events": {}}}
        info = sm.find_new_coverage(child_cov, {}, parent_id=None)
        # 42 is already global, and parent_id is None → no relative
        self.assertEqual(info.global_edges, 0)
        self.assertEqual(info.relative_edges, 0)

    def test_new_global_uop(self):
        """A uop ID not in global coverage is counted."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {}, "rare_events": {}},
            reverse_uop_map={7: "uop_7"},
        )
        child_cov = {"harness_0": {"uops": {7: 1}, "edges": {}, "rare_events": {}}}
        info = sm.find_new_coverage(child_cov, {}, parent_id="p.py")
        self.assertEqual(info.global_uops, 1)

    def test_new_global_rare_event(self):
        """A rare event ID not in global coverage is counted."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {}, "rare_events": {}},
            reverse_rare_event_map={99: "deopt_99"},
        )
        child_cov = {"harness_0": {"uops": {}, "edges": {}, "rare_events": {99: 1}}}
        info = sm.find_new_coverage(child_cov, {}, parent_id="p.py")
        self.assertEqual(info.global_rare_events, 1)

    def test_multiple_harnesses(self):
        """Coverage across multiple harnesses is aggregated."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {}, "rare_events": {}},
            reverse_edge_map={1: "e1", 2: "e2", 3: "e3"},
        )
        child_cov = {
            "harness_0": {"edges": {1: 1, 2: 1}, "uops": {}, "rare_events": {}},
            "harness_1": {"edges": {3: 1}, "uops": {}, "rare_events": {}},
        }
        info = sm.find_new_coverage(child_cov, {}, parent_id="p.py")
        self.assertEqual(info.global_edges, 3)
        self.assertEqual(info.total_child_edges, 3)

    def test_total_child_edges_counts_all(self):
        """total_child_edges counts all edges including non-new ones."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {1: 10, 2: 10}, "rare_events": {}},
            reverse_edge_map={1: "e1", 2: "e2"},
        )
        child_cov = {"harness_0": {"edges": {1: 1, 2: 1}, "uops": {}, "rare_events": {}}}
        parent_lineage = {"harness_0": {"edges": {1, 2}, "uops": set(), "rare_events": set()}}
        info = sm.find_new_coverage(child_cov, parent_lineage, parent_id="p.py")
        self.assertEqual(info.total_child_edges, 2)
        self.assertEqual(info.global_edges, 0)
        self.assertEqual(info.relative_edges, 0)

    def test_unknown_id_uses_fallback_label(self):
        """Items with no reverse mapping still get counted (with fallback label)."""
        sm = _make_scoring_manager(
            global_coverage={"uops": {}, "edges": {}, "rare_events": {}},
            reverse_edge_map={},  # No mapping for ID 999
        )
        child_cov = {"harness_0": {"edges": {999: 1}, "uops": {}, "rare_events": {}}}
        info = sm.find_new_coverage(child_cov, {}, parent_id="p.py")
        self.assertEqual(info.global_edges, 1)


class TestScoreAndDecideInterestingness(unittest.TestCase):
    """Tests for ScoringManager.score_and_decide_interestingness."""

    def _make_ctx(self, **overrides) -> ScoringContext:
        defaults = {
            "parent_id": "parent.py",
            "mutation_info": {"strategy": "havoc", "mutator": "test"},
            "parent_file_size": 100,
            "parent_lineage_edge_count": 50,
            "child_file_size": 110,
        }
        defaults.update(overrides)
        return ScoringContext(**defaults)

    def test_seed_with_coverage_is_interesting(self):
        """Seed files (parent_id=None) with coverage are always interesting."""
        sm = _make_scoring_manager()
        info = NewCoverageInfo(global_edges=1)
        ctx = self._make_ctx(parent_id=None, mutation_info={"strategy": "seed"})
        self.assertTrue(sm.score_and_decide_interestingness(info, ctx))

    def test_seed_without_coverage_but_seed_strategy_is_interesting(self):
        """Seed files with 'seed' strategy are interesting even without coverage."""
        sm = _make_scoring_manager()
        info = NewCoverageInfo()
        ctx = self._make_ctx(parent_id=None, mutation_info={"strategy": "seed"})
        self.assertTrue(sm.score_and_decide_interestingness(info, ctx))

    def test_seed_without_coverage_or_strategy_not_interesting(self):
        """Seed files with no coverage and non-seed strategy are not interesting."""
        sm = _make_scoring_manager()
        info = NewCoverageInfo()
        ctx = self._make_ctx(parent_id=None, mutation_info={"strategy": "havoc"})
        self.assertFalse(sm.score_and_decide_interestingness(info, ctx))

    def test_mutation_with_high_score_is_interesting(self):
        """Normal mutation scoring above MIN_INTERESTING_SCORE is interesting."""
        sm = _make_scoring_manager()
        # 2 global edges = 20 points > 10 threshold
        info = NewCoverageInfo(global_edges=2)
        ctx = self._make_ctx()
        self.assertTrue(sm.score_and_decide_interestingness(info, ctx))

    def test_mutation_with_low_score_not_interesting(self):
        """Normal mutation scoring below MIN_INTERESTING_SCORE is not interesting."""
        sm = _make_scoring_manager()
        # 1 relative edge = 1 point < 10 threshold
        info = NewCoverageInfo(relative_edges=1)
        ctx = self._make_ctx()
        self.assertFalse(sm.score_and_decide_interestingness(info, ctx))

    def test_jit_zombie_triggers_interesting(self):
        """Zombie traces (50 points) should make a mutation interesting."""
        sm = _make_scoring_manager()
        info = NewCoverageInfo()
        ctx = self._make_ctx(jit_stats={"zombie_traces": 1})
        self.assertTrue(sm.score_and_decide_interestingness(info, ctx))

    def test_timing_mode_with_slowdown_is_interesting(self):
        """Timing mode with significant JIT slowdown is interesting."""
        sm = _make_scoring_manager(timing_fuzz=True)
        info = NewCoverageInfo()
        ctx = self._make_ctx(
            jit_avg_time_ms=100.0,
            nojit_avg_time_ms=10.0,
            nojit_cv=0.1,
        )
        self.assertTrue(sm.score_and_decide_interestingness(info, ctx))

    def test_timing_mode_without_slowdown_not_interesting(self):
        """Timing mode without significant slowdown is not interesting."""
        sm = _make_scoring_manager(timing_fuzz=True)
        info = NewCoverageInfo()
        ctx = self._make_ctx(
            jit_avg_time_ms=10.0,
            nojit_avg_time_ms=10.0,
            nojit_cv=0.1,
        )
        self.assertFalse(sm.score_and_decide_interestingness(info, ctx))

    def test_exactly_at_threshold_is_interesting(self):
        """Score exactly at MIN_INTERESTING_SCORE (10.0) is interesting."""
        sm = _make_scoring_manager()
        # 1 global edge = 10.0 = MIN_INTERESTING_SCORE
        info = NewCoverageInfo(global_edges=1)
        ctx = self._make_ctx()
        self.assertTrue(sm.score_and_decide_interestingness(info, ctx))

    def test_just_below_threshold_not_interesting(self):
        """Score just below MIN_INTERESTING_SCORE is not interesting."""
        sm = _make_scoring_manager()
        # 9 relative edges = 9.0 < 10.0
        info = NewCoverageInfo(relative_edges=9)
        ctx = self._make_ctx()
        self.assertFalse(sm.score_and_decide_interestingness(info, ctx))

    def test_parent_jit_stats_forwarded_to_scorer(self):
        """Parent JIT stats are used for threshold comparison."""
        sm = _make_scoring_manager()
        info = NewCoverageInfo()
        # Child density 12.0, parent density 10.0 → threshold = max(10.0, 10.0 * 1.25) = 12.5
        # 12.0 < 12.5 → no tachycardia bonus
        ctx = self._make_ctx(
            jit_stats={"max_exit_density": 12.0},
            parent_jit_stats={"max_exit_density": 10.0},
        )
        self.assertFalse(sm.score_and_decide_interestingness(info, ctx))


if __name__ == "__main__":
    unittest.main(verbosity=2)
