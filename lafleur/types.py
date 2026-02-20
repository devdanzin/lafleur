"""Shared type definitions for lafleur.

This module defines TypedDict types for the major dict schemas that flow
between modules. Using a dedicated types module avoids circular imports.

The TypedDicts (JitStats, MutationInfo) are used instead of dataclass
because they are persisted inside coverage_state.pkl — TypedDict is a
plain dict at runtime, so existing pickle files load without migration.

The AnalysisResult hierarchy uses frozen dataclasses to replace the
untyped dict returned by analyze_run(), enabling isinstance()-based
dispatch and preventing accidental mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict


class JitStats(TypedDict, total=False):
    """JIT vitals parsed from driver log output and stored in discovery_mutation.

    Uses total=False because:
    - Delta metrics are only present in session mode.
    - Older pickled states may lack fields added after their creation.
    - Some fields (watched_dependencies) are conditionally populated.

    See doc/dev/03_coverage_and_feedback.md for field semantics.
    """

    # Absolute metrics (always present in new data, may be missing in old pickles)
    max_exit_count: int
    max_chain_depth: int
    zombie_traces: int
    min_code_size: int
    max_exit_density: float
    watched_dependencies: list[str]

    # Delta metrics (session mode only — isolate child script's contribution)
    child_delta_max_exit_density: float
    child_delta_max_exit_count: int
    child_delta_total_exits: int | float
    child_delta_new_executors: int
    child_delta_new_zombies: int


class MutationInfo(TypedDict, total=False):
    """Metadata describing the mutation that created a corpus file.

    Stored as discovery_mutation in per_file_coverage entries.
    Uses total=False because:
    - Seed files have only {"strategy": "generative_seed"} or {"strategy": "seed"}.
    - jit_stats is injected by scoring.py after initial creation.
    - watched_dependencies moved into jit_stats but may exist at top level in old data.

    See doc/dev/05_state_and_data_formats.md for field semantics.
    """

    strategy: str
    transformers: list[str]
    jit_stats: JitStats
    watched_dependencies: list[str]  # Legacy location; newer data stores this in jit_stats
    # Fields set by specific mutation stages
    sliced: bool
    targets: list[str]
    seed: int
    runtime_seed: int


# ---------------------------------------------------------------------------
# AnalysisResult hierarchy — returned by ScoringManager.analyze_run()
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisResult:
    """Base class for all analyze_run() return values.

    Use isinstance() to determine the variant and access variant-specific fields.
    Frozen to prevent accidental mutation (a past bug source).
    """

    status: str


@dataclass(frozen=True)
class NewCoverageResult(AnalysisResult):
    """Returned when the child produced new coverage worth keeping."""

    core_code: str
    baseline_coverage: dict
    content_hash: str
    coverage_hash: str
    execution_time_ms: int
    parent_id: str | None
    mutation_info: MutationInfo
    mutation_seed: int
    jit_avg_time_ms: float | None = None
    nojit_avg_time_ms: float | None = None


@dataclass(frozen=True)
class CrashResult(AnalysisResult):
    """Returned when the child crashed."""

    mutation_info: MutationInfo
    parent_id: str | None
    fingerprint: str | None = None


@dataclass(frozen=True)
class NoChangeResult(AnalysisResult):
    """Returned when the child produced no new coverage."""

    pass


@dataclass(frozen=True)
class DivergenceResult(AnalysisResult):
    """Returned when differential testing detected a behavioral divergence."""

    mutation_info: MutationInfo
