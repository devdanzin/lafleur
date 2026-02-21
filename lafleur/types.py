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

from lafleur.coverage import HarnessCoverage


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
# LineageHarnessData / CorpusFileMetadata — per_file_coverage entry typing
# ---------------------------------------------------------------------------


class LineageHarnessData(TypedDict, total=False):
    """Coverage data for a single harness within a lineage profile.

    Unlike HarnessCoverage (which uses Counter[int] for hit counts),
    lineage profiles use set[int] since they only track presence/absence
    across the ancestry chain.
    """

    uops: set[int]
    edges: set[int]
    rare_events: set[int]
    max_trace_length: int
    max_side_exits: int


class CorpusFileMetadata(TypedDict, total=False):
    """Metadata for a single corpus file in per_file_coverage.

    This is the most widely accessed data structure in the codebase.
    Uses total=False because:
    - Old pickle files may lack fields added in later versions
      (content_hash, coverage_hash, mutation_seed were added post-launch).
    - Some fields (subsumed_children_count) are only set by specific
      operations and may not exist on most entries.
    - All consumers already use .get() with defaults.

    See doc/dev/05_state_and_data_formats.md for field semantics.
    """

    # --- Identity & lineage ---
    parent_id: str | None
    lineage_depth: int
    content_hash: str
    coverage_hash: str

    # --- Discovery context ---
    discovery_time: str  # ISO 8601
    execution_time_ms: int
    file_size_bytes: int
    discovery_mutation: MutationInfo
    mutation_seed: int

    # --- Coverage data ---
    baseline_coverage: dict[str, HarnessCoverage]
    lineage_coverage_profile: dict[str, LineageHarnessData]

    # --- Mutable runtime state ---
    mutations_since_last_find: int
    total_finds: int
    is_sterile: bool

    # --- Post-hoc additions (may be absent on most entries) ---
    subsumed_children_count: int  # Set by prune_corpus only


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
