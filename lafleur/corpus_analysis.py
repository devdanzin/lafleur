"""
Corpus analysis and statistics for lafleur fuzzing sessions.

This module provides functionality to analyze the evolutionary history
of the fuzzing corpus, computing statistics about file sizes, execution
times, lineage depths, and mutation effectiveness.
"""

from __future__ import annotations

import statistics
from collections import Counter
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lafleur.corpus_manager import CorpusManager


def calculate_distribution(values: list[int | float]) -> dict[str, float | None]:
    """
    Calculate descriptive statistics for a list of numeric values.

    Args:
        values: List of numeric values to analyze.

    Returns:
        Dictionary with min, max, mean, and median. Returns zeros/None for empty lists.
    """
    if not values:
        return {"min": None, "max": None, "mean": None, "median": None}

    return {
        "min": min(values),
        "max": max(values),
        "mean": round(statistics.mean(values), 2),
        "median": round(statistics.median(values), 2),
    }


def generate_corpus_stats(corpus_manager: CorpusManager) -> dict[str, Any]:
    """
    Generate comprehensive statistics about the fuzzing corpus.

    Analyzes the evolutionary history, file characteristics, and mutation
    effectiveness from the corpus manager's state.

    Args:
        corpus_manager: The CorpusManager instance containing corpus metadata.

    Returns:
        Dictionary containing corpus statistics including:
        - Global counts (total files, sterile rate)
        - Distributions (file size, execution time, depth)
        - Tree topology (roots, leaves, max depth)
        - Mutation intelligence (successful mutation histogram)
    """
    # Access the per-file coverage metadata
    per_file_coverage = corpus_manager.coverage_state.state.get("per_file_coverage", {})

    total_files = len(per_file_coverage)

    # Handle empty corpus
    if total_files == 0:
        return {
            "total_files": 0,
            "sterile_count": 0,
            "sterile_rate": 0.0,
            "viable_count": 0,
            "file_size_distribution": calculate_distribution([]),
            "execution_time_distribution": calculate_distribution([]),
            "lineage_depth_distribution": calculate_distribution([]),
            "mutations_since_find_distribution": calculate_distribution([]),
            "root_count": 0,
            "leaf_count": 0,
            "max_depth": 0,
            "successful_strategies": {},
            "successful_mutators": {},
        }

    # Collect data for analysis
    sterile_count = 0
    file_sizes: list[int] = []
    execution_times: list[float] = []
    lineage_depths: list[int] = []
    mutations_since_find: list[int] = []
    parent_ids: set[str] = set()
    all_file_ids: set[str] = set()
    max_depth = 0
    mutation_counter: Counter[str] = Counter()  # Strategies
    mutator_counter: Counter[str] = Counter()  # Individual transformers

    for filename, metadata in per_file_coverage.items():
        all_file_ids.add(filename)

        # Count sterile files
        if metadata.get("is_sterile", False):
            sterile_count += 1

        # Collect numeric values for distributions
        if "file_size_bytes" in metadata:
            file_sizes.append(metadata["file_size_bytes"])

        if "execution_time_ms" in metadata:
            execution_times.append(metadata["execution_time_ms"])

        depth = metadata.get("lineage_depth", 0)
        lineage_depths.append(depth)
        max_depth = max(max_depth, depth)

        if "mutations_since_last_find" in metadata:
            mutations_since_find.append(metadata["mutations_since_last_find"])

        # Track parent relationships for tree topology
        parent_id = metadata.get("parent_id")
        if parent_id is not None:
            parent_ids.add(parent_id)

        # Count successful mutations by strategy and individual mutators
        discovery_mutation = metadata.get("discovery_mutation", {})
        if discovery_mutation:
            strategy = discovery_mutation.get("strategy", "unknown")
            mutation_counter[strategy] += 1

            # Also count individual transformers/mutators
            transformers = discovery_mutation.get("transformers", [])
            for transformer in transformers:
                mutator_counter[transformer] += 1

    # Calculate tree topology
    root_count = sum(
        1 for metadata in per_file_coverage.values() if metadata.get("parent_id") is None
    )

    # Leaf files are those that never appear as a parent
    leaf_count = len(all_file_ids - parent_ids)

    # Calculate sterile rate
    sterile_rate = sterile_count / total_files if total_files > 0 else 0.0

    return {
        # Global counts
        "total_files": total_files,
        "sterile_count": sterile_count,
        "sterile_rate": round(sterile_rate, 4),
        "viable_count": total_files - sterile_count,
        # Distributions
        "file_size_distribution": calculate_distribution(file_sizes),
        "execution_time_distribution": calculate_distribution(execution_times),
        "lineage_depth_distribution": calculate_distribution(lineage_depths),
        "mutations_since_find_distribution": calculate_distribution(mutations_since_find),
        # Tree topology
        "root_count": root_count,
        "leaf_count": leaf_count,
        "max_depth": max_depth,
        # Mutation intelligence (convert Counter to dict for JSON serialization)
        "successful_strategies": dict(mutation_counter.most_common()),
        "successful_mutators": dict(mutator_counter.most_common()),
    }
