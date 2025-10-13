"""
This module contains generic, reusable helper functions and classes for the lafleur fuzzer.

It includes utilities for logging, managing run statistics, and structuring data.
"""

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from io import TextIOWrapper
from pathlib import Path
from typing import Any

RUN_STATS_FILE = Path("fuzz_run_stats.json")


def load_run_stats() -> dict[str, Any]:
    """
    Load the persistent run statistics from the JSON file.
    Returns a default structure if the file doesn't exist.
    """
    if not RUN_STATS_FILE.is_file():
        return {
            "start_time": datetime.now(timezone.utc).isoformat(),
            "last_update_time": None,
            "total_sessions": 0,
            "total_mutations": 0,
            "corpus_size": 0,
            "crashes_found": 0,
            "timeouts_found": 0,
            "divergences_found": 0,
            "new_coverage_finds": 0,
            "sum_of_mutations_per_find": 0,
            "average_mutations_per_find": 0.0,
            "global_seed_counter": 0,
            "corpus_file_counter": 0,
        }
    try:
        with open(RUN_STATS_FILE, "r", encoding="utf-8") as f:
            stats: dict[str, Any] = json.load(f)
            # Add new fields if loading an older stats file
            stats.setdefault("sum_of_mutations_per_find", 0)
            stats.setdefault("average_mutations_per_find", 0.0)
            stats.setdefault("global_seed_counter", 0)
            stats.setdefault("corpus_file_counter", 0)
            stats.setdefault("divergences_found", 0)
            return stats
    except (json.JSONDecodeError, IOError) as e:
        print(
            f"Warning: Could not load run stats file. Starting fresh. Error: {e}", file=sys.stderr
        )
        # Return a default structure on error
        return load_run_stats()


def save_run_stats(stats: dict[str, Any]) -> None:
    """
    Save the updated run statistics to the JSON file.
    """
    with open(RUN_STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, sort_keys=True)


class TeeLogger:
    """
    A file-like object that writes to both a file and another stream
    (like the original stdout), and flushes immediately.
    """

    def __init__(self, file_path: str | Path, original_stream: TextIOWrapper) -> None:
        """Initialize the logger with a file path and an existing stream."""
        self.original_stream = original_stream
        self.log_file = open(file_path, "w", encoding="utf-8")

    def write(self, message: str) -> None:
        """Write a message to both the original stream and the log file."""
        self.original_stream.write(message)
        self.log_file.write(message)
        self.flush()

    def flush(self) -> None:
        """Flushe both the original stream and the log file."""
        self.original_stream.flush()
        self.log_file.flush()

    def close(self) -> None:
        """Close the log file."""
        self.log_file.close()


@dataclass
class ExecutionResult:
    """A simple data class to hold the results of a child process execution."""

    returncode: int
    log_path: Path
    source_path: Path
    execution_time_ms: int
    is_divergence: bool = False
    jit_stdout: str | None = None
    nojit_stdout: str | None = None
    jit_avg_time_ms: float | None = None
    nojit_avg_time_ms: float | None = None
    nojit_cv: float | None = None
