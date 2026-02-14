"""
This module contains generic, reusable helper functions and classes for the lafleur fuzzer.

It includes utilities for logging, managing run statistics, and structuring data.
"""

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

RUN_STATS_FILE = Path("fuzz_run_stats.json")

# Standard environment variables for running JIT-enabled Python targets.
# Used by both CorpusManager (sync/seed) and ExecutionManager (fuzzing runs).
FUZZING_ENV = os.environ.copy()
FUZZING_ENV.update(
    {
        "PYTHON_LLTRACE": "2",
        "PYTHON_OPT_DEBUG": "4",
        "PYTHON_JIT": "1",
        "ASAN_OPTIONS": "detect_leaks=0",
    }
)


def _default_run_stats() -> dict[str, Any]:
    """Return the canonical default run statistics structure."""
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


def load_run_stats() -> dict[str, Any]:
    """
    Load the persistent run statistics from the JSON file.
    Returns a default structure if the file doesn't exist.
    """
    if not RUN_STATS_FILE.is_file():
        return _default_run_stats()
    try:
        with open(RUN_STATS_FILE, "r", encoding="utf-8") as f:
            stats: dict[str, Any] = json.load(f)
            # Fill in any fields missing from older stats files
            defaults = _default_run_stats()
            for key, value in defaults.items():
                if key != "start_time":
                    stats.setdefault(key, value)
            return stats
    except (json.JSONDecodeError, IOError) as e:
        print(
            f"Warning: Could not load run stats file. Starting fresh. Error: {e}",
            file=sys.stderr,
        )
        return _default_run_stats()


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

    def __init__(self, file_path: str | Path, original_stream: TextIO) -> None:
        """Initialize the logger with a file path and an existing stream."""
        self.original_stream = original_stream
        self.log_file = open(file_path, "w", encoding="utf-8")

    def write(self, message: str) -> None:
        """Write a message to both the original stream and the log file."""
        self.original_stream.write(message)
        self.log_file.write(message)
        self.flush()

    def flush(self) -> None:
        """Flush both the original stream and the log file."""
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
    divergence_reason: str | None = None
    jit_output: str | None = None
    nojit_output: str | None = None
    jit_avg_time_ms: float | None = None
    nojit_avg_time_ms: float | None = None
    nojit_cv: float | None = None
    parent_path: Path | None = None
    session_files: list[Path] | None = None
