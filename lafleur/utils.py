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
    """Save the updated run statistics to the JSON file."""
    try:
        with open(RUN_STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, sort_keys=True)
    except (IOError, OSError) as e:
        print(
            f"Warning: Could not save run stats: {e}",
            file=sys.stderr,
        )


class TeeLogger:
    """
    A file-like object that writes to both a file and another stream
    (like the original stdout), and flushes immediately.

    Features:
    - Repeat collapsing: consecutive identical lines are collapsed into
      a single line with a (×N) suffix.
    - Verbosity filtering: when verbose=False, detail-level messages
      (individual mutator actions, per-run boilerplate, individual
      coverage discoveries) are suppressed from both console and file.
    """

    # Lines matching these prefixes are suppressed in quiet mode.
    # Checked in order — first match wins. Be specific to avoid
    # accidentally suppressing important lines.
    _QUIET_SUPPRESS_PREFIXES: tuple[str, ...] = (
        # Mutator detail lines (4-space indent + arrow)
        "    -> Injecting",
        "    -> Removing",
        "    -> Slicing",
        "    -> Spamming with:",
        "    -> Prepending",
        "    -> Swapping",
        "    -> Applying",
        "    -> Creating",
        "    -> Wrapping",
        "    -> Shuffling",
        "    -> Inserting",
        "    -> Modifying",
        "    -> Adding",
        "    -> Converting",
        "    -> Corrupting",
        "    -> Patching",
        "    -> Polluting",
        "    -> Mutating",
        "    -> Transposing",
        "    -> Normalizing",
        "    -> Sanitizing",
        "    -> Decorating",
        "    -> Variable",
        "    -> Failed",
        "    -> SyntaxError",
        "    -> Targeting",
        "    -> Run #",
        # Mutator error/warning lines (4-space indent + bracket)
        "    [!] SyntaxError",
        # Stage notifications
        "  [~] Large AST detected",
        "  [~] Running HAVOC",
        "  [~] Running DETERMINISTIC",
        "  [~] Running SPAM",
        "  [~] Running HELPER+SNIPER",
        "  [~] Running SNIPER",
        "  [~] Detected",
        "  [!] No helpers available",
        # Execution boilerplate
        "[COVERAGE]",
        "[SESSION]",
        "[MIXER]",
        # Individual relative discoveries (globals are important, relatives are noisy)
        "[NEW RELATIVE EDGE]",
        "[NEW RELATIVE UOP]",
        "[NEW RELATIVE RARE_EVENT]",
        # Non-interesting child results
        "  [+] Child IS NOT interesting",
        # Corpus score calculation (happens twice per mutation cycle)
        "[+] Calculating corpus scores",
    )

    def __init__(
        self,
        file_path: str | Path,
        original_stream: TextIO,
        verbose: bool = True,
    ) -> None:
        """Initialize the logger with a file path and an existing stream.

        Args:
            file_path: Path to the log file.
            original_stream: The original stream (e.g., sys.stdout) to tee to.
            verbose: If False, suppress detail-level messages. Default True.
        """
        self.original_stream = original_stream
        self.log_file = open(file_path, "w", encoding="utf-8")
        self.verbose = verbose

        # Repeat collapsing state
        self._last_line: str | None = None
        self._repeat_count: int = 0
        # Track whether the last write was suppressed, so the trailing
        # "\n" from print() can be swallowed too.
        self._last_was_suppressed: bool = False

    def _is_suppressed(self, line: str) -> bool:
        """Check if a line should be suppressed in quiet mode."""
        if self.verbose:
            return False
        stripped = line.lstrip()
        # Use the original line for prefixes that include leading whitespace
        for prefix in self._QUIET_SUPPRESS_PREFIXES:
            if line.startswith(prefix) or stripped.startswith(prefix):
                return True
        return False

    def _flush_repeat(self) -> None:
        """Flush the buffered repeated line, if any."""
        if self._last_line is None:
            return

        if self._repeat_count > 1:
            suffix = f" (×{self._repeat_count})"
            # Insert suffix before trailing newline if present
            if self._last_line.endswith("\n"):
                output = self._last_line[:-1] + suffix + "\n"
            else:
                output = self._last_line + suffix
        else:
            output = self._last_line

        self.original_stream.write(output)
        self.log_file.write(output)

        self._last_line = None
        self._repeat_count = 0

    def write(self, message: str) -> None:
        """Write a message to both the original stream and the log file.

        Consecutive identical lines are collapsed. Empty writes and bare
        newlines are passed through immediately without affecting the
        repeat buffer.
        """
        # Pass through empty strings and bare newlines (print() separators)
        if not message or message == "\n":
            # Swallow the trailing "\n" that print() sends after a suppressed line.
            if message == "\n" and self._last_was_suppressed:
                self._last_was_suppressed = False
                return
            # Flush any pending repeat first
            if message == "\n" and self._last_line is not None:
                # This newline might be print()'s end='\n' after a
                # line that's already buffered with its own \n.
                # Only pass through if the buffered line doesn't end with \n.
                if not self._last_line.endswith("\n"):
                    self._flush_repeat()
                    self.original_stream.write(message)
                    self.log_file.write(message)
                    self._do_flush()
                    return
                # Otherwise, the \n is redundant — ignore it
                return
            self.original_stream.write(message)
            self.log_file.write(message)
            self._do_flush()
            return

        # Check verbosity suppression
        if self._is_suppressed(message):
            self._last_was_suppressed = True
            return
        self._last_was_suppressed = False

        # Repeat collapsing: compare stripped content
        stripped = message.rstrip("\n")
        if stripped == "" and message != "":
            # Message is only newlines — pass through
            self._flush_repeat()
            self.original_stream.write(message)
            self.log_file.write(message)
            self._do_flush()
            return

        if self._last_line is not None:
            last_stripped = self._last_line.rstrip("\n")
            if stripped == last_stripped:
                self._repeat_count += 1
                return

        # Different line — flush the old one and buffer the new one
        self._flush_repeat()
        self._last_line = message
        self._repeat_count = 1

    def _do_flush(self) -> None:
        """Flush both underlying streams."""
        self.original_stream.flush()
        self.log_file.flush()

    def flush(self) -> None:
        """Flush any buffered repeat and both underlying streams."""
        self._flush_repeat()
        self._do_flush()

    def close(self) -> None:
        """Flush any buffered repeat and close the log file."""
        self._flush_repeat()
        self._do_flush()
        self.log_file.close()

    @property
    def encoding(self) -> str:
        """Return the encoding of the original stream."""
        return getattr(self.original_stream, "encoding", "utf-8")

    def isatty(self) -> bool:
        """Return whether the original stream is a TTY."""
        return hasattr(self.original_stream, "isatty") and self.original_stream.isatty()

    def fileno(self) -> int:
        """Return the file descriptor of the original stream.

        Raises OSError if the original stream doesn't have a file descriptor.
        """
        if hasattr(self.original_stream, "fileno"):
            return self.original_stream.fileno()
        raise OSError("TeeLogger does not have a file descriptor")


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
