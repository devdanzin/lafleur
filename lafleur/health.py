"""
Health monitoring for the lafleur fuzzer.

Records discrete adverse events to a JSONL log file for observability.
The HealthMonitor is designed to be non-intrusive: it never raises
exceptions and adds negligible overhead to the fuzzing loop.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Threshold for consecutive timeout warnings
CONSECUTIVE_TIMEOUT_THRESHOLD = 5

# Threshold for file size warnings (bytes)
FILE_SIZE_WARNING_THRESHOLD = 100_000  # 100KB


class HealthMonitor:
    """Track and record adverse fuzzing events for observability.

    Writes events to a JSONL log file and maintains in-memory counters
    for rate-based detection (e.g. consecutive timeouts from one parent).

    All public methods silently swallow exceptions to ensure the monitor
    never crashes the fuzzer.
    """

    def __init__(self, log_path: Path) -> None:
        """Initialize the HealthMonitor.

        Args:
            log_path: Path to the JSONL health events log file.
        """
        self.log_path = log_path
        self.counters: dict[str, int] = {}

        # State for consecutive timeout tracking
        self._timeout_parent: str | None = None
        self._timeout_streak: int = 0

    def _write_event(self, category: str, event: str, **kwargs: Any) -> None:
        """Append a single event to the JSONL log.

        Args:
            category: Event category (mutation_pipeline, execution, corpus_health).
            event: Event type name.
            **kwargs: Additional event-specific fields.
        """
        try:
            record: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "cat": category,
                "event": event,
            }
            record.update(kwargs)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass  # Never crash the fuzzer for a health event

        # Update in-memory counter
        counter_key = f"{category}.{event}"
        self.counters[counter_key] = self.counters.get(counter_key, 0) + 1

    # =========================================================================
    # Mutation Pipeline Events
    # =========================================================================

    def record_parent_parse_failure(self, parent_id: str, error: str) -> None:
        """Record a parent file that could not be parsed into AST."""
        self._write_event(
            "mutation_pipeline",
            "parent_parse_failure",
            parent_id=parent_id,
            error=error,
        )

    def record_mutation_recursion_error(self, parent_id: str) -> None:
        """Record a RecursionError during AST transformation."""
        self._write_event(
            "mutation_pipeline",
            "mutation_recursion_error",
            parent_id=parent_id,
        )

    def record_unparse_recursion_error(self, parent_id: str) -> None:
        """Record a RecursionError during ast.unparse()."""
        self._write_event(
            "mutation_pipeline",
            "unparse_recursion_error",
            parent_id=parent_id,
        )

    def record_child_script_none(self, parent_id: str, mutation_seed: int) -> None:
        """Record a mutation that produced no usable child script."""
        self._write_event(
            "mutation_pipeline",
            "child_script_none",
            parent_id=parent_id,
            mutation_seed=mutation_seed,
        )

    def record_core_code_syntax_error(self, parent_id: str | None, error: str) -> None:
        """Record core code that failed ast.parse() validation before saving."""
        self._write_event(
            "mutation_pipeline",
            "core_code_syntax_error",
            parent_id=parent_id or "seed",
            error=error,
        )

    # =========================================================================
    # Execution Events
    # =========================================================================

    def record_timeout(self, parent_id: str) -> None:
        """Record a timeout and track consecutive streaks per parent.

        Writes a consecutive_timeouts event when the streak for a single
        parent reaches CONSECUTIVE_TIMEOUT_THRESHOLD.
        """
        if parent_id == self._timeout_parent:
            self._timeout_streak += 1
        else:
            self._timeout_parent = parent_id
            self._timeout_streak = 1

        if self._timeout_streak == CONSECUTIVE_TIMEOUT_THRESHOLD:
            self._write_event(
                "execution",
                "consecutive_timeouts",
                parent_id=parent_id,
                count=self._timeout_streak,
            )

    def reset_timeout_streak(self) -> None:
        """Reset the timeout streak (call after a non-timeout result)."""
        self._timeout_streak = 0
        self._timeout_parent = None

    def record_ignored_crash(self, reason: str, returncode: int) -> None:
        """Record a crash that was detected but filtered out."""
        self._write_event(
            "execution",
            "ignored_crash",
            reason=reason,
            returncode=returncode,
        )

    def record_deepening_sterility(
        self, parent_id: str, depth: int, mutations_attempted: int
    ) -> None:
        """Record a deepening session that hit the sterility limit."""
        self._write_event(
            "execution",
            "deepening_sterility",
            parent_id=parent_id,
            depth=depth,
            mutations_attempted=mutations_attempted,
        )

    # =========================================================================
    # Corpus Health Events
    # =========================================================================

    def record_file_size_warning(self, file_id: str, size_bytes: int) -> None:
        """Record a corpus file that exceeds the size warning threshold."""
        self._write_event(
            "corpus_health",
            "file_size_warning",
            file_id=file_id,
            size_bytes=size_bytes,
        )

    def record_duplicate_rejected(self, content_hash: str, coverage_hash: str) -> None:
        """Record an interesting child rejected as a duplicate."""
        self._write_event(
            "corpus_health",
            "duplicate_rejected",
            content_hash=content_hash[:10],
            coverage_hash=coverage_hash[:10],
        )

    def record_corpus_sterility(self, parent_id: str, mutations_since_last_find: int) -> None:
        """Record a parent reaching the corpus sterility limit."""
        self._write_event(
            "corpus_health",
            "corpus_sterility_reached",
            parent_id=parent_id,
            mutations_since_last_find=mutations_since_last_find,
        )

    # =========================================================================
    # Summary
    # =========================================================================

    def get_summary(self) -> dict[str, int]:
        """Return a copy of the in-memory event counters.

        Returns:
            Dict mapping "category.event" keys to occurrence counts.
        """
        return dict(self.counters)
