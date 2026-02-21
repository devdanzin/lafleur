"""
Artifact management and telemetry for the lafleur fuzzer.

This module provides:
- ArtifactManager ("The Librarian"): log processing, crash detection, artifact saving
- TelemetryManager: run statistics persistence and time-series logging
"""

from __future__ import annotations

import difflib
import json
import random
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent
from typing import TYPE_CHECKING

import psutil
from compression import zstd

from lafleur.analysis import CrashFingerprinter, CrashSignature, CrashType
from lafleur.corpus_analysis import generate_corpus_stats
from lafleur.corpus_manager import CORPUS_DIR
from lafleur.health import extract_error_excerpt
from lafleur.utils import save_run_stats

if TYPE_CHECKING:
    from lafleur.corpus_manager import CorpusManager
    from lafleur.coverage import CoverageManager
    from lafleur.health import HealthMonitor
    from lafleur.learning import MutatorScoreTracker
    from lafleur.types import MutationInfo

# Log processing constants
TIMEOUT_LOG_COMPRESSION_THRESHOLD = 1_048_576  # 1 MB
TRUNCATE_HEAD_SIZE = 50 * 1024  # 50 KB
TRUNCATE_TAIL_SIZE = 300 * 1024  # 300 KB

# Keywords that indicate a crash even if exit code is 0.
# Matching is case-insensitive (keyword.lower() vs log_content.lower()).
# Trailing spaces in "Assertion " and "Abort " prevent false positives
# on Python-level exceptions like AssertionError and AbortError.
CRASH_KEYWORDS = [
    "Segmentation fault",
    "JITCorrectnessError",
    "Assertion ",
    "Abort ",
    "Fatal Python error",
    "panic",
    "AddressSanitizer",
]


class ArtifactManager:
    """
    Manages saving and processing of fuzzer artifacts.

    This class handles log file processing, crash detection, and saving of
    various artifact types (crashes, timeouts, divergences, regressions).
    """

    def __init__(
        self,
        crashes_dir: Path,
        timeouts_dir: Path,
        divergences_dir: Path,
        regressions_dir: Path,
        fingerprinter: CrashFingerprinter,
        max_timeout_log_bytes: int,
        max_crash_log_bytes: int,
        session_fuzz: bool = False,
        health_monitor: "HealthMonitor | None" = None,
    ):
        """
        Initialize the ArtifactManager.

        Args:
            crashes_dir: Directory to save crash artifacts
            timeouts_dir: Directory to save timeout artifacts
            divergences_dir: Directory to save divergence artifacts
            regressions_dir: Directory to save regression artifacts
            fingerprinter: CrashFingerprinter instance for crash analysis
            max_timeout_log_bytes: Maximum size for timeout logs before truncation
            max_crash_log_bytes: Maximum size for crash logs before truncation
            session_fuzz: Whether session fuzzing mode is enabled
            health_monitor: Optional HealthMonitor for adverse event tracking
        """
        self.crashes_dir = crashes_dir
        self.timeouts_dir = timeouts_dir
        self.divergences_dir = divergences_dir
        self.regressions_dir = regressions_dir
        self.fingerprinter = fingerprinter
        self.max_timeout_log_bytes = max_timeout_log_bytes
        self.max_crash_log_bytes = max_crash_log_bytes
        self.session_fuzz = session_fuzz
        self.health_monitor = health_monitor
        self.last_crash_fingerprint: str = ""

        # Ensure directories exist
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        self.timeouts_dir.mkdir(parents=True, exist_ok=True)
        self.divergences_dir.mkdir(parents=True, exist_ok=True)
        self.regressions_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _get_log_suffix(processed_log_path: Path) -> str:
        """Return the appropriate log suffix for a processed log file.

        Handles truncated ('_truncated.log'), compressed ('.log.zst'),
        and plain ('.log') log files.
        """
        if processed_log_path.name.endswith("_truncated.log"):
            return "_truncated.log"
        elif processed_log_path.name.endswith(".log.zst"):
            return ".log.zst"
        return ".log"

    def _safe_copy(
        self, src: Path, dst: Path, label: str, *, preserve_metadata: bool = False
    ) -> bool:
        """Copy a file, logging on OSError instead of crashing.

        Args:
            src: Source path.
            dst: Destination path.
            label: Human-readable label for error messages (e.g. "regression file").
            preserve_metadata: If True, use shutil.copy2 to preserve timestamps.

        Returns:
            True if the copy succeeded, False otherwise.
        """
        # Validate arguments — a MagicMock or other non-path reaching here
        # can cause catastrophic fd corruption (see: MagicMock.__index__ == 1).
        if not isinstance(src, (str, Path)):
            print(  # type: ignore[unreachable]
                f"  [!] BUG: _safe_copy called with invalid src type "
                f"{type(src).__name__} for {label}. Skipping.",
                file=sys.stderr,
            )
            return False
        if not isinstance(dst, (str, Path)):
            print(  # type: ignore[unreachable]
                f"  [!] BUG: _safe_copy called with invalid dst type "
                f"{type(dst).__name__} for {label}. Skipping.",
                file=sys.stderr,
            )
            return False

        try:
            if preserve_metadata:
                shutil.copy2(src, dst)
            else:
                shutil.copy(src, dst)
            return True
        except OSError as e:
            print(f"  [!] CRITICAL: Could not save {label}: {e}", file=sys.stderr)
            return False

    def truncate_huge_log(self, log_path: Path, original_size: int) -> Path:
        """
        Truncate a huge log file by keeping only the head and tail.

        Args:
            log_path: Path to the log file
            original_size: Original size of the log file in bytes

        Returns:
            Path to the truncated file (or original if truncation failed)
        """
        truncated_path = log_path.with_name(f"{log_path.stem}_truncated{log_path.suffix}")
        try:
            with open(log_path, "rb") as src, open(truncated_path, "wb") as dst:
                # Write Head
                dst.write(src.read(TRUNCATE_HEAD_SIZE))

                # Write Marker
                mb_size = original_size / (1024 * 1024)
                msg = f"\n\n... [Log Truncated by Lafleur: Original size {mb_size:.2f} MB] ...\n\n"
                dst.write(msg.encode("utf-8", errors="replace"))

                # Write Tail
                src.seek(original_size - TRUNCATE_TAIL_SIZE)
                dst.write(src.read(TRUNCATE_TAIL_SIZE))

            log_path.unlink()  # Delete the original huge file
            return truncated_path
        except Exception as e:
            print(f"  [!] Warning: Could not truncate huge log: {e}", file=sys.stderr)
            return log_path  # Fallback to keeping the original

    def compress_log_stream(self, log_path: Path) -> Path:
        """
        Compress a log file using streaming to avoid high memory usage.

        Args:
            log_path: Path to the log file

        Returns:
            Path to the compressed file (or original if compression failed)
        """
        compressed_path = log_path.with_suffix(".log.zst")
        try:
            # Use zstd.open for streaming compression (Python 3.14+ feature)
            with open(log_path, "rb") as src, zstd.open(compressed_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

            log_path.unlink()  # Delete the original file
            return compressed_path
        except Exception as e:
            print(f"  [!] Warning: Could not compress log stream: {e}", file=sys.stderr)
            if compressed_path.exists():
                compressed_path.unlink()
            return log_path  # Fallback to keeping the original

    def process_log_file(self, log_path: Path, max_size_bytes: int, label: str = "Log") -> Path:
        """
        Apply size policies to a log file: Truncate if huge, Compress if large, Keep if small.

        Args:
            log_path: Path to the log file
            max_size_bytes: Maximum size threshold for truncation
            label: Label for log messages (e.g., "Timeout log", "Crash log")

        Returns:
            Path to the processed file
        """
        try:
            if not log_path.exists():
                return log_path

            log_size = log_path.stat().st_size

            # Tier 3: Huge Log -> Truncate
            if log_size > max_size_bytes:
                print(
                    f"  [*] {label} is huge ({log_size / (1024 * 1024):.1f} MB), truncating...",
                    file=sys.stderr,
                )
                return self.truncate_huge_log(log_path, log_size)

            # Tier 2: Large Log -> Compress
            elif log_size > TIMEOUT_LOG_COMPRESSION_THRESHOLD:
                print(f"  [*] {label} is large, compressing with zstd...", file=sys.stderr)
                return self.compress_log_stream(log_path)

            # Tier 1: Small Log -> Keep as is
            return log_path

        except Exception as e:
            print(f"  [!] Warning: Error processing {label.lower()}: {e}", file=sys.stderr)
            return log_path

    def _save_timeout_artifact(
        self,
        source_path: Path,
        parent_path: Path,
        dest_dir: Path,
        label: str,
        *,
        log_path: Path | None = None,
    ) -> None:
        """Save a timeout artifact (source and optional processed log).

        Args:
            source_path: Path to the script that timed out.
            parent_path: Path to the parent script.
            dest_dir: Directory to save the artifact.
            label: Human-readable label for messages (e.g. "Timeout", "Regression timeout").
            log_path: Optional log file to process and save alongside the source.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)

        base_name = f"timeout_{source_path.stem}_{parent_path.name}"
        dest_source = dest_dir / f"{base_name}.py"

        if not self._safe_copy(source_path, dest_source, f"{label} source file"):
            return

        if log_path is not None:
            log_to_save = self.process_log_file(
                log_path, self.max_timeout_log_bytes, f"{label} log"
            )
            if log_to_save.exists():
                log_suffix = self._get_log_suffix(log_to_save)
                dest_log = dest_dir / f"{base_name}{log_suffix}"
                self._safe_copy(log_to_save, dest_log, f"{label} log file")
                if log_to_save != log_path:
                    log_to_save.unlink()

        print(f"  [+] {label} saved to {dest_source}", file=sys.stderr)

    def handle_timeout(
        self, child_source_path: Path, child_log_path: Path, parent_path: Path
    ) -> None:
        """
        Handle a standard timeout by saving the test case and processing the log.

        Args:
            child_source_path: Path to the child script that timed out
            child_log_path: Path to the log file from the timed out execution
            parent_path: Path to the parent script

        Returns:
            None (stat key: "timeouts_found")
        """
        print("  [!!!] TIMEOUT DETECTED! Saving test case.", file=sys.stderr)
        self._save_timeout_artifact(
            child_source_path,
            parent_path,
            self.timeouts_dir,
            "Timeout",
            log_path=child_log_path,
        )

    def save_regression_timeout(self, source_path: Path, parent_path: Path) -> None:
        """
        Save a test case that timed out with the JIT but not without.

        Args:
            source_path: Path to the script that caused the regression timeout
            parent_path: Path to the parent script

        Returns:
            None (stat key: "regression_timeouts_found")
        """
        print("  [!!!] JIT-INDUCED TIMEOUT DETECTED! Saving test case.", file=sys.stderr)
        self._save_timeout_artifact(
            source_path,
            parent_path,
            self.regressions_dir / "timeouts",
            "Regression timeout",
        )

    def save_jit_hang(self, source_path: Path, parent_path: Path) -> None:
        """
        Save a test case that timed out with the JIT enabled but not disabled.

        Args:
            source_path: Path to the script that caused the JIT hang
            parent_path: Path to the parent script

        Returns:
            None (stat key: "jit_hangs_found")
        """
        print("  [!!!] JIT-INDUCED HANG DETECTED! Saving test case.", file=sys.stderr)

        dest_dir = self.divergences_dir / "jit_hangs"
        dest_dir.mkdir(parents=True, exist_ok=True)

        dest_path = dest_dir / f"hang_{source_path.stem}_{parent_path.name}.py"
        if self._safe_copy(source_path, dest_path, "JIT hang file"):
            print(f"  [+] JIT hang saved to {dest_path}", file=sys.stderr)

    def save_standalone_crash(
        self,
        source_path: Path,
        exit_code: int,
        crash_signature: CrashSignature | None = None,
    ) -> Path:
        """Save a standalone (non-session) crash in a structured directory.

        Creates the same directory layout as save_session_crash() so that
        campaign and report tools can discover and aggregate these crashes.

        Args:
            source_path: Path to the script that triggered the crash.
            exit_code: The exit code from the crashed execution.
            crash_signature: Optional crash fingerprint metadata.

        Returns:
            Path to the created crash directory.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        random_suffix = random.randint(1000, 9999)
        crash_dir = self.crashes_dir / f"crash_{timestamp}_{random_suffix}"
        crash_dir.mkdir(parents=True, exist_ok=True)

        # Write metadata.json
        if crash_signature:
            metadata_path = crash_dir / "metadata.json"
            metadata = crash_signature.to_dict()
            metadata["timestamp"] = timestamp
            metadata_path.write_text(json.dumps(metadata, indent=2))

        dest_name = "crash_script.py"
        self._safe_copy(
            source_path, crash_dir / dest_name, "crash source file", preserve_metadata=True
        )

        reproduce_script = crash_dir / "reproduce.sh"
        reproduce_content = dedent(f"""\
            #!/bin/bash
            # Crash reproducer
            # Exit code: {exit_code}
            # Generated: {timestamp}

            python3 {dest_name}
        """)
        reproduce_script.write_text(reproduce_content)
        reproduce_script.chmod(0o755)

        return crash_dir

    def save_session_crash(
        self,
        scripts: list[Path],
        exit_code: int,
        crash_signature: CrashSignature | None = None,
        *,
        parent_id: str | None = None,
        polluter_ids: list[str] | None = None,
    ) -> Path:
        """
        Save a session crash bundle containing all scripts in the sequence.

        In session fuzzing mode, crashes may depend on JIT state built by earlier
        scripts in the sequence. This method creates a crash directory containing
        all scripts with sequential prefixes, plus a reproduce.sh script.

        Args:
            scripts: List of script paths in execution order (e.g., [parent, child])
            exit_code: The exit code from the crashed execution
            crash_signature: Optional crash fingerprint metadata

        Returns:
            Path to the created crash directory (stat key: "crashes_found" handled by caller)
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        random_suffix = random.randint(1000, 9999)
        crash_dir = self.crashes_dir / f"session_crash_{timestamp}_{random_suffix}"

        crash_dir.mkdir(parents=True, exist_ok=True)

        if crash_signature:
            metadata_path = crash_dir / "metadata.json"
            metadata = crash_signature.to_dict()
            metadata["timestamp"] = timestamp
            # Record corpus filenames for lineage tracing
            session_corpus_files: dict[str, str | list[str] | None] = {
                "warmup": parent_id,
            }
            if polluter_ids:
                session_corpus_files["polluters"] = polluter_ids
            metadata["session_corpus_files"] = session_corpus_files
            metadata_path.write_text(json.dumps(metadata, indent=2))

        script_names = []
        for i, script_path in enumerate(scripts):
            if i == len(scripts) - 1:
                dest_name = f"{i:02d}_attack.py"
            elif i == 0:
                dest_name = f"{i:02d}_warmup.py"
            else:
                dest_name = f"{i:02d}_script.py"

            dest_path = crash_dir / dest_name
            self._safe_copy(
                script_path, dest_path, f"session script {dest_name}", preserve_metadata=True
            )
            script_names.append(dest_name)

        reproduce_script = crash_dir / "reproduce.sh"
        reproduce_content = dedent(f"""
            #!/bin/bash
            # Session crash reproducer
            # Exit code: {exit_code}
            # Generated: {timestamp}

            python3 -m lafleur.driver {" ".join(script_names)}
        """).strip()

        reproduce_script.write_text(reproduce_content)
        reproduce_script.chmod(0o755)  # Make executable

        return crash_dir

    def check_for_crash(
        self,
        return_code: int,
        log_content: str,
        source_path: Path,
        log_path: Path,
        parent_path: Path | None = None,
        session_files: list[Path] | None = None,
        *,
        parent_id: str | None = None,
        mutation_info: MutationInfo | None = None,
        polluter_ids: list[str] | None = None,
    ) -> bool:
        """
        Check for crashes, determine the cause (Signal/Retcode/Keyword), and save artifacts.

        Args:
            return_code: Exit code from the child process
            log_content: Content of the log file
            source_path: Path to the script that was executed
            log_path: Path to the log file
            parent_path: Path to the parent script (for session mode)
            session_files: List of all scripts in the session (for session mode)
            parent_id: Parent corpus file being mutated (for health monitoring).
            mutation_info: Mutation context dict (for health monitoring).
            polluter_ids: Corpus filenames of polluter scripts (for session mode).

        Returns:
            True if a crash was detected and saved (stat key: "crashes_found" handled by caller)
        """
        crash_signature = None
        crash_reason = None

        strategy = mutation_info.get("strategy") if mutation_info else None

        # 1. Analyze with Fingerprinter
        if return_code != 0:
            # Ignore standard termination signals (SIGKILL=-9, SIGTERM=-15)
            # These are usually caused by timeouts or OOM killers, not JIT bugs.
            if return_code in (-9, -15):
                print(f"  [~] Ignoring signal {return_code} (SIGKILL/SIGTERM).", file=sys.stderr)
                if self.health_monitor:
                    self.health_monitor.record_ignored_crash(
                        reason=f"SIGNAL:{-return_code}",
                        returncode=return_code,
                        parent_id=parent_id,
                        strategy=strategy,
                    )
                return False

            crash_signature = self.fingerprinter.analyze(return_code, log_content)

            # Filter out crashes marked as IGNORE (OOM, allocation failures, etc.)
            if crash_signature.crash_type == CrashType.IGNORE:
                print(
                    f"  [~] Ignoring uninteresting crash: {crash_signature.fingerprint}",
                    file=sys.stderr,
                )
                if self.health_monitor:
                    self.health_monitor.record_ignored_crash(
                        reason=crash_signature.fingerprint,
                        returncode=return_code,
                        parent_id=parent_id,
                        strategy=strategy,
                    )
                return False

            # Filter out mundane Python errors (Exit Code 1).
            # This correctly handles SyntaxError and IndentationError from invalid
            # mutations — the fingerprinter classifies them as PYTHON_UNCAUGHT.
            # We must NOT use a substring check on log_content because LLTRACE
            # output and caught exceptions routinely contain "SyntaxError:" even
            # when the actual crash is a signal (SIGSEGV, SIGABRT, etc.).
            if crash_signature.crash_type == CrashType.PYTHON_UNCAUGHT:
                fp = crash_signature.fingerprint
                if "SyntaxError" in fp or "IndentationError" in fp:
                    print(
                        "  [~] Ignoring SyntaxError/IndentationError from invalid mutation.",
                        file=sys.stderr,
                    )
                if self.health_monitor:
                    self.health_monitor.record_ignored_crash(
                        reason=crash_signature.fingerprint,
                        returncode=return_code,
                        parent_id=parent_id,
                        strategy=strategy,
                        error_excerpt=extract_error_excerpt(log_content),
                    )
                return False

            crash_reason = crash_signature.fingerprint

        # 2. Check Keywords (Fallback if return code was 0 but log indicates panic)
        if not crash_reason:
            for keyword in CRASH_KEYWORDS:
                if keyword.lower() in log_content.lower():
                    # Sanitize keyword: lowercase, spaces to underscores, remove non-alphanumeric
                    safe_kw = re.sub(r"[^a-z0-9_]", "", keyword.lower().replace(" ", "_"))
                    crash_reason = f"keyword_{safe_kw}"
                    # Retroactively create a signature
                    crash_signature = CrashSignature(
                        category="KEYWORD",
                        crash_type=CrashType.UNKNOWN,
                        returncode=return_code,
                        signal_name=None,
                        fingerprint=crash_reason,
                    )
                    break

        # 3. Save Artifacts if Crash Detected
        if crash_reason:
            self.last_crash_fingerprint = crash_reason
            print(f"  [!!!] CRASH DETECTED! ({crash_reason}). Saving...", file=sys.stderr)

            # Process the log (truncate/compress) using the crash-specific limit
            log_to_save = self.process_log_file(log_path, self.max_crash_log_bytes, "Crash log")

            # Branch based on session fuzzing mode
            if self.session_fuzz and parent_path is not None:
                # Session mode: save crash bundle with all scripts
                # Use session_files if available (includes polluters), otherwise use parent+child
                scripts_to_save = session_files if session_files else [parent_path, source_path]
                num_scripts = len(scripts_to_save)
                print(
                    f"  [SESSION] Saving crash bundle with {num_scripts} script(s).",
                    file=sys.stderr,
                )
                crash_dir = self.save_session_crash(
                    scripts_to_save,
                    return_code,
                    crash_signature,
                    parent_id=parent_id,
                    polluter_ids=polluter_ids,
                )

                # Determine log destination name
                log_suffix = self._get_log_suffix(log_to_save)
                crash_log_path = crash_dir / f"session_crash{log_suffix}"

                if self._safe_copy(log_to_save, crash_log_path, "session crash log"):
                    if log_to_save != log_path:
                        log_to_save.unlink()
                    print(f"  [!!!] Session crash bundle saved to: {crash_dir}", file=sys.stderr)

            else:
                # Standard mode: save single child in structured directory
                crash_dir = self.save_standalone_crash(source_path, return_code, crash_signature)

                # Copy log into the crash directory
                log_suffix = self._get_log_suffix(log_to_save)
                crash_log_path = crash_dir / f"crash{log_suffix}"

                if self._safe_copy(log_to_save, crash_log_path, "crash log file"):
                    if log_to_save != log_path:
                        log_to_save.unlink()
                    print(f"  [!!!] Crash saved to: {crash_dir}", file=sys.stderr)

            return True

        return False

    def save_divergence(
        self, source_path: Path, jit_output: str, nojit_output: str, reason: str
    ) -> None:
        """
        Save artifacts from a JIT divergence for a given reason.

        Args:
            source_path: Path to the script that caused the divergence
            jit_output: Output from JIT-enabled execution
            nojit_output: Output from JIT-disabled execution
            reason: Reason/category for the divergence

        Returns:
            None (stat key: "divergences_found")
        """
        print(f"  [!!!] JIT DIVERGENCE DETECTED ({reason})! Saving test case.", file=sys.stderr)

        dest_dir = self.divergences_dir / reason
        dest_dir.mkdir(parents=True, exist_ok=True)

        base_filename = f"divergence_{source_path.stem}"
        dest_source_path = dest_dir / f"{base_filename}.py"

        diff_path = dest_dir / f"{base_filename}.diff"

        if not self._safe_copy(source_path, dest_source_path, "divergence source file"):
            return

        diff = difflib.unified_diff(
            nojit_output.splitlines(keepends=True),
            jit_output.splitlines(keepends=True),
            fromfile="nojit_output",
            tofile="jit_output",
        )
        try:
            diff_path.write_text("".join(diff))
        except IOError as e:
            print(f"  [!] CRITICAL: Could not save divergence diff: {e}", file=sys.stderr)
            return

        print(f"  [+] Divergence artifacts saved to {dest_dir}", file=sys.stderr)

    def save_regression(self, source_path: Path, jit_time: float, nojit_time: float) -> None:
        """
        Save a test case that causes a significant JIT performance regression.

        Args:
            source_path: Path to the script that caused the regression
            jit_time: Execution time with JIT in milliseconds
            nojit_time: Execution time without JIT in milliseconds

        Returns:
            None (stat key: "regressions_found")
        """
        print("  [!!!] JIT PERFORMANCE REGRESSION DETECTED! Saving test case.", file=sys.stderr)

        filename = f"regression_jit_{jit_time:.0f}ms_nojit_{nojit_time:.0f}ms_{source_path.name}"
        dest_path = self.regressions_dir / filename

        if self._safe_copy(source_path, dest_path, "regression file"):
            print(f"  [+] Regression saved to {dest_path}", file=sys.stderr)


class TelemetryManager:
    """Manages run statistics persistence and time-series telemetry logging.

    Extracted from ArtifactManager to separate artifact saving from telemetry
    concerns. All dependencies are required — this class is always created
    with full context by the orchestrator.
    """

    def __init__(
        self,
        run_stats: dict,
        coverage_manager: "CoverageManager",
        corpus_manager: "CorpusManager",
        score_tracker: "MutatorScoreTracker",
        timeseries_log_path: Path,
    ):
        """Initialize the TelemetryManager.

        Args:
            run_stats: Shared run statistics dictionary.
            coverage_manager: CoverageManager for coverage state access.
            corpus_manager: CorpusManager for corpus statistics.
            score_tracker: MutatorScoreTracker for telemetry saving.
            timeseries_log_path: Path to the time-series JSONL log file.
        """
        self.run_stats = run_stats
        self.coverage_manager = coverage_manager
        self.corpus_manager = corpus_manager
        self.score_tracker = score_tracker
        self.timeseries_log_path = timeseries_log_path

        # Cached corpus size to avoid expensive rglob scans
        self._cached_corpus_size_bytes: int | None = None
        self._cached_corpus_file_count: int = 0

    def update_and_save_run_stats(self, global_seed_counter: int) -> None:
        """Update dynamic run statistics and save them to the stats file."""
        self.run_stats["last_update_time"] = datetime.now(timezone.utc).isoformat()
        self.run_stats["corpus_size"] = len(
            self.coverage_manager.state.get("per_file_coverage", {})
        )
        global_cov = self.coverage_manager.state.get("global_coverage", {})
        self.run_stats["global_uops"] = len(global_cov.get("uops", {}))
        self.run_stats["global_edges"] = len(global_cov.get("edges", {}))
        self.run_stats["global_rare_events"] = len(global_cov.get("rare_events", {}))
        self.run_stats["global_seed_counter"] = global_seed_counter
        self.run_stats["corpus_file_counter"] = self.corpus_manager.corpus_file_counter

        total_finds = self.run_stats.get("new_coverage_finds", 0)
        if total_finds > 0:
            self.run_stats["average_mutations_per_find"] = (
                self.run_stats.get("sum_of_mutations_per_find", 0) / total_finds
            )

        save_run_stats(self.run_stats)

        # Generate and save corpus statistics
        try:
            corpus_stats = generate_corpus_stats(self.corpus_manager)
            corpus_stats_path = Path("corpus_stats.json")
            with open(corpus_stats_path, "w", encoding="utf-8") as f:
                json.dump(corpus_stats, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Could not save corpus stats: {e}", file=sys.stderr)

    def log_timeseries_datapoint(self) -> None:
        """Append a snapshot of the current run statistics to the time-series log."""
        datapoint = self.run_stats.copy()
        datapoint["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Add system resource metrics
        try:
            datapoint["system_load_1min"] = psutil.getloadavg()[0]
        except (OSError, AttributeError):
            datapoint["system_load_1min"] = None

        datapoint["process_rss_mb"] = round(psutil.Process().memory_info().rss / (1024 * 1024), 2)

        # Corpus size: use cache, refresh only when file count changes
        datapoint["corpus_size_mb"] = self._get_corpus_size_mb()

        # Disk usage
        try:
            datapoint["disk_usage_percent"] = psutil.disk_usage(Path.cwd()).percent
        except OSError:
            datapoint["disk_usage_percent"] = None

        try:
            with open(self.timeseries_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(datapoint) + "\n")
        except IOError as e:
            print(
                f"[!] Warning: Could not write to time-series log file: {e}",
                file=sys.stderr,
            )

        self.score_tracker.save_telemetry()

    def _get_corpus_size_mb(self) -> float | None:
        """Get corpus directory size in MB, using a cache to avoid frequent disk scans.

        The cache is invalidated when the number of corpus files changes.
        """
        try:
            current_file_count = len(self.coverage_manager.state.get("per_file_coverage", {}))

            if (
                self._cached_corpus_size_bytes is None
                or current_file_count != self._cached_corpus_file_count
            ):
                corpus_size_bytes = sum(
                    f.stat().st_size for f in CORPUS_DIR.rglob("*") if f.is_file()
                )
                self._cached_corpus_size_bytes = corpus_size_bytes
                self._cached_corpus_file_count = current_file_count

            return round(self._cached_corpus_size_bytes / (1024 * 1024), 2)
        except OSError:
            return None
