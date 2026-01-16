"""
Child process execution for the lafleur fuzzer.

This module provides the ExecutionManager class ("The Muscle") which handles:
- Running child processes for coverage gathering
- Differential testing (JIT vs non-JIT comparison)
- Performance timing fuzzing
- Session mode execution with the mixer strategy
"""

import os
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from textwrap import dedent, indent
from typing import TYPE_CHECKING

from lafleur.coverage import PROTO_TRACE_REGEX, OPTIMIZED_TRACE_REGEX
from lafleur.utils import ExecutionResult

if TYPE_CHECKING:
    from lafleur.artifacts import ArtifactManager
    from lafleur.corpus_manager import CorpusManager


# Environment variables for JIT execution with debug logging
ENV = os.environ.copy()
ENV.update(
    {
        "PYTHON_LLTRACE": "2",
        "PYTHON_OPT_DEBUG": "4",
        "PYTHON_JIT": "1",
        "ASAN_OPTIONS": "detect_leaks=0",
    }
)

# Session fuzzing: The Mixer strategy
MIXER_PROBABILITY = 0.3  # 30% chance to prepend polluter scripts

# Code snippet for differential testing state serialization
SERIALIZATION_SNIPPET = dedent("""
    # --- BEGIN INJECTED SERIALIZATION CODE ---
    import types
    import inspect
    import json

    class LafleurStateEncoder(json.JSONEncoder):
        '''A custom JSON encoder that handles complex types found in locals().'''
        def default(self, o):
            if isinstance(o, bytes):
                try:
                    # Try to decode as UTF-8, with a fallback for binary data
                    return o.decode('utf-8', errors='replace')
                except Exception:
                    return repr(o)
            elif inspect.isfunction(o):
                return f"<function: {o.__name__}>"
            elif inspect.isclass(o):
                return f"<class: {o.__name__}>"
            elif inspect.ismodule(o):
                return None  # Exclude modules entirely
            elif hasattr(o, '__class__') and hasattr(o.__class__, '__module__') and o.__class__.__module__ == '__main__':
                 return f"<instance of: {o.__class__.__name__}>"

            # For any other unknown types, use a generic repr
            try:
                return super().default(o)
            except TypeError:
                return f"<unserializable type: {type(o).__name__}>"

    # Filter out keys we don't care about before serialization
    state_dict = locals().copy()
    IGNORE_KEYS = {
        '__name__', '__doc__', '__package__', '__loader__',
        '__spec__', '__builtins__', 'LafleurStateEncoder', 'json',
        'types', 'inspect'
    }
    filtered_state = {k: v for k, v in state_dict.items() if k not in IGNORE_KEYS and not k.startswith('__')}

    # Check if the harness loop actually ran and produced a result
    if 'final_harness_locals' in filtered_state:
        print(json.dumps(filtered_state['final_harness_locals'], sort_keys=True, indent=2, cls=LafleurStateEncoder))
    # --- END INJECTED SERIALIZATION CODE ---
""")


class ExecutionManager:
    """
    Manages child process execution for the fuzzer.

    This class handles running child scripts with various modes:
    - Differential testing (comparing JIT vs non-JIT execution)
    - Timing fuzzing (measuring performance differences)
    - Coverage gathering (normal execution with JIT debug logging)
    - Session mode with the mixer strategy
    """

    def __init__(
        self,
        target_python: str,
        timeout: int,
        artifact_manager: "ArtifactManager",
        corpus_manager: "CorpusManager",
        differential_testing: bool = False,
        timing_fuzz: bool = False,
        session_fuzz: bool = False,
    ):
        """
        Initialize the ExecutionManager.

        Args:
            target_python: Path to the Python interpreter to use
            timeout: Timeout in seconds for child processes
            artifact_manager: ArtifactManager for handling timeouts and crashes
            corpus_manager: CorpusManager for mixer strategy parent selection
            differential_testing: Enable differential testing mode
            timing_fuzz: Enable timing-based fuzzing mode
            session_fuzz: Enable session mode execution
        """
        self.target_python = target_python
        self.timeout = timeout
        self.artifact_manager = artifact_manager
        self.corpus_manager = corpus_manager
        self.differential_testing = differential_testing
        self.timing_fuzz = timing_fuzz
        self.session_fuzz = session_fuzz

    def _run_timed_trial(
        self, source_path: Path, num_runs: int, jit_enabled: bool
    ) -> tuple[float | None, bool, float | None]:
        """
        Run a script multiple times to get a stable execution time.

        Args:
            source_path: Path to the script to run
            num_runs: Number of runs to perform
            jit_enabled: Whether to enable JIT compilation

        Returns:
            Tuple of (average_time_ms, did_timeout, coefficient_of_variation).
            Returns None for time and CV if measurements are unstable.
        """
        timings_ms: list[float] = []
        env = os.environ.copy()
        env["PYTHON_JIT"] = "1" if jit_enabled else "0"
        # Explicitly disable our noisy debug logs for timing runs
        env["PYTHON_LLTRACE"] = "0"
        env["PYTHON_OPT_DEBUG"] = "0"

        print(f"[TIMING] Running timed trial with JIT={jit_enabled}.", file=sys.stderr)

        # Run N+2 times and discard the min/max runs as outliers
        for _ in range(num_runs + 2):
            try:
                start_time = time.monotonic()
                subprocess.run(
                    [self.target_python, str(source_path)],
                    capture_output=True,  # We only care about time, not output
                    timeout=self.timeout,
                    env=env,
                    check=True,  # Raise exception on non-zero exit code
                )
                end_time = time.monotonic()
                timings_ms.append((end_time - start_time) * 1000)
            except subprocess.TimeoutExpired:
                return None, True, None  # Signal a timeout
            except subprocess.CalledProcessError:
                # The script crashed during a timing run. This is a bug, but not a
                # performance regression. We'll treat it as unstable.
                print("  [~] Child crashed during timing run, aborting.", file=sys.stderr)
                return None, False, None

        if len(timings_ms) < 3:
            return None, False, None  # Not enough data points

        timings_ms.sort()
        stable_timings = timings_ms[1:-1]  # Discard min and max outliers

        mean = statistics.mean(stable_timings)
        print(f"  [~] Mean for JIT={jit_enabled}: {mean / 1000:.3f}s.", file=sys.stderr)
        if mean == 0:
            return 0.0, False, 0.0  # Extremely fast, no variation

        stdev = statistics.stdev(stable_timings)
        cv = stdev / mean  # Coefficient of Variation

        # If variation is > 20%, the measurement is too noisy to be reliable.
        CV_THRESHOLD = 0.20
        if cv > CV_THRESHOLD:
            print(
                f"  [~] Timing measurements too noisy (CV={cv:.2f}). Discarding run.",
                file=sys.stderr,
            )
            return None, False, None

        return mean, False, cv

    def _filter_jit_stderr(self, stderr_content: str) -> str:
        """
        Remove known, benign JIT debug messages from stderr output.

        Args:
            stderr_content: Raw stderr output from a subprocess

        Returns:
            Filtered stderr with JIT tracing output removed
        """
        lines = stderr_content.splitlines()
        # Filter out lines that are known to be part of the JIT's tracing output
        filtered_lines = [
            line
            for line in lines
            if not line.strip().startswith(
                ("Created a proto-trace", "Optimized trace", "SIDE EXIT")
            )
        ]
        return "\n".join(filtered_lines)

    def execute_child(
        self,
        source_code: str,
        child_source_path: Path,
        child_log_path: Path,
        parent_path: Path,
    ) -> tuple[ExecutionResult | None, str | None]:
        """
        Execute a child script, checking for divergences, timing, and gathering coverage.

        The execution proceeds through up to three stages:
        1. Differential Correctness Fuzzing (if enabled)
        2. Performance Timing Fuzzing (if enabled)
        3. Normal Coverage-Gathering Run

        Args:
            source_code: The source code to execute
            child_source_path: Path where the child script will be written
            child_log_path: Path for the execution log
            parent_path: Path to the parent script

        Returns:
            Tuple of (ExecutionResult or None, stat_key or None).
            stat_key indicates which run_stat should be incremented:
            - "timeouts_found": Normal timeout
            - "jit_hangs_found": JIT-specific hang during differential testing
            - "regression_timeouts_found": Performance regression timeout
            - None: No stat update needed (success or handled elsewhere)
        """
        jit_avg_ms: float | None = None
        nojit_avg_ms: float | None = None
        nojit_cv: float | None = None

        # --- Stage 1: Differential Correctness Fuzzing (if enabled) ---
        if self.differential_testing:
            instrumented_code = source_code + "\n" + SERIALIZATION_SNIPPET
            child_source_path.write_text(instrumented_code)

            # Run Non-JIT
            nojit_run = None
            try:
                nojit_env = ENV.copy()
                nojit_env["PYTHON_JIT"] = "0"
                # Disable debug logs for a clean stderr comparison
                nojit_env["PYTHON_LLTRACE"] = "0"
                nojit_env["PYTHON_OPT_DEBUG"] = "0"
                print("[DIFFERENTIAL] Running child with JIT=False.", file=sys.stderr)
                nojit_run = subprocess.run(
                    [self.target_python, str(child_source_path)],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=nojit_env,
                )
            except subprocess.TimeoutExpired:
                self.artifact_manager.handle_timeout(child_source_path, child_log_path, parent_path)
                return None, "timeouts_found"

            # Run JIT
            jit_run = None
            try:
                jit_env = ENV.copy()
                jit_env["PYTHON_JIT"] = "1"
                jit_env["PYTHON_LLTRACE"] = "0"
                jit_env["PYTHON_OPT_DEBUG"] = "0"
                print("[DIFFERENTIAL] Running child with JIT=True.", file=sys.stderr)
                jit_run = subprocess.run(
                    [self.target_python, str(child_source_path)],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=jit_env,
                )
            except subprocess.TimeoutExpired:
                self.artifact_manager.save_jit_hang(child_source_path, parent_path)
                return None, "jit_hangs_found"

            # If both runs completed, compare their results sequentially.
            if nojit_run and jit_run:
                # 1. Check for exit code mismatch
                if jit_run.returncode != nojit_run.returncode:
                    return ExecutionResult(
                        source_path=child_source_path,
                        log_path=child_log_path,
                        returncode=0,
                        execution_time_ms=0,
                        is_divergence=True,
                        divergence_reason="exit_code_mismatch",
                        jit_output=f"Exit Code: {jit_run.returncode}",
                        nojit_output=f"Exit Code: {nojit_run.returncode}",
                        parent_path=parent_path,
                    ), None

                # 2. Check for stderr mismatch (after filtering)
                filtered_jit_stderr = self._filter_jit_stderr(jit_run.stderr)
                filtered_nojit_stderr = self._filter_jit_stderr(nojit_run.stderr)
                if filtered_jit_stderr != filtered_nojit_stderr:
                    return ExecutionResult(
                        source_path=child_source_path,
                        log_path=child_log_path,
                        returncode=0,
                        execution_time_ms=0,
                        is_divergence=True,
                        divergence_reason="stderr_mismatch",
                        jit_output=filtered_jit_stderr,
                        nojit_output=filtered_nojit_stderr,
                        parent_path=parent_path,
                    ), None

                # 3. Check for stdout mismatch
                if jit_run.stdout != nojit_run.stdout:
                    return ExecutionResult(
                        source_path=child_source_path,
                        log_path=child_log_path,
                        returncode=0,
                        execution_time_ms=0,
                        is_divergence=True,
                        divergence_reason="stdout_mismatch",
                        jit_output=jit_run.stdout,
                        nojit_output=nojit_run.stdout,
                        parent_path=parent_path,
                    ), None
            print("  [~] No divergences found.", file=sys.stderr)

        # --- Stage 2: Performance Timing Fuzzing (if enabled) ---
        # This runs if differential testing is off, or if it found no divergence.
        if self.timing_fuzz:
            child_source_path.write_text(source_code)  # Ensure original code is used
            num_timing_runs = 5

            nojit_avg_ms, timed_out, nojit_cv = self._run_timed_trial(
                child_source_path, num_timing_runs, jit_enabled=False
            )
            if timed_out:
                self.artifact_manager.handle_timeout(child_source_path, child_log_path, parent_path)
                return None, "timeouts_found"

            jit_avg_ms, timed_out, _ = self._run_timed_trial(
                child_source_path, num_timing_runs, jit_enabled=True
            )
            if timed_out:
                self.artifact_manager.save_regression_timeout(child_source_path, parent_path)
                return None, "regression_timeouts_found"

        # --- Stage 3: Normal Coverage-Gathering Run ---
        # This always runs unless a critical bug was found in a previous stage.
        try:
            print("[COVERAGE] Running child with JIT=True.", file=sys.stderr)
            # Re-write the original source to ensure we're not running instrumented code
            child_source_path.write_text(source_code)

            # Build the command based on session fuzzing mode
            session_files: list[Path] | None = None
            if self.session_fuzz:
                # Session mode: run parent (warmup) then child (attack) in same process
                print("[SESSION] Using session driver for warm JIT fuzzing.", file=sys.stderr)

                # The Mixer: Prepend random corpus files to pollute JIT state
                if random.random() < MIXER_PROBABILITY:
                    # Select 1-3 random polluter scripts from corpus
                    num_polluters = random.randint(1, 3)
                    polluters: list[Path] = []

                    # Try to get polluters from corpus (handle empty corpus gracefully)
                    try:
                        for _ in range(num_polluters):
                            selection = self.corpus_manager.select_parent()
                            if selection:
                                polluters.append(selection[0])
                    except (AttributeError, IndexError):
                        # Corpus empty or select_parent not available
                        pass

                    if polluters:
                        session_files = polluters + [parent_path, child_source_path]
                        print(
                            f"  [MIXER] Active: Added {len(polluters)} polluter(s) to session.",
                            file=sys.stderr,
                        )
                    else:
                        # Fallback to standard session
                        session_files = [parent_path, child_source_path]
                else:
                    # Standard session mode
                    session_files = [parent_path, child_source_path]

                cmd = [
                    self.target_python,
                    "-m",
                    "lafleur.driver",
                ] + [str(f) for f in session_files]
            else:
                # Normal mode: run child in fresh process
                cmd = [self.target_python, str(child_source_path)]

            with open(child_log_path, "w") as log_file:
                start_time = time.monotonic()
                result = subprocess.run(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.timeout,
                    env=ENV,  # Use the global ENV with debug flags for coverage
                )
                end_time = time.monotonic()

            return ExecutionResult(
                returncode=result.returncode,
                log_path=child_log_path,
                source_path=child_source_path,
                execution_time_ms=int((end_time - start_time) * 1000),
                jit_avg_time_ms=jit_avg_ms,
                nojit_avg_time_ms=nojit_avg_ms,
                nojit_cv=nojit_cv,
                parent_path=parent_path,
                session_files=session_files if self.session_fuzz else None,
            ), None
        except subprocess.TimeoutExpired:
            self.artifact_manager.handle_timeout(child_source_path, child_log_path, parent_path)
            return None, "timeouts_found"
        except Exception as e:
            # Instead of letting the exception propagate, we create a "failure"
            # result so the analyzer can inspect the log and non-zero exit code.
            print(
                f"  [!] An OS-level error occurred during child execution: {e}",
                file=sys.stderr,
            )
            # A common exit code for segfaults is -11. We'll use a high
            # number to indicate an exceptional failure that was caught.
            return ExecutionResult(
                returncode=255,  # Indicates a crash caught by the orchestrator
                log_path=child_log_path,
                source_path=child_source_path,
                execution_time_ms=0,
                parent_path=parent_path,
                session_files=session_files if self.session_fuzz else None,
            ), None

    def verify_target_capabilities(self) -> None:
        """
        Verify that the target Python interpreter produces the expected JIT debug output.

        Raises a RuntimeError if the JIT does not appear to be active or logging correctly.
        """
        print(
            f"[*] Verifying target interpreter capabilities: {self.target_python}...",
            file=sys.stderr,
        )

        # A minimal script to trigger the JIT
        stimulus_code = dedent("""
            def workload():
                for i in range(1000):
                    x = i + 1
            for x in range(100):
                workload()
        """)

        # Use the exact environment we rely on for coverage
        env = ENV.copy()

        try:
            # Run the stimulus
            result = subprocess.run(
                [self.target_python, "-c", stimulus_code],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )

            # Check for JIT signals in stderr
            has_proto = PROTO_TRACE_REGEX.search(f"{result.stderr}\n{result.stdout}")
            has_opt = OPTIMIZED_TRACE_REGEX.search(f"{result.stderr}\n{result.stdout}")

            if not (has_proto or has_opt):
                stderr_stdout = result.stderr + "\n" + result.stdout
                output = indent(
                    stderr_stdout[:500] + "..." if len(stderr_stdout) > 500 else stderr_stdout,
                    "    ",
                )
                # If we don't see traces, the JIT likely isn't enabled or built correctly.
                error_msg = dedent(f"""
                    [!] CRITICAL: The target interpreter '{self.target_python}' did not produce JIT debug output.

                    Lafleur requires a CPython build with the experimental JIT enabled and configured for debug logging.

                    Troubleshooting:
                    1. Ensure you built CPython with: ./configure --with-pydebug --enable-experimental-jit
                    2. Ensure you ran: make -j$(nproc)
                    3. Ensure the environment variables PYTHON_JIT=1, PYTHON_LLTRACE=4, and PYTHON_OPT_DEBUG=4 are respected.

                    Output received from target (stderr +  stdout):
                    {output}
                """)
                raise RuntimeError(error_msg)

            print(
                "  [+] Target interpreter validated successfully (JIT traces detected).",
                file=sys.stderr,
            )

        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Target interpreter '{self.target_python}' timed out during verification check."
            )
        except RuntimeError as e:
            print(e)
            sys.exit(1)
