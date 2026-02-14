from dataclasses import dataclass, asdict
from enum import Enum
import re
import signal
from typing import Optional


class CrashType(str, Enum):
    ASAN_VIOLATION = "ASAN_VIOLATION"
    C_ASSERTION = "C_ASSERTION"
    PYTHON_PANIC = "PYTHON_PANIC"
    PYTHON_UNCAUGHT = "PYTHON_UNCAUGHT"
    RAW_SEGFAULT = "RAW_SEGFAULT"
    UNKNOWN = "UNKNOWN"
    IGNORE = "IGNORE"  # Uninteresting crashes (OOM, allocation failures, etc.)


@dataclass
class CrashSignature:
    type: str  # High-level category (ASAN, ASSERT, etc)
    crash_type: CrashType  # Enum for programmatic handling
    returncode: int
    signal_name: Optional[str]
    fingerprint: str  # Unique string for minimization matching

    def to_dict(self) -> dict:
        return asdict(self)


class CrashFingerprinter:
    """Analyzes logs and exit codes to fingerprint crashes."""

    # Regex patterns for extraction
    # Primary: Extract error type from SUMMARY line (most reliable)
    ASAN_SUMMARY_PATTERN = re.compile(r"SUMMARY:\s+AddressSanitizer:\s+([a-zA-Z0-9-]+)")
    # Fallback: Extract from ERROR line (e.g., "ERROR: AddressSanitizer: heap-use-after-free")
    ASAN_ERROR_PATTERN = re.compile(r"ERROR:\s+AddressSanitizer:\s+([a-zA-Z0-9-]+)")
    ASAN_SEGV_PATTERN = re.compile(r"AddressSanitizer:\s+SEGV\s+on\s+unknown\s+address")
    # Stack frame pattern: #N 0xADDR in function_name /path/to/file.c:line:col
    ASAN_FRAME_PATTERN = re.compile(
        r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(.*)$", re.MULTILINE
    )
    ASSERT_PATTERN = re.compile(r"Assertion\s+[`'\"](.*?)['\"]\s+failed")
    # Captures file and line for assertion if available
    ASSERT_LOC_PATTERN = re.compile(r"([^:\s]+):(\d+):\s+[^:]+:\s+Assertion")
    PYTHON_PANIC_PATTERN = re.compile(r"Fatal Python error:\s+([^\n]+)")
    PYTHON_EXCEPTION_PATTERN = re.compile(
        r"^\s*([A-Z][a-zA-Z0-9_]+(?:Error|Exception)):\s", re.MULTILINE
    )

    # ASan error types that indicate OOM/allocation issues (not JIT bugs)
    ASAN_IGNORE_TYPES = frozenset(
        {
            "allocation-size-too-big",
            "out-of-memory",
            "allocator-out-of-memory",
        }
    )

    # Function names to skip when looking for the culprit frame
    # These are allocators, interceptors, and generic wrappers
    ASAN_SKIP_FUNCTIONS = frozenset(
        {
            # Memory allocators
            "malloc",
            "free",
            "realloc",
            "calloc",
            "memalign",
            "posix_memalign",
            "aligned_alloc",
            # Python memory allocators
            "_PyMem_RawMalloc",
            "_PyMem_RawRealloc",
            "_PyMem_RawFree",
            "_PyMem_Malloc",
            "_PyMem_Realloc",
            "_PyMem_Free",
            "_PyMem_DebugRawAlloc",
            "_PyMem_DebugRawMalloc",
            "_PyMem_DebugRawRealloc",
            "_PyMem_DebugRawFree",
            "_PyMem_DebugMalloc",
            "_PyMem_DebugRealloc",
            "_PyMem_DebugFree",
            "_PyObject_GC_NewVar",
            "_PyObject_Malloc",
            "_PyObject_Realloc",
            "_PyObject_Free",
            "_PyObject_DebugMalloc",
            "_PyObject_DebugRealloc",
            "_PyObject_DebugFree",
            "PyMem_Malloc",
            "PyMem_Realloc",
            "PyMem_Free",
            "PyObject_Malloc",
            "PyObject_Realloc",
            "PyObject_Free",
            # Libc internals
            "__libc_start_main",
            "__libc_start_call_main",
            "_start",
        }
    )

    def _parse_asan_stack(self, log_content: str) -> Optional[str]:
        """
        Parse ASan stack trace to find the first meaningful CPython function.

        Returns the function name or None if no meaningful frame found.
        """
        frames = self.ASAN_FRAME_PATTERN.findall(log_content)

        for frame_num, func_name, location in frames:
            # Skip unknown module frames
            if func_name == "(<unknown" or "<unknown module>" in location:
                continue

            # Skip allocator and interceptor functions
            if func_name in self.ASAN_SKIP_FUNCTIONS:
                continue

            # Skip ASan interceptors (often start with __)
            if func_name.startswith("__asan_") or func_name.startswith("__interceptor_"):
                continue

            # Found a meaningful frame
            return func_name

        return None

    def analyze(self, returncode: int, log_content: str) -> CrashSignature:
        """
        Analyze a crash to determine its unique fingerprint.
        """

        # 1. AddressSanitizer (Highest Priority)
        # Try SUMMARY line first (most reliable), then fall back to ERROR line
        asan_match = self.ASAN_SUMMARY_PATTERN.search(log_content)
        if not asan_match:
            asan_match = self.ASAN_ERROR_PATTERN.search(log_content)

        if asan_match:
            error_type = asan_match.group(1).lower()

            # Filter out uninteresting ASan errors (OOM, allocation failures)
            if error_type in self.ASAN_IGNORE_TYPES:
                return CrashSignature(
                    type="ASAN_IGNORED",
                    crash_type=CrashType.IGNORE,
                    returncode=returncode,
                    signal_name=None,
                    fingerprint=f"IGNORE:ASAN:{error_type}",
                )

            # Handle SEGV on unknown address specially
            if error_type == "segv" or self.ASAN_SEGV_PATTERN.search(log_content):
                error_type = "SEGV"

            # Parse stack trace to find the culprit function
            culprit_func = self._parse_asan_stack(log_content)
            if culprit_func:
                fingerprint = f"ASAN:{error_type}:{culprit_func}"
            else:
                fingerprint = f"ASAN:{error_type}:unknown"

            return CrashSignature(
                type="ASAN",
                crash_type=CrashType.ASAN_VIOLATION,
                returncode=returncode,
                signal_name=None,
                fingerprint=fingerprint,
            )

        # 2. C-Level Assertion Failure
        assert_match = self.ASSERT_PATTERN.search(log_content)
        if assert_match:
            assert_text = assert_match.group(1)
            # Try to get location
            loc_match = self.ASSERT_LOC_PATTERN.search(log_content)
            if loc_match:
                filename = loc_match.group(1)
                lineno = loc_match.group(2)
                fingerprint = f"ASSERT:{filename}:{lineno}:{assert_text}"
            else:
                fingerprint = f"ASSERT:{assert_text}"

            return CrashSignature(
                type="ASSERT",
                crash_type=CrashType.C_ASSERTION,
                returncode=returncode,
                signal_name="SIGABRT" if returncode == -6 else None,
                fingerprint=fingerprint,
            )

        # 3. Python Panic (Fatal Error)
        panic_match = self.PYTHON_PANIC_PATTERN.search(log_content)
        if panic_match:
            panic_msg = panic_match.group(1).strip()
            return CrashSignature(
                type="PANIC",
                crash_type=CrashType.PYTHON_PANIC,
                returncode=returncode,
                signal_name=None,
                fingerprint=f"PANIC:{panic_msg}",
            )

        # 4. Uncaught Python Exception (Exit Code 1)
        # Note: The orchestrator often filters these, but we analyze them for completeness
        if returncode == 1:
            exc_match = self.PYTHON_EXCEPTION_PATTERN.search(log_content)
            if exc_match:
                exc_type = exc_match.group(1)
                return CrashSignature(
                    type="PYTHON",
                    crash_type=CrashType.PYTHON_UNCAUGHT,
                    returncode=1,
                    signal_name=None,
                    fingerprint=f"PYTHON:{exc_type}",
                )

        # 5. Raw Signal (Segfault, etc.)
        if returncode < 0:
            sig_val = abs(returncode)
            try:
                sig_name = signal.Signals(sig_val).name
            except ValueError:
                sig_name = f"SIG_{sig_val}"

            return CrashSignature(
                type="SEGV" if sig_name == "SIGSEGV" else "SIGNAL",
                crash_type=CrashType.RAW_SEGFAULT if sig_name == "SIGSEGV" else CrashType.UNKNOWN,
                returncode=returncode,
                signal_name=sig_name,
                fingerprint=f"SIGNAL:{sig_name}",
            )

        # Fallback
        return CrashSignature(
            type="UNKNOWN",
            crash_type=CrashType.UNKNOWN,
            returncode=returncode,
            signal_name=None,
            fingerprint=f"EXIT:{returncode}",
        )
