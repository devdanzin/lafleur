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
    ASAN_PATTERN = re.compile(r"AddressSanitizer:\s+([a-z0-9-]+)\s+")
    ASSERT_PATTERN = re.compile(r"Assertion\s+[`'\"](.*?)['\"]\s+failed")
    # Captures file and line for assertion if available
    ASSERT_LOC_PATTERN = re.compile(r"([^:\s]+):(\d+):\s+[^:]+:\s+Assertion")
    PYTHON_PANIC_PATTERN = re.compile(r"Fatal Python error:\s+([^\n]+)")
    PYTHON_EXCEPTION_PATTERN = re.compile(
        r"^\s*([A-Z][a-zA-Z0-9_]+(?:Error|Exception)):\s", re.MULTILINE
    )

    def analyze(self, returncode: int, log_content: str) -> CrashSignature:
        """
        Analyze a crash to determine its unique fingerprint.
        """

        # 1. AddressSanitizer (Highest Priority)
        asan_match = self.ASAN_PATTERN.search(log_content)
        if asan_match:
            error_type = asan_match.group(1)
            # Future improvement: Extract top stack frame for better de-duplication
            return CrashSignature(
                type="ASAN",
                crash_type=CrashType.ASAN_VIOLATION,
                returncode=returncode,
                signal_name=None,
                fingerprint=f"ASAN:{error_type}",
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
