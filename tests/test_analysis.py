import unittest
from unittest.mock import MagicMock
from lafleur.analysis import CrashFingerprinter, CrashType, CrashSignature


class TestCrashFingerprinter(unittest.TestCase):
    def setUp(self):
        self.fingerprinter = CrashFingerprinter()

    def test_asan_detection(self):
        log = """
        ...
        AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc...
        READ of size 8 at 0x602000000010 thread T0
        ...
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.type, "ASAN")
        self.assertEqual(sig.crash_type, CrashType.ASAN_VIOLATION)
        self.assertEqual(sig.fingerprint, "ASAN:heap-use-after-free")

    def test_assertion_detection(self):
        log = """
        Debug info...
        python: pycore_optimizer.c:452: _Py_uop_analyze: Assertion 'ctx->valid' failed.
        Aborted (core dumped)
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.type, "ASSERT")
        self.assertEqual(sig.crash_type, CrashType.C_ASSERTION)
        # Should capture filename, line, and message
        self.assertEqual(sig.fingerprint, "ASSERT:pycore_optimizer.c:452:ctx->valid")

    def test_assertion_no_loc(self):
        log = "Assertion 'x > 0' failed."
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.fingerprint, "ASSERT:x > 0")

    def test_python_panic(self):
        log = "Fatal Python error: This is a panic message\n..."
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.type, "PANIC")
        self.assertEqual(sig.crash_type, CrashType.PYTHON_PANIC)
        self.assertEqual(sig.fingerprint, "PANIC:This is a panic message")

    def test_raw_segfault(self):
        log = "Just died silently"
        # SIGSEGV is usually 11, so returncode -11
        sig = self.fingerprinter.analyze(-11, log)
        self.assertEqual(sig.type, "SEGV")
        self.assertEqual(sig.crash_type, CrashType.RAW_SEGFAULT)
        self.assertEqual(sig.fingerprint, "SIGNAL:SIGSEGV")

    def test_unknown_signal(self):
        sig = self.fingerprinter.analyze(-99, "die")
        self.assertEqual(sig.type, "SIGNAL")
        self.assertEqual(sig.fingerprint, "SIGNAL:SIG_99")

    def test_uncaught_python_exception(self):
        log = """
        Traceback (most recent call last):
          File "foo.py", line 1, in <module>
        ValueError: bad value
        """
        sig = self.fingerprinter.analyze(1, log)
        self.assertEqual(sig.type, "PYTHON")
        self.assertEqual(sig.crash_type, CrashType.PYTHON_UNCAUGHT)
        self.assertEqual(sig.fingerprint, "PYTHON:ValueError")

    def test_python_exception_ignored_if_not_traceback(self):
        # Exit code 1 but no traceback found -> UNKNOWN/EXIT:1
        log = "Some script output"
        sig = self.fingerprinter.analyze(1, log)
        self.assertEqual(sig.type, "UNKNOWN")
        self.assertEqual(sig.fingerprint, "EXIT:1")


if __name__ == "__main__":
    unittest.main()
