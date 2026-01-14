import unittest
from lafleur.analysis import CrashFingerprinter, CrashType


class TestCrashFingerprinter(unittest.TestCase):
    def setUp(self):
        self.fingerprinter = CrashFingerprinter()

    def test_asan_detection(self):
        log = """
        ...
        SUMMARY: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc...

        ...
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.type, "ASAN")
        self.assertEqual(sig.crash_type, CrashType.ASAN_VIOLATION)
        self.assertEqual(sig.fingerprint, "ASAN:heap-use-after-free:unknown")

    def test_asan_with_stack_trace(self):
        """Test extraction of specific function names from ASan logs."""
        log = """
=================================================================
==3031457==ERROR: AddressSanitizer: heap-use-after-free on address 0x7d2eb305a936
    #0 0x5e651cdbe308 in stop_tracing_and_jit /home/danzin/projects/jit_cpython/Python/ceval.c:1483:33
    #1 0x5e651cd7b242 in _PyEval_EvalFrameDefault /home/danzin/projects/jit_cpython/Python/generated_cases.c.h:11823:27
SUMMARY: AddressSanitizer: heap-use-after-free /home/danzin/projects/jit_cpython/Python/ceval.c:1483:33 in stop_tracing_and_jit
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.type, "ASAN")
        # Ensure we stripped the path and found the function
        self.assertEqual(sig.fingerprint, "ASAN:heap-use-after-free:stop_tracing_and_jit")

    def test_asan_ignores_allocators(self):
        """Test that we skip malloc/free frames to find the real culprit."""
        log = """
=================================================================
==123==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x123 in malloc (/lib/x86_64-linux-gnu/libasan.so+0x123)
    #1 0x456 in _PyMem_DebugRawAlloc Objects/obmalloc.c:100
    #2 0x789 in _PyObject_GC_NewVar Python/gc.c:200
    #3 0xABC in actual_buggy_function Modules/parser.c:50
SUMMARY: AddressSanitizer: heap-buffer-overflow
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.fingerprint, "ASAN:heap-buffer-overflow:actual_buggy_function")

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
