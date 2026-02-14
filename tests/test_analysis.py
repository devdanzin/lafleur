import json
import unittest

from lafleur.analysis import CrashFingerprinter, CrashSignature, CrashType


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
        self.assertEqual(sig.category, "ASAN")
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
        self.assertEqual(sig.category, "ASAN")
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
        self.assertEqual(sig.category, "ASSERT")
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
        self.assertEqual(sig.category, "PANIC")
        self.assertEqual(sig.crash_type, CrashType.PYTHON_PANIC)
        self.assertEqual(sig.fingerprint, "PANIC:This is a panic message")

    def test_raw_segfault(self):
        log = "Just died silently"
        # SIGSEGV is usually 11, so returncode -11
        sig = self.fingerprinter.analyze(-11, log)
        self.assertEqual(sig.category, "SEGV")
        self.assertEqual(sig.crash_type, CrashType.RAW_SEGFAULT)
        self.assertEqual(sig.fingerprint, "SIGNAL:SIGSEGV")

    def test_unknown_signal(self):
        sig = self.fingerprinter.analyze(-99, "die")
        self.assertEqual(sig.category, "SIGNAL")
        self.assertEqual(sig.fingerprint, "SIGNAL:SIG_99")

    def test_uncaught_python_exception(self):
        log = """
        Traceback (most recent call last):
          File "foo.py", line 1, in <module>
        ValueError: bad value
        """
        sig = self.fingerprinter.analyze(1, log)
        self.assertEqual(sig.category, "PYTHON")
        self.assertEqual(sig.crash_type, CrashType.PYTHON_UNCAUGHT)
        self.assertEqual(sig.fingerprint, "PYTHON:ValueError")

    def test_python_exception_ignored_if_not_traceback(self):
        # Exit code 1 but no traceback found -> UNKNOWN/EXIT:1
        log = "Some script output"
        sig = self.fingerprinter.analyze(1, log)
        self.assertEqual(sig.category, "UNKNOWN")
        self.assertEqual(sig.fingerprint, "EXIT:1")

    def test_asan_segv_pattern(self):
        """Test ASan SEGV on unknown address triggers SEGV error type."""
        log = """
SUMMARY: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x123 in some_function /path/to/file.c:10
        """
        sig = self.fingerprinter.analyze(-11, log)
        self.assertEqual(sig.category, "ASAN")
        self.assertEqual(sig.crash_type, CrashType.ASAN_VIOLATION)
        self.assertIn("ASAN:SEGV:some_function", sig.fingerprint)

    def test_asan_segv_via_segv_pattern_not_summary(self):
        """Test SEGV detection via ASAN_SEGV_PATTERN when error type is not 'segv'."""
        log = """
ERROR: AddressSanitizer: heap-use-after-free on address 0x123
AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x123 in buggy_func /path/file.c:10
        """
        sig = self.fingerprinter.analyze(-11, log)
        self.assertEqual(sig.fingerprint, "ASAN:SEGV:buggy_func")

    def test_asan_ignore_out_of_memory(self):
        """Test that OOM ASan errors are classified as IGNORE."""
        log = "SUMMARY: AddressSanitizer: out-of-memory"
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.category, "ASAN_IGNORED")
        self.assertEqual(sig.crash_type, CrashType.IGNORE)
        self.assertEqual(sig.fingerprint, "IGNORE:ASAN:out-of-memory")

    def test_asan_ignore_allocation_size_too_big(self):
        """Test that allocation-size-too-big is classified as IGNORE."""
        log = "SUMMARY: AddressSanitizer: allocation-size-too-big"
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.crash_type, CrashType.IGNORE)
        self.assertIn("allocation-size-too-big", sig.fingerprint)

    def test_asan_skips_interceptor_frames(self):
        """Test that __asan_ and __interceptor_ frames are skipped."""
        log = """
ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x111 in __asan_memcpy /asan/asan_interceptors.c:100
    #1 0x222 in __interceptor_memcpy /asan/asan_interceptors.c:200
    #2 0x333 in real_culprit /src/file.c:50
SUMMARY: AddressSanitizer: heap-buffer-overflow
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.fingerprint, "ASAN:heap-buffer-overflow:real_culprit")

    def test_asan_skips_unknown_module_frames(self):
        """Test that unknown module frames are skipped in stack parsing."""
        log = """
ERROR: AddressSanitizer: heap-use-after-free
    #0 0x111 in (<unknown /some/path
    #1 0x222 in some_func <unknown module>
    #2 0x333 in real_func /src/real.c:10
SUMMARY: AddressSanitizer: heap-use-after-free
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.fingerprint, "ASAN:heap-use-after-free:real_func")

    def test_asan_all_frames_skipped_gives_unknown(self):
        """Test that if all stack frames are skippable, fingerprint uses 'unknown'."""
        log = """
ERROR: AddressSanitizer: stack-buffer-overflow
    #0 0x111 in malloc (/lib/libasan.so+0x111)
    #1 0x222 in _PyMem_RawMalloc Objects/obmalloc.c:100
SUMMARY: AddressSanitizer: stack-buffer-overflow
        """
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.fingerprint, "ASAN:stack-buffer-overflow:unknown")

    def test_assertion_signal_name_sigabrt(self):
        """Test that assertion with returncode -6 gets signal_name SIGABRT."""
        log = "Assertion 'x != NULL' failed."
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.signal_name, "SIGABRT")

    def test_assertion_signal_name_none_for_other_codes(self):
        """Test that assertion with returncode != -6 gets signal_name None."""
        log = "Assertion 'x != NULL' failed."
        sig = self.fingerprinter.analyze(134, log)
        self.assertIsNone(sig.signal_name)

    def test_fallback_exit_code_zero(self):
        """Test fallback for normal exit code 0."""
        sig = self.fingerprinter.analyze(0, "normal output")
        self.assertEqual(sig.category, "UNKNOWN")
        self.assertEqual(sig.crash_type, CrashType.UNKNOWN)
        self.assertEqual(sig.fingerprint, "EXIT:0")

    def test_to_dict_has_type_key(self):
        """Test that to_dict serializes 'category' as 'type' for backward compat."""
        sig = CrashSignature(
            category="ASAN",
            crash_type=CrashType.ASAN_VIOLATION,
            returncode=-6,
            signal_name=None,
            fingerprint="ASAN:heap-use-after-free:func",
        )
        d = sig.to_dict()
        self.assertIn("type", d)
        self.assertNotIn("category", d)
        self.assertEqual(d["type"], "ASAN")

    def test_to_dict_json_roundtrip(self):
        """Test that to_dict output is JSON-serializable and contains all fields."""
        sig = CrashSignature(
            category="ASSERT",
            crash_type=CrashType.C_ASSERTION,
            returncode=-6,
            signal_name="SIGABRT",
            fingerprint="ASSERT:file.c:10:cond",
        )
        d = sig.to_dict()
        serialized = json.dumps(d)
        loaded = json.loads(serialized)
        self.assertEqual(loaded["type"], "ASSERT")
        self.assertEqual(loaded["crash_type"], str(CrashType.C_ASSERTION))
        self.assertEqual(loaded["returncode"], -6)
        self.assertEqual(loaded["signal_name"], "SIGABRT")
        self.assertEqual(loaded["fingerprint"], "ASSERT:file.c:10:cond")

    def test_asan_error_pattern_fallback(self):
        """Test that ERROR line is used when SUMMARY line is absent."""
        log = "ERROR: AddressSanitizer: stack-overflow on address 0x123"
        sig = self.fingerprinter.analyze(-6, log)
        self.assertEqual(sig.category, "ASAN")
        self.assertEqual(sig.crash_type, CrashType.ASAN_VIOLATION)


if __name__ == "__main__":
    unittest.main()
