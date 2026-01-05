import unittest
from unittest.mock import MagicMock, patch
import sys
from lafleur.driver import get_jit_stats

# Mock _opcode if not present
try:
    import _opcode
except ImportError:
    _opcode = MagicMock()
    sys.modules["_opcode"] = _opcode


class TestRecursiveScanning(unittest.TestCase):
    def test_recursive_scanning_finds_nested_code(self):
        """Test that get_jit_stats recursively finds code objects in nested functions."""

        # Create a function with a nested function
        def outer():
            def inner():
                pass

            return inner

        # We need to mock _opcode.get_executor to avoid errors and return None
        # We also need to patch HAS_OPCODE to True
        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes"),
        ):
            mock_opcode.get_executor.return_value = None

            namespace = {"outer": outer}
            stats = get_jit_stats(namespace)

            # Should find at least 2 functions: outer and inner
            # outer code object contains inner code object as a constant
            self.assertGreaterEqual(stats["functions_scanned"], 2)

            # Verify we scanned the code objects of both outer and inner
            # We can't easily verify the exact arguments to get_executor without capturing
            # the code objects first, but the count is a good proxy.

    def test_recursive_scanning_finds_nested_class_methods(self):
        """Test that get_jit_stats recursively finds methods in nested classes."""

        def container():
            class Nested:
                def method(self):
                    pass

            return Nested

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes"),
        ):
            mock_opcode.get_executor.return_value = None

            namespace = {"container": container}
            stats = get_jit_stats(namespace)

            # Should find: container, Nested (body is code), method
            # Note: Class body is executed as a code object too!
            self.assertGreaterEqual(stats["functions_scanned"], 3)


if __name__ == "__main__":
    unittest.main()
