import unittest
from unittest.mock import MagicMock, patch

# Ensure lafleur.driver is imported
import lafleur.driver as driver


class TestJITIntrospection(unittest.TestCase):
    def test_zombie_trace_detection(self):
        """Test that get_jit_stats correctly detects zombie traces via ctypes."""

        # Mock executor object
        mock_executor = MagicMock()

        # Mock the pointer returned by ctypes.cast
        mock_ptr = MagicMock()
        # Set the fields we want to inspect
        mock_ptr.contents.pending_deletion = 1
        mock_ptr.contents.valid = 1
        mock_ptr.contents.warm = 1

        # We need to patch:
        # 1. driver.HAS_OPCODE -> True
        # 2. driver._opcode -> Mock
        # 3. driver.ctypes.cast -> returns mock_ptr

        with (
            patch.object(driver, "HAS_OPCODE", True),
            patch.object(driver, "_opcode", create=True) as mock_opcode,
            patch.object(driver.ctypes, "cast", return_value=mock_ptr) as mock_cast,
        ):
            # Setup _opcode.get_executor to return our mock executor for the first offset
            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 100

            # Create a namespace with a dummy function
            def my_func():
                pass

            namespace = {"my_func": my_func}

            # Run the function under test
            stats = driver.get_jit_stats(namespace)

            # Verify basic stats
            self.assertEqual(stats["executors"], 1)
            self.assertEqual(stats["functions_scanned"], 1)

            # Verify introspection stats
            self.assertEqual(stats["zombie_traces"], 1)
            self.assertEqual(stats["valid_traces"], 1)
            self.assertEqual(stats["warm_traces"], 1)

            # Verify ctypes.cast was called correctly
            mock_cast.assert_called_once()
            args, _ = mock_cast.call_args
            self.assertEqual(args[0], id(mock_executor))

            # Verify the type cast target
            # args[1] should be a pointer type to PyExecutorObject
            # Since we patched driver.ctypes, POINTER is also a mock.
            # So args[1] is the result of driver.ctypes.POINTER(driver.PyExecutorObject)

    def test_introspection_exception_handling(self):
        """Test that get_jit_stats handles ctypes exceptions gracefully."""

        mock_executor = MagicMock()

        with (
            patch.object(driver, "HAS_OPCODE", True),
            patch.object(driver, "_opcode", create=True) as mock_opcode,
            patch.object(driver.ctypes, "cast") as mock_cast,
        ):
            # Setup exception
            mock_cast.side_effect = ValueError("Cast failed")

            mock_opcode.get_executor.return_value = mock_executor

            def my_func():
                pass

            namespace = {"my_func": my_func}

            stats = driver.get_jit_stats(namespace)

            # Should not crash, just not count the detailed stats
            self.assertEqual(stats["executors"], 1)
            self.assertEqual(stats["zombie_traces"], 0)
            self.assertEqual(stats["valid_traces"], 0)
            self.assertEqual(stats["warm_traces"], 0)


if __name__ == "__main__":
    unittest.main()
