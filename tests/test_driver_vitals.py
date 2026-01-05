import unittest
from unittest.mock import MagicMock, patch
from lafleur.driver import get_jit_stats


class TestJITVitals(unittest.TestCase):
    def test_jit_vitals_aggregation(self):
        """Test that get_jit_stats correctly aggregates max_exit_count, max_chain_depth and min_code_size."""

        # Mock executor objects
        mock_exec1 = MagicMock()
        mock_exec2 = MagicMock()

        # Mock pointer contents
        mock_ptr1 = MagicMock()
        mock_ptr1.contents.exit_count = 10
        mock_ptr1.contents.vm_data.chain_depth = 5
        mock_ptr1.contents.code_size = 100
        mock_ptr1.contents.vm_data.pending_deletion = 0
        mock_ptr1.contents.vm_data.valid = 1
        mock_ptr1.contents.vm_data.warm = 1

        mock_ptr2 = MagicMock()
        mock_ptr2.contents.exit_count = 50
        mock_ptr2.contents.vm_data.chain_depth = 2
        mock_ptr2.contents.code_size = 50
        mock_ptr2.contents.vm_data.pending_deletion = 0
        mock_ptr2.contents.vm_data.valid = 1
        mock_ptr2.contents.vm_data.warm = 1

        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
            patch("lafleur.driver.ctypes.cast") as mock_cast,
        ):
            # Setup side effects
            mock_opcode.get_executor.side_effect = [mock_exec1, None, mock_exec2] + [None] * 1000
            mock_cast.side_effect = [mock_ptr1, mock_ptr2]

            def my_func():
                pass  # Need some bytes to scan
                pass
                pass

            namespace = {"my_func": my_func}
            stats = get_jit_stats(namespace)

            self.assertEqual(stats["max_exit_count"], 50)
            self.assertEqual(stats["max_chain_depth"], 5)
            self.assertEqual(stats["min_code_size"], 50)

    def test_jit_vitals_defaults(self):
        """Test default values for JIT vitals when no executors are found."""
        with (
            patch("lafleur.driver.HAS_OPCODE", True),
            patch("lafleur.driver._opcode") as mock_opcode,
        ):
            mock_opcode.get_executor.return_value = None

            def my_func():
                pass

            namespace = {"my_func": my_func}
            stats = get_jit_stats(namespace)

            self.assertEqual(stats["max_exit_count"], 0)
            self.assertEqual(stats["max_chain_depth"], 0)
            self.assertEqual(stats["min_code_size"], 0)


if __name__ == "__main__":
    unittest.main()
