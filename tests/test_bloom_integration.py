import unittest
from unittest.mock import MagicMock, patch
import ctypes
import io
from lafleur.driver import get_jit_stats, PyExecutorObject

class TestBloomIntegration(unittest.TestCase):
    def test_bloom_introspection_triggered(self):
        """Test that scan_watched_variables is triggered when density is high."""
        
        # Mock executor and pointer
        mock_executor = MagicMock()
        mock_ptr = MagicMock()
        
        # Configure the mock to return integer values when these attributes are accessed
        # Using PropertyMock to handle ctypes-like access
        type(mock_ptr.contents).exit_count = unittest.mock.PropertyMock(return_value=100)
        type(mock_ptr.contents).code_size = unittest.mock.PropertyMock(return_value=5)
        
        # For vm_data (nested struct)
        mock_vm_data = MagicMock()
        type(mock_vm_data).pending_deletion = unittest.mock.PropertyMock(return_value=0)
        type(mock_vm_data).valid = unittest.mock.PropertyMock(return_value=1)
        type(mock_vm_data).warm = unittest.mock.PropertyMock(return_value=1)
        type(mock_vm_data).chain_depth = unittest.mock.PropertyMock(return_value=1)
        
        # Bloom filter: Set all bits to 1 so everything matches
        all_ones = (ctypes.c_uint32 * 8)(*[0xFFFFFFFF] * 8)
        mock_bloom = MagicMock()
        mock_bloom.bits = all_ones
        mock_vm_data.bloom = mock_bloom
        
        mock_ptr.contents.vm_data = mock_vm_data
        
        with patch('lafleur.driver.HAS_OPCODE', True), \
             patch('lafleur.driver._opcode') as mock_opcode, \
             patch('lafleur.driver.ctypes.cast', return_value=mock_ptr), \
             patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            
            # Setup get_executor to return our mock
            mock_opcode.get_executor.side_effect = [mock_executor] + [None] * 1000
            
            # Define a namespace with a function (required by scanner) and some variables
            def dummy_func(): pass
            namespace = {"my_global": 123, "__builtins__": {}, "func": dummy_func}
            
            get_jit_stats(namespace)
            
            # Capture output
            output = mock_stdout.getvalue()
            
            # Verify EKG log
            self.assertIn("[EKG] WATCHED:", output)
            self.assertIn("my_global", output)

if __name__ == '__main__':
    unittest.main()
