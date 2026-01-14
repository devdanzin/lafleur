import unittest


class TestJITClamping(unittest.TestCase):
    def test_dynamic_clamping_logic(self):
        """Test the dynamic clamping logic logic."""
        # Since we can't easily test `analyze_run` directly without massive mocking,
        # we'll implement the logic here as a standalone test to verify the math
        # before applying it to the codebase. This is a "unit test for the concept".

        def calculate_saved_density(parent_density, child_density):
            if parent_density > 0:
                return min(parent_density * 5.0, child_density)
            else:
                return child_density

        # Case 1: First generation (parent density 0)
        self.assertEqual(calculate_saved_density(0.0, 100.0), 100.0)

        # Case 2: Normal growth (parent 10, child 40) - should save actual child density
        self.assertEqual(calculate_saved_density(10.0, 40.0), 40.0)

        # Case 3: Massive spike (parent 10, child 1000) - should clamp to 50
        self.assertEqual(calculate_saved_density(10.0, 1000.0), 50.0)

        # Case 4: Zero growth (parent 10, child 5) - should save actual child density
        self.assertEqual(calculate_saved_density(10.0, 5.0), 5.0)


if __name__ == "__main__":
    unittest.main()
