import ast
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from lafleur.orchestrator import LafleurOrchestrator
from lafleur.utils import RUN_STATS_FILE


class TestSniperTargeting(unittest.TestCase):
    def setUp(self):
        save_file = Path(RUN_STATS_FILE)
        save_file.unlink(missing_ok=True)

    def test_harness_exclusion(self):
        """Test that the harness function itself is excluded from sniper targets."""
        # Setup mocks
        orch = LafleurOrchestrator(fusil_path="dummy")

        # Mock dependencies
        orch.coverage_manager = MagicMock()
        orch.coverage_manager.state = {
            "per_file_coverage": {
                "test.py": {
                    "mutation_info": {
                        "jit_stats": {
                            "watched_dependencies": ["len", "uop_harness_test", "MyGlobal"]
                        }
                    },
                    "lineage_coverage_profile": {},
                }
            }
        }

        # Mock AST retrieval
        harness_node = ast.FunctionDef(
            name="uop_harness_test", args=ast.arguments(), body=[ast.Pass()], decorator_list=[]
        )
        setup_nodes = []
        parent_tree = ast.Module(body=[harness_node], type_ignores=[])

        # Create a mock path that has .name = "test.py"
        mock_path = MagicMock()
        mock_path.name = "test.py"

        with (
            patch.object(
                orch.mutation_controller,
                "_get_nodes_from_parent",
                return_value=(harness_node, parent_tree, setup_nodes),
            ),
            patch.object(
                orch.mutation_controller, "get_mutated_harness", return_value=(None, None)
            ) as mock_get_mutated,
            patch("lafleur.orchestrator.CORPUS_DIR"),
        ):
            # Run cycle (will abort early due to mock_get_mutated returning None, but enough to test logic)
            orch.execute_mutation_and_analysis_cycle(mock_path, 100.0, 1, False)

            # Verify get_mutated_harness called with filtered keys
            call_args = mock_get_mutated.call_args
            self.assertIsNotNone(call_args)
            watched_keys = call_args.kwargs.get("watched_keys") or []

            self.assertIn("len", watched_keys)
            self.assertIn("MyGlobal", watched_keys)
            self.assertNotIn("uop_harness_test", watched_keys)


if __name__ == "__main__":
    unittest.main()
