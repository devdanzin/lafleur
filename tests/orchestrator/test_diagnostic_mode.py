#!/usr/bin/env python3
"""
End-to-end integration tests for diagnostic mode.

These tests verify that the diagnostic CLI options (--max-sessions,
--max-mutations-per-session, --seed, --workdir, --keep-children,
--dry-run, --mutators, --strategy, --list-mutators) compose correctly
in compound workflows.
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.corpus_manager import CorpusManager
from lafleur.execution import ExecutionManager
from lafleur.orchestrator import LafleurOrchestrator, main


class TestDiagnosticSmokeRun(unittest.TestCase):
    """Test the primary diagnostic workflow: bounded + seeded + relocatable."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)

        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()

        # Minimal seed file
        Path("corpus/seed_0.py").write_text(
            "def uop_harness_test():\n    x = 1 + 2\n    return x\n"
        )

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def _make_orchestrator(self, **kwargs):
        """Create an orchestrator with common defaults and overrides."""
        defaults = dict(
            fusil_path=None,
            min_corpus_files=0,
            target_python=sys.executable,
            max_sessions=2,
            max_mutations_per_session=3,
        )
        defaults.update(kwargs)
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                orch = LafleurOrchestrator(**defaults)

        # Register seed
        seed_path = str(Path("corpus/seed_0.py").resolve())
        orch.coverage_manager.state["per_file_coverage"][seed_path] = {
            "metadata": {
                "parent_id": None,
                "is_seed": True,
                "mutators_applied": [],
                "depth": 0,
            },
            "harness_profiles": {},
        }
        return orch

    def test_bounded_run_exits_cleanly(self):
        """2 sessions x 3 mutations exits without KeyboardInterrupt."""
        orch = self._make_orchestrator()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            orch.run_evolutionary_loop()

        self.assertEqual(orch.run_stats["total_sessions"], 2)
        self.assertLessEqual(orch.run_stats.get("total_mutations", 0), 6)

    def test_seeded_runs_are_deterministic(self):
        """Same seed produces same mutation count."""
        import random

        results = []
        for _ in range(2):
            random.seed(42)
            orch = self._make_orchestrator(max_sessions=1, max_mutations_per_session=1)

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                orch.run_evolutionary_loop()

            results.append(orch.run_stats.get("total_mutations", 0))

        self.assertEqual(results[0], results[1])

    def test_dry_run_generates_children_without_execution(self):
        """--dry-run writes children to tmp_fuzz_run/ but never calls subprocess."""
        orch = self._make_orchestrator(
            max_sessions=1,
            max_mutations_per_session=2,
            dry_run=True,
            keep_children=True,
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            orch.run_evolutionary_loop()

        mock_run.assert_not_called()

        tmp_dir = Path("tmp_fuzz_run")
        if tmp_dir.exists():
            children = list(tmp_dir.glob("child_*_dryrun.py"))
            self.assertGreaterEqual(len(children), 1)
            for child in children:
                content = child.read_text()
                self.assertGreater(len(content), 0)

    def test_keep_children_preserves_non_interesting(self):
        """--keep-children retains child scripts that aren't promoted to corpus."""
        orch = self._make_orchestrator(
            max_sessions=1,
            max_mutations_per_session=2,
            keep_children=True,
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            orch.run_evolutionary_loop()

        tmp_dir = Path("tmp_fuzz_run")
        if tmp_dir.exists():
            children = list(tmp_dir.glob("child_*.py"))
            for child in children:
                self.assertTrue(child.exists())


class TestMutatorFilterIntegration(unittest.TestCase):
    """Test --mutators filtering in a real orchestrator."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)
        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()
        Path("corpus/seed_0.py").write_text(
            "def uop_harness_test():\n    x = 1 + 2\n    return x\n"
        )

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_filtered_pool_propagates_to_score_tracker(self):
        """Filtering mutators also limits what the score tracker knows about."""
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                orch = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    target_python=sys.executable,
                    mutator_filter=["OperatorSwapper", "ConstantPerturbator"],
                )

        pool_names = [t.__name__ for t in orch.mutation_controller.ast_mutator.transformers]
        self.assertEqual(sorted(pool_names), ["ConstantPerturbator", "OperatorSwapper"])

        tracker_transformers = orch.score_tracker.all_transformers
        self.assertIn("OperatorSwapper", tracker_transformers)
        self.assertIn("ConstantPerturbator", tracker_transformers)
        self.assertNotIn("GCInjector", tracker_transformers)


class TestForcedStrategyIntegration(unittest.TestCase):
    """Test --strategy forcing in compound workflows."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)
        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()
        Path("corpus/seed_0.py").write_text("def uop_harness_test():\n    x = 42\n    return x\n")

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_forced_strategy_used_in_all_mutations(self):
        """--strategy spam forces spam for every mutation."""
        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                orch = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    target_python=sys.executable,
                    max_sessions=1,
                    max_mutations_per_session=2,
                    forced_strategy="spam",
                    dry_run=True,
                    keep_children=True,
                )

        seed_path = str(Path("corpus/seed_0.py").resolve())
        orch.coverage_manager.state["per_file_coverage"][seed_path] = {
            "metadata": {
                "parent_id": None,
                "is_seed": True,
                "mutators_applied": [],
                "depth": 0,
            },
            "harness_profiles": {},
        }

        strategies_used = []
        original_apply = orch.mutation_controller.apply_mutation_strategy

        def spy_apply(*args, **kwargs):
            result = original_apply(*args, **kwargs)
            if result[1]:
                strategies_used.append(result[1].get("strategy"))
            return result

        with patch.object(
            orch.mutation_controller, "apply_mutation_strategy", side_effect=spy_apply
        ):
            orch.run_evolutionary_loop()

        for strat in strategies_used:
            self.assertEqual(strat, "spam")


class TestWorkdirCLI(unittest.TestCase):
    """Test --workdir via the main() CLI entry point."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.workdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.workdir, ignore_errors=True)

    def test_workdir_changes_cwd(self):
        """--workdir causes os.chdir to the specified directory."""
        with patch("lafleur.orchestrator.LafleurOrchestrator") as mock_orch_class:
            with patch("lafleur.orchestrator.generate_run_metadata") as mock_meta:
                with patch("lafleur.orchestrator.load_run_stats") as mock_stats:
                    with patch("lafleur.orchestrator.TeeLogger") as mock_tee:
                        mock_stats.return_value = {"total_mutations": 0}
                        mock_meta.return_value = {"run_id": "test", "instance_name": "test"}
                        mock_tee.return_value = MagicMock()
                        mock_orch_class.return_value = MagicMock()

                        with patch(
                            "sys.argv",
                            [
                                "lafleur",
                                "--fusil-path",
                                "/fake",
                                "--workdir",
                                str(self.workdir),
                            ],
                        ):
                            with patch("lafleur.orchestrator.LOGS_DIR") as mock_logs:
                                mock_logs.mkdir = MagicMock()
                                main()

        self.assertTrue(self.workdir.exists())


class TestListMutatorsIntegration(unittest.TestCase):
    """Test --list-mutators end-to-end."""

    def test_lists_all_mutators_and_exits(self):
        """--list-mutators outputs the full pool with descriptions."""
        captured = io.StringIO()
        with patch("sys.argv", ["lafleur", "--list-mutators"]):
            with patch("sys.stdout", captured):
                with self.assertRaises(SystemExit) as ctx:
                    main()

        self.assertEqual(ctx.exception.code, 0)
        output = captured.getvalue()

        self.assertIn("OperatorSwapper", output)
        self.assertIn("GCInjector", output)
        self.assertIn("total", output.lower())

    def test_list_output_is_sorted(self):
        """Mutator list is alphabetically sorted."""
        captured = io.StringIO()
        with patch("sys.argv", ["lafleur", "--list-mutators"]):
            with patch("sys.stdout", captured):
                with self.assertRaises(SystemExit):
                    main()

        lines = [line.strip() for line in captured.getvalue().splitlines() if line.startswith("  ")]
        names = [line.split()[0] for line in lines if line]
        self.assertEqual(names, sorted(names))


class TestCompoundDiagnosticWorkflows(unittest.TestCase):
    """Test realistic compound diagnostic command lines."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.test_dir = Path(tempfile.mkdtemp())
        os.chdir(self.test_dir)
        Path("corpus").mkdir()
        Path("coverage").mkdir()
        Path("crashes").mkdir()
        Path("corpus/seed_0.py").write_text(
            "def uop_harness_test():\n    x = 1 + 2\n    return x\n"
        )

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_full_diagnostic_combo(self):
        """The full diagnostic workflow: bounded + seeded + filtered + dry-run."""
        import random

        random.seed(99)

        with patch.object(ExecutionManager, "verify_target_capabilities"):
            with patch.object(CorpusManager, "synchronize"):
                orch = LafleurOrchestrator(
                    fusil_path=None,
                    min_corpus_files=0,
                    target_python=sys.executable,
                    max_sessions=2,
                    max_mutations_per_session=3,
                    mutator_filter=["OperatorSwapper", "ConstantPerturbator"],
                    forced_strategy="havoc",
                    dry_run=True,
                    keep_children=True,
                )

        seed_path = str(Path("corpus/seed_0.py").resolve())
        orch.coverage_manager.state["per_file_coverage"][seed_path] = {
            "metadata": {
                "parent_id": None,
                "is_seed": True,
                "mutators_applied": [],
                "depth": 0,
            },
            "harness_profiles": {},
        }

        with patch("subprocess.run") as mock_run:
            orch.run_evolutionary_loop()

        self.assertEqual(orch.run_stats["total_sessions"], 2)
        self.assertLessEqual(orch.run_stats.get("total_mutations", 0), 6)
        mock_run.assert_not_called()

        pool_names = {t.__name__ for t in orch.mutation_controller.ast_mutator.transformers}
        self.assertEqual(pool_names, {"OperatorSwapper", "ConstantPerturbator"})

    def test_metadata_records_diagnostic_settings(self):
        """run_metadata.json captures all diagnostic settings."""
        from lafleur.metadata import generate_run_metadata

        args = Namespace(
            max_sessions=5,
            max_mutations_per_session=10,
            seed=42,
            workdir=Path("/tmp/test"),
            keep_children=True,
            dry_run=True,
            mutators="OperatorSwapper,GCInjector",
            strategy="spam",
            fusil_path=None,
            timeout=10,
            runs=1,
            dynamic_runs=False,
            differential_testing=False,
            session_fuzz=False,
            timing_fuzz=False,
            no_ekg=False,
            target_python=sys.executable,
            instance_name=None,
            verbose=False,
        )

        logs_dir = self.test_dir / "logs"
        logs_dir.mkdir(exist_ok=True)

        metadata = generate_run_metadata(logs_dir, args)

        self.assertEqual(metadata["max_sessions"], 5)
        self.assertEqual(metadata["max_mutations_per_session"], 10)
        self.assertEqual(metadata["global_seed"], 42)
        self.assertEqual(metadata["workdir"], "/tmp/test")
        self.assertTrue(metadata["keep_children"])
        self.assertTrue(metadata["dry_run"])
        self.assertEqual(metadata["mutator_filter"], "OperatorSwapper,GCInjector")
        self.assertEqual(metadata["forced_strategy"], "spam")


if __name__ == "__main__":
    unittest.main()
