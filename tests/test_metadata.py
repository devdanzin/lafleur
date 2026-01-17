"""
Tests for the metadata module (lafleur/metadata.py).

This module tests the run metadata generation functionality including
Docker-style naming, git info retrieval, package listing, and the main
generate_run_metadata function.
"""

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.metadata import (
    generate_docker_style_name,
    get_git_info,
    get_installed_packages,
    get_target_python_info,
    load_existing_metadata,
    generate_run_metadata,
    ADJECTIVES,
    NOUNS,
)


class TestDockerStyleName(unittest.TestCase):
    """Tests for Docker-style name generation."""

    def test_generates_adjective_noun_format(self):
        """Test that name is in adjective-noun format."""
        name = generate_docker_style_name()
        parts = name.split("-")
        self.assertEqual(len(parts), 2)
        self.assertIn(parts[0], ADJECTIVES)
        self.assertIn(parts[1], NOUNS)

    def test_generates_different_names(self):
        """Test that names vary (not always the same)."""
        # Generate multiple names and check they're not all identical
        names = {generate_docker_style_name() for _ in range(10)}
        # Very unlikely to get all the same name 10 times
        self.assertGreater(len(names), 1)


class TestGetGitInfo(unittest.TestCase):
    """Tests for git info retrieval."""

    @patch("lafleur.metadata.subprocess.run")
    def test_returns_commit_and_dirty_status(self, mock_run):
        """Test successful git info retrieval."""
        # Mock git rev-parse HEAD
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123def456\n"),
            MagicMock(returncode=0, stdout=""),  # Not dirty
        ]

        info = get_git_info()

        self.assertEqual(info["commit"], "abc123def456")
        self.assertFalse(info["dirty"])

    @patch("lafleur.metadata.subprocess.run")
    def test_dirty_status_when_uncommitted_changes(self, mock_run):
        """Test dirty status detection."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123\n"),
            MagicMock(returncode=0, stdout="M file.py\n"),  # Dirty
        ]

        info = get_git_info()

        self.assertTrue(info["dirty"])

    @patch("lafleur.metadata.subprocess.run")
    def test_handles_git_failure(self, mock_run):
        """Test handling of git command failures."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="error"),
            MagicMock(returncode=1, stdout="", stderr="error"),
        ]

        info = get_git_info()

        self.assertEqual(info["commit"], "unknown")
        self.assertFalse(info["dirty"])

    @patch("lafleur.metadata.subprocess.run")
    def test_handles_timeout(self, mock_run):
        """Test handling of subprocess timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=5)

        info = get_git_info()

        self.assertEqual(info["commit"], "unknown")
        self.assertFalse(info["dirty"])

    @patch("lafleur.metadata.subprocess.run")
    def test_handles_file_not_found(self, mock_run):
        """Test handling when git is not installed."""
        mock_run.side_effect = FileNotFoundError("git not found")

        info = get_git_info()

        self.assertEqual(info["commit"], "unknown")
        self.assertFalse(info["dirty"])


class TestGetInstalledPackages(unittest.TestCase):
    """Tests for installed package listing."""

    @patch("lafleur.metadata.distributions")
    def test_returns_sorted_packages(self, mock_distributions):
        """Test that packages are returned sorted by name."""
        mock_dist1 = MagicMock()
        mock_dist1.metadata = {"Name": "zebra", "Version": "1.0"}
        mock_dist2 = MagicMock()
        mock_dist2.metadata = {"Name": "alpha", "Version": "2.0"}

        mock_distributions.return_value = [mock_dist1, mock_dist2]

        packages = get_installed_packages()

        self.assertEqual(len(packages), 2)
        # Should be sorted by name (alpha before zebra)
        self.assertEqual(packages[0]["name"], "alpha")
        self.assertEqual(packages[1]["name"], "zebra")

    @patch("lafleur.metadata.distributions")
    def test_returns_empty_list_when_no_packages(self, mock_distributions):
        """Test handling of empty package list."""
        mock_distributions.return_value = []

        packages = get_installed_packages()

        self.assertEqual(packages, [])


class TestGetTargetPythonInfo(unittest.TestCase):
    """Tests for target Python interpreter info retrieval."""

    @patch("lafleur.metadata.subprocess.run")
    def test_successful_retrieval(self, mock_run):
        """Test successful info retrieval from target Python."""
        mock_result = {
            "version": "3.14.0",
            "executable": "/usr/bin/python3",
            "config_args": "--enable-jit",
            "packages": [{"name": "pip", "version": "24.0"}],
        }
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(mock_result), stderr="")

        info = get_target_python_info("/usr/bin/python3")

        self.assertEqual(info["version"], "3.14.0")
        self.assertFalse(info["fallback"])

    @patch("lafleur.metadata.subprocess.run")
    def test_fallback_on_subprocess_failure(self, mock_run):
        """Test fallback to current interpreter on failure."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")

        info = get_target_python_info("/nonexistent/python")

        self.assertTrue(info["fallback"])
        # Should still have version info from current interpreter
        self.assertIn("version", info)

    @patch("lafleur.metadata.subprocess.run")
    def test_fallback_on_timeout(self, mock_run):
        """Test fallback on subprocess timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="python", timeout=30)

        info = get_target_python_info("/slow/python")

        self.assertTrue(info["fallback"])

    @patch("lafleur.metadata.subprocess.run")
    def test_fallback_on_file_not_found(self, mock_run):
        """Test fallback when Python executable not found."""
        mock_run.side_effect = FileNotFoundError("python not found")

        info = get_target_python_info("/missing/python")

        self.assertTrue(info["fallback"])

    @patch("lafleur.metadata.subprocess.run")
    def test_fallback_on_json_decode_error(self, mock_run):
        """Test fallback on invalid JSON response."""
        mock_run.return_value = MagicMock(returncode=0, stdout="not json", stderr="")

        info = get_target_python_info("/bad/python")

        self.assertTrue(info["fallback"])


class TestLoadExistingMetadata(unittest.TestCase):
    """Tests for loading existing metadata files."""

    def test_returns_none_when_file_not_exists(self):
        """Test returning None for non-existent file."""
        result = load_existing_metadata(Path("/nonexistent/metadata.json"))
        self.assertIsNone(result)

    def test_loads_valid_metadata(self):
        """Test loading valid metadata file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            metadata_path = Path(tmp_dir) / "run_metadata.json"
            expected = {"run_id": "test-123", "instance_name": "test-instance"}
            metadata_path.write_text(json.dumps(expected))

            result = load_existing_metadata(metadata_path)

            self.assertEqual(result, expected)

    def test_returns_none_on_invalid_json(self):
        """Test returning None for invalid JSON."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            metadata_path = Path(tmp_dir) / "run_metadata.json"
            metadata_path.write_text("not valid json {{{")

            result = load_existing_metadata(metadata_path)

            self.assertIsNone(result)


class TestGenerateRunMetadata(unittest.TestCase):
    """Tests for the main generate_run_metadata function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("lafleur.metadata.get_target_python_info")
    @patch("lafleur.metadata.get_git_info")
    @patch("lafleur.metadata.psutil.cpu_count")
    @patch("lafleur.metadata.psutil.virtual_memory")
    @patch("lafleur.metadata.shutil.disk_usage")
    def test_generates_new_metadata(
        self,
        mock_disk,
        mock_mem,
        mock_cpu,
        mock_git,
        mock_python,
    ):
        """Test generating new metadata from scratch."""
        # Setup mocks
        mock_python.return_value = {
            "version": "3.14.0",
            "executable": "/usr/bin/python3",
            "config_args": "--enable-jit",
            "packages": [],
            "fallback": False,
        }
        mock_git.return_value = {"commit": "abc123", "dirty": False}
        mock_cpu.return_value = 8
        mock_mem.return_value = MagicMock(total=16 * 1024**3)
        mock_disk.return_value = MagicMock(free=100 * 1024**3)

        args = argparse.Namespace(
            fusil_path="/path/to/fusil",
            corpus_timeout=10,
        )

        metadata = generate_run_metadata(self.output_dir, args)

        # Check structure
        self.assertIn("run_id", metadata)
        self.assertIn("instance_name", metadata)
        self.assertIn("environment", metadata)
        self.assertIn("hardware", metadata)
        self.assertIn("configuration", metadata)

        # Check file was created
        metadata_path = self.output_dir / "run_metadata.json"
        self.assertTrue(metadata_path.exists())

    @patch("lafleur.metadata.get_target_python_info")
    @patch("lafleur.metadata.get_git_info")
    @patch("lafleur.metadata.psutil.cpu_count")
    @patch("lafleur.metadata.psutil.virtual_memory")
    @patch("lafleur.metadata.shutil.disk_usage")
    def test_preserves_existing_identity(
        self,
        mock_disk,
        mock_mem,
        mock_cpu,
        mock_git,
        mock_python,
    ):
        """Test that existing run_id and instance_name are preserved."""
        # Create existing metadata
        existing_metadata = {
            "run_id": "existing-run-id",
            "instance_name": "existing-instance",
        }
        self.output_dir.mkdir(exist_ok=True)
        metadata_path = self.output_dir / "run_metadata.json"
        metadata_path.write_text(json.dumps(existing_metadata))

        # Setup mocks
        mock_python.return_value = {
            "version": "3.14.0",
            "executable": "/usr/bin/python3",
            "config_args": "",
            "packages": [],
            "fallback": False,
        }
        mock_git.return_value = {"commit": "abc123", "dirty": False}
        mock_cpu.return_value = 8
        mock_mem.return_value = MagicMock(total=16 * 1024**3)
        mock_disk.return_value = MagicMock(free=100 * 1024**3)

        args = argparse.Namespace()

        metadata = generate_run_metadata(self.output_dir, args)

        # Identity should be preserved
        self.assertEqual(metadata["run_id"], "existing-run-id")
        self.assertEqual(metadata["instance_name"], "existing-instance")

    @patch("lafleur.metadata.get_target_python_info")
    @patch("lafleur.metadata.get_git_info")
    @patch("lafleur.metadata.psutil.cpu_count")
    @patch("lafleur.metadata.psutil.virtual_memory")
    @patch("lafleur.metadata.shutil.disk_usage")
    def test_uses_provided_instance_name(
        self,
        mock_disk,
        mock_mem,
        mock_cpu,
        mock_git,
        mock_python,
    ):
        """Test that provided instance_name is used for new runs."""
        # Setup mocks
        mock_python.return_value = {
            "version": "3.14.0",
            "executable": "/usr/bin/python3",
            "config_args": "",
            "packages": [],
            "fallback": False,
        }
        mock_git.return_value = {"commit": "abc123", "dirty": False}
        mock_cpu.return_value = 8
        mock_mem.return_value = MagicMock(total=16 * 1024**3)
        mock_disk.return_value = MagicMock(free=100 * 1024**3)

        args = argparse.Namespace(instance_name="my-custom-instance")

        metadata = generate_run_metadata(self.output_dir, args)

        self.assertEqual(metadata["instance_name"], "my-custom-instance")

    @patch("lafleur.metadata.get_target_python_info")
    @patch("lafleur.metadata.get_git_info")
    @patch("lafleur.metadata.psutil.cpu_count")
    @patch("lafleur.metadata.psutil.virtual_memory")
    @patch("lafleur.metadata.shutil.disk_usage")
    def test_uses_target_python(
        self,
        mock_disk,
        mock_mem,
        mock_cpu,
        mock_git,
        mock_python,
    ):
        """Test that target_python argument is passed correctly."""
        mock_python.return_value = {
            "version": "3.15.0",
            "executable": "/custom/python",
            "config_args": "--enable-jit",
            "packages": [],
            "fallback": False,
        }
        mock_git.return_value = {"commit": "abc123", "dirty": False}
        mock_cpu.return_value = 8
        mock_mem.return_value = MagicMock(total=16 * 1024**3)
        mock_disk.return_value = MagicMock(free=100 * 1024**3)

        args = argparse.Namespace(target_python="/custom/python")

        metadata = generate_run_metadata(self.output_dir, args)

        # Verify get_target_python_info was called with target_python
        mock_python.assert_called_once_with("/custom/python")
        self.assertEqual(metadata["environment"]["target_python"], "/custom/python")

    @patch("lafleur.metadata.get_target_python_info")
    @patch("lafleur.metadata.get_git_info")
    @patch("lafleur.metadata.psutil.cpu_count")
    @patch("lafleur.metadata.psutil.virtual_memory")
    @patch("lafleur.metadata.shutil.disk_usage")
    def test_captures_env_vars(
        self,
        mock_disk,
        mock_mem,
        mock_cpu,
        mock_git,
        mock_python,
    ):
        """Test that environment variables are captured."""
        mock_python.return_value = {
            "version": "3.14.0",
            "executable": "/usr/bin/python3",
            "config_args": "",
            "packages": [],
            "fallback": False,
        }
        mock_git.return_value = {"commit": "abc123", "dirty": False}
        mock_cpu.return_value = 8
        mock_mem.return_value = MagicMock(total=16 * 1024**3)
        mock_disk.return_value = MagicMock(free=100 * 1024**3)

        args = argparse.Namespace()

        with patch.dict("os.environ", {"PYTHON_JIT": "1", "PYTHON_LLTRACE": "2"}):
            metadata = generate_run_metadata(self.output_dir, args)

        env_vars = metadata["configuration"]["env_vars"]
        self.assertEqual(env_vars["PYTHON_JIT"], "1")
        self.assertEqual(env_vars["PYTHON_LLTRACE"], "2")


if __name__ == "__main__":
    unittest.main()
