"""
Tests for the triage module (lafleur/triage.py).

This module tests the refactored testable helper functions that handle
import/export of issues and triage actions.
"""

import json
import tempfile
import unittest
from pathlib import Path

from lafleur.registry import CrashRegistry
from lafleur.triage import (
    do_export_issues,
    do_import_issues,
    get_triage_candidates,
    handle_triage_action,
    discover_instances,
)


class TestTriageImportExport(unittest.TestCase):
    """Tests for issue import/export functionality."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_issues_empty(self):
        """Test exporting when no issues exist."""
        output_path = Path(self.temp_dir.name) / "export.json"
        count = do_export_issues(self.registry, output_path)

        self.assertEqual(count, 0)
        self.assertTrue(output_path.exists())

        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data, [])

    def test_export_issues_with_data(self):
        """Test exporting issues with data."""
        # Add some issues
        self.registry.record_issue(
            {
                "issue_number": 123,
                "title": "Test Bug",
                "url": "https://github.com/test/123",
                "crash_status": "REPORTED",
            }
        )
        self.registry.record_issue(
            {
                "issue_number": 456,
                "title": "Another Bug",
                "url": "https://github.com/test/456",
                "crash_status": "FIXED",
            }
        )

        output_path = Path(self.temp_dir.name) / "export.json"
        count = do_export_issues(self.registry, output_path)

        self.assertEqual(count, 2)

        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 2)

        # Verify issue numbers are present
        issue_numbers = {item["issue_number"] for item in data}
        self.assertEqual(issue_numbers, {123, 456})

    def test_import_issues_valid(self):
        """Test importing valid issues."""
        input_path = Path(self.temp_dir.name) / "import.json"
        issues = [
            {"issue_number": 100, "title": "Bug A", "crash_status": "NEW"},
            {"issue_number": 200, "title": "Bug B", "crash_status": "FIXED"},
        ]
        with open(input_path, "w", encoding="utf-8") as f:
            json.dump(issues, f)

        count = do_import_issues(self.registry, input_path)
        self.assertEqual(count, 2)

        # Verify they were imported
        fetched = self.registry.get_all_reported_issues()
        self.assertEqual(len(fetched), 2)

    def test_import_issues_file_not_found(self):
        """Test importing from non-existent file."""
        input_path = Path(self.temp_dir.name) / "nonexistent.json"

        with self.assertRaises(FileNotFoundError):
            do_import_issues(self.registry, input_path)

    def test_import_issues_invalid_json(self):
        """Test importing invalid JSON."""
        input_path = Path(self.temp_dir.name) / "invalid.json"
        with open(input_path, "w", encoding="utf-8") as f:
            f.write("not valid json {{{")

        with self.assertRaises(json.JSONDecodeError):
            do_import_issues(self.registry, input_path)

    def test_import_issues_not_a_list(self):
        """Test importing JSON that's not a list."""
        input_path = Path(self.temp_dir.name) / "notlist.json"
        with open(input_path, "w", encoding="utf-8") as f:
            json.dump({"issue_number": 123}, f)

        with self.assertRaises(ValueError) as ctx:
            do_import_issues(self.registry, input_path)
        self.assertIn("must contain a list", str(ctx.exception))

    def test_import_issues_missing_issue_number(self):
        """Test importing issues missing required field."""
        input_path = Path(self.temp_dir.name) / "missing.json"
        with open(input_path, "w", encoding="utf-8") as f:
            json.dump([{"title": "No issue number"}], f)

        with self.assertRaises(ValueError) as ctx:
            do_import_issues(self.registry, input_path)
        self.assertIn("missing required field", str(ctx.exception))

    def test_roundtrip_export_import(self):
        """Test that export -> import preserves data."""
        # Add issues
        original_issues = [
            {"issue_number": 111, "title": "First", "crash_status": "NEW"},
            {"issue_number": 222, "title": "Second", "crash_status": "FIXED"},
        ]
        for issue in original_issues:
            self.registry.record_issue(issue)

        # Export
        export_path = Path(self.temp_dir.name) / "roundtrip.json"
        do_export_issues(self.registry, export_path)

        # Create new registry and import
        new_db_path = Path(self.temp_dir.name) / "new_crashes.db"
        new_registry = CrashRegistry(new_db_path)
        count = do_import_issues(new_registry, export_path)

        self.assertEqual(count, 2)
        fetched = new_registry.get_all_reported_issues()
        self.assertEqual(len(fetched), 2)


class TestTriageCandidates(unittest.TestCase):
    """Tests for getting triage candidates."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_new_crashes(self):
        """Test getting NEW crashes for triage."""
        # Add some crashes
        self.registry.add_sighting("ASSERT:test1", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:test2", "run1", "inst1", "2025-01-01")

        candidates = get_triage_candidates(self.registry)
        self.assertEqual(len(candidates), 2)

    def test_get_filtered_crashes(self):
        """Test getting crashes filtered by status."""
        # Add a crash and mark it
        self.registry.add_sighting("ASSERT:test1", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:test1", "REPORTED")

        # NEW filter should return empty
        candidates = get_triage_candidates(self.registry)
        self.assertEqual(len(candidates), 0)

        # REPORTED filter should return 1
        candidates = get_triage_candidates(self.registry, status_filter="REPORTED")
        self.assertEqual(len(candidates), 1)


class TestTriageActions(unittest.TestCase):
    """Tests for triage action handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)
        # Add a crash to work with
        self.fingerprint = "ASSERT:test_crash"
        self.registry.add_sighting(self.fingerprint, "run1", "inst1", "2025-01-01")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_action_report(self):
        """Test report action links to issue and sets status."""
        # Record issue first
        self.registry.record_issue({"issue_number": 999, "title": "Test"})

        success, msg = handle_triage_action(
            self.registry, self.fingerprint, "report", issue_number=999
        )

        self.assertTrue(success)
        self.assertIn("999", msg)

        # Verify status changed
        crash = self.registry.get_crash(self.fingerprint)
        self.assertEqual(crash["triage_status"], "REPORTED")

    def test_action_report_missing_issue(self):
        """Test report action fails without issue number."""
        success, msg = handle_triage_action(self.registry, self.fingerprint, "report")

        self.assertFalse(success)
        self.assertIn("required", msg.lower())

    def test_action_ignore(self):
        """Test ignore action sets status."""
        success, msg = handle_triage_action(self.registry, self.fingerprint, "ignore")

        self.assertTrue(success)
        crash = self.registry.get_crash(self.fingerprint)
        self.assertEqual(crash["triage_status"], "IGNORED")

    def test_action_fixed(self):
        """Test fixed action sets status."""
        success, msg = handle_triage_action(self.registry, self.fingerprint, "fixed")

        self.assertTrue(success)
        crash = self.registry.get_crash(self.fingerprint)
        self.assertEqual(crash["triage_status"], "FIXED")

    def test_action_note(self):
        """Test note action adds note."""
        success, msg = handle_triage_action(
            self.registry, self.fingerprint, "note", note_text="Test note"
        )

        self.assertTrue(success)
        crash = self.registry.get_crash(self.fingerprint)
        self.assertIn("Test note", crash.get("notes", ""))

    def test_action_note_empty(self):
        """Test note action fails with empty note."""
        success, msg = handle_triage_action(self.registry, self.fingerprint, "note", note_text="")

        self.assertFalse(success)
        self.assertIn("no note", msg.lower())

    def test_action_link(self):
        """Test link action."""
        self.registry.record_issue({"issue_number": 888, "title": "Bug"})

        success, msg = handle_triage_action(
            self.registry, self.fingerprint, "link", issue_number=888
        )

        self.assertTrue(success)

    def test_action_unlink(self):
        """Test unlink action."""
        # Link first
        self.registry.record_issue({"issue_number": 777, "title": "Bug"})
        self.registry.link_crash_to_issue(self.fingerprint, 777)

        success, msg = handle_triage_action(self.registry, self.fingerprint, "unlink")

        self.assertTrue(success)

    def test_action_status_change(self):
        """Test status change action."""
        success, msg = handle_triage_action(
            self.registry, self.fingerprint, "status", new_status="TRIAGED"
        )

        self.assertTrue(success)
        crash = self.registry.get_crash(self.fingerprint)
        self.assertEqual(crash["triage_status"], "TRIAGED")

    def test_action_status_invalid(self):
        """Test status change with invalid status."""
        success, msg = handle_triage_action(
            self.registry, self.fingerprint, "status", new_status="INVALID"
        )

        self.assertFalse(success)
        self.assertIn("invalid", msg.lower())

    def test_action_unknown(self):
        """Test unknown action returns error."""
        success, msg = handle_triage_action(self.registry, self.fingerprint, "unknown_action")

        self.assertFalse(success)
        self.assertIn("unknown", msg.lower())

    def test_action_shorthand(self):
        """Test single-letter action shortcuts."""
        # Test 'i' for ignore
        success, _ = handle_triage_action(self.registry, self.fingerprint, "i")
        self.assertTrue(success)

        # Reset and test 'm' for fixed
        self.registry.set_triage_status(self.fingerprint, "NEW")
        success, _ = handle_triage_action(self.registry, self.fingerprint, "m")
        self.assertTrue(success)
        crash = self.registry.get_crash(self.fingerprint)
        self.assertEqual(crash["triage_status"], "FIXED")


class TestDiscoverInstances(unittest.TestCase):
    """Tests for instance discovery."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_discover_empty_directory(self):
        """Test discovering instances in empty directory."""
        instances = discover_instances(self.root)
        self.assertEqual(instances, [])

    def test_discover_nonexistent_directory(self):
        """Test discovering instances in non-existent directory."""
        instances = discover_instances(self.root / "nonexistent")
        self.assertEqual(instances, [])

    def test_discover_single_instance(self):
        """Test discovering a single valid instance."""
        # Create instance structure
        logs_dir = self.root / "logs"
        logs_dir.mkdir()
        (logs_dir / "run_metadata.json").write_text("{}")

        instances = discover_instances(self.root)
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0], self.root)

    def test_discover_multiple_instances(self):
        """Test discovering multiple instances in subdirectories."""
        # Create two instance subdirectories
        for name in ["run1", "run2"]:
            inst_dir = self.root / name
            logs_dir = inst_dir / "logs"
            logs_dir.mkdir(parents=True)
            (logs_dir / "run_metadata.json").write_text("{}")

        instances = discover_instances(self.root)
        self.assertEqual(len(instances), 2)

    def test_discover_ignores_invalid_subdirs(self):
        """Test that directories without metadata are ignored."""
        # Create one valid and one invalid instance
        valid_dir = self.root / "valid"
        valid_logs = valid_dir / "logs"
        valid_logs.mkdir(parents=True)
        (valid_logs / "run_metadata.json").write_text("{}")

        invalid_dir = self.root / "invalid"
        invalid_dir.mkdir()  # No logs/run_metadata.json

        instances = discover_instances(self.root)
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0].name, "valid")


if __name__ == "__main__":
    unittest.main()
