"""
Tests for the triage module (lafleur/triage.py).

This module tests the refactored testable helper functions that handle
import/export of issues and triage actions.
"""

import argparse
import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch, MagicMock

from lafleur.registry import CrashRegistry
from lafleur.triage import (
    do_export_issues,
    do_import_issues,
    get_triage_candidates,
    handle_triage_action,
    discover_instances,
    load_json_file,
    get_revision_date,
    parse_iso_timestamp,
    import_campaign,
    show_status,
    list_crashes,
    show_crash,
    export_issues,
    import_issues,
    main,
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


class TestLoadJsonFile(unittest.TestCase):
    """Tests for load_json_file helper function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_loads_valid_json(self):
        """Test loading valid JSON file."""
        json_path = self.temp_path / "test.json"
        data = {"key": "value", "number": 42}
        json_path.write_text(json.dumps(data))

        result = load_json_file(json_path)
        self.assertEqual(result, data)

    def test_returns_none_for_nonexistent_file(self):
        """Test returning None for non-existent file."""
        result = load_json_file(self.temp_path / "nonexistent.json")
        self.assertIsNone(result)

    def test_returns_none_for_invalid_json(self):
        """Test returning None for invalid JSON."""
        json_path = self.temp_path / "invalid.json"
        json_path.write_text("not valid json {{{")

        result = load_json_file(json_path)
        self.assertIsNone(result)


class TestGetRevisionDate(unittest.TestCase):
    """Tests for get_revision_date helper function."""

    @patch("lafleur.triage.subprocess.run")
    def test_returns_timestamp_for_valid_revision(self, mock_run):
        """Test getting timestamp for valid git revision."""
        mock_run.return_value = MagicMock(returncode=0, stdout="1704067200\n")

        result = get_revision_date("abc123")

        self.assertEqual(result, 1704067200)

    @patch("lafleur.triage.subprocess.run")
    def test_returns_none_for_invalid_revision(self, mock_run):
        """Test returning None for invalid revision."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        result = get_revision_date("invalid")

        self.assertIsNone(result)

    @patch("lafleur.triage.subprocess.run")
    def test_handles_timeout(self, mock_run):
        """Test handling subprocess timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=10)

        result = get_revision_date("abc123")

        self.assertIsNone(result)

    @patch("lafleur.triage.subprocess.run")
    def test_handles_value_error(self, mock_run):
        """Test handling non-numeric output."""
        mock_run.return_value = MagicMock(returncode=0, stdout="not a number")

        result = get_revision_date("abc123")

        self.assertIsNone(result)


class TestParseIsoTimestamp(unittest.TestCase):
    """Tests for parse_iso_timestamp helper function."""

    def test_parses_valid_timestamp(self):
        """Test parsing valid ISO timestamp."""
        result = parse_iso_timestamp("2025-01-01T12:00:00+00:00")
        self.assertEqual(result, 1735732800)

    def test_parses_z_suffix(self):
        """Test parsing timestamp with Z suffix."""
        result = parse_iso_timestamp("2025-01-01T12:00:00Z")
        self.assertEqual(result, 1735732800)

    def test_returns_none_for_empty_string(self):
        """Test returning None for empty string."""
        result = parse_iso_timestamp("")
        self.assertIsNone(result)

    def test_returns_none_for_invalid_format(self):
        """Test returning None for invalid format."""
        result = parse_iso_timestamp("not a timestamp")
        self.assertIsNone(result)


class TestImportCampaign(unittest.TestCase):
    """Tests for import_campaign CLI command."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "crashes.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exits_on_nonexistent_directory(self):
        """Test exit when campaign directory doesn't exist."""
        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path / "nonexistent"))

        with self.assertRaises(SystemExit) as ctx:
            import_campaign(args)
        self.assertEqual(ctx.exception.code, 1)

    def test_exits_when_no_instances_found(self):
        """Test exit when no valid instances are found."""
        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        with self.assertRaises(SystemExit) as ctx:
            import_campaign(args)
        self.assertEqual(ctx.exception.code, 1)

    def test_imports_crashes_from_instances(self):
        """Test importing crashes from valid instances."""
        # Create instance structure
        inst_dir = self.temp_path / "instance1"
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "run_metadata.json").write_text(
            json.dumps({"instance_name": "test-instance", "run_id": "run123"})
        )

        # Create crash
        crash_dir = inst_dir / "crashes" / "crash1"
        crash_dir.mkdir(parents=True)
        (crash_dir / "metadata.json").write_text(
            json.dumps({"fingerprint": "ASSERT:test", "timestamp": "20250101_120000"})
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        import_campaign(args)

        # Verify crash was imported
        registry = CrashRegistry(self.db_path)
        crashes = registry.get_all_crashes()
        self.assertEqual(len(crashes), 1)
        self.assertEqual(crashes[0]["fingerprint"], "ASSERT:test")


class TestShowStatus(unittest.TestCase):
    """Tests for show_status CLI command."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_shows_empty_registry_status(self):
        """Test showing status of empty registry."""
        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("CRASH REGISTRY STATUS", output)
        self.assertIn("Total unique crashes:", output)

    def test_shows_populated_registry_status(self):
        """Test showing status with crashes."""
        self.registry.add_sighting("ASSERT:test", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Total unique crashes:", output)


class TestListCrashes(unittest.TestCase):
    """Tests for list_crashes CLI command."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_lists_no_crashes(self):
        """Test listing when no crashes exist."""
        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("No crashes found", output)

    def test_lists_crashes(self):
        """Test listing crashes."""
        self.registry.add_sighting("ASSERT:test1", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:test2", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("ASSERT:test1", output)
        self.assertIn("ASSERT:test2", output)

    def test_lists_crashes_with_status_filter(self):
        """Test listing crashes with status filter."""
        self.registry.add_sighting("ASSERT:test1", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:test1", "IGNORED")
        self.registry.add_sighting("ASSERT:test2", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, status="NEW")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertNotIn("ASSERT:test1", output)
        self.assertIn("ASSERT:test2", output)


class TestShowCrash(unittest.TestCase):
    """Tests for show_crash CLI command."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_shows_nonexistent_crash(self):
        """Test showing non-existent crash."""
        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:nonexistent")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Crash not found", output)

    def test_shows_existing_crash(self):
        """Test showing existing crash details."""
        self.registry.add_sighting("ASSERT:test", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:test")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("CRASH DETAILS", output)
        self.assertIn("ASSERT:test", output)
        self.assertIn("inst1", output)

    def test_shows_linked_issue(self):
        """Test showing crash with linked issue."""
        self.registry.add_sighting("ASSERT:test", "run1", "inst1", "2025-01-01")
        self.registry.record_issue(
            {"issue_number": 123, "title": "Test Bug", "url": "https://example.com"}
        )
        self.registry.link_crash_to_issue("ASSERT:test", 123)

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:test")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Linked Issue", output)
        self.assertIn("#123", output)


class TestExportIssuesCLI(unittest.TestCase):
    """Tests for export_issues CLI command."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exports_issues(self):
        """Test exporting issues via CLI."""
        self.registry.record_issue({"issue_number": 123, "title": "Bug"})
        output_path = Path(self.temp_dir.name) / "export.json"

        args = argparse.Namespace(db=self.db_path, output=output_path)

        export_issues(args)

        self.assertTrue(output_path.exists())


class TestImportIssuesCLI(unittest.TestCase):
    """Tests for import_issues CLI command."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "crashes.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_imports_issues(self):
        """Test importing issues via CLI."""
        input_path = Path(self.temp_dir.name) / "import.json"
        input_path.write_text(json.dumps([{"issue_number": 456, "title": "Bug"}]))

        args = argparse.Namespace(db=self.db_path, input=input_path)

        import_issues(args)

        registry = CrashRegistry(self.db_path)
        issues = registry.get_all_reported_issues()
        self.assertEqual(len(issues), 1)

    def test_exits_on_file_not_found(self):
        """Test exit when input file not found."""
        args = argparse.Namespace(
            db=self.db_path, input=Path(self.temp_dir.name) / "nonexistent.json"
        )

        with self.assertRaises(SystemExit) as ctx:
            import_issues(args)
        self.assertEqual(ctx.exception.code, 1)


class TestRunInteractiveTriage(unittest.TestCase):
    """Tests for run_interactive_triage function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exits_when_no_new_crashes(self):
        """Test exit when no NEW crashes found."""
        from lafleur.triage import run_interactive_triage

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("no crashes need triage", output.lower())

    def test_interactive_loop_quit(self):
        """Test quitting interactive mode."""
        from lafleur.triage import run_interactive_triage

        self.registry.add_sighting("ASSERT:test", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        # Simulate user pressing 'q' to quit
        with patch("builtins.input", return_value="q"):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Exiting", output)


class TestRunReviewTriage(unittest.TestCase):
    """Tests for run_review_triage function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exits_when_no_crashes_with_status(self):
        """Test exit when no crashes with specified status."""
        from lafleur.triage import run_review_triage

        args = argparse.Namespace(db=self.db_path, status="REPORTED")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("No crashes with status", output)

    def test_review_quit(self):
        """Test quitting review mode."""
        from lafleur.triage import run_review_triage

        self.registry.add_sighting("ASSERT:test", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:test", "REPORTED")

        args = argparse.Namespace(db=self.db_path, status="REPORTED")

        # Simulate user pressing 'q' to quit
        with patch("builtins.input", return_value="q"):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Exiting", output)


class TestMain(unittest.TestCase):
    """Tests for main CLI entry point."""

    def test_no_command_shows_help(self):
        """Test that no command shows help."""
        with patch("sys.argv", ["triage"]):
            with patch("lafleur.triage.argparse.ArgumentParser.print_help") as mock_help:
                main()
                mock_help.assert_called_once()

    @patch("lafleur.triage.show_status")
    def test_status_command(self, mock_status):
        """Test status command invocation."""
        with patch("sys.argv", ["triage", "--db", "test.db", "status"]):
            main()
            mock_status.assert_called_once()

    @patch("lafleur.triage.list_crashes")
    def test_list_command(self, mock_list):
        """Test list command invocation."""
        with patch("sys.argv", ["triage", "--db", "test.db", "list"]):
            main()
            mock_list.assert_called_once()

    @patch("lafleur.triage.export_issues")
    def test_export_issues_command(self, mock_export):
        """Test export-issues command invocation."""
        with patch("sys.argv", ["triage", "--db", "test.db", "export-issues", "output.json"]):
            main()
            mock_export.assert_called_once()

    @patch("lafleur.triage.import_issues")
    def test_import_issues_command(self, mock_import):
        """Test import-issues command invocation."""
        with patch("sys.argv", ["triage", "--db", "test.db", "import-issues", "input.json"]):
            main()
            mock_import.assert_called_once()


if __name__ == "__main__":
    unittest.main()
