"""
Tests for display/output functions in lafleur/triage.py.

This module tests the output formatting functions by capturing stdout
and verifying the content matches expectations.
"""

import argparse
import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from lafleur.registry import CrashRegistry
from lafleur.triage import (
    list_crashes,
    show_crash,
    show_status,
    import_campaign,
)


class TestListCrashesDisplay(unittest.TestCase):
    """Tests for list_crashes output formatting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_displays_header_row(self):
        """Test that header row is displayed."""
        self.registry.add_sighting("ASSERT:test", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("Fingerprint", output)
        self.assertIn("Status", output)
        self.assertIn("Hits", output)
        self.assertIn("Issue", output)

    def test_displays_crash_fingerprint(self):
        """Test that crash fingerprints are displayed."""
        self.registry.add_sighting("ASSERT:unique_fingerprint_123", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("ASSERT:unique_fingerprint_123", output)

    def test_displays_triage_status(self):
        """Test that triage status is displayed."""
        self.registry.add_sighting("ASSERT:new", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:ignored", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:ignored", "IGNORED")

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("NEW", output)
        self.assertIn("IGNORED", output)

    def test_displays_sighting_count(self):
        """Test that sighting counts are displayed."""
        # Add multiple sightings for one crash
        self.registry.add_sighting("ASSERT:multi", "run1", "inst1", "2025-01-01T10:00:00")
        self.registry.add_sighting("ASSERT:multi", "run2", "inst2", "2025-01-01T11:00:00")
        self.registry.add_sighting("ASSERT:multi", "run3", "inst3", "2025-01-01T12:00:00")

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        # Should show 3 sightings
        self.assertIn("3", output)

    def test_displays_linked_issue_number(self):
        """Test that linked issue numbers are displayed."""
        self.registry.add_sighting("ASSERT:linked", "run1", "inst1", "2025-01-01")
        self.registry.record_issue({"issue_number": 12345, "title": "Test Bug"})
        self.registry.link_crash_to_issue("ASSERT:linked", 12345)

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("#12345", output)

    def test_displays_issue_title_truncated(self):
        """Test that issue title is displayed (truncated if long)."""
        self.registry.add_sighting("ASSERT:titled", "run1", "inst1", "2025-01-01")
        self.registry.record_issue(
            {"issue_number": 999, "title": "This is a very long title that should be truncated"}
        )
        self.registry.link_crash_to_issue("ASSERT:titled", 999)

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("#999", output)
        # Title should be present but truncated
        self.assertIn("This is a very long", output)

    def test_displays_dash_for_no_issue(self):
        """Test that dash is displayed when no issue is linked."""
        self.registry.add_sighting("ASSERT:noissue", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        # The line should end with a dash for unlinked crashes
        lines = output.split("\n")
        crash_line = [line for line in lines if "ASSERT:noissue" in line][0]
        self.assertTrue(crash_line.strip().endswith("-"))

    def test_filters_by_new_status(self):
        """Test filtering by NEW status."""
        self.registry.add_sighting("ASSERT:new1", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:ignored1", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:ignored1", "IGNORED")

        args = argparse.Namespace(db=self.db_path, status="NEW")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("ASSERT:new1", output)
        self.assertNotIn("ASSERT:ignored1", output)

    def test_filters_by_ignored_status(self):
        """Test filtering by IGNORED status."""
        self.registry.add_sighting("ASSERT:new2", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:ignored2", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:ignored2", "IGNORED")

        args = argparse.Namespace(db=self.db_path, status="IGNORED")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertNotIn("ASSERT:new2", output)
        self.assertIn("ASSERT:ignored2", output)

    def test_no_crashes_message(self):
        """Test message when no crashes exist."""
        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        self.assertIn("No crashes found", output)

    def test_orders_by_sighting_count(self):
        """Test that crashes are ordered by sighting count (descending)."""
        self.registry.add_sighting("ASSERT:few", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:many", "run1", "inst1", "2025-01-01T10:00:00")
        self.registry.add_sighting("ASSERT:many", "run2", "inst2", "2025-01-01T11:00:00")
        self.registry.add_sighting("ASSERT:many", "run3", "inst3", "2025-01-01T12:00:00")

        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            list_crashes(args)

        output = captured_output.getvalue()
        # "many" should appear before "few" due to higher count
        many_pos = output.find("ASSERT:many")
        few_pos = output.find("ASSERT:few")
        self.assertLess(many_pos, few_pos)


class TestShowCrashDisplay(unittest.TestCase):
    """Tests for show_crash output formatting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_displays_crash_header(self):
        """Test that crash details header is displayed."""
        self.registry.add_sighting("ASSERT:header", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:header")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("CRASH DETAILS", output)
        self.assertIn("=" * 60, output)

    def test_displays_fingerprint(self):
        """Test that fingerprint is displayed."""
        self.registry.add_sighting("ASSERT:fp_display", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:fp_display")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Fingerprint:", output)
        self.assertIn("ASSERT:fp_display", output)

    def test_displays_triage_status(self):
        """Test that triage status is displayed."""
        self.registry.add_sighting("ASSERT:status", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:status", "REPORTED")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:status")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Triage Status:", output)
        self.assertIn("REPORTED", output)

    def test_displays_dates(self):
        """Test that first seen and latest seen dates are displayed."""
        self.registry.add_sighting("ASSERT:dates", "run1", "inst1", "2025-01-01T10:00:00")
        self.registry.add_sighting("ASSERT:dates", "run2", "inst2", "2025-01-15T15:00:00")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:dates")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("First Seen:", output)
        self.assertIn("Latest Seen:", output)

    def test_displays_sighting_count(self):
        """Test that total sighting count is displayed."""
        self.registry.add_sighting("ASSERT:count", "run1", "inst1", "2025-01-01T10:00:00")
        self.registry.add_sighting("ASSERT:count", "run2", "inst2", "2025-01-01T11:00:00")
        self.registry.add_sighting("ASSERT:count", "run3", "inst3", "2025-01-01T12:00:00")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:count")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Total Sightings:", output)
        self.assertIn("3", output)

    def test_displays_instances(self):
        """Test that instance names are displayed."""
        self.registry.add_sighting("ASSERT:inst", "run1", "instance-alpha", "2025-01-01")
        self.registry.add_sighting("ASSERT:inst", "run2", "instance-beta", "2025-01-02")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:inst")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Instances:", output)
        self.assertIn("instance-alpha", output)
        self.assertIn("instance-beta", output)

    def test_displays_notes(self):
        """Test that notes are displayed when present."""
        self.registry.add_sighting("ASSERT:noted", "run1", "inst1", "2025-01-01")
        self.registry.add_note("ASSERT:noted", "This is a test note for the crash")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:noted")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Notes:", output)
        self.assertIn("This is a test note for the crash", output)

    def test_displays_linked_issue_section(self):
        """Test that linked issue section is displayed."""
        self.registry.add_sighting("ASSERT:issue", "run1", "inst1", "2025-01-01")
        self.registry.record_issue(
            {
                "issue_number": 54321,
                "title": "JIT crash on iteration",
                "url": "https://github.com/python/cpython/issues/54321",
                "issue_status": "Open",
                "crash_status": "REPORTED",
            }
        )
        self.registry.link_crash_to_issue("ASSERT:issue", 54321)

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:issue")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Linked Issue", output)
        self.assertIn("#54321", output)
        self.assertIn("JIT crash on iteration", output)
        self.assertIn("https://github.com/python/cpython/issues/54321", output)
        self.assertIn("Issue Status:", output)
        self.assertIn("Crash Status:", output)

    def test_displays_recent_sightings(self):
        """Test that recent sightings section is displayed."""
        self.registry.add_sighting("ASSERT:sightings", "run1", "inst-1", "2025-01-01T10:00:00")
        self.registry.add_sighting("ASSERT:sightings", "run2", "inst-2", "2025-01-02T11:00:00")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:sightings")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Recent Sightings", output)
        self.assertIn("inst-1", output)
        self.assertIn("inst-2", output)

    def test_displays_cpython_revision_in_sightings(self):
        """Test that CPython revision is displayed in sightings."""
        self.registry.add_sighting(
            "ASSERT:rev", "run1", "inst1", "2025-01-01", cpython_revision="abc123def456"
        )

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:rev")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("rev:", output)
        self.assertIn("abc123de", output)  # Truncated to 8 chars

    def test_displays_na_for_missing_revision(self):
        """Test that N/A is displayed when revision is missing."""
        self.registry.add_sighting("ASSERT:norev", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path, fingerprint="ASSERT:norev")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("rev: N/A", output)

    def test_crash_not_found_message(self):
        """Test message when crash is not found."""
        args = argparse.Namespace(db=self.db_path, fingerprint="NONEXISTENT:fingerprint")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_crash(args)

        output = captured_output.getvalue()
        self.assertIn("Crash not found", output)
        self.assertIn("NONEXISTENT:fingerprint", output)


class TestShowStatusDisplay(unittest.TestCase):
    """Tests for show_status output formatting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_displays_header(self):
        """Test that header is displayed."""
        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("CRASH REGISTRY STATUS", output)
        self.assertIn("=" * 60, output)

    def test_displays_database_path(self):
        """Test that database path is displayed."""
        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Database:", output)
        self.assertIn(str(self.db_path), output)

    def test_displays_total_crashes(self):
        """Test that total unique crashes count is displayed."""
        self.registry.add_sighting("ASSERT:crash1", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:crash2", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Total unique crashes:", output)
        self.assertIn("2", output)

    def test_displays_total_sightings(self):
        """Test that total sightings count is displayed."""
        self.registry.add_sighting("ASSERT:crash", "run1", "inst1", "2025-01-01T10:00:00")
        self.registry.add_sighting("ASSERT:crash", "run2", "inst2", "2025-01-01T11:00:00")
        self.registry.add_sighting("ASSERT:crash", "run3", "inst3", "2025-01-01T12:00:00")

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Total sightings:", output)
        self.assertIn("3", output)

    def test_displays_reported_issues_count(self):
        """Test that reported issues count is displayed."""
        self.registry.record_issue({"issue_number": 1, "title": "Bug 1"})
        self.registry.record_issue({"issue_number": 2, "title": "Bug 2"})

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Reported issues:", output)
        self.assertIn("2", output)

    def test_displays_linked_count(self):
        """Test that linked to issues count is displayed."""
        self.registry.add_sighting("ASSERT:linked", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:unlinked", "run1", "inst1", "2025-01-01")
        self.registry.record_issue({"issue_number": 100, "title": "Bug"})
        self.registry.link_crash_to_issue("ASSERT:linked", 100)

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Linked to issues:", output)

    def test_displays_unique_instances(self):
        """Test that unique instances count is displayed."""
        self.registry.add_sighting("ASSERT:crash", "run1", "instance-a", "2025-01-01")
        self.registry.add_sighting("ASSERT:crash", "run2", "instance-b", "2025-01-02")
        self.registry.add_sighting("ASSERT:crash", "run3", "instance-a", "2025-01-03")

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Unique instances:", output)
        # Should be 2 (instance-a and instance-b)

    def test_displays_unique_runs(self):
        """Test that unique runs count is displayed."""
        self.registry.add_sighting("ASSERT:crash", "run-uuid-1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:crash", "run-uuid-2", "inst2", "2025-01-02")

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Unique runs:", output)

    def test_displays_triage_status_breakdown(self):
        """Test that triage status breakdown is displayed."""
        self.registry.add_sighting("ASSERT:new1", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:new2", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:ignored", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:ignored", "IGNORED")
        self.registry.add_sighting("ASSERT:reported", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:reported", "REPORTED")

        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("By triage status:", output)
        self.assertIn("NEW:", output)
        self.assertIn("IGNORED:", output)
        self.assertIn("REPORTED:", output)

    def test_displays_zero_counts(self):
        """Test that zero counts are displayed for empty registry."""
        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            show_status(args)

        output = captured_output.getvalue()
        self.assertIn("Total unique crashes:", output)
        self.assertIn("0", output)


class TestImportCampaignDisplay(unittest.TestCase):
    """Tests for import_campaign with real directory structures."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "crashes.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_instance(
        self,
        name: str,
        run_id: str = "run-uuid",
        crashes: list[dict] | None = None,
        python_version: str = "3.15.0a3",
    ) -> Path:
        """Helper to create a valid instance directory structure."""
        inst_dir = self.temp_path / name
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)

        # Create run_metadata.json
        metadata = {
            "instance_name": name,
            "run_id": run_id,
            "environment": {"python_version": python_version},
        }
        (logs_dir / "run_metadata.json").write_text(json.dumps(metadata))

        # Create fuzz_run_stats.json
        stats = {"start_time": "2025-01-01T00:00:00"}
        (inst_dir / "fuzz_run_stats.json").write_text(json.dumps(stats))

        # Create crashes
        if crashes:
            crashes_dir = inst_dir / "crashes"
            for i, crash in enumerate(crashes):
                crash_dir = crashes_dir / f"crash_{i}"
                crash_dir.mkdir(parents=True)
                (crash_dir / "metadata.json").write_text(json.dumps(crash))

        return inst_dir

    def test_imports_single_instance(self):
        """Test importing from a single instance directory."""
        self._create_instance(
            "test-instance",
            run_id="run-123",
            crashes=[
                {"fingerprint": "ASSERT:crash1", "timestamp": "20250101_120000"},
            ],
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)

        output = captured_output.getvalue()
        self.assertIn("Found 1 instance(s)", output)
        self.assertIn("test-instance", output)
        self.assertIn("Imported 1 sighting", output)

        # Verify crash was imported
        registry = CrashRegistry(self.db_path)
        crashes = registry.get_all_crashes()
        self.assertEqual(len(crashes), 1)
        self.assertEqual(crashes[0]["fingerprint"], "ASSERT:crash1")

    def test_imports_multiple_instances(self):
        """Test importing from multiple instance directories."""
        self._create_instance(
            "instance-1",
            run_id="run-1",
            crashes=[{"fingerprint": "ASSERT:from_inst1", "timestamp": "20250101_100000"}],
        )
        self._create_instance(
            "instance-2",
            run_id="run-2",
            crashes=[{"fingerprint": "ASSERT:from_inst2", "timestamp": "20250101_110000"}],
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)

        output = captured_output.getvalue()
        self.assertIn("Found 2 instance(s)", output)
        self.assertIn("instance-1", output)
        self.assertIn("instance-2", output)

        # Verify both crashes were imported
        registry = CrashRegistry(self.db_path)
        crashes = registry.get_all_crashes()
        self.assertEqual(len(crashes), 2)

    def test_imports_multiple_crashes_from_instance(self):
        """Test importing multiple crashes from a single instance."""
        self._create_instance(
            "multi-crash",
            crashes=[
                {"fingerprint": "ASSERT:crash_a", "timestamp": "20250101_100000"},
                {"fingerprint": "ASSERT:crash_b", "timestamp": "20250101_110000"},
                {"fingerprint": "ASSERT:crash_c", "timestamp": "20250101_120000"},
            ],
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)

        output = captured_output.getvalue()
        self.assertIn("Imported 3 sighting", output)

        # Verify all crashes were imported
        registry = CrashRegistry(self.db_path)
        crashes = registry.get_all_crashes()
        self.assertEqual(len(crashes), 3)

    def test_handles_duplicate_sightings(self):
        """Test that duplicate sightings are skipped."""
        self._create_instance(
            "duplicates",
            run_id="run-dup",
            crashes=[
                {"fingerprint": "ASSERT:dup", "timestamp": "20250101_120000"},
            ],
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        # Import twice
        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)
            import_campaign(args)

        output = captured_output.getvalue()
        # Second import should show duplicate skipped
        self.assertIn("duplicates skipped", output)

    def test_skips_instance_without_metadata(self):
        """Test that instances without valid metadata are skipped."""
        # Create instance with invalid metadata
        inst_dir = self.temp_path / "invalid"
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "run_metadata.json").write_text("not valid json {{{")

        # Create valid instance
        self._create_instance(
            "valid",
            crashes=[{"fingerprint": "ASSERT:valid", "timestamp": "20250101_120000"}],
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)

        output = captured_output.getvalue()
        self.assertIn("Skipping invalid", output)
        self.assertIn("No valid metadata", output)

    def test_skips_instance_without_crashes_dir(self):
        """Test that instances without crashes directory are noted."""
        inst_dir = self.temp_path / "no-crashes"
        logs_dir = inst_dir / "logs"
        logs_dir.mkdir(parents=True)
        metadata = {"instance_name": "no-crashes", "run_id": "run-1"}
        (logs_dir / "run_metadata.json").write_text(json.dumps(metadata))
        # No crashes directory created

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)

        output = captured_output.getvalue()
        self.assertIn("No crashes directory", output)

    def test_skips_crash_without_fingerprint(self):
        """Test that crashes without fingerprints are skipped."""
        inst_dir = self._create_instance("no-fp")

        # Create a crash without fingerprint
        crash_dir = inst_dir / "crashes" / "bad_crash"
        crash_dir.mkdir(parents=True)
        (crash_dir / "metadata.json").write_text(json.dumps({"timestamp": "20250101_120000"}))

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)

        # Should complete without error
        output = captured_output.getvalue()
        self.assertIn("no-fp", output)

    def test_displays_registry_summary(self):
        """Test that registry summary is displayed after import."""
        self._create_instance(
            "summary",
            crashes=[{"fingerprint": "ASSERT:summary", "timestamp": "20250101_120000"}],
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            import_campaign(args)

        output = captured_output.getvalue()
        self.assertIn("Registry now contains:", output)
        self.assertIn("unique crashes", output)
        self.assertIn("total sightings", output)
        self.assertIn("unique instances", output)

    def test_extracts_revision_from_python_version(self):
        """Test that CPython revision is extracted from python_version string."""
        self._create_instance(
            "revision",
            python_version="3.15.0a3+ (heads/main-dirty:e0fb2780649, Jan 1 2025)",
            crashes=[{"fingerprint": "ASSERT:rev", "timestamp": "20250101_120000"}],
        )

        args = argparse.Namespace(db=self.db_path, campaign_dir=str(self.temp_path))

        import_campaign(args)

        # Verify revision was extracted
        registry = CrashRegistry(self.db_path)
        sightings = registry.get_sightings("ASSERT:rev")
        self.assertEqual(len(sightings), 1)
        self.assertEqual(sightings[0]["cpython_revision"], "e0fb2780649")


if __name__ == "__main__":
    unittest.main()
