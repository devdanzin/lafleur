import unittest
import sqlite3
import tempfile
from pathlib import Path
from lafleur.registry import CrashRegistry


class TestCrashRegistry(unittest.TestCase):
    def setUp(self):
        # Use a temporary file for the DB to ensure fresh state
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        # Registry uses context managers for connections, no explicit close needed on instance
        self.temp_dir.cleanup()

    def test_init_creates_tables(self):
        """Test that tables are created on initialization."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check crashes table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='crashes'")
        self.assertIsNotNone(cursor.fetchone())

        # Check reported_issues table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reported_issues'")
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    def test_register_crash_and_sightings(self):
        """Test registering a new crash and adding sightings."""
        fingerprint = "ASSERT:file.c:123"

        # 1. Add sighting (creates crash row implicitly)
        # add_sighting(fingerprint, run_id, instance_name, timestamp, ...)
        success = self.registry.add_sighting(
            fingerprint,
            "run_1",
            "inst_1",
            "2025-01-01T12:00:00"
        )
        self.assertTrue(success)

        # 2. Verify data
        crash = self.registry.get_crash(fingerprint)
        self.assertIsNotNone(crash)
        self.assertEqual(crash["triage_status"], "NEW")

        # Sighting count
        self.assertEqual(self.registry.get_sighting_count(fingerprint), 1)

    def test_link_issue_and_regression(self):
        """Test linking a crash to an issue and detecting regression."""
        fingerprint = "SEGV:mem_error"
        self.registry.add_sighting(fingerprint, "run_1", "inst_1", "2025-01-01")

        # Record the issue first so we have details
        self.registry.record_issue({
            "issue_number": 123,
            "title": "Memory Error",
            "url": "https://github.com/python/cpython/issues/123",
            "crash_status": "FIXED"
        })

        # Link to issue
        self.registry.link_crash_to_issue(fingerprint, 123)

        # Mark as FIXED (method is set_triage_status)
        self.registry.set_triage_status(fingerprint, "FIXED")

        # Check context
        ctx = self.registry.get_crash_context(fingerprint)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx["crash_status"], "FIXED")
        self.assertEqual(ctx["issue_number"], 123)
        self.assertEqual(ctx["triage_status"], "FIXED")

    def test_import_export_issues(self):
        """Test upserting known issues."""
        issues = [
            {
                "issue_number": 999,
                "title": "Test Bug",
                "url": "http://test",
                "crash_status": "OPEN",
                "notes": "Note"
            }
        ]
        count = self.registry.upsert_reported_issues(issues)
        self.assertEqual(count, 1)

        # Verify it exists
        fetched = self.registry.get_all_reported_issues()
        self.assertEqual(len(fetched), 1)
        self.assertEqual(fetched[0]["issue_number"], 999)
