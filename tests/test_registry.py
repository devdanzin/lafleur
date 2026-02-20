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
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='reported_issues'"
        )
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    def test_register_crash_and_sightings(self):
        """Test registering a new crash and adding sightings."""
        fingerprint = "ASSERT:file.c:123"

        # 1. Add sighting (creates crash row implicitly)
        # add_sighting(fingerprint, run_id, instance_name, timestamp, ...)
        success = self.registry.add_sighting(fingerprint, "run_1", "inst_1", "2025-01-01T12:00:00")
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
        self.registry.record_issue(
            {
                "issue_number": 123,
                "title": "Memory Error",
                "url": "https://github.com/python/cpython/issues/123",
                "crash_status": "FIXED",
            }
        )

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
                "notes": "Note",
            }
        ]
        count = self.registry.upsert_reported_issues(issues)
        self.assertEqual(count, 1)

        # Verify it exists
        fetched = self.registry.get_all_reported_issues()
        self.assertEqual(len(fetched), 1)
        self.assertEqual(fetched[0]["issue_number"], 999)

    def test_upsert_partial_preserves_existing(self):
        """Test that partial upsert preserves existing fields."""
        # Insert a complete issue first
        full_issue = {
            "issue_number": 100,
            "title": "Original Title",
            "url": "https://github.com/issue/100",
            "description": "Original description",
            "issue_status": "Open",
            "crash_status": "NEW",
        }
        self.registry.upsert_reported_issues([full_issue])

        # Now upsert with only a partial update
        partial_update = {
            "issue_number": 100,
            "issue_status": "Closed",
        }
        self.registry.upsert_reported_issues([partial_update])

        # Verify that existing fields were preserved
        issues = self.registry.get_all_reported_issues()
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue["issue_number"], 100)
        self.assertEqual(issue["title"], "Original Title")  # PRESERVED
        self.assertEqual(issue["url"], "https://github.com/issue/100")  # PRESERVED
        self.assertEqual(issue["description"], "Original description")  # PRESERVED
        self.assertEqual(issue["issue_status"], "Closed")  # UPDATED
        self.assertEqual(issue["crash_status"], "NEW")  # PRESERVED

    def test_upsert_new_issue_works(self):
        """Test that upserting a brand new issue still inserts correctly."""
        new_issue = {
            "issue_number": 200,
            "title": "New Bug",
            "url": "https://github.com/issue/200",
        }
        count = self.registry.upsert_reported_issues([new_issue])
        self.assertEqual(count, 1)

        issues = self.registry.get_all_reported_issues()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["title"], "New Bug")

    def test_upsert_multiple_mixed(self):
        """Test upserting a mix of new and existing issues."""
        # Insert initial issue
        self.registry.upsert_reported_issues(
            [
                {
                    "issue_number": 300,
                    "title": "Existing",
                    "description": "Keep this",
                }
            ]
        )

        # Upsert: update existing + insert new
        batch = [
            {"issue_number": 300, "issue_status": "Closed"},  # Partial update
            {"issue_number": 301, "title": "Brand New"},  # New issue
        ]
        count = self.registry.upsert_reported_issues(batch)
        self.assertEqual(count, 2)

        issues = self.registry.get_all_reported_issues()
        self.assertEqual(len(issues), 2)

        issue_300 = next(i for i in issues if i["issue_number"] == 300)
        self.assertEqual(issue_300["title"], "Existing")  # Preserved
        self.assertEqual(issue_300["description"], "Keep this")  # Preserved
        self.assertEqual(issue_300["issue_status"], "Closed")  # Updated

        issue_301 = next(i for i in issues if i["issue_number"] == 301)
        self.assertEqual(issue_301["title"], "Brand New")
