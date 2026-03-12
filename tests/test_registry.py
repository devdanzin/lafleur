import sqlite3
import tempfile
import unittest
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

    def test_duplicate_sighting_returns_false(self):
        """Test that adding the same sighting twice returns False on the duplicate."""
        fp = "ASSERT:dup_test"
        self.registry.add_sighting(fp, "run_1", "inst_1", "2025-01-01T00:00:00")
        result = self.registry.add_sighting(fp, "run_1", "inst_1", "2025-01-01T00:00:00")
        self.assertFalse(result)
        self.assertEqual(self.registry.get_sighting_count(fp), 1)

    def test_multiple_sightings_same_fingerprint(self):
        """Test multiple sightings of the same crash from different runs."""
        fp = "SEGV:multi"
        self.registry.add_sighting(fp, "run_1", "inst_1", "2025-01-01T00:00:00")
        self.registry.add_sighting(fp, "run_2", "inst_2", "2025-01-02T00:00:00")
        self.assertEqual(self.registry.get_sighting_count(fp), 2)

    def test_set_triage_status(self):
        """Test changing triage status of a crash."""
        fp = "ASSERT:status_test"
        self.registry.add_sighting(fp, "run_1", "inst_1", "2025-01-01")

        result = self.registry.set_triage_status(fp, "IGNORED")
        self.assertTrue(result)

        crash = self.registry.get_crash(fp)
        self.assertEqual(crash["triage_status"], "IGNORED")

    def test_set_triage_status_nonexistent_returns_false(self):
        """Test set_triage_status returns False for unknown fingerprint."""
        result = self.registry.set_triage_status("nonexistent", "IGNORED")
        self.assertFalse(result)

    def test_add_note(self):
        """Test adding a note to a crash."""
        fp = "ASSERT:note_test"
        self.registry.add_sighting(fp, "run_1", "inst_1", "2025-01-01")

        result = self.registry.add_note(fp, "This is a known issue")
        self.assertTrue(result)

        crash = self.registry.get_crash(fp)
        self.assertEqual(crash["notes"], "This is a known issue")

    def test_add_note_nonexistent_returns_false(self):
        """Test add_note returns False for unknown fingerprint."""
        result = self.registry.add_note("nonexistent", "note")
        self.assertFalse(result)

    def test_get_new_crashes(self):
        """Test retrieving all NEW crashes."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp2", "run_1", "inst_1", "2025-01-02")
        self.registry.set_triage_status("fp1", "IGNORED")

        new_crashes = self.registry.get_new_crashes()
        self.assertEqual(len(new_crashes), 1)
        self.assertEqual(new_crashes[0]["fingerprint"], "fp2")

    def test_get_triaged_crashes_all(self):
        """Test retrieving all triaged (non-NEW) crashes."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp2", "run_1", "inst_1", "2025-01-02")
        self.registry.set_triage_status("fp1", "TRIAGED")
        self.registry.set_triage_status("fp2", "IGNORED")

        triaged = self.registry.get_triaged_crashes()
        self.assertEqual(len(triaged), 2)

    def test_get_triaged_crashes_filtered(self):
        """Test retrieving triaged crashes filtered by specific status."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp2", "run_1", "inst_1", "2025-01-02")
        self.registry.set_triage_status("fp1", "TRIAGED")
        self.registry.set_triage_status("fp2", "IGNORED")

        triaged = self.registry.get_triaged_crashes(status="TRIAGED")
        self.assertEqual(len(triaged), 1)
        self.assertEqual(triaged[0]["fingerprint"], "fp1")

    def test_get_all_crashes(self):
        """Test retrieving all crashes regardless of status."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp2", "run_1", "inst_1", "2025-01-02")

        all_crashes = self.registry.get_all_crashes()
        self.assertEqual(len(all_crashes), 2)

    def test_get_all_crashes_filtered(self):
        """Test filtering crashes by triage status."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp2", "run_1", "inst_1", "2025-01-02")
        self.registry.set_triage_status("fp1", "IGNORED")

        filtered = self.registry.get_all_crashes(triage_status="NEW")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["fingerprint"], "fp2")

    def test_get_stats(self):
        """Test summary statistics."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp1", "run_2", "inst_2", "2025-01-02")
        self.registry.add_sighting("fp2", "run_1", "inst_1", "2025-01-03")
        self.registry.record_issue({"issue_number": 1, "title": "Bug"})

        stats = self.registry.get_stats()
        self.assertEqual(stats["total_crashes"], 2)
        self.assertEqual(stats["total_sightings"], 3)
        self.assertEqual(stats["total_issues"], 1)
        self.assertEqual(stats["by_triage_status"]["NEW"], 2)
        self.assertEqual(stats["unique_instances"], 2)
        self.assertEqual(stats["unique_runs"], 2)

    def test_get_sightings(self):
        """Test retrieving sightings for a crash."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp1", "run_2", "inst_2", "2025-01-02")

        sightings = self.registry.get_sightings("fp1")
        self.assertEqual(len(sightings), 2)

    def test_get_sightings_with_limit(self):
        """Test sightings with a limit."""
        self.registry.add_sighting("fp1", "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting("fp1", "run_2", "inst_2", "2025-01-02")
        self.registry.add_sighting("fp1", "run_3", "inst_3", "2025-01-03")

        sightings = self.registry.get_sightings("fp1", limit=2)
        self.assertEqual(len(sightings), 2)

    def test_unlink_crash_from_issue(self):
        """Test unlinking a crash from its issue."""
        fp = "ASSERT:unlink"
        self.registry.add_sighting(fp, "run_1", "inst_1", "2025-01-01")
        self.registry.record_issue({"issue_number": 42, "title": "Bug"})
        self.registry.link_crash_to_issue(fp, 42)

        crash = self.registry.get_crash(fp)
        self.assertEqual(crash["issue_number"], 42)

        result = self.registry.unlink_crash_from_issue(fp)
        self.assertTrue(result)

        crash = self.registry.get_crash(fp)
        self.assertIsNone(crash["issue_number"])

    def test_get_crash_nonexistent(self):
        """Test get_crash returns None for unknown fingerprint."""
        self.assertIsNone(self.registry.get_crash("nonexistent"))

    def test_get_crash_context_nonexistent(self):
        """Test get_crash_context returns None for unknown fingerprint."""
        self.assertIsNone(self.registry.get_crash_context("nonexistent"))

    def test_get_crash_details(self):
        """Test that get_crash returns complete details."""
        fp = "ASSERT:details"
        self.registry.add_sighting(fp, "run_1", "inst_1", "2025-01-01")
        self.registry.add_sighting(fp, "run_2", "inst_2", "2025-01-02")

        crash = self.registry.get_crash(fp)
        self.assertEqual(crash["fingerprint"], fp)
        self.assertEqual(crash["sighting_count"], 2)
        self.assertEqual(crash["latest_sighting"], "2025-01-02")
        self.assertIn("inst_1", crash["instances"])
        self.assertIn("inst_2", crash["instances"])

    def test_upsert_empty_list(self):
        """Test that upserting an empty list returns 0."""
        self.assertEqual(self.registry.upsert_reported_issues([]), 0)

    def test_upsert_skips_missing_issue_number(self):
        """Test that upsert skips dicts without issue_number."""
        count = self.registry.upsert_reported_issues([{"title": "No number"}])
        self.assertEqual(count, 0)

    def test_record_issue_update(self):
        """Test updating an existing issue via record_issue."""
        self.registry.record_issue({"issue_number": 50, "title": "Original"})
        self.registry.record_issue({"issue_number": 50, "title": "Updated"})

        issues = self.registry.get_all_reported_issues()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["title"], "Updated")
