"""
Tests for interactive triage functions in lafleur/triage.py.

This module tests the interactive wizard and triage loop functions by mocking
user input and capturing output, while testing the real implementations.
"""

import argparse
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from lafleur.registry import CrashRegistry
from lafleur.triage import (
    record_issue_wizard,
    run_interactive_triage,
    run_review_triage,
)


class TestRecordIssueWizard(unittest.TestCase):
    """Tests for record_issue_wizard function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_records_new_issue_with_all_fields(self):
        """Test recording a new issue with all fields provided."""
        # Add a crash to link
        self.registry.add_sighting("ASSERT:test_crash", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        # Simulate user input for all prompts
        user_inputs = [
            "12345",  # Issue number
            "JIT crash on list comprehension",  # Title
            "https://github.com/python/cpython/issues/12345",  # URL
            "testuser",  # Reported by
            "2025-01-15",  # Reported date
            "Crash when using list comprehension with JIT enabled",  # Description
            "abc123def456",  # CPython revision
            "3.15.0a3",  # CPython version
            "--enable-experimental-jit",  # Build info
            "Open",  # Issue status
            "REPORTED",  # Crash status
            "",  # Linked PRs
            "Linux",  # Tested OSes
            "type-crash",  # Labels
            "ASSERT:test_crash",  # Fingerprint to link
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                record_issue_wizard(args)

        output = captured_output.getvalue()
        self.assertIn("Recorded issue #12345", output)
        self.assertIn("Linked crash to issue #12345", output)

        # Verify issue was recorded
        issues = self.registry.get_all_reported_issues()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["issue_number"], 12345)
        self.assertEqual(issues[0]["title"], "JIT crash on list comprehension")

        # Verify crash was linked
        crash = self.registry.get_crash("ASSERT:test_crash")
        self.assertEqual(crash["issue_number"], 12345)

    def test_records_issue_with_defaults(self):
        """Test recording an issue using default values."""
        args = argparse.Namespace(db=self.db_path)

        # Use defaults for optional fields
        user_inputs = [
            "99999",  # Issue number
            "Test bug",  # Title
            "",  # URL (use default)
            "reporter",  # Reported by
            "",  # Reported date (use default)
            "A test bug",  # Description
            "",  # CPython revision (empty)
            "",  # CPython version (empty)
            "",  # Build info (empty)
            "",  # Issue status (default: Open)
            "",  # Crash status (default: REPORTED)
            "",  # Linked PRs
            "",  # Tested OSes
            "",  # Labels
            "",  # Fingerprint (skip linking)
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                record_issue_wizard(args)

        output = captured_output.getvalue()
        self.assertIn("Recorded issue #99999", output)
        self.assertIn("Done!", output)

        # Verify issue was recorded with defaults
        issues = self.registry.get_all_reported_issues()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["issue_status"], "Open")
        self.assertEqual(issues[0]["crash_status"], "REPORTED")

    def test_validates_issue_number_input(self):
        """Test that invalid issue number is rejected."""
        args = argparse.Namespace(db=self.db_path)

        # First provide invalid input, then valid
        user_inputs = [
            "",  # Empty (rejected)
            "not_a_number",  # Invalid (rejected)
            "123",  # Valid
            "Test issue",  # Title
            "",  # URL
            "user",  # Reported by
            "",  # Reported date
            "desc",  # Description
            "",  # CPython revision
            "",  # CPython version
            "",  # Build info
            "",  # Issue status
            "",  # Crash status
            "",  # Linked PRs
            "",  # Tested OSes
            "",  # Labels
            "",  # Fingerprint
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                record_issue_wizard(args)

        output = captured_output.getvalue()
        self.assertIn("Issue number is required", output)
        self.assertIn("Please enter a valid integer", output)
        self.assertIn("Recorded issue #123", output)

    def test_updates_existing_issue_when_confirmed(self):
        """Test updating an existing issue when user confirms."""
        # Create existing issue
        self.registry.record_issue(
            {"issue_number": 555, "title": "Old Title", "url": "https://old.url"}
        )

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "555",  # Issue number (exists)
            "y",  # Update existing? Yes
            "New Title",  # New title
            "https://new.url",  # New URL
            "updater",  # Reported by
            "",  # Reported date
            "Updated description",  # Description
            "",  # CPython revision
            "",  # CPython version
            "",  # Build info
            "",  # Issue status
            "",  # Crash status
            "",  # Linked PRs
            "",  # Tested OSes
            "",  # Labels
            "",  # Fingerprint
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                record_issue_wizard(args)

        output = captured_output.getvalue()
        self.assertIn("already exists", output)
        self.assertIn("Recorded issue #555", output)

        # Verify issue was updated
        issues = self.registry.get_all_reported_issues()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["title"], "New Title")

    def test_skips_update_and_links_only(self):
        """Test declining update but linking to existing issue."""
        # Create existing issue
        self.registry.record_issue({"issue_number": 666, "title": "Keep This"})

        # Add a crash to link
        self.registry.add_sighting("ASSERT:link_me", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "666",  # Issue number (exists)
            "n",  # Update existing? No
            "ASSERT:link_me",  # Fingerprint to link
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                record_issue_wizard(args)

        output = captured_output.getvalue()
        self.assertIn("already exists", output)
        self.assertIn("Linked crash to issue #666", output)

        # Verify issue wasn't modified
        issues = self.registry.get_all_reported_issues()
        self.assertEqual(issues[0]["title"], "Keep This")

        # Verify crash was linked
        crash = self.registry.get_crash("ASSERT:link_me")
        self.assertEqual(crash["issue_number"], 666)

    def test_handles_nonexistent_fingerprint(self):
        """Test handling when fingerprint doesn't exist in registry."""
        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "777",  # Issue number
            "Test",  # Title
            "",  # URL
            "user",  # Reported by
            "",  # Reported date
            "desc",  # Description
            "",  # CPython revision
            "",  # CPython version
            "",  # Build info
            "",  # Issue status
            "",  # Crash status
            "",  # Linked PRs
            "",  # Tested OSes
            "",  # Labels
            "NONEXISTENT:fingerprint",  # Fingerprint (doesn't exist)
            "n",  # Create anyway? No
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                record_issue_wizard(args)

        output = captured_output.getvalue()
        self.assertIn("Crash fingerprint not found", output)

    def test_creates_crash_record_when_confirmed(self):
        """Test creating a crash record for unknown fingerprint when user confirms."""
        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "888",  # Issue number
            "Test",  # Title
            "",  # URL
            "user",  # Reported by
            "",  # Reported date
            "desc",  # Description
            "",  # CPython revision
            "",  # CPython version
            "",  # Build info
            "",  # Issue status
            "",  # Crash status
            "",  # Linked PRs
            "",  # Tested OSes
            "",  # Labels
            "NEW:fingerprint",  # Fingerprint (doesn't exist)
            "y",  # Create anyway? Yes
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                record_issue_wizard(args)

        output = captured_output.getvalue()
        self.assertIn("Created crash record and linked to issue #888", output)

        # Verify crash was created
        crash = self.registry.get_crash("NEW:fingerprint")
        self.assertIsNotNone(crash)
        self.assertEqual(crash["issue_number"], 888)


class TestRunInteractiveTriage(unittest.TestCase):
    """Tests for run_interactive_triage function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_no_crashes_message(self):
        """Test message when no NEW crashes need triage."""
        args = argparse.Namespace(db=self.db_path)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("All caught up", output)
        self.assertIn("no crashes need triage", output.lower())

    def test_report_action_links_issue(self):
        """Test report action links crash to issue."""
        self.registry.add_sighting("ASSERT:crash1", "run1", "inst1", "2025-01-01")
        self.registry.record_issue({"issue_number": 111, "title": "Bug 111"})

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "r",  # Report action
            "111",  # Issue number
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Linked to Issue #111", output)

        # Verify crash status
        crash = self.registry.get_crash("ASSERT:crash1")
        self.assertEqual(crash["triage_status"], "REPORTED")
        self.assertEqual(crash["issue_number"], 111)

    def test_ignore_action_marks_ignored(self):
        """Test ignore action marks crash as IGNORED."""
        self.registry.add_sighting("ASSERT:noise", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        user_inputs = ["i"]  # Ignore action

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("IGNORED", output)

        # Verify crash status
        crash = self.registry.get_crash("ASSERT:noise")
        self.assertEqual(crash["triage_status"], "IGNORED")

    def test_fixed_action_marks_fixed(self):
        """Test fixed action marks crash as FIXED."""
        self.registry.add_sighting("ASSERT:fixed", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        user_inputs = ["m"]  # Mark fixed action

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("FIXED", output)

        # Verify crash status
        crash = self.registry.get_crash("ASSERT:fixed")
        self.assertEqual(crash["triage_status"], "FIXED")

    def test_note_action_saves_note(self):
        """Test note action saves note and continues."""
        self.registry.add_sighting("ASSERT:noted", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "n",  # Note action
            "This is a test note",  # Note text
            "q",  # Quit after noting
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Note saved", output)

        # Verify note was saved
        crash = self.registry.get_crash("ASSERT:noted")
        self.assertIn("test note", crash.get("notes", ""))

    def test_skip_action_moves_to_next(self):
        """Test skip action moves to next crash."""
        self.registry.add_sighting("ASSERT:skip1", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:skip2", "run1", "inst1", "2025-01-02")

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "s",  # Skip first
            "q",  # Quit on second
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Skipped", output)
        self.assertIn("[2/2]", output)

        # Verify first crash is still NEW
        crash = self.registry.get_crash("ASSERT:skip1")
        self.assertEqual(crash["triage_status"], "NEW")

    def test_quit_action_exits(self):
        """Test quit action exits the loop."""
        self.registry.add_sighting("ASSERT:quit", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        with patch("builtins.input", return_value="q"):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Exiting triage loop", output)

    def test_invalid_action_shows_error(self):
        """Test invalid action shows error and reprompts."""
        self.registry.add_sighting("ASSERT:invalid", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "x",  # Invalid action
            "q",  # Then quit
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Invalid action", output)

    def test_report_validates_issue_number(self):
        """Test report action validates issue number input."""
        self.registry.add_sighting("ASSERT:validate", "run1", "inst1", "2025-01-01")
        self.registry.record_issue({"issue_number": 222, "title": "Bug"})

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "r",  # Report action
            "",  # Empty (rejected)
            "abc",  # Invalid (rejected)
            "222",  # Valid
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Issue number is required", output)
        self.assertIn("Please enter a valid integer", output)
        self.assertIn("Linked to Issue #222", output)

    def test_completes_all_crashes(self):
        """Test completing triage for all crashes."""
        self.registry.add_sighting("ASSERT:first", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:second", "run1", "inst1", "2025-01-02")

        args = argparse.Namespace(db=self.db_path)

        user_inputs = [
            "i",  # Ignore first
            "i",  # Ignore second
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Triage session complete", output)

        # Verify both were triaged
        crash1 = self.registry.get_crash("ASSERT:first")
        crash2 = self.registry.get_crash("ASSERT:second")
        self.assertEqual(crash1["triage_status"], "IGNORED")
        self.assertEqual(crash2["triage_status"], "IGNORED")

    def test_handles_eof_on_action(self):
        """Test handling EOF on action input."""
        self.registry.add_sighting("ASSERT:eof", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        with patch("builtins.input", side_effect=EOFError):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("EOF received", output)

    def test_handles_keyboard_interrupt(self):
        """Test handling keyboard interrupt."""
        self.registry.add_sighting("ASSERT:interrupt", "run1", "inst1", "2025-01-01")

        args = argparse.Namespace(db=self.db_path)

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Interrupted", output)

    def test_shows_existing_notes(self):
        """Test that existing notes are displayed."""
        self.registry.add_sighting("ASSERT:noted", "run1", "inst1", "2025-01-01")
        self.registry.add_note("ASSERT:noted", "Previous note here")

        args = argparse.Namespace(db=self.db_path)

        with patch("builtins.input", return_value="q"):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_interactive_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Previous note here", output)


class TestRunReviewTriage(unittest.TestCase):
    """Tests for run_review_triage function."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crashes.db"
        self.registry = CrashRegistry(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_no_triaged_crashes_message(self):
        """Test message when no triaged crashes exist."""
        args = argparse.Namespace(db=self.db_path, status=None)

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("No triaged crashes to review", output)

    def test_no_crashes_with_status_message(self):
        """Test message when no crashes have specified status."""
        self.registry.add_sighting("ASSERT:test", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:test", "IGNORED")

        args = argparse.Namespace(db=self.db_path, status="REPORTED")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("No crashes with status 'REPORTED'", output)

    def test_link_action_links_issue(self):
        """Test link action links crash to issue."""
        self.registry.add_sighting("ASSERT:link", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:link", "TRIAGED")
        self.registry.record_issue({"issue_number": 333, "title": "Bug"})

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        user_inputs = [
            "l",  # Link action
            "333",  # Issue number
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Linked to Issue #333", output)

        # Verify link
        crash = self.registry.get_crash("ASSERT:link")
        self.assertEqual(crash["issue_number"], 333)

    def test_unlink_action_removes_link(self):
        """Test unlink action removes issue link."""
        self.registry.add_sighting("ASSERT:unlink", "run1", "inst1", "2025-01-01")
        self.registry.record_issue({"issue_number": 444, "title": "Bug"})
        self.registry.link_crash_to_issue("ASSERT:unlink", 444)

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        user_inputs = ["u"]  # Unlink action

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Unlinked from Issue #444", output)

        # Verify unlink
        crash = self.registry.get_crash("ASSERT:unlink")
        self.assertIsNone(crash["issue_number"])

    def test_unlink_when_not_linked(self):
        """Test unlink action when no issue is linked."""
        self.registry.add_sighting("ASSERT:notlinked", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:notlinked", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        user_inputs = [
            "u",  # Unlink action (but nothing to unlink)
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("No issue linked", output)

    def test_status_action_changes_status(self):
        """Test status action changes crash status."""
        self.registry.add_sighting("ASSERT:status", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:status", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        user_inputs = [
            "s",  # Status action
            "FIXED",  # New status
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Status changed to FIXED", output)

        # Verify status changed
        crash = self.registry.get_crash("ASSERT:status")
        self.assertEqual(crash["triage_status"], "FIXED")

    def test_status_action_invalid_status(self):
        """Test status action with invalid status."""
        self.registry.add_sighting("ASSERT:invalid", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:invalid", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        user_inputs = [
            "s",  # Status action
            "INVALID_STATUS",  # Invalid
            "s",  # Try again
            "FIXED",  # Valid
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Invalid status", output)
        self.assertIn("Status changed to FIXED", output)

    def test_note_action_saves_note(self):
        """Test note action saves note and continues."""
        self.registry.add_sighting("ASSERT:note", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:note", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        user_inputs = [
            "n",  # Note action
            "Review note",  # Note text
            "q",  # Quit
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Note saved", output)

        # Verify note
        crash = self.registry.get_crash("ASSERT:note")
        self.assertIn("Review note", crash.get("notes", ""))

    def test_keep_action_no_changes(self):
        """Test keep action makes no changes."""
        self.registry.add_sighting("ASSERT:keep", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:keep", "REPORTED")

        args = argparse.Namespace(db=self.db_path, status="REPORTED")

        user_inputs = ["k"]  # Keep action

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("No changes made", output)

    def test_quit_action_exits(self):
        """Test quit action exits the loop."""
        self.registry.add_sighting("ASSERT:quit", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:quit", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        with patch("builtins.input", return_value="q"):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Exiting review loop", output)

    def test_displays_linked_issue_info(self):
        """Test that linked issue info is displayed."""
        self.registry.add_sighting("ASSERT:linked", "run1", "inst1", "2025-01-01")
        self.registry.record_issue(
            {"issue_number": 555, "title": "Important Bug", "url": "https://example.com/555"}
        )
        self.registry.link_crash_to_issue("ASSERT:linked", 555)

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        with patch("builtins.input", return_value="q"):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("#555", output)
        self.assertIn("Important Bug", output)
        self.assertIn("https://example.com/555", output)

    def test_completes_all_reviews(self):
        """Test completing review for all crashes."""
        self.registry.add_sighting("ASSERT:review1", "run1", "inst1", "2025-01-01")
        self.registry.add_sighting("ASSERT:review2", "run1", "inst1", "2025-01-02")
        self.registry.set_triage_status("ASSERT:review1", "TRIAGED")
        self.registry.set_triage_status("ASSERT:review2", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        user_inputs = [
            "k",  # Keep first
            "k",  # Keep second
        ]

        with patch("builtins.input", side_effect=user_inputs):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Review session complete", output)

    def test_handles_eof(self):
        """Test handling EOF during review."""
        self.registry.add_sighting("ASSERT:eof", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:eof", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        with patch("builtins.input", side_effect=EOFError):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("EOF received", output)

    def test_handles_keyboard_interrupt(self):
        """Test handling keyboard interrupt during review."""
        self.registry.add_sighting("ASSERT:interrupt", "run1", "inst1", "2025-01-01")
        self.registry.set_triage_status("ASSERT:interrupt", "TRIAGED")

        args = argparse.Namespace(db=self.db_path, status="TRIAGED")

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            captured_output = StringIO()
            with patch("sys.stdout", captured_output):
                run_review_triage(args)

        output = captured_output.getvalue()
        self.assertIn("Interrupted", output)


if __name__ == "__main__":
    unittest.main()
