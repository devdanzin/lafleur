"""
Crash registry for tracking crashes and linking them to GitHub issues.

This module provides a SQLite-based registry for storing crash fingerprints,
sightings across fuzzing runs, and links to reported GitHub issues.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class CrashRegistry:
    """
    SQLite-based crash registry for tracking crashes and their triage status.

    Manages three tables:
    - reported_issues: GitHub issues linked to crashes
    - crashes: Unique crash fingerprints and their triage status
    - sightings: Individual occurrences of crashes across runs
    """

    def __init__(self, db_path: str | Path = "crashes.db") -> None:
        """
        Initialize the crash registry.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create database tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Table for GitHub issues
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reported_issues (
                    issue_number INTEGER PRIMARY KEY,
                    title TEXT,
                    url TEXT,
                    reported_date TEXT,
                    reported_by TEXT,
                    description TEXT,
                    cpython_revision TEXT,
                    cpython_version TEXT,
                    build_info TEXT,
                    issue_status TEXT DEFAULT 'Open',
                    crash_status TEXT DEFAULT 'NEW',
                    linked_prs TEXT,
                    tested_oses TEXT,
                    labels TEXT
                )
            """)

            # Table for unique crash fingerprints
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS crashes (
                    fingerprint TEXT PRIMARY KEY,
                    issue_number INTEGER,
                    triage_status TEXT DEFAULT 'NEW',
                    first_seen_date TEXT,
                    notes TEXT,
                    FOREIGN KEY (issue_number) REFERENCES reported_issues(issue_number)
                )
            """)

            # Table for individual crash sightings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sightings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    run_id TEXT,
                    instance_name TEXT,
                    timestamp TEXT,
                    cpython_revision TEXT,
                    revision_date INTEGER,
                    FOREIGN KEY (fingerprint) REFERENCES crashes(fingerprint)
                )
            """)

            # Create index for faster sighting lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_sightings_fingerprint
                ON sightings(fingerprint)
            """)

            # Create unique index to prevent duplicate sightings
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_sightings_unique
                ON sightings(fingerprint, run_id, timestamp)
            """)

    def add_sighting(
        self,
        fingerprint: str,
        run_id: str,
        instance_name: str,
        timestamp: str,
        cpython_revision: str | None = None,
        revision_date: int | None = None,
    ) -> bool:
        """
        Record a crash sighting, creating the crash record if it doesn't exist.

        Args:
            fingerprint: Unique crash fingerprint.
            run_id: UUID of the fuzzing run.
            instance_name: Name of the fuzzing instance.
            timestamp: ISO8601 timestamp of the crash.
            cpython_revision: Git commit hash of CPython being tested.
            revision_date: Unix timestamp of the CPython revision.

        Returns:
            True if the sighting was added, False if it was a duplicate.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Ensure crash record exists
            cursor.execute(
                """
                INSERT OR IGNORE INTO crashes (fingerprint, first_seen_date, triage_status)
                VALUES (?, ?, 'NEW')
                """,
                (fingerprint, timestamp),
            )

            # Try to insert sighting (will fail silently on duplicate due to unique index)
            try:
                cursor.execute(
                    """
                    INSERT INTO sightings
                    (fingerprint, run_id, instance_name, timestamp, cpython_revision, revision_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fingerprint,
                        run_id,
                        instance_name,
                        timestamp,
                        cpython_revision,
                        revision_date,
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                # Duplicate sighting
                return False

    def get_crash(self, fingerprint: str) -> dict[str, Any] | None:
        """
        Get crash details including linked issue information.

        Args:
            fingerprint: The crash fingerprint to look up.

        Returns:
            Dictionary with crash details and linked issue, or None if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Get crash with optional issue join
            cursor.execute(
                """
                SELECT
                    c.fingerprint,
                    c.issue_number,
                    c.triage_status,
                    c.first_seen_date,
                    c.notes,
                    i.title AS issue_title,
                    i.url AS issue_url,
                    i.issue_status,
                    i.crash_status
                FROM crashes c
                LEFT JOIN reported_issues i ON c.issue_number = i.issue_number
                WHERE c.fingerprint = ?
                """,
                (fingerprint,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            result = dict(row)

            # Get sighting count and latest sighting
            cursor.execute(
                """
                SELECT COUNT(*) as count, MAX(timestamp) as latest
                FROM sightings WHERE fingerprint = ?
                """,
                (fingerprint,),
            )
            stats = cursor.fetchone()
            result["sighting_count"] = stats["count"]
            result["latest_sighting"] = stats["latest"]

            # Get unique instances that saw this crash
            cursor.execute(
                """
                SELECT DISTINCT instance_name FROM sightings WHERE fingerprint = ?
                """,
                (fingerprint,),
            )
            result["instances"] = [r["instance_name"] for r in cursor.fetchall()]

            return result

    def get_crash_context(self, fingerprint: str) -> dict[str, Any] | None:
        """
        Get crash context for report enrichment.

        Performs a lightweight query to get triage status and linked issue info
        for use in campaign reports.

        Args:
            fingerprint: The crash fingerprint to look up.

        Returns:
            Dictionary with triage_status, issue_number, issue_url, crash_status,
            and title. Returns None if fingerprint not found in registry.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    c.triage_status,
                    c.issue_number,
                    i.url AS issue_url,
                    i.crash_status,
                    i.title
                FROM crashes c
                LEFT JOIN reported_issues i ON c.issue_number = i.issue_number
                WHERE c.fingerprint = ?
                """,
                (fingerprint,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            return dict(row)

    def get_all_crashes(self, triage_status: str | None = None) -> list[dict[str, Any]]:
        """
        Get all crashes, optionally filtered by triage status.

        Args:
            triage_status: Optional filter (NEW, TRIAGED, IGNORED).

        Returns:
            List of crash dictionaries.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if triage_status:
                cursor.execute(
                    """
                    SELECT
                        c.fingerprint,
                        c.issue_number,
                        c.triage_status,
                        c.first_seen_date,
                        c.notes,
                        i.title AS issue_title,
                        i.issue_status,
                        COUNT(s.id) AS sighting_count
                    FROM crashes c
                    LEFT JOIN reported_issues i ON c.issue_number = i.issue_number
                    LEFT JOIN sightings s ON c.fingerprint = s.fingerprint
                    WHERE c.triage_status = ?
                    GROUP BY c.fingerprint
                    ORDER BY sighting_count DESC
                    """,
                    (triage_status,),
                )
            else:
                cursor.execute(
                    """
                    SELECT
                        c.fingerprint,
                        c.issue_number,
                        c.triage_status,
                        c.first_seen_date,
                        c.notes,
                        i.title AS issue_title,
                        i.issue_status,
                        COUNT(s.id) AS sighting_count
                    FROM crashes c
                    LEFT JOIN reported_issues i ON c.issue_number = i.issue_number
                    LEFT JOIN sightings s ON c.fingerprint = s.fingerprint
                    GROUP BY c.fingerprint
                    ORDER BY sighting_count DESC
                    """
                )

            return [dict(row) for row in cursor.fetchall()]

    def record_issue(self, data: dict[str, Any]) -> int:
        """
        Insert or update a reported GitHub issue.

        Args:
            data: Dictionary with issue fields. Must include 'issue_number'.

        Returns:
            The issue number.
        """
        issue_number = data["issue_number"]

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if issue exists
            cursor.execute(
                "SELECT issue_number FROM reported_issues WHERE issue_number = ?",
                (issue_number,),
            )
            exists = cursor.fetchone() is not None

            if exists:
                # Update existing issue
                fields = []
                values = []
                for key, value in data.items():
                    if key != "issue_number" and value is not None:
                        fields.append(f"{key} = ?")
                        values.append(value)

                if fields:
                    values.append(issue_number)
                    cursor.execute(
                        f"UPDATE reported_issues SET {', '.join(fields)} WHERE issue_number = ?",
                        values,
                    )
            else:
                # Insert new issue
                columns = list(data.keys())
                placeholders = ", ".join(["?"] * len(columns))
                cursor.execute(
                    f"INSERT INTO reported_issues ({', '.join(columns)}) VALUES ({placeholders})",
                    list(data.values()),
                )

        return issue_number

    def link_crash_to_issue(self, fingerprint: str, issue_number: int) -> bool:
        """
        Link a crash fingerprint to a GitHub issue.

        Args:
            fingerprint: The crash fingerprint.
            issue_number: The GitHub issue number.

        Returns:
            True if the link was created, False if crash doesn't exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE crashes
                SET issue_number = ?, triage_status = 'TRIAGED'
                WHERE fingerprint = ?
                """,
                (issue_number, fingerprint),
            )

            return cursor.rowcount > 0

    def set_triage_status(self, fingerprint: str, status: str) -> bool:
        """
        Update the triage status of a crash.

        Args:
            fingerprint: The crash fingerprint.
            status: New status (NEW, TRIAGED, IGNORED).

        Returns:
            True if updated, False if crash doesn't exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE crashes SET triage_status = ? WHERE fingerprint = ?",
                (status, fingerprint),
            )

            return cursor.rowcount > 0

    def add_note(self, fingerprint: str, note: str) -> bool:
        """
        Add or update notes for a crash.

        Args:
            fingerprint: The crash fingerprint.
            note: Note text to add.

        Returns:
            True if updated, False if crash doesn't exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE crashes SET notes = ? WHERE fingerprint = ?",
                (note, fingerprint),
            )

            return cursor.rowcount > 0

    def get_new_crashes(self) -> list[dict[str, Any]]:
        """
        Get all crashes with NEW triage status.

        Returns:
            List of crash dictionaries ordered by first_seen_date.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM crashes
                WHERE triage_status = 'NEW'
                ORDER BY first_seen_date ASC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_triaged_crashes(self, status: str | None = None) -> list[dict[str, Any]]:
        """
        Get crashes that have been triaged (non-NEW status).

        Args:
            status: Optional specific status to filter by (TRIAGED, REPORTED, IGNORED, FIXED).
                    If None, returns all non-NEW crashes.

        Returns:
            List of crash dictionaries with linked issue info, ordered by first_seen_date.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if status:
                cursor.execute(
                    """
                    SELECT
                        c.fingerprint,
                        c.issue_number,
                        c.triage_status,
                        c.first_seen_date,
                        c.notes,
                        i.title AS issue_title,
                        i.url AS issue_url,
                        i.issue_status
                    FROM crashes c
                    LEFT JOIN reported_issues i ON c.issue_number = i.issue_number
                    WHERE c.triage_status = ?
                    ORDER BY c.first_seen_date ASC
                    """,
                    (status,),
                )
            else:
                cursor.execute(
                    """
                    SELECT
                        c.fingerprint,
                        c.issue_number,
                        c.triage_status,
                        c.first_seen_date,
                        c.notes,
                        i.title AS issue_title,
                        i.url AS issue_url,
                        i.issue_status
                    FROM crashes c
                    LEFT JOIN reported_issues i ON c.issue_number = i.issue_number
                    WHERE c.triage_status != 'NEW'
                    ORDER BY c.first_seen_date ASC
                    """
                )

            return [dict(row) for row in cursor.fetchall()]

    def unlink_crash_from_issue(self, fingerprint: str) -> bool:
        """
        Unlink a crash from its associated issue.

        Args:
            fingerprint: The crash fingerprint.

        Returns:
            True if unlinked, False if crash doesn't exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE crashes
                SET issue_number = NULL
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            )

            return cursor.rowcount > 0

    def get_sighting_count(self, fingerprint: str) -> int:
        """
        Get the number of sightings for a crash.

        Args:
            fingerprint: The crash fingerprint.

        Returns:
            Number of sightings.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM sightings WHERE fingerprint = ?",
                (fingerprint,),
            )
            return cursor.fetchone()[0]

    def get_stats(self) -> dict[str, Any]:
        """
        Get summary statistics about the registry.

        Returns:
            Dictionary with counts and status breakdowns.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            stats: dict[str, Any] = {}

            # Total crashes
            cursor.execute("SELECT COUNT(*) FROM crashes")
            stats["total_crashes"] = cursor.fetchone()[0]

            # Total sightings
            cursor.execute("SELECT COUNT(*) FROM sightings")
            stats["total_sightings"] = cursor.fetchone()[0]

            # Total issues
            cursor.execute("SELECT COUNT(*) FROM reported_issues")
            stats["total_issues"] = cursor.fetchone()[0]

            # Crashes by triage status
            cursor.execute(
                """
                SELECT triage_status, COUNT(*) as count
                FROM crashes GROUP BY triage_status
                """
            )
            stats["by_triage_status"] = {row["triage_status"]: row["count"] for row in cursor}

            # Crashes linked to issues
            cursor.execute("SELECT COUNT(*) FROM crashes WHERE issue_number IS NOT NULL")
            stats["linked_to_issues"] = cursor.fetchone()[0]

            # Unique instances
            cursor.execute("SELECT COUNT(DISTINCT instance_name) FROM sightings")
            stats["unique_instances"] = cursor.fetchone()[0]

            # Unique run IDs
            cursor.execute("SELECT COUNT(DISTINCT run_id) FROM sightings")
            stats["unique_runs"] = cursor.fetchone()[0]

            return stats

    def get_sightings(self, fingerprint: str, limit: int | None = None) -> list[dict[str, Any]]:
        """
        Get sightings for a specific crash.

        Args:
            fingerprint: The crash fingerprint.
            limit: Maximum number of sightings to return.

        Returns:
            List of sighting dictionaries.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT * FROM sightings
                WHERE fingerprint = ?
                ORDER BY timestamp DESC
            """
            if limit:
                query += f" LIMIT {limit}"

            cursor.execute(query, (fingerprint,))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_reported_issues(self) -> list[dict[str, Any]]:
        """
        Get all reported issues from the registry.

        Returns:
            List of dictionaries with issue data (keys matching column names).
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reported_issues ORDER BY issue_number")
            return [dict(row) for row in cursor.fetchall()]

    def upsert_reported_issues(self, issues: list[dict[str, Any]]) -> int:
        """
        Insert or update multiple reported issues atomically.

        Args:
            issues: List of dictionaries with issue data.
                    Each dict must include 'issue_number'.

        Returns:
            Count of records processed.
        """
        if not issues:
            return 0

        # Define the column order for consistency
        columns = [
            "issue_number",
            "title",
            "url",
            "reported_date",
            "reported_by",
            "description",
            "cpython_revision",
            "cpython_version",
            "build_info",
            "issue_status",
            "crash_status",
            "linked_prs",
            "tested_oses",
            "labels",
        ]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            count = 0

            for issue in issues:
                if "issue_number" not in issue:
                    continue

                # Build values list, using None for missing keys
                values = [issue.get(col) for col in columns]

                placeholders = ", ".join(["?"] * len(columns))

                # Use ON CONFLICT to preserve existing data for omitted fields.
                # COALESCE(excluded.col, col) means: use the new value if
                # non-NULL, otherwise keep the existing value.
                update_cols = [c for c in columns if c != "issue_number"]
                update_clause = ", ".join(f"{c} = COALESCE(excluded.{c}, {c})" for c in update_cols)

                cursor.execute(
                    f"INSERT INTO reported_issues ({', '.join(columns)}) "
                    f"VALUES ({placeholders}) "
                    f"ON CONFLICT(issue_number) DO UPDATE SET {update_clause}",
                    values,
                )
                count += 1

            return count
