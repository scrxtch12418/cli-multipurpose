"""
Scan History & Differential Change Tracking via SQLite.
Persists normalized scan metadata and findings for historical tracking,
delta comparisons (new vs fixed findings), and audit compliance.
"""

import json
import os
import sqlite3
from typing import List, Dict, Any, Optional

from core.models import AggregatedScanReport, Finding, Severity, Confidence


DEFAULT_DB_PATH = "scan_history.db"


class HistoryStore:
    """Manages scan history persistence and comparisons in SQLite."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                scope_name TEXT,
                start_time TEXT NOT NULL,
                end_time TEXT,
                total_findings INTEGER NOT NULL,
                modules_count INTEGER NOT NULL,
                severity_summary_json TEXT NOT NULL
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                affected_asset TEXT NOT NULL,
                remediation TEXT NOT NULL,
                PRIMARY KEY (id, scan_id),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            )
            """)
            conn.commit()
        finally:
            conn.close()

    def save_scan(self, report: AggregatedScanReport):
        """Saves a completed scan run and its unique findings."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, target, profile, scope_name, start_time, end_time,
                total_findings, modules_count, severity_summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.scan_id,
                report.target,
                report.profile,
                report.scope_name,
                report.start_time,
                report.end_time,
                len(report.all_findings),
                len(report.results),
                json.dumps(report.severity_summary)
            ))

            for f in report.all_findings:
                cursor.execute("""
                INSERT OR REPLACE INTO findings (
                    id, scan_id, check_id, title, severity, confidence,
                    affected_asset, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.id,
                    report.scan_id,
                    f.check_id,
                    f.title,
                    f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                    f.confidence.value if isinstance(f.confidence, Confidence) else str(f.confidence),
                    f.affected_asset,
                    f.remediation
                ))
            conn.commit()
        finally:
            conn.close()

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Lists recent scan summaries."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT scan_id, target, profile, start_time, total_findings, severity_summary_json
            FROM scans ORDER BY start_time DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "scan_id": r["scan_id"],
                    "target": r["target"],
                    "profile": r["profile"],
                    "start_time": r["start_time"],
                    "total_findings": r["total_findings"],
                    "severity_summary": json.loads(r["severity_summary_json"])
                })
            return results
        finally:
            conn.close()

    def get_findings_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieves all findings recorded for a specific scan."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, check_id, title, severity, confidence, affected_asset, remediation
            FROM findings WHERE scan_id = ?
            """, (scan_id,))
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def compare_scans(self, scan_id_old: str, scan_id_new: str) -> Dict[str, Any]:
        """
        Calculates diff between two scans:
        - new_findings: introduced in newer scan
        - fixed_findings: resolved in newer scan
        - persisting_findings: still present
        """
        old_findings = {f["id"]: f for f in self.get_findings_for_scan(scan_id_old)}
        new_findings = {f["id"]: f for f in self.get_findings_for_scan(scan_id_new)}

        old_ids = set(old_findings.keys())
        new_ids = set(new_findings.keys())

        introduced = [new_findings[fid] for fid in (new_ids - old_ids)]
        resolved = [old_findings[fid] for fid in (old_ids - new_ids)]
        persisting = [new_findings[fid] for fid in (old_ids & new_ids)]

        return {
            "scan_id_old": scan_id_old,
            "scan_id_new": scan_id_new,
            "introduced_count": len(introduced),
            "resolved_count": len(resolved),
            "persisting_count": len(persisting),
            "introduced_findings": introduced,
            "resolved_findings": resolved,
            "persisting_findings": persisting,
        }

    def clear_history(self):
        """Clears all historical scan records."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM findings")
            cursor.execute("DELETE FROM scans")
            conn.commit()
        finally:
            conn.close()


# Default singleton instance
history_store = HistoryStore()
