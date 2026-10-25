#!/usr/bin/env python3
"""
ARECON Change Detection & Attack Surface Drift Engine (core/change_detector.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Tracks evolution of target infrastructure across scans:
- New subdomains
- IP address mutations
- Status code shifts
- Newly exposed API routes & source maps
"""

from typing import Any, Dict, List
from core.db import ReconDB


class ChangeDetector:
    def __init__(self, db: ReconDB):
        self.db = db

    def get_drift_summary(self, root_domain: str, scan_id: int) -> Dict[str, Any]:
        """Collects all changes logged during a specific scan run."""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT change_type, target, old_value, new_value, created_at
                FROM changes
                WHERE root_domain = ? AND scan_id = ?
                ORDER BY id ASC
                """,
                (root_domain.lower().strip(), scan_id),
            )
            rows = cursor.fetchall()

        categorized: Dict[str, List[Dict[str, Any]]] = {
            "NEW_SUBDOMAIN": [],
            "IP_CHANGE": [],
            "STATUS_CHANGE": [],
            "NEW_ENDPOINT": [],
            "DISCLOSED_SOURCEMAP": [],
            "NEW_CLOUD_BUCKET": [],
        }

        for r in rows:
            entry = dict(r)
            c_type = entry.get("change_type", "OTHER")
            if c_type in categorized:
                categorized[c_type].append(entry)
            else:
                categorized.setdefault(c_type, []).append(entry)

        total_changes = len(rows)
        return {
            "root_domain": root_domain,
            "scan_id": scan_id,
            "total_drift_events": total_changes,
            "has_drift": total_changes > 0,
            "changes_by_type": categorized,
        }
