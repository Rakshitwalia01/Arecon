#!/usr/bin/env python3
"""
ARECON Database Module (core/db.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Normalized SQLite asset store for continuous attack-surface intelligence,
historical change tracking, confidence scoring, and relationship mapping.
"""

import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple


class ReconDB:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "arecon.db")
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scans history
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_domain TEXT NOT NULL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                total_candidates INTEGER DEFAULT 0,
                live_hosts INTEGER DEFAULT 0,
                live_services INTEGER DEFAULT 0,
                endpoints_count INTEGER DEFAULT 0,
                new_assets_count INTEGER DEFAULT 0
            )
            """)

            # Normalized assets table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_domain TEXT NOT NULL,
                hostname TEXT NOT NULL UNIQUE,
                ips TEXT,
                cname TEXT,
                is_wildcard INTEGER DEFAULT 0,
                status_code INTEGER,
                title TEXT,
                technologies TEXT,
                service_versions TEXT,
                cdn_waf TEXT,
                security_headers TEXT,
                takeover_risk TEXT,
                confidence_score REAL DEFAULT 1.0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # Safe column migration if table already existed
            try:
                cursor.execute("ALTER TABLE assets ADD COLUMN service_versions TEXT")
            except Exception:
                pass

            try:
                cursor.execute("ALTER TABLE assets ADD COLUMN open_ports TEXT")
            except Exception:
                pass

            # Endpoints and APIs
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_domain TEXT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                path TEXT,
                endpoint_type TEXT,
                parameters TEXT,
                source_map_exposed INTEGER DEFAULT 0,
                discovery_source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # Historical attack surface drift / changes
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                root_domain TEXT NOT NULL,
                change_type TEXT NOT NULL,
                target TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # Asset Relationship Graph
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_domain TEXT NOT NULL,
                source_node TEXT NOT NULL,
                source_type TEXT NOT NULL,
                target_node TEXT NOT NULL,
                target_type TEXT NOT NULL,
                relationship TEXT NOT NULL,
                UNIQUE(root_domain, source_node, target_node, relationship)
            )
            """)

            # Third-Party Integrations
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS integrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_domain TEXT NOT NULL,
                asset_hostname TEXT NOT NULL,
                integration_name TEXT NOT NULL,
                category TEXT NOT NULL,
                indicator TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(root_domain, asset_hostname, integration_name)
            )
            """)

            # Open Ports and Services
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_domain TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ip TEXT,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                service_name TEXT,
                version TEXT,
                confidence REAL DEFAULT 1.0,
                source TEXT DEFAULT 'nmap',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(root_domain, hostname, port, protocol)
            )
            """)

            conn.commit()

    def start_scan(self, target_domain: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scans (target_domain, started_at) VALUES (?, CURRENT_TIMESTAMP)",
                (target_domain.lower().strip(),),
            )
            conn.commit()
            return cursor.lastrowid

    def finish_scan(
        self,
        scan_id: int,
        candidates: int,
        live_hosts: int,
        live_services: int,
        endpoints: int,
        new_assets: int,
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scans 
                SET completed_at = CURRENT_TIMESTAMP,
                    total_candidates = ?,
                    live_hosts = ?,
                    live_services = ?,
                    endpoints_count = ?,
                    new_assets_count = ?
                WHERE id = ?
                """,
                (candidates, live_hosts, live_services, endpoints, new_assets, scan_id),
            )
            conn.commit()

    def record_asset(
        self,
        scan_id: int,
        root_domain: str,
        hostname: str,
        ips: List[str],
        cname: Optional[str] = None,
        is_wildcard: bool = False,
        status_code: Optional[int] = None,
        title: Optional[str] = None,
        technologies: Optional[List[str]] = None,
        service_versions: Optional[Dict[str, str]] = None,
        cdn_waf: Optional[str] = None,
        security_headers: Optional[Dict[str, Any]] = None,
        takeover_risk: Optional[str] = None,
        confidence_score: float = 1.0,
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Records or updates an asset, detecting and logging any changes (IPs, Status, Versions, CNAME).
        Returns (is_new, changes_detected).
        """
        hostname = hostname.lower().strip()
        root_domain = root_domain.lower().strip()
        ips_json = json.dumps(sorted(ips)) if ips else "[]"
        tech_json = json.dumps(sorted(technologies)) if technologies else "[]"
        vers_json = json.dumps(service_versions) if service_versions else "{}"
        sec_json = json.dumps(security_headers) if security_headers else "{}"
        changes = []
        is_new = False

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets WHERE hostname = ?", (hostname,))
            existing = cursor.fetchone()

            if existing is None:
                is_new = True
                cursor.execute(
                    """
                    INSERT INTO assets (
                        root_domain, hostname, ips, cname, is_wildcard, status_code,
                        title, technologies, service_versions, cdn_waf, security_headers, takeover_risk,
                        confidence_score, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (
                        root_domain,
                        hostname,
                        ips_json,
                        cname,
                        1 if is_wildcard else 0,
                        status_code,
                        title,
                        tech_json,
                        vers_json,
                        cdn_waf,
                        sec_json,
                        takeover_risk,
                        confidence_score,
                    ),
                )
                # Log NEW_SUBDOMAIN change
                ch = {
                    "scan_id": scan_id,
                    "root_domain": root_domain,
                    "change_type": "NEW_SUBDOMAIN",
                    "target": hostname,
                    "old_value": None,
                    "new_value": f"IPs: {ips_json}, Status: {status_code}",
                }
                changes.append(ch)
                cursor.execute(
                    """
                    INSERT INTO changes (scan_id, root_domain, change_type, target, old_value, new_value)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, root_domain, ch["change_type"], ch["target"], ch["old_value"], ch["new_value"]),
                )
            else:
                # Check for IP change
                old_ips = existing["ips"]
                if old_ips and old_ips != ips_json:
                    ch = {
                        "scan_id": scan_id,
                        "root_domain": root_domain,
                        "change_type": "IP_CHANGE",
                        "target": hostname,
                        "old_value": old_ips,
                        "new_value": ips_json,
                    }
                    changes.append(ch)
                    cursor.execute(
                        "INSERT INTO changes (scan_id, root_domain, change_type, target, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?)",
                        (scan_id, root_domain, ch["change_type"], ch["target"], ch["old_value"], ch["new_value"]),
                    )

                # Check for Status code change
                old_status = existing["status_code"]
                if status_code is not None and old_status != status_code:
                    ch = {
                        "scan_id": scan_id,
                        "root_domain": root_domain,
                        "change_type": "STATUS_CHANGE",
                        "target": hostname,
                        "old_value": str(old_status),
                        "new_value": str(status_code),
                    }
                    changes.append(ch)
                    cursor.execute(
                        "INSERT INTO changes (scan_id, root_domain, change_type, target, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?)",
                        (scan_id, root_domain, ch["change_type"], ch["target"], ch["old_value"], ch["new_value"]),
                    )

                # Check for Service Version change
                try:
                    old_vers = existing["service_versions"] or "{}"
                    if vers_json != "{}" and old_vers != "{}" and old_vers != vers_json:
                        ch = {
                            "scan_id": scan_id,
                            "root_domain": root_domain,
                            "change_type": "VERSION_CHANGE",
                            "target": hostname,
                            "old_value": old_vers,
                            "new_value": vers_json,
                        }
                        changes.append(ch)
                        cursor.execute(
                            "INSERT INTO changes (scan_id, root_domain, change_type, target, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?)",
                            (scan_id, root_domain, ch["change_type"], ch["target"], ch["old_value"], ch["new_value"]),
                        )
                except Exception:
                    pass

                # Update existing record
                cursor.execute(
                    """
                    UPDATE assets SET
                        ips = COALESCE(?, ips),
                        cname = COALESCE(?, cname),
                        is_wildcard = ?,
                        status_code = COALESCE(?, status_code),
                        title = COALESCE(?, title),
                        technologies = COALESCE(?, technologies),
                        service_versions = COALESCE(?, service_versions),
                        cdn_waf = COALESCE(?, cdn_waf),
                        security_headers = COALESCE(?, security_headers),
                        takeover_risk = COALESCE(?, takeover_risk),
                        confidence_score = ?,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE hostname = ?
                    """,
                    (
                        ips_json if ips else None,
                        cname,
                        1 if is_wildcard else 0,
                        status_code,
                        title,
                        tech_json if technologies else None,
                        vers_json if service_versions else None,
                        cdn_waf,
                        sec_json if security_headers else None,
                        takeover_risk,
                        confidence_score,
                        hostname,
                    ),
                )
            conn.commit()

        return is_new, changes

    def record_endpoint(
        self,
        scan_id: int,
        root_domain: str,
        url: str,
        path: str,
        endpoint_type: str = "Generic",
        parameters: Optional[List[str]] = None,
        source_map_exposed: bool = False,
        discovery_source: str = "Spider",
    ) -> bool:
        root_domain = root_domain.lower().strip()
        params_json = json.dumps(sorted(parameters)) if parameters else "[]"
        is_new = False

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM endpoints WHERE url = ?", (url,))
            existing = cursor.fetchone()

            if existing is None:
                is_new = True
                cursor.execute(
                    """
                    INSERT INTO endpoints (
                        root_domain, url, path, endpoint_type, parameters,
                        source_map_exposed, discovery_source, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (
                        root_domain,
                        url,
                        path,
                        endpoint_type,
                        params_json,
                        1 if source_map_exposed else 0,
                        discovery_source,
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO changes (scan_id, root_domain, change_type, target, old_value, new_value)
                    VALUES (?, ?, 'NEW_ENDPOINT', ?, NULL, ?)
                    """,
                    (scan_id, root_domain, url, f"Type: {endpoint_type}, Params: {params_json}"),
                )
            else:
                cursor.execute(
                    """
                    UPDATE endpoints SET
                        endpoint_type = ?,
                        parameters = ?,
                        source_map_exposed = ?,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE url = ?
                    """,
                    (endpoint_type, params_json, 1 if source_map_exposed else 0, url),
                )
            conn.commit()

        return is_new

    def record_relationship(
        self,
        root_domain: str,
        source_node: str,
        source_type: str,
        target_node: str,
        target_type: str,
        relationship: str,
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO relationships (
                    root_domain, source_node, source_type, target_node, target_type, relationship
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (root_domain.lower().strip(), source_node, source_type, target_node, target_type, relationship),
            )
            conn.commit()

    def get_assets(self, root_domain: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM assets WHERE root_domain = ? ORDER BY hostname ASC",
                (root_domain.lower().strip(),),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_endpoints(self, root_domain: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM endpoints WHERE root_domain = ? ORDER BY id DESC",
                (root_domain.lower().strip(),),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_recent_changes(self, root_domain: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM changes 
                WHERE root_domain = ? 
                ORDER BY id DESC 
                LIMIT ?
                """,
                (root_domain.lower().strip(), limit),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_relationships(self, root_domain: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM relationships WHERE root_domain = ?",
                (root_domain.lower().strip(),),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def record_integration(
        self,
        root_domain: str,
        asset_hostname: str,
        integration_name: str,
        category: str,
        indicator: Optional[str] = None,
    ) -> bool:
        """Records a detected third-party integration (e.g. Stripe, GA, Sentry)."""
        root_domain = root_domain.lower().strip()
        asset_hostname = asset_hostname.lower().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO integrations (
                    root_domain, asset_hostname, integration_name, category, indicator
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (root_domain, asset_hostname, integration_name, category, indicator),
            )
            inserted = cursor.rowcount > 0
            conn.commit()
            return inserted

    def get_integrations(self, root_domain: str, asset_hostname: Optional[str] = None) -> List[Dict[str, Any]]:
        root_domain = root_domain.lower().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if asset_hostname:
                cursor.execute(
                    "SELECT * FROM integrations WHERE root_domain = ? AND asset_hostname = ? ORDER BY category, integration_name",
                    (root_domain, asset_hostname.lower().strip()),
                )
            else:
                cursor.execute(
                    "SELECT * FROM integrations WHERE root_domain = ? ORDER BY category, integration_name",
                    (root_domain,),
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def record_open_port(
        self,
        root_domain: str,
        hostname: str,
        ip: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "",
        version: str = "",
        confidence: float = 1.0,
        source: str = "nmap",
    ) -> bool:
        """Records an open port/service and syncs the port number into assets.open_ports."""
        root_domain = root_domain.lower().strip()
        hostname = hostname.lower().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO open_ports (
                    root_domain, hostname, ip, port, protocol, service_name, version, confidence, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (root_domain, hostname, ip, port, protocol.lower(), service_name, version, confidence, source),
            )
            inserted = cursor.rowcount > 0

            # Update asset record's open_ports JSON array
            cursor.execute("SELECT port, protocol, service_name FROM open_ports WHERE hostname = ?", (hostname,))
            all_ports = [{"port": r["port"], "protocol": r["protocol"], "service": r["service_name"]} for r in cursor.fetchall()]
            cursor.execute(
                "UPDATE assets SET open_ports = ? WHERE hostname = ?",
                (json.dumps(all_ports), hostname),
            )
            conn.commit()
            return inserted

    def get_open_ports(self, root_domain: str, hostname: Optional[str] = None) -> List[Dict[str, Any]]:
        root_domain = root_domain.lower().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if hostname:
                cursor.execute(
                    "SELECT * FROM open_ports WHERE root_domain = ? AND hostname = ? ORDER BY port ASC",
                    (root_domain, hostname.lower().strip()),
                )
            else:
                cursor.execute(
                    "SELECT * FROM open_ports WHERE root_domain = ? ORDER BY hostname ASC, port ASC",
                    (root_domain,),
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
