#!/usr/bin/env python3
"""
ARECON Security Hypothesis Prioritizer (core/prioritizer.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Maps all discovered attack-surface evidence into prioritized testing hypotheses
aligned with OWASP Web Security Testing Guide (WSTG).
"""

import urllib.parse
from typing import Any, Dict, List, Optional, Set


class SecurityHypothesisPrioritizer:
    @staticmethod
    def evaluate(
        endpoints: List[str],
        web_inventory: List[Dict[str, Any]],
        js_api_data: Optional[List[Dict[str, Any]]] = None,
        cloud_buckets: Optional[List[Dict[str, Any]]] = None,
        takeovers: Optional[List[Dict[str, Any]]] = None,
        active_findings: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, str]]:
        hypotheses = []

        # 1. Subdomain Takeover Vulnerabilities
        if takeovers:
            for t in takeovers:
                if t.get("vulnerable"):
                    hypotheses.append({
                        "priority": "CRITICAL",
                        "category": "Domain Hijacking (WSTG-CONF-06)",
                        "target": t.get("host", ""),
                        "hypothesis": f"Dangling CNAME points to claimable {t.get('service')}. Proof: {t.get('proof')}",
                    })

        # 2. Public Storage Exposure
        if cloud_buckets:
            for b in cloud_buckets:
                if b.get("exposure") == "PUBLIC_LISTING":
                    hypotheses.append({
                        "priority": "HIGH",
                        "category": "Cloud Storage (WSTG-CONF-CLOUD)",
                        "target": b.get("url", ""),
                        "hypothesis": f"Publicly listable {b.get('provider')} storage bucket discovered.",
                    })
                elif b.get("exposure") == "PUBLIC_ACCESSIBLE":
                    hypotheses.append({
                        "priority": "MEDIUM",
                        "category": "Cloud Storage (WSTG-CONF-CLOUD)",
                        "target": b.get("url", ""),
                        "hypothesis": f"Publicly accessible {b.get('provider')} storage bucket discovered.",
                    })

        # 3. JavaScript & API Discoveries
        if js_api_data:
            for js_item in js_api_data:
                # Source maps
                for sm in js_item.get("source_maps_exposed", []):
                    hypotheses.append({
                        "priority": "MEDIUM",
                        "category": "Information Disclosure (WSTG-INFO-05)",
                        "target": sm,
                        "hypothesis": "Exposed JavaScript Source Map (.js.map) exposes client-side source code and internal routes.",
                    })

                # Swagger / OpenAPI
                for spec in js_item.get("openapi_specs", []):
                    hypotheses.append({
                        "priority": "HIGH",
                        "category": "API Documentation (WSTG-INFO-06)",
                        "target": spec.get("spec_url", ""),
                        "hypothesis": f"Exposed OpenAPI/Swagger documentation discloses {len(spec.get('routes', []))} API routes and parameter models.",
                    })

                # GraphQL Introspection
                gql = js_item.get("graphql_endpoint")
                if gql:
                    if gql.get("introspection_enabled"):
                        hypotheses.append({
                            "priority": "HIGH",
                            "category": "API Security (WSTG-APIT-01)",
                            "target": gql.get("graphql_url", ""),
                            "hypothesis": "GraphQL endpoint with introspection enabled allows extraction of complete backend data schema.",
                        })
                    else:
                        hypotheses.append({
                            "priority": "MEDIUM",
                            "category": "API Security (WSTG-APIT-01)",
                            "target": gql.get("graphql_url", ""),
                            "hypothesis": "GraphQL endpoint detected. Test for unauthenticated queries and batching abuse.",
                        })

        # 4. Automatic Service & Software Version Findings
        for item in web_inventory:
            url = item.get("url", "")
            for vf in item.get("version_findings", []):
                if vf.get("type") == "OUTDATED_OR_EOL":
                    hypotheses.append({
                        "priority": vf.get("severity", "HIGH"),
                        "category": "Vulnerable/Outdated Components (WSTG-CONF-04)",
                        "target": url,
                        "hypothesis": vf.get("description", ""),
                    })
                elif vf.get("type") == "VERSION_DISCLOSURE":
                    hypotheses.append({
                        "priority": "LOW",
                        "category": "Version Disclosure (WSTG-INFO-02)",
                        "target": url,
                        "hypothesis": vf.get("description", ""),
                    })

        # 5. HTTP Headers and Configurations
        for item in web_inventory:
            url = item.get("url", "")
            sec = item.get("security_headers", {})
            if not sec.get("hsts") and url.startswith("https://"):
                hypotheses.append({
                    "priority": "LOW",
                    "category": "Configuration (WSTG-CONF-07)",
                    "target": url,
                    "hypothesis": "Missing HTTP Strict Transport Security (HSTS) header allows potential SSL stripping.",
                })
            if not sec.get("csp"):
                hypotheses.append({
                    "priority": "LOW",
                    "category": "Client-Side (WSTG-CLNT-09)",
                    "target": url,
                    "hypothesis": "Missing Content Security Policy (CSP) increases exploitability of injection flaws.",
                })
            if sec.get("cors_allow_origin") == "*":
                hypotheses.append({
                    "priority": "MEDIUM",
                    "category": "CORS (WSTG-CONF-11)",
                    "target": url,
                    "hypothesis": "Wildcard CORS origin (Access-Control-Allow-Origin: *) may expose authenticated responses.",
                })

        # 5. Endpoint Routes & Parameters
        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep)
            path = parsed.path.lower()
            query = parsed.query.lower()

            if any(term in path for term in ("/login", "/auth", "/oauth", "/sso", "/signin", "/register")):
                hypotheses.append({
                    "priority": "HIGH",
                    "category": "Authentication (WSTG-ATHN)",
                    "target": ep,
                    "hypothesis": "Authentication entry point: test credential stuffing resistance, password reset flows, and MFA bypass.",
                })
            elif any(term in path for term in ("/admin", "/manage", "/portal", "/dashboard", "/console")):
                hypotheses.append({
                    "priority": "HIGH",
                    "category": "Authorization (WSTG-ATHZ)",
                    "target": ep,
                    "hypothesis": "Privileged management portal: verify authorization enforcement and role privilege escalation.",
                })
            elif "/api/" in path:
                hypotheses.append({
                    "priority": "HIGH",
                    "category": "API Security (WSTG-APIT)",
                    "target": ep,
                    "hypothesis": "API route: test object identifiers for IDOR / Broken Object Level Authorization (BOLA).",
                })
            elif any(term in path for term in ("/upload", "/file", "/download", "/attachment")):
                hypotheses.append({
                    "priority": "MEDIUM",
                    "category": "Input Validation (WSTG-INPV-11)",
                    "target": ep,
                    "hypothesis": "File handling: test extension validation, path traversal, and unauthenticated upload execution.",
                })
            elif any(param in query for param in ("id=", "user=", "account=", "uid=", "doc=")):
                hypotheses.append({
                    "priority": "MEDIUM",
                    "category": "Authorization / IDOR (WSTG-ATHZ-04)",
                    "target": ep,
                    "hypothesis": "Parameterized request: test numeric and GUID identifiers for horizontal authorization bypass.",
                })

        # 6. Active Scan & Network Assessment Findings
        if active_findings:
            # Direct hypotheses passed from active scanner
            for h in active_findings.get("hypotheses", []):
                hypotheses.append(h)

            # TLS Audit findings
            for tls in active_findings.get("tls_findings", []):
                for v in tls.get("vulnerabilities", []):
                    hypotheses.append(v)

            # Error harvesting stack traces
            for err in active_findings.get("error_disclosures", []):
                if "hypothesis" in err:
                    hypotheses.append(err["hypothesis"])

            # Sensitive exposed database / management ports
            sensitive_ports = {
                21: ("FTP", "HIGH"),
                23: ("Telnet", "HIGH"),
                1433: ("MSSQL", "HIGH"),
                1521: ("Oracle DB", "HIGH"),
                3306: ("MySQL", "HIGH"),
                3389: ("RDP", "HIGH"),
                5432: ("PostgreSQL", "HIGH"),
                5900: ("VNC", "HIGH"),
                6379: ("Redis", "CRITICAL"),
                9200: ("Elasticsearch", "CRITICAL"),
                27017: ("MongoDB", "CRITICAL"),
            }
            for p in active_findings.get("open_ports", []):
                port_num = p.get("port")
                if port_num in sensitive_ports:
                    svc_name, prio = sensitive_ports[port_num]
                    hypotheses.append({
                        "priority": prio,
                        "category": "Exposed Database / Admin Service (WSTG-CONF-02)",
                        "target": f"{p.get('hostname')}:{port_num}",
                        "hypothesis": f"Directly exposed {svc_name} port without application boundary. Test for default credentials and unauthorized access.",
                    })

        # Deduplicate
        unique_hypo = []
        seen = set()
        for h in hypotheses:
            key = (h["category"], h["target"])
            if key not in seen:
                seen.add(key)
                unique_hypo.append(h)

        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(unique_hypo, key=lambda x: priority_order.get(x["priority"], 99))
