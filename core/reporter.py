#!/usr/bin/env python3
"""
ARECON Comprehensive Reporting Engine (core/reporter.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Generates:
- Structured JSON database dump
- Markdown report with Mermaid architecture & relationship graphs
- Attack Surface Drift / Change audit
"""

import json
import time
from typing import Any, Dict, List, Optional


class ReconReporter:
    @staticmethod
    def generate_markdown(
        target_domain: str,
        candidates: List[Dict[str, Any]],
        dns_assets: List[Dict[str, Any]],
        web_inventory: List[Dict[str, Any]],
        endpoints: List[str],
        hypotheses: List[Dict[str, str]],
        drift_data: Optional[Dict[str, Any]],
        js_api_data: Optional[List[Dict[str, Any]]],
        cloud_buckets: Optional[List[Dict[str, Any]]],
        mermaid_graph: Optional[str],
        output_file: str,
        active_findings: Optional[Dict[str, Any]] = None,
        integrations: Optional[List[Dict[str, Any]]] = None,
    ):
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"# ARECON Attack Surface Intelligence Report: `{target_domain}`\n\n")
            f.write(f"**Author / Framework:** ARECON by Rakshit Walia  \n")
            f.write(f"**Execution Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  \n")
            f.write(f"**Methodology:** Advanced Continuous Bug Bounty Reconnaissance Architecture\n\n")

            # 1. Executive Summary
            f.write("## 1. Executive Summary\n\n")
            f.write(f"- **Candidate Hostnames (Multi-Source Passive):** {len(candidates)}\n")
            f.write(f"- **Live Resolved DNS Assets:** {len(dns_assets)}\n")
            f.write(f"- **Responsive Web Applications:** {len(web_inventory)}\n")
            f.write(f"- **Mapped Endpoints & Routes:** {len(endpoints)}\n")
            f.write(f"- **Prioritized Security Hypotheses (OWASP WSTG):** {len(hypotheses)}\n")
            if drift_data:
                f.write(f"- **Attack Surface Drift Events:** {drift_data.get('total_drift_events', 0)}\n")
            if cloud_buckets:
                f.write(f"- **Exposed Cloud Storage Buckets:** {len(cloud_buckets)}\n")
            if active_findings and active_findings.get("open_ports"):
                f.write(f"- **Open Network Ports & Services:** {len(active_findings.get('open_ports', []))}\n")
            if integrations:
                f.write(f"- **Third-Party Integrations Mapped:** {len(integrations)}\n")
            f.write("\n")

            # 2. Attack Surface Drift / Change Detection
            f.write("## 2. Attack Surface Drift & Change Detection\n\n")
            if drift_data and drift_data.get("has_drift"):
                changes = drift_data.get("changes_by_type", {})
                f.write("| Event Type | Target Asset | Details |\n")
                f.write("| :--- | :--- | :--- |\n")
                for c_type, entries in changes.items():
                    for entry in entries:
                        f.write(f"| `{c_type}` | `{entry['target']}` | {entry.get('new_value', '')} |\n")
                f.write("\n")
            else:
                f.write("ℹ️ *No attack surface drift observed compared to previous baseline scan.*\n\n")

            # 3. JavaScript & API Surface
            f.write("## 3. JavaScript & API Surface\n\n")
            if js_api_data:
                all_openapi = []
                all_graphql = []
                all_maps = []
                for j in js_api_data:
                    all_openapi.extend(j.get("openapi_specs", []))
                    if j.get("graphql_endpoint"):
                        all_graphql.append(j["graphql_endpoint"])
                    all_maps.extend(j.get("source_maps_exposed", []))

                if all_openapi:
                    f.write("### Exposed OpenAPI / Swagger Specifications\n")
                    for spec in all_openapi:
                        f.write(f"- **Spec URL:** [{spec['spec_url']}]({spec['spec_url']})  \n")
                        f.write(f"  *Title:* `{spec.get('title')}` (v{spec.get('version')}) — `{len(spec.get('routes', []))}` routes documented.\n")
                    f.write("\n")

                if all_graphql:
                    f.write("### GraphQL Endpoints\n")
                    for gql in all_graphql:
                        intro = "⚠️ **Introspection Open**" if gql.get("introspection_enabled") else "Introspection Restricted"
                        f.write(f"- **Endpoint:** `{gql['graphql_url']}` ({intro})\n")
                    f.write("\n")

                if all_maps:
                    f.write("### Exposed Source Maps (.js.map)\n")
                    for m in all_maps:
                        f.write(f"- `{m}`\n")
                    f.write("\n")
            else:
                f.write("*No client-side API schemas or source maps identified.*\n\n")

            # 4. Cloud & Infrastructure Exposure
            f.write("## 4. Cloud Storage & Infrastructure Exposure\n\n")
            if cloud_buckets:
                f.write("| Provider | Bucket URL | Exposure Level |\n")
                f.write("| :--- | :--- | :--- |\n")
                for b in cloud_buckets:
                    f.write(f"| {b['provider']} | [{b['url']}]({b['url']}) | `{b['exposure']}` |\n")
                f.write("\n")
            else:
                f.write("✅ *No publicly accessible cloud storage buckets found.*\n\n")

            # 5. Automated Service & Software Version Inventory
            f.write("## 5. Automated Service & Software Version Inventory\n\n")
            has_versions = False
            version_rows = []
            for item in web_inventory:
                url = item.get("url", "")
                sv = item.get("service_versions", {})
                vf = {f["service"]: f for f in item.get("version_findings", [])}
                for s_name, s_ver in sv.items():
                    if s_name == "OS":
                        continue
                    has_versions = True
                    flag = "✅ Supported"
                    if s_name in vf and vf[s_name].get("type") == "OUTDATED_OR_EOL":
                        flag = f"🚨 **Outdated/EOL ({vf[s_name].get('severity')})**"
                    elif s_ver and s_ver != "Detected":
                        flag = "ℹ️ Version Disclosed"
                    version_rows.append((url, s_name, s_ver, flag))

            if has_versions:
                f.write("| Web Asset | Software / Service | Detected Version | Security Posture |\n")
                f.write("| :--- | :--- | :--- | :--- |\n")
                for url, s_name, s_ver, flag in version_rows:
                    f.write(f"| [{url}]({url}) | **{s_name}** | `{s_ver}` | {flag} |\n")
                f.write("\n")
            else:
                f.write("ℹ️ *No specific software version numbers were disclosed across probed endpoints.*\n\n")

            # 6. Live Web Applications
            f.write("## 6. Live Web Applications & Technologies\n\n")
            f.write("| Status | URL | Title | Tech Stack | Security Headers |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- |\n")
            for item in web_inventory:
                tech = ", ".join(item.get("technologies", [])) or "Generic"
                sec = item.get("security_headers", {})
                sec_badges = []
                if sec.get("hsts"):
                    sec_badges.append("HSTS")
                if sec.get("csp"):
                    sec_badges.append("CSP")
                sec_str = " + ".join(sec_badges) if sec_badges else "None"
                f.write(
                    f"| `{item.get('status_code')}` | [{item.get('url')}]({item.get('url')}) | "
                    f"{item.get('title', '')[:30]} | {tech} | {sec_str} |\n"
                )
            f.write("\n")

            # 7. Active Network & Integrations Assessment
            has_active = bool((active_findings and (active_findings.get("open_ports") or active_findings.get("tls_findings"))) or integrations)
            if has_active:
                f.write("## 7. Active Network & Third-Party Integrations\n\n")
                if active_findings and active_findings.get("open_ports"):
                    f.write("### Open Ports & Network Services\n\n")
                    f.write("| Host / IP | Port | Protocol | Service / Version | Source |\n")
                    f.write("| :--- | :--- | :--- | :--- | :--- |\n")
                    for p in active_findings["open_ports"]:
                        f.write(f"| `{p.get('hostname')}` | `{p.get('port')}` | `{p.get('protocol', 'tcp')}` | **{p.get('service', 'unknown')}** ({p.get('version', '')}) | `{p.get('source')}` |\n")
                    f.write("\n")

                if integrations:
                    f.write("### Third-Party Script & API Integrations\n\n")
                    f.write("| Asset Hostname | Category | Integration Name | Matched Signature |\n")
                    f.write("| :--- | :--- | :--- | :--- |\n")
                    for itg in integrations:
                        f.write(f"| `{itg.get('asset_hostname') or itg.get('asset')}` | `{itg.get('category')}` | **{itg.get('integration_name') or itg.get('integration')}** | `{itg.get('indicator')}` |\n")
                    f.write("\n")

                if active_findings and active_findings.get("tls_findings"):
                    f.write("### TLS & Certificate Audits\n\n")
                    f.write("| Target Host | Protocol | Cipher Suite | Weak Protocols | Expiration |\n")
                    f.write("| :--- | :--- | :--- | :--- | :--- |\n")
                    for t in active_findings["tls_findings"]:
                        c_name = t.get("cipher", {}).get("name", "Unknown") if isinstance(t.get("cipher"), dict) else "Unknown"
                        weak_p = ", ".join(t.get("weak_protocols", [])) or "None"
                        exp = f"{t.get('days_until_expiration')} days" if t.get("days_until_expiration") is not None else "N/A"
                        f.write(f"| `{t.get('host')}:{t.get('port')}` | `{t.get('protocol_version')}` | `{c_name}` | `{weak_p}` | {exp} |\n")
                    f.write("\n")

            # 8. Prioritized Security Test Hypotheses
            f.write("## 8. Prioritized Security Hypotheses (OWASP WSTG)\n\n")
            f.write("| Priority | Category | Target Asset | Security Hypothesis |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for h in hypotheses:
                p_badge = f"**{h['priority']}**" if h["priority"] in ("CRITICAL", "HIGH") else h["priority"]
                f.write(f"| {p_badge} | {h['category']} | `{h['target']}` | {h['hypothesis']} |\n")
            f.write("\n")

            # 9. Asset Relationship Topology (Mermaid)
            if mermaid_graph:
                f.write("## 9. Asset Relationship Topology\n\n")
                f.write(mermaid_graph + "\n\n")
