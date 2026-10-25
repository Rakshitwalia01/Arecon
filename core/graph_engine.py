#!/usr/bin/env python3
"""
ARECON Asset Relationship Graph Engine (core/graph_engine.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Constructs node-edge topologies connecting:
- Root Domains ➔ Subdomains ➔ IP Addresses
- Subdomains ➔ CDN/WAF & Cloud Providers
- Applications ➔ Tech Stacks ➔ APIs & Identity Workflows
Exports to:
- Structured JSON (nodes & links for UI graphs)
- Mermaid graph markup (for reports)
"""

import json
from typing import Any, Dict, List, Optional, Set, Tuple


class RelationshipGraph:
    def __init__(self, root_domain: str):
        self.root_domain = root_domain.lower().strip()
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._seen_edges: Set[Tuple[str, str, str]] = set()

        # Add root domain node
        self.add_node(self.root_domain, "RootDomain", {"label": self.root_domain})

    def add_node(self, node_id: str, node_type: str, metadata: Optional[Dict[str, Any]] = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": metadata.get("label", node_id) if metadata else node_id,
                "metadata": metadata or {},
            }

    def add_edge(self, source: str, target: str, relationship: str):
        edge_key = (source, target, relationship)
        if edge_key not in self._seen_edges:
            self._seen_edges.add(edge_key)
            self.edges.append({
                "source": source,
                "target": target,
                "relationship": relationship,
            })

    def build_from_scan_data(
        self,
        assets: List[Dict[str, Any]],
        web_inventory: List[Dict[str, Any]],
        js_api_data: List[Dict[str, Any]],
        cloud_buckets: List[Dict[str, Any]],
    ):
        # 1. Subdomains & IPs
        for asset in assets:
            host = asset.get("hostname")
            if not host:
                continue
            self.add_node(host, "Subdomain", {"label": host, "status": asset.get("status_code")})
            if host != self.root_domain:
                self.add_edge(self.root_domain, host, "HAS_SUBDOMAIN")

            # IPs
            ips = asset.get("ips")
            if isinstance(ips, str):
                try:
                    ips = json.loads(ips)
                except Exception:
                    ips = []
            if isinstance(ips, list):
                for ip in ips:
                    self.add_node(ip, "IPAddress", {"label": ip})
                    self.add_edge(host, ip, "RESOLVES_TO")

            # CNAME / Cloud Provider
            cname = asset.get("cname")
            if cname:
                self.add_node(cname, "CNAME", {"label": cname})
                self.add_edge(host, cname, "ALIASED_TO")

        # 2. Web Inventory & Tech Stack
        for item in web_inventory:
            url = item.get("url", "")
            if not url:
                continue
            host = item.get("host") or url.split("://")[-1].split("/")[0].split(":")[0]
            self.add_node(url, "WebApplication", {
                "label": item.get("title", url)[:25] or url,
                "status_code": item.get("status_code"),
            })
            self.add_edge(host, url, "SERVES_APP")

            # Tech stacks
            for tech in item.get("technologies", []):
                tech_node_id = f"tech:{tech}"
                self.add_node(tech_node_id, "Technology", {"label": tech})
                self.add_edge(url, tech_node_id, "RUNS_TECH")

            # WAF/CDN
            cdn = item.get("cdn_waf")
            if cdn:
                cdn_node_id = f"infra:{cdn}"
                self.add_node(cdn_node_id, "InfraProvider", {"label": cdn})
                self.add_edge(host, cdn_node_id, "PROTECTED_BY")

        # 3. APIs & Endpoints
        for js_item in js_api_data:
            base_url = js_item.get("base_url", "")
            for api_route in js_item.get("extracted_api_routes", [])[:10]:
                api_node_id = f"{base_url}{api_route}"
                self.add_node(api_node_id, "APIEndpoint", {"label": api_route})
                self.add_edge(base_url, api_node_id, "EXPOSES_ROUTE")

        # 4. Storage Buckets
        for b in cloud_buckets:
            b_url = b.get("url", "")
            if b_url:
                self.add_node(b_url, "CloudStorage", {"label": b_url, "provider": b.get("provider")})
                self.add_edge(self.root_domain, b_url, "USES_STORAGE")

    def to_json(self) -> Dict[str, Any]:
        return {
            "root_domain": self.root_domain,
            "nodes": list(self.nodes.values()),
            "links": self.edges,
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
            },
        }

    def to_mermaid(self, max_edges: int = 40) -> str:
        """Generates a clean Mermaid flowchart representation."""
        lines = ["```mermaid", "graph TD"]
        count = 0
        for edge in self.edges:
            if count >= max_edges:
                lines.append("    ...[\"+ More nodes and relations in JSON model\"]")
                break
            src = edge["source"].replace(".", "_").replace(":", "_").replace("/", "_").replace("-", "_")
            dst = edge["target"].replace(".", "_").replace(":", "_").replace("/", "_").replace("-", "_")
            rel = edge["relationship"]
            lines.append(f'    {src}["{edge["source"]}"] -->|{rel}| {dst}["{edge["target"]}"]')
            count += 1
        lines.append("```")
        return "\n".join(lines)
