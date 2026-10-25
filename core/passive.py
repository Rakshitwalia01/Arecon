#!/usr/bin/env python3
"""
ARECON Multi-Source Passive Subdomain Discovery (core/passive.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Queries independent public intelligence feeds without touching target infrastructure:
- Certificate Transparency logs (crt.sh)
- HackerTarget API
- AlienVault OTX Passive DNS
- Anubis DB
- URLScan.io public index
Applies multi-source correlation and confidence scoring.
"""

import concurrent.futures
import json
import ssl
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Set, Tuple
from core.scope import ScopeFilter

USER_AGENT = "Mozilla/5.0 (compatible; ARECON-PassiveDiscovery/2.0; +https://authorized-bugbounty.org)"


class PassiveDiscovery:
    def __init__(self, target_domain: str, scope: ScopeFilter, timeout: int = 10):
        self.target_domain = target_domain.lower().strip()
        self.scope = scope
        self.timeout = timeout

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _fetch_url(self, url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8", errors="ignore")
        return ""

    def query_crt_sh(self) -> Set[str]:
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{self.target_domain}&output=json"
        try:
            content = self._fetch_url(url)
            if content:
                data = json.loads(content)
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if self.scope.is_in_scope(name):
                            subdomains.add(name)
        except Exception:
            pass
        return subdomains

    def query_hackertarget(self) -> Set[str]:
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.target_domain}"
        try:
            content = self._fetch_url(url)
            for line in content.splitlines():
                parts = line.strip().split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if self.scope.is_in_scope(sub):
                        subdomains.add(sub)
        except Exception:
            pass
        return subdomains

    def query_alienvault_otx(self) -> Set[str]:
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target_domain}/passive_dns"
        try:
            content = self._fetch_url(url)
            if content:
                data = json.loads(content)
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if self.scope.is_in_scope(hostname):
                        subdomains.add(hostname)
        except Exception:
            pass
        return subdomains

    def query_anubis(self) -> Set[str]:
        subdomains = set()
        url = f"https://jldc.me/anubis/subdomains/{self.target_domain}"
        try:
            content = self._fetch_url(url)
            if content:
                data = json.loads(content)
                if isinstance(data, list):
                    for sub in data:
                        sub = str(sub).strip().lower()
                        if self.scope.is_in_scope(sub):
                            subdomains.add(sub)
        except Exception:
            pass
        return subdomains

    def run(self) -> List[Dict[str, Any]]:
        """
        Executes multi-source queries, aggregates observations,
        and computes confidence scores based on source consensus.
        """
        source_observations: Dict[str, Set[str]] = {}

        tasks = {
            "crt.sh": self.query_crt_sh,
            "HackerTarget": self.query_hackertarget,
            "AlienVault": self.query_alienvault_otx,
            "Anubis": self.query_anubis,
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_src = {executor.submit(func): src for src, func in tasks.items()}
            for future in concurrent.futures.as_completed(future_to_src):
                src = future_to_src[future]
                try:
                    found = future.result()
                    for host in found:
                        source_observations.setdefault(host, set()).add(src)
                except Exception:
                    pass

        # Always include root domain
        source_observations.setdefault(self.target_domain, set()).add("TargetScope")

        results = []
        for host, sources in source_observations.items():
            count = len(sources)
            if count >= 3:
                confidence = 1.0
            elif count == 2:
                confidence = 0.85
            else:
                confidence = 0.65

            results.append({
                "hostname": host,
                "sources": sorted(list(sources)),
                "sources_count": count,
                "confidence_score": confidence,
            })

        return sorted(results, key=lambda x: (-x["confidence_score"], x["hostname"]))
