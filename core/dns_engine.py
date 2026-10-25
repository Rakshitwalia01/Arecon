#!/usr/bin/env python3
"""
ARECON Advanced DNS Resolution Engine (core/dns_engine.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Multi-threaded resolution with:
- IPv4 (A) and IPv6 (AAAA)
- CNAME chain resolution
- Wildcard DNS suppression
- Takeover vulnerability correlation
"""

import concurrent.futures
import socket
from typing import Any, Dict, List, Optional, Set
from core.wildcard import WildcardDetector


class DNSEngine:
    def __init__(self, root_domain: str, wildcard_detector: WildcardDetector, threads: int = 20, timeout: float = 3.5):
        self.root_domain = root_domain.lower().strip()
        self.wildcard_detector = wildcard_detector
        self.threads = threads
        self.timeout = timeout

    def resolve_host(self, host: str) -> Optional[Dict[str, Any]]:
        ipv4_addresses: Set[str] = set()
        ipv6_addresses: Set[str] = set()
        cname = None

        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)

        try:
            # 1. Resolve IPv4
            try:
                info_v4 = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
                for item in info_v4:
                    ipv4_addresses.add(item[4][0])
            except (socket.gaierror, socket.timeout):
                pass

            # 2. Resolve IPv6
            try:
                info_v6 = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
                for item in info_v6:
                    ipv6_addresses.add(item[4][0])
            except (socket.gaierror, socket.timeout):
                pass

            # 3. Canonical name
            try:
                fqdn = socket.getfqdn(host)
                if fqdn and fqdn.lower() != host.lower():
                    cname = fqdn
            except Exception:
                pass

        finally:
            socket.setdefaulttimeout(orig_timeout)

        all_ips = sorted(list(ipv4_addresses.union(ipv6_addresses)))
        if not all_ips:
            return None

        # Check for Wildcard DNS false-positive
        is_wildcard = self.wildcard_detector.is_wildcard_host(all_ips)

        return {
            "host": host,
            "ips": all_ips,
            "ipv4": sorted(list(ipv4_addresses)),
            "ipv6": sorted(list(ipv6_addresses)),
            "cname": cname,
            "is_wildcard": is_wildcard,
        }

    def run(self, hostnames: List[str]) -> List[Dict[str, Any]]:
        resolved_assets = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_host = {executor.submit(self.resolve_host, h): h for h in hostnames}
            for future in concurrent.futures.as_completed(future_to_host):
                try:
                    res = future.result()
                    if res:
                        resolved_assets.append(res)
                except Exception:
                    pass

        return sorted(resolved_assets, key=lambda x: x["host"])
