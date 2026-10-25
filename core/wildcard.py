#!/usr/bin/env python3
"""
ARECON Wildcard DNS Detection Module (core/wildcard.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Identifies wildcard DNS zones to eliminate false-positive subdomains and reduce noise.
"""

import socket
import uuid
from typing import List, Set, Tuple


class WildcardDetector:
    def __init__(self, root_domain: str, timeout: float = 3.0):
        self.root_domain = root_domain.lower().strip()
        self.timeout = timeout
        self.wildcard_ips: Set[str] = set()
        self.has_wildcard: bool = False

    def detect(self) -> Tuple[bool, Set[str]]:
        """
        Queries 3 random non-existent subdomains.
        If 2 or more resolve to identical IP addresses, wildcard DNS is detected.
        """
        probes = [
            f"arecon-wc-{uuid.uuid4().hex[:10]}.{self.root_domain}",
            f"probe-nx-{uuid.uuid4().hex[:10]}.{self.root_domain}",
            f"check-wildcard-{uuid.uuid4().hex[:10]}.{self.root_domain}",
        ]

        resolved_sets = []
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)

        try:
            for probe in probes:
                try:
                    info = socket.getaddrinfo(probe, None, socket.AF_INET, socket.SOCK_STREAM)
                    ips = {item[4][0] for item in info}
                    if ips:
                        resolved_sets.append(ips)
                except (socket.gaierror, socket.timeout):
                    pass
        finally:
            socket.setdefaulttimeout(orig_timeout)

        if len(resolved_sets) >= 2:
            # Common IPs across random subdomains
            common_ips = resolved_sets[0].intersection(*resolved_sets[1:])
            if common_ips:
                self.has_wildcard = True
                self.wildcard_ips = common_ips
                return True, self.wildcard_ips

        self.has_wildcard = False
        return False, set()

    def is_wildcard_host(self, ips: List[str]) -> bool:
        """Checks if a resolved IP list matches the wildcard pattern."""
        if not self.has_wildcard or not ips:
            return False
        # If all resolved IPs match the wildcard IP set
        return set(ips).issubset(self.wildcard_ips)
