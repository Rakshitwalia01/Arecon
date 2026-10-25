#!/usr/bin/env python3
"""
ARECON Scope Governance & Filter Module (core/scope.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Enforces strict in-scope authorization and out-of-scope exclusions.
"""

import os
import re
from typing import List, Optional


class ScopeFilter:
    """Enforces scope boundaries and out-of-scope exclusions."""

    def __init__(self, target_domain: str, exclusion_file: Optional[str] = None):
        self.target_domain = target_domain.lower().strip()
        self.exclusions: List[re.Pattern] = []

        if exclusion_file and os.path.exists(exclusion_file):
            with open(exclusion_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.add_exclusion(line)

    def add_exclusion(self, pattern_str: str):
        pattern_str = pattern_str.strip()
        if not pattern_str:
            return
        try:
            self.exclusions.append(re.compile(pattern_str, re.IGNORECASE))
        except re.error:
            self.exclusions.append(re.compile(re.escape(pattern_str), re.IGNORECASE))

    def is_in_scope(self, hostname: str) -> bool:
        hostname = hostname.lower().strip()
        # Must match the root target domain or be a subdomain
        if not (hostname == self.target_domain or hostname.endswith(f".{self.target_domain}")):
            return False

        # Must not match any exclusion pattern
        for pattern in self.exclusions:
            if pattern.search(hostname):
                return False
        return True
