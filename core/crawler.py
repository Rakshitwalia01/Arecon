#!/usr/bin/env python3
"""
ARECON Web Crawling & Historical URL Collector (core/crawler.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Collects:
- Passive historical URLs via Wayback Machine CDX API
- Active client-side routes & form action targets
- Excludes destructive operations (logout, delete, drop)
"""

import concurrent.futures
from html.parser import HTMLParser
import json
import ssl
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Set
from core.scope import ScopeFilter

USER_AGENT = "Mozilla/5.0 (compatible; ARECON-Crawler/2.0; +https://authorized-bugbounty.org)"


class HTMLLinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): v for k, v in attrs if v}
        target = None
        if tag in ("a", "link") and "href" in attr_dict:
            target = attr_dict["href"]
        elif tag in ("script", "img", "iframe", "source") and "src" in attr_dict:
            target = attr_dict["src"]
        elif tag == "form" and "action" in attr_dict:
            target = attr_dict["action"]

        if target and not target.startswith(("javascript:", "mailto:", "tel:", "#")):
            abs_url = urllib.parse.urljoin(self.base_url, target)
            self.links.add(abs_url)


class WebCrawler:
    def __init__(self, target_domain: str, scope: ScopeFilter, timeout: int = 6):
        self.target_domain = target_domain.lower().strip()
        self.scope = scope
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def fetch_wayback_urls(self, limit: int = 150) -> Set[str]:
        url = (
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}/*"
            f"&output=json&collapse=urlkey&limit={limit}&fl=original"
        )
        found_urls = set()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for row in data[1:]:
                        if row and isinstance(row, list):
                            u = row[0].strip()
                            parsed = urllib.parse.urlparse(u)
                            if self.scope.is_in_scope(parsed.hostname or ""):
                                found_urls.add(u)
        except Exception:
            pass
        return found_urls

    def crawl_endpoint(self, base_url: str) -> Set[str]:
        discovered = set()
        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                content_type = resp.headers.get("content-type", "")
                if "text/html" in content_type:
                    body = resp.read(80000).decode("utf-8", errors="ignore")
                    parser = HTMLLinkExtractor(base_url)
                    parser.feed(body)
                    for link in parser.links:
                        parsed = urllib.parse.urlparse(link)
                        if self.scope.is_in_scope(parsed.hostname or ""):
                            # Filter media files
                            if not parsed.path.lower().endswith(
                                (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2")
                            ):
                                # Discard destructive endpoints
                                if not any(bad in parsed.path.lower() for bad in ("logout", "signout", "delete")):
                                    discovered.add(link)
        except Exception:
            pass
        return discovered

    def run(self, live_urls: List[str], active: bool = False) -> List[str]:
        all_endpoints = set(live_urls)
        # 1. Wayback passive discovery
        historical = self.fetch_wayback_urls()
        all_endpoints.update(historical)

        # 2. Active spidering
        if active and live_urls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_url = {executor.submit(self.crawl_endpoint, u): u for u in live_urls[:12]}
                for future in concurrent.futures.as_completed(future_to_url):
                    try:
                        all_endpoints.update(future.result())
                    except Exception:
                        pass

        return sorted(list(all_endpoints))
