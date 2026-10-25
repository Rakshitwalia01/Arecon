#!/usr/bin/env python3
"""
ARECON Cloud & Infrastructure Exposure Analyzer (core/cloud_analyzer.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Discovers:
- Public cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob)
- Cloud-hosted application domains & CDN relationships
- Dangling DNS CNAME records vulnerable to subdomain takeover
"""

import concurrent.futures
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

USER_AGENT = "Mozilla/5.0 (compatible; ARECON-CloudExposure/2.0; +https://authorized-bugbounty.org)"

# Known takeover fingerprints
TAKEOVER_PATTERNS = {
    "s3.amazonaws.com": ("AWS S3 Bucket", "The specified bucket does not exist"),
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku App", "No such app"),
    "azurewebsites.net": ("Azure App Service", "404 Web Site not found"),
    "trafficmanager.net": ("Azure Traffic Manager", "Service Unavailable"),
    "zendesk.com": ("Zendesk Help Center", "Help Center Closed"),
    "pantheonsite.io": ("Pantheon", "The gods are wise, but do not know of the site which you seek"),
    "shopify.com": ("Shopify Store", "Sorry, this shop is currently unavailable"),
    "ghost.io": ("Ghost Blog", "The thing you were looking for is no longer here"),
    "surge.sh": ("Surge.sh", "project not found"),
    "readme.io": ("ReadMe", "Project doesnt exist"),
}


class CloudAnalyzer:
    def __init__(self, target_domain: str, timeout: float = 3.5):
        self.target_domain = target_domain.lower().strip()
        self.brand_name = self.target_domain.split(".")[0]
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def check_bucket_url(self, provider: str, url: str) -> Optional[Dict[str, Any]]:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                # HTTP 200 means public listing or readable
                body = resp.read(2048).decode("utf-8", errors="ignore")
                is_listing = ("<ListBucketResult" in body) or ("ListBucket" in body)
                return {
                    "provider": provider,
                    "url": url,
                    "status": resp.status,
                    "exposure": "PUBLIC_LISTING" if is_listing else "PUBLIC_ACCESSIBLE",
                }
        except urllib.error.HTTPError as e:
            # HTTP 403 means bucket exists but is private (still good asset knowledge)
            if e.code == 403:
                return {
                    "provider": provider,
                    "url": url,
                    "status": 403,
                    "exposure": "EXISTS_PROTECTED",
                }
            return None
        except Exception:
            return None

    def scan_storage_buckets(self) -> List[Dict[str, Any]]:
        """Tests common permutations for public S3, GCS, and Azure buckets."""
        permutations = [
            self.brand_name,
            f"{self.brand_name}-assets",
            f"{self.brand_name}-media",
            f"{self.brand_name}-static",
            f"{self.brand_name}-data",
            f"{self.brand_name}-public",
            f"{self.brand_name}-prod",
            f"{self.brand_name}-dev",
            f"{self.brand_name}-backup",
        ]

        bucket_candidates = []
        for name in permutations:
            # AWS S3
            bucket_candidates.append(("AWS S3", f"https://{name}.s3.amazonaws.com"))
            # Google Cloud Storage
            bucket_candidates.append(("Google Cloud Storage", f"https://storage.googleapis.com/{name}"))
            # Azure Blob
            bucket_candidates.append(("Azure Blob", f"https://{name}.blob.core.windows.net/$web"))

        discovered_buckets = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_bucket = {executor.submit(self.check_bucket_url, p, u): (p, u) for p, u in bucket_candidates}
            for future in concurrent.futures.as_completed(future_to_bucket):
                try:
                    res = future.result()
                    if res:
                        discovered_buckets.append(res)
                except Exception:
                    pass

        return discovered_buckets

    def verify_takeover(self, host: str, cname: str) -> Optional[Dict[str, Any]]:
        """Inspects whether a CNAME points to a known cloud service and verifies if the service is orphaned."""
        cname_lower = cname.lower()
        for domain_sig, (service_name, error_phrase) in TAKEOVER_PATTERNS.items():
            if domain_sig in cname_lower:
                # Probe the host over HTTP to check for the claimable error response
                for proto in ("http://", "https://"):
                    probe_url = f"{proto}{host}"
                    try:
                        req = urllib.request.Request(probe_url, headers={"User-Agent": USER_AGENT})
                        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                            body = resp.read(8192).decode("utf-8", errors="ignore")
                            if error_phrase.lower() in body.lower():
                                return {
                                    "host": host,
                                    "cname": cname,
                                    "service": service_name,
                                    "vulnerable": True,
                                    "confidence": "HIGH",
                                    "proof": error_phrase,
                                }
                    except urllib.error.HTTPError as e:
                        try:
                            body = e.read(8192).decode("utf-8", errors="ignore")
                            if error_phrase.lower() in body.lower():
                                return {
                                    "host": host,
                                    "cname": cname,
                                    "service": service_name,
                                    "vulnerable": True,
                                    "confidence": "HIGH",
                                    "proof": error_phrase,
                                }
                        except Exception:
                            pass
                    except Exception:
                        pass

                # If CNAME matches signature but error phrase not immediately returned
                return {
                    "host": host,
                    "cname": cname,
                    "service": service_name,
                    "vulnerable": False,
                    "confidence": "POTENTIAL_POINTER",
                    "proof": f"Points to {cname}",
                }
        return None
