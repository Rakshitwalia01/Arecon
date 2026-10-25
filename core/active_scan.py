#!/usr/bin/env python3
"""
ARECON Active Reconnaissance & Network Assessment Module (core/active_scan.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Capabilities:
1. Strict Scope Governance: Validates all target hosts/IPs against ScopeFilter before any probe.
2. Port & Service Scanning: Configurable Nmap wrapper (-T2 to -T4, top-1000 or full-range)
   with automatic pure-Python socket connect fallback.
3. Zero-Guessing Robots & Sitemap Harvester: Parses robots.txt and sitemap.xml to catalog endpoints.
4. Directory & Route Bruteforcing: Wraps ffuf/gobuster with soft-404 baseline size detection and Python fallback.
5. TLS Security & Certificate Audit: Analyzes protocol versions (TLS 1.0/1.1 deprecation), cipher suites,
   and certificate chain issues mapped to OWASP WSTG-CRYP-01/03.
6. Verbose Error & Stack Trace Harvester: Safe probes triggering framework debug disclosures (log only).
7. Third-Party Integration Signature Mapper: Offline static fingerprinting of 20+ payment gateways,
   analytics, tracking, monitoring, and CDN services.
8. Rate Limiting & Concurrency Controls: Safeguards targets from aggressive traffic.
"""

import concurrent.futures
from datetime import datetime, timezone
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple

from core.db import ReconDB
from core.scope import ScopeFilter


# Common fallback ports for TCP socket scan when nmap is not installed
COMMON_PORTS = [
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (135, "msrpc"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (1433, "ms-sql-s"),
    (1521, "oracle"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (6379, "redis"),
    (8000, "http-alt"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9200, "elasticsearch"),
    (27017, "mongodb"),
]

# Sensitive paths for built-in directory bruteforcing
DEFAULT_DIR_WORDLIST = [
    "admin",
    "administrator",
    "api",
    "api/v1",
    "api/v2",
    "api/docs",
    "app",
    "backup",
    "backup.zip",
    "config",
    "config.json",
    "console",
    "dashboard",
    "docs",
    "env",
    ".env",
    ".git/HEAD",
    ".gitignore",
    "graphql",
    "health",
    "healthcheck",
    "login",
    "manage",
    "metrics",
    "openapi.json",
    "portal",
    "server-status",
    "sitemap.xml",
    "status",
    "swagger",
    "swagger.json",
    "swagger-ui.html",
    "uploads",
    "v1",
    "v2",
    "web.config",
    "wp-admin",
    "wp-login.php",
]

# Third-party integration signatures
INTEGRATION_SIGNATURES = [
    # Payment Processors
    {"name": "Stripe", "category": "Payment Gateway", "patterns": [r"js\.stripe\.com", r"checkout\.stripe\.com", r"stripe-js", r"Stripe\("]},
    {"name": "PayPal", "category": "Payment Gateway", "patterns": [r"paypal\.com/sdk", r"paypalobjects\.com", r"paypal\.Buttons"]},
    {"name": "Square", "category": "Payment Gateway", "patterns": [r"web\.squarecdn\.com", r"sq-payment-form"]},
    {"name": "Adyen", "category": "Payment Gateway", "patterns": [r"checkoutshopper.*\.adyen\.com", r"adyen\.min\.js"]},
    {"name": "Braintree", "category": "Payment Gateway", "patterns": [r"js\.braintreegateway\.com", r"braintree-web"]},
    {"name": "Razorpay", "category": "Payment Gateway", "patterns": [r"checkout\.razorpay\.com"]},
    {"name": "Paddle", "category": "Payment Gateway", "patterns": [r"cdn\.paddle\.com/paddle/paddle\.js"]},
    # Analytics & Tracking
    {"name": "Google Analytics", "category": "Analytics", "patterns": [r"google-analytics\.com/(?:analytics|ga)\.js", r"googletagmanager\.com/gtag/js", r"gtag\("]},
    {"name": "Google Tag Manager", "category": "Analytics", "patterns": [r"googletagmanager\.com/gtm\.js"]},
    {"name": "Segment", "category": "Analytics", "patterns": [r"cdn\.segment\.com/analytics\.js", r"analytics\.load\("]},
    {"name": "Mixpanel", "category": "Analytics", "patterns": [r"cdn\.mxpnl\.com", r"mixpanel\.init"]},
    {"name": "Hotjar", "category": "Analytics", "patterns": [r"static\.hotjar\.com", r"hjid:"]},
    {"name": "Amplitude", "category": "Analytics", "patterns": [r"cdn\.amplitude\.com", r"amplitude\.getInstance"]},
    {"name": "Meta Pixel", "category": "Tracking", "patterns": [r"connect\.facebook\.net/.*/fbevents\.js", r"fbq\("]},
    {"name": "PostHog", "category": "Analytics", "patterns": [r"app\.posthog\.com", r"posthog\.init"]},
    # Customer Communication & Support
    {"name": "Intercom", "category": "Customer Support", "patterns": [r"widget\.intercom\.io", r"Intercom\("]},
    {"name": "Zendesk", "category": "Customer Support", "patterns": [r"static\.zdassets\.com", r"zE\("]},
    {"name": "Crisp", "category": "Customer Support", "patterns": [r"client\.crisp\.chat"]},
    {"name": "HubSpot", "category": "Marketing/CRM", "patterns": [r"js\.hs-scripts\.com", r"hbspt\."]},
    # Error & Performance Monitoring
    {"name": "Sentry", "category": "Error Monitoring", "patterns": [r"browser\.sentry-cdn\.com", r"@sentry/", r"Sentry\.init"]},
    {"name": "Datadog", "category": "Monitoring", "patterns": [r"datadoghq-browser-agent", r"DD_RUM", r"DD_LOGS"]},
    {"name": "New Relic", "category": "Monitoring", "patterns": [r"js-agent\.newrelic\.com", r"NREUM"]},
    {"name": "Bugsnag", "category": "Error Monitoring", "patterns": [r"d2wy8f7a9urs9l\.cloudfront\.net", r"Bugsnag\.start"]},
    {"name": "LogRocket", "category": "Session Recording", "patterns": [r"cdn\.logrocket\.io", r"LogRocket\.init"]},
    # CDN & Bot Protection
    {"name": "Cloudflare Turnstile", "category": "Bot Protection", "patterns": [r"challenges\.cloudflare\.com/turnstile"]},
    {"name": "Google reCAPTCHA", "category": "Bot Protection", "patterns": [r"google\.com/recaptcha", r"grecaptcha"]},
    {"name": "hCaptcha", "category": "Bot Protection", "patterns": [r"js\.hcaptcha\.com", r"hcaptcha"]},
]


class ActiveScanner:
    """
    Orchestrates active reconnaissance modules while strictly enforcing scope boundaries,
    rate limits, and error handling.
    """

    def __init__(
        self,
        scope: ScopeFilter,
        db: ReconDB,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.scope = scope
        self.db = db
        self.config = config or {}

        # Configurable settings
        self.scan_id = self.config.get("scan_id", 0)
        self.root_domain = self.config.get("target_domain", self.scope.target_domain)
        self.rate_limit_delay = float(self.config.get("rate_limit_delay", 0.05))
        self.max_concurrency = int(self.config.get("concurrency", 8))
        self.timeout = float(self.config.get("timeout", 5.0))
        self.nmap_timing = self.config.get("nmap_timing", "-T3")
        self.full_ports = bool(self.config.get("full_ports", False))
        self.wordlist_path = self.config.get("wordlist")
        self.extensions = self.config.get("extensions", ["php", "html", "json", "js"])

    # -------------------------------------------------------------------------
    # 1. SCOPE VALIDATION
    # -------------------------------------------------------------------------
    def is_target_in_scope(self, target: str) -> bool:
        """Strictly checks if a host or URL is authorized by the ScopeFilter."""
        hostname = target
        if "://" in target:
            try:
                hostname = urllib.parse.urlparse(target).hostname or target
            except Exception:
                pass
        else:
            hostname = target.split(":")[0]
        return self.scope.is_in_scope(hostname)

    # -------------------------------------------------------------------------
    # 2. ROBOTS.TXT & SITEMAP.XML PARSING
    # -------------------------------------------------------------------------
    def parse_robots_and_sitemap(self, host: str, protocol: str = "https") -> List[str]:
        """
        Fetches and parses robots.txt and sitemap.xml.
        Zero-guessing, low-cost path harvesting.
        """
        if not self.is_target_in_scope(host):
            return []

        discovered_urls: Set[str] = set()
        base_url = f"{protocol}://{host}"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARECON/2.0 Security Scanner"

        # 1. Fetch robots.txt
        robots_url = f"{base_url}/robots.txt"
        sitemap_urls: List[str] = []
        try:
            req = urllib.request.Request(robots_url, headers={"User-Agent": user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="ignore")
                    for line in body.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        lower = line.lower()
                        if lower.startswith("disallow:") or lower.startswith("allow:"):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                path = parts[1].strip()
                                if path and not path.startswith("*"):
                                    # Clean wildcards / query hints
                                    clean_path = path.split("$")[0].split("*")[0]
                                    if clean_path and clean_path != "/":
                                        full_url = urllib.parse.urljoin(base_url, clean_path)
                                        if self.is_target_in_scope(full_url):
                                            discovered_urls.add(full_url)
                                            self.db.record_endpoint(
                                                scan_id=self.scan_id,
                                                root_domain=self.root_domain,
                                                url=full_url,
                                                path=clean_path,
                                                endpoint_type="RobotsDisallow" if lower.startswith("disallow:") else "RobotsAllow",
                                                discovery_source="robots.txt",
                                            )
                        elif lower.startswith("sitemap:"):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                sm = parts[1].strip()
                                if sm.startswith("http"):
                                    sitemap_urls.append(sm)
        except Exception:
            pass

        # Fallback to default sitemap if none declared
        if not sitemap_urls:
            sitemap_urls.append(f"{base_url}/sitemap.xml")

        # 2. Parse sitemaps
        for sm_url in sitemap_urls:
            if not self.is_target_in_scope(sm_url):
                continue
            try:
                time.sleep(self.rate_limit_delay)
                req = urllib.request.Request(sm_url, headers={"User-Agent": user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        content = resp.read().decode("utf-8", errors="ignore")
                        # Extract <loc> tags
                        loc_matches = re.findall(r"<loc>(.*?)</loc>", content, re.IGNORECASE)
                        for loc in loc_matches:
                            loc = loc.strip()
                            if self.is_target_in_scope(loc):
                                parsed = urllib.parse.urlparse(loc)
                                path = parsed.path or "/"
                                discovered_urls.add(loc)
                                self.db.record_endpoint(
                                    scan_id=self.scan_id,
                                    root_domain=self.root_domain,
                                    url=loc,
                                    path=path,
                                    endpoint_type="SitemapEntry",
                                    discovery_source="sitemap.xml",
                                )
            except Exception:
                pass

        return sorted(list(discovered_urls))

    # -------------------------------------------------------------------------
    # 3. NMAP / SOCKET PORT & SERVICE SCANNING
    # -------------------------------------------------------------------------
    def run_nmap_scan(
        self,
        targets: List[str],
        timing: Optional[str] = None,
        full_range: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Executes Nmap port scan across authorized targets.
        If Nmap binary is absent, falls back to a multi-threaded pure-Python socket scan.
        """
        timing = timing or self.nmap_timing
        in_scope_targets = [t for t in targets if self.is_target_in_scope(t)]
        if not in_scope_targets:
            return []

        results: List[Dict[str, Any]] = []
        nmap_bin = shutil.which("nmap")

        if nmap_bin:
            for target in in_scope_targets:
                cmd = [nmap_bin, timing, "-sV", "--version-light", "-oX", "-"]
                if full_range:
                    cmd.extend(["-p-"])
                else:
                    cmd.extend(["--top-ports", "1000"])
                cmd.append(target)

                try:
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
                    if proc.returncode == 0 and proc.stdout:
                        parsed = self._parse_nmap_xml(proc.stdout, target)
                        results.extend(parsed)
                except Exception:
                    # Fallback to socket scan on error
                    fallback = self._run_socket_scan_target(target)
                    results.extend(fallback)
        else:
            # Pure Python socket scan fallback
            for target in in_scope_targets:
                fallback = self._run_socket_scan_target(target)
                results.extend(fallback)

        return results

    def _parse_nmap_xml(self, xml_content: str, default_target: str) -> List[Dict[str, Any]]:
        """Parses Nmap XML output and records open ports to DB."""
        findings = []
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                # Extract address
                addr_elem = host.find("address")
                ip = addr_elem.attrib.get("addr", default_target) if addr_elem is not None else default_target
                
                # Extract hostname if available
                host_elem = host.find("hostnames/hostname")
                hostname = host_elem.attrib.get("name", default_target) if host_elem is not None else default_target

                if not self.is_target_in_scope(hostname):
                    continue

                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        state_elem = port_elem.find("state")
                        if state_elem is not None and state_elem.attrib.get("state") == "open":
                            port_id = int(port_elem.attrib.get("portid", 0))
                            protocol = port_elem.attrib.get("protocol", "tcp")
                            service_elem = port_elem.find("service")
                            service_name = service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown"
                            product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                            version = service_elem.attrib.get("version", "") if service_elem is not None else ""
                            full_ver = f"{product} {version}".strip() or service_name

                            finding = {
                                "hostname": hostname,
                                "ip": ip,
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "version": full_ver,
                                "confidence": 1.0,
                                "source": "nmap",
                            }
                            findings.append(finding)
                            self.db.record_open_port(
                                root_domain=self.root_domain,
                                hostname=hostname,
                                ip=ip,
                                port=port_id,
                                protocol=protocol,
                                service_name=service_name,
                                version=full_ver,
                                confidence=1.0,
                                source="nmap",
                            )
        except Exception:
            pass
        return findings

    def _run_socket_scan_target(self, target: str) -> List[Dict[str, Any]]:
        """Pure-Python multi-threaded TCP connect scan on common ports."""
        findings = []
        if not self.is_target_in_scope(target):
            return []

        # Resolve IP
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target

        def probe_port(p_info: Tuple[int, str]):
            port, s_name = p_info
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(min(self.timeout, 1.5))
                res = sock.connect_ex((ip, port))
                sock.close()
                if res == 0:
                    return {
                        "hostname": target,
                        "ip": ip,
                        "port": port,
                        "protocol": "tcp",
                        "service": s_name,
                        "version": s_name,
                        "confidence": 0.9,
                        "source": "socket_fallback",
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_concurrency, 12)) as executor:
            futures = [executor.submit(probe_port, p) for p in COMMON_PORTS]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    findings.append(res)
                    self.db.record_open_port(
                        root_domain=self.root_domain,
                        hostname=target,
                        ip=ip,
                        port=res["port"],
                        protocol="tcp",
                        service_name=res["service"],
                        version=res["version"],
                        confidence=0.9,
                        source="socket_fallback",
                    )
        return findings

    # -------------------------------------------------------------------------
    # 4. DIRECTORY & ENDPOINT BRUTEFORCING
    # -------------------------------------------------------------------------
    def run_dirbrute(
        self,
        base_url: str,
        wordlist_path: Optional[str] = None,
        extensions: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Directory and route discovery against HTTP(S) services.
        Uses soft-404 baseline detection to eliminate false positives.
        Wraps ffuf/gobuster if present, otherwise uses built-in Python requests.
        """
        if not self.is_target_in_scope(base_url):
            return []

        base_url = base_url.rstrip("/")
        wordlist = wordlist_path or self.wordlist_path
        discovered: List[Dict[str, Any]] = []

        # 1. Establish soft-404 baseline
        baseline_code, baseline_size = self._get_soft_404_baseline(base_url)

        # 2. Check for ffuf
        ffuf_bin = shutil.which("ffuf")
        if ffuf_bin and wordlist and os.path.exists(wordlist):
            try:
                temp_out = os.path.join(tempfile.gettempdir(), f"ffuf_{int(time.time())}.json")
                cmd = [
                    ffuf_bin,
                    "-u", f"{base_url}/FUZZ",
                    "-w", wordlist,
                    "-mc", "200,204,301,302,307,401,403",
                    "-t", str(min(self.max_concurrency, 10)),
                    "-rate", "20",
                    "-o", temp_out,
                    "-of", "json",
                    "-s",
                ]
                if baseline_size > 0:
                    cmd.extend(["-fs", str(baseline_size)])

                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                if os.path.exists(temp_out):
                    with open(temp_out, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for r in data.get("results", []):
                            u = r.get("url", "")
                            st = r.get("status", 200)
                            sz = r.get("length", 0)
                            if u and self.is_target_in_scope(u):
                                path = urllib.parse.urlparse(u).path
                                item = {"url": u, "path": path, "status": st, "length": sz}
                                discovered.append(item)
                                self.db.record_endpoint(
                                    scan_id=self.scan_id,
                                    root_domain=self.root_domain,
                                    url=u,
                                    path=path,
                                    endpoint_type="DirBrute",
                                    discovery_source="ffuf",
                                )
                    try:
                        os.remove(temp_out)
                    except Exception:
                        pass
                return discovered
            except Exception:
                pass

        # 3. Python Directory Bruteforce Fallback
        paths_to_test = DEFAULT_DIR_WORDLIST
        if wordlist and os.path.exists(wordlist):
            try:
                with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    paths_to_test = [line.strip().lstrip("/") for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                paths_to_test = DEFAULT_DIR_WORDLIST

        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARECON/2.0 Security Scanner"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for p in paths_to_test:
            time.sleep(self.rate_limit_delay)
            probe_url = f"{base_url}/{p}"
            if not self.is_target_in_scope(probe_url):
                continue

            try:
                req = urllib.request.Request(probe_url, headers={"User-Agent": user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    st = resp.status
                    body = resp.read()
                    sz = len(body)

                    # Soft-404 filter: status match and body length within tolerance
                    if baseline_size > 0 and abs(sz - baseline_size) < 30:
                        continue

                    if st in (200, 204, 301, 302, 307, 401, 403):
                        item = {"url": probe_url, "path": f"/{p}", "status": st, "length": sz}
                        discovered.append(item)
                        self.db.record_endpoint(
                            scan_id=self.scan_id,
                            root_domain=self.root_domain,
                            url=probe_url,
                            path=f"/{p}",
                            endpoint_type="DirBrute",
                            discovery_source="dirbrute_python",
                        )
            except urllib.error.HTTPError as e:
                # 401 and 403 are notable findings
                if e.code in (401, 403):
                    item = {"url": probe_url, "path": f"/{p}", "status": e.code, "length": 0}
                    discovered.append(item)
                    self.db.record_endpoint(
                        scan_id=self.scan_id,
                        root_domain=self.root_domain,
                        url=probe_url,
                        path=f"/{p}",
                        endpoint_type="DirBrute",
                        discovery_source="dirbrute_python",
                    )
            except Exception:
                pass

        return discovered

    def _get_soft_404_baseline(self, base_url: str) -> Tuple[int, int]:
        """Probes a randomized path to determine the baseline soft-404 status and body size."""
        random_path = f"arecon_probe_baseline_{int(time.time())}"
        probe_url = f"{base_url}/{random_path}"
        user_agent = "Mozilla/5.0 ARECON/2.0"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(probe_url, headers={"User-Agent": user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read()
                return resp.status, len(body)
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
                return e.code, len(body)
            except Exception:
                return e.code, 0
        except Exception:
            return 404, 0

    # -------------------------------------------------------------------------
    # 5. TLS CONFIGURATION & CERTIFICATE AUDIT
    # -------------------------------------------------------------------------
    def audit_tls(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Audits TLS protocol versions, cipher strength, and certificate chain/expiry.
        Scores issues against OWASP WSTG-CRYP-01/03.
        """
        if not self.is_target_in_scope(host):
            return {}

        finding: Dict[str, Any] = {
            "host": host,
            "port": port,
            "protocol_version": None,
            "cipher": None,
            "cert_valid": False,
            "cert_expired": False,
            "cert_issuer": None,
            "cert_subject": None,
            "days_until_expiration": None,
            "weak_protocols": [],
            "weak_ciphers": [],
            "vulnerabilities": [],
        }

        # 1. Connect and inspect active certificate & negotiated cipher
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    finding["protocol_version"] = ssock.version()
                    cipher_tuple = ssock.cipher()
                    if cipher_tuple:
                        cipher_name, proto, bits = cipher_tuple
                        finding["cipher"] = {"name": cipher_name, "protocol": proto, "bits": bits}
                        if bits and bits < 128:
                            finding["weak_ciphers"].append(f"{cipher_name} ({bits} bits)")
                            finding["vulnerabilities"].append({
                                "priority": "HIGH",
                                "category": "Cryptography (WSTG-CRYP-01)",
                                "target": f"{host}:{port}",
                                "hypothesis": f"Weak SSL/TLS cipher suite negotiated: {cipher_name} with key length < 128 bits.",
                            })

                    cert = ssock.getpeercert(binary_form=False)
                    if cert and "notAfter" in cert:
                        try:
                            # Format: 'May 15 12:00:00 2025 GMT'
                            expire_dt = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_left = (expire_dt - now).days
                            finding["days_until_expiration"] = days_left
                            finding["cert_valid"] = days_left > 0
                            if days_left <= 0:
                                finding["cert_expired"] = True
                                finding["vulnerabilities"].append({
                                    "priority": "HIGH",
                                    "category": "Certificate Validation (WSTG-CRYP-03)",
                                    "target": f"{host}:{port}",
                                    "hypothesis": f"Expired TLS certificate detected! Expired on {cert['notAfter']}.",
                                })
                        except Exception:
                            pass
        except Exception:
            pass

        # 2. Check for Deprecated Protocol Versions (TLS 1.0, TLS 1.1)
        deprecated_versions = []
        if hasattr(ssl, "TLSVersion"):
            for ver_name, ver_enum in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
                try:
                    dep_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    dep_ctx.check_hostname = False
                    dep_ctx.verify_mode = ssl.CERT_NONE
                    dep_ctx.minimum_version = ver_enum
                    dep_ctx.maximum_version = ver_enum
                    with socket.create_connection((host, port), timeout=min(self.timeout, 2.0)) as s:
                        with dep_ctx.wrap_socket(s, server_hostname=host) as ds:
                            deprecated_versions.append(ver_name)
                except Exception:
                    pass

        finding["weak_protocols"] = deprecated_versions
        for dep in deprecated_versions:
            finding["vulnerabilities"].append({
                "priority": "MEDIUM",
                "category": "Cryptography (WSTG-CRYP-01)",
                "target": f"{host}:{port}",
                "hypothesis": f"Deprecated and insecure protocol supported: {dep}. Susceptible to downgrade and cryptographic attacks.",
            })

        return finding

    # -------------------------------------------------------------------------
    # 6. VERBOSE ERROR & STACK TRACE HARVESTING
    # -------------------------------------------------------------------------
    def harvest_error_pages(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Sends safe, scope-respecting malformed probes designed to trigger
        default framework error pages (Django, Express, PHP, Spring, ASP.NET, Rails)
        and parses stack traces for tech-stack/path disclosure (log only, no exploitation).
        """
        if not self.is_target_in_scope(base_url):
            return []

        base_url = base_url.rstrip("/")
        disclosures: List[Dict[str, Any]] = []

        # Safe non-exploitative test vectors
        test_probes = [
            ("?id='", "quote_syntax"),
            ("?test[]=1", "array_param"),
            ("/%00", "null_byte"),
            ("/arecon_error_harvest_trigger_[test]", "bracket_path"),
        ]

        user_agent = "Mozilla/5.0 ARECON/2.0"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Error patterns indicating stack trace / debug mode
        stack_patterns = [
            ("Django Debug Mode", r"(?:Traceback \(most recent call last\):.*Django Version:|Django Version:.*Traceback \(most recent call last\)|django\.db\.utils|django\.core\.exceptions)", "Django"),
            ("Python Stack Trace", r"Traceback \(most recent call last\):", "Python"),
            ("Node.js / Express Stack Trace", r"(?:ReferenceError|TypeError|SyntaxError):.*at\s+(?:Module\.|anonymous|Object)", "Node.js"),
            ("PHP Fatal / Warning", r"(?:Fatal error|Parse error|Warning):.*in\s+(?:/[a-zA-Z0-9_\-\./]+\.php|C:\\[a-zA-Z0-9_\-\.\\]+\.php)\s+on\s+line", "PHP"),
            ("Spring / Java Stack Trace", r"(?:java\.lang\.[a-zA-Z]+Exception|org\.springframework\..*Exception)", "Java/Spring"),
            ("ASP.NET Server Error", r"Server Error in '.*' Application\..*Stack Trace:", "ASP.NET"),
            ("Ruby on Rails Exception", r"ActionController::RoutingError|ActiveRecord::.*Rails\.root:", "Ruby on Rails"),
            ("Internal Path Disclosure", r"(?:/(?:var/www|usr/share|home/[a-zA-Z0-9_]+|app/node_modules)|[C-Z]:\\(?:inetpub|inetpub\\wwwroot|Users\\[a-zA-Z0-9_]+))", "Path Disclosure"),
        ]

        for suffix, probe_type in test_probes:
            time.sleep(self.rate_limit_delay)
            probe_url = f"{base_url}{suffix}"
            try:
                req = urllib.request.Request(probe_url, headers={"User-Agent": user_agent})
                body = ""
                status_code = 200
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                        body = resp.read().decode("utf-8", errors="ignore")
                        status_code = resp.status
                except urllib.error.HTTPError as e:
                    status_code = e.code
                    try:
                        body = e.read().decode("utf-8", errors="ignore")
                    except Exception:
                        body = ""

                if body:
                    for desc, pat, tech in stack_patterns:
                        if re.search(pat, body, re.IGNORECASE | re.DOTALL):
                            disclosure = {
                                "target_url": probe_url,
                                "probe_type": probe_type,
                                "status_code": status_code,
                                "technology": tech,
                                "pattern_matched": desc,
                                "hypothesis": {
                                    "priority": "HIGH" if "Debug Mode" in desc or "Stack Trace" in desc else "MEDIUM",
                                    "category": "Error Handling (WSTG-ERRH-01)",
                                    "target": probe_url,
                                    "hypothesis": f"Improper error handling exposes internal {tech} stack trace / debug details on {probe_type} probe.",
                                },
                            }
                            disclosures.append(disclosure)
                            break  # Avoid duplicate matches on same probe
            except Exception:
                pass

        return disclosures

    # -------------------------------------------------------------------------
    # 7. THIRD-PARTY INTEGRATION MAPPER
    # -------------------------------------------------------------------------
    def map_third_party_integrations(
        self,
        html_or_js: str,
        asset_hostname: str,
    ) -> List[Dict[str, str]]:
        """
        Parses crawled HTML or JavaScript for known analytics, CDN, and payment-processor
        script signatures (pure offline static database) and writes to integrations table.
        """
        if not self.is_target_in_scope(asset_hostname) or not html_or_js:
            return []

        matched_integrations = []
        for sig in INTEGRATION_SIGNATURES:
            name = sig["name"]
            cat = sig["category"]
            for pat in sig["patterns"]:
                match = re.search(pat, html_or_js, re.IGNORECASE)
                if match:
                    indicator = match.group(0)[:80]
                    self.db.record_integration(
                        root_domain=self.root_domain,
                        asset_hostname=asset_hostname,
                        integration_name=name,
                        category=cat,
                        indicator=indicator,
                    )
                    matched_integrations.append({
                        "asset": asset_hostname,
                        "integration": name,
                        "category": cat,
                        "indicator": indicator,
                    })
                    break  # One match per signature is enough

        return matched_integrations

    # -------------------------------------------------------------------------
    # 8. MASTER RUN PIPELINE ENTRYPOINT
    # -------------------------------------------------------------------------
    def execute(self) -> Dict[str, Any]:
        """Runs the active scan sub-tasks according to user configuration."""
        results: Dict[str, Any] = {
            "open_ports": [],
            "robots_endpoints": [],
            "dirbrute_endpoints": [],
            "tls_findings": [],
            "error_disclosures": [],
            "integrations": [],
            "hypotheses": [],
        }

        # Pull in-scope assets from database
        raw_assets = self.db.get_assets(self.root_domain)
        in_scope_hosts = [a["hostname"] for a in raw_assets if self.is_target_in_scope(a["hostname"])]
        if not in_scope_hosts:
            in_scope_hosts = [self.root_domain] if self.is_target_in_scope(self.root_domain) else []

        # 1. Robots.txt and Sitemap scraping
        if self.config.get("robots_scan", False) or self.config.get("active_scan", False):
            for host in in_scope_hosts[:10]:
                ep_list = self.parse_robots_and_sitemap(host)
                results["robots_endpoints"].extend(ep_list)

        # 2. Port & Service Scanning via Nmap / Socket
        if self.config.get("active_scan", False):
            ports_found = self.run_nmap_scan(
                targets=in_scope_hosts,
                timing=self.nmap_timing,
                full_range=self.full_ports,
            )
            results["open_ports"].extend(ports_found)

            # Generate hypotheses for exposed database/admin services
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
            for p in ports_found:
                port_num = p.get("port")
                if port_num in sensitive_ports:
                    svc_name, prio = sensitive_ports[port_num]
                    results["hypotheses"].append({
                        "priority": prio,
                        "category": "Exposed Database / Admin Service (WSTG-CONF-02)",
                        "target": f"{p['hostname']}:{port_num}",
                        "hypothesis": f"Directly exposed {svc_name} port without application boundary. Test for default credentials and unauthorized access.",
                    })

        # 3. Directory / Endpoint Bruteforce
        if self.config.get("dirbrute", False):
            for host in in_scope_hosts[:5]:
                base_url = f"https://{host}"
                dir_res = self.run_dirbrute(base_url, wordlist_path=self.wordlist_path)
                results["dirbrute_endpoints"].extend(dir_res)

        # 4. TLS Security Audit
        if self.config.get("tls_audit", False):
            for host in in_scope_hosts[:8]:
                tls_res = self.audit_tls(host)
                if tls_res:
                    results["tls_findings"].append(tls_res)
                    results["hypotheses"].extend(tls_res.get("vulnerabilities", []))

        # 5. Verbose Error Harvesting
        if self.config.get("active_scan", False):
            for host in in_scope_hosts[:5]:
                base_url = f"https://{host}"
                errors = self.harvest_error_pages(base_url)
                for err in errors:
                    results["error_disclosures"].append(err)
                    if "hypothesis" in err:
                        results["hypotheses"].append(err["hypothesis"])

        return results


def run(
    scope: ScopeFilter,
    db: ReconDB,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Standard module entrypoint conforming to ARECON 2.0 Layer 2/3 contracts."""
    scanner = ActiveScanner(scope=scope, db=db, config=config)
    return scanner.execute()
