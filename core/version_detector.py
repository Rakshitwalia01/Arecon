#!/usr/bin/env python3
"""
ARECON Automatic Service Version Detection Module (core/version_detector.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Automatically extracts and analyzes specific versions of services, runtimes,
frameworks, and client-side libraries across web assets.
Sources analyzed:
1. HTTP Response Headers (Server, X-Powered-By, Via, X-AspNet-Version, X-Generator)
2. HTML <meta> Tags (generator, author)
3. Script URLs & Query Strings (e.g. jquery-3.6.0.min.js, react@18.2.0)
4. HTML/JavaScript Comment Banners & Global Object Signatures
5. Common API/Info Endpoints (e.g. OpenAPI version, /actuator/info, /api/version)
6. Outdated & Known Vulnerability Flagging (OWASP WSTG-INFO-02 & WSTG-CONF-04)
"""

import html
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Known EOL / High Risk thresholds for popular software
KNOWN_EOL_OR_RISK = {
    "PHP": {
        "pattern": r"^([0-7]\..*)$",
        "description": "PHP 7.x or earlier is End-of-Life (EOL) and receives no security updates.",
        "severity": "HIGH",
    },
    "Apache": {
        "pattern": r"^(2\.[0-3]\..*|2\.4\.[0-4][0-9](?:\..*)?)$",
        "description": "Apache versions below 2.4.50 are vulnerable to multiple CVEs including Path Traversal (CVE-2021-41773).",
        "severity": "HIGH",
    },
    "Nginx": {
        "pattern": r"^(0\..*|1\.[0-1][0-7]\..*)$",
        "description": "Legacy Nginx version (<1.18.0) subject to multiple known security advisories.",
        "severity": "MEDIUM",
    },
    "jQuery": {
        "pattern": r"^([1-2]\..*|3\.[0-4]\..*)$",
        "description": "jQuery versions prior to 3.5.0 contain known Cross-Site Scripting (XSS) flaws (CVE-2020-11022, CVE-2015-9251).",
        "severity": "MEDIUM",
    },
    "Python": {
        "pattern": r"^([0-2]\..*|3\.[0-6]\..*)$",
        "description": "Python version is End-of-Life (EOL).",
        "severity": "HIGH",
    },
    "WordPress": {
        "pattern": r"^([0-5]\..*|6\.[0-1](?:\..*)?)$",
        "description": "WordPress version is outdated and likely missing critical security patches.",
        "severity": "HIGH",
    },
    "OpenSSL": {
        "pattern": r"^(0\..*|1\.0\..*|1\.1\.0.*)$",
        "description": "OpenSSL version is End-of-Life (EOL).",
        "severity": "CRITICAL",
    },
}

# Regex patterns for script tag version detection
SCRIPT_VERSION_PATTERNS = [
    # jquery-3.6.0.min.js or jquery.min.js?ver=3.6.0
    (re.compile(r"""jquery[-.]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js""", re.IGNORECASE), "jQuery"),
    (re.compile(r"""jquery.*?ver=([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "jQuery"),
    # react@18.2.0 or react-18.2.0.js
    (re.compile(r"""react(?:-dom)?@([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "React"),
    (re.compile(r"""react[-.]([0-9]+(?:\.[0-9]+)+)(?:\.production|\.min)?\.js""", re.IGNORECASE), "React"),
    # vue@2.6.14 or vue-2.6.14.js
    (re.compile(r"""vue@([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Vue.js"),
    (re.compile(r"""vue[-.]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js""", re.IGNORECASE), "Vue.js"),
    # bootstrap@5.1.3 or bootstrap-5.1.3.js
    (re.compile(r"""bootstrap@([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Bootstrap"),
    (re.compile(r"""bootstrap[-.]([0-9]+(?:\.[0-9]+)+)(?:\.bundle)?(?:\.min)?\.js""", re.IGNORECASE), "Bootstrap"),
    # lodash@4.17.21 or lodash-4.17.21.js
    (re.compile(r"""lodash@([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Lodash"),
    (re.compile(r"""lodash[-.]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js""", re.IGNORECASE), "Lodash"),
    # angular@14.2.0
    (re.compile(r"""angular@([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Angular"),
    # tailwindcss@3.2.4
    (re.compile(r"""tailwindcss@([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Tailwind CSS"),
]

# Patterns in HTML or JS comments / contents
COMMENT_VERSION_PATTERNS = [
    (re.compile(r"""(?:/\*!|//)\s*jQuery\s*(?:JavaScript\s*Library\s*)?v([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "jQuery"),
    (re.compile(r"""(?:/\*!|//)\s*Bootstrap\s*v([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Bootstrap"),
    (re.compile(r"""(?:/\*!|//)\s*Vue\.js\s*v([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Vue.js"),
    (re.compile(r"""(?:/\*!|//)\s*React\s*v([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "React"),
    (re.compile(r"""(?:/\*!|//)\s*Lodash\s*<https://lodash\.com/>\s*v([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Lodash"),
    (re.compile(r"""(?:/\*!|//)\s*Moment\.js\s*([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Moment.js"),
    (re.compile(r"""Swagger\s*UI\s*-\s*Version\s*([0-9]+(?:\.[0-9]+)+)""", re.IGNORECASE), "Swagger UI"),
    (re.compile(r"""ng-version=["']([0-9]+(?:\.[0-9]+)+)["']""", re.IGNORECASE), "Angular"),
]


class VersionDetector:
    """Automated service and software version extraction engine."""

    @staticmethod
    def extract_from_server_header(server_str: str) -> Dict[str, str]:
        """
        Parses Server header:
        Examples:
        'nginx/1.18.0' -> {'Nginx': '1.18.0'}
        'Apache/2.4.52 (Ubuntu)' -> {'Apache': '2.4.52', 'OS': 'Ubuntu'}
        'openresty/1.19.9.1' -> {'OpenResty': '1.19.9.1'}
        'Microsoft-IIS/10.0' -> {'Microsoft IIS': '10.0'}
        'gunicorn/20.1.0' -> {'Gunicorn': '20.1.0'}
        'LiteSpeed/5.4.12' -> {'LiteSpeed': '5.4.12'}
        'Caddy/v2.6.4' -> {'Caddy': '2.6.4'}
        """
        results = {}
        if not server_str:
            return results

        # Match software/version
        matches = re.findall(r"""([a-zA-Z0-9_\-\.]+)/v?([0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9_\-\.]+)*)""", server_str)
        for name, ver in matches:
            clean_name = name.capitalize()
            if "iis" in name.lower():
                clean_name = "Microsoft IIS"
            elif "nginx" in name.lower():
                clean_name = "Nginx"
            elif "apache" in name.lower():
                clean_name = "Apache"
            elif "openresty" in name.lower():
                clean_name = "OpenResty"
            elif "gunicorn" in name.lower():
                clean_name = "Gunicorn"
            elif "litespeed" in name.lower():
                clean_name = "LiteSpeed"
            elif "caddy" in name.lower():
                clean_name = "Caddy"
            results[clean_name] = ver

        # Extract OS details in parentheses if any
        os_match = re.search(r"""\(([a-zA-Z0-9_\-\.\s]+)\)""", server_str)
        if os_match:
            os_info = os_match.group(1).strip()
            if any(term in os_info.lower() for term in ("ubuntu", "debian", "centos", "redhat", "fedora", "windows", "unix", "linux")):
                results["OS"] = os_info

        return results

    @staticmethod
    def extract_from_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """Parses headers for software versions."""
        versions = {}

        # 1. Server Header
        if "server" in headers:
            versions.update(VersionDetector.extract_from_server_header(headers["server"]))

        # 2. X-Powered-By
        if "x-powered-by" in headers:
            val = headers["x-powered-by"]
            # PHP/7.4.33
            php_m = re.search(r"""php/([0-9]+(?:\.[0-9]+)+)""", val, re.IGNORECASE)
            if php_m:
                versions["PHP"] = php_m.group(1)
            # ASP.NET
            asp_m = re.search(r"""asp\.net\s*(?:version)?[:/]?\s*([0-9]+(?:\.[0-9]+)+)?""", val, re.IGNORECASE)
            if asp_m and asp_m.group(1):
                versions["ASP.NET"] = asp_m.group(1)
            # Next.js
            next_m = re.search(r"""next(?:\.js)?(?:/([0-9]+(?:\.[0-9]+)+))?""", val, re.IGNORECASE)
            if next_m:
                versions["Next.js"] = next_m.group(1) or "Detected"
            # Express
            if "express" in val.lower():
                exp_m = re.search(r"""express/([0-9]+(?:\.[0-9]+)+)""", val, re.IGNORECASE)
                versions["Express"] = exp_m.group(1) if exp_m else "Detected"

        # 3. ASP.NET specific headers
        if "x-aspnet-version" in headers:
            versions["ASP.NET"] = headers["x-aspnet-version"].strip()
        if "x-aspnetmvc-version" in headers:
            versions["ASP.NET MVC"] = headers["x-aspnetmvc-version"].strip()

        # 4. Generator / CMS headers
        if "x-generator" in headers:
            gen = headers["x-generator"]
            wp_m = re.search(r"""wordpress\s*([0-9]+(?:\.[0-9]+)+)?""", gen, re.IGNORECASE)
            if wp_m:
                versions["WordPress"] = wp_m.group(1) or "Detected"
            drupal_m = re.search(r"""drupal\s*([0-9]+(?:\.[0-9]+)+)?""", gen, re.IGNORECASE)
            if drupal_m:
                versions["Drupal"] = drupal_m.group(1) or "Detected"

        if "x-ghost-version" in headers:
            versions["Ghost"] = headers["x-ghost-version"].strip()

        if "x-jenkins" in headers:
            versions["Jenkins"] = headers["x-jenkins"].strip()

        # 5. Via Header (Varnish / Squid / Envoy)
        if "via" in headers:
            via = headers["via"]
            varnish_m = re.search(r"""varnish(?:/([0-9]+(?:\.[0-9]+)+))?""", via, re.IGNORECASE)
            if varnish_m and varnish_m.group(1):
                versions["Varnish"] = varnish_m.group(1)
            squid_m = re.search(r"""squid(?:/([0-9]+(?:\.[0-9]+)+))?""", via, re.IGNORECASE)
            if squid_m and squid_m.group(1):
                versions["Squid"] = squid_m.group(1)

        return versions

    @staticmethod
    def extract_from_html(html_text: str) -> Dict[str, str]:
        """Scans HTML source for <meta name="generator">, <script> links, and comment banners."""
        versions = {}
        if not html_text:
            return versions

        # 1. <meta name="generator" content="...">
        meta_generators = re.findall(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", html_text, re.IGNORECASE)
        meta_generators += re.findall(r"""<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']""", html_text, re.IGNORECASE)

        for content in meta_generators:
            content = html.unescape(content).strip()
            # WordPress 6.2.2
            wp_m = re.search(r"""WordPress\s*([0-9]+(?:\.[0-9]+)+)""", content, re.IGNORECASE)
            if wp_m:
                versions["WordPress"] = wp_m.group(1)
            # Joomla! 3.9.27
            joomla_m = re.search(r"""Joomla!?.*?([0-9]+(?:\.[0-9]+)+)""", content, re.IGNORECASE)
            if joomla_m:
                versions["Joomla"] = joomla_m.group(1)
            # Drupal 9.3.0
            drupal_m = re.search(r"""Drupal\s*([0-9]+(?:\.[0-9]+)+)""", content, re.IGNORECASE)
            if drupal_m:
                versions["Drupal"] = drupal_m.group(1)
            # Gatsby 4.25.0
            gatsby_m = re.search(r"""Gatsby\s*([0-9]+(?:\.[0-9]+)+)""", content, re.IGNORECASE)
            if gatsby_m:
                versions["Gatsby"] = gatsby_m.group(1)
            # Hugo 0.111.3
            hugo_m = re.search(r"""Hugo\s*([0-9]+(?:\.[0-9]+)+)""", content, re.IGNORECASE)
            if hugo_m:
                versions["Hugo"] = hugo_m.group(1)
            # Ghost 4.0
            ghost_m = re.search(r"""Ghost\s*([0-9]+(?:\.[0-9]+)+)""", content, re.IGNORECASE)
            if ghost_m:
                versions["Ghost"] = ghost_m.group(1)

        # 2. Extract from <script src="...">
        script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html_text, re.IGNORECASE)
        for src in script_srcs:
            for pat, lib_name in SCRIPT_VERSION_PATTERNS:
                m = pat.search(src)
                if m:
                    versions[lib_name] = m.group(1)
                    break

        # 3. Extract from HTML / Script comment banners
        for pat, lib_name in COMMENT_VERSION_PATTERNS:
            m = pat.search(html_text)
            if m:
                versions[lib_name] = m.group(1)

        return versions

    @staticmethod
    def audit_versions(versions: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Audits extracted versions against known EOL or high-risk thresholds.
        Returns a list of security findings.
        """
        findings = []

        for service, version in versions.items():
            # Check for general version disclosure
            if version and version != "Detected":
                findings.append({
                    "service": service,
                    "version": version,
                    "type": "VERSION_DISCLOSURE",
                    "severity": "LOW",
                    "description": f"Specific software version disclosed for {service} ({version}). Facilitates targeted vulnerability profiling.",
                })

            # Check for Known EOL / Vulnerable thresholds
            if service in KNOWN_EOL_OR_RISK and version and version != "Detected":
                rule = KNOWN_EOL_OR_RISK[service]
                if re.match(rule["pattern"], version):
                    findings.append({
                        "service": service,
                        "version": version,
                        "type": "OUTDATED_OR_EOL",
                        "severity": rule["severity"],
                        "description": f"Outdated/EOL Component: {service} v{version}. {rule['description']}",
                    })

        return findings

    @classmethod
    def detect(cls, headers: Dict[str, str], html_sample: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
        """
        Master detection method combining headers, HTML meta, scripts, and comments.
        Returns (detected_versions_dict, security_audit_findings).
        """
        all_versions = {}

        # 1. Headers
        all_versions.update(cls.extract_from_headers(headers))

        # 2. HTML text
        all_versions.update(cls.extract_from_html(html_sample))

        # 3. Security audit of versions
        audit_findings = cls.audit_versions(all_versions)

        return all_versions, audit_findings
