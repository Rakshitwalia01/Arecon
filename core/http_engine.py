#!/usr/bin/env python3
"""
ARECON HTTP Probing & Technology Fingerprinting Engine (core/http_engine.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Captures:
- Status codes & redirect chains
- Title & HTML metadata
- Technology stack clustering
- CDN / WAF / Cloud identification
- Security headers (HSTS, CSP, X-Frame-Options, CORS origin)
"""

import concurrent.futures
import html
from html.parser import HTMLParser
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from core.version_detector import VersionDetector

USER_AGENT = "Mozilla/5.0 (compatible; ARECON-WebProber/2.0; +https://authorized-bugbounty.org)"

TECH_SIGNATURES = {
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "React": [r"react\.production\.min\.js", r"react-dom", r'id="root"'],
    "Vue.js": [r"vue\.min\.js", r'data-v-[a-f0-9]+', r'id="app"'],
    "Angular": [r"ng-version=", r"ng-bind"],
    "WordPress": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
    "Express": [r"x-powered-by:\s*express"],
    "Django": [r"csrfmiddlewaretoken", r"__admin__"],
    "Laravel": [r"xsrf-token", r"laravel_session"],
    "Spring Boot": [r"whitelabel error page", r"spring-boot"],
    "Metabase": [r"metabase", r"metabase-bootstrap"],
    "Grafana": [r"grafana", r"window\.grafanaBootData"],
    "PHP": [r"x-powered-by:\s*php", r"\.php"],
    "ASP.NET": [r"x-aspnet-version", r"x-powered-by:\s*asp\.net"],
}

CDN_WAF_SIGNATURES = {
    "Cloudflare": [r"cf-ray", r"server:\s*cloudflare", r"__cfduid"],
    "AWS CloudFront": [r"x-amz-cf-id", r"cloudfront"],
    "Fastly": [r"x-fastly-request-id", r"fastly"],
    "Akamai": [r"x-akamai-transformed", r"akamai"],
    "Imperva": [r"x-iinfo", r"incap_ses"],
    "Azure Front Door": [r"x-azure-ref", r"azureedge\.net"],
    "Nginx": [r"server:\s*nginx"],
    "Apache": [r"server:\s*apache"],
}


class HTMLTitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title and not self.title:
            self.title = data.strip()


class HTTPEngine:
    def __init__(self, threads: int = 15, timeout: float = 5.0):
        self.threads = threads
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def probe_url(self, target_url: str) -> Optional[Dict[str, Any]]:
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
            },
        )

        try:
            start_time = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                elapsed = round((time.time() - start_time) * 1000, 2)
                status_code = resp.status
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                body_bytes = resp.read(100000)
                body_text = body_bytes.decode("utf-8", errors="ignore")

                # Title extraction
                parser = HTMLTitleParser()
                try:
                    parser.feed(body_text[:20000])
                    title = html.unescape(parser.title)
                except Exception:
                    title = ""

                headers_str = "\n".join([f"{k}: {v}" for k, v in headers_dict.items()])
                combined = f"{headers_str}\n\n{body_text}"

                # Tech Stack Identification
                technologies = []
                for tech, patterns in TECH_SIGNATURES.items():
                    for pat in patterns:
                        if re.search(pat, combined, re.IGNORECASE):
                            technologies.append(tech)
                            break

                # CDN/WAF Identification
                cdn_waf = None
                for cdn, patterns in CDN_WAF_SIGNATURES.items():
                    for pat in patterns:
                        if re.search(pat, combined, re.IGNORECASE):
                            cdn_waf = cdn
                            break

                # Automatic Service & Software Version Detection
                service_versions, version_findings = VersionDetector.detect(headers_dict, body_text)
                for svc, ver in service_versions.items():
                    label = f"{svc} {ver}" if ver and ver != "Detected" else svc
                    if label not in technologies and svc != "OS":
                        technologies.append(label)

                # Security Headers
                sec_headers = {
                    "hsts": "strict-transport-security" in headers_dict,
                    "csp": "content-security-policy" in headers_dict,
                    "x_frame_options": headers_dict.get("x-frame-options"),
                    "cors_allow_origin": headers_dict.get("access-control-allow-origin"),
                    "server": headers_dict.get("server"),
                }

                return {
                    "url": target_url,
                    "host": urllib.parse.urlparse(target_url).hostname,
                    "status_code": status_code,
                    "title": title or "No Title",
                    "content_length": len(body_bytes),
                    "latency_ms": elapsed,
                    "technologies": technologies,
                    "service_versions": service_versions,
                    "version_findings": version_findings,
                    "cdn_waf": cdn_waf,
                    "security_headers": sec_headers,
                    "html_sample": body_text[:30000],
                }
        except urllib.error.HTTPError as e:
            headers_dict = {k.lower(): v for k, v in e.headers.items()}
            service_versions, version_findings = VersionDetector.detect(headers_dict, "")
            tech_err = [f"{s} {v}" if v and v != "Detected" else s for s, v in service_versions.items() if s != "OS"]
            return {
                "url": target_url,
                "host": urllib.parse.urlparse(target_url).hostname,
                "status_code": e.code,
                "title": f"HTTP {e.code}",
                "content_length": 0,
                "latency_ms": 0,
                "technologies": tech_err,
                "service_versions": service_versions,
                "version_findings": version_findings,
                "cdn_waf": None,
                "security_headers": {
                    "hsts": "strict-transport-security" in headers_dict,
                    "csp": "content-security-policy" in headers_dict,
                    "server": headers_dict.get("server"),
                },
                "html_sample": "",
            }
        except Exception:
            return None

    def probe_host(self, host: str) -> Optional[Dict[str, Any]]:
        res = self.probe_url(f"https://{host}")
        if not res:
            res = self.probe_url(f"http://{host}")
        return res

    def run(self, live_hosts: List[str]) -> List[Dict[str, Any]]:
        web_services = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_host = {executor.submit(self.probe_host, h): h for h in live_hosts}
            for future in concurrent.futures.as_completed(future_to_host):
                try:
                    res = future.result()
                    if res:
                        web_services.append(res)
                except Exception:
                    pass

        return sorted(web_services, key=lambda x: x["url"])
