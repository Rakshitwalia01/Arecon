#!/usr/bin/env python3
"""
ARECON JavaScript & API Reconnaissance Engine (core/js_api_scanner.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Deep extraction of:
- JavaScript bundles & Source Maps (.js.map)
- Client-side route & API endpoint discovery
- Parameter harvesting
- OpenAPI / Swagger documentation schema parsing
- GraphQL endpoint & introspection detection
"""

import concurrent.futures
import html
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

USER_AGENT = "Mozilla/5.0 (compatible; ARECON-APIScanner/2.0; +https://authorized-bugbounty.org)"

# Regex patterns for API route discovery in JS files
JS_ROUTE_PATTERNS = [
    re.compile(r"""(?:["'`])(/(?:api|v[0-9]+|rest|graphql|oauth|auth|admin|portal|internal)/[a-zA-Z0-9_\-/{}.]+)(?:["'`])"""),
    re.compile(r"""(?:path|url|endpoint|route)\s*:\s*["'`](/[a-zA-Z0-9_\-/{}.]+)["'`]"""),
    re.compile(r"""fetch\s*\(\s*["'`](/[a-zA-Z0-9_\-/{}.]+)["'`]"""),
    re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*["'`](/[a-zA-Z0-9_\-/{}.]+)["'`]"""),
]

# Parameter patterns in JS or URLs
PARAM_PATTERNS = [
    re.compile(r"""[?&]([a-zA-Z0-9_\-]+)="""),
    re.compile(r"""(?:params|data|body)\s*:\s*\{\s*([a-zA-Z0-9_\-]+)\s*:"""),
    re.compile(r"""(?:query|variables)\s*:\s*\{\s*([a-zA-Z0-9_\-]+)\s*:"""),
]

SWAGGER_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api/documentation",
    "/docs",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphiql",
    "/graphql/console",
]


class JSAPIScanner:
    def __init__(self, target_domain: str, timeout: float = 4.0, max_js_files: int = 15):
        self.target_domain = target_domain.lower().strip()
        self.timeout = timeout
        self.max_js_files = max_js_files

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _safe_request(self, url: str, method: str = "GET", data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        req_headers = {"User-Agent": USER_AGENT}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read(200000)  # Read up to 200KB
                return status, resp_headers, body
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, b""
        except Exception:
            return 0, {}, b""

    def check_source_map(self, js_url: str) -> Optional[str]:
        """Checks if a corresponding .js.map file is publicly accessible."""
        map_url = js_url + ".map"
        status, headers, body = self._safe_request(map_url)
        if status == 200 and len(body) > 10:
            try:
                # Validate if it's actual JSON source map
                data = json.loads(body.decode("utf-8", errors="ignore"))
                if "sources" in data or "mappings" in data:
                    return map_url
            except Exception:
                pass
        return None

    def analyze_js_file(self, js_url: str) -> Dict[str, Any]:
        """Fetches and parses a JavaScript file to extract hidden API routes and parameters."""
        status, _, body = self._safe_request(js_url)
        discovered_routes = set()
        discovered_params = set()
        source_map = None

        if status == 200 and body:
            js_text = body.decode("utf-8", errors="ignore")

            # Route extraction
            for pat in JS_ROUTE_PATTERNS:
                for match in pat.findall(js_text):
                    clean_match = match.split("?")[0].strip()
                    if len(clean_match) > 1 and not clean_match.endswith((".png", ".jpg", ".svg", ".css")):
                        discovered_routes.add(clean_match)

            # Parameter extraction
            for pat in PARAM_PATTERNS:
                for match in pat.findall(js_text):
                    if len(match) > 1 and match not in ("true", "false", "null", "undefined"):
                        discovered_params.add(match)

            # Check source map
            source_map = self.check_source_map(js_url)

        return {
            "js_url": js_url,
            "routes": sorted(list(discovered_routes)),
            "parameters": sorted(list(discovered_params)),
            "source_map": source_map,
        }

    def probe_swagger_openapi(self, base_url: str) -> List[Dict[str, Any]]:
        """Probes for exposed Swagger / OpenAPI specifications and extracts documented endpoints."""
        discovered_specs = []
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in SWAGGER_PATHS:
            target_url = urllib.parse.urljoin(origin, path)
            status, _, body = self._safe_request(target_url)
            if status == 200 and body:
                try:
                    data = json.loads(body.decode("utf-8", errors="ignore"))
                    paths = data.get("paths", {})
                    if isinstance(paths, dict) and paths:
                        extracted_routes = []
                        for route, methods in paths.items():
                            if isinstance(methods, dict):
                                for method, details in methods.items():
                                    extracted_routes.append({
                                        "path": route,
                                        "method": method.upper(),
                                        "summary": details.get("summary", ""),
                                        "parameters": [p.get("name") for p in details.get("parameters", []) if isinstance(p, dict)],
                                    })
                        discovered_specs.append({
                            "spec_url": target_url,
                            "title": data.get("info", {}).get("title", "OpenAPI Spec"),
                            "version": data.get("info", {}).get("version", "1.0"),
                            "routes": extracted_routes,
                        })
                        break
                except Exception:
                    pass
        return discovered_specs

    def probe_graphql(self, base_url: str) -> Optional[Dict[str, Any]]:
        """Checks for GraphQL endpoint and probes for schema introspection."""
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in GRAPHQL_PATHS:
            gql_url = urllib.parse.urljoin(origin, path)
            # Try a lightweight query
            test_query = json.dumps({"query": "{ __typename }"}).encode("utf-8")
            status, _, body = self._safe_request(
                gql_url,
                method="POST",
                data=test_query,
                headers={"Content-Type": "application/json"},
            )

            if status == 200 and body:
                try:
                    data = json.loads(body.decode("utf-8", errors="ignore"))
                    if "data" in data or "errors" in data:
                        # Test if introspection is open
                        intro_query = json.dumps({"query": "{ __schema { types { name } } }"}).encode("utf-8")
                        s_intro, _, b_intro = self._safe_request(
                            gql_url,
                            method="POST",
                            data=intro_query,
                            headers={"Content-Type": "application/json"},
                        )
                        introspection_open = False
                        if s_intro == 200 and b"__schema" in b_intro:
                            introspection_open = True

                        return {
                            "graphql_url": gql_url,
                            "introspection_enabled": introspection_open,
                        }
                except Exception:
                    pass
        return None

    def scan_web_service(self, base_url: str, html_content: str) -> Dict[str, Any]:
        """Full JS and API scan for a given live web service."""
        # 1. Extract script tags
        script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html_content, re.IGNORECASE)
        js_urls = []
        for src in script_srcs:
            if not src.startswith(("data:", "javascript:")):
                abs_url = urllib.parse.urljoin(base_url, src)
                js_urls.append(abs_url)

        # 2. Analyze JS files concurrently (up to max_js_files)
        js_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self.analyze_js_file, u): u for u in js_urls[:self.max_js_files]}
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    res = future.result()
                    if res:
                        js_results.append(res)
                except Exception:
                    pass

        # 3. Probe OpenAPI / Swagger
        specs = self.probe_swagger_openapi(base_url)

        # 4. Probe GraphQL
        graphql = self.probe_graphql(base_url)

        # Aggregate routes and params
        all_routes = set()
        all_params = set()
        exposed_maps = []

        for js_res in js_results:
            all_routes.update(js_res["routes"])
            all_params.update(js_res["parameters"])
            if js_res["source_map"]:
                exposed_maps.append(js_res["source_map"])

        return {
            "base_url": base_url,
            "js_files_analyzed": len(js_results),
            "source_maps_exposed": exposed_maps,
            "extracted_api_routes": sorted(list(all_routes)),
            "harvested_parameters": sorted(list(all_params)),
            "openapi_specs": specs,
            "graphql_endpoint": graphql,
        }
