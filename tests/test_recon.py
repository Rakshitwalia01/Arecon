#!/usr/bin/env python3
"""
ARECON 2.0 Test Suite (tests/test_recon.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Tests:
- Scope Filtering
- Wildcard DNS Detection
- Normalized SQLite Store & History (ReconDB)
- JavaScript & API Recon (Source maps, route extraction, Swagger/OpenAPI)
- Authentication & Identity Mapping (OIDC, SAML, Login)
- Cloud Storage Exposure & CNAME Takeover Verification
- Asset Relationship Graph Topology
- Change Detection & Drift Tracking
- OWASP WSTG Hypothesis Prioritization
- End-to-End Pipeline Integration with Mock HTTP Server
"""

import http.server
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_ROOT)

import recon
from core import (
    ActiveScanner,
    ChangeDetector,
    CloudAnalyzer,
    DNSEngine,
    HTTPEngine,
    IdentityMapper,
    JSAPIScanner,
    PassiveDiscovery,
    ReconDB,
    ReconReporter,
    RelationshipGraph,
    ScopeFilter,
    SecurityHypothesisPrioritizer,
    VersionDetector,
    WebCrawler,
    WildcardDetector,
)


class MockHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "nginx/1.18.0")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Mock Enterprise Portal</title>
                <script src="/static/app.bundle.js"></script>
            </head>
            <body>
                <a href="/login">Login</a>
                <a href="/api/v1/users?id=123">API</a>
                <a href="/admin/portal">Admin</a>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode("utf-8"))

        elif self.path == "/static/app.bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            js_code = """
            const apiEndpoint = "/api/v2/payments";
            const oauthEndpoint = "/oauth/token";
            function fetchUser(userId) {
                return fetch("/api/v1/users/" + userId);
            }
            """
            self.wfile.write(js_code.encode("utf-8"))

        elif self.path == "/static/app.bundle.js.map":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"version": 3, "sources": ["src/index.js", "src/api.js"], "mappings": "AAAA"}).encode("utf-8"))

        elif self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Internal Payment API", "version": "2.1"},
                "paths": {
                    "/api/v2/payments": {
                        "get": {"summary": "List payments", "parameters": [{"name": "limit"}]},
                        "post": {"summary": "Create payment"}
                    }
                }
            }
            self.wfile.write(json.dumps(spec).encode("utf-8"))

        elif self.path == "/.well-known/openid-configuration":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            oidc = {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/oauth/authorize",
                "token_endpoint": "https://auth.example.com/oauth/token"
            }
            self.wfile.write(json.dumps(oidc).encode("utf-8"))

        elif self.path == "/saml/metadata":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(b"<EntityDescriptor entityID='https://example.com/sp'><SPSSODescriptor></SPSSODescriptor></EntityDescriptor>")

        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            robots_txt = "User-agent: *\nDisallow: /admin/secret\nDisallow: /internal/config\nSitemap: /sitemap.xml\n"
            self.wfile.write(robots_txt.encode("utf-8"))

        elif self.path == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <url><loc>http://127.0.0.1/about</loc></url>
              <url><loc>http://127.0.0.1/api/v3/status</loc></url>
            </urlset>"""
            self.wfile.write(sitemap_xml.encode("utf-8"))

        elif self.path == "/admin" or self.path == "/admin/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Admin Portal</h1></body></html>")

        elif "id='" in self.path:
            self.send_response(500)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            debug_error = """
            Django Version: 3.2.1
            Traceback (most recent call last):
              File "/var/www/app/views.py", line 42, in get
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            django.db.utils.OperationalError: near "'": syntax error
            """
            self.wfile.write(debug_error.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            self.rfile.read(content_len)
        if self.path == "/graphql":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": {"__schema": {"types": [{"name": "User"}]}}}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class TestARECONAdvancedModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockHTTPHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_arecon.db")
        self.db = ReconDB(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scope_enforcement(self):
        scope = ScopeFilter("target.com")
        scope.add_exclusion(r"^staging-.*")
        scope.add_exclusion(r"zendesk")

        self.assertTrue(scope.is_in_scope("target.com"))
        self.assertTrue(scope.is_in_scope("app.target.com"))
        self.assertFalse(scope.is_in_scope("othertarget.com"))
        self.assertFalse(scope.is_in_scope("staging-api.target.com"))
        self.assertFalse(scope.is_in_scope("zendesk.target.com"))

    def test_wildcard_detector_filter(self):
        detector = WildcardDetector("example.com")
        detector.has_wildcard = True
        detector.wildcard_ips = {"93.184.216.34"}

        self.assertTrue(detector.is_wildcard_host(["93.184.216.34"]))
        self.assertFalse(detector.is_wildcard_host(["1.2.3.4"]))

    def test_db_change_detection_and_drift(self):
        scan_id_1 = self.db.start_scan("target.com")
        # First scan: brand new asset
        is_new, changes = self.db.record_asset(
            scan_id=scan_id_1,
            root_domain="target.com",
            hostname="api.target.com",
            ips=["1.1.1.1"],
            status_code=200,
        )
        self.assertTrue(is_new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["change_type"], "NEW_SUBDOMAIN")

        # Second scan: IP changes and Status Code flips to 500
        scan_id_2 = self.db.start_scan("target.com")
        is_new_2, changes_2 = self.db.record_asset(
            scan_id=scan_id_2,
            root_domain="target.com",
            hostname="api.target.com",
            ips=["1.1.1.2"],
            status_code=500,
        )
        self.assertFalse(is_new_2)
        change_types = [c["change_type"] for c in changes_2]
        self.assertIn("IP_CHANGE", change_types)
        self.assertIn("STATUS_CHANGE", change_types)

        detector = ChangeDetector(self.db)
        drift = detector.get_drift_summary("target.com", scan_id_2)
        self.assertTrue(drift["has_drift"])
        self.assertEqual(drift["total_drift_events"], 2)

    def test_js_and_api_recon_against_mock(self):
        scanner = JSAPIScanner("127.0.0.1", timeout=3.0)
        base_url = f"http://127.0.0.1:{self.port}"
        
        # Test JS route extraction & source maps
        js_url = f"{base_url}/static/app.bundle.js"
        js_res = scanner.analyze_js_file(js_url)
        self.assertIn("/api/v2/payments", js_res["routes"])
        self.assertIn("/oauth/token", js_res["routes"])
        self.assertEqual(js_res["source_map"], f"{js_url}.map")

        # Test Swagger discovery
        specs = scanner.probe_swagger_openapi(base_url)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0]["title"], "Internal Payment API")

        # Test GraphQL introspection
        gql = scanner.probe_graphql(base_url)
        self.assertIsNotNone(gql)
        self.assertTrue(gql["introspection_enabled"])

    def test_identity_mapper_against_mock(self):
        mapper = IdentityMapper(timeout=3.0)
        base_url = f"http://127.0.0.1:{self.port}"
        id_res = mapper.map_identity(base_url)

        self.assertIsNotNone(id_res["oidc_configuration"])
        self.assertEqual(id_res["oidc_configuration"]["issuer"], "https://auth.example.com")
        self.assertIsNotNone(id_res["saml_metadata"])

    def test_relationship_graph_generation(self):
        graph = RelationshipGraph("target.com")
        graph.build_from_scan_data(
            assets=[{"hostname": "app.target.com", "ips": ["10.0.0.1"], "cname": "app.cloudfront.net"}],
            web_inventory=[{"url": "https://app.target.com", "technologies": ["Next.js", "React"], "cdn_waf": "AWS CloudFront"}],
            js_api_data=[{"base_url": "https://app.target.com", "extracted_api_routes": ["/api/v1/auth"]}],
            cloud_buckets=[{"url": "https://target-assets.s3.amazonaws.com", "provider": "AWS S3"}],
        )

        graph_json = graph.to_json()
        self.assertGreater(len(graph_json["nodes"]), 4)
        self.assertGreater(len(graph_json["links"]), 4)

        mermaid = graph.to_mermaid()
        self.assertIn("```mermaid", mermaid)
        self.assertIn("target.com", mermaid)

    def test_version_detection_engine(self):
        headers = {
            "server": "nginx/1.18.0 (Ubuntu)",
            "x-powered-by": "PHP/7.4.33",
            "x-aspnet-version": "4.0.30319",
        }
        html_text = """
        <html>
        <head>
            <meta name="generator" content="WordPress 5.8.1" />
            <script src="/js/jquery-3.4.1.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </head>
        <body ng-version="14.2.0">
            <!-- /*! Vue.js v2.6.14 */ -->
        </body>
        </html>
        """
        versions, findings = VersionDetector.detect(headers, html_text)
        self.assertEqual(versions.get("Nginx"), "1.18.0")
        self.assertEqual(versions.get("PHP"), "7.4.33")
        self.assertEqual(versions.get("WordPress"), "5.8.1")
        self.assertEqual(versions.get("jQuery"), "3.4.1")
        self.assertEqual(versions.get("Bootstrap"), "5.1.3")
        self.assertEqual(versions.get("Angular"), "14.2.0")
        self.assertEqual(versions.get("Vue.js"), "2.6.14")

        # Test security auditing of EOL / vulnerable versions
        vuln_types = [f["type"] for f in findings]
        self.assertIn("OUTDATED_OR_EOL", vuln_types)
        self.assertIn("VERSION_DISCLOSURE", vuln_types)

        eol_services = [f["service"] for f in findings if f["type"] == "OUTDATED_OR_EOL"]
        self.assertIn("PHP", eol_services)
        self.assertIn("WordPress", eol_services)
        self.assertIn("jQuery", eol_services)

    def test_db_version_change_drift(self):
        scan_id_1 = self.db.start_scan("versiontest.com")
        self.db.record_asset(
            scan_id=scan_id_1,
            root_domain="versiontest.com",
            hostname="web.versiontest.com",
            ips=["1.1.1.1"],
            service_versions={"Nginx": "1.18.0", "PHP": "7.4.33"},
        )

        scan_id_2 = self.db.start_scan("versiontest.com")
        _, changes = self.db.record_asset(
            scan_id=scan_id_2,
            root_domain="versiontest.com",
            hostname="web.versiontest.com",
            ips=["1.1.1.1"],
            service_versions={"Nginx": "1.20.1", "PHP": "8.1.0"},
        )
        change_types = [c["change_type"] for c in changes]
        self.assertIn("VERSION_CHANGE", change_types)

    def test_takeover_verification_logic(self):
        analyzer = CloudAnalyzer("target.com")
        # Test known signature mapping
        result = analyzer.verify_takeover("invalid-test.target.com", "test.s3.amazonaws.com")
        # Won't connect in unit test, but verifies the logic executes without exception
        self.assertTrue(result is None or isinstance(result, dict))


    def test_pipeline_integration(self):
        base_url = f"http://127.0.0.1:{self.port}"
        # Test full end-to-end pipeline against local mock
        res = recon.run_pipeline(
            target_domain="127.0.0.1",
            output_dir=self.temp_dir,
            active_crawl=False,
            threads=2,
            timeout=3,
            db=self.db,
        )
        self.assertEqual(res["target"], "127.0.0.1")
        self.assertGreater(len(res["dns_assets"]), 0)
        self.assertTrue(os.path.exists(res["report_file"]))
        with open(res["report_file"], "r", encoding="utf-8") as f:
            report_text = f.read()
        self.assertIn("ARECON Attack Surface Intelligence Report", report_text)

    def test_active_scan_scope_rejection(self):
        scope = ScopeFilter("target.com")
        scope.add_exclusion(r"^internal-.*")
        scanner = ActiveScanner(scope, self.db, {"target_domain": "target.com"})

        self.assertTrue(scanner.is_target_in_scope("app.target.com"))
        self.assertTrue(scanner.is_target_in_scope("https://api.target.com/v1"))
        self.assertFalse(scanner.is_target_in_scope("attacker.com"))
        self.assertFalse(scanner.is_target_in_scope("https://internal-db.target.com"))
        self.assertFalse(scanner.is_target_in_scope("google.com"))

    def test_robots_and_sitemap_parsing(self):
        scope = ScopeFilter("127.0.0.1")
        scan_id = self.db.start_scan("127.0.0.1")
        scanner = ActiveScanner(scope, self.db, {"target_domain": "127.0.0.1", "scan_id": scan_id})

        discovered = scanner.parse_robots_and_sitemap(f"127.0.0.1:{self.port}", protocol="http")
        self.assertTrue(any("/admin/secret" in u for u in discovered))
        self.assertTrue(any("/internal/config" in u for u in discovered))
        self.assertTrue(any("/about" in u for u in discovered))

        endpoints = self.db.get_endpoints("127.0.0.1")
        ep_urls = [e["url"] for e in endpoints]
        self.assertTrue(any("/admin/secret" in u for u in ep_urls))

    def test_nmap_scan_xml_parsing_and_db_persistence(self):
        scope = ScopeFilter("127.0.0.1")
        scan_id = self.db.start_scan("127.0.0.1")
        # Ensure asset exists in DB
        self.db.record_asset(scan_id=scan_id, root_domain="127.0.0.1", hostname="127.0.0.1", ips=["127.0.0.1"])

        scanner = ActiveScanner(scope, self.db, {"target_domain": "127.0.0.1", "scan_id": scan_id})

        sample_nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <hostnames><hostname name="127.0.0.1" type="user"/></hostnames>
            <ports>
              <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
              <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="OpenSSL" version="1.1.1"/></port>
              <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.28"/></port>
            </ports>
          </host>
        </nmaprun>
        """

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = sample_nmap_xml

        with patch("shutil.which", return_value="/usr/local/bin/nmap"):
            with patch("subprocess.run", return_value=mock_proc):
                results = scanner.run_nmap_scan(["127.0.0.1"])
                self.assertEqual(len(results), 3)
                ports = [r["port"] for r in results]
                self.assertIn(80, ports)
                self.assertIn(443, ports)
                self.assertIn(3306, ports)

                db_ports = self.db.get_open_ports("127.0.0.1")
                self.assertEqual(len(db_ports), 3)

    def test_dirbrute_python_fallback(self):
        scope = ScopeFilter("127.0.0.1")
        scan_id = self.db.start_scan("127.0.0.1")
        scanner = ActiveScanner(scope, self.db, {
            "target_domain": "127.0.0.1",
            "scan_id": scan_id,
            "rate_limit_delay": 0.0,
        })

        base_url = f"http://127.0.0.1:{self.port}"
        discovered = scanner.run_dirbrute(base_url)
        discovered_paths = [d["path"] for d in discovered]
        self.assertIn("/admin", discovered_paths)

    def test_error_harvesting_stack_trace_detection(self):
        scope = ScopeFilter("127.0.0.1")
        scanner = ActiveScanner(scope, self.db, {"target_domain": "127.0.0.1", "rate_limit_delay": 0.0})

        base_url = f"http://127.0.0.1:{self.port}"
        disclosures = scanner.harvest_error_pages(base_url)
        self.assertGreater(len(disclosures), 0)
        finding = disclosures[0]
        self.assertEqual(finding["technology"], "Django")
        self.assertEqual(finding["hypothesis"]["category"], "Error Handling (WSTG-ERRH-01)")

    def test_third_party_integration_signatures(self):
        scope = ScopeFilter("example.com")
        scanner = ActiveScanner(scope, self.db, {"target_domain": "example.com"})

        html_sample = """
        <html>
        <head>
            <script src="https://js.stripe.com/v3/"></script>
            <script src="https://www.paypal.com/sdk/js?client-id=sb"></script>
            <script async src="https://www.googletagmanager.com/gtag/js?id=G-12345"></script>
            <script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script>
            <script src="https://www.datadoghq-browser-agent.com/datadog-rum-v4.js"></script>
        </head>
        <body><h1>Payment Portal</h1></body>
        </html>
        """

        integrations = scanner.map_third_party_integrations(html_sample, "pay.example.com")
        names = [i["integration"] for i in integrations]
        self.assertIn("Stripe", names)
        self.assertIn("PayPal", names)
        self.assertIn("Google Analytics", names)
        self.assertIn("Sentry", names)
        self.assertIn("Datadog", names)

        # Check database records
        db_itg = self.db.get_integrations("example.com", "pay.example.com")
        self.assertEqual(len(db_itg), 5)

    def test_tls_audit_fallback(self):
        scope = ScopeFilter("127.0.0.1")
        scanner = ActiveScanner(scope, self.db, {"target_domain": "127.0.0.1"})
        res = scanner.audit_tls("127.0.0.1", port=self.port)
        # Verify structure returned without throwing unhandled exceptions
        self.assertIsInstance(res, dict)
        self.assertIn("vulnerabilities", res)
        self.assertIn("weak_protocols", res)

    def test_pipeline_with_active_scan_flags(self):
        res = recon.run_pipeline(
            target_domain="127.0.0.1",
            output_dir=self.temp_dir,
            threads=2,
            timeout=3,
            db=self.db,
            active_scan=False,
            robots_scan=True,
            dirbrute=False,
            tls_audit=False,
        )
        self.assertIn("active_findings", res)
        self.assertIn("integrations", res)
        self.assertTrue(os.path.exists(res["report_file"]))
        with open(res["report_file"], "r", encoding="utf-8") as f:
            report_text = f.read()
        self.assertIn("ARECON Attack Surface Intelligence Report", report_text)


if __name__ == "__main__":
    unittest.main()
