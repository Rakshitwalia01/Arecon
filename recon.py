#!/usr/bin/env python3
"""
ARECON 2.0 — Advanced Attack Surface Management & Bug Bounty Reconnaissance Engine
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License
Platform: Windows, macOS, Linux

Features:
- Normalized SQLite Asset Store & History Tracking
- Multi-Source Passive Discovery with Confidence Scoring
- Wildcard DNS Detection & False-Positive Elimination
- IPv4 & IPv6 Resolution, CNAME Chains, and Takeover Verification
- Deep HTTP & Framework Clustering (Next.js, React, Vue, Express, Metabase, etc.)
- JavaScript Recon: Source Map (.js.map) Exposure, Client-Side API Route & Param Extraction
- OpenAPI/Swagger & GraphQL Introspection Discovery
- Authentication & Identity Flow Mapping (OIDC, OAuth, SAML, Account Lifecycle)
- Cloud & Storage Permutations (AWS S3, Google Cloud Storage, Azure Blob)
- Active Port & Service Scanning with Nmap and pure-Python socket fallback
- Zero-Guessing Robots.txt and Sitemap.xml path extraction
- Soft-404 baseline directory and endpoint bruteforcing (ffuf / Python)
- Pure-Python TLS Configuration & Certificate Expiration Audit
- Verbose Error Page / Stack Trace Harvesting (WSTG-ERRH-01)
- Offline Third-Party Integration Signature Mapping (25+ services)
- Asset Relationship Graph Generation (JSON & Mermaid Topology)
- Historical Change Detection & Attack Surface Drift Audit
- OWASP WSTG Hypothesis Prioritization
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure RECON root is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Enable ANSI escape sequences on Windows console
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

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
    WebCrawler,
    WildcardDetector,
)

# Terminal ANSI colors
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log_info(msg: str):
    print(f"{BLUE}[INFO]{RESET} {msg}")


def log_success(msg: str):
    print(f"{GREEN}[SUCCESS]{RESET} {msg}")


def log_warn(msg: str):
    print(f"{YELLOW}[WARN]{RESET} {msg}")


def log_error(msg: str):
    print(f"{RED}[ERROR]{RESET} {msg}", file=sys.stderr)


def run_pipeline(
    target_domain: str,
    scope_file: Optional[str] = None,
    output_dir: str = "./recon_output",
    active_crawl: bool = False,
    threads: int = 15,
    timeout: int = 5,
    db: Optional[ReconDB] = None,
    active_scan: bool = False,
    dirbrute: bool = False,
    tls_audit: bool = False,
    robots_scan: bool = False,
    wordlist: Optional[str] = None,
    nmap_timing: str = "-T3",
    full_ports: bool = False,
) -> Dict[str, Any]:
    target = target_domain.lower().strip()
    target_out_dir = os.path.join(output_dir, target)
    os.makedirs(target_out_dir, exist_ok=True)

    if db is None:
        db = ReconDB()

    scan_id = db.start_scan(target)

    print(f"\n{BOLD}{CYAN}=============================================================={RESET}")
    print(f"{BOLD}{CYAN} ARECON 2.0 ADVANCED ATTACK SURFACE ENGINE{RESET}")
    print(f" Target: {BOLD}{target}{RESET} | Scan ID: #{scan_id}")
    print(f"{BOLD}{CYAN}=============================================================={RESET}\n")

    # 1. Scope Governance
    log_info("Stage 1: Enforcing Scope Governance & Exclusions...")
    scope = ScopeFilter(target, scope_file)

    # 2. Wildcard DNS Detection
    log_info("Stage 2: Probing for Wildcard DNS zones...")
    wc_detector = WildcardDetector(target, timeout=float(timeout))
    has_wc, wc_ips = wc_detector.detect()
    if has_wc:
        log_warn(f"Wildcard DNS detected for {target}! Wildcard IPs: {', '.join(wc_ips)}")
    else:
        log_success("No wildcard DNS interference detected.")

    # 3. Multi-Source Passive Discovery
    log_info("Stage 3: Multi-Source Passive Subdomain Discovery...")
    passive = PassiveDiscovery(target, scope, timeout=timeout)
    passive_results = passive.run()
    candidate_hosts = [p["hostname"] for p in passive_results]
    log_success(f"Discovered {len(candidate_hosts)} unique candidate hostnames across independent feeds.")

    # 4. DNS Resolution & IPv4/IPv6 Validation
    log_info(f"Stage 4: Multi-Threaded DNS Resolution ({threads} workers)...")
    dns_engine = DNSEngine(target, wc_detector, threads=threads, timeout=float(timeout))
    dns_assets = dns_engine.run(candidate_hosts)

    # Filter out wildcard-generated hosts
    valid_dns_assets = [d for d in dns_assets if not d.get("is_wildcard")]
    live_hosts = [d["host"] for d in valid_dns_assets]
    log_success(f"Resolved {len(valid_dns_assets)} live, in-scope hosts (filtered {len(dns_assets) - len(valid_dns_assets)} wildcard records).")

    # 5. Cloud Storage Permutations & Takeover Verification
    log_info("Stage 5: Analyzing Cloud Storage Buckets & Dangling CNAMEs...")
    cloud_analyzer = CloudAnalyzer(target, timeout=float(timeout))
    cloud_buckets = cloud_analyzer.scan_storage_buckets()
    if cloud_buckets:
        log_warn(f"Discovered {len(cloud_buckets)} cloud storage bucket references!")
    else:
        log_info("No public storage buckets exposed on brand permutations.")

    # Verify potential takeovers
    takeover_findings = []
    for d in valid_dns_assets:
        cname = d.get("cname")
        if cname:
            t_res = cloud_analyzer.verify_takeover(d["host"], cname)
            if t_res:
                takeover_findings.append(t_res)
                if t_res.get("vulnerable"):
                    log_warn(f"CRITICAL: Subdomain takeover possible on {d['host']} -> {cname} ({t_res.get('service')})")

    # 6. HTTP Probing & Technology Clustering
    log_info(f"Stage 6: Probing HTTP/HTTPS services across {len(live_hosts)} hosts...")
    http_engine = HTTPEngine(threads=threads, timeout=float(timeout))
    web_inventory = http_engine.run(live_hosts)
    log_success(f"Identified {len(web_inventory)} responsive web applications.")

    # 7. JavaScript Deep Recon & API Schema Discovery
    log_info("Stage 7: JavaScript Bundle Analysis & API Extraction...")
    js_scanner = JSAPIScanner(target, timeout=float(timeout))
    js_api_results = []
    for item in web_inventory[:10]:
        html_sample = item.get("html_sample", "")
        if html_sample:
            js_res = js_scanner.scan_web_service(item["url"], html_sample)
            js_api_results.append(js_res)

    # 8. Authentication & Identity Flow Mapping
    log_info("Stage 8: Authentication & Identity Entry Point Discovery...")
    identity_mapper = IdentityMapper(timeout=float(timeout))
    identity_findings = []
    for item in web_inventory[:5]:
        id_res = identity_mapper.map_identity(item["url"])
        identity_findings.append(id_res)

    # 9. Web Crawling & Historical URL Collection
    log_info("Stage 9: URL Collection & Historical Route Mapping...")
    crawler = WebCrawler(target, scope, timeout=timeout)
    live_urls = [item["url"] for item in web_inventory]
    all_endpoints = crawler.run(live_urls, active=active_crawl)

    # Add client-side routes discovered via JS scanner
    for js_item in js_api_results:
        base_u = js_item.get("base_url", "")
        for route in js_item.get("extracted_api_routes", []):
            full_route_url = f"{base_u}{route}" if not route.startswith("http") else route
            all_endpoints.append(full_route_url)

    all_endpoints = sorted(list(set(all_endpoints)))
    log_success(f"Total catalogued attack surface: {len(all_endpoints)} routes & API endpoints.")

    # 10. Third-Party Integration Signature Mapping & Active Recon
    active_scanner = ActiveScanner(
        scope=scope,
        db=db,
        config={
            "scan_id": scan_id,
            "target_domain": target,
            "nmap_timing": nmap_timing,
            "full_ports": full_ports,
            "wordlist": wordlist,
            "timeout": float(timeout),
            "concurrency": threads,
            "active_scan": active_scan,
            "dirbrute": dirbrute,
            "tls_audit": tls_audit,
            "robots_scan": robots_scan,
        },
    )

    integrations = []
    for item in web_inventory:
        html_sample = item.get("html_sample", "")
        if html_sample:
            itg = active_scanner.map_third_party_integrations(html_sample, item["host"])
            integrations.extend(itg)

    # Active Scanning & Network Assessment (Opt-in sub-steps)
    active_findings = {
        "open_ports": [],
        "robots_endpoints": [],
        "dirbrute_endpoints": [],
        "tls_findings": [],
        "error_disclosures": [],
        "integrations": integrations,
        "hypotheses": [],
    }

    if active_scan or dirbrute or tls_audit or robots_scan:
        log_info("Stage: Active Reconnaissance & Network Assessment...")
        active_findings = active_scanner.execute()
        active_findings["integrations"] = integrations

        # Feed discovered endpoints into attack surface
        for ep in active_findings.get("robots_endpoints", []):
            all_endpoints.append(ep)
        for ep_obj in active_findings.get("dirbrute_endpoints", []):
            if isinstance(ep_obj, dict) and "url" in ep_obj:
                all_endpoints.append(ep_obj["url"])
            elif isinstance(ep_obj, str):
                all_endpoints.append(ep_obj)

        all_endpoints = sorted(list(set(all_endpoints)))
        if active_findings.get("open_ports"):
            log_success(f"Active scan identified {len(active_findings['open_ports'])} open network ports & services.")

    # 11. Record Assets into Normalized SQLite Store
    new_assets_count = 0
    for d in valid_dns_assets:
        matching_web = next((w for w in web_inventory if w["host"] == d["host"]), None)
        status_code = matching_web["status_code"] if matching_web else None
        title = matching_web["title"] if matching_web else None
        technologies = matching_web["technologies"] if matching_web else []
        service_versions = matching_web.get("service_versions", {}) if matching_web else {}
        cdn_waf = matching_web["cdn_waf"] if matching_web else None
        sec_headers = matching_web["security_headers"] if matching_web else {}

        matching_takeover = next((t for t in takeover_findings if t["host"] == d["host"]), None)
        takeover_risk = matching_takeover.get("proof") if matching_takeover else None

        is_new, _ = db.record_asset(
            scan_id=scan_id,
            root_domain=target,
            hostname=d["host"],
            ips=d["ips"],
            cname=d.get("cname"),
            is_wildcard=d.get("is_wildcard", False),
            status_code=status_code,
            title=title,
            technologies=technologies,
            service_versions=service_versions,
            cdn_waf=cdn_waf,
            security_headers=sec_headers,
            takeover_risk=takeover_risk,
        )
        if is_new:
            new_assets_count += 1

    # Record Endpoints into SQLite
    for ep in all_endpoints:
        ep_type = "Generic"
        if "/api/" in ep.lower() or "/v1/" in ep.lower():
            ep_type = "API"
        elif any(k in ep.lower() for k in ("/login", "/auth", "/oauth", "/sso")):
            ep_type = "Auth"
        elif any(k in ep.lower() for k in ("/admin", "/portal", "/dashboard")):
            ep_type = "Admin"
        elif "/graphql" in ep.lower():
            ep_type = "GraphQL"

        db.record_endpoint(
            scan_id=scan_id,
            root_domain=target,
            url=ep,
            path=ep.split("://")[-1].split("/", 1)[-1] if "/" in ep.split("://")[-1] else "/",
            endpoint_type=ep_type,
        )

    # 11. Build Asset Relationship Graph
    log_info("Stage 10: Generating Asset Relationship Graph...")
    graph = RelationshipGraph(target)
    graph.build_from_scan_data(valid_dns_assets, web_inventory, js_api_results, cloud_buckets)
    mermaid_graph = graph.to_mermaid()

    # 12. Change Detection & Attack Surface Drift
    change_detector = ChangeDetector(db)
    drift_data = change_detector.get_drift_summary(target, scan_id)

    # 13. OWASP WSTG Prioritization
    log_info("Stage 11: Prioritizing Security Hypotheses (OWASP WSTG)...")
    hypotheses = SecurityHypothesisPrioritizer.evaluate(
        endpoints=all_endpoints,
        web_inventory=web_inventory,
        js_api_data=js_api_results,
        cloud_buckets=cloud_buckets,
        takeovers=takeover_findings,
        active_findings=active_findings,
    )

    # 14. Finish scan & write reports
    db.finish_scan(
        scan_id=scan_id,
        candidates=len(candidate_hosts),
        live_hosts=len(valid_dns_assets),
        live_services=len(web_inventory),
        endpoints=len(all_endpoints),
        new_assets=new_assets_count,
    )

    # Markdown Report
    report_file = os.path.join(target_out_dir, "report.md")
    ReconReporter.generate_markdown(
        target_domain=target,
        candidates=passive_results,
        dns_assets=valid_dns_assets,
        web_inventory=web_inventory,
        endpoints=all_endpoints,
        hypotheses=hypotheses,
        drift_data=drift_data,
        js_api_data=js_api_results,
        cloud_buckets=cloud_buckets,
        mermaid_graph=mermaid_graph,
        output_file=report_file,
        active_findings=active_findings,
        integrations=integrations,
    )

    # Graph JSON export
    graph_json_file = os.path.join(target_out_dir, "relationship_graph.json")
    with open(graph_json_file, "w", encoding="utf-8") as f:
        json.dump(graph.to_json(), f, indent=2)

    total_service_versions = sum(len(w.get("service_versions", {})) for w in web_inventory)

    # Print summary
    print("\n" + "=" * 65)
    print(f"{BOLD}{CYAN} ARECON 2.0 ATTACK SURFACE SUMMARY: {target}{RESET}")
    print("=" * 65)
    print(f"  • Passive Candidate Hosts:    {len(candidate_hosts)}")
    print(f"  • Live Resolved DNS Assets:   {len(valid_dns_assets)}")
    print(f"  • Responsive Web Services:    {len(web_inventory)}")
    print(f"  • Service Versions Checked:   {total_service_versions}")
    print(f"  • Discovered Endpoints/APIs:  {len(all_endpoints)}")
    print(f"  • Prioritized OWASP Findings: {len(hypotheses)}")
    print(f"  • Attack Surface Drift Events: {drift_data['total_drift_events']}")
    print(f"  • Cloud Storage Disclosures:  {len(cloud_buckets)}")
    if active_findings.get("open_ports"):
        print(f"  • Open Ports / Services:      {len(active_findings['open_ports'])}")
    if integrations:
        print(f"  • Third-Party Integrations:   {len(integrations)}")
    if active_findings.get("tls_findings"):
        print(f"  • TLS Hosts Audited:          {len(active_findings['tls_findings'])}")
    print("-" * 65)
    if hypotheses:
        print(f"{BOLD}Top Priority Security Hypotheses:{RESET}")
        for h in hypotheses[:5]:
            p_color = RED if h["priority"] in ("CRITICAL", "HIGH") else (YELLOW if h["priority"] == "MEDIUM" else BLUE)
            print(f"  [{p_color}{h['priority']}{RESET}] {h['category']} -> {h['target']}")
            print(f"       Hypothesis: {h['hypothesis']}")
    print("=" * 65 + "\n")
    log_success(f"Reconnaissance complete! Report: {report_file}")

    return {
        "target": target,
        "scan_id": scan_id,
        "candidates": candidate_hosts,
        "dns_assets": valid_dns_assets,
        "web_inventory": web_inventory,
        "endpoints": all_endpoints,
        "hypotheses": hypotheses,
        "drift_data": drift_data,
        "js_api_data": js_api_results,
        "cloud_buckets": cloud_buckets,
        "active_findings": active_findings,
        "integrations": integrations,
        "graph_json": graph.to_json(),
        "report_file": report_file,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ARECON 2.0 — Advanced Attack Surface Management & Bug Bounty Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", required=True, help="Target root domain (e.g. example.com)")
    parser.add_argument("-s", "--scope", default=None, help="File containing out-of-scope regex exclusions")
    parser.add_argument("-o", "--output", default="./recon_output", help="Output directory")
    parser.add_argument("--active", action="store_true", help="Enable active application crawling & spidering")
    parser.add_argument("--threads", type=int, default=15, help="Concurrency worker threads (default: 15)")
    parser.add_argument("--timeout", type=int, default=5, help="Network timeout in seconds (default: 5)")
    parser.add_argument("--active-scan", action="store_true", help="Enable active Nmap/socket port & service scanning")
    parser.add_argument("--dirbrute", action="store_true", help="Enable directory and endpoint bruteforcing")
    parser.add_argument("--tls-audit", action="store_true", help="Enable TLS configuration & certificate security audit")
    parser.add_argument("--robots-scan", action="store_true", help="Scrape and parse robots.txt and sitemap.xml")
    parser.add_argument("--wordlist", default=None, help="Custom wordlist path for directory bruteforcing")
    parser.add_argument("--nmap-timing", default="-T3", choices=["-T2", "-T3", "-T4"], help="Nmap timing template (default: -T3)")
    parser.add_argument("--full-ports", action="store_true", help="Scan full port range (1-65535) instead of top 1000")

    args = parser.parse_args()
    run_pipeline(
        target_domain=args.domain,
        scope_file=args.scope,
        output_dir=args.output,
        active_crawl=args.active,
        threads=args.threads,
        timeout=args.timeout,
        active_scan=args.active_scan,
        dirbrute=args.dirbrute,
        tls_audit=args.tls_audit,
        robots_scan=args.robots_scan,
        wordlist=args.wordlist,
        nmap_timing=args.nmap_timing,
        full_ports=args.full_ports,
    )


if __name__ == "__main__":
    main()
