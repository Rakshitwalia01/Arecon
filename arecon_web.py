#!/usr/bin/env python3
"""
ARECON 2.0 — Web Application Reconnaissance & Attack Surface Management GUI
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License
Platform: Windows, macOS, Linux
Theme: Clean White Background, Red Buttons, Black Text
"""

import http.server
import json
import os
import re
import socketserver
import sys
import threading
import time
import urllib.parse
import webbrowser
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from core.db import ReconDB
import recon

# Global scan state
CURRENT_SCAN: Dict[str, Any] = {
    "is_running": False,
    "target": "",
    "phase": "IDLE",
    "progress": 0,
    "logs": [],
    "candidates": [],
    "dns_assets": [],
    "web_inventory": [],
    "endpoints": [],
    "hypotheses": [],
    "drift_data": None,
    "js_api_data": [],
    "cloud_buckets": [],
    "graph_json": None,
    "report_md": "",
    "error": None,
    "active_findings": {},
    "integrations": [],
}
SCAN_LOCK = threading.Lock()
DB = ReconDB()


def append_log(msg: str):
    with SCAN_LOCK:
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] {msg}"
        CURRENT_SCAN["logs"].append(entry)


def run_recon_job(
    target: str,
    scope_text: str,
    active_crawl: bool,
    threads: int,
    timeout: int,
    active_scan: bool = False,
    dirbrute: bool = False,
    tls_audit: bool = False,
    robots_scan: bool = False,
    nmap_timing: str = "-T3",
    full_ports: bool = False,
):
    global CURRENT_SCAN
    try:
        with SCAN_LOCK:
            CURRENT_SCAN["is_running"] = True
            CURRENT_SCAN["target"] = target
            CURRENT_SCAN["phase"] = "STARTING"
            CURRENT_SCAN["progress"] = 5
            CURRENT_SCAN["logs"] = []
            CURRENT_SCAN["candidates"] = []
            CURRENT_SCAN["dns_assets"] = []
            CURRENT_SCAN["web_inventory"] = []
            CURRENT_SCAN["endpoints"] = []
            CURRENT_SCAN["hypotheses"] = []
            CURRENT_SCAN["drift_data"] = None
            CURRENT_SCAN["js_api_data"] = []
            CURRENT_SCAN["cloud_buckets"] = []
            CURRENT_SCAN["active_findings"] = {}
            CURRENT_SCAN["integrations"] = []
            CURRENT_SCAN["graph_json"] = None
            CURRENT_SCAN["report_md"] = ""
            CURRENT_SCAN["error"] = None

        append_log(f"Starting ARECON 2.0 Attack Surface Engine for: {target}")

        # Temporary scope file if exclusions provided
        scope_file = None
        if scope_text.strip():
            scope_file = os.path.join(SCRIPT_DIR, ".temp_scope.txt")
            with open(scope_file, "w", encoding="utf-8") as f:
                f.write(scope_text)

        # Run pipeline
        with SCAN_LOCK:
            CURRENT_SCAN["phase"] = "DISCOVERY"
            CURRENT_SCAN["progress"] = 25
        append_log("Multi-Source Passive Enumeration & Wildcard DNS detection...")

        result = recon.run_pipeline(
            target_domain=target,
            scope_file=scope_file,
            output_dir=os.path.join(SCRIPT_DIR, "recon_output"),
            active_crawl=active_crawl,
            threads=threads,
            timeout=timeout,
            db=DB,
            active_scan=active_scan,
            dirbrute=dirbrute,
            tls_audit=tls_audit,
            robots_scan=robots_scan,
            nmap_timing=nmap_timing,
            full_ports=full_ports,
        )

        with open(result["report_file"], "r", encoding="utf-8") as f:
            report_text = f.read()

        with SCAN_LOCK:
            CURRENT_SCAN["phase"] = "COMPLETED"
            CURRENT_SCAN["progress"] = 100
            CURRENT_SCAN["is_running"] = False
            CURRENT_SCAN["candidates"] = result["candidates"]
            CURRENT_SCAN["dns_assets"] = result["dns_assets"]
            CURRENT_SCAN["web_inventory"] = result["web_inventory"]
            CURRENT_SCAN["endpoints"] = result["endpoints"]
            CURRENT_SCAN["hypotheses"] = result["hypotheses"]
            CURRENT_SCAN["drift_data"] = result["drift_data"]
            CURRENT_SCAN["js_api_data"] = result["js_api_data"]
            CURRENT_SCAN["cloud_buckets"] = result["cloud_buckets"]
            CURRENT_SCAN["active_findings"] = result.get("active_findings", {})
            CURRENT_SCAN["integrations"] = result.get("integrations", [])
            CURRENT_SCAN["graph_json"] = result["graph_json"]
            CURRENT_SCAN["report_md"] = report_text

        append_log(f"ARECON 2.0 run finished! Report saved at {result['report_file']}")

    except Exception as e:
        with SCAN_LOCK:
            CURRENT_SCAN["is_running"] = False
            CURRENT_SCAN["phase"] = "ERROR"
            CURRENT_SCAN["error"] = str(e)
        append_log(f"Pipeline error: {e}")


# ==============================================================================
# EMBEDDED DASHBOARD (WHITE BG, RED BUTTON, BLACK TEXT)
# ==============================================================================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARECON 2.0 — By Rakshit Walia</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #FFFFFF;
            --surface-color: #FFFFFF;
            --border-color: #000000;
            --border-light: #E5E7EB;
            --text-main: #000000;
            --text-muted: #4B5563;
            --btn-red: #EF4444;
            --btn-red-hover: #DC2626;
            --btn-red-active: #B91C1C;
            --badge-crit: #7F1D1D;
            --badge-high: #FEE2E2;
            --badge-high-text: #991B1B;
            --badge-med: #FEF3C7;
            --badge-med-text: #92400E;
            --badge-low: #E0E7FF;
            --badge-low-text: #3730A3;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            -webkit-font-smoothing: antialiased;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px;
        }

        .container {
            max-width: 1480px;
            margin: 0 auto;
        }

        /* Top Header */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 3px solid var(--border-color);
            margin-bottom: 24px;
        }

        .brand-title {
            font-size: 38px;
            font-weight: 900;
            letter-spacing: -1.5px;
            color: var(--text-main);
            line-height: 1;
        }

        .brand-subtitle {
            font-size: 13px;
            font-weight: 800;
            letter-spacing: 3px;
            color: var(--btn-red);
            text-transform: uppercase;
            margin-top: 4px;
        }

        .brand-tag {
            background-color: #000000;
            color: #FFFFFF;
            font-size: 11px;
            font-weight: 700;
            padding: 6px 14px;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Architecture Flowchart Navigation */
        .flowchart-bar {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            margin-bottom: 28px;
        }

        .flow-step {
            border: 2px solid var(--border-color);
            background: #FFFFFF;
            padding: 12px 10px;
            text-align: center;
            border-radius: 6px;
            transition: all 0.2s ease;
        }

        .flow-step.active {
            background: #FEE2E2;
            border-color: var(--btn-red);
            transform: translateY(-2px);
            box-shadow: 0 4px 0 #000000;
        }

        .flow-step.completed {
            background: #F3F4F6;
            border-color: #000000;
        }

        .flow-step-num {
            font-size: 10px;
            font-weight: 800;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .flow-step-title {
            font-size: 12px;
            font-weight: 800;
            color: var(--text-main);
            margin-top: 2px;
        }

        /* Layout Grid */
        .grid-layout {
            display: grid;
            grid-template-columns: 360px 1fr;
            gap: 24px;
        }

        /* Sidebar Control Card */
        .control-card {
            background: var(--surface-color);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            box-shadow: 4px 4px 0 #000000;
            height: fit-content;
        }

        .card-header {
            font-size: 16px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding-bottom: 12px;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .form-group {
            margin-bottom: 18px;
        }

        label {
            display: block;
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
            color: var(--text-main);
        }

        input[type="text"], textarea, select {
            width: 100%;
            padding: 12px 14px;
            background: #FFFFFF;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-main);
            outline: none;
            transition: border-color 0.15s;
        }

        input[type="text"]:focus, textarea:focus, select:focus {
            border-color: var(--btn-red);
            box-shadow: 0 0 0 1px var(--btn-red);
        }

        textarea {
            resize: vertical;
            min-height: 80px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            text-transform: none;
        }

        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: var(--btn-red);
            cursor: pointer;
        }

        /* BUTTONS: RED BUTTON, BLACK TEXT */
        .btn-red {
            display: flex;
            justify-content: center;
            align-items: center;
            width: 100%;
            background-color: var(--btn-red);
            color: #000000;
            font-size: 15px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 15px 20px;
            border: 2px solid #000000;
            border-radius: 6px;
            cursor: pointer;
            box-shadow: 3px 3px 0 #000000;
            transition: all 0.15s ease;
        }

        .btn-red:hover {
            background-color: var(--btn-red-hover);
            transform: translate(-1px, -1px);
            box-shadow: 4px 4px 0 #000000;
        }

        .btn-red:active {
            transform: translate(2px, 2px);
            box-shadow: 1px 1px 0 #000000;
        }

        .btn-red:disabled {
            background-color: #E5E7EB;
            color: #9CA3AF;
            border-color: #9CA3AF;
            cursor: not-allowed;
            box-shadow: none;
            transform: none;
        }

        .btn-secondary {
            display: flex;
            justify-content: center;
            align-items: center;
            width: 100%;
            background-color: #FFFFFF;
            color: #000000;
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            padding: 10px 14px;
            border: 2px solid #000000;
            border-radius: 6px;
            cursor: pointer;
            margin-top: 10px;
            transition: all 0.15s;
        }

        .btn-secondary:hover {
            background: #F3F4F6;
        }

        /* Results Display Card */
        .results-card {
            background: var(--surface-color);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            box-shadow: 4px 4px 0 #000000;
            padding: 24px;
            display: flex;
            flex-direction: column;
            min-height: 650px;
        }

        /* Navigation Tabs */
        .tabs {
            display: flex;
            gap: 6px;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 20px;
            overflow-x: auto;
        }

        .tab-btn {
            background: none;
            border: none;
            padding: 10px 14px;
            font-size: 12px;
            font-weight: 800;
            color: var(--text-muted);
            cursor: pointer;
            border-bottom: 3px solid transparent;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
            transition: all 0.15s;
        }

        .tab-btn.active {
            color: #000000;
            border-bottom-color: var(--btn-red);
        }

        .tab-content {
            display: none;
            flex: 1;
        }

        .tab-content.active {
            display: block;
        }

        /* Tables */
        .table-wrapper {
            overflow-x: auto;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            max-height: 520px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }

        th {
            background: #F9FAFB;
            color: #000000;
            font-weight: 800;
            padding: 12px 14px;
            border-bottom: 2px solid var(--border-color);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-light);
            color: #000000;
            font-weight: 500;
        }

        tr:hover td {
            background-color: #F9FAFB;
        }

        /* Console Output */
        .console-box {
            background: #FFFFFF;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #000000;
            height: 500px;
            overflow-y: auto;
            white-space: pre-wrap;
            line-height: 1.6;
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid var(--border-color);
        }

        .badge-crit {
            background: #7F1D1D;
            color: #FFFFFF;
            border-color: #000000;
        }

        .badge-high {
            background: var(--badge-high);
            color: var(--badge-high-text);
        }

        .badge-med {
            background: var(--badge-med);
            color: var(--badge-med-text);
        }

        .badge-low {
            background: var(--badge-low);
            color: var(--badge-low-text);
        }

        .badge-tech {
            background: #F3F4F6;
            color: #000000;
            font-size: 11px;
            font-weight: 700;
            padding: 3px 6px;
            border-radius: 4px;
            margin-right: 4px;
            display: inline-block;
            border: 1px solid #D1D5DB;
        }

        .markdown-viewer {
            background: #FFFFFF;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            padding: 24px;
            height: 500px;
            overflow-y: auto;
            font-family: 'Inter', sans-serif;
            font-size: 14px;
            line-height: 1.7;
            white-space: pre-wrap;
        }

        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: #9CA3AF;
            margin-right: 6px;
        }

        .status-dot.running {
            background-color: var(--btn-red);
            box-shadow: 0 0 0 3px #FEE2E2;
            animation: pulse 1.5s infinite;
        }

        .status-dot.done {
            background-color: #10B981;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.4; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Top Header -->
        <header>
            <div>
                <h1 class="brand-title">ARECON 2.0</h1>
                <div class="brand-subtitle">BY RAKSHIT WALIA  |  ATTACK SURFACE INTELLIGENCE</div>
            </div>
            <div style="display: flex; gap: 12px; align-items: center;">
                <div class="brand-tag">Normalized SQLite Store</div>
            </div>
        </header>

        <!-- 5-Layer Advanced Architecture Flow -->
        <div class="flowchart-bar">
            <div class="flow-step" id="step-scope">
                <div class="flow-step-num">Layer 01</div>
                <div class="flow-step-title">Scope & Policy</div>
            </div>
            <div class="flow-step" id="step-passive">
                <div class="flow-step-num">Layer 02</div>
                <div class="flow-step-title">Multi-Source Discovery</div>
            </div>
            <div class="flow-step" id="step-app">
                <div class="flow-step-num">Layer 03</div>
                <div class="flow-step-title">JS & API Surface</div>
            </div>
            <div class="flow-step" id="step-graph">
                <div class="flow-step-num">Layer 04</div>
                <div class="flow-step-title">Relationship Graph</div>
            </div>
            <div class="flow-step" id="step-drift">
                <div class="flow-step-num">Layer 05</div>
                <div class="flow-step-title">Drift & WSTG Hypotheses</div>
            </div>
        </div>

        <!-- Main Grid -->
        <div class="grid-layout">
            <!-- Sidebar Controls -->
            <div class="control-card">
                <div class="card-header">
                    <span>Target & Policy</span>
                    <span id="scan-status-badge"><span class="status-dot" id="status-indicator"></span><span id="status-text">Ready</span></span>
                </div>

                <div class="form-group">
                    <label for="target-domain">Target Root Domain</label>
                    <input type="text" id="target-domain" placeholder="e.g. example.com" value="collegedekho.com">
                </div>

                <div class="form-group">
                    <label for="scope-exclusions">Out-of-Scope Exclusions (Regex/Lines)</label>
                    <textarea id="scope-exclusions" placeholder="zendesk&#10;shopify&#10;statuspage"></textarea>
                </div>

                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="active-crawl">
                        Enable Active Web Spidering
                    </label>
                </div>

                <div class="form-group">
                    <label for="thread-count">Concurrency (Threads)</label>
                    <select id="thread-count">
                        <option value="15" selected>15 Workers</option>
                        <option value="25">25 Workers (High Speed)</option>
                    </select>
                </div>

                <div class="form-group" style="border-top: 1px solid #E5E7EB; padding-top: 10px; margin-top: 10px;">
                    <span style="font-weight: 700; font-size: 0.85rem; color: #111827; display: block; margin-bottom: 8px;">Active Recon Modules (Opt-In)</span>
                    <label class="checkbox-label" style="margin-bottom: 6px;">
                        <input type="checkbox" id="active-scan">
                        Nmap / Port & Service Scan
                    </label>
                    <label class="checkbox-label" style="margin-bottom: 6px;">
                        <input type="checkbox" id="robots-scan">
                        Robots.txt & Sitemap Scraper
                    </label>
                    <label class="checkbox-label" style="margin-bottom: 6px;">
                        <input type="checkbox" id="dirbrute">
                        Directory & Route Bruteforcing
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="tls-audit">
                        TLS Configuration & Cert Audit
                    </label>
                </div>

                <!-- RED BUTTON, BLACK TEXT -->
                <button class="btn-red" id="start-btn" onclick="startScan()">
                    ⚡ START RECONNAISSANCE
                </button>

                <button class="btn-secondary" onclick="exportReport()">
                    📥 Export Markdown Report
                </button>
            </div>

            <!-- Results Notebook -->
            <div class="results-card">
                <div class="tabs">
                    <button class="tab-btn active" onclick="switchTab('tab-terminal')">Terminal Log</button>
                    <button class="tab-btn" onclick="switchTab('tab-web')">Live Web (<span id="count-web">0</span>)</button>
                    <button class="tab-btn" onclick="switchTab('tab-versions')">Service Versions (<span id="count-versions">0</span>)</button>
                    <button class="tab-btn" onclick="switchTab('tab-api')">JS & APIs (<span id="count-api">0</span>)</button>
                    <button class="tab-btn" onclick="switchTab('tab-cloud')">Cloud & Takeovers (<span id="count-cloud">0</span>)</button>
                    <button class="tab-btn" onclick="switchTab('tab-drift')">Attack Surface Drift (<span id="count-drift">0</span>)</button>
                    <button class="tab-btn" onclick="switchTab('tab-active')">Active & Integrations (<span id="count-active">0</span>)</button>
                    <button class="tab-btn" onclick="switchTab('tab-hypotheses')">OWASP Hypotheses (<span id="count-hypo">0</span>)</button>
                    <button class="tab-btn" onclick="switchTab('tab-report')">Executive Report</button>
                </div>

                <!-- Tab 1: Terminal Log -->
                <div class="tab-content active" id="tab-terminal">
                    <div class="console-box" id="console-output">ARECON 2.0 Engine ready. Enter target domain and click START RECONNAISSANCE.</div>
                </div>

                <!-- Tab 2: Live Web Inventory -->
                <div class="tab-content" id="tab-web">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Status</th>
                                    <th>URL</th>
                                    <th>Title</th>
                                    <th>Tech Stack & Versions</th>
                                    <th>CDN / WAF</th>
                                    <th>Security Headers</th>
                                </tr>
                            </thead>
                            <tbody id="web-table-body">
                                <tr><td colspan="6" style="text-align:center; color:#6B7280;">No web applications discovered yet.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Tab 2.5: Service Versions & Software Inventory -->
                <div class="tab-content" id="tab-versions">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Web Asset</th>
                                    <th>Service / Component</th>
                                    <th>Detected Version</th>
                                    <th>Security Status & CVE Risk</th>
                                </tr>
                            </thead>
                            <tbody id="versions-table-body">
                                <tr><td colspan="4" style="text-align:center; color:#6B7280;">No service versions extracted yet.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Tab 3: JS & API Explorer -->
                <div class="tab-content" id="tab-api">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Discovery Type</th>
                                    <th>Target Asset / Spec</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody id="api-table-body">
                                <tr><td colspan="3" style="text-align:center; color:#6B7280;">No client-side APIs or schemas scanned yet.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Tab 4: Cloud & Takeovers -->
                <div class="tab-content" id="tab-cloud">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Provider / Category</th>
                                    <th>Target Resource</th>
                                    <th>Exposure Level / Status</th>
                                </tr>
                            </thead>
                            <tbody id="cloud-table-body">
                                <tr><td colspan="3" style="text-align:center; color:#6B7280;">No cloud storage buckets or takeovers checked yet.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Tab 5: Attack Surface Drift -->
                <div class="tab-content" id="tab-drift">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Event Type</th>
                                    <th>Target Asset</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody id="drift-table-body">
                                <tr><td colspan="3" style="text-align:center; color:#6B7280;">Drift comparison requires at least one baseline scan in SQLite.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Tab: Active & Integrations -->
                <div class="tab-content" id="tab-active">
                    <h4 style="margin: 0 0 10px 0; font-size: 0.95rem; font-weight: 700; color: #111827;">Open Network Ports & Services</h4>
                    <div class="table-wrapper" style="margin-bottom: 25px;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Host / IP</th>
                                    <th>Port</th>
                                    <th>Protocol</th>
                                    <th>Service</th>
                                    <th>Version</th>
                                    <th>Source</th>
                                </tr>
                            </thead>
                            <tbody id="ports-table-body">
                                <tr><td colspan="6" style="text-align:center; color:#6B7280;">No open ports scanned or detected.</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h4 style="margin: 0 0 10px 0; font-size: 0.95rem; font-weight: 700; color: #111827;">Third-Party Integrations Mapped (Payment, Analytics, CDN, Support)</h4>
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Asset Hostname</th>
                                    <th>Category</th>
                                    <th>Integration</th>
                                    <th>Signature Indicator</th>
                                </tr>
                            </thead>
                            <tbody id="integrations-table-body">
                                <tr><td colspan="4" style="text-align:center; color:#6B7280;">No third-party scripts detected.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Tab 6: OWASP Hypotheses -->
                <div class="tab-content" id="tab-hypotheses">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Priority</th>
                                    <th>OWASP Category</th>
                                    <th>Target Asset</th>
                                    <th>Testing Hypothesis</th>
                                </tr>
                            </thead>
                            <tbody id="hypo-table-body">
                                <tr><td colspan="4" style="text-align:center; color:#6B7280;">No vulnerabilities prioritized yet.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Tab 7: Executive Report -->
                <div class="tab-content" id="tab-report">
                    <div class="markdown-viewer" id="markdown-output">Execution report will appear here once the scan completes.</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let pollInterval = null;

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        async function startScan() {
            const target = document.getElementById('target-domain').value.trim();
            if (!target) {
                alert('Please enter a target domain.');
                return;
            }

            const exclusions = document.getElementById('scope-exclusions').value;
            const activeCrawl = document.getElementById('active-crawl').checked;
            const threads = parseInt(document.getElementById('thread-count').value);
            const activeScan = document.getElementById('active-scan').checked;
            const robotsScan = document.getElementById('robots-scan').checked;
            const dirbrute = document.getElementById('dirbrute').checked;
            const tlsAudit = document.getElementById('tls-audit').checked;

            document.getElementById('start-btn').disabled = true;
            document.getElementById('status-indicator').className = 'status-dot running';
            document.getElementById('status-text').innerText = 'Running';

            try {
                const res = await fetch('/api/scan/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        target: target,
                        exclusions: exclusions,
                        active_crawl: activeCrawl,
                        threads: threads,
                        timeout: 5,
                        active_scan: activeScan,
                        robots_scan: robotsScan,
                        dirbrute: dirbrute,
                        tls_audit: tlsAudit
                    })
                });

                const data = await res.json();
                if (data.status === 'started') {
                    if (pollInterval) clearInterval(pollInterval);
                    pollInterval = setInterval(pollStatus, 1200);
                }
            } catch (err) {
                alert('Failed to start scan: ' + err);
                document.getElementById('start-btn').disabled = false;
            }
        }

        async function pollStatus() {
            try {
                const res = await fetch('/api/scan/status');
                const data = await res.json();

                // Console output
                const consoleBox = document.getElementById('console-output');
                if (data.logs && data.logs.length > 0) {
                    consoleBox.innerText = data.logs.join('\\n');
                    consoleBox.scrollTop = consoleBox.scrollHeight;
                }

                // Update Counts
                document.getElementById('count-web').innerText = (data.web_inventory || []).length;
                document.getElementById('count-hypo').innerText = (data.hypotheses || []).length;
                
                let verCount = 0;
                (data.web_inventory || []).forEach(w => {
                    verCount += Object.keys(w.service_versions || {}).filter(k => k !== 'OS').length;
                });
                document.getElementById('count-versions').innerText = verCount;

                let apiCount = 0;
                if (data.js_api_data) {
                    data.js_api_data.forEach(j => {
                        apiCount += (j.extracted_api_routes || []).length;
                        apiCount += (j.openapi_specs || []).length;
                        if (j.graphql_endpoint) apiCount++;
                    });
                }
                document.getElementById('count-api').innerText = apiCount;
                document.getElementById('count-cloud').innerText = (data.cloud_buckets || []).length;

                const driftTotal = (data.drift_data && data.drift_data.total_drift_events) || 0;
                document.getElementById('count-drift').innerText = driftTotal;

                const openPorts = (data.active_findings && data.active_findings.open_ports) || [];
                const integrations = data.integrations || [];
                document.getElementById('count-active').innerText = openPorts.length + integrations.length;

                // Render Tables
                renderWebTable(data.web_inventory);
                renderVersionsTable(data.web_inventory);
                renderApiTable(data.js_api_data);
                renderCloudTable(data.cloud_buckets);
                renderDriftTable(data.drift_data);
                renderActiveTable(data.active_findings, data.integrations);
                renderHypoTable(data.hypotheses);

                if (data.report_md) {
                    document.getElementById('markdown-output').innerText = data.report_md;
                }

                if (!data.is_running && data.phase === 'COMPLETED') {
                    clearInterval(pollInterval);
                    document.getElementById('start-btn').disabled = false;
                    document.getElementById('status-indicator').className = 'status-dot done';
                    document.getElementById('status-text').innerText = 'Completed';
                } else if (!data.is_running && data.phase === 'ERROR') {
                    clearInterval(pollInterval);
                    document.getElementById('start-btn').disabled = false;
                    document.getElementById('status-indicator').className = 'status-dot';
                    document.getElementById('status-text').innerText = 'Error';
                }
            } catch (e) {
                console.error(e);
            }
        }

        function renderWebTable(items) {
            const tbody = document.getElementById('web-table-body');
            if (!items || items.length === 0) return;

            tbody.innerHTML = items.map(i => {
                const techBadges = (i.technologies || []).map(t => {
                    return `<span class="badge-tech">${t}</span>`;
                }).join(' ') || 'Generic';
                const cdn = i.cdn_waf ? `<span class="badge badge-low">${i.cdn_waf}</span>` : '—';
                const sec = i.security_headers || {};
                const badges = [];
                if (sec.hsts) badges.push('<span class="badge badge-low">HSTS</span>');
                if (sec.csp) badges.push('<span class="badge badge-low">CSP</span>');
                const secStr = badges.length ? badges.join(' ') : '<span style="color:#9CA3AF;">None</span>';

                return `<tr>
                    <td><strong>${i.status_code}</strong></td>
                    <td><a href="${i.url}" target="_blank" style="color:#000000; text-decoration:underline;">${i.url}</a></td>
                    <td>${i.title || ''}</td>
                    <td>${techBadges}</td>
                    <td>${cdn}</td>
                    <td>${secStr}</td>
                </tr>`;
            }).join('');
        }

        function renderVersionsTable(items) {
            const tbody = document.getElementById('versions-table-body');
            if (!items || items.length === 0) return;

            let rows = [];
            items.forEach(i => {
                const sv = i.service_versions || {};
                const vfMap = {};
                (i.version_findings || []).forEach(f => { vfMap[f.service] = f; });

                for (const [svc, ver] of Object.entries(sv)) {
                    if (svc === 'OS') continue;
                    let flagHtml = '<span class="badge badge-low">Active / Detected</span>';
                    if (vfMap[svc] && vfMap[svc].type === 'OUTDATED_OR_EOL') {
                        const sevClass = vfMap[svc].severity === 'HIGH' ? 'badge-high' : 'badge-med';
                        flagHtml = `<span class="badge ${sevClass}">🚨 Outdated / EOL (${vfMap[svc].severity})</span> <span style="font-size:11px; color:#991B1B;">${vfMap[svc].description || ''}</span>`;
                    } else if (ver && ver !== 'Detected') {
                        flagHtml = '<span class="badge badge-low">ℹ️ Version Disclosed</span>';
                    }

                    rows.push(`<tr>
                        <td><a href="${i.url}" target="_blank" style="color:#000000; text-decoration:underline;">${i.url}</a></td>
                        <td><strong>${svc}</strong></td>
                        <td><code>${ver}</code></td>
                        <td>${flagHtml}</td>
                    </tr>`);
                }
            });

            if (rows.length > 0) {
                tbody.innerHTML = rows.join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#6B7280;">No specific software versions disclosed across probed web services.</td></tr>';
            }
        }

        function renderApiTable(jsData) {
            const tbody = document.getElementById('api-table-body');
            if (!jsData || jsData.length === 0) return;

            let rows = [];
            jsData.forEach(item => {
                (item.openapi_specs || []).forEach(spec => {
                    rows.push(`<tr>
                        <td><span class="badge badge-high">OpenAPI / Swagger</span></td>
                        <td><a href="${spec.spec_url}" target="_blank">${spec.spec_url}</a></td>
                        <td>${spec.title} (v${spec.version}) — ${spec.routes.length} routes documented</td>
                    </tr>`);
                });

                if (item.graphql_endpoint) {
                    const g = item.graphql_endpoint;
                    const b = g.introspection_enabled ? '<span class="badge badge-high">Introspection OPEN</span>' : '<span class="badge badge-low">Active</span>';
                    rows.push(`<tr>
                        <td><span class="badge badge-med">GraphQL Endpoint</span></td>
                        <td><code>${g.graphql_url}</code></td>
                        <td>${b}</td>
                    </tr>`);
                }

                (item.source_maps_exposed || []).forEach(sm => {
                    rows.push(`<tr>
                        <td><span class="badge badge-med">Source Map</span></td>
                        <td><a href="${sm}" target="_blank">${sm}</a></td>
                        <td>Exposes original client source code</td>
                    </tr>`);
                });

                (item.extracted_api_routes || []).slice(0, 15).forEach(r => {
                    rows.push(`<tr>
                        <td><span class="badge badge-low">Client API Route</span></td>
                        <td><code>${item.base_url}${r}</code></td>
                        <td>Extracted from JavaScript bundles</td>
                    </tr>`);
                });
            });

            if (rows.length) tbody.innerHTML = rows.join('');
        }

        function renderCloudTable(buckets) {
            const tbody = document.getElementById('cloud-table-body');
            if (!buckets || buckets.length === 0) return;

            tbody.innerHTML = buckets.map(b => {
                const bClass = b.exposure === 'PUBLIC_LISTING' ? 'badge-high' : 'badge-med';
                return `<tr>
                    <td><strong>${b.provider}</strong></td>
                    <td><a href="${b.url}" target="_blank">${b.url}</a></td>
                    <td><span class="badge ${bClass}">${b.exposure}</span></td>
                </tr>`;
            }).join('');
        }

        function renderDriftTable(driftData) {
            const tbody = document.getElementById('drift-table-body');
            if (!driftData || !driftData.has_drift) return;

            let rows = [];
            const changes = driftData.changes_by_type || {};
            for (const [cType, entries] of Object.entries(changes)) {
                entries.forEach(e => {
                    rows.push(`<tr>
                        <td><span class="badge badge-med">${cType}</span></td>
                        <td><code>${e.target}</code></td>
                        <td>${e.new_value || ''}</td>
                    </tr>`);
                });
            }
            if (rows.length) tbody.innerHTML = rows.join('');
        }

        function renderActiveTable(activeFindings, integrations) {
            const portsTbody = document.getElementById('ports-table-body');
            const openPorts = (activeFindings && activeFindings.open_ports) || [];
            if (openPorts.length > 0) {
                portsTbody.innerHTML = openPorts.map(p => {
                    return `<tr>
                        <td><strong>${p.hostname || p.ip}</strong></td>
                        <td><span class="badge badge-high">${p.port}</span></td>
                        <td>${p.protocol || 'tcp'}</td>
                        <td><strong>${p.service || 'unknown'}</strong></td>
                        <td>${p.version || ''}</td>
                        <td><code>${p.source || 'nmap'}</code></td>
                    </tr>`;
                }).join('');
            } else {
                portsTbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#6B7280;">No open ports scanned or detected.</td></tr>';
            }

            const itgTbody = document.getElementById('integrations-table-body');
            if (integrations && integrations.length > 0) {
                itgTbody.innerHTML = integrations.map(i => {
                    return `<tr>
                        <td><strong>${i.asset || i.asset_hostname}</strong></td>
                        <td><span class="badge badge-med">${i.category}</span></td>
                        <td><strong>${i.integration || i.integration_name}</strong></td>
                        <td><code>${i.indicator || ''}</code></td>
                    </tr>`;
                }).join('');
            } else {
                itgTbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#6B7280;">No third-party scripts detected.</td></tr>';
            }
        }

        function renderHypoTable(items) {
            const tbody = document.getElementById('hypo-table-body');
            if (!items || items.length === 0) return;

            tbody.innerHTML = items.map(h => {
                const pClass = h.priority === 'CRITICAL' ? 'badge-crit' : (h.priority === 'HIGH' ? 'badge-high' : (h.priority === 'MEDIUM' ? 'badge-med' : 'badge-low'));
                return `<tr>
                    <td><span class="badge ${pClass}">${h.priority}</span></td>
                    <td><strong>${h.category}</strong></td>
                    <td><code>${h.target}</code></td>
                    <td>${h.hypothesis}</td>
                </tr>`;
            }).join('');
        }

        function exportReport() {
            const report = document.getElementById('markdown-output').innerText;
            if (!report || report.startsWith('Execution report')) {
                alert('No report generated yet. Run a scan first!');
                return;
            }
            const blob = new Blob([report], {type: 'text/markdown'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'ARECON_Report.md';
            a.click();
        }
    </script>
</body>
</html>
"""


class ReconRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))

        elif parsed.path == "/api/scan/status":
            with SCAN_LOCK:
                data = dict(CURRENT_SCAN)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/scan/start":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            payload = json.loads(post_body)

            target = payload.get("target", "").strip()
            exclusions = payload.get("exclusions", "")
            active_crawl = bool(payload.get("active_crawl", False))
            threads = int(payload.get("threads", 15))
            timeout = int(payload.get("timeout", 5))
            active_scan = bool(payload.get("active_scan", False))
            robots_scan = bool(payload.get("robots_scan", False))
            dirbrute = bool(payload.get("dirbrute", False))
            tls_audit = bool(payload.get("tls_audit", False))
            nmap_timing = payload.get("nmap_timing", "-T3")
            full_ports = bool(payload.get("full_ports", False))

            if not target:
                self.send_response(400)
                self.end_headers()
                return

            t = threading.Thread(
                target=run_recon_job,
                args=(target, exclusions, active_crawl, threads, timeout, active_scan, dirbrute, tls_audit, robots_scan, nmap_timing, full_ports),
                daemon=True,
            )
            t.start()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "started"}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()


def launch_web_gui(port: int = 8088, open_browser: bool = True):
    server_address = ("127.0.0.1", port)
    socketserver.TCPServer.allow_reuse_address = True
    try:
        httpd = socketserver.TCPServer(server_address, ReconRequestHandler)
    except OSError:
        port = 8090
        server_address = ("127.0.0.1", port)
        httpd = socketserver.TCPServer(server_address, ReconRequestHandler)

    url = f"http://127.0.0.1:{port}"
    print(f"\n==============================================================")
    print(f" ARECON 2.0 GUI BY RAKSHIT WALIA")
    print(f" Theme: White Background | Red Button | Black Text")
    print(f" Dashboard URL: {url}")
    print(f"==============================================================\n")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down ARECON GUI server.")
        httpd.server_close()


if __name__ == "__main__":
    launch_web_gui()
