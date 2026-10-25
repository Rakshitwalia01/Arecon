#!/usr/bin/env python3
"""
ARECON 2.0 Desktop GUI — Native Cross-Platform Desktop Interface
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License
Theme: Clean White Background, Red Buttons, Black Text
Supported OS: Windows, macOS, Linux
"""

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
import urllib.parse
import webbrowser

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from core.db import ReconDB
import recon

DEFAULT_FONT_FAMILY = "Segoe UI" if os.name == "nt" else "Helvetica"


class RedButton(tk.Label):
    """Custom Label-based button guaranteeing vibrant Red background, Black text across Windows, macOS & Linux."""

    def __init__(self, parent, text, command=None, font=(DEFAULT_FONT_FAMILY, 11, "bold"), pady=8, padx=14, **kwargs):
        super().__init__(
            parent,
            text=text,
            bg="#EF4444",
            fg="#000000",
            font=font,
            padx=padx,
            pady=pady,
            cursor="hand2",
            relief="solid",
            bd=2,
            **kwargs,
        )
        self.command = command
        self._disabled = False
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", lambda e: self.config(bg="#DC2626") if not self._disabled else None)
        self.bind("<Leave>", lambda e: self.config(bg="#EF4444") if not self._disabled else None)

    def _on_click(self, event):
        if not self._disabled and self.command:
            self.command()

    def set_state(self, state: str):
        if state == "disabled":
            self._disabled = True
            self.config(bg="#E5E7EB", fg="#9CA3AF", cursor="arrow")
        else:
            self._disabled = False
            self.config(bg="#EF4444", fg="#000000", cursor="hand2")


class ARECONApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ARECON 2.0 — By Rakshit Walia")
        self.root.geometry("1150x740")
        self.root.minsize(980, 640)
        self.root.configure(bg="#FFFFFF")

        self.is_scanning = False
        self.results_dir = os.path.join(SCRIPT_DIR, "recon_output")
        self.db = ReconDB()

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TNotebook", background="#FFFFFF", borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#F3F4F6",
            foreground="#000000",
            font=("Helvetica", 10, "bold"),
            padding=[12, 6],
            borderwidth=1,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#FFFFFF")],
            foreground=[("selected", "#DC2626")],
            expand=[("selected", [0, 0, 0, 0])],
        )

        style.configure(
            "Red.Horizontal.TProgressbar",
            troughcolor="#F3F4F6",
            background="#EF4444",
            lightcolor="#EF4444",
            darkcolor="#DC2626",
            bordercolor="#000000",
            thickness=10,
        )

        style.configure(
            "Treeview",
            background="#FFFFFF",
            foreground="#000000",
            rowheight=24,
            fieldbackground="#FFFFFF",
            font=("Helvetica", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#F9FAFB",
            foreground="#000000",
            font=("Helvetica", 10, "bold"),
            relief="solid",
            borderwidth=1,
        )
        style.map("Treeview", background=[("selected", "#FEE2E2")], foreground=[("selected", "#000000")])

    def _build_ui(self):
        # 1. Header Frame
        header = tk.Frame(self.root, bg="#FFFFFF", padx=20, pady=12, bd=2, relief="solid")
        header.pack(fill="x", padx=16, pady=(16, 10))

        title_frame = tk.Frame(header, bg="#FFFFFF")
        title_frame.pack(side="left")

        title_lbl = tk.Label(title_frame, text="ARECON 2.0", font=("Helvetica", 24, "bold"), bg="#FFFFFF", fg="#000000")
        title_lbl.pack(anchor="w")

        subtitle_lbl = tk.Label(
            title_frame,
            text="BY RAKSHIT WALIA  |  ATTACK SURFACE INTELLIGENCE & RECON",
            font=("Helvetica", 9, "bold"),
            bg="#FFFFFF",
            fg="#EF4444",
        )
        subtitle_lbl.pack(anchor="w")

        web_btn = RedButton(header, text="🌐 LAUNCH WEB UI", command=self._open_web_ui, font=("Helvetica", 9, "bold"), pady=4)
        web_btn.pack(side="right")

        # 2. Main Paned Layout
        main_paned = tk.PanedWindow(self.root, orient="horizontal", bg="#FFFFFF", sashwidth=4, bd=0)
        main_paned.pack(fill="both", expand=True, padx=16, pady=6)

        # 2A. Left Panel
        left_frame = tk.Frame(main_paned, bg="#FFFFFF", padx=14, pady=14, bd=2, relief="solid", width=310)
        main_paned.add(left_frame, minsize=290)

        ctrl_title = tk.Label(left_frame, text="TARGET & PARAMETERS", font=("Helvetica", 11, "bold"), bg="#FFFFFF", fg="#000000")
        ctrl_title.pack(anchor="w", pady=(0, 10))

        tk.Label(left_frame, text="TARGET ROOT DOMAIN:", font=("Helvetica", 9, "bold"), bg="#FFFFFF", fg="#000000").pack(anchor="w")
        self.domain_var = tk.StringVar(value="collegedekho.com")
        self.domain_entry = tk.Entry(left_frame, textvariable=self.domain_var, font=("Helvetica", 11), bg="#FFFFFF", fg="#000000", bd=2, relief="solid")
        self.domain_entry.pack(fill="x", pady=(2, 10))

        tk.Label(left_frame, text="OUT-OF-SCOPE EXCLUSIONS (LINES):", font=("Helvetica", 9, "bold"), bg="#FFFFFF", fg="#000000").pack(anchor="w")
        self.scope_text = tk.Text(left_frame, height=5, font=("Courier", 10), bg="#FFFFFF", fg="#000000", bd=2, relief="solid")
        self.scope_text.insert("1.0", "zendesk\nshopify\nstatuspage")
        self.scope_text.pack(fill="x", pady=(2, 10))

        self.active_crawl_var = tk.BooleanVar(value=False)
        crawl_chk = tk.Checkbutton(
            left_frame,
            text="Enable Active Crawling",
            variable=self.active_crawl_var,
            bg="#FFFFFF",
            fg="#000000",
            activebackground="#FFFFFF",
            font=("Helvetica", 9, "bold"),
        )
        crawl_chk.pack(anchor="w", pady=(0, 6))

        tk.Label(left_frame, text="CONCURRENCY (THREADS):", font=("Helvetica", 9, "bold"), bg="#FFFFFF", fg="#000000").pack(anchor="w")
        self.threads_var = tk.StringVar(value="15")
        threads_spin = ttk.Spinbox(left_frame, from_=5, to=30, textvariable=self.threads_var, width=10)
        threads_spin.pack(anchor="w", pady=(2, 14))

        self.start_btn = RedButton(left_frame, text="⚡ START RECON", command=self._start_scan, pady=10)
        self.start_btn.pack(fill="x", pady=(0, 8))

        self.open_dir_btn = RedButton(left_frame, text="📁 OPEN OUTPUT FOLDER", command=self._open_output_dir, pady=6, font=("Helvetica", 9, "bold"))
        self.open_dir_btn.pack(fill="x")

        self.status_var = tk.StringVar(value="Status: Ready")
        self.status_lbl = tk.Label(left_frame, textvariable=self.status_var, font=("Helvetica", 9, "bold"), bg="#FFFFFF", fg="#000000")
        self.status_lbl.pack(anchor="w", pady=(16, 4))

        self.progress = ttk.Progressbar(left_frame, style="Red.Horizontal.TProgressbar", mode="determinate")
        self.progress.pack(fill="x")

        # 2B. Right Panel Notebook
        right_frame = tk.Frame(main_paned, bg="#FFFFFF", padx=10, pady=10, bd=2, relief="solid")
        main_paned.add(right_frame, minsize=600)

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Terminal Log
        self.tab_log = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_log, text="Terminal Log")
        self.log_text = tk.Text(self.tab_log, font=("Courier", 10), bg="#FFFFFF", fg="#000000", bd=1, relief="solid")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 2: Live Web Inventory
        self.tab_web = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_web, text="Web Inventory")
        self.web_tree = ttk.Treeview(self.tab_web, columns=("status", "url", "title", "tech", "cdn"), show="headings")
        self.web_tree.heading("status", text="Status")
        self.web_tree.heading("url", text="URL")
        self.web_tree.heading("title", text="Title")
        self.web_tree.heading("tech", text="Tech Stack & Versions")
        self.web_tree.heading("cdn", text="CDN/WAF")
        self.web_tree.column("status", width=60, anchor="center")
        self.web_tree.column("url", width=230)
        self.web_tree.column("title", width=170)
        self.web_tree.column("tech", width=160)
        self.web_tree.column("cdn", width=100)
        self.web_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 2.5: Service Versions
        self.tab_ver = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_ver, text="Service Versions")
        self.ver_tree = ttk.Treeview(self.tab_ver, columns=("url", "service", "version", "status"), show="headings")
        self.ver_tree.heading("url", text="Web Asset")
        self.ver_tree.heading("service", text="Service / Component")
        self.ver_tree.heading("version", text="Detected Version")
        self.ver_tree.heading("status", text="Security Status")
        self.ver_tree.column("url", width=230)
        self.ver_tree.column("service", width=150)
        self.ver_tree.column("version", width=120)
        self.ver_tree.column("status", width=220)
        self.ver_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 3: JS & API Surface
        self.tab_api = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_api, text="JS & APIs")
        self.api_tree = ttk.Treeview(self.tab_api, columns=("type", "target", "details"), show="headings")
        self.api_tree.heading("type", text="Type")
        self.api_tree.heading("target", text="Target")
        self.api_tree.heading("details", text="Details")
        self.api_tree.column("type", width=120)
        self.api_tree.column("target", width=260)
        self.api_tree.column("details", width=260)
        self.api_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 4: Cloud & Takeovers
        self.tab_cloud = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_cloud, text="Cloud & Takeovers")
        self.cloud_tree = ttk.Treeview(self.tab_cloud, columns=("provider", "url", "exposure"), show="headings")
        self.cloud_tree.heading("provider", text="Provider")
        self.cloud_tree.heading("url", text="Bucket / Target URL")
        self.cloud_tree.heading("exposure", text="Exposure")
        self.cloud_tree.column("provider", width=130)
        self.cloud_tree.column("url", width=300)
        self.cloud_tree.column("exposure", width=150)
        self.cloud_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 5: Attack Surface Drift
        self.tab_drift = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_drift, text="Drift Queue")
        self.drift_tree = ttk.Treeview(self.tab_drift, columns=("event", "target", "details"), show="headings")
        self.drift_tree.heading("event", text="Drift Event")
        self.drift_tree.heading("target", text="Target")
        self.drift_tree.heading("details", text="Details")
        self.drift_tree.column("event", width=140)
        self.drift_tree.column("target", width=240)
        self.drift_tree.column("details", width=260)
        self.drift_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 6: OWASP Hypotheses
        self.tab_hypo = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_hypo, text="OWASP Hypotheses")
        self.hypo_tree = ttk.Treeview(self.tab_hypo, columns=("priority", "category", "target", "hypothesis"), show="headings")
        self.hypo_tree.heading("priority", text="Priority")
        self.hypo_tree.heading("category", text="Category")
        self.hypo_tree.heading("target", text="Target")
        self.hypo_tree.heading("hypothesis", text="Hypothesis")
        self.hypo_tree.column("priority", width=80, anchor="center")
        self.hypo_tree.column("category", width=160)
        self.hypo_tree.column("target", width=180)
        self.hypo_tree.column("hypothesis", width=260)
        self.hypo_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 7: Executive Report
        self.tab_report = tk.Frame(self.notebook, bg="#FFFFFF")
        self.notebook.add(self.tab_report, text="Executive Report")
        self.report_text = tk.Text(self.tab_report, font=("Helvetica", 10), bg="#FFFFFF", fg="#000000", bd=1, relief="solid")
        self.report_text.pack(fill="both", expand=True, padx=4, pady=4)

        self._log("ARECON 2.0 Engine ready. Attack surface intelligence framework active.")

    def _log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")

    def _start_scan(self):
        target = self.domain_var.get().strip()
        if not target:
            messagebox.showwarning("Validation Error", "Please provide a target domain.")
            return

        if self.is_scanning:
            return

        self.is_scanning = True
        self.start_btn.set_state("disabled")
        self.progress["value"] = 5
        self.status_var.set(f"Scanning: {target}...")

        # Clear existing trees
        for tree in (self.web_tree, self.ver_tree, self.api_tree, self.cloud_tree, self.drift_tree, self.hypo_tree):
            for item in tree.get_children():
                tree.delete(item)

        thread = threading.Thread(target=self._run_scan_thread, args=(target,), daemon=True)
        thread.start()

    def _run_scan_thread(self, target: str):
        try:
            scope_raw = self.scope_text.get("1.0", "end")
            threads = int(self.threads_var.get() or "15")
            active_crawl = self.active_crawl_var.get()

            scope_file = None
            if scope_raw.strip():
                scope_file = os.path.join(SCRIPT_DIR, ".temp_scope.txt")
                with open(scope_file, "w", encoding="utf-8") as f:
                    f.write(scope_raw)

            self._log(f"Starting ARECON 2.0 execution on {target}")
            self.root.after(0, lambda: self.progress.config(value=20))

            res = recon.run_pipeline(
                target_domain=target,
                scope_file=scope_file,
                output_dir=self.results_dir,
                active_crawl=active_crawl,
                threads=threads,
                timeout=5,
                db=self.db,
            )

            self.root.after(0, lambda: self.progress.config(value=80))

            # Populate trees
            self.root.after(0, lambda: self._populate_trees(res))

            # Load report
            with open(res["report_file"], "r") as f:
                content = f.read()
            self.root.after(0, lambda: self._update_report(content))

            self._log(f"ARECON run completed. Intelligence saved in SQLite and {res['report_file']}")
            self.root.after(0, self._scan_complete)

        except Exception as e:
            self._log(f"Error: {e}")
            self.root.after(0, self._scan_error)

    def _populate_trees(self, res):
        # Web Tree
        for w in res.get("web_inventory", []):
            tech = ", ".join(w.get("technologies", [])) or "Generic"
            cdn = w.get("cdn_waf") or "—"
            self.web_tree.insert("", "end", values=(w["status_code"], w["url"], w.get("title", ""), tech, cdn))

        # Service Versions Tree
        for w in res.get("web_inventory", []):
            url = w.get("url", "")
            sv = w.get("service_versions", {})
            vf_map = {f["service"]: f for f in w.get("version_findings", [])}
            for svc, ver in sv.items():
                if svc == "OS":
                    continue
                status_str = "Supported"
                if svc in vf_map and vf_map[svc].get("type") == "OUTDATED_OR_EOL":
                    status_str = f"OUTDATED/EOL ({vf_map[svc].get('severity')})"
                elif ver and ver != "Detected":
                    status_str = "Version Disclosed"
                self.ver_tree.insert("", "end", values=(url, svc, ver, status_str))

        # API Tree
        for j in res.get("js_api_data", []):
            for s in j.get("openapi_specs", []):
                self.api_tree.insert("", "end", values=("OpenAPI/Swagger", s.get("spec_url"), f"{s.get('title')} ({len(s.get('routes', []))} routes)"))
            if j.get("graphql_endpoint"):
                g = j["graphql_endpoint"]
                intro = "Introspection OPEN" if g.get("introspection_enabled") else "Active"
                self.api_tree.insert("", "end", values=("GraphQL", g.get("graphql_url"), intro))
            for sm in j.get("source_maps_exposed", []):
                self.api_tree.insert("", "end", values=("Source Map", sm, "Exposed source code"))
            for r in j.get("extracted_api_routes", [])[:10]:
                self.api_tree.insert("", "end", values=("Client API", f"{j.get('base_url')}{r}", "Found in JS bundle"))

        # Cloud Tree
        for b in res.get("cloud_buckets", []):
            self.cloud_tree.insert("", "end", values=(b.get("provider"), b.get("url"), b.get("exposure")))

        # Drift Tree
        drift = res.get("drift_data")
        if drift and drift.get("has_drift"):
            for c_type, entries in drift.get("changes_by_type", {}).items():
                for e in entries:
                    self.drift_tree.insert("", "end", values=(c_type, e.get("target"), e.get("new_value")))

        # Hypotheses Tree
        for h in res.get("hypotheses", []):
            self.hypo_tree.insert("", "end", values=(h["priority"], h["category"], h["target"], h["hypothesis"]))

    def _update_report(self, content):
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", content)

    def _scan_complete(self):
        self.is_scanning = False
        self.progress["value"] = 100
        self.status_var.set("Status: Completed")
        self.start_btn.set_state("normal")
        messagebox.showinfo("ARECON Finished", "Attack surface reconnaissance completed successfully!")

    def _scan_error(self):
        self.is_scanning = False
        self.status_var.set("Status: Error")
        self.start_btn.set_state("normal")
        messagebox.showerror("ARECON Error", "An error occurred during reconnaissance execution.")

    def _open_output_dir(self):
        os.makedirs(self.results_dir, exist_ok=True)
        if sys.platform == "darwin":
            subprocess.run(["open", self.results_dir])
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", self.results_dir])
        elif os.name == "nt":
            os.startfile(self.results_dir)

    def _open_web_ui(self):
        script_path = os.path.join(SCRIPT_DIR, "arecon_web.py")
        subprocess.Popen([sys.executable, script_path])
        time.sleep(0.8)
        webbrowser.open("http://127.0.0.1:8088")


def main():
    root = tk.Tk()
    app = ARECONApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
