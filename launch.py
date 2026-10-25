#!/usr/bin/env python3
"""
ARECON 2.0 Universal Cross-Platform Launcher
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License
Platform: Windows, macOS, Linux, BSD

Usage:
    python launch.py           # Launch native desktop GUI
    python launch.py --desktop # Launch native desktop GUI
    python launch.py --web     # Launch web dashboard at http://127.0.0.1:8088
    python launch.py --cli -d example.com # Run CLI reconnaissance directly
"""

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


def print_banner():
    print("=" * 62)
    print(" ARECON 2.0 — Attack Surface Management & Reconnaissance")
    print(" Author: RAKSHIT WALIA")
    print(" Copyright (c) 2026 Rakshit Walia. All rights reserved.")
    print(" Theme:  White Background | Red Buttons | Black Text")
    print("=" * 62)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--web", "-w"):
        import arecon_web
        arecon_web.launch_web_gui()
    elif len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c"):
        import recon
        sys.argv.pop(1)
        recon.main()
    elif len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        print_banner()
        print("\nUniversal Launcher Options:")
        print("  python launch.py           Launch native desktop GUI (Default)")
        print("  python launch.py --web     Launch modern web dashboard in browser")
        print("  python launch.py --cli -d <domain> [options]  Run CLI reconnaissance engine")
    else:
        try:
            import arecon_gui
            arecon_gui.main()
        except ImportError:
            # Fallback to web GUI if tkinter is not installed (e.g. headless Linux servers)
            print("[INFO] Desktop environment (Tkinter) not available. Launching Web Dashboard...")
            import arecon_web
            arecon_web.launch_web_gui()


if __name__ == "__main__":
    main()
