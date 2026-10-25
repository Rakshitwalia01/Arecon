#!/usr/bin/env bash
# ==============================================================================
# ARECON GUI Launcher — By Rakshit Walia
# Copyright (c) 2026 Rakshit Walia. All rights reserved.
# License: MIT License
# Theme: Clean White Background, Red Buttons, Black Text
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TK_SILENCE_DEPRECATION=1

# Detect python executable across Linux, macOS, BSD
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "Error: Python 3 is required but neither 'python3' nor 'python' was found in PATH." >&2
    exit 1
fi

echo "=============================================================="
echo " ARECON 2.0 — Web Application Reconnaissance GUI"
echo " Author: RAKSHIT WALIA"
echo " Theme:  White Background | Red Buttons | Black Text"
echo "=============================================================="

MODE="${1:---desktop}"

if [[ "$MODE" == "--web" || "$MODE" == "-w" ]]; then
    echo "[*] Launching ARECON Web Dashboard in your browser..."
    exec "$PYTHON_CMD" "${SCRIPT_DIR}/arecon_web.py"
elif [[ "$MODE" == "--desktop" || "$MODE" == "-d" ]]; then
    echo "[*] Launching ARECON Native Desktop Window..."
    exec "$PYTHON_CMD" "${SCRIPT_DIR}/arecon_gui.py"
else
    echo "Usage: $0 [--desktop | --web]"
    echo "  --desktop, -d   Launch native Desktop GUI (Default)"
    echo "  --web, -w       Launch modern local Web Dashboard in Browser"
    exit 1
fi
