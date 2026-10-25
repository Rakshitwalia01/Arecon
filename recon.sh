#!/usr/bin/env bash
# ==============================================================================
# ARECON Reconnaissance CLI Wrapper — Bug Bounty & Security Assessments
# Author: Rakshit Walia
# Copyright (c) 2026 Rakshit Walia. All rights reserved.
# License: MIT License
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_ENGINE="${SCRIPT_DIR}/recon.py"

if [[ ! -f "$PYTHON_ENGINE" ]]; then
    echo "Error: Python engine not found at $PYTHON_ENGINE" >&2
    exit 1
fi

# Detect python executable across Linux, macOS, BSD
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "Error: Python 3 is required but neither 'python3' nor 'python' was found in PATH." >&2
    exit 1
fi

# Pass all arguments directly to the unified python recon engine
exec "$PYTHON_CMD" "$PYTHON_ENGINE" "$@"
