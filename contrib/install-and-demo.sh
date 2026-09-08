#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# One-time install + demo script for traxerax-lite.
#
# What it does:
#   1. Installs system dependencies via apt (with sudo)
#   2. Creates a virtualenv and installs Python dependencies
#   3. Builds the optional eBPF kernel probe (skips gracefully if not possible)
#   4. Runs a full demo against the real host: real log analysis, report,
#      host audit, integrity baseline + scan, and a short rootkit scan
#
# Usage:
#   bash contrib/install-and-demo.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VENV="$REPO_ROOT/.venv"
PYTHON="$VENV/bin/python"
DEMO_DB="/tmp/traxerax-lite-demo.db"

banner() {
    printf '\n\033[1m\033[36m== %s ==\033[0m\n' "$1"
}

run_root() {
    sudo env PYTHONPATH=src "$PYTHON" "$@"
}

banner "1/6  Installing system dependencies (sudo)"
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y \
        python3-venv python3-pip \
        clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev
else
    echo "WARNING: apt-get not found. Skipping system packages."
    echo "Ensure python3-venv, clang, llvm-strip, bpftool, and libbpf are installed."
fi

banner "2/6  Setting up Python virtualenv"
if [ ! -x "$PYTHON" ]; then
    python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r requirements.txt pyyaml

banner "3/6  Building eBPF kernel probe (optional)"
if [ -f /sys/kernel/btf/vmlinux ]; then
    if make -C ebpf; then
        echo "eBPF loader built: ebpf/rootwatch-loader"
    else
        echo "WARNING: eBPF build failed; continuing without kernel telemetry."
    fi
else
    echo "Kernel BTF not available; skipping eBPF build."
    echo "(rootkit detection will fall back to /proc-based checks)"
fi

banner "4/6  Demo: real log analysis + summary report (sudo)"
rm -f "$DEMO_DB"
sudo rm -f "$DEMO_DB"

# Pick the first existing path for each real log source.
first_of() {
    local p
    for p in "$@"; do
        if [ -r "$p" ] || sudo test -r "$p"; then
            printf '%s' "$p"
            return 0
        fi
    done
    return 1
}

LOG_ARGS=()
if AUTH_LOG=$(first_of /var/log/auth.log /var/log/secure); then
    LOG_ARGS+=(--auth-log "$AUTH_LOG")
fi
if FAIL2BAN_LOG=$(first_of /var/log/fail2ban.log); then
    LOG_ARGS+=(--fail2ban-log "$FAIL2BAN_LOG")
fi
if NGINX_LOG=$(first_of /var/log/nginx/access.log); then
    LOG_ARGS+=(--nginx-log "$NGINX_LOG")
fi
if MAIL_LOG=$(first_of /var/log/mail.log /var/log/maillog); then
    LOG_ARGS+=(--mail-log "$MAIL_LOG")
fi

if [ ${#LOG_ARGS[@]} -eq 0 ]; then
    echo "No supported log files found on this host; skipping log ingestion."
else
    echo "Ingesting: ${LOG_ARGS[*]}"
    run_root -m traxerax_lite.main "${LOG_ARGS[@]}" --db-path "$DEMO_DB"
fi
run_root -m traxerax_lite.main \
    --report summary \
    --db-path "$DEMO_DB"

banner "5/6  Demo: host audit + file integrity (sudo)"
run_root -m traxerax_lite.main --audit --db-path "$DEMO_DB"
run_root -m traxerax_lite.main --integrity-baseline --db-path "$DEMO_DB"
run_root -m traxerax_lite.main --integrity-scan --db-path "$DEMO_DB"

banner "6/6  Demo: rootkit scan (sudo, short kernel window)"
if [ -x ebpf/rootwatch-loader ]; then
    run_root -m traxerax_lite.main --rootkit-scan --kernel-duration 5 --db-path "$DEMO_DB"
else
    echo "eBPF loader not built; running /proc-only rootkit scan instead."
    run_root -m traxerax_lite.main --rootkit-scan --kernel-duration 1 --db-path "$DEMO_DB"
fi

banner "Done"
echo "Demo database: $DEMO_DB (delete it whenever you like)"
echo ""
echo "Next steps:"
echo "  - Audit again:            sudo PYTHONPATH=src $PYTHON -m traxerax_lite.main --audit"
echo "  - Investigate one IP:     PYTHONPATH=src $PYTHON -m traxerax_lite.main --report ip --ip <addr> --db-path $DEMO_DB"
echo "  - Hunt presets:           PYTHONPATH=src $PYTHON -m traxerax_lite.main --report hunt --hunt-preset cross-source --db-path $DEMO_DB"
echo "  - Automate with cron:     see contrib/cron.example"
echo "  - Styling knobs:          NO_COLOR=1, TRAXERAX_COLOR=always|never, TRAXERAX_NO_GLYPHS=1"
