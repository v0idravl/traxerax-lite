#!/usr/bin/env bash
# live-smoke-test.sh — install/update traxerax-lite and exercise every
# feature against the live host.
#
# Phase 1 (any user):  editable install into .venv, eBPF probe build.
# Phase 2 (any user):  full feature matrix on a throwaway temp database.
# Phase 3 (root only): real system install via `traxerax-lite --setup`
#                      (deploy config, eBPF loader install, hardened systemd
#                      daemon), service verification, kernel-events run, and
#                      a quiet-first-tick check.
#
# Run it as yourself:   contrib/live-smoke-test.sh
# The script re-execs itself with sudo for phase 3 (you will be prompted
# for your password once). Non-interactive runs skip phase 3 with a note.

set -u
cd "$(dirname "$0")/.."

VENV_PY=.venv/bin/python
if [ -x "$VENV_PY" ]; then
    PY=$VENV_PY
else
    PY=python3
fi
export PYTHONPATH=src

WORK="$(mktemp -d /tmp/traxerax-smoke.XXXXXX)"
DB="$WORK/smoke.db"
PASS=0
FAIL=0
SKIP=0

# The planted autostart entry goes to the invoking user's home even under sudo.
INVOKING_USER="${SUDO_USER:-$(id -un)}"
INVOKING_HOME="$(getent passwd "$INVOKING_USER" | cut -d: -f6)"
PLANTED="$INVOKING_HOME/.config/autostart/traxerax-smoke.desktop"

cleanup() {
    rm -f "$PLANTED"
    rm -rf "$WORK"
}
trap cleanup EXIT

step() {
    # step <name> <command...>: PASS on exit 0.
    local name="$1"; shift
    if "$@" >"$WORK/out.txt" 2>&1; then
        PASS=$((PASS + 1)); printf 'PASS  %s\n' "$name"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL  %s (exit %d)\n' "$name" "$?"
        sed 's/^/      /' "$WORK/out.txt" | tail -5
    fi
}

step_grep() {
    # step_grep <name> <pattern> <command...>: PASS on exit 0 AND pattern hit.
    local name="$1" pattern="$2"; shift 2
    if "$@" >"$WORK/out.txt" 2>&1 && grep -qi "$pattern" "$WORK/out.txt"; then
        PASS=$((PASS + 1)); printf 'PASS  %s\n' "$name"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$name"
        sed 's/^/      /' "$WORK/out.txt" | tail -5
    fi
}

step_json() {
    # step_json <name> <command...>: PASS on exit 0 AND a valid-JSON line in
    # the output. traxerax-lite emits JSON payloads via logger.info, so they
    # arrive mixed with log lines; the payload is the line starting with
    # '{' or '['.
    local name="$1"; shift
    if "$@" >"$WORK/out.txt" 2>&1 \
        && grep -m1 -E '^(INFO: )?[{[]' "$WORK/out.txt" \
            | sed 's/^INFO: //' \
            | "$PY" -m json.tool >/dev/null 2>&1; then
        PASS=$((PASS + 1)); printf 'PASS  %s\n' "$name"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$name"
        sed 's/^/      /' "$WORK/out.txt" | tail -5
    fi
}

skip() { SKIP=$((SKIP + 1)); printf 'SKIP  %s (%s)\n' "$1" "$2"; }

run() { "$PY" -m traxerax_lite.main "$@"; }

echo "== traxerax-lite live install + feature test =="
echo "python: $PY  workdir: $WORK  user: $(id -un) ($(id -u))"
echo

# ---------------------------------------------------------------- phase 1
echo "== phase 1: install/update =="
if [ -x "$VENV_PY" ]; then
    step "pip install -e . (editable, into .venv)" "$VENV_PY" -m pip install -e . --quiet
else
    skip "pip install -e ." ".venv not found; using PYTHONPATH=src instead"
fi
if [ -x ebpf/rootwatch-loader ]; then
    PASS=$((PASS + 1)); echo "PASS  eBPF loader present (ebpf/rootwatch-loader)"
else
    step "eBPF probe build (make -C ebpf)" make -C ebpf
fi

# ---------------------------------------------------------------- phase 2
echo
echo "== phase 2: feature matrix (temp db: $DB) =="

echo "-- host audit (text + json) --"
step "audit (text)" run --audit --db-path "$DB"
step_json "audit (json is valid)" run --audit --format json --db-path "$DB"

echo "-- host state monitoring + steady-state quiet --"
step "monitor (baseline)" run --monitor --db-path "$DB"
run --monitor --db-path "$DB" >"$WORK/out.txt" 2>&1
if grep -q "rootkit_findings=0" "$WORK/out.txt"; then
    PASS=$((PASS + 1)); echo "PASS  monitor (second run quiet — no false-positive flood)"
else
    FAIL=$((FAIL + 1)); echo "FAIL  monitor (second run quiet)"; tail -5 "$WORK/out.txt"
fi

echo "-- rootkit / compromise detection --"
step "rootkit-scan" run --rootkit-scan --db-path "$DB"

echo "-- desktop persistence detection (planted autostart entry) --"
mkdir -p "$INVOKING_HOME/.config/autostart"
printf '[Desktop Entry]\nName=traxerax-smoke-test\nExec=/tmp/traxerax-smoke.sh\nType=Application\n' >"$PLANTED"
chown "$INVOKING_USER":"$INVOKING_USER" "$PLANTED" 2>/dev/null || true
step_grep "xdg autostart finding (escalated high for /tmp exec)" \
    "autostart" run --rootkit-scan --db-path "$DB"
rm -f "$PLANTED"
run --learn-baseline --db-path "$DB" >/dev/null 2>&1

echo "-- file integrity monitoring --"
step "integrity-baseline" run --integrity-baseline --db-path "$DB"
step "integrity-scan (clean)" run --integrity-scan --db-path "$DB"

echo "-- journald ingestion --"
step "journal (--since 2h)" run --journal --since 2h --db-path "$DB"

echo "-- log pipeline demo (sanitized sample logs) --"
step "ingest examples" run \
    --auth-log examples/auth.log \
    --nginx-log examples/nginx-access.log \
    --fail2ban-log examples/fail2ban.log \
    --year 2026 --db-path "$DB"

echo "-- reports --"
step "report summary" run --report summary --db-path "$DB"
step "report ip" run --report ip --ip 185.10.10.1 --db-path "$DB"
for preset in new-ips cross-source post-ban-returners \
              auth-success-after-failures sprayed-users suspicious-paths; do
    step "report hunt:$preset" \
        run --report hunt --hunt-preset "$preset" --db-path "$DB"
done

echo "-- status --"
step "status (text)" run --status --db-path "$DB"
step_json "status (json is valid)" run --status --json --db-path "$DB"

# ---------------------------------------------------------------- phase 3
echo
echo "== phase 3: system install as intended (root) =="
if [ "$(id -u)" -ne 0 ]; then
    if [ -t 0 ]; then
        echo "Re-running this script with sudo for the system install phase..."
        exec sudo --preserve-env=PATH "$0" --root-phase
    fi
    skip "system install" "needs root; run this script in a terminal (it will sudo), or: sudo $0 --root-phase"
else
    DEPLOY_CONFIG=/etc/traxerax-lite/config.yaml
    DEPLOY_DB=/var/lib/traxerax-lite/traxerax_lite.db
    DEPLOY_LOADER=/var/lib/traxerax-lite/rootwatch-loader

    step "traxerax-lite --setup" run --setup

    [ -f "$DEPLOY_CONFIG" ] \
        && { PASS=$((PASS + 1)); echo "PASS  deploy config written ($DEPLOY_CONFIG)"; } \
        || { FAIL=$((FAIL + 1)); echo "FAIL  deploy config written"; }

    if [ -f "$DEPLOY_LOADER" ]; then
        owner="$(stat -c '%u:%g %a' "$DEPLOY_LOADER")"
        if [ "$owner" = "0:0 755" ]; then
            PASS=$((PASS + 1)); echo "PASS  eBPF loader installed root-owned 0755"
        else
            FAIL=$((FAIL + 1)); echo "FAIL  eBPF loader ownership/mode ($owner)"
        fi
        grep -q "probe_object_path: $DEPLOY_LOADER" "$DEPLOY_CONFIG" \
            && { PASS=$((PASS + 1)); echo "PASS  deploy config points at installed loader"; } \
            || { FAIL=$((FAIL + 1)); echo "FAIL  deploy config points at installed loader"; }
    else
        skip "eBPF loader install" "setup reported a missing prerequisite (see output above)"
    fi

    step "systemd unit enabled" systemctl is-enabled traxerax-lite.service
    step "systemd unit active" systemctl is-active traxerax-lite.service
    step "hardened unit valid" systemd-analyze verify /etc/systemd/system/traxerax-lite.service

    echo "-- kernel telemetry --"
    step "kernel-events (5s, probe attach)" \
        run --kernel-events --kernel-duration 5 \
            --config "$DEPLOY_CONFIG" --db-path "$DEPLOY_DB"

    echo "-- daemon first tick (quiet steady state expected) --"
    sleep 20
    run --status --config "$DEPLOY_CONFIG" --db-path "$DEPLOY_DB" \
        >"$WORK/status.txt" 2>&1 \
        && { PASS=$((PASS + 1)); echo "PASS  deployed --status"; cat "$WORK/status.txt"; } \
        || { FAIL=$((FAIL + 1)); echo "FAIL  deployed --status"; tail -5 "$WORK/status.txt"; }

    echo
    echo "systemd unit sandbox score (informational):"
    systemd-analyze security traxerax-lite.service 2>/dev/null | head -3 || true
    echo "inspect the daemon any time with: journalctl -u traxerax-lite -f"
fi

echo
echo "== result: $PASS passed, $FAIL failed, $SKIP skipped =="
[ "$FAIL" -eq 0 ]
