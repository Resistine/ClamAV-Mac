#!/bin/bash
# Comprehensive macOS verification for ClamAV + clamd + clamonacc (ESF).
#
# Run:
#   ./scripts/tests/macos-verify.sh
#
# Optional:
#   RUN_FRESHCLAM=1 ./scripts/tests/macos-verify.sh   # update DBs (requires network + sudo)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

CLAM_PREFIX="/usr/local/clamav"
CLAMD="${CLAM_PREFIX}/sbin/clamd"
CLAMONACC="${CLAM_PREFIX}/sbin/clamonacc"
CLAMDSCAN="${CLAM_PREFIX}/bin/clamdscan"
CLAMSCAN="${CLAM_PREFIX}/bin/clamscan"
FRESHCLAM="${CLAM_PREFIX}/bin/freshclam"

CONF_CLAMD="${CLAM_PREFIX}/etc/clamd.conf"
DB_DIR="${CLAM_PREFIX}/share/clamav"

PASS=0
FAIL=0
WARN=0

say() { printf "%s\n" "$*"; }
ok()  { PASS=$((PASS+1)); printf "✓ %s\n" "$*"; }
bad() { FAIL=$((FAIL+1)); printf "✗ %s\n" "$*"; }
warn(){ WARN=$((WARN+1)); printf "! %s\n" "$*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { bad "Missing required command: $1"; return 1; }
}

section() {
  echo ""
  echo "=== $* ==="
}

have_file() {
  [[ -f "$1" ]] || { bad "Missing file: $1"; return 1; }
}

have_exec() {
  [[ -x "$1" ]] || { bad "Missing executable: $1"; return 1; }
}

check_port_3310() {
  if nc -z 127.0.0.1 3310 >/dev/null 2>&1; then
    ok "clamd port open: 127.0.0.1:3310"
    return 0
  fi
  bad "clamd port NOT reachable on 127.0.0.1:3310"
  say "  - Start clamd: sudo ${CLAMD} --config-file=${CONF_CLAMD} &"
  return 1
}

eicar_write() {
  local out="$1"
  # zsh-safe, bash-safe; prints a trailing newline.
  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\\n' > "$out"
}

section "Environment"
if [[ "$(uname -s)" != "Darwin" ]]; then
  warn "This verifier is designed for macOS (Darwin). Current: $(uname -s)"
fi
ok "Repo: ${ROOT_DIR}"

need_cmd nc || true
need_cmd ps || true
need_cmd grep || true
need_cmd awk || true
need_cmd sed || true
need_cmd shasum || true
need_cmd codesign || true
need_cmd otool || true
need_cmd log || true

section "Installed binaries"
have_exec "$CLAMD" || true
have_exec "$CLAMONACC" || true
have_exec "$CLAMDSCAN" || true
have_exec "$CLAMSCAN" || true
have_exec "$FRESHCLAM" || warn "freshclam not found (DB updates won't be possible via this script)"
have_file "$CONF_CLAMD" || true

section "Process status"
if pgrep -x clamd >/dev/null 2>&1; then
  ok "clamd process running"
else
  warn "clamd process not detected (that's OK if you're only using clamscan)"
fi

if pgrep -x clamonacc >/dev/null 2>&1; then
  ok "clamonacc process running"
else
  warn "clamonacc process not detected (on-access scanning is OFF)"
fi

section "clamd connectivity"
check_port_3310 || true

section "Database presence"
if [[ -d "$DB_DIR" ]]; then
  ok "DB directory exists: $DB_DIR"
else
  bad "DB directory missing: $DB_DIR"
  say "  - Create it: sudo mkdir -p $DB_DIR && sudo chown -R _clamav:_clamav $DB_DIR"
fi

sig_count="$(ls -1 "$DB_DIR" 2>/dev/null | egrep -c '\\.(cvd|cld)$' || true)"
if [[ "$sig_count" -ge 1 ]]; then
  ok "Found signature DB files: ${sig_count} file(s) in $DB_DIR"
else
  warn "No .cvd/.cld signatures found in $DB_DIR (scans will be ineffective)"
  say "  - Update DBs: sudo ${FRESHCLAM}"
fi

if [[ "${RUN_FRESHCLAM:-0}" == "1" ]]; then
  section "freshclam update (RUN_FRESHCLAM=1)"
  if [[ -x "$FRESHCLAM" ]]; then
    warn "Running freshclam (requires sudo + network)."
    sudo "$FRESHCLAM" || warn "freshclam returned non-zero (check output above)"
  else
    bad "freshclam requested but not installed at $FRESHCLAM"
  fi
fi

section "RPATH sanity (no build-tree paths)"
if [[ -x "$CLAMD" ]]; then
  if otool -l "$CLAMD" | grep -q "/build/"; then
    bad "clamd contains build-tree RPATHs (should not)."
  else
    ok "clamd RPATHs look clean (no /build/ paths)"
  fi
fi

if [[ -x "$CLAMONACC" ]]; then
  if otool -l "$CLAMONACC" | grep -q "/build/"; then
    bad "clamonacc contains build-tree RPATHs (should not)."
  else
    ok "clamonacc RPATHs look clean (no /build/ paths)"
  fi
fi

section "Code signing + entitlements"
if [[ -x "$CLAMONACC" ]]; then
  # Show entitlements and confirm ESF entitlement is present.
  if codesign -d --entitlements :- "$CLAMONACC" 2>/dev/null | grep -q "com.apple.developer.endpoint-security.client"; then
    ok "clamonacc has ESF entitlement (com.apple.developer.endpoint-security.client)"
  else
    bad "clamonacc missing ESF entitlement (cannot use Endpoint Security Framework)"
  fi
fi

section "On-demand scan test (EICAR)"
tmp_eicar="/tmp/eicar-verify-$$.txt"
eicar_write "$tmp_eicar"
ok "Created EICAR file: $tmp_eicar"

if [[ -x "$CLAMSCAN" ]]; then
  if "$CLAMSCAN" "$tmp_eicar" 2>/dev/null | grep -q "Eicar-Signature FOUND"; then
    ok "clamscan detects EICAR (standalone engine OK)"
  else
    warn "clamscan did NOT report EICAR as FOUND (DB missing/old?)"
  fi
else
  bad "clamscan missing at $CLAMSCAN"
fi

if nc -z 127.0.0.1 3310 >/dev/null 2>&1 && [[ -x "$CLAMDSCAN" ]]; then
  if "$CLAMDSCAN" "$tmp_eicar" 2>/dev/null | grep -q "Eicar-Signature FOUND"; then
    ok "clamdscan detects EICAR via clamd (daemon path OK)"
  else
    warn "clamdscan did NOT report EICAR as FOUND (clamd config/DB?)"
  fi
else
  warn "Skipping clamdscan test (clamd not reachable or clamdscan missing)"
fi

rm -f "$tmp_eicar" || true

section "On-access (clamonacc) smoke checks"
if pgrep -x clamonacc >/dev/null 2>&1; then
  ok "clamonacc is running"

  # ESF deadline crash patterns in recent logs (best-effort; may be empty if syslog disabled).
  if log show --last 5m --style compact --predicate 'process == "clamonacc" && (eventMessage CONTAINS "Corpse" || eventMessage CONTAINS "deadline" || eventMessage CONTAINS "EndpointSecurity client terminated")' 2>/dev/null | tail -1 | grep -q .; then
    warn "Recent clamonacc crash/deadline messages found (check: log show --last 10m --predicate 'process == \"clamonacc\"')"
  else
    ok "No obvious ESF deadline crash messages in last 5 minutes"
  fi

  warn "FDA/TCC note: If you see 'Caller lacks TCC authorization for Full Disk Access' in Console, grant Full Disk Access to clamonacc AND the launching app (Terminal/Cursor)."
else
  warn "clamonacc not running; on-access scanning is not active."
  say "  - Start: sudo ${CLAMONACC} -F --config-file=${CONF_CLAMD}"
fi

section "Summary"
say "PASS: ${PASS}  WARN: ${WARN}  FAIL: ${FAIL}"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi


