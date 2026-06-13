#!/usr/bin/env bash
#
# APTWatcher installer -- bootstraps the agent on a SIFT workstation.
#
# Design contract (see CLAUDE.md in the repository root):
#   * Evidence-machine safe: refuses to run as root, never writes outside
#     the target repo and its virtualenv.
#   * Idempotent: safe to re-run. Re-running updates the clone and
#     reinstalls the Python package into the existing venv.
#   * Explicit: every step prints what it is about to do before doing it,
#     and every network call (git clone, pip install) is logged.
#   * Tool-probe only: reports missing SIFT binaries but never tries to
#     install them. The installer assumes SIFT is already provisioned.
#
# Usage:
#   bash install.sh
#   or, once it ships at a public URL:
#       curl -fsSL <raw-url>/install.sh | bash
#
# Review this script before piping it into bash on a workstation you care
# about. That is the correct default stance for any curl-pipe installer.

set -euo pipefail

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

REPO_URL="${APTW_REPO_URL:-https://github.com/aptwatcher/APTWatcher.git}"
TARGET_DIR="${APTW_TARGET_DIR:-${HOME}/APTWatcher}"
MIN_PY="3.11"
VENV_DIR=".venv"

# Temp scratch for the trap; set empty so the trap can test safely.
TMP_WORK=""

# -----------------------------------------------------------------------------
# Output helpers (timestamped; colour only when attached to a TTY)
# -----------------------------------------------------------------------------

if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    C_INFO=$'\033[1;34m'
    C_WARN=$'\033[1;33m'
    C_ERR=$'\033[1;31m'
    C_OK=$'\033[1;32m'
    C_OFF=$'\033[0m'
else
    C_INFO=""; C_WARN=""; C_ERR=""; C_OK=""; C_OFF=""
fi

_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log()  { printf "%s %s[INFO]%s %s\n"  "$(_ts)" "${C_INFO}" "${C_OFF}" "$*"; }
ok()   { printf "%s %s[ OK ]%s %s\n"  "$(_ts)" "${C_OK}"   "${C_OFF}" "$*"; }
warn() { printf "%s %s[WARN]%s %s\n"  "$(_ts)" "${C_WARN}" "${C_OFF}" "$*" >&2; }
die()  { printf "%s %s[FAIL]%s %s\n"  "$(_ts)" "${C_ERR}"  "${C_OFF}" "$*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Trap: clean up scratch dir; on non-zero exit, point the user somewhere useful
# -----------------------------------------------------------------------------

cleanup() {
    local rc=$?
    if [ -n "${TMP_WORK}" ] && [ -d "${TMP_WORK}" ]; then
        rm -rf -- "${TMP_WORK}"
    fi
    if [ "${rc}" -ne 0 ]; then
        warn "Installer exited with status ${rc}."
        warn "Review docs/TRY-IT-OUT.md for the manual install path, or file an issue."
    fi
    exit "${rc}"
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------------------
# Step 1: refuse root
# -----------------------------------------------------------------------------

log "Step 1/10: checking effective user id"
if [ "$(id -u)" = "0" ]; then
    die "refuse to run as root. APTWatcher operates in read-only evidence mode; installers on evidence machines must run as a regular user with sudo available."
fi
ok "running as uid $(id -u) ($(id -un))"

# -----------------------------------------------------------------------------
# Step 2: Python version check
# -----------------------------------------------------------------------------

log "Step 2/10: verifying Python >= ${MIN_PY}"
if ! command -v python3 >/dev/null 2>&1; then
    die "python3 not found on PATH. Install Python ${MIN_PY} or newer and re-run."
fi

# Python version-check snippet -- single source of truth, exits 0 if OK.
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"; then
    PY_VER="$(python3 -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])' 2>/dev/null || echo unknown)"
    die "Python ${PY_VER} is too old. APTWatcher requires Python ${MIN_PY}+ (uses datetime.UTC). Install a newer interpreter and re-run."
fi
ok "python3 $(python3 -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])') is >= ${MIN_PY}"

# -----------------------------------------------------------------------------
# Step 3: baseline dependencies (info only, not all fatal)
# -----------------------------------------------------------------------------

log "Step 3/10: probing baseline dependencies"
for bin in git curl sudo; do
    if command -v "${bin}" >/dev/null 2>&1; then
        ok "  found: ${bin} -> $(command -v "${bin}")"
    else
        if [ "${bin}" = "git" ]; then
            die "git is required for clone/update and was not found on PATH."
        fi
        warn "  missing: ${bin} (non-fatal, but some workflows expect it)"
    fi
done

if python3 -m pip --version >/dev/null 2>&1; then
    ok "  found: python3 -m pip ($(python3 -m pip --version | awk '{print $1, $2}'))"
else
    die "python3 -m pip is unavailable. Install python3-pip (or ensurepip) and re-run."
fi

# -----------------------------------------------------------------------------
# Step 4: SIFT tool probes (info only; installer never installs these)
# -----------------------------------------------------------------------------

log "Step 4/10: probing SIFT forensic toolchain (informational)"

# Each entry is "label|canonical_path". The canonical paths are the ones
# CLAUDE.md and the MCP wrappers under src/core/sift/ assume by default.
SIFT_TOOLS=(
    "Volatility 3|/opt/volatility3/vol.py"
    "Plaso log2timeline|/usr/bin/log2timeline.py"
    "Plaso psort|/usr/bin/psort.py"
    "Sleuthkit fls|/usr/bin/fls"
    "Sleuthkit icat|/usr/bin/icat"
    "bulk_extractor|/usr/bin/bulk_extractor"
    "YARA|/usr/bin/yara"
    "Hayabusa|/opt/hayabusa/hayabusa"
)

sift_missing=0
for entry in "${SIFT_TOOLS[@]}"; do
    label="${entry%%|*}"
    path="${entry##*|}"
    if [ -e "${path}" ]; then
        ok "  found:   ${label} at ${path}"
    else
        warn "  missing: ${label} -- expected at ${path} (canonical per CLAUDE.md)"
        sift_missing=$((sift_missing + 1))
    fi
done

if [ "${sift_missing}" -gt 0 ]; then
    warn "${sift_missing} SIFT tool(s) missing. APTWatcher will still install;"
    warn "preflight will mark those wrappers as MISSING_REQUIRED at run time."
    warn "This installer does not install SIFT binaries -- provision SIFT separately."
else
    ok "all probed SIFT tools present at canonical paths"
fi

# -----------------------------------------------------------------------------
# Step 5: clone or update the repo
# -----------------------------------------------------------------------------

log "Step 5/10: ensuring repo at ${TARGET_DIR}"
if [ -d "${TARGET_DIR}/.git" ]; then
    log "  existing clone detected at ${TARGET_DIR} -- running git pull"
    log "  NETWORK: git -C ${TARGET_DIR} pull --ff-only"
    git -C "${TARGET_DIR}" pull --ff-only
    ok "  repo updated"
elif [ -e "${TARGET_DIR}" ]; then
    die "${TARGET_DIR} exists but is not a git checkout. Move it aside or set APTW_TARGET_DIR to a free path, then re-run."
else
    log "  NETWORK: git clone ${REPO_URL} ${TARGET_DIR}"
    git clone "${REPO_URL}" "${TARGET_DIR}"
    ok "  repo cloned"
fi

# -----------------------------------------------------------------------------
# Step 6: create or reuse the virtualenv
# -----------------------------------------------------------------------------

log "Step 6/10: creating virtualenv at ${TARGET_DIR}/${VENV_DIR}"
if [ -x "${TARGET_DIR}/${VENV_DIR}/bin/python" ]; then
    ok "  venv already present -- reusing"
else
    python3 -m venv "${TARGET_DIR}/${VENV_DIR}"
    ok "  venv created"
fi

# shellcheck disable=SC1091
# Activation is intentional: we want subsequent pip calls inside the venv.
. "${TARGET_DIR}/${VENV_DIR}/bin/activate"
ok "  venv activated: $(command -v python)"

# -----------------------------------------------------------------------------
# Step 7: upgrade pip inside the venv
# -----------------------------------------------------------------------------

log "Step 7/10: upgrading pip inside the venv"
log "  NETWORK: pip install --upgrade pip"
python -m pip install --upgrade pip

# -----------------------------------------------------------------------------
# Step 8: install APTWatcher in editable mode
# -----------------------------------------------------------------------------

log "Step 8/10: installing APTWatcher (editable) from ${TARGET_DIR}"
log "  NETWORK: pip install -e ${TARGET_DIR}"
( cd "${TARGET_DIR}" && python -m pip install -e . )
ok "  aptwatcher installed"

# -----------------------------------------------------------------------------
# Step 9: smoke test the console script
# -----------------------------------------------------------------------------

log "Step 9/10: smoke-testing the aptwatcher CLI"
if command -v aptwatcher >/dev/null 2>&1; then
    # `aptwatcher version` is the defined subcommand (see src/agent_extension/cli.py).
    if aptwatcher version >/dev/null 2>&1; then
        ok "  aptwatcher version: $(aptwatcher version 2>/dev/null | head -n 1)"
    else
        warn "  aptwatcher on PATH but 'aptwatcher version' failed -- try 'aptwatcher --help' manually"
    fi
else
    warn "  aptwatcher not on PATH after install -- activate the venv first:"
    warn "    source ${TARGET_DIR}/${VENV_DIR}/bin/activate"
fi

# -----------------------------------------------------------------------------
# Step 10: next steps
# -----------------------------------------------------------------------------

log "Step 10/10: install complete -- next steps"
cat <<EOF

Next steps:
  1. Activate the venv in each new shell:
         source ${TARGET_DIR}/${VENV_DIR}/bin/activate
  2. Walk the judge-facing happy path:
         ${TARGET_DIR}/docs/TRY-IT-OUT.md
  3. Read the operating contract before driving real evidence:
         ${TARGET_DIR}/CLAUDE.md
  4. Browse the narrative scenarios:
         ${TARGET_DIR}/scenarios/README.md
  5. Render the run audit log for a completed incident:
         aptwatcher audit-render --help

Read-only evidence mode is the default. Tier 1+ adapters (TAXII, MISP,
Netcraft, GLPI) ship with dry_run=True; publication requires an explicit
--live flag and a signed IncidentBundle.

EOF

ok "APTWatcher installer finished cleanly"
