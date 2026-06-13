#!/usr/bin/env bash
#
# APTWatcher VM preparation -- provisions a SIFT workstation for development,
# evaluation, and submission.
#
# This is the heavier sibling of ../install.sh. Where install.sh only *probes*
# the forensic toolchain (and refuses to touch the system), this script will
# *install* any missing SIFT tools at the canonical paths that CLAUDE.md and
# the MCP wrappers under src/core/sift/ assume by default, then build the
# project virtualenv with the dev + docs extras needed to run the submission
# gates (see scripts/run-gates.sh).
#
# Design contract:
#   * Idempotent: safe to re-run. Present tools are detected and skipped.
#   * Explicit: every step announces itself; every network/apt/sudo call is
#     logged before it runs.
#   * Least privilege: refuses to run as root. Uses sudo only for the system
#     package and /opt installs, never for the project venv.
#   * Canonical paths only: installs to the exact paths the wrappers expect.
#     Override targets via the documented env vars if your layout differs.
#   * Non-destructive to evidence: touches only system package dirs, /opt,
#     and the project tree. Never writes into an evidence path.
#
# Usage:
#   bash scripts/prepare-vm.sh                 # full provision + python env
#   bash scripts/prepare-vm.sh --check-only    # verify only, install nothing
#   bash scripts/prepare-vm.sh --skip-tools    # python env only
#   bash scripts/prepare-vm.sh --skip-python   # forensic toolchain only
#
# Environment overrides:
#   APTW_VOL3_DIR        (default /opt/volatility3)
#   APTW_HAYABUSA_DIR    (default /opt/hayabusa)
#   APTW_HAYABUSA_VERSION(default: latest release resolved from GitHub)
#   APTW_TARGET_DIR      (default: this repository's root)
#   APTW_PYTHON          (default python3)
#
# Review this script before running it on a workstation you care about.

set -euo pipefail

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_DIR="${APTW_TARGET_DIR:-${REPO_ROOT}}"
PYTHON_BIN="${APTW_PYTHON:-python3}"
VENV_DIR="${TARGET_DIR}/.venv"
MIN_PY="3.11"

VOL3_DIR="${APTW_VOL3_DIR:-/opt/volatility3}"
HAYABUSA_DIR="${APTW_HAYABUSA_DIR:-/opt/hayabusa}"
HAYABUSA_VERSION="${APTW_HAYABUSA_VERSION:-}"   # empty -> resolve latest

CHECK_ONLY=0
SKIP_TOOLS=0
SKIP_PYTHON=0

# -----------------------------------------------------------------------------
# Output helpers (timestamped; colour only on a TTY)
# -----------------------------------------------------------------------------

if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    C_INFO=$'\033[1;34m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'
    C_OK=$'\033[1;32m'; C_OFF=$'\033[0m'
else
    C_INFO=""; C_WARN=""; C_ERR=""; C_OK=""; C_OFF=""
fi

_ts()  { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log()  { printf "%s %s[INFO]%s %s\n" "$(_ts)" "${C_INFO}" "${C_OFF}" "$*"; }
ok()   { printf "%s %s[ OK ]%s %s\n" "$(_ts)" "${C_OK}"   "${C_OFF}" "$*"; }
warn() { printf "%s %s[WARN]%s %s\n" "$(_ts)" "${C_WARN}" "${C_OFF}" "$*" >&2; }
die()  { printf "%s %s[FAIL]%s %s\n" "$(_ts)" "${C_ERR}"  "${C_OFF}" "$*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

while [ "$#" -gt 0 ]; do
    case "$1" in
        --check-only) CHECK_ONLY=1 ;;
        --skip-tools) SKIP_TOOLS=1 ;;
        --skip-python) SKIP_PYTHON=1 ;;
        -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# sudo helper: log every privileged call before running it
# -----------------------------------------------------------------------------

run_sudo() {
    log "  SUDO: $*"
    sudo "$@"
}

# =============================================================================
# Step 1: preflight -- user, sudo, base tooling
# =============================================================================

log "Step 1/7: preflight checks"

if [ "$(id -u)" = "0" ]; then
    die "refuse to run as root. Run as a regular user with sudo available; the project venv must not be owned by root."
fi
ok "running as uid $(id -u) ($(id -un))"

if [ "${CHECK_ONLY}" -eq 0 ] && [ "${SKIP_TOOLS}" -eq 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "sudo not found; required to install system packages and /opt tools."
    command -v apt-get >/dev/null 2>&1 || die "apt-get not found. This script targets the Debian/Ubuntu-based SIFT workstation."
    ok "sudo and apt-get available"
fi

for bin in git curl; do
    command -v "${bin}" >/dev/null 2>&1 || die "${bin} is required and was not found on PATH."
done
ok "git and curl present"

command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "${PYTHON_BIN} not found on PATH."
if ! "${PYTHON_BIN}" -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"; then
    die "${PYTHON_BIN} is older than ${MIN_PY}. APTWatcher needs Python ${MIN_PY}+ (uses datetime.UTC)."
fi
ok "${PYTHON_BIN} $(${PYTHON_BIN} -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])') is >= ${MIN_PY}"

# =============================================================================
# Canonical SIFT tool table -- label|canonical_path
# =============================================================================

SIFT_TOOLS=(
    "Volatility 3|${VOL3_DIR}/vol.py"
    "Plaso log2timeline|/usr/bin/log2timeline.py"
    "Plaso psort|/usr/bin/psort.py"
    "Sleuthkit fls|/usr/bin/fls"
    "Sleuthkit icat|/usr/bin/icat"
    "bulk_extractor|/usr/bin/bulk_extractor"
    "YARA|/usr/bin/yara"
    "Hayabusa|${HAYABUSA_DIR}/hayabusa"
)

probe_tools() {
    local missing=0 entry label path
    for entry in "${SIFT_TOOLS[@]}"; do
        label="${entry%%|*}"; path="${entry##*|}"
        if [ -e "${path}" ]; then
            ok "  found:   ${label} at ${path}"
        else
            warn "  missing: ${label} -- expected at ${path}"
            missing=$((missing + 1))
        fi
    done
    return "${missing}"
}

# =============================================================================
# Step 2: apt-provided forensic tools (sleuthkit, bulk_extractor, yara, plaso)
# =============================================================================

install_apt_tools() {
    log "Step 2/7: apt-provided forensic tools"

    # pkg|sentinel_path -- install the package only if its sentinel is absent.
    local apt_targets=(
        "sleuthkit|/usr/bin/fls"
        "bulk-extractor|/usr/bin/bulk_extractor"
        "yara|/usr/bin/yara"
        "plaso-tools|/usr/bin/log2timeline.py"
    )
    local to_install=() entry pkg sentinel
    for entry in "${apt_targets[@]}"; do
        pkg="${entry%%|*}"; sentinel="${entry##*|}"
        if [ -e "${sentinel}" ]; then
            ok "  present: ${pkg} (${sentinel})"
        else
            warn "  will install: ${pkg}"
            to_install+=("${pkg}")
        fi
    done

    if [ "${#to_install[@]}" -eq 0 ]; then
        ok "  all apt-provided tools already present"
        return 0
    fi

    log "  NETWORK: apt-get update"
    run_sudo apt-get update -y
    log "  NETWORK: apt-get install ${to_install[*]}"
    run_sudo apt-get install -y "${to_install[@]}"
    ok "  apt tools installed"
}

# =============================================================================
# Step 3: Volatility 3 -> ${VOL3_DIR}/vol.py
# =============================================================================

install_volatility3() {
    log "Step 3/7: Volatility 3 at ${VOL3_DIR}"
    if [ -e "${VOL3_DIR}/vol.py" ]; then
        ok "  present: vol.py at ${VOL3_DIR}"
        return 0
    fi
    if [ ! -d "${VOL3_DIR}" ]; then
        log "  NETWORK: git clone volatility3 -> ${VOL3_DIR}"
        run_sudo git clone --depth 1 https://github.com/volatilityfoundation/volatility3.git "${VOL3_DIR}"
    fi
    if [ -f "${VOL3_DIR}/requirements.txt" ]; then
        log "  NETWORK: pip install volatility3 requirements (system)"
        run_sudo "${PYTHON_BIN}" -m pip install --break-system-packages -r "${VOL3_DIR}/requirements.txt" \
            || warn "  optional volatility3 requirements failed; core triage still works"
    fi
    [ -f "${VOL3_DIR}/vol.py" ] && ok "  Volatility 3 ready: python3 ${VOL3_DIR}/vol.py" \
        || die "  volatility3 clone did not yield ${VOL3_DIR}/vol.py"
}

# =============================================================================
# Step 4: Hayabusa -> ${HAYABUSA_DIR}/hayabusa
# =============================================================================

install_hayabusa() {
    log "Step 4/7: Hayabusa at ${HAYABUSA_DIR}"
    if [ -e "${HAYABUSA_DIR}/hayabusa" ]; then
        ok "  present: hayabusa at ${HAYABUSA_DIR}"
        return 0
    fi

    local ver="${HAYABUSA_VERSION}"
    if [ -z "${ver}" ]; then
        log "  NETWORK: resolving latest Hayabusa release tag from GitHub API"
        ver="$(curl -fsSL https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest \
            | grep -oE '"tag_name": *"[^"]+"' | head -n1 | sed -E 's/.*"([^"]+)"$/\1/')" \
            || die "  could not resolve latest Hayabusa version; set APTW_HAYABUSA_VERSION and re-run."
    fi
    local numver="${ver#v}"
    local asset="hayabusa-${numver}-lin-x64-gnu.zip"
    local url="https://github.com/Yamato-Security/hayabusa/releases/download/${ver}/${asset}"
    local tmp; tmp="$(mktemp -d)"

    log "  NETWORK: downloading ${asset}"
    curl -fsSL -o "${tmp}/hayabusa.zip" "${url}" \
        || die "  download failed: ${url} (check APTW_HAYABUSA_VERSION / asset name)"
    command -v unzip >/dev/null 2>&1 || run_sudo apt-get install -y unzip
    run_sudo mkdir -p "${HAYABUSA_DIR}"
    run_sudo unzip -o "${tmp}/hayabusa.zip" -d "${HAYABUSA_DIR}" >/dev/null

    # Release archives name the binary hayabusa-<ver>-lin-x64-gnu; normalize it.
    local bin
    bin="$(run_sudo find "${HAYABUSA_DIR}" -maxdepth 2 -type f -name 'hayabusa-*-lin-x64-gnu' | head -n1)"
    if [ -n "${bin}" ] && [ ! -e "${HAYABUSA_DIR}/hayabusa" ]; then
        run_sudo ln -sf "${bin}" "${HAYABUSA_DIR}/hayabusa"
    fi
    run_sudo chmod +x "${HAYABUSA_DIR}/hayabusa" 2>/dev/null || true
    rm -rf "${tmp}"
    [ -e "${HAYABUSA_DIR}/hayabusa" ] && ok "  Hayabusa ready: ${HAYABUSA_DIR}/hayabusa" \
        || die "  Hayabusa binary not found after extraction in ${HAYABUSA_DIR}"
}

# =============================================================================
# Step 5: project virtualenv + editable install with dev/docs extras
# =============================================================================

setup_python_env() {
    log "Step 5/7: project virtualenv at ${VENV_DIR}"
    if [ -x "${VENV_DIR}/bin/python" ]; then
        ok "  venv present -- reusing"
    else
        "${PYTHON_BIN}" -m venv "${VENV_DIR}"
        ok "  venv created"
    fi
    # shellcheck disable=SC1091
    . "${VENV_DIR}/bin/activate"
    log "  NETWORK: pip install --upgrade pip"
    python -m pip install --upgrade pip >/dev/null
    log "  NETWORK: pip install -e .[dev,docs] (test + lint + mkdocs toolchain)"
    ( cd "${TARGET_DIR}" && python -m pip install -e ".[dev,docs]" )
    ok "  aptwatcher installed with dev + docs extras"
}

# =============================================================================
# Step 6: preflight the agent against the freshly provisioned toolchain
# =============================================================================

run_preflight() {
    log "Step 6/7: aptwatcher preflight"
    if [ -x "${VENV_DIR}/bin/aptwatcher" ]; then
        "${VENV_DIR}/bin/aptwatcher" preflight || warn "  preflight reported issues -- review output above"
    else
        warn "  aptwatcher CLI not in venv; skipping preflight (run scripts/prepare-vm.sh without --skip-python)"
    fi
}

# =============================================================================
# Main
# =============================================================================

if [ "${CHECK_ONLY}" -eq 1 ]; then
    log "Check-only mode: verifying canonical SIFT toolchain, installing nothing"
    if probe_tools; then
        ok "all SIFT tools present at canonical paths"
        exit 0
    else
        warn "one or more SIFT tools missing -- re-run without --check-only to provision"
        exit 1
    fi
fi

if [ "${SKIP_TOOLS}" -eq 0 ]; then
    install_apt_tools
    install_volatility3
    install_hayabusa
else
    log "Steps 2-4/7: --skip-tools set, skipping forensic toolchain"
fi

if [ "${SKIP_PYTHON}" -eq 0 ]; then
    setup_python_env
    run_preflight
else
    log "Steps 5-6/7: --skip-python set, skipping Python environment"
fi

# =============================================================================
# Step 7: final verification + summary
# =============================================================================

log "Step 7/7: final verification"
final_missing=0
probe_tools || final_missing=$?

echo
if [ "${final_missing}" -eq 0 ]; then
    ok "VM preparation complete -- all canonical SIFT tools present"
else
    warn "VM preparation finished with ${final_missing} tool(s) still missing (see above)"
fi

cat <<EOF

Next steps:
  1. Activate the venv:        source ${VENV_DIR}/bin/activate
  2. Run the submission gates: bash ${SCRIPT_DIR}/run-gates.sh
  3. Read the operator runbook: ${TARGET_DIR}/RUNBOOK.md

EOF

[ "${final_missing}" -eq 0 ] || exit 1
ok "prepare-vm.sh finished cleanly"
