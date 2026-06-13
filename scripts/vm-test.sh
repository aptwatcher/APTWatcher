#!/usr/bin/env bash
#
# Autonomous in-VM deployment test for APTWatcher (Linux/macOS host).
#
# Bash twin of scripts/vm-test.ps1. Starts the SIFT VM headless, waits for the
# guest, delivers the source (git clone or local copy), runs prepare-vm.sh +
# run-gates.sh inside the guest, pulls the gate logs back, and powers off.
# All the real work lives in the two guest-side bash scripts; this only owns
# the VM lifecycle and remote-exec plumbing.
#
# Backends: VirtualBox (VBoxManage) and VMware (vmrun, Fusion/Workstation).
# Hyper-V is Windows-only -- use vm-test.ps1 there.
#
# SECURITY: no credentials in this file. Prefer an SSH key, or supply the guest
# password via APTW_GUEST_PASSWORD. In guest-control mode the password is
# written to a 0600 temp file and passed to VBoxManage via --passwordfile,
# never on the command line.
#
# Usage:
#   bash scripts/vm-test.sh --hypervisor virtualbox --vm-name SIFT \
#       --exec guest --guest-user <user> --source local      # SSH-free
#   bash scripts/vm-test.sh --hypervisor vmware --vmx /path/sift.vmx \
#       --exec ssh --guest-user <user> --guest-key ~/.ssh/sift --source git
#
# Exit code mirrors run-gates.sh inside the guest.

set -euo pipefail

# -----------------------------------------------------------------------------
# Defaults / env fallbacks
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

HYPERVISOR="auto"
EXEC="auto"
SOURCE="git"
VM_NAME="${APTW_VM_NAME:-}"
VMX="${APTW_VMX:-}"
REPO_URL="${APTW_REPO_URL:-https://github.com/aptwatcher/APTWatcher.git}"
LOCAL_REPO="${REPO_ROOT}"
TARGET_DIR="${APTW_TARGET_DIR:-~/APTWatcher}"
GUEST_USER="${APTW_GUEST_USER:-}"
GUEST_HOST="${APTW_GUEST_HOST:-}"
GUEST_KEY="${APTW_GUEST_KEY:-}"
GUEST_PASSWORD="${APTW_GUEST_PASSWORD:-}"
BOOT_TIMEOUT=300
FAST=0
KEEP_RUNNING=0

PWFILE=""
SSH_TARGET=""
SSH_OPTS=()
EXCLUDES=(.venv vm .git site __pycache__ .pytest_cache)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    C_INFO=$'\033[1;34m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_OK=$'\033[1;32m'; C_OFF=$'\033[0m'
else
    C_INFO=""; C_WARN=""; C_ERR=""; C_OK=""; C_OFF=""
fi
_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log()  { printf "%s %s[INFO]%s %s\n" "$(_ts)" "${C_INFO}" "${C_OFF}" "$*"; }
ok()   { printf "%s %s[ OK ]%s %s\n" "$(_ts)" "${C_OK}"   "${C_OFF}" "$*"; }
warn() { printf "%s %s[WARN]%s %s\n" "$(_ts)" "${C_WARN}" "${C_OFF}" "$*" >&2; }
die()  { printf "%s %s[FAIL]%s %s\n" "$(_ts)" "${C_ERR}"  "${C_OFF}" "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found on PATH: $1"; }

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --hypervisor) HYPERVISOR="$2"; shift 2 ;;
        --exec) EXEC="$2"; shift 2 ;;
        --source) SOURCE="$2"; shift 2 ;;
        --vm-name) VM_NAME="$2"; shift 2 ;;
        --vmx) VMX="$2"; shift 2 ;;
        --repo-url) REPO_URL="$2"; shift 2 ;;
        --local-repo) LOCAL_REPO="$2"; shift 2 ;;
        --target-dir) TARGET_DIR="$2"; shift 2 ;;
        --guest-user) GUEST_USER="$2"; shift 2 ;;
        --guest-host) GUEST_HOST="$2"; shift 2 ;;
        --guest-key) GUEST_KEY="$2"; shift 2 ;;
        --boot-timeout) BOOT_TIMEOUT="$2"; shift 2 ;;
        --fast) FAST=1; shift ;;
        --keep-running) KEEP_RUNNING=1; shift ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
cleanup() {
    local rc=$?
    [ "${KEEP_RUNNING}" -eq 1 ] || stop_vm || true
    [ -n "${PWFILE}" ] && [ -f "${PWFILE}" ] && rm -f "${PWFILE}"
    exit "${rc}"
}

# -----------------------------------------------------------------------------
# Hypervisor resolution
# -----------------------------------------------------------------------------
resolve_hypervisor() {
    if [ "${HYPERVISOR}" != "auto" ]; then echo "${HYPERVISOR}"; return; fi
    if command -v VBoxManage >/dev/null 2>&1; then echo "virtualbox"; return; fi
    if command -v vmrun >/dev/null 2>&1; then echo "vmware"; return; fi
    die "could not auto-detect a hypervisor (no VBoxManage / vmrun). Pass --hypervisor."
}

# -----------------------------------------------------------------------------
# VM lifecycle
# -----------------------------------------------------------------------------
start_vm() {
    case "${HV}" in
        virtualbox)
            [ -n "${VM_NAME}" ] || die "VirtualBox needs --vm-name."
            log "starting VirtualBox VM '${VM_NAME}' (headless)"
            VBoxManage startvm "${VM_NAME}" --type headless
            ;;
        vmware)
            [ -n "${VMX}" ] || die "VMware needs --vmx (path to the .vmx)."
            log "starting VMware VM '${VMX}' (nogui)"
            vmrun start "${VMX}" nogui
            ;;
    esac
    ok "VM start issued"
}

stop_vm() {
    log "powering off VM"
    case "${HV:-}" in
        virtualbox) VBoxManage controlvm "${VM_NAME}" acpipowerbutton 2>/dev/null || true
                    sleep 8
                    VBoxManage controlvm "${VM_NAME}" poweroff 2>/dev/null || true ;;
        vmware)     vmrun stop "${VMX}" soft 2>/dev/null || true ;;
    esac
    ok "VM powered off"
}

get_guest_ip() {
    if [ -n "${GUEST_HOST}" ]; then echo "${GUEST_HOST}"; return; fi
    log "resolving guest IP from hypervisor" >&2
    local ip=""
    case "${HV}" in
        virtualbox)
            ip="$(VBoxManage guestproperty get "${VM_NAME}" /VirtualBox/GuestInfo/Net/0/V4/IP 2>/dev/null \
                  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" ;;
        vmware)
            ip="$(vmrun getGuestIPAddress "${VMX}" -wait 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" ;;
    esac
    [ -n "${ip}" ] || die "could not resolve guest IP; pass --guest-host."
    echo "${ip}"
}

# -----------------------------------------------------------------------------
# Exec
# -----------------------------------------------------------------------------
init_exec() {
    [ -n "${GUEST_USER}" ] || die "guest user required: --guest-user or APTW_GUEST_USER."
    if [ "${EXECMODE}" = "ssh" ]; then
        need ssh
        local ip; ip="$(get_guest_ip)"
        SSH_TARGET="${GUEST_USER}@${ip}"
        SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
        [ -n "${GUEST_KEY}" ] && SSH_OPTS+=(-i "${GUEST_KEY}")
        ok "SSH target: ${SSH_TARGET}"
    else
        [ "${HV}" = "vmware" ] || [ "${HV}" = "virtualbox" ] || die "guest-control needs VirtualBox or VMware."
        [ -n "${GUEST_PASSWORD}" ] || die "guest-control needs APTW_GUEST_PASSWORD."
        if [ "${HV}" = "virtualbox" ]; then
            PWFILE="$(mktemp)"; chmod 600 "${PWFILE}"; printf '%s' "${GUEST_PASSWORD}" > "${PWFILE}"
        fi
        ok "guest-control mode (${HV})"
    fi
}

# invoke_guest "<bash command line>" -> returns guest command exit code
invoke_guest() {
    local cmd="$1"
    if [ "${EXECMODE}" = "ssh" ]; then
        ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "bash -lc '${cmd}'"
        return $?
    fi
    case "${HV}" in
        virtualbox)
            VBoxManage guestcontrol "${VM_NAME}" run --username "${GUEST_USER}" --passwordfile "${PWFILE}" \
                --exe /bin/bash -- bash -lc "${cmd}"
            return $? ;;
        vmware)
            vmrun -gu "${GUEST_USER}" -gp "${GUEST_PASSWORD}" runProgramInGuest "${VMX}" /bin/bash -lc "${cmd}"
            return $? ;;
    esac
    return 1
}

# -----------------------------------------------------------------------------
# Code delivery
# -----------------------------------------------------------------------------
copy_repo() {
    log "delivering local repo to guest (excluding: ${EXCLUDES[*]})"
    local rsync_excludes=()
    local e
    for e in "${EXCLUDES[@]}"; do rsync_excludes+=(--exclude "${e}"); done

    if [ "${EXECMODE}" = "ssh" ]; then
        if command -v rsync >/dev/null 2>&1; then
            invoke_guest "rm -rf ${TARGET_DIR} && mkdir -p ${TARGET_DIR}" >/dev/null
            rsync -az -e "ssh ${SSH_OPTS[*]}" "${rsync_excludes[@]}" "${LOCAL_REPO}/" "${SSH_TARGET}:${TARGET_DIR}/"
        else
            need scp
            local stage; stage="$(mktemp -d)/aptw-src"; mkdir -p "${stage}"
            cp -a "${LOCAL_REPO}/." "${stage}/"
            for e in "${EXCLUDES[@]}"; do rm -rf "${stage:?}/${e}"; done
            invoke_guest "rm -rf ${TARGET_DIR} && mkdir -p ${TARGET_DIR}" >/dev/null
            scp "${SSH_OPTS[@]}" -r "${stage}/." "${SSH_TARGET}:${TARGET_DIR}/"
            rm -rf "$(dirname "${stage}")"
        fi
    elif [ "${HV}" = "virtualbox" ]; then
        # SSH-free: stage a clean tree, copy it in with VBoxManage, assemble.
        local parent stage; parent="$(mktemp -d)"; stage="${parent}/aptw-src"; mkdir -p "${stage}"
        if command -v rsync >/dev/null 2>&1; then
            rsync -a "${rsync_excludes[@]}" "${LOCAL_REPO}/" "${stage}/"
        else
            cp -a "${LOCAL_REPO}/." "${stage}/"
            for e in "${EXCLUDES[@]}"; do rm -rf "${stage:?}/${e}"; done
        fi
        invoke_guest "rm -rf /tmp/aptw-src" >/dev/null || true
        VBoxManage guestcontrol "${VM_NAME}" copyto --username "${GUEST_USER}" --passwordfile "${PWFILE}" \
            --recursive --target-directory /tmp "${stage}"
        invoke_guest "rm -rf ${TARGET_DIR} && mkdir -p ${TARGET_DIR} && cp -a /tmp/aptw-src/. ${TARGET_DIR}/ && rm -rf /tmp/aptw-src" \
            || die "guest-side assemble of copied tree failed"
        rm -rf "${parent}"
    else
        die "local-source copy over guest-control is only implemented for VirtualBox; use --exec ssh, or --source git."
    fi
    ok "local repo delivered to ${TARGET_DIR}"
}

deliver_code() {
    if [ "${SOURCE}" = "git" ]; then
        log "git clone/pull ${REPO_URL} -> ${TARGET_DIR} (in guest)"
        invoke_guest "if [ -d ${TARGET_DIR}/.git ]; then git -C ${TARGET_DIR} pull --ff-only; else git clone ${REPO_URL} ${TARGET_DIR}; fi" \
            || die "git delivery failed in guest"
    else
        copy_repo
    fi
    ok "code delivered"
}

# -----------------------------------------------------------------------------
# Wait for guest
# -----------------------------------------------------------------------------
wait_guest() {
    log "waiting for guest to become reachable (timeout ${BOOT_TIMEOUT}s)"
    local deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if invoke_guest "true" >/dev/null 2>&1; then ok "guest is reachable"; return; fi
        sleep 5
    done
    die "guest did not become reachable within ${BOOT_TIMEOUT}s"
}

pull_logs() {
    local logdir="${LOCAL_REPO}/vm-test-logs"
    mkdir -p "${logdir}"
    if [ "${EXECMODE}" = "ssh" ]; then
        scp "${SSH_OPTS[@]}" "${SSH_TARGET}:/tmp/aptw_*.log" "${logdir}/" 2>/dev/null || true
        log "gate logs copied to ${logdir} (if any)"
    elif [ "${HV}" = "virtualbox" ]; then
        local name
        for name in aptw_pytest.log aptw_ruff.log aptw_mypy.log aptw_eval.log aptw_mkdocs.log aptw_cleanroom.log; do
            VBoxManage guestcontrol "${VM_NAME}" copyfrom --username "${GUEST_USER}" --passwordfile "${PWFILE}" \
                --target-directory "${logdir}" "/tmp/${name}" 2>/dev/null || true
        done
        log "gate logs copied to ${logdir} (if any)"
    fi
}

# =============================================================================
# Main
# =============================================================================
HV="$(resolve_hypervisor)"
EXECMODE="${EXEC}"; [ "${EXECMODE}" = "auto" ] && EXECMODE="ssh"
log "hypervisor=${HV} exec=${EXECMODE} source=${SOURCE}"

trap cleanup EXIT INT TERM

start_vm
init_exec
wait_guest
deliver_code

log "running prepare-vm.sh in guest"
invoke_guest "cd ${TARGET_DIR} && bash scripts/prepare-vm.sh" || warn "prepare-vm.sh reported issues (continuing)"

GATE_FLAG=""; [ "${FAST}" -eq 1 ] && GATE_FLAG=" --fast"
log "running run-gates.sh${GATE_FLAG} in guest"
set +e
invoke_guest "cd ${TARGET_DIR} && source .venv/bin/activate && bash scripts/run-gates.sh${GATE_FLAG}"
GATE_EXIT=$?
set -e

pull_logs

echo
if [ "${GATE_EXIT}" -eq 0 ]; then
    ok "AUTONOMOUS VM TEST PASSED -- all gates green inside the VM"
else
    warn "AUTONOMOUS VM TEST FAILED -- run-gates.sh exit ${GATE_EXIT} (see vm-test-logs)"
fi
# cleanup() runs on EXIT and powers off; preserve the gate exit code.
trap - EXIT
cleanup_rc="${GATE_EXIT}"
[ -n "${PWFILE}" ] && [ -f "${PWFILE}" ] && rm -f "${PWFILE}"
[ "${KEEP_RUNNING}" -eq 1 ] || stop_vm || true
exit "${cleanup_rc}"
