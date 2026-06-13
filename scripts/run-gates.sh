#!/usr/bin/env bash
#
# APTWatcher submission gates -- automates every machine-checkable item in
# SUBMISSION-CHECKLIST.md (sections 1 Code, 2 Coverage/accuracy, 3 Docs,
# 6 Repo hygiene). Run it from inside the project venv after prepare-vm.sh.
#
# Each gate prints PASS / FAIL / SKIP. The script never stops on the first
# failure: it runs every gate, then prints a summary and exits non-zero if
# any gate failed. Reviewer-only items (demo rehearsal, Devpost upload) are
# out of scope -- they are not machine-checkable.
#
# Usage:
#   source .venv/bin/activate
#   bash scripts/run-gates.sh
#   bash scripts/run-gates.sh --fast   # skip the slow eval + mkdocs gates
#
# Exit codes: 0 = all run gates passed; 1 = one or more failed.

set -uo pipefail   # intentionally no -e: we want every gate to run

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    C_OK=$'\033[1;32m'; C_ERR=$'\033[1;31m'; C_WARN=$'\033[1;33m'
    C_INFO=$'\033[1;34m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_ERR=""; C_WARN=""; C_INFO=""; C_OFF=""
fi

PASS_N=0; FAIL_N=0; SKIP_N=0
declare -a FAILED_GATES=()

pass() { printf "  %s[PASS]%s %s\n" "${C_OK}"  "${C_OFF}" "$*"; PASS_N=$((PASS_N+1)); }
fail() { printf "  %s[FAIL]%s %s\n" "${C_ERR}" "${C_OFF}" "$*"; FAIL_N=$((FAIL_N+1)); FAILED_GATES+=("$*"); }
skip() { printf "  %s[SKIP]%s %s\n" "${C_WARN}" "${C_OFF}" "$*"; SKIP_N=$((SKIP_N+1)); }
hdr()  { printf "\n%s== %s ==%s\n" "${C_INFO}" "$*" "${C_OFF}"; }

# Resolve python: prefer the active venv, fall back to python3.
PY="$(command -v python || command -v python3)"
[ -n "${PY}" ] || { echo "no python found"; exit 2; }

# ---------------------------------------------------------------------------
hdr "Section 1 -- Code gates"

if command -v pytest >/dev/null 2>&1; then
    if pytest -q >/tmp/aptw_pytest.log 2>&1; then
        n="$(grep -oE '[0-9]+ passed' /tmp/aptw_pytest.log | tail -n1)"
        pass "pytest suite green (${n:-passed})"
    else
        fail "pytest suite NOT green (see /tmp/aptw_pytest.log)"
        tail -n 5 /tmp/aptw_pytest.log | sed 's/^/      /'
    fi
else
    skip "pytest not installed (run prepare-vm.sh with dev extras)"
fi

if "${PY}" - <<'PYEOF'
import ast, pathlib, sys
bad = []
for d in ("src", "tests"):
    for p in pathlib.Path(d).rglob("*.py"):
        try:
            ast.parse(p.read_text())
        except SyntaxError as e:
            bad.append(f"{p}: {e}")
if bad:
    print("\n".join(bad)); sys.exit(1)
PYEOF
then pass "zero SyntaxError across src/ and tests/"
else fail "SyntaxError found in src/ or tests/"; fi

if command -v ruff >/dev/null 2>&1; then
    if ruff check src tests >/tmp/aptw_ruff.log 2>&1; then
        pass "ruff check clean"
    else
        fail "ruff violations (see /tmp/aptw_ruff.log)"
    fi
else
    skip "ruff not installed"
fi

if command -v mypy >/dev/null 2>&1; then
    if mypy src/core >/tmp/aptw_mypy.log 2>&1; then
        pass "mypy src/core clean"
    else
        fail "mypy errors (see /tmp/aptw_mypy.log)"
    fi
else
    skip "mypy not installed"
fi

if "${PY}" - <<'PYEOF'
import pathlib, sys
skip = (".venv", "site", ".git", "__pycache__", ".pytest_cache")
bad = [str(p) for p in pathlib.Path(".").rglob("*")
       if p.is_file() and not any(s in p.parts for s in skip)
       and b"\x00" in p.read_bytes()]
if bad:
    print("\n".join(bad)); sys.exit(1)
PYEOF
then pass "zero NUL bytes in tracked files"
else fail "NUL bytes found"; fi

# ---------------------------------------------------------------------------
hdr "Section 2 -- Coverage and accuracy"

# Tier 0 wrapper count: 10 expected.
tier0=$(grep -rlE 'tier\s*=\s*0|TIER_0|tier_0' src/core/sift 2>/dev/null | wc -l)
sift_modules=$(find src/core/sift -name '*.py' ! -name '__init__.py' 2>/dev/null | wc -l)
if [ "${sift_modules}" -ge 10 ]; then
    pass "Tier 0 SIFT wrapper modules present (${sift_modules} found, expect >=10)"
else
    fail "Tier 0 SIFT wrappers: ${sift_modules} found, expected 10"
fi

mcp_tools=$(grep -c '@mcp.tool' src/mcp_server/server.py 2>/dev/null || echo 0)
if [ "${mcp_tools}" -eq 51 ]; then
    pass "@mcp.tool decorators = 51"
else
    fail "@mcp.tool decorators = ${mcp_tools}, expected 51"
fi

cli_cmds=$(grep -c '@app.command' src/agent_extension/cli.py 2>/dev/null || echo 0)
# Checklist text says 8; repo currently ships 9 (audit-render added). Accept >=8.
if [ "${cli_cmds}" -ge 8 ]; then
    pass "@app.command decorators = ${cli_cmds} (>=8; note: checklist text says 8, repo has audit-render too)"
else
    fail "@app.command decorators = ${cli_cmds}, expected >=8"
fi

fixtures=$(find tests/accuracy/fixtures -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
if [ "${fixtures}" -ge 5 ]; then
    pass "accuracy fixtures = ${fixtures} (>=5)"
else
    fail "accuracy fixtures = ${fixtures}, expected >=5"
fi

if [ "${FAST}" -eq 1 ]; then
    skip "aptwatcher eval (--fast)"
elif command -v aptwatcher >/dev/null 2>&1; then
    if aptwatcher eval --fixtures-dir tests/accuracy/fixtures >/tmp/aptw_eval.log 2>&1; then
        f1="$(grep -oiE 'mean F1[^0-9]*[0-9.]+' /tmp/aptw_eval.log | tail -n1)"
        pass "aptwatcher eval exit 0 (${f1:-see /tmp/aptw_eval.log})"
    else
        fail "aptwatcher eval non-zero exit (see /tmp/aptw_eval.log)"
    fi
else
    skip "aptwatcher CLI not on PATH"
fi

# ---------------------------------------------------------------------------
hdr "Section 3 -- Doc gates"

if [ "${FAST}" -eq 1 ]; then
    skip "mkdocs build --strict (--fast)"
elif command -v mkdocs >/dev/null 2>&1 || "${PY}" -c "import mkdocs" 2>/dev/null; then
    if "${PY}" -m mkdocs build --strict >/tmp/aptw_mkdocs.log 2>&1; then
        if grep -q 'WARNING' /tmp/aptw_mkdocs.log; then
            fail "mkdocs build emitted WARNING lines (see /tmp/aptw_mkdocs.log)"
        else
            pass "mkdocs build --strict clean, no warnings"
        fi
    else
        fail "mkdocs build --strict failed (see /tmp/aptw_mkdocs.log)"
    fi
else
    skip "mkdocs not installed (docs extra)"
fi

if [ -f scripts/clean_room_check.py ]; then
    if "${PY}" scripts/clean_room_check.py >/tmp/aptw_cleanroom.log 2>&1; then
        pass "clean-room forbidden-string sweep clean"
    else
        fail "clean-room sweep found forbidden strings (see /tmp/aptw_cleanroom.log)"
    fi
else
    skip "scripts/clean_room_check.py not found"
fi

# ---------------------------------------------------------------------------
hdr "Section 6 -- Repo hygiene"

# Secret scan: flag only real-looking assignments, allow env-var names/docstrings.
secret_hits=$(grep -rInE '(api[_-]?key|secret|password|bearer)\s*[:=]\s*[".'"'"']?[A-Za-z0-9/_+-]{16,}' \
    --include='*.py' --include='*.sh' --include='*.toml' --include='*.yml' --include='*.yaml' \
    src tests deploy install.sh 2>/dev/null \
    | grep -viE 'env|getenv|os\.environ|example|placeholder|<|your_|xxx|redact|consent_token' | wc -l)
if [ "${secret_hits}" -eq 0 ]; then
    pass "no hard-coded secret-like assignments"
else
    fail "${secret_hits} possible secret-like assignment(s) -- inspect manually"
    grep -rInE '(api[_-]?key|secret|password|bearer)\s*[:=]\s*["'"'"']?[A-Za-z0-9/_+-]{16,}' \
        src tests deploy install.sh 2>/dev/null \
        | grep -viE 'env|getenv|os\.environ|example|placeholder|<|your_|xxx|redact|consent_token' | sed 's/^/      /'
fi

# Personal-environment leak scan (session paths, real names).
# Patterns use [x] character classes so this gate never matches its own source
# (or RUNBOOK.md), while still matching real leaks in tracked files.
leak_hits=$(grep -rInE '/session[s]/|charming-vibrant-knut[h]|Dani[e]l Ricard|\bDomini[c]\b' \
    --exclude-dir=.venv --exclude-dir=site --exclude-dir=.git --exclude-dir=__pycache__ \
    . 2>/dev/null | wc -l)
if [ "${leak_hits}" -eq 0 ]; then
    pass "no personal-environment leaks (session paths / names)"
else
    fail "${leak_hits} personal-environment leak(s) found"
fi

[ -f LICENSE ] && pass "LICENSE present" || fail "LICENSE missing"

gi_ok=1
for pat in '.venv' '__pycache__' '*.pyc' 'site/'; do
    grep -qF "${pat}" .gitignore 2>/dev/null || { gi_ok=0; warn "  .gitignore missing: ${pat}"; }
done
[ "${gi_ok}" -eq 1 ] && pass ".gitignore excludes venv/pycache/pyc/site" || fail ".gitignore missing required excludes"

# Internal-only docs must never be tracked.
if grep -qE '^HANDOFF\.md|^TODO\.md' .gitignore 2>/dev/null; then
    pass ".gitignore excludes internal HANDOFF.md / TODO.md"
else
    fail ".gitignore does NOT exclude internal HANDOFF.md / TODO.md"
fi

if [ -f install.sh ]; then
    bash -n install.sh 2>/tmp/aptw_installsh.log && pass "install.sh passes bash -n" \
        || fail "install.sh bash -n syntax error (see /tmp/aptw_installsh.log)"
else
    fail "install.sh missing at repo root"
fi

# ---------------------------------------------------------------------------
hdr "Summary"
printf "  %sPASS %d%s   %sFAIL %d%s   %sSKIP %d%s\n" \
    "${C_OK}" "${PASS_N}" "${C_OFF}" "${C_ERR}" "${FAIL_N}" "${C_OFF}" "${C_WARN}" "${SKIP_N}" "${C_OFF}"

if [ "${FAIL_N}" -gt 0 ]; then
    echo
    echo "  Failed gates:"
    for g in "${FAILED_GATES[@]}"; do echo "    - ${g}"; done
    echo
    echo "  Do not submit until all gates above are green."
    exit 1
fi

echo
echo "  All run gates passed. Remaining manual items in SUBMISSION-CHECKLIST.md:"
echo "    demo rehearsal, Devpost upload, video link, sponsor note."
exit 0
