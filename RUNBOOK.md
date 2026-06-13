# APTWatcher DFIR — VM & submission runbook

Operator runbook for provisioning a SIFT workstation, validating the project
against every machine-checkable gate, and getting it submission-ready. Follow
top to bottom. Each phase has a one-command path and a manual fallback.

> Prereqs: a Debian/Ubuntu-based SIFT workstation, a regular (non-root) user
> with `sudo`, and network access for package installs. The agent itself runs
> read-only on evidence; this runbook is the operator-side setup, not an
> evidence-handling procedure.

---

## TL;DR — three commands

```bash
git clone https://github.com/aptwatcher/APTWatcher.git ~/APTWatcher && cd ~/APTWatcher
bash scripts/prepare-vm.sh          # installs forensic toolchain + python env
source .venv/bin/activate && bash scripts/run-gates.sh   # validates everything
```

If `run-gates.sh` ends with `PASS … FAIL 0`, the machine-checkable part of the
submission is green. The only things left are the human items (demo recording,
Devpost upload).

---

## Phase 1 — Provision the VM

`scripts/prepare-vm.sh` is idempotent and safe to re-run. It installs any
missing forensic tools at the canonical paths the MCP wrappers expect (see
`CLAUDE.md`), then builds the project virtualenv with the `dev` + `docs` extras.

```bash
bash scripts/prepare-vm.sh
```

What it does, in order:

1. Preflight — refuses root, checks `sudo`, `apt-get`, `git`, `curl`, Python ≥ 3.11.
2. apt tools — `sleuthkit`, `bulk-extractor`, `yara`, `plaso-tools` (only if missing).
3. Volatility 3 — `git clone` into `/opt/volatility3`, installs its requirements.
4. Hayabusa — downloads the latest release into `/opt/hayabusa` and normalizes the binary name.
5. Python env — creates `.venv`, installs `pip install -e ".[dev,docs]"`.
6. `aptwatcher preflight` — confirms the agent sees the toolchain.
7. Final verification — re-probes every canonical path and prints a summary.

Useful variants:

```bash
bash scripts/prepare-vm.sh --check-only   # verify the toolchain, install nothing
bash scripts/prepare-vm.sh --skip-tools   # python env only (tools already there)
bash scripts/prepare-vm.sh --skip-python  # forensic toolchain only
```

Path overrides (export before running) if your layout is non-standard:
`APTW_VOL3_DIR`, `APTW_HAYABUSA_DIR`, `APTW_HAYABUSA_VERSION`, `APTW_TARGET_DIR`,
`APTW_PYTHON`.

### Canonical tool paths (verification table)

| Tool | Canonical path | Provisioned by |
|---|---|---|
| Volatility 3 | `/opt/volatility3/vol.py` | git clone (step 3) |
| Plaso log2timeline | `/usr/bin/log2timeline.py` | apt `plaso-tools` |
| Plaso psort | `/usr/bin/psort.py` | apt `plaso-tools` |
| Sleuthkit fls | `/usr/bin/fls` | apt `sleuthkit` |
| Sleuthkit icat | `/usr/bin/icat` | apt `sleuthkit` |
| bulk_extractor | `/usr/bin/bulk_extractor` | apt `bulk-extractor` |
| YARA | `/usr/bin/yara` | apt `yara` |
| Hayabusa | `/opt/hayabusa/hayabusa` | GitHub release (step 4) |

Manual fallback if a single tool fails: install it by hand at the path above,
then re-run `bash scripts/prepare-vm.sh --check-only` to confirm.

---

## Phase 1b — Autonomous in-VM test (optional, hands-off)

To validate the *whole* deployment inside the SIFT VM without manual steps,
use the host orchestrator. It starts the VM headless, waits for the guest,
delivers the code, runs `prepare-vm.sh` + `run-gates.sh` inside the guest,
copies the gate logs back to `vm-test-logs/`, and powers the VM off — exiting
with the gate result. The heavy lifting stays in the two bash scripts; this
orchestrator only owns the VM lifecycle and remote exec.

Two interchangeable orchestrators, same behavior and flags:

- **`scripts/vm-test.ps1`** — Windows host (PowerShell). Backends: VMware
  (`vmrun`), Hyper-V, VirtualBox (`VBoxManage`).
- **`scripts/vm-test.sh`** — Linux/macOS host (bash). Backends: VirtualBox
  (`VBoxManage`), VMware Fusion/Workstation (`vmrun`). Hyper-V is Windows-only.

Both support SSH or hypervisor guest-control for exec, and `git` clone or
local-copy for delivery. SSH is recommended (and required for a Linux guest
under Hyper-V); VirtualBox additionally supports a fully SSH-free path via
guest-control.

```powershell
# VMware + SSH key + git clone, fully autonomous:
.\scripts\vm-test.ps1 -Hypervisor vmware -Vmx 'C:\Users\<you>\Dev\APTWatcher\vm\sift.vmx' `
    -Exec ssh -GuestUser <guest-user> -GuestKey $HOME\.ssh\sift_id_ed25519 -Source git

# Hyper-V + SSH + local working tree, keep VM up on failure to inspect:
.\scripts\vm-test.ps1 -Hypervisor hyperv -VmName SIFT -Exec ssh `
    -GuestUser <guest-user> -GuestKey $HOME\.ssh\sift_id_ed25519 -Source local -KeepRunning

# VirtualBox, SSH-free (everything over VBoxManage guest-control):
$env:APTW_GUEST_PASSWORD = 'your-guest-password'
.\scripts\vm-test.ps1 -Hypervisor virtualbox -VmName SIFT -Exec guest `
    -GuestUser <guest-user> -Source local
```

On a Linux or macOS host, use the bash twin with the same semantics:

```bash
# VirtualBox, SSH-free (everything over VBoxManage guest-control):
export APTW_GUEST_PASSWORD='your-guest-password'
bash scripts/vm-test.sh --hypervisor virtualbox --vm-name SIFT \
    --exec guest --guest-user <guest-user> --source local

# VMware Fusion + SSH key + git clone:
bash scripts/vm-test.sh --hypervisor vmware --vmx ~/VMs/sift/sift.vmx \
    --exec ssh --guest-user <guest-user> --guest-key ~/.ssh/sift_id_ed25519 --source git
```

Credentials are **never** stored in the repo. Pass them per-run via parameters
or the `APTW_GUEST_USER` / `APTW_GUEST_HOST` / `APTW_GUEST_KEY` /
`APTW_GUEST_PASSWORD` environment variables. Prefer an SSH key over a password;
the SIFT image ships with SSH and a default user you provision a key for. In
guest-control mode the password is written to a temporary file and passed to
`VBoxManage` via `--passwordfile`, never on the command line.

Prerequisites in the guest (one-time):

- **SSH mode** (VMware / Hyper-V / VirtualBox): SSH enabled and your public key
  in the guest user's `~/.ssh/authorized_keys`.
- **VirtualBox guest-control mode** (no SSH, recommended for the SIFT box on a
  laptop): install **VirtualBox Guest Additions** in the VM and pass the guest
  username + password. `vm-test.ps1` then starts the VM, copies the working
  tree in, runs `prepare-vm.sh` + `run-gates.sh`, pulls the gate logs back to
  `vm-test-logs/`, and powers off — all through `VBoxManage`, no networking
  required.

Everything else (forensic toolchain, Python env) is installed by
`prepare-vm.sh` on the first run.

---

## Phase 2 — Run the submission gates

`scripts/run-gates.sh` automates every machine-checkable item in
`SUBMISSION-CHECKLIST.md` (sections 1, 2, 3, 6). It runs all gates even if some
fail, then prints a `PASS / FAIL / SKIP` summary and exits non-zero on any FAIL.

```bash
source .venv/bin/activate
bash scripts/run-gates.sh          # full run
bash scripts/run-gates.sh --fast   # skip the slow eval + mkdocs gates
```

Gates covered:

- **Code** — `pytest -q`, AST syntax sweep, `ruff check src tests`, `mypy src/core`, NUL-byte scan.
- **Coverage/accuracy** — Tier 0 wrapper count, 42 `@mcp.tool`, CLI command count, ≥ 5 accuracy fixtures, `aptwatcher eval`.
- **Docs** — `mkdocs build --strict` (no warnings), clean-room forbidden-string sweep.
- **Repo hygiene** — secret scan, personal-environment leak scan, `LICENSE`, `.gitignore` excludes (incl. internal `HANDOFF.md`/`TODO.md`), `install.sh` `bash -n`.

Logs for any failing gate are written under `/tmp/aptw_*.log`.

> Note: the checklist text says "8 `@app.command`"; the repo now ships 9
> (`audit-render` was added). The gate accepts ≥ 8 and prints the count — update
> the checklist text to 9 when convenient.

---

## Phase 3 — Repo hygiene before pushing

The single highest-risk mistake is publishing the internal working folder.
`APTWatcher-internal/` (HANDOFF, TODO, event screenshots) must **never** be
pushed. It lives as a sibling directory and is excluded by `.gitignore`, but
verify before the first push:

```bash
cd ~/APTWatcher
git init                                    # if not already a repo
git add -A
git status --short | grep -iE 'HANDOFF|TODO|internal|sans-event' \
  && echo "STOP: internal files staged" || echo "clean: no internal files staged"
git grep -inE '/session[s]/|Dani[e]l Ricard|\bDomini[c]\b' && echo "STOP: leak found" || echo "clean: no leaks"
```

Both checks should print `clean:`. If either prints `STOP:`, fix before
committing. (These same scans are also run by `run-gates.sh` Section 6.)

Then push:

```bash
git remote add origin https://github.com/aptwatcher/APTWatcher.git
git branch -M main
git commit -m "APTWatcher submission"
git push -u origin main
```

---

## Phase 4 — Manual items (not automatable)

These are reviewer-observable and stay on the human's plate (see
`SUBMISSION-CHECKLIST.md` sections 4, 5, 7):

- Rehearse `demo/SCRIPT.md` (target ≤ 5:00 recorded); pre-record fallback clips.
- Test the screen recorder on the target VM; generate S04 keys on the recording host (do not commit them).
- Upload `docs/DEVPOST.md` to Devpost; add project images, team members, video link, tags.
- Post the announcement; add a feedback issue template; thank sponsors.

---

## Quick troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `prepare-vm.sh` refuses to run | running as root | run as a regular user with `sudo` available |
| Hayabusa download 404 | release asset name changed | set `APTW_HAYABUSA_VERSION=vX.Y.Z` and re-run |
| `aptwatcher: command not found` | venv not active | `source .venv/bin/activate` |
| volatility3 requirements fail | optional deps | non-fatal; core memory triage still works |
| `mkdocs` gate SKIP | docs extra not installed | re-run `prepare-vm.sh` (installs `.[dev,docs]`) |
| eval F1 below target | fixtures/model drift | inspect `/tmp/aptw_eval.log`; tune before submission |

---

_This runbook pairs with `install.sh` (lightweight, probe-only installer for end
users) and `scripts/prepare-vm.sh` (heavier provisioner for the build/eval host)._
