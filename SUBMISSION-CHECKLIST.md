# APTWatcher DFIR — submission checklist

> Final pre-submit gate for the hackathon. Every item is machine-checkable
> or reviewer-observable. Work top to bottom, check each box, do not
> submit until all are green. Keep the list short, imperative, and
> skimmable.

## 1. Code gates

- [ ] Run `pytest -q` on Python 3.11+ and confirm the full suite is green (target 500+ tests).
- [ ] Run `python3 -c "import ast, pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('src').rglob('*.py')] + [ast.parse(p.read_text()) for p in pathlib.Path('tests').rglob('*.py')]"` and confirm zero SyntaxError.
- [ ] Run `ruff check src tests` and confirm zero violations (or document the baseline in `docs/reference/ruff-baseline.md`).
- [ ] Run `mypy src/core` and confirm zero errors if a mypy config exists; otherwise skip.
- [ ] Run `python3 -c "import pathlib; assert not [p for p in pathlib.Path('.').rglob('*') if p.is_file() and b'\x00' in p.read_bytes()], 'nul bytes found'"` and confirm zero NUL bytes in tracked files.

## 2. Coverage and accuracy

- [ ] Confirm Tier 0 wrapper count is 10/10 (volatility3, plaso, bulk_extractor, sleuthkit, yara_scan, hayabusa, regripper, chainsaw, timesketch, sift_update).
- [ ] Confirm 51 `@mcp.tool` decorators in `src/mcp_server/server.py` (42 Tier 0 + 9 Tier 1 intel: intel_lookup, enrich_ip/domain/hash, feed_threatfox/tweetfeed, admin_version/health/providers_status).
- [ ] Confirm 9 `@app.command` decorators in `src/agent_extension/cli.py` (`version`, `profiles`, `preflight`, `knowledge-search`, `run`, `analyze`, `publish`, `eval`, `audit-render`).
- [ ] Confirm at least 5 accuracy fixtures under `tests/accuracy/fixtures/`.
- [ ] Run `aptwatcher eval --fixtures-dir tests/accuracy/fixtures`, confirm exit 0 with mean F1 at or above 0.60 (target 0.80 for submission).

## 3. Doc gates

- [ ] Run `python3 -m mkdocs build --strict` and confirm exit 0 with no `WARNING` lines.
- [ ] Open `docs/reference/audit-report.md` and confirm 0 orphan pages and 0 broken links.
- [ ] Run the forbidden-string grep sweep over `knowledge/` and submission docs and confirm no hits.
- [ ] Confirm `docs/ACCURACY.md`, `docs/TRY-IT-OUT.md`, `docs/DATASET.md`, and `docs/DEVPOST.md` are all in `mkdocs.yml` nav and linked from `docs/README.md`.

## 4. Demo readiness

- [ ] Review `demo/SCRIPT.md` and rehearse timings (target 4:30 spoken, at most 5:00 recorded).
- [ ] Pre-record fallback clips for each one-minute segment.
- [ ] Test asciinema and the screen recorder on the target VM.
- [ ] Generate S04 scenario keys on the recording host and confirm they are not committed.

## 5. Devpost narrative

- [ ] Upload `docs/DEVPOST.md` into Devpost and verify copy-paste formatting.
- [ ] Upload project images (architecture diagram, screenshots).
- [ ] Add team members in the Devpost project settings.
- [ ] Link the video URL in the Devpost submission form.
- [ ] Apply tags (defensive IR, agentic, SIFT).

## 6. Repo hygiene

- [ ] Confirm a `LICENSE` file (MIT) is present at the repo root.
- [ ] Open the repo on GitHub and confirm `README.md` renders correctly.
- [ ] Run `git grep -iE 'api_key|secret|password|bearer'` and confirm only docstrings and env-var-name references are returned.
- [ ] Re-run the NUL-byte scan from section 1 and confirm zero hits across tracked files.
- [ ] Confirm `.gitignore` excludes `.venv`, `__pycache__`, `*.pyc`, `site/`, and `accuracy-runs/`.
- [ ] Confirm `install.sh` is present at the repo root, executable, passes `bash -n install.sh`, contains zero forbidden-string hits, and is documented in `docs/TRY-IT-OUT.md` under the `## Quick install (one-liner)` section.

## 7. Post-submission

- [ ] Publish the announcement tweet or post using the template in `demo/ANNOUNCE.md` (write that file if it is missing).
- [ ] Add a feedback issue template under `.github/ISSUE_TEMPLATE/` on GitHub.
- [ ] Send a thank-you note to sponsors.
