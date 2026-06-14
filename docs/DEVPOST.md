## Devpost narrative

> A prose companion to `ARCHITECTURE.md`. If `ARCHITECTURE.md` is the
> diagram a judge inspects, this page is the story we would tell over a
> coffee about why APTWatcher exists, what we built, what hurt, what we
> learned, and where the project is going. We wrote it in the Devpost
> submission shape so a reader who lands here from the competition site
> gets the same account an in-person reviewer would.

## 1. Inspiration

We kept running into the same three-way shortage. Defensive incident
response analysts are drowning in alerts, watching queues grow faster
than they can triage, and the tooling they have keeps adding more signal
without meaningfully reducing the effort of reading it. At the same
time, the visible wave of LLM agents over the last two years has been
aimed almost everywhere else: offensive security copilots, business
productivity assistants, code-generation pair programmers. The handful
of LLM agents that did aim at defensive IR tended to share a single
failure mode — they would hallucinate. A model would produce a
confident paragraph about "lateral movement from HOST-07 to HOST-12
using Kerberos pass-the-ticket," and when you looked at the evidence
the model had been given, HOST-12 had never appeared in any tool
output. The finding was invented, it read as authoritative, and it
would have poisoned whatever downstream decision an analyst built on
top of it. A confident liar is worse than a silent tool.

We wanted to build the agent that the IR analyst could actually leave
alone for a shift. That meant several things at once. Read-only by
default, because an agent that can disturb evidence is an agent that
can destroy a case. Tier-gated for anything state-changing, because
"state-changing" is a category that needs an explicit yes from the
human, not a prompt-engineered shrug. Audit-logged end to end, because
nobody should have to take the agent's word for what it did. And
self-correcting when a claim lacks citation, because the defense
against hallucination is not a bigger model but a smaller, stricter
contract that every claim must anchor itself to something a reviewer
can go check. We chose to build on Protocol SIFT because that is the
offline forensic workstation a lot of responders already trust, and
because putting the agent on an air-gapped host matched the "do no
harm" posture we wanted the product to have by default.

The name picks up a double meaning deliberately. "APT" as in advanced
persistent threat, the class of adversary the product is tuned to
notice. "Watcher" because the agent is passive first — it observes, it
reasons, it reports, and only reaches for an action after an operator
has explicitly said yes. The project sits inside a defensive-IR
hackathon with a June 2026 deadline, and the hackathon's "autonomous
execution quality" tiebreaker and "architectural guardrails" weighted
criterion gave us a clear forcing function for the design: every
architectural decision we made had to be defensible to a skeptical
reviewer looking for the failure mode.

## 2. What it does

APTWatcher ingests triage evidence — a disk image, a memory image, a
log bundle, a pcap, or any combination — and drives an autonomous
plan-execute-verify-self-correct loop over it. The loop produces a
structured set of findings, a set of extracted indicators of
compromise, a signed portable incident bundle, a bilingual analyst
report in English and French, generated YARA and Suricata rules
covering the observed tactics, and a STIX 2.1 bundle ready for
downstream sharing. The shape of the output set was chosen
deliberately so that APTWatcher drops into an analyst workflow that
already consumes those formats — nobody has to adopt a new viewer or
learn a new report template to use what the agent produces.

The agent ships in three deployment modes that share a single codebase.
Mode A is the direct agent extension: Claude Code or a headless CLI
imports the core package and drives the full loop locally. Mode B is a
standalone MCP server that exposes the typed forensics tools over
stdio so any MCP-capable client can consume them. Mode C is the hybrid
— Mode A drives the loop, Mode B supplies the subset of tools where a
structural guardrail beats prompt engineering. We built all three
because the judging surface benefits from breadth and the operators
who will actually deploy the product benefit from choice. The cost of
three surfaces is one well-typed core package that all three
import from; the benefit is that no operator is forced to adopt a
particular client.

The MCP surface today exposes fifty-one typed tools: forty-two Tier 0
read-only forensic tools and nine Tier 1 intel lookups. The Tier 0
forensic wrappers cover Volatility 3 for memory analysis, Plaso
(log2timeline and psort) for supertimelines, bulk-extractor for
artifact carving, Sleuthkit primitives (mmls, fsstat, fls, icat) for
disk-image work, YARA for pattern matching, Hayabusa for Windows event
log triage, Chainsaw for Sigma-based event-log hunting, and RegRipper
for Windows registry forensics. The SIFT update path is exposed as a
consent-gated tool so an agent cannot accidentally mutate the VM's
tool inventory mid-run. On top of those the MCP server exposes the
bundle export and import primitives, the rule generators (YARA,
Suricata, Sigma), the IOC exporters (STIX 2.1, community YAML, per-type
text), and the report renderers (docx, analyst Markdown, generation
report). The nine Tier 1 intel lookups stay disabled until the
operator opts in. Every tool is pydantic-typed on both sides.

The headline product differentiator is the offline-to-online handoff.
Real defensive IR is a two-phase workflow. Phase one runs on the
air-gapped SIFT workstation, which is where the evidence lives and
where you want the agent to stay read-only. Phase two runs on an
online management host where the live remediation actions happen —
pushing a detection to an EDR, adding a hash to a block list, filing
an incident ticket with the IR workflow. Most agent products pick one
side of that line and call the other side out of scope. APTWatcher
bridges the two with a versioned pydantic `IncidentBundle` serialized
to canonical JSON and signed with a detached Ed25519 signature over
the manifest, findings, IOCs, and audit. The offline agent produces
the bundle; the online peer verifies the signature before any
remediation fires. The wire between offline and online is deliberately
pluggable — USB stick, signed file drop, git commit, ticket
attachment — because the bundle is the contract and the transport is
the operator's choice.

## 3. How we built it

We made a deliberate bet on a shared-brain architecture from the first
week. A single `src/core/` package owns every piece of business logic,
and every deployment surface — the direct-agent CLI, the MCP server,
the hybrid — is a thin wrapper on top of it. The invariant we wrote
down and then defended in code review is that if a function needs to
know which deployment mode invoked it, the function belongs in the
surface, not in the core. The brain is mode-agnostic. That invariant
paid for itself repeatedly: every time we added a tool, a type, or a
strategy, we implemented it once and got three deployment stories for
free. By the end of phase 3 the core package sits near thirteen
thousand lines of Python across about sixty modules, and the full
`src/` tree is just over sixteen thousand lines of Python covering the
core, the CLI, and the MCP server put together.

The tier model is the second architectural bet. We picked five tiers
stacked by blast radius: Tier 0 read-only forensic triage, Tier 1
external threat intel lookups, Tier 2 IR workflow integration, Tier 3
defensive containment, Tier 4 offensive containment. Tier 0 is on by
default; everything above is off until the operator opts in through
configuration. Tiers 3 and 4 require an additional runtime CLI flag on
top of the config flag, and Tier 4 requires a legal acknowledgement
phrase on top of that. The gate is implemented at the configuration
layer: the MCP server checks `cfg.tiers.tier_N` before a tool runs,
and tools from a disabled tier are refused with a structured error
rather than raised as a transport failure. No prompt can coax the
agent into a disabled tier because, from the agent's point of view,
the tool simply declines. The Tier 0 wrappers that mutate state — the
most notable being `sift_update`, which can install packages on the
SIFT VM — stack a consent-token check on top of the tier check. A
caller without a consent token receives a refusal with the exact
remediation instruction and no side effect on disk.

The type contract is pydantic all the way down. `Finding`,
`IOCVerdict`, `AuditEvent`, `IncidentBundle`, `HostEvidence`,
`PreflightReport`, `KBEntry`, and their friends are declared with
`extra="forbid"` so that a payload drift — a tool emitting a field the
schema does not know about — fails loud rather than quietly corrupting
the shape downstream. The tier enumeration, the verdict enumeration
(`malicious`, `suspicious`, `benign`, `unknown`), and the spoliation
risk enumeration all live in `core.types` and are the single source of
truth every surface imports from. The audit event itself carries a
`schema_version` field stamped at the logger boundary so future
readers can tell which contract produced a given log line.

Self-correction is the third bet, and the one we expect a judge to
probe hardest. The `LLMSelfCorrector` strategy runs after every
verify pass with a flat list of issues the verifier produced: each
issue carries a severity (`block`, `warn`, `info`), a rule identifier,
a finding id, and a human-readable detail. The corrector returns a
single JSON object with three decision channels — `resolved`,
`dropped`, and `replan` — plus a short `notes` string. We chose to
route the gate through the `AgentLoop.finalize()` call site because
the architectural form of "don't emit without self-correction" is a
refusal at the emitter, not a paragraph in a system prompt. The
emitter checks `state.self_correction_done_for_current_findings`
before writing the `report_emit` event, and any call to
`AgentLoop.add_finding` after the last correction pass flips that
flag back to false. A prompt cannot talk the agent around the gate
because the gate is in code; the prompt only influences which
findings get dropped versus resolved, and the fallback for malformed
model output is a conservative "drop every finding with a block-level
issue" rule that looks the same as the null corrector. The
`SelfCorrector` specification, the invariants the gate enforces
today, and the invariants it is moving toward are in
`docs/design/self-correction-gates.md`; the tier-gating contract for
its sibling guardrail is in `docs/design/tier-gating.md`.

Audit logging came first, not last. Every tool call is a pair of
events — a `tool_call` with `phase=start` and a second with
`phase=end`, sharing a correlation ID — so a reviewer can walk the
log and always know which end matches which start. Every LLM
round-trip is an `llm_call` event with tool name, iteration, model
identifier, and the fields the strategy chose to publish. Every
preflight pins the tool inventory; every consent-gated action writes
a `sift_update_consent` (or equivalent) entry with the consent token
length but never the raw token; every self-correction pass writes a
`self_correction` event with the decision payload. The log is JSONL,
append-only, fsync'd on every write. It is fully grep-able with `jq`
and hand-auditable by a skeptical reviewer; we built the consumer
queries while we built the producer so the schema would be something
you could reason about, not something you had to reverse-engineer.

The knowledge base is clean-room. Every entry declares a
`source_type` from a closed set (`author-original`, `llm-synthesis`,
`mitre-attack`, `nist`, `public-blog-summary`, and one isolated
community-licensed bucket), and a CI-style grep sweeps forbidden
strings out of the tree before any commit lands. At the time of
writing the knowledge tree holds thirty-two curated entries. That
number is deliberately smaller than what we could have achieved with
a looser policy — we ruled out whole categories of material because
we could not cleanly attribute them — but the corpus is defensible,
each entry is citation-attributed, and the loader exposes a typed
search surface over the tree so the planner's knowledge grounding is
a first-class input rather than a paragraph dropped into a prompt.

The offline-to-online handoff is cryptographically signed. An
`IncidentBundle` is a pydantic payload (`schema_version`,
`incident_id`, `findings`, `iocs`, `yara_rules`, `hashes`,
`remediation_playbook`, `evidence_manifest`) serialized to canonical
JSON, paired with a sha256 digest over the manifest plus findings
plus IOCs plus audit in a fixed order, and signed with a detached
Ed25519 signature. The keys are managed out-of-band by the operator.
The online peer verifies the signature and the digest before any
action fires. We exercised the full round trip in scenario S04,
which also includes adversarial sub-cases for byte tampering and
signer swap so the importer's refusal paths are covered.

The accuracy harness is the last piece of the house, and we built
it to a deliberately minimal spec. A `FakeModelClient` replays a
canned transcript through the real `AgentLoop`. A scoring module
compares the loop's output findings and IOCs against a hand-labeled
golden, producing per-finding and per-IOC precision, recall, and
F1. The per-tier rollup breaks the aggregate out so a regression on
high-confidence findings cannot hide behind a smoothed average. The
`aptwatcher eval` invocation form — described in `docs/ACCURACY.md`
and its companion design note — is the smoke test we run before a
demo recording: a green exit at a declared threshold, or no
recording until the failure is triaged. The baseline today is a mean
F1 of 1.000 across eight seed fixtures, and we were careful to document
what the perfect score does and does not mean. It validates the
scoring plumbing end to end; it does not yet validate the agent's
ability to synthesize findings from tool output. We said so in the
doc before we had a single number on the page, because a baseline
we can fool ourselves about is worse than no baseline at all.

## 4. Challenges we ran into

The first and loudest challenge was keeping LLM hallucinations out of
the final bundle. Early prototypes would produce beautiful-looking
findings that, when traced back through the audit log, had no
citation tying them to a tool call. The fix was not a bigger prompt
but the architectural form of the self-correction gate: the verifier
emits a `rule1_evidence_required` block-severity issue for any
finding whose `evidence` list is empty, and the self-corrector's
safe-default fallback drops such findings outright. The report
emitter refuses to fire without a self-correction event on the
current finding set. Together those three pieces turn "don't
hallucinate" from a prompt-engineering wish into a code-path
invariant. The remaining hallucination risk lives inside findings
that do carry a citation but misread the cited tool output, and we
are tracking that as the next iteration of the verifier rules.

The second challenge was the tooling around our own dev loop. Our
source-editing tools occasionally truncate a file mid-expression on
a write, corrupting the module in ways that are invisible until an
import fails. We hit this often enough, especially on large files
like `src/core/types.py` and `src/mcp_server/server.py`, that we
built a recovery workflow around a bash heredoc — rewrite the file
from a known-good snapshot, parse it with `ast.parse` as a commit
gate, and refuse the commit if the parse fails. Every session ends
with a QC sweep that walks every source file and every test file
through `ast.parse` plus a NUL-byte scan plus a `mkdocs build
--strict` run. The gate is cheap, fast, and has caught multiple
truncation bugs before they reached the branch. We did not expect
to need to build scaffolding around the scaffolding; by the time we
realized we needed it, we were grateful we had invested the hour.

The third challenge was tuning the tier gate for usability without
softening it. Consent tokens felt tedious early on because we were
stamping one on every tool call. The fix was to isolate the consent
requirement to the operations that genuinely change state — the SIFT
update path, the eventual Timesketch upload path, the Tier 3
containment primitives — and leave the read-only wrappers alone. The
usability cost dropped sharply and the safety property got sharper
rather than weaker: a consent token on a read-only operation is
theater; a consent token on an operation that can alter a registry
hive is a real interlock.

The fourth challenge was the clean-room knowledge base scope. We had
a large corpus of personal reference material we could have drawn on
to pre-populate the tree, and we ruled every single piece of it out
because the sources were not ones we could publish under an open
license. The knowledge base grew more slowly as a result, thirty-two
curated entries at the time of writing, but every entry is
attributed, every entry is citation-linked, and we can stand behind
the corpus in front of a reviewer. We consider the slower growth a
feature, not a bug — a knowledge base you cannot publish is a
knowledge base your agent cannot be trusted to quote.

The fifth challenge was a Python version floor. Our code relies on
`datetime.UTC`, which landed in Python 3.11, and our development
sandbox runs Python 3.10. We took the one-directional hit on purpose
rather than reach back to `datetime.timezone.utc` everywhere, because
future maintenance reads cleaner with the newer form and the
hackathon deadline is firmly inside the 3.11 era. The full suite —
746 passing, one skipped — runs on a Python 3.11+ host at the end of
every session, and we developed a confidence habit around
AST-parse-plus-`mkdocs build --strict` for the in-session iterations.
The trade is documented in every handoff so the next session starts
with eyes open.

The sixth challenge is the one that emerges from having three
deployment modes share a brain. Every core change has to be tested
against all three surfaces, and it is very easy to change something
in `src/core/` that quietly breaks one surface while the other two
still look fine. The countermeasure we landed on was to mirror the
surface-specific tests — each surface has its own integration tests
that exercise the same core contract from its own entry point — and
to run the full cross-surface set before declaring a wave complete.
The three-surface architecture is a feature of the project, but the
engineering cost of maintaining it is real and worth calling out.

## 5. Accomplishments we're proud of

We shipped a single typed MCP surface of fifty-one tools that
covers memory forensics, timeline forensics, artifact carving,
disk-image primitives, Windows registry forensics, Windows event-log
triage, pattern matching, external intel lookups, the signed bundle
round-trip, the rule generators, the IOC exporters, and the report
renderers. Every tool has a pydantic input contract and a pydantic
output contract; every tool is reachable from all three deployment
modes through the same core calls. Fifty-one is not a number we
picked as a target; it is what emerged from saying yes to every tool
that cleared the bar of "we can wrap this with a typed runner and an
allow-list." Behind the surface sit 746 passing tests, zero ruff
violations, and a mypy-strict-clean `src/core`.

We built the offline-to-online flow end to end with a cryptographic
trust boundary. An operator can run APTWatcher on an air-gapped SIFT
VM, sign the resulting bundle with an Ed25519 key, carry the bundle
across the boundary through whatever transport suits the environment,
and have the online peer verify the signature and the content digest
before any remediation action fires. We are not aware of another
autonomous defensive IR agent that takes the signed-handoff pattern
as a first-class contract rather than an afterthought.

We wrote the accuracy methodology before we had any results. The
threshold policy, the exit-code contract, the declared gate of
aggregate mean F1 at or above 0.80 for the submission checkpoint —
all of it lives in `docs/ACCURACY.md` and predates the first
scorecard. That matters because a benchmark whose target is set
after the result is known is a benchmark whose target you could
silently nudge. We wanted a gate we had to meet, not a gate we got
to decorate.

We kept the knowledge base clean-room. Every one of the thirty-two
committed entries carries a documented `source_type`, every entry
attributes its source, and the forbidden-string policy is enforced
by a grep sweep in CI. We ruled out material we could have used
because we could not publish it, and the result is a corpus that
stands on its own in the repository.

We shipped a bilingual report pipeline, English and French, with
identical sectioning in both languages. The docx renderer uses a
single internationalization dictionary; adding a third language is
a dictionary entry, not a rewrite. The motivation was practical
rather than ornamental — IR teams in bilingual environments
routinely have to produce the same incident report twice, and
automating the second pass is a real time saver.

We built the audit log as a first-class product surface. The log is
JSONL, append-only, fsync'd, and grep-able with `jq` in one-liners
we put in the design doc. A reviewer can answer "did the run emit a
report," "how many correction passes happened," "did the corrector
ever fall back to safe default," and "which tool calls cited which
findings" with four unambiguous queries against the log file. The
log is the hand-auditable artifact a skeptical reviewer should be
able to use to reconstruct the run, and we built it to that brief
from day one.

## 6. What we learned

Contract-first types paid back faster than we expected. Every
pydantic model locked in a shape that would otherwise have drifted
across the three deployment surfaces. We caught shape drift during
development many times, and the catch point was always a model
validator raising on an unknown field, not a downstream consumer
silently producing garbage. The habit of writing `extra="forbid"`
on every model — not just the ones we thought were sensitive —
turned into a quiet, persistent productivity multiplier.

LLM self-correction turned out to be more valuable as a schema gate
than as a creativity gate. Early iterations of the self-corrector
prompt tried to do too much — rewrite summaries, reweight
confidences, invent missing citations. The results were mixed, and
the architectural review of every intervention was expensive. The
change that made the corrector useful was narrowing its remit: let
the planner brainstorm freely, then cut brutally at the gate when a
claim does not cite. We found we would rather have a planner that
proposes ten findings and loses three at the gate than a planner
that proposes seven findings all of which pass, because the first
shape lets us see what the model was considering and the second
shape does not.

Parallel agent dispatch during development — running three to five
sub-agents per turn on independent slices of a wave — roughly
doubled our per-session throughput without sacrificing quality
control. The cheap quality gates (AST parse, `mkdocs build
--strict`, NUL-byte scan, clean-room forbidden-string grep) carried
the QC load that a human reviewer would otherwise have borne per
sub-agent. The gates did not catch every class of bug, but they
caught the catastrophic ones, and the residual work fit inside a
single final QC pass per session. We did not expect the QC gates to
be load-bearing for the development workflow; once we saw the
pattern, we invested in them deliberately.

## 7. What's next

The accuracy fixture set has widened from two seed scenarios to
eight — Linux persistence, ransomware pre-encryption, lateral SMB
movement, DNS tunneling, credential dumping, phishing beacon, macOS
persistence, and cloud IAM escalation. The next step, per the
roadmap in `docs/ACCURACY.md`, is recalibrating the threshold once
the per-tier rollup has meaningful numbers in every bucket.

A real-LLM smoke test on the Anthropic backend is the next
milestone on the execution side. Everything the accuracy harness
reports today is produced by `FakeModelClient` replaying canned
transcripts. The pre-submission rehearsal will drive the same
scenarios through the real `AnthropicModelClient`, record the same
scorecard numbers, and publish the delta between the two runs.
Until that delta is measured, the offline harness is an upper
bound on real performance, not a prediction of it.

Phase 3.1 external intel has landed: nine Tier 1 lookup tools now
ride the `IOCAggregator` contract and the HTTP provider base class,
with the APT Watch adapter among the first implementations on the
contract. Degradation on missing credentials is a first-class
behavior of the aggregator — the tier is still useful if only one
provider is reachable — and the remaining intel work is provider
breadth, not plumbing.

Phase 3.3 defensive containment is the next Tier 3 wiring
task. The primitives — process kill, local RST, DNS sinkhole — are
scaffolded; the tier gate, the consent gate, and the pre/post hash
chain are designed; the live integration with the `cnc_disruptor`
surface is the remaining work. We are treating that phase
conservatively: each containment primitive ships with an operator
confirmation path, and the demo stays off containment by default.

End-to-end demo rehearsal on a vanilla SIFT VM is a submission
gate. A five-minute recorded demo covering the triage run, the
bundle sign, the online import, and one publication adapter is
the other submission gate. The accuracy gate is already green on
the eight-fixture set; the recording is the remaining work.

The submission also opens a community contribution path for the
knowledge base. New entries land under `knowledge/` through pull
requests against the `source_type` policy documented in
`knowledge/README.md`. We want the corpus to grow in the open
under the same clean-room rules that produced it, so a future
maintainer inherits a tree they can keep standing behind.

## 8. Built with

We built APTWatcher in Python 3.11 and above. The data layer uses
pydantic 2 for every contract, with `extra="forbid"` as the
project-wide default. The direct-agent CLI uses Typer for its nine
top-level subcommands and argparse for the analyze-and-publish
family. The MCP server uses FastMCP for the stdio transport and
tool registration. Report rendering uses python-docx for the
bilingual analyst report; configuration and knowledge-base front
matter use PyYAML. The bundle signing uses the `cryptography`
library's Ed25519 primitives. The LLM adapter targets the
Anthropic Claude API through a typed `AnthropicModelClient` with
retry and backoff. YARA, Sigma, and STIX 2.1 serve as the output
formats for rules and IOC bundles. The documentation site is
built with mkdocs-material. The project is MIT-licensed and runs
on top of Protocol SIFT where Volatility 3, Plaso, bulk-extractor,
Sleuthkit, YARA, Hayabusa, Chainsaw, and RegRipper are the
wrapped tools.

## 9. Try it out

The try-it-out instructions live at `docs/TRY-IT-OUT.md`, which
walks through the installation, the configuration file, the
optional tier flags, and the two flagship commands. The
two-minute smoke test is the accuracy harness replay, documented
in `docs/ACCURACY.md`:

```
aptwatcher eval --fixtures-dir tests/accuracy/fixtures
```

The command discovers every manifest under the fixtures
directory, runs the scoring pipeline against each, writes a
timestamped JSON and Markdown scorecard, and exits with the
aggregate mean F1 compared against the threshold flag (default
0.60). A green exit on the eight seed fixtures is the "did you wire
the pipeline correctly" check. The longer form is the full
analyze-and-publish pipeline, which produces the signed bundle
alongside the analysis outputs:

```
aptwatcher analyze \
    --incident-id <id> \
    --profile windows-host-triage \
    --evidence <path> \
    --output-dir <path> \
    --sign --operator <name> --private-key-path <path>
```

The analyze command fans the verified findings and IOCs into the
rule generators, the IOC exporters, the bilingual report
renderers, and the signed `IncidentBundle` exporter. With
`--sign`, the bundle manifest is digested and the detached Ed25519
signature is written alongside. Without `--sign`, the unsigned
bundle is emitted for dev-loop use. The full option reference is
in the try-it-out page, and the architecture context is in
`docs/ARCHITECTURE.md`. If you are reading this on the Devpost
site, the repository README is the next click — it carries the
one-line install and links back into the documentation site where
every claim on this page has a design note backing it.
