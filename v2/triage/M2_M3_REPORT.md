# NTK Thesis V2 — M2/M3 local core report

## Original-task continuation (base 682a818)

Queue behavior now matches the supplied five-page advisor PDF: default view excludes
only human CONFIRMED_FALSE; `--all`/show/history retain access; reopen restores the
row. No SQLite schema/history migration or row deletion. Real-engine SCRIPTED-DEMO
on a synthetic SQL allowlist control passed 1 -> 0 -> 1 and stale-hash refusal.
Explicit --path-map resolves INT-01 paths without editing raw JSON; hash/line/offset
gates remain active. Real WSL execution is blocked by E_ACCESSDENIED; mappings are
verified with synthetic-path collector and CLI regressions. No new Qwen execution.
See `baseline/ADVISOR_ORIGINAL_TASK_STATUS.md` for current evidence and Git delivery;
earlier queue/all-state descriptions and source-availability claims below are historical.

## P0 integration handover update

Continuation base: `5a5250643cbe08b3edf86474d9c879fc3c2fb3cc`, `v2/codex-core`, clean at start.
Current checks: baseline 24/24 PASS (22 original + 2 patch checks); triage 51 run,
50 PASS / 1 SKIP (Windows symlink privilege); compileall PASS. Logs are
`v2/baseline/evidence/p0-m1-tests.txt` and `v2/triage/evidence/p0-triage-tests.txt`.
Delivery status: **not committed/pushed**. Authorized workspace-only `git add --
v2/baseline v2/triage` failed with exit 128: cannot create
`integration/.git/worktrees/codex/index.lock` (Permission denied). No escalation,
ACL/ownership/security change or remote write attempted. HEAD remains the continuation
base `5a5250643cbe08b3edf86474d9c879fc3c2fb3cc`, not a commit of this new work.

New files this round: baseline `.gitattributes`, `ADVISOR_M1_EVIDENCE.md`,
`verify_patch.py`, `tests/test_patch.py`; triage `SCHEMA_CONTRACT.md`, `runtime.py`,
`export_pilot.py`, `demo_freshness.py`, `tests/test_contract.py`.
Modified: baseline scanner (whitespace only), generator/generated patch, README/report;
triage evidence/ollama/CLI, existing tests, README/report. No file outside these two
allowed directories was modified. Generated logs and the inspected scorer copy are
ignored. Code whitespace check passes with generated patch excluded; full diff check
reports preserved deleted-upstream whitespace inside the patch. No patch text was
manually altered to suppress that warning; actual Git apply is warning-free.
Added `SCHEMA_CONTRACT.md` (schema 1.1), an exact raw-byte/index-ID pilot exporter,
per-warning HTTP/runtime provenance and `demo_freshness.py`. Existing IDs/nested
formats/human states remain unchanged. Real OpenGrep freshness demo passed:
scripted confirm-true on unmodified synthetic copy; editing that copy causes
confirm-false refusal; history and original fixtures unchanged. No new real Qwen
execution is claimed. Mock HTTP never becomes verified model runtime.

Pinned Antigravity scorer at `103e5f0411bcf962cf4b31ee8c07f181ec2dd444` was read,
not changed. Its smoke check on four exported real-engine alerts + disabled-inference
REVIEW records found no join anomalies; all four intentionally UNLABELED. See contract
for exact mapping and runtime limitations. Earlier sections below are historical.

Date: 2026-11-11, Asia/Saigon. Branch: `v2/codex-core`.

**Verified local implementation: PASS with limitations. M2 real Qwen acceptance:
PENDING/BLOCKED by unavailable local service. No model-runtime completion claimed.**
M3 safety mechanisms are tested locally; this is not a claim of a correct security
classifier or complete evaluation on real projects.

## 1. M1 verification and integration boundary

Read AGENTS, TASK_BOARD, MODEL_POLICY, M1 report, README and scanner/config/CLI.
Existing M1 regression suite: 22 tests PASS. Existing real-02 JSON/SARIF verification:
4 findings, 4 SARIF results, 0 Safe.java findings and 16 grounded trace locations PASS.
The source snapshot/license provenance tests also passed.

The existing fork is a scanner-only extraction from simple_semgrepAI 0.2.0 at
`2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` (MIT). It does not replace the full
upstream web, RAG, reporting and LLM stack. Those components are not safe to imply
local-only by applying the scanner patch. The new CLI reuses the scanner directly
and implements the required local triage/review path without invoking that stack.
No M1 code change was necessary; no comprehensive real-project M1 claim is made.

## 2. Implemented in v2/triage/

- `evidence.py`: raw JSON retention, strict JSON parsing (including duplicate-key
  rejection), source-root confinement, actual UTF-8/CRLF line/column/offset checks,
  snippets, SHA-256 per referenced Java file, verified source/sink/intermediate
  locations and raw trace preservation. Malformed/partial scans keep issues and
  readable warnings; missing or unsupported traces do not acquire invented flows.
- `ollama.py`: bounded loopback HTTP only, no proxies/redirects/cloud fallback;
  default model `qwen3.5:9b-q4_K_M`; structured prompt/schema; three proposed states;
  exact citation/path/line/hash checks; current-version recheck; failures become
  UNDETERMINED with reasons and retained raw response when available.
- `store.py`: local SQLite records, queue and explicit human actions. REFUTED never
  changes OPEN. False confirmation requires complete evidence and matching current
  hashes for every referenced Java file, including trace source files. Audit stores
  actor/time/reason/warning/source versions/evidence digest. Reopening preserves history.
- `cli.py`, `__main__.py`: real scan or raw JSON import, evidence/assessment JSONL,
  SQLite queue/show/decide/history. Fresh output directories prevent overwrite.
  No source patching or deletion feature exists.
- `tests/test_triage.py`: evidence, model schema/citations, failures, review,
  CLI and actual HTTP transport integration with an explicitly simulated server.
- `verify_demo.py`: independent verification of the real-engine synthetic demo.
- `README.md`, `evidence/README.md`, `.gitignore`, `__init__.py` and this report.

New triage code is independently authored using Python standard library. Its only
runtime dependency on inherited code is the M1 scanner/config import for real scans.
No advisor ZIP was found by scoped filename search, including ignored files while
excluding legacy backend/apps/research/evaluation. No advisor code/license integration
is claimed. No changes were made to legacy code, evaluation or the task board.

## 3. Commands executed and observed results

Executed from the workspace root in PowerShell:

```powershell
python -m unittest discover -s v2/baseline/tests -v > v2/triage/evidence/m1-tests.txt 2>&1
python v2/baseline/verify_real.py v2/baseline/evidence/real-02
python -m unittest discover -s v2/triage/tests -v > v2/triage/evidence/triage-tests.txt 2>&1
python -m compileall -q v2/triage
python -m v2.triage run --source-root v2/baseline/fixtures/java --output-dir v2/triage/evidence/demo-real --timeout 2 > v2/triage/evidence/demo-real-cli.txt 2>&1
python -m v2.triage queue --db v2/triage/evidence/demo-real/review.sqlite > v2/triage/evidence/demo-queue.json
python -m v2.triage.verify_demo v2/triage/evidence/demo-real
```

| Verification | Actual result |
| --- | --- |
| Existing M1 unit tests | PASS: 22/22 |
| New triage suite | PASS: 42 run, 41 passed, 1 skipped |
| Symlink creation test | SKIPPED: Windows account lacks symlink creation privilege; no elevation attempted |
| Compileall | PASS |
| Real OpenGrep version | 1.20.0 |
| Real CLI scan JSON / SARIF | PASS: engine exits 0, 2 Java files, 4 findings / 4 SARIF results |
| Source-grounded triage demo | PASS: 20 finding/source/intermediate/sink locations match actual source |
| Actual local Ollama tags probe | FAIL: timeout at 127.0.0.1:11434; logged |
| Actual model requests for four warnings | FAIL: each timed out; all four retained UNDETERMINED and OPEN |
| Mock model / actual loopback HTTP transport | PASS: schema request, exact citations, REFUTED stays OPEN, redirects refused |
| False confirmation on changed/missing/hash-mismatched source | PASS: refused, no decision appended |
| Human false confirmation / history / reopen | PASS in temporary synthetic test stores only |

The 42 tests cover valid/invalid JSON, duplicates, malformed findings, complete/missing
traces, unsupported trace shapes, bad content/offsets, skipped paths/nonzero or unknown
engine exit, exact/wrong citations, missing evidence, invalid model schema/JSON,
unavailable/timeout/incomplete/wrong-model responses, path traversal, outside trace paths,
multi-file freshness, CRLF/UTF-8, false confirmation, reopening, explicit human true,
hash mismatch, no automatic dismissal, duplicate-import preservation and CLI/HTTP flow.
Partial engine failures and post-scan version-read errors also preserve the queue.
The one skipped symlink case remains a validation gap on this Windows account;
ordinary traversal/absolute-outside/trace-path confinement tests passed.

One attempted invocation of the baseline-specific verifier against the new triage
engine folder failed because that folder has no baseline `findings.json` artifact.
It was the wrong verifier for this pipeline. No result was fabricated to satisfy it;
the new triage verifier independently checks its actual artifacts and passed.

The local availability probe used `OllamaClient(timeout=2).tags()`, writing
`evidence/ollama-probe.json`. The recorded UTC timestamp is
`2026-11-10T19:56:51.027611+00:00` (2026-11-11 local time). No model install/pull,
hardware provisioning or overlapping JavisOS infrastructure work occurred.

## 4. Evidence and interpretation

All generated evidence is local and Git-ignored:

- `evidence/m1-tests.txt`, `evidence/triage-tests.txt`.
- `evidence/ollama-probe.json`: actual timeout, model_runtime_executed false.
- `evidence/demo-real/engine/`: actual engine argv, version/stdout/stderr/exit files,
  `opengrep.json`, `opengrep.sarif`.
- `evidence/demo-real/input.opengrep.json`, `evidence.json`, `assessments.jsonl`,
  `review.sqlite` and `demo-verification.json` with artifact SHA-256.
- `evidence/demo-real-cli.txt`, `evidence/demo-queue.json`.
- `evidence/source-manifest.json`: SHA-256 of final triage source/docs and test/runtime logs.

The real example source remains baseline `Vulnerable.java`: request source on line 5,
intermediate variable on line 6 and sinks on lines 7–10. The constant-only Safe.java
was scanned with no findings. This is synthetic functional evidence, not precision,
recall, false-positive rate or performance benchmark evidence.

**OpenGrep is real. Qwen responses in tests are mocks. The demo used actual failed
Ollama connection attempts, not a simulated successful Qwen run.** Correct quotations
only demonstrate source grounding; `security_conclusion_verified` always remains
false. Even a correctly cited REFUTED assessment requires an explicit human decision.

## 5. Limits and server handoff

- Real Qwen model availability, quantization/digest, successful JSON generation,
  timing/resource use and server compatibility are still pending with JavisOS.
- Configure an externally managed loopback tunnel if the model lives on the server;
  this adapter intentionally refuses a remote endpoint. Test Ollama's installed
  support for schema `format`, `think: false`, 4096 context and the exact model tag.
  Any incompatible response/error remains UNDETERMINED; no silent model substitution.
- Trace support covers the observed CliLoc/intermediate_vars format. Unknown CliCall
  variants are retained and require review/future tested support.
- Imported JSON cannot prove its historical source version. Pass the genuine exit
  code; hashes capture evidence collection time. Direct scans hash inputs before
  and after OpenGrep. Keep source stable during scan/inference/confirmation.
- Local SQLite actor names are self-declared; application audit is transactional but
  not tamper-proof against direct database edits. No OS isolation against concurrent
  adversarial file replacement is claimed.
- Demo rules have limited framework/sanitizer coverage. No labeled corpus or measured
  accuracy is available. No automatic security conclusion is treated as final truth.
- Before reporting full completion to the advisor: preserve this runtime evidence,
  resolve the skipped filesystem test in an appropriate test environment, obtain real
  server Qwen logs/structured outputs/model identity, run human review on representative
  labeled Java cases (especially CWE-22/89), and confirm the intended upstream/ZIP
  integration boundary and license if the private package is later supplied.

## 6. Git delivery

Read-only Git checks use the authorized per-command workspace exception:

```powershell
$repoPath = (Get-Location).Path.Replace('\', '/')
git -c "safe.directory=$repoPath" status --short --branch
git -c "safe.directory=$repoPath" diff --check
git -c "safe.directory=$repoPath" rev-parse HEAD
```

Branch remains `v2/codex-core`; HEAD remains
`b7246823dba53c0c4cd3f6d8a7e853147f901bac`. **No implementation commit was created**;
that SHA is the unchanged base, not a commit containing this work. Prior M1 local
changes remain intact; this task creates `v2/triage/` source/tests/docs, expands its
tracked placeholder README, and stores ignored
generated evidence. Tracked diff whitespace check passed (it does not cover untracked
new files). The known worktree-index write blocker remains:
`integration/.git/worktrees/codex/index.lock: Permission denied`.
No Git write was retried, no ACL/ownership/sandbox/trust configuration changed,
and no commit/push was attempted in this task. Commit from a permitted PowerShell
environment after reviewing the local files; never commit the ignored evidence stores.
