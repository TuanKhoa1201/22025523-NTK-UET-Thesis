# M1 execution report

## Root-cause continuation (base 0c2ffa1)

Current report: `ROOT_CAUSE_REPAIR_REPORT.md`. Six original upstream blobs remain
exact; generated NTK patch now reconstructs four files including scan_manifest.py.
Direct advisor-patched original scanner ran real OpenGrep (4 JSON/SARIF findings)
with recording/local-config overlay; source was an offline snapshot, NOT full clone
or Typer CLI. Full checkout/CLI remains PENDING (clone HTTPS blocked, typer absent
in isolated venv). No RAG/cloud activated. Source/exit captures now gate reimport.
Local changes are uncommitted due to index.lock permissions; prior entries are historical.

## Original-task continuation (base 682a818)

Current authoritative handover: `ADVISOR_ORIGINAL_TASK_STATUS.md`. The advisor
materials are now available and were inspected privately. Patch check/apply on the
verified offline snapshot passed; full clone failed HTTPS; genuine upstream CLI
help/scan both failed at missing typer. Therefore full upstream app remains NOT
PROVEN. Separate binary flag probe and NTK real scan/handoff passed (4 findings,
rule IDs/trace/raw bytes retained). Earlier sections are historical.

## P0 advisor handover update

Starting HEAD for this continuation: `5a5250643cbe08b3edf86474d9c879fc3c2fb3cc`.
Current baseline suite: 24/24 PASS (22 original + 2 patch checks).
Git staging remains blocked by index.lock permissions; no new commit or push.
The existing base SHA above does not contain this continuation's local changes.
See `ADVISOR_M1_EVIDENCE.md` for the current concise report. Real OpenGrep 1.20.0
rerun at `evidence/advisor-m1/`: 4 JSON/SARIF findings and 16 grounded trace locations.
Patch generation and actual Git apply round trip pass; six upstream blobs remain exact.
Only fork whitespace was normalized; upstream bytes were not changed. Raw `.patch`
text retains deleted upstream whitespace, which Git diff --check can warn about even
though applying the patch produces clean fork code with no Git apply warnings.
Earlier sections below are historical results, not the current Git delivery status.

## Resumed execution — 2026-11-11

**M0 workspace checks: PASS. M1 scanner replacement: PASS on real OpenGrep with
synthetic Java inputs.** This is a functional acceptance demonstration, not
a vulnerability-accuracy benchmark or a completed local-Qwen milestone.

The earlier ownership blocker below was resolved using the user's explicit
per-command Git trust authorization. No global config, ACL or security setting changed.

### Workspace and M0 evidence

Host: `LAPTOP-PSMH40NJ`; observed local timestamp:
`2026-11-11T02:37:23.5981124+07:00`.

Exact PowerShell Git prefix for every subsequent Git command:

```powershell
$repoPath = (Get-Location).Path.Replace('\', '/')
git -c "safe.directory=$repoPath" branch --show-current
git -c "safe.directory=$repoPath" status --short --branch
git -c "safe.directory=$repoPath" rev-parse HEAD
git -c "safe.directory=$repoPath" worktree list
git -c "safe.directory=$repoPath" config user.name
git -c "safe.directory=$repoPath" config user.email
git -c "safe.directory=$repoPath" remote -v
```

Results: `v2/codex-core`; initial HEAD
`b7246823dba53c0c4cd3f6d8a7e853147f901bac`; only pre-existing untracked change
was `v2/baseline/M1_REPORT.md`. Worktree listing showed separate integration,
Codex and Antigravity branches at that initial commit. Git identity and origin were
configured. No other worktree was edited.

`Get-Content` succeeded for AGENTS, M0_CHECKLIST, TASK_BOARD, MODEL_POLICY and the
existing report. A temporary `v2/baseline/.m0_write_probe` was written, read back,
asserted equal to `ok`, then removed; a one-case `unittest.FunctionTestCase`
passed. `python --version`: 3.13.3.

`Get-Command python,py,opengrep,ollama,wsl,curl.exe -ErrorAction SilentlyContinue`
found OpenGrep at `C:\Users\HP\.opengrep\cli\latest\opengrep.exe`;
Ollama was not found on PATH. `wsl --list --quiet` failed with
`Wsl/E_ACCESSDENIED`; Windows-native OpenGrep was used. Server/GPU/model availability,
advisor private module/license and private incoming/evidence setup were not verified.
Those broader M0 checklist items remain pending; no inference device was selected.

### Upstream inspection and implementation

- Repository: [hardw00t/simple_semgrepAI](https://github.com/hardw00t/simple_semgrepAI/tree/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9).
- Pinned commit: `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`; package version 0.2.0;
  MIT, copyright 2025 hardw00t. Retrieved via connected GitHub API after direct
  `curl.exe -L --fail --max-time 30 https://api.github.com/repos/hardw00t/simple_semgrepAI/commits/main -o v2/baseline/upstream-commit.json`
  failed with connection error 7. That attempted download produced no provenance artifact.
- Inspected scanner, CLI, configuration, package dependencies, default YAML and license
  before modifying them. Six exact upstream files are retained in `upstream/`;
  provenance records their actual Git blob SHAs. Unit tests verify all six byte-for-byte.
- `fork/semgrepai/scanner.py` derives from the upstream scanner; `config.py` and
  `cli.py` replace cloud-capable initialization with a standard-library local scanner path.
  It runs OpenGrep JSON/SARIF, stores evidence, preserves empty successful envelopes,
  rejects failed/partial/malformed runs, and marks findings REVIEW.
- Native `extra.dataflow_trace` takes precedence and is retained without flattening
  or invented steps; legacy top-level traces remain a fallback. No LLM was called.
- New local Java demonstration taint rules cover CWE-22, CWE-78, CWE-79, CWE-89.
  New synthetic positive/negative Java fixtures support focused verification.
- `opengrep.patch` records the three modified upstream files.
  `make_patch.py` regenerates it; README explains inheritance, changes and reproduction.

### Exact verification commands and results

From workspace root, PowerShell:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'v2/baseline/fork'
python -m semgrepai v2/baseline/fixtures/java --output-dir v2/baseline/evidence/real-02
python v2/baseline/verify_real.py v2/baseline/evidence/real-02
python -m unittest discover -s v2/baseline/tests -v
python v2/baseline/make_patch.py
```

| Check | Actual result |
| --- | --- |
| Installed engine version | PASS: 1.20.0; captured version subprocess exit 0 |
| Real JSON invocation | PASS: exit 0, 2 files, 4 rules, 4 findings, errors empty |
| Real SARIF invocation | PASS: exit 0, 4 results |
| Constant-only Safe.java control | PASS: scanned, 0 findings |
| Native trace preservation | PASS: all four normalized traces equal raw traces |
| Source grounding of real trace | PASS: 16 source/intermediate/sink locations match byte offsets and line/column text |
| Unit suite | PASS: 22 tests; subprocess cases are mocks, not runtime evidence |
| Upstream integrity | PASS: six source files match API Git blob hashes |
| Patch generation | PASS |

Actual scan argv is captured in `real-02/json.command.json` and
`real-02/sarif.command.json`. In portable notation it is:

```text
opengrep scan --config <absolute-workspace>/v2/baseline/rules/java.yml --json --dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60 --include *.java <absolute-workspace>/v2/baseline/fixtures/java
```

The second invocation substitutes `--sarif` for `--json`; arguments are passed
as a subprocess list, without shell interpolation. Engine log/settings paths are
set per child process into its output directory. Engine subprocess version/JSON/SARIF
exit codes were all 0. CLI returned 0.

Example from the actual CWE-22 trace: `Vulnerable.java:5`,
`req.getParameter("input")` → variable `input` on line 5 → `forwarded` on line 6 →
`new File(forwarded)` on line 7. The other actual sink lines are 8, 9 and 10.
The raw tagged trace is included in local `real-02/verification.json`.

### Evidence paths and practical limitations

- `v2/baseline/evidence/real-02/`: actual command arrays, version stdout/stderr,
  JSON/SARIF stdout/stderr and exit codes, `opengrep.json`, `opengrep.sarif`,
  `findings.json`, `verification.json` with input/output SHA-256 and example trace.
- `v2/baseline/evidence/unit-tests.txt`: final 22-test unit log.
- `v2/baseline/evidence/real-01/`: failed first genuine engine attempt, exit 2,
  unsupported `--metrics` flag. Removed that incompatible flag after reading the
  installed CLI help in `evidence/opengrep-help.txt`.
- Initial bare `opengrep --version` failed because its default home log was not
  writable. Redirecting child log/settings into workspace resolved this without escalation.

Generated logs/results are intentionally ignored by Git and remain on this machine.
They contain only synthetic inputs; no private datasets or scanned production code
were added. Private-data evidence storage outside Git remains a separate setup item.
These four rules have narrow source/sink coverage, no comprehensive sanitizer model,
and no measured recall/precision. Fixtures need not compile; OpenGrep parses their Java
source without resolving the placeholder Request/Response/Statement types.
No Ollama/Qwen run, advisor dataset evaluation, legacy modification, IRIS, CodeQL,
fine-tuning or CWSS work occurred. The task board was not marked complete.

### Changed files and Git delivery

All changes are under `v2/baseline/`: report and README; ignore policy;
six upstream source files plus provenance; scanner-only fork and MIT license;
four-rule Java YAML; two Java fixtures; unit tests; runtime verifier;
patch generator and patch; evidence README.

Commit: **not created**. Attempted:

```powershell
git -c "safe.directory=$repoPath" add -- v2/baseline
```

Actual failure (exit 128):

```text
fatal: Unable to create 'C:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/integration/.git/worktrees/codex/index.lock': Permission denied
```

The worktree index resides outside the writable workspace. No escalation, ACL change,
additional trust exception, commit or push was attempted. Changes remain local.
HEAD remains the initial `b7246823dba53c0c4cd3f6d8a7e853147f901bac` (this is not
a commit containing this implementation). A permitted Git environment is needed to commit.

Final checks: `python -m compileall -q v2/baseline/fork v2/baseline/tests v2/baseline/verify_real.py v2/baseline/make_patch.py`
passed. `git -c "safe.directory=$repoPath" diff --check` passed for tracked changes;
staged checks could not run because staging failed. Final status contains only
changes under `v2/baseline/`.

---

## Previous attempt (preserved history; superseded by resumed results above)

Date: 2026-11-11 (Asia/Saigon).

## Status

**M0: FAIL / BLOCKED. M1: NOT STARTED; not accepted.**

The user explicitly requires stopping if workspace ownership/permissions are inappropriate. Git rejected the initial branch, status and commit checks because repository ownership differs from the execution identity. No Git trust exception or permission change was attempted.

## Commands and observed results

Executed in PowerShell:

| Command | Result |
| --- | --- |
| `Get-Location` | PASS: `C:\Users\HP\OneDrive\Documents\NTK-Thesis-V2\codex` |
| `git branch --show-current` | FAIL: `fatal: detected dubious ownership in repository` |
| `git status --short` | FAIL: same ownership error |
| `git rev-parse HEAD` | FAIL: same ownership error; no SHA obtained |
| `Get-Content AGENTS.md` | PASS: file readable |
| `Get-Content v2/docs/M0_CHECKLIST.md` | PASS: file readable |
| `Get-Content v2/docs/TASK_BOARD.md` | PASS: file readable; M0 and M1 listed TODO |
| `Get-Content v2/docs/MODEL_POLICY.md` | PASS: file readable |
| `Test-Path -LiteralPath 'v2/baseline/M1_REPORT.md'` | False before report creation; no existing report overwritten |
| `Test-Path -LiteralPath 'v2/baseline' -PathType Container` | True |

Observed Git stderr, repeated for the three Git commands:

```text
fatal: detected dubious ownership in repository at 'C:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/codex'
'C:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/codex/.git' is owned by:
    'S-1-5-21-3252983786-677309692-1831176909-1001'
but the current user is:
    'S-1-5-21-3252983786-677309692-1831176909-1007'
```

The initial PowerShell batch returned exit code 0 because its final file read succeeded. This does **not** mean the Git checks passed; their actual stderr is reproduced above.

## Changes and verification

- Only this report was added. No implementation, legacy code, Git configuration or permissions were changed.
- Report creation confirms write access to this file only; broader permission checks and the small test were not run after the stop condition.
- No upstream code, license or commit was inspected; no patch/fork was created.
- No unit tests, mocks, scanner version checks or real OpenGrep scans were run. There are no findings JSON, trace or runtime evidence artifacts.
- Evidence path: `v2/baseline/M1_REPORT.md` (command outcomes and observed stderr above).
- Commit SHA: unavailable. No commit or push attempted.

## Unresolved issues

Run under the repository owner's intended account or have the workspace administrator resolve/explicitly authorize Git ownership trust for this checkout. Then repeat M0, including branch `v2/codex-core`, working-tree status, HEAD, write verification and a small test, before beginning M1. Repository changes could not be assessed while Git refused access.
