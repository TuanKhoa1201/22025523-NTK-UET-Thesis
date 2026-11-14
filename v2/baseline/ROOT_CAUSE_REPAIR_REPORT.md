# Root-cause repair — original task and evidence continuity

Base: `0c2ffa10c5f0d565325681e8ec2e33796fd4a68c`, branch `v2/codex-core`, clean at start.

**FULL UPSTREAM: PENDING, not PASS.** A clean full clone and the upstream Typer CLI
have not run successfully in this sandbox. The actual original scanner (private
advisor patch + NTK isolation/recording overlay, offline pinned snapshot) did run
OpenGrep and transfer four intact findings to triage. This is deliberately a narrower
claim than full checkout/CLI/application acceptance.

## Requirement → observed evidence

Read `_advisor_sources/README_FIRST.txt`, REQUIREMENTS_MATRIX, both PDFs and the ZIP
patch documentation. Private extracted text/hashes stay ignored under `evidence/`;
no original advisor package was added to public source. Prior results are retained.

| Requirement / defect | Repair or evidence | Current status |
| --- | --- | --- |
| Upstream identity / patch integrity | Pin 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9; six public Git blobs exact; generated NTK patch applies to four fork files including new scan_manifest.py | PASS |
| Full source available | New Git clone exit 128, github.com:443 connection refused | PENDING |
| Original entrypoint / dependencies | pyproject script semgrepai=semgrepai.cli:app; main.py and package __main__ also import app; eager __init__/CLI/config pulled validator, RAG, provider stack | Root cause identified |
| No RAG/cloud activation | New bounded overlay lazily initializes package, guards original Typer scan with --scan-only, loads scanner-only config, disables unrelated commands, returns before RAG/validator | Code/AST/config tests PASS; full CLI runtime PENDING |
| Isolated Python installation | venv created; offline minimal install of typer/rich/PyYAML/hatchling exit 1, no typer distribution available; safe CLI help/scan exit 1 at missing typer | PENDING |
| Windows console encoding | Direct original-scanner attempt failed UnicodeEncodeError in Rich on cp1252; process-local PYTHONUTF8=1/PYTHONIOENCODING=utf-8 resolved it | Real retry PASS |
| Original scanner execution | Real advisor-patched scanner with local config/recording; imports assert no semgrepai.rag, chromadb or semgrepai.llm.providers; JSON/SARIF 4/4 findings | PASS for direct scanner only |
| Raw handoff | Exact raw bytes, scan IDs, rule IDs and trace retained; 4 in/4 out with captured source and process exits | PASS |
| Scan-time source identity | Capture source inventory/rule hashes before and after engine; raw JSON/SARIF + command/stdout/stderr/exit hashes; validate on reimport | PASS |
| Declared --engine-exit 0 | Retained as operator declaration, never proof; original captured exits have a separate integrity flag; no manifest means REVIEW | PASS |
| Source edit, queue, history | Real SCRIPTED-DEMO queue 1→0→1; stale false confirmation refused; two historical events unchanged | PASS |
| Windows/WSL mapping | Existing explicit path-map retained, raw paths/JSON unchanged; mapping and scan-time source hashes must both match | Regression PASS; real WSL still PENDING |
| Live model execution | Separate protocol checker; triage exit 0 is not proof; supports UNDETERMINED/REFUTED/SUPPORTED equally | Checker tests PASS; actual local service unavailable |
| Paired pilot / Java real project | No labels or accuracy fabricated; no new real Qwen, no full-project benchmark in this task | PENDING / colleagues' work |

## Actual runtime outcomes in this round

Windows, Python 3.13.3, OpenGrep 1.20.0. Logs are local and ignored:

- `baseline/evidence/root-clone.txt`: clone 128.
- `baseline/evidence/root-isolated-install.txt`: isolated offline installation 1.
- `baseline/evidence/root-safe-cli/probe.json`: advisor patch check/apply 0/0;
  safe upstream CLI help/scan 1/1 (typer); separate binary flags JSON/SARIF 0/0.
  Snapshot kind is explicitly OFFLINE/targeted, not a full clone. Probe completion
  exit alone is not CLI or task success: inspect the separate fields.
- `baseline/evidence/root-offline-original-scanner/`: failed Rich encoding attempt.
- `baseline/evidence/root-offline-original-scanner-utf8/`: direct original-scanner
  exit 0, four findings, actual engine exits version/JSON/SARIF 0/0/0. Source is the
  prior verified offline snapshot, not a newly cloned repository. No Typer CLI ran.
- `triage/evidence/root-original-handoff/`: import exit 0 with manifest; four intact
  raw findings/rule IDs/traces; handoff-verification.json PASS.
- `triage/evidence/root-live/`: NTK direct CLI exit 0, four JSON/SARIF findings,
  20 source-grounded locations; four UNDETERMINED/OPEN assessments because no Ollama
  HTTP response was received. `live_check` exit 2, protocol PENDING (zero reported
  responses). It is not Qwen runtime evidence.
- `triage/evidence/root-import/`: manifest-bound reimport exit 0 without a declared
  engine code; recorded process exits were used.
- `triage/evidence/root-queue/queue-demo.json`: real engine, allowlisted synthetic
  query, scripted review actor, history retained and hash mismatch refused.

CWE-22 example: `Vulnerable.java:5` request source → variables at 5–6 → File sink
at 7. CWE-89: same source/variables → SQL sink at 10. Fixtures and four local rules
are demonstrations, not a measured accuracy dataset. The original scanner still
has its inherited normalization logic; triage always receives the raw files.

## Upstream execution recipe for JavisOS (not executed here)

Use a fresh private experiment directory. Do not install the full upstream dependency
set or execute its legacy default scan path: those activate the RAG/validator flow.
The public NTK preparer reads the private ZIP at runtime; it does not vendor it.

```bash
NTK=/path/to/ntk-worktree
ADVISOR=/private/advisor-sources
WORK=/private/ntk-root-repair
mkdir -p "$WORK"
git clone https://github.com/hardw00t/simple_semgrepAI.git "$WORK/upstream"
git -C "$WORK/upstream" checkout --detach 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9
git -C "$WORK/upstream" status --porcelain  # must be empty
python3 -m venv "$WORK/venv"
PY="$WORK/venv/bin/python"
"$PY" -m pip install 'typer>=0.12.0' 'rich>=13.5.0' 'PyYAML>=6.0.1' hatchling
"$PY" -m pip freeze > "$WORK/runtime-requirements.txt"
cd "$NTK"
"$PY" v2/baseline/prepare_upstream_local.py --upstream "$WORK/upstream" --advisor-dir "$ADVISOR" --output-dir "$WORK/prepared"
"$PY" -m pip install --no-deps --no-build-isolation -e "$WORK/prepared/source"
cd "$WORK/prepared/source"
unset PYTHONPATH
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
export SEMGREP_LOG_FILE="$WORK/upstream-engine.log"
export SEMGREP_SETTINGS_FILE="$WORK/upstream-settings.yml"
"$PY" -m semgrepai --help
"$PY" -m semgrepai scan "$NTK/v2/baseline/fixtures/java" --rules-path "$NTK/v2/baseline/rules/java.yml" --config-path "$PWD/semgrepai.yml" --output-dir "$WORK/upstream-capture" --scan-only
# Installed console entrypoint is also available: "$WORK/venv/bin/semgrepai" scan ... --scan-only
cd "$NTK"
"$PY" -m v2.triage run --source-root v2/baseline/fixtures/java --json "$WORK/upstream-capture/opengrep.json" --scan-manifest "$WORK/upstream-capture/scan-manifest.json" --output-dir "$WORK/triage-import" --no-llm
```

On Windows the venv interpreter is `venv/Scripts/python.exe`; set UTF-8 on that
process too. Record each command's actual exit separately. Preparation refuses an
unverified/incomplete checkout and uses pinned Git object bytes (not CRLF-converted
checkout bytes). `patch-results.json` proves check/apply; `preparation.json` proves
only checkout/overlay preparation. The inherited CLI scan function calls the inherited
advisor-patched scanner; NTK replaces dependency edges and records its real subprocess
exits/file outputs. Provider/RAG modules are neither imported nor called on this path.
Unrelated commands and scan without --scan-only are refused.

Scope: bounded upstream CLI/scan-path verification, not legacy web/RAG/LLM acceptance.
This overlay is an independently generated delta on the private advisor-patched
source. It is not a replacement claim for the whole upstream product. MIT license
and the untouched upstream modules remain in the private prepared tree.

## Current local reproduction

Use new output directories each time:

```powershell
python -m v2.triage run --source-root v2/baseline/fixtures/java --output-dir v2/triage/evidence/new-scan --timeout 2
python -m v2.triage.live_check v2/triage/evidence/new-scan
python -m v2.triage run --source-root v2/baseline/fixtures/java --json v2/triage/evidence/new-scan/engine/opengrep.json --scan-manifest v2/triage/evidence/new-scan/engine/scan-manifest.json --output-dir v2/triage/evidence/new-import --no-llm
python -m v2.triage.demo_queue --output-dir v2/triage/evidence/new-queue
python v2/baseline/verify_patch.py
python -m unittest discover -s v2/baseline/tests -v
python -m unittest discover -s v2/triage/tests -v
```

Do not manufacture a scan manifest later for historical JSON. Import without one is
retained with REVIEW/UNDETERMINED and cannot authorize a new false confirmation.
Keep the entire capture directory (manifest, adjacent command/exit/output files and
rules snapshot), together with a frozen source checkout; copying the manifest alone
is insufficient. Existing human history is not migrated or rewritten. Existing older
records without scan-time provenance need a fresh scan before new false confirmation.

Manifest checks provide integrity/consistency, not a signature: someone who can
rewrite every sidecar can forge an unsigned receipt. Independent run logs, external
artifact hashes and provenance review are still required for stronger attestation.
Model protocol checks likewise verify recorded transport/payload/model counters, not
the physical execution of a particular model. No SUPPORTED-only success test exists.

## Validation / delivery

Baseline: 27 PASS. Triage: 70 run, 69 PASS, 1 SKIP (Windows symlink privilege).
Includes original regressions, overlay import/guard tests, wrong hash/exit/manifest,
old source changed outside trace, new source inventory, legacy import refusal,
mapping/JSON/citation errors, Ollama timeout/mock and wrong finding/request/response
identity checks. Patch applies to four fork files; upstream snapshot remains exact.
Compileall PASS. Logs: `baseline/evidence/root-tests.txt`, `triage/evidence/root-tests.txt`.

**Git delivery: not committed/pushed.** Authorized scoped staging failed with exit
128: cannot create `integration/.git/worktrees/codex/index.lock` (Permission denied).
No escalation, ACL/ownership/security change or remote write. HEAD remains
`0c2ffa10c5f0d565325681e8ec2e33796fd4a68c`; it is not a new implementation commit.
Allowed directories only; no change to evaluation, repository verifier, Actions or
integration branches. Snapshot upstream blob files were not modified.

New source: baseline `prepare_upstream_local.py`, `upstream_local_support/scanner_config.py`,
`upstream_local_support/scan_recording.py`, `fork/semgrepai/scan_manifest.py`,
`tests/test_local_overlay.py`; triage `scan_receipt.py`, `live_check.py`,
`tests/capture_fixture.py`, `tests/test_scan_receipt.py`; this report.
Modified: scanner/patch generator/generated patch and verifier, advisor probe,
handoff verifier, triage evidence/CLI/runtime/Ollama/exporter, related tests,
README/schema/status reports. All are under v2/baseline or v2/triage.

Owner's safe manual commands outside the sandbox, after reviewing the staged file list:

```powershell
$repoPath = (Get-Location).Path.Replace('\', '/')
git -c "safe.directory=$repoPath" branch --show-current # must be v2/codex-core
git -c "safe.directory=$repoPath" add -- v2/baseline v2/triage
git -c "safe.directory=$repoPath" diff --cached --stat
git -c "safe.directory=$repoPath" commit -m "Bind scans to source receipts and isolate upstream CLI verification"
git -c "safe.directory=$repoPath" push origin v2/codex-core
```

Do not force-add ignored evidence or advisor originals. Runtime requirement freezes,
private patches/source copies, raw captures and model responses remain local/private.
