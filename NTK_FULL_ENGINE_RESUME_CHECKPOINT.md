# NTK full-engine continuation checkpoint — 2026-11-02

## Stop condition and Git

Stopped at the user's explicit request to preserve the remaining weekly quota.
This is an engineering checkpoint, **not full E2E acceptance or a release**.

- Branch: `cwss-inference-v2-220`.
- Starting HEAD: `b2ebbbf53e9feaa58f46fccf9fe617d37a645670`.
- Checkpoint revision: the commit containing this document; obtain its exact ID with
  `git log -1 --format=%H -- NTK_FULL_ENGINE_RESUME_CHECKPOINT.md`.
- Main remains `97716ce3c4d38f83941fe0e219a9a67d2b6e4dae` in the separate official worktree.
- No reset, clean, history rewrite, database deletion, model change, or frontend source change.
- Research adapter PID 56143 was interrupted deliberately. Its worker stopped with it.
  Final process inspection found **no remaining continuation runner/IRIS worker**.
  KeyboardInterrupt in that run is an intentional quota stop, not a database failure.
- The short helper-scope CodeQL probe already running at the priority change finished normally.

## Production WebGoat E2E: NOT_STARTED

`work/full-engine-completion-20261102/run_production_webgoat.py` was prepared but **never executed**.
There is no new production WebGoat scan ID, persisted finding report, production cold/warm result,
or full-engine PASS. The `production-e2e-v1` runtime did not exist at final inspection.

Durable, Git-tracked runners are now:

- `tools/resume_original_iris_webgoat.py`: resume unfinished research CWEs using existing DB/API caches.
- `tools/run_full_engine_webgoat.py`: execute the actual production pipeline, persistence, and HTTP
  checks in a separate runtime; then repeat for semantic/CWSS equivalence.

Both require `--execute`; without it they only print help. Syntax compilation and `--help` passed.
**The production runner itself is not E2E-validated yet.** It uses explicit non-strict original mode
so an IRIS limitation can be persisted as PARTIAL, not silently called original-engine success.
Its first run is `INITIAL_PRIMED`, with DB/API caches already populated; it must not be described
as an all-layer cold scan. It binds research HTTP to 127.0.0.1:8782 and closes that server on exit.
The normal demo ports are not used. Scenario HTTP validation currently requests at most the first
100 findings; paginate this check if the eventual scan has more findings.

## Verified component results

| Check | Actual result | Evidence under `work/full-engine-completion-20261102/` |
|---|---|---|
| WebGoat pinned source | `5357a65e054976cd7d79b81ef3906ded050ed921`; 355 Java, 1,024,693 bytes | `webgoat-source-manifest.json` |
| Existing CodeQL DB | 355 archived Java files rechecked against source SHA-256 | `quota-checkpoint-receipt.json`; archive hash below |
| OpenGrep production rules | 355/355 scanned, 84 candidates, no missing files or scanner errors | `resume-webgoat-opengrep.json` |
| Original upstream | Pristine pinned `3a12f45750f58135bcc58c7fdf4c20786b600e31` | run request/logs, initial audit |
| CodeQL | 2.25.6; Java no-build, no project build scripts executed | DB metadata and run logs |
| Canonical batching | Actual cuda:0 input/output; serial/batch equal for 3 development APIs, including ProcessBuilder.start | `canonical-batch-equivalence.json` |
| Persistent DB cache | First 19.403 s; repeat 0.271 s; changed source 19.487 s with a different DB ID | `persistent-database-cache-probe.json` |
| Full backend suite before last small coverage/cache edits | 270 tests, 1 skipped, 0 failed | `resume-backend-release-tests.log` |
| Final related tests | 36 tests PASS, covering adapter, new cache/coverage/corroboration guards and aggregates | `checkpoint-targeted-tests.log` |
| Frontend contracts/build | 16 tests PASS; Vite build PASS, existing large-chunk warning | command output in session; no frontend source edits |

Three-API equivalence is a development regression, not a general accuracy guarantee.
The one-file cache speedup is **not WebGoat E2E speedup**.

### IRIS four-CWE status

The original failed continuation run is retained at:

`/home/tuankhoa/ntk-full-engine-20261102/resumed-full-iris-v1/runs/e3ad5ce5c6134f86-1793604145001815841`

The corrected but deliberately interrupted run is:

`/home/tuankhoa/ntk-full-engine-20261102/resumed-full-iris-v1/runs/c392ed883aeea751-1793605349063359342`

Within that run, outputs are below
`upstream-execution/output/ntk__source_d0f051b03fd2bcba/fresh/`.

| CWE | Real upstream SAPipeline status at stop | Raw results / thread flows | API cache entries (valid / rejected) |
|---|---|---:|---:|
| 22 | Main query, corroboration and postprocessing completed; mining contract limitations remain | 26 / 46 | 982 (949 / 33) |
| 78 | Main query, corroboration and postprocessing completed; mining contract limitations remain | 28 / 48 | 996 (961 / 35) |
| 79 | API mining interrupted; no final query result in this run | NOT_RUN | 724 (695 / 29) |
| 89 | Not reached by this full-mining run | NOT_RUN | 0 |

These are raw CodeQL results, **not verified vulnerability counts or triage totals**.
No aggregate `worker-result.json` was produced for the interrupted run; do not interpret its absence
as loss of already written SARIF, API caches or model outputs. There are 2,702 persisted API-response
entries across the three CWEs above. Native function-parameter mining also has its own cache.
The first run recorded 63 unique parameter generations, with 3 schema-invalid outputs.

Separate native-query + stock-model component probes ran all four CWEs successfully:

- Small six-file DB: all four query commands and corroboration queries exited 0.
- Full WebGoat DB, **stock models only**: CWE-22 7 results/15 flows; CWE-78 0/0;
  CWE-79 0/0; CWE-89 16/27.
- Receipts: `four-cwe-codegen-probe.json`, `stock-proof-probe.json`, `webgoat-stock-only-results.json`.

Those probes are **not full IRIS scans or A/B/C/D ablation**. The old reported “exit 1 after 76.5 s”
was not reproduced in saved probe receipts: the CWE-22 entry is exit 0 at 76.528 s, and all four logs
show successful SARIF export. A different, real duplicate-option failure was found and fixed below.

## Changes and fixes included in the checkpoint

Under `backend/ntk-production-v2/scripts/`:

- `ntk_original_iris_adapter.py`: opt-in full-source profile; verified preexisting DB reuse;
  separate persistent DB cache; batch Javac snapshot prewarm; streaming model hashes;
  source/license Git-blob binding; extension/library/executable hashes; corroboration binding;
  explicit cached-execution provenance and reusable PARTIAL results only for completed queries
  with known contract limitations. Budget/query/extraction/source-binding failures are not cached.
- `ntk_original_iris_worker.py`: actual SAPipeline still owns discovery/mining/query execution;
  opt-in full mining; generated-pack extension; stock-flow corroboration; no duplicated CLI flags;
  reuse query evaluation for SARIF/CSV instead of forcing `--rerun` twice.
- `ntk_local_role_batch.py`: bounded canonical local CUDA batches; exact raw output and token/device
  telemetry. API identity-prefill retry is disabled by default after its ProcessBuilder regression.
- `ntk_codeql_models.py`: conservative projection of installed manual CodeQL model facts.
  Missing model entries are never interpreted as `none` or safe.
- `ntk_engine_cache.py`: content-bound DB cache, archive verification, process/resource guards,
  dependency receipts. Missing psutil disk-I/O support is reported unavailable, not zero.
- `ntk_iris_codegen_extension.py`: NTK generated-pack union with installed stock security models;
  original upstream checkout remains unchanged.
- `ntk_iris_full_mining.py`: per-CWE/model/prompt API cache, strict schema validation, explicit
  unsupported/unexamined counts, native parameter task and cache. Invalid outputs do not become specs.
- `ntk_scan_aggregates.py`: whole-persisted-scan counts/CWSS profile statistics, no pagination bias
  and no triage changes or fabricated empty-scan score.
- `ntk_web_backend_service.py`: opt-in `.mvn` Java wrapper inventory; whole-scan aggregate persistence;
  separate inventory, engine-execution and semantic-coverage status.
- `ntk_pipeline_telemetry_and_datasets.py`: carry aggregate data into indexed scan summaries.

Tests: `tests/test_full_iris_cache.py`, `tests/test_scan_aggregates.py`.
Tracked continuation tools: the two scripts listed above. No frontend source files were changed.

Two real execution defects were fixed:

1. The wrapper and corroboration call both supplied `--threads`/`--ram`; CodeQL exited 2.
   The wrapper now adds only missing flags, and the caller no longer duplicates them.
   The corrected CWE-22 and CWE-78 corroboration queries ran successfully.
2. The installed psutil lacks `Process.io_counters`; the cache creation monitor raised AttributeError.
   Optional I/O telemetry is now guarded; real DB creation/hit/source-invalidation passed afterward.

## Blockers and unverified work

- Canonical Qwen still rejects some default-package and generic-constructor identities/signatures.
  Do not repair model outputs into trusted facts or enable identity prefill merely to pass schema.
  ProcessBuilder.start regressed from `sink` to `none` with prefill in a real development test.
- Native parameter task has malformed JSON outputs. EO06 is not proven for contextual vulnerability
  reasoning; posthoc remains explicitly disabled in this profile.
- Schema validity is not semantic accuracy. Full mandatory mining is not accepted while rejected or
  unexamined tasks remain. No no-path result establishes safety.
- Final adapter binding over all four WebGoat queries has not completed. The new production runner,
  final persistence/16-metric CWSS/HTTP aggregate checks and warm equivalence remain unexecuted.
- Current adapter guards still include 500 Java / 32 MiB; WebGoat fits. Larger OWASP full-repository
  acceptance has not been demonstrated. No complete semantic/framework coverage claim.
- Initial production run will reuse primed DB/API caches. A true all-layer cold benchmark remains absent.
- Fresh held-out evaluation, leakage exclusion and full A/B/C/D ablation remain NOT_RUN/NOT_PROVEN.
  Preserve old 40-case baseline: REVIEW 75%, automatic REPORT recall 15%; do not relabel old 46 as unseen.
- Check final source freeze before evaluation: research runs were development runs, and adapter/cache
  checks were improved after their launch. They are not receipts for a frozen final release.
- Cache keys include generator/mining/prompt hashes. Do not casually reformat or change those modules
  before resumption: that invalidates API cache reuse. Do not weaken cache keys to conceal changes.
  Final hashes were checked against an existing response entry and match:
  generator `7714823b823de1a4b7ce77f687e5c3e945cf579963066797875aa0568303a253`,
  mining `1968ee8f8bbce069510c286e3224dc6ffb23ab47be4d0203df63fc07ca6ac947`,
  shared prompt `f1d661ff0c92535f593abf677db95c836f1bfc4f342d65a8b5c69a9b4ec0af61`.

### Useful completed dependency diagnosis, not NTK accuracy

Official six-case labels/source bytes were verified at OWASP commit
`f40c618c5a709afce350ef06ed2899c85cf586e9`; CSV SHA-256
`1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`.
The old six-file DB omitted helper sources. Adding the same commit's helpers produced a 27-Java
development DB; unchanged stock CWE-22 queries then found both positive regression callsites.
The safe XSS case 02229 still has a stock-model path. CWE-78 case 00007 uses the environment-array
slot of Runtime.exec and is still missed by the stock component. Do not tune to testcase names.
Cross-CWE hits are retained in `six-helpers-component-results.json`; no full NTK accuracy metric is
claimed from this component experiment. No labels were passed to scanner/inference.

## Preserve these paths

All raw artifacts remain outside Git. `work/` is already ignored.

- Repo: `/mnt/c/Users/HP/Documents/NTK-Thesis-Migration/NTK-CWSS-V2-220`
- Python: `/home/tuankhoa/.venvs/ntk-production-20261028/bin/python`
- Source: `/home/tuankhoa/iris/data/project-sources/WebGoat`
- Staged all-Java source: `/home/tuankhoa/ntk-full-engine-20261102/webgoat-all-java-v1`
- Valid DB: `/home/tuankhoa/ntk-full-engine-20261102/webgoat-full-db-v1`
- DB `src.zip` SHA-256: `be42c747a35d1f5cfb555bd678a8189572b16be6c5cf596e37909f6efa3bc17a`
- DB metadata SHA-256: `2a70251e66986bb608e27b8967aac9875c82aeaabc3c01291a752058e4f3386a`
- IRIS: `/home/tuankhoa/ntk-original-iris-research-20261102/upstream-iris-v2-3a12f457`
- CLI: `/home/tuankhoa/iris/codeql/codeql`
- Java library pack: `/home/tuankhoa/.codeql/packages/codeql/java-all/9.1.2`
- Research runtime: `/home/tuankhoa/ntk-full-engine-20261102/resumed-full-iris-v1`
- API and parameter caches: that runtime's `persistent-cache/api-roles/` and `parameter-roles/`
- License binding: that runtime's `reviewed-public-license.json`
- Local audit/receipts/backups: `work/full-engine-completion-20261102/`
- Current copied source checkpoint: `work/full-engine-completion-20261102/resume-source-checkpoint/`
- Start-of-work tracked source backups: `work/full-engine-completion-20261102/baseline/`
- Exact stop receipt: `work/full-engine-completion-20261102/quota-checkpoint-receipt.json`
- Helper DB receipt/path: `work/full-engine-completion-20261102/six-helper-scope-database.json`
- Canonical model paths: existing `work/acceptance/runtime/launch-env.json` (required by both runners).
- Adapter SHA unchanged: `176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`.

Demo remains separate: backend 8765 HTTP 200; frontend 5173 HTTP 200 from Windows.
WSL localhost:5173 was refused even while Windows returned 200; do not restart the frontend solely
because of that WSL networking difference. Original scan `SCAN-20261101164045-3AA266` JSON hash is still
`70645502e5b86ba59231340a94c540c29c424c119c6650c6d579023b3050e891`.

## Exact continuation after quota reset

Run these in Windows PowerShell. Use WSL Git, not Windows Git. A sandbox WSL E_ACCESSDENIED requires
the same approved WSL escalation as this session; do not change repository metadata permissions.

```powershell
wsl.exe -d Ubuntu-22.04 --exec git -C /mnt/c/Users/HP/Documents/NTK-Thesis-Migration/NTK-CWSS-V2-220 status --short
wsl.exe -d Ubuntu-22.04 --exec git -C /mnt/c/Users/HP/Documents/NTK-Thesis-Migration/NTK-CWSS-V2-220 log -1 --format=%H
```

First resume only the unfinished research queries; existing valid API caches are reused:

```powershell
wsl.exe -d Ubuntu-22.04 --exec /home/tuankhoa/.venvs/ntk-production-20261028/bin/python -u /mnt/c/Users/HP/Documents/NTK-Thesis-Migration/NTK-CWSS-V2-220/tools/resume_original_iris_webgoat.py --execute --cwes 79,89
```

Read `work/full-engine-completion-20261102/resumed-full-iris-result.json` and its referenced run logs.
Its `cwe_scope` is only 79/89 for that command; combine evidence with preserved 22/78 receipts, do not
claim the new receipt itself covers all four. Resolve technical failures; preserve model abstention.

Then execute the prepared production pipeline on all four CWEs, in its separate runtime:

```powershell
wsl.exe -d Ubuntu-22.04 --exec /home/tuankhoa/.venvs/ntk-production-20261028/bin/python -u /mnt/c/Users/HP/Documents/NTK-Thesis-Migration/NTK-CWSS-V2-220/tools/run_full_engine_webgoat.py --execute
```

Outputs: `work/full-engine-completion-20261102/production-webgoat-runs.json`,
`production-webgoat-equivalence.json`, and `/home/tuankhoa/ntk-full-engine-20261102/production-e2e-v1/`.
Inspect failures before calling anything accepted. Do not mock a completed adapter result to bypass
mining limitations. Do not recreate the existing 355-file database or clear caches for convenience.

Next priorities: (1) finish 79/89 with cache reuse; (2) validate actual production union/triage/CWSS/report
and persisted API totals; (3) warm equivalence with truthful cache-state labeling; (4) resolve contract
coverage and context limitations; (5) freeze code/config before independent OWASP evaluation/ablation.
No frontend redesign. No new work is running in the background at this checkpoint.

```text
WEBGOAT_FULL_JAVA_INVENTORY=PASS
WEBGOAT_OPENGREP_COMPONENT=PASS
ORIGINAL_IRIS_FOUR_CWE_FULL_MINING=PARTIAL_INTERRUPTED_BY_REQUEST
WEBGOAT_PRODUCTION_E2E=NOT_STARTED
WEBGOAT_COLD_WARM_E2E=NOT_RUN
INDEPENDENT_ACCURACY_AND_ABLATION=NOT_RUN
FULL_NTK_E2E_ACCEPTANCE=PARTIAL
DEMO_BASELINE_PRESERVED=PASS
```
