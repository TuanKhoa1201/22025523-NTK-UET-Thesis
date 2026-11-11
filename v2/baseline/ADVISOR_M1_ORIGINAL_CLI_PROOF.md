# M1 original CLI proof: simple_semgrepAI -> OpenGrep

**LAPTOP M1 ORIGINAL CLI runtime = PASS. Server acceptance = PENDING.**

The inherited Typer CLI, with the advisor patch and NTK scan-only overlay, actually
ran OpenGrep on the laptop. This is stronger evidence than patch application or a
direct scanner call. The original `proof.json` still says `SERVER_RUNTIME_PENDING`;
this report does not alter that field or claim server acceptance or full web/RAG operation.

- Branch: `v2/advisor-m1-proof-20261111`.
- NTK base HEAD: `940363f93aecaec5d2872a688addf974b31cccf7`; new delivery SHA: see section 7.
- Upstream: [hardw00t/simple_semgrepAI 0.2.0, MIT](https://github.com/hardw00t/simple_semgrepAI/tree/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9).
- Exact upstream commit: `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`.
- Exact tree: `c0ab3e20152ce5c3e6b80e1525288ad59c9aee93`, 96 files;
  `pinned_upstream_tree.json` and preparation bind the full source inventory.
- Advisor PDFs, matrix, README and private ZIP were consulted in the preparation
  work. Private originals, the ZIP, full checkout and runtime outputs are not published.

## 1. LIVE laptop evidence, 11 November 2026

Evidence root (outside repository):
`C:\Users\HP\NTK-M1-Runtime\proof-20261111-224908-bf784076`.
Host: `LAPTOP-PSMH40NJ`. Worker Python **3.12.3**, Typer **0.17.5**, Rich **15.0.0**,
PyYAML **6.0.3**; native Windows OpenGrep **1.20.0**.

The user executed the runner in Windows PowerShell and verified runner exit **0**
and an independent audit exit **0**. Codex subsequently READ the actual evidence
and performed an additional read-only audit, exit **0**, without rescanning.
The audit checks preparation, patch hashes, command log hashes, source/artifact
receipts, CLI origin, JSON/SARIF identity and handoff. Hashes establish consistency,
not a signed attestation of host role or independent security labels.

| Component | Result | Observed evidence |
| --- | --- | --- |
| Full pinned upstream preparation | PASS | 96 original files verified; prepared source hashes still match |
| Advisor `git apply --check`, `git apply` | PASS | `prepared/patch-results.json`: exits 0, 0 |
| Dependencies / CLI help / CLI scan / triage | PASS | `proof.json` command receipts: exits 0/0/0/0, no timeout; stdout/stderr hashes verified |
| Original CLI runtime | PASS on laptop | `capture/cli-origin.json`: `semgrepai.__main__`, `semgrepai.cli.scan`, completed exit hook, no forbidden imports |
| OpenGrep version / JSON / SARIF | PASS | Original recorded engine exits 0/0/0, 4 JSON findings and 4 SARIF findings |
| Handoff | PASS | 4 -> 4; raw bytes, full rule IDs, finding IDs, trace preserved |
| Source/artifact capture | PASS | 16 artifacts and 2 Java source SHA-256 values verified |
| CWE demo examples | PASS | CWE-22 and CWE-89 with source, intermediate variables and sink below |
| Server acceptance | PENDING | No server command logs provided; aggregate field remains `SERVER_RUNTIME_PENDING` |
| Full web/RAG and Qwen inference | NOT RUN / NOT REQUESTED | Scan-only isolates imports; triage uses `--no-llm`; no cloud inference |

Raw JSON SHA-256:
`fe8dcfe7279b3d4448d22418948673fc686f25f6be1c6e38165fa9821be8f8a2`.
Original `proof.json` SHA-256, unchanged during audit:
`033d7fa3c36cf85748482b2e55594eb22bc4a9fddd219310442961a38b6e6e26`.

Within the evidence root:

- `prepared/source/`: full upstream copy, advisor patch + NTK overlay;
  `prepared/preparation.json`, `patch-results.json`, `ntk-local-overlay.patch` record preparation.
- `dependencies.*.txt`, `cli-help.*.txt`, `cli-scan.*.txt`, `triage.*.txt`: actual command logs.
- `capture/opengrep.json`, `opengrep.sarif`, `scan-manifest.json`, `cli-origin.json`:
  captured outputs and receipts. JSON and SARIF are two engine invocations within
  one captured CLI session, with source/rule hashes checked across the session.
- `triage/input.opengrep.json`, `evidence.json`, `handoff-verification.json`: unchanged input and extracted evidence.

Local ignored audit output:
`v2/baseline/evidence/closeout-live-audit.json`, with stdout in
`closeout-live-audit.stdout.txt`. No original evidence was rewritten.

**`--scan-only` is an NTK overlay option, not an original upstream feature.**

## 2. Nguồn gốc tính năng và đóng góp

| Năng lực | Upstream có sẵn / hạn chế | Patch tham khảo của thầy | Phần NTK |
| --- | --- | --- | --- |
| Static scan và JSON/SARIF | [scanner.py](https://github.com/hardw00t/simple_semgrepAI/blob/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9/semgrepai/scanner.py#L15): gọi Semgrep, fallback --config=auto, hai subprocess JSON/SARIF | Binary OpenGrep cấu hình, local rules, timeout/jobs, dataflow-traces/taint-intrafile; Semgrep dependency thành optional | Scanner-only prototype đã có; đợt này giữ CLI Typer và scanner kế thừa, xác minh toàn cây ghim và instrument subprocess |
| Ba nhóm nhận định, giải thích, risk score, gợi ý sửa | [validator.py:64–119](https://github.com/hardw00t/simple_semgrepAI/blob/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9/semgrepai/validator.py#L64): Verdict, Justification, Risk Score 1–10, Recommended Fixes | Không phải ý tưởng mới do NTK tạo | NTK bổ sung grounding/hash/fail-safe; không nhận là tác giả của verdict/explanation/fix/risk-score có sẵn |
| Ollama | [providers.py:328](https://github.com/hardw00t/simple_semgrepAI/blob/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9/semgrepai/llm/providers.py#L328) đã có ChatOllama | YAML mặc định Ollama/Qwen | Client local và hợp đồng triage là phần NTK từ trước; không gọi model trong proof scan-only này |
| Review | [API findings:179](https://github.com/hardw00t/simple_semgrepAI/blob/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9/semgrepai/api/routes/findings.py#L179) đã cập nhật triage status; bulk triage tại 243 | ZIP độc lập có triage; không đồng nghĩa đã tích hợp toàn app | Queue CLI/SQLite, audit/reopen và kiểm tra phiên bản nguồn là NTK từ trước; giữ nguyên trong đợt này |
| Trace | Scanner gốc đọc top-level list; JSON thực tế có extra.dataflow_trace | Sửa extra; flatten CliLoc/CliCall | Giữ raw JSON/trace, kiểm chứng source lines/offset; không bỏ finding khi thiếu bằng chứng |
| Java context | [code_analyzer.py:379](https://github.com/hardw00t/simple_semgrepAI/blob/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9/semgrepai/analyzers/code_analyzer.py#L379) dùng Python AST; Java context cấu trúc chưa được chứng minh | ZIP có java_context.py riêng; patch bốn tệp không tự nối module đó vào app | Hiện có verified snippets/trace; không tuyên bố đã tích hợp tree-sitter/caller/callee của thầy |
| Tính liên tục | CLI gốc eager-import validator/RAG/config, có nhánh khởi tạo RAG | Patch sửa pyproject, YAML, config, scanner; giữ CLI gốc | Overlay scan-only; scan manifest nguồn/rules/exit; handoff Qwen qua raw JSON là các phần NTK; đợt này thêm CLI-origin hook, full-tree guard và proof runner |

Entry gốc `pyproject.toml` khai báo `semgrepai = semgrepai.cli:app`; package
`__main__.py` cũng gọi app đó. NTK không thay nó bằng CLI mới: sửa tối thiểu hàm
Typer `scan`, giữ lệnh gọi `scanner.scan(target_path, rules_path)` và scanner của
upstream đã được patch thầy. RAG/provider import được cô lập; lệnh ngoài phạm vi bị từ chối.

## 3. Diff và cách nhận diện đúng đường CLI

Patch thầy gồm **4 tệp**: pyproject.toml, semgrepai.yml, config.py, scanner.py.
Patch NTK scanner-only `opengrep.patch` là sản phẩm khác; PASS của nó không chứng minh
CLI upstream. Overlay mới sinh vào private `prepared/ntk-local-overlay.patch`.

Diff CLI rút gọn dưới đây phản ánh `overlay_cli(upstream cli.py)`; các context khác bỏ qua:

```diff
-from .validator import AIValidator
-from .reporter import HTMLReporter
-from .rag import RAGStore
-from .config import ConfigManager
+from .scan_recording import recording, record_cli_origin
@@ scan(...)
+    scan_only: bool = typer.Option(False, "--scan-only", ...)
+    if not scan_only or rules_path is None or not rules_path.is_file():
+        raise typer.BadParameter(...)
-        scanner = SemgrepScanner()
-        results = scanner.scan(target_path, rules_path)
+        with recording(target_path, rules_path, output_dir):
+            record_cli_origin(__file__, SemgrepScanner, "enter")
+            scanner = SemgrepScanner(config_path=str(config_path) if config_path else None)
+            results = scanner.scan(target_path, rules_path)
+            record_cli_origin(__file__, SemgrepScanner, "exit")
+        return  # before inherited RAG/validator branch
```

Không sửa dữ liệu để tạo dấu CLI. Hook chỉ chạy trong hàm CLI kế thừa, ghi main
module, argv, đường dẫn/hash của CLI và scanner, cùng danh sách import bị cấm.
Proof runner bắt buộc `main_module=semgrepai.__main__`, argv có scan/--scan-only,
stage=exit, code hash đúng cây đã chuẩn bị. Gọi scanner trực tiếp hoặc CLI thay thế
không có bằng chứng này sẽ bị từ chối. Hash toàn cây được kiểm tra lại sau chạy.

The LIVE NTK overlay (relative to the advisor-patched full source) has this
`git apply --stat` output; it excludes the private advisor patch itself:

```text
 semgrepai/cli.py            | 21 +++++++---
 semgrepai/scanner.py        | 11 +++--
 semgrepai/scanner_config.py | 19 +++++++++
 semgrepai/scan_recording.py | 89 +++++++++++++++++++++++++++++++++++++++++++
 semgrepai/scan_manifest.py  | 64 +++++++++++++++++++++++++++++++
 semgrepai/__init__.py       | 12 +++---
 6 files changed, 199 insertions(+), 17 deletions(-)
```

The four previously tracked NTK baseline files currently report via
`git diff --stat -- v2/baseline`: 136 insertions, 38 deletions. This excludes new
untracked delivery files listed in section 7; the staged stat must include them.
No whitespace changes were made to upstream snapshots or `opengrep.patch`.

## 4. Real findings and trace examples

Input: `v2/baseline/fixtures/java/{Vulnerable,Safe}.java` (synthetic examples).
Rules: `v2/baseline/rules/java.yml` (four local Java taint rules).
Both examples below are from the LIVE upstream CLI capture, not the older direct-scanner demo.
Coordinates are 1-based; end columns and byte offsets are exclusive.

| Rule suffix (display only) | Source in Vulnerable.java | Intermediate steps | Finding / sink |
| --- | --- | --- | --- |
| `ntk.java.cwe22` | 5:24-49, `req.getParameter("input")` | `input` 5:16-21; `forwarded` 6:16-25 | 7:9-28, `new File(forwarded)` |
| `ntk.java.cwe89` | 5:24-49, same source | Same trace variables | 10:9-80, `stmt.executeQuery("SELECT * FROM users WHERE name='" + forwarded + "'")` |

Full captured rule IDs (never shortened for joins):
- `C.Users.HP.OneDrive.Documents.NTK-Thesis-V2.codex.v2.baseline.rules.ntk.java.cwe22`
- `C.Users.HP.OneDrive.Documents.NTK-Thesis-V2.codex.v2.baseline.rules.ntk.java.cwe89`

`extra.dataflow_trace` is preserved in raw JSON and triage records. The read-only
audit re-extracts the locations and verifies source bytes, line/column and offsets.
Other captured rules are CWE-78/CWE-79. This small intrafile synthetic demo is not
validation on real projects, a complete rule set, or an accuracy measurement.
`Safe.java` has no finding in this capture; no claim of general absence of vulnerabilities.

## 5. Reproduction and JavisOS handoff

For READ-ONLY verification of the existing laptop run, from the NTK workspace:

```powershell
$Py = 'C:\Users\HP\NTK-M1-Runtime\venv\Scripts\python.exe'
$Proof = 'C:\Users\HP\NTK-M1-Runtime\proof-20261111-224908-bf784076'
& $Py v2/baseline/audit_original_cli.py $Proof
$auditExit = $LASTEXITCODE # expected 0 while all source/artifact paths remain available
```

The actual recorded scan command ran from `$Proof\prepared\source`, using the
worker above. This command is evidence of the inherited CLI route, not a request
to rerun into the occupied capture directory:

```powershell
$Repo = 'C:\Users\HP\OneDrive\Documents\NTK-Thesis-V2\codex'
& $Py -m semgrepai scan "$Repo\v2\baseline\fixtures\java" `
  --rules-path "$Repo\v2\baseline\rules\java.yml" `
  --config-path "$Proof\prepared\source\semgrepai.yml" `
  --output-dir "$Proof\capture" --scan-only
```

JavisOS: use a separate checkout of this proof branch, never mutate the integration
worktree. Run from the NTK checkout root; configure private paths and choose a
NEW output directory. Install OpenGrep separately and record its actual version
(1.20.0 verified on laptop; server 1.25 is not yet verified here).
No full application/RAG dependencies or Semgrep cloud installation are required.

```powershell
$Work = 'C:\private\ntk-m1-server'
$Advisor = 'C:\private\advisor-sources'
New-Item -ItemType Directory -Force $Work | Out-Null
# Clone once; reuse only an already verified clean pinned checkout.
git clone https://github.com/hardw00t/simple_semgrepAI.git "$Work\upstream"
git -C "$Work\upstream" checkout --detach 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9
py -3.12 -m venv "$Work\venv"
$Py = "$Work\venv\Scripts\python.exe"
& $Py -m pip install typer==0.17.5 rich==15.0.0 PyYAML==6.0.3
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$Proof = "$Work\proof-server-01" # must not exist
& $Py v2/baseline/prove_original_cli.py --upstream "$Work\upstream" `
  --advisor-dir $Advisor --output-dir $Proof --python $Py --timeout 180
$runnerExit = $LASTEXITCODE
if ($runnerExit -ne 0) { throw "Runner failed: $runnerExit; inspect proof.json/logs" }
& $Py v2/baseline/audit_original_cli.py $Proof
$auditExit = $LASTEXITCODE
if ($auditExit -ne 0) { throw "Evidence audit failed: $auditExit" }
```

WSL/Linux, from the separate NTK proof checkout, with all paths on that host:

```bash
WORK=/private/ntk-m1-server
ADVISOR=/private/advisor-sources
mkdir -p "$WORK"
git clone https://github.com/hardw00t/simple_semgrepAI.git "$WORK/upstream" &&
git -C "$WORK/upstream" checkout --detach 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9 &&
python3.12 -m venv "$WORK/venv" &&
"$WORK/venv/bin/python" -m pip install typer==0.17.5 rich==15.0.0 PyYAML==6.0.3 &&
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 "$WORK/venv/bin/python" v2/baseline/prove_original_cli.py \
  --upstream "$WORK/upstream" --advisor-dir "$ADVISOR" \
  --output-dir "$WORK/proof-server-01" --python "$WORK/venv/bin/python" --timeout 180 &&
"$WORK/venv/bin/python" v2/baseline/audit_original_cli.py "$WORK/proof-server-01"
```

Runner invokes the inherited `python -m semgrepai scan ... --scan-only` and then
`python -m v2.triage run --source-root <java> --json <capture/opengrep.json>
--scan-manifest <capture/scan-manifest.json> --output-dir <triage> --no-llm`.
It captures original engine exits; no manually declared `--engine-exit 0` is needed.
Do not put the scanner-only fork on PYTHONPATH. Keep raw paths unchanged; audit
requires original source/prepared paths to remain accessible. Cross-host evidence
relocation is not silently mapped; rerun on the server or supply the existing
explicit triage mapping workflow rather than rewriting raw JSON.

JavisOS must return host/version, runner/audit exit codes, `proof.json`, command
logs, preparation/patch/overlay hashes, capture and triage evidence, and the two
examples. Runtime PASS on laptop is established; server acceptance remains a
separate review. The runner intentionally retains its aggregate pending field.

## 6. Closeout changes, tests and historical blockers

No CLI rescan was performed in prompt 11.2. Small additional checks:

- `finding_identity.py`: compare JSON/SARIF rule IDs and primary file/start/end
  coordinates as a multiset, including duplicate multiplicity; allow URI encoding
  and drive-letter normalization without rewriting artifacts or inventing WSL mapping.
- `prove_original_cli.py`: reject failed dependency probes or absent dependency
  versions before help/scan; validate JSON/SARIF identity during capture inspection.
- `verify_handoff.py`: same identity checks, explicit exceptions instead of
  optimization-sensitive assertions; optional read-only verification.
- `audit_original_cli.py`: audit existing successful evidence without executing
  commands or altering it; missing/malformed evidence or hash mismatch returns 2.
- Regression fixtures cover wrong rules/locations, duplicate loss, missing logs,
  malformed proof, nonzero exits/timeouts, missing dependency/binary, changed source,
  changed raw output, wrong finding identity and trace/provenance. These are UNIT
  fixtures/mocks, distinct from the recorded LIVE laptop OpenGrep run.

Commands from workspace root (logs under ignored `v2/baseline/evidence/`):

| Command | Exit / result |
| --- | --- |
| `python v2/baseline/verify_patch.py` | 0; 6 original blobs, deterministic patch, check/apply reproduces 4 fork files |
| `python -m unittest discover -s v2/baseline/tests -v` | 0; 51 run: **50 PASS / 1 SKIP**, no failures |
| `python -m compileall -q v2/baseline/prepare_upstream_local.py v2/baseline/prove_original_cli.py v2/baseline/audit_original_cli.py v2/baseline/finding_identity.py v2/baseline/verify_handoff.py v2/baseline/upstream_local_support v2/baseline/fork v2/baseline/tests` | 0 |
| `python v2/baseline/audit_original_cli.py <existing-laptop-proof> --output v2/baseline/evidence/closeout-live-audit.json` | 0; read-only LIVE evidence audit, no rescan |
| `git -c safe.directory=<workspace> diff --check -- v2/baseline` | 0; no whitespace errors in tracked diff |

The optional live integration test is SKIP because a second scan was not requested;
this does not negate the recorded CLI PASS. Test logs: `closeout-tests.txt`,
`closeout-patch.txt`, `closeout-compile.txt`, `closeout-diff-check.txt`.

Historical, RESOLVED on laptop by the user: sandbox GitHub HTTPS clone failure,
missing Typer and dependency download failure. These older logs remain historical
and are no longer current laptop runtime blockers. The optional .ps1 launcher was
blocked by execution policy; direct Python execution succeeded without changing policy.
Qwen, full web/RAG, real-project generalization and independent labeled evaluation
are outside this proof. No claim of FULL UPSTREAM APPLICATION PASS is made.

## 7. Git delivery

**Not committed or pushed.** Final staging attempt on the required branch returned
exit **128**: permission denied creating
`integration/.git/worktrees/codex/index.lock`. Log:
`v2/baseline/evidence/closeout-git-add.txt`. No ACL, ownership, lock deletion,
reset, escalation or security setting changes were attempted. Changes remain local.
HEAD is still `940363f93aecaec5d2872a688addf974b31cccf7`, not a new delivery commit.
The owner must commit/push outside sandbox; the commands below target only the proof branch.

Pending files, all under `v2/baseline/`:

- Modified: README.md, prepare_upstream_local.py,
  upstream_local_support/scan_recording.py, verify_handoff.py.
- New: ADVISOR_M1_ORIGINAL_CLI_PROOF.md, pinned_upstream_tree.json,
  prove_original_cli.py, run_original_cli_proof.ps1, audit_original_cli.py,
  finding_identity.py, tests/test_original_cli_proof.py,
  tests/test_original_cli_audit.py, tests/test_finding_identity.py.

If metadata remains blocked, owner can review and commit in external PowerShell:

```powershell
$repoPath = (Get-Location).Path.Replace('\', '/')
if ((git -c "safe.directory=$repoPath" branch --show-current) -ne 'v2/advisor-m1-proof-20261111') { throw 'Wrong branch' }
git -c "safe.directory=$repoPath" diff --check
git -c "safe.directory=$repoPath" add -- v2/baseline
if ($LASTEXITCODE -ne 0) { throw 'Staging failed; do not commit' }
git -c "safe.directory=$repoPath" diff --cached --stat
# Review staged paths: no private ZIP, checkout, venv, runtime output or secrets.
git -c "safe.directory=$repoPath" commit -m "Prove original OpenGrep CLI and audit laptop runtime evidence"
if ($LASTEXITCODE -ne 0) { throw 'Commit failed; do not push' }
git -c "safe.directory=$repoPath" push -u origin v2/advisor-m1-proof-20261111
```
