# Nhiệm vụ gốc — tình trạng có bằng chứng

Nhánh `v2/codex-core`, nền `682a81815020e32852d969bdb27d6648fd568429`.
**Chưa chứng minh bản fork đầy đủ simple_semgrepAI chạy thành công.** Scanner/CLI
NTK quét thật và chuyển nguyên vẹn sang triage đã PASS; không đồng nhất hai kết quả.

Đã đối chiếu nguồn riêng trong `_advisor_sources`: PDF 21 trang (4–6, 9–10,
14–17), PDF 5 trang (1–3, 5), REQUIREMENTS_MATRIX, README/patch/findings/java_context/
triage của ZIP. Chỉ dùng làm nguồn đối chiếu/thử nghiệm; không đưa PDF/ZIP/patch thầy
hoặc toàn bộ mã riêng của thầy vào repository public. Nội dung kiểm tra riêng được
lưu dưới `evidence/` và Git-ignore. Gói ZIP được đọc là `opengrep-triage.zip`, không
phải gói `Bo_ma_OpenGrep_Java_Qwen.zip` khác được đề cập trong PDF 5 trang.

## Đối chiếu upstream / patch thầy / NTK

Upstream [hardw00t/simple_semgrepAI, 2c79a58](https://github.com/hardw00t/simple_semgrepAI/tree/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9),
`pyproject.toml` version 0.2.0, MIT. Sáu blob public trong `upstream/` vẫn nguyên vẹn;
ba entrypoint public bổ sung chỉ nằm trong snapshot thử nghiệm bị ignore, có blob SHA.

| Thành phần | Upstream gốc | Patch 4 tệp của thầy | NTK hiện có |
| --- | --- | --- | --- |
| Tệp sửa | Không vá | pyproject.toml, semgrepai.yml, config.py, scanner.py | scanner.py, config.py, cli.py; entrypoint/package riêng |
| Engine | Semgrep / auto | binary cấu hình, mặc định OpenGrep; Semgrep dependency chuyển optional | OpenGrep riêng; không cài Semgrep trong đường quét NTK |
| Luật | auto hoặc custom | local `../opengrep-rules/java`, hoặc --rules-path | local `rules/java.yml`, 4 luật demo |
| Cờ | JSON/SARIF hai lượt | --dataflow-traces, --taint-intrafile, timeout/jobs | --dataflow-traces, timeout/jobs, no-git-ignore, disable-version-check |
| Trace chuẩn hóa | Tìm top-level list | Đọc extra.dataflow_trace, làm phẳng CliLoc/CliCall | Giữ native raw trace; kiểm chứng CliLoc/intermediate; CliCall chưa hỗ trợ thì UNDETERMINED |
| CLI | Typer, eager import validator/RAG/reporter | CLI nguyên bản giữ nguyên | CLI standard-library scanner-only; kết nối triage riêng qua raw JSON |
| LLM | Có cloud-capable providers | YAML mặc định Ollama/qwen3.5:9b | Chỉ loopback Ollama; Qwen tag cấu hình, không cloud fallback |
| Java context | Đường cũ có Python AST và context dòng | Patch không tích hợp module Java-context của ZIP vào CLI gốc | Snippet/trace/hash kiểm chứng; chưa tương đương tree-sitter/caller/callee của ZIP |

Kế thừa public: lớp scanner, giao diện scan/envelope, helpers metadata/context/references.
NTK tự lập trình: runner an toàn/lưu bằng chứng, triage JSONL, citation/hash gates,
review SQLite/CLI, ánh xạ đường dẫn và demo kiểm chứng. ZIP thầy được so sánh, không
âm thầm thay thế các kiểm tra đã PASS. Không mở rộng CliCall/tree-sitter trong đợt này.

## Ba mức kết quả riêng biệt

| Thử nghiệm thực tế trên Windows/Python 3.13.3/OpenGrep 1.20.0 | Exit / kết quả |
| --- | --- |
| Git clone sạch từ GitHub | 128: không kết nối được github.com:443; **chưa có clone đầy đủ** |
| Patch thầy trên snapshot public ghim, Git index thử nghiệm riêng | git apply --check 0; git apply 0; git diff --stat: 4 files, 117 insertions, 32 deletions |
| CLI upstream thật sau patch: python -m semgrepai --help | 1: ModuleNotFoundError: No module named 'typer' |
| CLI upstream thật: python -m semgrepai scan ... | 1: cùng lỗi import; chưa tới scanner |
| Cài riêng typer vào thư mục thử nghiệm | 1: No matching distribution found for typer |
| Binary trực tiếp với cờ patch thầy, luật NTK local | JSON exit 0, SARIF exit 0; 4/4 findings, errors rỗng; **không phải scan thành công qua CLI gốc** |
| CLI scanner-only NTK chạy thật | Exit 0; 4 JSON findings, 4 SARIF results |
| NTK raw JSON → triage không model | Exit 0; 4 vào / 4 ra; raw bytes, rule ID và trace không mất/đổi |
| Queue demo real engine, review scripted | PASS: 1 → 0 → 1; stale confirm-false bị chặn; history giữ nguyên |

Giới hạn quan trọng: do clone bị chặn, kết quả patch tại laptop là trên **targeted
snapshot đã kiểm chứng blob**, không được ghi thành kiểm chứng trên full clean clone.
Snapshot có entrypoint/CLI nguyên bản; chưa phải toàn bộ dependencies/source của app.
CLI dừng tại dependency đầu tiên; không dùng mock/stub để giả app chạy. Môi trường
còn thiếu chromadb, và chưa chứng minh toàn bộ dependency graph có thể cài được.
Không có Qwen thật mới trong lượt này. Các thông tin server trong matrix là nguồn
đối chiếu từ đồng nghiệp, không phải runtime tự đo ở laptop.

## Lệnh Windows đã chạy và bằng chứng

Chạy từ workspace root; dùng output mới khi tái lập:

```powershell
python v2/baseline/advisor_probe.py --advisor-dir '..\_advisor_sources' --output-dir v2/baseline/evidence/advisor-new
python v2/baseline/verify_patch.py
$env:PYTHONPATH = Join-Path (Get-Location) 'v2/baseline/fork'
python -m semgrepai v2/baseline/fixtures/java --output-dir v2/baseline/evidence/scan-new
python -m v2.triage run --source-root v2/baseline/fixtures/java --json v2/baseline/evidence/scan-new/opengrep.json --engine-exit 0 --output-dir v2/triage/evidence/bridge-new --no-llm
python v2/baseline/verify_handoff.py --engine v2/baseline/evidence/scan-new --triage v2/triage/evidence/bridge-new
python -m v2.triage.demo_queue --output-dir v2/triage/evidence/queue-new
```

`advisor_probe.py` không cài dependency, không commit, không tạo cloud fallback.
Nó lưu từng argv/stdout/stderr/exit code và phân loại snapshot offline. Nếu không có
entrypoint cache private, cung cấp `--upstream <clean-full-clone>`; không giả cache là
clone. Bản clone phải sạch và HEAD đúng pin. Timeout CLI mặc định 45 giây, có thể đặt
`--cli-timeout 600` khi kiểm tra máy chủ.

Raw NTK thực tế: `evidence/original-task-ntk/opengrep.json`, `opengrep.sarif` và
version/command/stdout/stderr/exit files. Rule `v2.baseline.rules.ntk.java.cwe22` có
source `Vulnerable.java:5`, trung gian dòng 5–6, sink `new File(forwarded)` dòng 7.
CWE-89 có cùng source, sink `stmt.executeQuery(...)` dòng 10. Đây là mẫu tổng hợp,
Safe.java được quét không có finding; không suy ra precision/recall.

Bằng chứng bổ sung (ignored):

- `baseline/evidence/upstream-clone.txt`, `upstream-install.txt`: lỗi thật.
- `baseline/evidence/advisor-original/probe.json`, `patch-*.stdout/stderr.txt`,
  `original-cli-*.stderr.txt`, `flag-probe.json/.sarif`: patch/CLI/flag tách biệt.
- `triage/evidence/original-task-bridge/handoff-verification.json`: byte/ID/trace join.
- `triage/evidence/queue-original-task/queue-demo.json`: toàn bộ argv CLI, actor
  SCRIPTED-DEMO, count 1/0/1, hai event confirm-false/reopen và refusal không thêm event.
- `triage/evidence/wsl-availability.txt`: WSL không khởi chạy được (E_ACCESSDENIED).

## Queue và INT-01

`queue()` mặc định chỉ loại CONFIRMED_FALSE khỏi view; `queue(include_all=True)` và
CLI `queue --all` truy xuất tất cả. `show/history` vẫn thấy bản ghi đã ẩn; reopen
trả về OPEN và queue. Không DELETE row, không sửa event cũ; SUPPORTED/REFUTED không
tự thay human state. confirm-false vẫn bắt buộc SHA-256 của mọi file nguồn/trace.

Demo dùng ca SQL tổng hợp có allowlist đúng chuỗi `SELECT 1` trước sink. Luật demo
không mô hình hóa sanitizer này nên phát một cảnh báo thật từ engine, được gắn actor
**SCRIPTED-DEMO** để kiểm tra API duyệt; không phải nhãn người thật hoặc kết quả mô hình.
Không xác nhận một fixture lỗ hổng thật là giả để làm đẹp demo. Source được sửa là bản
tạm; nguồn gốc repository không đổi, sau refusal state OPEN và hai event giữ nguyên.

INT-01: `--path-map '/mnt/c/project=C:\project'` ánh xạ tường minh, ghi mapping vào
evidence; `raw_finding/raw_trace/input.opengrep.json` giữ nguyên. Mỗi snippet giữ
`raw_path` và local relative `path`, kiểm chứng hash/line/column/offset như trước.
Target ngoài root, traversal, prefix không khớp không được đoán hoặc tự sửa. Regression
WSL-path PASS trên fixture mô phỏng; **real WSL → Windows handoff còn chờ JavisOS**.
Không thêm CliCall/context mới hoặc làm yếu citation checks để vượt lỗi đường dẫn.

## Lệnh JavisOS cần chạy trên máy chủ

Ví dụ Bash; đặt `NTK` là repo/worktree của Javis và `ADVISOR` là nguồn riêng đã chuyển
an toàn lên máy chủ. Lệnh này là hướng dẫn chưa chạy tại laptop:

```bash
NTK=/path/to/ntk-worktree
ADVISOR=/private/advisor-sources
WORK=/private/ntk-original-experiment
mkdir -p "$WORK"
git clone https://github.com/hardw00t/simple_semgrepAI.git "$WORK/upstream"
git -C "$WORK/upstream" checkout --detach 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9
git -C "$WORK/upstream" status --short
cd "$NTK"
python v2/baseline/advisor_probe.py --advisor-dir "$ADVISOR" --upstream "$WORK/upstream" --output-dir v2/baseline/evidence/server-original --cli-timeout 600
# Probe copies the clean checkout and privately applies the ZIP patch; inspect patch logs first.
python -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install -e "$NTK/v2/baseline/evidence/server-original/source"
cd "$NTK/v2/baseline/evidence/server-original/source"
export SEMGREP_LOG_FILE="$PWD/engine.log"
export SEMGREP_SETTINGS_FILE="$PWD/engine-settings.yml"
# Inspect semgrepai.yml: provider=ollama, loopback URL, exact installed Qwen tag.
# Use no [semgrep] extra. Clear PYTHONPATH inherited from any scanner-only run.
unset PYTHONPATH
"$WORK/venv/bin/python" -m semgrepai --help
"$WORK/venv/bin/python" -m semgrepai scan "$NTK/v2/baseline/fixtures/java" --rules-path "$NTK/v2/baseline/rules/java.yml" --config-path "$PWD/semgrepai.yml" --output-dir "$PWD/cli-report"
# Original scanner writes raw reports/semgrep.json and reports/semgrep.sarif in cwd.
cd "$NTK"
"$WORK/venv/bin/python" -m v2.triage run --source-root "$NTK/v2/baseline/fixtures/java" --json "$NTK/v2/baseline/evidence/server-original/source/reports/semgrep.json" --engine-exit 0 --output-dir v2/triage/evidence/server-original-import --no-llm
```

Giữ exit code thật của CLI/engine: nếu khác 0, thay `--engine-exit 0` bằng mã lỗi và
không coi output một phần là scan đầy đủ. Việc tải Qwen/hạ tầng do Javis phụ trách;
ghi version OpenGrep/Ollama/model tag+digest, log JSON và thời gian thật. Cờ patch thầy
đã chạy được trên laptop 1.20; Javis vẫn cần kiểm chứng CLI app đầy đủ trên 1.25 của server.
Original CLI vẫn khởi tạo RAG/validator/reporter; cài dependency thành công hoặc có raw
JSON chưa đủ chứng minh toàn app hoàn tất. Lưu riêng kết quả help, scan và triage.

## Kiểm thử và Git delivery

- M1: 24/24 PASS; patch verification PASS.
- M2/M3: 59 chạy, 58 PASS, 1 SKIP (không có quyền tạo symlink trên Windows).
- Queue CLI/store regression và WSL-prefix mapping/escape/offset regression PASS.
- Mock LLM/HTTP chỉ dùng trong unit/integration test; real engine dùng cho các demo
  trên. Không có inference Qwen thật mới hoặc số liệu phân loại độc lập.
- Log: `baseline/evidence/original-task-tests.txt`, `triage/evidence/original-task-tests.txt`.
- Git delivery: **chưa commit/push**. `git add -- v2/baseline v2/triage` thất bại
  exit 128: không tạo được `integration/.git/worktrees/codex/index.lock` vì
  Permission denied. Không nâng quyền/thay ACL; HEAD vẫn là nền 682a818 ở đầu báo cáo.

Tệp mới cần commit: `baseline/ADVISOR_ORIGINAL_TASK_STATUS.md`, `advisor_probe.py`,
`verify_handoff.py`; `triage/demo_queue.py`, `tests/test_queue_paths.py`.
Tệp sửa: baseline `README.md`, `M1_REPORT.md`; triage `store.py`, `cli.py`,
`evidence.py`, `demo_freshness.py`, `tests/test_triage.py`, `README.md`,
`SCHEMA_CONTRACT.md`, `M2_M3_REPORT.md` (mọi đường dẫn đều dưới `v2/`).

Sau khi kiểm tra bằng PowerShell có quyền Git metadata, chỉ trên nhánh sở hữu:

```powershell
git branch --show-current  # phải là v2/codex-core
git add -- v2/baseline v2/triage
git diff --cached --stat
git commit -m "Align advisor review queue and preserve WSL evidence paths"
git push origin v2/codex-core
```

Các lệnh thủ công trên chạy ngoài sandbox bằng tài khoản chủ repository; nếu cần
ngoại lệ ownership, chỉ dùng `git -c "safe.directory=$repoPath"` cho workspace này.
Không force, không đưa thư mục evidence (đã ignore) hoặc nguồn riêng thầy vào commit.

Còn thiếu trước khi gọi hoàn thành nhiệm vụ gốc: clean clone + cài dependency +
full upstream CLI scan thành công trên máy chủ, kiểm tra lỗi tiếp theo của RAG/validator,
full raw handoff từ chính CLI đó, và báo cáo Java thực tế có bằng chứng model/nhãn
độc lập. Những việc này không được thay bằng kết quả scanner-only hay thông tin kể lại.
