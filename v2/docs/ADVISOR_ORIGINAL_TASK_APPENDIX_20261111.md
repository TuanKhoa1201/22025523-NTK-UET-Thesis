# Phụ lục Kỹ thuật Đầy đủ - Báo cáo Tiến độ Lần 1: Kết quả Thực hiện Nhiệm vụ Ban đầu (simple_semgrepAI -> OpenGrep + Local Qwen)

- **Dự án:** NTK Thesis V2 (`TuanKhoa1201/22025523-NTK-UET-Thesis`)
- **Link nhánh tích hợp trên GitHub:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/tree/v2/integration-pilot`
- **Commit tích hợp đã hợp nhất (`Codex` + `Antigravity` + `JavisOS`):** Hợp nhất `origin/v2/codex-core` (`c36bc120de2922413c53c26e42648b184ac3e5c7`) và `origin/v2/antigravity-review` (`f25ce45a812a94198f09db7b296a2caf52174ca3`) trên nền `f92d5f915c9dc9a34604efa29820e662fd7b616b` / `da26b87206fd0d7a5873e957dc1713cde03fe322`
- **Bảng đối chứng A/B chính thức:** `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.md` và `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.csv` (bản sao đồng bộ tại `v2/docs/ADVISOR_PAIRED_PILOT_20261111.md` và `.csv`)
- **Bản phụ lục tóm tắt (độ dài mục tiêu 2-3 trang Markdown & PDF):** `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.md` và `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.pdf`
- **Ngày lập báo cáo:** `2026-11-11` (`Asia/Bangkok`)
- **Phân định phạm vi kỹ thuật (5 nguyên tắc bắt buộc):**
  1. **Patch upstream (`v2/baseline/verify_patch.py`) & Scanner/CLI tinh gọn (`v2/baseline/fork/semgrepai/`) đã chạy thật (`PASS`)** trên cả Windows (qua cầu nối WSL2) và Linux/WSL2, khớp khứ hồi 4 tệp fork (`scanner.py`, `config.py`, `cli.py`, `scan_manifest.py`).
  2. **Toàn bộ ứng dụng `simple_semgrepAI` upstream đầy đủ** (giao diện web FastAPI/Uvicorn, cơ sở dữ liệu vector ChromaDB RAG, chuỗi LangChain gọi API đám mây) **chưa chạy thành công (`PENDING / NOT DONE`)** do xung đột phụ thuộc và nằm ngoài kiến trúc suy luận cục bộ có kiểm chứng trích dẫn.
  3. **`OpenGrep 1.25.0` và `Qwen3.5:9b-q4_K_M` đã chạy thật trên mã nguồn Java tổng hợp** (`SmokeVulnSample.java`, **SYNTHETIC SMOKE PILOT**, `n = 3`), được xác minh ở cả chế độ `REPLAY` lịch sử đã khóa (`scan_sha256: 005863f2...`) và chế độ `LIVE` mới có gắn `scan-manifest.json` (`scan_sha256: 4d628a21...`, `manifest_sha256: 77da8733...`).
  4. **Trạng thái xác thực runtime Ollama (`qwen3.5:9b-q4_K_M`):** **`OLLAMA_REPORTED_UNATTESTED` (`PENDING` đối với chứng thực phần cứng độc lập)** — Cờ `independently_verified_model_runtime = false` (`qwen_runtime_verified = false`) được giữ nguyên theo thiết kế vì phản hồi HTTP cục bộ không tự chứng thực phần cứng độc lập.
  5. **Chưa có kết quả benchmark độc lập** trên dự án Java thực tế hoặc bộ OWASP Benchmark (trạng thái: **NOT DONE**).

---

## A. Môi trường Thực nghiệm (Đã Xác minh Thực tế)

| Thành phần | Phiên bản / Cấu hình thực tế | Đường dẫn / Định danh kiểm chứng |
|---|---|---|
| **Hệ điều hành Host** | `Microsoft Windows 11 Pro` (`10.0.26200`), CPU `Intel Core i5-13400F` (16 luồng), RAM `63.82 GB` | Máy chủ thực nghiệm `ADMIN-PC` (`v2/docs/M0_M2_SERVER_ENV_REPORT.md`) |
| **Môi trường WSL2** | `Ubuntu-IRIS` (WSL2), `Python 3.10.22`, `OpenJDK 17.0.20.1` | Dùng để chạy binary Linux của OpenGrep |
| **Python (Windows)** | `Python 3.12.10` (máy chủ `ADMIN-PC`); `Python 3.13.3` (máy trạm phát triển M1) | `C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe` |
| **OpenGrep Engine** | `OpenGrep 1.25.0` (trên máy chủ WSL2); `OpenGrep 1.20.0` (trên máy trạm M1) | Binary WSL2: `/home/tuankhoa/.opengrep/cli/v1.25.0/opengrep` (`SHA-256: 9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33`). Cầu nối Windows: `C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.cmd` |
| **Ollama Runtime** | `Ollama 0.40.7` (Windows standalone CUDA `v13`) | `F:\ACTIVE-WORKSPACES\Tools\Ollama\v0.40.7\bin\ollama.exe`, `OLLAMA_HOST=127.0.0.1:11434`, `OLLAMA_NOPRUNE=true`, `OLLAMA_MODELS=F:\ACTIVE-WORKSPACES\Models\Ollama_Staging_20261023-124046-0d639a03` |
| **GPU phục vụ suy luận** | `NVIDIA GeForce RTX 4060 Ti 16 GB` (`16380 MiB` VRAM, Driver `591.86`, CUDA `13.1`) | Offload `100% GPU` xác nhận qua `ollama ps` và `nvidia-smi` |
| **Mô hình Qwen cục bộ** | 1. **`qwen3.5:9b-q4_K_M`** (mô hình chính)<br>2. **`qwen3:8b`** (mô hình smoke test ban đầu) | 1. Manifest SHA-256: `7dd7bb310c1f18ad132c7fd72e73d4f6cff2e916c596a818701d2a1269037c7f` (GGUF `5.63 GB` `02d45dc1...` + `mmproj` `921.7 MB` `f836f08f...`)<br>2. Digest: `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` |

---

## B. Nhiệm vụ Gốc: Upstream `simple_semgrepAI` và Đối chiếu Bản Vá (Diff)

### 1. Nguồn gốc Upstream và Vai trò Công cụ Gốc
- **Repository gốc:** `https://github.com/hardw00t/simple_semgrepAI`
- **Commit ghim cố định:** `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` (phiên bản `0.2.0`, giấy phép `MIT`, copyright 2025 hardw00t).
- **Vai trò ban đầu của `simple_semgrepAI`:** Công cụ gốc gọi `semgrep scan --config=auto` để quét mã nguồn, sau đó nạp kết quả vào chuỗi xử lý gồm LangChain (gọi API đám mây Anthropic/OpenAI/OpenRouter hoặc Ollama), cơ sở dữ liệu vector ChromaDB (RAG), giao diện web FastAPI/Uvicorn và bộ sinh báo cáo HTML. Bản gốc đọc nhầm đường dẫn vết dữ liệu tại `result['dataflow_trace']` ở top-level thay vì `result['extra']['dataflow_trace']`, nên luôn làm rỗng thông tin truy vết dòng dữ liệu (`dataflow_trace`).
- **Bản chụp nguyên bản (Snapshot Provenance):** 6 tệp upstream gốc được bảo toàn nguyên vẹn từng byte (bằng thuộc tính `-text` trong `v2/baseline/.gitattributes`) và kiểm chứng Git blob SHA-1 tại `v2/baseline/upstream/PROVENANCE.json`:
  - `LICENSE` (`0d6c6874fbcd9b3af4e566714be96ee9f8f42886`)
  - `semgrepai/scanner.py` (`e1945da5f6e96f14b0028933ef994b6cbb4f1241`)
  - `semgrepai/config.py` (`b3433b07d1e41ee8bab21b233c80fe35d5dd485d`)
  - `semgrepai/cli.py` (`b0f3ab7daacedcf85211393a635b52cf462fafe2`)
  - `pyproject.toml` (`a997a9fd53c3714fe4c50ab4844f60c086240e7f`)
  - `semgrepai.yml` (`1fdf83173e837a442b2f5c8695ea05203ecb9476`)

### 2. Các phần Kế thừa, Sửa đổi và Bổ sung trong Nhánh Đồ án (`v2/baseline/fork/`)
- **Kế thừa:** Giao diện lớp `SemgrepScanner.scan()`, cấu trúc đầu ra JSON/SARIF, các phương thức trích xuất ngữ cảnh mã nguồn (`_extract_code`), siêu dữ liệu và tài liệu tham chiếu (`_extract_references`, `_extract_security_patterns`).
- **Sửa đổi (`v2/baseline/opengrep.patch`, khớp khứ hồi 4 tệp fork):**
  1. `semgrepai/scanner.py`: Đổi binary mặc định từ `semgrep` sang `opengrep`; bỏ `--config=auto` để bắt buộc nhận file luật YAML cục bộ; bổ sung các cờ `--dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60`; cô lập biến môi trường log/settings về thư mục đầu ra; lưu vết thực thi (`*.command.json`, `*.stdout.txt`, `*.stderr.txt`, `*.exit.txt`) và `scan-manifest.json` (`ScanCapture`); đọc và bảo toàn nguyên trạng cấu trúc `extra.dataflow_trace` (`taint_source`, `intermediate_vars`, `taint_sink`); gán trạng thái mặc định `REVIEW` cho mọi cảnh báo.
  2. `semgrepai/config.py`: Thay cấu hình phụ thuộc `pydantic`/cloud bằng `OpenGrepConfig` dùng thư viện chuẩn Python.
  3. `semgrepai/cli.py`: Chuyển thành CLI quét cục bộ thuần túy (`python -m semgrepai`), tách khỏi ngăn xếp web/RAG/cloud LLM của upstream.
  4. `semgrepai/scan_manifest.py`: Ghi nhận và xác thực biên lai quét `scan-manifest.json` (`schema = "ntk-scan-capture-1"`) ràng buộc SHA-256 nguồn trước/sau khi quét, SHA-256 bộ luật, mã thoát engine và các tệp đầu ra.
- **Bổ sung mới ngoài upstream:** Bộ luật taint Java cục bộ (`v2/baseline/rules/java.yml`, `v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml`), mô-đun kiểm chứng bằng chứng, biên lai quét (`scan_receipt.py`, `live_check.py`, `export_pilot.py`) và hàng đợi kiểm duyệt SQLite (`v2/triage/`), cùng bộ công cụ chấm điểm đối chứng (`v2/evaluation/`).

### 3. Đối chiếu giữa Patch NTK (`v2/baseline/opengrep.patch`) và Patch trong Gói Tham khảo của Giảng viên (`opengrep-triage.zip`)
Gói tham khảo `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\opengrep-triage.zip` (`SHA-256: 5f39d2fb84bbc50e63b0b2b0c4618f84d7878bab1458cc99377223ee9c31b1cd`) đã được giải nén và kiểm thử trong môi trường cô lập ngoài Git worktree tại `C:\Users\Admin\ntk-thesis-v2\evidence\p0_1_advisor_zip_isolated` (lưu ý: tệp `Bo_ma_OpenGrep_Java_Qwen.zip` được nhắc trong PDF 5 trang không có trong thư mục nguồn - **NOT PROVIDED**):

| Tiêu chí đối chiếu | Patch NTK (`v2/baseline/opengrep.patch`) | Patch Giảng viên (`patches/simple_semgrepAI_opengrep.patch`) |
|---|---|---|
| **Số tệp trong bản vá** | **4 tệp fork:** `semgrepai/scanner.py`, `semgrepai/config.py`, `semgrepai/cli.py`, `semgrepai/scan_manifest.py` | **4 tệp upstream:** `pyproject.toml`, `semgrepai.yml`, `semgrepai/config.py`, `semgrepai/scanner.py` |
| **Quản lý phụ thuộc** | Tách hẳn sang thư viện chuẩn Python cho phần scanner/CLI để không cần cài `semgrep`, `langchain`, `chromadb`. | Giữ cấu trúc `pyproject.toml` gốc của upstream (còn `langchain`, `chromadb`, `fastapi`), chỉ chuyển `semgrep>=1.100.0` sang optional extra `[semgrep]`. |
| **Tham số dòng lệnh OpenGrep** | `--config <rules> --json/--sarif --dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60` | `--timeout <t> --jobs <j> --dataflow-traces --taint-intrafile --config <rules>` |
| **Xử lý `extra.dataflow_trace` & Provenance** | Giữ nguyên cấu trúc ATD gốc của OpenGrep (`CliLoc`, `intermediate_vars`) và sinh `scan-manifest.json` (`ntk-scan-capture-1`) để `v2/triage` kiểm chứng dòng, cột, byte offset và SHA-256. | Làm phẳng (`flatten`) cây `CliLoc`/`CliCall` thành danh sách bước tuần tự `[{type, path, line, content}]`. |
| **Kết quả kiểm chứng thực tế** | `python v2/baseline/verify_patch.py` đạt **PASS** (`git apply --check` và `git apply` khứ hồi khớp 100% với 4 tệp trong `v2/baseline/fork`). | `git apply --check` trên 4 blob upstream gốc đạt **PASS**; bộ unit test cô lập của gói thầy đạt **15/15 PASS (`0.37s`)** (`evidence/p0_1_advisor_zip_isolated/pytest_15_results.txt`). |

---

## C. Lệnh Tái lập Thực tế trên Máy chủ Windows PowerShell

### 1. Nhóm lệnh kiểm chứng tức thời trên bằng chứng đã lưu (`REPLAY`, `exit_code = 0`, không gọi lại Qwen, không ghi đè file Git)

Chạy từ PowerShell trên máy chủ `ADMIN-PC`:

```powershell
Set-Location "C:\Users\Admin\ntk-thesis-v2\integration-pilot"
$env:PATH = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0;$env:PATH"

# 1. Kiểm chứng chính sách kho mã, patch upstream (4 fork files), toàn bộ 162 Unit Tests và 11 cổng tích hợp -> exit_code = 0
python scripts/verify-repository.py
python v2/baseline/verify_patch.py
python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q
python v2/scripts/run_v2_quality_gate.py

# 2. Chạy tái lập toàn trình ở chế độ REPLAY sang thư mục mới ngoài Git -> exit_code = 0
$ReplayDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_replay_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "v2\demo\reproduce_integration_pilot.ps1" `
  -Mode REPLAY `
  -EvidenceRoot $ReplayDir
```

### 2. Nhóm lệnh quét mới OpenGrep 1.25.0 + `scan-manifest.json` và chạy `v2.triage run` ở chế độ `LIVE`

Lưu ý quan trọng về chính sách Fail-Closed của CLI sau khi hợp nhất `c36bc12`:
- `python -m semgrepai` và `python -m v2.triage run` đều bắt buộc `--output-dir` **phải là thư mục mới chưa tồn tại** (`output.mkdir(parents=True, exist_ok=False)`).
- Khi gọi `python -m v2.triage run --json <raw.json> --engine-exit 0` **mà không truyền `--scan-manifest`**, công cụ sẽ đánh dấu `scan_provenance.origin = "declared_only"`, `source_capture_verified = false`, đưa các cảnh báo về `UNDETERMINED` và trả về **`exit_code = 2`** (fail-closed) để ngăn việc tự nâng cấp một tệp JSON rời thành bằng chứng quét đã xác minh.
- Để đạt `exit_code = 0` và `source_capture_verified = true`, bắt buộc quét qua `python -m semgrepai` (sinh `scan-manifest.json`) rồi truyền `--scan-manifest` sang `v2.triage run`, hoặc chạy `reproduce_integration_pilot.ps1 -Mode LIVE`:

```powershell
# 3. Chạy tái lập toàn trình ở chế độ LIVE (quét mới OpenGrep 1.25.0 + scan-manifest.json + gọi thật Ollama Qwen3.5:9b-q4_K_M) -> exit_code = 0
$LiveDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "v2\demo\reproduce_integration_pilot.ps1" `
  -Mode LIVE `
  -SkipHeavyDemos `
  -EvidenceRoot $LiveDir

# 4. Hoặc chạy từng bước thủ công (quét tạo scan-manifest.json -> v2.triage run có --scan-manifest -> export_pilot):
$StepDir = "C:\Users\Admin\ntk-thesis-v2\evidence\manual_live_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$env:PYTHONPATH = "v2/baseline/fork"
python -m semgrepai "v2\evaluation\smoke_evidence" `
  --rules-path "v2/baseline/rules/java.yml" `
  --output-dir "$StepDir\live_scan"
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

python -m v2.triage run `
  --source-root "v2\evaluation\smoke_evidence" `
  --json "$StepDir\live_scan\opengrep.json" `
  --scan-manifest "$StepDir\live_scan\scan-manifest.json" `
  --engine-exit 0 `
  --output-dir "$StepDir\triage_live" `
  --model qwen3.5:9b-q4_K_M `
  --endpoint http://127.0.0.1:11434 `
  --timeout 180

python -m v2.triage.export_pilot `
  "$StepDir\triage_live\assessments.jsonl" `
  --raw-json "$StepDir\live_scan\opengrep.json" `
  --output-dir "$StepDir\export_pilot"
```

---

## D. Kết quả Quét OpenGrep 1.25.0, Phân tích Qwen3.5-9B và Bảng Đối chứng Sơ bộ

### 1. Tổng hợp Số lượng Cảnh báo OpenGrep theo Bộ Luật và Đầu vào
- **Đầu vào chính:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (`SHA-256: 090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9`, kích thước `2,131 bytes`, gồm 4 phương thức: 2 phương thức có lỗ hổng `unsafeSqlLookup`, `unsafeFileRead` và 2 phương thức đối chứng an toàn `safeSqlLookup`, `safeFileRead`).
  1. **Quét với bộ luật M1 `v2/baseline/rules/java.yml` (`SHA-256: f34e7b51880cc5baf4ff3cda47a16232c8d405b8fd5e65aaed1aa3745367d5aa`):** Xuất **3 cảnh báo** (`2 TP` tại dòng 28 `CWE-89`, dòng 33 `CWE-22`; `1 FP` tại dòng 47 `CWE-22` ở `safeFileRead` do luật M1 chưa khai báo `FilenameUtils.getName` là sanitizer).
     - Bản quét lịch sử đã khóa (`REPLAY`): `v2/demo/smoke_m1_rules_raw.opengrep.json` (`scan_sha256: 005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`).
     - Bản quét `LIVE` mới có gắn `scan-manifest.json`: `evidence/repro_live_verified_20261111_c36_f25/live_scan/opengrep.json` (`scan_sha256: 4d628a214c737a99931ac51cce7f260bf3843b4f3610b3a5eb5a278bc919cfb9`, `manifest_sha256: 77da87339e1c087879fb177c09b0a7fe00ec8e16ac77e5f145f94cd597d498d2`).
  2. **Quét với bộ luật có khai báo sanitizer `v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml` (`SHA-256: 087f313ccbff779dcc9029380fed024bc0b8ff85a22a4c436cd69c18855decd2`):** Xuất **2 cảnh báo** (`CWE-89` dòng 28 và `CWE-22` dòng 34), `0` báo động giả (`evidence/qwen35_real_20261111_135144/input.opengrep.json`, `SHA-256: d5f3b0ce59601fc38039e249d03308b1182a5f5c41c0382bf5875110e1c9b37f`).
- **Đầu vào fixture cơ sở M1 (`v2/baseline/fixtures/java/Vulnerable.java` + `Safe.java`):** Xuất **4 cảnh báo** trên `Vulnerable.java` (`CWE-22` dòng 7, `CWE-78` dòng 8, `CWE-79` dòng 9, `CWE-89` dòng 10) và **0 cảnh báo** trên `Safe.java`.

### 2. Ba Ví dụ Đầu ra Thực tế trên Cùng Phép Quét M1 (`n = 3`, `qwen3.5:9b-q4_K_M`)
Nguồn bằng chứng `REPLAY` đã khóa: `v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl` (`SHA-256: dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5`); nguồn bằng chứng `LIVE` mới có `scan-manifest.json`: `C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25\triage_live_qwen35\assessments.jsonl` (`SHA-256: 939f0949d270a002b65b279510f830a63b065fa2286da1a6db37442e1e517d84`).

1. **Finding #0 - `CWE-89` tại `unsafeSqlLookup` (Nhãn fixture: `SYNTHETIC TP`):**
   - **Alert ID:** `5c3fa49a9a739ca38e3711e51b676c5c9894a523a8ef1e5f276a3b7d033672b0` (`REPLAY`) / `35a3a20e7d67e76496be38e146cc3ea6812d3bb932c8b9a73f8061a0547dd342` (`LIVE`) (`rule_id: v2.baseline.rules.ntk.java.cwe89`)
   - **Dataflow Trace:** Source dòng `25:28..25:60` (`request.getParameter("username")`) -> Intermediate `userInput` (dòng `25:16..25:25`), `query` (dòng `26:16..26:21`) -> Sink dòng `28:16..28:40` (`stmt.executeQuery(query)`).
   - **Kết quả `qwen3.5:9b-q4_K_M`:** `status = SUPPORTED`, `citation_check = MATCHED` (trích dẫn nguyên văn dòng `25-28`, khớp `sha256: 090c9349...`), `state = OPEN`, `requires_human_review = true`, `elapsed_seconds = 19.719s` (`REPLAY`, `eval_count = 334`) / `8.063s` (`LIVE`, `eval_count = 347`).
   - **Nhận định của mô hình:** Xác định đúng lỗi nối chuỗi trực tiếp `userInput` vào câu lệnh SQL truyền cho `stmt.executeQuery()` và đề xuất dùng `PreparedStatement` với tham số `?`.
2. **Finding #1 - `CWE-22` tại `unsafeFileRead` (Nhãn fixture: `SYNTHETIC TP`):**
   - **Alert ID:** `76501a37112c42a9d4e46cf1fadeb1794aa417284ce0ce4d415a6986f5a773e9` (`REPLAY`) / `651f41b05f5548ba17d0f1b5236ffd457bf0386a7602459644c378c4486fe43d` (`LIVE`) (`rule_id: v2.baseline.rules.ntk.java.cwe22`)
   - **Dataflow Trace:** Source dòng `32:32..32:62` (`request.getParameter("report")`) -> Intermediate `rawReportName` (dòng `32:16..32:29`) -> Sink dòng `33:27..33:72` (`new File("/var/app/reports/" + rawReportName)`).
   - **Kết quả `qwen3.5:9b-q4_K_M`:** `status = SUPPORTED`, `citation_check = MATCHED` (trích dẫn nguyên văn dòng `32` và `33`, khớp `sha256: 090c9349...`), `state = OPEN`, `requires_human_review = true`, `elapsed_seconds = 10.953s` (`REPLAY`, `eval_count = 458`) / `10.406s` (`LIVE`, `eval_count = 441`).
   - **Nhận định của mô hình:** Chỉ rõ tham số `report` đi thẳng vào `new File(...)` không qua chuẩn hóa đường dẫn, cho phép tấn công `../../../etc/passwd`.
3. **Finding #2 - `CWE-22` Cảnh báo giả tại `safeFileRead` dòng 47 (Nhãn fixture: `SYNTHETIC FP`):**
   - **Alert ID:** `3252602faf5bdb45ef2a393cdf9d72350514515468d9b170d1083410e7716249` (`REPLAY`) / `0dbe51f18de76dd409a7148793dd69030bd887e08c460b0ddd638b42e4c7291f` (`LIVE`) (`rule_id: v2.baseline.rules.ntk.java.cwe22`)
   - **Dataflow Trace:** Source dòng `45:32..45:62` (`request.getParameter("report")`) -> Intermediate `rawReportName` (dòng `45:16..45:29`) -> `cleanName` (dòng `46:16..46:25`, `FilenameUtils.getName(rawReportName)`) -> Sink dòng `47:27..47:68` (`new File("/var/app/reports/" + cleanName)`).
   - **Kết quả `qwen3.5:9b-q4_K_M`:** `status = SUPPORTED` (**nhận định chưa đạt: xếp FP thành TP**), `citation_check = MATCHED` (trích dẫn nguyên văn dòng `45-47`, khớp `sha256: 090c9349...`), `state = OPEN`, `requires_human_review = true`, `elapsed_seconds = 10.078s` (`REPLAY`, `eval_count = 409`) / `9.969s` (`LIVE`, `eval_count = 412`).
   - **Phân tích nguyên nhân mô hình không đề xuất loại FP dòng 47:** Trong trường `explanation`, `qwen3.5:9b-q4_K_M` nhận diện có lệnh `FilenameUtils.getName(rawReportName)` ở dòng 46 và nêu đúng tác dụng loại bỏ chuỗi `../`, nhưng lập luận quá bảo thủ rằng hàm này chưa kiểm tra danh sách trắng (whitelist) tên tệp hợp lệ nên vẫn giữ kết luận `SUPPORTED`.

### 3. Bảng Đối chứng Sơ bộ A/B trên Cùng Phép Quét (`SYNTHETIC SMOKE PILOT`, `n = 3`)

| Chỉ số đối chứng | Nhánh A: OpenGrep 1.25.0 đơn lẻ | Nhánh B (`REPLAY` lịch sử đã khóa `005863f2...`) | Nhánh B (`LIVE` có `scan-manifest.json` `4d628a21...`) |
|---|---|---|---|
| **Tổng số cảnh báo đầu vào** | `3` (`1 CWE-89`, `2 CWE-22`) | `3` (`1 CWE-89`, `2 CWE-22`) | `3` (`1 CWE-89`, `2 CWE-22`) |
| **Nhãn thiết kế của fixture (`SYNTHETIC`)** | `2 TP` (dòng 28, 33), `1 FP` (dòng 47) | `2 TP` (dòng 28, 33), `1 FP` (dòng 47) | `2 TP` (dòng 28, 33), `1 FP` (dòng 47) |
| **Trạng thái `scan_provenance`** | `N/A` | `HISTORICAL_UNBUNDLED` (`REVIEW` khi bật `--require-scan-provenance`) | **`VERIFIED_CAPTURE` (`source_capture_verified = true`)** |
| **Trạng thái mô hình & Kiểm chứng trích dẫn** | Không áp dụng | `3/3 SUPPORTED`, `3/3 citation_check = MATCHED` | `3/3 SUPPORTED`, `3/3 citation_check = MATCHED` |
| **FP được đề xuất loại đúng (`Proposed FP Removal`)** | `0/1 (0.0%)` | **`0/1 (0.0%)`** (mô hình xếp FP dòng 47 là `SUPPORTED`) | **`0/1 (0.0%)`** (mô hình xếp FP dòng 47 là `SUPPORTED`) |
| **TP bị đề xuất loại nhầm (`Erroneously Proposed TP Removal`)** | `0/2 (0.0%)` | **`0/2 (0.0%)`** (`2/2 KEEP_TP`) | **`0/2 (0.0%)`** (`2/2 KEEP_TP`) |
| **Số cảnh báo ở trạng thái `REVIEW` / `UNDETERMINED`** | `3/3` (chưa phân loại) | `0/3 (0.0%)` ở chế độ lịch sử (`3/3` ở strict receipt gate) | `0/3 (0.0%)` ở lượt live (`3/3` khi tắt kết nối Ollama) |
| **Số cảnh báo tự động bị loại bỏ (`Auto-dismissed`)** | `0` | **`0/3`** (100% giữ `state = OPEN`, bắt buộc người duyệt) | **`0/3`** (100% giữ `state = OPEN`, bắt buộc người duyệt) |
| **Độ trễ suy luận trung bình (`elapsed_seconds`)** | Không áp dụng | **`13.583 giây/cảnh báo`** (tổng `40.750s`, có cold-load) | **`9.479 giây/cảnh báo`** (tổng `28.438s`, warm GPU) |

---

## E. Kết quả Kiểm thử Phần mềm & Trạng thái Demo Kiểm duyệt (Sau Merge Cuối cùng)

### 1. Kết quả Kiểm thử Tự động (Sau khi merge `v2/codex-core` `c36bc12` và `v2/antigravity-review` `f25ce45`)

| Bộ kiểm thử | Lệnh thực thi | Kết quả xác minh (`PASS` / `FAIL` / `SKIP`) |
|---|---|---|
| **Repository Policy Gate** | `python scripts/verify-repository.py` | **`PASS` (`19` tệp bắt buộc, `99` module Python, `16` JSON, `3` JSONL)** |
| **M1 Scanner & Provenance Tests** | `python -m pytest v2/baseline/tests -v` | **`27 passed`, `14 subtests passed`, `0 failed`, `0 skipped` (`0.34s`)** |
| **M2/M3 Triage & Review Queue Tests** | `python -m pytest v2/triage/tests -v` | **`70 passed`, `12 subtests passed`, `0 failed`, `0 skipped` (`4.00s`)** |
| **M4/M5 Evaluation & Adapter Tests** | `python -m pytest v2/evaluation/tests -v` | **`28 passed`, `0 failed`, `0 skipped` (`0.07s`)** |
| **Quality Gate & Fail-Closed Tests** | `python -m pytest v2/demo/tests -v` | **`37 passed`, `0 failed`, `0 skipped` (`7.35s`)** |
| **Tổng hợp Unit Tests V2** | `python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q` | **`162 passed` (`26 subtests passed`), `0 failed`, `0 skipped`** |
| **Cổng Kiểm định Tích hợp V2** | `python v2/scripts/run_v2_quality_gate.py` | **`PASS` (`11/11` bước kiểm định đạt, `exit_code = 0`)** |
| **Kiểm chứng khứ hồi `opengrep.patch`** | `python v2/baseline/verify_patch.py` | **`PASS` (`exit_code = 0`, 6 upstream blobs, 4 fork files)** |
| **Kiểm chứng handoff `OpenGrep -> v2.triage`** | `python v2/baseline/verify_handoff.py --engine ... --triage ...` | **`PASS` (`exit_code = 0`, `raw_json_bytes_unchanged = true`)** |

### 2. Trạng thái Từng Bước của Demo Quy trình Kiểm duyệt Liên hoàn (`demo_queue.py`, `demo_freshness.py` & CLI 7 Bước)
Đối chiếu kết quả chạy thực tế sau merge trong `C:\Users\Admin\ntk-thesis-v2\evidence\repro_replay_20261111_c36_f25\queue_demo\queue-demo.json`, `freshness_demo\freshness-demo.json` và `evidence\p0_final_integration_20261111\smoke_m1_cli_workflow\`:

| Bước kiểm duyệt theo yêu cầu | Trạng thái | Bằng chứng thực tế đã xác minh (`exit_code` & output) |
|---|---|---|
| **1. `confirm-false` trên cảnh báo giả với actor `SCRIPTED-DEMO`** | **HOÀN THÀNH (`PASS`, `exit_code = 0`)** | `python -m v2.triage decide --db $Db $Id confirm-false --actor SCRIPTED-DEMO --reason ...` chuyển trạng thái cảnh báo sang `CONFIRMED_FALSE` (`queue-demo.json` và `smoke_m1_cli_workflow/04_confirm_false.json`). |
| **2. Ẩn cảnh báo `CONFIRMED_FALSE` khỏi hàng đợi `queue` mặc định** | **HOÀN THÀNH (`PASS`, `exit_code = 0`)** | Sau `confirm-false`, lệnh `python -m v2.triage queue --db $Db` giảm số cảnh báo từ `1 -> 0` (trong `demo_queue.py`) và từ `3 -> 2` (trong `smoke_m1_cli_workflow/05_queue_default_after_hide.json`). |
| **3. Truy vấn `queue --all`, `show` và `history`** | **HOÀN THÀNH (`PASS`, `exit_code = 0`)** | `python -m v2.triage queue --db $Db --all` vẫn trả đủ bản ghi (`1` trong `demo_queue.py`, `3` trong `06_queue_all_after_hide.json`); `show` hiển thị `state = "CONFIRMED_FALSE"`; `history` ghi nhận `sequence = 1`, `actor = "SCRIPTED-DEMO"`, `action = "confirm-false"`, kèm `source_version` và `evidence_sha256`. |
| **4. Mở lại (`reopen`) và xuất hiện lại trong `queue` mặc định** | **HOÀN THÀNH (`PASS`, `exit_code = 0`)** | `python -m v2.triage decide --db $Db $Id reopen --actor SCRIPTED-DEMO --reason ...` đưa trạng thái về `OPEN`; lệnh `queue` mặc định khôi phục `0 -> 1` (`demo_queue.py`) và `2 -> 3` (`10_queue_after_reopen.json`); `history` ghi nhận `sequence = 2` (`action = "reopen"`). |
| **5. Chặn xác nhận khi SHA-256 mã nguồn thay đổi sau khi quét** | **HOÀN THÀNH (`PASS`, `exit_code = 2`)** | Khi sửa đổi bản sao tệp Java sau lượt quét (`AllowlistedQuery.java`: `aec52e68... -> b0c9daba...`; `SmokeVulnSample.java`: `090c9349... -> 10219f10...`), lệnh `decide ... confirm-false` bị từ chối với `exit_code = 2`: `UNDETERMINED / operation refused: source unavailable/changed; rescan required: source hash mismatch; rescan required`. Lịch sử `history` giữ nguyên `2` sự kiện, không phát sinh bản ghi mới. |

---

## F. Hạn chế và Khó khăn Kỹ thuật Còn Tồn tại

1. **Toàn bộ ứng dụng `simple_semgrepAI` upstream chưa chạy thành công (`PENDING / NOT DONE`, chỉ tách riêng Scanner/CLI):** `v2/baseline/fork/semgrepai/` chỉ trích xuất và chuyển đổi thành phần scanner/config/CLI sang OpenGrep bằng thư viện chuẩn Python (đã chạy thật). Toàn bộ phần ứng dụng web FastAPI, cơ sở dữ liệu vector ChromaDB (RAG) và LangChain gọi API đám mây của `simple_semgrepAI` gốc chưa được chạy thành công do xung đột phụ thuộc và không phù hợp với mục tiêu suy luận cục bộ có kiểm chứng trích dẫn của đồ án.
2. **Khác biệt đường dẫn Windows/WSL2 và chính sách Smart App Control:** Trên Windows 11 (`ADMIN-PC`), bản thực thi rời `opengrep_windows_x86.exe` (`v1.25.0`) bị Smart App Control chặn tiến trình con (`Error 4551`), phải chạy qua `/usr/local/bin/opengrep` trong WSL2 `Ubuntu-IRIS` kết hợp cầu nối `opengrep.cmd` và cờ `--path-map`.
3. **Vấn đề chuẩn hóa xuống dòng CRLF trên Windows và cơ chế bảo toàn byte bằng `-text`:** Cấu hình `core.autocrlf=true` của Git trên Windows được xử lý trong `v2/baseline/.gitattributes` bằng cách đặt **`upstream/** -text` và `opengrep.patch -text`** để bảo toàn nguyên vẹn từng byte của 6 tệp upstream cùng file patch; trong khi các tệp mã nguồn Python của bản fork (`fork/semgrepai/*.py`, `make_patch.py`, `verify_patch.py`) dùng `text eol=lf`. Nhờ đó bộ kiểm thử M1 đạt `27/27 PASS`.
4. **Kết quả chưa đạt của `qwen3.5:9b-q4_K_M` trước cảnh báo giả có sanitizer (`FilenameUtils.getName` tại dòng 47):** Dù trích dẫn đúng dòng 45-47 (`citation_check = MATCHED`), mô hình vẫn đánh giá cảnh báo giả ở dòng 47 là `SUPPORTED` (`0/1` FP được đề xuất loại) vì yêu cầu kiểm tra thêm whitelist ký tự thay vì tin tưởng hoàn toàn vào `FilenameUtils.getName`.
5. **Trạng thái `.github/workflows/v2-quality-gate.yml` (`BLOCKED` bởi quyền OAuth `workflow`):** Token GitHub trong keyring máy chủ hiện chỉ có scope `gist, read:org, repo` (thiếu `workflow`), nên chưa thể push trực tiếp vào `.github/workflows/`. Cổng kiểm định 11 bước được lưu tại `v2/workflows/v2-quality-gate.yml` + `v2/scripts/run_v2_quality_gate.py` và chạy tự động qua Git `pre-push` hook trên worktree tích hợp.
6. **Chưa có kết quả thực nghiệm trên dự án Java thực tế và OWASP Benchmark độc lập (`NOT DONE`):** Toàn bộ kết quả hiện tại giới hạn ở các tệp Java mẫu tổng hợp (`SmokeVulnSample.java`, `Vulnerable.java`, `Safe.java`). Việc quét một dự án Java mã nguồn mở thực tế (P0.4) và đánh giá định lượng trên tập 30-60 cảnh báo có nhãn độc lập / OWASP Benchmark vẫn chưa thực hiện (**NOT DONE**).
