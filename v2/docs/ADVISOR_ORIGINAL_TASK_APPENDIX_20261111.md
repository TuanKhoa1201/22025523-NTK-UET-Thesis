# Phụ lục Báo cáo Tiến độ Lần 1: Kết quả Thực hiện Nhiệm vụ Ban đầu (simple_semgrepAI -> OpenGrep + Local Qwen)

- **Dự án:** NTK Thesis V2 (`TuanKhoa1201/22025523-NTK-UET-Thesis`)
- **Nhánh tích hợp đã xác minh:** `v2/integration-pilot` (commit cơ sở `fa6fa48c915e9fda0960f9f53579a101d4a32b25`)
- **Ngày lập báo cáo:** `2026-11-11` (`Asia/Bangkok`)
- **Phạm vi bằng chứng:** Tài liệu này tổng hợp kết quả thực thi thực tế từ nhiệm vụ ban đầu (chuyển đổi công cụ quét từ Semgrep sang OpenGrep và kết nối mô hình Qwen cục bộ để phân loại cảnh báo Java). Mọi số liệu kiểm thử tích hợp dưới đây thuộc commit `fa6fa48c915e9fda0960f9f53579a101d4a32b25` (chưa bao gồm commit mới `0c2ffa10c5f0d565325681e8ec2e33796fd4a68c` trên nhánh `v2/codex-core` chưa merge). Các phép thử trên `SmokeVulnSample.java` là **SYNTHETIC SMOKE TEST** (kiểm thử thông luồng trên mã mẫu tổng hợp), không phải benchmark độ chính xác độc lập.

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
| **Mô hình Qwen cục bộ** | 1. **`qwen3.5:9b-q4_K_M`** (mô hình chính)<br>2. **`qwen3:8b`** (mô hình smoke test P0) | 1. Manifest SHA-256: `7dd7bb310c1f18ad132c7fd72e73d4f6cff2e916c596a818701d2a1269037c7f` (GGUF `5.63 GB` `02d45dc1...` + `mmproj` `921.7 MB` `f836f08f...`)<br>2. Digest: `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` |

---

## B. Nhiệm vụ Gốc: Upstream `simple_semgrepAI` và Đối chiếu Bản Vá (Diff)

### 1. Nguồn gốc Upstream và Vai trò Công cụ Gốc
- **Repository gốc:** `https://github.com/hardw00t/simple_semgrepAI`
- **Commit ghim cố định:** `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` (phiên bản `0.2.0`, giấy phép `MIT`, copyright 2025 hardw00t).
- **Vai trò ban đầu của `simple_semgrepAI`:** Công cụ gốc gọi `semgrep scan --config=auto` để quét mã nguồn, sau đó nạp kết quả vào chuỗi xử lý gồm LangChain (gọi API đám mây Anthropic/OpenAI/OpenRouter hoặc Ollama), cơ sở dữ liệu vector ChromaDB (RAG), giao diện web FastAPI/Uvicorn và bộ sinh báo cáo HTML. Bản gốc đọc nhầm đường dẫn vết dữ liệu tại `result['dataflow_trace']` ở top-level thay vì `result['extra']['dataflow_trace']`, nên luôn làm rỗng thông tin truy vết dòng dữ liệu (`dataflow_trace`).
- **Bản chụp nguyên bản (Snapshot Provenance):** 6 tệp upstream gốc được lưu nguyên vẹn byte và kiểm chứng Git blob SHA-1 tại `v2/baseline/upstream/PROVENANCE.json`:
  - `LICENSE` (`0d6c6874fbcd9b3af4e566714be96ee9f8f42886`)
  - `semgrepai/scanner.py` (`e1945da5f6e96f14b0028933ef994b6cbb4f1241`)
  - `semgrepai/config.py` (`b3433b07d1e41ee8bab21b233c80fe35d5dd485d`)
  - `semgrepai/cli.py` (`b0f3ab7daacedcf85211393a635b52cf462fafe2`)
  - `pyproject.toml` (`a997a9fd53c3714fe4c50ab4844f60c086240e7f`)
  - `semgrepai.yml` (`1fdf83173e837a442b2f5c8695ea05203ecb9476`)

### 2. Các phần Kế thừa, Sửa đổi và Bổ sung trong Nhánh Đồ án (`v2/baseline/fork/`)
- **Kế thừa:** Giao diện lớp `SemgrepScanner.scan()`, cấu trúc đầu ra JSON/SARIF, các phương thức trích xuất ngữ cảnh mã nguồn (`_extract_code`), siêu dữ liệu và tài liệu tham chiếu (`_extract_references`, `_extract_security_patterns`).
- **Sửa đổi (`v2/baseline/opengrep.patch`, SHA-256: `c33d3c4d4aace2f283e5666f6cf6c06e4ed569424d82a82083f8d5a6bee52e41`):**
  1. `semgrepai/scanner.py`: Đổi binary mặc định từ `semgrep` sang `opengrep`; bỏ `--config=auto` để bắt buộc nhận file luật YAML cục bộ; bổ sung các cờ `--dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60`; cô lập biến môi trường log/settings về thư mục đầu ra; lưu vết thực thi (`*.command.json`, `*.stdout.txt`, `*.stderr.txt`, `*.exit.txt`); đọc và bảo toàn nguyên trạng cấu trúc `extra.dataflow_trace` (`taint_source`, `intermediate_vars`, `taint_sink`); gán trạng thái mặc định `REVIEW` cho mọi cảnh báo.
  2. `semgrepai/config.py`: Thay cấu hình phụ thuộc `pydantic`/cloud bằng `OpenGrepConfig` dùng thư viện chuẩn Python.
  3. `semgrepai/cli.py`: Chuyển thành CLI quét cục bộ thuần túy (`python -m semgrepai`), tách khỏi ngăn xếp web/RAG/cloud LLM của upstream.
- **Bổ sung mới ngoài upstream:** Bộ luật taint Java cục bộ (`v2/baseline/rules/java.yml`, `v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml`), mô-đun kiểm chứng bằng chứng và hàng đợi kiểm duyệt SQLite (`v2/triage/`), cùng bộ công cụ chấm điểm đối chứng (`v2/evaluation/`).

### 3. Đối chiếu giữa Patch NTK (`v2/baseline/opengrep.patch`) và Patch trong Gói Tham khảo của Giảng viên (`opengrep-triage.zip`)
Gói tham khảo `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\opengrep-triage.zip` (`SHA-256: 5f39d2fb84bbc50e63b0b2b0c4618f84d7878bab1458cc99377223ee9c31b1cd`) đã được giải nén và kiểm thử trong môi trường cô lập ngoài Git worktree tại `C:\Users\Admin\ntk-thesis-v2\evidence\p0_1_advisor_zip_isolated` (lưu ý: tệp `Bo_ma_OpenGrep_Java_Qwen.zip` được nhắc trong PDF 5 trang không có trong thư mục nguồn - **NOT PROVIDED**):

| Tiêu chí đối chiếu | Patch NTK (`v2/baseline/opengrep.patch`) | Patch Giảng viên (`patches/simple_semgrepAI_opengrep.patch`) |
|---|---|---|
| **Số tệp upstream được sửa** | **3 tệp:** `semgrepai/scanner.py`, `semgrepai/config.py`, `semgrepai/cli.py` | **4 tệp:** `pyproject.toml`, `semgrepai.yml`, `semgrepai/config.py`, `semgrepai/scanner.py` |
| **Quản lý phụ thuộc** | Tách hẳn sang thư viện chuẩn Python cho phần scanner/CLI để không cần cài `semgrep`, `langchain`, `chromadb`. | Giữ cấu trúc `pyproject.toml` gốc của upstream (còn `langchain`, `chromadb`, `fastapi`), chỉ chuyển `semgrep>=1.100.0` sang optional extra `[semgrep]`. |
| **Tham số dòng lệnh OpenGrep** | `--config <rules> --json/--sarif --dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60` | `--timeout <t> --jobs <j> --dataflow-traces --taint-intrafile --config <rules>` |
| **Xử lý `extra.dataflow_trace`** | Giữ nguyên cấu trúc ATD gốc của OpenGrep (`CliLoc`, `intermediate_vars`) để `v2/triage/evidence.py` kiểm chứng chính xác dòng, cột, byte offset và SHA-256. | Làm phẳng (`flatten`) cây `CliLoc`/`CliCall` thành danh sách bước tuần tự `[{type, path, line, content}]`. |
| **Kết quả kiểm chứng thực tế** | `python v2/baseline/verify_patch.py` đạt **PASS** (`git apply --check` và `git apply` khứ hồi khớp 100% với `v2/baseline/fork`). | `git apply --check` trên 4 blob upstream gốc đạt **PASS**; bộ unit test cô lập của gói thầy đạt **15/15 PASS (`0.37s`)** (`evidence/p0_1_advisor_zip_isolated/pytest_15_results.txt`). |

---

## C. Lệnh Chạy Thực tế trên Máy chủ (Đã Kiểm chứng, `exit_code = 0`)

Tất cả các lệnh dưới đây chạy tại thư mục gốc worktree tích hợp `C:\Users\Admin\ntk-thesis-v2\integration-pilot`:

```powershell
# 1. Kiểm tra môi trường máy chủ (Ollama 0.40.7, OpenGrep 1.25.0 WSL2 & Windows Bridge) -> exit_code = 0
powershell -ExecutionPolicy Bypass -File v2/scripts/check_v2_env.ps1

# 2. Kiểm chứng tính toàn vẹn 6 blob upstream và áp dụng thử opengrep.patch -> exit_code = 0
python v2/baseline/verify_patch.py

# 3. Quét thật OpenGrep 1.25.0 qua CLI fork M1 trên bộ fixture Java (xuất JSON + SARIF + kiểm chứng trace) -> exit_code = 0
$env:PYTHONPATH = Join-Path (Get-Location) 'v2/baseline/fork'
python -m semgrepai v2/baseline/fixtures/java --rules-path v2/baseline/rules/java.yml --output-dir C:\Users\Admin\ntk-thesis-v2\evidence\p0_m1_advisor_verify
python v2/baseline/verify_real.py C:\Users\Admin\ntk-thesis-v2\evidence\p0_m1_advisor_verify

# 4. Quét thật OpenGrep 1.25.0 trên SmokeVulnSample.java với bộ luật M1 (sinh 3 cảnh báo: 2 TP, 1 FP) -> exit_code = 0
wsl.exe -d Ubuntu-IRIS -- /usr/local/bin/opengrep scan `
  --config v2/baseline/rules/java.yml `
  --json --dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60 `
  v2/evaluation/smoke_evidence/SmokeVulnSample.java > v2/demo/smoke_m1_rules_raw.opengrep.json

# 5. Đưa 3 cảnh báo từ raw JSON vào v2.triage và gọi thật Qwen3.5:9b-q4_K_M qua Ollama localhost -> exit_code = 0
python -m v2.triage run `
  --source-root C:\Users\Admin\ntk-thesis-v2\integration-pilot\v2\evaluation\smoke_evidence `
  --path-base C:\Users\Admin\ntk-thesis-v2\integration-pilot `
  --json v2/demo/smoke_m1_rules_raw.opengrep.json `
  --engine-exit 0 `
  --output-dir C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1 `
  --model qwen3.5:9b-q4_K_M `
  --endpoint http://127.0.0.1:11434 `
  --timeout 120

# 6. Xem hàng đợi SQLite và kiểm tra bảng đối chứng qua bộ chấm điểm v2.evaluation.score_pilot -> exit_code = 0
python -m v2.triage queue --db C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\review.sqlite
python -m v2.evaluation.score_pilot `
  --alerts v2/demo/smoke_m1_rules_raw.opengrep.json `
  --labels C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\synthetic_fixture_labels_direct.json `
  --triage C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\assessments.jsonl `
  --out-json C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\score_pilot_direct_codex_adapter_report.json `
  --out-md C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\score_pilot_direct_codex_adapter_report.md
```

---

## D. Kết quả Quét OpenGrep 1.25.0, Phân tích Qwen3.5-9B và Bảng Đối chứng Sơ bộ

### 1. Tổng hợp Số lượng Cảnh báo OpenGrep theo Bộ Luật và Đầu vào
- **Đầu vào chính:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (`SHA-256: 090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9`, kích thước `2,131 bytes`, gồm 4 phương thức: 2 phương thức có lỗ hổng `unsafeSqlLookup`, `unsafeFileRead` và 2 phương thức đối chứng an toàn `safeSqlLookup`, `safeFileRead`).
  1. **Quét với bộ luật M1 `v2/baseline/rules/java.yml` (`SHA-256: f34e7b51880cc5baf4ff3cda47a16232c8d405b8fd5e65aaed1aa3745367d5aa`):** Xuất **3 cảnh báo** (`v2/demo/smoke_m1_rules_raw.opengrep.json`, `SHA-256: 005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`), gồm **2 TP** (dòng 28 `CWE-89`, dòng 33 `CWE-22`) và **1 FP** (dòng 47 `CWE-22` tại `safeFileRead` do luật M1 chưa khai báo `FilenameUtils.getName` là sanitizer).
  2. **Quét với bộ luật có khai báo sanitizer `v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml` (`SHA-256: 087f313ccbff779dcc9029380fed024bc0b8ff85a22a4c436cd69c18855decd2`):** Xuất **2 cảnh báo** (`CWE-89` dòng 28 và `CWE-22` dòng 34), `0` báo động giả (`evidence/qwen35_real_20261111_135144/input.opengrep.json`, `SHA-256: d5f3b0ce59601fc38039e249d03308b1182a5f5c41c0382bf5875110e1c9b37f`).
- **Đầu vào fixture cơ sở M1 (`v2/baseline/fixtures/java/Vulnerable.java` + `Safe.java`):** Xuất **4 cảnh báo** trên `Vulnerable.java` (`CWE-22` dòng 7, `CWE-78` dòng 8, `CWE-79` dòng 9, `CWE-89` dòng 10) và **0 cảnh báo** trên `Safe.java`.

### 2. Ba Ví dụ Đầu ra Thực tế trên Cùng Phép Quét M1 (`n = 3`, `qwen3.5:9b-q4_K_M`)
Nguồn bằng chứng: `C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\assessments.jsonl` (`SHA-256: dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5`).

1. **Finding #0 - `CWE-89` tại `unsafeSqlLookup` (Nhãn fixture: `SYNTHETIC TP`):**
   - **Alert ID:** `5c3fa49a9a739ca38e3711e51b676c5c9894a523a8ef1e5f276a3b7d033672b0` (`rule_id: v2.baseline.rules.ntk.java.cwe89`)
   - **Dataflow Trace:** Source dòng `25:28..25:60` (`request.getParameter("username")`) -> Intermediate `userInput` (dòng `25:16..25:25`), `query` (dòng `26:16..26:21`) -> Sink dòng `28:16..28:40` (`stmt.executeQuery(query)`).
   - **Kết quả `qwen3.5:9b-q4_K_M`:** `status = SUPPORTED`, `citation_check = MATCHED` (trích dẫn nguyên văn dòng `25-28`, khớp `sha256: 090c9349...`), `state = OPEN`, `requires_human_review = true`, `elapsed_seconds = 19.719s` (`load_duration = 10.895s`, `eval_count = 334`).
   - **Nhận định của mô hình:** Xác định đúng lỗi nối chuỗi trực tiếp `userInput` vào câu lệnh SQL truyền cho `stmt.executeQuery()` và đề xuất dùng `PreparedStatement` với tham số `?`.
2. **Finding #1 - `CWE-22` tại `unsafeFileRead` (Nhãn fixture: `SYNTHETIC TP`):**
   - **Alert ID:** `76501a37112c42a9d4e46cf1fadeb1794aa417284ce0ce4d415a6986f5a773e9` (`rule_id: v2.baseline.rules.ntk.java.cwe22`)
   - **Dataflow Trace:** Source dòng `32:32..32:62` (`request.getParameter("report")`) -> Intermediate `rawReportName` (dòng `32:16..32:29`) -> Sink dòng `33:27..33:72` (`new File("/var/app/reports/" + rawReportName)`).
   - **Kết quả `qwen3.5:9b-q4_K_M`:** `status = SUPPORTED`, `citation_check = MATCHED` (trích dẫn nguyên văn dòng `32` và `33`, khớp `sha256: 090c9349...`), `state = OPEN`, `requires_human_review = true`, `elapsed_seconds = 10.953s` (`eval_count = 458`).
   - **Nhận định của mô hình:** Chỉ rõ tham số `report` đi thẳng vào `new File(...)` không qua chuẩn hóa đường dẫn, cho phép tấn công `../../../etc/passwd`.
3. **Finding #2 - `CWE-22` Cảnh báo giả tại `safeFileRead` dòng 47 (Nhãn fixture: `SYNTHETIC FP`):**
   - **Alert ID:** `3252602faf5bdb45ef2a393cdf9d72350514515468d9b170d1083410e7716249` (`rule_id: v2.baseline.rules.ntk.java.cwe22`)
   - **Dataflow Trace:** Source dòng `45:32..45:62` (`request.getParameter("report")`) -> Intermediate `rawReportName` (dòng `45:16..45:29`) -> `cleanName` (dòng `46:16..46:25`, `FilenameUtils.getName(rawReportName)`) -> Sink dòng `47:27..47:68` (`new File("/var/app/reports/" + cleanName)`).
   - **Kết quả `qwen3.5:9b-q4_K_M`:** `status = SUPPORTED` (**nhận định sai FP thành TP**), `citation_check = MATCHED` (trích dẫn nguyên văn dòng `45-47`, khớp `sha256: 090c9349...`), `state = OPEN`, `requires_human_review = true`, `elapsed_seconds = 10.078s` (`eval_count = 409`).
   - **Phân tích nguyên nhân mô hình không đề xuất loại FP dòng 47:** Trong trường `explanation`, `qwen3.5:9b-q4_K_M` nhận diện có lệnh `FilenameUtils.getName(rawReportName)` ở dòng 46 và nêu đúng tác dụng loại bỏ chuỗi `../`, nhưng lập luận quá bảo thủ rằng hàm này chưa kiểm tra danh sách trắng (whitelist) tên tệp hợp lệ nên vẫn giữ kết luận `SUPPORTED`.

### 3. Bảng Đối chứng Sơ bộ A/B trên Cùng Phép Quét (`SYNTHETIC SMOKE TEST`, `n = 3`)

| Chỉ số đối chứng | Nhánh A: OpenGrep 1.25.0 đơn lẻ | Nhánh B: OpenGrep 1.25.0 + `qwen3.5:9b-q4_K_M` (`v2.triage`) |
|---|---|---|
| **Tổng số cảnh báo đầu vào** | `3` (`1 CWE-89`, `2 CWE-22`) | `3` (`1 CWE-89`, `2 CWE-22`) |
| **Nhãn thiết kế của fixture (`SYNTHETIC`)** | `2 TP` (dòng 28, 33), `1 FP` (dòng 47) | `2 TP` (dòng 28, 33), `1 FP` (dòng 47) |
| **Trạng thái mô hình & Kiểm chứng trích dẫn** | Không áp dụng | `3/3 SUPPORTED`, `3/3 citation_check = MATCHED` |
| **FP được đề xuất loại đúng (`Proposed FP Removal`)** | `0/1 (0.0%)` | **`0/1 (0.0%)`** (mô hình xếp FP dòng 47 là `SUPPORTED`) |
| **TP bị đề xuất loại nhầm (`Erroneously Proposed TP Removal`)** | `0/2 (0.0%)` | **`0/2 (0.0%)`** (cả 2 TP đều được giữ là `SUPPORTED`) |
| **Số cảnh báo ở trạng thái `REVIEW` / `UNDETERMINED`** | `3/3` (chưa phân loại) | `0/3 (0.0%)` ở lượt live (`3/3` nếu tắt kết nối Ollama) |
| **Số cảnh báo tự động bị loại bỏ (`Auto-dismissed`)** | `0` | **`0/3`** (100% giữ `state = OPEN`, bắt buộc người duyệt) |
| **Độ trễ suy luận trung bình (`elapsed_seconds`)** | Không áp dụng | **`13.583 giây/cảnh báo`** (tổng `40.750s`; warm-cache `~10.516s`) |

---

## E. Kết quả Kiểm thử Phần mềm & Trạng thái Demo Kiểm duyệt

### 1. Kết quả Kiểm thử Tự động (Tại commit tích hợp `fa6fa48c915e9fda0960f9f53579a101d4a32b25`)
*(Lưu ý: Kết quả dưới đây thuộc phiên bản tích hợp đã xác minh tại commit `fa6fa48`, không tự nhận là kết quả của commit mới `0c2ffa10c5f0d565325681e8ec2e33796fd4a68c` trên nhánh `v2/codex-core` chưa merge).*

| Bộ kiểm thử | Lệnh thực thi | Kết quả xác minh |
|---|---|---|
| **M1 Scanner & Provenance Tests** | `python -m unittest discover -s v2/baseline/tests -v` | **24/24 PASS** (`0.254s`) |
| **M2/M3 Triage & Review Queue Tests** | `python -m unittest discover -s v2/triage/tests -v` | **51/51 PASS** (`1.916s`) |
| **M4/M5 Evaluation & Adapter Tests** | `python -m unittest discover -s v2/evaluation/tests -v` | **20/20 PASS** (`0.038s`) |
| **Kiểm chứng khứ hồi `opengrep.patch`** | `python v2/baseline/verify_patch.py` | **PASS** (`exit_code = 0`) |

### 2. Trạng thái Từng Bước của Demo Quy trình Kiểm duyệt (`p0_3_review_workflow_demo` & `tamper_demo`)
Đối chiếu kết quả thực tế trong `C:\Users\Admin\ntk-thesis-v2\evidence\p0_3_review_workflow_demo` và `C:\Users\Admin\ntk-thesis-v2\evidence\p0_integration_pilot\tamper_demo`:

| Bước kiểm duyệt theo yêu cầu | Trạng thái | Bằng chứng thực tế đã ghi nhận |
|---|---|---|
| **1. `confirm-false` trên cảnh báo giả (dòng 47)** | **HOÀN THÀNH (`PASS`)** | `evidence/p0_integration_pilot/tamper_demo/case5a_confirm_false_unchanged.json` (actor `DEMO/SYNTHETIC`, chuyển cảnh báo `3252602f...` sang `CONFIRMED_FALSE`). |
| **2. Chặn xác nhận khi SHA-256 mã nguồn thay đổi** | **HOÀN THÀNH (`PASS`, `exit_code = 2`)** | `evidence/p0_integration_pilot/tamper_demo/case5b_confirm_false_tampered.stderr.txt`: `UNDETERMINED / operation refused: source unavailable/changed; rescan required: source hash mismatch; rescan required: SmokeVulnSample.java` (cùng `v2/triage/demo_freshness.py`). |
| **3. Ẩn cảnh báo `CONFIRMED_FALSE` khỏi hàng đợi mặc định** | **PENDING (Chờ merge commit Codex `0c2ffa1`)** | Tại commit `fa6fa48`, lệnh `queue` mặc định vẫn hiển thị bản ghi `CONFIRMED_FALSE` (`queue_after_demo_decisions.json`). Bản sửa trên `v2/codex-core` (`0c2ffa10c5f0d565325681e8ec2e33796fd4a68c`) sẽ được kiểm chứng sau khi merge. |
| **4. Xem lịch sử (`history`) và mở lại (`reopen`)** | **PASS trong Unit Test / `PENDING` CLI kịch bản `p0_3`** | Đã PASS trong bộ 51 unit test (`v2/triage/tests/test_triage.py`); thư mục `evidence/p0_3_review_workflow_demo` mới dừng ở bước trích xuất `triage_run/evidence.json` do hết thời gian chờ của phiên trước. |

---

## F. Hạn chế và Khó khăn Kỹ thuật Còn Tồn tại

1. **Bản fork upstream đầy đủ chưa được chứng minh chạy đầu-cuối:** `v2/baseline/fork/` chỉ trích xuất và chuyển đổi thành phần scanner/config/CLI sang OpenGrep bằng thư viện chuẩn Python. Toàn bộ phần ứng dụng web FastAPI, RAG ChromaDB và LangChain của `simple_semgrepAI` gốc chưa được chạy thực nghiệm do xung đột phụ thuộc và không nằm trong mục tiêu suy luận cục bộ có kiểm chứng trích dẫn của đồ án.
2. **Khác biệt đường dẫn Windows/WSL2 và chính sách Smart App Control:** Trên Windows 11 (`ADMIN-PC`), bản thực thi rời `opengrep_windows_x86.exe` (`v1.25.0`) bị Smart App Control chặn tiến trình con (`Error 4551`), phải chạy qua `/usr/local/bin/opengrep` trong WSL2 `Ubuntu-IRIS`. Khi truyền đường dẫn tuyệt đối Windows vào WSL2, JSON đầu ra mang tiền tố `/mnt/c/...` gây lỗi tìm tệp trên Windows nếu không quét bằng đường dẫn tương đối từ gốc workspace hoặc chỉ định `--path-base` khớp.
3. **Vấn đề chuẩn hóa xuống dòng CRLF trên Windows:** Cấu hình `core.autocrlf=true` của Git trên Windows ban đầu làm đổi byte `LF -> CRLF` trong `v2/baseline/upstream/LICENSE` và `pyproject.toml`, khiến kiểm tra SHA-1 blob thất bại (21/22 PASS ở vòng đầu). Đã xử lý triệt để bằng `.gitattributes` (`eol=lf`), nâng kết quả M1 lên `24/24 PASS`.
4. **Hạn chế của `qwen3.5:9b-q4_K_M` trước cảnh báo giả có sanitizer (`FilenameUtils.getName`):** Dù trích dẫn đúng dòng 45-47 (`citation_check = MATCHED`), mô hình vẫn đánh giá cảnh báo giả ở dòng 47 là `SUPPORTED` (`0/1` FP được đề xuất loại) vì yêu cầu kiểm tra thêm whitelist ký tự thay vì tin tưởng hoàn toàn vào `FilenameUtils.getName`. Điều này cho thấy việc kết hợp khai báo `pattern-sanitizers` trong luật OpenGrep và cải tiến ngữ cảnh sanitizer trong prompt là cần thiết ở bước tiếp theo.
5. **Chưa có kết quả thực nghiệm trên dự án Java thực tế và OWASP Benchmark độc lập:** Toàn bộ kết quả hiện tại giới hạn ở các tệp Java mẫu tổng hợp (`SmokeVulnSample.java`, `Vulnerable.java`, `Safe.java`). Việc quét một dự án Java mã nguồn mở thực tế (P0.4) và đánh giá định lượng trên tập 30-60 cảnh báo có nhãn độc lập / OWASP Benchmark vẫn chưa thực hiện (**NOT DONE**).
