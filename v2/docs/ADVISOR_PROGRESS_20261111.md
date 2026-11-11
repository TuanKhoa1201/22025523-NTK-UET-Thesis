# BÁO CÁO TIẾN ĐỘ ĐẦU TIÊN - NTK THESIS V2 (OPENGREP + LOCAL QWEN TRIAGE)

- **Ngày báo cáo:** `2026-11-11`
- **Repository:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis`
- **Nhánh tích hợp:** `v2/integration-pilot` (Worktree độc lập tại `C:\Users\Admin\ntk-thesis-v2\integration-pilot`)
- **Các nhánh thành phần đã hợp nhất (`git merge --no-ff`):**
  - Nhánh gốc khởi tạo: `origin/thesis-v2/opengrep-qwen` (`b7246823dba53c0c4cd3f6d8a7e853147f901bac`)
  - Nhánh M1/M2/M3 (Codex): `origin/v2/codex-core` (`5a5250643cbe08b3edf86474d9c879fc3c2fb3cc`)
  - Nhánh M4/M5 (Antigravity): `origin/v2/antigravity-review` (`103e5f0411bcf962cf4b31ee8c07f181ec2dd444`)
  - Nhánh M0/M2 Hạ tầng & Thực nghiệm (JavisOS): `origin/v2/javis-benchmark` (`43e1d648402704b9bc42698e62175805d720f7ff`)
- **Phạm vi báo cáo:** Chứng minh tiến độ tích hợp đầu tiên (M0 -> M1 -> M2/M3 smoke test chạy thật trên phần cứng cục bộ). **Không tuyên bố hoàn thành toàn bộ khóa luận hay công bố độ chính xác (Precision/Recall) trên tập benchmark lớn.**

---

## A. Nhiệm vụ gốc (Upstream Inheritance & OpenGrep Replacement)

1. **Công cụ gốc (`simple_semgrepAI`):**
   - Nguồn upstream: `https://github.com/hardw00t/simple_semgrepAI`
   - Commit ghim cố định (Pinned Commit): `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` (phiên bản `0.2.0`, giấy phép `MIT`, Copyright 2025 hardw00t).
   - Lưu trữ đối chứng nguyên bản: `v2/baseline/upstream/` kèm tệp kiểm chứng Git blob SHA-1 `v2/baseline/upstream/PROVENANCE.json` (6 tệp gốc giữ nguyên từng byte ở chuẩn LF).
2. **Thay đổi sang OpenGrep và Triage cục bộ:**
   - Bản fork tinh gọn tại `v2/baseline/fork/semgrepai/` (`scanner.py`, `config.py`, `cli.py`) và bản vá đối chiếu `v2/baseline/opengrep.patch` (sinh tự động qua `v2/baseline/make_patch.py`).
   - Thay thế lời gọi `semgrep` bằng `opengrep scan` cục bộ với cờ `--json` / `--sarif`, `--dataflow-traces`, `--no-git-ignore`, `--disable-version-check`, `--jobs 1`.
   - Bảo toàn cấu trúc `extra.dataflow_trace` nguyên bản (`CliLoc`, `taint_source`, `intermediate_vars`, `taint_sink`) mà không tự suy diễn bước trung gian.
3. **Phân biệt phần đã tích hợp và phần không tích hợp:**
   - **Đã tích hợp và chạy thật:** Lớp quét `SemgrepScanner` dùng `OpenGrep` (`v2/baseline/fork/semgrepai/`) và mô-đun đối chứng mã nguồn + suy luận Ollama loopback + hàng đợi kiểm duyệt SQLite (`v2/triage/`).
   - **Chủ đích loại bỏ / không tích hợp từ upstream:** Toàn bộ thành phần gọi LLM đám mây, RAG, vector database và giao diện web của `simple_semgrepAI` gốc bị loại bỏ để bảo đảm mã nguồn không bao giờ rời khỏi máy chủ cục bộ (`127.0.0.1`).
   - **Gói module riêng của giảng viên (Advisor ZIP):** Chưa có tệp ZIP trong thư mục cục bộ nên **chưa tích hợp** và không tuyên bố đã chạy module riêng của giảng viên.

---

## B. Môi trường Thực thi Đã Kiểm chứng (M0 & M2 Readiness)

| Thành phần | Thông số thực tế trên máy chủ | Trạng thái |
|---|---|---|
| **Hệ điều hành** | Windows 11 Pro `10.0.26200` + WSL2 `Ubuntu-IRIS` | **PASS** |
| **Python** | Windows: `Python 3.12.10` / WSL2: `Python 3.10.22` | **PASS** |
| **GPU & VRAM** | `NVIDIA GeForce RTX 4060 Ti` (`16,380 MiB` VRAM, Driver `591.86`, CUDA `13.1`, Compute `8.9`) | **PASS** |
| **RAM & Lưu trữ** | RAM `63.82 GB` (trống `~40.6 GB`); ổ `C:` trống `192 GB`, ổ `F:` trống `302.7 GB` | **PASS** |
| **OpenGrep Engine** | `OpenGrep 1.25.0` tại WSL2 `/usr/local/bin/opengrep` (`SHA-256: 9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33`) + cầu nối Windows `C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.cmd` | **PASS** |
| **Ollama Server** | `Ollama v0.40.7` (`http://127.0.0.1:11434`, chạy với `OLLAMA_NOPRUNE=true`, kho model trên ổ `F:`) | **PASS** |
| **Model Qwen chạy thật** | `qwen3:8b` (`digest: 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`, `Q4_K_M`, offload `100% GPU`) và `qwen3:14b` (`digest: bdbd181c33f2...`, `Q4_K_M`, `41/41 layers GPU`) | **PASS** |
| **Model mục tiêu `qwen3.5:9b-q4_K_M`** | Tiến trình `ollama pull qwen3.5:9b-q4_K_M` (`PID 4364`) đang tải nền an toàn: tệp `mmproj` (`f836f08f9211`, `921 MB`) đã đạt `100%`; tệp trọng số chính (`02d45dc1cf45`, `5.6 GB`) đang ở mức `43%` (`2.4 GB / 5.6 GB`, tốc độ `~1.2 MB/s`) | **PENDING (IN_PROGRESS)** |

---

## C. Thực nghiệm Chạy Thật từ Bản Tích hợp (`v2/integration-pilot`)

### C.1. Kết quả 3 Bộ Unit Test trên Nhánh Tích hợp

1. **M1 Scanner Tests (`python -m unittest discover -s v2/baseline/tests -v`):**
   - Chạy **22 tests**: **21 PASS, 1 FAIL, 0 SKIP**.
   - **Phân tích 1 ca FAIL (`test_upstream_snapshot_matches_git_blob_hashes`):** Trên Windows với `core.autocrlf=true`, tệp `.gitattributes` ở gốc repo chưa khai báo `eol=lf` cho tệp không phần mở rộng (`LICENSE`) và `.toml` (`pyproject.toml`). Do đó Git checkout 2 tệp này ra working tree với `CRLF` (`w/crlf`), làm lệch SHA-1 khi đọc byte trực tiếp từ đĩa dù blob trong Git index (`i/lf`) khớp 100% với `PROVENANCE.json`. Trách nhiệm khắc phục: **Codex** (thêm `v2/baseline/upstream/** text eol=lf` hoặc chuẩn hóa đọc blob).
2. **M2/M3 Triage Tests (`python -m unittest discover -s v2/triage/tests -v`):**
   - Chạy **42 tests**: **42 PASS, 0 FAIL, 0 SKIP** (`1.811s`, bao gồm cả kiểm thử chống symlink escape `test_symlink_escape_forbidden`).
3. **M4/M5 Evaluation Tests (`python -m unittest discover -s v2/evaluation/tests -v`):**
   - Chạy **10 tests**: **10 PASS, 0 FAIL, 0 SKIP** (`0.015s`).
   - *Lưu ý:* Tệp `v2/evaluation/fixtures/qwen_triage_outputs.fixture.jsonl` của nhánh Antigravity dùng đuôi `.jsonl` đang bị script kiểm tra repo cũ `scripts/verify-repository.py` chặn theo biểu thức chính quy cấm `.jsonl`. Trách nhiệm khắc phục: **Antigravity** (đổi tên fixture sang `.json` hoặc cập nhật cấu hình kiểm tra).

### C.2. Quét OpenGrep 1.25.0 Thực tế trên Mã Java Tổng hợp

- **Tệp mã nguồn Java đầu vào:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java`
  - **SHA-256 (working tree):** `090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9`
  - **Cấu trúc mẫu:** 2 phương thức có lỗ hổng thật (`unsafeSqlLookup` - `CWE-89`, `unsafeFileRead` - `CWE-22`) và 2 phương thức đối chứng an toàn (`safeSqlLookup` dùng `PreparedStatement`, `safeFileRead` dùng `FilenameUtils.getName`).
- **Lệnh chạy thực tế từ gốc worktree `C:\Users\Admin\ntk-thesis-v2\integration-pilot`:**
  ```powershell
  wsl.exe -d Ubuntu-IRIS -- /usr/local/bin/opengrep scan `
    --config v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml `
    --json --dataflow-traces --no-git-ignore --disable-version-check --jobs 1 --timeout 60 `
    v2/evaluation/smoke_evidence/SmokeVulnSample.java
  ```
  *(Và lệnh tương đương với `--sarif` để xuất SARIF).*
- **Bộ quy tắc 1 (`v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml`, `SHA-256: 7f712640c102f834c01552400ef8832265874f397b6260676eb13615308cf179`):**
  - **Exit code:** `0`, `errors: []`.
  - **Đầu ra lưu tại:** `v2/demo/smoke_v2_taint_raw.opengrep.json` (`SHA-256: d5f3b0ce59601fc38039e249d03308b1182a5f5c41c0382bf5875110e1c9b37f`) và `v2/demo/smoke_v2_taint_raw.opengrep.sarif` (`SHA-256: 0b061251650b60361b9be62f5a99c09579335eb4ef5c49c2463cc1532d637dc2`).
  - **Kết quả phát hiện (2 cảnh báo):**
    1. **Rule ID:** `v2.evaluation.smoke_evidence.ntk.v2.java.cwe89.httpservlet-jdbc-sqli-taint` (`CWE-89`)
       - **Taint Source:** Dòng `25`, cột `28..60` (`request.getParameter("username")`)
       - **Intermediate Vars:** `userInput` (dòng `25`, cột `16..25`) -> `query` (dòng `26`, cột `16..21`)
       - **Taint Sink:** Dòng `28`, cột `16..40` (`stmt.executeQuery(query)`)
    2. **Rule ID:** `v2.evaluation.smoke_evidence.ntk.v2.java.cwe22.httpservlet-path-traversal-taint` (`CWE-22`)
       - **Taint Source:** Dòng `32`, cột `32..62` (`request.getParameter("report")`)
       - **Intermediate Vars:** `rawReportName` (dòng `32`, cột `16..29`) -> `targetFile` (dòng `33`, cột `14..24`)
       - **Taint Sink:** Dòng `34`, cột `16..47` (`new FileInputStream(targetFile)`)
- **Bộ quy tắc 2 (`v2/baseline/rules/java.yml` của Codex M1, `SHA-256: 0565c1b8693221cf8a39150b5ef434e11796281c85fb5d8ec7555dc1809e8d01`):**
  - **Đầu ra lưu tại:** `v2/demo/smoke_m1_rules_raw.opengrep.json` (`SHA-256: 005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`).
  - **Kết quả phát hiện (3 cảnh báo):** Ngoài 2 lỗ hổng thật tại dòng `28` (`ntk.java.cwe89`) và dòng `33` (`ntk.java.cwe22`), bộ luật cơ sở M1 (chưa khai báo `pattern-sanitizers`) sinh thêm **1 cảnh báo giả (False Positive)** tại dòng `47` (`new File("/var/app/reports/" + cleanName)` trong hàm `safeFileRead`, nơi `cleanName` đã được làm sạch qua `FilenameUtils.getName` ở dòng `46`).

### C.3. Kết quả Chạy Pipeline `v2/triage` + Local Ollama `qwen3:8b` (Smoke Test Tích hợp)

- **Lệnh thực thi:**
  ```powershell
  python -m v2.triage run `
    --source-root C:\Users\Admin\ntk-thesis-v2\integration-pilot\v2\evaluation\smoke_evidence `
    --path-base C:\Users\Admin\ntk-thesis-v2\integration-pilot `
    --json C:\Users\Admin\ntk-thesis-v2\evidence\p0_integration_pilot\opengrep_smoke_scan\smoke_v2_taint_rules_raw.opengrep.json `
    --engine-exit 0 `
    --output-dir C:\Users\Admin\ntk-thesis-v2\evidence\p0_integration_pilot\triage_run1_smoke_v2_rules_qwen3_8b `
    --model qwen3:8b --timeout 120
  ```
- **Cấu hình Ollama thực tế trong `v2/triage/ollama.py`:** Endpoint `http://127.0.0.1:11434/api/chat`, model `qwen3:8b` (`digest: 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`), `stream: false`, `think: false`, `options: {"temperature": 0, "num_ctx": 4096, "num_predict": 1200}`, JSON Schema ép buộc `status`, `explanation`, `citations`, `fix_suggestion`.
- **Tổng hợp 9 lượt suy luận `qwen3:8b` thật trên 3 lô thử nghiệm (chi tiết lưu tại `v2/demo/triage_qwen3_8b_summary.json`):**

| Lô chạy | Cảnh báo (Rule / CWE / Dòng) | Phản hồi gốc của `qwen3:8b` | Kiểm tra trích dẫn (`validate_answer`) | Trạng thái mô hình sau kiểm định | Trạng thái hàng đợi (`review.sqlite`) | Thời gian suy luận |
|---|---|---|---|---|---|---|
| **Run 1** (`SmokeVulnSample` + `v2_taint_rules`) | `[0]` `cwe89` - Dòng `28` (TP) | `SUPPORTED` (trích dẫn dòng `25-28`) | `MATCHED` (khớp từng ký tự & SHA-256) | **`SUPPORTED`** | `OPEN` | `12.70s` |
| **Run 1** (`SmokeVulnSample` + `v2_taint_rules`) | `[1]` `cwe22` - Dòng `34` (TP) | `SUPPORTED` (trích dẫn dòng `32, 33, 34`) | `NOT_VERIFIED` (`qwen3:8b` lược bỏ 8 dấu cách đầu dòng khi trích dẫn từng dòng lẻ) | **`UNDETERMINED`** (Fail-safe) | `OPEN` | `10.81s` |
| **Run 2** (`SmokeVulnSample` + `m1_rules`) | `[0]` `ntk.java.cwe89` - Dòng `28` (TP) | `SUPPORTED` (trích dẫn dòng `25-28`) | `MATCHED` | **`SUPPORTED`** | `OPEN` | `6.72s` |
| **Run 2** (`SmokeVulnSample` + `m1_rules`) | `[1]` `ntk.java.cwe22` - Dòng `33` (TP) | `SUPPORTED` (trích dẫn dòng `32, 33`) | `NOT_VERIFIED` (lược bỏ 8 dấu cách đầu dòng) | **`UNDETERMINED`** (Fail-safe) | `OPEN` | `8.22s` |
| **Run 2** (`SmokeVulnSample` + `m1_rules`) | `[2]` `ntk.java.cwe22` - Dòng `47` (**FP** ở `safeFileRead`) | `SUPPORTED` (trích dẫn dòng `45, 47`, bỏ sót sanitizer dòng `46`) | `NOT_VERIFIED` (lược bỏ 8 dấu cách đầu dòng) | **`UNDETERMINED`** (Fail-safe) | `OPEN` | `9.64s` |
| **Run 3** (`Vulnerable.java` + `m1_rules`) | `[0]` `ntk.java.cwe22` - Dòng `7` (TP) | `SUPPORTED` (trích dẫn dòng `5, 7, 8, 10`) | `NOT_VERIFIED` (lược bỏ 8 dấu cách đầu dòng) | **`UNDETERMINED`** (Fail-safe) | `OPEN` | `11.44s` |
| **Run 3** (`Vulnerable.java` + `m1_rules`) | `[1]` `ntk.java.cwe78` - Dòng `8` (TP) | `SUPPORTED` (trích dẫn dòng `5-11`) | `NOT_VERIFIED` (`quote` gồm dòng `5-10`, thiếu dòng `11` là dấu `}`) | **`UNDETERMINED`** (Fail-safe) | `OPEN` | `7.11s` |
| **Run 3** (`Vulnerable.java` + `m1_rules`) | `[2]` `ntk.java.cwe79` - Dòng `9` (TP) | `SUPPORTED` (trích dẫn dòng `5, 9, 10`) | `MATCHED` (giữ nguyên 8 dấu cách đầu dòng) | **`SUPPORTED`** | `OPEN` | `11.23s` |
| **Run 3** (`Vulnerable.java` + `m1_rules`) | `[3]` `ntk.java.cwe89` - Dòng `10` (TP) | `SUPPORTED` (trích dẫn dòng `5, 10`) | `MATCHED` (giữ nguyên 8 dấu cách đầu dòng) | **`SUPPORTED`** | `OPEN` | `7.70s` |

- **Kiểm chứng cơ chế bảo vệ hàng đợi & chống lệch SHA-256 (`DEMO/SYNTHETIC`):**
  1. **Không tự động ẩn cảnh báo:** Cả 9/9 cảnh báo sau khi chạy `qwen3:8b` đều giữ trạng thái `state = "OPEN"` và `requires_human_review = true` trong `review.sqlite`.
  2. **Thử nghiệm xác nhận cảnh báo giả hợp lệ (`Case 5A - DEMO/SYNTHETIC`):** Trên bản sao thử nghiệm độc lập, thực thi `python -m v2.triage decide --db ... 3252602faf5b... confirm-false --actor "DEMO/SYNTHETIC" --reason "DEMO/SYNTHETIC: Line 46 sanitizes path via FilenameUtils.getName(rawReportName)"` khi tệp Java chưa bị sửa đổi -> `exit_code = 0`, trạng thái chuyển sang `CONFIRMED_FALSE` nhưng cảnh báo vẫn hiển thị minh bạch trong `queue` kèm lịch sử kiểm toán đầy đủ.
  3. **Thử nghiệm chặn quyết định khi mã nguồn thay đổi sau lúc quét (`Case 5B - DEMO/SYNTHETIC`):** Sau khi thêm 1 dòng chú thích vào bản sao `SmokeVulnSample.java` (làm thay đổi SHA-256), lệnh `python -m v2.triage decide ... confirm-false --actor "DEMO/SYNTHETIC"` lập tức bị từ chối với **`exit_code = 2`** và thông báo:
     `UNDETERMINED / operation refused: source unavailable/changed; rescan required: source hash mismatch; rescan required: SmokeVulnSample.java`. Cảnh báo giữ nguyên trạng thái `OPEN`.

---

## D. Đối chứng Ban đầu (OpenGrep Đơn lẻ vs. OpenGrep + Local Qwen)

| Tiêu chí đối chứng (Phạm vi Smoke Test Tổng hợp) | Nhánh A: OpenGrep 1.25.0 Đơn lẻ | Nhánh B: OpenGrep 1.25.0 + `v2/triage` (`qwen3:8b`) |
|---|---|---|
| **Trên `SmokeVulnSample.java` + `v2_java_taint_rules.yaml` (2 TP, 2 hàm an toàn)** | Phát hiện `2/2` TP (`CWE-89` dòng 28, `CWE-22` dòng 34), `0` cảnh báo trên 2 hàm an toàn | Giữ nguyên `2/2` cảnh báo ở trạng thái `OPEN` (`1 SUPPORTED` có trích dẫn khớp tuyệt đối, `1 UNDETERMINED` do mô hình lược bỏ khoảng trắng đầu dòng). Không có TP nào bị đề xuất loại nhầm (`0/2`). |
| **Trên `SmokeVulnSample.java` + `v2/baseline/rules/java.yml` (2 TP, 1 FP ở `safeFileRead`)** | Phát hiện `2/2` TP và sinh `1` FP tại dòng 47 (do thiếu khai báo sanitizer `FilenameUtils.getName`) | Giữ nguyên cả `3/3` cảnh báo ở trạng thái `OPEN`. Trên ca FP dòng 47, `qwen3:8b` trả về `SUPPORTED` (chưa nhận diện được `FilenameUtils.getName` là hàm làm sạch) và bị chuyển về `UNDETERMINED` do lệch khoảng trắng trích dẫn. |

> **Lưu ý học thuật bắt buộc:** Kết quả trên chỉ bao gồm **2 tệp Java tổng hợp** (`SmokeVulnSample.java` với 2 lỗ hổng + 2 hàm an toàn; `Vulnerable.java` / `Safe.java` với 4 lỗ hổng + 1 hàm an toàn). **Tuyệt đối không suy diễn tỷ lệ báo động giả (FP rate) = 0% cho toàn hệ thống và không công bố Precision/Recall** khi chưa chạy trên tập đánh giá khóa cứng 30-60 cảnh báo độc lập (M4/M5).

---

## E. Giới hạn Hiện tại, Lỗi Tích hợp Phát hiện & Bước Tiếp theo

### E.1. Phân tách Minh bạch Trạng thái Thực tế
- **Mã mẫu (Synthetic Fixtures):** `SmokeVulnSample.java`, `Vulnerable.java`, `Safe.java` và các tệp trong `v2/evaluation/fixtures/` (`TEST_FIXTURE_ONLY`).
- **Mock Tests:** Các bài kiểm thử đơn vị trong `v2/baseline/tests/`, `v2/triage/tests/`, `v2/evaluation/tests/`.
- **Đã chạy thật (Real Execution):** `OpenGrep 1.25.0` (JSON + SARIF + `extra.dataflow_trace`), `Ollama 0.40.7` trên GPU `RTX 4060 Ti 16 GB`, suy luận `qwen3:8b` và `qwen3:14b`, lưu trữ và kiểm chứng SHA-256 trong `v2/triage` (`review.sqlite`).
- **Đang chờ (Pending):** Model `qwen3.5:9b-q4_K_M` đang tải nền (`43%`, `2.4 GB / 5.6 GB`); gói module riêng của giảng viên; bộ dữ liệu gán nhãn độc lập 30-60 cảnh báo (M4/M5).

### E.2. Danh mục Lỗi Tích hợp Còn Tồn tại & Phân công Agent Khắc phục

| Mã lỗi | Mô tả kỹ thuật đã xác minh thực nghiệm | Ảnh hưởng | Agent chịu trách nhiệm |
|---|---|---|---|
| **INT-01** | **Không tương thích đường dẫn WSL `/mnt/c/...` khi `v2.triage` gọi trực tiếp `SemgrepScanner.scan()` trên Windows:** `scanner.py` gọi `Path(target_path).resolve()` truyền đường dẫn tuyệt đối Windows vào `opengrep.cmd`, khiến OpenGrep trong WSL xuất `"path": "/mnt/c/Users/..."`. Khi `v2/triage/evidence.py` (`SourceTree.resolve`) chạy trên Windows Python, `Path("/mnt/c/...").resolve(strict=True)` tìm `C:\mnt\c\...` và báo lỗi `[WinError 3]`, đẩy mọi cảnh báo về `UNDETERMINED`. *(Hiện đã vượt qua an toàn bằng cách quét đường dẫn tương đối từ gốc workspace hoặc dùng manifest ánh xạ `v2/demo/wsl_to_windows_mapping_manifest.json`).* | Chặn chế độ quét trực tiếp không qua `--json` khi dùng cầu nối Windows -> WSL. | **Codex** (`v2/baseline` & `v2/triage`) |
| **INT-02** | **Lệch Schema giữa đầu ra `v2/triage` (`assessments.jsonl`) của Codex và đầu vào `v2/evaluation/score_pilot.py` của Antigravity:** (1) Codex đặt khóa định danh là `"id"` (SHA-256 của `scan_sha256:index`), trong khi `score_pilot.py` yêu cầu `"alert_id"` dạng `path:start:end:cwe:rule:idx`; (2) Codex đặt kết quả ở `assessment.status` (`SUPPORTED`/`REFUTED`/`UNDETERMINED`), trong khi `score_pilot.py` đọc `verdict` ở mức gốc (`TP`/`FP`/`REVIEW`); (3) Codex lưu `citations` dạng mảng object và `elapsed_seconds`, trong khi `score_pilot.py` đọc `cited_lines` (mảng số nguyên) và `latency_ms`. | `score_pilot.py` báo `Triage record missing alert_id` và chuyển 100% bản ghi Codex về `REVIEW`. | **Antigravity & Codex** (bổ sung bộ chuyển đổi schema thống nhất) |
| **INT-03** | **Kiểm tra trích dẫn `actual != cite["quote"]` trong `v2/triage/ollama.py` quá cứng với khoảng trắng đầu dòng:** Khi `qwen3:8b` trích dẫn đúng 100% nội dung dòng lệnh Java nhưng lược bỏ 8 dấu cách thụt lề đầu dòng, `validate_answer()` bác bỏ toàn bộ kết luận sang `UNDETERMINED` (5/9 cảnh báo). | Làm tăng tỷ lệ `UNDETERMINED` giả tạo do lỗi định dạng khoảng trắng. | **Codex** (`v2/triage/ollama.py`) |
| **INT-04** | **Lỗi `CRLF` trên Windows trong `test_upstream_snapshot_matches_git_blob_hashes` (`v2/baseline/tests/test_scanner.py`) và tệp `.jsonl` trong `scripts/verify-repository.py`:** `v2/baseline/upstream/LICENSE` và `pyproject.toml` bị checkout với `CRLF` khi `core.autocrlf=true`; tệp `qwen_triage_outputs.fixture.jsonl` bị chặn bởi quy tắc cấm `.jsonl` của script kiểm tra repo cũ. | Làm 1 unit test M1 và `verify-repository.py` trả về `exit_code = 1`. | **Codex** (`.gitattributes`) & **Antigravity** (đổi đuôi fixture) |

### E.3. Bước Tiếp theo (Next Actions)
1. **P1 (Ngay khi `qwen3.5:9b-q4_K_M` tải xong 100%):** Chạy lại đúng script `v2/demo/reproduce_integration_pilot.ps1 -Model "qwen3.5:9b-q4_K_M"` trên cùng tệp `smoke_v2_taint_raw.opengrep.json` và `smoke_m1_rules_raw.opengrep.json` để đối chiếu trực tiếp với `qwen3:8b`.
2. **Đồng bộ Schema Codex <-> Antigravity:** Khắc phục `INT-01`..`INT-04` trên nhánh tương ứng và merge vào `v2/integration-pilot`.
3. **M4/M5 Benchmark (30-60 cảnh báo độc lập):** Xây dựng và khóa cứng (`validate_pilot_lock.py`) bộ 30-60 cảnh báo thực tế (ưu tiên `CWE-22` và `CWE-89`), gán nhãn độc lập trước khi chạy chấm điểm chính thức.
