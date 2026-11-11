# BÁO CÁO TIẾN ĐỘ LẦN 1 - NTK THESIS V2 (OPENGREP + LOCAL QWEN TRIAGE)

- **Ngày báo cáo:** `2026-11-11`
- **Repository:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis`
- **Nhánh tích hợp:** `v2/integration-pilot` (Worktree độc lập tại `C:\Users\Admin\ntk-thesis-v2\integration-pilot`)
- **Các nhánh thành phần đã hợp nhất (`git merge --no-ff` trên nền `f92d5f915c9dc9a34604efa29820e662fd7b616b`):**
  - `origin/v2/codex-core`: **`c36bc120de2922413c53c26e42648b184ac3e5c7`** (`v2: bind scan receipts and harden upstream scan-only verification` - M1 baseline scanner/patch 4 file + `scan-manifest.json` chuẩn `ntk-scan-capture-1`, M2/M3 triage, `scan_receipt.py`, `live_check.py`, `export_pilot.py`, SQLite queue ẩn `CONFIRMED_FALSE`, `--path-map`, `demo_queue.py`, `verify_handoff.py`)
  - `origin/v2/antigravity-review`: **`f25ce45a812a94198f09db7b296a2caf52174ca3`** (`v2: harden independent evaluation and audit Qwen paired pilot` - M4/M5 evaluation, `score_pilot.py`, `codex_adapter.py`, `build_paired_pilot_table.py`, `validate_pilot_lock.py`, `INDEPENDENT_EVALUATION_AUDIT_20261111.md`, `smoke_m1_verified_labels.json`)
  - `origin/v2/javis-benchmark` / nền tích hợp: **`f92d5f915c9dc9a34604efa29820e662fd7b616b`** / `da26b87206fd0d7a5873e957dc1713cde03fe322` (`scripts/verify-repository.py`, `v2/scripts/run_v2_quality_gate.py`, `v2/demo/reproduce_integration_pilot.ps1`, `v2/demo/verify_repro_contract.py`, `v2/demo/tests/test_quality_gate.py`)
- **Bộ tài liệu bàn giao trong nhánh `v2/integration-pilot`:**
  - Bảng đối chứng A/B chính thức: `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.md` và `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.csv` (bản sao đồng bộ tại `v2/docs/ADVISOR_PAIRED_PILOT_20261111.md` và `.csv`)
  - Báo cáo kiểm toán độc lập M4: `v2/evaluation/INDEPENDENT_EVALUATION_AUDIT_20261111.md`
  - Phụ lục nhiệm vụ gốc (bản ngắn 2-3 trang Markdown & PDF): `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.md` và `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.pdf`
  - Phụ lục nhiệm vụ gốc (bản kỹ thuật đầy đủ): `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_20261111.md`
  - Tin nhắn tóm tắt gửi giảng viên: `v2/docs/ADVISOR_MESSAGE_20261111.md`
  - Script tái lập tích hợp (tách bạch `-Mode REPLAY` và `-Mode LIVE`): `v2/demo/reproduce_integration_pilot.ps1`
- **Phân định phạm vi và trạng thái xác minh (5 nguyên tắc minh bạch bắt buộc):**
  1. **Patch upstream (`v2/baseline/verify_patch.py`):** **`PASS`** (`6 upstream blobs; deterministic patch; git apply --check/apply matches 4 fork files`).
  2. **Scanner/CLI upstream đã vá (`v2/baseline/fork/semgrepai/`):** **`PASS`** (chạy thật `OpenGrep 1.25.0` JSON + SARIF và sinh `scan-manifest.json` chuẩn `ntk-scan-capture-1`).
  3. **Toàn bộ ứng dụng `simple_semgrepAI` upstream đầy đủ (FastAPI web, ChromaDB RAG, LangChain cloud LLM):** **`PENDING / NOT DONE`** (chưa chạy thành công ngăn xếp web/RAG/cloud upstream do xung đột phụ thuộc và nằm ngoài kiến trúc cục bộ).
  4. **Trạng thái xác thực runtime Ollama (`qwen3.5:9b-q4_K_M`):** **`OLLAMA_REPORTED_UNATTESTED` (`PENDING` đối với chứng thực phần cứng độc lập)** — Đã xác minh `3/3` phản hồi HTTP 200 từ `http://127.0.0.1:11434/api/chat`, `3/3` JSON hợp lệ, `3/3 citation_check = MATCHED`, `reported_eval_count > 0`, `model_identity_matched = true`; cờ `independently_verified_model_runtime = false` (`qwen_runtime_verified = false`) được giữ nguyên theo thiết kế vì phản hồi HTTP cục bộ không tự chứng thực phần cứng độc lập.
  5. **Phân biệt `REPLAY PASS` vs. `LIVE PASS` và phạm vi `SYNTHETIC SMOKE PILOT, n = 3`:** Đã kiểm chứng thành công cả chế độ `REPLAY` (trên dữ liệu lịch sử đã khóa `scan_sha256: 005863f2...`) và chế độ `LIVE` mới có gắn `scan-manifest.json` (`scan_sha256: 4d628a21...`, `manifest_sha256: 77da8733...` tại `evidence/repro_live_verified_20261111_c36_f25`). **Chưa có kết quả benchmark độc lập trên dự án Java thực tế hoặc OWASP Benchmark (`NOT DONE`).**

---

## A. Nhiệm vụ gốc (Upstream Inheritance, OpenGrep Replacement & Scan Receipt Binding)

1. **Công cụ gốc (`simple_semgrepAI`):**
   - Nguồn upstream: `https://github.com/hardw00t/simple_semgrepAI`
   - Commit ghim cố định (Pinned Commit): `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` (phiên bản `0.2.0`, giấy phép `MIT`, Copyright 2025 hardw00t).
   - Lưu trữ đối chứng nguyên bản: `v2/baseline/upstream/` kèm tệp kiểm chứng Git blob SHA-1 `v2/baseline/upstream/PROVENANCE.json` (6 tệp gốc và `opengrep.patch` được bảo toàn nguyên vẹn từng byte bằng thuộc tính `-text` trong `v2/baseline/.gitattributes`).
2. **Thay đổi sang OpenGrep và Ràng buộc Biên lai Quét (`scan-manifest.json`):**
   - Bản fork tinh gọn tại `v2/baseline/fork/semgrepai/` (`scanner.py`, `config.py`, `cli.py`, `scan_manifest.py`) và bản vá đối chiếu `v2/baseline/opengrep.patch` (kiểm chứng khứ hồi qua `python v2/baseline/verify_patch.py` đạt `PASS` trên cả 4 tệp fork).
   - Thay thế lời gọi `semgrep` bằng `opengrep scan` cục bộ với cờ `--json` / `--sarif`, `--dataflow-traces`, `--no-git-ignore`, `--disable-version-check`, `--jobs 1`.
   - Sinh biên lai quét `scan-manifest.json` (`schema = "ntk-scan-capture-1"`) ghi nhận mã băm SHA-256 của mã nguồn trước/sau khi quét (`sources_before`, `sources_after`), mã băm bộ luật (`rules_before_sha256`, `rules_after_sha256`), toàn bộ tham số dòng lệnh, mã thoát thực tế (`runs.json.exit_code`, `runs.sarif.exit_code`) và mã băm các tệp đầu ra.
   - Bảo toàn cấu trúc `extra.dataflow_trace` nguyên bản (`CliLoc`, `taint_source`, `intermediate_vars`, `taint_sink`); kiểm chứng toàn vẹn byte và trace qua `python v2/baseline/verify_handoff.py` đạt `PASS`.
3. **Đối chiếu với gói tham khảo `opengrep-triage.zip` của giảng viên:**
   - Gói `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\opengrep-triage.zip` (`SHA-256: 5f39d2fb84bbc50e63b0b2b0c4618f84d7878bab1458cc99377223ee9c31b1cd`) đã được kiểm thử trong môi trường cô lập ngoài Git worktree (`evidence/p0_1_advisor_zip_isolated`), đạt `15/15 pytest PASS` và `git apply --check` đạt `PASS`.
   - Tệp `Bo_ma_OpenGrep_Java_Qwen.zip` được nhắc trong PDF 5 trang không có trong thư mục nguồn (**NOT PROVIDED**).

---

## B. Môi trường Thực thi & Kết quả Kiểm thử Tự động Sau Hợp nhất (`162/162 PASS`)

| Thành phần / Bộ kiểm thử | Thông số / Lệnh kiểm chứng thực tế | Kết quả (`PASS` / `FAIL` / `SKIP`) |
|---|---|---|
| **Hệ điều hành & Python** | Windows 11 Pro `10.0.26200` (`Python 3.12.10`) + WSL2 `Ubuntu-IRIS` (`Python 3.10.22`) | **PASS** |
| **GPU & Ollama Runtime** | `NVIDIA GeForce RTX 4060 Ti 16 GB` + `Ollama v0.40.7` (`127.0.0.1:11434`, `100% GPU`) | **PASS** |
| **OpenGrep Engine** | `OpenGrep 1.25.0` tại WSL2 `/usr/local/bin/opengrep` + cầu nối Windows `opengrep.cmd` | **PASS** |
| **Model Qwen chạy thật** | **`qwen3.5:9b-q4_K_M`** (`manifest SHA-256: 7dd7bb31...`) và **`qwen3:8b`** (`digest: 500a1f06...`) | **`OLLAMA_REPORTED_UNATTESTED` (`3/3` HTTP 200)** |
| **Repository Policy Gate** | `python scripts/verify-repository.py` | **`PASS` (`19` tệp bắt buộc, `99` module Python, `16` JSON, `3` JSONL)** |
| **M1 Scanner & Receipt Tests** | `python -m pytest v2/baseline/tests -v` | **`27 passed` (`14 subtests`), `0 failed`, `0 skipped` (`0.34s`)** |
| **M2/M3 Triage & Manifest Tests** | `python -m pytest v2/triage/tests -v` | **`70 passed` (`12 subtests`), `0 failed`, `0 skipped` (`4.00s`)** |
| **M4/M5 Evaluation & Audit Tests** | `python -m pytest v2/evaluation/tests -v` | **`28 passed`, `0 failed`, `0 skipped` (`0.07s`)** |
| **Quality Gate & Fail-Closed Tests** | `python -m pytest v2/demo/tests -v` | **`37 passed`, `0 failed`, `0 skipped` (`7.35s`)** |
| **Tổng cộng Unit Tests V2** | `python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q` | **`162 passed` (`26 subtests`), `0 failed`, `0 skipped` (`exit_code = 0`)** |
| **Cổng Kiểm định Tích hợp V2** | `python v2/scripts/run_v2_quality_gate.py` | **`PASS` (`11/11` bước kiểm định đạt, `exit_code = 0`)** |
| **Patch & Handoff Verification** | `python v2/baseline/verify_patch.py` & `python v2/baseline/verify_handoff.py` | **`PASS` (`exit_code = 0`, 4 fork files khớp patch)** |
| **Review Queue & Tamper Demo** | `python -m v2.triage.demo_queue` & `python -m v2.triage.demo_freshness` | **`PASS` (`exit_code = 0`, `1 -> 0 -> 1`, stale `exit_code = 2`)** |

---

## C. Bảng Kết quả Đối chứng Chính thức với `qwen3.5:9b-q4_K_M` (`SYNTHETIC SMOKE PILOT`, `n = 3`)

### 1. Phân biệt rõ Kiểm chứng Lịch sử (`REPLAY`) và Kiểm chứng Có Biên lai Mới (`LIVE`)
- **Bằng chứng `REPLAY` lịch sử đã khóa (trước `c36bc12`, giữ nguyên từng byte):**
  - Raw scan: `v2/demo/smoke_m1_rules_raw.opengrep.json` (`scan_sha256: 005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`).
  - Assessments: `v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl` (`SHA-256: dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5`).
  - Trạng thái `scan_provenance`: Do được thu thập trước khi có cơ chế `scan-manifest.json`, bản ghi không chứa trường `evidence.scan_provenance` (`HISTORICAL_UNBUNDLED`). Khi chấm điểm lịch sử (`score_pilot.py` mặc định), cả 3 cảnh báo đạt `3/3 SUPPORTED -> KEEP_TP` (`3/3 MATCHED`, độ trễ trung bình `13583.333 ms`). Khi chạy qua cổng biên lai nghiêm ngặt mới (`export_pilot.py` hoặc `score_pilot.py --require-scan-provenance`) mà không có `scan-manifest.json`, cả `3/3` cảnh báo bị hạ an toàn (fail-closed) về `REVIEW` và không được tự nâng cấp thành bằng chứng quét mới.
- **Bằng chứng `LIVE` mới có gắn `scan-manifest.json` (sau khi hợp nhất `c36bc12` + `f25ce45`):**
  - Thư mục bằng chứng ngoài Git: `C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25`
  - Raw scan mới: `live_scan\opengrep.json` (`scan_sha256: 4d628a214c737a99931ac51cce7f260bf3843b4f3610b3a5eb5a278bc919cfb9`) + `live_scan\scan-manifest.json` (`manifest_sha256: 77da87339e1c087879fb177c09b0a7fe00ec8e16ac77e5f145f94cd597d498d2`, `source_capture_verified = true`, `exit_capture_verified = true`).
  - Assessments mới: `triage_live_qwen35\assessments.jsonl` (`SHA-256: 939f0949d270a002b65b279510f830a63b065fa2286da1a6db37442e1e517d84`).
  - Kết quả: Đạt `3/3 SUPPORTED -> KEEP_TP` ngay cả khi bật `--require-scan-provenance` và `v2.triage.export_pilot`, `3/3 MATCHED`, `0/1` FP được đề xuất loại, `0/2` TP bị loại nhầm, `0/3` tự động xóa (`100% OPEN`), độ trễ trung bình `9479.333 ms` (`8063.0 ms`, `10406.0 ms`, `9969.0 ms`).

### 2. Bảng Đối chứng Chi tiết Từng Cảnh báo (`v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.csv`, `SHA-256: ed1d0b01e5473ffd9099cdb7151d795d1ed6291621d9ae7e15fc90cd66962b85`)

| Alert ID (`REPLAY` / `LIVE`) | Idx | CWE & Vị trí | Nhãn Kiểm chứng (`SYNTHETIC_GROUND_TRUTH`) | Nhánh A (OpenGrep) | Nhánh B (`qwen3.5:9b-q4_K_M`) | Kiểm chứng Trích dẫn (`qwen3.5:9b-q4_K_M`) | Độ trễ `REPLAY` / `LIVE` (`ms`) | Hàng đợi Con người | Tham chiếu (`qwen3:8b`) |
|---|---:|---|---|---|---|---|---|---|---|
| `5c3fa49a...` (`REPLAY`)<br>`35a3a20e...` (`LIVE`) | `0` | `CWE-89`<br>`SmokeVulnSample.java:28` | `TRUE_POSITIVE` | `KEEP` | `SUPPORTED` (`KEEP_TP`) | `MATCHED (lines=25,26,27,28; sha256=VERIFIED)` | `19719.0 ms` (`334` tok)<br>`8063.0 ms` (`347` tok) | `OPEN` | `SUPPORTED` -> `KEEP_TP` (`MATCHED`, `6719.0 ms`) |
| `76501a37...` (`REPLAY`)<br>`651f41b0...` (`LIVE`) | `1` | `CWE-22`<br>`SmokeVulnSample.java:33` | `TRUE_POSITIVE` | `KEEP` | `SUPPORTED` (`KEEP_TP`) | `MATCHED (lines=32,33; sha256=VERIFIED)` | `10953.0 ms` (`458` tok)<br>`10406.0 ms` (`441` tok) | `OPEN` | `SUPPORTED` -> `REVIEW` (`NOT_VERIFIED`, `8219.0 ms`) |
| `3252602f...` (`REPLAY`)<br>`0dbe51f1...` (`LIVE`) | `2` | `CWE-22`<br>`SmokeVulnSample.java:47` | `FALSE_POSITIVE` (`FilenameUtils.getName` d.46) | `KEEP` | **`SUPPORTED` (`KEEP_TP` - chưa loại được FP)** | `MATCHED (lines=45,46,47; sha256=VERIFIED)` | `10078.0 ms` (`409` tok)<br>`9969.0 ms` (`412` tok) | `OPEN` | `SUPPORTED` -> `REVIEW` (`NOT_VERIFIED`, `9641.0 ms`) |

| Chỉ số đối chứng bắt buộc (`SYNTHETIC SMOKE PILOT`, `n = 3`) | Nhánh A: OpenGrep 1.25.0 đơn lẻ | Nhánh B (`REPLAY` lịch sử đã khóa `005863f2...`) | Nhánh B (`LIVE` có `scan-manifest.json` `4d628a21...`) | Tham chiếu: OpenGrep 1.25.0 + `qwen3:8b` |
|---|---|---|---|---|
| **1. Tổng số cảnh báo & Nhãn kiểm chứng** | `3` (`2 TP`, `1 FP`) | `3` (`2 TP`, `1 FP`) | `3` (`2 TP`, `1 FP`) | `3` (`2 TP`, `1 FP`) |
| **2. Trạng thái `scan_provenance`** | `N/A` | `HISTORICAL_UNBUNDLED` (`REVIEW` nếu bật `--require-scan-provenance`) | **`VERIFIED_CAPTURE` (`source_capture_verified = true`)** | `HISTORICAL_UNBUNDLED` |
| **3. FP được đề xuất loại đúng / Tổng FP** | `0/1 (0.0%)` | **`0/1 (0.0%)`** (xếp FP dòng 47 là `SUPPORTED`) | **`0/1 (0.0%)`** (xếp FP dòng 47 là `SUPPORTED`) | `0/1 (0.0%)` (hạ về `UNDETERMINED -> REVIEW`) |
| **4. TP bị đề xuất loại nhầm / Tổng TP** | `0/2 (0.0%)` | **`0/2 (0.0%)`** (`2/2 KEEP_TP`) | **`0/2 (0.0%)`** (`2/2 KEEP_TP`) | **`0/2 (0.0%)`** (`1/2 KEEP_TP` + `1/2 REVIEW`) |
| **5. Tổng TP được giữ lại an toàn** | `2/2 (100.0%)` | **`2/2 (100.0%)`** | **`2/2 (100.0%)`** | **`2/2 (100.0%)`** |
| **6. Số cảnh báo ở trạng thái `REVIEW` / `UNDETERMINED`** | `0/3 (0.0%)` | **`0/3 (0.0%)`** (`3/3` nếu bật strict receipt gate) | **`0/3 (0.0%)`** (`3/3` khi ngắt Ollama để thử fail-safe) | `2/3 (66.7%)` (do cắt khoảng trắng đầu dòng) |
| **7. Tỷ lệ JSON hợp lệ & Trích dẫn `MATCHED`** | Không áp dụng | **`3/3 (100.0%)` JSON, `3/3 (100.0%) MATCHED`** | **`3/3 (100.0%)` JSON, `3/3 (100.0%) MATCHED`** | `3/3 (100.0%)` JSON, `1/3 (33.3%) MATCHED` |
| **8. Số cảnh báo tự động bị loại bỏ (`Auto-dismissed`)** | `0/3 (0.0%)` | **`0/3 (0.0%)`** (`100% state = OPEN`) | **`0/3 (0.0%)`** (`100% state = OPEN`) | **`0/3 (0.0%)`** (`100% state = OPEN`) |
| **9. Độ trễ suy luận trung bình (`Mean` / `P50` / `Max`)** | Không áp dụng | **`13583.333 ms`** \| `10953.0 ms` \| `19719.0 ms` | **`9479.333 ms`** \| `9969.0 ms` \| `10406.0 ms` | `8193.0 ms` \| `8219.0 ms` \| `9641.0 ms` |

---

## D. Kết quả Kiểm chứng Demo Quy trình Kiểm duyệt Liên hoàn (`P0.3` - `PASS`)

Toàn bộ 7 bước kiểm duyệt theo yêu cầu đã được kiểm chứng thực tế qua `python -m v2.triage.demo_queue` (`evidence/repro_replay_20261111_c36_f25/queue_demo/queue-demo.json`) và `python -m v2.triage.demo_freshness`:
1. **Duyệt `confirm-false` với actor `SCRIPTED-DEMO`:** Chuyển cảnh báo giả sang `CONFIRMED_FALSE` (`exit_code = 0`).
2. **Ẩn khỏi hàng đợi mặc định (`queue`):** Số cảnh báo trong `python -m v2.triage queue --db $Db` giảm từ `1 -> 0` (trong `demo_queue.py`) và từ `3 -> 2` (trên `SmokeVulnSample.java`).
3. **Bảo toàn trong SQLite (`queue --all`, `show`, `history`):** `queue --all` vẫn trả đủ `1` và `3` bản ghi; `show` hiển thị `state = "CONFIRMED_FALSE"`; `history` ghi nhận `sequence = 1`, `actor = "SCRIPTED-DEMO"`, `action = "confirm-false"`, `source_version` và `evidence_sha256`.
4. **Mở lại (`reopen`):** `decide ... reopen --actor SCRIPTED-DEMO` (`exit_code = 0`) đưa trạng thái về `OPEN` và cảnh báo xuất hiện lại trong `queue` mặc định (`0 -> 1` và `2 -> 3`); `history` ghi nhận `sequence = 2`.
5. **Chặn xác nhận khi mã nguồn thay đổi SHA-256 sau lượt quét:** Khi thêm chú thích vào bản sao tệp Java (`AllowlistedQuery.java`: `aec52e68... -> b0c9daba...`; `SmokeVulnSample.java`: `090c9349... -> 10219f10...`), lệnh `decide ... confirm-false` bị từ chối với **`exit_code = 2`** (`UNDETERMINED / operation refused: source unavailable/changed; rescan required: source hash mismatch`), lịch sử `history` giữ nguyên `2` sự kiện.

---

## E. Lệnh Tái lập Toàn trình Đã Xác minh (`exit_code = 0`)

```powershell
Set-Location "C:\Users\Admin\ntk-thesis-v2\integration-pilot"
$env:PATH = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0;$env:PATH"

# 1. Kiểm chứng chính sách kho mã, patch upstream (4 fork files), toàn bộ 162 Unit Tests và 11 cổng tích hợp -> exit_code = 0
python scripts/verify-repository.py
python v2/baseline/verify_patch.py
python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q
python v2/scripts/run_v2_quality_gate.py

# 2. Chạy tái lập chế độ REPLAY (dùng bằng chứng đã lưu, kiểm chứng khớp scan_sha256, không gọi lại Qwen) -> exit_code = 0
$ReplayDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_replay_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "v2\demo\reproduce_integration_pilot.ps1" `
  -Mode REPLAY `
  -EvidenceRoot $ReplayDir

# 3. Chạy tái lập chế độ LIVE (quét mới OpenGrep 1.25.0 + scan-manifest.json + gọi thật Ollama Qwen3.5:9b-q4_K_M) -> exit_code = 0
$LiveDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "v2\demo\reproduce_integration_pilot.ps1" `
  -Mode LIVE `
  -SkipHeavyDemos `
  -EvidenceRoot $LiveDir
```

---

## F. Phân loại Trạng thái Thực hiện & Giới hạn Còn Tồn tại

| Hạng mục yêu cầu | Trạng thái | Ghi chú & Giới hạn kỹ thuật |
|---|---|---|
| **1. Tách và chuẩn hóa Scanner/CLI `simple_semgrepAI` -> `OpenGrep 1.25.0` + `scan-manifest.json`** | **HOÀN THÀNH (`PASS`)** | Bảo toàn 6 blob upstream bằng `-text` trong `.gitattributes`; `verify_patch.py` (4 fork files), `verify_handoff.py` và `27/27` bài test M1 đạt `PASS`. |
| **2. Chạy toàn bộ ứng dụng `simple_semgrepAI` upstream đầy đủ (Web/RAG/Cloud)** | **HOÀN THÀNH MỘT PHẦN (`PENDING` full app)** | Chỉ kế thừa và chạy thật tầng scanner/CLI; tầng FastAPI web, ChromaDB RAG và LangChain cloud LLM của upstream chưa chạy thành công do xung đột phụ thuộc và không dùng trong kiến trúc cục bộ. |
| **3. Suy luận cục bộ `qwen3.5:9b-q4_K_M` (`REPLAY` & `LIVE`) + Bảng đối chứng A/B** | **HOÀN THÀNH (`PASS` trên `SYNTHETIC SMOKE PILOT`, `n = 3`; runtime `OLLAMA_REPORTED_UNATTESTED`)** | Đã chạy thật cả `REPLAY` và `LIVE` có `scan-manifest.json` trên RTX 4060 Ti 16 GB (`3/3 SUPPORTED`, `3/3 MATCHED`, `0/2` TP bị loại nhầm, `0/1` FP được đề xuất loại do mô hình yêu cầu thêm whitelist tên tệp). Cờ `independently_verified_model_runtime = false` giữ nguyên vì HTTP cục bộ không tự chứng thực phần cứng độc lập. |
| **4. Demo quy trình kiểm duyệt liên hoàn (`confirm-false -> ẩn -> --all/history -> reopen -> chặn khi đổi SHA-256`)** | **HOÀN THÀNH (`PASS`)** | Đã xác minh toàn trình sau merge qua `demo_queue.py`, `demo_freshness.py` và `70/70` bài test M2/M3. |
| **5. Đặt workflow `.github/workflows/v2-quality-gate.yml` lên GitHub Actions** | **BLOCKED (thiếu quyền OAuth `workflow`)** | Token GitHub trong keyring máy chủ hiện chỉ có scope `gist, read:org, repo` (thiếu `workflow`), nên GitHub từ chối push vào `.github/workflows/`. Đặc tả được lưu tại `v2/workflows/v2-quality-gate.yml` và thực thi tự động qua `v2/scripts/run_v2_quality_gate.py` + Git `pre-push` hook trên worktree tích hợp. |
| **6. Quét dự án Java thực tế (`P0.4`) & Đánh giá độc lập 30-60 cảnh báo / OWASP Benchmark** | **CHƯA LÀM (`NOT DONE`)** | Sẽ thực hiện ở giai đoạn thực nghiệm M4 kế tiếp theo thiết kế trong `v2/evaluation/INDEPENDENT_EVALUATION_AUDIT_20261111.md`. |
