# BÁO CÁO TIẾN ĐỘ LẦN 1 - NTK THESIS V2 (OPENGREP + LOCAL QWEN TRIAGE)

- **Ngày báo cáo:** `2026-11-11`
- **Repository:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis`
- **Nhánh tích hợp:** `v2/integration-pilot` (Worktree độc lập tại `C:\Users\Admin\ntk-thesis-v2\integration-pilot`)
- **Các nhánh thành phần đã hợp nhất (`git merge --no-ff`):**
  - `origin/v2/codex-core`: `0c2ffa10c5f0d565325681e8ec2e33796fd4a68c` (M1 baseline scanner/patch + M2/M3 triage, SQLite queue hiding `CONFIRMED_FALSE`, `--path-map`, `demo_queue.py`, `verify_handoff.py`)
  - `origin/v2/antigravity-review`: `c061d7ff8a62d58e57ab368ecc6297a938cea28c` (M4/M5 evaluation, `score_pilot.py`, `codex_adapter.py`, `build_paired_pilot_table.py`, `smoke_m1_verified_labels.json`)
  - `origin/v2/javis-benchmark`: `43e1d648402704b9bc42698e62175805d720f7ff` (M0/M2 server environment, OpenGrep 1.25.0 + Ollama 0.40.7 + `qwen3.5:9b-q4_K_M` live GPU execution)
- **Bộ tài liệu bàn giao trong nhánh `v2/integration-pilot`:**
  - Bảng đối chứng A/B chính thức: `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.md` và `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.csv` (bản sao đồng bộ tại `v2/docs/ADVISOR_PAIRED_PILOT_20261111.md` và `.csv`)
  - Phụ lục nhiệm vụ gốc (bản ngắn mục tiêu 2-3 trang): `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.md`
  - Phụ lục nhiệm vụ gốc (bản kỹ thuật đầy đủ): `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_20261111.md`
  - Tin nhắn tóm tắt gửi giảng viên: `v2/docs/ADVISOR_MESSAGE_20261111.md`
  - Script tái lập tích hợp: `v2/demo/reproduce_integration_pilot.ps1`
- **Phạm vi báo cáo (4 phân định minh bạch):**
  1. **Scanner/CLI tinh gọn (`v2/baseline/fork/semgrepai/`) đã chạy thật.**
  2. **Toàn bộ ứng dụng `simple_semgrepAI` upstream đầy đủ (FastAPI web, ChromaDB RAG, LangChain cloud LLM) chưa chạy thành công.**
  3. **`OpenGrep 1.25.0` và `Qwen3.5:9b-q4_K_M` đã chạy thật trên mã nguồn Java tổng hợp (`SYNTHETIC SMOKE PILOT`, `n = 3`).**
  4. **Chưa có kết quả benchmark độc lập trên dự án Java thực tế hoặc OWASP Benchmark (`NOT DONE`).**

---

## A. Nhiệm vụ gốc (Upstream Inheritance & OpenGrep Replacement)

1. **Công cụ gốc (`simple_semgrepAI`):**
   - Nguồn upstream: `https://github.com/hardw00t/simple_semgrepAI`
   - Commit ghim cố định (Pinned Commit): `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` (phiên bản `0.2.0`, giấy phép `MIT`, Copyright 2025 hardw00t).
   - Lưu trữ đối chứng nguyên bản: `v2/baseline/upstream/` kèm tệp kiểm chứng Git blob SHA-1 `v2/baseline/upstream/PROVENANCE.json` (6 tệp gốc và `opengrep.patch` được bảo toàn nguyên vẹn từng byte bằng thuộc tính `-text` trong `v2/baseline/.gitattributes`).
2. **Thay đổi sang OpenGrep và Triage cục bộ:**
   - Bản fork tinh gọn tại `v2/baseline/fork/semgrepai/` (`scanner.py`, `config.py`, `cli.py`) và bản vá đối chiếu `v2/baseline/opengrep.patch` (kiểm chứng khứ hồi qua `python v2/baseline/verify_patch.py` đạt `PASS`).
   - Thay thế lời gọi `semgrep` bằng `opengrep scan` cục bộ với cờ `--json` / `--sarif`, `--dataflow-traces`, `--no-git-ignore`, `--disable-version-check`, `--jobs 1`.
   - Bảo toàn cấu trúc `extra.dataflow_trace` nguyên bản (`CliLoc`, `taint_source`, `intermediate_vars`, `taint_sink`) mà không tự suy diễn bước trung gian; kiểm chứng toàn vẹn byte và trace qua `python v2/baseline/verify_handoff.py` đạt `PASS`.
3. **Đối chiếu với gói tham khảo `opengrep-triage.zip` của giảng viên:**
   - Gói `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\opengrep-triage.zip` (`SHA-256: 5f39d2fb84bbc50e63b0b2b0c4618f84d7878bab1458cc99377223ee9c31b1cd`) đã được kiểm thử trong môi trường cô lập ngoài Git worktree (`evidence/p0_1_advisor_zip_isolated`), đạt `15/15 pytest PASS` và `git apply --check` đạt `PASS`.
   - Tệp `Bo_ma_OpenGrep_Java_Qwen.zip` được nhắc trong PDF 5 trang không có trong thư mục nguồn (**NOT PROVIDED**).

---

## B. Môi trường Thực thi & Kết quả Kiểm thử Tự động Sau Hợp nhất (`105/105 PASS`)

| Thành phần / Bộ kiểm thử | Thông số / Lệnh kiểm chứng thực tế | Kết quả (`PASS` / `FAIL` / `SKIP`) |
|---|---|---|
| **Hệ điều hành & Python** | Windows 11 Pro `10.0.26200` (`Python 3.12.10`) + WSL2 `Ubuntu-IRIS` (`Python 3.10.22`) | **PASS** |
| **GPU & Ollama Runtime** | `NVIDIA GeForce RTX 4060 Ti 16 GB` + `Ollama v0.40.7` (`127.0.0.1:11434`, `100% GPU`) | **PASS** |
| **OpenGrep Engine** | `OpenGrep 1.25.0` tại WSL2 `/usr/local/bin/opengrep` + cầu nối Windows `opengrep.cmd` | **PASS** |
| **Model Qwen chạy thật** | **`qwen3.5:9b-q4_K_M`** (`manifest SHA-256: 7dd7bb31...`) và **`qwen3:8b`** (`digest: 500a1f06...`) | **PASS** |
| **M1 Scanner Tests** | `python -m pytest v2/baseline/tests -v` | **`24 passed` (`14 subtests`), `0 failed`, `0 skipped` (`0.18s`)** |
| **M2/M3 Triage Tests** | `python -m pytest v2/triage/tests -v` | **`59 passed` (`12 subtests`), `0 failed`, `0 skipped` (`3.46s`)** |
| **M4/M5 Evaluation Tests** | `python -m pytest v2/evaluation/tests -v` | **`22 passed`, `0 failed`, `0 skipped` (`0.11s`)** |
| **Tổng cộng Unit Tests** | `python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests -v` | **`105 passed` (`26 subtests`), `0 failed`, `0 skipped`** |
| **Patch & Handoff Verification** | `python v2/baseline/verify_patch.py` & `python v2/baseline/verify_handoff.py` | **`PASS` (`exit_code = 0`)** |
| **Review Queue & Tamper Demo** | `python -m v2.triage.demo_queue` & `python -m v2.triage.demo_freshness` | **`PASS` (`exit_code = 0`, `1 -> 0 -> 1`, stale `exit_code = 2`)** |

---

## C. Bảng Kết quả Đối chứng Chính thức với `qwen3.5:9b-q4_K_M` (`SYNTHETIC SMOKE PILOT`, `n = 3`)

- **Đầu vào cố định:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (`SHA-256: 090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9`), bộ quy tắc `v2/baseline/rules/java.yml` (`SHA-256: f34e7b51880cc5baf4ff3cda47a16232c8d405b8fd5e65aaed1aa3745367d5aa`), raw scan `v2/demo/smoke_m1_rules_raw.opengrep.json` (`SHA-256: 005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`), nhãn kiểm chứng mã nguồn `v2/evaluation/smoke_m1_verified_labels.json` (`2 TP, 1 FP`).
- **Đầu ra suy luận `qwen3.5:9b-q4_K_M`:** `v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl` (bản sao nguyên vẹn của `C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\assessments.jsonl`, `SHA-256: dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5`).
- **Bảng đối chứng chi tiết từng cảnh báo (`v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.csv`, `SHA-256: ed1d0b01e5473ffd9099cdb7151d795d1ed6291621d9ae7e15fc90cd66962b85`):**

| Alert ID (`SHA256(scan_sha256:idx)`) | Idx | CWE & Vị trí | Nhãn Kiểm chứng (`SYNTHETIC_GROUND_TRUTH`) | Nhánh A (OpenGrep) | Nhánh B (`qwen3.5:9b-q4_K_M`) | Kiểm chứng Trích dẫn (`qwen3.5:9b-q4_K_M`) | Độ trễ (`ms`) / Tokens | Hàng đợi Con người | Tham chiếu (`qwen3:8b`) |
|---|---:|---|---|---|---|---|---|---|---|
| `5c3fa49a9a73...3672b0` | `0` | `CWE-89`<br>`SmokeVulnSample.java:28` | `TRUE_POSITIVE` | `KEEP` | `SUPPORTED` (`KEEP_TP`) | `MATCHED (lines=25,26,27,28; sha256=VERIFIED)` | `19719.0 ms` (`334` tok) | `OPEN` | `SUPPORTED` -> `KEEP_TP` (`MATCHED`, `6719.0 ms`) |
| `76501a37112c...a773e9` | `1` | `CWE-22`<br>`SmokeVulnSample.java:33` | `TRUE_POSITIVE` | `KEEP` | `SUPPORTED` (`KEEP_TP`) | `MATCHED (lines=32,33; sha256=VERIFIED)` | `10953.0 ms` (`458` tok) | `OPEN` | `SUPPORTED` -> `REVIEW` (`NOT_VERIFIED`, `8219.0 ms`) |
| `3252602faf5b...716249` | `2` | `CWE-22`<br>`SmokeVulnSample.java:47` | `FALSE_POSITIVE` (`FilenameUtils.getName` d.46) | `KEEP` | **`SUPPORTED` (`KEEP_TP` - chưa loại được FP)** | `MATCHED (lines=45,46,47; sha256=VERIFIED)` | `10078.0 ms` (`409` tok) | `OPEN` | `SUPPORTED` -> `REVIEW` (`NOT_VERIFIED`, `9641.0 ms`) |

| Chỉ số đối chứng bắt buộc (`SYNTHETIC SMOKE PILOT`, `n = 3`) | Nhánh A: OpenGrep 1.25.0 đơn lẻ | Nhánh B: OpenGrep 1.25.0 + `qwen3.5:9b-q4_K_M` (Mục tiêu) | Tham chiếu: OpenGrep 1.25.0 + `qwen3:8b` |
|---|---|---|---|
| **1. Tổng số cảnh báo & Nhãn kiểm chứng** | `3` (`2 TP` dòng 28, 33; `1 FP` dòng 47) | `3` (`2 TP` dòng 28, 33; `1 FP` dòng 47) | `3` (`2 TP` dòng 28, 33; `1 FP` dòng 47) |
| **2. FP được đề xuất loại đúng / Tổng FP** | `0/1 (0.0%)` | **`0/1 (0.0%)`** (mô hình xếp FP dòng 47 là `SUPPORTED`) | `0/1 (0.0%)` (hạ về `UNDETERMINED -> REVIEW`) |
| **3. TP bị đề xuất loại nhầm / Tổng TP** | `0/2 (0.0%)` | **`0/2 (0.0%)`** (cả 2 TP đều được giữ là `KEEP_TP`) | **`0/2 (0.0%)`** (`1/2 KEEP_TP` + `1/2 REVIEW`) |
| **4. Tổng TP được giữ lại an toàn** | `2/2 (100.0%)` | **`2/2 (100.0%)`** (`2/2 KEEP_TP`) | **`2/2 (100.0%)`** (`1/2 KEEP_TP` + `1/2 REVIEW`) |
| **5. Số cảnh báo ở trạng thái `REVIEW` / `UNDETERMINED`** | `0/3 (0.0%)` | **`0/3 (0.0%)`** (`3/3` khi ngắt kết nối Ollama để thử fail-safe) | `2/3 (66.7%)` (do cắt khoảng trắng đầu dòng) |
| **6. Tỷ lệ JSON hợp lệ & Trích dẫn `MATCHED`** | Không áp dụng | **`3/3 (100.0%)` JSON hợp lệ, `3/3 (100.0%) MATCHED`** | `3/3 (100.0%)` JSON hợp lệ, `1/3 (33.3%) MATCHED` |
| **7. Số cảnh báo tự động bị loại bỏ (`Auto-dismissed`)** | `0/3 (0.0%)` | **`0/3 (0.0%)`** (100% giữ `state = OPEN` chờ người duyệt) | **`0/3 (0.0%)`** |
| **8. Độ trễ suy luận trung bình (`Mean` / `P50` / `Max`)** | Không áp dụng | **`13583.333 ms`** (`13.583s`) \| `10953.0 ms` \| `19719.0 ms` | `8193.0 ms` (`8.193s`) \| `8219.0 ms` \| `9641.0 ms` |

---

## D. Kết quả Kiểm chứng Demo Quy trình Kiểm duyệt Liên hoàn (`P0.3` - `PASS`)

Sau khi hợp nhất `origin/v2/codex-core` (`0c2ffa1`), toàn bộ 7 bước kiểm duyệt theo yêu cầu đã được kiểm chứng thực tế qua `python -m v2.triage.demo_queue` (`evidence/p0_final_integration_20261111/queue_demo/queue-demo.json`) và chuỗi lệnh CLI trên bản sao độc lập của `SmokeVulnSample.java` (`evidence/p0_final_integration_20261111/smoke_m1_cli_workflow/`):
1. **Duyệt `confirm-false` với actor `SCRIPTED-DEMO`:** Chuyển cảnh báo giả sang `CONFIRMED_FALSE` (`exit_code = 0`).
2. **Ẩn khỏi hàng đợi mặc định (`queue`):** Số cảnh báo trong `python -m v2.triage queue --db $Db` giảm từ `1 -> 0` (trong `demo_queue.py`) và từ `3 -> 2` (trên `SmokeVulnSample.java`).
3. **Bảo toàn trong SQLite (`queue --all`, `show`, `history`):** `queue --all` vẫn trả đủ `1` và `3` bản ghi; `show` hiển thị `state = "CONFIRMED_FALSE"`; `history` ghi nhận `sequence = 1`, `actor = "SCRIPTED-DEMO"`, `action = "confirm-false"`, `source_version` và `evidence_sha256`.
4. **Mở lại (`reopen`):** `decide ... reopen --actor SCRIPTED-DEMO` (`exit_code = 0`) đưa trạng thái về `OPEN` và cảnh báo xuất hiện lại trong `queue` mặc định (`0 -> 1` và `2 -> 3`); `history` ghi nhận `sequence = 2`.
5. **Chặn xác nhận khi mã nguồn thay đổi SHA-256 sau lượt quét:** Khi thêm chú thích vào bản sao tệp Java (`AllowlistedQuery.java`: `aec52e68... -> b0c9daba...`; `SmokeVulnSample.java`: `090c9349... -> 10219f10...`), lệnh `decide ... confirm-false` bị từ chối với **`exit_code = 2`** (`UNDETERMINED / operation refused: source unavailable/changed; rescan required: source hash mismatch`), lịch sử `history` giữ nguyên `2` sự kiện.

---

## E. Lệnh Tái lập Toàn trình Đã Xác minh (`exit_code = 0`)

```powershell
Set-Location "C:\Users\Admin\ntk-thesis-v2\integration-pilot"
$ReproDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $ReproDir | Out-Null
$env:PATH = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0;$env:PATH"

# 1. Kiểm chứng patch upstream và chạy toàn bộ 105 bài Unit Test -> exit_code = 0
python v2/baseline/verify_patch.py
python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests -v

# 2. Chạy demo quy trình kiểm duyệt liên hoàn (confirm-false -> ẩn -> --all/show/history -> reopen -> chặn khi lệch SHA-256) -> exit_code = 0
python -m v2.triage.demo_queue --output-dir "$ReproDir\queue_demo"
python -m v2.triage.demo_freshness --output-dir "$ReproDir\freshness_demo"
python v2/baseline/verify_handoff.py --engine "$ReproDir\freshness_demo\run\engine" --triage "$ReproDir\freshness_demo\run"

# 3. Sinh bảng đối chứng A/B (.csv/.json) và chấm điểm từ bằng chứng Qwen3.5-9B đã lưu -> exit_code = 0
python v2/evaluation/build_paired_pilot_table.py `
  --opengrep "v2/demo/smoke_m1_rules_raw.opengrep.json" `
  --labels "v2/evaluation/smoke_m1_verified_labels.json" `
  --qwen35-triage "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl" `
  --qwen3-8b-reference "v2/demo/triage_qwen3_8b_summary.json" `
  --source-root "C:\Users\Admin\ntk-thesis-v2\integration-pilot" `
  --output-csv "$ReproDir\ADVISOR_PAIRED_PILOT_20261111.csv" `
  --output-json "$ReproDir\paired_pilot_summary.json"

$env:PYTHONPATH = "v2/evaluation"
python -m v2.evaluation.score_pilot `
  --opengrep "v2/demo/smoke_m1_rules_raw.opengrep.json" `
  --labels "v2/evaluation/smoke_m1_verified_labels.json" `
  --triage "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl" `
  --source-root "C:\Users\Admin\ntk-thesis-v2\integration-pilot" `
  --output-json "$ReproDir\score_pilot_verified.json" `
  --output-md "$ReproDir\score_pilot_verified.md"
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
```

---

## F. Phân loại Trạng thái Thực hiện & Giới hạn Còn Tồn tại

| Hạng mục yêu cầu | Trạng thái | Ghi chú & Giới hạn kỹ thuật |
|---|---|---|
| **1. Tách và chuẩn hóa Scanner/CLI `simple_semgrepAI` -> `OpenGrep 1.25.0`** | **HOÀN THÀNH (`PASS`)** | Bảo toàn 6 blob upstream bằng `-text` trong `.gitattributes`; `verify_patch.py`, `verify_handoff.py` và `24/24` bài test M1 đạt `PASS`. |
| **2. Chạy toàn bộ ứng dụng `simple_semgrepAI` upstream đầy đủ (Web/RAG/Cloud)** | **HOÀN THÀNH MỘT PHẦN** | Chỉ kế thừa và chạy thật tầng scanner/CLI; tầng FastAPI web, ChromaDB RAG và LangChain cloud LLM của upstream chưa chạy thành công do xung đột phụ thuộc và không dùng trong kiến trúc cục bộ. |
| **3. Suy luận cục bộ `qwen3.5:9b-q4_K_M` + Kiểm chứng trích dẫn & Bảng đối chứng A/B** | **HOÀN THÀNH (`PASS` trên `SYNTHETIC SMOKE PILOT`, `n = 3`)** | Đã chạy thật trên RTX 4060 Ti 16 GB (`3/3 SUPPORTED`, `3/3 MATCHED`, `0/2` TP bị loại nhầm, `0/1` FP được đề xuất loại do mô hình chưa tin tưởng hoàn toàn vào `FilenameUtils.getName`). |
| **4. Demo quy trình kiểm duyệt liên hoàn (`confirm-false -> ẩn -> --all/history -> reopen -> chặn khi đổi SHA-256`)** | **HOÀN THÀNH (`PASS`)** | Đã xác minh toàn trình sau merge qua `demo_queue.py`, `demo_freshness.py`, `59/59` bài test M2/M3 và chuỗi CLI trên bản sao `SmokeVulnSample.java`. |
| **5. Quét dự án Java thực tế (`P0.4`) & Đánh giá độc lập 30-60 cảnh báo / OWASP Benchmark** | **CHƯA LÀM (`NOT DONE`)** | Sẽ thực hiện ở giai đoạn thực nghiệm kế tiếp sau khi thống nhất phạm vi báo cáo tiến độ lần 1 với giảng viên. |
