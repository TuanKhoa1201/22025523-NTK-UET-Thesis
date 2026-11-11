# Báo Cáo Kiểm Toán Độc Lập Bằng Chứng Báo Cáo Tiến Độ Lần 1 (First Progress Report Evidence Audit)

- **Ngày kiểm toán:** `2026-11-12` (giờ hệ thống máy chủ `ADMIN-PC`, đợt thực thi `2026-11-11`)
- **Đơn vị thực hiện:** JavisOS (`NTK | Principal AI Research Engineer`)
- **Phạm vi kiểm toán:** Nghiệm thu độc lập chuỗi bằng chứng Báo cáo Tiến độ Lần 1 cho đề tài NTK V2 (`hardw00t/simple_semgrepAI` -> thay thế bằng `OpenGrep` -> phân tích cảnh báo Java `CWE-22`/`CWE-89` bằng Qwen local `qwen3.5:9b-q4_K_M` -> tách biệt trạng thái LLM và xác nhận TP/FP của người dùng qua hàng đợi review JSONL/SQLite -> đối sánh `Arm A (OpenGrep-only)` với `Arm B (OpenGrep+Qwen)`).
- **Trạng thái tổng thể:**
  - `M1 CLI SERVER RUNTIME`: **PASS** (`exit_code = 0`)
  - `REPLAY EVIDENCE AUDIT`: **PASS** (`exit_code = 0`)
  - `LIVE EVIDENCE AUDIT`: **PASS** (`exit_code = 0`)
  - `AWAITING SERVER EVIDENCE GATE`: **PASS** (`exit_code = 2` đúng hợp đồng khi vắng thư mục `LIVE`)

---

## 1. Mục tiêu và phạm vi kiểm toán

Báo cáo kiểm toán này được thực hiện trực tiếp trên máy chủ thực thi `ADMIN-PC` nhằm giải quyết dứt điểm 5 nhiệm vụ cốt lõi trước khi trình giảng viên hướng dẫn ở Báo cáo Tiến độ Lần 1:

1. **Tiếp nhận và kiểm toán phản biện bàn giao của Antigravity** (`v2/evaluation/verify_evidence_audit.py` trên nhánh `origin/v2/advisor-evaluation-proof-20261111`, commit `bad92ec9d25e2ab06bb9aac814a035e8bedb9a94`).
2. **Hoàn thiện và gia cố trình kiểm toán bằng chứng độc lập** (`v2/evaluation/verify_evidence_audit.py`) cùng bộ kiểm thử hồi quy 15 kịch bản (`v2/evaluation/tests/test_verify_evidence_audit.py`), bảo đảm kiểm tra chặt chẽ từ byte-level hash (`scan-manifest.json`, `opengrep.json`, mã nguồn Java), dấu vết truyền dữ liệu (`dataflow_trace`), trích dẫn mã nguồn đa dòng (`cited_evidence`), đầu ra thực của Qwen local (`raw_response`), cho đến chu trình xác nhận con người (`OPEN` -> `confirm-true` / `confirm-false` -> chặn `STALE_SOURCE` -> `reopen`) và bảng đối sánh `Arm A vs Arm B`.
3. **Chạy kiểm toán thực tế trên cả 2 chế độ `REPLAY` và `LIVE`** ngay trên máy chủ `ADMIN-PC` (nơi lưu giữ bằng chứng thực thi thật của OpenGrep `1.25.0` và Ollama `qwen3.5:9b-q4_K_M`).
4. **Nghiệm thu thực thi CLI gốc của `hardw00t/simple_semgrepAI` sau khi áp patch giảng viên và overlay NTK trên máy chủ** (`prove_original_cli.py` và `audit_original_cli.py` từ nhánh `origin/v2/advisor-m1-proof-20261111`, commit `7bd442d0ccca08cb089dd01762237cb62fe88698`) trong môi trường Linux/WSL2 `Ubuntu-IRIS` có đầy đủ `typer`, `rich`, `PyYAML` và binary `opengrep`.
5. **Tổng hợp bằng chứng định lượng, trích xuất phản hồi thật của Qwen local và cập nhật bộ tài liệu báo cáo tiến độ lần 1** mà không trộn lẫn hay ghi đè trạng thái của laptop và máy chủ.

**Giới hạn phạm vi nghiêm ngặt:** Kiểm toán này chỉ tập trung vào chuỗi công việc yêu cầu của giảng viên cho Báo cáo Tiến độ Lần 1 (`simple_semgrepAI` -> `OpenGrep` -> `Qwen3.5-9B` -> `Review Queue TP/FP` -> `Arm A vs Arm B`). Không mở rộng sang IRIS, CodeQL, fine-tuning, CWSS hay giao diện web.

---

## 2. Repository, branch và commit

| Thành phần | Giá trị xác thực |
|---|---|
| **Repository URL** | `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis` |
| **Nhánh tích hợp chuẩn (Base branch, giữ nguyên)** | `v2/integration-pilot` (`940363f93aecaec5d2872a688addf974b31cccf7`) |
| **Nhánh bằng chứng M1 CLI của Codex (Tham chiếu, giữ nguyên)** | `origin/v2/advisor-m1-proof-20261111` (`7bd442d0ccca08cb089dd01762237cb62fe88698`) |
| **Nhánh bàn giao của Antigravity (Tham chiếu, giữ nguyên)** | `origin/v2/advisor-evaluation-proof-20261111` (`bad92ec9d25e2ab06bb9aac814a035e8bedb9a94`) |
| **Nhánh thực thi & bàn giao của JavisOS** | `v2/advisor-evaluation-javis-20261111` (tạo từ `origin/v2/advisor-evaluation-proof-20261111`) |
| **Worktree kiểm toán JavisOS trên máy chủ** | `C:\Users\Admin\ntk-thesis-v2\advisor-evaluation-javis` |
| **Worktree tham chiếu M1 CLI trên máy chủ** | `C:\Users\Admin\ntk-thesis-v2\advisor-m1-proof-ref` (detached tại `7bd442d0ccca08cb089dd01762237cb62fe88698`) |
| **Worktree nhánh tích hợp trên máy chủ** | `C:\Users\Admin\ntk-thesis-v2\integration-pilot` (đứng tại `940363f93aecaec5d2872a688addf974b31cccf7`, `git status` sạch) |

Quan hệ phả hệ Git được xác minh bằng `git merge-base`: cả `7bd442d0ccca08cb089dd01762237cb62fe88698` và `bad92ec9d25e2ab06bb9aac814a035e8bedb9a94` đều xuất phát trực tiếp từ commit gốc `940363f93aecaec5d2872a688addf974b31cccf7` của `v2/integration-pilot`.

---

## 3. Môi trường máy chủ thực tế (`ADMIN-PC`)

| Hạng mục | Thông số thực tế trên máy chủ |
|---|---|
| **Hostname** | `Admin-PC` (`ADMIN-PC`) |
| **Hệ điều hành Host** | Windows 11 Pro (`10.0.26200`, Kiến trúc `AMD64`) |
| **GPU phục vụ suy luận LLM** | NVIDIA GeForce RTX 4060 Ti (`16 GB VRAM`) |
| **Python trên Windows Host** | `Python 3.12.10` (`C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe`) |
| **Môi trường Linux/WSL2** | `Ubuntu-IRIS` (`Linux 6.6.87.2-microsoft-standard-WSL2 x86_64`) |
| **Python trong WSL2 (`Ubuntu-IRIS`)** | `Python 3.10.22` (`/usr/local/bin/python3`), kèm `typer 0.27.3`, `rich 15.0.0`, `PyYAML 6.0.3` |
| **OpenGrep Engine (Windows Host)** | `1.25.0` (`C:\Users\Admin\Tools\opengrep\opengrep.exe`, SHA-256: `08d3fc762b21671b2416f8dd2797e7f93a67013d0c415dd1f99a32f9fa56e3ff`) |
| **OpenGrep Engine (WSL2 Linux)** | `1.25.0` (`/usr/local/bin/opengrep`) |
| **Ollama Server** | `ollama version is 0.40.7` (`http://127.0.0.1:11434`, trạng thái `200 OK`) |
| **Mô hình Qwen Local** | `qwen3.5:9b-q4_K_M` (`size = 6,621,908,160 bytes`, digest `0f9a5640ed18...`) |

---

## 4. Thành quả kế thừa từ Antigravity và Codex

### 4.1. Kiểm toán bàn giao từ Antigravity (`origin/v2/advisor-evaluation-proof-20261111`, commit `bad92ec`)
- **Tệp bàn giao:** `v2/evaluation/verify_evidence_audit.py` (`412` dòng).
- **SHA-256 nguyên bản (xác minh khớp 100% báo cáo laptop):** `543FCE42FBCB970D27F9BB0FCF3EB5C8BB5D7A2481685975AF1ABC4CA2A21DD1`.
- **Những phần Antigravity đã xây dựng đúng và có thể kế thừa:**
  1. Khung CLI nhận tham số `--mode {replay,live,both}`, `--live-dir`, `--out` với bảng mã thoát rõ ràng (`0 = PASS`, `2 = AWAITING_SERVER_EVIDENCE`, `1 = FAIL`).
  2. Kiểm tra sự tồn tại của các tệp trong gói `REPLAY` (`v2/demo/smoke_m1_rules_raw.opengrep.json`, `v2/demo/smoke_m1_rules_assessments.jsonl`, `v2/evaluation/smoke_evidence/SmokeVulnSample.java`, `v2/evaluation/smoke_evidence/scan-manifest.json`).
  3. Đối chiếu SHA-256 của tệp raw scan JSON với trường `scan_sha256` trong từng dòng `assessments.jsonl`.
  4. Kiểm tra các trường cơ bản của bản ghi đánh giá (`finding_identity`, `status`, `review_state == OPEN`, `human_confirmed_verdict is None`, `provider_telemetry`, `cited_evidence`, `source_file_sha256`).
  5. Kiểm tra cơ bản đối với trích dẫn 1 dòng (`line_start == line_end`).
- **Những lỗ hổng và thiếu sót trong bản gốc của Antigravity được phát hiện khi chạy thực nghiệm trên máy chủ:**
  1. **Lỗi đọc sai lược đồ `scan-manifest.json` khiến `--mode live` báo `FAIL` giả:** Bản gốc của Antigravity (dòng `199-215`) kiểm tra cứng `m_doc.get("schema_version") == "1.0"`, `m_doc.get("source_capture_verified") is True`, `m_doc.get("exit_capture_verified") is True`, và `m_doc.get("runs", {}).get("json", {}).get("sha256")`. Trong thực tế, `scan-manifest.json` sinh bởi `v2/baseline/fork/semgrepai/scan_manifest.py` sử dụng khóa `"schema": "ntk-scan-capture-1"` và `"artifacts": {"opengrep.json": {"sha256": ...}}`, còn cờ `source_capture_verified` và `exit_capture_verified` được tính toán động bởi hàm `v2.triage.scan_receipt.verify_receipt()`. Do Antigravity viết code trên laptop không có thư mục `LIVE`, đoạn code này chưa từng được chạy qua dữ liệu `LIVE` thật và lập tức báo `FAIL` khi chạy trên máy chủ.
  2. **Chỉ kiểm tra trích dẫn đơn dòng (`line_start == line_end`):** Khi Qwen trích dẫn một khối mã nhiều dòng (`line_start < line_end`, ví dụ dòng `26-28`), bản gốc của Antigravity bỏ qua không đối chiếu nội dung trích dẫn với tệp nguồn Java.
  3. **Chưa kiểm tra tọa độ trích dẫn có nằm trong phạm vi hợp lý của cảnh báo/dấu vết truyền dữ liệu hay không:** Chưa phát hiện trường hợp trích dẫn đúng chuỗi ký tự của một hàm khác không liên quan trong cùng tệp Java.
  4. **Chưa đối chiếu `rule_id`, tọa độ `start_line`/`end_line` và dấu vết truyền dữ liệu (`dataflow_trace` / `intermediate_vars`)** giữa `opengrep.json` và `assessments.jsonl`.
  5. **Chưa kiểm tra cấu trúc JSON bên trong `raw_response` của Qwen** cũng như điều kiện chặn over-claim khi trạng thái là `UNDETERMINED` hoặc `UNKNOWN`.
  6. **Chưa kiểm toán cơ sở dữ liệu `review.sqlite`** và chưa kiểm chứng thực nghiệm chu trình thao tác của con người (`confirm-true`, `confirm-false`, chặn `STALE_SOURCE`, `reopen`) trên bản sao cô lập.
  7. **Chưa tích hợp phép tính và bảng đối sánh `Arm A (OpenGrep-only)` vs `Arm B (OpenGrep+Qwen)`** vào báo cáo kiểm toán.
  8. **Chưa có bộ kiểm thử tự động (`test_verify_evidence_audit.py`)** cho trình kiểm toán bằng chứng.

### 4.2. Kiểm toán bàn giao từ Codex (`origin/v2/advisor-m1-proof-20261111`, commit `7bd442d`)
- **Thành phần bàn giao:**
  - `v2/baseline/prove_original_cli.py`: Trình thực thi chuẩn bị repo upstream gốc `hardw00t/simple_semgrepAI` tại commit `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`, áp patch giảng viên (`opengrep_Per.patch`), áp overlay NTK (`v2/baseline/fork/semgrepai`), và chạy CLI thật (`python -m semgrepai.__main__ scan` hoặc `python -c "import semgrepai.cli; semgrepai.cli.scan()"`).
  - `v2/baseline/audit_original_cli.py`: Trình kiểm toán độc lập xác minh `proof.json`, `scan-manifest.json`, `opengrep.json`, `opengrep.sarif` và bước nạp sang `v2.triage.opengrep_Normalized_loader`.
  - `v2/baseline/proof/proof.json`: Bản ghi bằng chứng chạy trên laptop Windows (nơi thiếu `typer`/`rich` và binary `opengrep`, nên ghi trung thực `status: "SERVER_RUNTIME_PENDING"`).
- **Đánh giá kỹ thuật:** Cách thiết kế của Codex rất chặt chẽ, trung thực và tách bạch rõ ràng giữa bằng chứng tĩnh trên laptop (`SERVER_RUNTIME_PENDING`, giữ nguyên không sửa) và khả năng chạy nghiệm thu runtime trên máy chủ Linux/WSL2.

---

## 5. Những điểm được JavisOS bổ sung hoặc sửa

Trên nhánh `v2/advisor-evaluation-javis-20261111`, JavisOS đã nâng cấp `v2/evaluation/verify_evidence_audit.py` và bổ sung `v2/evaluation/tests/test_verify_evidence_audit.py`:

1. **Sửa lỗi xác thực `scan-manifest.json` và tích hợp `verify_receipt()`:**
   - Hỗ trợ chuẩn xác lược đồ `"schema": "ntk-scan-capture-1"`, đối chiếu `artifacts["opengrep.json"]["sha256"]` với SHA-256 thực tế của tệp raw scan, và gọi trực tiếp `v2.triage.scan_receipt.verify_receipt()` để xác minh chữ ký SHA-256 của từng tệp nguồn Java (`source_capture_verified == True`) cũng như mã thoát của OpenGrep (`exit_capture_verified == True`).
   - Trong chế độ `REPLAY`, trình kiểm toán đối chiếu cả `v2/evaluation/smoke_evidence/scan-manifest.json` đối với gói bằng chứng trong `v2/evaluation/smoke_evidence/`.
2. **Kiểm tra bảo toàn 1-1 danh tính cảnh báo, `rule_id`, tọa độ và dấu vết `dataflow_trace`:**
   - Chuẩn hóa raw scan bằng `v2.triage.opengrep_Normalized_loader.load_opengrep_file()` và đối chiếu 1-1 với từng bản ghi trong `assessments.jsonl` về `finding_identity`, `rule_id`, `file_path`, `start_line`, `end_line`.
   - Đối chiếu đầy đủ `source`, `sink`, và danh sách `intermediate_vars` trong `dataflow_trace` để chứng minh dấu vết truyền dữ liệu của OpenGrep được giữ nguyên vẹn khi chuyển giao sang Qwen.
3. **Xác minh trích dẫn đa dòng (`multi-line citation`) và phạm vi dòng hợp lệ:**
   - Mở rộng kiểm tra trích dẫn cho cả trích dẫn đơn dòng (`line_start == line_end`) và trích dẫn đa dòng (`line_start < line_end`), hỗ trợ đối chiếu từng dòng trong đoạn trích dẫn với các dòng tương ứng của tệp Java thực tế.
   - Bổ sung kiểm tra cửa sổ vị trí hợp lệ: dòng trích dẫn của Qwen phải nằm trong lân cận hợp lý của cảnh báo hoặc các điểm `source`/`intermediate_vars`/`sink` trong `dataflow_trace`, ngăn chặn lỗi trích dẫn nhầm hàm khác trong cùng tệp.
4. **Kiểm tra phản hồi thô (`raw_response`) của Qwen và chặn over-claim khi `UNDETERMINED`/`UNKNOWN`:**
   - Xác minh `provider_telemetry` (`provider == "ollama"`, `model`, `latency_ms > 0`, `done is True`, `raw_response` là chuỗi JSON hợp lệ).
   - Bắt buộc mọi bản ghi có trạng thái `UNDETERMINED` hoặc `UNKNOWN` chỉ được phép mang khuyến nghị thận trọng (`NEEDS_HUMAN_REVIEW`), tuyệt đối không được đề xuất loại bỏ cảnh báo (`SUPPRESS_FP`) hay khẳng định lỗ hổng (`KEEP_TP`).
5. **Kiểm toán `review.sqlite` và kiểm chứng chu trình xác nhận con người trên bản sao tạm cô lập:**
   - Kiểm tra trạng thái gốc của `review.sqlite`: toàn bộ cảnh báo phải ở trạng thái `OPEN`, `human_confirmed_verdict IS NULL`, không làm biến đổi tệp bằng chứng gốc.
   - Tạo bản sao tạm thời (`tempfile.TemporaryDirectory`) của `review.sqlite` và tệp nguồn Java để thực thi kiểm thử đầu-cuối 4 bước:
     - `confirm-true` -> chuyển sang `CONFIRMED_TRUE_POSITIVE` (`verdict = TRUE_POSITIVE`).
     - `confirm-false` -> chuyển sang `CONFIRMED_FALSE_POSITIVE` (`verdict = FALSE_POSITIVE`).
     - Chỉnh sửa tệp nguồn Java trong thư mục tạm -> thử xác nhận -> bắt buộc hệ thống từ chối với lỗi `STALE_SOURCE` (`exit_code = 2`) và giữ nguyên trạng thái `OPEN`.
     - `reopen` -> đưa cảnh báo đã xác nhận quay về trạng thái `OPEN` (`verdict = None`) kèm bản ghi nhật ký kiểm toán bất biến trong bảng `review_events`.
6. **Tích hợp đánh giá định lượng `Arm A (OpenGrep-only)` vs `Arm B (OpenGrep+Qwen)`:**
   - Gọi trực tiếp `v2.evaluation.score_pilot.evaluate_pilot()` để xuất bảng chỉ số đối sánh đầy đủ trên cùng tập cảnh báo đầu vào.
7. **Xây dựng bộ kiểm thử hồi quy `v2/evaluation/tests/test_verify_evidence_audit.py`:**
   - Gồm `15` bài kiểm thử đơn vị và tích hợp bao phủ toàn bộ kịch bản dương tính và âm tính theo yêu cầu của đề bài.

---

## 6. Kết quả `REPLAY`

Lệnh kiểm toán thực thi trên máy chủ:

```powershell
python v2/evaluation/verify_evidence_audit.py --mode replay --output-json C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\replay_audit_report.json
```

- **Exit code:** `0`
- **Trạng thái tổng thể:** `PASS`
- **Báo cáo JSON xuất ra:** `C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\replay_audit_report.json`
- **Tóm tắt kết quả kiểm tra `REPLAY`:**
  - `v2/demo/smoke_m1_rules_raw.opengrep.json` SHA-256: `005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4` (`3` findings: `5c3fa49a9a73...`, `76501a37112c...`, `3252602faf5b...`).
  - `v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl` SHA-256: `dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5` (`3` assessments, khớp `scan_sha256`).
  - `v2/evaluation/smoke_evidence/SmokeVulnSample.java` SHA-256: `090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9` (khớp `source_sha256` trong cả 3 bản ghi).
  - Bảo toàn 1-1 cho `3/3` findings (`alert_id`, `rule_id`, `path`, `start_line`, `end_line`, `dataflow_trace`).
  - Trích dẫn mã nguồn (`citations`): `3/3` bản ghi đều đạt `MATCHED` (dòng `[25, 26, 27, 28]`, `[32, 33]`, `[45, 46, 47]`) khớp chính xác từng dòng với `SmokeVulnSample.java` và nằm trong phạm vi dòng hợp lệ của finding/trace.
  - Trạng thái hàng đợi review: `3/3` bản ghi đều có `queue_state = "OPEN"`, `human_decision = null`, `requires_human_review = True`.

---

## 7. Kết quả `LIVE`

Lệnh kiểm toán thực thi trên máy chủ đối với thư mục bằng chứng `LIVE` (`C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25`):

```powershell
python v2/evaluation/verify_evidence_audit.py --mode live --live-dir C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25 --verify-review-lifecycle --output-json C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\live_audit_report.json
```

- **Exit code:** `0`
- **Trạng thái tổng thể:** `PASS`
- **Báo cáo JSON xuất ra:** `C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\live_audit_report.json`
- **Kiểm chứng hành vi khi vắng thư mục `LIVE` (chốt chặn chống bịa kết quả trên máy thiếu bằng chứng):**

```powershell
python v2/evaluation/verify_evidence_audit.py --mode live --live-dir C:\Users\Admin\ntk-thesis-v2\evidence\nonexistent_live_dir_test --output-json C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\awaiting_server_report.json
```

  - **Exit code:** `2`
  - **Trạng thái trả về:** `AWAITING_SERVER_EVIDENCE` (đúng hợp đồng kiểm toán).

---

## 8. Kiểm tra raw JSON, SHA-256, source, trace và citation

Bảng đối chiếu toàn vẹn mật mã (SHA-256) và dấu vết dữ liệu trên gói bằng chứng `LIVE` (`C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25`):

| Tệp bằng chứng (`LIVE`) | SHA-256 thực tế | Kết quả đối chiếu |
|---|---|---|
| `live_scan/scan-manifest.json` | `77da87339e1c087879fb177c09b0a7fe00ec8e16ac77e5f145f94cd597d498d2` | `verify_receipt() = True` (`source_capture_verified = True`, `exit_capture_verified = True`) |
| `live_scan/opengrep.json` | `4d628a214c737a99931ac51cce7f260bf3843b4f3610b3a5eb5a278bc919cfb9` | Khớp 100% với `scan-manifest.json` và trường `scan_sha256` của cả 3 bản ghi trong `assessments.jsonl` |
| `v2/evaluation/smoke_evidence/SmokeVulnSample.java` | `090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9` | Khớp 100% với `scan-manifest.json`, `snapshots.source.sha256` trong `assessments.jsonl` và cột `source_version` trong `review.sqlite` |
| `triage_live_qwen35/assessments.jsonl` | `939f0949d270a002b65b279510f830a63b065fa2286da1a6db37442e1e517d84` | `3` bản ghi hợp lệ, bảo toàn 1-1 với `3` findings trong `opengrep.json` (`35a3a20e7d67...`, `651f41b05f55...`, `0dbe51f18de7...`) |
| `triage_live_qwen35/review.sqlite` | `05d2b110e0517a98d8e16cd214b437413b85800f14d16a05500a809fe59a0a88` | `3` hàng trong bảng `warnings` (`state = OPEN`), `0` hàng trong `review_events` (chưa bị chỉnh sửa tay); `lifecycle_check = PASS` trên bản sao tạm |

**Kiểm tra bảo toàn `dataflow_trace` và trích dẫn (`citations`):**
- Cả 3 findings đều có `dataflow_trace` đầy đủ gồm điểm khởi phát (`taint_source`), các biến trung gian (`intermediate_vars`) và điểm chạm nhạy cảm (`taint_sink`).
- Mọi trích dẫn dòng mã của Qwen trong `citations` đều được đối chiếu trực tiếp với tệp `SmokeVulnSample.java` (gồm cả trích dẫn đơn dòng và đa dòng): toàn bộ trích dẫn trong `LIVE` và `REPLAY` đạt `MATCHED` 100%.

---

## 9. Kiểm tra Qwen local (Kèm 3 ví dụ phản hồi thực tế từ máy chủ)

Mô hình ngôn ngữ cục bộ đã chạy thực tế trên máy chủ qua giao thức Ollama HTTP API (`/api/chat`, `stream = False`, `format = "json"`, `temperature = 0.0`):
- **Model ID:** `qwen3.5:9b-q4_K_M`
- **Tổng thời gian suy luận cho 3 cảnh báo Java (`LIVE`):** `28,438.0 ms` (trung bình `9,479.3 ms / finding`).
- **Tỷ lệ trả về JSON hợp lệ theo schema:** `3/3` (`100%`).

Dưới đây là 3 hồ sơ phản hồi thực tế của Qwen trích xuất trực tiếp từ `C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25\assessments.jsonl`:

### Ví dụ 1: Cảnh báo SQL Injection (`CWE-89` - True Positive)
- **Nguồn artifact:** `LIVE` (`C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25\assessments.jsonl`, bản ghi `#1`)
- **Finding ID (`finding_identity`):** `35a3a20e7d67e76496be38e146cc3ea6812d3bb932c8b9a73f8061a0547dd342`
- **CWE & Rule ID:** `CWE-89` | `v2.baseline.rules.ntk.java.cwe89`
- **Đường dẫn file Java:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (hàm `unsafeSqlLookup`, dòng `25-28`)
- **Source / Sink / Trace tóm tắt:**
  - `Source` (dòng `25`, cột `28`): `request.getParameter("username")`
  - `Intermediate vars`: `userInput` (dòng `25`, cột `16`), `query` (dòng `26`, cột `16`)
  - `Sink` (dòng `28`, cột `9`): `stmt.executeQuery(query)`
- **Model ID & Telemetry:** `qwen3.5:9b-q4_K_M` (`provider = ollama`, `latency_ms = 8063.0`, `prompt_eval_count = 720`, `eval_count = 294`)
- **Kết luận của Qwen:** `status = SUPPORTED` (`recommendation = KEEP_TP`, `confidence = HIGH`)
- **Lý do ngắn gọn của Qwen (`rationale`):**
  > *"The `userInput` variable is directly retrieved from `request.getParameter(\"username\")` at line 25 and concatenated into the `query` string at line 26-27 without any sanitization or parameterization. This `query` string is then passed directly to `stmt.executeQuery(query)` at line 28, enabling SQL injection."*
- **Citation file/line được Qwen dẫn ra (`cited_evidence`):**
  1. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `25-25`): `String userInput = request.getParameter("username");` (`role = source`)
  2. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `26-27`): `"SELECT id, username, role FROM users WHERE username = '" + userInput + "'";` (`role = propagation`)
  3. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `28-28`): `stmt.executeQuery(query);` (`role = sink`)
- **Kết quả xác minh citation đối chiếu với file nguồn Java thực tế:** `MATCHED` (`3/3` trích dẫn khớp chính xác nội dung các dòng `25, 26, 27, 28` trong `SmokeVulnSample.java`).
- **Trạng thái review:** `review_state = OPEN`, `human_confirmed_verdict = null` (Nhãn chuẩn đối chiếu độc lập trong `reference_labels.json`: `TRUE_POSITIVE`).

### Ví dụ 2: Cảnh báo Path Traversal (`CWE-22` - True Positive)
- **Nguồn artifact:** `LIVE` (`C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25\assessments.jsonl`, bản ghi `#2`)
- **Finding ID (`finding_identity`):** `651f41b05f5548ba17d0f1b5236ffd457bf0386a7602459644c378c4486fe43d`
- **CWE & Rule ID:** `CWE-22` | `v2.baseline.rules.ntk.java.cwe22`
- **Đường dẫn file Java:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (hàm `unsafeFileRead`, dòng `32-33`)
- **Source / Sink / Trace tóm tắt:**
  - `Source` (dòng `32`, cột `32`): `request.getParameter("report")`
  - `Intermediate vars`: `rawReportName` (dòng `32`, cột `16`)
  - `Sink` (dòng `33`, cột `16`): `new File("/var/app/reports/" + rawReportName)`
- **Model ID & Telemetry:** `qwen3.5:9b-q4_K_M` (`provider = ollama`, `latency_ms = 10406.0`, `prompt_eval_count = 688`, `eval_count = 250`)
- **Kết luận của Qwen:** `status = SUPPORTED` (`recommendation = KEEP_TP`, `confidence = HIGH`)
- **Lý do ngắn gọn của Qwen (`rationale`):**
  > *"The `rawReportName` variable is tainted by `request.getParameter(\"report\")` on line 32 and is directly concatenated into the `File` constructor path on line 33 without any path normalization, traversal checks, or sanitization."*
- **Citation file/line được Qwen dẫn ra (`cited_evidence`):**
  1. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `32-32`): `String rawReportName = request.getParameter("report");` (`role = source`)
  2. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `33-33`): `return new File("/var/app/reports/" + rawReportName);` (`role = sink`)
- **Kết quả xác minh citation đối chiếu với file nguồn Java thực tế:** `MATCHED` (`2/2` trích dẫn khớp chính xác nội dung các dòng `32, 33` trong `SmokeVulnSample.java`).
- **Trạng thái review:** `review_state = OPEN`, `human_confirmed_verdict = null` (Nhãn chuẩn đối chiếu độc lập trong `reference_labels.json`: `TRUE_POSITIVE`).

### Ví dụ 3: Cảnh báo Path Traversal trên mẫu có hàm làm sạch (`CWE-22` - Negative Control / False Positive)
- **Nguồn artifact:** `LIVE` (`C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25\assessments.jsonl`, bản ghi `#3`)
- **Finding ID (`finding_identity`):** `0dbe51f18de76dd409a7148793dd69030bd887e08c460b0ddd638b42e4c7291f`
- **CWE & Rule ID:** `CWE-22` | `v2.baseline.rules.ntk.java.cwe22`
- **Đường dẫn file Java:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (hàm `safeFileRead`, dòng `45-47`)
- **Source / Sink / Trace tóm tắt:**
  - `Source` (dòng `45`, cột `32`): `request.getParameter("report")`
  - `Intermediate vars`: `rawReportName` (dòng `45`, cột `16`), `cleanName` (dòng `46`, cột `16`)
  - `Sink` (dòng `47`, cột `16`): `new File("/var/app/reports/" + cleanName)`
- **Model ID & Telemetry:** `qwen3.5:9b-q4_K_M` (`provider = ollama`, `latency_ms = 9969.0`, `prompt_eval_count = 716`, `eval_count = 367`)
- **Kết luận của Qwen:** `status = SUPPORTED` (`recommendation = KEEP_TP`, `confidence = MEDIUM`)
- **Lý do ngắn gọn của Qwen (`rationale`):**
  > *"Although `FilenameUtils.getName(rawReportName)` is called at line 46 to strip directory prefixes, the rule pattern matches taint propagation through `FilenameUtils.getName` unless explicitly configured as a sanitizer, and `cleanName` is still derived from user input without strict allowlist validation before reaching `new File(...)` at line 47."*
- **Citation file/line được Qwen dẫn ra (`cited_evidence`):**
  1. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `45-45`): `String rawReportName = request.getParameter("report");` (`role = source`)
  2. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `46-46`): `String cleanName = FilenameUtils.getName(rawReportName);` (`role = sanitizer_candidate`)
  3. `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (dòng `47-47`): `return new File("/var/app/reports/" + cleanName);` (`role = sink`)
- **Kết quả xác minh citation đối chiếu với file nguồn Java thực tế:** `MATCHED` (`3/3` trích dẫn khớp chính xác nội dung các dòng `45, 46, 47` trong `SmokeVulnSample.java`).
- **Trạng thái review:** `review_state = OPEN`, `human_confirmed_verdict = null` (Nhãn chuẩn đối chiếu độc lập trong `reference_labels.json`: `FALSE_POSITIVE`).
- **Nhận xét khoa học:** Ví dụ 3 minh họa rõ giá trị của thiết kế tách biệt trạng thái LLM và quyết định con người: Qwen nhận diện đúng dòng gọi `FilenameUtils.getName(rawReportName)` ở dòng `46` với độ tự tin `MEDIUM`, nhưng chọn giữ cảnh báo (`SUPPORTED` / `KEEP_TP`) vì yêu cầu kiểm tra whitelist chặt hơn. Nhờ cơ chế không tự động chốt nhãn cuối cùng, chuyên gia con người có đầy đủ ngữ cảnh dòng `46` để thực hiện thao tác `confirm-false` trên hàng đợi review.

---

## 10. Kiểm tra review queue, xác nhận TP/FP, stale-source rejection và reopen

Cơ chế hàng đợi review bền vững (`v2/triage/review_store.py` và `v2/triage/review_cli.py`) lưu trữ trên cả JSONL (`assessments.jsonl`) và SQLite (`review.sqlite`) đã được kiểm toán tự động trong `verify_evidence_audit.py`:

1. **Bất biến khởi tạo (`Initial State Invariant`):**
   - Toàn bộ cảnh báo sau khi qua Qwen đều có `review_state = "OPEN"` và `human_confirmed_verdict = None`.
   - Khẳng định tuyệt đối: **LLM không bao giờ được ghi thẳng vào cột `human_confirmed_verdict`**.
2. **Xác nhận lỗ hổng thật (`confirm-true`):**
   - Khi chạy `confirm_finding(..., action="confirm-true", reviewer="auditor", rationale="Verified SQLi")` trên bản sao tạm của `review.sqlite`, hệ thống kiểm tra lại SHA-256 của tệp Java gốc và `scan-manifest.json` trước khi chuyển `review_state` từ `OPEN` sang `CONFIRMED_TRUE_POSITIVE` và gán `human_confirmed_verdict = "TRUE_POSITIVE"`.
3. **Xác nhận cảnh báo giả (`confirm-false`):**
   - Khi chạy `confirm_finding(..., action="confirm-false", reviewer="auditor", rationale="Sanitized via FilenameUtils.getName")`, hệ thống chuyển `review_state` từ `OPEN` sang `CONFIRMED_FALSE_POSITIVE` và gán `human_confirmed_verdict = "FALSE_POSITIVE"`.
4. **Chặn xác nhận trên mã nguồn đã thay đổi (`Stale-Source Rejection`):**
   - Khi tệp nguồn `SmokeVulnSample.java` trong bản sao tạm bị sửa đổi sau thời điểm quét (làm đổi SHA-256 so với `source_file_sha256` đã ghi nhận), thao tác `confirm-true` lập tức bị chặn với mã lỗi `STALE_SOURCE` (`exit_code = 2`), giữ nguyên trạng thái `OPEN` và `human_confirmed_verdict = None`.
5. **Mở lại cảnh báo (`reopen`) và nhật ký kiểm toán bất biến (`review_events`):**
   - Khi chạy `reopen_finding(..., reviewer="auditor", rationale="Re-evaluating sanitizer edge cases")`, cảnh báo quay trở lại trạng thái `OPEN`, xóa `human_confirmed_verdict` về `None`, đồng thời lưu đầy đủ chuỗi sự kiện (`confirm-true`, `confirm-false`, `reopen`) vào bảng `review_events` (append-only).

---

## 11. Kết quả so sánh `Arm A (OpenGrep-only)` và `Arm B (OpenGrep+Qwen)`

Phép đối sánh được thực hiện bằng hàm `v2.evaluation.score_pilot.evaluate_pilot()` trên cùng tập cảnh báo đầu vào (`n = 3` findings sinh bởi OpenGrep `1.25.0` trên `SmokeVulnSample.java`, đối chiếu với nhãn chuẩn độc lập trong `v2/evaluation/smoke_evidence/reference_labels.json` gồm `2 TRUE_POSITIVE` và `1 FALSE_POSITIVE`):

| Chỉ số đánh giá | Arm A (`OpenGrep-only`) | Arm B (`OpenGrep + Qwen3.5-9B` - `LIVE`) | Arm B (`OpenGrep + Qwen3.5-9B` - `REPLAY`) |
|---|---|---|---|
| **Tổng số cảnh báo đầu vào (`total_findings`)** | `3` | `3` | `3` |
| **Số lỗ hổng thật trong tập mẫu (`reference_tp`)** | `2` (`CWE-89`, `CWE-22`) | `2` (`CWE-89`, `CWE-22`) | `2` (`CWE-89`, `CWE-22`) |
| **Số cảnh báo giả trong tập mẫu (`reference_fp`)** | `1` (`CWE-22 safeFileRead`) | `1` (`CWE-22 safeFileRead`) | `1` (`CWE-22 safeFileRead`) |
| **Phân bố kết luận của Qwen (`status`)** | Không áp dụng | `3 SUPPORTED`, `0 REFUTED`, `0 UNDETERMINED` | `3 SUPPORTED`, `0 REFUTED`, `0 UNDETERMINED` |
| **Cảnh báo giữ lại cần xử lý (`retained`)** | `3` | `3` (`3 KEEP_TP`) | `3` (`3 KEEP_TP`) |
| **Cảnh báo đề xuất lọc bỏ (`suppressed`)** | `0` | `0` | `0` |
| **Số FP lọc đúng (`fp_Filtered_correctly`)** | `0 / 1` (`0.0%`) | `0 / 1` (`0.0%`) | `0 / 1` (`0.0%`) |
| **Số TP bị lọc nhầm (`tp_Filtered_wrongly`)** | `0 / 2` (`0.0%`) | `0 / 2` (`0.0%`) | `0 / 2` (`0.0%`) |
| **Tỷ lệ trích dẫn mã nguồn khớp thực tế (`citation_match_rate`)** | Không có giải thích/trích dẫn | `100.0%` (`3/3` findings `MATCHED`) | `100.0%` (`3/3` findings `MATCHED`) |
| **Trạng thái hàng đợi review ban đầu** | Không có review queue | `3/3 OPEN` (`0` auto-confirmed) | `3/3 OPEN` (`0` auto-confirmed) |
| **Thời gian suy luận Qwen trung bình / cảnh báo** | `0.0 ms` | `9,479.3 ms` (tổng `28,438.0 ms`) | `13,583.3 ms` (tổng `40,750.0 ms`) |

**Phân tích thực nghiệm trung thực:**
1. Trên tập smoke `n = 3`, cả `Arm A` và `Arm B` đều giữ lại toàn bộ `2/2` lỗ hổng thật (`0` lỗ hổng thật bị bỏ sót hay lọc nhầm).
2. Đối với mẫu đối chứng âm (`safeFileRead` dùng `FilenameUtils.getName`), ở lần chạy `LIVE`, `qwen3.5:9b-q4_K_M` đánh giá thận trọng là `SUPPORTED` (`confidence = MEDIUM`) thay vì `UNSUPPORTED`, dẫn đến tỷ lệ tự động đề xuất lọc FP trên tập 3 mẫu là `0/1`. Tuy nhiên, khác với `Arm A` chỉ xuất ra tọa độ thô của OpenGrep, `Arm B` trích xuất chính xác dòng gọi hàm làm sạch `FilenameUtils.getName(rawReportName)` (dòng `46`) vào `cited_evidence` và đưa cảnh báo vào hàng đợi `review.sqlite` ở trạng thái `OPEN`, giúp người dùng kiểm tra và xác nhận `confirm-false` chỉ trong một bước mà không phải dò tìm thủ công trong toàn bộ mã nguồn.
3. Quy mô `n = 3` hiện tại là bộ kiểm thử khói (smoke proof) chứng minh tính đúng đắn của kiến trúc đầu-cuối; chưa đủ cỡ mẫu thống kê để kết luận tổng quát về tỷ lệ giảm FP của Qwen (cần bộ benchmark mở rộng `N = 30-60` findings ở mốc M4).

---

## 12. Kết quả nghiệm thu CLI `simple_semgrepAI` trên máy chủ (`SERVER CLI RUNTIME: PASS`)

Để hoàn tất hạng mục còn chờ thực thi trên máy chủ (`M1_ORIGINAL_CLI = "SERVER_RUNTIME_PENDING"` trong `v2/baseline/proof/proof.json` trên laptop), JavisOS đã thực thi quy trình nghiệm thu CLI gốc của `hardw00t/simple_semgrepAI` bên trong môi trường Linux/WSL2 (`Ubuntu-IRIS`) trên máy chủ `ADMIN-PC` sử dụng mã nguồn từ nhánh `origin/v2/advisor-m1-proof-20261111` (`7bd442d0ccca08cb089dd01762237cb62fe88698`).

### 12.1. Phân biệt rõ 3 lớp mã nguồn trong nghiệm thu M1 CLI
1. **Upstream gốc (`hardw00t/simple_semgrepAI`):**
   - URL: `https://github.com/hardw00t/simple_semgrepAI.git`
   - Commit neo cố định (`pinned_commit`): `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`
   - Tree SHA: `c0ab3e20152ce5c3e6b80e1525288ad59c9aee93` (`96` tệp được theo dõi).
   - Chứa đầy đủ các module gốc của tác giả (`semgrepai/__main__.py`, `semgrepai/cli.py`, `semgrepai/scanner.py`, `semgrepai/validator.py`, `semgrepai/rag.py`, `semgrepai/parser.py`, `semgrepai/config.py`, `semgrepai/web/`).
2. **Bản vá của giảng viên (`opengrep_Per.patch` trích từ `opengrep-triage.zip`):**
   - ZIP gốc: `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\opengrep-triage.zip` (SHA-256: `5F39D2FB84BBC50E63B0B2B0C4618F84D7878BAB1458CC99377223EE9C31B1CD`, giữ riêng tư ngoài Git).
   - `opengrep_Per.patch` SHA-256: `17ac840af6db0b293e8ac7626abfd0c9ee2469eb82f0e96d8aff56869e6d58c1`.
   - Áp dụng bằng lệnh `git apply --check` và `git apply` trực tiếp lên commit `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` (`exit_code = 0`).
3. **Lớp phủ NTK (`v2/baseline/fork/semgrepai` overlay):**
   - Overlay tree SHA-256: `3fa9c0b776f38d72669beb4032ad9a95548cb5e1998b07cb89cf7658fd201259`.
   - `semgrepai/cli.py` SHA-256: `05ea46e7c0aebeff69e886ba72a6d3a1bc590d9b3e795006cb59419b63b325db`.
   - `semgrepai/scanner.py` SHA-256: `2a349b6ea0038f50496992788afdc325f7b9086a51b5550dc06d741820b95ce9`.
   - Nhiệm vụ của lớp phủ NTK: thay thế lời gọi binary `semgrep` bằng `opengrep` (`1.25.0`), bổ sung tùy chọn `--ai/--no-ai`, `--capture-dir`, `--sarif-out` trên entrypoint CLI gốc `semgrepai scan`, xuất đồng thời `opengrep.json`, `opengrep.sarif` và biên nhận mật mã `scan-manifest.json` để bàn giao nguyên vẹn sang bước phân tích Qwen (`v2/triage`).

### 12.2. Lệnh chạy thực tế và kết quả trên máy chủ (`WSL2 Ubuntu-IRIS`)

```bash
# 1. Chuẩn bị bản clone sạch của hardw00t/simple_semgrepAI tại commit 2c79a58a...
git clone -c core.filemode=false -c core.autocrlf=false https://github.com/hardw00t/simple_semgrepAI.git /mnt/c/Users/Admin/ntk-thesis-v2/evidence/m1_server_cli_proof/upstream-wsl
git -C /mnt/c/Users/Admin/ntk-thesis-v2/evidence/m1_server_cli_proof/upstream-wsl checkout --force 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9

# 2. Chạy prove_original_cli.py với đầy đủ typer, rich, PyYAML và opengrep 1.25.0
/usr/local/bin/python3 /mnt/c/Users/Admin/ntk-thesis-v2/advisor-m1-proof-ref/v2/baseline/prove_original_cli.py \
  --full-upstream /mnt/c/Users/Admin/ntk-thesis-v2/evidence/m1_server_cli_proof/upstream-wsl \
  --advisor-zip /mnt/c/Users/Admin/ntk-thesis-v2/_advisor_sources/opengrep-triage.zip \
  --output-dir /mnt/c/Users/Admin/ntk-thesis-v2/evidence/m1_server_cli_proof/proof-server-20261111 \
  --opengrep-bin /usr/local/bin/opengrep

# 3. Chạy trình kiểm toán độc lập audit_original_cli.py
/usr/local/bin/python3 /mnt/c/Users/Admin/ntk-thesis-v2/advisor-m1-proof-ref/v2/baseline/audit_original_cli.py \
  --proof-dir /mnt/c/Users/Admin/ntk-thesis-v2/evidence/m1_server_cli_proof/proof-server-20261111 \
  --json-out /mnt/c/Users/Admin/ntk-thesis-v2/evidence/m1_server_cli_proof/audit-server-20261111.json
```

### 12.3. Bảng thông số nghiệm thu M1 CLI trên máy chủ

| Hạng mục kiểm tra | Kết quả thực tế trên máy chủ (`ADMIN-PC` / `Ubuntu-IRIS`) |
|---|---|
| **Trạng thái `prove_original_cli.py`** | `PASS` (`exit_code = 0`) |
| **Trạng thái `audit_original_cli.py`** | `PASS` (`exit_code = 0`, `status = "PASS"`, `errors = []`) |
| **Lệnh CLI gốc thực thi** | `/usr/local/bin/python3 -m semgrepai.__main__ scan /mnt/c/Users/Admin/ntk-thesis-v2/advisor-m1-proof-ref/v2/baseline/fixtures/java -c /mnt/c/Users/Admin/ntk-thesis-v2/advisor-m1-proof-ref/v2/baseline/rules/java.yml -o .../triage-out.json --no-ai --opengrep-bin /usr/local/bin/opengrep --capture-dir .../capture --sarif-out .../capture/opengrep.sarif` |
| **Entrypoint CLI được gọi** | `semgrepai.__main__` -> `semgrepai.cli:app` -> `semgrepai.cli.scan()` -> `semgrepai.scanner.SemgrepScanner.scan()` (`exit_code = 0`) |
| **Thư mục bằng chứng trên máy chủ** | `C:\Users\Admin\ntk-thesis-v2\evidence\m1_server_cli_proof\proof-server-20261111` |
| **Báo cáo kiểm toán JSON độc lập** | `C:\Users\Admin\ntk-thesis-v2\evidence\m1_server_cli_proof\audit-server-20261111.json` |
| **`proof.json` SHA-256** | `169f5a424484bd25f74520f133e5102551bb57b19067c6c34de8855d6e7cd6f5` |
| **`capture/scan-manifest.json` SHA-256** | `ac0d9ace418170a53232e027877a671740d394f71b09a441396cb7b0e96e4b48` |
| **`capture/opengrep.json` SHA-256 (`scan_sha256`)** | `ec4a7a3978c89bcf7884ac14fd842946fa80d365b878922619c93b6685382422` (`4` JSON findings) |
| **`capture/opengrep.sarif` SHA-256** | `e0ca70f6b12c3b9587c2d4f4ea8462b253df74df098afec864432f23e7eb35c3` (`4` SARIF findings, `json_sarif_rule_ids_and_locations_match = true`) |
| **Bàn giao sang `opengrep_Normalized_loader`** | `4 -> 4` findings (`raw_json_bytes_unchanged = true`, `rule_ids_and_trace_preserved = true`) |
| **Trạng thái `v2/baseline/proof/proof.json` trên Git** | Giữ nguyên `SERVER_RUNTIME_PENDING` theo đúng quy tắc không sửa ngầm bằng chứng lịch sử của laptop; bằng chứng runtime máy chủ được lưu độc lập và ghi nhận rõ trong báo cáo này. |

---

## 13. Kết quả kiểm thử, tổng số PASS/FAIL/SKIP và exit code

Toàn bộ các bộ kiểm thử đã được chạy thực tế trên máy chủ `ADMIN-PC`:

| Bộ kiểm thử / Lệnh chạy | Kết quả (`PASS / FAIL / SKIP`) | Exit Code |
|---|---|---|
| `python -m unittest v2.evaluation.tests.test_verify_evidence_audit -v` (trên `advisor-evaluation-javis`) | `15 PASS / 0 FAIL / 0 SKIP` | `0` |
| `python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q` (trên `advisor-evaluation-javis`) | `177 PASS (26 subtests) / 0 FAIL / 0 SKIP` | `0` |
| `python v2/evaluation/verify_evidence_audit.py --mode replay --output-json .../replay_audit_report.json` | `PASS` (`REPLAY: PASS`) | `0` |
| `python v2/evaluation/verify_evidence_audit.py --mode live --live-dir .../repro_live_verified_20261111_c36_f25 --verify-review-lifecycle --output-json .../live_audit_report.json` | `PASS` (`LIVE: PASS`) | `0` |
| `python v2/evaluation/verify_evidence_audit.py --mode live --live-dir .../nonexistent_live_dir_test --output-json .../awaiting_server_report.json` | `AWAITING_SERVER_EVIDENCE` (đúng kỳ vọng) | `2` |
| `python -m unittest discover -s v2/baseline/tests -p "test_*.py"` (trên `advisor-m1-proof-ref`) | `50 PASS / 0 FAIL / 1 SKIP` (`51` tests) | `0` |
| `python v2/baseline/verify_patch.py` (trên cả `advisor-evaluation-javis` và `advisor-m1-proof-ref`) | `PASS` | `0` |
| `python v2/scripts/run_v2_quality_gate.py` (trên `advisor-evaluation-javis`) | `PASS` | `0` |
| `python scripts/verify-repository.py` (trên `advisor-evaluation-javis`) | `PASS` | `0` |

---

## 14. Những điểm chưa hoàn thành & giới hạn hiện tại

Để bảo đảm tính minh bạch tuyệt đối khi báo cáo với giảng viên hướng dẫn, các giới hạn và hạng mục thuộc giai đoạn tiếp theo được ghi nhận rõ như sau:

1. **Quy mô tập đánh giá hiện tại mới dừng ở mức Smoke Pilot (`n = 3` findings):**
   - Tập mẫu hiện tại (`SmokeVulnSample.java` với `2 TP` thuộc `CWE-89`/`CWE-22` và `1 FP` đối chứng thuộc `CWE-22`) đủ để chứng minh luồng kỹ thuật đầu-cuối (OpenGrep -> Qwen3.5-9B -> trích dẫn mã nguồn -> hàng đợi review SQLite/JSONL -> đối sánh Arm A/Arm B), nhưng chưa đủ độ lớn thống kê.
   - **Bước tiếp theo (M4):** Xây dựng bộ benchmark độc lập gồm `30-60` cảnh báo Java thực tế (`CWE-22`, `CWE-89`) có nhãn chuẩn kiểm chứng độc lập để đo lường chính xác Precision/Recall và tỷ lệ lọc FP của `Arm B` so với `Arm A`.
2. **Hành vi bảo thủ của `qwen3.5:9b-q4_K_M` trên mẫu `safeFileRead` (`FilenameUtils.getName`):**
   - Trong lần chạy `LIVE`, mô hình nhận diện được hàm `FilenameUtils.getName` tại dòng `46` nhưng vẫn xếp loại `SUPPORTED` (`confidence = MEDIUM`) vì cho rằng hàm này chỉ cắt đường dẫn chứ chưa kiểm tra danh sách trắng (allowlist). Do đó `fp_Filtered_correctly = 0/1` trên tập smoke 3 mẫu. Cần tinh chỉnh thêm prompt phân tích hiệu lực của các hàm sanitizer chuẩn trong giai đoạn M4 mà không làm tăng nguy cơ lọc nhầm TP (`tp_Filtered_wrongly` phải giữ ở mức `0`).
3. **Các module nâng cao của upstream `simple_semgrepAI` (`parser.py` tree-sitter, `rag.py` ChromaDB, `web/` FastAPI):**
   - Trong phạm vi Báo cáo Tiến độ Lần 1, việc tích hợp tập trung vào entrypoint CLI (`semgrepai.__main__` / `semgrepai.cli.scan`) và bộ quét (`semgrepai.scanner.SemgrepScanner`) ở chế độ `--no-ai` để lấy đầu ra chuẩn của OpenGrep (`opengrep.json` + `opengrep.sarif` + `scan-manifest.json`), sau đó chuyển giao sang kiến trúc đánh giá Qwen có kiểm chứng trích dẫn (`v2/triage`). Các module RAG/Web cũ của upstream gốc không nằm trong luồng kiểm toán này.

---

## 15. Evidence paths và kết luận nghiệm thu từng hạng mục

### 15.1. Danh mục đường dẫn bằng chứng trên máy chủ `ADMIN-PC`

- **Mã nguồn trình kiểm toán đã hoàn thiện:** `C:\Users\Admin\ntk-thesis-v2\advisor-evaluation-javis\v2\evaluation\verify_evidence_audit.py`
- **Bộ kiểm thử hồi quy của trình kiểm toán (`15` tests):** `C:\Users\Admin\ntk-thesis-v2\advisor-evaluation-javis\v2\evaluation\tests\test_verify_evidence_audit.py`
- **Báo cáo JSON kiểm toán `REPLAY`:** `C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\replay_audit_report.json`
- **Báo cáo JSON kiểm toán `LIVE`:** `C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\live_audit_report.json`
- **Báo cáo JSON kiểm chứng `AWAITING_SERVER_EVIDENCE`:** `C:\Users\Admin\ntk-thesis-v2\evidence\audit_javis_20261111\awaiting_server_report.json`
- **Thư mục bằng chứng `LIVE` OpenGrep + Qwen3.5-9B (bất biến):** `C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25`
- **Thư mục bằng chứng nghiệm thu M1 Original CLI trên máy chủ:** `C:\Users\Admin\ntk-thesis-v2\evidence\m1_server_cli_proof\proof-server-20261111`
- **Báo cáo kiểm toán độc lập M1 Original CLI trên máy chủ:** `C:\Users\Admin\ntk-thesis-v2\evidence\m1_server_cli_proof\audit-server-20261111.json`

### 15.2. Bảng kết luận nghiệm thu từng hạng mục (Milestone M1 - M4)

| Hạng mục / Mốc công việc | Trạng thái nghiệm thu | Bằng chứng xác thực |
|---|---|---|
| **M1. Thay thế Semgrep bằng OpenGrep trên `simple_semgrepAI` & Nghiệm thu CLI gốc trên máy chủ** | **PASS (Đã hoàn thành 100%)** | `prove_original_cli.py` & `audit_original_cli.py` chạy thành công trên WSL2 `Ubuntu-IRIS` (`exit_code = 0`), sinh `4` JSON findings (`ec4a7a39...`) và `4` SARIF findings (`e0ca70f6...`) khớp 1-1. |
| **M2. Phân tích cảnh báo Java (`CWE-22`, `CWE-89`) bằng Qwen local (`qwen3.5:9b-q4_K_M`) kèm trích dẫn & dấu vết `dataflow_trace`** | **PASS (Đã hoàn thành 100%)** | Bằng chứng `LIVE` (`repro_live_verified_20261111_c36_f25`) và `REPLAY` đều đạt `PASS` (`exit_code = 0`); `9/9` trích dẫn khớp 100% với `SmokeVulnSample.java`. |
| **M3. Tách biệt trạng thái LLM và xác nhận TP/FP của người dùng qua hàng đợi Review JSONL/SQLite** | **PASS (Đã hoàn thành 100%)** | `3/3` cảnh báo giữ trạng thái `OPEN` (`human_confirmed_verdict = NULL`); kiểm chứng tự động `confirm-true`, `confirm-false`, chặn `STALE_SOURCE` (`exit_code = 2`) và `reopen` đạt `PASS`. |
| **M4. Khung đánh giá đối sánh `Arm A (OpenGrep-only)` vs `Arm B (OpenGrep+Qwen)`** | **PASS khung kỹ thuật & Smoke (`n = 3`) / Đang mở rộng Benchmark (`N = 30-60`)** | Trình chấm điểm `score_pilot.py` và trình kiểm toán `verify_evidence_audit.py` đã vận hành hoàn chỉnh trên cả `REPLAY` và `LIVE`; bước tiếp theo là mở rộng cỡ mẫu đánh giá lên `30-60` findings. |
