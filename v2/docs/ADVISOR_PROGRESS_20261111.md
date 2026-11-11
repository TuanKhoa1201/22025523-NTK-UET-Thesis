# BÁO CÁO TIẾN ĐỘ LẦN 1 - NTK THESIS V2 (OPENGREP + LOCAL QWEN TRIAGE)

- **Ngày báo cáo:** `2026-11-11`
- **Repository:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis`
- **Nhánh tích hợp:** `v2/integration-pilot` (Worktree độc lập tại `C:\Users\Admin\ntk-thesis-v2\integration-pilot`)
- **Commit tích hợp cơ sở đã xác minh kiểm thử:** `fa6fa48c915e9fda0960f9f53579a101d4a32b25` (cập nhật phụ lục tại `d89d28dbd31ad09451311557d0ceca879c914940`)
- **Phụ lục nhiệm vụ gốc:**
  - Bản ngắn (mục tiêu 2-3 trang khi xuất tài liệu): `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.md`
  - Bản kỹ thuật đầy đủ: `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_20261111.md`
- **Phạm vi báo cáo:**
  1. **Scanner/CLI tinh gọn (`v2/baseline/fork/semgrepai/`) đã chạy thật.**
  2. **Toàn bộ ứng dụng `simple_semgrepAI` upstream đầy đủ (FastAPI web, ChromaDB RAG, LangChain cloud LLM) chưa chạy thành công.**
  3. **`OpenGrep 1.25.0` và `Qwen3.5:9b-q4_K_M` đã chạy thật trên mã nguồn Java tổng hợp (`SYNTHETIC SMOKE TEST`, `n = 3`).**
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
   - Bảo toàn cấu trúc `extra.dataflow_trace` nguyên bản (`CliLoc`, `taint_source`, `intermediate_vars`, `taint_sink`) mà không tự suy diễn bước trung gian.
3. **Đối chiếu với gói tham khảo `opengrep-triage.zip` của giảng viên:**
   - Gói `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\opengrep-triage.zip` (`SHA-256: 5f39d2fb84bbc50e63b0b2b0c4618f84d7878bab1458cc99377223ee9c31b1cd`) đã được kiểm thử trong môi trường cô lập ngoài Git worktree (`evidence/p0_1_advisor_zip_isolated`), đạt `15/15 pytest PASS` và `git apply --check` đạt `PASS`.
   - Tệp `Bo_ma_OpenGrep_Java_Qwen.zip` được nhắc trong PDF 5 trang không có trong thư mục nguồn (**NOT PROVIDED**).

---

## B. Môi trường Thực thi & Kết quả Kiểm thử Tự động (Tại Commit `fa6fa48`)

| Thành phần / Bộ kiểm thử | Thông số / Lệnh kiểm chứng thực tế | Trạng thái |
|---|---|---|
| **Hệ điều hành & Python** | Windows 11 Pro `10.0.26200` (`Python 3.12.10`) + WSL2 `Ubuntu-IRIS` (`Python 3.10.22`) | **PASS** |
| **GPU & Ollama Runtime** | `NVIDIA GeForce RTX 4060 Ti 16 GB` + `Ollama v0.40.7` (`127.0.0.1:11434`, `100% GPU`) | **PASS** |
| **OpenGrep Engine** | `OpenGrep 1.25.0` tại WSL2 `/usr/local/bin/opengrep` + cầu nối Windows `opengrep.cmd` | **PASS** |
| **Model Qwen chạy thật** | **`qwen3.5:9b-q4_K_M`** (`manifest SHA-256: 7dd7bb31...`) và **`qwen3:8b`** (`digest: 500a1f06...`) | **PASS** |
| **M1 Scanner Tests** | `python -m unittest discover -s v2/baseline/tests -v` | **24/24 PASS** (`0.181s`) |
| **M2/M3 Triage Tests** | `python -m unittest discover -s v2/triage/tests -v` | **51/51 PASS** (`2.335s`) |
| **M4/M5 Evaluation Tests** | `python -m unittest discover -s v2/evaluation/tests -v` | **20/20 PASS** (`0.020s`) |
| **Patch Verification** | `python v2/baseline/verify_patch.py` | **PASS** (`exit_code = 0`) |

---

## C. Thực nghiệm Đối chứng Sơ bộ với `qwen3.5:9b-q4_K_M` (`SYNTHETIC SMOKE TEST`, `n = 3`)

- **Đầu vào cố định:** `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (`SHA-256: 090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9`), bộ quy tắc `v2/baseline/rules/java.yml` (`SHA-256: f34e7b51880cc5baf4ff3cda47a16232c8d405b8fd5e65aaed1aa3745367d5aa`), raw scan `v2/demo/smoke_m1_rules_raw.opengrep.json` (`SHA-256: 005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`).
- **Bằng chứng suy luận `qwen3.5:9b-q4_K_M`:** `C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\assessments.jsonl` (`SHA-256: dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5`).

| Chỉ số đối chứng (`SYNTHETIC SMOKE TEST`, `n = 3`) | Nhánh A: OpenGrep 1.25.0 đơn lẻ | Nhánh B: OpenGrep 1.25.0 + `qwen3.5:9b-q4_K_M` (`v2.triage`) |
|---|---|---|
| **Tổng số cảnh báo & Nhãn thiết kế** | `3` (`2 TP` dòng 28, 33; `1 FP` dòng 47) | `3` (`2 TP` dòng 28, 33; `1 FP` dòng 47) |
| **Kết quả mô hình & Kiểm chứng trích dẫn** | Không áp dụng | **`3/3 SUPPORTED`**, **`3/3 citation_check = MATCHED`** |
| **FP được đề xuất loại đúng (`Proposed FP Removal`)** | `0/1 (0.0%)` | **`0/1 (0.0%)`** (mô hình xếp FP dòng 47 là `SUPPORTED`) |
| **TP bị đề xuất loại nhầm (`Erroneously Proposed TP Removal`)** | `0/2 (0.0%)` | **`0/2 (0.0%)`** (cả 2 TP đều được giữ lại) |
| **Số cảnh báo ở trạng thái `REVIEW` / `UNDETERMINED`** | `3/3` | **`0/3 (0.0%)`** (`3/3` khi ngắt kết nối Ollama để thử fail-safe) |
| **Số cảnh báo tự động bị loại bỏ (`Auto-dismissed`)** | `0` | **`0/3`** (100% giữ `state = OPEN` chờ người duyệt) |
| **Độ trễ suy luận trung bình (`elapsed_seconds`)** | Không áp dụng | **`13.583 giây/cảnh báo`** (tổng `40.750s`) |

---

## D. Lệnh Chấm điểm và Tái lập Đã Xác minh (`exit_code = 0`)

```powershell
Set-Location "C:\Users\Admin\ntk-thesis-v2\integration-pilot"
$ReproDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $ReproDir | Out-Null

# Chấm điểm từ bằng chứng đã lưu (không gọi lại Qwen, không ghi đè evidence gốc) -> exit_code = 0
$env:PYTHONPATH = "v2/evaluation"
python -m v2.evaluation.score_pilot `
  --opengrep "v2/demo/smoke_m1_rules_raw.opengrep.json" `
  --labels "C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\synthetic_fixture_labels_direct.json" `
  --triage "C:\Users\Admin\ntk-thesis-v2\evidence\p0_2_qwen35_live_smoke_m1\assessments.jsonl" `
  --source-root "C:\Users\Admin\ntk-thesis-v2\integration-pilot" `
  --output-json "$ReproDir\score_pilot_verified.json" `
  --output-md "$ReproDir\score_pilot_verified.md"
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
```

---

## E. Các Phần Đang Chờ Đồng bộ để Chốt Báo cáo Lần 1

1. **Chờ merge từ `v2/codex-core` (`commit 0c2ffa10c5f0d565325681e8ec2e33796fd4a68c`):** Bản sửa ẩn cảnh báo `CONFIRMED_FALSE` khỏi hàng đợi `queue` mặc định và hoàn tất kịch bản CLI liên hoàn (`confirm-false -> ẩn khỏi queue mặc định -> history -> reopen -> chặn khi đổi SHA-256`).
2. **Chờ hoàn tất và merge từ `v2/antigravity-review`:** Bảng đối chứng tổng hợp và trích xuất thời gian suy luận `elapsed_seconds -> latency_ms` trên nhánh đánh giá.
3. **Các hạng mục thực nghiệm giai đoạn tiếp theo (`NOT DONE`):** Quét thử nghiệm trên một dự án Java mã nguồn mở thực tế (`P0.4`) và đánh giá định lượng trên tập 30-60 cảnh báo độc lập / OWASP Benchmark.
