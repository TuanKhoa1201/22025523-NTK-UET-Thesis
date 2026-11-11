Em chào thầy ạ,

Em xin gửi thầy Báo cáo tiến độ lần 1 hoàn chỉnh (đã hợp nhất các bản cập nhật mới nhất của `v2/codex-core` `c36bc12`, `v2/antigravity-review` `f25ce45` và `v2/integration-pilot` `f92d5f9`), Bảng kết quả đối chứng A/B chính thức và Phụ lục nhiệm vụ gốc (Markdown + PDF) của khóa luận V2 (`simple_semgrepAI` -> `OpenGrep 1.25.0` + `Qwen3.5:9b-q4_K_M` cục bộ trên GPU RTX 4060 Ti 16 GB):

1. **Nhánh tích hợp & Bộ sản phẩm trên GitHub (`v2/integration-pilot`):**
   - Nhánh tích hợp: `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/tree/v2/integration-pilot` (đã hợp nhất `v2/codex-core` `c36bc120de2922413c53c26e42648b184ac3e5c7`, `v2/antigravity-review` `f25ce45a812a94198f09db7b296a2caf52174ca3` trên nền `f92d5f915c9dc9a34604efa29820e662fd7b616b`).
   - Bảng đối chứng A/B chính thức (`.md` & `.csv`): `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.md` và `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.csv` (bản sao đồng bộ tại `v2/docs/`).
   - Phụ lục nhiệm vụ gốc (bản ngắn mục tiêu 2-3 trang Markdown & PDF): `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.md` và `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_SHORT_20261111.pdf`
   - Phụ lục nhiệm vụ gốc (bản kỹ thuật đầy đủ): `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_20261111.md`
   - Báo cáo tiến độ, Báo cáo kiểm toán độc lập M4 & Script tái lập: `v2/docs/ADVISOR_PROGRESS_20261111.md`, `v2/evaluation/INDEPENDENT_EVALUATION_AUDIT_20261111.md`, `v2/demo/reproduce_integration_pilot.ps1`

2. **Kết quả nhiệm vụ gốc, Kiểm thử (`162/162 PASS`, `11/11` cổng tích hợp `PASS`) & Xin ý kiến thầy về phạm vi fork:**
   - Em đã trích xuất phần scanner/config/CLI từ `hardw00t/simple_semgrepAI` (`commit 2c79a58`) sang `OpenGrep 1.25.0` kèm biên lai quét `scan-manifest.json` (`ntk-scan-capture-1`), bảo toàn nguyên vẹn byte 6 tệp upstream bằng `-text` trong `v2/baseline/.gitattributes` (`verify_patch.py` PASS trên 4 tệp fork, `verify_handoff.py` PASS; toàn bộ **162/162 bài unit test** gồm `27/27` M1, `70/70` M2/M3, `28/28` Evaluation, `37/37` Quality Gate và `11/11` bước trong `run_v2_quality_gate.py` đều `PASS`) và kiểm thử cô lập gói `opengrep-triage.zip` của thầy (`15/15 pytest PASS`).
   - Toàn bộ ngăn xếp ứng dụng upstream đầy đủ (FastAPI web, ChromaDB RAG, LangChain cloud LLM) chưa chạy thành công (`PENDING / NOT DONE`) do xung đột phụ thuộc và không phù hợp với kiến trúc suy luận cục bộ có kiểm chứng trích dẫn. **Em xin phép hỏi ý kiến thầy để xác nhận phạm vi chỉ kế thừa và chuẩn hóa phần scanner/CLI tinh gọn (`v2/baseline/fork/semgrepai/`) thay vì duy trì toàn bộ ứng dụng web/RAG của upstream ạ.**

3. **Bảng đối chứng A/B trên mã Java tổng hợp (`SmokeVulnSample.java`, `SYNTHETIC SMOKE PILOT`, `n = 3` - Cả `REPLAY` lịch sử và `LIVE` có `scan-manifest.json`) & Demo Kiểm duyệt Liên hoàn (`PASS`):**

| Cảnh báo (`v2/baseline/rules/java.yml`) | Nhãn Kiểm chứng (`SYNTHETIC`) | Nhánh A (OpenGrep) | Nhánh B (`qwen3.5:9b-q4_K_M`: `REPLAY` / `LIVE`) | Kiểm chứng Trích dẫn & Hàng đợi |
|---|---|---|---|---|
| **#0 (`5c3fa49a...` / `35a3a20e...`):** `CWE-89` - Dòng 28 (`unsafeSqlLookup`) | `TRUE_POSITIVE` | `KEEP` | `SUPPORTED` (`KEEP_TP`, `19719.0 ms` / `8063.0 ms`) | `MATCHED` (dòng 25-28), `OPEN` |
| **#1 (`76501a37...` / `651f41b0...`):** `CWE-22` - Dòng 33 (`unsafeFileRead`) | `TRUE_POSITIVE` | `KEEP` | `SUPPORTED` (`KEEP_TP`, `10953.0 ms` / `10406.0 ms`) | `MATCHED` (dòng 32-33), `OPEN` |
| **#2 (`3252602f...` / `0dbe51f1...`):** `CWE-22` - Dòng 47 (`safeFileRead`) | `FALSE_POSITIVE` | `KEEP` | **`SUPPORTED` (Chưa đạt - xếp FP là TP, `10078.0 ms` / `9969.0 ms`)** | `MATCHED` (dòng 45-47), `OPEN` |

- **Chỉ số tổng hợp (`n = 3`):** `2 TP, 1 FP`; **FP được đề xuất loại đúng: `0/1 (0.0%)`** (ở dòng 47 mô hình nhận ra có `FilenameUtils.getName` tại dòng 46 nhưng vẫn bảo thủ yêu cầu thêm whitelist tên tệp nên xếp `SUPPORTED`); **TP bị đề xuất loại nhầm: `0/2 (0.0%)`**; **`3/3 SUPPORTED` và `3/3 MATCHED`**; **`0/3` cảnh báo tự động bị loại bỏ** (`100%` giữ `state = OPEN`); độ trễ trung bình **`13583.333 ms` (`REPLAY`, có cold-load)** và **`9479.333 ms` (`LIVE`, warm GPU)**.
- **Phân định `scan_provenance` (`REPLAY` vs `LIVE`) & Runtime Attestation:** Bản `REPLAY` lịch sử (`005863f2...`) được thu thập trước khi có `scan-manifest.json` nên được phân loại là `HISTORICAL_UNBUNDLED` (bị hạ về `REVIEW` nếu bật cờ nghiêm ngặt `--require-scan-provenance`); bản `LIVE` mới (`4d628a21...`, `manifest_sha256: 77da8733...`) có `scan-manifest.json` hợp lệ (`source_capture_verified = true`, `VERIFIED_CAPTURE`) nên giữ nguyên `3/3 KEEP_TP` qua cả `export_pilot.py` và `score_pilot.py --require-scan-provenance`. Trạng thái giao thức runtime Ollama là `OLLAMA_REPORTED_UNATTESTED` (`independently_verified_model_runtime = false` theo thiết kế).
- **Demo quy trình kiểm duyệt liên hoàn (`demo_queue.py`, `demo_freshness.py` & CLI 7 bước):** Đã kiểm chứng thành công toàn trình với actor `SCRIPTED-DEMO`: `confirm-false` -> ẩn khỏi `queue` mặc định (`1 -> 0` và `3 -> 2`) -> vẫn giữ trong SQLite (`queue --all`, `show`, `history`) -> `reopen` xuất hiện lại (`0 -> 1` và `2 -> 3`) -> sửa tệp Java sau khi quét làm đổi SHA-256 thì thao tác `confirm-false` bị chặn (`exit_code = 2: source hash mismatch; rescan required`), lịch sử `history` không bị thay đổi.
- **Giới hạn hiện tại (`NOT DONE` / `BLOCKED`):** Chưa có kết quả quét trên dự án Java thực tế (`P0.4`) và chưa chạy benchmark độc lập 30-60 cảnh báo trên OWASP Benchmark (`NOT DONE`). Tệp `.github/workflows/v2-quality-gate.yml` hiện đang `BLOCKED` khi push lên GitHub Cloud Actions do token OAuth trên máy chủ thiếu scope `workflow` (đã kích hoạt qua `v2/scripts/run_v2_quality_gate.py` và Git `pre-push` hook cục bộ).

4. **Lệnh chạy kiểm tra tối thiểu trên máy chủ (đã xác minh `exit_code = 0`):**
```powershell
Set-Location "C:\Users\Admin\ntk-thesis-v2\integration-pilot"
$env:PATH = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0;$env:PATH"

python scripts/verify-repository.py
python v2/baseline/verify_patch.py
python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q
python v2/scripts/run_v2_quality_gate.py

$ReplayDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_replay_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "v2\demo\reproduce_integration_pilot.ps1" -Mode REPLAY -EvidenceRoot $ReplayDir
```

Em cảm ơn thầy ạ!
