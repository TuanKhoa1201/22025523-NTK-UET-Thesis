# NTK Thesis V2 — Báo cáo Đánh giá Sơ bộ Trình Giảng viên (Advisor Evaluation Summary)

**Nhánh kiểm thử độc lập**: `v2/antigravity-review`
**Thời điểm báo cáo**: `2026-11-11T12:33:00+07:00`

> [!IMPORTANT]
> Báo cáo này tuân thủ nguyên tắc trung thực học thuật của NTK Thesis V2 ([`AGENTS.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/AGENTS.md)): **phân biệt tuyệt đối giữa kết quả kiểm thử công cụ (trên dữ liệu giả lập `TEST FIXTURE`) và kết quả thực nghiệm benchmark thật (`PENDING` / `N/A` khi chưa có bộ nhãn độc lập khóa cứng).**

---

## 1. Tóm tắt Trạng thái Sẵn sàng cho M4/M5

| Hạng mục | Trạng thái | Chi tiết xác minh |
|---|---|---|
| **Đồng bộ Schema với Codex (`v2/triage`)** | **HOÀN TẤT (PASS)** | [`codex_adapter.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/codex_adapter.py) chuyển đổi có kiểm chứng `assessments.jsonl` (`SUPPORTED` $\to$ `KEEP_TP`, `REFUTED` $\to$ `PROPOSED_FP`, `UNDETERMINED` $\to$ `REVIEW`) và ghép 1-1 từ `raw_finding` + `scan_sha256` mà không phụ thuộc vào `id` nội bộ của Codex. |
| **Cơ chế Fail-Safe & Cổng Phê duyệt Con người (M3)** | **HOÀN TẤT (PASS)** | Bắt buộc kiểm tra `source_sha256` và sự tồn tại thực sự của dòng mã `citations` trong tệp Java/snapshot trước khi cho phép đề xuất `PROPOSED_FP`. Mọi cảnh báo đều được giữ lại (`auto_dismissed_alerts = 0`, `requires_human_confirmation = True`). |
| **Cơ chế Khóa cứng Tập dữ liệu (`STRICT_LOCK` — M4)** | **HOÀN TẤT (PASS)** | [`validate_pilot_lock.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/validate_pilot_lock.py) chặn cứng mọi bộ dữ liệu không đạt chuẩn 30–60 cảnh báo, tỷ trọng `CWE-22` + `CWE-89` $< 70\%$, thiếu `source_sha256`, thiếu người gán nhãn độc lập hoặc chứa dấu hiệu `TEST FIXTURE`. |
| **Kiểm thử Hồi quy Bộ Công cụ Đánh giá** | **20/20 PASS** | `python -m unittest discover -s v2/evaluation/tests -p "test_*.py" -v` đạt 20/20 bài kiểm thử (`0 FAIL`, `0 SKIP`). |
| **Bộ Nhãn Độc lập Khóa cứng 30–60 Cảnh báo (M4)** | **PENDING** | Chưa có tệp nhãn độc lập đã khóa cứng (`m4_acceptance_ready = True`) trên nhánh `v2/antigravity-review`. |
| **Chấm điểm Thực nghiệm Cuối cùng (M5)** | **PENDING** | Chỉ công bố tỷ lệ phân loại sau khi ghép đầu ra thật của OpenGrep + Qwen với bộ nhãn độc lập đã khóa ở M4. |

---

## 2. Phân tách Chỉ số Đã Xác minh Kỹ thuật và Chỉ số Chưa Công bố Thực nghiệm

### 2.1. Các chỉ số kỹ thuật đã xác minh trên bộ công cụ đánh giá (`v2/evaluation/`)
- **Tương thích định dạng & kiểm chứng toàn vẹn**: `20/20` kịch bản unit test đạt `PASS` (`0 FAIL`).
- **Tỷ lệ cảnh báo bị tự động xóa không qua xác nhận con người**: `0 / N` (`0.0%` — bị chặn cứng bởi thiết kế và kiểm tra `human_approval_violations`).
- **Khả năng chặn đề xuất FP ảo (trích dẫn dòng không tồn tại, dòng comment, thiếu/sai SHA-256, lệch CWE)**: `100%` các trường hợp vi phạm trong bộ kiểm thử bị chuyển an toàn về `REVIEW`.

### 2.2. Các chỉ số thực nghiệm chưa thể công bố (Đợi bộ nhãn độc lập M4 & dữ liệu chạy thật M5)
- **Tỷ lệ cảnh báo giả được đề xuất loại đúng (`Proposed FP Removal Rate`)**: `N/A (PENDING INDEPENDENT LABELS)`
- **Tỷ lệ cảnh báo thật bị đề xuất loại nhầm (`Erroneously Proposed TP Removal Rate`)**: `N/A (PENDING INDEPENDENT LABELS)`
- **Thời gian suy luận thực tế trên tập Pilot 30–60 cảnh báo (`Mean / P50 / P95 Latency`)**: `PENDING REAL RUN`

> [!WARNING]
> Kiểm tra khớp trích dẫn dòng mã nguồn và mã băm SHA-256 chỉ là **điều kiện cần về mặt hình thức** để một kết luận `REFUTED` của Qwen không bị loại bỏ ngay lập tức; nó **không chứng minh kết luận bảo mật của mô hình là đúng**. Hiệu quả lọc cảnh báo giả chỉ được phép công bố khi đối chiếu với nhãn độc lập do con người gán trước khi chạy mô hình.

---

## 3. Bảng Đánh giá Sơ bộ Trình Giảng viên (Dữ liệu Thật: `PENDING` / `N/A` khi chưa có Nhãn Độc lập)

### 3.1. Bảng So sánh Hai Nhánh Thực nghiệm (Arm A vs. Arm B)

| Chỉ số đánh giá | Nhánh A: OpenGrep Đơn lẻ | Nhánh B: OpenGrep + Local Qwen | Trạng thái dữ liệu |
|---|---|---|---|
| **Tổng số cảnh báo trong tập Pilot khóa cứng ($N_{\text{total}}$)** | `PENDING (Target: 30–60)` | `PENDING (Target: 30–60)` | Chờ khóa M4 (`STRICT_LOCK`) |
| **Số cảnh báo thật ($N_{\text{TP}}$) / giả ($N_{\text{FP}}$) / mơ hồ ($N_{\text{AMB}}$)** | `N/A` | `N/A` | Chờ gán nhãn độc lập |
| **Số cảnh báo bị tự động loại bỏ không qua con người** | `0` | `0` (Bắt buộc xác nhận thủ công) | Đã khóa bằng cơ chế Fail-safe |
| **Đề xuất loại đúng cảnh báo giả ($\text{FP}_{\text{proposed\_drop}} / N_{\text{FP}}$)** | `0 / 0 (N/A)` | `0 / 0 (N/A — PENDING LABELS)` | Không tính khi chưa có nhãn độc lập |
| **Đề xuất loại nhầm cảnh báo thật ($\text{TP}_{\text{proposed\_drop}} / N_{\text{TP}}$)** | `0 / 0 (N/A)` | `0 / 0 (N/A — PENDING LABELS)` | Luôn hiển thị tử số / mẫu số |
| **Số cảnh báo chuyển `REVIEW` ($N_{\text{review}} / N_{\text{total}}$)** | `N_total / N_total (100.0%)` | `PENDING REAL RUN` | Gồm `UNDETERMINED` + Fail-safe override |
| **Độ phủ phản hồi hợp lệ (`Triage Coverage`)** | `N/A` | `PENDING REAL RUN` | Tỷ lệ JSON hợp lệ từ Codex/Qwen |
| **Độ trễ xử lý (`Mean / P50 / P95 ms`)** | `PENDING REAL RUN` | `PENDING REAL RUN` | Đo từ `assessments.jsonl` thật |

### 3.2. Bảng Phân rã Theo CWE (Ưu tiên `CWE-22`, `CWE-89`; Báo cáo riêng `CWE-78`, `CWE-79`)

| Phạm vi / CWE | Phân tầng | Tổng cảnh báo | Nhãn TP | Nhãn FP | Đề xuất loại đúng FP (`k / N_FP`) | Đề xuất loại nhầm TP (`k / N_TP`) | Cần xem thêm (`REVIEW`) | Độ phủ Triage | Độ trễ `Mean / P95` (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **`ALL`** | OVERALL | `PENDING` | `N/A` | `N/A` | `0/0 (N/A)` | `0/0 (N/A)` | `PENDING` | `PENDING` | `PENDING` |
| **`PRIORITY (CWE-22, CWE-89)`** | PRIORITY_TIER_1 ($\ge 70\%$) | `PENDING` | `N/A` | `N/A` | `0/0 (N/A)` | `0/0 (N/A)` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-22` (Path Traversal)** | PRIORITY_TIER_1 | `PENDING` | `N/A` | `N/A` | `0/0 (N/A)` | `0/0 (N/A)` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-89` (SQL Injection)** | PRIORITY_TIER_1 | `PENDING` | `N/A` | `N/A` | `0/0 (N/A)` | `0/0 (N/A)` | `PENDING` | `PENDING` | `PENDING` |
| **`SECONDARY (CWE-78, CWE-79)`** | SECONDARY_TIER_2 | `PENDING` | `N/A` | `N/A` | `0/0 (N/A)` | `0/0 (N/A)` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-78` (Command Injection)** | SECONDARY_TIER_2 | `PENDING` | `N/A` | `N/A` | `0/0 (N/A)` | `0/0 (N/A)` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-79` (Cross-Site Scripting)** | SECONDARY_TIER_2 | `PENDING` | `N/A` | `N/A` | `0/0 (N/A)` | `0/0 (N/A)` | `PENDING` | `PENDING` | `PENDING` |

---

## 4. Quy trình 3 Bước Chạy Thực nghiệm M4/M5 Ngay Khi Ghép Nhánh

1. **Bước 1 — Khóa cứng tập dữ liệu M4 ở chế độ `STRICT_LOCK`**:
   ```powershell
   python v2/evaluation/validate_pilot_lock.py `
     --mode STRICT_LOCK `
     --opengrep <locked_opengrep_scan.json> `
     --labels <independent_ground_truth_labels.json> `
     --source-root <java_source_root> `
     --write-lock v2/evaluation/m4_lock_manifest.json
   ```
2. **Bước 2 — Xác minh không có chỉnh sửa hậu kỳ trên tập nhãn trước khi chấm điểm M5**:
   ```powershell
   python v2/evaluation/validate_pilot_lock.py `
     --mode STRICT_LOCK `
     --opengrep <locked_opengrep_scan.json> `
     --labels <independent_ground_truth_labels.json> `
     --verify-lock v2/evaluation/m4_lock_manifest.json
   ```
3. **Bước 3 — Chấm điểm đầu ra `assessments.jsonl` thật từ Codex/JavisOS**:
   ```powershell
   python v2/evaluation/score_pilot.py `
     --opengrep <locked_opengrep_scan.json> `
     --labels <independent_ground_truth_labels.json> `
     --triage <codex_assessments.jsonl> `
     --source-root <java_source_root> `
     --output-json v2/evaluation/m5_eval_report.json `
     --output-md v2/evaluation/m5_eval_report.md
   ```
