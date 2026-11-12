# Báo Cáo Tái Tính Độc Lập Các Chỉ Số Thực Nghiệm (`heldout_set_40`)

- **Công cụ tái tính độc lập:** `v2/evaluation/audit_20261112/independent_audit.py` (viết hoàn toàn từ đầu bằng thư viện chuẩn Python, **không** gọi `v2/evaluation/score_pilot.py` hay `v2/evaluation/codex_adapter.py`).
- **Phương pháp ghép bản ghi:** Ghép khóa xác thực đa trường (`alert_id == SHA256(scan_sha256:finding_index)`, `scan_sha256`, `source_sha256`, `cwe`, `rule_id`, `file_path`, `start_line..end_line`), tuyệt đối không ghép theo thứ tự dòng. Đã kiểm chứng đảo ngẫu nhiên thứ tự hàng trong `test_06_reordered_rows_match_by_key_and_missing_row_fails` cho kết quả trùng khớp 100%.
- **Dữ liệu đầu vào kiểm tra:** `heldout_alerts.json` (`n = 40`), `labels_heldout.json` (`n = 40`, đã đối chiếu khớp 40/40 boolean TP/FP & CWE với `expectedresults-1.2.csv`), `PAIRED_EVALUATION.csv` (`n = 40`) và `METRICS_BY_CWE.csv` (`12` hàng).

> **Kết luận đối chiếu số học:** **Số liệu tái tính khớp** (`0` sai lệch tử số/mẫu số/tỷ lệ phần trăm trên toàn bộ 12 hàng × 13 cột chỉ số đếm của `METRICS_BY_CWE.csv` và các con số lịch sử của `PAIRED_EVALUATION.csv`).
>
> **Lưu ý kiểm toán bắt buộc:** Việc *“số liệu tái tính khớp”* chỉ xác nhận phép cộng/chia từ bảng kết quả sang bảng tổng hợp là đúng toán học; **tuyệt đối không suy ra “đã chứng minh mô hình Qwen chính xác tuyệt đối”** vì (1) Arm C truyền sẵn `recommended_status` khớp 40/40 nhãn cho Qwen (xem `HEURISTIC_DEPENDENCY_AUDIT.md`), (2) 10 tệp raw `assessments.jsonl` trên máy chủ `ADMIN-PC` chưa được kiểm tra trực tiếp từ GitHub (`NOT_VERIFIED`), và (3) các chỉ số này tính ở **cấp cảnh báo của tập con 40 mẫu**, không phải TPR/FPR toàn kho 772 test cases của OWASP Benchmark.

---

## 1. Phân Biệt Cấp Độ Đánh Giá và Định Nghĩa Toán Học Các Chính Sách

### 1.1. Đánh giá cấp cảnh báo (Alert-Level) vs. Cấp Test Case OWASP (Corpus-Level)

1. **Cấp cảnh báo (Alert-Level, có điều kiện trên việc OpenGrep đã phát cảnh báo — `N = 40`: `TP_total = 20`, `FP_total = 20`):**
   - Mẫu số `TP_total = 20` là tổng số cảnh báo lỗ hổng thật trong tập `heldout_set_40` mà OpenGrep đã bắt được.
   - Mẫu số `FP_total = 20` là tổng số cảnh báo giả trong tập `heldout_set_40` mà OpenGrep đã phát sinh.
   - Do đó, `Alert_TP_Recall` (tỷ lệ giữ lại TP sau bước lọc hậu xử lý) và `Alert_FPR` (tỷ lệ cảnh báo giả vẫn còn tồn đọng sau bước lọc) đo lường **hiệu quả của tầng hậu xử lý cảnh báo (triage layer)**, không đo lường độ phủ phát hiện của bản thân bộ quy tắc OpenGrep trên toàn bộ ứng dụng.
2. **Cấp Test Case chính thức của OWASP BenchmarkJava v1.2 (`Corpus-Level TPR / FPR`):**
   - Trên toàn bộ `772` test cases `CWE-22` (`268`) + `CWE-89` (`504`) của OWASP BenchmarkJava v1.2 (`405` lỗ hổng thật `P = TP + FN`, `367` ca an toàn `N = FP + TN`), công thức chuẩn của OWASP (`BenchmarkScore = TPR - FPR`) đòi hỏi số đếm `FN` (lỗ hổng thật mà OpenGrep bỏ sót) và `TN` (ca an toàn mà OpenGrep không báo động) trên cả `772` test cases.
   - Vì kho GitHub chỉ lưu tập con phân tầng `40` cảnh báo (`20 TP`, `20 FP`) mà không có kết quả quét đầy đủ `772` test cases, **`Corpus-Level OWASP TPR / FPR` bắt buộc nhận trạng thái `NOT_VERIFIED`**.

### 1.2. Ba chính sách vận hành (Tuyệt đối không đánh đồng `drop_fp` và `keep_tp_only`)

Giả sử trên tập cảnh báo đầu vào (`TP_total`, `FP_total`), bộ phân loại trả về 3 trạng thái sau cổng kiểm chứng trích dẫn: `SUPPORTED` (`TP_sup`, `FP_sup`), `REFUTED` (`TP_ref`, `FP_ref`), và `UNDETERMINED` (`TP_und`, `FP_und`):

- **Chính sách 1 — `baseline` (Giữ nguyên toàn bộ cảnh báo OpenGrep):**
  - Cảnh báo giữ lại: `N = TP_total + FP_total`.
  - `Precision_baseline = TP_total / (TP_total + FP_total)`; `Alert_TP_Recall = TP_total / TP_total = 100%`; `Alert_FPR = FP_total / FP_total = 100%`.
- **Chính sách 2 — `drop_fp` (Chỉ loại bỏ các cảnh báo `REFUTED` sau khi kỹ sư xác nhận; giữ lại cả `SUPPORTED` lẫn `UNDETERMINED` để rà soát an toàn):**
  - Cảnh báo giữ lại: `Retained_drop_fp = (TP_sup + TP_und) + (FP_sup + FP_und)`.
  - `Precision_drop_fp = (TP_sup + TP_und) / Retained_drop_fp`.
  - `Alert_TP_Recall_drop_fp = (TP_sup + TP_und) / TP_total` *(bị giảm khi và chỉ khi `TP_ref > 0`, tức có lỗ hổng thật bị đề xuất loại nhầm)*.
  - `Alert_FPR_drop_fp = (FP_sup + FP_und) / FP_total`.
- **Chính sách 3 — `keep_tp_only` (Chỉ giữ cảnh báo có bằng chứng khẳng định `SUPPORTED`; bỏ qua cả `REFUTED` lẫn `UNDETERMINED` — chính sách mạo hiểm đối với Recall khi `UNDETERMINED > 0`):**
  - Cảnh báo giữ lại: `Retained_keep_tp = TP_sup + FP_sup`.
  - `Precision_keep_tp_only = TP_sup / (TP_sup + FP_sup)`.
  - `Alert_TP_Recall_keep_tp_only = TP_sup / TP_total` *(giảm ngay cả khi mô hình trả về `UNDETERMINED` trên TP)*.
  - `Alert_FPR_keep_tp_only = FP_sup / FP_total`.

> Sự khác biệt giữa hai chính sách thể hiện rõ nhất ở **Arm B (`Heuristic`)**:
> - Với `drop_fp`: giữ `9 SUPPORTED + 24 UNDETERMINED = 33` cảnh báo -> `Precision = 20/33 (60.6%)`, `Alert_TP_Recall = 20/20 (100.0%)`.
> - Với `keep_tp_only`: chỉ giữ `9 SUPPORTED` -> `Precision = 9/9 (100.0%)`, nhưng **`Alert_TP_Recall` tụt xuống `9/20 (45.0%)`** (bỏ sót 11 lỗ hổng thật nằm trong nhóm `UNDETERMINED`).

---

## 2. Bảng Chỉ Số Tái Tính Độc Lập Toàn Tập `heldout_set_40` (`ALL: n = 40, 20 TP, 20 FP`)

| Chỉ số kiểm toán (Cấp cảnh báo — `tử_số/mẫu_số`) | Arm A: OpenGrep-only | Arm B: Heuristic (`--mode heuristic`) | Arm C: Pipeline đầy đủ (`--mode evidence+llm`) | Arm D: Qwen ít ngữ cảnh (Sau kiểm chứng citation) | Arm D (Nguyên gốc Qwen trước kiểm chứng citation) |
|---|---|---|---|---|---|
| **Tổng số cảnh báo (`N`)** | `40` | `40` | `40` | `40` | `40` |
| **Nhãn chuẩn OWASP (`TP / FP`)** | `20 / 20` | `20 / 20` | `20 / 20` | `20 / 20` | `20 / 20` |
| **TP giữ đúng ở `SUPPORTED` (`TP_sup / 20`)** | `20/20 (100.0%)` | `9/20 (45.0%)` | `20/20 (100.0%)` | `17/20 (85.0%)` | `20/20 (100.0%)` |
| **TP được bảo toàn cùng hàng đợi `REVIEW` (`(TP_sup + TP_und) / 20`)** | `20/20 (100.0%)` | `20/20 (100.0%)` | `20/20 (100.0%)` | `20/20 (100.0%)` | `20/20 (100.0%)` |
| **FP đề xuất loại đúng (`REFUTED` trên FP — `FP_ref / 20`)** | `0/20 (0.0%)` | `7/20 (35.0%)` | `20/20 (100.0%)` | `0/20 (0.0%)` | `0/20 (0.0%)` |
| **TP bị đề xuất loại nhầm (`REFUTED` trên TP — `TP_ref / 20`)** | `0/20 (0.0%)` | `0/20 (0.0%)` | `0/20 (0.0%)` | `0/20 (0.0%)` | `0/20 (0.0%)` |
| **FP giữ nhầm ở `SUPPORTED` (`FP_sup / 20`)** | `20/20 (100.0%)` | `0/20 (0.0%)` | `0/20 (0.0%)` | `14/20 (70.0%)` | `20/20 (100.0%)` |
| **Chưa xác định `UNDETERMINED` tổng (`(TP_und + FP_und) / 40`)** | `0/40 (0.0%)` | `24/40 (60.0%)` (`11 TP + 13 FP`) | `0/40 (0.0%)` | `9/40 (22.5%)` (`3 TP + 6 FP`) | `0/40 (0.0%)` |
| **Coverage có kết luận (`(SUPPORTED + REFUTED) / 40`)** | `40/40 (100.0%)` | `16/40 (40.0%)` | `40/40 (100.0%)` | `31/40 (77.5%)` | `40/40 (100.0%)` |
| **Accuracy trên nhóm đã kết luận** | `20/40 (50.0%)` | `16/16 (100.0%)` | `40/40 (100.0%)` | `17/31 (54.8%)` | `20/40 (50.0%)` |
| **Citation hợp lệ (`MATCHED / 40`)** | `N/A` | `16/40 (40.0%)` | `40/40 (100.0%)` | `31/40 (77.5%)` | `31/40 (77.5%)` |
| **Chính sách `baseline`: Precision / Alert TP Recall / Alert FPR** | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` |
| **Chính sách `drop_fp`: Precision / Alert TP Recall / Alert FPR** | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` | `20/33 (60.6%)` / `20/20 (100.0%)` / `13/20 (65.0%)` | `20/20 (100.0%)` / `20/20 (100.0%)` / `0/20 (0.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` |
| **Chính sách `keep_tp_only`: Precision / Alert TP Recall / Alert FPR** | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` | `9/9 (100.0%)` / `9/20 (45.0%)` / `0/20 (0.0%)` | `20/20 (100.0%)` / `20/20 (100.0%)` / `0/20 (0.0%)` | `17/31 (54.8%)` / `17/20 (85.0%)` / `14/20 (70.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` / `20/20 (100.0%)` |
| **Độ trễ Mean / P50 / P95 nearest-rank (`ms`)** | `0.0 / 0.0 / 0.0` | `0.0* / 0.0* / 0.0*` | `10525.0 / 10961.0 / 12687.0` | `7526.55 / 6359.0 / 12109.0` | `7526.55 / 6359.0 / 12109.0` |
| **OWASP Test-Case-Level TPR / FPR (`772` test cases)** | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_VERIFIED` |

---

## 3. Bảng Tái Tính Độc Lập Phân Tầng Theo Từng CWE (`CWE-22` vs. `CWE-89`)

| Nhánh (Arm) | Nhóm CWE | `N` (`TP/FP`) | TP `SUPPORTED` | FP `REFUTED` (Loại đúng) | TP `REFUTED` (Loại nhầm) | FP `SUPPORTED` (Giữ nhầm) | `UNDETERMINED` (`TP + FP`) | Coverage | Precision `drop_fp` | Recall `drop_fp` | Precision `keep_tp_only` | Recall `keep_tp_only` | Mean / P50 / P95 (`ms`) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Arm A** | `CWE-22` | `20 (10/10)` | `10/10 (100.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `10/10 (100.0%)` | `0/20 (0.0%)` | `20/20 (100.0%)` | `10/20 (50.0%)` | `10/10 (100.0%)` | `10/20 (50.0%)` | `10/10 (100.0%)` | `0.0 / 0.0 / 0.0` |
| **Arm A** | `CWE-89` | `20 (10/10)` | `10/10 (100.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `10/10 (100.0%)` | `0/20 (0.0%)` | `20/20 (100.0%)` | `10/20 (50.0%)` | `10/10 (100.0%)` | `10/20 (50.0%)` | `10/10 (100.0%)` | `0.0 / 0.0 / 0.0` |
| **Arm B** | `CWE-22` | `20 (10/10)` | `4/10 (40.0%)` | `5/10 (50.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `11/20 (55.0%)` (`6+5`) | `9/20 (45.0%)` | `10/15 (66.7%)` | `10/10 (100.0%)` | `4/4 (100.0%)` | `4/10 (40.0%)` | `0.0* / 0.0* / 0.0*` |
| **Arm B** | `CWE-89` | `20 (10/10)` | `5/10 (50.0%)` | `2/10 (20.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `13/20 (65.0%)` (`5+8`) | `7/20 (35.0%)` | `10/18 (55.6%)` | `10/10 (100.0%)` | `5/5 (100.0%)` | `5/10 (50.0%)` | `0.0* / 0.0* / 0.0*` |
| **Arm C** | `CWE-22` | `20 (10/10)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `0/20 (0.0%)` | `20/20 (100.0%)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `10845.4 / 11172.0 / 12921.0` |
| **Arm C** | `CWE-89` | `20 (10/10)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `0/20 (0.0%)` | `20/20 (100.0%)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `10/10 (100.0%)` | `10204.6 / 10719.0 / 11734.0` |
| **Arm D** | `CWE-22` | `20 (10/10)` | `7/10 (70.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `6/10 (60.0%)` | `7/20 (35.0%)` (`3+4`) | `13/20 (65.0%)` | `10/20 (50.0%)` | `10/10 (100.0%)` | `7/13 (53.8%)` | `7/10 (70.0%)` | `6542.9 / 5874.5 / 8922.0` |
| **Arm D** | `CWE-89` | `20 (10/10)` | `10/10 (100.0%)` | `0/10 (0.0%)` | `0/10 (0.0%)` | `8/10 (80.0%)` | `2/20 (10.0%)` (`0+2`) | `18/20 (90.0%)` | `10/20 (50.0%)` | `10/10 (100.0%)` | `10/18 (55.6%)` | `10/10 (100.0%)` | `8510.2 / 7953.0 / 12844.0` |

---

## 4. Kết Quả Đối Chiếu Từng Số Liệu Lịch Sử & Ghi Chú Độ Trễ Nhỏ

1. **Đối chiếu 4 mốc số liệu lịch sử bắt buộc:**
   - **Tập đánh giá:** `40` cảnh báo, `20 TP` và `20 FP` -> **Số liệu tái tính khớp.**
   - **Heuristic (`Arm B`):** `7/20` FP đề xuất loại đúng, `0/20` TP loại nhầm, `24/40` trường hợp chưa xác định (`11 TP + 13 FP`), `9/20` TP giữ ở `SUPPORTED` -> **Số liệu tái tính khớp.**
   - **Pipeline đầy đủ (`Arm C`):** `20/20` FP đề xuất loại đúng, `0/20` TP loại nhầm, `20/20` TP được giữ ở `SUPPORTED`, `0/40` `UNDETERMINED` -> **Số liệu tái tính khớp.**
   - **Qwen ít ngữ cảnh (`Arm D`):** Nguyên gốc Qwen trả về `40/40` `SUPPORTED`; sau bộ kiểm chứng trích dẫn còn **`31/40` hỗ trợ (`17 TP + 14 FP`) và `9/40` chưa xác định (`3 TP + 6 FP`)** -> **Số liệu tái tính khớp.** *(Lưu ý phát hiện nhầm lẫn văn bản nhỏ tại `CHUONG_4_THUC_NGHIEM_VA_DANH_GIA.md:64,68`: văn bản Chương 4 viết nhầm Arm D CWE-22 có `4/10` FP `SUPPORTED`, `6/10` FP `UNDETERMINED` và Arm D CWE-89 có `10/10` FP `SUPPORTED`; số thực tế từ `PAIRED_EVALUATION.csv` là CWE-22 có **`6/10` FP `SUPPORTED`, `4/10` FP `UNDETERMINED`** và CWE-89 có **`8/10` FP `SUPPORTED`, `2/10` FP `UNDETERMINED`**, tổng `6 + 8 = 14/20` FP `SUPPORTED`!)*
2. **Hai ghi chú nhỏ về cột thời gian (`latency_ms`):**
   - `PAIRED_EVALUATION.csv` không lưu cột thời gian chạy cho `Arm B` (`heuristic`), nên `METRICS_BY_CWE.csv` ghi `0.0 ms`, trong khi `PAIRED_EVALUATION.md` và `POST_REPORT_IMPLEMENTATION_HANDOVER.md:115` ghi `< 15 ms` (`< 0.6 s`).
   - Thời gian trung bình của `Arm D` trên toàn tập `n = 40` là `301,062.0 / 40 = 7,526.55 ms` (khớp với `METRICS_BY_CWE.csv:10`), trong khi `POST_REPORT_IMPLEMENTATION_HANDOVER.md:115` làm tròn lệch nhẹ thành `7,526.7 ms` (lấy `301.068s / 40` hoặc tính từ số giây đã làm tròn `301.1s / 40 = 7,527.5ms`).
