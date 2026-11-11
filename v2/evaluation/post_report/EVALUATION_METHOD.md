# PHƯƠNG PHÁP ĐÁNH GIÁ THỰC NGHIỆM BẮT CẶP (`EVALUATION_METHOD`)

- **Giai đoạn:** Stage 4 — Đánh giá thực nghiệm bắt cặp (Paired Evaluation) trên tập Held-Out khóa cứng (`n = 40`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Công cụ kiểm chứng hợp đồng và chấm điểm:** `v2/demo/verify_repro_contract.py`, `v2/evaluation/validate_pilot_lock.py`, `v2/triage/export_pilot.py`, `v2/evaluation/score_pilot.py`, `v2/evaluation/build_paired_pilot_table.py`

---

## 1. Thiết kế thực nghiệm bắt cặp (Paired Experimental Design)

Để đảm bảo tính khách quan khoa học và khả năng tái lập, toàn bộ các nhánh so sánh được chạy trên **cùng một bản chụp kết quả quét OpenGrep khóa cứng** (`stage1_heldout_set_40_scan/opengrep.json`, `scan_sha256 = 67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b`, `manifest_sha256 = 3f5488d9a8de308b33111b5b5b88fd2bf6342ff3a18d8b9458b6936725b64fab`) và đối chiếu với cùng một bộ nhãn chuẩn độc lập (`labels_heldout.json`, `combined_lock_sha256 = 4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09`).

### Cấu trúc tập Held-Out (`n = 40` cảnh báo độc lập)
- **Nguồn:** OWASP BenchmarkJava v1.2 (`commit 8b67a88d73b2594570fc21150705283de884620b`), 40 tệp Java riêng biệt (mỗi tệp đúng 1 cảnh báo), tách biệt 100% với tập `dev_set_16` (`n = 16`).
- **Phân bố lớp lỗ hổng và nhãn chuẩn:**
  - `CWE-22` (Path Traversal): `20` cảnh báo (`10 TRUE_POSITIVE`, `10 FALSE_POSITIVE`).
  - `CWE-89` (SQL Injection): `20` cảnh báo (`10 TRUE_POSITIVE`, `10 FALSE_POSITIVE`).
  - Tổng cộng: `20 TRUE_POSITIVE` + `20 FALSE_POSITIVE` = `40` cảnh báo (`Precision` gốc của OpenGrep = `20/40 = 50.0%`).

---

## 2. Bốn nhánh so sánh (Comparison Arms)

1. **Nhánh A — `OpenGrep-only` (Baseline SAST):**
   - Giữ nguyên toàn bộ 40 cảnh báo đầu ra của OpenGrep v1.25.0.
2. **Nhánh B — `OpenGrep + heuristic` (`--mode heuristic`):**
   - Chỉ sử dụng bộ phân tích tĩnh nội phương thức (`v2/triage/heuristics.py`), không gọi mô hình ngôn ngữ lớn.
   - Đề xuất `REFUTED` (`PROPOSED_FP`) khi phát hiện nguồn hằng an toàn (`SeparateClassRequest.getTheValue`), sanitizer tường minh đúng ngữ cảnh, hoặc nhánh `switch`/ghi đè hằng nội phương thức; trả về `UNDETERMINED` (`REVIEW`) đối với các luồng đi qua phương thức phụ trợ (`Test.doSomething`, `ThingFactory`) hoặc cấu trúc tập hợp.
3. **Nhánh C — `OpenGrep + evidence + Qwen` (`--mode evidence+llm`, Pipeline đề xuất):**
   - Kết hợp trích xuất ngữ cảnh phương thức + callee cùng tệp (`v2/triage/java_context.py`), làm phẳng `CliCall` (`v2/triage/evidence.py`), tín hiệu dẫn xuất (`v2/triage/heuristics.py`), suy luận bằng mô hình cục bộ `qwen3.5:9b-q4_K_M` qua Ollama loopback (`http://127.0.0.1:11434`, `temperature = 0`, `num_ctx = 8192`), kiểm chứng trích dẫn đơn dòng (`validate_answer`), và lưu trữ vào hàng đợi duyệt thủ công SQLite (`ReviewStore`).
4. **Nhánh D — Ablation `OpenGrep + Qwen ít ngữ cảnh` (`--mode llm`):**
   - Sử dụng cùng mô hình `qwen3.5:9b-q4_K_M` và cùng bộ kiểm tra trích dẫn đơn dòng, nhưng chỉ cung cấp cửa sổ ngắn `[sl - 3, el + 3]` quanh vị trí cảnh báo, lược bỏ hoàn toàn ngữ cảnh mở rộng (`java_context`) và tín hiệu dẫn xuất (`evidence_signals`). Nhánh này dùng để đo lường trực tiếp đóng góp của tầng trích xuất ngữ cảnh Java và làm giàu bằng chứng (Stage 2 & Stage 3).

---

## 3. Ba chính sách hậu xử lý (Post-Triage Queue Policies)

Theo định nghĩa trong `v2/evaluation/score_pilot.py`, mỗi nhánh được đánh giá dưới 3 chính sách:
1. **`baseline`:** Giữ toàn bộ 40 cảnh báo (`TP + FP`).
2. **`drop_fp` (Chính sách trọng tâm — Human-Confirmed FP Dismissal Simulation):**
   - Giữ lại các cảnh báo có phán quyết `KEEP_TP` (`SUPPORTED`) và `REVIEW` (`UNDETERMINED`).
   - Đánh giá hiệu quả giảm báo động giả nếu người duyệt xác nhận các đề xuất `PROPOSED_FP` (`REFUTED`).
   - **Lưu ý quản trị:** Trong vận hành thực tế của `v2/triage`, `REFUTED` **không bao giờ tự động ẩn cảnh báo** (`auto_dismissed = False`, `state = OPEN` cho tới khi người duyệt chạy `decide confirm-false`).
3. **`keep_tp_only`:** Chỉ giữ các cảnh báo `KEEP_TP` (`SUPPORTED`), tách riêng cả `REVIEW` (`UNDETERMINED`) và `PROPOSED_FP` (`REFUTED`).

---

## 4. Hệ thống chỉ số đánh giá (kèm `tử số / mẫu số`)

- **Phân phối phán quyết trên `TRUE_POSITIVE` (`n = 20`):**
  - `TP -> SUPPORTED (KEEP_TP)`: Số lỗ hổng thật được giữ đúng.
  - `TP -> REFUTED (PROPOSED_FP)`: **Số lỗ hổng thật bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp`) — Chỉ số rủi ro an toàn quan trọng nhất (mục tiêu = `0/20`).**
  - `TP -> UNDETERMINED (REVIEW)`: Số lỗ hổng thật chưa đủ bằng chứng, được giữ lại trong hàng đợi duyệt thủ công.
- **Phân phối phán quyết trên `FALSE_POSITIVE` (`n = 20`):**
  - `FP -> REFUTED (PROPOSED_FP)`: Số báo động giả được phát hiện và đề xuất bác bỏ đúng (`correctly_proposed_fp`).
  - `FP -> SUPPORTED (KEEP_TP)`: Số báo động giả bị bỏ lọt như lỗ hổng thật.
  - `FP -> UNDETERMINED (REVIEW)`: Số báo động giả được chuyển sang duyệt thủ công.
- **Chỉ số tổng hợp dưới chính sách `drop_fp`:**
  - `Precision = TP_retained / (TP_retained + FP_retained)`
  - `Recall (TP Retention Rate) = TP_retained / Total_TP`
  - `F1-score = 2 * Precision * Recall / (Precision + Recall)`
  - `FP Reduction Rate = FP_dismissed / Total_FP`
- **Chỉ số chất lượng bằng chứng và thời gian chạy:**
  - `Citation Exact Match Rate`: Tỷ lệ cảnh báo có `citation_check == MATCHED` trên tổng số cảnh báo có kết luận.
  - `Latency`: Trung bình (`mean`), trung vị (`median`), phân vị 95 (`p95`) và tổng thời gian chạy (`total_seconds`).
