# NTK Thesis V2 — Báo cáo Tương thích Schema Codex & Kiểm chứng Fail-Safe

**Nhánh thực hiện**: `v2/antigravity-review`
**Thời điểm cập nhật**: `2026-11-11T12:33:00+07:00`
**Phạm vi**: [`v2/evaluation/codex_adapter.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/codex_adapter.py), [`v2/evaluation/score_pilot.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/score_pilot.py), [`v2/evaluation/validate_pilot_lock.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/validate_pilot_lock.py), [`v2/evaluation/tests/test_codex_compatibility_and_failsafe.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/tests/test_codex_compatibility_and_failsafe.py).

---

## 1. Bộ chấm điểm có nhận đúng Output của Codex không?

**CÓ — Đã tương thích đầy đủ và có kiểm chứng một-một.**

1. **Chuyển đổi trạng thái quyết định (`codex_adapter.CODEX_STATUS_MAP`)**:
   - `SUPPORTED` $\to$ `KEEP_TP`
   - `REFUTED` $\to$ `PROPOSED_FP` *(chỉ khi vượt qua đầy đủ các cổng kiểm chứng SHA-256, dòng trích dẫn thực tế, khớp CWE và không tự động xóa; nếu trượt bất kỳ cổng nào $\to$ tự động chuyển về `REVIEW`)*
   - `UNDETERMINED`, bản ghi có trường `error`, thiếu chứng cứ hoặc lỗi JSON $\to$ `REVIEW`
2. **Hỗ trợ cấu trúc lồng nhau của `assessment.jsonl` / `assessments.jsonl`**:
   - Đọc trực tiếp cấu trúc `{ "id": ..., "evidence": { "raw_finding": ..., "cwe": [...], "snapshots": ..., "snippets": ..., "trace": ... }, "assessment": { "status": ..., "citations": ..., "explanation": ... } }`.
   - Hỗ trợ `evidence.cwe` ở cả dạng danh sách (`["CWE-89: SQL Injection"]`) và chuỗi đơn.
   - Hỗ trợ `assessment.citations` ở cả dạng số dòng (`[42, 43]`), đối tượng (`[{"path": "...", "line": 42}, {"start_line": 42, "end_line": 44}]`), và chuỗi (`["File.java:42", "L42-L44"]`).
3. **Ánh xạ 1-1 tái lập được (Không giả định `id` của Codex trùng `alert_id`)**:
   - Hàm [`match_and_convert_codex_records`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/codex_adapter.py#L317-L446) đối chiếu `scan_sha256` (nếu có), chữ ký chuẩn hóa `(normalized_file_path, start_line, end_line, start_col, end_col, rule_id, normalized_cwe)` từ `evidence.raw_finding` và thứ tự `finding_index`.
   - Nếu không ghép chắc chắn được 1-1 hoặc có nhiều finding trùng vị trí/rule mà không có `finding_index` phân biệt, bản ghi bị đưa vào `anomalies.unmatched_or_ambiguous_triage_records` và cảnh báo OpenGrep tương ứng tự động rơi về `REVIEW` (tuyệt đối không ghép theo suy đoán).

---

## 2. Những lỗi đã phát hiện và sửa (Bugs Found & Fixed in P0)

| Mã mục | Lỗi phát hiện trong phiên bản trước | Cách khắc phục đã triển khai |
|---|---|---|
| **P0-1** | `score_pilot.py` trước đây chưa nhận cấu trúc lồng nhau `id` / `evidence` / `assessment` và 3 trạng thái `SUPPORTED` / `REFUTED` / `UNDETERMINED` của Codex. | Xây dựng [`codex_adapter.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/codex_adapter.py) và tích hợp trực tiếp vào [`score_pilot.evaluate_pilot`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/score_pilot.py#L430-L725). |
| **P0-2** | Khi `source_sha256` bị bỏ trống (`None`) ở cảnh báo hoặc ở bản ghi triage, `score_pilot.py` bỏ qua kiểm tra SHA-256 và vẫn cho phép `PROPOSED_FP`. | Bắt buộc phải có `source_sha256` hợp lệ và khớp nhau trước khi chấp nhận `REFUTED` $\to$ `PROPOSED_FP`; nếu thiếu hoặc sai lệch, ghi vào `anomalies.sha256_mismatches` và ép về `REVIEW`. |
| **P0-3** | `_validate_evidence_grounding` trước đây chỉ kiểm tra số dòng `cited_lines` nằm trong khoảng `[context_start_line, context_end_line]`, không kiểm tra dòng đó có thực sự tồn tại và chứa mã lệnh thực trong file Java / snapshot hay không. | Trích xuất nội dung dòng thực tế từ file `.java` trên đĩa (`--source-root`) hoặc từ `evidence.snapshots` / `evidence.snippets` đã xác minh SHA-256. Nếu dòng trích dẫn không tồn tại, là dòng trống hoặc chỉ chứa comment (`//`, `/*`, `*`), ghi vào `missing_or_invalid_citations` & `ungrounded_fp_overrides` và ép về `REVIEW`. |
| **P0-4** | Chưa có rào chắn ngăn việc vô tình dùng kết quả của Qwen/Codex làm tệp nhãn `ground_truth`. | Trong `_extract_labels` và `validate_pilot_dataset`, mọi nhãn có nguồn `qwen`/`ollama`/`llm`/`codex`/`auto` hoặc chứa cấu trúc `assessment` đều bị từ chối vào `rejected_auto_generated_labels`. |
| **P0-5** | `validate_pilot_lock.py` trước đây để mặc định `min_priority_share=0.5` và chỉ phát cảnh báo (`warnings`) khi tập dữ liệu dưới 30 cảnh báo, thiếu tỷ trọng CWE ưu tiên hoặc thiếu `source_sha256`. | Đặt mặc định chế độ `STRICT_LOCK` với `min_alerts=30`, `max_alerts=60`, `min_priority_share=0.70`. Biến mọi vi phạm kích thước, tỷ trọng CWE-22/89 $< 70\%$, thiếu `annotated_by`, thiếu 64-hex `source_sha256`, nhãn mồ côi hoặc dấu hiệu `TEST FIXTURE` thành lỗi chặn (`errors`), từ chối tạo manifest nghiệm thu M4. Tách riêng chế độ `--mode smoke` (`m4_acceptance_ready=False`) cho việc thử công cụ. |

---

## 3. Các Kiểm thử Đã Chạy (Unit Tests & CLI Smoke Tests)

- **Lệnh chạy**:
  ```powershell
  python -m unittest discover -s v2/evaluation/tests -p "test_*.py" -v
  ```
- **Kết quả**: **20 PASS / 0 FAIL / 0 SKIP** (thời gian chạy `0.176s`, exit code `0`).
  - [`test_codex_compatibility_and_failsafe.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/tests/test_codex_compatibility_and_failsafe.py) (9/9 PASS):
    1. `test_1_codex_nested_schema_conversion`
    2. `test_2_deterministic_id_matching_and_mismatch_rejection`
    3. `test_3_wrong_or_missing_sha256_blocks_refuted_fp`
    4. `test_4_refuted_with_nonexistent_or_comment_citation_overridden_to_review`
    5. `test_5_model_concludes_wrong_cwe`
    6. `test_6_no_ground_truth_and_reject_auto_generated_labels`
    7. `test_7_benchmark_below_minimum_size_rejected_by_strict_lock`
    8. `test_8_erroneously_proposed_tp_removal_tracked_with_numerator_denominator`
    9. `test_9_retain_all_alerts_for_human_confirmation_and_block_auto_dismiss`
  - [`test_score_pilot.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/tests/test_score_pilot.py) (8/8 PASS)
  - [`test_validate_pilot_lock.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/tests/test_validate_pilot_lock.py) (3/3 PASS)

---

## 4. Trạng thái Truy cập Dữ liệu Thật & Rủi ro Còn lại

- **Truy cập dữ liệu từ nhánh `v2/javis-benchmark` / `v2/codex-core`**:
  - Trong workspace `antigravity` hiện tại (commit nền `103e5f0411bcf962cf4b31ee8c07f181ec2dd444`), thư mục `v2/evaluation/smoke_evidence/` và `v2/triage/*.py` chưa được merge sang nhánh `v2/antigravity-review`, đồng thời sandbox cô lập quyền đọc sang thư mục anh em `../codex` và `../integration/.git`.
  - Khi người dùng hoặc JavisOS chạy lệnh `score_pilot.py` trên máy chủ/terminal thông thường trỏ tới `smoke_evidence/` hoặc `assessments.jsonl` thật, bộ parser trong `codex_adapter.py` sẽ tự động đọc và kiểm chứng mà không cần chỉnh sửa code.
- **Rủi ro còn lại**:
  - Kiểm chứng hình thức (khớp SHA-256 và dòng trích dẫn tồn tại trong mã nguồn) chỉ chứng minh mô hình trích dẫn đúng vị trí mã nguồn, **không chứng minh kết luận bảo mật của LLM là đúng**. Vì vậy mọi kết luận `REFUTED` vẫn bắt buộc phải giữ lại chờ con người xác nhận (`requires_human_confirmation=True`) và chỉ được tính điểm chính xác khi đối chiếu với bộ nhãn độc lập của M4.
