# KIỂM CHỨNG WORKFLOW DUYỆT THỦ CÔNG, CỔNG AN TOÀN FAIL-CLOSED VÀ BỘ NEGATIVE TESTS (`HUMAN_REVIEW_VERIFICATION`)

- **Giai đoạn:** Stage 6 — Kiểm thử Workflow Duyệt Thủ Công & Negative Tests
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Tệp kiểm thử tự động:** `v2/triage/tests/test_human_review_negative_suite.py` (`16/16 PASSED`)
- **Bằng chứng chạy thực tế CLI:** `C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112\runs\stage6_human_review_demo\cli_lifecycle_transcript.json`

---

## 1. Bất biến an toàn cốt lõi (Core Governance Invariants)

1. **Không tự động ẩn cảnh báo (`No Auto-Dismissal`):**
   - Mọi cảnh báo mới nhập vào `ReviewStore` (`v2/triage/store.py`) đều khởi tạo ở trạng thái `state = "OPEN"` và `requires_human_review = True`, bất kể mô hình trả về `SUPPORTED`, `REFUTED` hay `UNDETERMINED`.
   - Khi mô hình trả về `REFUTED` (`PROPOSED_FP`), cảnh báo **vẫn hiển thị nguyên vẹn** trong lệnh `python -m v2.triage queue --db <db>`.
2. **Điều kiện bắt buộc để chuyển sang `CONFIRMED_FALSE` (`confirm-false`):**
   - Phải có `--actor` khác rỗng và `--reason` khác rỗng;
   - `record["issues"]` phải rỗng (`[]`);
   - `record["scan_provenance"]["source_capture_verified"]` phải bằng `True`;
   - Mọi tệp nguồn trong `record["snapshots"]` (cả tệp chính chứa sink lẫn mọi tệp tham gia vào `dataflow_trace`) phải còn tồn tại trên đĩa và có mã băm SHA-256 hiện hành khớp tuyệt đối với thời điểm quét (`check_current(record)`).
3. **Nhật ký kiểm toán bất biến (`Immutable Audit Trail`):**
   - Bảng `history` trong SQLite lưu tuần tự từng thao tác (`sequence`, `warning_id`, `actor`, `timestamp`, `action`, `reason`, `source_version`, `observed_version`, `evidence_sha256`).
   - Lệnh `reopen` khôi phục trạng thái cảnh báo về `OPEN` và giữ nguyên toàn bộ các bản ghi lịch sử trước đó.

---

## 2. Kết quả 16 ca kiểm thử trong `v2/triage/tests/test_human_review_negative_suite.py`

| STT | Tên ca kiểm thử (`test_human_review_negative_suite.py`) | Kỳ vọng | Kết quả thực tế |
|---:|---|---|---|
| 1 | `test_01_model_refuted_never_auto_dismisses_and_stays_open_in_queue` | `REFUTED` giữ `state = OPEN`, hiện trong `queue`, `history = []` | `PASS` |
| 2 | `test_02_valid_confirm_false_hides_from_default_queue_shows_in_all_and_logs_history` | Chuyển `CONFIRMED_FALSE`, ẩn khỏi `queue`, hiện trong `queue --all`, ghi `history` | `PASS` |
| 3 | `test_03_confirm_false_missing_actor_is_refused` | Từ chối (`exit_code = 2`), giữ `state = OPEN` | `PASS` |
| 4 | `test_04_confirm_false_missing_reason_is_refused` | Từ chối (`exit_code = 2`), giữ `state = OPEN` | `PASS` |
| 5 | `test_05_confirm_false_after_primary_source_modified_is_refused` | Phát hiện lệch SHA-256 tệp nguồn chính (`rescan required`), từ chối | `PASS` |
| 6 | `test_06_confirm_false_after_trace_file_modified_is_refused` | Phát hiện lệch SHA-256 tệp nguồn trên đường truyền `dataflow_trace`, từ chối | `PASS` |
| 7 | `test_07_confirm_false_after_source_file_deleted_is_refused` | Phát hiện tệp nguồn bị xóa, từ chối (`exit_code = 2`) | `PASS` |
| 8 | `test_08_confirm_false_with_evidence_issues_or_missing_provenance_is_refused` | Từ chối khi `issues != []` hoặc `source_capture_verified != True` | `PASS` |
| 9 | `test_09_confirm_true_transitions_state_and_keeps_warning_in_default_queue` | Chuyển `CONFIRMED_TRUE`, vẫn hiển thị trong `queue` mặc định, ghi `history` | `PASS` |
| 10 | `test_10_reopen_restores_open_state_and_preserves_full_audit_history` | Chuyển lại `OPEN`, hiển thị lại trong `queue`, giữ đủ 2 sự kiện trong `history` | `PASS` |
| 11 | `test_11_duplicate_import_does_not_overwrite_human_review_decision` | Ném `sqlite3.IntegrityError`, bảo toàn quyết định `CONFIRMED_FALSE` đã lưu | `PASS` |
| 12 | `test_12_wrong_scan_hash_or_tampered_source_hash_blocks_confirm_false` | Phát hiện lệch `scan-manifest.json` (`opengrep.json` SHA-256) và `snapshots` SHA-256, từ chối `confirm-false` | `PASS` |
| 13 | `test_13_wrong_alert_id_and_invalid_state_action_are_refused` | Từ chối `alert_id` không tồn tại (`unknown warning`) và hành động trạng thái không hợp lệ | `PASS` |
| 14 | `test_14_wrong_citation_downgrades_to_undetermined` | Sai quote, sai dòng hoặc sai SHA-256 tệp đều ném `EvidenceError` và hạ về `UNDETERMINED` | `PASS` |
| 15 | `test_15_ollama_service_error_and_timeout_downgrade_to_undetermined` | Lỗi kết nối/timeout Ollama hạ về `UNDETERMINED` và giữ `state = OPEN` | `PASS` |
| 16 | `test_16_malformed_json_from_llm_or_scan_is_handled_fail_closed` | JSON sai định dạng từ LLM hoặc raw scan được xử lý fail-closed (`UNDETERMINED` / `issues`) | `PASS` |

---

## 3. Bằng chứng chạy vòng đời CLI thực tế (`stage6_human_review_demo`)

Thực thi trên bản sao độc lập `review_demo.sqlite` (`scan_sha256 = ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f`, `16` cảnh báo):

1. **Trạng thái hàng đợi ban đầu (`01_initial_queue`):**
   - `16/16` cảnh báo đều có `state = "OPEN"` và hiển thị trong `queue` mặc định (bao gồm cả các cảnh báo có `model_status = "REFUTED"` như `0a26cd70...` trên `BenchmarkTest00131.java`).
2. **Từ chối khi thiếu `actor` hoặc `reason` (`03_negative_empty_actor`, `04_negative_empty_reason`):**
   - `exit_code = 2`, `stderr = "UNDETERMINED / operation refused: actor and reason are required"`.
3. **Xác nhận báo động giả hợp lệ (`05_valid_confirm_false` trên `0a26cd70...`):**
   - `exit_code = 0`, `state` chuyển sang `"CONFIRMED_FALSE"`.
   - Hàng đợi mặc định (`06_queue_after_confirm_false`) giảm từ `16` xuống `15` cảnh báo.
   - Hàng đợi đầy đủ (`07_queue_all_after_confirm_false` với `--all`) hiển thị đủ `16` cảnh báo.
4. **Mở lại cảnh báo (`09_reopen_fp_candidate`) và kiểm tra lịch sử (`10_history_after_reopen`):**
   - `state` quay về `"OPEN"`, hàng đợi mặc định khôi phục đủ `16` cảnh báo, và `history` lưu trọn vẹn 2 bản ghi (`sequence = 1: confirm-false`, `sequence = 2: reopen`).
5. **Xác nhận lỗ hổng thật (`11_confirm_true_on_tp` trên `10764728...` - `BenchmarkTest00001.java`):**
   - `state` chuyển sang `"CONFIRMED_TRUE"`, cảnh báo tiếp tục hiển thị trong hàng đợi mặc định (`12_queue_after_confirm_true`) kèm bản ghi kiểm toán `sequence = 3` trong `history` (`evidence_sha256 = ec15df5380d57867a480ad1458c4e3b8808f1184fc22111a6d22a0c65d41855b`).
