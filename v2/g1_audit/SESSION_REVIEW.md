# Kiểm toán chuyên sâu G1 — biên nhận cuối phiên tiếp nối

**PREPARED_WAITING_FOR_CANDIDATE; phán quyết nghiệm thu G1: INCOMPLETE — CANDIDATE_NOT_AVAILABLE.**

**Bổ sung sau công bố:** JavisOS phát hành receipt readiness tại `4de45981cd83dcada56186d707fe9f11609ed006`. Đã đối chiếu public report, chưa đọc raw máy chủ; candidate vẫn chưa có. Lượt regression mới nhất **130 PASS**, receipt `receipts/POST_JAVIS_CHECKS.json`; xem `RUNTIME_CROSSCHECK.md`. Các số 127 và nhận định chưa có report bên dưới mô tả cửa sổ kiểm tra trước cập nhật này, được giữ lại làm lịch sử rõ ràng.

`reference_sha = 457183f9e17892fe284da04b57ef6c5c24b008e0`; `candidate_sha = null`; `javis_tested_sha = null`. Bốn lần đọc remote xen giữa các chặng công việc đều thấy Antigravity giữ SHA trên và JavisOS giữ `bf19b5e1392645baba55e5039ebc0d71a1af9aaa`. Git tree ở các HEAD đó không có `v2/g1_integration/CANDIDATE.json` hoặc `v2/g1_runtime/.../VERDICT.json`. Không coi reference là ứng viên G1 mới.

## Kết quả và bằng chứng

Lượt cuối **127 PASS / 0 FAIL / 0 ERROR / 0 SKIP / 0 XFAIL / 0 XPASS**, bảy tiến trình exit 0. Có **95 test do Codex sở hữu**, **32 test prompt/review của Antigravity**. Số test được tính từ unittest discovery/run/outcome, đối chiếu log/exit và kiểm lại hash bằng `verify_test_receipt.py`. Không cộng baseline 59 hoặc các lượt chạy trước vào kết quả này.

Lệnh đã chạy:

```text
python -X utf8 -B v2/g1_audit/run_checks.py --checkout v2/g1_audit/.local/reference --expected-sha 457183f9e17892fe284da04b57ef6c5c24b008e0 --output v2/g1_audit/.local/deep-final-v2
python -X utf8 -B v2/g1_audit/verify_test_receipt.py v2/g1_audit/.local/deep-final-v2
```

Cả hai exit 0. Lệnh cụ thể từng tiến trình, discovery/run, thời gian, môi trường, hash test/harness/stdout/stderr/receipt có ở `receipts/FINAL_CHECKS.json`. Log gốc giữ tại `.local/deep-final-v2/`, không push. Khi tái lập dùng output mới.

Kiểm tra CLI của auditor trên artifact synthetic hoàn chỉnh: sáu kiểm tra dữ liệu PASS, bốn gate quan sát runtime INCOMPLETE, aggregate **INCOMPLETE / exit 2**. Đổi JSONL thành duplicate key: **FAIL / exit 1**. Không cung cấp bundle: **INCOMPLETE / exit 2**. Đây là kiểm tra auditor bằng dữ liệu tổng hợp, không có scan/model thật. Command receipts ở `SESSION_VERDICT.json`.

## Những phần đã hoàn thành

Gia cố parser JSON/JSONL và schema/join/order; manifest/argv/hash/source; SARIF columns/severity/CWE khi có; snippet byte/line/quote/hash; SQLite scan/warning/event/digest/version replay; runner và bộ xác minh receipt. Hỗ trợ `--capture` riêng cho layout CLI kế thừa, không cần sửa hoặc dời artifact. Chi tiết ở `AUDITOR_UPGRADE.md` và `TEST_COVERAGE.md`.

Phản chứng có positive controls cho scan rỗng hợp lệ, SARIF thiếu optional fields, URI local có encoding, manifest stdout/file-output, source mapping rõ ràng, SQLite confirm true/false/reopen, không đổi byte database khi audit, và receipt có skip hợp lệ. Các lỗi model/validator/source không làm mất cảnh báo. Xem `COUNTEREXAMPLES.md`.

Kiểm tra thiết kế CLI được ghi trong `CLI_REVIEW.md` và `receipts/STATIC_CLI_REFERENCE.json`. Đã phân biệt triage riêng, scanner-only fork và Typer CLI kế thừa. Reference scan-only overlay có return sau scanner; chưa có bridge G1 tại SHA này. Không sửa producer hoặc kết luận candidate chưa xuất hiện có lỗi triển khai.

## Tám gate nghiệm thu

| Gate | Trạng thái | Lý do còn thiếu |
|---|---|---|
| Fork CLI | INCOMPLETE | Chưa có candidate và executed-call receipts |
| Engine | INCOMPLETE | Chưa có OpenGrep scan candidate |
| Qwen local | INCOMPLETE | Chưa có request/response/prompt/digest/runtime candidate |
| Validator | INCOMPLETE | Chỉ có synthetic/mock trên reference |
| Human review | INCOMPLETE | Chỉ có SQLite/Java tạm, chưa có CLI demo G1 |
| STALE_SOURCE | INCOMPLETE | Chưa có source hash từ scanner thật của candidate |
| Reproducibility | INCOMPLETE | Bộ audit đã có lệnh, ứng viên integration/demo còn thiếu |
| Candidate integrity | INCOMPLETE | Chưa có candidate diff để kiểm; thay đổi của Codex chỉ thuộc `v2/g1_audit/` |

## Lỗi và trở ngại

| ID | Mức độ | Bằng chứng và phạm vi |
|---|---|---|
| G1-EVIDENCE-01 | BLOCKER nghiệm thu | Marker READY chưa có; không là lỗi production đã xác lập |
| G1-EVIDENCE-02 | BLOCKER nghiệm thu | Chưa có runtime receipt theo candidate trên JavisOS; chưa kiểm raw máy chủ |
| G1-GIT-01 | MINOR | `v2/demo/.gitattributes:1` có BOM làm parser cached coi comment là pattern với Git `2.39.1.windows.1` |

Cảnh báo Git tái hiện bằng `git -C <reference> check-attr --cached -a -- v2/demo/smoke_m1_rules_raw.opengrep.json`, exit 0 kèm stderr `(SHA-256: is not a valid attribute name`. Positive control repo tạm: có BOM → warning, bỏ BOM → hết warning; `-text` vẫn được áp dụng ở cả hai. Hash raw Git blob và working file giống nhau: `005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`. Comment attributes có chuyển LF/CRLF trong checkout nhưng raw được giữ nguyên. Không sửa attributes hoặc raw; Antigravity có thể xử lý comment BOM với ưu tiên thấp. Evidence: `receipts/GIT_ATTRIBUTES.json`.

Không có MAJOR production mới được xác lập. Các lỗi auditor đã sửa được liệt kê riêng trong báo cáo phản chứng, không quy thành lỗi Antigravity.

## Giới hạn và bàn giao

Không có candidate thực sự được kiểm trong phiên này; không phát hành biên nhận C2 giả. Biên nhận tiền ứng viên `G1-C1/VERDICT.json` và Markdown giữ nguyên, truy xuất được tại `b74e5a31f24daa2141bb17ff5195801923b1512c`; hash bản hiện tại ghi trong `SESSION_VERDICT.json`. Khi C1 thật xuất hiện phải lưu/đối chiếu tiền ứng viên, kiểm SHA mới và cập nhật biên nhận với lịch sử rõ ràng.

Không đọc raw evidence máy chủ, không quan sát runtime JavisOS và không chạy Qwen/OpenGrep trong bộ test. Công cụ join public receipt đúng SHA đã có; join khớp vẫn không phải attestation. Một cặp JSON/SARIF lịch sử chỉ dùng kiểm định dạng; không đánh giá lại G0. Không đo accuracy/TP/FP hoặc kết luận Qwen cải thiện OpenGrep.

Giới hạn còn lại: artifacts và actor unsigned; source race giữa các phép kiểm không được OS cô lập; path_base thiếu metadata không được đoán; optional SARIF fields vắng được công bố thay vì tự điền; trước/sau tracked-file guards không chứng minh được mọi thay đổi tạm thời rồi phục hồi giữa hai phép kiểm. Runtime thật, no-rescan, prompt/hash/digest và demo phải được kiểm trên candidate cố định.

Checkpoint gia cố: `6d9d3f5` (đầy đủ SHA trong `SESSION_VERDICT.json`). Commit chứa biên nhận cuối tra bằng `git log -1 --format=%H -- v2/g1_audit/SESSION_VERDICT.json`. Chỉ công bố mã audit/tài liệu/receipt an toàn; `.local`, logs, SQLite và raw prompt không nằm trong commit.
