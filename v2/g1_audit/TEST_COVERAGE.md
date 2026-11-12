# Bao phủ nghiệm thu G1

Baseline 59 PASS tại `b74e5a3` giữ nguyên lịch sử. Lượt nâng cấp checkpoint 97 PASS có receipt riêng; lượt cuối được ghi trong `receipts/FINAL_CHECKS.json`. Không cộng các lượt chạy lại để tăng số test.

Bổ sung sau receipt JavisOS: lượt mới nhất 130 PASS được ghi riêng trong `receipts/POST_JAVIS_CHECKS.json`, thay cho số 127 của cửa sổ trước. `review_javis.py` kiểm tra public readiness report, có synthetic positive/negative controls trong `test_release.py`; bảy kiểm tra report thật được ghi riêng ở `RUNTIME_CROSSCHECK.md`, không tính thành unittest/live runtime.

| Nhóm yêu cầu | Mã kiểm tra chính | Loại bằng chứng | Phần còn thiếu khi chưa có candidate |
|---|---|---|---|
| B1 JSON/JSONL | `contracts.strict`, `validate_bundle`, `validate_rows`; `test_deep_audit` | Synthetic corruption + positive control | Artifact thực của integration |
| B2 Capture | `Audit.manifest`, `sources`; stdout/file-output positive controls | Hợp đồng producer đọc static + synthetic | OpenGrep thực, engine/config/source provenance và no-rescan |
| B3 JSON/SARIF | `compare_sarif`; các ca URI/column/rule metadata/multiplicity | Synthetic và cặp format lịch sử chỉ đọc | Cặp cùng lượt quét candidate |
| B4 SQLite | `Audit.database`, `test_deep_audit`; lifecycle/stale tests | Synthetic artifacts, negative/positive runtime ứng dụng Python cục bộ | CLI demo G1 và DB/receipts cùng scan thật |
| B5 Runner | `unittest_probe`, `reconcile`, `guard_checkout`, `verify_test_receipt`; `test_runner` | Tiến trình unittest thật; bài con cố ý fail/skip được kiểm bằng bài cha | Test receipt gắn SHA candidate thực |
| C2 Java grounding | `Audit.sources`, `CandidateChecks`, peer prompt/review suites | Java tạm + mock transport | Snapshot/trace gắn scanner thật |
| C3 Qwen/validator | `CandidateChecks`, peer payload suite | Mock request/response; không có Qwen thật | Tag/digest/prompt/hash/HTTP raw và quan sát local |
| C4 Human review | `CandidateChecks`, peer review suite | SQLite tạm; actor SCRIPTED | Thao tác CLI candidate và độc lập quyết định người thật |
| D CLI kế thừa | `inspect_cli`, `CLI_REVIEW.md` | Static AST/hash; không call trace runtime | Entry module + executed function + patched scanner/bridge receipts |
| E/F Candidate/JavisOS | `inspect_release`, `test_release` | Git tree/remote HEAD; join synthetic | Marker READY và runtime đúng SHA |
| G Git attributes | `inspect_git_attributes` | Git 2.39.1 thực trên pinned checkout + repo synthetic BOM/no-BOM | Khuyến nghị Antigravity xử lý comment BOM; không chặn G1 nếu raw giữ nguyên |

Các test case dùng `subTest` tính theo số bài unittest discovery, không tính mỗi mutation thành một bài riêng. Expected failures và unexpected successes có trường riêng. Test vắng/import lỗi không được chuyển thành PASS. Skip phải có log và outcome; lượt cuối báo cáo số skip thực tế. Các module test producer được chọn đúng hai nhóm phục vụ prompt/validator/kiểm duyệt, không chạy lại toàn bộ kiểm toán G0.

Không có synthetic PASS nào được tính vào tám gate runtime như bằng chứng live. Gate verdict cuối nằm trong `SESSION_VERDICT.json`.
