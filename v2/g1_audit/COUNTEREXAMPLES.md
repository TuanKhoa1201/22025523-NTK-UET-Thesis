# Báo cáo phản chứng G1

Nguồn kiểm thử: Java/JSON/SARIF/SQLite tự tạo trong thư mục tạm; mock `OllamaClient.request`; test prompt/review được chọn từ checkout Antigravity cố định. Không có lượt quét OpenGrep hoặc inference Qwen thật trong các test này. Không đo nhãn TP/FP hay hiệu quả LLM.

| Nhóm phản chứng | Thao tác | Kết quả được kiểm |
|---|---|---|
| JSON/JSONL | Duplicate key, NaN/Infinity/overflow, sai schema/status, thiếu/thừa/đảo row, trùng ID/index, sai alert/scan hash, raw trace đổi | Parser hoặc join từ chối; không default PASS |
| JSON/SARIF | Một phía rỗng, thừa/mất/nhân đôi finding, sai rule/line/column/severity/CWE/ruleIndex, invocation thất bại | FAIL khi dữ liệu mâu thuẫn; cả hai empty hợp lệ có positive control |
| URI/path | Traversal literal/percent, URI remote, query, percent sai; raw source ngoài root | Từ chối. File URI local và URI space-encoding có positive control; không sửa raw |
| Manifest | Hash/log đổi, rules/source trước-sau khác, exit sai, `success` sai kiểu, version/format/target/config bất nhất, file-output thoát capture | FAIL. Artifact bị thiếu là INCOMPLETE theo hợp đồng; exit 0 không bù được thiếu output |
| Java | Hash/size khác, snippet quote/matched/line/column sai, source bị sửa/xóa, thêm file vào inventory | Từ chối tính toàn vẹn hiện tại; không gọi thiếu trace là cảnh báo giả |
| Model/validator | JSON/schema/citation sai, source/sink thiếu, helper chưa giải quyết, REFUTED thiếu căn cứ, model 404/offline/timeout/HTTP error/truncated/wrong ID, nguồn đổi trong request | UNDETERMINED hoặc validator từ chối, cảnh báo vẫn giữ trong SQLite |
| Prompt | Trường heuristic và nested verdict cài thêm; Java literal chứa token status và chỉ thị giả | Blind payload loại trường heuristic; literal vẫn nằm trong user evidence, không trở thành system instruction. Không khẳng định model thật sẽ chống được prompt injection |
| Human review | REFUTED nhập mới; true/false/reopen; duplicate import; stale/delete/outside-root rồi confirm-false | OPEN cho REFUTED; queue/all/history đúng; action bị từ chối giữ state/history, reopen còn dùng được |
| SQLite artifact | Forged source+observed cùng nhau, digest evidence sai, mất warning, sai scan join, trạng thái không có event, orphan event, actor/reason/time sai | Auditor từ chối; positive control dùng đúng snapshot object và observed hash string thông qua |
| Test receipts | Zero discovery, import error, subtest fail, skip, exit/count/log/aggregate/hash mâu thuẫn, wrong checkout SHA/tracked changes | Không nhận là lượt test PASS; số discovery/run/outcome được đối chiếu độc lập với log |
| Release/runtime | Marker chưa có/chưa READY, SHA marker khác Git, JavisOS khác candidate ID/SHA | Chưa có candidate vẫn INCOMPLETE; receipt khớp chỉ chứng minh join public, không trở thành raw/runtime attestation |

Một test đọc cặp `v2/demo/smoke_v2_taint_raw.opengrep.{json,sarif}` có sẵn tại reference chỉ để kiểm SARIF format (rule descriptors/defaultConfiguration/CWE tags/columns). File không được sao chép lên audit, không chỉnh sửa, không dùng để chứng minh G1/G0 runtime; hash nguồn định dạng được ghi trong báo cáo cuối.

Lỗi đã tìm trong **bộ audit**, đã sửa: so sánh sai hình dạng source-version SQLite; parser target dựa vào argv cuối không tương thích file-output CLI kế thừa; dùng JSON parser thường ở JSONL/SQLite; đếm test bằng regex thiếu đối chiếu discovery; SQLite connection chưa đóng trên Windows. Đây không phải lỗi production được quy cho Antigravity.

Giới hạn phản chứng: kiểm dữ liệu/luồng fail-closed không chứng minh kết luận an ninh đúng. Citation có thể khớp văn bản nhưng vẫn không chứng minh cơ chế bảo vệ; output luôn phải giữ `security_conclusion_verified=false` và kiểm duyệt người dùng. Lịch sử unsigned có thể bị người sửa toàn bộ artifacts giả mạo; auditor chỉ phát hiện mâu thuẫn quan sát được, không tạo ra authentication hoặc execution attestation.
