# Biên nhận kiểm toán độc lập G1-C1

**Phán quyết: INCOMPLETE — CANDIDATE_NOT_AVAILABLE.**

Remote Antigravity ở cả đầu và cuối phiên vẫn là `457183f9e17892fe284da04b57ef6c5c24b008e0`. `git ls-tree` tại SHA này không có `v2/g1_integration/CANDIDATE.json`. Chưa có ứng viên READY để nghiệm thu. `tested_sha` của candidate là null; SHA trên chỉ là mã nền đã kiểm tra trong checkout detached riêng. Nhánh Codex ban đầu `30b0bac464ade5c5f32287917eb877a575308a06`, JavisOS `bf19b5e1392645baba55e5039ebc0d71a1af9aaa`.

## Kết quả đã thực hiện

**59 PASS / 0 FAIL / 0 SKIP**, exit 0 cho cả bốn tiến trình kiểm thử. 27 test audit độc lập (19 test target, 8 test auditor), 32 test hợp đồng/kiểm duyệt của Antigravity. Tất cả là synthetic/mock, không gọi OpenGrep/Qwen thật. Chạy lại sau thay đổi cuối cùng bằng:

```text
python -X utf8 -B v2/g1_audit/run_checks.py --checkout v2/g1_audit/.local/reference --expected-sha 457183f9e17892fe284da04b57ef6c5c24b008e0 --output v2/g1_audit/.local/checks-final
```

Thư mục output phải mới khi tái lập. Runner lưu riêng argv, cwd, exit, thời gian, phiên bản môi trường và hash log. Các lệnh cụ thể cùng số test từng tiến trình trong `VERDICT.json`; đường dẫn máy cá nhân được thay bằng placeholder trong bản công khai.

Kiểm tra không có runtime bundle trả **INCOMPLETE, exit 2**, không tự PASS. Marker lookup exit 0, stdout rỗng. Đây là phép kiểm tra bộ audit, không phải scanner thất bại. Log/SQLite/prompt raw không được công bố. Receipt công khai chứa hash, không chứa nguồn riêng.

Các invariant đã kiểm: payload blind loại heuristic/nested verdict nhưng giữ literal Java trùng status; validator từ chối JSON/schema/citation sai và nguồn thay đổi; REFUTED không tự ẩn cảnh báo; quyết định true/false và reopen giữ lịch sử; duplicate import không ghi đè; nguồn sửa/xóa/thoát root chặn confirm-false, giữ queue và lịch sử; mock lỗi HTTP/offline/timeout về UNDETERMINED.

## Lỗi và điều kiện nghiệm thu

`G1-EVIDENCE-01`, mức ACCEPTANCE_BLOCKER do thiếu bằng chứng: marker candidate chưa tồn tại. Không xác lập lỗi production G1 từ việc thiếu candidate. Lệnh tái hiện:

```text
git ls-tree -r --name-only 457183f9e17892fe284da04b57ef6c5c24b008e0 v2/g1_integration
```

Cả mười điều kiện nghiệm thu G1 đều INCOMPLETE trong phạm vi candidate/runtime. Test mã nền không được nâng thành PASS cho candidate. Không sửa production, dữ liệu G0, nhãn hoặc lịch sử. Không dùng báo cáo G0 như bằng chứng G1.

## Giới hạn và bước nghiệm thu tiếp theo

Checklist C1–C8 và lệnh demo được nêu ở `../README.md`. Khi có READY: fetch, lấy SHA thực, checkout detached mới, lưu candidate_id/marker hash, chạy lại test và kiểm tra runtime bundle cùng CLI receipts. Phải quan sát CLI kế thừa → scanner OpenGrep → raw handoff không rescan; đối chiếu request/response/prompt/digest Qwen local, validator và SQLite/demo tại cùng SHA. Chưa có G1-C2 để kiểm tra trong phiên này.

Auditor artifact chỉ kiểm tra tính nhất quán; các gate quan sát độc lập luôn INCOMPLETE cho tới khi reviewer có evidence thật. Chưa có adapter SARIF column/severity/CWE đầy đủ. Hash/HTTP/model counters không là attestation hệ thống, citation đúng không là security truth, và không có đo TP/FP hay thực nghiệm G3.

Thời điểm, môi trường, lệnh, exit, hash bằng chứng và hash mã kiểm tra ở `VERDICT.json`. Commit chứa biên nhận được xác định qua `git log -1 --format=%H -- v2/g1_audit/G1-C1/VERDICT.json`; không ghi SHA tự tham chiếu giả vào file.
