# Đối chiếu receipt JavisOS sau cập nhật remote

Sau khi công bố checkpoint `dfca40ab179356330c770c963d03913b4feb7173`, remote JavisOS đổi từ `bf19b5e…` sang **`4de45981cd83dcada56186d707fe9f11609ed006`**. Đã fetch riêng nhánh JavisOS, không đổi nhánh làm việc hoặc sửa producer. Phần này bổ sung cho quan sát trước đó, không làm candidate xuất hiện hồi tố.

Nguồn: `v2/g1_runtime/G1-C1/VERDICT.json` và `RUNTIME_REPORT.md` tại commit JavisOS trên. SHA-256 JSON công khai: `9c731a6b7409b25fbae3bbfeeef40a136f218c3dc5cbfcf4a9068b8dc8c1bf2e`.

**Kết quả Codex: 7 kiểm tra nhất quán public receipt PASS; nghiệm thu G1 vẫn INCOMPLETE.** `candidate_available=false`, `tested_sha=null`, `reference_pre_g1_sha=457183f9e17892fe284da04b57ef6c5c24b008e0`, trùng mã nền Codex đang kiểm. Không có candidate để join. `javis_tested_sha` vẫn null; SHA công bố report không phải SHA hệ thống được nghiệm thu.

## Dữ liệu JavisOS báo cáo và kiểm tra Codex

| Mục | JavisOS báo cáo | Phạm vi kiểm tra Codex |
|---|---|---|
| Engine | OpenGrep 1.25.0 qua wrapper đếm lời gọi và WSL | Đối chiếu version giữa các phần JSON; chưa đọc wrapper/child-exec/raw logs máy chủ |
| Model | `qwen3.5:9b-q4_K_M`, digest `56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90`, loopback | Tag/digest/endpoint nhất quán trong report; không kiểm daemon/GPU hoặc digest thực |
| Prompt | `v2.2.1-cwe22-cwe89-whitelist`; schema hash và hash request từng warning | Kiểm hình dạng hash; chưa có prompt/request bytes để tái tính. Schema hash không thay thế prompt SHA |
| Finding/trace | 5 finding, 5 có source/sink | Số đếm khớp 5 hàng report; 4 ID demo1 khớp công thức từ scan hash/index khai báo |
| HTTP/validator | 5 lời gọi demo, 4 hợp lệ, 1 không hợp lệ; preflight thêm 1 | Các counter khớp từng hàng, status histogram 4 SUPPORTED + 1 UNDETERMINED. Không tự quan sát HTTP |
| Review | Hàng đầu OPEN; false confirmation SCRIPTED-DEMO, reopen; stale-source exit 2 không thêm event | Các trường mô tả nhất quán; chưa đọc SQLite, source hoặc action logs gốc |
| Handoff | Scanner-only CLI rồi triage import riêng; 0 scan thêm trong triage | Receipt tự nhận chưa có integrated bridge; không dùng để PASS CLI kế thừa G1 |
| Thời gian/exit | 23 command receipts; wall 85.38534 giây, Qwen tổng 52.875 giây | Kiểm timestamp, exit/hash syntax và cộng latency từng warning |
| Artifacts | 19 hash artifact public | Hash có hình dạng SHA-256; không tái tính từ artifact riêng. Demo2 raw scan hash chưa có trong bảng này nên chưa tự join ID demo2 |

Demo 5 được ghi rõ fault injection mock. Demo 2 có raw model REFUTED nhưng validator UNDETERMINED, warning vẫn OPEN trước quyết định SCRIPTED-DEMO. Không coi đây là quyết định độc lập của chuyên gia hoặc ground truth. Wording “Qwen UNDETERMINED” trong Markdown phải hiểu là trạng thái sau validator; JSON giữ riêng raw REFUTED và validated UNDETERMINED.

## Công cụ và lệnh tái lập

```text
python -X utf8 -B v2/g1_audit/review_javis.py --receipt <ban-xuat-VERDICT.json-dung-commit-JavisOS> --reference-sha 457183f9e17892fe284da04b57ef6c5c24b008e0 --output <file-json-moi>
```

Lượt đã chạy có 7 kiểm tra public consistency PASS, exit 2 vì chưa nghiệm thu candidate. Kết quả: `receipts/JAVIS_PUBLIC_REVIEW.json`. Adapter này dành riêng receipt readiness tiền ứng viên; candidate thực phải qua `inspect_release.py` để join đúng candidate_id và tested_sha, rồi kiểm raw/runtime riêng.

Lượt regression sau cập nhật: **130 PASS / 0 FAIL / 0 ERROR / 0 SKIP**, gồm 98 test Codex và 32 test Antigravity. `receipts/POST_JAVIS_CHECKS.json` là receipt mới nhất; `FINAL_CHECKS.json` (127) và baseline/checkpoint trước đó được giữ nguyên. Bảy kiểm tra receipt công khai không cộng vào số bài unittest này.

Wrapper `opengrep_counted.cmd` là cơ chế hợp lệ có thể dùng trong runtime. Auditor hiện trả INCOMPLETE khi chưa được cung cấp chain wrapper → binary thực; tên wrapper lạ không tự trở thành lỗi engine. Executable Semgrep được xác định rõ vẫn FAIL. Không thay wrapper/producer để vượt test.

Giới hạn: chỉ đọc public report trong Git, không truy cập vùng private trên ADMIN-PC; chưa đọc raw JSON/SARIF, prompt/HTTP bodies, nguồn, SQLite hay daemon logs. Các mức “runtime observed” trong report là quan sát **do JavisOS công bố**, không phải Codex tự quan sát. Gate G1 không được nâng thành PASS từ receipt này.
