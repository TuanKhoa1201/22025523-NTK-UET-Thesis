# Bộ nghiệm thu độc lập G1

Phạm vi: đường CLI kế thừa simple_semgrepAI → OpenGrep → Qwen local → validator → kiểm duyệt. Chỉ thư mục này thuộc quyền sửa của reviewer. Không dùng kết quả G0 để chứng minh runtime G1. Python 3.10+, thư viện chuẩn. Không có inference cloud hoặc benchmark.

## Chạy kiểm tra phản chứng

Tạo checkout detached riêng tại SHA ứng viên đã fetch và xác minh marker `v2/g1_integration/CANDIDATE.json` có trạng thái `READY_FOR_INDEPENDENT_TEST`. Ghi nguyên marker và hash ở vùng bằng chứng riêng. Không chạy trên branch có thể thay đổi. Ví dụ từ repository chứa bộ audit:

```text
python -X utf8 -B v2/g1_audit/run_checks.py --checkout <checkout-detached> --expected-sha <full-SHA> --output <thu-muc-moi-ngoai-checkout>
```

Runner kiểm tra SHA và thay đổi tracked trước/sau, timeout 90 giây cho từng tiến trình, ghi argv/cwd/exit, thời gian, SHA-256 stdout/stderr, mã test và số PASS/FAIL/SKIP vào `checks.json`. Log gốc chỉ lưu cục bộ. Không ghi vào checkout được kiểm tra; fixture Java và SQLite nằm trong TemporaryDirectory riêng. Hai module test của Antigravity được chọn vì trực tiếp kiểm tra prompt/validator/kiểm duyệt G1; đây không phải mở lại kiểm toán G0. Test mô phỏng không chứng thực scanner/model thật. Lỗi import hoặc test rỗng không được tính thành công.

## Kiểm toán hiện vật chỉ đọc

```text
python -X utf8 -B v2/g1_audit/audit.py --checkout <checkout-detached> --evidence <runtime-bundle> --output <thu-muc-moi-ngoai-checkout-va-evidence>
```

Bundle cần `engine/{scan-manifest.json,opengrep.json,opengrep.sarif,rules.snapshot.yml,version.*,json.*,sarif.*}`, `input.opengrep.json`, `evidence.json`, `assessments.jsonl`, `review.sqlite`. Các tên log theo hợp đồng `ntk-scan-capture-1`. Nếu integration dùng layout khác, xuất một bản sao riêng có mapping được reviewer ghi nhận; tuyệt đối không sửa raw/SQLite gốc. Nguồn Java theo `evidence.json.root` phải còn truy cập được trên máy kiểm tra. Chưa có tự động remap nguồn xuyên máy.

Auditor độc lập tính lại hash, đối chiếu bytes handoff, full finding ID theo hash scan/index, raw finding/trace, rule/severity/CWE JSON, multiset JSON/SARIF, snapshot/scan-time hash và replay trạng thái từ sự kiện SQLite. SQLite mở `mode=ro&immutable=1`; nếu WAL chưa rỗng, yêu cầu người tạo evidence cung cấp snapshot nhất quán, không tự checkpoint. Không đọc hoặc tin `summary.json`. Không chạy lệnh được khai báo trong evidence. Đầu ra `audit.json`, `audit.md`; exit 0/1/2 tương ứng PASS/FAIL/INCOMPLETE.

Thiếu file → INCOMPLETE; artifact có nhưng sai hợp đồng → FAIL. Hash chỉ chứng minh nhất quán, không chứng thực người tạo. Trường runtime là bộ đếm quan sát được khai báo, không phải kết luận đã chạy Qwen thật. Auditor luôn giữ các gate cần quan sát độc lập ở INCOMPLETE; không có đường tự động PASS G1 từ artifact unsigned. Reviewer phải lập VERDICT riêng sau khi kiểm tra CLI, model và demo trên đúng SHA.

## Hợp đồng nghiệm thu và mức bao phủ

| Ca | Đã chuẩn bị tự động | Bằng chứng runtime bắt buộc khi có candidate |
|---|---|---|
| C1 | Ghim SHA, kiểm tra trạng thái checkout; gate CLI chưa được tự động thông qua | `semgrepai.__main__`/console entry → `semgrepai.cli` → patched scanner; module/code hash, argv/config, command receipt và handoff. Scanner-only, CLI triage hoặc script riêng không đủ |
| C2 | Manifest/hash/exit/stdout/file-output, raw bytes, ID/trace, multiset rule/path/line JSON/SARIF | Engine executable thực và version; config/rule hashes; source trước/sau; SARIF column/severity/CWE rule-index mapping cần kiểm tra bổ sung; số lần gọi scanner đúng thiết kế (hai lượt JSON/SARIF trong một session được phép, handoff không scan lại) |
| C3 | Đếm mock/request/response/validator tách riêng; chặn endpoint ngoài loopback | Request/response bytes và hash, finding join, model/tag/digest từ tags/show, prompt version/hash/contract, thời gian, daemon/observer logs. HTTP 200/exit 0/transport không đủ; local observed vẫn không phải attestation hệ thống |
| C4 | Blind whitelist, nested injection, giữ nguyên literal Java trùng status; peer whitelist suite | Payload thật tương ứng request và prompt hash |
| C5 | JSON/schema/status/citation file/line/quote/hash, thiếu bằng chứng và nguồn đổi; positive citation control không nhận security truth | Raw model status đối chiếu output validator, lỗi → UNDETERMINED; citation đúng không chứng minh kết luận bảo mật đúng |
| C6 | REFUTED vẫn OPEN; confirm true/false, queue/all, reopen/history, duplicate import; peer negative suite | CLI receipt + SQLite cùng demo; actor SCRIPTED phải ghi rõ, không giả danh đánh giá người thật |
| C7 | Bản sao Java tạm, sửa byte/xóa/traversal, từ chối false, queue giữ cảnh báo, lịch sử giữ nguyên và reopen | Scan-time SHA từ scanner thật trước khi sửa; receipt CLI từ chối và SQLite trước/sau |
| C8 | Offline/timeout/HTTP error được mock; incomplete context và validator lỗi; malformed artifact fail closed | Scan lỗi, JSON/SARIF lỗi, missing trace/context, nguồn đổi giữa các bước trên integration thật |

Mười điều kiện của giảng viên (fork CLI, OpenGrep, không cần Semgrep, raw bảo toàn, Qwen local, validator ba nhóm, human review độc lập, source hash, demo/tái lập, commit/thực nghiệm) đều phải có bằng chứng riêng. Unit PASS chỉ hỗ trợ gate được kiểm, không thay thế mười điều kiện này. Không đo precision/recall/TP/FP hoặc dùng Qwen làm ground truth.

## Giới hạn và công bố

Không có candidate thì biên nhận G1-C1 ghi `CANDIDATE_NOT_AVAILABLE`, tested candidate SHA = null; SHA mã nền phải ghi tách riêng. Tối đa hai vòng ứng viên trong phiên. G1-C2 cần SHA và kết quả mới. Chỉ commit mã audit, báo cáo và hash/biên nhận công khai an toàn; không commit `.local`, prompt riêng, SQLite hoặc raw log. Báo cáo không được sửa trạng thái INCOMPLETE thành PASS bằng tay khi thiếu bằng chứng.
