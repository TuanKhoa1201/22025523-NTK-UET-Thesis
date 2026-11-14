# Bộ nghiệm thu độc lập G1

Phạm vi: đường CLI kế thừa simple_semgrepAI → OpenGrep → Qwen local → validator → kiểm duyệt. Chỉ thư mục này thuộc quyền sửa của reviewer. Không dùng kết quả G0 để chứng minh runtime G1. Python 3.10+, thư viện chuẩn. Không có inference cloud hoặc benchmark.

## Chạy kiểm tra phản chứng

Tạo checkout detached riêng tại SHA ứng viên đã fetch và xác minh marker `v2/g1_integration/CANDIDATE.json` có trạng thái `READY_FOR_INDEPENDENT_TEST`. Ghi nguyên marker và hash ở vùng bằng chứng riêng. Không chạy trên branch có thể thay đổi. Ví dụ từ repository chứa bộ audit:

```text
python -X utf8 -B v2/g1_audit/run_checks.py --checkout <checkout-detached> --expected-sha <full-SHA> --output <thu-muc-moi-ngoai-checkout>
```

Runner yêu cầu checkout detached, kiểm tra SHA và thay đổi tracked trước/sau, timeout 90 giây cho từng tiến trình, ghi argv/cwd/exit, thời gian, SHA-256 stdout/stderr, mã test và số PASS/FAIL/ERROR/SKIP/XFAIL/XPASS vào `checks.json`. `unittest_probe.py` ghi số discovery, số test chạy và outcome từng bài; runner đối chiếu chúng với log và exit. Log gốc chỉ lưu cục bộ. Không ghi vào checkout được kiểm tra; fixture Java và SQLite nằm trong TemporaryDirectory riêng. Hai module test của Antigravity được chọn vì trực tiếp kiểm tra prompt/validator/kiểm duyệt G1; đây không phải mở lại kiểm toán G0. Test mô phỏng không chứng thực scanner/model thật. Lỗi import hoặc test rỗng không được tính thành công.

## Kiểm toán hiện vật chỉ đọc

```text
python -X utf8 -B v2/g1_audit/audit.py --checkout <checkout-detached> --evidence <runtime-bundle> --output <thu-muc-moi-ngoai-checkout-va-evidence>
python -X utf8 -B v2/g1_audit/verify_test_receipt.py <thu-muc-chua-checks.json-va-log>
```

Bundle cần `engine/{scan-manifest.json,opengrep.json,opengrep.sarif,rules.snapshot.yml,version.*,json.*,sarif.*}`, `input.opengrep.json`, `evidence.json`, `assessments.jsonl`, `review.sqlite`. Các tên log theo hợp đồng `ntk-scan-capture-1`. Nếu CLI ghi capture riêng, dùng `--capture <thu-muc-capture-goc>` và `--evidence <thu-muc-triage>`; auditor đọc trực tiếp hai thư mục, không cần di chuyển/viết lại raw. Nguồn Java theo `evidence.json.root` phải còn truy cập được trên máy kiểm tra. Path mappings WSL đã ghi rõ trong evidence được kiểm lại theo prefix; không đoán `path_base` hoặc tự remap nguồn xuyên máy. Layout hoặc trường hợp không có đủ metadata được báo INCOMPLETE.

Auditor độc lập tính lại hash, đối chiếu bytes handoff, full finding ID theo hash scan/index, raw finding/trace, rule/severity/CWE JSON, multiset JSON/SARIF, snapshot/scan-time hash và replay trạng thái từ sự kiện SQLite. SQLite mở `mode=ro&immutable=1`; nếu WAL chưa rỗng, yêu cầu người tạo evidence cung cấp snapshot nhất quán, không tự checkpoint. Không đọc hoặc tin `summary.json`. Không chạy lệnh được khai báo trong evidence. Đầu ra `audit.json`, `audit.md`; exit 0/1/2 tương ứng PASS/FAIL/INCOMPLETE.

Thiếu file → INCOMPLETE; artifact có nhưng sai hợp đồng → FAIL. Hash chỉ chứng minh nhất quán, không chứng thực người tạo. Trường runtime là bộ đếm quan sát được khai báo, không phải kết luận đã chạy Qwen thật. Auditor luôn giữ các gate cần quan sát độc lập ở INCOMPLETE; không có đường tự động PASS G1 từ artifact unsigned. Reviewer phải lập VERDICT riêng sau khi kiểm tra CLI, model và demo trên đúng SHA.

## Hợp đồng nghiệm thu và mức bao phủ

| Ca | Đã chuẩn bị tự động | Bằng chứng runtime bắt buộc khi có candidate |
|---|---|---|
| C1 | Ghim SHA, kiểm tra trạng thái checkout; gate CLI chưa được tự động thông qua | `semgrepai.__main__`/console entry → `semgrepai.cli` → patched scanner; module/code hash, argv/config, command receipt và handoff. Scanner-only, CLI triage hoặc script riêng không đủ |
| C2 | Manifest/hash/exit/stdout/file-output, raw bytes, ID/trace, multiset rule/path/line, cột/severity/CWE/ruleIndex SARIF khi có; đếm mức bao phủ trường tùy chọn | Engine executable thực và version; config/rule hashes; source trước/sau; số lần gọi scanner đúng thiết kế (hai lượt JSON/SARIF trong một session được phép, handoff không scan lại) |
| C3 | Đếm mock/request/response/validator tách riêng; chặn endpoint ngoài loopback | Request/response bytes và hash, finding join, model/tag/digest từ tags/show, prompt version/hash/contract, thời gian, daemon/observer logs. HTTP 200/exit 0/transport không đủ; local observed vẫn không phải attestation hệ thống |
| C4 | Blind whitelist, nested injection, giữ nguyên literal Java trùng status; peer whitelist suite | Payload thật tương ứng request và prompt hash |
| C5 | JSON/schema/status/citation file/line/quote/hash, thiếu bằng chứng và nguồn đổi; positive citation control không nhận security truth | Raw model status đối chiếu output validator, lỗi → UNDETERMINED; citation đúng không chứng minh kết luận bảo mật đúng |
| C6 | REFUTED vẫn OPEN; confirm true/false, queue/all, reopen/history, duplicate import; peer negative suite | CLI receipt + SQLite cùng demo; actor SCRIPTED phải ghi rõ, không giả danh đánh giá người thật |
| C7 | Bản sao Java tạm, sửa byte/xóa/traversal, từ chối false, queue giữ cảnh báo, lịch sử giữ nguyên và reopen | Scan-time SHA từ scanner thật trước khi sửa; receipt CLI từ chối và SQLite trước/sau |
| C8 | Offline/timeout/HTTP error được mock; incomplete context và validator lỗi; malformed artifact fail closed | Scan lỗi, JSON/SARIF lỗi, missing trace/context, nguồn đổi giữa các bước trên integration thật |

Mười điều kiện của giảng viên (fork CLI, OpenGrep, không cần Semgrep, raw bảo toàn, Qwen local, validator ba nhóm, human review độc lập, source hash, demo/tái lập, commit/thực nghiệm) đều phải có bằng chứng riêng. Unit PASS chỉ hỗ trợ gate được kiểm, không thay thế mười điều kiện này. Không đo precision/recall/TP/FP hoặc dùng Qwen làm ground truth.

## Giới hạn và công bố

Không có candidate thì biên nhận G1-C1 ghi `CANDIDATE_NOT_AVAILABLE`, tested candidate SHA = null; SHA mã nền phải ghi tách riêng. Tối đa hai vòng ứng viên trong phiên. G1-C2 cần SHA và kết quả mới. Chỉ commit mã audit, báo cáo và hash/biên nhận công khai an toàn; không commit `.local`, prompt riêng, SQLite hoặc raw log. Báo cáo không được sửa trạng thái INCOMPLETE thành PASS bằng tay khi thiếu bằng chứng.

## Công cụ kiểm tra bổ sung

```text
python -X utf8 -B v2/g1_audit/inspect_cli.py --checkout <checkout-detached> --expected-sha <SHA> --output <file-json-moi-ngoai-checkout>
python -X utf8 -B v2/g1_audit/inspect_release.py --checkout <checkout-detached> --expected-sha <SHA> --output <file-json-moi-ngoai-checkout>
python -X utf8 -B v2/g1_audit/inspect_release.py --checkout <checkout-detached> --expected-sha <SHA> --runtime-receipt <VERDICT-JavisOS.json> --output <file-json-moi-ngoai-checkout>
python -X utf8 -B v2/g1_audit/inspect_git_attributes.py --checkout <checkout-detached> --output <thu-muc-moi-ngoai-checkout>
```

`inspect_cli` chỉ lập inventory AST/hash, không thực thi producer. `inspect_release` lấy SHA từ Git thay vì tin SHA marker; join JavisOS phải đúng candidate ID và SHA, kết quả đọc public receipt vẫn INCOMPLETE về raw/runtime. `inspect_git_attributes` chỉ đọc checkout gốc và dùng repo synthetic tạm trong output để kiểm tra BOM; không sửa attributes hay raw của producer. `public_receipt.py` công bố số đếm/hash đã đối chiếu lại log, không công bố stdout/stderr body. Các báo cáo mới: `AUDITOR_UPGRADE.md`, `TEST_COVERAGE.md`, `COUNTEREXAMPLES.md`, `CLI_REVIEW.md`, `SESSION_REVIEW.md` và `SESSION_VERDICT.json`. Biên nhận tiền ứng viên G1-C1 vẫn giữ nguyên tại commit `b74e5a3` và trong cây hiện tại.

Đối chiếu receipt readiness JavisOS: `review_javis.py --receipt <VERDICT.json> --reference-sha <SHA-ma-nen> --output <file-moi>`. Kiểm tra này chỉ dùng receipt public trước candidate; không phải đọc raw hoặc attestation. Xem `RUNTIME_CROSSCHECK.md` và `receipts/JAVIS_PUBLIC_REVIEW.json`. Regression mới nhất sau cập nhật JavisOS nằm tại `receipts/POST_JAVIS_CHECKS.json`. Wrapper engine chưa có child-exec receipts được báo INCOMPLETE thay vì suy đoán danh tính binary.
