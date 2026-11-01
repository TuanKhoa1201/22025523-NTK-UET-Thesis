# NTK — Tổng hợp nghiệm thu nhiều dự án và đầu vào, 02/11/2026

**NTK_THESIS_E2E_READY=PARTIAL cho phạm vi mở rộng này.** Đã chạy thật cả 8 dự án, kiểm tra input, sửa lỗi và quét lại sau sửa. Ba scan chỉ bao phủ 16 file; detector chưa phân biệt traversal của cặp Spark. Demo vận hành ổn định; không tuyên bố mọi Java vulnerability được phát hiện.

## Báo cáo và bằng chứng

- [8 dự án, nguồn, scope, scan IDs, CWSS và URLs](NTK_8_PROJECT_E2E_REPORT.md).
- [Input validation, ZIP/Git/local, zero candidates và website](NTK_INPUT_VALIDATION_REPORT.md).
- [Phạm vi đánh giá accuracy](NTK_DETECTION_ACCURACY_REPORT.md).
- [Ground truth OWASP 6+40, trước/sau sửa, metric và giới hạn ablation](NTK_GROUND_TRUTH_EVALUATION.md).
- [Manifest nguồn](docs/evaluation-20261102/source-manifest.json), [80 stage records](docs/evaluation-20261102/multiproject-stages.csv), [2.624 metric records](docs/evaluation-20261102/multiproject-metrics.csv), CSV/JSON evaluation ở cùng thư mục.

Raw requests/responses, ZIPs, code snapshots, private paths/registries, screenshots, logs và database backups chỉ trong **ignored `work/e2e-multiproject-acceptance/`**. Không đưa dataset private, model, SQLite hoặc screenshots lên GitHub. Giữ nguyên `work/acceptance/runtime` cho demo.

## Lỗi được tìm và sửa

| Vấn đề trước sửa | Nguyên nhân | Bản sửa và kiểm tra sau |
|---|---|---|
| ZIP Python/mixed bị xử lý như executable forbidden | `.py` nằm trong danh sách cấm trước bước inventory | Bỏ qua source Python thụ động; mixed Java tiếp tục; không giải nén/chạy Python; giữ bytecode/scripts/size/traversal guards |
| File giả `.java`/Java lỗi cú pháp có thể đi vào scan rỗng | Chỉ inventory theo suffix; parse không là điều kiện đầu vào | JavacTask parse-only, diagnostics theo file; JAVA_SYNTAX_ERROR ở stage 02, không Qwen/findings giả |
| Zero findings chưa có database CWSS trả lỗi scenario | Endpoint yêu cầu database trước khi xét danh sách rỗng | HTTP 200 assessments=[]; không tạo database/score/16 metric giả |
| Scanner chưa upload ZIP, thiếu ref/subpath/scope | UI mới chỉ có placeholder và Git URL | Tích hợp multipart `/api/scan-jobs` hiện hữu; trạng thái thật, size/extension guard, chống double-click; thêm ref/subpath/bounded scope |
| HTTP error mới bị trạng thái scan cũ ghi đè | Effect restore chạy khi reset job_id trong lần submit tiếp | Ngừng restore khi busy/submitting; clear riêng active panel selection; giữ history |
| Cache Git bị coi dirty dù source bytes không đổi | DrvFS đổi executable bit sau checkout | `git -c core.filemode=false status` chỉ cho lệnh kiểm tra; không sửa config; nội dung/untracked/commit/SHA vẫn kiểm tra |
| Library local inventory từng xóa symlink | Inventory gọi unlink | Bỏ qua symlink và bảo toàn source; HTTP local path mode vẫn tắt |
| Một OWASP true case bị SUPPRESS sai | Case/default switch cùng control scope; thiếu break/default metadata | Scope điều kiện cho CaseTree; metadata; AST V5 và namespace cache mới; case đổi SUPPRESS→REVIEW; không ép REPORT/score |
| History không hiện đủ scan cũ từ browser cache rỗng | API chỉ lấy trang đầu 25 scan; UI đọc ngược từ cache giới hạn 50 | Đọc summary phân trang; render danh sách backend độc lập cache; cache vẫn 50, giới hạn tải 2.000 có cảnh báo; browser xác nhận đủ 92 scan và 8 dự án |

Không sửa rule, threshold, CWSS weights hoặc ground truth để làm PASS. Lỗi switch được sửa sau khi thấy kết quả đánh giá nên lượt 40 sau sửa được công bố là hồi quy sau phát hiện lỗi; không gọi là tập độc lập chưa từng thấy.

Các lần thử chưa đạt và lỗi harness được giữ trong logs: Java bridge compile ở lần nháp, page_size ngoài contract của verifier, race chờ React mount trong browser harness, và lỗi switch/cache thực tế. Kết quả PASS chỉ lấy từ các lượt cuối sau sửa; không xóa artifacts thất bại để che lỗi.

## Kiểm thử thực tế

| Nhóm | Kết quả cuối |
|---|---|
| Backend full unittest suite | **237/237 PASS**, gồm CWSS V2, source collector, AST/false suppression, input safety, lifecycle/index/report, Real25 |
| Evaluation metric unit tests | **2/2 PASS**; ba convention REVIEW, undefined denominator không bị điền metric giả |
| Frontend Node tests | **17/17 PASS**, gồm adapter nối backend thật, multipart/error contract, pagination và cache history |
| React production build | **PASS**, 445 modules; cảnh báo bundle >500 kB còn tồn tại |
| OpenGrep/Javac smoke | **PASS**, 6 fixture candidates, 3 methods AST; JDK 17 |
| API GitHub | **11 ca PASS** theo expected contract, gồm 4 ngôn ngữ, README, mixed, URL/ref/source errors |
| API ZIP/safe/unknown | **21 ca PASS** theo contract; library tests bổ sung symlink, upload/entries/decompression/file/ratio limits với fixtures nhỏ |
| Browser Edge thật | **33 checks PASS** cho 8 project Results, input/error/partial/empty states; double-click chỉ 1 POST |
| Browser bổ sung sau khi dữ liệu tải xong | **3 states PASS**: zero không có `/100`, safe có SUPPRESS/0.0, unknown có REVIEW |
| History từ browser cache rỗng | **PASS**, 92/92 scan hiển thị, đủ 8 project IDs; FAILED và COMPLETED phân biệt đúng |
| Website demo | **12/12 trang PASS**, desktop + Results mobile sanity; report download hoàn thành; replay đến stage 10 và play/pause |
| Scan demo cũ | **37 API checks PASS**; 10 findings; REPORT/REVIEW/SUPPRESS = **2/6/2**; scenario 006/008/009/010 = **84.0/0.0/86.0/0.0** |
| Persist sau restart backend kiểm thử | **48 API checks PASS** trên 8 scan cuối: source-bound CWSS, report, summary, findings, trace vẫn còn |
| Private Real25 | SHA256SUMS **7 entries PASS**, đúng NTK_REAL25_DIR; tests thực chạy, không sửa dataset/expected scores |
| Model | Local/offline, cloud_calls_enabled=false; production actual_model_device=cuda:0 và LoRA params cuda:0; adapter SHA giữ nguyên |
| Khởi động demo | Launcher `-CheckOnly` PASS, tái sử dụng backend/frontend đúng runtime; không ghi đè database |

Browser đã kiểm tra Overview, Scanner, History, Results, Finding Detail, Review, CWSS Scoring, Reports, Dataset, Training, Evaluation và Trace Replay. Không có runtime exception hay lỗi API ngoài lỗi input cố ý trong lượt cuối. Screenshots đã xem, tiếng Việt không mojibake. Không có browser dependency mới được cài.

So với lượt 235 tests trước sửa switch, bộ cuối có thêm hai regression tests switch và đạt 237. Bộ 234/235 trước đó không được dùng để khẳng định lỗi switch đã an toàn.

## Kết quả và giới hạn nghiên cứu

8 scan cuối có **82 candidates**, 82/82 source hash khớp manifest, 16 metrics × 2 modes/finding. Spring Petclinic quét 49 Java, 0 candidates, 0 Qwen, 0 CWSS assessments. WebGoat, OWASP operational fixture và WebGoat SQL có nhãn PARTIAL; bảng 8 dự án không gọi chúng là FULL coverage. WebGoat SQL trùng source WebGoat, không phải mẫu accuracy độc lập.

Spark fixed/vuln cùng upstream và có advisory/source diff phù hợp, nhưng hiện cùng 9 UNKNOWN/REVIEW. Đây là giới hạn detector/dataflow abstraction; không chứng minh bản fixed sạch mọi lỗ hổng hay bản vuln không có lỗi. Path guard fixture nhỏ cũng vẫn REVIEW khi không đủ proof; không auto SUPPRESS.

OWASP 40 cases cuối: report-only TP=3, FP=0, TN=20, FN=17; recall tự REPORT **15%**, F1 **26,09%**, **75% REVIEW**, automatic decision coverage **25%**. Nếu giữ REVIEW trong queue như positive: TP=18, FP=15, TN=5, FN=2; đây không phải 18 TP đã được tự xác minh. Case switch sai suppression đã được giữ lại ở REVIEW; hai true cases vẫn không có target candidate.

Nguồn nhãn là expectedresults-1.2.csv của commit f40c618…, không là kết quả NTK. 6 ca cũ là regression; 40 ca mở rộng đã loại identifiable prior cases nhưng không chứng minh leakage-free. Không có exhaustive ground truth cho 8 source trees nên accuracy tổng thể 8 dự án là NOT_EVALUATED. Chỉ có stage-observation A/B/C thực tế, chưa có full configuration ablation ba deployment được kiểm soát độc lập; không khẳng định riêng Qwen làm tăng precision/recall.

CWSS V2 vẫn là MITRE CWSS 1.0.1 prioritization. FC không tự thành Proven True; UNKNOWN không nâng thành verified; reference scenario là giả định nghiên cứu. Mọi decision mới giữ `numeric_score_used_for_decision=false`, `final_heuristic_score=null`; fields/aggregate legacy phục vụ compatibility lịch sử vẫn có thể còn trong raw API. Không tái tuyên bố mọi tên field legacy đã bị xóa khỏi schema.

Hiệu năng: 8 scan trước/sau sửa lần lượt có **12/6 GPU calls thực**, timer pipeline backend tổng **101,485/65,607 giây**; evaluation 40 baseline có **11 GPU calls**, recheck dùng cache role hợp lệ; input controls có 1 GPU call; hai scan demo fresh có 5+5 GPU calls. Tổng **40 GPU calls** trong các scan mới có records liệt kê, không gồm receipt lịch sử. Không chạy inference CUDA đồng thời, không download base model hay retrain. Timer backend và số cache hit/miss ở CSV/JSON; timer không đo đầy đủ client/network và thời gian publication/index/CWSS phục vụ API, không dùng cold/warm numbers làm benchmark công bằng.

## Runtime và demo

- Demo: [http://127.0.0.1:5173](http://127.0.0.1:5173/#/results?scan_id=SCAN-20261101164045-3AA266), API 8765; backend PID sau nạp bản sửa **43996**. Scan cũ JSON SHA-256 vẫn `70645502e5b86ba59231340a94c540c29c424c119c6650c6d579023b3050e891`.
- Scan GitHub fresh cuối sau sửa: **SCAN-20261101183021-AADAB9**, 10 findings, 5 GPU inference thật, 36,000 giây timer backend. [Results](http://127.0.0.1:5173/#/results?scan_id=SCAN-20261101183021-AADAB9).
- 8 dự án/evaluation có store riêng: [frontend 5174](http://127.0.0.1:5174), API 8766; backend cuối **44621**, đã bỏ model khỏi VRAM bằng restart khi không có job để dành GPU cho demo. Đọc scan/report không tải model; source evidence đã persist.
- Các lần nạp backend mới chỉ thực hiện khi không có job, kiểm tra đúng PID/script/port/store; SQLite được backup read-only trước nạp demo, không thay thế database. Scan/model/dataset cũ không bị xóa. Chỉ runtime test riêng và demo được cập nhật bằng source đã kiểm thử.
- Python `/home/tuankhoa/.venvs/ntk-production-20261028/bin/python`; JDK `/usr/lib/jvm/java-17-openjdk-amd64`; base model, LoRA và dataset paths trong local launch-env đã được kiểm tra tồn tại. Adapter SHA-256 giữ `176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`.
- Sau mở lại máy: launcher `tools/start-demo.ps1` đã có PID/port/path checks; không autostart Windows, không ghi đè store. Chưa reboot máy thật trong đợt này. Không xóa `work/acceptance/runtime`.

Kịch bản bảo vệ: mở scan demo cũ → finding 009/006 và bảng 16 metric → safe 008/010 và audit SUPPRESS → replay 10 stages → tải report. Sau đó mở Petclinic tại 5174 để trình bày zero candidates đúng scope; upload ZIP Python nhỏ để trình bày lỗi có code; trình bày ma trận 40 case và giới hạn REVIEW/Spark thay vì nói hệ thống “100% chính xác”.

## Files và Git

Source/tests/tooling đã commit và push trên **cwss-inference-v2-220**: engine/input commit **5fa5159**, History commit **1a8c7ec** (tiếp từ baseline 39c647c); không merge main/force push/reset/clean. Commit báo cáo đi tiếp trên cùng nhánh; SHA cuối được kiểm tra với remote ref sau push và ghi receipt local, hiển thị trong kết quả bàn giao.

19 files source/tests/tooling thay đổi:

- `apps/22025523-thesis/src/pages/Scanner.jsx`
- `apps/22025523-thesis/src/pages/Results.jsx`
- `apps/22025523-thesis/src/services/api.js`
- `apps/22025523-thesis/src/pages/HistoryPage.jsx`
- `apps/22025523-thesis/src/services/scanHistory.js`
- `apps/22025523-thesis/tests/input-api-contract.test.cjs`
- `apps/22025523-thesis/tests/history-schema.test.cjs`
- `backend/ntk-production-v2/scripts/javac_ast_bridge/NtkJavacAstExtractor.java`
- `backend/ntk-production-v2/scripts/ntk_alert_verification.py`
- `backend/ntk-production-v2/scripts/ntk_web_backend_service.py`
- `backend/ntk-production-v2/scripts/ntk_cwss_reference_scenario_api.py`
- `backend/ntk-production-v2/tests/test_input_validation.py`
- `backend/ntk-production-v2/tests/test_ast_false_suppression.py`
- `backend/ntk-production-v2/tests/test_source_inventory_binding.py`
- `tools/run_multiproject_acceptance.py`
- `tools/evaluate_benchmark.py`
- `tools/verify-input-browser.cjs`
- `tools/verify-history-browser.cjs`
- `tools/tests/test_evaluation_metrics.py`

Bổ sung 4 báo cáo chuyên đề, báo cáo tổng hợp này, appendix ở NTK_FINAL_ACCEPTANCE_REPORT.md, hướng dẫn tools và public metadata/CSV dưới docs/evaluation-20261102. Git ignore `/work/` đã có từ trước; không commit runtime artifacts. Secrets scan và staged-path audit thực hiện trước push. Dừng phát triển tính năng sau bàn giao này.

```text
NTK_8_PROJECT_E2E=PARTIAL
NON_JAVA_INPUT_HANDLING=PASS
ZERO_FINDINGS_HANDLING=PASS
MIXED_LANGUAGE_SOURCE_HANDLING=PASS
VULNERABILITY_DETECTION_ACCURACY=EVALUATED
CWSS_V2_PROVENANCE=PASS
FRONTEND_ACCEPTANCE=PASS
BACKEND_ACCEPTANCE=PASS
GITHUB_SYNC_STATUS=SYNCED
DEMO_STATUS=READY
```
