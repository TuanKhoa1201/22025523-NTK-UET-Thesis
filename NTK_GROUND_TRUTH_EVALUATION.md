# NTK — OWASP BenchmarkJava ground truth evaluation

VULNERABILITY_DETECTION_ACCURACY=EVALUATED trên mẫu và quy ước công bố dưới đây. **UNSEEN/LEAKAGE_FREE_STATUS=NOT_PROVEN. POSTFIX_40=REGRESSION_AFTER_EVALUATION_DISCOVERY.** Không dùng kết quả này để khẳng định độ chính xác tổng quát hoặc Qwen cải thiện precision/recall.

## Nguồn, chọn mẫu và tách nhãn

OWASP BenchmarkJava v1.2, commit cố định `f40c618c5a709afce350ef06ed2899c85cf586e9`; [ground truth gốc](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/f40c618c5a709afce350ef06ed2899c85cf586e9/expectedresults-1.2.csv), [source tree](https://github.com/OWASP-Benchmark/BenchmarkJava/tree/f40c618c5a709afce350ef06ed2899c85cf586e9/src/main/java/org/owasp/benchmark/testcode). SHA-256 CSV: `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`. Fetch đúng Git object, chỉ sparse checkout 46 Java + CSV; không build/chạy test servlet. Java source có license OWASP/GPLv2; báo cáo chỉ công bố tên, hashes và kết quả đo.

6 case yêu cầu là regression đã dùng phát triển, không là tập blind. 40 case mở rộng chia đều 5 true/5 false cho mỗi CWE-22/78/79/89; lựa chọn xác định bằng sort SHA-256 seed `NTK_EVAL_FIXED_SEED_20261102:<case>`, loại 6 ca cũ, 16 ca operational đã dùng và các ID case nhận diện được từ registry trước đó. Đã kiểm tra có giới hạn 73 artifacts/registries, 14457339 bytes; loại 26 IDs. Không công bố nội dung/path dataset private. Không đủ manifest toàn bộ training/rule tuning để chứng minh chưa từng thấy hoặc không có bản sao semantically tương đương. Bộ 40 cân bằng không phản ánh prevalence thực tế.

CSV nhãn/selection không gửi backend/inference. ZIP chỉ chứa Java; Qwen nhận callee identity/API role contract, không true/false. Không retrain, đổi threshold, CWSS weights hoặc rule nhằm khớp nhãn. Bug control-flow phát hiện qua đánh giá được sửa bằng test tổng quát; cả kết quả trước sửa được giữ và bộ 40 sau sửa chỉ là recheck.

## Đơn vị, ghép finding và REVIEW

Đơn vị = **(test case, target CWE)**, không là số findings. Ghép chính xác filename stem BenchmarkTestNNNNN và CWE trong expectedresults; nhiều callsite cùng target được gộp một quyết định: có REPORT => positive; nếu không REPORT mà có REVIEW => abstention; còn lại SUPPRESS/no target candidate => negative. No candidate là negative vận hành, không chứng minh safe. Finding khác CWE giữ riêng trong CSV, không tự coi là FP vì CSV chỉ nhãn weakness mục tiêu.

- Report-only: chỉ REPORT positive, REVIEW đưa vào negative để đo khả năng tự báo cáo (true REVIEW được tính FN theo quy ước, không gọi là verified safe).
- Selective: bỏ REVIEW khỏi ma trận; phải đọc cùng review rate/decision coverage, không suy recall toàn bộ từ mẫu quyết định.
- Retain-review: REPORT + REVIEW positive, đo queue giữ lại; không gọi REVIEW là TP đã xác minh.

Precision=TP/(TP+FP); recall=TP/(TP+FN); FPR=FP/(FP+TN); F1=2TP/(2TP+FP+FN). REVIEW rate=n_review/N; automatic decision coverage=(N−n_review)/N. Mẫu số 0 => N/A, không điền 0 hoặc 1 tùy tiện.

## Sáu ca hồi quy — kết quả cuối

| Case | Target | CSV true | Target candidates | Other-CWE candidates | IRIS T/S/U | REPORT/REVIEW/SUPPRESS | Case decision |
|---|---|---|---|---|---|---|---|
| BenchmarkTest00001 | CWE-22 | True | 1 | 2 | 0/0/1 | 0/1/0 | REVIEW |
| BenchmarkTest00002 | CWE-22 | True | 1 | 1 | 0/0/1 | 0/1/0 | REVIEW |
| BenchmarkTest00006 | CWE-78 | True | 1 | 0 | 1/0/0 | 1/0/0 | POSITIVE |
| BenchmarkTest00007 | CWE-78 | True | 1 | 1 | 0/0/1 | 0/1/0 | REVIEW |
| BenchmarkTest00008 | CWE-89 | True | 1 | 0 | 1/0/0 | 1/0/0 | POSITIVE |
| BenchmarkTest02229 | CWE-79 | False | 1 | 0 | 0/1/0 | 0/0/1 | NEGATIVE |


Các findings ngoài CWE mục tiêu của 6 ca:

| Case | Finding | Other CWE | Line | Decision | IRIS proof |
|---|---|---|---|---|---|
| BenchmarkTest00001 | FINDING-002-CWE079-doPost-L75 | CWE-79 | 75 | REVIEW | UNKNOWN |
| BenchmarkTest00001 | FINDING-003-CWE079-doPost-L87 | CWE-79 | 87 | REVIEW | UNKNOWN |
| BenchmarkTest00002 | FINDING-005-CWE079-doPost-L74 | CWE-79 | 74 | REVIEW | UNKNOWN |
| BenchmarkTest00007 | FINDING-008-CWE079-doPost-L65 | CWE-79 | 65 | SUPPRESS | PROVEN_SAFE |


CSV [trước sửa](docs/evaluation-20261102/ground-truth-findings.csv), [sau sửa](docs/evaluation-20261102/ground-truth-findings-postfix.csv) giữ mọi finding/off-target/line, proof, prediction và reason codes (các cột bổ sung có ở bản sau sửa). Không cộng các extra CWE này thành nhiều TP.

## Ma trận và chỉ số trước/sau sửa

| Set | Version | REVIEW convention | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---|---|---|---|---|---|---|---|---|---|
| six | BEFORE_SWITCH_FIX | report_only_review_as_negative | 2 | 0 | 1 | 3 | 100.00% | 40.00% | 0.00% | 57.14% |
| six | BEFORE_SWITCH_FIX | selective_decided_only | 2 | 0 | 1 | 0 | 100.00% | 100.00% | 0.00% | 100.00% |
| six | BEFORE_SWITCH_FIX | retain_review_as_positive | 5 | 0 | 1 | 0 | 100.00% | 100.00% | 0.00% | 100.00% |
| six | POSTFIX_RECHECK | report_only_review_as_negative | 2 | 0 | 1 | 3 | 100.00% | 40.00% | 0.00% | 57.14% |
| six | POSTFIX_RECHECK | selective_decided_only | 2 | 0 | 1 | 0 | 100.00% | 100.00% | 0.00% | 100.00% |
| six | POSTFIX_RECHECK | retain_review_as_positive | 5 | 0 | 1 | 0 | 100.00% | 100.00% | 0.00% | 100.00% |
| forty | BEFORE_SWITCH_FIX | report_only_review_as_negative | 3 | 0 | 20 | 17 | 100.00% | 15.00% | 0.00% | 26.09% |
| forty | BEFORE_SWITCH_FIX | selective_decided_only | 3 | 0 | 5 | 3 | 100.00% | 50.00% | 0.00% | 66.67% |
| forty | BEFORE_SWITCH_FIX | retain_review_as_positive | 17 | 15 | 5 | 3 | 53.12% | 85.00% | 75.00% | 65.38% |
| forty | POSTFIX_RECHECK | report_only_review_as_negative | 3 | 0 | 20 | 17 | 100.00% | 15.00% | 0.00% | 26.09% |
| forty | POSTFIX_RECHECK | selective_decided_only | 3 | 0 | 5 | 2 | 100.00% | 60.00% | 0.00% | 75.00% |
| forty | POSTFIX_RECHECK | retain_review_as_positive | 18 | 15 | 5 | 2 | 54.55% | 90.00% | 75.00% | 67.92% |


40 cases trước sửa: REVIEW 72.50%, automatic decision coverage 27.50%. Sau sửa: REVIEW 75.00%, automatic decision coverage 25.00%. Precision trên rất ít REPORT/decided cases không phải accuracy 100% và không bảo đảm ngoài mẫu.

Theo CWE, report-only sau sửa:

| CWE | Cases | TP | FP | TN | FN | REVIEW | Automatic coverage |
|---|---|---|---|---|---|---|---|
| CWE-22 | 10 | 1 | 0 | 5 | 4 | 60.00% | 40.00% |
| CWE-78 | 10 | 0 | 0 | 5 | 5 | 100.00% | 0.00% |
| CWE-79 | 10 | 0 | 0 | 5 | 5 | 60.00% | 40.00% |
| CWE-89 | 10 | 2 | 0 | 5 | 3 | 80.00% | 20.00% |


## Phát hiện lỗi thực và frozen baseline

Trước sửa, BenchmarkTest02241 (CSV CWE-79=true) bị SUPPRESS: extractor cho các assignment ở case/default cùng control scope, nên phép gán hằng ở default ghi đè đường taint. Case metadata cũng thiếu has_break/is_default làm constant switch có thể chọn sai reaching definitions. Đây là lỗi control-flow, không phải CWSS threshold. Bản sửa tạo conditional scope cho CaseTree, xuất break/default metadata, tăng AST_ANALYSIS_VERSION V5 và namespace cache để không tái sử dụng AST/site proof cũ. Tests tổng quát có unknown selector, helper, literal selector, break và default; dữ liệu/nhãn không thay đổi.

Sau sửa chạy lại cả 8 dự án và 46 ca với scan IDs mới. Case 02241 không còn tự SUPPRESS; vẫn còn những no-candidate/UNKNOWN và identity mismatch cần REVIEW. Cases 02463 (path) và 02600 (XSS) không có target OpenGrep candidate ở baseline: giới hạn detector/rule chưa được sửa trên tập đánh giá. Qwen role output không chứng minh dòng dữ liệu safe/vulnerable và có thể khác observed AST callsite; CWE ngoài nhãn vẫn chỉ báo cáo, không tự gán ground truth.

## Ablation — chỉ quan sát thành phần đã chạy

A = candidate OpenGrep thực. B = chạy lại Javac AST/dataflow thật, dùng policy proof-only (PROVEN_TAINT positive; UNKNOWN REVIEW; PROVEN_SAFE/no candidate negative), không Qwen. C = production Evidence Fusion + Alert Triage với Qwen local thực/cache hợp lệ. Đây là **stage-observation comparison**, không phải ba deployment production độc lập được benchmark về latency. Không tạo số liệu cho full configuration ablation chưa chạy; B/C có policy khác khả năng abstain của A, vì thế không suy causal improvement của Qwen từ A→C.

Report-only cho bảng so sánh thành phần sau sửa:

| Set | Observed configuration | TP | FP | TN | FN | Precision | Recall | FPR | F1 | REVIEW |
|---|---|---|---|---|---|---|---|---|---|---|
| six | A_opengrep | 5 | 1 | 0 | 0 | 83.33% | 100.00% | 100.00% | 90.91% | 0.00% |
| six | B_fresh_ast | 2 | 0 | 1 | 3 | 100.00% | 40.00% | 0.00% | 57.14% | 50.00% |
| six | C_full_triage | 2 | 0 | 1 | 3 | 100.00% | 40.00% | 0.00% | 57.14% | 50.00% |
| forty | A_opengrep | 18 | 16 | 4 | 2 | 52.94% | 90.00% | 80.00% | 66.67% | 0.00% |
| forty | B_fresh_ast | 3 | 0 | 20 | 17 | 100.00% | 15.00% | 0.00% | 26.09% | 75.00% |
| forty | C_full_triage | 3 | 0 | 20 | 17 | 100.00% | 15.00% | 0.00% | 26.09% | 75.00% |


Đọc [metric JSON trước](docs/evaluation-20261102/ground-truth-metrics.json) và [sau](docs/evaluation-20261102/ground-truth-metrics-postfix.json) để đối chiếu đủ ba convention. Không có bằng chứng trong mẫu này để tuyên bố riêng Qwen làm precision/recall tăng. FULL_CONFIGURATION_ABLATION=NOT_RUN; stage A/B/C observations đã chạy thật, không giả lập output.

## Hiệu năng và artifacts

| Set/version | Scan | E2E seconds | Actual GPU calls | Qwen cache hits |
|---|---|---|---|---|
| six BEFORE | SCAN-20261101175706-B421DB | 5.242 | 0 | 5 |
| forty BEFORE | SCAN-20261101175754-151CAB | 56.543 | 11 | 0 |
| six POSTFIX | SCAN-20261101182255-AD791D | 3.374 | 0 | 5 |
| forty POSTFIX | SCAN-20261101182302-90E69B | 1.153 | 0 | 11 |


40-case baseline dùng cache riêng mới: 11 GPU inference thật, 0 LLM cache hit; 6-case baseline dùng 5 cache hits, 0 GPU mới. Recheck sau sửa có cache khi role identity/model/prompt giữ nguyên; AST/site proof dùng V5. Timing là số đo laptop cụ thể, không so tốc độ cold/warm như cùng điều kiện.

CSV [test case trước](docs/evaluation-20261102/ground-truth-cases.csv) và [sau](docs/evaluation-20261102/ground-truth-cases-postfix.csv) có toàn bộ 46 case, target labels, SHA-256 Java, candidate counts, IRIS, triage và scan IDs. ZIP/ground truth registry private/raw API/model không được commit. CWSS chỉ là prioritization MITRE 1.0.1, không tham gia gán TP/FP hoặc các công thức accuracy.
