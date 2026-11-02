# NTK — Final core-engine acceptance, 2026-11-02

**Overall: PARTIAL.** Original IRIS/CodeQL đã chạy thật và tích hợp Stage 05 có strict E2E evidence. Chưa hoàn thành tương thích mọi tác vụ LLM, phân biệt Spark CVE, held-out mới, full A/B/C/D ablation hoặc original-engine coverage toàn bộ 8 dự án. Không chuyển các giới hạn đó thành PASS.

## Git, bảo toàn và source changes

Branch `cwss-inference-v2-220`; nền `aa017e8292a37c16e3b5af9b051e03e68c7e7104`. Core source commit **`5f6c8b584327547269a1f4c11236c85f04ba0882`**; sparse-coverage correction **`edd3276883e009d274c7efc0a1096e8eebad6e34`**. Commit chứa báo cáo này chỉ bổ sung public acceptance metadata/tài liệu. Không merge main, rewrite history hoặc force push.

Baseline ban đầu sạch; đã ghi status/branches/worktrees và sao lưu source, sáu reports cùng CWSS SQLite snapshots trước sửa. Main worktree vẫn `97716ce`. SHA scan demo `SCAN-20261101164045-3AA266` giữ nguyên `70645502e5b86ba59231340a94c540c29c424c119c6650c6d579023b3050e891`. Sáu baseline reports giữ nguyên hashes. Không xóa/sửa checkpoint, dataset private, runtime demo hoặc scan cũ.

Source files thay đổi:

- `backend/ntk-production-v2/scripts/ntk_original_iris_adapter.py`: pinned engine/config/license gate, isolated database/process control, SARIF/source binding, cache, union và evidence policy.
- `backend/ntk-production-v2/scripts/ntk_original_iris_worker.py`: gọi upstream SAPipeline, local-only model bridge, strict contracts và bounded scheduling.
- `backend/ntk-production-v2/scripts/ntk_local_gpu_lock.py`: khóa generation giữa các process mới.
- `backend/ntk-production-v2/scripts/ntk_web_backend_service.py`: Stage 05 integration, origins/telemetry/provenance và hai bản sửa coverage.
- `backend/ntk-production-v2/scripts/ntk_pipeline_telemetry_and_datasets.py`: nhãn engine thực tế cho trace mới.
- `backend/ntk-production-v2/tests/test_original_iris_adapter.py`, `test_opengrep_inventory_coverage.py`.
- `tools/run_engine_ablation.py`: independent-arm runner; chỉ arm A đã được nghiệm thu bằng runner trong lượt này.

Không sửa frontend design, OpenGrep rules, AST proof semantics, CWSS weights hoặc LoRA. Public evidence tại [docs/engine-evaluation-20261102](docs/engine-evaluation-20261102/). Raw/source/model outputs và SQLite/SARIF/DBs giữ trong ignored `work/original-iris-engineering-20261102/` hoặc `/home/tuankhoa/ntk-original-iris-research-20261102/`.

## Original engine và fresh execution

Official IRIS v2 commit **`3a12f45750f58135bcc58c7fdf4c20786b600e31`**; CodeQL **2.25.6**, Java extractor **1.22.1**. Java-only no-build databases và native CWE-22/CWE-78 queries đã chạy. Không khẳng định native CWE-79/CWE-89 đã được nghiệm thu runtime. MIT source/query libraries khác với CodeQL CLI/engine chịu GitHub Terms; chỉ public academic source đã xác minh được dùng. [Chi tiết license, paths và architecture](NTK_ORIGINAL_IRIS_INTEGRATION_REPORT.md).

| Execution thật | Kết quả | Inference mới |
|---|---|---:|
| Six-case strict attempt | Native query có 4 paths; một API identity bị Qwen echo sai; strict job ERROR/PARTIAL | 57 |
| Single-case strict pipeline | 10 stages, 1 OpenGrep + 1 IRIS-only candidate, source-bound path; persisted `SCAN-20261102040240-F4CEF6` | 14 |
| Fresh GitHub async strict HTTP | `SCAN-20261102043446-FCD123`, 10 stages COMPLETED, 1 REPORT / 1 REVIEW, 0 SUPPRESS | 14 |
| Sparse-scope correction/cache regression | `SCAN-20261102044459-B082A2`, PARTIAL_BOUNDED, original cache hit, 10 stages completed | 0 |
| Fresh demo 8765, existing fallback process | `SCAN-20261102044104-D032E7`, completed, actual input/output `cuda:0` | 1 |

Fresh strict HTTP dùng exact public BenchmarkJava commit `f40c618c5a709afce350ef06ed2899c85cf586e9`, chỉ **BenchmarkTest00006**; original CWE scope **78**. Tổng 304.301 giây, adapter/native phase 282.596 giây. Query thật `java/my-command-line-injection-extra`, path sáu nodes từ L46 đến `pb.command` L66; source bytes đối chiếu Git. IRIS-only L66 giữ REVIEW vì chưa xác minh execution sink/slot đầy đủ; OpenGrep L69 REPORT theo local evidence. Không đếm hai findings thành hai TP.

Fresh HTTP đầu trả nhầm FULL trên materialized sparse scope; đã giữ nguyên record để audit và sửa bằng scan mới B082A2: `repository_inventory_complete=false`, `repository_total_java_files=null`, counts chỉ phạm vi đã checkout. Không tuyên bố full Benchmark hoặc đoán số file bị bỏ qua. Cache recheck không được gọi là fresh inference.

Raw receipts: `final-http-submitted/job/full/trace/ranking/scenario/report/model.json`, `scope-regression-full.json`, `demo-fresh-full.json`. Initial direct runner từng thiếu scan ID khi gọi persistence; đã sửa orchestration và xác minh lại bằng async HTTP lifecycle, không đổi output phát hiện để che lỗi.

## Qwen và CWSS

Adapter SHA đọc lại từ file vẫn **`176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`**. Fresh strict HTTP và demo đều có model/base/LoRA/input/output trên `cuda:0`, local-files-only và cloud disabled. Native workers và backend mới dùng GPU lock; các lượt được thực hiện tuần tự. Tổng **399 generations có receipts trong nhóm nghiệm thu**, không cộng cache hits/test doubles. Prototype đầu thiếu serialized per-call device fields cho 54 API calls; các lượt release có device telemetry đầy đủ. Không dùng CUDA execution làm bằng chứng tăng accuracy.

EO06 được huấn luyện API-role, không chứng minh năng lực native function-source/contextual vulnerability reasoning. Posthoc có JSON hợp lệ nhưng kết luận logic sai. Output đó chỉ advisory, không SUPPRESS; generic identity mismatch bị từ chối. `IRIS_LOCAL_LLM_COMPATIBILITY=PARTIAL`.

| Strict HTTP finding | Decision | GENERAL_JAVA | Reference scenario | Metrics | FC |
|---|---|---:|---:|---:|---|
| OpenGrep L69 | REPORT | 16.0 | 84.0 | 16 | D |
| Original IRIS-only L66 | REVIEW | 12.6 | 67.1 | 16 | D |

Reference scenario là giả định nghiên cứu, không chứng minh deployment Internet. [32 metric rows](docs/engine-evaluation-20261102/strict-smoke-metric-provenance.csv) có code, weight, classification, rule, evidence và provenance. CWSS là MITRE 1.0.1 priority, không phải CVSS/TP probability; điểm không thay đổi triage. Default/estimated metrics không biến thành verified vì source-bound. Scan cũ vẫn 10 findings, 2 REPORT / 6 REVIEW / 2 SUPPRESS; scores mục tiêu 006/008/009/010 được kiểm tra riêng trong preservation receipts.

## Spark và 8 dự án

[Spark analysis](NTK_SPARK_CVE_2016_9177_ANALYSIS.md): đúng cặp commits, full Java-only DB creation thành công, V1/V2 native queries thực thi thật. Mỗi bản mỗi policy 64 generations, partial mining; **zero raw thread flows ở cả bốn execution**. V2 dự đoán 18 sources/2 sinks/44 none mỗi bản nhưng chưa bao phủ JDK sink models; không chứng minh CVE-specific behavior hoặc quantitative detection gain. Chi tiết hashes/durations ở [spark-native-executions.json](docs/engine-evaluation-20261102/spark-native-executions.json).

Các số REPORT/REVIEW/SUPPRESS dưới đây là **baseline lịch sử**, không tái sử dụng làm kết quả E2E mới. Cột Java/candidates là **OpenGrep-only mới**, không phải full NTK hoặc whole-program IRIS analysis.

| Project | New Java scanned | New OG candidates | Historical R/Rv/S | Original IRIS mới | Coverage acceptance |
|---|---:|---:|---|---|---|
| WebGoat | 355/355 | 84 | 7/3/3 | NOT_RUN | OG inventory only; baseline E2E partial |
| mini_vulnerable_java_CVE-89_1.0 | 11/11 | 6 | 3/2/1 | NOT_RUN | OG inventory only |
| owasp_benchmark_CVE-2026-0005_1.0 | 2766/2766 | 5273 | 7/19/4 | NOT_RUN | OG inventory only; baseline E2E partial |
| spark_CVE-2016-9177_fixed | 167/167 | 20 | 0/9/0 | DB/query yes, mining PARTIAL | No CVE differentiation |
| spark_CVE-2016-9177_vuln | 168/168 | 19 | 0/9/0 | DB/query yes, mining PARTIAL | No CVE differentiation |
| spring-petclinic | 49/49 | 0 | 0/0/0 | NOT_RUN | Zero OG candidates, not proof of safety |
| sqli_mini_CVE-2026-TEST-0001_1.0 | 1/1 | 2 | 1/0/1 | NOT_RUN | Local research fixture, no independent CVE claim |
| webgoat_sql_CVE-2026-0006_1.0 | 355/355 | 84 | 7/3/3 | NOT_RUN | Same WebGoat source; not independent sample |

Total mới **3872 Java submitted/scanned, 5488 candidates, zero scanner errors**. Hai WebGoat inventories có thêm Maven wrapper Java so với 354 cũ; chỉ đọc, không chạy wrapper. Seven Git-backed sources khớp mọi Java blob tại đúng commits; một local fixture không có Git commit. Existing build artifacts ở mini và untracked historical result ở WebGoat SQL không bị sửa/dọn.

Spark candidate tăng 9 → 19/20 do `src/test` trước bị default directory-ignore bỏ qua. Backend đã sửa explicit inventory/`paths.scanned` verification và đổi cache policy key. Không gọi khác biệt đó là CVE detection improvement. Source hashes, counts, scan IDs lịch sử ở [source scope CSV](docs/engine-evaluation-20261102/eight-project-source-scope.csv).

## Scientific status và regression

Baseline 40 case giữ TP/FP/TN/FN=3/0/20/17, REVIEW=75%, auto-REPORT recall=15%. Target REVIEW taxonomy: helper-return unproven 22, array state 5, insufficient local trace 3. Không đo lại baseline này dưới full original engine; AFTER metrics là NOT_MEASURED. Không có held-out mới, leakage-free chưa chứng minh, full A/B/C/D chưa chạy; chỉ arm A runner smoke đã thực thi. [Detection](NTK_DETECTION_IMPROVEMENT_REPORT.md), [ablation](NTK_COMPONENT_ABLATION_REPORT.md).

| Check thực hiện trong lượt này | Kết quả |
|---|---|
| Full backend suite cuối | **260 passed, 0 failures/errors/skips** |
| Private Real25 SHA256SUMS | **7 entries khớp**; tests dùng đúng NTK_REAL25_DIR, không đổi expected scores |
| Frontend current Node suite | **16 passed**; không tái khẳng định số 17 từ report cũ |
| Metric calculation tests | **2 passed** |
| React build | **445 modules**, PASS; chunk-size warning còn tồn tại |
| Chrome visual regression | **12 pages PASS**, screenshots, zero render/API/encoding errors, report download verified |
| Real OpenGrep/Javac/CWSS | Có trong live scans và regression; test fixtures không được tính là original IRIS smoke |
| Cache | Genuine hit zero GPU; worker policy invalidation + cancellation; sparse-scope cache regression zero GPU |

## Demo và giới hạn bàn giao

Demo **http://127.0.0.1:5173**, API **http://127.0.0.1:8765** còn hoạt động. Fresh demo scan D032E7 đã nạp Qwen CUDA sau reboot; GPU cuối khoảng 1199/4096 MiB, utilization 0%. Không restart process demo đang phục vụ: nó giữ baseline implementation/fallback trong phiên này. Source mới và original strict integration được thử trên research servers độc lập, không âm thầm đổi demo thành original engine. Research 8780 đã dừng; 8781 được mở lại để đọc scope-regression/strict scan history bằng runtime riêng. Các report HTTP checks ghi nhận thời điểm kiểm tra, không cam kết tự khởi động research servers sau reboot. Demo launch scripts giữ nguyên.

Kịch bản bảo vệ: mở Overview → History, chọn Real10 cũ → chứng minh 10 findings/2-6-2 và CWSS metric provenance → mở fresh demo D032E7/model CUDA → trình bày riêng strict IRIS scan FCD123 và corrected-scope B082A2 bằng receipts → giải thích L66 REVIEW, Spark chưa phân biệt, baseline recall/REVIEW và giới hạn ablation. Không trình bày 5488 OpenGrep candidates như 5488 verified vulnerabilities.

Blockers còn lại: local LLM ngoài training contract; bounded mining không phủ đủ source/sink; custom interprocedural/sanitizer modeling chưa xác minh Spark; native CWE-79/89 chưa acceptance; full eight-project original E2E/held-out/causal ablation chưa hoàn thành. Không triển khai thêm chức năng giao diện trong đợt này.

```text
ORIGINAL_IRIS_UPSTREAM=PASS
CODEQL_JAVA_DATABASE=PASS
ORIGINAL_IRIS_ENGINE=PARTIAL
IRIS_LOCAL_LLM_COMPATIBILITY=PARTIAL
IRIS_NTK_STAGE05_INTEGRATION=PASS
SPARK_VULNERABLE_FIXED_DIFFERENTIATION=FAILED
REVIEW_RATE_BEFORE=75%
REVIEW_RATE_AFTER=NOT_MEASURED
AUTO_REPORT_RECALL_BEFORE=15%
AUTO_REPORT_RECALL_AFTER=NOT_MEASURED
DETECTION_ACCURACY=EVALUATED_BASELINE_ONLY
DETECTION_IMPROVEMENT=NO_DEMONSTRATED_GAIN
QWEN_CONTRIBUTION=NOT_PROVEN
FULL_CONFIGURATION_ABLATION=NOT_RUN
FULL_SOURCE_COVERAGE_8_PROJECTS=PARTIAL
CWSS_V2_PROVENANCE=PASS
POST_REBOOT_CUDA_INFERENCE=PASS
BACKEND_REGRESSION=PASS
FRONTEND_REGRESSION=PASS
DEMO_READY=PASS
```

PASS ở Stage 05 giới hạn ở strict single-case execution được nêu; DEMO_READY chỉ baseline demo đang được bảo toàn. Hai trạng thái đó không nâng ORIGINAL_IRIS_ENGINE hoặc full thesis acceptance thành PASS. GitHub sync được ghi trong commit/sync receipt sau public-artifact review.
