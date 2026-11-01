# NTK — 8 project E2E acceptance, 02/11/2026

**NTK_8_PROJECT_E2E=PARTIAL.** Cả 8 dự án có scan production mới và artifact hợp lệ; 3 lượt chỉ quét 16 file, không phải FULL E2E COVERAGE. Spark traversal chưa được phân biệt đúng. Đây là nghiệm thu vận hành theo phạm vi, không phải chứng nhận khả năng phát hiện mọi lỗ hổng.

Baseline Git `39c647c86594b09d69a8ed2ac541f547c1131150`, branch `cwss-inference-v2-220`. WSL Ubuntu-22.04, Python 3.10.20, JDK 17, OpenGrep 1.25.0; Qwen2.5-Coder-0.5B + LoRA local CUDA, không API LLM bên ngoài. Dùng backend/store riêng 8766, frontend 5174; giữ runtime demo 8765/5173 và lịch sử gốc.

## Nguồn và phạm vi

Đã tìm có giới hạn trong manifests/runtime/source caches và các thư mục NTK/Downloads đã biết. Tìm thấy đủ 8 thư mục cũ tại `/home/tuankhoa/iris/data/project-sources`; không tải model, không training, không build/chạy mã không tin cậy. Đối chiếu từng Java blob với Git tree trước khi đóng ZIP, tính archive SHA-256 và từng file SHA-256. Các Git projects đều có byte Java khớp commit; thay đổi `target/` compiled outputs và `opengrep_results.json` không được đóng vào archive. Fixture SQL mini không có Git riêng; không dùng SHA repository cha làm provenance giả.

Giới hạn production: ZIP 25 MiB, 4.000 entries, 512 KiB/file, 64 MiB Java mặc định, ceiling 128 MiB; default inventory 3.000 file, ceiling 10.000. Lượt nghiệm thu cố ý chọn tối đa 200 file, hoặc 16 file trên dự án lớn. Không tăng giới hạn; dung lượng trống ban đầu ổ Windows khoảng 26 GiB. FULL trong bảng chỉ nói toàn bộ Java inventory của archive đã khai báo, không phải toàn bộ ngôn ngữ hoặc bảo mật repository. Build descriptors/resources không được chạy và dependency classpath không được build.

## Kết quả cuối sau sửa AST switch

G = GENERAL_JAVA; R = reference scenario giả định. Các dãy điểm ghi cả số lượng, không phải xác suất TP.

| Project | Source verified | Java scanned | Coverage | Candidates | REPORT | REVIEW | SUPPRESS | CWSS | E2E status |
|---|---|---|---|---|---|---|---|---|---|
| WebGoat | Git bytes/commit | 16/354 | PARTIAL | 13 | 7 | 3 | 3 | G: 0.0 × 2, 12.6 × 7, 15.0 × 3, 16.4 × 1; R: 0.0 × 2, 67.1 × 7, 80.2 × 3, 86.0 × 1 | COMPLETED, PARTIAL scope |
| mini_vulnerable_java_CVE-89_1.0 | Git bytes/commit | 11/11 | FULL Java scope | 6 | 3 | 2 | 1 | G: 0.0 × 1, 12.6 × 2, 14.7 × 2, 15.0 × 1; R: 0.0 × 1, 67.1 × 2, 78.3 × 2, 80.2 × 1 | COMPLETED |
| owasp_benchmark_CVE-2026-0005_1.0 | Git bytes/commit | 16/2766 | PARTIAL | 30 | 7 | 19 | 4 | G: 0.0 × 1, 12.6 × 22, 16.0 × 2, 16.1 × 4, 16.4 × 1; R: 0.0 × 1, 67.1 × 22, 84.0 × 2, 84.7 × 4, 86.0 × 1 | COMPLETED, PARTIAL scope |
| spark_CVE-2016-9177_fixed | Git bytes/commit | 167/167 | FULL Java scope | 9 | 0 | 9 | 0 | G: 12.6 × 9; R: 67.1 × 9 | COMPLETED |
| spark_CVE-2016-9177_vuln | Git bytes/commit | 168/168 | FULL Java scope | 9 | 0 | 9 | 0 | G: 12.6 × 9; R: 67.1 × 9 | COMPLETED |
| spring-petclinic | Git bytes/commit | 49/49 | FULL Java scope | 0 | 0 | 0 | 0 | G: Không có assessment; R: Không có assessment | COMPLETED |
| sqli_mini_CVE-2026-TEST-0001_1.0 | Archive SHA; research fixture | 1/1 | FULL Java scope | 2 | 1 | 0 | 1 | G: 0.0 × 1, 15.0 × 1; R: 0.0 × 1, 80.2 × 1 | COMPLETED |
| webgoat_sql_CVE-2026-0006_1.0 | Git bytes/commit | 16/354 | PARTIAL | 13 | 7 | 3 | 3 | G: 0.0 × 2, 12.6 × 7, 15.0 × 3, 16.4 × 1; R: 0.0 × 2, 67.1 × 7, 80.2 × 3, 86.0 × 1 | COMPLETED, PARTIAL scope |


Source commits/archive SHA và allowlist: [manifest](docs/evaluation-20261102/source-manifest.json). [10 stage × 8 scan](docs/evaluation-20261102/multiproject-stages.csv), [16 metric × 2 modes/finding](docs/evaluation-20261102/multiproject-metrics.csv). CSV metric chứa code, weight, classification, rule, evidence và provenance thật. FC giữ D; TI=N chỉ khi engine xác nhận local safe độc lập. IRIS safe nhưng CWSS không xác nhận được vẫn có điểm default, không ép thành 0.

### WebGoat

- Version/source: `5357a65e054976cd7d79b81ef3906ded050ed921`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: https://github.com/WebGoat/WebGoat.git.
- Archive SHA-256: `c3d096ac797135961297290a83bf9a70458f193d3e50c99a1a6a51eab83e2da4`. Source local: `/home/tuankhoa/iris/data/project-sources/WebGoat`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **354 / 16 / 338**; PARTIAL_BOUNDED. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 16, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN", "file_allowlist": ["src/main/java/org/owasp/webgoat/lessons/pathtraversal/PathTraversal.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUpload.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadBase.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadFix.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRemoveUserInput.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionAdvanced.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionQuiz.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjection.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java"]}`.
- OpenGrep candidates: 13; IRIS taint/safe/unknown: 7/3/3; triage REPORT/REVIEW/SUPPRESS: 7/3/3.
- Qwen role identities: 5; cache hits: 2; fresh requests: 3; GPU calls thực: 3. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: 0.0 × 2, 12.6 × 7, 15.0 × 3, 16.4 × 1; reference scenario: 0.0 × 2, 67.1 × 7, 80.2 × 3, 86.0 × 1. Source-bound: 13/13; đủ 16 metric ở hai mode. Blockers: `{"UNSUPPORTED_OR_UNPROVEN_OVERLOAD": 7, "RECEIVER_TYPE_UNPROVEN": 6, "INDEPENDENT_LOCAL_PROOF_NOT_CONFIRMED": 4, "AST_CALLSITE_MISSING_OR_AMBIGUOUS": 2, "SINK_SLOT_UNCOVERED": 3, "IRIS_UNKNOWN_NO_LOCAL_FLOW_PROOF": 3, "RECEIVER_ORIGIN_UNPROVEN": 1}`.
- E2E: 27.408 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182104-AD4FF8`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182104-AD4FF8); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182104-AD4FF8/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182104-AD4FF8/pipeline-trace).
### mini_vulnerable_java_CVE-89_1.0

- Version/source: `920fef72e1b8bc9f67c80772033f89b9efb0f5b5`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: https://github.com/TuanKhoa1201/mini-vulnerable-java.git.
- Archive SHA-256: `ab5acbb40658686645b8f4a41d9fb7916a0c0b73a8f2840db2ffb3e3d42f14ae`. Source local: `/home/tuankhoa/iris/data/project-sources/mini_vulnerable_java_CVE-89_1.0`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **11 / 11 / 0**; FULL_SOURCE_COVERAGE. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 200, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN"}`.
- OpenGrep candidates: 6; IRIS taint/safe/unknown: 3/1/2; triage REPORT/REVIEW/SUPPRESS: 3/2/1.
- Qwen role identities: 5; cache hits: 4; fresh requests: 1; GPU calls thực: 1. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: 0.0 × 1, 12.6 × 2, 14.7 × 2, 15.0 × 1; reference scenario: 0.0 × 1, 67.1 × 2, 78.3 × 2, 80.2 × 1. Source-bound: 6/6; đủ 16 metric ở hai mode. Blockers: `{"SINK_SLOT_UNCOVERED": 2, "IRIS_UNKNOWN_NO_LOCAL_FLOW_PROOF": 2}`.
- E2E: 8.111 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182138-6DFEEC`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182138-6DFEEC); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182138-6DFEEC/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182138-6DFEEC/pipeline-trace).
### owasp_benchmark_CVE-2026-0005_1.0

- Version/source: `0352dbb5a4f1e9c29edb2d648bd869bd9f431dcd`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: https://github.com/OWASP-Benchmark/BenchmarkJava.git.
- Archive SHA-256: `778c73d04e3cd2501a3e533c863c1e01b087576f1ae21d3c53aebd8bddcc0e15`. Source local: `/home/tuankhoa/iris/data/project-sources/owasp_benchmark_CVE-2026-0005_1.0`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **2766 / 16 / 2750**; PARTIAL_BOUNDED. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 16, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN", "file_allowlist": ["src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00004.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00005.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00006.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00007.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00009.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00010.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00011.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00012.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00014.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00015.java", "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00016.java"]}`.
- OpenGrep candidates: 30; IRIS taint/safe/unknown: 7/4/19; triage REPORT/REVIEW/SUPPRESS: 7/19/4.
- Qwen role identities: 6; cache hits: 5; fresh requests: 1; GPU calls thực: 1. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: 0.0 × 1, 12.6 × 22, 16.0 × 2, 16.1 × 4, 16.4 × 1; reference scenario: 0.0 × 1, 67.1 × 22, 84.0 × 2, 84.7 × 4, 86.0 × 1. Source-bound: 30/30; đủ 16 metric ở hai mode. Blockers: `{"AST_CALLSITE_MISSING_OR_AMBIGUOUS": 8, "UNSUPPORTED_OR_UNPROVEN_OVERLOAD": 10, "RECEIVER_TYPE_UNPROVEN": 10, "SINK_SLOT_UNCOVERED": 19, "IRIS_UNKNOWN_NO_LOCAL_FLOW_PROOF": 19, "INDEPENDENT_LOCAL_PROOF_NOT_CONFIRMED": 3}`.
- E2E: 9.012 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182148-2F9E73`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182148-2F9E73); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182148-2F9E73/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182148-2F9E73/pipeline-trace).
### spark_CVE-2016-9177_fixed

- Version/source: `efcb46c710e3f56805b9257a63d1306882f4faf9`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: https://github.com/perwendel/spark.git.
- Archive SHA-256: `9eca9ddd6b0e293a08917fa49e235e753c5451815c3fd61ef0eabdb9262755f7`. Source local: `/home/tuankhoa/iris/data/project-sources/spark_CVE-2016-9177_fixed`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **167 / 167 / 0**; FULL_SOURCE_COVERAGE. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 200, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN"}`.
- OpenGrep candidates: 9; IRIS taint/safe/unknown: 0/0/9; triage REPORT/REVIEW/SUPPRESS: 0/9/0.
- Qwen role identities: 4; cache hits: 3; fresh requests: 1; GPU calls thực: 1. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: 12.6 × 9; reference scenario: 67.1 × 9. Source-bound: 9/9; đủ 16 metric ở hai mode. Blockers: `{"RECEIVER_TYPE_UNPROVEN": 9, "RECEIVER_ORIGIN_UNPROVEN": 3, "SINK_SLOT_UNCOVERED": 9, "IRIS_UNKNOWN_NO_LOCAL_FLOW_PROOF": 9, "UNSUPPORTED_OR_UNPROVEN_OVERLOAD": 6, "AST_CALLSITE_MISSING_OR_AMBIGUOUS": 3}`.
- E2E: 7.190 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182214-794D59`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182214-794D59); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182214-794D59/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182214-794D59/pipeline-trace).
### spark_CVE-2016-9177_vuln

- Version/source: `ce57dfb949ed183405f75dee8cf3262b45c9b3b5`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: https://github.com/perwendel/spark.git.
- Archive SHA-256: `044c2c387b443b510f56075c0e3ce694fdf6cff32d51f54ee0702af4a79f9780`. Source local: `/home/tuankhoa/iris/data/project-sources/spark_CVE-2016-9177_vuln`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **168 / 168 / 0**; FULL_SOURCE_COVERAGE. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 200, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN"}`.
- OpenGrep candidates: 9; IRIS taint/safe/unknown: 0/0/9; triage REPORT/REVIEW/SUPPRESS: 0/9/0.
- Qwen role identities: 4; cache hits: 4; fresh requests: 0; GPU calls thực: 0. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: 12.6 × 9; reference scenario: 67.1 × 9. Source-bound: 9/9; đủ 16 metric ở hai mode. Blockers: `{"RECEIVER_TYPE_UNPROVEN": 9, "RECEIVER_ORIGIN_UNPROVEN": 3, "SINK_SLOT_UNCOVERED": 9, "IRIS_UNKNOWN_NO_LOCAL_FLOW_PROOF": 9, "UNSUPPORTED_OR_UNPROVEN_OVERLOAD": 6, "AST_CALLSITE_MISSING_OR_AMBIGUOUS": 3}`.
- E2E: 5.147 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182228-873348`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182228-873348); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182228-873348/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182228-873348/pipeline-trace).
### spring-petclinic

- Version/source: `f182358d02e4a68e52bdbabf55ca7800288511e7`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: https://github.com/spring-projects/spring-petclinic.git.
- Archive SHA-256: `903728cda20921cba04fd75efda53ec6c8183ece1674d8c9bfbc7e5044f997e9`. Source local: `/home/tuankhoa/iris/data/project-sources/spring-petclinic`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **49 / 49 / 0**; FULL_SOURCE_COVERAGE. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 200, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN"}`.
- OpenGrep candidates: 0; IRIS taint/safe/unknown: 0/0/0; triage REPORT/REVIEW/SUPPRESS: 0/0/0.
- Qwen role identities: 0; cache hits: 0; fresh requests: 0; GPU calls thực: 0. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: Không có assessment; reference scenario: Không có assessment. Source-bound: 0/0; đủ 16 metric ở hai mode. Blockers: `{}`.
- E2E: 4.593 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182238-CB2409`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182238-CB2409); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182238-CB2409/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182238-CB2409/pipeline-trace).
### sqli_mini_CVE-2026-TEST-0001_1.0

- Version/source: `LOCAL_FIXTURE; archive SHA-256`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: fixture nghiên cứu local, không gán Git commit của repository cha.
- Archive SHA-256: `bd62ee027c85c4dc2a5850dac67b92e48788113ac0c9130d391041f11c6c5a9a`. Source local: `/home/tuankhoa/iris/data/project-sources/sqli_mini_CVE-2026-TEST-0001_1.0`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **1 / 1 / 0**; FULL_SOURCE_COVERAGE. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 200, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN"}`.
- OpenGrep candidates: 2; IRIS taint/safe/unknown: 1/1/0; triage REPORT/REVIEW/SUPPRESS: 1/0/1.
- Qwen role identities: 2; cache hits: 2; fresh requests: 0; GPU calls thực: 0. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: 0.0 × 1, 15.0 × 1; reference scenario: 0.0 × 1, 80.2 × 1. Source-bound: 2/2; đủ 16 metric ở hai mode. Blockers: `{}`.
- E2E: 3.571 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182244-9171E5`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182244-9171E5); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182244-9171E5/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182244-9171E5/pipeline-trace).
### webgoat_sql_CVE-2026-0006_1.0

- Version/source: `5357a65e054976cd7d79b81ef3906ded050ed921`; source mode production `JAVA_ZIP_ARCHIVE_UPLOAD` từ bản Java đã đối chiếu. Upstream: https://github.com/WebGoat/WebGoat.git.
- Archive SHA-256: `1f854bd53519bb596e5101abd372cc51e73e1ced9c89d6b4a690aaf05b338aca`. Source local: `/home/tuankhoa/iris/data/project-sources/webgoat_sql_CVE-2026-0006_1.0`. Không chạy build script của dự án.
- Java discovered/scanned/skipped: **354 / 16 / 338**; PARTIAL_BOUNDED. Phần bị bỏ qua chưa được kiểm tra. Giới hạn của lượt chạy: `{"max_files_limit": 16, "scan_scope_policy": "BOUNDED_PARTIAL_SCAN", "file_allowlist": ["src/main/java/org/owasp/webgoat/lessons/pathtraversal/PathTraversal.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUpload.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadBase.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadFix.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRemoveUserInput.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionAdvanced.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionQuiz.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjection.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java"]}`.
- OpenGrep candidates: 13; IRIS taint/safe/unknown: 7/3/3; triage REPORT/REVIEW/SUPPRESS: 7/3/3.
- Qwen role identities: 5; cache hits: 5; fresh requests: 0; GPU calls thực: 0. Role classification không phải phán quyết vulnerability TP/FP.
- CWSS GENERAL_JAVA: 0.0 × 2, 12.6 × 7, 15.0 × 3, 16.4 × 1; reference scenario: 0.0 × 2, 67.1 × 7, 80.2 × 3, 86.0 × 1. Source-bound: 13/13; đủ 16 metric ở hai mode. Blockers: `{"UNSUPPORTED_OR_UNPROVEN_OVERLOAD": 7, "RECEIVER_TYPE_UNPROVEN": 6, "INDEPENDENT_LOCAL_PROOF_NOT_CONFIRMED": 4, "AST_CALLSITE_MISSING_OR_AMBIGUOUS": 2, "SINK_SLOT_UNCOVERED": 3, "IRIS_UNKNOWN_NO_LOCAL_FLOW_PROOF": 3, "RECEIVER_ORIGIN_UNPROVEN": 1}`.
- E2E: 0.574 s; API scan/summary/findings/CWSS/report/trace đều HTTP 200; 10 stage có trạng thái/duration thật trong CSV. Zero candidates có stage 06 SKIPPED.
- Scan `SCAN-20261101182250-D3C5C9`; [Results](http://127.0.0.1:5174/#/results?scan_id=SCAN-20261101182250-D3C5C9); [JSON report](http://127.0.0.1:8766/api/scans/SCAN-20261101182250-D3C5C9/report?format=json); [Trace](http://127.0.0.1:8766/api/scans/SCAN-20261101182250-D3C5C9/pipeline-trace).


## So sánh Spark và tính độc lập của nguồn

Cặp Spark cùng upstream `perwendel/spark`, commits `ce57dfb949ed183405f75dee8cf3262b45c9b3b5` và `efcb46c710e3f56805b9257a63d1306882f4faf9`. [Issue #700](https://github.com/perwendel/spark/issues/700) mô tả arbitrary file read, liên kết CVE-2016-9177 và xác nhận fix; [commit sửa](https://github.com/perwendel/spark/commit/efcb46c710e3f56805b9257a63d1306882f4faf9) merge PR #701. Hai snapshot không phải hai commit liền nhau: 28 files khác; diff liên quan handlers/staticfiles/DirectoryTraversal đã lưu local. Không suy ground truth từ chữ fixed/vuln.

Hai scan hiện cùng 9 candidates UNKNOWN/REVIEW và default CWSS 12.6/67.1. Vị trí traversal trong abstraction resource/static files không được rule hiện tại bắt/giải quyết thành flow proof. Đây là giới hạn coverage/phân tích liên thủ tục; không phải chứng cứ hai bản an toàn hoặc fix vô hiệu. Không đổi rule/threshold để làm đẹp cặp này, không khẳng định bản fixed không có lỗ hổng khác.

`webgoat_sql_CVE-2026-0006_1.0` có cùng commit và Java bytes với WebGoat; đây là hai scan vận hành, không phải hai mẫu accuracy độc lập. `CVE-2026-*`/`TEST` trong tên bộ nghiên cứu không được xem như CVE/advisory đã xác minh. OWASP operational fixture dùng commit `0352dbb...`, khác evaluation commit `f40c618...`; hai nhóm được tách rõ.

Logs, full responses, source snapshots, ZIPs và screenshots chỉ ở ignored `work/e2e-multiproject-acceptance/`. Không commit source ZIP, dataset private, SQLite, model hoặc screenshots. Các scan trước sửa vẫn được giữ; bảng trên dùng scan ID mới sau sửa.
