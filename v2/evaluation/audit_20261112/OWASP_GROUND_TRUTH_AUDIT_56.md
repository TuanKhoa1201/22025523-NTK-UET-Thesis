# Biên Bản Kiểm Toán Độc Lập 56 Nhãn OWASP BenchmarkJava v1.2 và Phân Loại 20 Cảnh Báo Dự Án Thực Tế

> [!WARNING]
> **Đính chính 13/11/2026 (Antigravity tự đính chính):** Dòng 83 gọi phương thức chứa cảnh báo `UserDao.java:63` là `readSafe`; tên thật là `open` (`UserDao.java:61`). Kết luận về 56 nhãn OWASP không đổi và đã được tái kiểm từ nguồn công khai (`v2/evaluation/g0_final_review/verify_owasp_public.py`, 56/56 khớp).

- **Nhánh thực nghiệm được kiểm toán:** `v2/post-report-cwe22-cwe89-20261112` @ `86636b9de22e59efcca2d3786434727c6ae082e4`
- **Nhánh kiểm toán độc lập:** `kiem-toan/du-lieu-va-ket-qua-20261112`
- **Nguồn Ground Truth chuẩn đối chiếu:** `OWASP-Benchmark/BenchmarkJava` v1.2 tại commit ghim cứng `8b67a88d73b2594570fc21150705283de884620b`
- **Tệp nhãn gốc OWASP:** `expectedresults-1.2.csv` (`95,328` bytes LF, `2,740` test cases; `SHA-256 = 1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`)
- **Script kiểm chứng tự động:** `v2/evaluation/audit_20261112/independent_audit.py` + `v2/evaluation/audit_20261112/owasp_v1_2_reference_56.json`

---

## 1. Kết Quả Tổng Quan Kiểm Toán Nhãn Chuẩn (`56` Cảnh Báo Benchmark + `20` Cảnh Báo Ngoài Benchmark)

| Hạng mục kiểm toán | Kết quả | Trạng thái | Chi tiết thực chứng |
|---|---|---|---|
| Tồn tại, hợp lệ và duy nhất của `16` bản ghi `dev_set_16` | `16/16` hợp lệ, `0` trùng lặp | `PASS` | Khớp 1–1 theo khóa `alert_id` giữa `dev_alerts.json`, `labels_development.json` và `labels_development.csv`. |
| Tồn tại, hợp lệ và duy nhất của `40` bản ghi `heldout_set_40` | `40/40` hợp lệ, `0` trùng lặp | `PASS` | Khớp 1–1 theo khóa `alert_id` giữa `heldout_alerts.json`, `labels_heldout.json` và `labels_heldout.csv`. |
| Định danh tất định Contract 1.1 (`SHA256(scan_sha256 + ":" + finding_index)`) | `56/56` khớp chính xác | `PASS` | `16/16` thuộc `scan_sha256 = ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f`; `40/40` thuộc `scan_sha256 = 67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b`. |
| Tách biệt giữa tập phát triển (`16`) và tập đánh giá (`40`) | `0` trùng lặp | `PASS` | `0` giao nhau trên cả 4 khóa: `test_case`, `file_path`, `alert_id` và `source_sha256` (`56` tệp `.java` riêng biệt). |
| Đối chiếu `test_case`, `CWE` và nhãn boolean (`TRUE_POSITIVE` / `FALSE_POSITIVE`) với `expectedresults-1.2.csv` | `56/56` khớp (`16/16` + `40/40`) | `PASS` | Toàn bộ `28 TP` và `28 FP` (`28 CWE-22`, `28 CWE-89`) khớp chính xác với cột `category`, `cwe` và `real vulnerability` của OWASP BenchmarkJava v1.2; không có nhãn nào lấy từ đầu ra của Qwen. |
| Đối chiếu `source_sha256` với tệp `.java` gốc của OWASP tại commit `8b67a88d...` | `56/56` khớp (LF bytes) | `PASS` | Cả 56 giá trị `source_sha256` khớp 100% với tệp gốc `src/main/java/org/owasp/benchmark/testcode/BenchmarkTestXXXXX.java` chuẩn LF. |
| Độ chính xác của trường giải thích `annotator_rationale` / `sanitizer_or_reason` trong tệp nhãn | `52/56` khớp cơ chế mã; **`4/56` sai hoặc chung chung** | **`FAIL` (trên lý giải)** | Phát hiện 2 bản ghi mô tả sai hoàn toàn cơ chế mã nguồn (`BenchmarkTest00863`, `BenchmarkTest01746`), 1 bản ghi để nhãn mẫu chung chung (`BenchmarkTest01752`), và 1 bản ghi bỏ sót nguồn hằng `getTheValue` (`BenchmarkTest00864`). |
| Đối chiếu vị trí dòng/byte-offset với raw `opengrep.json` gốc | Chưa có raw `opengrep.json` trên GitHub | **`NOT_VERIFIED`** | GitHub chỉ lưu bản rút gọn `dev_alerts.json` và `heldout_alerts.json`; kiểm chứng dòng sink trên tệp `.java` gốc đạt `56/56`, nhưng kiểm chứng byte-offset trên raw `opengrep.json` cần chạy trên `ADMIN-PC`. |
| Bằng chứng đóng băng tập `heldout_set_40` và cấu hình trước khi chạy mô hình | Khóa thiếu `config_sha256` + lệch CRLF/LF khi checkout | **`PARTIAL`** | Xem Mục 3 bên dưới. |
| Phân loại riêng `20` cảnh báo dự án/demo ở Stage 5 | Nhãn thủ công (`MANUAL_CODE_REVIEW`), trộn `5` cảnh báo demo tổng hợp | **`PARTIAL`** | Không phải Ground Truth chính thức của OWASP; gồm `11` WebGoat + `4` `java-sec-code` + `5` `demo/UserDao.java`. |

> **Kết luận tổng hợp cho phần Nhãn chuẩn:** **`PARTIAL`** (Nhãn boolean TP/FP, CWE và `source_sha256` của 56 cảnh báo đạt `PASS` 100% khi đối chiếu trực tiếp với OWASP BenchmarkJava v1.2; tuy nhiên lý giải `annotator_rationale` có 4 lỗi xác thực do sinh tự động theo mẫu và chưa kiểm chứng được raw `opengrep.json` trên máy chủ).

---

## 2. Phân Biệt Nhãn Cấp Test Case (OWASP) và Nhãn Cấp Cảnh Báo / Sink

1. **Bản chất của `expectedresults-1.2.csv`:** OWASP BenchmarkJava v1.2 cung cấp nhãn ở **cấp độ test case (servlet)** (`BenchmarkTestXXXXX -> category, real vulnerability, cwe`), được thiết kế sao cho mỗi servlet kiểm tra đúng một lỗ hổng mục tiêu. Trong toàn bộ kho Benchmark v1.2 có `2,740` test cases, trong đó:
   - `pathtraver` (`CWE-22`): `268` test cases (`133 TP`, `135 FP`).
   - `sqli` (`CWE-89`): `504` test cases (`272 TP`, `232 FP`).
   - Tổng cộng `CWE-22 + CWE-89`: **`772` test cases (`405 TP`, `367 FP`)**.
2. **Kiểm chứng ánh xạ sang cấp cảnh báo / sink trên 56 bản ghi:**
   - Qua kiểm tra trực tiếp mã nguồn 56 tệp `.java` tại commit `8b67a88d73b2594570fc21150705283de884620b`, mỗi tệp trong `dev_set_16` (`16` tệp) và `heldout_set_40` (`40` tệp) chỉ phát sinh **đúng 1 cảnh báo duy nhất** (`56` cảnh báo = `56` servlet khác nhau), và tọa độ `start_line..end_line` của từng cảnh báo đều nằm đúng câu lệnh sink `CWE-22` (`new java.io.File(...)`, `new java.io.FileInputStream(...)`, `new java.io.FileOutputStream(...)`) hoặc sink `CWE-89` (`prepareStatement(...)`, `prepareCall(...)`, `executeQuery(...)`, `executeUpdate(...)`, `execute(...)`, `addBatch(...)`).
   - Do không có cảnh báo phụ (spurious secondary rule match) hay đa-sink mâu thuẫn trong 56 tệp này, nhãn boolean TP/FP ở cấp test case của OWASP đồng nhất hợp lệ với nhãn ở cấp sink cho 56 cảnh báo này.
   - **Giới hạn bắt buộc ghi nhận:** Vì raw `opengrep.json` (`ecc1fa46...` và `67c3b049...`) nằm trên `ADMIN-PC` ngoài Git, việc xác nhận OpenGrep không sinh thêm cảnh báo thứ hai nào bị lọc bỏ khi trích xuất tập con cần JavisOS xác nhận bằng `independent_audit.py --server-evidence-dir` trên máy chủ (`NOT_VERIFIED` từ phía GitHub).

---

## 3. Các Sai Lệch Xác Thực Trong Trường Lý Giải Nhãn (`annotator_rationale` & `sanitizer_or_reason`)

Dù trường `annotated_by` trong `labels_development.json` và `labels_heldout.json` được ghi là `"NTK-manual-code-review+OWASP-Benchmark-v1.2"`, cấu trúc câu lặp lại theo khuôn mẫu cho thấy văn bản giải thích được sinh tự động bằng biểu thức chính quy (liên quan tới công cụ tạo nhãn trên máy chủ) dẫn đến **4 sai lệch thực tế** khi đối chiếu với mã nguồn gốc của OWASP:

| STT | Tệp & Định danh bản ghi (`alert_id`) | Test Case (`Split`) | Giá trị thực tế trong tệp nhãn (`labels_*.csv` / `.json` / `DATASET_MANIFEST.md`) | Giá trị kỳ vọng đúng theo mã nguồn OWASP (`8b67a88d...`) | Nguyên nhân gốc rễ & Mức độ |
|---:|---|---|---|---|---|
| 1 | `v2/evaluation/post_report/labels_heldout.csv:40`, `labels_heldout.json` (`bb5a6a2cee5cf796b32c04c7e553b6ea275b8c8a843875285dea1338d9798ad7`) | `BenchmarkTest01746.java` (`heldout_set_40`, `CWE-22`, `FALSE_POSITIVE`) | Ghi `constant_ternary_arithmetic_branch`: khẳng định dòng 96 `bar = (7 * 42) - num > 200 ? "This should never happen" : param;` dùng điều kiện `(7 * 18) + num > 200` với `num = 106` luôn đúng và gán chuỗi hằng cho `bar`. | Trong `BenchmarkTest01746.java` dòng 94–96, `num = 106` và `(7 * 42) - 106 = 188 <= 200` là **`false`**, nên toán tử 3 ngôi gán **`param`** (nhánh giữ nguyên tham số, đúng như chú thích dòng 93 `assigns param to bar on false condition`). Lý do thực sự test case này là `FALSE_POSITIVE` nằm ở **dòng 45**: `String param = scr.getTheValue("BenchmarkTest01746");` (trả về hằng `"bar"` theo `SeparateClassRequest.java:52-54`). | **HIGH** — Script sinh rationale ghép nhầm mẫu biểu thức số học mà không tính giá trị toán học và bỏ sót `scr.getTheValue(...)` ở dòng 45. |
| 2 | `v2/evaluation/post_report/labels_development.csv:12`, `labels_development.json` (`bb95eb45e23ca2c541f8665bf5dd9411b9302a8f6f254791afabdddf0c5d80d0`) | `BenchmarkTest00863.java` (`dev_set_16`, `CWE-22`, `FALSE_POSITIVE`) | Ghi `external_thing_interface_constant_return`: khẳng định `ThingInterface.doSomething` trả về hằng số không nhiễm bẩn cho test case này. | Trong OWASP BenchmarkJava v1.2, cả `Thing1.java:25-26` (`return i`) và `Thing2.java:25-26` (`new StringBuilder(i).toString()`, được chọn bởi `thing.properties:1` `thing=Thing2`) đều **giữ nguyên chuỗi đầu vào**. Lý do thực sự `BenchmarkTest00863.java` là `FALSE_POSITIVE` nằm ở **dòng 45**: `String param = scr.getTheValue("BenchmarkTest00863");` (trả về hằng `"bar"`). (Bản thân `SANITIZER_CASE_REVIEW.md:27` ghi đúng là do `getTheValue`, mâu thuẫn trực tiếp với `labels_development.csv:12`.) | **HIGH** — Hiểu sai hành vi của `ThingFactory`/`ThingInterface` và bỏ sót `getTheValue` ở dòng 45. |
| 3 | `v2/evaluation/post_report/labels_heldout.csv:41`, `labels_heldout.json` (`f905aaf22f022c1ed4c90d47547aa47f6d1e883bed4d766fcccf2c3e12f237d7`) | `BenchmarkTest01752.java` (`heldout_set_40`, `CWE-22`, `FALSE_POSITIVE`) | Ghi nhãn mẫu chung chung `benchmark_false_positive_non_tainted_flow (source line 44, sink line 60)` và `"overwritten by a deterministic non-tainted branch or safe wrapper"`. | Dòng 45 gọi `scr.getTheValue("BenchmarkTest01752")` trả về hằng `"bar"`, sau đó `Test.doSomething` (dòng 78–83) đưa `param` vào `map11351.put("keyB-11351", param)` và lấy lại chính khóa `"keyB-11351"` (tức luồng `HashMap` bảo toàn tham số, còn điểm triệt tiêu taint nằm ở `getTheValue` dòng 45). | **MEDIUM** — Chuỗi fallback tự động chưa được rà soát thủ công cụ thể như cam kết trong `LABELING_PROTOCOL.md`. |
| 4 | `v2/evaluation/post_report/labels_heldout.csv:19`, `labels_heldout.json` (`783253de48f562b336c212e5a5280c9f6ca20313a26f4836ac5ad60ffa19a740`) | `BenchmarkTest00864.java` (`heldout_set_40`, `CWE-22`, `FALSE_POSITIVE`) | Mô tả dòng 44 đọc HTTP input qua `SeparateClassRequest` rồi lọc bởi `valuesList.get(1)` ở dòng 56. | Tệp này có **hai** lớp an toàn đồng thời: ngay dòng 45 `scr.getTheValue("BenchmarkTest00864")` đã trả về hằng `"bar"` (không đọc HTTP), và dòng 56 `valuesList.get(1)` lấy thêm hằng `"moresafe"`. | **LOW** — Mô tả thiếu tầng nguồn hằng `getTheValue()` ở dòng 45 (mâu thuẫn nhẹ với `PAIRED_EVALUATION.csv:19` vốn giải thích theo dòng 45 `getTheValue`). |

> **Phát hiện bổ sung về độ phủ mẫu `HashMap`:** `LABEL_VALIDATION_REPORT.md:46-47` khẳng định tập dữ liệu bao phủ mẫu cảnh báo giả qua `HashMap`, nhưng kiểm tra toàn bộ 56 tệp `.java` cho thấy **chỉ có duy nhất `1/56` tệp (`BenchmarkTest01752.java`) chứa `HashMap`**, và trong tệp đó `HashMap` truyền cùng khóa `keyB-11351` (không phải mẫu FP chọn khóa an toàn `keyA`). Tập 56 cảnh báo có **`0/56`** ca FP do `HashMap` chọn khóa hằng.

---

## 4. Kiểm Toán Thời Điểm Hình Thành Tập Kiểm Tra và Khóa Dữ Liệu (`STRICT_LOCK`)

1. **Dấu thời gian Git trên nhánh `v2/post-report-cwe22-cwe89-20261112`:**
   - Commit `38d8769` (*Stage 1: 56-alert dataset & `STRICT_LOCK` manifest*): `2026-11-12 03:45:14 +0700`.
   - Commit `6649493` & `8a1ef91` (*Stage 2–3: `java_context.py`, `heuristics.py`, prompt `v2.1` & `dev_set_16` eval*): `2026-11-12 04:26:00–04:26:01 +0700`.
   - Commit `e5e60ea` (*Stage 4: `PAIRED_EVALUATION.csv` trên `heldout_set_40`*): `2026-11-12 04:41:21 +0700`.
   - Khoảng cách `04:26:01 -> 04:41:21` là `920 giây` (`15 phút 20 giây`), đủ chứa tổng thời gian suy luận được báo cáo của Arm C (`421.0 s`) + Arm D (`301.1 s`) = `722.1 s`.
2. **Ba giới hạn kỹ thuật khiến trạng thái khóa chỉ đạt `PARTIAL` (không thể chứng minh độc lập tuyệt đối):**
   - **Thiếu khóa cấu hình/prompt trong manifest (`LOCK-01`):** Trong `v2/evaluation/post_report/heldout_strict_lock_manifest.json:8-9`, hai trường `"config_file": null` và `"config_sha256": null` bị bỏ trống. Phiên bản `heuristics.py` và prompt `v2.1` không được băm vào `combined_lock_sha256`.
   - **Vỡ mã băm byte-level khi checkout Git do CRLF -> LF (`LOCK-02`):** `heldout_strict_lock_manifest.json` ghi:
     - `opengrep_sha256 = ba9967f3ae1dcbe940e8e7dea7df36ff873232fe5787f42c3fd2c84e066b1826` (mã băm của `heldout_alerts.json` ở dạng **CRLF** trên Windows trước khi commit), trong khi tệp lưu trong Git (`*.json text eol=lf`) có mã băm **LF** là `3ea68283fdbece7425c6af9caf65cc0942031752c62eab6dc73820a31a920f7d`.
     - `labels_sha256 = 7f7fdff1be650f1f6335b61c312bde133a41f42974017eaaaea19bde069b65d3` (**CRLF**), trong khi tệp trên Git (**LF**) có mã băm `1e7306127dbf5f91c62a7f143d047e4714aa6197624990a0c31c9dd3e9ddc1a4`.
     - Hệ quả: chạy `python v2/evaluation/validate_pilot_lock.py --mode STRICT_LOCK --opengrep v2/evaluation/post_report/heldout_alerts.json --labels v2/evaluation/post_report/labels_heldout.json --verify-lock v2/evaluation/post_report/heldout_strict_lock_manifest.json` trên bản clone sạch sẽ báo **FAIL (`exit_code = 1`)**! (Trong biên bản bàn giao dòng 138, lệnh kiểm tra đã bỏ qua tham số `--verify-lock` nên không phát hiện lỗi này.)
   - **Không có cơ chế tiền đăng ký độc lập ngoài máy cá nhân:** Lịch sử commit cục bộ trước khi push không thể chứng minh mật mã học rằng tác giả chưa từng xem danh sách test case của OWASP Benchmark trước khi viết bộ regex đặc thù OWASP trong `heuristics.py` (ví dụ `heuristics.py:78-81` có viết sẵn bộ giải `MAP_PUT_RE` / `MAP_GET_RE` dù `dev_set_16` có `0` mẫu `HashMap`).

---

## 5. Phân Loại Riêng 20 Cảnh Báo Ngoài OWASP Benchmark (`REAL_PROJECT_EVALUATION.md`)

20 cảnh báo trong `v2/evaluation/post_report/REAL_PROJECT_EVALUATION.md` (`scan_sha256 = 99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041`) **KHÔNG phải Ground Truth chính thức của OWASP Benchmark** và phải được tách bạch rõ thành 3 nhóm nguồn gốc:

| Nguồn mã nguồn | Bản chất dữ liệu | Số cảnh báo OpenGrep | Số luồng mã độc lập thực tế | Nhãn thủ công (`TP / FP`) | Kết quả Arm C (`SUPPORTED / REFUTED / UNDETERMINED`) | Nhận xét kiểm toán |
|---|---|---:|---:|---|---|---|
| **1. `OWASP WebGoat`** (`commit 5357a65e...`) | Ứng dụng huấn luyện bảo mật chứa lỗ hổng chủ đích (Open-source training app) | `11` | `7` (có `4` cặp cảnh báo trùng vị trí do 2 rule SQLi cùng bắt một hàm) | `8 TP / 3 FP` (`MANUAL_CODE_REVIEW`) | `11 SUPPORTED / 0 REFUTED / 0 UNDETERMINED` | Giữ đúng `8/8` TP nhưng lọc được **`0/3` (`0.0%`) FP**. |
| **2. `java-sec-code`** (`commit 4711f4e1...`) | Kho mã mẫu lỗ hổng bảo mật Java (Vulnerability showcase repo) | `4` | `2` (`jdbc_sqli_vul` và `jdbc_ps_vuln`, mỗi hàm sinh 2 cảnh báo trùng) | `4 TP / 0 FP` (`MANUAL_CODE_REVIEW`) | `4 SUPPORTED / 0 REFUTED / 0 UNDETERMINED` | Không có ca FP nào để kiểm định khả năng lọc báo động giả. |
| **3. `demo/UserDao.java`** (từ `opengrep-triage.zip`) | **Tệp mã demo tổng hợp (`70` dòng)** trong gói tài liệu hướng dẫn | `5` | `3` (`findUnsafe` dòng 23 sinh 2 cảnh báo; `runQuery` dòng 42 sinh 2 cảnh báo; `readSafe` dòng 63 sinh 1 cảnh báo) | `4 TP / 1 FP` (`SYNTHETIC_DEMO_MANUAL`) | `5 SUPPORTED / 0 REFUTED / 0 UNDETERMINED` | **Không phải dự án thực tế mã nguồn mở**; gộp chung vào tiêu đề *"20 cảnh báo dự án Java thực tế"* là không chính xác về phân loại dữ liệu. |
| **Tổng cộng** | Hỗn hợp Training Repo + Synthetic Demo | **`20`** | **`12` luồng độc lập** | **`16 TP / 4 FP`** (Nhãn thủ công) | **`20 SUPPORTED / 0 REFUTED / 0 UNDETERMINED`** | **Tỷ lệ lọc FP thực tế ngoài OWASP Benchmark = `0/4 (0.0%)`** (`Precision drop_fp = 16/20 = 80.0%`, không đổi so với OpenGrep đơn lẻ). |
