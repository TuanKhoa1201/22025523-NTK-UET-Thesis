# DATASET MANIFEST — Tập Dữ Liệu Đánh Giá CWE-22 & CWE-89 (Stage 1)

## 1. Tổng Quan Tập Dữ Liệu

- **Mục đích:** Vượt qua giới hạn của bộ smoke test `n = 3` (`SmokeVulnSample.java`), thiết lập bộ dữ liệu đánh giá chuẩn cho 2 nhóm lỗ hổng trọng tâm `CWE-22` (Path Traversal) và `CWE-89` (SQL Injection) với tổng cộng **56 cảnh báo đã gán nhãn độc lập** (`16` cảnh báo thuộc tập Development và `40` cảnh báo thuộc tập Held-out Evaluation).
- **Nguồn dữ liệu gốc:** OWASP BenchmarkJava v1.2 (`/home/tuankhoa/migration/ntk_ft211_sources/BenchmarkJava`, Git commit `8b67a88d73b2594570fc21150705283de884620b`, tệp nhãn gốc `expectedresults-1.2.csv` SHA-256: `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`).
- **Bộ quy tắc OpenGrep đã ghim:** `v2/evaluation/post_report/rules/p_java_cwe22_cwe89.yml` (SHA-256: `4d12f6deabee1bcf17f1bcce845f05eaf84b312ee13aa6a9cd9721ea879695f9`), trích xuất nguyên bản 9 rule `CWE-22`/`CWE-89` từ bản ghim `p-java.raw.yaml` (SHA-256: `5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1`).
- **Công cụ quét:** OpenGrep OSS `1.25.0` với cờ `--dataflow-traces --taint-intrafile --no-git-ignore --disable-version-check`, kèm biên bản chụp thực thi `ScanCapture` (`scan-manifest.json`, schema `ntk-scan-capture-1`).

## 2. Phân Bổ Các Tập Dữ Liệu (100% Tách Biệt Giữa Development và Held-Out)

| Tập dữ liệu | Mục đích sử dụng | Tổng số cảnh báo | CWE-22 TP | CWE-22 FP | CWE-89 TP | CWE-89 FP | `scan_sha256` | `manifest_sha256` |
|---|---|---:|---:|---:|---:|---:|---|---|
| `dev_set_16` (`labels_development.csv`) | Tinh chỉnh prompt, ngữ cảnh Java và heuristic sanitizer (Giai đoạn 2-3) | **16** | 4 | 4 | 4 | 4 | `ecc1fa4634bfc862...` | `67d708880cb7a93f...` |
| `heldout_set_40` (`labels_heldout.csv`) | Đánh giá ghép cặp chính thức (Giai đoạn 4), khóa trước khi chạy Qwen | **40** | 10 | 10 | 10 | 10 | `67c3b04903e75f4b...` | `3f5488d9a8de308b...` |
| **Tổng cộng** | **Toàn bộ tập CWE-22/CWE-89 có nhãn độc lập** | **56** | **14** | **14** | **14** | **14** | - | - |

> **Bổ sung cho kiểm thử hồi quy (Stage 2-3):** Ngoài 16 cảnh báo OWASP BenchmarkJava trong `dev_set_16`, quá trình kiểm thử hồi quy trích dẫn và sanitizer ở Giai đoạn 2-3 còn sử dụng bộ `SmokeVulnSample.java` (`n = 3`: 1 CWE-89 TP, 1 CWE-22 TP, 1 CWE-22 FP với `FilenameUtils.getName`) và `UserDao.java` (`n = 5` dưới bộ rule `p/java`, gồm `getCanonicalPath().startsWith(BASE_DIR)` và luồng liên hàm `findViaHelper -> runQuery`).

## 3. Danh Mục Chi Tiết Tập Development (`n = 16`)

| `#` | `file_path` | `cwe` | `start_line` | `expected_label` | `sanitizer_or_reason` | `source_sha256` |
|---:|---|---|---:|---|---|---|
| 0 | `BenchmarkTest00001.java` | `CWE-22` | 72 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 55 -> sink line 72) | `a83e78f8e9dd7b94...` |
| 1 | `BenchmarkTest00008.java` | `CWE-89` | 57 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 45 -> sink line 57) | `9bc49dbe491a3916...` |
| 2 | `BenchmarkTest00102.java` | `CWE-89` | 73 | `TRUE_POSITIVE` | no_sanitizer_external_thing_interface_passthrough (line 66: `org.owasp.benchmark.helpers.ThingInterface thing =` returns `param`) | `4ee3d85461784e6b...` |
| 3 | `BenchmarkTest00103.java` | `CWE-89` | 76 | `TRUE_POSITIVE` | no_sanitizer_tainted_arithmetic_branch (line 71: `bar = (7 * 42) - num > 200 ? "This should never happen" : param;` evaluates to `param`) | `a2835ca20d356ed6...` |
| 4 | `BenchmarkTest00131.java` | `CWE-22` | 72 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 53: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `7091b80b2b9f186e...` |
| 5 | `BenchmarkTest00190.java` | `CWE-89` | 68 | `FALSE_POSITIVE` | safe_collection_index_selection (line 60: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `e9b906300fd16ae1...` |
| 6 | `BenchmarkTest00191.java` | `CWE-89` | 77 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 53: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `258434bdbb2c3b20...` |
| 7 | `BenchmarkTest00216.java` | `CWE-22` | 68 | `TRUE_POSITIVE` | no_sanitizer_tainted_arithmetic_branch (line 65: `if ((500 / 42) + num > 200) bar = param;` evaluates to `param`) | `8cfaacce6f3aea7b...` |
| 8 | `BenchmarkTest00527.java` | `CWE-22` | 64 | `TRUE_POSITIVE` | no_sanitizer_external_thing_interface_passthrough (line 60: `org.owasp.benchmark.helpers.ThingInterface thing =` returns `param`) | `3700b27707423bab...` |
| 9 | `BenchmarkTest00620.java` | `CWE-22` | 60 | `FALSE_POSITIVE` | safe_collection_index_selection (line 57: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `12bf356c39f6ba2a...` |
| 10 | `BenchmarkTest00863.java` | `CWE-22` | 51 | `FALSE_POSITIVE` | external_thing_interface_constant_return (line 47: `org.owasp.benchmark.helpers.ThingInterface thing =` in OWASP Benchmark FP case) | `69d31a8b396303a3...` |
| 11 | `BenchmarkTest00950.java` | `CWE-22` | 68 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 54 -> sink line 68) | `a5729f499e742ab5...` |
| 12 | `BenchmarkTest00998.java` | `CWE-89` | 74 | `TRUE_POSITIVE` | no_sanitizer_tainted_arithmetic_branch (line 98: `bar = (7 * 42) - num > 200 ? "This should never happen" : param;` evaluates to `param`) | `c8151e0cd1f3bce7...` |
| 13 | `BenchmarkTest01010.java` | `CWE-89` | 71 | `FALSE_POSITIVE` | safe_collection_index_selection (line 99: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `9d89a8a68982822f...` |
| 14 | `BenchmarkTest01031.java` | `CWE-22` | 58 | `FALSE_POSITIVE` | safe_collection_index_selection (line 97: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `efb0bce0a68e68f8...` |
| 15 | `BenchmarkTest01096.java` | `CWE-89` | 56 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 74: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `62a893d3dbaf217e...` |

## 4. Danh Mục Chi Tiết Tập Held-Out Evaluation (`n = 40`)

| `#` | `file_path` | `cwe` | `start_line` | `expected_label` | `sanitizer_or_reason` | `source_sha256` |
|---:|---|---|---:|---|---|---|
| 0 | `BenchmarkTest00011.java` | `CWE-22` | 54 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 45 -> sink line 54) | `2f7d82f88b6c0d4f...` |
| 1 | `BenchmarkTest00018.java` | `CWE-89` | 57 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 45 -> sink line 57) | `f050b4ae7057c0e3...` |
| 2 | `BenchmarkTest00024.java` | `CWE-89` | 52 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 44 -> sink line 52) | `6886ac19a08825f8...` |
| 3 | `BenchmarkTest00025.java` | `CWE-89` | 51 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 44 -> sink line 51) | `c136d4ea5dc4f7f5...` |
| 4 | `BenchmarkTest00038.java` | `CWE-89` | 63 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 46 -> sink line 63) | `cefc086af3dfc9af...` |
| 5 | `BenchmarkTest00040.java` | `CWE-22` | 49 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 45 -> sink line 49) | `d0c0a5ae358ae44c...` |
| 6 | `BenchmarkTest00062.java` | `CWE-22` | 78 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 54 -> sink line 78) | `c44197ff092d91e5...` |
| 7 | `BenchmarkTest00108.java` | `CWE-89` | 92 | `TRUE_POSITIVE` | no_sanitizer_switch_tainted_branch (line 68: char switchTarget = guess.charAt(2); selects branch assigning `param`) | `0d6d1a3a413aea99...` |
| 8 | `BenchmarkTest00132.java` | `CWE-22` | 77 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 53: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `0b7b0d2ccc2cfd09...` |
| 9 | `BenchmarkTest00134.java` | `CWE-22` | 74 | `FALSE_POSITIVE` | safe_collection_index_selection (line 60: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `b740e58e539ebe49...` |
| 10 | `BenchmarkTest00135.java` | `CWE-22` | 83 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 53: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `c01963ab392a2ca7...` |
| 11 | `BenchmarkTest00197.java` | `CWE-89` | 65 | `FALSE_POSITIVE` | safe_collection_index_selection (line 60: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `7f87ad19c6c0517c...` |
| 12 | `BenchmarkTest00205.java` | `CWE-89` | 66 | `FALSE_POSITIVE` | safe_collection_index_selection (line 60: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `396d6ec97ed0fc30...` |
| 13 | `BenchmarkTest00218.java` | `CWE-22` | 102 | `TRUE_POSITIVE` | no_sanitizer_switch_tainted_branch (line 63: char switchTarget = guess.charAt(2); selects branch assigning `param`) | `a35197feae5ed8a7...` |
| 14 | `BenchmarkTest00264.java` | `CWE-22` | 65 | `TRUE_POSITIVE` | no_sanitizer_tainted_arithmetic_branch (line 57: `if ((500 / 42) + num > 200) bar = param;` evaluates to `param`) | `2c7371e6232d9848...` |
| 15 | `BenchmarkTest00340.java` | `CWE-89` | 77 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 55: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `cf6aa646d4a85e57...` |
| 16 | `BenchmarkTest00763.java` | `CWE-89` | 74 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 50: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `9fd2a74645c6dca2...` |
| 17 | `BenchmarkTest00864.java` | `CWE-22` | 59 | `FALSE_POSITIVE` | safe_collection_index_selection (line 56: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `402ffac5a02c4cf6...` |
| 18 | `BenchmarkTest00949.java` | `CWE-22` | 68 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 54 -> sink line 68) | `8f8b95414642bc4f...` |
| 19 | `BenchmarkTest00952.java` | `CWE-22` | 88 | `TRUE_POSITIVE` | no_sanitizer_switch_tainted_branch (line 115: char switchTarget = guess.charAt(2); selects branch assigning `param`) | `2d84e8b0a1979a8d...` |
| 20 | `BenchmarkTest00953.java` | `CWE-22` | 79 | `TRUE_POSITIVE` | no_sanitizer_tainted_collection_index (line 105: `bar = valuesList.get(0); // get the param value` selects tainted element) | `2d482fabb5d2550c...` |
| 21 | `BenchmarkTest00956.java` | `CWE-22` | 79 | `TRUE_POSITIVE` | no_sanitizer_tainted_arithmetic_branch (line 100: `if ((500 / 42) + num > 200) bar = param;` evaluates to `param`) | `e129ef03fbfb10f7...` |
| 22 | `BenchmarkTest00996.java` | `CWE-89` | 74 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 55 -> sink line 74) | `5af30fbd350e93ec...` |
| 23 | `BenchmarkTest00997.java` | `CWE-89` | 74 | `TRUE_POSITIVE` | no_sanitizer_tainted_collection_index (line 102: `bar = valuesList.get(0); // get the param value` selects tainted element) | `f40f07651b12d1da...` |
| 24 | `BenchmarkTest01004.java` | `CWE-89` | 73 | `TRUE_POSITIVE` | no_sanitizer_switch_tainted_branch (line 92: char switchTarget = guess.charAt(2); selects branch assigning `param`) | `63312fa0af7682ae...` |
| 25 | `BenchmarkTest01006.java` | `CWE-89` | 72 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 54 -> sink line 72) | `a823a02ac4283b0f...` |
| 26 | `BenchmarkTest01011.java` | `CWE-89` | 71 | `TRUE_POSITIVE` | no_sanitizer_tainted_arithmetic_branch (line 92: `if ((500 / 42) + num > 200) bar = param;` evaluates to `param`) | `617fbdacf592a9cd...` |
| 27 | `BenchmarkTest01012.java` | `CWE-89` | 73 | `FALSE_POSITIVE` | safe_collection_index_selection (line 96: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `0f805f0b449de79b...` |
| 28 | `BenchmarkTest01028.java` | `CWE-22` | 70 | `FALSE_POSITIVE` | safe_collection_index_selection (line 104: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `12177004ce7ceba8...` |
| 29 | `BenchmarkTest01030.java` | `CWE-22` | 73 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 100: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `4f1f5e85a4234bef...` |
| 30 | `BenchmarkTest01085.java` | `CWE-89` | 56 | `FALSE_POSITIVE` | safe_collection_index_selection (line 85: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `47fce56105247369...` |
| 31 | `BenchmarkTest01110.java` | `CWE-22` | 80 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 107: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `9bdaf8e09e3e73e5...` |
| 32 | `BenchmarkTest01156.java` | `CWE-22` | 72 | `TRUE_POSITIVE` | no_sanitizer_direct_or_intrafile_taint_flow (source line 44 -> sink line 72) | `ae204f5ae3264983...` |
| 33 | `BenchmarkTest01212.java` | `CWE-89` | 60 | `FALSE_POSITIVE` | safe_collection_index_selection (line 86: `bar = valuesList.get(1); // get the last 'safe' value` selects constant element) | `6121cac0d07b3ace...` |
| 34 | `BenchmarkTest01215.java` | `CWE-89` | 59 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 82: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `afa995514e405566...` |
| 35 | `BenchmarkTest01233.java` | `CWE-22` | 48 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 74: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `c896625d387667de...` |
| 36 | `BenchmarkTest01385.java` | `CWE-89` | 57 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 76: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `62faeec88b757bf0...` |
| 37 | `BenchmarkTest01389.java` | `CWE-89` | 55 | `FALSE_POSITIVE` | constant_switch_branch_safe (line 84: char switchTarget = guess.charAt(1); // condition 'B', which is safe -> case 'B' assigns constant string) | `259e1de65a3a1ad6...` |
| 38 | `BenchmarkTest01746.java` | `CWE-22` | 66 | `FALSE_POSITIVE` | constant_ternary_arithmetic_branch (line 96: `bar = (7 * 42) - num > 200 ? "This should never happen" : param;` evaluates to constant string) | `67d81ccf4b814474...` |
| 39 | `BenchmarkTest01752.java` | `CWE-22` | 60 | `FALSE_POSITIVE` | benchmark_false_positive_non_tainted_flow (source line 44, sink line 60) | `c4c13f85e8839211...` |
