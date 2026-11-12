# Biên Bản Bàn Giao Triển Khai Giai Đoạn Sau Báo Cáo Lần 1 (`POST_REPORT_IMPLEMENTATION_HANDOVER`)

- **Đề tài khóa luận:** *"Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn"*
- **Kho mã nguồn (GitHub):** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis`
- **Nhánh triển khai (Branch):** `v2/post-report-cwe22-cwe89-20261112`
- **Worktree làm việc:** `C:\Users\Admin\ntk-thesis-v2\post-report-cwe22-cwe89`
- **Thư mục bằng chứng thực nghiệm độc lập (ngoài Git):** `C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112`
- **Phạm vi lỗ hổng trọng tâm:** `CWE-22` (Path Traversal) và `CWE-89` (SQL Injection) trên mã nguồn Java.
- **Trạng thái nghiệm thu cuối cùng:** **`READY_FOR_ADVISOR_REVIEW`** (Đạt đủ 13/13 tiêu chí hoàn thành trong Prompt 13 Mục XVIII; tuyệt đối không tự tuyên bố `THESIS_COMPLETED` trước khi giảng viên hướng dẫn phê duyệt).

---

## 1. Bảng Đối Chiếu 13 Tiêu Chí Nghiệm Thu (`READY_FOR_ADVISOR_REVIEW` — Mục XVIII)

| # | Tiêu chí bắt buộc (Prompt 13 — Mục XVIII) | Trạng thái | Bằng chứng thực chứng trong Repository & Evidence Root |
|---|---|---|---|
| `1` | Những bằng chứng nhiệm vụ gốc vẫn nguyên vẹn & Stage 0–7 đủ deliverables | **ĐẠT (`PASS`)** | Các worktree cũ (`advisor-evaluation-javis`, `advisor-m1-proof-ref`, `integration-pilot`, `javis`) giữ nguyên trạng thái sạch; toàn bộ tài liệu và bảng dữ liệu tại `v2/evaluation/post_report/`, `v2/docs/`, `v2/docs/thesis/`. |
| `2` | Pipeline OpenGrep + Qwen cục bộ hoạt động trên dữ liệu thực tế thuộc phạm vi (`>= 40` mẫu có nhãn) | **ĐẠT (`76` mẫu: `56` Benchmark + `20` Real Projects)** | `DATASET_MANIFEST.md`, `DATASET_PROVENANCE.json` (`16` dev + `40` held-out từ OWASP Benchmark + `20` cảnh báo từ `WebGoat`, `java-sec-code`, `UserDao`). |
| `3` | Bộ dữ liệu đánh giá có nguồn, nhãn kiểm tra được và tách biệt dev / held-out (`0` overlap) | **ĐẠT (`0` overlap)** | `LABELING_PROTOCOL.md`, `LABEL_VALIDATION_REPORT.md` và `heldout_strict_lock_manifest.json` (`validate_pilot_lock.py --mode STRICT_LOCK` đạt `exit_code = 0`). |
| `4` | Bảng đối chứng có số đếm và mẫu số chính xác (Arm A, Arm B, Arm C, Arm D) | **ĐẠT (`PASS`)** | `PAIRED_EVALUATION.csv`, `PAIRED_EVALUATION.md`, `METRICS_BY_CWE.csv` trên tập `heldout_set_40` (`n = 40`). |
| `5` | Có báo cáo `TP bị đề xuất loại nhầm` (`erroneously_proposed_fp_on_tp`) với `tử_số/mẫu_số` | **ĐẠT (`0/20 [0.0%]` trên held-out; `0/8 [0.0%]` trên dev; `0/16 [0.0%]` trên dự án thực tế)** | `FALSE_DISMISSAL_ANALYSIS.md`, `PAIRED_EVALUATION.md`, `METRICS_BY_CWE.csv`. |
| `6` | Citation được kiểm chứng và báo cáo rõ `UNDETERMINED` | **ĐẠT (`40/40 [100.0%]` khớp trên held-out Arm C; `16/16` trên dev; `20/20` trên dự án thực tế)** | `EVIDENCE_QUALITY_AUDIT.md`, `CITATION_REGRESSION_RESULTS.json`, `UNDETERMINED_ANALYSIS.md`. |
| `7` | Không tự đóng cảnh báo (No Auto-Dismissal) | **ĐẠT (`PASS`)** | `v2/triage/store.py` khởi tạo mọi cảnh báo ở `state = "OPEN"`, `requires_human_review = True`. |
| `8` | Cơ chế source SHA-256, reopen và negative tests được kiểm thử | **ĐẠT (`16/16 PASS`)** | `v2/triage/tests/test_human_review_negative_suite.py` (`16 passed`) và `HUMAN_REVIEW_VERIFICATION.md`. |
| `9` | Các test quan trọng và Quality Gate đều `PASS` | **ĐẠT (`PASS`)** | `verify-repository.py`, `verify_patch.py`, `pytest` (`200 passed, 26 subtests passed`), `run_v2_quality_gate.py` (`11/11 checks passed`) đều đạt `exit_code = 0`. |
| `10` | Báo cáo có phân tích trường hợp đúng/sai (tối thiểu 5 case studies) | **ĐẠT (`6` Case Studies)** | `CASE_STUDIES_CWE22_CWE89.md` và `SANITIZER_CASE_REVIEW.md`. |
| `11` | Có bản nháp tài liệu khóa luận Chương 1–5 gắn với số liệu thực | **ĐẠT (5 Chương)** | `v2/docs/thesis/CHUONG_1_GIOI_THIEU.md` .. `CHUONG_5_KET_LUAN.md`. |
| `12` | Không commit tệp nhạy cảm hoặc bị cấm (`.pdf`, `.zip`, `.sqlite`, cache lớn) | **ĐẠT (`PASS`)** | Được kiểm tra tự động bởi `python scripts/verify-repository.py` và `git diff --check`. |
| `13` | Git đã ghi lại công việc hợp lệ và có tài liệu bàn giao tái lập | **ĐẠT (`PASS`)** | Nhánh `v2/post-report-cwe22-cwe89-20261112` đã commit theo từng giai đoạn và push lên `origin`. |

---

## 2. Chi Tiết Bàn Giao Theo Đúng Cấu Trúc Mục XVII (A -> I)

### A. Tóm tắt bằng tiếng Việt

1. **Đã làm thêm những gì:**
   - Kiểm toán toàn bộ điểm xuất phát sau Báo cáo tiến độ lần 1 (`POST_REPORT_BASELINE_AUDIT.md`) và cố định `.gitattributes` để chống lỗi chuyển đổi dòng CRLF.
   - Xây dựng bộ dữ liệu phân tầng có nhãn kiểm chứng độc lập cho `CWE-22` và `CWE-89` gồm `56` cảnh báo từ OWASP BenchmarkJava v1.2 (`16` cảnh báo `dev_set_16` + `40` cảnh báo `heldout_set_40` khóa `STRICT_LOCK`) và `20` cảnh báo từ 3 nguồn mã Java thực tế (`OWASP WebGoat`, `java-sec-code`, `UserDao`).
   - Nâng cấp pipeline trích xuất bằng chứng và ngữ cảnh Java (`v2/triage/evidence.py`, `v2/triage/java_context.py`, `v2/triage/heuristics.py`, `v2/triage/ollama.py`): làm phẳng đệ quy nút `CliCall`, trích xuất phương thức bao ngoài + callee cùng tệp, bổ sung tín hiệu tĩnh (`heuristic_signals`), chuẩn hóa `candidate_citations` và tinh chỉnh prompt `v2.1-cwe22-cwe89-grounded` trên `dev_set_16`.
   - Thực hiện đánh giá đối chứng bắt cặp 4 nhánh (`Arm A: OpenGrep-only`, `Arm B: OpenGrep + heuristic`, `Arm C: OpenGrep + evidence + Qwen`, `Arm D: OpenGrep + Qwen ablation không ngữ cảnh mở rộng/tín hiệu tĩnh`) và 3 chính sách (`baseline`, `drop_fp`, `keep_tp_only`) trên tập độc lập `heldout_set_40` (`n = 40`).
   - Biên soạn 6 nghiên cứu tình huống chuyên sâu (`CASE_STUDIES_CWE22_CWE89.md`), kiểm thử 16 ca phủ định quy trình duyệt của con người (`test_human_review_negative_suite.py`), và hoàn thiện bản nháp 5 chương khóa luận (`v2/docs/thesis/CHUONG_1..5.md`).
2. **Vì sao làm:**
   - Ở Báo cáo tiến độ lần 1, kết quả pilot mới dừng ở 3 cảnh báo tổng hợp (`SmokeVulnSample.java`, `FP đề xuất loại đúng = 0/1`). Cần chứng minh bằng thực nghiệm có nhãn độc lập (30–60 cảnh báo CWE-22/CWE-89) rằng việc kết hợp OpenGrep + bằng chứng ngữ cảnh Java + Qwen3.5-9B cục bộ thực sự giúp phát hiện cảnh báo giả mà không đề xuất loại nhầm lỗ hổng thật.
3. **Cải thiện được điều gì:**
   - Trên `dev_set_16` (`8 TP, 8 FP`): cải thiện từ `4/8 (50.0%) TP, 0/8 (0.0%) FP, 6/16 (37.5%) citation` ở `v1.0` lên **`8/8 (100.0%) TP, 8/8 (100.0%) FP, 0/8 (0.0%) loại nhầm TP, 16/16 (100.0%) citation`** ở `v2.1`.
   - Trên tập kiểm định độc lập `heldout_set_40` (`20 TP, 20 FP`): **Arm C (`--mode evidence+llm`)** đạt **`20/20 (100.0%)` TP giữ đúng**, **`20/20 (100.0%)` FP đề xuất loại đúng**, **`0/20 (0.0%)` TP bị đề xuất loại nhầm**, **`0/40 (0.0%)` `UNDETERMINED`**, **`40/40 (100.0%)` citation hợp lệ**, nâng Precision (`drop_fp`) từ `50.0%` (`20/40`) của OpenGrep đơn lẻ lên **`100.0%` (`20/20`)**.
   - Trên `20` cảnh báo dự án thực tế (`16 TP, 4 FP`): giữ đúng **`16/16 (100.0%)` TP**, **`0/16 (0.0%)` loại nhầm TP**, **`20/20 (100.0%)` citation hợp lệ**.
4. **Còn thiếu gì:**
   - Gói `Bo_ma_OpenGrep_Java_Qwen.zip` được nhắc ở trang 3 Tài liệu B (5 trang) chưa được cung cấp trên máy chủ (`NOT_PROVIDED`).
   - Giới hạn kỹ thuật tự nhiên của phân tích nội tệp: 4 cảnh báo FP trên dự án thực tế có sanitizer nằm ở tệp khác (`WebGoatUser.java`) hoặc nằm sau dòng sink constructor `new File(...)` (`UserDao.java:64`) được hệ thống giữ bảo toàn ở Nhóm 1 (`SUPPORTED`) để con người duyệt.
5. **Bước nào cần giảng viên xác nhận (`PENDING_ADVISOR_DECISION`):**
   - Xác nhận xem có cần cung cấp bổ sung gói `Bo_ma_OpenGrep_Java_Qwen.zip` hay gói `opengrep-triage.zip` (`SHA-256: 5f39d2fb...`) đã là gói mã chuẩn duy nhất.
   - Rà soát và cho ý kiến nhận xét đối với bộ kết quả đối chứng `heldout_set_40` (`n = 40`), 6 case studies và bản nháp 5 chương khóa luận tại `v2/docs/thesis/`.

### B. Git

- **Repository:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis`
- **Branch:** `v2/post-report-cwe22-cwe89-20261112` (tách từ commit gốc đã nghiệm thu `150dccab3c7faa7af9e37533378dd863cb643292`).
- **Chuỗi Commit theo từng giai đoạn trên nhánh `v2/post-report-cwe22-cwe89-20261112`:**
  1. `30f6094` — `v2(stage0): add post-report baseline audit and lock smoke raw scan binary gitattributes`
  2. `38d8769` — `v2(stage1): add 56-alert CWE-22/CWE-89 benchmark dataset (16 dev + 40 held-out) and STRICT_LOCK manifest`
  3. `6649493` — `feat(v2-stage2): add Java method/callee context extractor, CliCall trace flattening, and citation audit`
  4. `8a1ef91` — `feat(v2-stage3): add CWE-22/CWE-89 heuristics, prompt v2.1 modes, and dev-set evaluation`
  5. `2ac0dd3` — `test(v2-stage6): add human review negative suite, CLI lifecycle verification, and evaluation method docs`
  6. `e5e60ea` — `feat(v2-stage4): add paired evaluation results on frozen held-out set (n=40)`
  7. `562d5b9` — `feat(v2-stage5): add real Java project evaluation (WebGoat, java-sec-code, UserDao) and 6 CWE-22/CWE-89 case studies`
  8. Commit hoàn tất Stage 7 & Handover (`v2/docs/thesis/CHUONG_1..5.md`, `v2/docs/POST_REPORT_IMPLEMENTATION_HANDOVER.md`, `v2/triage/tests/test_human_review_negative_suite.py` 16 tests) đã được commit và push lên `origin/v2/post-report-cwe22-cwe89-20261112`.
- **Trạng thái Git:** Sạch (`working tree clean`), không sửa đổi bất kỳ nhánh bảo vệ nào (`main`, `thesis-v2/opengrep-qwen`, `v2/integration-pilot`, `v2/advisor-m1-proof-20261111`, `v2/advisor-evaluation-javis-20261111`).

### C. Môi trường

- **Máy chủ:** `ADMIN-PC`
- **Hệ điều hành:** Windows 11 Pro (10.0.26200) + WSL2 Ubuntu
- **Python:** `Python 3.12.10` (Windows Host) & `Python 3.10.22` (WSL2 Ubuntu)
- **OpenGrep:** `1.25.0` (`C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.exe` -> WSL2 `/home/tuankhoa/.opengrep/cli/latest/opengrep`)
- **Ollama:** Endpoint cục bộ `http://127.0.0.1:11434` (`OLLAMA_NOPRUNE=true`)
- **Mô hình Qwen:** `qwen3.5:9b-q4_K_M` (`digest: 56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90`, `9.0B`, `Q4_K_M`, `temperature = 0`, `num_ctx = 8192`, `think = false`)
- **GPU / VRAM:** `NVIDIA GeForce RTX 4060 Ti` (`16,380 MiB` VRAM)
- **Phiên bản bộ quy tắc:** `v2/evaluation/post_report/rules/p_java_cwe22_cwe89.yml` (`14` quy tắc Java CWE-22/CWE-89 trích từ `p-java.raw.yaml`, `SHA-256: 5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1`).

### D. Dataset

- **Nguồn dữ liệu:**
  1. **OWASP BenchmarkJava v1.2:** Commit `8b67a88d73b2594570fc21150705283de884620b`, tệp nhãn gốc `expectedresults-1.2.csv` (`SHA-256: 353762c72ef5bcd7fd2dc9ad3bc8dc1fa2fae1ade4cd4aa1dedf7ea42de2a040`).
  2. **Dự án thực tế & mẫu đối chiếu:**
     - `OWASP WebGoat` (commit `5357a65e054976cd7d79b81ef3906ded050ed921`, giấy phép GPL-2.0)
     - `java-sec-code` (commit `4711f4e186258c6e0dd5c3863e7c9592e7e9026a`, giấy phép Apache-2.0)
     - `examples/demo/src/main/java/demo/UserDao.java` (gói `opengrep-triage.zip`, `SHA-256: 5f39d2fb...`).
- **Quy mô và cách chia:**
  - **`dev_set_16` (`n = 16`):** `8` CWE-22 (`4 TP, 4 FP`) + `8` CWE-89 (`4 TP, 4 FP`), `INDEPENDENT_GROUND_TRUTH`, `0` mẫu chưa xác minh.
  - **`heldout_set_40` (`n = 40`):** `20` CWE-22 (`10 TP, 10 FP`) + `20` CWE-89 (`10 TP, 10 FP`), `INDEPENDENT_GROUND_TRUTH`, `0` mẫu chưa xác minh, khóa `STRICT_LOCK` (`combined_lock_sha256 = 4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09`), `0` trùng lặp tệp/test case với `dev_set_16`.
  - **`real_projects_20` (`n = 20`):** `2` CWE-22 (`1 TP, 1 FP`) + `18` CWE-89 (`15 TP, 3 FP`), kiểm tra thủ công từng dòng sink (`MANUAL_CODE_REVIEW_VERIFIED`).

### E. Thực nghiệm

#### Bảng đối chứng 4 nhánh trên tập Held-Out đóng băng `heldout_set_40` (`n = 40`: `20 TP, 20 FP`)

| Chỉ số bắt buộc (`tử_số/mẫu_số`) | Arm A: OpenGrep-only | Arm B: OpenGrep + Heuristic (`--mode heuristic`) | Arm C: OpenGrep + Evidence + Qwen (`--mode evidence+llm`) | Arm D: OpenGrep + Qwen Ablation (`--mode llm`) |
|---|---|---|---|---|
| **Tổng số cảnh báo (`CWE-22` + `CWE-89`)** | `40` (`20 + 20`) | `40` (`20 + 20`) | `40` (`20 + 20`) | `40` (`20 + 20`) |
| **Tổng TP có nhãn / FP có nhãn** | `20 TP / 20 FP` | `20 TP / 20 FP` | `20 TP / 20 FP` | `20 TP / 20 FP` |
| **FP được đề xuất loại đúng (`REFUTED` trên FP)** | `0/20 (0.0%)` | `7/20 (35.0%)` | **`20/20 (100.0%)`** | `0/20 (0.0%)` |
| **TP bị đề xuất loại nhầm (`REFUTED` trên TP)** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** |
| **TP giữ ở Nhóm 1 (`SUPPORTED` trên TP)** | `20/20 (100.0%)` | `9/20 (45.0%)` | **`20/20 (100.0%)`** | `17/20 (85.0%)` |
| **FP bị xếp nhầm vào Nhóm 1 (`SUPPORTED` trên FP)** | `20/20 (100.0%)` | `0/20 (0.0%)` | **`0/20 (0.0%)`** | `14/20 (70.0%)` |
| **Số trường hợp `UNDETERMINED` (Nhóm 3)** | `0/40 (0.0%)` | `24/40 (60.0%)` | **`0/40 (0.0%)`** | `9/40 (22.5%)` |
| **Coverage (`SUPPORTED + REFUTED` / `40`)** | `40/40 (100.0%)` | `16/40 (40.0%)` | **`40/40 (100.0%)`** | `31/40 (77.5%)` |
| **Accuracy trên nhóm đã quyết định** | `20/40 (50.0%)` | `16/16 (100.0%)` | **`40/40 (100.0%)`** | `17/31 (54.8%)` |
| **Số citation hợp lệ / không hợp lệ** | `N/A` | `16/40 (40.0%)` / `24/40` | **`40/40 (100.0%)` / `0/40`** | `31/40 (77.5%)` / `9/40` |
| **Tỷ lệ JSON hợp lệ (`valid_json_rate`)** | `N/A` | `N/A` | **`40/40 (100.0%)`** | **`40/40 (100.0%)`** |
| **Precision / Recall theo chính sách `baseline`** | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` |
| **Precision / Recall theo chính sách `drop_fp`** | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/33 (60.6%)` / `20/20 (100.0%)` | **`20/20 (100.0%)` / `20/20 (100.0%)`** | `20/40 (50.0%)` / `20/20 (100.0%)` |
| **Precision / Recall theo chính sách `keep_tp_only`** | `20/40 (50.0%)` / `20/20 (100.0%)` | `9/9 (100.0%)` / `9/20 (45.0%)` | **`20/20 (100.0%)` / `20/20 (100.0%)`** | `17/31 (54.8%)` / `17/20 (85.0%)` |
| **Thời gian trung bình / Tổng thời gian suy luận** | `0 ms` / `0 s` | `<15 ms` / `<0.6 s` | `10,525.0 ms` / `421.0 s` | `7,526.7 ms` / `301.1 s` |
| **Tổng số lỗi thực nghiệm / lỗi runtime** | `0` | `0` | `0` | `0` |

### F. Phân tích trường hợp (`v2/evaluation/post_report/CASE_STUDIES_CWE22_CWE89.md`)

Đã hoàn thành **6 Case Studies thực chứng** có đầy đủ mã nguồn gốc, dòng cảnh báo, trace, kết luận Qwen, căn cứ nhãn và hướng sửa:
1. **Case Study 1 (`CWE-22` TP — `BenchmarkTest00001.java:60`):** Lỗ hổng Path Traversal qua cookie chảy trực tiếp vào `new FileInputStream(fileName)` — Qwen3.5-9B (`Arm C`) nhận diện đúng `SUPPORTED` kèm trích dẫn dòng 44, 57, 60.
2. **Case Study 2 (`CWE-22` FP — `BenchmarkTest00002.java:69`):** Cảnh báo giả do nhánh điều kiện hằng số `(7 * 42) - num > 200` trong `Test.doSomething` luôn gán `bar = "This_should_always_happen"` — `Arm D` phán nhầm là `SUPPORTED`, còn `Arm C` nhận diện đúng `REFUTED`.
3. **Case Study 3 (`CWE-89` TP dùng sai `PreparedStatement` — `BenchmarkTest00008.java:61` & `SQLI.java:149`):** Nối chuỗi động `sql` trước khi gọi `connection.prepareStatement(sql)` không dùng dấu `?` — `Arm C` nhận diện đúng lỗ hổng thật `SUPPORTED`.
4. **Case Study 4 (`CWE-89` FP qua cấu trúc `HashMap` — `BenchmarkTest00033.java:68`):** Dữ liệu bẩn lưu ở `"keyB-31693"` nhưng câu lệnh SQL lấy `"keyA-31693"` chứa chuỗi hằng — `Arm D` phán nhầm là `SUPPORTED`, còn `Arm C` nhận diện đúng `REFUTED`.
5. **Case Study 5 (`CWE-22` TP trên dự án thực tế — `WebGoat/ProfileUploadRetrieval.java:91`):** Kiểm tra `request.getQueryString().contains("..")` bị vượt qua bởi URL encoding `%2e%2e%2f` trước khi truyền vào `new File(catPicturesDirectory, ...)` — `Arm C` phân tích đúng `SUPPORTED`.
6. **Case Study 6 (`CWE-22` FP bị giữ nhầm do Post-Sink Guard — `demo/UserDao.java:63`):** Phép kiểm tra `!f.getCanonicalPath().startsWith(BASE_DIR)` nằm ở dòng 64 (sau dòng sink `new File` ở dòng 63) — phân tích trung thực nguyên nhân `Arm C` giữ ở `SUPPORTED` và đề xuất mở rộng cửa sổ post-constructor guard.

### G. Kiểm thử

| Lệnh kiểm thử thực tế | Kết quả PASS/FAIL/SKIP | Exit Code | Đường dẫn Log / Bằng chứng |
|---|---|---|---|
| `python scripts/verify-repository.py` | `Repository verification passed` | `0` | `evidence/post_report_cwe22_cwe89_20261112/logs/final_verify_repository.log` |
| `python v2/baseline/verify_patch.py` | `Patch verification passed` | `0` | `evidence/post_report_cwe22_cwe89_20261112/logs/final_verify_patch.log` |
| `python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q` | `200 passed, 26 subtests passed` (`0 failed`, `0 skipped`) | `0` | `evidence/post_report_cwe22_cwe89_20261112/logs/final_pytest_suite.log` |
| `python -m pytest v2/triage/tests/test_human_review_negative_suite.py -v` | `16 passed` (`0 failed`, `0 skipped`) | `0` | `evidence/post_report_cwe22_cwe89_20261112/logs/final_negative_suite.log` |
| `python -m pytest v2/triage/tests/test_stage2_stage3_cwe22_cwe89.py -v` | `5 passed` (`0 failed`, `0 skipped`) | `0` | `evidence/post_report_cwe22_cwe89_20261112/logs/final_stage2_stage3_tests.log` |
| `python v2/scripts/run_v2_quality_gate.py` | `PASS (11/11 checks passed)` | `0` | `evidence/post_report_cwe22_cwe89_20261112/logs/stage0_quality_gate.json` |
| `python v2/evaluation/validate_pilot_lock.py --mode STRICT_LOCK --opengrep v2/evaluation/post_report/heldout_alerts.json --labels v2/evaluation/post_report/labels_heldout.json` | `PASS (STRICT_LOCK valid)` | `0` | `v2/evaluation/post_report/heldout_strict_lock_manifest.json` |

### H. Những phần chưa hoàn thành & Phân loại Trạng thái

| Hạng mục | Phân loại trạng thái | Ghi chú chi tiết |
|---|---|---|
| Giai đoạn 0: Kiểm toán Baseline & Khắc phục CRLF | `PASS` | Hoàn thành 100% (`POST_REPORT_BASELINE_AUDIT.md`). |
| Giai đoạn 1: Tập dữ liệu `CWE-22`/`CWE-89` (`16` dev + `40` held-out) | `PASS` | Hoàn thành 100%, đạt chuẩn `STRICT_LOCK` (`0` overlap). |
| Giai đoạn 2: Trích xuất ngữ cảnh Java, `CliCall` & Kiểm toán Citation | `PASS` | Hoàn thành 100% (`java_context.py`, `evidence.py`, `EVIDENCE_QUALITY_AUDIT.md`). |
| Giai đoạn 3: Tinh chỉnh Heuristic & Prompt `v2.1` trên `dev_set_16` | `PASS` | Hoàn thành 100% (`8/8 TP`, `8/8 FP`, `16/16 citation`). |
| Giai đoạn 4: Thực nghiệm đối chứng 4 nhánh trên `heldout_set_40` (`n = 40`) | `PASS` | Hoàn thành 100% (`20/20 TP`, `20/20 FP`, `0/20 loại nhầm TP`, `40/40 citation`). |
| Giai đoạn 5: Dự án Java thực tế (`n = 20`) & 6 Case Studies | `PASS` | Hoàn thành 100% (`WebGoat`, `java-sec-code`, `UserDao`, `6` case studies). |
| Giai đoạn 6: Kiểm thử quy trình xác nhận của con người (`16` tests) | `PASS` | Hoàn thành 100% (`16/16 PASS` + CLI lifecycle transcript). |
| Giai đoạn 7: Bản nháp 5 Chương Khóa luận (`CHUONG_1..5.md`) | `PASS` | Hoàn thành bản nháp đầy đủ số liệu thật tại `v2/docs/thesis/`. |
| Gói mã `Bo_ma_OpenGrep_Java_Qwen.zip` | `PENDING_ADVISOR_DECISION` | Ghi nhận `NOT_PROVIDED` trên máy chủ; đã sử dụng `opengrep-triage.zip` (`5f39d2fb...`) theo đúng hướng dẫn Mục II.3. |
| Mở rộng sang `CWE-78`, `CWE-79`, CWSS, Fine-tuning, IRIS, CodeQL | `NOT_APPLICABLE` | Nằm ngoài phạm vi giai đoạn này theo ranh giới tuyệt đối tại Mục II.2 & Mục III. |

### I. Tiếp tục công việc (Resume & Handover Instructions)

1. **Tiến trình chạy ngầm hiện tại:** `NONE` (`0` tiến trình nền đang chạy; toàn bộ 5 checkpoints trong `evidence/post_report_cwe22_cwe89_20261112/checkpoints/*.ckpt.jsonl` đã hoàn tất 100% số mẫu).
2. **Checkpoint cuối cùng đã lưu:**
   - `stage3_dev16_armC_v2_1_evidence_llm.ckpt.jsonl` (`16/16` hoàn tất)
   - `stage4_heldout40_armC_evidence_llm.ckpt.jsonl` (`40/40` hoàn tất)
   - `stage4_heldout40_armD_llm_ablation.ckpt.jsonl` (`40/40` hoàn tất)
   - `stage5_real_projects_armC_evidence_llm.ckpt.jsonl` (`20/20` hoàn tất)
3. **Lệnh tái lập / resume an toàn (không gọi lại LLM nhờ cache & checkpoint):**
   ```powershell
   Set-Location "C:\Users\Admin\ntk-thesis-v2\post-report-cwe22-cwe89"
   python scripts/verify-repository.py
   python v2/baseline/verify_patch.py
   python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q
   python v2/scripts/run_v2_quality_gate.py
   python "C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112\logs\score_stage4_heldout40.py"
   ```
4. **Lưu ý bảo toàn dữ liệu:**
   - Tuyệt đối không xóa thư mục `C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112\cache` và `checkpoints` để bảo toàn toàn bộ biên nhận suy luận gốc của `qwen3.5:9b-q4_K_M`.
   - Không chạy tinh chỉnh prompt thêm trên tập `heldout_set_40` để giữ nguyên tính độc lập khoa học của kết quả đối chứng.
