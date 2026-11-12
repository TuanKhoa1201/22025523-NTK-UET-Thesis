# Chương 4: Thực Nghiệm và Đánh Giá

## 4.1. Môi Trường Thực Nghiệm và Thiết Lập Bộ Dữ Liệu

### 4.1.1. Môi trường phần cứng và phần mềm
- **Hệ điều hành & Runtime:** Windows 11 Pro kết hợp WSL2 (Ubuntu), Python `3.12.10`.
- **Công cụ phân tích tĩnh (SAST Engine):** OpenGrep `v1.25.0` chạy với cờ `--dataflow-traces --taint-intrafile` trên tập quy tắc ghim cố định `v2/evaluation/post_report/rules/p_java_cwe22_cwe89.yml` (`14` quy tắc Java CWE-22/CWE-89 trích xuất từ `p-java.raw.yaml`, SHA-256 gốc: `5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1`).
- **Mô hình suy luận cục bộ (Local LLM):** `qwen3.5:9b-q4_K_M` (`model_id` xác thực qua Ollama HTTP API tại `http://127.0.0.1:11434/api/chat`), cấu hình tất định `temperature = 0`, `num_ctx = 8192`, `thinking = false`, ép buộc đầu ra theo JSON Schema `SCHEMA` (`SUPPORTED`, `REFUTED`, `UNDETERMINED`).

### 4.1.2. Cấu trúc bộ dữ liệu thực nghiệm (`N_total = 76` cảnh báo: `56` Benchmark + `20` Dự án thực tế)

| Tập dữ liệu | Quy mô (`n`) | Phân bố CWE & Nhãn chuẩn | Mã băm quét (`scan_sha256`) | Mục đích sử dụng |
|---|---|---|---|---|
| **1. `dev_set_16`** (Development Split) | `n = 16` | `8` CWE-22 (`4 TP, 4 FP`) + `8` CWE-89 (`4 TP, 4 FP`) | `c1be1d5e1be23a7ddba48fa7e0d61049234fd6003be057cf15893977c04d08c2` | Phân tích nguyên nhân lỗi của baseline `v1.0`, tinh chỉnh trích xuất ngữ cảnh, tín hiệu tĩnh và prompt `v2.0 -> v2.1`. |
| **2. `heldout_set_40`** (Frozen Held-Out Split — `STRICT_LOCK`) | `n = 40` | `20` CWE-22 (`10 TP, 10 FP`) + `20` CWE-89 (`10 TP, 10 FP`) | `67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b` | Đánh giá bắt cặp độc lập 4 nhánh (Arm A, Arm B, Arm C, Arm D) sau khi đã đóng băng hoàn toàn mã nguồn và prompt. |
| **3. `real_projects_20`** (`WebGoat`, `java-sec-code`, `UserDao`) | `n = 20` | `2` CWE-22 (`1 TP, 1 FP`) + `18` CWE-89 (`15 TP, 3 FP`) | `99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041` | Kiểm tra khả năng tổng quát hóa và phân tích giới hạn trên mã nguồn dự án mở thực tế. |

Tập `heldout_set_40` đã vượt qua kiểm định khóa nghiêm ngặt `validate_pilot_lock.py --mode STRICT_LOCK` (`exit_code = 0`, `valid_lock_candidate = true`, `m4_acceptance_ready = true`, `combined_lock_sha256 = 4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09`) trước khi bất kỳ lượt suy luận Stage 4 nào được thực thi.

---

## 4.2. Thực Nghiệm Phát Triển và Tiến Hóa Prompt Trên Tập `dev_set_16` (`n = 16`)

Trên tập phát triển `dev_set_16` (`8 TP, 8 FP`), 5 lượt thực nghiệm có kiểm soát đã được tiến hành để đo lường tác động của từng cải tiến kỹ thuật:

| Lượt thực nghiệm trên `dev_set_16` (`n = 16`) | TP giữ đúng (`SUPPORTED` / `8 TP`) | FP phát hiện đúng (`REFUTED` / `8 FP`) | TP bị đề xuất loại nhầm (`REFUTED` / `8 TP`) | FP bị phán nhầm là TP (`SUPPORTED` / `8 FP`) | Nhóm 3 (`UNDETERMINED` / `16`) | Citation khớp (`MATCHED` / `16`) |
|---|---|---|---|---|---|---|
| **Exp 1: `v1.0_baseline`** (Trước nâng cấp Stage 2–3) | `4/8 (50.0%)` | `0/8 (0.0%)` | `0/8 (0.0%)` | `2/8 (25.0%)` | `10/16 (62.5%)` | `6/16 (37.5%)` |
| **Exp 2: `v2.1_armB_heuristic`** (`--mode heuristic`) | `4/8 (50.0%)` | `3/8 (37.5%)` | `0/8 (0.0%)` | `0/8 (0.0%)` | `9/16 (56.2%)` | `7/16 (43.8%)` |
| **Exp 3: `v2.0_armD_llm_ablation`** (`--mode llm`) | `7/8 (87.5%)` | `0/8 (0.0%)` | `0/8 (0.0%)` | `8/8 (100.0%)` | `1/16 (6.2%)` | `15/16 (93.8%)` |
| **Exp 4: `v2.0_armC_evidence_llm`** (Prompt `v2.0`) | `7/8 (87.5%)` | `8/8 (100.0%)` | `0/8 (0.0%)` | `0/8 (0.0%)` | `1/16 (6.2%)` | `15/16 (93.8%)` |
| **Exp 5: `v2.1_armC_evidence_llm_frozen`** (Prompt `v2.1` đóng băng) | **`8/8 (100.0%)`** | **`8/8 (100.0%)`** | **`0/8 (0.0%)`** | **`0/8 (0.0%)`** | **`0/16 (0.0%)`** | **`16/16 (100.0%)`** |

**Phân tích tiến hóa kỹ thuật từ Exp 1 đến Exp 5:**
1. Ở **Exp 1 (`v1.0_baseline`)**, hệ thống chỉ đạt `4/8` TP và `0/8` FP do 4 nguyên nhân gốc rễ: (i) `evidence.py` từ chối nút `CliCall` trên `6/8` ca CWE-22; (ii) lặp lại các đoạn trích trung gian làm tràn cửa sổ `num_ctx = 4096` (`done_reason = length` trên `BenchmarkTest00018.java`); (iii) trường `"matched"` thiếu dấu `;` làm trượt `verify_citations`; và (iv) thiếu thân hàm `Test.doSomething` cùng tín hiệu nhánh hằng số.
2. Sau khi giải phẳng `CliCall`, nâng `num_ctx = 8192`, mở rộng ngữ cảnh Java (`java_context.py`) và bổ sung `heuristic_signals` ở **Exp 4 (`v2.0`)**, tỷ lệ phát hiện FP tăng vọt từ `0/8 (0.0%)` lên `8/8 (100.0%)`, chỉ còn 1 ca TP (`BenchmarkTest00216.java`) bị hạ xuống `UNDETERMINED` do trích dẫn dòng cuối của câu lệnh 2 dòng (dòng 68–69) thiếu dấu `;`.
3. Ở **Exp 5 (`v2.1` đóng băng)**, việc loại bỏ trường `"matched"` khỏi prompt snippet và chuẩn hóa tối đa 3 ứng viên trích dẫn đơn dòng theo thứ tự tăng dần (`candidate_citations`) đã giúp hệ thống đạt `8/8 (100.0%)` TP, `8/8 (100.0%)` FP, `0/8 (0.0%)` loại nhầm TP và `16/16 (100.0%)` trích dẫn khớp mã nguồn.

---

## 4.3. Kết Quả Đánh Giá Bắt Cặp Độc Lập Trên Tập Held-Out Đóng Băng `heldout_set_40` (`n = 40`)

Sau khi đóng băng hoàn toàn mã nguồn và prompt `v2.1-cwe22-cwe89-grounded` ở cuối Stage 3, hệ thống được chạy đánh giá một lần trên tập `heldout_set_40` (`20 TP`, `20 FP`) qua 4 nhánh đối chứng:

### 4.3.1. Bảng so sánh tổng thể 4 nhánh (4-Arm Paired Comparison)

| Chỉ số đánh giá (`tử_số/mẫu_số`) | Arm A: OpenGrep Standalone | Arm B: Heuristic (`--mode heuristic`) | Arm C: Full Pipeline (`--mode evidence+llm`) | Arm D: LLM Ablation (`--mode llm`) |
|---|---|---|---|---|
| **TP giữ ở Nhóm 1 (`SUPPORTED` / `KEEP_TP`)** | `20/20 (100.0%)` | `9/20 (45.0%)` | **`20/20 (100.0%)`** | `17/20 (85.0%)` |
| **TP giữ tổng cộng (`KEEP_TP + REVIEW`)** | `20/20 (100.0%)` | `20/20 (100.0%)` | **`20/20 (100.0%)`** | `20/20 (100.0%)` |
| **FP đề xuất loại đúng ở Nhóm 2 (`REFUTED`)** | `0/20 (0.0%)` | `7/20 (35.0%)` | **`20/20 (100.0%)`** | `0/20 (0.0%)` |
| **TP bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp`)** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** |
| **FP bị xếp nhầm vào Nhóm 1 (`SUPPORTED` trên FP)** | `20/20 (100.0%)` | `0/20 (0.0%)` | **`0/20 (0.0%)`** | `14/20 (70.0%)` |
| **Tỷ lệ Nhóm 3 (`UNDETERMINED` / `REVIEW`)** | `0/40 (0.0%)` | `24/40 (60.0%)` | **`0/40 (0.0%)`** | `9/40 (22.5%)` |
| **Tỷ lệ Citation khớp mã nguồn (`MATCHED`)** | `N/A` | `16/40 (40.0%)` | **`40/40 (100.0%)`** | `31/40 (77.5%)` |
| **Precision theo chính sách `drop_fp`** | `20/40 (50.0%)` | `20/33 (60.6%)` | **`20/20 (100.0%)`** | `20/40 (50.0%)` |
| **TP Recall theo chính sách `drop_fp`** | `20/20 (100.0%)` | `20/20 (100.0%)` | **`20/20 (100.0%)`** | `20/20 (100.0%)` |
| **Precision theo chính sách `keep_tp_only`** | `20/40 (50.0%)` | `9/9 (100.0%)` | **`20/20 (100.0%)`** | `17/31 (54.8%)` |
| **Độ trễ trung bình / trung vị / P95 (`ms`)** | `0 / 0 / 0` | `<15 / <15 / <15` | `10,525 / 10,961 / 12,687` | `7,527 / 6,359 / 12,109` |

### 4.3.2. Phân tích kết quả theo từng CWE (`CWE-22` vs `CWE-89`)
- **Trên `CWE-22` (`n = 20`: `10 TP, 10 FP`):**
  - Arm B (`--mode heuristic`) giữ đúng `4/10 (40.0%)` TP và lọc đúng `5/10 (50.0%)` FP nội phương thức, nâng Precision `drop_fp` từ `10/20 (50.0%)` lên `10/15 (66.7%)`, nhưng phải chuyển `11/20 (55.0%)` cảnh báo sang `UNDETERMINED`.
  - Arm D (`--mode llm` ablation) giữ `7/10 (70.0%)` TP nhưng lọc được `0/10 (0.0%)` FP (`4/10` FP bị phán là `SUPPORTED`, `6/10` FP rơi vào `UNDETERMINED`).
  - Arm C (`--mode evidence+llm`) đạt `10/10 (100.0%)` TP `SUPPORTED`, `10/10 (100.0%)` FP `REFUTED`, `0/10 (0.0%)` loại nhầm TP, `20/20 (100.0%)` trích dẫn khớp mã nguồn.
- **Trên `CWE-89` (`n = 20`: `10 TP, 10 FP`):**
  - Arm B (`--mode heuristic`) giữ đúng `5/10 (50.0%)` TP và lọc đúng `2/10 (20.0%)` FP, chuyển `13/20 (65.0%)` cảnh báo qua lớp phụ trợ `Test.doSomething` sang `UNDETERMINED`.
  - Arm D (`--mode llm` ablation) giữ `10/10 (100.0%)` TP nhưng phán nhầm cả `10/10 (100.0%)` FP thành `SUPPORTED` do không nhìn thấy thân hàm `Test.doSomething`.
  - Arm C (`--mode evidence+llm`) đạt `10/10 (100.0%)` TP `SUPPORTED`, `10/10 (100.0%)` FP `REFUTED`, `0/10 (0.0%)` loại nhầm TP, `20/20 (100.0%)` trích dẫn khớp mã nguồn.

**Trả lời RQ1 & RQ2:** Sự chênh lệch giữa Arm D (`0/20` FP phát hiện được), Arm B (`7/20` FP phát hiện được) và Arm C (`20/20` FP phát hiện được) chứng minh rằng **cả hai thành phần** — (1) tầng trích xuất ngữ cảnh phương thức/callee mở rộng + tín hiệu tĩnh và (2) tầng suy luận ngữ nghĩa của mô hình cục bộ `Qwen3.5-9B` — đều không thể thay thế lẫn nhau. Khi thiếu ngữ cảnh mở rộng và tín hiệu tĩnh (Arm D), LLM bị mù trước các phép biến đổi trong hàm phụ trợ; ngược lại, khi chỉ dùng quy tắc tĩnh đơn thuần (Arm B), `60.0%` (`24/40`) cảnh báo phải đẩy về hàng đợi `UNDETERMINED`.

---

## 4.4. Đánh Giá Trên Mã Nguồn Dự Án Mở Thực Tế (`n = 20`) và Kiểm Chứng Hàng Đợi Duyệt Thủ Công

### 4.4.1. Kết quả trên 20 cảnh báo dự án thực tế (`OWASP WebGoat`, `java-sec-code`, `UserDao`)
Trên `20` cảnh báo sinh ra từ `8` tệp mã nguồn thực tế (`16 TP, 4 FP`):
- **Tỷ lệ giữ lại lỗ hổng thật (`SUPPORTED` trên TP):** `16/16 (100.0%)`, bao gồm cả các ca sử dụng sai `PreparedStatement` không có dấu `?` (`java-sec-code/SQLI.java:149,153`, `WebGoat/Assignment5.java:60,65`), nối chuỗi vào mệnh đề `ORDER BY` (`WebGoat/Servers.java:73`), và lỗ hổng Path Traversal qua mặt kiểm tra `getQueryString()` bằng URL encoding (`WebGoat/ProfileUploadRetrieval.java:91`).
- **Tỷ lệ TP bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp`):** **`0/16 (0.0%)`**.
- **Tỷ lệ trích dẫn khớp mã nguồn (`citation_check == MATCHED`):** **`20/20 (100.0%)`** (độ trễ trung bình `9.10s / cảnh báo`).
- **Phân tích trung thực 4 ca FP ngoài Benchmark:** Cả 4 cảnh báo (`UserDao.java:63` kiểm tra `getCanonicalPath().startsWith(...)` ở dòng 64 sau dòng sink 63; `WebGoat/UserService.java:52` kiểm tra `@Pattern` ở tệp khác `WebGoatUser.java`; và `WebGoat/SqlInjectionLesson8.java:154,158` dùng `action.replace('\'', '"')`) đều được hệ thống đóng băng giữ bảo toàn ở Nhóm 1 (`SUPPORTED`). Điều này phản ánh đúng giới hạn phạm vi nội tệp và cửa sổ tiền-sink của hệ thống hiện tại: khi bằng chứng làm sạch nằm ở tệp khác hoặc sau dòng sink, hệ thống ưu tiên không bỏ lọt lỗ hổng.

### 4.4.2. Kiểm chứng cơ chế xác nhận của con người (Human Review Verification — RQ3)
Bộ kiểm thử tự động `v2/triage/tests/test_human_review_negative_suite.py` (`16/16` ca kiểm thử đạt `PASS`) và kịch bản vòng đời CLI thực tế (`stage6_human_review_demo/cli_lifecycle_transcript.json`) đã xác nhận:
1. Mọi cảnh báo sau khi chạy `triage run` đều có trạng thái `review_status = OPEN` (`0` cảnh báo tự động chuyển sang `CONFIRMED_FALSE`).
2. Mọi lệnh `decide` thiếu `--reviewer`, thiếu `--reason`, truyền `--cite` sai định dạng, sai đường dẫn tệp, hoặc trích dẫn số dòng nằm ngoài phạm vi bằng chứng đã xác thực SHA-256 đều bị từ chối với `EvidenceError` (`exit_code = 2`) và giữ nguyên trạng thái `OPEN`.
3. Khi cung cấp đầy đủ thông tin hợp lệ, quyết định được ghi bất biến vào cả bảng `review_events` trong SQLite và tệp `decisions.jsonl`.
