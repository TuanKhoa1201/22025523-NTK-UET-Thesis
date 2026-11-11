# LABELING PROTOCOL — Quy Trình Gán Nhãn Độc Lập Cho CWE-22 & CWE-89 (Stage 1)

## 1. Nguyên Tắc Cốt Lõi (Chống Nhiễm Bẩn Dữ Liệu & Tự Gán Nhãn)

1. **Tuyệt đối không dùng đầu ra của LLM để tạo nhãn chuẩn (Ground Truth):** Mọi kết quả từ Qwen (`qwen3.5:9b-q4_K_M`), Codex hay heuristic đều bị chặn bởi danh sách cấm `FORBIDDEN_AUTO_LABEL_SOURCES` trong `v2/evaluation/score_pilot.py` và `v2/evaluation/validate_pilot_lock.py`.
2. **Khóa nhãn trước khi chạy mô hình trên tập Held-Out (`Pre-Inference Lock`):** Toàn bộ 40 cảnh báo của `heldout_set_40` được trích xuất, kiểm tra đối chiếu mã nguồn, gán nhãn và khóa mã băm (`heldout_strict_lock_manifest.json`, `combined_lock_sha256 = 4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09`) **trước khi** thực hiện bất kỳ lượt suy luận Qwen nào trên tập Held-Out.
3. **Tách biệt hoàn toàn giữa Development và Held-Out:** Không có bất kỳ tệp `.java` nào xuất hiện đồng thời trong `dev_set_16` (`16` tệp) và `heldout_set_40` (`40` tệp). Kiểm chứng giao tập: `set(dev_16).isdisjoint(set(heldout_40)) == True`.

## 2. Quy Trình Xác Minh Nhãn 2 Tầng (Two-Layer Ground-Truth Verification)

Mỗi cảnh báo trong `labels_development.csv` (`n = 16`) và `labels_heldout.csv` (`n = 40`) phải vượt qua đồng thời 2 tầng kiểm tra:

### Tầng 1: Đối chiếu nhãn chuẩn OWASP BenchmarkJava v1.2 (`expectedresults-1.2.csv`)
- Tệp `expectedresults-1.2.csv` (SHA-256: `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`) cung cấp nhãn chuẩn chính thức từ dự án OWASP cho từng servlet `BenchmarkTestXXXXX.java`:
  - `category = pathtraver` (`cwe = 22`) hoặc `category = sqli` (`cwe = 89`).
  - `real vulnerability = true` -> `TRUE_POSITIVE`; `real vulnerability = false` -> `FALSE_POSITIVE`.

### Tầng 2: Kiểm tra trực tiếp dòng Sink và đường truyền dữ liệu trong mã nguồn Java
Vì nhãn của OWASP Benchmark được gán ở mức tệp test case (`BenchmarkTestXXXXX`), chúng tôi thực hiện kiểm tra mã nguồn từng tệp để bảo đảm cảnh báo OpenGrep khớp đúng dòng sink của test case:
1. Chỉ chọn các tệp có **đúng 1 cảnh báo OpenGrep duy nhất** tại dòng sink thực thi (`new java.io.File(...)`, `new java.io.FileInputStream(...)`, `statement.executeQuery(...)`, `statement.executeUpdate(...)`, `connection.prepareStatement(...)`, `JDBCtemplate.batchUpdate(...)`).
2. Xác định dòng nguồn (`request.getParameter`, `request.getHeader`, `request.getCookies`, `SeparateClassRequest`), hàm nội bộ cùng tệp (`private static String doSomething(...)` nếu có), và cơ chế phân nhánh/bộ sưu tập/lọc dữ liệu trên biến trung gian `bar`:
   - **Cơ chế gây cảnh báo giả (`FALSE_POSITIVE`) trong OWASP Benchmark:**
     - `constant_switch_branch_safe`: `String guess = "ABC"; char switchTarget = guess.charAt(1);` luôn chọn nhánh `case 'B': bar = "bob";` (hằng chuỗi an toàn), nhưng phân tích tĩnh không nhạy nhánh (path-insensitive) trên `switch` vẫn báo lỗi.
     - `safe_collection_index_selection`: Danh sách `valuesList` thêm `"safe"`, `param`, `"moresafe"`, sau đó gọi `valuesList.remove(0)` và lấy `bar = valuesList.get(1)` (tức phần tử hằng `"moresafe"`), nhưng phân tích tĩnh đánh dấu bẩn cả danh sách (`collection-insensitive`).
     - `safe_hashmap_constant_key_lookup`: Dữ liệu bẩn `param` được đưa vào `keyB`, nhưng `bar = (String) map.get("keyA-...")` lấy giá trị hằng `"a_Value"` từ khóa an toàn `keyA`.
     - `constant_ternary_arithmetic_branch`: Biểu thức số học cố định `(7 * 18) + num > 200` (với `num = 106`) luôn đúng và gán chuỗi hằng `"This_should_always_happen"` cho `bar`.
     - `external_thing_interface_constant_return`: Ủy quyền qua `ThingInterface.doSomething(param)` trả về hằng an toàn (trường hợp thân hàm nằm ở tệp ngoài).
   - **Cơ chế lỗ hổng thật (`TRUE_POSITIVE`):**
     - Tham số HTTP đi trực tiếp hoặc qua hàm nội bộ `doSomething(...)` / nhánh `switch` / phần tử `List` / khóa `HashMap` chứa `param` tới thẳng sink `File` / `FileInputStream` (`CWE-22`) hoặc câu lệnh SQL nối chuỗi (`CWE-89`) mà không có chuẩn hóa đường dẫn hay tham số hóa truy vấn.

## 3. Cấu Trúc Trường Dữ Liệu Của Mỗi Nhãn

Mỗi dòng trong `labels_development.csv` và `labels_heldout.csv` gồm đầy đủ các trường bắt buộc:
- `alert_id`: Định danh chuẩn `SHA256(UTF8(scan_sha256 + ":" + finding_index))`.
- `finding_index`: Chỉ số cảnh báo (`0..N-1`) trong `opengrep.json`.
- `scan_sha256`: Mã băm SHA-256 của tệp `opengrep.json` đã khóa.
- `rule_id`: Mã quy tắc OpenGrep phát hiện cảnh báo.
- `cwe`: Mã CWE chuẩn hóa (`CWE-22` hoặc `CWE-89`).
- `file_path`: Đường dẫn tương đối tới tệp `.java` trong `source_root`.
- `start_line`, `end_line`: Dòng bắt đầu và kết thúc của sink cảnh báo.
- `expected_label`: `TRUE_POSITIVE` hoặc `FALSE_POSITIVE`.
- `label_source`: `OWASP_Benchmark_v1.2_expectedresults_csv_plus_manual_sink_line_verification`.
- `source_sha256`: Mã băm SHA-256 của tệp mã nguồn `.java` gốc.
- `rationale`: Giải thích chi tiết dòng nguồn, biến trung gian và dòng sink bằng chứng.
- `sanitizer_or_reason`: Tóm tắt cơ chế an toàn (với `FALSE_POSITIVE`) hoặc lý do thiếu kiểm soát (với `TRUE_POSITIVE`).
