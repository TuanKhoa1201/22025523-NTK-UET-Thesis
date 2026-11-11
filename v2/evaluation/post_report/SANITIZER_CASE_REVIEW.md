# ĐÁNH GIÁ KỸ THUẬT CÁC MẪU SANITIZER, NGUỒN HẰNG VÀ NHÁNH BẤT BIẾN TRONG JAVA (`CWE-22` & `CWE-89`)

- **Giai đoạn:** Stage 2 — Nâng cấp trích xuất ngữ cảnh Java, làm giàu bằng chứng và kiểm tra trích dẫn
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Mô-đun cài đặt:** `v2/triage/java_context.py`, `v2/triage/heuristics.py`, `v2/triage/evidence.py`, `v2/triage/ollama.py`

---

## 1. Mục tiêu

Phân biệt chính xác giữa:
1. **Sanitizer hợp lệ đúng ngữ cảnh lỗ hổng** (làm mất khả năng khai thác `CWE-22` hoặc `CWE-89`),
2. **Biến đổi/mã hóa sai ngữ cảnh (Wrong-Context Encoding / Non-Sanitizer)** dễ gây nhầm lẫn cho cả SAST lẫn LLM 9B,
3. **Nguồn hằng an toàn (Safe Constant Source)** và **Nhánh điều kiện/tập hợp hằng bất biến (Constant Overwrite / Constant Branch / Safe Collection Element)** khiến dữ liệu đầu vào không bao giờ chạm tới sink.

---

## 2. Phân loại chi tiết đối với `CWE-22` (Path Traversal)

| STT | Mẫu kỹ thuật trong mã nguồn Java | Bản chất bảo mật đối với `CWE-22` | Phân loại trong `v2/triage/heuristics.py` | Quy tắc kết luận |
|---:|---|---|---|---|
| 1 | `FilenameUtils.getName(path)` / `Paths.get(p).getFileName()` / `new File(p).getName()` | Cắt bỏ hoàn toàn các thành phần thư mục và chuỗi `../` / `..\`, chỉ giữ lại tên tệp cuối cùng. | `CWE22_SANITIZER_PATTERNS` (`sanitizers_found`) | Đề xuất `REFUTED` (`PROPOSED_FP`), chờ người duyệt xác nhận. |
| 2 | `file.getCanonicalPath()` hoặc `path.normalize()` **kết hợp** kiểm tra `.startsWith(allowedBaseDir)` | Giải quyết toàn bộ liên kết tượng trưng và `..`, đồng thời cưỡng chế đường dẫn đích nằm trong thư mục gốc cho phép. | `CWE22_SANITIZER_PATTERNS` (yêu cầu đồng thời có `.startsWith(` trong phương thức) | Đề xuất `REFUTED` (`PROPOSED_FP`). |
| 3 | Chỉ gọi `.normalize()` hoặc `.getCanonicalPath()` nhưng **không** kiểm tra `.startsWith(...)` | Đường dẫn được chuẩn hóa nhưng vẫn có thể trỏ ra ngoài thư mục cho phép. | Không được công nhận là sanitizer | Giữ `SUPPORTED` hoặc `UNDETERMINED`. |
| 4 | `java.net.URLDecoder.decode(param, "UTF-8")` | Giải mã `%2e%2e%2f` thành `../`, làm lộ chuỗi traversal chứ **không** ngăn chặn `CWE-22`. | `WRONG_CONTEXT_ENCODERS` (`non_sanitizers_found`) | Giữ `SUPPORTED` (nếu không có chốt chặn khác). |
| 5 | `ESAPI.encoder().encodeForHTML(...)` gọi tại `response.getWriter().println(...)` sau khi mở tệp | Chỉ mã hóa HTML ở đầu ra giao diện sau khi `FileInputStream` / `File` đã thực thi; không bảo vệ thao tác truy cập tệp. | `WRONG_CONTEXT_ENCODERS` (`non_sanitizers_found`) | Giữ `SUPPORTED`. |
| 6 | `SeparateClassRequest.getTheValue(...)` (`BenchmarkTest00863.java`) | Trong `SeparateClassRequest.java` (dòng 53–56), `getTheValue(String p)` luôn trả về hằng chuỗi `"bar"` thay vì đọc từ `HttpServletRequest`. OpenGrep báo động giả do gộp chung taint của đối tượng `scr`. | `SAFE_CONSTANT_SOURCE_GET_THE_VALUE` | Đề xuất `REFUTED` (`PROPOSED_FP`). |

---

## 3. Phân loại chi tiết đối với `CWE-89` (SQL Injection)

| STT | Mẫu kỹ thuật trong mã nguồn Java | Bản chất bảo mật đối với `CWE-89` | Phân loại trong `v2/triage/heuristics.py` | Quy tắc kết luận |
|---:|---|---|---|---|
| 1 | `connection.prepareStatement(sql)` với dấu hỏi `?` và `ps.setString(1, param)` (không nối chuỗi `+` vào `sql`) | Tham số hóa truy vấn; trình điều khiển JDBC tách biệt cấu trúc lệnh SQL và dữ liệu tham số. | `parameterized_prepared_statement` | Đề xuất `REFUTED` (`PROPOSED_FP`). |
| 2 | `connection.prepareStatement("SELECT ... " + bar)` hoặc `connection.prepareCall("{call " + bar + "}")` | Dù gọi `prepareStatement` / `prepareCall`, chuỗi SQL vẫn được ghép nối động bằng `+ bar` trước khi biên dịch câu lệnh. | Sink `CWE-89` thực thụ (không phải truy vấn tham số hóa) | Giữ `SUPPORTED` nếu `bar` nhiễm bẩn. |
| 3 | `ESAPI.encoder().encodeForSQL(codec, param)` | Mã hóa chuyên biệt cho ngữ cảnh câu lệnh SQL theo codec cơ sở dữ liệu. | `CWE89_SANITIZER_PATTERNS` (`ESAPI.encodeForSQL`) | Đề xuất `REFUTED` (`PROPOSED_FP`). |
| 4 | Ép kiểu số nguyên `Integer.parseInt(param)` / `Long.parseLong(param)` / `UUID.fromString(param)` trước khi ghép chuỗi | Giới hạn miền giá trị nghiêm ngặt về kiểu số/UUID, không thể chèn cú pháp SQL. | `CWE89_SANITIZER_PATTERNS` (`Integer.parseInt`) | Đề xuất `REFUTED` (`PROPOSED_FP`). |
| 5 | `ESAPI.encoder().encodeForHTML(results.toString())` hoặc `StringEscapeUtils.escapeHtml(...)` | Mã hóa HTML chống XSS (`CWE-79`) trên kết quả trả về; hoàn toàn không ngăn chặn SQL Injection tại `executeQuery` / `batchUpdate` / `prepareCall`. | `WRONG_CONTEXT_ENCODERS` (`non_sanitizers_found`) | Giữ `SUPPORTED`. |

---

## 4. Các mẫu dòng chảy dữ liệu nội phương thức và liên phương thức cùng tệp (`Test.doSomething`)

Trong bộ kiểm chuẩn OWASP BenchmarkJava v1.2 cũng như các lớp DAO/Servlet thực tế, nhiều cảnh báo của OpenGrep phụ thuộc vào ngữ cảnh bên ngoài cửa sổ `[sl - 3, el + 3]` mặc định:

1. **Ghi đè hằng số trực tiếp (`direct_const_overwrite`):**
   - Ví dụ: `SmokeVulnSample.java` (dòng 17–19): `String id = req.getParameter("id"); id = "42"; return stmt.executeQuery("SELECT ... " + id);`.
   - `v2/triage/heuristics.py` phát hiện phép gán lại biến bằng hằng chuỗi giữa `source_line` và `sink_line` và trích dẫn trực tiếp dòng ghi đè.
2. **Nhánh `switch (switchTarget)` với hằng ký tự (`switch_constant_char_branch`):**
   - Ví dụ: `BenchmarkTest00131.java`, `BenchmarkTest00191.java`, `BenchmarkTest01096.java`: `String guess = "ABC"; char switchTarget = guess.charAt(1);` luôn cho `switchTarget == 'B'`, đi vào `case 'B': bar = "bob";`.
   - Ngược lại, nếu nhánh được chọn gán `bar = param;`, dòng chảy nhiễm bẩn vẫn hoạt động (`TAINTED`).
3. **Biểu thức số học hằng trong toán tử ba ngôi hoặc `if/else` (`arithmetic_ternary_*` / `arithmetic_if_*`):**
   - Ví dụ `TP`: `BenchmarkTest00103.java`, `BenchmarkTest00998.java`: `int num = 106; bar = (7 * 42) - num > 200 ? "This should never happen" : param;` -> `294 - 106 = 188 <= 200` (False) -> `bar = param` (`SUPPORTED`).
   - Ví dụ `TP`: `BenchmarkTest00216.java`: `int num = 196; if ((500 / 42) + num > 200) bar = param;` -> `11 + 196 = 207 > 200` (True) -> `bar = param` (`SUPPORTED`).
   - Ví dụ `FP`: Khi biểu thức hằng `> 200` đúng và chọn nhánh hằng `"This_should_always_happen"`, biến `bar` nhận hằng số an toàn (`REFUTED`).
4. **Thao tác danh sách `List.add` / `List.remove(0)` / `List.get(1)` (`list_index_safe_constant`):**
   - Ví dụ `FP`: `BenchmarkTest00190.java`, `BenchmarkTest00620.java`, `BenchmarkTest01010.java`, `BenchmarkTest01031.java`: danh sách được thêm `["safe", param, "moresafe"]`, sau đó gọi `valuesList.remove(0)` làm dịch phần tử thành `[param, "moresafe"]`. Lệnh `bar = valuesList.get(1)` lấy phần tử `"moresafe"` (hằng an toàn), trong khi `valuesList.get(0)` lấy `param` (nhiễm bẩn).
5. **Truy xuất khóa `Map.put` / `Map.get` (`map_key_safe_constant` vs `map_key_tainted_value`):**
   - Phân biệt khóa chứa hằng chuỗi (`"keyA-..." -> "a_Value"`) với khóa chứa dữ liệu đầu vào (`"keyB-..." -> param`).
