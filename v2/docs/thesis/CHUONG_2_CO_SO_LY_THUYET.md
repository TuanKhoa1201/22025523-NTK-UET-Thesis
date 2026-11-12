# Chương 2: Cơ Sở Lý Thuyết

## 2.1. Phân Tích Tĩnh Mã Nguồn Mở Với OpenGrep và Cơ Chế Taint Tracking

### 2.1.1. Kiến trúc khớp mẫu và theo dõi luồng dữ liệu (`--taint-intrafile`)
OpenGrep (nhánh mã nguồn mở kế thừa từ Semgrep CE) biểu diễn mã nguồn Java dưới dạng Cây Cú pháp Trừu tượng Chung (Generic AST) và Đồ thị Luồng Điều khiển (Control-Flow Graph — CFG) ở phạm vi từng tệp hoặc từng phương thức. Trong chế độ theo dõi vết (`mode: taint` kết hợp cờ `--dataflow-traces` và `--taint-intrafile`), một quy tắc bảo mật định nghĩa ba thành phần:
- **Nguồn dữ liệu bẩn (`pattern-sources`):** Các điểm nhập dữ liệu từ bên ngoài, ví dụ `HttpServletRequest.getParameter(...)`, `getHeader(...)`, `getCookies()`, `getQueryString()`, hoặc các tham số `@RequestParam` trong Spring MVC.
- **Điểm nhạy cảm (`pattern-sinks`):** Các lệnh gọi API thực thi truy vấn cơ sở dữ liệu (`Statement.executeQuery`, `Connection.prepareStatement`, `JdbcTemplate.execute`) hoặc truy cập hệ thống tệp (`new File(...)`, `new FileInputStream(...)`, `new FileOutputStream(...)`, `Paths.get(...)`).
- **Hàm làm sạch (`pattern-sanitizers`):** Các biểu thức biến đổi hoặc kiểm tra được quy tắc công nhận là triệt tiêu dữ liệu bẩn.

### 2.1.2. Cấu trúc `dataflow_trace` và nút `CliCall` trong OpenGrep
Khi phát hiện một đường đi từ `source` tới `sink`, OpenGrep xuất đối tượng `extra.dataflow_trace` gồm:
- `taint_source`: Tọa độ byte/dòng/cột và nội dung biểu thức nguồn.
- `intermediate_vars`: Danh sách các biến trung gian trên đường truyền vết.
- `taint_sink`: Tọa độ và nội dung biểu thức đích, hoặc một cấu trúc đệ quy dạng **`CliCall`**:
  `["CliCall", [[location, content], intermediate_call_vars, inner_sink_or_clicall]]`.
Trong phân tích nội tệp (`--taint-intrafile`), khi dữ liệu đi qua lời gọi hàm hoặc constructor lồng nhau (đặc biệt phổ biến ở `CWE-22` với tỷ lệ `91.5%` cảnh báo trên OWASP Benchmark), OpenGrep đóng gói chuỗi truyền tham số vào nút `CliCall`. Nếu bộ trích xuất bằng chứng không giải phẳng (flatten) đệ quy và đối chiếu byte-offset cho các nút `CliCall` hợp lệ, thông tin vết truyền dữ liệu sẽ bị mất hoặc bị từ chối sai.

---

## 2.2. Đặc Trưng Kỹ Thuật Của Lỗ Hổng `CWE-22` và `CWE-89` Trong Java

### 2.2.1. `CWE-22`: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
Lỗ hổng `CWE-22` xảy ra khi ứng dụng ghép nối trực tiếp dữ liệu do người dùng kiểm soát vào đường dẫn tệp truyền tới `java.io.File`, `FileInputStream`, `FileOutputStream`, hoặc `java.nio.file.Paths` mà không chuẩn hóa và kiểm tra biên thư mục gốc. Kẻ tấn công sử dụng chuỗi `../` (hoặc biến thể mã hóa URL `%2e%2e%2f`) để thoát khỏi thư mục cho phép.
- **Mẫu lỗ hổng thật (True Positive):** Dữ liệu từ `request.getParameter`/`getHeaders`/`getCookies` (hoặc đi qua phép giải mã `URLDecoder.decode`, qua phần tử tập hợp vẫn giữ giá trị gốc, hoặc bị kiểm tra sai trên chuỗi chưa giải mã `request.getQueryString()`) đi tới constructor của `File`/`FileInputStream`.
- **Mẫu cảnh báo giả hoặc đã làm sạch (False Positive / Sanitized):**
  1. Đường dẫn được rút gọn về tên tệp đơn bằng `FilenameUtils.getName(...)` hoặc `Paths.get(...).getFileName()`.
  2. Đường dẫn chuẩn hóa được kiểm tra tiền tố thư mục gốc: `file.getCanonicalPath().startsWith(trustedBaseDir)` hoặc `path.normalize().startsWith(basePath)`.
  3. Biến truyền vào sink thực chất nhận giá trị từ nhánh hằng số (`switchTarget`, nhánh `else` của điều kiện số học luôn đúng/sai, hoặc phần tử hằng sau khi `valuesList.remove(0)` đã xóa phần tử bẩn).

### 2.2.2. `CWE-89`: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
Lỗ hổng `CWE-89` xảy ra khi dữ liệu đầu vào được ghép nối trực tiếp (`+`, `String.format`, `StringBuilder.append`) vào câu lệnh SQL thực thi qua `Statement`, `PreparedStatement` hoặc `JdbcTemplate`, cho phép kẻ tấn công thay đổi cấu trúc cú pháp truy vấn.
- **Điểm mù phổ biến về `PreparedStatement`:** Nhiều bộ lọc tĩnh hoặc mô hình ngôn ngữ mắc sai lầm khi thấy sự xuất hiện của `connection.prepareStatement(sql)` là kết luận ngay cảnh báo giả. Thực tế, nếu chuỗi `sql` được nối chuỗi động trước khi truyền vào `prepareStatement(sql)` (không dùng dấu giữ chỗ `?` và `setString`/`setInt`), lỗ hổng SQL Injection vẫn xảy ra hoàn toàn (như trong `BenchmarkTest00008.java` hoặc `SQLI.jdbc_ps_vuln` của `java-sec-code`).
- **Mẫu an toàn thực sự:** Truy vấn sử dụng dấu giữ chỗ `?` không nối chuỗi bẩn, ép kiểu số nguyên (`Integer.parseInt`, `Long.parseLong`), hoặc biến nối vào câu lệnh SQL xuất phát từ nhánh hằng số / khóa cố định trong `Map` / phương thức trả về hằng `SeparateClassRequest.getTheValue(...)`.

---

## 2.3. Suy Luận Cục Bộ Với Mô Hình Ngôn Ngữ Lớn và Yêu Cầu Kiểm Chứng Bằng Chứng (Grounded Triage)

Mô hình ngôn ngữ lớn cục bộ như `Qwen3.5-9B` (lượng tử hóa `Q4_K_M`, chạy qua Ollama) có khả năng đọc hiểu ngữ nghĩa mã nguồn Java vượt trội so với biểu thức chính quy, nhưng lại chịu hai giới hạn khi áp dụng vào kiểm toán bảo mật:
1. **Phụ thuộc chặt vào cửa sổ ngữ cảnh đầu vào:** Nếu chỉ cung cấp 1–2 dòng tại `source` và `sink` mà thiếu phần thân phương thức (`doPost`) hoặc phương thức phụ trợ trong cùng tệp (`Test.doSomething`), mô hình không nhìn thấy phép gán đè bằng hằng số hay thao tác `valuesList.remove(0)`, dẫn tới kết luận sai toàn bộ cảnh báo giả thành lỗ hổng thật.
2. **Không tự đảm bảo tính xác thực của trích dẫn:** Mô hình có thể sinh ra số dòng lệch 1–2 dòng hoặc cắt bớt ký tự cuối dòng (như dấu `;`) khi trích dẫn mã nguồn.

Do đó, một hệ thống hậu xử lý đạt chuẩn nghiên cứu và vận hành phải kết hợp **trích xuất bằng chứng tĩnh có cấu trúc (Structured Static Evidence)** với **cổng kiểm chứng trích dẫn tất định (Deterministic Citation Verification Gate)** và **cơ chế phân loại 3 nhóm an toàn (3-Way Fail-Closed Triage: `SUPPORTED`, `REFUTED`, `UNDETERMINED`)**.
