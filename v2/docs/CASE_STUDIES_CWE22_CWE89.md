# Phân Tích Điển Hình (Case Studies) Cho Lỗ Hổng `CWE-22` và `CWE-89` (6 Nghiên Cứu Tình Huống)

Tài liệu này trình bày **6 nghiên cứu tình huống (case studies)** đại diện cho đầy đủ các kịch bản thực nghiệm của khóa luận trên cả tập kiểm định đóng băng (`heldout_set_40`) và mã nguồn dự án mở thực tế (`OWASP WebGoat`, `java-sec-code`, `UserDao`).

---

## Case Study 1: `CWE-22` True Positive — Truyền Tham Số Qua Lớp Phụ Trợ Nội Tệp (`BenchmarkTest00949.java`, `heldout_set_40`)

- **Tệp và vị trí:** `BenchmarkTest00949.java`, dòng `44–88` (`alert_id = 0a496844...`, `CWE-22`, nhãn chuẩn: `TRUE_POSITIVE`).
- **Đặc trưng mã nguồn:**
  - Tại phương thức `doPost` (dòng 44–56), dữ liệu bẩn được đọc từ cookie HTTP `theCookie.getValue()` và giải mã qua `java.net.URLDecoder.decode(param, "UTF-8")` (dòng 54).
  - Thay vì đi thẳng vào sink, biến `param` được truyền qua phương thức nội bộ `String bar = new Test().doSomething(request, param);` (dòng 56), rồi mới truyền vào `FileInputStream` tại dòng 61–62:
    `fis = new java.io.FileInputStream(new java.io.File(fileName));`
  - Bên trong lớp nội bộ `private class Test` (dòng 77–91), phương thức `doSomething` gán `String bar = param;` tại dòng 88 và trả về nguyên vẹn dữ liệu bẩn.
- **So sánh giữa các nhánh (Arms):**
  - **Baseline `v1.0` & Arm B (`--mode heuristic`):** Nút `CliCall` trong `dataflow_trace` của OpenGrep đóng gói lời gọi `doSomething`; ở Arm B, bộ quy tắc nội phương thức trả về `UNDETERMINED` vì không tự suy luận qua lớp phụ trợ `Test`.
  - **Arm C (`--mode evidence+llm`):** Mô-đun `java_context.py` tự động mở rộng snippet `finding` tới dòng 91 để bao trùm toàn bộ lớp `Test.doSomething`. Mô hình `Qwen3.5-9B` kết luận chính xác **`SUPPORTED`** (`citation_check = MATCHED`), trích dẫn nguyên văn dòng 54 (`URLDecoder.decode`), dòng 62 (`new FileInputStream`) và dòng 88 (`String bar = param;`).

---

## Case Study 2: `CWE-22` False Positive — Cấu Trúc Danh Sách Xóa Phần Tử Bẩn Bằng `remove(0)` (`BenchmarkTest01110.java`, `heldout_set_40`)

- **Tệp và vị trí:** `BenchmarkTest01110.java`, dòng `49–98` (`CWE-22`, nhãn chuẩn: `FALSE_POSITIVE`).
- **Đặc trưng mã nguồn:**
  - Dữ liệu người dùng `param` được đọc từ header HTTP tại dòng 49 và truyền vào `new Test().doSomething(request, param)` (dòng 53).
  - Trong `Test.doSomething` (dòng 80–99):
    ```java
    String bar = "alsosafe";
    if (param != null) {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0); // xóa "safe", đưa param về index 0, "moresafe" về index 1
        bar = valuesList.get(1); // lấy phần tử ở index 1 -> luôn là hằng "moresafe"!
    }
    return bar;
    ```
- **Tại sao OpenGrep và Arm D (`--mode llm` Ablation) thất bại?**
  - OpenGrep đánh dấu bẩn toàn bộ `valuesList` khi thấy `valuesList.add(param)`, nên báo động giả tại dòng 58 (`new java.io.File(bar)`).
  - Ở **Arm D (`--mode llm` không có `java_context` và `heuristic_signals`)**, snippet chỉ chứa dòng 49 và dòng 58 mà không có thân hàm `Test.doSomething` (dòng 80–99), khiến Qwen3.5-9B kết luận sai thành `SUPPORTED` (hoặc lệch trích dẫn).
- **Cách Arm C (`--mode evidence+llm`) giải quyết:**
  - `java_context.py` đưa toàn bộ thân hàm `Test.doSomething` vào ngữ cảnh, và `heuristics.py` mô phỏng chính xác thao tác thêm 3 phần tử `["safe", param, "moresafe"]`, xóa chỉ số `0` còn `[param, "moresafe"]`, và lấy `valuesList.get(1)` = `"moresafe"`.
  - Mô hình `Qwen3.5-9B` kết luận chính xác **`REFUTED` (`PROPOSED_FP`)** với trích dẫn khớp 100% tại dòng 49, 58 và 95 (`bar = valuesList.get(1);`).

---

## Case Study 3: `CWE-89` True Positive — Sử Dụng Sai `PreparedStatement` Với Nối Chuỗi Động (`java-sec-code/SQLI.java`, Dòng 139–153)

- **Tệp và vị trí:** `java-sec-code/SQLI.java`, phương thức `jdbc_ps_vuln` tại dòng `139–153` (`CWE-89`, nhãn chuẩn: `TRUE_POSITIVE`).
- **Đặc trưng mã nguồn:**
  ```java
  @RequestMapping("/jdbc/ps/vuln")
  public String jdbc_ps_vuln(@RequestParam("username") String username) {
      ...
      String sql = "select * from users where username = '" + username + "'";
      PreparedStatement st = con.prepareStatement(sql);
      logger.info(st.toString());
      ResultSet rs = st.executeQuery();
  ```
- **Ý nghĩa kỹ thuật:**
  - Đây là bẫy kinh điển đối với các bộ lọc hậu xử lý ngây thơ: nếu một hệ thống chỉ kiểm tra sự xuất hiện của kiểu `PreparedStatement` hoặc lệnh gọi `con.prepareStatement(...)` để loại cảnh báo, nó sẽ **loại nhầm một lỗ hổng SQL Injection thật (False Dismissal)**.
  - Trong thiết kế của khóa luận (`v2/triage/heuristics.py`), tín hiệu `cwe89_parameterized_query` chỉ được kích hoạt khi câu lệnh SQL sử dụng dấu giữ chỗ `?` và không có phép nối chuỗi động từ biến bẩn. Do dòng 149 nối trực tiếp `+ username +`, hệ thống kích hoạt tín hiệu `cwe89_dynamic_sql_concatenation`, và `Qwen3.5-9B` kết luận chính xác **`SUPPORTED`** ở cả hai cảnh báo dòng 149 và 153, đồng thời chỉ rõ trong `explanation`: *"không sử dụng PreparedStatement placeholder '?'"*.

---

## Case Study 4: `CWE-89` False Positive — Truy Xuất Khóa Hằng An Toàn Từ `HashMap` Trong Phương Thức Phụ Trợ (`BenchmarkTest01215.java`, `heldout_set_40`)

- **Tệp và vị trí:** `BenchmarkTest01215.java`, dòng `46–89` (`CWE-89`, nhãn chuẩn: `FALSE_POSITIVE`).
- **Đặc trưng mã nguồn:**
  - Tham số HTTP được đọc tại dòng 46 và truyền vào `String bar = new Test().doSomething(request, param);` (dòng 53).
  - Trong `Test.doSomething` (dòng 74–89):
    ```java
    java.util.HashMap<String, Object> map78742 = new java.util.HashMap<String, Object>();
    map78742.put("keyA-78742", "a_Value"); // khóa A chứa hằng chuỗi an toàn
    map78742.put("keyB-78742", param);     // khóa B chứa dữ liệu bẩn từ HTTP request
    bar = (String) map78742.get("keyA-78742"); // lấy giá trị từ khóa A -> luôn là "a_Value"
    ```
  - Sau đó tại dòng 56–58, `bar` được nối vào câu lệnh SQL `{call verifyUserPassword('foo', '" + bar + "')}` truyền vào `connection.prepareCall(...)`.
- **So sánh giữa các nhánh (Arms):**
  - **Arm A (OpenGrep):** Báo động giả vì không phân biệt được khóa `"keyA-78742"` và `"keyB-78742"` trong `HashMap`.
  - **Arm B (`--mode heuristic`):** Chuyển về `UNDETERMINED` vì luồng đi qua lớp nội bộ `Test.doSomething` và cấu trúc `HashMap`.
  - **Arm D (`--mode llm` Ablation):** Kết luận sai thành `SUPPORTED` vì không nhìn thấy thân hàm `Test.doSomething`.
  - **Arm C (`--mode evidence+llm`):** Nhờ ngữ cảnh mở rộng tới dòng 89 và tín hiệu đối chiếu khóa `HashMap`, `Qwen3.5-9B` kết luận chính xác **`REFUTED` (`PROPOSED_FP`)** kèm trích dẫn dòng 46, 56 và 86 (`bar = (String) map78742.get("keyA-78742");`).

---

## Case Study 5: `CWE-22` True Positive Trên Dự Án Thực Tế — Lỗ Hổng Qua Mặt Kiểm Tra `getQueryString()` Bằng URL Encoding (`WebGoat/ProfileUploadRetrieval.java`)

- **Tệp và vị trí:** `WebGoat/ProfileUploadRetrieval.java`, dòng `81–93` (`CWE-22`, nhãn chuẩn: `TRUE_POSITIVE`).
- **Đặc trưng mã nguồn:**
  ```java
  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    var queryParams = request.getQueryString();
    if (queryParams != null && (queryParams.contains("..") || queryParams.contains("/"))) {
      return ResponseEntity.badRequest()
          .body("Illegal characters are not allowed in the query params");
    }
    try {
      var id = request.getParameter("id");
      var catPicture =
          new File(catPicturesDirectory, (id == null ? RandomUtils.nextInt(1, 11) : id) + ".jpg");
  ```
- **Ý nghĩa bảo mật sâu sắc:**
  - Nhìn thoáng qua, dòng 85–88 có vẻ như đã chặn chuỗi `".."` và `"/"`. Tuy nhiên, `request.getQueryString()` trả về chuỗi truy vấn thô **chưa giải mã URL** (raw URL-encoded query string), trong khi `request.getParameter("id")` ở dòng 90 **tự động giải mã URL** (`%2e%2e%2f` -> `../`). Do đó, kẻ tấn công gửi `?id=%2e%2e%2fpath-traversal-secret` sẽ vượt qua hoàn toàn lệnh `if` ở dòng 85 và đọc được tệp bí mật ở thư mục cha.
  - Hệ thống của khóa luận không coi `.contains("..")` trên `getQueryString()` là một sanitizer hợp lệ cho `CWE-22` (chỉ công nhận chuẩn hóa đường dẫn thực sự như `FilenameUtils.getName` hoặc `getCanonicalPath().startsWith(...)`), nên đã phân loại chính xác cảnh báo này vào **Nhóm 1 (`SUPPORTED`)** kèm trích dẫn dòng 90 và 92.

---

## Case Study 6: Phân Tích Giới Hạn Thực Tế — Kiểm Tra `getCanonicalPath().startsWith(...)` Đặt Sau Dòng Sink (`demo/UserDao.java:63` vs `SmokeVulnSample.java:46`)

- **Tệp và vị trí:** `demo/UserDao.java`, phương thức `open` tại dòng `61–68` (`CWE-22`, nhãn chuẩn: `FALSE_POSITIVE`).
- **Đặc trưng mã nguồn:**
  ```java
  61: public File open(HttpServletRequest request) throws IOException {
  62:     String fileName = request.getParameter("f");
  63:     File f = new File(BASE_DIR + fileName);
  64:     if (!f.getCanonicalPath().startsWith(BASE_DIR)) {
  65:         throw new IOException("blocked");
  66:     }
  67:     return f;
  68: }
  ```
- **Phân tích nguyên nhân hệ thống đóng băng giữ cảnh báo ở `SUPPORTED`:**
  - Quy tắc `httpservlet-path-traversal` của OpenGrep đánh dấu ngay constructor `new File(BASE_DIR + fileName)` tại **dòng 63** là `taint_sink` (`sink_line = 63`), bởi nhiều quy tắc SAST coi bản thân việc khởi tạo đối tượng `File` với đường dẫn bẩn là điểm nguy hiểm.
  - Tuy nhiên, trong Java, phương thức `f.getCanonicalPath()` bắt buộc phải gọi trên đối tượng `File f` **sau khi** `f` đã được khởi tạo — tức là tại **dòng 64** (`ln_no = 64 > sink_line = 63`).
  - Trong mô-đun `v2/triage/heuristics.py` đã đóng băng ở cuối Stage 3, vòng lặp quét sanitizer chỉ kiểm tra các dòng trước hoặc tại điểm sink (`if ln_no <= sink_line:`, dòng 433). Vì dòng 64 nằm sau dòng 63, tín hiệu `getCanonicalPath_startsWith` không được kích hoạt và hệ thống giữ cảnh báo ở trạng thái bảo toàn `SUPPORTED`.
- **Bài học thiết kế và hướng cải tiến:**
  - Trường hợp này minh họa rõ sự đánh đổi giữa **độ an toàn (không bỏ lọt TP)** và **độ nhạy phát hiện sanitizer hậu-khởi-tạo (post-instantiation guard)**: đối với các sink chỉ mới khởi tạo đối tượng đường dẫn (`new File(...)`, `Paths.get(...)`) mà chưa thực hiện I/O (`new FileInputStream(...)`, `Files.readAllBytes(...)`), cửa sổ kiểm tra sanitizer nên mở rộng từ `source_line` đến hết câu lệnh `return` hoặc lệnh đọc tệp thực sự trong phương thức bao ngoài, miễn là không có lệnh đọc/ghi tệp nào xảy ra trước dòng `if (!f.getCanonicalPath().startsWith(...)) throw ...`.
