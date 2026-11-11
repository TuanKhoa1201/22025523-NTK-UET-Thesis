# Đánh Giá Thực Nghiệm Trên Mã Nguồn Dự Án Java Thực Tế (`OWASP WebGoat`, `java-sec-code`, `UserDao`)

## 1. Mục Tiêu và Thiết Kế Thực Nghiệm Mở Rộng (Stage 5)

Bên cạnh bộ dữ liệu chuẩn hóa trích từ OWASP Benchmark (`dev_set_16` và `heldout_set_40`), khóa luận thực hiện đánh giá bổ sung trên **8 tệp mã nguồn Java thuộc các dự án mã nguồn mở và mô-đun đa phương thức thực tế** (không thuộc OWASP Benchmark) nhằm kiểm tra:
1. Khả năng vận hành của toàn bộ đường ống (`ScanCapture -> OpenGrep -> Evidence & Java Context -> Local Qwen3.5-9B -> Citation Check`) trên mã nguồn sử dụng Spring MVC (`@RestController`, `@RequestMapping`, `@GetMapping`, `@PostMapping`, `@RequestParam`), `JdbcTemplate`, và cấu trúc nhiều phương thức trong cùng một lớp.
2. Cách hệ thống xử lý các trường hợp sử dụng sai `PreparedStatement` (nối chuỗi động bên trong `prepareStatement(...)` hoặc mệnh đề `ORDER BY`), kiểm tra đường dẫn bị qua mặt bởi URL encoding, và các giới hạn thực tế khi hàm kiểm tra nằm ở tệp khác (cross-file validation) hoặc nằm sau dòng khởi tạo đối tượng `File`.

---

## 2. Nguồn Dữ Liệu và Biên Nhận Quét (`stage5_real_projects_scan`)

- **Thư mục nguồn chụp tĩnh:** `C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112\sources\real_projects` (8 tệp `.java`).
- **Bộ quy tắc:** `v2/evaluation/post_report/rules/p_java_cwe22_cwe89.yml` (`--dataflow-traces --taint-intrafile`).
- **Mã băm xác thực:**
  - `scan_sha256` (`opengrep.json`): `99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041`
  - `manifest_sha256` (`scan-manifest.json`): `688083ecec3e04bc03d2e6ae5f958c7df3bdf1c69af0b2971c574abb7f4b90b6`
- **Tổng số cảnh báo OpenGrep sinh ra:** `n = 20` cảnh báo (`2` cảnh báo `CWE-22` và `18` cảnh báo `CWE-89`).
  - Lưu ý quan trọng ở tầng SAST: Các phương thức đã tham số hóa chuẩn bằng dấu `?` trong cùng tệp (như `SQLI.jdbc_sqli_sec` tại dòng 95–131 của `java-sec-code` và `UserDao.findSafe` tại dòng 27–32) hoặc gán đè bằng hằng số trực tiếp trong cùng hàm (`UserDao.findConstant` tại dòng 46–51) đã được chính bộ lọc taint của OpenGrep loại bỏ ngay từ bước quét. Do đó, `20` cảnh báo còn lại đi vào tầng triage đều là các ca khó hơn.

---

## 3. Bảng Kết Quả Chi Tiết Trên 20 Cảnh Báo Dự Án Thực Tế (`stage5_real_projects_armC_evidence_llm`)

| # | Dự án / Tệp mã nguồn | Dòng | CWE | Quy tắc OpenGrep | Nhãn thực tế (Ground Truth) | Kết luận Arm C (`Qwen3.5-9B`) | Kiểm tra Citation | Độ trễ (`s`) | Nhận xét kỹ thuật |
|---|---|---|---|---|---|---|---|---|---|
| `00` | `WebGoat/Assignment5.java` | `60-64` | `CWE-89` | `tainted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `11.09s` | Nối chuỗi `username_login` trực tiếp vào `prepareStatement` (không dùng `?`). |
| `01` | `WebGoat/Assignment5.java` | `65` | `CWE-89` | `formatted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.66s` | Thực thi `statement.executeQuery()` trên câu lệnh nối chuỗi. |
| `02` | `WebGoat/ProfileUploadRetrieval.java` | `91-92` | `CWE-22` | `httpservlet-path-traversal` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.98s` | Kiểm tra `getQueryString().contains("..")` bị qua mặt bởi URL encoding khi `getParameter("id")` giải mã `%2e%2e%2f`. |
| `03` | `WebGoat/Servers.java` | `73-75` | `CWE-89` | `tainted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `10.41s` | Nối trực tiếp `@RequestParam String column` vào mệnh đề `ORDER BY` trong `prepareStatement`. |
| `04` | `WebGoat/SqlInjectionLesson5a.java` | `63` | `CWE-89` | `tainted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.95s` | Nối chuỗi `accountName` trực tiếp vào câu lệnh `SELECT`. |
| `05` | `WebGoat/SqlInjectionLesson5a.java` | `67` | `CWE-89` | `formatted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `10.02s` | Thực thi `statement.executeQuery(query)` không tham số hóa. |
| `06` | `WebGoat/SqlInjectionLesson8.java` | `66-70` | `CWE-89` | `tainted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `13.02s` | Nối chuỗi `name` và `auth_tan` vào câu lệnh `SELECT`. |
| `07` | `WebGoat/SqlInjectionLesson8.java` | `78` | `CWE-89` | `formatted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `9.26s` | Thực thi `statement.executeQuery(query)` tại `injectableQueryConfidentiality`. |
| `08` | `WebGoat/SqlInjectionLesson8.java` | `154` | `CWE-89` | `tainted-sql-string` | `FALSE_POSITIVE` (Ad-hoc quote strip) | `SUPPORTED` | `MATCHED` | `9.41s` | Hàm `log` gọi `action = action.replace('\'', '"')` tại dòng 148 trước khi nối vào chuỗi đơn `'...'` của HSQLDB. Hệ thống giữ lại bảo toàn vì `replace` không phải chuẩn tham số hóa `?`. |
| `09` | `WebGoat/SqlInjectionLesson8.java` | `158` | `CWE-89` | `formatted-sql-string` | `FALSE_POSITIVE` (Ad-hoc quote strip) | `SUPPORTED` | `MATCHED` | `8.00s` | Cùng cặp với cảnh báo `#08` tại `statement.executeUpdate(logQuery)`. Mô hình trích dẫn rõ dòng 148 và giải thích `replace` không thay thế cho `PreparedStatement`. |
| `10` | `WebGoat/UserService.java` | `52` | `CWE-89` | `spring-sqli` | `FALSE_POSITIVE` (Cross-file `@Pattern`) | `SUPPORTED` | `MATCHED` | `8.22s` | Ràng buộc `@Pattern(regexp = "[a-z0-9-]*")` của `username` nằm ở tệp khác (`WebGoatUser.java`); trong phạm vi nội tệp `UserService.java`, không có bộ lọc nên hệ thống giữ lại an toàn. |
| `11` | `demo/UserDao.java` | `23` | `CWE-89` | `tainted-sql-from-http-request` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `7.38s` | Nối chuỗi trực tiếp `request.getParameter("id")` trong `findUnsafe`. |
| `12` | `demo/UserDao.java` | `23` | `CWE-89` | `formatted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `7.66s` | Cùng dòng 23 (`findUnsafe`) từ quy tắc thứ hai. |
| `13` | `demo/UserDao.java` | `42` | `CWE-89` | `tainted-sql-from-http-request` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.14s` | Luồng truyền qua hàm phụ trợ nội tệp `findViaHelper` (dòng 36–37) sang `runQuery` (dòng 40–42). |
| `14` | `demo/UserDao.java` | `42` | `CWE-89` | `formatted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.09s` | Cùng dòng 42 (`runQuery`) từ quy tắc thứ hai. |
| `15` | `demo/UserDao.java` | `63` | `CWE-22` | `httpservlet-path-traversal` | `FALSE_POSITIVE` (Post-sink check) | `SUPPORTED` | `MATCHED` | `8.84s` | Lệnh kiểm tra `!f.getCanonicalPath().startsWith(BASE_DIR)` nằm ở dòng 64 (ngay sau dòng sink `new File(...)` tại dòng 63); do cửa sổ quét sanitizer của `heuristics.py` chỉ xét `ln_no <= sink_line`, cảnh báo được giữ lại bảo toàn. |
| `16` | `java-sec-code/SQLI.java` | `65` | `CWE-89` | `tainted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.94s` | Phương thức `jdbc_sqli_vul`: nối chuỗi `@RequestParam("username")` vào `Statement`. |
| `17` | `java-sec-code/SQLI.java` | `67` | `CWE-89` | `formatted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.03s` | Thực thi `statement.executeQuery(sql)` trong `jdbc_sqli_vul`. |
| `18` | `java-sec-code/SQLI.java` | `149` | `CWE-89` | `tainted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `10.41s` | Phương thức `jdbc_ps_vuln`: dùng `PreparedStatement` nhưng nối chuỗi `+ username` thay vì dùng dấu `?`. |
| `19` | `java-sec-code/SQLI.java` | `153` | `CWE-89` | `formatted-sql-string` | `TRUE_POSITIVE` | `SUPPORTED` | `MATCHED` | `8.20s` | Thực thi `st.executeQuery()` trong `jdbc_ps_vuln`. |

---

## 4. Tổng Hợp Định Lượng và Bài Học Nghiên Cứu Từ Mã Nguồn Thực Tế

1. **Độ chính xác bảo toàn lỗ hổng thật (TP Retention) và Kiểm chứng trích dẫn:**
   - **Tỷ lệ giữ lại TP (`SUPPORTED` trên TP):** `16/16 (100.0%)`.
   - **Tỷ lệ TP bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp`):** **`0/16 (0.0%)`**.
   - **Tỷ lệ khớp trích dẫn mã nguồn (`citation_check == MATCHED`):** **`20/20 (100.0%)`** (thời gian chạy tổng cộng `182.00s`, trung bình `9.10s / cảnh báo`).
2. **Khả năng phân biệt sử dụng đúng và sai `PreparedStatement` (`java-sec-code/SQLI.java` & `WebGoat/Servers.java`):**
   - Trong `java-sec-code/SQLI.java`, phương thức an toàn `jdbc_sqli_sec` (dùng `?` và `st.setString(1, username)`) không bị báo động giả, trong khi phương thức `jdbc_ps_vuln` (dòng 139–153: dùng `con.prepareStatement(sql)` nhưng `sql` được ghép chuỗi `+ username`) được cả `heuristics.py` và `Qwen3.5-9B` nhận diện chính xác là `SUPPORTED` (`TRUE_POSITIVE`), kèm giải thích rõ việc thiếu dấu giữ chỗ `?`.
3. **Phát hiện giới hạn thực tế (Limitations Observed in Real Projects):**
   - Qua 4 cảnh báo `#08, #09, #10, #15`, thực nghiệm chỉ ra 3 giới hạn trung thực của kiến trúc phân tích nội tệp hiện tại:
     - *(a) Kiểm tra hợp lệ nằm ở tệp khác (Cross-file validation — `#10 UserService.java:52`):* Khi ràng buộc `@Pattern(regexp = "[a-z0-9-]*")` đặt trong lớp DTO `WebGoatUser.java`, bộ trích xuất ngữ cảnh một tệp (`java_context.py`) không nhìn thấy annotation đó nên giữ cảnh báo ở trạng thái `SUPPORTED`.
     - *(b) Kiểm tra đường dẫn chuẩn hóa đặt sau lệnh khởi tạo `new File(...)` (Post-constructor guard — `#15 UserDao.java:63`):* Khi OpenGrep đặt tọa độ sink tại `new File(BASE_DIR + fileName)` (dòng 63) nhưng lệnh kiểm tra `!f.getCanonicalPath().startsWith(BASE_DIR)` nằm ở dòng 64 (`ln_no > sink_line`), bộ phát hiện sanitizer tiền-sink (`ln_no <= sink_line`) không kích hoạt tín hiệu `REFUTED`.
     - *(c) Làm sạch ngữ cảnh hẹp bằng `String.replace` (`#08, #09 SqlInjectionLesson8.java:154/158`):* Mô hình nhận thấy dòng 148 `action = action.replace('\'', '"')` nhưng từ chối coi phép thay thế ký tự đơn lẻ là biện pháp phòng chống SQL Injection tổng quát, ưu tiên giữ lại cảnh báo thay vì mạo hiểm bỏ lọt.
