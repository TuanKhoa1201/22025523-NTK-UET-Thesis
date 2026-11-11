# ĐÁNH GIÁ KỸ THUẬT CÁC MẪU SANITIZER, NGUỒN HẰNG VÀ NHÁNH BẤT BIẾN TRONG JAVA (`CWE-22` & `CWE-89`)

- **Giai đoạn:** Stage 2 — Nâng cấp trích xuất ngữ cảnh Java, làm giàu bằng chứng và kiểm tra trích dẫn
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Mô-đun cài đặt:** `v2/triage/java_context.py`, `v2/triage/heuristics.py`, `v2/triage/evidence.py`, `v2/triage/ollama.py`
- **Bản đồng bộ:** Xem đầy đủ tại [`v2/evaluation/post_report/SANITIZER_CASE_REVIEW.md`](../evaluation/post_report/SANITIZER_CASE_REVIEW.md).

---

## Tóm tắt các quy tắc phân biệt chính

1. **Sanitizer hợp lệ đối với `CWE-22`:** `FilenameUtils.getName(...)`, `Path.getFileName()`, `File.getName()`, hoặc `getCanonicalPath()` / `normalize()` đi kèm kiểm tra tiền tố `.startsWith(allowedBaseDir)`.
2. **Sanitizer hợp lệ đối với `CWE-89`:** Truy vấn tham số hóa `PreparedStatement` với `?` (không ghép chuỗi `+` vào câu lệnh SQL), `ESAPI.encoder().encodeForSQL(...)`, hoặc ép kiểu số học `Integer.parseInt` / `Long.parseLong` / `UUID.fromString`.
3. **Biến đổi không phải Sanitizer (Non-Sanitizers):** `ESAPI.encoder().encodeForHTML(...)`, `StringEscapeUtils.escapeHtml(...)`, và `URLDecoder.decode(...)` không vô hiệu hóa `CWE-22` hay `CWE-89`.
4. **Nguồn hằng và nhánh bất biến:** `SeparateClassRequest.getTheValue(...)` (luôn trả về `"bar"`), ghi đè hằng trực tiếp (`id = "42"`), `switch (guess.charAt(1))` vào nhánh hằng `'B'`, toán tử số học hằng `(a * b) +- num > 200`, `valuesList.remove(0)` + `valuesList.get(1)`, và `map.get(safeKey)`.
