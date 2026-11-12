# Chương 5: Kết Luận và Hướng Phát Triển

## 5.1. Tổng Kết Các Kết Quả Đạt Được

Khóa luận đã hoàn thành mục tiêu thiết kế, hiện thực hóa và kiểm định thực nghiệm hệ thống hậu xử lý cảnh báo phân tích tĩnh kết hợp **OpenGrep (`v1.25.0`)** và mô hình ngôn ngữ lớn cục bộ **Qwen3.5-9B (`qwen3.5:9b-q4_K_M` qua Ollama)** cho mã nguồn Java, tập trung sâu vào hai lớp lỗ hổng trọng tâm **`CWE-22` (Path Traversal)** và **`CWE-89` (SQL Injection)**. Các kết quả chính được chứng minh bằng bằng chứng thực nghiệm gồm:

1. **Hoàn thiện kiến trúc trích xuất bằng chứng và ngữ cảnh Java có kiểm chứng mã băm (`v2/triage/`):**
   - Giải quyết triệt để điểm mù nút đệ quy `CliCall` trong `dataflow_trace` của OpenGrep (`v2/triage/evidence.py`), vốn xuất hiện trên `91.5%` cảnh báo `CWE-22` của OWASP Benchmark.
   - Xây dựng bộ trích xuất ngữ cảnh phương thức và hàm phụ trợ cùng tệp (`v2/triage/java_context.py`) kết hợp bộ tín hiệu phân tích tĩnh (`v2/triage/heuristics.py`) và chuẩn hóa ứng viên trích dẫn đơn dòng (`candidate_citations`), nâng tỷ lệ khớp trích dẫn nguyên văn (`citation_check == MATCHED`) từ `6/16 (37.5%)` ở baseline `v1.0` lên `16/16 (100.0%)` trên tập phát triển `dev_set_16` và **`40/40 (100.0%)`** trên tập kiểm định độc lập `heldout_set_40`.

2. **Chứng minh hiệu quả định lượng trên tập Held-Out đóng băng (`heldout_set_40`, `n = 40`: `20 TP, 20 FP`):**
   - Trong đánh giá bắt cặp 4 nhánh (Arm A: OpenGrep đơn thuần; Arm B: Heuristic không LLM; Arm C: Đường ống đầy đủ `evidence+llm`; Arm D: Ablation `llm` không có ngữ cảnh mở rộng/tín hiệu tĩnh):
     - **Arm C (`--mode evidence+llm`)** giữ lại chính xác **`20/20 (100.0%)`** lỗ hổng thật ở Nhóm 1 (`SUPPORTED`), phát hiện và đề xuất loại chính xác **`20/20 (100.0%)`** cảnh báo giả ở Nhóm 2 (`REFUTED` / `PROPOSED_FP`), đạt tỷ lệ **TP bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp`) = `0/20 (0.0%)`**, nâng Precision theo chính sách `drop_fp` từ `20/40 (50.0%)` của OpenGrep đơn thuần lên **`20/20 (100.0%)`** với độ trễ trung bình `10.53 giây / cảnh báo`.
     - Đối chứng thực nghiệm chỉ rõ: nếu chỉ dùng quy tắc heuristic tất định (Arm B), hệ thống chỉ lọc được `7/20 (35.0%)` FP và phải đẩy `24/40 (60.0%)` cảnh báo vào `UNDETERMINED`; nếu chỉ dùng LLM mà thiếu ngữ cảnh phương thức mở rộng và tín hiệu tĩnh (Arm D), mô hình lọc được `0/20 (0.0%)` FP (`14/20` FP bị phán nhầm thành `SUPPORTED`).

3. **Đánh giá trên mã nguồn dự án thực tế (`n = 20`) và bảo chứng an toàn vận hành (Human-in-the-Loop):**
   - Trên `20` cảnh báo từ `OWASP WebGoat`, `java-sec-code` và `UserDao`, hệ thống giữ lại `16/16 (100.0%)` lỗ hổng thật (`0/16` loại nhầm TP) và đạt `20/20 (100.0%)` trích dẫn khớp mã nguồn, nhận diện chính xác cả các trường hợp dùng sai `PreparedStatement` không có dấu `?` và lỗ hổng qua mặt `getQueryString()` bằng URL encoding.
   - Cơ chế hàng đợi xác nhận thủ công trên SQLite (`v2/triage/review.py`) được kiểm chứng qua `16/16` ca kiểm thử phủ định tự động, đảm bảo không có bất kỳ cảnh báo giả nào bị đóng tự động khi chưa có định danh người duyệt, lý do và trích dẫn dòng mã hợp lệ.

---

## 5.2. Các Hạn Chế Hiện Tại (Threats to Validity & Limitations)

Với tinh thần trung thực khoa học, khóa luận ghi nhận rõ các giới hạn của hệ thống hiện tại:
1. **Giới hạn phạm vi nội tệp (Single-File Context Boundary):** Bộ trích xuất ngữ cảnh `v2/triage/java_context.py` hiện chỉ mở rộng phương thức bao ngoài và các hàm phụ trợ nằm trong **cùng một tệp `.java`**. Khi bộ kiểm tra hợp lệ hoặc hàm làm sạch nằm ở một lớp/tệp khác (ví dụ annotation `@Pattern` trong `WebGoatUser.java` đối với `UserService.java:52`), hệ thống không tự động truy vết liên tệp mà giữ cảnh báo ở trạng thái bảo toàn để con người rà soát.
2. **Giới hạn cửa sổ kiểm tra sanitizer hậu-khởi-tạo (Post-Sink Guard Window):** Đối với các quy tắc SAST đặt tọa độ sink ngay tại constructor `new File(...)` (như `UserDao.java:63`), nếu câu lệnh kiểm tra `!f.getCanonicalPath().startsWith(BASE_DIR)` nằm ở dòng kế tiếp (`ln_no > sink_line`), bộ phát hiện sanitizer tiền-sink trong `heuristics.py` chưa kích hoạt tín hiệu `REFUTED`.
3. **Quy mô và độ đa dạng của tập kiểm định:** Mặc dù tổng số mẫu có nhãn đã được mở rộng lên `56` cảnh báo Benchmark (`16` dev + `40` held-out) và `20` cảnh báo từ dự án thực tế (` tổng cộng 76` cảnh báo), các mẫu trong `heldout_set_40` vẫn mang cấu trúc servlet của OWASP Benchmark v1.2. Việc mở rộng tập kiểm định sang hàng trăm cảnh báo từ các hệ thống doanh nghiệp đa mô-đun lớn là bước cần thiết tiếp theo.
4. **Độ trễ suy luận tuần tự:** Suy luận cục bộ trên `qwen3.5:9b-q4_K_M` mất trung bình `~9.1–10.5 giây / cảnh báo`, phù hợp để chạy hậu xử lý cho các cảnh báo mức độ cao (`CWE-22`, `CWE-89`) trong CI/CD, nhưng cần cơ chế xử lý theo lô hoặc bộ nhớ đệm theo mã băm AST nếu quét hàng nghìn cảnh báo cùng lúc.

---

## 5.3. Hướng Phát Triển Tiếp Theo

1. **Mở rộng trích xuất ngữ cảnh liên tệp có giới hạn (Bounded Cross-File Call Graph Slicing):** Kết hợp bảng ký hiệu nhẹ (symbol table) ở phạm vi gói (package) để tự động đính kèm định nghĩa của tối đa 1–2 phương thức hoặc lớp DTO liên tệp trực tiếp trên đường truyền dữ liệu.
2. **Mở rộng cửa sổ phát hiện Post-Constructor Guard cho `CWE-22`:** Phân biệt giữa *sink khởi tạo đối tượng đường dẫn* (`new File`, `Paths.get`) và *sink thực thi I/O* (`new FileInputStream`, `Files.readAllBytes`), cho phép nhận diện các câu lệnh kiểm tra `getCanonicalPath().startsWith(...)` nằm giữa bước khởi tạo `File` và bước đọc/trả về tệp.
3. **Mở rộng sang các nhóm lỗ hổng khác (`CWE-78`, `CWE-79`, `CWE-502`, `CWE-918`):** Áp dụng cùng phương pháp thiết kế tín hiệu tĩnh chuyên biệt và tập kiểm định đóng băng `STRICT_LOCK` cho nhóm lỗ hổng OS Command Injection, Cross-Site Scripting và SSRF.
