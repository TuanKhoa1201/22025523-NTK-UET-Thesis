# Chương 1: Giới Thiệu Đề Tài

## 1.1. Đặt Vấn Đề và Bối Cảnh Nghiên Cứu

Trong quy trình phát triển phần mềm hiện đại (DevSecOps), các công cụ phân tích tĩnh mã nguồn mở (Static Application Security Testing — SAST) như Semgrep/OpenGrep đóng vai trò là tuyến phòng thủ đầu tiên để phát hiện sớm các lỗ hổng bảo mật trong mã nguồn Java. Tuy nhiên, một hạn chế cố hữu của các công cụ SAST dựa trên khớp mẫu cú pháp và lan truyền vết nội tệp (`intra-file taint tracking`) là **tỷ lệ cảnh báo giả (False Positive — FP) cao** khi gặp các cấu trúc luồng điều khiển và biến đổi dữ liệu phức tạp trong thực tế:

1. **Nhánh điều kiện bất khả thi (Dead/Constant Control-Flow Branches):** Công cụ SAST đánh dấu dữ liệu đầu vào từ HTTP request (`HttpServletRequest.getParameter`, `getHeader`, `getCookies`) là nguồn bẩn (`tainted source`) và theo dõi biến đó đến điểm nhạy cảm (`sink`), nhưng không đánh giá được biểu thức điều kiện số học hoặc nhánh `switch/case` luôn chọn giá trị hằng an toàn trước khi tới `sink`.
2. **Thao tác trên cấu trúc dữ liệu tập hợp (Collection & Map Indexing):** Khi dữ liệu người dùng và chuỗi hằng cùng được đưa vào `List<String>` hoặc `Map<String, Object>`, phân tích tĩnh thường đánh dấu bẩn toàn bộ tập hợp (collection-level taint) thay vì theo dõi chính xác phần tử ở chỉ số `0` đã bị loại bỏ (`valuesList.remove(0)`) hay khóa được truy xuất là khóa chứa chuỗi an toàn (`map.get("keyA-...")`).
3. **Phương thức phụ trợ và lớp bọc nguồn hằng (Helper Methods & Wrapper Classes):** Khi dữ liệu đi qua các phương thức nội bộ trong cùng tệp (`new Test().doSomething(request, param)`) hoặc lấy từ phương thức trả về hằng số cố định (`SeparateClassRequest.getTheValue("...")`), việc chỉ quan sát dòng nguồn và dòng đích rời rạc khiến kỹ sư bảo mật mất nhiều thời gian truy vết thủ công.

Ngược lại, nếu sử dụng trực tiếp các Mô hình Ngôn ngữ Lớn (Large Language Models — LLM) thương mại trên đám mây để phân loại cảnh báo, tổ chức sẽ đối mặt với ba rủi ro nghiêm trọng:
- **Rủi ro lộ lọt mã nguồn nội bộ** khi gửi mã nguồn ứng dụng ra dịch vụ bên ngoài.
- **Hiện tượng ảo giác (Hallucination):** Mô hình tự suy diễn dòng mã không tồn tại hoặc viện dẫn sai vị trí làm sạch dữ liệu (`sanitizer`).
- **Rủi ro loại nhầm lỗ hổng thật (False Dismissal):** Nếu hệ thống tự động đóng cảnh báo dựa trên kết luận `FALSE_POSITIVE` của LLM mà không có cơ chế kiểm chứng bằng chứng mã nguồn và phê duyệt của con người, các lỗ hổng bảo mật nghiêm trọng sẽ bị bỏ lọt.

Xuất phát từ thực tế đó, khóa luận thực hiện đề tài: **"Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn"**, tập trung vào kiến trúc hậu xử lý cảnh báo an toàn (fail-closed SAST post-processing & triage) chạy hoàn toàn cục bộ (local inference).

---

## 1.2. Mục Tiêu và Câu Hỏi Nghiên Cứu

### 1.2.1. Mục tiêu tổng quát
Xây dựng và kiểm định thực nghiệm một đường ống (pipeline) kết hợp công cụ phân tích tĩnh nguồn mở **OpenGrep** với mô hình ngôn ngữ lớn cục bộ **Qwen3.5-9B (`qwen3.5:9b-q4_K_M` qua Ollama)**, bổ sung tầng trích xuất ngữ cảnh Java mở rộng, tín hiệu phân tích tĩnh phụ trợ, cổng kiểm chứng trích dẫn mã nguồn nguyên văn và hàng đợi xác nhận thủ công trên SQLite.

### 1.2.2. Các câu hỏi nghiên cứu (Research Questions)
- **RQ1 (Khả năng giảm cảnh báo giả an toàn):** Khi kết hợp OpenGrep với ngữ cảnh phương thức Java mở rộng, tín hiệu tĩnh và mô hình cục bộ `Qwen3.5-9B`, hệ thống có thể phát hiện và đề xuất loại bỏ bao nhiêu phần trăm cảnh báo giả (`FALSE_POSITIVE` -> Nhóm 2 `REFUTED` / `PROPOSED_FP`) trên hai nhóm lỗ hổng trọng tâm `CWE-22` (Path Traversal) và `CWE-89` (SQL Injection), đồng thời giữ tỷ lệ **TP bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp`)** ở mức tối thiểu?
- **RQ2 (Đóng góp của từng thành phần — Ablation Study):** So với (a) OpenGrep đơn thuần (Arm A), (b) bộ quy tắc heuristic tất định không dùng LLM (Arm B, `--mode heuristic`), và (c) mô hình Qwen3.5-9B chỉ đọc snippet mặc định không có ngữ cảnh mở rộng/tín hiệu tĩnh (Arm D, `--mode llm`), kiến trúc đầy đủ (Arm C, `--mode evidence+llm`) mang lại mức cải thiện định lượng như thế nào?
- **RQ3 (Tính toàn vẹn bằng chứng và an toàn vận hành):** Cổng kiểm chứng trích dẫn (`verify_citations`) và hàng đợi rà soát thủ công (`review.py`) ngăn chặn hiệu quả ra sao đối với các trích dẫn sai lệch và hành vi tự động đóng cảnh báo khi chưa có phê duyệt của con người?

---

## 1.3. Phạm Vi Nghiên Cứu và Giới Hạn Kỹ Thuật

Để đảm bảo chiều sâu thực nghiệm và tính chặt chẽ khoa học, khóa luận xác lập phạm vi rõ ràng:
1. **Ngôn ngữ và loại lỗ hổng trọng tâm:** Tập trung phân tích sâu hai lớp lỗ hổng phổ biến và nguy hiểm bậc nhất trong ứng dụng Java là **`CWE-22` (Path Traversal)** và **`CWE-89` (SQL Injection)**. Hai nhóm phụ `CWE-78` (OS Command Injection) và `CWE-79` (Cross-Site Scripting) chỉ được giữ ở mức tương thích cấu trúc dữ liệu, không mở rộng thực nghiệm sâu để tránh dàn trải nguồn lực.
2. **Mô hình suy luận cục bộ:** Sử dụng duy nhất mô hình mã nguồn mở chạy cục bộ **`qwen3.5:9b-q4_K_M`** thông qua máy chủ **Ollama (`127.0.0.1:11434`)** với `temperature = 0` và JSON Schema nghiêm ngặt; không sử dụng bất kỳ API LLM đám mây nào và không thực hiện huấn luyện lại (fine-tuning/LoRA).
3. **Nguyên tắc an toàn cốt lõi:** Đầu ra của mô hình chỉ đóng vai trò **đề xuất phân loại 3 nhóm** (`SUPPORTED` / `REFUTED` / `UNDETERMINED`), tuyệt đối không được dùng làm nhãn chuẩn (`ground truth`) và không tự động đóng cảnh báo giả khi chưa qua xác nhận của kỹ sư bảo mật.

---

## 1.4. Đóng Góp Chính Của Khóa Luận

1. **Thiết kế và hiện thực hóa đường ống hậu xử lý cảnh báo OpenGrep + Local Qwen3.5-9B có kiểm chứng bằng chứng:** Tích hợp liền mạch từ bước chụp biên nhận quét bất biến (`ScanCapture` / `scan-manifest.json`), trích xuất ngữ cảnh phương thức và hàm phụ trợ cùng tệp (`v2/triage/java_context.py`), chuẩn hóa chuỗi bước `CliCall` trong `dataflow_trace` (`v2/triage/evidence.py`), trích xuất tín hiệu tĩnh (`v2/triage/heuristics.py`), đến suy luận có kiểm chứng trích dẫn (`v2/triage/ollama.py`).
2. **Xây dựng bộ dữ liệu kiểm định phân tầng có nguồn gốc minh bạch (`n = 56` cảnh báo Benchmark + `n = 20` cảnh báo dự án mã nguồn mở thực tế):** Gồm tập phát triển `dev_set_16` (`n = 16`), tập kiểm định độc lập đóng băng `heldout_set_40` (`n = 40`, đạt chuẩn `STRICT_LOCK`), và tập đánh giá trên mã nguồn thực tế (`OWASP WebGoat`, `java-sec-code`, `UserDao`).
3. **Chứng minh thực nghiệm qua đối sánh bắt cặp 4 nhánh (4-Arm Paired Evaluation):** Trên tập `heldout_set_40` (`20 TP`, `20 FP`), kiến trúc đầy đủ (Arm C) giữ đúng `20/20 (100.0%)` TP ở Nhóm 1, phát hiện đúng `20/20 (100.0%)` FP ở Nhóm 2, đạt tỷ lệ **TP bị đề xuất loại nhầm = `0/20 (0.0%)`** và tỷ lệ khớp trích dẫn mã nguồn = `40/40 (100.0%)`, vượt trội rõ rệt so với Arm A (`0/20` FP), Arm B (`7/20` FP) và Arm D (`0/20` FP).
4. **Kiểm chứng cơ chế Human-in-the-Loop bất biến:** Xây dựng bộ kiểm thử phủ định (`16/16` ca kiểm thử trong `test_human_review_negative_suite.py`) chứng minh hệ thống từ chối mọi thao tác xác nhận thiếu định danh người duyệt, thiếu lý do, lệch mã băm nguồn/quét, sai mã cảnh báo, lỗi kết nối Ollama, JSON sai định dạng hoặc trích dẫn dòng mã không nằm trong phạm vi bằng chứng đã xác thực SHA-256.
