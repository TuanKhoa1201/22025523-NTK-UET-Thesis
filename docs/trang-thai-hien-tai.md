# Trạng thái thực hiện đồ án

Cập nhật ngày 14/11/2026.

## Phạm vi được ưu tiên

Fork simple_semgrepAI, OpenGrep và Qwen3.5-9B chạy cục bộ.

Tập trung trước vào CWE-22 và CWE-89.

## Bộ mã tham chiếu của thầy

- Đã tiếp nhận và xác minh bộ mã cùng nhật ký Colab.
- Kiểm thử ngoại tuyến trên ADMIN-PC: 9/9 bài kiểm thử đạt.
- OpenGrep 1.33.1 phát hiện đúng 8 cảnh báo của bộ demo.
- Ollama 0.40.16 và Qwen3.5-9B đã chạy cục bộ trên RTX 4060 Ti.
- Lượt smoke giới hạn hai cảnh báo đạt hợp đồng kỹ thuật.
- Lượt full-8 đầu tiên thất bại: 8 lượt gọi model, 7 phản hồi hợp lệ và 1 invalid_response.
- Kết quả phân loại trên ADMIN-PC khác Colab Tesla T4.
- Bằng chứng lượt thất bại đã được bảo tồn và kiểm toán.
- Lượt tái kiểm thử có kiểm soát đang chờ kết quả cuối cùng.

Không sử dụng tám mẫu tổng hợp này để tuyên bố hiệu quả trên dữ liệu nghiên cứu thật.

## Tích hợp fork

- Đang thực hiện tích hợp OpenGrep và Qwen.
- Cần kiểm tra mã nguồn thay đổi và trích dẫn thực.
- Cần quy trình người dùng xác nhận cảnh báo giả.
- Phần tích hợp thực tế còn tồn tại điều kiện chặn nghiệm thu.
- Chưa tuyên bố hoàn thành toàn bộ backend.

## Công cụ điều phối (đã tạm dừng phát triển)

- Các phiên bản phát triển, commit và bằng chứng kiểm toán được bảo toàn trên laptop.
- Tái kiểm toán độc lập A7 kết luận REMEDIATION_INCOMPLETE_REVIEW_REQUIRED: có 5 findings, trong đó 3 blocker.
- Đã quyết định đóng băng Orchestrator, không tiếp tục mở rộng hoặc giao thêm nhiệm vụ sửa lỗi.
- Codex đã hoàn thành lượt tái kiểm toán; kết quả chưa đáp ứng điều kiện triển khai.
- Không triển khai Orchestrator lên ADMIN-PC. Ba agent được người vận hành phối hợp trực tiếp để ưu tiên hoàn thiện OpenGrep và Qwen.

## Những công việc tiếp theo

1. Kiểm toán và tích hợp mã nguồn mới vào nhánh chính.
2. Tái hiện thực nghiệm theo cùng tập dữ liệu và cùng định nghĩa chỉ số.
3. Hoàn thiện cơ chế xử lý cảnh báo thật, giả và chưa đủ bằng chứng.
4. Hoàn thiện kiểm thử an toàn G2, đánh giá G3 và nghiệm thu E2E Java trong G4 theo thứ tự được duyệt.
5. Chuẩn bị hồ sơ báo cáo và bảo vệ đồ án.

## Quy định bằng chứng

Giữ nguyên các kết quả FAILED, BLOCKED và các hiện vật thực nghiệm gốc.

Không công bố token, model weights, cơ sở dữ liệu production hoặc hồ sơ riêng tư trên GitHub công khai.

Mỗi kết quả phải có lệnh chạy, phạm vi dữ liệu, phiên bản công cụ, bằng chứng và giới hạn kết luận.