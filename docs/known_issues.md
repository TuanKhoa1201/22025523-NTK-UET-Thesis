# Những điểm cần lưu ý khi triển khai

Tình trạng được rà soát ngày 05/11/2026.

| Vấn đề | Trạng thái | Hướng xử lý |
|---|---|---|
| Chạy trên máy mới cần model và checkpoint LoRA | Còn phụ thuộc artifact riêng | Chuẩn bị nguồn được cấp phép, đối chiếu SHA-256 và cấu hình đường dẫn WSL |
| Dataset trên máy mới không có sẵn | Theo thiết kế | Chuyển giao riêng bốn file đã xác minh; không sinh bản ghi giả |
| IRIS gốc cần CodeQL và upstream | Theo thiết kế | Cấu hình chế độ IRIS gốc và ghi log chế độ thực sự khi đánh giá |
| Đánh giá độ chính xác SAST chưa có bộ ground truth hoàn chỉnh đã công bố | Cần bổ sung | Khóa corpus, đo TP/FP/FN và báo cáo riêng theo CWE |
| Khả năng chạy GPU khác nhau theo phần cứng | Cần kiểm tra trên máy đích | Xác nhận CUDA, torch, driver, thời gian suy luận thực tế |
| HTTP backend chưa phải dịch vụ công khai | Cần giới hạn truy cập | Chỉ chạy localhost; thêm xác thực và giới hạn tài nguyên nếu mở mạng |
| Dependency cảnh báo phiên bản và bundle frontend lớn | Cần bảo trì | Đánh giá cập nhật có kiểm soát, không nâng cấp cưỡng ép trước bảo vệ |
| Khởi động bằng Linux script có thể khác startup trước đó trên laptop | Cần chạy smoke trên máy thực tế | Dùng script mới, không ghi đè môi trường đang chạy nếu chưa kiểm chứng |
| Phân trang và lưu trạng thái sau quét lớn | Cần kiểm thử định kỳ | So summary với toàn bộ findings, thử tải lại lịch sử sau refresh |

Lỗi tham số CLI của startup script cũ đã được sửa trong bản `bin/start_ntk_backend.sh`. Bộ script Windows/WSL cấp repository được thêm để vận hành trên máy khác, nhưng chỉ được coi là nghiệm thu khi kiểm tra trực tiếp tại môi trường đích.

Các vấn đề trên không đồng nghĩa hệ thống đang hoạt động lỗi trên laptop hiện tại.
