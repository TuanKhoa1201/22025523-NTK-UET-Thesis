# Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn

Đồ án tốt nghiệp ngành Công nghệ thông tin, Trường Đại học Công nghệ, Đại học Quốc gia Hà Nội.

Repository này lưu trữ mã nguồn, tài liệu, quá trình phát triển và các kết quả kiểm chứng của đồ án tốt nghiệp.

## Hướng nghiên cứu hiện hành

Hệ thống được phát triển theo yêu cầu của thầy hướng dẫn:

- Fork dự án simple_semgrepAI.
- Tích hợp OpenGrep làm công cụ phát hiện cảnh báo mã nguồn.
- Sử dụng Qwen3.5-9B qua Ollama chạy cục bộ, không gửi mã nguồn lên dịch vụ suy luận đám mây.
- Phân tích ngữ cảnh và trích dẫn dòng mã nguồn thực tế.
- Kiểm tra mã nguồn có thay đổi trước khi xác nhận cảnh báo giả.
- Giữ lại cảnh báo thiếu bằng chứng để người dùng kiểm tra.
- Đánh giá bằng Ground Truth và các chỉ số được định nghĩa thống nhất.
- Ưu tiên nghiên cứu CWE-22 và CWE-89 trong giai đoạn đầu.

Các mẫu CWE-78 và CWE-79 có thể xuất hiện trong bộ demo tham chiếu, không đồng nghĩa với việc mở rộng phạm vi nghiên cứu chính.

## Trạng thái phát triển

Hệ thống đang trong quá trình tích hợp và kiểm toán. Không coi toàn bộ đồ án đã nghiệm thu.

Các công việc đang được thực hiện:

1. Kiểm chứng bộ mã tham chiếu OpenGrep và Qwen của thầy.
2. Hoàn thiện tích hợp trong fork simple_semgrepAI.
3. Bổ sung kiểm tra bằng chứng mã nguồn và xác nhận cảnh báo giả.
4. Phối hợp trực tiếp Antigravity, Codex và JavisOS. Orchestrator đã tạm dừng phát triển sau kiểm toán chưa đạt.
5. Xây dựng thực nghiệm đối chứng có thể tái lập.

Xem `docs/trang-thai-hien-tai.md` để biết kết quả đã kiểm tra và các giới hạn tồn tại.

## Quy định phát triển

Đọc `AGENTS.md` trước khi thực hiện thay đổi.

Mọi commit phải viết bằng tiếng Việt tự nhiên, mô tả chính xác thay đổi thực tế. Không force-push, không tạo thêm nhánh remote và không sửa lịch sử đã công bố.

## Lưu trữ hệ thống cũ

Toàn bộ phiên bản nghiên cứu trước được giữ tại nhánh:

`history/legacy-thesis-20261114`

Frontend React/Vite cũ nằm trong nhánh này và sẽ được xem xét tái sử dụng sau khi backend mới đáp ứng yêu cầu.

Ba nhánh `v2/codex-core`, `v2/antigravity-review` và `v2/javis-benchmark` được giữ làm lịch sử phát triển trước khi có Orchestrator. Không tự động hợp nhất toàn bộ các nhánh này.

## Lưu ý

Nhánh chính hiện đang được chuyển đổi sang kiến trúc mới. Mã nguồn backend chính thức sẽ được tích hợp sau khi kiểm tra tính phù hợp, quyền sử dụng và bằng chứng kiểm thử.

Một lượt demo thành công hoặc số bài kiểm thử đạt không tự động chứng minh toàn bộ hệ thống đã hoàn thành.