# Quy định phối hợp phát triển đồ án tốt nghiệp

## 1. Phạm vi đồ án chính thức

Tên đề tài: **Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn**.

Hệ thống đang được phát triển theo yêu cầu thầy hướng dẫn, ưu tiên:

- Fork dự án `simple_semgrepAI`.
- Sử dụng OpenGrep làm công cụ phân tích tĩnh.
- Sử dụng Qwen3.5-9B chạy cục bộ thông qua Ollama.
- Kiểm chứng trích dẫn bằng chứng và tính toàn vẹn mã nguồn.
- Phân biệt cảnh báo thật, cảnh báo giả và trường hợp chưa đủ bằng chứng.
- Yêu cầu người dùng xác nhận trước khi loại cảnh báo giả.
- Thực nghiệm có Ground Truth và bảng đối chứng đáng tin cậy.
- Tập trung trước vào CWE-22 và CWE-89.

Mã nguồn của đồ án trước được lưu tại `history/legacy-thesis-20261114`. Frontend cũ có thể được tái sử dụng sau khi backend mới đáp ứng yêu cầu.

Không tự đưa IRIS, LoRA, CWSS hoặc kiến trúc đồ án trước trở lại phạm vi triển khai hiện tại khi chưa có phê duyệt.

## 2. Quy định Git bắt buộc

Codex, Antigravity, JavisOS và mọi tiến trình hỗ trợ phải tuân thủ:

- Không tạo thêm nhánh remote.
- Không force-push.
- Không sửa, viết lại hoặc xóa lịch sử commit đã công bố.
- Không thay đổi các nhánh lịch sử.
- Không tự ý cập nhật nhánh `main` nếu chưa được cấp quyền tích hợp.
- Không ghi đè công việc của agent khác.
- Không tự động merge toàn bộ nhánh cũ vào `main`.
- Không đưa dữ liệu bí mật, trọng số mô hình, token, khóa truy cập hoặc dữ liệu production lên GitHub.

Agent được phép sử dụng nhánh cục bộ hoặc worktree riêng để phát triển và kiểm thử.

Việc cập nhật `main` phải được điều phối tuần tự, kiểm tra xung đột và xác nhận quyền thực hiện.

Orchestrator đã tạm dừng phát triển sau tái kiểm toán chưa đạt. Sử dụng quy trình tích hợp thủ công có kiểm soát.

## 3. Quy định thông điệp commit

Mọi commit phải viết bằng **tiếng Việt tự nhiên**, mô tả chính xác những thay đổi thực tế.

Không sử dụng tiền tố `feat`, `fix`, `chore`, `refactor` hoặc các tiền tố phân loại tương tự.

Không sử dụng tên viết tắt cá nhân như `NTK`, `ntk`.

Không sử dụng ký hiệu mốc công việc như `G0`, `G1`, `A1`, `A2` hoặc các mã giai đoạn tương tự trong thông điệp commit.

Không dùng thông điệp mơ hồ hoặc khẳng định vượt quá bằng chứng.

Ví dụ hợp lệ:

- `Bổ sung kiểm tra mã nguồn trước khi xác nhận cảnh báo giả`
- `Ghi nhận kết quả thực nghiệm OpenGrep và Qwen trên máy chủ`
- `Bổ sung kiểm thử khi mô hình trả thiếu trích dẫn mã nguồn`
- `Cập nhật bảng đối chứng cảnh báo thật và cảnh báo giả`

Mỗi commit phải có thay đổi thực tế tương ứng. Không tạo commit rỗng để mô phỏng tiến độ.

## 4. Quy định về bằng chứng và nghiệm thu

Không thay đổi bằng chứng thực nghiệm gốc để làm đẹp kết quả.

Không xóa các lượt thử nghiệm thất bại.

Không tự tạo kết quả mô hình, trích dẫn mã nguồn, checksum hoặc số liệu đo lường.

Không tự tuyên bố PASS chỉ vì lệnh trả mã 0 hoặc có một số bài kiểm thử thành công.

Phải phân biệt kiểm thử đơn vị, kiểm thử tích hợp, demo mô phỏng, thực nghiệm dữ liệu thật và nghiệm thu của người vận hành.

Mọi phép so sánh phải sử dụng cùng tập dữ liệu, cùng Ground Truth, cùng quy tắc ghép cảnh báo và cùng định nghĩa chỉ số.

Phải báo cáo cả số cảnh báo giả được đề xuất loại và số cảnh báo thật bị đề xuất loại nhầm.

Nếu phản hồi mô hình thiếu bằng chứng, phải giữ lại cảnh báo để kiểm tra thay vì tự động loại bỏ.

Trước khi xác nhận cảnh báo giả, phải kiểm tra tính toàn vẹn của mã nguồn được phân tích.

## 5. Phân công và phối hợp

Antigravity ưu tiên lập trình và sửa lỗi phức tạp; Codex ưu tiên kiểm toán độc lập; JavisOS phụ trách runtime trên ADMIN-PC. Ba agent nhận nhiệm vụ qua người vận hành, làm việc trên các workspace riêng.

Người thực hiện và người kiểm toán độc lập phải được phân biệt rõ.

Mỗi nhiệm vụ phải lưu được mã nguồn thay đổi, kết quả kiểm thử, đường dẫn bằng chứng, commit SHA và các vấn đề còn tồn tại.

Không tự kiểm toán để phê duyệt chính phần việc mình vừa thực hiện.

Không agent hoặc công cụ hỗ trợ nào được tự cấp quyền vượt qua điều kiện kiểm toán hoặc phê duyệt của người vận hành.

Ba agent không được đồng thời push lên `main`.

## 6. Quy trình cập nhật nhánh chính

Trước khi cập nhật GitHub:

1. Xác minh repository, remote, nhánh và commit HEAD hiện tại.
2. Kiểm tra danh sách file thay đổi và phạm vi được giao.
3. Kiểm tra dữ liệu bí mật, dữ liệu production và bằng chứng thực nghiệm.
4. Chạy các kiểm thử phù hợp với thay đổi.
5. Thu thập kết quả kiểm toán độc lập nếu nhiệm vụ yêu cầu.
6. Kiểm tra xung đột với commit mới nhất trên `main`.
7. Chỉ tích hợp khi được người vận hành hoặc tiến trình tích hợp được ủy quyền chấp thuận.
8. Báo cáo commit SHA mới sau khi cập nhật thành công.

Nếu điều kiện chưa đạt, giữ thay đổi cục bộ và báo cáo trạng thái thực tế.

## 7. Ghi nhận tiến độ nghiên cứu

GitHub phải phản ánh quá trình phát triển liên tục, không chờ hoàn thành toàn bộ đồ án mới commit.

Các kết quả FAILED hoặc BLOCKED có giá trị nghiên cứu vẫn phải được ghi nhận trung thực.

Không đưa dữ liệu demo tổng hợp thành kết quả benchmark nghiên cứu.

Mỗi báo cáo tiến độ phải phân biệt rõ việc đã thực hiện, việc được kiểm chứng, việc chưa hoàn thành và công việc tiếp theo.

**Nguyên tắc cao nhất: tính đúng đắn, khả năng kiểm chứng, bảo tồn lịch sử và tuân thủ yêu cầu thầy hướng dẫn quan trọng hơn số lượng commit hoặc kết quả PASS.**
