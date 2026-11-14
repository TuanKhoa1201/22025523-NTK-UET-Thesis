# Quy trình cập nhật GitHub

## Quyền cập nhật

Chỉ người vận hành hoặc một tiến trình tích hợp được ủy quyền mới được push lên main.

Codex, Antigravity và JavisOS không được push đồng thời lên main.

## Quy trình

1. Agent thực hiện thay đổi trong workspace riêng.
2. Tạo commit cục bộ với thông điệp tiếng Việt tự nhiên.
3. Ghi lệnh chạy, kết quả và các giới hạn còn lại.
4. Agent độc lập kiểm toán thay đổi và bằng chứng.
5. Người vận hành kiểm tra quyền tích hợp.
6. Tiến trình tích hợp kiểm tra HEAD mới nhất của main.
7. Chỉ thực hiện push fast-forward, không force-push.
8. Ghi nhận SHA commit đã công bố.

## Bảo vệ lịch sử

Không tạo thêm nhánh remote.

Không tự động merge toàn bộ nhánh agent cũ.

Không sửa lịch sử Git đã công bố.

Không thay đổi nhánh history/legacy-thesis-20261114.

## Thực nghiệm

Không sửa bằng chứng gốc để cải thiện kết quả.

Mọi phép so sánh phải sử dụng cùng tập dữ liệu, Ground Truth và định nghĩa chỉ số.

Lệnh chạy thành công không đồng nghĩa với nghiệm thu toàn bộ hệ thống.

Những kết quả thất bại phải được giữ lại và giải thích trung thực.

## Trạng thái hiện tại

Orchestrator đang được sửa và kiểm toán. Chưa sử dụng cơ chế tự động push lên main khi chưa được nghiệm thu.