# Quy trình cập nhật GitHub

## Quyền cập nhật

Chỉ người vận hành hoặc tiến trình tích hợp được ủy quyền mới được push lên `main`. Codex, Antigravity và JavisOS làm việc trên các workspace riêng, không push đồng thời lên nhánh chính.

## Quy trình

1. Thực hiện thay đổi trong workspace riêng, kiểm tra diff và phạm vi được giao.
2. Rà soát dữ liệu nhạy cảm, chạy kiểm thử phù hợp, lưu lệnh chạy, kết quả và giới hạn.
3. Thu thập kiểm toán độc lập theo yêu cầu. Không tự phê duyệt phần việc mình vừa thực hiện.
4. Xác minh remote, HEAD mới nhất của `main` và nội dung cần công bố; dừng nếu có xung đột.
5. Sau khi người vận hành phê duyệt, tạo commit cục bộ bằng tiếng Việt tự nhiên, kiểm tra Git tree rồi push fast-forward.
6. Kiểm tra lại SHA commit, Git tree, danh sách ref và kết quả CI trên GitHub. Ghi nhận biên nhận phát hành.

Không force-push, không tự tạo nhánh remote hoặc hợp nhất toàn bộ nhánh agent cũ. Cập nhật GitHub không cấp quyền triển khai hoặc khởi động lại hệ thống. Nếu CI chưa đạt, báo cáo nguyên nhân. Ngoại lệ công bố mốc mã nguồn phải được người vận hành phê duyệt riêng, kèm phạm vi và giới hạn. Không tắt workflow hoặc bỏ test để làm CI đạt.

## Lưu trữ và thu gọn nhánh

Bản sao [Thesis-History](https://github.com/TuanKhoa1201/Thesis-History) ở chế độ Private, gồm 127 commit, 5 nhánh và 1 tag tại thời điểm sao lưu ngày 27/11/2026. Đã kiểm chứng khả năng khôi phục từ GitHub. Các commit gốc và tài liệu lịch sử được giữ nguyên. Bản sao không bao gồm toàn bộ dữ liệu ngoài Git.

Bốn nhánh dự kiến thu gọn trên repository chính: `history/legacy-thesis-20261114`, `v2/antigravity-review`, `v2/codex-core` và `v2/javis-benchmark`. Chỉ người vận hành mới được phê duyệt việc xóa ref. Trước khi xóa, cần kiểm tra:

- Bản sao cục bộ và bản lưu trữ trên GitHub còn đầy đủ, SHA các nhánh cần xóa khớp với bản sao.
- Không có commit mới chưa được bảo toàn, PR đang mở hoặc công việc còn phụ thuộc vào các nhánh này.
- Tài liệu hiện hành dẫn tới đúng commit trong bản lưu trữ; người cần xem có quyền truy cập.
- `main`, tag và repository `Thesis-History` nằm ngoài phạm vi xóa.

Dừng nếu thiếu bằng chứng hoặc phát hiện SHA thay đổi. Sau khi xóa tên nhánh cũ, kiểm tra lại `main`, tag và các ref trong repository lưu trữ. Không viết lại commit đã công bố. Các hồ sơ cũ được giữ nguyên; khi cần, tra cứu tên nhánh theo SHA trong README.

## Thực nghiệm và bằng chứng

Mọi phép so sánh phải dùng cùng tập dữ liệu, Ground Truth, quy tắc ghép cảnh báo và định nghĩa chỉ số. Không sửa bằng chứng gốc hoặc chọn lại kết quả để làm đẹp số liệu. Giữ các lượt thử thất bại và giải thích nguyên nhân.

Phân biệt kết quả kiểm thử, demo, thực nghiệm và nghiệm thu. CI của commit chỉ sửa tài liệu không chứng minh lỗi tại commit mã nguồn đã được xử lý. Không đưa token, raw HTTP, dữ liệu vận hành hoặc source quét riêng tư lên GitHub.

## Tổ chức công việc hiện tại

Orchestrator đã dừng phát triển sau tái kiểm toán chưa đạt. Người vận hành phối hợp các agent trực tiếp, kiểm tra từng thay đổi trước khi tích hợp. Không tự động push hoặc deploy. Xem thêm [trạng thái đồ án](trang-thai-hien-tai.md) và [quy định phát triển](../AGENTS.md).
