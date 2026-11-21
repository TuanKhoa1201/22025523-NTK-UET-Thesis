# Giao diện web đồ án — OpenGrep + Qwen3.5-9B + Human Review

Giao diện React/Vite kết nối với tầng HTTP API `v2/api` phục vụ phân tích mã nguồn Java (ưu tiên CWE-22 và CWE-89) qua 6 giai đoạn: tiếp nhận nguồn (GitHub HTTPS / ZIP), quét tĩnh OpenGrep, trích xuất bằng chứng và mã băm SHA-256, suy luận cục bộ Qwen3.5-9B qua Ollama, kiểm chứng trích dẫn mã nguồn và hàng đợi kiểm duyệt con người (Human Review) lưu trên SQLite.

## Phát triển, kiểm thử và đóng gói

Yêu cầu Node.js 20+ và npm.

```bash
npm ci
npm run lint
node --test tests/v2-*.test.cjs
npm run build
npm run dev
```

Sau khi chạy `npm run dev`, mở địa chỉ do Vite hiển thị (thường là `http://localhost:5173`).

## Kết nối backend `v2/api`

- Địa chỉ API có thể cấu hình qua biến môi trường `VITE_API_BASE_URL` (file `.env.local`, không commit) hoặc trực tiếp trên thanh kết nối trong giao diện.
- Cổng `8765` bị chặn theo chính sách dự án; URL API không được chứa thông tin xác thực nhúng, query string hoặc fragment.
- **Không đặt API Bearer Token trong biến `VITE_*`** vì biến `VITE_*` được đóng gói vào JavaScript phía trình duyệt. Token phiên chỉ nhập trong RAM tại giao diện và bị ràng buộc chặt theo đúng API origin; khi đổi hoặc đặt lại origin, token của origin trước được xóa để không gửi sang origin khác.

## Nguyên tắc hiển thị dữ liệu

- Tách biệt hai trục: nhận định kiểm chứng của mô hình (`SUPPORTED`, `REFUTED`, `UNDETERMINED`) và trạng thái kiểm duyệt của con người (`OPEN`, `CONFIRMED_TRUE`, `CONFIRMED_FALSE`).
- Cảnh báo `REFUTED` từ mô hình vẫn giữ trạng thái `OPEN` cho tới khi người kiểm duyệt xác nhận, đồng thời máy chủ kiểm tra toàn vẹn SHA-256 (trả `409 STALE_SOURCE` nếu mã nguồn thay đổi).
- Cảnh báo thiếu bằng chứng hoặc trích dẫn không khớp được hạ cấp về `UNDETERMINED` để giữ lại kiểm tra, không tự động loại bỏ.
- Áp dụng nguyên tắc fail-closed: không suy ra `NO_FINDINGS` khi phản hồi API thiếu danh sách findings và tổng số; không mặc định nguồn gốc `REAL_SCAN` khi thiếu `data_origin` hoặc bằng chứng capture chưa được xác minh; cảnh báo khi danh sách lịch sử từ API bị thiếu hoặc không khớp `total_count`.
- Dữ liệu kiểm thử mô phỏng (`MOCK_SYNTHETIC_TEST`) bị cách ly khỏi giao diện vận hành thực và báo cáo xuất ra.

Xem thêm mô tả hợp đồng HTTP API tại `../../v2/api/README.md`.
