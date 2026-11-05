# Giao diện hệ thống đồ án

Frontend sử dụng React, Vite và JavaScript. Website phục vụ quét mã nguồn Java, theo dõi 10 giai đoạn phân tích, xem cảnh báo, điểm CWSS, lịch sử, báo cáo và dữ liệu nghiên cứu.

## Phát triển và kiểm tra

Yêu cầu Node.js 20 và npm.

```bash
npm ci
node --test
npm run build
npm run dev
```

Sau khi chạy `npm run dev`, mở địa chỉ do Vite hiển thị, thường là `http://localhost:5173`.

## Kết nối backend

Mặc định frontend gọi `http://localhost:8765`. Có thể tạo file `.env.local` (không commit):

```env
VITE_API_BASE_URL=http://127.0.0.1:8765
```

Backend chạy qua Windows/WSL theo `../../docs/chay-tren-may-khac.md`. Không đặt khóa API, bearer token hoặc thông tin riêng vào biến `VITE_*`; những giá trị này có thể xuất hiện trong JavaScript phía trình duyệt.

## Chế độ dữ liệu

- **LIVE**: lấy tiến trình và cảnh báo thực từ backend.
- **Minh họa**: một số trang nghiên cứu có thể dùng dữ liệu ví dụ. Những số liệu này phải được ghi nhãn, không được tính như kết quả kiểm thử thật.
- **Dữ liệu nghiên cứu**: trang Dataset Explorer tải manifest, bản ghi và file xuất trực tiếp từ API. Nếu thiếu dataset riêng trong WSL, màn hình hiển thị lỗi thay vì tự tạo bản ghi.
- **CWSS**: mức ưu tiên có yếu tố tham chiếu, không phải xác suất một lỗ hổng thật.

Phạm vi Java và các CWE-22, CWE-78, CWE-79, CWE-89. Không nên suy diễn chức năng quét sang các ngôn ngữ hoặc loại lỗi khác.

## Tài liệu

Xem `../../docs/architecture.md`, `../../docs/api_and_demo.md` và `../../evaluation/bao-cao-kiem-thu-da-xac-minh.md`.
