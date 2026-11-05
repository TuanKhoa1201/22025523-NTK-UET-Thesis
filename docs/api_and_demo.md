# Kết nối API và kiểm thử bản demo

Hệ thống đồ án được vận hành cục bộ với frontend React/Vite trên Windows và backend Python trong WSL2. API mặc định ở `http://127.0.0.1:8765`, website dùng cổng Vite được thông báo khi chạy `npm run dev`.

## Bắt đầu

Đọc `docs/chay-tren-may-khac.md`. Để kiểm tra backend:

```powershell
.\scripts\windows\check-backend.ps1
.\scripts\windows\check-backend.ps1 -CheckDatasets
```

Các đường dẫn có thể dùng trong bản đang chạy:

| API | Mục đích |
|---|---|
| `GET /api/health` | Kiểm tra dịch vụ và khả năng sẵn sàng |
| `GET /api/model` | Trạng thái model cục bộ |
| `POST /api/scan-jobs` | Tạo tác vụ quét Java |
| `GET /api/scan-jobs/{job_id}` | Tiến độ quét |
| `GET /api/scans/{scan_id}/summary` | Tổng quan kết quả |
| `GET /api/scans/{scan_id}/findings/page` | Phân trang cảnh báo |
| `GET /api/scans/{scan_id}/pipeline-trace` | Nhật ký 10 giai đoạn |
| `GET /api/datasets/manifest` | Nguồn gốc và thống kê dataset |
| `GET /api/datasets/{dataset_id}/records` | Danh sách bản ghi |
| `GET /api/datasets/{dataset_id}/export?format=csv` | Xuất CSV, JSONL hoặc XLSX |

Chỉ sử dụng route có thật trong phiên bản backend đang chạy. HTTP 200 chưa chứng minh nội dung đã đúng; cần kiểm tra số dòng, checksum, phân trang và trạng thái từng tác vụ.

## Chạy thử

1. Kiểm tra health, OpenGrep, JDK và adapter.
2. Chạy fixture Java quy mô nhỏ trong `backend/ntk-production-v2/fixtures/`.
3. Kiểm tra đủ 10 stage, tình trạng ghi lưu và khả năng tải lại kết quả.
4. Đối chiếu summary với tất cả trang findings, không chỉ trang đầu.
5. Phân biệt `PROVEN_TAINT`, `PROVEN_SAFE`, `UNKNOWN` và `REPORT`, `REVIEW`, `SUPPRESS`.
6. Xem CWSS, nguồn metric và giả định của kịch bản tham chiếu.
7. Với dataset gốc, kiểm tra manifest cùng xuất CSV, JSONL, XLSX.

Bản kiểm thử thực tế ngày 05/11/2026 được ghi trong `evaluation/bao-cao-kiem-thu-da-xac-minh.md`.

## Bảo mật

Không đặt khóa truy cập trong `.env.local` của Vite, không đưa token vào log và không công khai dịch vụ REST chỉ dựa vào hạn chế CORS. Hạn chế số lượng file và dung lượng khi tiếp nhận ZIP hoặc dự án ngoài.
