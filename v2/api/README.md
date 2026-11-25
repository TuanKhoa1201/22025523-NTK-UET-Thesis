# HTTP API Adapter (`v2/api`)

Lớp HTTP API mỏng kết nối giao diện web React/Vite với pipeline phân tích OpenGrep + Qwen3.5-9B qua Ollama cục bộ + SQLite `ReviewStore`.

## Nguyên tắc bất biến

1. **Không viết lại logic lõi:** Toàn bộ kiểm chứng biên nhận quét, trích xuất bằng chứng Java (`v2.triage.evidence`), kiểm chứng trích dẫn & SHA-256 (`v2.triage.ollama`), chốt chặn `STALE_SOURCE` và hàng đợi SQLite (`v2.triage.store.ReviewStore`) được gọi trực tiếp từ gói `v2/triage`, `v2/baseline/fork`, và `v2/g1_integration` mà không sửa đổi tệp đã niêm phong.
2. **Tập luật Java CWE-22/CWE-89 và ngữ cảnh nâng cao trong `v2/api`:**
   - Mặc định dùng tập luật cục bộ `v2/api/rules/java_cwe22_cwe89.yml` (có thể ghi đè bằng `--rules-path` hoặc `NTK_RULES_PATH`), bật `taint_intrafile: true`, hỗ trợ nguồn Servlet/Spring/JAX-RS, sink SQL có ràng buộc kiểu để tránh dương tính giả `.execute()` phi-SQL và tránh báo nhầm `PreparedStatement`/`JdbcTemplate` dùng tham số `?`.
   - Làm giàu ngữ cảnh phương thức Java cân bằng ngoặc (`v2/api/java_context_v2.py`) cho annotation Spring lồng ngoặc, đính kèm helper cùng tệp ở xa đã xác minh SHA-256, nén đoạn mã trùng lặp và giới hạn prompt `<= 32_000` byte trước khi chuyển cho `OllamaClient`.
   - Bộ nhớ đệm tái sử dụng kết luận Qwen (`v2/api/qwen_cache.py`) **đã khóa an toàn (`SAFELY_DISABLED`)**: mặc định tắt (`NTK_ENABLE_QWEN_CACHE=0`), cấu hình bật cache bị từ chối rõ ràng và mọi phiên phân tích đều gọi Qwen cục bộ qua HTTP trực tiếp với raw capture từng lượt.
3. **Đọc không gây đột biến (Zero-Mutation Read):** Tất cả các endpoint `GET` mở `review.sqlite` qua URI chỉ-đọc `?mode=ro`, kết hợp bộ nhớ đệm đọc `assessments.jsonl` khóa theo SHA-256 nội dung để phát hiện tức thời mọi thay đổi dù chỉ 1 byte trên đĩa mà không sinh tệp journal.
4. **Bảo mật biên mạng & dữ liệu:**
   - Mặc định lắng nghe trên `127.0.0.1:8780` (hoặc IP riêng Tailscale `100.64.0.0/10` khi cấu hình tường minh).
   - Cấm tuyệt đối cổng `8765` và địa chỉ wildcard `0.0.0.0` mặc định.
   - Hạn chế `Access-Control-Allow-Origin` theo danh sách trắng cấu hình (`NTK_CORS_ORIGINS`), không dùng `*`.
   - Bắt buộc `Authorization: Bearer <NTK_API_TOKEN>` (so sánh hằng thời gian `hmac.compare_digest`) cho mọi thao tác khởi tạo quét và thay đổi quyết định Human Review.
   - Kiểm tra nghiêm ngặt URL GitHub và giải nén luồng ZIP chống path traversal, symlink, tỷ lệ nén bất thường (ZIP bomb) và giới hạn tệp Java `<= 1 MB`.
   - Cách ly hoàn toàn dữ liệu kiểm thử `mock` khỏi chế độ vận hành thực (`TEST_DATA_ISOLATED`).

## Các Endpoint REST (`ntk-thesis-web-api-1`)

| Phương thức & Đường dẫn | Mô tả | Xác thực |
|---|---|---|
| `GET /api/health` | Kiểm tra thực tế trạng thái API, binary OpenGrep, Ollama `/api/tags`, model Qwen và mã băm tập luật | Công khai tối thiểu / Đầy đủ khi có Bearer token |
| `GET /api/model` | Trạng thái kết nối Ollama cục bộ và model Qwen3.5-9B | Theo `NTK_API_READ_AUTH` |
| `POST /api/scan-jobs` | Tạo job phân tích dự án Java từ JSON `{repo_url, commit_sha?, no_llm?}` hoặc `multipart/form-data` (`file=.zip`) | Bắt buộc Bearer token |
| `GET /api/scan-jobs` | Danh sách các job phân tích | Theo `NTK_API_READ_AUTH` |
| `GET /api/scan-jobs/{job_id}` | Trạng thái thực tế 6 giai đoạn và tiến độ xử lý từng cảnh báo | Theo `NTK_API_READ_AUTH` |
| `GET /api/scans` | Danh sách các phiên quét hợp lệ trong vùng cho phép | Theo `NTK_API_READ_AUTH` |
| `GET /api/scans/{scan_id}` | Thống kê tổng hợp & provenance của phiên quét (alias `/summary`) | Theo `NTK_API_READ_AUTH` |
| `GET /api/scans/{scan_id}/findings` | Danh sách cảnh báo có lọc (`cwe`, `file`, `query`, `validated_status`, `human_review_state`) & phân trang | Theo `NTK_API_READ_AUTH` |
| `GET /api/scans/{scan_id}/findings/{finding_id}` | Chi tiết cảnh báo, các đoạn mã bằng chứng, `dataflow_trace`, trích dẫn Qwen và lịch sử kiểm duyệt | Theo `NTK_API_READ_AUTH` |
| `GET /api/scans/{scan_id}/review-queue` | Hàng đợi Human Review (`?include_all=false` ẩn duy nhất `CONFIRMED_FALSE` do người duyệt xác nhận) | Theo `NTK_API_READ_AUTH` |
| `POST /api/scans/{scan_id}/findings/{finding_id}/confirm-true` | Xác nhận cảnh báo thật (`{actor, reason}`) | Bắt buộc Bearer token |
| `POST /api/scans/{scan_id}/findings/{finding_id}/confirm-false` | Xác nhận cảnh báo giả kèm kiểm tra SHA-256 source drift; trả `409 STALE_SOURCE` nếu mã nguồn đổi | Bắt buộc Bearer token |
| `POST /api/scans/{scan_id}/findings/{finding_id}/reopen` | Mở lại cảnh báo về `OPEN` (`{actor, reason}`) | Bắt buộc Bearer token |
| `GET /api/scans/{scan_id}/findings/{finding_id}/history` | Lịch sử `events` và `rejected_decisions` của một cảnh báo | Theo `NTK_API_READ_AUTH` |
| `GET /api/scans/{scan_id}/review-history` | Toàn bộ lịch sử kiểm duyệt và quyết định bị từ chối của phiên quét | Theo `NTK_API_READ_AUTH` |
| `GET /api/scans/{scan_id}/report` | Xuất báo cáo JSON đầy đủ bảo toàn provenance và kết nối `export_pilot` | Theo `NTK_API_READ_AUTH` |

## Khởi động cục bộ

```powershell
$env:NTK_API_TOKEN = "<TOKEN_DO_NGUOI_VAN_HANH_DAT_TOI_THIEU_12_KY_TU>"
$env:NTK_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
python -X utf8 -B -m v2.api --host 127.0.0.1 --port 8780
```
