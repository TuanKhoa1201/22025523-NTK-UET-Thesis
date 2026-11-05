# Danh mục bằng chứng và trạng thái xác minh

Cập nhật ngày 05/11/2026.

| Nội dung | Bằng chứng đang có | Mức độ xác nhận |
|---|---|---|
| Backend và API | Health báo OK trên laptop | Xác minh khả năng đáp ứng API |
| Dataset | Bốn file JSONL có SHA-256 và số dòng trùng manifest | PASS |
| Truy xuất dữ liệu | API manifest và 20 record đầu Track B trả hợp lệ | PASS |
| Xuất dữ liệu | CSV 417624, JSONL 815251, XLSX 135280 byte | PASS đối với file được tạo |
| Quét OWASP BenchmarkJava | 100 file Java, 154 findings | Kết quả chạy có giới hạn |
| Triage | REPORT 25, REVIEW 108, SUPPRESS 21 | Kết quả vận hành, chưa phải TP/FP độc lập |
| Bằng chứng luồng | PROVEN_TAINT 25, UNKNOWN 108, PROVEN_SAFE 21 | Kết quả engine trên tập con |
| Huấn luyện | Receipt có macro-F1, ECE, adapter hash | Có biên bản lịch sử, chưa chạy lại độc lập |
| CWSS | Có module và API, gồm metric provenance | Chưa được hiệu chỉnh trên nhãn rủi ro thực tế |
| GitHub | Frontend build thành công khi đồng bộ | Không thay cho E2E với model |

Để xác nhận các bước tiếp theo, xem `evaluation/huong-dan-tai-lap-thuc-nghiem.md`. Không thêm dữ liệu riêng hoặc file chứa thông tin đăng nhập.
