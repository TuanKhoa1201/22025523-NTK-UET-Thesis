# Kết quả kiểm thử hệ thống đồ án - ngày 05/11/2026

Tài liệu ghi lại những kết quả đã kiểm tra trên laptop cá nhân. Các con số bên dưới
phản ánh những lần chạy thực tế, không thay thế đánh giá độ chính xác trên toàn bộ mã nguồn Java.

## Kiểm thử quá trình phân tích

- Hệ thống dùng OpenGrep để tìm vị trí nghi vấn, phân tích cấu trúc và luồng dữ liệu
  để đối chiếu bằng chứng, sau đó dùng mô hình ngôn ngữ cục bộ hỗ trợ phân loại vai trò API.
- Phạm vi hiện tại là mã nguồn Java, tập trung vào CWE-22, CWE-78, CWE-79 và CWE-89.
- Đã quét tập con 100 tệp Java trong OWASP BenchmarkJava, không phải toàn bộ repository.
- Kết quả có 154 cảnh báo: 25 REPORT, 108 REVIEW và 21 SUPPRESS.
- Trạng thái bằng chứng: 25 PROVEN_TAINT, 21 PROVEN_SAFE và 108 UNKNOWN.
- Quyết định triage chỉ mang ý nghĩa xử lý cảnh báo, không phải nhãn đúng/sai đã được xác minh độc lập.

## Dữ liệu phục vụ huấn luyện và đánh giá

| Tập dữ liệu | Số bản ghi | SHA-256 |
| --- | ---: | --- |
| Track A - dữ liệu tin cậy | 275 | d179fa063b6a0bb0a8e5080aa0391564a71d22e4a816aa33ecff5fe9a6a423eb |
| Track B - dữ liệu huấn luyện chính | 781 | 2bb70c53ee12cc9e677895488479a58ef1ffbfd4b25d9d5055d6db5d7df8899f |
| Dữ liệu đánh giá | 166 | dfafd66d66957cf83b0f105ef0c98c63db62ff41456a822ea59f02a53801622d |
| Dữ liệu chờ rà soát | 137 | f6ec8d347d60ea70259dc5d8e446c33ba9b4eb3c280066b6d6a806d909bc3005 |

Track A là tập con của Track B, vì vậy không được tính trùng 275 bản ghi.
Tổng số bản ghi duy nhất của bốn tập là 1.084.

API dữ liệu đã trả về manifest hợp lệ và cho phép truy xuất 20 bản ghi đầu tiên
trong 781 bản ghi Track B. Đã kiểm tra xuất CSV, JSONL và XLSX thành công,
ứng với dung lượng 417624, 815251 và 135280 byte.

## Lưu trữ và tái lập

Repository chỉ chứa mã nguồn, quy tắc phân tích và tài liệu nghiên cứu.
Dataset gốc, trọng số mô hình, checkpoint, tệp kết quả quét, SQLite
và thông tin đăng nhập được lưu riêng trên máy, không đưa lên GitHub.
