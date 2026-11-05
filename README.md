# Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn

Đồ án tốt nghiệp ngành Công nghệ thông tin, Trường Đại học Công nghệ, Đại học Quốc gia Hà Nội.

Đây là nguyên mẫu phục vụ nghiên cứu bảo mật mã nguồn Java. Hệ thống sử dụng OpenGrep, phân tích cú pháp và luồng dữ liệu Java, mô hình Qwen chạy cục bộ và cơ chế ưu tiên cảnh báo. Kết quả cần được kiểm chứng, không phải chứng nhận mã nguồn an toàn.

## Có gì trong repository?

- `apps/22025523-thesis/` - website React/Vite, nhập dự án GitHub hoặc ZIP, theo dõi các bước quét, xem cảnh báo, lịch sử, bằng chứng và điểm CWSS.
- `backend/ntk-production-v2/` - REST API Python, bộ quy tắc OpenGrep, phân tích Java AST, bộ kết nối IRIS, suy luận Qwen LoRA, dữ liệu nghiên cứu, lưu kết quả và kiểm thử.
- `scripts/windows/` và `scripts/linux/` - cấu hình, khởi động, dừng và kiểm tra hệ thống trên Windows 11 với WSL2.
- `.github/workflows/` - kiểm thử tự động đối với mã nguồn có thể công khai.
- `docs/`, `research/`, `evaluation/` - kiến trúc, giao thức, kiểm thử và các giới hạn nghiên cứu.

Phạm vi phát hiện hiện tại: **CWE-22, CWE-78, CWE-79, CWE-89**, chỉ áp dụng với mã nguồn Java. OpenGrep đưa ra ứng viên cảnh báo; kết quả IRIS/AST và mô hình giúp bổ sung bằng chứng. Hệ thống phân loại `REPORT`, `REVIEW`, `SUPPRESS`; không đồng nhất những trạng thái này với kết luận đúng/sai của chuyên gia.

## Clone và kiểm tra mã nguồn

Yêu cầu: Git, Node.js 20, npm, Python 3.11 và JDK 17. Có thể chạy các kiểm thử mã nguồn mà không cần GPU, dataset hoặc checkpoint:

```bash
git clone https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis.git
cd 22025523-NTK-UET-Thesis
python3 scripts/verify-repository.py
bash scripts/linux/test-backend-stdlib.sh
cd apps/22025523-thesis
npm ci
node --test
npm run build
```

Kiểm thử Java AST và các phép tính thuần Python không chứng minh toàn bộ pipeline có model chạy thành công.

## Chạy đầy đủ trên Windows 11 và WSL2

Xem [hướng dẫn chuyển hệ thống sang máy khác](docs/chay-tren-may-khac.md).

Chế độ vận hành đầy đủ cần thêm OpenGrep, các phụ thuộc Python, bộ trọng số Qwen tương thích, checkpoint LoRA được tinh chỉnh và dataset VNext 3.1 nếu muốn dùng trang dữ liệu nghiên cứu. **Những artifact này không được đóng gói vào Git**. Clone xong mà chưa có checkpoint sẽ chưa thể suy luận bằng model đã fine-tune. Mã nguồn không tự tải model qua đám mây khi chạy.

Trên Windows, sau khi chuẩn bị WSL và các artifact cục bộ:

```powershell
.\scripts\windows\check-environment.ps1
.\scripts\windows\configure-backend.ps1 -BaseModelPath "/home/user/models/qwen-base" -AdapterPath "/home/user/models/adapter-best" -DatasetPath "/home/user/data/dataset_vnext_3_1"
.\scripts\windows\start-backend.ps1
.\scripts\windows\check-backend.ps1 -CheckDatasets
```

Thay ví dụ đường dẫn bằng **đường dẫn có thật trong WSL**. Tên thư mục không phải tên người dùng hay nơi bắt buộc lưu model.

Trong cửa sổ khác:

```powershell
cd apps\22025523-thesis
npm ci
npm run dev
```

Website mặc định dùng API `http://localhost:8765`. Kiểm tra trang dữ liệu và thực hiện quét thử một dự án Java nhỏ trước khi quét repository lớn. Không đưa cổng backend lên Internet nếu chưa có xác thực và giới hạn truy cập.

## Dữ liệu và kết quả đã xác minh

Ngày 05/11/2026, lần thử trên laptop với 100 file Java của OWASP BenchmarkJava ghi nhận 154 cảnh báo, trong đó 25 `REPORT`, 108 `REVIEW`, 21 `SUPPRESS`. Đây là kết quả vận hành có giới hạn, **không phải số đo precision hoặc recall**. Bốn bộ dataset được xác minh SHA-256 và số dòng; API xuất CSV, JSONL và XLSX chạy thành công.

Xem [báo cáo kiểm thử có căn cứ](evaluation/bao-cao-kiem-thu-da-xac-minh.md), [nguồn gốc dataset](research/dataset_provenance.md) và [cơ chế chấm điểm](research/scoring_v1_2.md).

## Giới hạn và quyền sử dụng

- Hệ thống phân tích mã nguồn Java, không kiểm chứng mọi CWE, mọi ngôn ngữ hoặc mọi đường đi dữ liệu.
- Chế độ IRIS gốc và CodeQL cần upstream, giấy phép và cấu hình riêng. Không được coi AST dự phòng là IRIS gốc.
- CWSS là thước đo ưu tiên trong điều kiện giả định và bằng chứng hiện có, không phải xác suất một cảnh báo đúng.
- Dataset, checkpoint, cache, database, thông tin đăng nhập và mã nguồn bên thứ ba không được phát hành kèm repository này.
- Xem [thông báo phần mềm bên thứ ba](THIRD_PARTY_NOTICES.md) và [các vấn đề đang theo dõi](docs/known_issues.md).
