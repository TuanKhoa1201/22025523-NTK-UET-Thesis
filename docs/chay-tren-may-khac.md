# Cài đặt hệ thống đồ án trên máy Windows khác

Hướng dẫn này tách hai mục tiêu: kiểm tra mã nguồn từ GitHub, và chạy pipeline thực tế với model cục bộ. Máy mới có thể thực hiện mục tiêu thứ nhất chỉ với phần mềm nguồn mở phổ biến. Mục tiêu thứ hai cần thêm các artifact riêng được cung cấp hợp pháp.

## 1. Điều kiện sử dụng

- Windows 11, WSL2 Ubuntu, Git, Node.js 20, npm.
- Trong Ubuntu: Python 3.10 hoặc 3.11, `python3-venv`, `python3-pip`, Git, curl, JDK 17, OpenGrep.
- Để sử dụng suy luận cục bộ: model `Qwen/Qwen2.5-Coder-0.5B-Instruct` đã tải về và checkpoint LoRA tương thích. GPU CUDA được khuyến nghị; khả năng chạy CPU và thời gian xử lý cần được kiểm tra riêng.
- Dataset phục vụ trang nghiên cứu chỉ cần khi dùng Data Explorer; gồm bốn file JSONL có checksum đã công bố trong báo cáo. Dataset **không nằm trong repository**.

Nếu máy mới chưa có model và adapter, không được coi thao tác clone thành công là đã chạy xong hệ thống đầy đủ.

## 2. Cài đặt WSL2

Mở PowerShell với quyền quản trị, nếu máy chưa có WSL:

```powershell
wsl --install -d Ubuntu
```

Trong Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl openjdk-17-jdk
```

Cài OpenGrep theo tài liệu phát hành chính thức của dự án tại <https://github.com/opengrep/opengrep>. Kiểm tra `opengrep --version`, `java -version`, `git --version`. Không dùng OpenGrep khác phiên bản khi so sánh số lượng cảnh báo mà không ghi rõ phiên bản.

## 3. Tải mã nguồn và chạy kiểm thử không cần model

Trong PowerShell:

```powershell
git clone https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis.git
cd 22025523-NTK-UET-Thesis
.\scripts\windows\check-environment.ps1
.\scripts\windows\verify-source.ps1
```

Trong WSL, nếu cần tạo môi trường Python:

```bash
bash /mnt/c/duong-dan-den-repository/scripts/linux/setup-runtime.sh
```

Nên dùng `wslpath` để chuyển đường dẫn Windows sang WSL thay vì chép nguyên đường dẫn ví dụ. Có thể chạy trực tiếp các script từ thư mục clone trong WSL.

Lưu ý: `setup-runtime.sh` cài toàn bộ dependencies Python. Cài PyTorch và CUDA phải phù hợp driver thực tế. Khi chỉ kiểm thử mã nguồn, không cần cài thư viện suy luận lớn.

## 4. Chuẩn bị model và dữ liệu

Lưu model base và adapter trong thư mục ngoài Git, ví dụ:

```text
/home/user/models/qwen-base/config.json
/home/user/models/adapter-best/adapter_config.json
/home/user/models/adapter-best/adapter_model.safetensors
/home/user/data/dataset_vnext_3_1/*.jsonl
```

Tải model base từ nguồn được cấp phép và chuẩn bị checkpoint LoRA tương ứng thông qua bản sao lưu được phép chuyển giao. Không dùng adapter bất kỳ và gọi đó là model của nghiên cứu. Không tự tạo các dòng dataset để vượt qua bước kiểm tra checksum.

Nếu cần xác minh dataset, xem `evaluation/bao-cao-kiem-thu-da-xac-minh.md`. Trọng số adapter có dấu SHA-256 ghi trong provenance; phải xác minh file thật trước khi công bố đã tái lập cùng mô hình.

## 5. Tạo cấu hình riêng, không commit

Trong PowerShell tại thư mục clone:

```powershell
.\scripts\windows\configure-backend.ps1 `
  -BaseModelPath "/home/user/models/qwen-base" `
  -AdapterPath "/home/user/models/adapter-best" `
  -DatasetPath "/home/user/data/dataset_vnext_3_1"
```

Script tạo `backend/ntk-production-v2/config/ntk_backend.env`, được Git bỏ qua. Sửa `PYTHON_BIN`, `NTK_INFERENCE_DEVICE` và `NTK_OPENGREP_BIN` theo môi trường thực tế. Không đưa thông tin đăng nhập hoặc đường dẫn cá nhân vào README.

Nếu không có dataset, bỏ tham số `-DatasetPath`. Khi đó backend có thể chạy quét nhưng API dữ liệu nghiên cứu chưa thể trả về bộ dataset chính thức.

## 6. Khởi động backend và frontend

Trong PowerShell:

```powershell
.\scripts\windows\start-backend.ps1
.\scripts\windows\check-backend.ps1
.\scripts\windows\check-backend.ps1 -CheckDatasets
```

Mặc định API ở `http://127.0.0.1:8765`. Script backend quản lý PID và log trong các thư mục riêng. Nếu máy đang dùng cổng đó, phải giải quyết xung đột cổng trước; không tự ý kill một tiến trình lạ.

Mở cửa sổ PowerShell khác:

```powershell
cd apps\22025523-thesis
npm ci
npm run dev
```

Mở URL do Vite hiển thị, thường là `http://localhost:5173`. Khi muốn dùng cổng backend khác, đặt `VITE_API_BASE_URL` trong file `.env.local`, không commit file này. Không để token nhạy cảm trong biến môi trường Vite.

## 7. Nghiệm thu chức năng

1. Kiểm tra `/api/health`, OpenGrep và Java sẵn sàng, đường dẫn model và adapter tồn tại.
2. Kiểm tra `/api/datasets/manifest` khi đã có đủ dataset.
3. Chạy một dự án Java nhỏ từ GitHub hoặc ZIP. Không dùng dữ liệu riêng chưa được cấp phép.
4. Theo dõi 10 giai đoạn thực tế; trạng thái hoàn tất chỉ có ý nghĩa khi có kết quả đã lưu.
5. Xem summary, finding pagination, evidence `PROVEN_TAINT`, `PROVEN_SAFE`, `UNKNOWN`, CWSS và các quyết định triage.
6. Tải lại trình duyệt, kiểm tra lịch sử và chức năng xuất dữ liệu.
7. Khi kiểm thử độ chính xác, phải có nhãn tham chiếu độc lập; không dùng số `REPORT` để suy ra true positives.

Dừng backend bằng `scripts/windows/stop-backend.ps1`. Script từ chối dừng nếu có scan đang hoạt động. Dùng `-Force` chỉ khi đã quyết định ngắt tiến trình và chấp nhận rủi ro mất tác vụ.

## 8. Giới hạn khi clone

GitHub chứa mã nguồn và fixture kiểm thử, **không chứa trọng số Qwen, checkpoint LoRA, dataset nghiên cứu hay bản chạy IRIS gốc đã cài sẵn**. Việc cài mới có thể phát sinh sự khác biệt do driver GPU, CUDA, JDK, môi trường Python, OpenGrep và mã upstream. Cần lưu phiên bản và checksum trong biên bản nghiệm thu.

Không mở backend cho Internet nếu chưa có xác thực, giới hạn truy cập và phương án bảo vệ tài nguyên.
