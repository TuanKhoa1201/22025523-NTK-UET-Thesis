# Hướng dẫn tái lập kết quả thực nghiệm

Tài liệu này mô tả cách kiểm tra lại các tuyên bố đã công bố. Nó không thay thế bộ dataset hoặc model chưa được chuyển giao.

## A. Kiểm tra không cần artifact riêng

```bash
python3 scripts/verify-repository.py
bash scripts/linux/test-backend-stdlib.sh
cd apps/22025523-thesis
npm ci
node --test
npm run build
```

Các bước này xác minh cú pháp, thư viện chuẩn, Java AST được biên dịch và frontend. Chúng không chạy inference Qwen hoặc quét toàn bộ dự án.

## B. Xác minh artifact riêng

Nhận bản sao model, LoRA adapter và dataset từ nguồn được phép sử dụng. Lưu ngoài Git, không thay đổi nội dung để khớp số dòng. Kiểm tra SHA-256 của bốn file dataset theo `bao-cao-kiem-thu-da-xac-minh.md`. Kiểm tra adapter với SHA-256 đã ghi trong receipt, xác nhận base model và tokenizer cùng phiên bản.

## C. Chạy kiểm thử thực tế

1. Ghi ngày, hệ điều hành, WSL, JDK, OpenGrep, Python, Torch, CUDA, GPU và revision model.
2. Lưu SHA-256 dataset, adapter và input ZIP hoặc commit GitHub.
3. Chạy lần kiểm thử với phạm vi cụ thể, bảo toàn log 10 bước, trạng thái model và thời gian.
4. Lưu response summary, findings paginated và CWSS vào thư mục riêng.
5. Kiểm tra tổng số findings và decisions, sau đó đối chiếu thủ công một mẫu tình huống.
6. Chỉ báo cáo TP/FP/FN khi có ground truth độc lập và quy tắc matching rõ ràng.
7. So sánh từng cấu hình trên cùng tập dữ liệu đã khóa, tránh thay đổi corpus giữa các lần đo.

## D. Bộ dữ liệu phải tách biệt

Track A 275 là subset của Track B 781. Development 166 không dùng để train. Quarantine 137 bị loại, không dùng làm đánh giá chung. Holdout phải được định danh và cách ly trong biên bản riêng. Không cộng chồng các bản ghi trùng.

## E. Mẫu báo cáo

| Trường | Nội dung cần ghi |
|---|---|
| Mã nguồn hệ thống | Commit GitHub |
| Đầu vào | Repository, commit, số file Java được nhận |
| Phạm vi CWE | 22, 78, 79, 89 |
| Cấu hình engine | OpenGrep, AST fallback hoặc IRIS gốc, model LoRA |
| Nguồn gốc | Hash của model, adapter, corpus, dataset |
| Chỉ số | Findings, triage, evidence, thời gian, TP/FP/FN nếu có |
| Giới hạn | Phần chưa bao phủ, trường hợp không xác định, lỗi cấu hình |

Không thêm số liệu suy đoán vào kết quả đã xác minh.
