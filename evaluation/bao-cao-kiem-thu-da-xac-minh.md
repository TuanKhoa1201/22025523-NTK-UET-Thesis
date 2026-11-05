# Báo cáo kết quả kiểm thử hệ thống đồ án

Ngày ghi nhận: 05/11/2026. Dữ liệu ở đây là kết quả kiểm tra đã được ghi trong biên bản chạy trên laptop cá nhân. Không tự tạo số liệu mới.

## 1. Quét mã nguồn Java

- Bộ thử: 100 file Java thuộc OWASP BenchmarkJava.
- Phạm vi quét: một tập con, không phải toàn bộ BenchmarkJava.
- Kết quả: **154 ứng viên cảnh báo**.
- Quyết định xử lý: `REPORT` 25, `REVIEW` 108, `SUPPRESS` 21.
- Trạng thái bằng chứng: `PROVEN_TAINT` 25, `UNKNOWN` 108, `PROVEN_SAFE` 21.
- Phạm vi phát hiện: CWE-22, CWE-78, CWE-79, CWE-89.

| Tín hiệu | Số lượng | Cách diễn giải |
|---|---:|---|
| REPORT | 25 | Cảnh báo được giữ lại ưu tiên kiểm tra |
| REVIEW | 108 | Thiếu bằng chứng để kết luận |
| SUPPRESS | 21 | Có căn cứ hạ ưu tiên trong phạm vi kiểm tra |
| PROVEN_TAINT | 25 | Có bằng chứng đường dữ liệu đến thao tác nhạy cảm |
| UNKNOWN | 108 | Không đủ bằng chứng, không đồng nghĩa an toàn |
| PROVEN_SAFE | 21 | Có bằng chứng an toàn trong phạm vi mã đã phân tích |

Không thể suy ra precision, recall hoặc F1 chỉ từ các con số này, vì chưa có bộ nhãn TP/FP độc lập đã công bố cho toàn bộ 154 cảnh báo. Số `SUPPRESS` không chứng minh 21 false positives đã được con người kiểm tra. Không được gọi kết quả quét 100 file là đánh giá toàn bộ dự án OWASP BenchmarkJava.

## 2. Dataset nghiên cứu

Bốn file JSONL đã được xác minh lại bằng SHA-256 và số dòng vào ngày 05/11/2026.

| Bộ dữ liệu | Dòng | SHA-256 |
|---|---:|---|
| Track A - dữ liệu tin cậy | 275 | `d179fa063b6a0bb0a8e5080aa0391564a71d22e4a816aa33ecff5fe9a6a423eb` |
| Track B - huấn luyện chính | 781 | `2bb70c53ee12cc9e677895488479a58ef1ffbfd4b25d9d5055d6db5d7df8899f` |
| Development - chọn checkpoint | 166 | `dfafd66d66957cf83b0f105ef0c98c63db62ff41456a822ea59f02a53801622d` |
| Quarantine - loại khỏi huấn luyện | 137 | `f6ec8d347d60ea70259dc5d8e446c33ba9b4eb3c280066b6d6a806d909bc3005` |

Track A nằm hoàn toàn trong Track B. Tổng số bản ghi duy nhất là **1.084** theo công thức 781 + 166 + 137, không cộng Track A thêm lần nữa.

API `GET /api/datasets/manifest` đã trả về `status=OK`. API bản ghi Track B trả 20 bản ghi trên trang đầu, xác nhận tổng 781 bản ghi.

| Định dạng xuất | Dung lượng đã ghi nhận |
|---|---:|
| CSV | 417.624 byte |
| JSONL | 815.251 byte |
| XLSX | 135.280 byte |

Đây là kiểm tra lưu file thành công, chưa phải xác minh rằng tất cả ô trong mỗi file xuất đều khớp từng trường dataset gốc.

## 3. Biên bản huấn luyện và kết quả lịch sử

Manifest của backend cung cấp biên bản hoàn tất quá trình tinh chỉnh với cấu hình:

- Model gốc: `Qwen/Qwen2.5-Coder-0.5B-Instruct`.
- Bộ train chính: Track B, 781 bản ghi.
- Development: 166 bản ghi.
- Checkpoint được chọn: epoch 3, adapter thuộc cấu hình nghiên cứu hiện tại.
- Macro-F1 Development do biên bản ghi nhận: `0.9609474124056009`.
- Macro-F1 holdout do biên bản ghi nhận: `0.9854132091178436`.
- Holdout ECE do biên bản ghi nhận: `0.01552490234375`.
- Tỷ lệ JSON hợp lệ trong biên bản: `1.0`.
- SHA-256 adapter được biên bản công bố: `176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`.

**Trạng thái bằng chứng:** Các chỉ số trên đã xuất hiện trong manifest và receipt của backend, nhưng chưa được chạy lại độc lập trong lần kiểm thử ngày 05/11. Không xem các chỉ số API role classification này là độ chính xác phát hiện lỗ hổng của pipeline đầy đủ.

## 4. Chấm điểm

Backend có code MITRE CWSS 1.0.1, các module suy luận và nguồn gốc metric. Điểm là giá trị ưu tiên phụ thuộc bằng chứng và các tham số môi trường giả định; chưa có kiểm định độc lập chứng minh điểm phản ánh xác suất khai thác, mức độ nghiêm trọng thực tế trong mọi triển khai hay true/false positive.

Những yếu tố chưa xác minh như quyền truy cập, tài sản, Internet và kiểm soát môi trường phải được ghi rõ giả định, không tự khẳng định từ mã nguồn.

## 5. Giới hạn và tái lập

- Repository không phân phối tập dataset gốc, checkpoint LoRA, database và scan archive riêng.
- Kết quả vận hành được ghi từ laptop cá nhân, không phải phép đo trên GitHub Actions.
- Chạy lại cần khóa version, checksum, phạm vi quét, cấu hình tài nguyên và corpus.
- Các kết luận về độ chính xác phải dùng nhãn độc lập; chưa có trong báo cáo này.
- Dữ liệu từ phần mềm bên thứ ba chỉ được công bố ở mức metadata, tỷ lệ tổng hợp và checksum phù hợp với giấy phép.

Tài liệu liên quan: `docs/ket-qua-kiem-thu-he-thong-2026-11-05.md`, `research/dataset_provenance.md` và `research/finetuning_protocol.md`.
