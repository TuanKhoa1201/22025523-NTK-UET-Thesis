# 22025523 - NTK Java Vulnerability Detection Platform

Graduation thesis at VNU University of Engineering and Technology.

Thesis: Phat trien cong cu phat hien lo hong ma nguon ket hop phan tich tinh nguon mo va mo hinh ngon ngu lon.

## Architecture

- OpenGrep OSS: Java vulnerability candidate detection.
- OpenJDK 17 JavacTask AST: program and dataflow analysis.
- IRIS-inspired semantic analysis.
- Locally fine-tuned Qwen2.5-Coder-0.5B-Instruct LoRA.
- Heuristic SAST Evidence Fusion V1.2 and alert triage.
- React/Vite dashboard with 10-stage visualization.

## Supported CWE categories

CWE-022, CWE-078, CWE-079 and CWE-089.

Source coverage does not imply coverage of all vulnerabilities.
SAST scores are heuristic priorities, not CVSS or calibrated probabilities.

## Repository structure

- apps/22025523-thesis/ - React/Vite frontend.
- backend/ntk-production-v2/ - Python API, OpenGrep, AST and LoRA integration.

## Frontend commands

cd apps/22025523-thesis
npm ci
npm run dev

## Development status

Đã kiểm thử quy trình quét mã nguồn Java và kết nối dữ liệu nghiên cứu trên laptop. Kết quả quét giới hạn phạm vi đã được lưu và truy xuất lại; đánh giá độ chính xác độc lập tiếp tục là phần việc nghiên cứu.

## Research history

https://github.com/TuanKhoa1201/NTK-UET-Thesis

Frontend migration commit: 804d520
Backend migration commit: a02edc9

The historical repository includes earlier IRIS and CodeQL research.
Current production code is organized separately in this repository.

## Attribution and limitations

See THIRD_PARTY_NOTICES.md and backend/ntk-production-v2/LICENSE.
The project is an academic prototype. Findings require verification.
Private datasets, scan archives and model weights are not bundled.

## Kết quả kiểm thử mới nhất - 05/11/2026

Hệ thống đồ án đã chạy thành công quy trình quét mã nguồn Java trên laptop,
từ phát hiện vị trí nghi vấn, đối chiếu bằng chứng đến hỗ trợ phân loại API,
chấm điểm ưu tiên và lưu kết quả. Trong lần kiểm thử với 100 tệp Java thuộc
OWASP BenchmarkJava, hệ thống ghi nhận 154 cảnh báo. Đây là lần quét giới hạn
phạm vi, không phải đánh giá toàn bộ dự án hoặc chứng nhận độ chính xác.

Bộ dữ liệu nghiên cứu đã được xác minh checksum và kiểm tra chức năng
xuất CSV, JSONL, XLSX. Xem thêm tại
[kết quả kiểm thử hệ thống](docs/ket-qua-kiem-thu-he-thong-2026-11-05.md).
Dữ liệu nội bộ và trọng số mô hình không được đưa lên repository.
