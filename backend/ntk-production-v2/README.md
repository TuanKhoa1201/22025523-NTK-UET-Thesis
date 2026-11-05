# Backend hệ thống đồ án

Backend Python cung cấp API quét mã nguồn Java, dùng OpenGrep, phân tích AST với JDK 17, bộ kết nối IRIS, Qwen LoRA chạy cục bộ, bằng chứng triage, CWSS và lưu trữ JSON/SQLite.

## Thành phần chính

| Thành phần | Mã nguồn |
|---|---|
| REST API, điều phối và suy luận | `scripts/ntk_web_backend_service.py` |
| Tiến trình 10 bước và dữ liệu nghiên cứu | `scripts/ntk_pipeline_telemetry_and_datasets.py` |
| Java AST, luồng dữ liệu, triage | `scripts/ntk_alert_verification.py` |
| Java AST parser | `scripts/javac_ast_bridge/NtkJavacAstExtractor.java` |
| Phân tích IRIS gốc khi được cấu hình | `scripts/ntk_original_iris_adapter.py`, `scripts/ntk_original_iris_worker.py` |
| CWSS và nguồn metric | `scripts/ntk_cwss_workflow.py`, `scripts/ntk_cwss_v101.py` và các module hỗ trợ |
| Huấn luyện model | `scripts/eo06_main_train_eval_e2e_pipeline.py` |
| Bộ quy tắc Java | `rules/ntk_opengrep_java_ruleset_v1_4.yaml` |
| Kiểm thử | `tests/`, `fixtures/` |

Chế độ mặc định là Java AST. Không được coi việc có adapter IRIS trong repository là đã chạy IRIS gốc khi thiếu CodeQL/upstream.

## Chạy trên máy khác

Hướng dẫn chuẩn nằm ở `../../docs/chay-tren-may-khac.md`. Trên WSL2:

```bash
bash scripts/linux/setup-runtime.sh
bash scripts/linux/check-environment.sh
bash scripts/linux/start-backend.sh
```

Các script trên nằm ở cấp root repository, không phải bên trong thư mục backend. Cần có file `config/ntk_backend.env` riêng, model gốc, checkpoint LoRA và OpenGrep đã cài. Nếu cần trang dữ liệu, cấu hình thêm dataset VNext 3.1.

Chỉ kiểm thử các phần không phụ thuộc model bằng:

```bash
bash scripts/linux/test-backend-stdlib.sh
```

## Phạm vi

Hệ thống hỗ trợ Java, CWE-22, CWE-78, CWE-79, CWE-89. Model phân loại API role, còn triage hợp nhất nhiều bằng chứng và có trạng thái chưa đủ dữ liệu. CWSS là điểm ưu tiên, không phải phương pháp xác minh TP/FP.

Không commit trọng số, dataset, SQLite, file kết quả quét, credential hoặc file cấu hình riêng. Những giá trị môi trường đã ghi trong `config/ntk_backend.env.example` chỉ là ví dụ.
