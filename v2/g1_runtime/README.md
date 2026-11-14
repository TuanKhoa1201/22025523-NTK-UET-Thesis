# Bộ Kiểm Thử Runtime & Chứng Thực Độc Lập G1 (JavisOS - ADMIN-PC)

Thư mục này chứa bộ công cụ kiểm thử thực tế (runtime harness) và biên nhận công khai đã làm sạch cho giai đoạn G1 trên máy chủ `ADMIN-PC`, thuộc nhánh `v2/javis-benchmark`.

## 1. Nguyên tắc vận hành và cô lập dữ liệu

- **Không sửa mã sản xuất:** Mọi kiểm thử đối với nhánh `v2/antigravity-review` đều thực hiện trên bản checkout tách rời tại `C:\NTK-G1\candidates\<CANDIDATE_ID>-<sha8>`. Không chỉnh sửa module tích hợp, không thay đổi prompt, không sửa response của mô hình.
- **Bảo toàn dữ liệu lịch sử G0:** Không can thiệp vào `C:\Users\Admin\ntk-thesis-v2\javis` hoặc `v2/evaluation/post_report/`.
- **Cô lập bằng chứng thô (Private Evidence):** Toàn bộ prompt chứa mã nguồn, raw response từ Ollama, cơ sở dữ liệu SQLite (`review.sqlite`), bản chụp mã nguồn và nhật ký tiến trình được lưu ngoài kho Git tại `C:\NTK-G1-Private\G1-Runtime\`.
- **Phân tách 6 mức chứng thực (Phase G):**
  1. `level_1_mock_or_synthetic_test`: Kiểm thử mô phỏng hoặc fault injection (ví dụ Demo 5).
  2. `level_2_real_scanner_executed`: OpenGrep `1.25.0` thực tế đã chạy và sinh JSON/SARIF kèm trace.
  3. `level_3_ollama_http_request_received`: Dịch vụ Ollama loopback (`127.0.0.1:11434`) đã nhận HTTP request.
  4. `level_4_ollama_response_recorded`: Ollama đã trả phản hồi HTTP 200 kèm payload JSON và mã băm SHA-256.
  5. `level_5_local_model_runtime_observed_by_host_logs`: Quan sát được hoạt động suy luận cục bộ của `qwen3.5:9b-q4_K_M` qua bộ đếm và nhật ký máy chủ (`eval_count`, `eval_duration`, `digest`), nhưng không đồng nhất với chữ ký chứng thực phần cứng bên thứ ba.
  6. `level_6_independent_ground_truth_security_correctness`: Kết luận đúng/sai bảo mật theo Ground Truth độc lập (không đánh giá trong phạm vi G1; `SUPPORTED`/`REFUTED` của Qwen không phải Ground Truth).

## 2. Lệnh thực thi tái lập trên máy chủ

```powershell
python -X utf8 -B v2/g1_runtime/verify_g1_runtime.py `
  --repo-root "C:\NTK-G1\javis-runtime" `
  --private-root "C:\NTK-G1-Private\G1-Runtime" `
  --candidates-root "C:\NTK-G1\candidates" `
  --candidate-id "G1-C1"
```

Chạy bộ kiểm thử tự động cho công cụ kiểm chứng và biên nhận công khai:

```powershell
python -m pytest v2/g1_runtime/test_g1_runtime.py -q
```
