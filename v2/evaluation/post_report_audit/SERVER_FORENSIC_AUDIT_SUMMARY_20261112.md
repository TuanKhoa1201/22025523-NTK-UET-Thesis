# Biên Nhận Kiểm Toán Độc Lập Trên Máy Chủ (`v2/post-report-cwe22-cwe89-20261112`)

- **Ngày kiểm toán:** `2026-11-12`
- **Commit đối chiếu (chế độ chỉ đọc):** `86636b9de22e59efcca2d3786434727c6ae082e4` (`v2/post-report-cwe22-cwe89-20261112`)
- **Trình kiểm toán độc lập mới:** `v2/evaluation/audit_server_forensic_receipt.py` (kèm kiểm thử đơn vị `v2/evaluation/tests/test_audit_server_forensic_receipt.py`)
- **Tính bất biến dữ liệu gốc:** `zero_mutation_verified = true` trên toàn bộ `263/263` tệp bằng chứng lịch sử (`0` thêm, `0` xóa, `0` sửa đổi).

---

## 1. Kết quả kiểm toán ba bản quét gốc OpenGrep (`Task A`)

- **Phiên bản thực thi:** OpenGrep `1.25.0` (`SHA-256 = b010709bb790086083442eabe9a0b6bf48064ed87cdf808591baecdb60ccdf73`), chạy với `--json --dataflow-traces --taint-intrafile --no-git-ignore --disable-version-check --jobs 4 --timeout 60`.
- **Bộ quy tắc thực tế (`v2/evaluation/post_report/rules/p_java_cwe22_cwe89.yml`):** chứa đúng **`9` quy tắc** (`2` CWE-22 + `7` CWE-89), `SHA-256 = 4d12f6deabee1bcf17f1bcce845f05eaf84b312ee13aa6a9cd9721ea879695f9`.
- **Đối chiếu mã băm và biên nhận `scan-manifest.json`:**
  1. `stage1_dev_set_16_scan/opengrep.json` (`64,362` bytes): `SHA-256 = ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f` (`16` tệp quét, `0` bỏ qua, `16/16` có `dataflow_trace`, `0` lỗi, `exit_code = 0`, `manifest_sha256 = 67d708880cb7a93f972586a137c159fff478783788c0bcb1a30d6cb866e8f298`).
  2. `stage1_heldout_set_40_scan/opengrep.json` (`172,103` bytes): `SHA-256 = 67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b` (`40` tệp quét, `0` bỏ qua, `40/40` có `dataflow_trace`, `0` lỗi, `exit_code = 0`, `manifest_sha256 = 3f5488d9a8de308b33111b5b5b88fd2bf6342ff3a18d8b9458b6936725b64fab`).
  3. `stage5_real_projects_scan/opengrep.json` (`72,634` bytes): `SHA-256 = 99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041` (`8` tệp quét, `0` bỏ qua, `20/20` có `dataflow_trace`, `0` lỗi, `exit_code = 0`, `manifest_sha256 = 688083ecec3e04bc03d2e6ae5f958c7df3bdf1c69af0b2971c574abb7f4b90b6`).
- **Đối chiếu kho mã nguồn gốc:** Khớp byte-for-byte `16/16` tệp dev và `40/40` tệp held-out với OWASP `BenchmarkJava` (`8b67a88d73b2594570fc21150705283de884620b`), `6/6` tệp với `WebGoat` (`5357a65e054976cd7d79b81ef3906ded050ed921`), `1/1` tệp với `java-sec-code` (`4711f4e186258c6e0dd5c3863e7c9592e7e9026a`) và `1/1` tệp `demo/UserDao.java` (`SHA-256 = 6c890fc869f74cdceb6bd8f73e04be4fc7ffb4defdab008c098642e146be1d24`). Cả 3 `scan-manifest.json` đạt `sources_before == sources_after` nhưng ở mức tự ghi cục bộ (`signed_or_independently_attested = false`).

---

## 2. Kết quả kiểm toán 10 tệp `assessments.jsonl` và phản hồi Qwen (`Task B`)

- **Toàn vẹn cấu trúc & liên kết mã băm:** `240/240` bản ghi trên 10 tệp JSONL (và `148/148` bản ghi trên 6 tệp checkpoint) hợp lệ JSON 100%, `0` dòng hỏng, `240/240` khớp `alert_id = SHA256(scan_sha256 + ":" + finding_index)` và khớp `source_sha256` với tệp Java trên đĩa.
- **Thực chứng phản hồi HTTP Ollama (`qwen3.5:9b-q4_K_M`):** Trong `164` bản ghi thuộc 7 lượt gọi LLM, có `158/164` bản ghi nhận phản hồi HTTP 200 từ `http://127.0.0.1:11434` (`done = true`, `eval_count > 0`, `response_json_sha256` khớp 100% với `raw_response`). Riêng `6/16` cảnh báo CWE-22 ở `stage2_dev16_baseline_v1_0` bị chặn trước khi gọi mô hình do cấu trúc `CliCall`. Mức độ xác thực runtime là **`OLLAMA_SELF_REPORTED_LOCAL_HTTP_UNATTESTED`** (`independently_verified_model_runtime = false`).
- **Lưu trữ prompt (`PROMPT_NOT_ATTESTED`):** Không tệp JSONL nào lưu nguyên văn chuỗi prompt thô. Tuy nhiên, `request_payload_sha256` khớp 100% (`116/116`) với hàm `v2.triage.ollama.request_payload()` hiện hành trên cả 4 lượt chạy khóa `v2.1` (`dev16_armC_v2_1`, `heldout40_armC`, `heldout40_armD`, `real_projects_armC`), và khớp `0/42` trên 3 lượt phát triển trước `v2.1`.
- **Phát hiện phương pháp luận trọng yếu (`evidence_signals`):** Không có rò rỉ nhãn chuẩn (`ground_truth` / `expected_label`) vào `evidence` (`0/240`). Tuy nhiên, ở Nhánh C (`--mode evidence+llm`), `ollama.py` truyền `evidence_signals = record["heuristic_signals"]` chứa sẵn `recommended_status`, `recommendation_reason` và `candidate_citations`. Trên cả 3 tập chạy `v2.1` (`76` cảnh báo), **phán quyết thô của Qwen trùng khớp `76/76` (`100%`) với `heuristic_signals.recommended_status`**. Ở Nhánh D (`stage4_heldout40_armD_llm_ablation`, không có `evidence_signals`), Qwen trả về thô **`40/40 SUPPORTED`**, và bộ kiểm chứng trích dẫn hậu xử lý hạ cấp **`9/40`** bản ghi (`3 TP`, `6 FP`) xuống `UNDETERMINED`.

---

## 3. Truy vết `scripts/ground_truth_verifier.py` (`Task C`)

- **Kết luận đối với đồ án:** **`HISTORICAL_GATE_NOT_REPRODUCED`**.
- Tệp `scripts/ground_truth_verifier.py` chưa từng tồn tại trong kho `ntk-thesis-v2`. Tệp thực tế (`SHA-256 = b16796e4bc4b7a2f4040988533db1ef04527507e0fb6f0afea185b073dae171c`) thuộc thư mục vận hành của Javis Brain ngoài kho đồ án, và biên nhận lịch sử `receipt_20261112_124648.json` (`SHA-256 = 56e9c1d2b5e926043c192697403182e74eca6c757fe593d8eec002dfa577d424`) kiểm tra **`0`** tệp, **`0`** cổng mạng và **`0`** cơ sở dữ liệu SQLite của `ntk-thesis-v2`.

---

## 4. Nhãn chuẩn, tái tính chỉ số & kiểm tra nhất quán (`Task D, E, F`)

- **OWASP Benchmark v1.2 (`expectedresults-1.2.csv`, `SHA-256 = 1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`):** Khớp 100% nhãn và CWE cho `16/16` dev và `40/40` held-out; `0` giao tập; `STRICT_LOCK` khớp `4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09` (`exit_code = 0`). Mỗi tệp trong 56 tệp chỉ phát sinh đúng `1` cảnh báo tại dòng sink thực tế.
- **Tái tính chỉ số độc lập (`heldout_set_40`):** Khớp 100% (`0` ô lệch) với `v2/evaluation/post_report/PAIRED_EVALUATION.csv`:
  - **Arm A (OpenGrep-only):** TP giữ `20/20`, FP bác bỏ `0/20`, `UNDETERMINED = 0/40`, precision `20/40 (50.0%)`.
  - **Arm B (`heuristic`):** TP giữ `8/20` (`20/20` nếu gộp `UNDETERMINED`), FP bác bỏ `8/20`, `UNDETERMINED = 24/40`, `drop_fp` precision `20/32 (62.5%)`, `keep_tp_only` precision `8/8 (100.0%)` với recall `8/20 (40.0%)`.
  - **Arm C (`evidence+llm`):** TP giữ `20/20`, FP bác bỏ `20/20`, loại nhầm TP `0/20`, `UNDETERMINED = 0/40`, trích dẫn hợp lệ `40/40`, cả `drop_fp` và `keep_tp_only` đạt `20/20 (100.0%)` (cần diễn giải kèm biến nhiễu `evidence_signals` nêu tại Mục 2).
  - **Arm D (`llm` ablation):** TP giữ `17/20` (`20/20` nếu gộp `UNDETERMINED`), FP bác bỏ `0/20`, FP giữ nhầm `14/20`, `UNDETERMINED = 9/40`, `drop_fp` precision `20/40 (50.0%)`, `keep_tp_only` precision `17/31 (54.8%)`.
- **Dự án thực tế (`20` cảnh báo trên `8` tệp = `12` điểm mã nguồn):** Cả Arm B và Arm C trả về `20/20 SUPPORTED` (`16/16` TP được giữ, `0/4` FP được bác bỏ). Độ tin cậy độc lập của 4 nhãn FP thủ công: `#15` (`UserDao.java:63`) `HIGH`, `#08/#09` (`SqlInjectionLesson8.java:154,158`) `MEDIUM`, `#10` (`UserService.java:52`) `MEDIUM_LOW`.
- **Các sai lệch tài liệu lịch sử cần đính chính ở vòng sau:** Tài liệu bàn giao/bản nháp Chương 4 ghi nhầm `14` quy tắc thay vì `9`, ghi nhầm mã băm dev scan `c1be1d5e...` thay vì `ecc1fa46...`, ghi nhầm mã băm CSV `353762c7...` thay vì `1809f6a6...`, và ghi nhầm `WebGoatUser.java` thay vì `UserForm.java:20`.
