# G1 End-to-End Integration (`v2/g1_integration`)

Gói tích hợp G1 kết nối trực tiếp bản fork đã ghim của `hardw00t/simple_semgrepAI` (`v0.2.0` @ `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`) với OpenGrep, bộ trích xuất bằng chứng Java, Qwen cục bộ qua Ollama (`http://127.0.0.1:11434`), bộ kiểm chứng trích dẫn (`validator`) và hàng đợi kiểm duyệt con người trên SQLite (`ReviewStore`).

## 1. Kiến trúc và nguồn gốc mã nguồn (Provenance)

| Tầng | Thành phần | Nguồn gốc | Phạm vi |
|---|---|---|---|
| 1 | Upstream gốc (96 tệp) | `hardw00t/simple_semgrepAI` `0.2.0` (`2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`, tree `c0ab3e20152ce5c3e6b80e1525288ad59c9aee93`) | Giữ nguyên cấu trúc gói `semgrepai.__main__` / `semgrepai.cli:app` và `SemgrepScanner` |
| 2 | Lớp chuyển đổi OpenGrep | Patch tham khảo `simple_semgrepAI_opengrep.patch` (từ vùng private `--advisor-dir`) hoặc chế độ dự phòng sạch `--scanner-layer ntk-cleanroom` khi máy chủ không có gói private | Thay Semgrep bằng OpenGrep cục bộ với `--dataflow-traces` và `--taint-intrafile` |
| 3 | Overlay tích hợp G1 | `v2/g1_integration/prepare_g1_fork.py`, `fork_support/`, `bridge.py` | Bảo toàn `--scan-only` (M1), bổ sung `--local-triage` và các lệnh kiểm duyệt (`queue`, `show`, `confirm-true`, `confirm-false`, `reopen`, `history`, `decide`), khóa các lệnh RAG/cloud/web |
| 4 | Phân tích bằng chứng & kiểm duyệt | `v2/triage/` (`evidence.py`, `ollama.py`, `java_context.py`, `heuristics.py`, `scan_receipt.py`, `store.py`, `cli.py`) | Hợp đồng prompt mặc định `blind`, kiểm tra whitelist đệ quy, tách biệt `raw_model_status` / `validated_status` / `human_review_state`, và chốt chặn `STALE_SOURCE` có cấu trúc |

## 2. Cài đặt và dựng bản fork G1 (ngoài Git)

Yêu cầu môi trường:
- Python >= 3.11 với `typer`, `rich`, `PyYAML`.
- Binary `opengrep` cục bộ (ví dụ OpenGrep 1.20.0+).
- Dịch vụ `ollama` cục bộ lắng nghe trên `http://127.0.0.1:11434` cùng model Qwen đã cài đặt (mặc định tham chiếu: `qwen3.5:9b-q4_K_M`).
  - *Lưu ý cho Windows + WSL2:* khi OpenGrep chạy qua cầu nối WSL2 và sinh đường dẫn `/mnt/<drive>/...`, `bridge.py` tự động suy xuất ánh xạ tin cậy một chiều từ đúng `source_root` đã xác minh sang đường dẫn Windows tương ứng mà không chỉnh sửa nội dung gốc của `opengrep.json` / `opengrep.sarif` (đồng thời hỗ trợ tùy chọn `--path-map PREFIX=LOCAL_DIR` cho các điểm gắn tùy chỉnh nằm trong `source_root`). Nếu `ollama` chạy trong WSL2, giữ một tiến trình WSL hoạt động trong suốt phiên gọi HTTP từ Windows để tránh WSL2 tự tạm dừng máy ảo khi nhàn rỗi.

Dựng bản fork vào thư mục riêng ngoài repository:

```bash
# Khi có thư mục private chứa opengrep-triage.zip (chuẩn M1/G1):
python -B -m v2.g1_integration.prepare_g1_fork \
  --upstream <UPSTREAM_SIMPLE_SEMGREPAI_2C79A58A> \
  --advisor-dir <PRIVATE_ADVISOR_DIR> \
  --output-dir <PRIVATE_RUN_ROOT>/fork-g1

# Chế độ dự phòng trên máy chủ sạch không có gói private của giảng viên:
python -B -m v2.g1_integration.prepare_g1_fork \
  --upstream <UPSTREAM_SIMPLE_SEMGREPAI_2C79A58A> \
  --scanner-layer ntk-cleanroom \
  --output-dir <PRIVATE_RUN_ROOT>/fork-g1
```

Bộ dựng kiểm tra toàn bộ 96 tệp upstream theo SHA-1 blob và sinh `<PRIVATE_RUN_ROOT>/fork-g1/g1-integration-overlay.patch` cùng `preparation.json`.

## 3. Chạy luồng tích hợp từ CLI kế thừa `semgrepai`

Đặt `PYTHONPATH=<PRIVATE_RUN_ROOT>/fork-g1/source:<REPO_ROOT>` (trên PowerShell dùng dấu `;` thay cho `:`):

```bash
# 1. Đường M1 (--scan-only) vẫn được bảo toàn nguyên vẹn:
python -B -m semgrepai scan v2/g1_integration/demo_fixtures/Demo1TruePositive.java \
  --rules-path v2/g1_integration/rules/java_g1_cwe22_cwe89.yml \
  --output-dir <PRIVATE_RUN_ROOT>/m1-check \
  --executable <OPENGREP_BINARY> \
  --scan-only

# 2. Đường G1 (--local-triage) đầy đủ: OpenGrep -> JSON/SARIF -> Evidence -> Qwen -> Validator -> SQLite:
python -B -m semgrepai scan v2/g1_integration/demo_fixtures/Demo1TruePositive.java \
  --rules-path v2/g1_integration/rules/java_g1_cwe22_cwe89.yml \
  --output-dir <PRIVATE_RUN_ROOT>/g1-run \
  --executable <OPENGREP_BINARY> \
  --local-triage \
  --endpoint http://127.0.0.1:11434 \
  --model qwen3.5:9b-q4_K_M \
  --prompt-contract blind \
  --timeout 180

# 3. Các thao tác hàng đợi kiểm duyệt của con người qua cùng CLI semgrepai:
python -B -m semgrepai queue --db <PRIVATE_RUN_ROOT>/g1-run/triage/review.sqlite
python -B -m semgrepai show <WARNING_ID> --db <PRIVATE_RUN_ROOT>/g1-run/triage/review.sqlite
python -B -m semgrepai confirm-true <WARNING_ID> --db <PRIVATE_RUN_ROOT>/g1-run/triage/review.sqlite \
  --actor "reviewer" --reason "Đã kiểm chứng luồng taint trực tiếp đến sink"
python -B -m semgrepai confirm-false <WARNING_ID> --db <PRIVATE_RUN_ROOT>/g1-run/triage/review.sqlite \
  --actor "reviewer" --reason "Đã kiểm chứng chốt chặn đường dẫn chính tắc hợp lệ"
python -B -m semgrepai queue --db <PRIVATE_RUN_ROOT>/g1-run/triage/review.sqlite --all
python -B -m semgrepai reopen <WARNING_ID> --db <PRIVATE_RUN_ROOT>/g1-run/triage/review.sqlite \
  --actor "lead-reviewer" --reason "Mở lại để rà soát bổ sung"
python -B -m semgrepai history <WARNING_ID> --db <PRIVATE_RUN_ROOT>/g1-run/triage/review.sqlite --include-rejected
```

## 4. Chạy kịch bản Demo 4 tình huống có thể tái lập

```bash
python -B -m v2.g1_integration.run_g1_demo \
  --prepared-source <PRIVATE_RUN_ROOT>/fork-g1/source \
  --output-dir <PRIVATE_RUN_ROOT>/demo-suite \
  --executable <OPENGREP_BINARY> \
  --endpoint http://127.0.0.1:11434 \
  --model qwen3.5:9b-q4_K_M \
  --timeout 180
```

## 5. Kiểm thử tự động

```bash
python -B -m unittest discover -s v2/g1_integration/tests -p "test_*.py" -v
python -B -m unittest discover -s v2/triage/tests -p "test_*.py" -q
python -B -m unittest discover -s v2/baseline/tests -p "test_*.py" -q
python -B v2/baseline/verify_patch.py
python -B scripts/verify-repository.py
```

## 6. Giới hạn kỹ thuật được công bố rõ

1. Ngữ cảnh cấu trúc Java bao phủ phương thức bao quanh cảnh báo và các hàm helper cùng tệp trong phạm vi tối đa 150 dòng; các lời gọi sang tệp khác hoặc vượt quá độ sâu cho phép không được suy đoán mà chuyển về `UNDETERMINED` và chặn `REFUTED`.
2. Giá trị `--actor` trong CLI là định danh chuỗi phục vụ nhật ký kiểm toán cục bộ, không phải cơ chế xác thực danh tính mật mã hay SSO.
3. SQLite bảo đảm ràng buộc khóa ngoại và nhật ký chỉ-ghi-thêm ở tầng ứng dụng, không tuyên bố chống chỉnh sửa tệp ở cấp quyền root/quản trị hệ điều hành.
4. Mọi tệp SQLite, JSONL kết quả chạy, prompt nguyên văn và raw response của LLM đều được giữ ở thư mục riêng ngoài Git.
