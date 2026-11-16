# G1 End-to-End Integration (`v2/g1_integration`)

Gói tích hợp G1 kết nối trực tiếp bản fork đã ghim của `hardw00t/simple_semgrepAI` (`v0.2.0` @ `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`) với OpenGrep, bộ trích xuất bằng chứng Java, Qwen cục bộ qua Ollama (`http://127.0.0.1:11434`), bộ kiểm chứng trích dẫn (`validator`) và hàng đợi kiểm duyệt con người trên SQLite (`ReviewStore`).

## 1. Kiến trúc và nguồn gốc mã nguồn (Provenance)

| Tầng | Thành phần | Nguồn gốc | Phạm vi |
|---|---|---|---|
| 1 | Upstream gốc (96 tệp) | `hardw00t/simple_semgrepAI` `0.2.0` (`2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`, tree `c0ab3e20152ce5c3e6b80e1525288ad59c9aee93`) | Giữ nguyên cấu trúc gói `semgrepai.__main__` / `semgrepai.cli:app` và `SemgrepScanner` |
| 2 | Lớp chuyển đổi OpenGrep | Patch tham khảo `simple_semgrepAI_opengrep.patch` (từ vùng private `--advisor-dir`) hoặc chế độ dự phòng sạch `--scanner-layer ntk-cleanroom` khi máy chủ không có gói private | Thay Semgrep bằng OpenGrep cục bộ với `--dataflow-traces` và `--taint-intrafile` |
| 3 | Overlay tích hợp G1 | `v2/g1_integration/prepare_g1_fork.py`, `fork_support/`, `bridge.py`, `exec_receipt.py`, `evaluate_r01_r03.py` | Bảo toàn `--scan-only` (M1), bổ sung `--local-triage`, lưu biên nhận nhị phân từng tiến trình, kiểm chứng raw HTTP capture cùng lượt gọi, cổng đánh giá chỉ-đọc R01–R03 và các lệnh kiểm duyệt (`queue`, `show`, `confirm-true`, `confirm-false`, `reopen`, `history`, `decide`), khóa các lệnh RAG/cloud/web |
| 4 | Phân tích bằng chứng & kiểm duyệt | `v2/triage/` (`evidence.py`, `ollama.py`, `verify_http_capture.py`, `java_context.py`, `heuristics.py`, `scan_receipt.py`, `store.py`, `cli.py`) | Hợp đồng prompt mặc định `blind`, lưu nguyên HTTP request/response body bytes cùng lượt gọi (`llm_io/*.body.bin` + `*.http-capture.json`), tách biệt `raw_model_status` / `validated_status` / `human_review_state`, và chốt chặn `STALE_SOURCE` có cấu trúc |

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

## 4. Chạy kịch bản Demo & kế hoạch nghiệm thu runtime chuẩn (`RUNTIME_ACCEPTANCE_PLAN.md`)

Đối với lượt nghiệm thu chính thức R01–R03 trên `ADMIN-PC`, bắt buộc tuân thủ quy trình một tập thực nghiệm chính (4 lượt gọi Qwen thật duy nhất: `2 + 1 + 1`) tách riêng khỏi tập đối chứng phụ (`--auxiliary-controls-only`, 0 lượt gọi Qwen thật) trong [RUNTIME_ACCEPTANCE_PLAN.md](RUNTIME_ACCEPTANCE_PLAN.md) để không nhân đôi thành 8 lượt gọi Qwen:

```bash
# Chế độ đối chứng phụ (chỉ chạy Demo 3b SYNTHETIC_MOCK_HTTP + Demo 4 --no-llm STALE_SOURCE, 0 lượt gọi Qwen thật):
python -X utf8 -B -m v2.g1_integration.run_g1_demo \
  --prepared-source <PRIVATE_RUN_ROOT>/fork-g1/source \
  --output-dir <PRIVATE_RUN_ROOT>/auxiliary/controls_suite \
  --executable <OPENGREP_BINARY> \
  --auxiliary-controls-only

# Chế độ demo độc lập đầy đủ 4 tình huống (khi không chạy song song với tập quét thủ công):
python -X utf8 -B -m v2.g1_integration.run_g1_demo \
  --prepared-source <PRIVATE_RUN_ROOT>/fork-g1/source \
  --output-dir <PRIVATE_RUN_ROOT>/demo-suite \
  --executable <OPENGREP_BINARY> \
  --endpoint http://127.0.0.1:11434 \
  --model qwen3.5:9b-q4_K_M \
  --timeout 180
```

## 5. Kiểm thử offline và gate cho G1-C4

G1-C2 tại `6ebf3ec6668741a346199f860cf349332ad94eae` giữ nguyên
`G1_C2_RUNTIME_ACCEPTANCE_FAILED`; G1-C3 tại `236439ead654d12448bb2cf711e534a243007afd`
giữ nguyên `RUNTIME_PLAN_REQUIRES_CORRECTION`. Prompt hiện hành:
`v2.2.2-cwe22-cwe89-canonical-citations`. Bộ tham chiếu giảng viên: OpenGrep `1.33.1`,
Ollama `0.40.16`, `qwen3.5:9b-q4_K_M`; môi trường `ADMIN-PC` thực tế: OpenGrep `1.25.0`,
Ollama `0.40.7`, `qwen3.5:9b-q4_K_M` (ghi rõ sai khác, không tự thay đổi môi trường).
Kết quả offline không chứng thực Qwen runtime. Các lệnh runtime ở mục 2–4 và
`RUNTIME_ACCEPTANCE_PLAN.md` là quy trình cho lượt được người vận hành cho phép riêng.

Ưu tiên Python 3.11.9 để đối chiếu ADMIN-PC; ghi executable/version thực tế.
Lượt phát triển này dùng venv Python 3.12.3 AMD64 được người vận hành phê duyệt,
với `typer==0.29.1`, `rich==15.0.0`, `PyYAML==6.0.3`; parity Python 3.11.9 chưa kiểm thử.
Tạo/cài venv bằng chính tài khoản chạy test, `include-system-site-packages=false`,
không nối `.pth` tới dependency bên ngoài. Chạy tại root của checkout G1-C4
detached riêng, pin full SHA từ manifest bàn giao bên ngoài. Không detach worktree phát triển.
Trong PowerShell, thay các placeholder bằng đường dẫn mới đã được cấp quyền:

```powershell
$c4Python = '<PYTHON_EXE>'
$c4Checkout = '<DETACHED_CHECKOUT>'
$c4Sha = '<FULL_C4_SHA_FROM_HANDOFF_MANIFEST>'
$c4Checks = '<NEW_EXTERNAL_CHECKS_DIR>'
Set-Location -LiteralPath $c4Checkout
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:G1_CHECKOUT = $c4Checkout
$env:G1_EXPECTED_SHA = $c4Sha
$env:TEMP = '<EXISTING_FRESH_EXTERNAL_TEMP_DIR>'
$env:TMP = $env:TEMP
$env:SEMGREP_LOG_FILE = '<NEW_WRITABLE_EXTERNAL_SCANNER_LOG>'
$env:SEMGREP_SETTINGS_FILE = '<NEW_WRITABLE_EXTERNAL_SCANNER_SETTINGS>'
$env:SEMGREP_SEND_METRICS = 'off'
$env:SEMGREP_ENABLE_VERSION_CHECK = '0'
$env:OPENGREP_ENABLE_VERSION_CHECK = '0'
& $c4Python -X utf8 -B -m unittest discover -s v2/g1_integration/tests -p 'test_*.py' -v
& $c4Python -X utf8 -B -m unittest discover -s v2/triage/tests -p 'test_*.py' -v
& $c4Python -X utf8 -B -m unittest discover -s v2/baseline/tests -p 'test_*.py' -v
& $c4Python -X utf8 -B -m unittest discover -s v2/g1_audit -p 'test_*.py' -v
& $c4Python -X utf8 -B v2/baseline/verify_patch.py
& $c4Python -X utf8 -B v2/g1_audit/run_checks.py --checkout $c4Checkout --expected-sha $c4Sha --output $c4Checks
& $c4Python -X utf8 -B v2/g1_audit/verify_test_receipt.py $c4Checks
```

Kiểm tra `$LASTEXITCODE` ngay sau từng lệnh; giữ stdout/stderr, hash log, số test và lý do skip.
Không chạy tiếp nâng gate nếu có FAIL/ERROR. Gate yêu cầu HEAD detached đúng SHA và tracked tree sạch
trước/sau; output phải mới và ngoài checkout. `G1_CHECKOUT`/`G1_EXPECTED_SHA` cần cho audit suite.
Audit helper tự truyền `git -c safe.directory=<exact checkout>`; không sửa cấu hình Git toàn máy.
Các biến scanner ở trên tránh ghi log/settings vào profile của tài khoản khác;
chúng chỉ áp dụng cho tiến trình kiểm thử, không đổi ACL hoặc cấu hình dịch vụ.
`verify_patch.py` ghi receipt ignored tại `v2/baseline/evidence/patch-verification.json`;
giữ receipt ra ngoài checkout để bàn giao. `run_checks.py` chạy tập synthetic chọn lọc,
không thay toàn bộ các suite hoặc kiểm tra vệ sinh bộ tệp công khai.

Skip phải được ghi rõ: test OpenGrep tích hợp khi không tìm thấy binary; live upstream proof khi
thiếu `NTK_M1_LIVE_UPSTREAM`/`NTK_M1_ADVISOR_DIR`; symlink khi tài khoản Windows không có khả năng tạo.
Không cung cấp dữ liệu PRIVATE cũ để bỏ skip. Tách `OFFLINE_SYNTHETIC`, `MOCK_HTTP`,
`REAL_OPENGREP`, `REAL_OLLAMA`, `NOT_TESTED` trong báo cáo. Không chạy Ollama trong nhiệm vụ implementation.

Errata: entrypoint kiểm tra vệ sinh repository ghi trong handoff cũ không tồn tại tại G1-C2.
Các suite/gate trên là entrypoint thực; chúng không chứng minh đã thay toàn bộ một kiểm tra vệ sinh
không còn spec. Trước công bố phải review inventory/diff riêng, loại dữ liệu riêng và secrets.

## 6. Giới hạn kỹ thuật được công bố rõ

1. Ngữ cảnh cấu trúc Java bao phủ phương thức bao quanh cảnh báo và các hàm helper cùng tệp trong phạm vi tối đa 150 dòng; các lời gọi sang tệp khác hoặc vượt quá độ sâu cho phép không được suy đoán mà chuyển về `UNDETERMINED` và chặn `REFUTED`.
2. Giá trị `--actor` trong CLI là định danh chuỗi phục vụ nhật ký kiểm toán cục bộ, không phải cơ chế xác thực danh tính mật mã hay SSO.
3. SQLite bảo đảm ràng buộc khóa ngoại và nhật ký chỉ-ghi-thêm ở tầng ứng dụng, không tuyên bố chống chỉnh sửa tệp ở cấp quyền root/quản trị hệ điều hành.
4. Mọi tệp SQLite, JSONL kết quả chạy, prompt nguyên văn và raw response của LLM đều được giữ ở thư mục riêng ngoài Git.
