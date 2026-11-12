# Hồ Sơ Bàn Giao G1 — Tích Hợp CLI Kế Thừa `simple_semgrepAI` → OpenGrep → Qwen Cục Bộ → SQLite Kiểm Duyệt

**Kết luận kỹ thuật G1 hiện tại:** **`G1_INCOMPLETE`**

**Lý do trung thực:** Toàn bộ mã tích hợp sản xuất G1, 163 bài kiểm thử tự động, kiểm chứng tương thích ngược M1 (`--scan-only`) và kịch bản demo thực tế 4 phần qua CLI kế thừa `python -m semgrepai` đã chạy thành công và được công bố tại ứng viên `G1-C1` (`ab4af37d8f3fc4060c0fb31fc85ca09d1172367b`). Tuy nhiên, tại thời điểm kết thúc cửa sổ chờ có giới hạn, hai nhánh độc lập `v2/codex-core` và `v2/javis-benchmark` vẫn đang giữ biên nhận tiền ứng viên (`tested_sha: null`, đối chiếu trên commit nền `457183f9e17892fe284da04b57ef6c5c24b008e0`), chưa công bố biên nhận `VERDICT.json` mới ghim đúng SHA ứng viên `ab4af37d8f3fc4060c0fb31fc85ca09d1172367b` cùng lượt chạy `qwen3.5:9b-q4_K_M` trên máy chủ `ADMIN-PC`. Theo nguyên tắc nghiêm ngặt của đồ án, không tự nâng kết luận lên `G1_TECHNICAL_PASS` khi chưa có đủ hai biên nhận độc lập khớp SHA.

> [!IMPORTANT]
> **Các kết quả G0 đã khóa được giữ nguyên tuyệt đối (không diễn giải lại, không chỉnh sửa dữ liệu lịch sử):**
> - `AUDIT_EXECUTION_COMPLETED=true`
> - `G0_ACCEPTANCE=CONDITIONAL`
> - `READY_FOR_G1=CONDITIONAL`
> - Đóng góp phân loại độc lập của Arm C lịch sử: `CONFOUNDED`
> - 14 errata vẫn ở trạng thái chờ giảng viên phê duyệt.

---

## 1. Nhánh và Commit Nền

- **Repository:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis`
- **Nhánh tích hợp được giao:** `v2/antigravity-review`
- **Commit nền trước G1:** `457183f9e17892fe284da04b57ef6c5c24b008e0`
- **Nhánh tham chiếu độc lập (chỉ đọc `git fetch` / `git show`, không merge):**
  - `v2/codex-core`: đầu phiên `30b0bac464ade5c5f32287917eb877a575308a06` → cuối phiên `a099ac670bc3c18996d47063dfee266fcde6a9d0`
  - `v2/javis-benchmark`: đầu phiên `bf19b5e1392645baba55e5039ebc0d71a1af9aaa` → cuối phiên `4de45981cd83dcada56186d707fe9f11609ed006`

## 2. Commit Tích Hợp

- **Candidate ID:** `G1-C1`
- **Commit ứng viên tích hợp (`G1-C1`):** `ab4af37d8f3fc4060c0fb31fc85ca09d1172367b` (`Kết nối OpenGrep và Qwen cục bộ vào luồng kiểm duyệt của công cụ kế thừa`)
- **Marker ứng viên:** `v2/g1_integration/CANDIDATE.json` (SHA-256: `13863bbca9ef548170ac1b0ec7358e0846b0fc0262a6001116c165188d6a5b3f`, trạng thái `READY_FOR_INDEPENDENT_TEST`, không tự ghi SHA vào bên trong tệp).
- **Ghi chú về commit bàn giao:** Commit bổ sung hai tệp báo cáo `v2/g1_integration/G1_FINAL_HANDOFF.md` và `v2/g1_integration/G1_FINAL_STATUS.json` nằm ngay trên `ab4af37d8f3fc4060c0fb31fc85ca09d1172367b` và không thay đổi bất kỳ tệp mã nguồn sản xuất hay bài kiểm thử nào; SHA thực của đầu nhánh luôn được xác định trực tiếp bằng `git rev-parse v2/antigravity-review`.

## 3. Upstream Commit

- **Upstream gốc:** `hardw00t/simple_semgrepAI`, phiên bản `0.2.0`
- **Pinned Commit:** `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`
- **Pinned Git Tree:** `c0ab3e20152ce5c3e6b80e1525288ad59c9aee93`
- **Kiểm chứng toàn vẹn:** Đầy đủ **96 tệp** upstream được kiểm tra SHA-256 trước khi vá qua danh mục `v2/g1_integration/pinned_upstream_tree.json` (SHA-256: `b6221da8e91736a936150d23e36e71fc1b981299da7b679361a5aa585c4fdcd3`).

## 4. Các Tệp Thay Đổi và Diff

Tại commit ứng viên `ab4af37d8f3fc4060c0fb31fc85ca09d1172367b` so với `457183f9e17892fe284da04b57ef6c5c24b008e0`: **27 tệp thay đổi (`+4041` dòng thêm, `-91` dòng xóa)**. Không có bất kỳ thay đổi nào trên `v2/crosscheck/`, `v2/evaluation/post_report/`, `v2/baseline/fork/`, `backend/` hay `apps/`.

- **9 tệp cập nhật trong `v2/triage/`:**
  - `v2/triage/evidence.py` (`+60/-...`): bổ sung `StaleSourceError` (`error_code = "STALE_SOURCE"`, `mismatched_paths`, `expected_hashes`, `observed_hashes`) khi kiểm tra mã băm Java lúc xác nhận giả.
  - `v2/triage/ollama.py` (`+478/-...`): đặt mặc định `DEFAULT_PROMPT_CONTRACT = "blind"`, kiểm tra đệ quy toàn bộ khóa lồng nhau và từ chối mọi khóa nhãn Ground Truth / gợi ý heuristic, giữ nguyên hàm tái tạo payload lịch sử v2.1 phục vụ đối chiếu G0, phân tách rõ `raw_model_status` và `validated_status`, siết cổng `REFUTED`, phân loại `failure_kind`, kiểm tra `/api/tags`, ghi nhật ký nguyên văn `llm_io/` ở vùng chạy riêng và dùng `Connection: close`.
  - `v2/triage/heuristics.py`: ràng buộc `ln_no <= sink_line` khi quét nguồn HTTP trong phương thức.
  - `v2/triage/scan_receipt.py`: chuẩn hóa URI `file://` và ký tự ổ đĩa Windows khi đối chiếu JSON/SARIF.
  - `v2/triage/store.py`: bổ sung bảng `rejected_decisions` ghi nhận nỗ lực `confirm-false` bị từ chối vì `STALE_SOURCE` mà không ghi vào `events` và vẫn giữ trạng thái `OPEN`.
  - `v2/triage/cli.py`: thêm `--prompt-contract` (mặc định `blind`), các lệnh `confirm-true`, `confirm-false`, `reopen`, cờ `--include-rejected` cho `history`, tách rõ `raw_model_status` / `validated_status` / `human_review_state`.
  - 3 tệp kiểm thử hồi quy cập nhật tương thích mặc định `blind`: `test_blind_spot_regressions.py`, `test_g0_v22_payload_contract.py`, `test_stage2_stage3_cwe22_cwe89.py`.
- **18 tệp tạo mới trong `v2/g1_integration/`:**
  - Bộ dựng fork G1 & hỗ trợ ghi nhận quá trình quét: `prepare_g1_fork.py`, `pinned_upstream_tree.json`, `fork_support/__init__.py`, `fork_support/scanner_config.py`, `fork_support/scan_manifest.py`, `fork_support/scan_recording.py`.
  - Bridge CLI kế thừa → `v2.triage`: `__init__.py`, `bridge.py`, `finding_identity.py`.
  - Tập luật Java CWE-22 & CWE-89 và bộ mẫu demo: `rules/java_g1_cwe22_cwe89.yml`, `demo_fixtures/Demo1TruePositive.java`, `demo_fixtures/Demo2ProtectedFalsePositive.java`, `demo_fixtures/Demo3ExternalHelperUndetermined.java`, `run_g1_demo.py`.
  - Kiểm thử tích hợp và hồ sơ ứng viên: `tests/__init__.py`, `tests/test_g1_integration.py`, `README.md`, `CANDIDATE.json`.
- **Mã băm diff thực tế sinh bởi `prepare_g1_fork.py`:**
  - Bản vá tham khảo của giảng viên (`advisor_patch_sha256`): `17ac840af6db0b293e8ac7626abfd0c9ee2469eb82f0e96d8aff56869e6d58c1`
  - Bản vá overlay tích hợp G1 trên nền patch giảng viên (`g1-integration-overlay.patch`): `70615781f31ca1be0d5fbbf790b04d16b2c978755ce12834fa2a8de328dcd117`
  - Bản vá overlay tích hợp G1 chế độ phòng sạch (`--scanner-layer ntk-cleanroom`): `e1039cb2b5d725884c0fda37be78b4e5de033d4374a50476108f1a3899aebe2b`

## 5. Nguồn Gốc Từng Thành Phần

| Thành phần | Nguồn gốc | Vai trò trong G1 | Ghi chú toàn vẹn |
|---|---|---|---|
| `semgrepai/__main__.py`, `semgrepai/cli.py`, `semgrepai/scanner.py` và 93 tệp còn lại | Upstream `hardw00t/simple_semgrepAI` v0.2.0 (`2c79a58a...`) | Entrypoint Typer `semgrepai.cli:app` và lớp `SemgrepScanner` gốc | Kiểm tra đủ 96 hash SHA-256 trước khi áp bản vá; không đẩy cây upstream vào Git |
| Lớp thay thế thực thi OpenGrep (`advisor-patch`) | Gói tham khảo riêng của giảng viên (ngoài Git) | Chuyển lệnh thực thi của `SemgrepScanner` sang OpenGrep cục bộ | Xác minh `git apply --check`; có chế độ dự phòng `--scanner-layer ntk-cleanroom` cho máy chủ không chứa gói riêng |
| `v2/baseline/` và nền tảng `v2/triage/` v2.2.1 | Mã NTK từ giai đoạn M1 / G0 (`457183f9...`) | Trích xuất bằng chứng nguồn Java, ngữ cảnh phương thức, SQLite `ReviewStore`, kiểm tra biên nhận quét | Giữ nguyên 100% `v2/baseline/fork/` và proof M1 cũ (`verify_patch.py` PASS) |
| `v2/g1_integration/` và phần mở rộng `v2/triage/` | Mã mới G1 do Antigravity triển khai (`ab4af37d...`) | Dựng fork tái lập, nối trực tiếp `semgrepai scan --local-triage` và các lệnh duyệt hàng đợi vào `v2.triage`, hợp đồng `blind`, chặn quét lặp, kiểm soát `STALE_SOURCE` và kịch bản demo 4 phần | Tách riêng trạng thái từng chặng trong `g1-run-manifest.json`; không coi `exit 0` của wrapper là thành công của Qwen/validator |

## 6. Lệnh Cài Đặt và Lệnh Chạy Hoàn Chỉnh

```powershell
# 1. Dựng bản fork G1 từ upstream đã ghim sang thư mục riêng ngoài Git
python -B -m v2.g1_integration.prepare_g1_fork `
  --upstream "<UPSTREAM_CLONE_DIR>" `
  --advisor-dir "<PRIVATE_ADVISOR_DIR>" `
  --output-dir "<PRIVATE_RUN_ROOT>\fork-g1"
# (Trên máy chủ sạch không có gói riêng của giảng viên, thay --advisor-dir bằng: --scanner-layer ntk-cleanroom)

# 2. Thiết lập PYTHONPATH trỏ vào bản fork đã dựng và thư mục gốc repository
$env:PYTHONPATH = "<PRIVATE_RUN_ROOT>\fork-g1\source;<REPO_ROOT>"

# 3. Kiểm tra tương thích M1 (--scan-only, chỉ chạy OpenGrep, không gọi RAG/LLM)
python -B -m semgrepai scan `
  v2/g1_integration/demo_fixtures/Demo1TruePositive.java `
  --rules-path v2/g1_integration/rules/java_g1_cwe22_cwe89.yml `
  --output-dir "<PRIVATE_RUN_ROOT>\m1-scan-only" `
  --executable "<OPENGREP_BIN>" `
  --scan-only

# 4. Chạy chu trình G1 đầy đủ qua CLI kế thừa (--local-triage, mặc định hợp đồng blind)
python -B -m semgrepai scan `
  v2/g1_integration/demo_fixtures/Demo1TruePositive.java `
  --rules-path v2/g1_integration/rules/java_g1_cwe22_cwe89.yml `
  --output-dir "<PRIVATE_RUN_ROOT>\g1-run" `
  --executable "<OPENGREP_BIN>" `
  --local-triage `
  --endpoint http://127.0.0.1:11434 `
  --model qwen3.5:9b-q4_K_M `
  --prompt-contract blind `
  --timeout 180

# 5. Các thao tác kiểm duyệt của con người ngay trên CLI kế thừa
python -B -m semgrepai queue --db "<PRIVATE_RUN_ROOT>\g1-run\triage\review.sqlite"
python -B -m semgrepai queue --db "<PRIVATE_RUN_ROOT>\g1-run\triage\review.sqlite" --all
python -B -m semgrepai show "<WARNING_ID>" --db "<PRIVATE_RUN_ROOT>\g1-run\triage\review.sqlite"
python -B -m semgrepai confirm-true "<WARNING_ID>" --db "<PRIVATE_RUN_ROOT>\g1-run\triage\review.sqlite" --actor "<OPERATOR>" --reason "<LY_DO>"
python -B -m semgrepai confirm-false "<WARNING_ID>" --db "<PRIVATE_RUN_ROOT>\g1-run\triage\review.sqlite" --actor "<OPERATOR>" --reason "<LY_DO>"
python -B -m semgrepai reopen "<WARNING_ID>" --db "<PRIVATE_RUN_ROOT>\g1-run\triage\review.sqlite" --actor "<OPERATOR>" --reason "<LY_DO>"
python -B -m semgrepai history "<WARNING_ID>" --db "<PRIVATE_RUN_ROOT>\g1-run\triage\review.sqlite" --include-rejected

# 6. Chạy trọn bộ kịch bản demo tái lập 4 phần
python -B -m v2.g1_integration.run_g1_demo `
  --prepared-source "<PRIVATE_RUN_ROOT>\fork-g1\source" `
  --output-dir "<PRIVATE_RUN_ROOT>\demo-suite" `
  --executable "<OPENGREP_BIN>" `
  --endpoint http://127.0.0.1:11434 `
  --model qwen3.5:9b-q4_K_M `
  --timeout 180
```

## 7. Phiên Bản OpenGrep / Ollama / Qwen Thực Tế

- **Trên máy phát triển cục bộ (đã chạy thực tế E2E):**
  - Python: `3.12.3` (`typer 0.17.5`, `rich 15.0.0`, `PyYAML 6.0.3`)
  - OpenGrep: `1.20.0`
  - Ollama: `0.34.2` chạy cục bộ trong WSL2 `Ubuntu-22.04`, truy cập qua loopback `http://127.0.0.1:11434` (tắt hoàn toàn proxy môi trường `ProxyHandler({})` và chặn mọi HTTP redirect)
  - Model thực tế đã xác minh qua `/api/tags` và chạy suy luận thật: `qwen2.5-coder:1.5b` (digest: `d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668`, dung lượng `986,062,089` bytes).
  - Kiểm chứng fail-closed với tag `qwen3.5:9b-q4_K_M` chưa cài trên laptop (do giới hạn 4GB VRAM / ~21 GiB ổ trống): Ollama trả HTTP `404`, hệ thống ghi nhận rõ `failure_kind = "MODEL_UNAVAILABLE"`, hạ về `validated_status = "UNDETERMINED"`, giữ nguyên mọi cảnh báo ở trạng thái `OPEN` và đánh dấu `all_stages_succeeded = false`.
- **Trên máy chủ chuẩn `ADMIN-PC` (theo biên nhận tiền ứng viên công bố trên `v2/javis-benchmark`):**
  - OpenGrep `1.25.0`, Ollama `0.40.7`, model tham chiếu `qwen3.5:9b-q4_K_M` (digest: `56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90`) — đang chờ JavisOS chạy lại trên commit ứng viên `ab4af37d8f3fc4060c0fb31fc85ca09d1172367b`.

## 8. Phiên Bản và Mã Băm Tập Luật (Rules)

- **Tập luật G1 mặc định:** `v2/g1_integration/rules/java_g1_cwe22_cwe89.yml`
  - **SHA-256:** `68ac64329098e45e36ee650af2d483ee70ee3dff889d73586f21be1b29ee2eba`
  - **Rule IDs:** `v2.g1_integration.rules.ntk.g1.java.cwe22.path-traversal` (CWE-22) và `v2.g1_integration.rules.ntk.g1.java.cwe89.sql-injection` (CWE-89), chế độ `mode: taint`.
- **Tập luật M1 cơ sở (giữ nguyên không sửa):** `v2/baseline/rules/java.yml`
  - **SHA-256:** `f34e7b51880cc5baf4ff3cda47a16232c8d405b8fd5e65aaed1aa3745367d5aa`

## 9. Manifest Nguồn, Luật và Quá Trình Quét

Mỗi lượt chạy `semgrepai scan --local-triage` sinh hai manifest độc lập trong thư mục đầu ra mới:
1. `capture/scan-manifest.json` (`schema: "ntk-scan-capture-1"`): ghi nhận thời điểm bắt đầu/kết thúc, `sources_before` và `sources_after` (SHA-256 từng tệp Java), `rules_before_sha256` và `rules_after_sha256`, toàn bộ `argv`/`exit_code`/stdout/stderr của đúng 3 tiến trình con OpenGrep (`--version`, `--json`, `--sarif`) cùng bảng băm SHA-256 của 16 hiện vật capture.
2. `g1-run-manifest.json` (`schema: "ntk-g1-run-manifest-1"`): ghi nhận `scanner_subprocess_invocations = 3`, `triage_subprocess_invocations = 0` (chứng minh không gọi lại OpenGrep lần thứ hai trong bước triage), kết quả kiểm tra `json_sarif_parity`, `handoff_verification`, kết quả `/api/tags`, và bảng trạng thái tách rời từng chặng (`scanner_status`, `source_integrity_status`, `json_sarif_parity_status`, `handoff_status`, `qwen_inference_status`, `validator_status`, `queue_status`, `all_stages_succeeded`).

Mã băm SHA-256 của các tệp nguồn Java dùng trong demo:
- `Demo1TruePositive.java`: `934fff73bb2053c1160f296e2e9747f87349eafdaae77145039d6d20668f24af`
- `Demo2ProtectedFalsePositive.java`: `51ca2bd23cb4134f93c1c59095240744ab9eb78184408a08eb5cd560de06a7b0`
- `Demo3ExternalHelperUndetermined.java`: `9945d19bd2aa007e99e37d3495c401684e467cfe8ef83489be793dd88a01f601`

## 10. Kết Quả Quét OpenGrep và Đối Chiếu JSON/SARIF

| Lượt chạy | Tệp mục tiêu | `scan_sha256` (`opengrep.json`) | Số findings JSON / SARIF | Parity JSON/SARIF | Quét lặp ở Triage |
|---|---|---|---|---|---|
| M1 `--scan-only` | `Demo1TruePositive.java` | `a8ecd08960df436c9ad8aeafedcdd761bc03b8154d8529ffbd11bc89ead4d735` | `2` / `2` | `MATCHED` | Không áp dụng |
| Demo 1 (`REAL_RUNTIME`) | `Demo1TruePositive.java` | `a8ecd08960df436c9ad8aeafedcdd761bc03b8154d8529ffbd11bc89ead4d735` | `2` / `2` | `MATCHED` | `0` lệnh |
| Demo 2 (`REAL_RUNTIME`) | `Demo2ProtectedFalsePositive.java` | `b01d85958b495033043ef59b624c32b25c227be11ed5381bab6eca7e4fd4d9b6` | `1` / `1` | `MATCHED` | `0` lệnh |
| Demo 3a (`REAL_RUNTIME`) | `Demo3ExternalHelperUndetermined.java` | `ff6a292f9b87545fb8f128a13e41260281e268aed50cff6cd2aadc1fa44cf446` | `1` / `1` | `MATCHED` | `0` lệnh |
| Demo 3b (`SYNTHETIC_MOCK_HTTP`) | `Demo2ProtectedFalsePositive.java` | `b01d85958b495033043ef59b624c32b25c227be11ed5381bab6eca7e4fd4d9b6` | `1` / `1` | `MATCHED` | `0` lệnh |
| Demo 4 (`STALE_SOURCE`) | `Demo4MutableCopy.java` | `89c2ae38afcabedf97e9ddab2bcf9d46c87cbf306a34e586fbf7cbf4efcccdca` | `1` / `1` | `MATCHED` | `0` lệnh |

## 11. Kết Quả Qwen Thô (`raw_model_status`) và Sau Validator (`validated_status`)

Báo cáo trung thực kết quả thực tế từ model nhỏ `qwen2.5-coder:1.5b` trên laptop (không chỉnh sửa đầu ra thô của mô hình):

| Kịch bản | Nguồn chạy | Warning ID (16 ký tự đầu) | CWE | `raw_model_status` | `validated_status` | `failure_kind` | Độ trễ (`ms`) | `eval_count` | `prompt_sha256` (16 ký tự đầu) |
|---|---|---|---|---|---|---|---|---|---|
| Demo 1 | `REAL_RUNTIME` (`qwen2.5-coder:1.5b`) | `292d424589d60690` | `CWE-89` | `SUPPORTED` | `UNDETERMINED` | `INVALID_CITATION` | `9109.0` | `226` | `48f4759cee485901` |
| Demo 1 | `REAL_RUNTIME` (`qwen2.5-coder:1.5b`) | `634be6d8388e5acf` | `CWE-22` | `SUPPORTED` | `UNDETERMINED` | `INVALID_CITATION` | `3235.0` | `209` | `2533efb5c4c6f165` |
| Demo 2 | `REAL_RUNTIME` (`qwen2.5-coder:1.5b`) | `a2329d5c3366078b` | `CWE-22` | `SUPPORTED` | `UNDETERMINED` | `INVALID_CITATION` | `14390.0` | `1063` | `d14ca9295204c8a8` |
| Demo 3a | `REAL_RUNTIME` (`qwen2.5-coder:1.5b`) | `da66db6d0374b57d` | `CWE-22` | `SUPPORTED` | `UNDETERMINED` | `INVALID_SCHEMA` | `2313.0` | `112` | `94320ee2efff1f3d` |
| Demo 3b | `SYNTHETIC_MOCK_HTTP` | `a2329d5c3366078b` | `CWE-22` | `null` | `UNDETERMINED` | `MALFORMED_JSON` | `0.0` | `null` | `d14ca9295204c8a8` |
| Demo 4 | `--no-llm` (`DISABLED`) | `217ab1ee7e35ee39` | `CWE-22` | `null` | `UNDETERMINED` | `DISABLED` | `null` | `null` | `null` |

- Trong cả 4 lời gọi Qwen thật (Demos 1, 2, 3a), `qwen2.5-coder:1.5b` đều hoàn tất HTTP 200 qua loopback (`protocol_status = "OLLAMA_REPORTED_UNATTESTED"`), trả JSON có `status = "SUPPORTED"`, nhưng do model 1.5B trích dẫn sai lệch `quote`/`sha256` hoặc thiếu trường cấu trúc trong schema nghiêm ngặt nên validator đã hạ toàn bộ về `validated_status = "UNDETERMINED"` đúng thiết kế an toàn, giữ nguyên `raw_model_status = "SUPPORTED"` để đối chiếu độc lập.

## 12. Số Findings và Số Findings Có Trace

- **Tổng số findings nạp qua 5 lượt chạy của bộ kịch bản demo:** `6` findings (`2` ở Demo 1 + `1` ở Demo 2 + `1` ở Demo 3a + `1` ở Demo 3b + `1` ở Demo 4).
- **Số findings bảo toàn đầy đủ `dataflow_trace` (`taint_source` → `taint_sink`):** **`6 / 6` findings (100%)**.
- **Số findings bị rơi hoặc bị tự động ẩn do lỗi Qwen / validator:** **`0` findings**.

## 13. Kết Quả Kiểm Duyệt Con Người và Chốt Chặn `STALE_SOURCE`

1. **Trạng thái mặc định sau ingest:** Tất cả `6/6` cảnh báo đều khởi tạo ở `human_review_state = "OPEN"`.
2. **Xác nhận thật (`confirm-true` — Demo 1):** Cảnh báo `292d424589d60690...` chuyển sang `CONFIRMED_TRUE`, vẫn hiển thị trong hàng đợi mặc định, ghi nhận `1` sự kiện kiểm duyệt hợp lệ kèm actor, timestamp, lý do và mã băm nguồn.
3. **Xác nhận giả và mở lại (`confirm-false` → `queue` → `queue --all` → `reopen` → `history` — Demo 2):**
   - Sau `confirm-false`: cảnh báo `a2329d5c3366078b...` ẩn khỏi hàng đợi mặc định (`0` cảnh báo), nhưng hiển thị đầy đủ ở trạng thái `CONFIRMED_FALSE` khi chạy `queue --all`.
   - Sau `reopen`: cảnh báo quay lại hàng đợi mặc định với trạng thái `OPEN`, bảo toàn nguyên vẹn lịch sử `2` sự kiện `["confirm-false", "reopen"]`.
4. **Từ chối xác nhận giả khi mã nguồn thay đổi (`STALE_SOURCE` — Demo 4):**
   - Sau khi bản sao `Demo4MutableCopy.java` bị sửa đổi trên đĩa (SHA-256 đổi từ `51ca2bd23cb4134f93c1c59095240744ab9eb78184408a08eb5cd560de06a7b0` sang `52b5fa1c08f1eef425c2acc63b07f87132fa94d732dd6d8ad411114911895151`), lệnh `semgrepai confirm-false` trả mã thoát `2` kèm thông báo có cấu trúc `[STALE_SOURCE]`.
   - Số sự kiện xác nhận thành công trong bảng `events`: **`0`**.
   - Số bản ghi từ chối trong bảng `rejected_decisions`: **`1`** (`rejection_code = "STALE_SOURCE"`).
   - Trạng thái cảnh báo trong hàng đợi: giữ nguyên **`OPEN`**.

## 14. Tổng Hợp Unit, Regression, Integration và Runtime Tests

| Bộ kiểm thử / Công cụ xác minh | Lệnh thực thi | Kết quả |
|---|---|---|
| Integration tests G1 (`v2/g1_integration/tests`) | `python -B -m unittest discover -s v2/g1_integration/tests -p "test_*.py" -q` | **10/10 PASS** |
| Regression & contract tests (`v2/triage/tests`) | `python -B -m unittest discover -s v2/triage/tests -p "test_*.py" -q` | **126 chạy: 125 PASS, 1 SKIP, 0 FAIL** |
| Baseline M1 tests (`v2/baseline/tests`) | `python -B -m unittest discover -s v2/baseline/tests -p "test_*.py" -q` | **27/27 PASS** |
| Kiểm chứng bản vá M1 (`verify_patch.py`) | `python -B v2/baseline/verify_patch.py` | **PASS** (khớp 6 blob upstream & 4 tệp fork) |
| Kiểm chứng vệ sinh kho mã (`verify-repository.py`) | `python -B scripts/verify-repository.py` | **PASS** (không có hiện vật riêng trong Git index) |
| Đối chiếu sáu chốt dữ liệu công khai của `audit.py` | Kiểm tra ngoại tuyến trên hiện vật thực của Demo 1, Demo 2, Demo 3a | **6/6 PASS** (`manifest`, `identity`, `sarif`, `sources`, `database`, `runtime`) |
| Kịch bản E2E 4 phần (`run_g1_demo.py`) | Chạy với OpenGrep `1.20.0` + Ollama `qwen2.5-coder:1.5b` | **PASS** (exit code `0`) |

## 15. Trạng Thái Biên Nhận Độc Lập Của Codex và JavisOS (Đối Chiếu Candidate SHA)

| Agent độc lập | Nhánh công bố | HEAD quan sát cuối | Tệp biên nhận | `tested_sha` trong biên nhận | Khớp SHA `G1-C1` (`ab4af37d...`)? | Phán quyết hiện có |
|---|---|---|---|---|---|---|
| **Codex** | `v2/codex-core` | `a099ac670bc3c18996d47063dfee266fcde6a9d0` | `v2/g1_audit/G1-C1/VERDICT.json` | `null` (tham chiếu `457183f9...`) | **CHƯA KHỚP** | `INCOMPLETE` (`CANDIDATE_NOT_AVAILABLE`, `0` lỗi mã sản xuất) |
| **JavisOS** | `v2/javis-benchmark` | `4de45981cd83dcada56186d707fe9f11609ed006` | `v2/g1_runtime/G1-C1/VERDICT.json` | `null` (tham chiếu `457183f9...`) | **CHƯA KHỚP** | `INCOMPLETE` (`CANDIDATE_NOT_AVAILABLE`, `0` lỗi mã sản xuất) |

- Cả hai agent đã công bố bộ kiểm tra sẵn sàng trước thời điểm `G1-C1` được push lên `origin/v2/antigravity-review` và chưa phát sinh commit mới trong 3 chu kỳ chờ giới hạn sau khi `ab4af37d8f3fc4060c0fb31fc85ca09d1172367b` được công bố. Khi Codex và JavisOS được kích hoạt chạy lại trên đầu nhánh `v2/antigravity-review`, hai biên nhận mới sẽ ghim trực tiếp SHA ứng viên đã công bố.

## 16. Các Vấn Đề Còn Tồn Tại và Giới Hạn Kỹ Thuật Trung Thực

1. **Chờ hai biên nhận độc lập ghim đúng SHA ứng viên:** Chưa có `VERDICT.json` hậu công bố từ Codex và JavisOS cho commit `ab4af37d8f3fc4060c0fb31fc85ca09d1172367b`; đây là lý do duy nhất khiến kết luận tổng hợp phải giữ ở mức `G1_INCOMPLETE`.
2. **Khác biệt model giữa laptop phát triển và máy chủ GPU:** Laptop chỉ đủ tài nguyên chạy `qwen2.5-coder:1.5b` (dẫn tới các phản hồi thô `SUPPORTED` bị validator hạ về `UNDETERMINED` do sai trích dẫn/schema); việc chứng thực suy luận thực của `qwen3.5:9b-q4_K_M` qua CLI đã tích hợp thuộc lượt chạy kiểm chứng máy chủ của JavisOS trên `ADMIN-PC`.
3. **Phạm vi phân tích ngữ cảnh Java:** `java_context.py` chỉ trích xuất phương thức bao quanh và các helper nội bộ cùng tệp trong giới hạn `<= 150` dòng; các lời gọi sang lớp/tệp khác được giữ nguyên là lời gọi ngoài chưa xác minh và bị chặn tự động xác nhận an toàn (`UNDETERMINED`).
4. **Giới hạn xác thực người duyệt và bảo vệ tệp cơ sở dữ liệu:** Tham số `--actor` trên CLI là chuỗi định danh vận hành cục bộ (không có hệ thống xác thực danh tính tập trung), và SQLite bảo đảm tính toàn vẹn lịch sử ở tầng ứng dụng chứ không tuyên bố chống chỉnh sửa ở cấp quản trị hệ điều hành.

## 17. Những Hạng Mục Chuyển Sang G2

1. Mở rộng bộ luật OpenGrep cục bộ và trích xuất tín hiệu ngữ cảnh Java sang đầy đủ CWE-78 và CWE-79 bên cạnh CWE-22 và CWE-89.
2. Bổ sung cơ chế tra cứu có giới hạn các hằng số/sanitizer khai báo liên tệp trong cùng thư mục nguồn quét mà vẫn giữ nguyên nguyên tắc fail-closed `UNDETERMINED` khi thiếu bằng chứng.
3. Chuẩn bị giao diện kết xuất số liệu thực nghiệm bị khóa phục vụ đánh giá định lượng G3 trên tập kiểm thử độc lập sau khi hoàn tất G1/G2.
4. Cải thiện tiện ích hiển thị hàng đợi kiểm duyệt theo lô cho người vận hành mà không làm suy yếu chốt kiểm tra SHA-256 `STALE_SOURCE`.

## 18. Trạng Thái Giảng Viên Nghiệm Thu

- **Trạng thái nghiệm thu của giảng viên hướng dẫn:** **`PENDING`** (chưa có xác nhận nghiệm thu của giảng viên; 14 errata từ G0 vẫn đang chờ phê duyệt).
