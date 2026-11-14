# Biên Nhận Thực Thi & Chứng Thực Runtime G1-C1 Trên Máy Chủ ADMIN-PC

- **Candidate ID:** `G1-C1`
- **Trạng thái Candidate (`v2/g1_integration/CANDIDATE.json`):** `False` (`CANDIDATE_NOT_AVAILABLE`)
- **Tested Candidate SHA:** `None`
- **SHA mã nền kiểm tra đối chứng (Pre-G1 HEAD trên `v2/antigravity-review`):** `457183f9e17892fe284da04b57ef6c5c24b008e0`
- **Upstream Commit (`simple_semgrepAI`):** `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`
- **Kết luận trong phạm vi Runtime G1:** **`INCOMPLETE`** (`CANDIDATE_NOT_AVAILABLE`)

## 1. Máy chủ và Môi trường Runtime (Giai đoạn A)

- **Máy chủ:** `ADMIN-PC` (`Windows-11-10.0.26200-SP0` + WSL2 `Ubuntu-IRIS`)
- **Python:** `3.12.10` (`3.12.10 (tags/v3.12.10:0cc8128, Apr  8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)]`)
- **Git:** `2.55.0.windows.5`
- **OpenGrep:** `1.25.0` (`<private-evidence-root>/bin/opengrep_counted.cmd -> WSL2 /usr/local/bin/opengrep`)
- **Ollama:** `0.40.7` (`F:\ACTIVE-WORKSPACES\Tools\Ollama\v0.40.7\bin\ollama.exe`, loopback `http://127.0.0.1:11434`)
- **Model cục bộ:** `qwen3.5:9b-q4_K_M` (digest: `56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90`, kích thước: `6550825550` bytes)
- **Tài nguyên phần cứng:** GPU `NVIDIA GeForce RTX 4060 Ti (16380 MiB VRAM, Driver 591.86)`, RAM `63.82 GB`, ổ trống `C: 190.75 GB`, `F: 292.65 GB`
- **Đồng hồ & Múi giờ:** `UTC ISO-8601 + Asia/Bangkok (UTC+07:00), monotonic intervals via time.perf_counter_ns()`
- **Thời gian phiên chạy:** Bắt đầu `2026-11-12T21:06:59.492086+00:00` (`2026-11-13T04:06:59.492086+07:00`), kết thúc `2026-11-12T21:08:24.877687+00:00` (`2026-11-13T04:08:24.877687+07:00`)
- **Phân tách thời gian:** Tổng wall-clock phiên E2E = `85385.34 ms`; Tổng thời gian quét OpenGrep = `19656.86 ms`; Tổng thời gian suy luận Qwen ghi nhận = `52.875 s`

## 2. Kết quả Preflight Độc Lập & Kiểm tra Marker Candidate (Giai đoạn B & C)

- **Preflight OpenGrep (`1.25.0`):** Exit code `0`, `4` findings, `4` JSON dataflow traces, `4` SARIF codeFlows.
- **Preflight Ollama/Qwen (`qwen3.5:9b-q4_K_M`):** HTTP `200`, thời gian `593.05 ms`, `eval_count = 18`, tắt proxy (`ProxyHandler({})`), chặn redirect (`NoRedirect`), không có cloud fallback. Không dùng kết quả preflight thay cho nghiệm thu G1.
- **Theo dõi nhánh `v2/antigravity-review`:** Đầu và cuối phiên đều ở SHA `457183f9e17892fe284da04b57ef6c5c24b008e0`. Lệnh `git ls-tree -r --name-only 457183f9e17892fe284da04b57ef6c5c24b008e0 v2/g1_integration` trả về rỗng (chưa có `v2/g1_integration/CANDIDATE.json` với `READY_FOR_INDEPENDENT_TEST`).
- **Hiện trạng CLI fork tại SHA `457183f9e17892fe284da04b57ef6c5c24b008e0`:** `v2/baseline/fork/semgrepai/cli.py` (SHA-256: `19e7ffe28affd9aa4f19e150acd879f955c4f3a4f0173fa9dfa3e67add8c811a`) đang ở trạng thái M1 scanner-only, sinh đầy đủ `opengrep.json`, `opengrep.sarif`, `scan-manifest.json` và `findings.json`, nhưng chưa nối cầu tự động sang `v2.triage` trong cùng một lệnh CLI fork (`fork_cli_has_triage_bridge_at_inspected_sha = False`).

## 3. Thực Thi Chuỗi Runtime & Đối Chiếu Không Quét Lại (Giai đoạn D)

- **Phạm vi thực thi:** `PRE_G1_COMPONENT_READINESS_PROBE_ONLY_NOT_CANDIDATE_ACCEPTANCE`
- **Số lần gọi OpenGrep trong pha quét (`semgrepai`):** `6` lệnh (`--version`, `--json`, `--sarif` cho mỗi lần quét)
- **Số lần gọi OpenGrep phát sinh thêm trong pha Triage/Qwen:** `0` lệnh (`no_redundant_rescan_verified = True`)
- **Tổng số findings đã chạy qua chuỗi thực tế (Demo 1 + Demo 2):** `5` findings (`5/5` có đầy đủ dataflow trace `source -> sink`)
- **Số lời gọi Qwen3.5-9B thật:** `5` lời gọi (`4` phản hồi hợp lệ khớp schema & trích dẫn mã nguồn, `1` phản hồi không hợp lệ)
- **Phân bố trạng thái sau Validator:** `{"SUPPORTED": 4, "UNDETERMINED": 1}`

### Chi tiết từng cảnh báo qua Qwen3.5-9B cục bộ

| Alert ID (rút gọn) | Rule ID | CWE | Dòng | Raw Status | Validated Status | Citation Check | Review State | Latency (s) | Eval Tokens |
|---|---|---|---|---|---|---|---|---|---|
| `8f2ebe62749f...` | `v2.baseline.rules.ntk.java.cwe22` | `CWE-22` | `7-7` | `SUPPORTED` | `SUPPORTED` | `MATCHED` (`2`) | `OPEN` | `12.39` | `315` |
| `704491957979...` | `v2.baseline.rules.ntk.java.cwe78` | `CWE-78` | `8-8` | `SUPPORTED` | `SUPPORTED` | `MATCHED` (`2`) | `OPEN` | `8.25` | `334` |
| `0e8658862ddb...` | `v2.baseline.rules.ntk.java.cwe79` | `CWE-79` | `9-9` | `SUPPORTED` | `SUPPORTED` | `MATCHED` (`3`) | `OPEN` | `9.016` | `369` |
| `eba1ff58561a...` | `v2.baseline.rules.ntk.java.cwe89` | `CWE-89` | `10-10` | `SUPPORTED` | `SUPPORTED` | `MATCHED` (`3`) | `OPEN` | `8.984` | `367` |
| `e156ce55273f...` | `v2.baseline.rules.ntk.java.cwe89` | `CWE-89` | `7-7` | `REFUTED` | `UNDETERMINED` | `NOT_VERIFIED` (`0`) | `OPEN` | `14.235` | `603` |

## 4. Kết Quả 5 Kịch Bản Demo Runtime G1 (Giai đoạn E)

1. **Demo 1 - Cảnh báo thật (CWE-22 & CWE-89):** Trạng thái `PASS`. Ghi nhận `4` findings thực từ OpenGrep `1.25.0` (gồm `CWE-22, CWE-78, CWE-79, CWE-89`), đầy đủ vị trí Java, source/sink trace (`True`), phản hồi thật từ `qwen3.5:9b-q4_K_M`, kiểm tra trích dẫn `MATCHED`, và toàn bộ `4` cảnh báo giữ trạng thái `OPEN` trong hàng đợi mặc định.
2. **Demo 2 - Cảnh báo giả có cơ chế bảo vệ (`AllowlistedQuery.java`):** Trạng thái `PASS`. Cảnh báo `e156ce55273f0640...` (`v2.baseline.rules.ntk.java.cwe89`) có chốt chặn allowlist hằng số `SELECT 1` trong mã Java. Qwen đánh giá `UNDETERMINED` nhưng hệ thống vẫn giữ trạng thái `OPEN` chờ người duyệt. Khi thực thi `confirm-false` bằng actor mô phỏng `SCRIPTED-DEMO` (`exit_code = 0`), số cảnh báo trong hàng đợi mặc định giảm từ `1 -> 0`, và khi xem toàn bộ (`queue --all`) vẫn còn `1` bản ghi ở trạng thái `CONFIRMED_FALSE`.
3. **Demo 3 - Mở lại cảnh báo (`reopen`):** Trạng thái `PASS`. Thực thi `reopen` trên cảnh báo `e156ce55273f0640...` (`exit_code = 0`). Cảnh báo quay lại hàng đợi mặc định (`1` bản ghi, trạng thái `OPEN`), lịch sử bảo toàn đủ `2` sự kiện (`confirm-false, reopen`), không mất bản ghi OpenGrep hay đánh giá Qwen.
4. **Demo 4 - Chặn xác nhận giả khi nguồn thay đổi (`STALE_SOURCE`):** Trạng thái `PASS`. Trên bản sao mã Java riêng, mã băm SHA-256 thay đổi từ `aec52e6804992b31...` sang `c58da303d11966a7...`. Lệnh `confirm-false` bị từ chối với `exit_code = 2` và thông báo `UNDETERMINED / operation refused: source unavailable/changed; rescan required: source hash mismatch; rescan required: AllowlistedQuery.java`. Không có sự kiện `confirm-false` mới được ghi thêm (`no_new_event_appended = True`), cảnh báo giữ nguyên trạng thái `OPEN`, và fixture G0 gốc được bảo toàn 100% (`g0_fixtures_unchanged = True`).
5. **Demo 5 - Xử lý lỗi Qwen (Mock Fault Injection):** Trạng thái `PASS` (`MOCK_FAULT_INJECTION_INVALID_JSON`). Khi dịch vụ mô hình trả về chuỗi JSON lỗi cú pháp (ghi rõ là fault injection mô phỏng, không phải lỗi từ Qwen thật), validator hạ trạng thái đánh giá về `UNDETERMINED` (`all_model_statuses_undetermined = True`) và giữ nguyên toàn bộ `4` cảnh báo ở trạng thái `OPEN` trong SQLite.

## 5. Phân Cấp Mức Chứng Thực (Giai đoạn G)

| Mức | Nội dung chứng thực | Quan sát được | Ghi chú phạm vi |
|---|---|---|---|
| `level_1_mock_or_synthetic_test` | Demo 5 fault injection (invalid JSON over loopback mock server) and 59/32 unit tests. | `True` | Tách biệt nghiêm ngặt theo Mục 8 |
| `level_2_real_scanner_executed` | OpenGrep v1.25.0 executed on ADMIN-PC (WSL2 Ubuntu-IRIS binary via bridge), producing verified JSON, SARIF, and dataflow traces. | `True` | Tách biệt nghiêm ngặt theo Mục 8 |
| `level_3_ollama_http_request_received` | Loopback http://127.0.0.1:11434 received 1 preflight request + 5 E2E/Demo requests with ProxyHandler({}) and NoRedirect. | `True` | Tách biệt nghiêm ngặt theo Mục 8 |
| `level_4_ollama_response_recorded` | All 6 real HTTP 200 responses from Ollama v0.40.7 recorded in private evidence with SHA-256 request/response binding. | `True` | Tách biệt nghiêm ngặt theo Mục 8 |
| `level_5_local_model_runtime_observed_by_host_logs` | Observed on ADMIN-PC via Ollama v0.40.7 /api/tags digest 56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90, eval_count > 0, and GPU RTX 4060 Ti execution; no third-party hardware attestation signature exists. | `True` | Tách biệt nghiêm ngặt theo Mục 8 |
| `level_6_independent_ground_truth_security_correctness` | Out of scope for G1 (belongs to G3). Qwen SUPPORTED/REFUTED outputs are model assessments, never Ground Truth. | `False` | Tách biệt nghiêm ngặt theo Mục 8 |

## 6. Mã Băm Hiện Vật (Artifact SHA-256) & Đường Dẫn Bằng Chứng Riêng (Giai đoạn F)

- **Vùng lưu trữ bằng chứng thô (ngoài GitHub):** `<private-evidence-root>/G1-C1/run_20261112T210701Z`

| Hiện vật (Artifact) | SHA-256 |
|---|---|
| `preflight/preflight_receipt.json` | `883b7d120bb91f6ec07d2f267f3a852b0d24d43cdd8324c588a87f16e7554240` |
| `preflight/opengrep_preflight.json` | `c701b4873bca7601945a2dbb60f7d1284c4785cd42bdf2f37deaee3a2447e170` |
| `preflight/opengrep_preflight.sarif` | `faffceed9d821c1326213a354104ee2f0fd7318398282d22e5dd6be1e8da26c5` |
| `preflight/qwen_preflight_request.json` | `59cdb16373ef9d81ca80b157b11d7e5d0eee4955b0145f66ae11011418c66be1` |
| `preflight/qwen_preflight_response.json` | `cca0688703bef462b9fd748a70a1c20a4a3d173ad4ef5cc66f53edfda532c0cc` |
| `fork_cli_scan/opengrep.json` | `5d2c605d4a5ce4b10757cd2bb584a940c4edaded6c0c9d8db7326d47cc78c5be` |
| `fork_cli_scan/opengrep.sarif` | `d7fb54a3e4ebab9ed3a85d569a1457abb63e0c1e8c87315a0fdde18f34efdbd5` |
| `fork_cli_scan/scan-manifest.json` | `3d408e803cdb8046c14e0949f9d3ae0eaec6263d7ab2d938c4ecf601cf7225c4` |
| `fork_cli_scan/findings.json` | `c84fd6aa839235be6c6cd53380de5af11e91565c67e3458006edd6d7b2f5a602` |
| `e2e_triage_qwen35/evidence.json` | `8b054f3c478a4883b88e415e3509592c74fbda0244d328b96b7533c05b96ab3a` |
| `e2e_triage_qwen35/assessments.jsonl` | `22d9be7450ecad86f290aafaeaf6f198b535c859d18a2252e6d9f9df089eee6a` |
| `e2e_triage_qwen35/review.sqlite` | `d3868c8894f3e015919075aa21283594ef2d8dcfed3725bac1dc4e3c7a30a1ad` |
| `e2e_triage_qwen35/live-protocol-check.json` | `fa1c422f74a517b40e6751ef0b010173c419730821b788358a5a3a751b776ac5` |
| `demo2_triage_qwen35/evidence.json` | `23523e83d8a65c9156f03b8d281d9e0a0813da6b701d9601afc8406efc07c9f6` |
| `demo2_triage_qwen35/assessments.jsonl` | `788399b8deb0b108d812ca0390ff0bb30bee1bc859d12ba8b689eddd7d0f6d93` |
| `demo2_triage_qwen35/review.sqlite` | `ba86765f94fa0af02ca4ff30ccfbf733520d021581f685671383b06d5729409e` |
| `demo5_fault_injection/assessments.jsonl` | `040dbc3a449b1e899fffb986fc231861154d5a2119daa0494d8641fffcd214fc` |
| `demo5_fault_injection/review.sqlite` | `be484766a27f7f6c69f6812e8c51973c20568a73be0ef26cba9b68273df95cdc` |
| `opengrep_invocations.jsonl` | `800ab8756520b0c0a2d90c6c6ceefef3186ec7a4d361fb0022bd5314804f6f38` |

## 7. Các Lỗi / Blocker Runtime & Các Mục Chưa Thể Chứng Thực

- **[G1-RUNTIME-CANDIDATE-01] (BLOCKER_FOR_G1_ACCEPTANCE) `CANDIDATE_NOT_AVAILABLE`:** Branch v2/antigravity-review is at 457183f9e17892fe284da04b57ef6c5c24b008e0 (pre-G1 HEAD) and does not contain v2/g1_integration/CANDIDATE.json with READY_FOR_INDEPENDENT_TEST. At this pre-G1 commit, v2/baseline/fork/semgrepai/cli.py is still the M1 scanner-only CLI and has not yet been bridged directly into v2.triage.

### Các mục chưa thể chứng thực hoặc nằm ngoài phạm vi:
- End-to-end single-command execution from a ready G1 candidate commit (v2/g1_integration/CANDIDATE.json is not yet published on v2/antigravity-review).
- Third-party cryptographic attestation of model inference (only host-level runtime observation on ADMIN-PC is possible).
- Held-out accuracy / Ground Truth evaluation of Qwen3.5-9B (belongs to stage G3, not G1).
- Independent human security analyst review (Demo 2/3/4 used simulated actor SCRIPTED-DEMO).
