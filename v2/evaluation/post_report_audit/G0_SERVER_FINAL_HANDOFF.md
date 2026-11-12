# Bàn Giao Cuối Cùng Giai Đoạn G0: Kiểm Toán Pháp Y Hiện Vật Máy Chủ & Phạm Vi Thực Chứng (`ADMIN-PC`)

- **Ngày lập biên bản:** `2026-11-13`
- **Vai trò thực hiện:** `Javis` (Kiểm toán độc lập hiện vật máy chủ, đối chiếu mã băm, kiểm định nhãn chuẩn & phân tích giới hạn phương pháp luận trên `ADMIN-PC`)
- **Phạm vi kỹ thuật:** Chỉ giới hạn trong bài toán **Java CWE-22 (Path Traversal) và CWE-89 (SQL Injection)** với quy trình **OpenGrep cục bộ + Qwen (`qwen3.5:9b-q4_K_M` qua Ollama HTTP)**. Không mở rộng sang IRIS, CodeQL, fine-tuning, CWSS hoặc giao diện.

---

## 1. Nhánh, Commit và Trạng Thái Git

- **Kho làm việc của Javis:** `C:\Users\Admin\ntk-thesis-v2\javis`
- **Nhánh làm việc:** `v2/javis-benchmark` (theo dõi `origin/v2/javis-benchmark`)
- **Commit nền đầu phiên (trước khi ghi biên bản bàn giao G0 cuối cùng):** `955edab4a03def71850f095918ce2890d5e544e0`
- **Commit mốc kiểm toán chỉ đọc (`worktree_root`):** `86636b9de22e59efcca2d3786434727c6ae082e4` (`C:\Users\Admin\ntk-thesis-v2\post-report-cwe22-cwe89`, nhánh `v2/post-report-cwe22-cwe89-20261112`)
- **Trạng thái lịch sử Git:** Không rebase, không force-push, không sửa lịch sử commit, không tạo nhánh từ xa mới, không chỉnh sửa các module thuộc quyền sở hữu của `Codex` (`v2/triage/*`, `v2/baseline/*`) hoặc `Antigravity` (`v2/docs/*`).
- **Tính bất biến của thư mục bằng chứng lịch sử (`C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112`):** `zero_mutation_verified = true` (`263/263` tệp nguyên vẹn tuyệt đối: `added = 0`, `removed = 0`, `modified = 0`).

---

## 2. Danh Sách Đầu Vào Đã Kiểm Và Mã Băm SHA-256 Liên Quan

Toàn bộ `263` tệp trong `evidence_root` và `37` tệp trong `worktree_root` (`v2/evaluation/post_report` và `v2/docs`) đã được lập danh mục tại `01_file_inventory_sha256.csv` / `.json`. Bảng dưới đây tổng hợp các đầu vào cốt lõi:

| Nhóm hiện vật | Đường dẫn tương đối / định danh | Kích thước / Số lượng | SHA-256 / Commit thực tế đã xác minh |
|---|---|---:|---|
| Bộ quy tắc OpenGrep | `v2/evaluation/post_report/rules/p_java_cwe22_cwe89.yml` | `9` quy tắc (`2` CWE-22, `7` CWE-89) | `4d12f6deabee1bcf17f1bcce845f05eaf84b312ee13aa6a9cd9721ea879695f9` |
| Binary OpenGrep (Windows PE) | `C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.exe` | `48,505,856` bytes (`v1.25.0`) | `b010709bb790086083442eabe9a0b6bf48064ed87cdf808591baecdb60ccdf73` |
| Binary OpenGrep (WSL Linux) | `/usr/local/bin/opengrep` (`Ubuntu-IRIS`, `v1.25.0`) | Binary ELF | `9ac4aebb6cb20bd808f1aaab6b35f09cd706d881fa7ef6f73e211b9fc3b69923` |
| Bản quét gốc 1 (`dev_set_16`) | `runs/stage1_dev_set_16_scan/opengrep.json` | `64,362` bytes (`16` cảnh báo) | `ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f` |
| Manifest quét 1 (`dev_set_16`) | `runs/stage1_dev_set_16_scan/scan-manifest.json` | `7,942` bytes | `67d708880cb7a93f972586a137c159fff478783788c0bcb1a30d6cb866e8f298` |
| SARIF quét 1 (`dev_set_16`) | `runs/stage1_dev_set_16_scan/opengrep.sarif` | `58,524` bytes (`16` kết quả) | `0b14d52b63313cb8cb317e37d79d2431db8e461ce46218cc169b997a5b3b1e0a` |
| Bản quét gốc 2 (`heldout_set_40`) | `runs/stage1_heldout_set_40_scan/opengrep.json` | `172,103` bytes (`40` cảnh báo) | `67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b` |
| Manifest quét 2 (`heldout_set_40`) | `runs/stage1_heldout_set_40_scan/scan-manifest.json` | `13,848` bytes | `3f5488d9a8de308b33111b5b5b88fd2bf6342ff3a18d8b9458b6936725b64fab` |
| SARIF quét 2 (`heldout_set_40`) | `runs/stage1_heldout_set_40_scan/opengrep.sarif` | `129,432` bytes (`40` kết quả) | `4248085bc26e4401fb7e04f1cf7ab9440284e1db70600c20ae2369c257a495c4` |
| Bản quét gốc 3 (`real_projects`) | `runs/stage5_real_projects_scan/opengrep.json` | `72,634` bytes (`20` cảnh báo) | `99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041` |
| Manifest quét 3 (`real_projects`) | `runs/stage5_real_projects_scan/scan-manifest.json` | `6,348` bytes | `688083ecec3e04bc03d2e6ae5f958c7df3bdf1c69af0b2971c574abb7f4b90b6` |
| SARIF quét 3 (`real_projects`) | `runs/stage5_real_projects_scan/opengrep.sarif` | `58,527` bytes (`20` kết quả) | `ef3f1d00e26f2964b046d3d7a3c9e9368186dcbf2bc87ab8ed00018e99dd9a07` |
| Nhãn chuẩn OWASP v1.2 | `sources/expectedresults-1.2.csv` | `62,286` bytes (`2,740` testcases) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Nhãn `dev_set_16` | `v2/evaluation/post_report/labels_development.json` | `30,084` bytes (`16` nhãn) | `4a6c9493fd549d561be11a31e7e98a922d97cd4d8f2881fb2a8b1ef4db9b3005` |
| Nhãn `heldout_set_40` | `v2/evaluation/post_report/labels_heldout.json` | `73,913` bytes (`40` nhãn) | `e0a31fd7542a79ff923b5e1099e7d6c6b9849e17b09d124dd76ec99ec0762165` |
| Cảnh báo khóa `heldout_set_40` | `v2/evaluation/post_report/heldout_alerts.json` | `177,065` bytes (`40` cảnh báo) | `383c715471bc69e180c0ae1628e6487de8df456084d20e374315460783d09e0f` |
| Manifest khóa `STRICT_LOCK` | `v2/evaluation/post_report/heldout_strict_lock_manifest.json` | `combined_lock_sha256` | `4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09` (`file SHA: cfd15014176ca88a1e7fb141e94788f50fd14c1e16e7e3a81e70d6ef0b4b8b87`) |
| Bảng đánh giá bắt cặp | `v2/evaluation/post_report/PAIRED_EVALUATION.csv` | `35,627` bytes (`40` dòng x `27` cột) | `e19fc514e04d786ab3465d83eb66494955e6507d8b5b2a04b8ca29c469062ae5` |
| Run 1 (`dev16_baseline_v1_0`) | `runs/stage2_dev16_baseline_v1_0/assessments.jsonl` | `204,791` bytes (`16` bản ghi) | `bf6b718193d0bc18e09ab19e4334a083651460cbba78c316e7203fd738b66c36` |
| Run 2 (`dev16_armB_heuristic`) | `runs/stage3_dev16_armB_heuristic/assessments.jsonl` | `157,108` bytes (`16` bản ghi) | `687811fc60498df221303f8e2524c5c4ca7fb1b238928efbc9b94cc4f47047f7` |
| Run 3 (`dev16_armC_evidence_llm`) | `runs/stage3_dev16_armC_evidence_llm/assessments.jsonl` | `223,281` bytes (`16` bản ghi) | `219853159b329b60f1dc392a8ca8ab8fc219225a93ca7cf4d2c7557a29cd948e` |
| Run 4 (`dev16_armC_v2_1`) | `runs/stage3_dev16_armC_v2_1_evidence_llm/assessments.jsonl` | `223,412` bytes (`16` bản ghi) | `1ca357fb8466466d85a0808867ed84fc9ef21c3310695462fd294957e8a9ae3b` |
| Run 5 (`dev16_armD_llm_ablation`) | `runs/stage3_dev16_armD_llm_ablation/assessments.jsonl` | `214,043` bytes (`16` bản ghi) | `00d9bf11e02f3632cb9ba9c98301be48188732d227bf51ae31197d7d97268e50` |
| Run 6 (`heldout40_armB_heuristic`) | `runs/stage4_heldout40_armB_heuristic/assessments.jsonl` | `388,520` bytes (`40` bản ghi) | `3fa5ab780ab7fa251205fb09dc83f62dc682e3e86f3cd18de49ac7c7f57f9761` |
| Run 7 (`heldout40_armC_evidence_llm`) | `runs/stage4_heldout40_armC_evidence_llm/assessments.jsonl` | `554,321` bytes (`40` bản ghi) | `be11efdb75999fd164dbbcbf3c962403f6743cdff89a9e1a86d78e99fb0706ff` |
| Run 8 (`heldout40_armD_llm_ablation`) | `runs/stage4_heldout40_armD_llm_ablation/assessments.jsonl` | `532,681` bytes (`40` bản ghi) | `8489c3b8e846b8061a7bf898216c343578a14aa2d406b42029699b08e333e7f7` |
| Run 9 (`real_projects_armB_heuristic`) | `runs/stage5_real_projects_armB_heuristic/assessments.jsonl` | `253,890` bytes (`20` bản ghi) | `d9b0047a278114084c45c504df63eb62c38f848bd0754a906f10142792072984` |
| Run 10 (`real_projects_armC_evidence_llm`) | `runs/stage5_real_projects_armC_evidence_llm/assessments.jsonl` | `332,960` bytes (`20` bản ghi) | `6d58f3fd2cb80736881682a45269e0131e026e270b79aa6deae11230272db994` |
| Upstream `BenchmarkJava` (WSL) | `/home/tuankhoa/migration/ntk_ft211_sources/BenchmarkJava` | `56/56` tệp Java khớp SHA-256 | Commit `8b67a88d73b2594570fc21150705283de884620b` (`clean = true`) |
| Upstream `WebGoat` (WSL) | `/home/tuankhoa/iris/data/project-sources/WebGoat` | `6/6` tệp Java khớp SHA-256 | Commit `5357a65e054976cd7d79b81ef3906ded050ed921` (`clean = true`) |
| Upstream `java-sec-code` (WSL) | `/home/tuankhoa/migration/ntk_ft211_sources/java-sec-code` | `1/1` tệp `SQLI.java` khớp SHA-256 | Commit `4711f4e186258c6e0dd5c3863e7c9592e7e9026a` (`clean = true`) |
| Mẫu thực nghiệm `UserDao.java` | `sources/real_projects/demo/UserDao.java` | `2,216` bytes (`70` dòng) | `6c890fc869f74cdceb6bd8f73e04be4fc7ffb4defdab008c098642e146be1d24` |

---

## 3. Phân Loại `PASS / FAIL / INCOMPLETE` Cho Từng Tiêu Chí (`C01`-`C09`)

Công cụ kiểm toán độc lập `v2/evaluation/audit_server_forensic_receipt.py` sử dụng cơ chế fail-closed (`0 = PASS`, `1 = FAIL`, `2 = INCOMPLETE`, có chốt chặn `force_pass_attempt_blocked`). Kết quả chạy trên hiện vật thực tế tại `C:\Users\Admin\ntk-thesis-v2\evidence\server_forensic_audit_failclosed_20261112\11_fail_closed_gate_verdict.json`:

| Mã tiêu chí | Tên tiêu chí kiểm toán kỹ thuật | Phân loại | Mã thoát / Tóm tắt định lượng |
|---|---|---|---|
| `C01_historical_immutability` | Tính bất biến của `263` tệp bằng chứng lịch sử trước và sau kiểm toán | **`PASS`** | `evidence_file_count = 263`, `zero_mutation_verified = true`, `added = 0`, `removed = 0`, `modified = 0` |
| `C02_opengrep_three_scans_and_9_rules` | Toàn vẹn 3 bản quét OpenGrep gốc, bộ 9 quy tắc YAML, `scan-manifest.json` và đối chiếu 1-1 với SARIF | **`PASS`** | `rule_count = 9`, `3/3` SHA-256 khớp, `3/3` SARIF khớp 1-1 (`16`, `40`, `20` findings), `0` lỗi/skip |
| `C03_ollama_10_assessments_and_6_checkpoints` | Toàn vẹn cấu trúc 10 tệp `assessments.jsonl` (`240` bản ghi), 6 tệp checkpoint (`148` bản ghi) và phản hồi HTTP Ollama | **`PASS`** | `10` JSONL (`240` bản ghi), `6` checkpoints (`148` bản ghi), `0` dòng lỗi, `158/158` `response_json_sha256` khớp |
| `C04_citations_and_post_validator_integrity` | Đối chiếu từng dòng trích dẫn (`citations`) và `snapshots.sha256` với tệp mã nguồn Java trên đĩa | **`PASS`** | `240/240` bản ghi khớp `snapshots[path].sha256` và khớp nguyên văn dòng mã nguồn trích dẫn trên đĩa |
| `C05_paired_evaluation_per_alert_table` | Đối chiếu độc lập toàn bộ `40` dòng x `27` cột (`1,080` ô) của `PAIRED_EVALUATION.csv` | **`PASS`** | `rows_verified = 40`, `columns_verified_count = 27`, `discrepancy_count = 0`, sai số latency `<= 0.05 ms` |
| `C06_ground_truth_56_owasp_and_20_real_projects` | Đối chiếu 56 nhãn OWASP với `expectedresults-1.2.csv`, kiểm tra giao tập `0`, `STRICT_LOCK` và cấu trúc 20 nhãn dự án thực tế | **`PASS`** | `16/16` dev + `40/40` held-out khớp CSV OWASP, `overlap = 0`, `STRICT_LOCK = 4fb55637...`, `20` cảnh báo (`12` loci) |
| `C07_sqlite_readonly_and_stale_source_lifecycle` | Kiểm tra chỉ đọc 10 tệp `review.sqlite` và kiểm thử vòng đời 5 bước + chốt chặn `STALE_SOURCE` trên bản sao tạm | **`PASS`** | `10/10` SQLite đạt `integrity_check = ok`, `0` human events; bản sao tạm đạt `5/5` bước (`STALE_SOURCE` exit code `2`) |
| `C08_guided_llm_confounder_and_zero_label_leakage` | Kiểm tra không rò rỉ khóa nhãn chuẩn vào prompt và định lượng mức độ dẫn dắt của `heuristic_signals` trong Nhánh C | **`PASS`** | `prompt_leak_hits_count = 0`; ghi nhận chính xác `concordance_display = 76/76` (`100%`) giữa `recommended_status` và Qwen |
| `C09_metrics_recomputation_alignment` | Tái tính độc lập toàn bộ ma trận nhầm lẫn, precision/recall (`drop_fp`, `keep_tp_only`), latency và đối chiếu `score_pilot` | **`PASS`** | Khớp tuyệt đối: Arm B (`9/20 TP`, `7/20 FP`, `20/33`), Arm C (`20/20`, `20/20`, `421,000 ms`), Arm D (`17/20`, `9/40`, `301,062 ms`) |

> **Lưu ý phương pháp luận tối quan trọng:** Kết quả `9/9 PASS` (`exit_code = 0`) là phán quyết kỹ thuật của bộ kiểm toán trên các tệp hiện vật đang lưu trên đĩa. Để tránh mọi sự hiểu lầm hoặc suy diễn quá mức, Mục 4 dưới đây bóc tách rõ ràng giới hạn chứng minh thực tế của từng cổng `C01`-`C09`.

---

## 4. Phạm Vi Chứng Minh Thực Sự Của Kết Quả `9/9 PASS`

Bảng dưới đây trả lời tường minh 5 câu hỏi bắt buộc cho từng tiêu chí `C01`-`C09`:
1. Tiêu chí kiểm tra chính xác điều gì?
2. Dùng dữ liệu thô nào?
3. Có độc lập với code production (`v2/triage/*`, `v2/baseline/*`, `v2/evaluation/*`) hay không?
4. Kết quả `PASS` chứng minh được điều gì?
5. Kết quả `PASS` **KHÔNG** chứng minh được điều gì?

| Tiêu chí | (1) Kiểm tra điều gì? | (2) Dữ liệu thô đầu vào | (3) Mức độ độc lập với code production | (4) `PASS` chứng minh được điều gì? | (5) `PASS` KHÔNG chứng minh được điều gì? |
|---|---|---|---|---|---|
| **`C01`** (`historical_immutability`) | Đối chiếu số lượng tệp, kích thước byte và SHA-256 của toàn bộ tệp trong `evidence_root` trước và sau khi chạy trình kiểm toán. | `263` tệp trong `evidence/post_report_cwe22_cwe89_20261112` và tệp chụp nhanh `00_pre_audit_sha256_snapshot.json`. | **Độc lập 100%** (chỉ dùng `hashlib.sha256` và `Path.stat` chuẩn của Python). | Chứng minh quá trình kiểm toán của Javis hoàn toàn chỉ đọc (`READ-ONLY`), không làm thay đổi dù chỉ 1 byte trong `263` tệp bằng chứng lịch sử. | **Không** chứng minh các tệp trong `evidence_root` được sinh ra như thế nào trước thời điểm chụp snapshot đầu tiên; không chứng minh tính độc lập của dữ liệu gốc. |
| **`C02`** (`opengrep_three_scans_and_9_rules`) | Kiểm tra số lượng quy tắc và SHA-256 của `p_java_cwe22_cwe89.yml`; kiểm tra SHA-256 của 3 tệp `opengrep.json`; kiểm tra `scan-manifest.json` (`sources_before == sources_after == disk`, `rules_before == rules_after`, `errors == 0`, `skipped == 0`, `100%` có `dataflow_trace`); đối chiếu multiset 1-1 giữa `opengrep.json` và `opengrep.sarif`. | `p_java_cwe22_cwe89.yml`, 3 thư mục `runs/stage1_dev_set_16_scan`, `stage1_heldout_set_40_scan`, `stage5_real_projects_scan` (`opengrep.json`, `opengrep.sarif`, `scan-manifest.json`, `rules.snapshot.yml`), và 64 tệp `.java` trong `sources/`. | **Độc lập phần lớn, phụ thuộc một phần:** Hàm `verify_sarif_against_opengrep_json` và kiểm tra SHA-256 là độc lập 100%; riêng bước kiểm tra cấu trúc biên nhận gọi thêm `v2.triage.scan_receipt.verify_receipt()` của code production. | Chứng minh bộ quy tắc trên đĩa có đúng `9` rule (không phải `14`), 3 tệp `opengrep.json` và `opengrep.sarif` khớp nhau 1-1, và mã nguồn Java trên đĩa khớp 100% với `sources_before`/`sources_after` trong manifest cũng như kho upstream WSL. | **Không** tự chạy lại binary `opengrep.exe` trong lúc kiểm toán; và các tệp `scan-manifest.json` chỉ là biên nhận tự ghi cục bộ (`signed_or_independently_attested = false`), không có chữ ký mật mã từ hệ thống CI bên ngoài. |
| **`C03`** (`ollama_10_assessments_and_6_checkpoints`) | Kiểm tra sự tồn tại và tính hợp lệ JSON của 10 tệp `assessments.jsonl` (`240` bản ghi) và 6 tệp `.ckpt.jsonl` (`148` bản ghi); kiểm tra công thức `alert_id = SHA256(scan_sha256 + ":" + finding_index)`; kiểm tra `http_status == 200`, `done == True`, `eval_count > 0`, `response_json_sha256` (`158/158`); kiểm tra `request_payload_sha256` trên 4 lượt chạy khóa `v2.1` (`116/116`). | 10 tệp `runs/*/assessments.jsonl`, 10 tệp `runs/*/input.opengrep.json`, 6 tệp `checkpoints/*.ckpt.jsonl`. | **Độc lập phần lớn, phụ thuộc một phần:** Kiểm tra JSONL, `alert_id` và `response_json_sha256` là độc lập 100%; riêng việc tái tạo preimage để kiểm tra `request_payload_sha256` (`116/116`) gọi hàm `v2.triage.ollama.request_payload()` của code production. | Chứng minh 240 bản ghi JSONL và 148 bản ghi checkpoint không bị hỏng/cắt cụt, `response_json_sha256` khớp 100% với `raw_response` được lưu, và 4 lượt chạy `v2.1` được tạo từ đúng hàm `request_payload()` hiện hành. | **Không** chứng thực độc lập tiến trình máy chủ Ollama (`OLLAMA_SELF_REPORTED_LOCAL_HTTP_UNATTESTED`); **không** chứng thực nguyên văn chuỗi prompt thô từ đĩa (`PROMPT_NOT_ATTESTED`); và **không** tái tạo được `request_payload_sha256` của 3 lượt chạy cũ trước `v2.1` (`0/42`). |
| **`C04`** (`citations_and_post_validator_integrity`) | Đối chiếu `evidence.snapshots[path].sha256` với tệp `.java` thực tế trên đĩa; đối chiếu từng phần tử trong `assessment.citations` (`path`, `start_line`, `end_line`, `quote`, `sha256`) với nội dung dòng thực tế của tệp `.java` trên đĩa (`actual_txt == c_quote`). | 10 tệp `runs/*/assessments.jsonl` và 64 tệp `.java` trong `sources/dev_set_16`, `sources/heldout_set_40`, `sources/real_projects`. | **Độc lập 100%** (viết lại bộ kiểm tra dòng và SHA-256 trực tiếp trên tệp `.java`, không gọi `v2.triage.validator`). | Chứng minh `240/240` bản ghi hậu kiểm không chứa trích dẫn bịa đặt (hallucinated lines/quotes): mọi dòng được giữ lại trong `assessment.citations` đều tồn tại nguyên văn trong tệp Java trên đĩa. | **Không** chứng minh dòng mã được trích dẫn thực sự là bằng chứng bảo mật đúng về mặt ngữ nghĩa (ví dụ: ở Nhánh D, Qwen trích dẫn đúng dòng sink nên qua được bộ kiểm chứng trích dẫn cho `14/20` FP nhưng phán quyết `SUPPORTED` vẫn là sai). |
| **`C05`** (`paired_evaluation_per_alert_table`) | Kiểm tra độc lập từng ô trong `40` dòng x `27` cột (`1,080` ô) của `PAIRED_EVALUATION.csv` so với `opengrep.json`, `labels_heldout.json`, `expectedresults-1.2.csv`, 3 tệp `assessments.jsonl` (Arm B, C, D) và `review.sqlite` (bao gồm kiểm tra sai số `latency_ms <= 0.05 ms` từng dòng). | `PAIRED_EVALUATION.csv`, `stage1_heldout_set_40_scan/opengrep.json`, `labels_heldout.json`, `expectedresults-1.2.csv`, `stage4_heldout40_arm{B,C,D}_*/assessments.jsonl`, `review.sqlite`. | **Độc lập 100%** (`audit_paired_evaluation_table` trong `server_forensic_gates.py` tự tính lại toàn bộ 27 cột từ dữ liệu thô, không gọi `build_paired_pilot_table.py`). | Chứng minh bảng `PAIRED_EVALUATION.csv` phản ánh trung thực 100% (`0/1,080` ô sai lệch) dữ liệu từ các tệp JSONL, SQLite và CSV gốc, không có hiện tượng sửa tay bảng tổng hợp hay tráo đổi latency giữa các cảnh báo. | **Không** chứng minh kết quả `20/20 TP` và `20/20 FP` của Nhánh C trong bảng là do năng lực suy luận độc lập của Qwen (vì bảng chỉ ghi lại kết quả của Nhánh C vốn đã bị dẫn dắt bởi `heuristic_signals`). |
| **`C06`** (`ground_truth_56_owasp_and_20_real_projects`) | Kiểm tra SHA-256 của `expectedresults-1.2.csv`; đối chiếu `16/16` nhãn dev và `40/40` nhãn held-out (`ground_truth`, `cwe`, token dòng sink, `1` finding/file); kiểm tra giao tập `dev` vs `heldout` bằng `0`; kiểm tra `STRICT_LOCK`; kiểm tra cấu trúc 20 nhãn dự án thực tế (`16 TP / 4 FP` trên `12` loci). | `expectedresults-1.2.csv`, `labels_development.json`, `labels_heldout.json`, `heldout_alerts.json`, `heldout_strict_lock_manifest.json`, 64 tệp `.java`. | **Độc lập trên kiểm tra OWASP CSV & giao tập; phụ thuộc một phần** vào `v2.evaluation.validate_pilot_lock` khi kiểm tra manifest `STRICT_LOCK` và dùng bảng hằng số `REAL_PROJECT_MANUAL_LABELS` trong script kiểm toán cho 20 cảnh báo thực tế. | Chứng minh 56 nhãn OWASP (`TRUE_POSITIVE`/`FALSE_POSITIVE` và `CWE-22`/`CWE-89`) khớp 100% với đáp án chính thức của OWASP Benchmark v1.2, không trùng lặp giữa dev và held-out, và khóa `STRICT_LOCK` hợp lệ về mặt toán học. | **Không** chứng minh các câu giải thích văn xuôi (`annotator_rationale`, `sanitizer_or_reason`) trong `labels_*.json` / `LABELING_PROTOCOL.md` là đúng cơ chế Java; và **không** chứng minh 4 nhãn FP thủ công trên dự án thực tế (`#08, #09, #10, #15`) là an toàn tuyệt đối vô điều kiện. |
| **`C07`** (`sqlite_readonly_and_stale_source_lifecycle`) | Sao chép 10 tệp `review.sqlite` ra thư mục tạm để chạy `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, kiểm tra khớp `warnings.state` với bảng `events` và `source_sha256`; chạy kiểm thử 5 bước vòng đời (`confirm-true`, `confirm-false`, `reopen`, từ chối action/actor sai, và chặn `confirm-false` với mã `STALE_SOURCE` exit `2` khi sửa tệp `.java` tạm). | 10 tệp `runs/*/review.sqlite` và bản sao tạm của `stage4_heldout40_armC_evidence_llm`. | **Kiểm tra cấu trúc SQLite độc lập 100%; kiểm thử vòng đời gọi trực tiếp code production** (`v2.triage.cli` và `v2.triage.store.ReviewStore`) trên bản sao tạm để xác minh cơ chế cổng chặn của hệ thống. | Chứng minh 10 tệp `review.sqlite` không bị hỏng cấu trúc, toàn bộ 240 cảnh báo đang ở trạng thái `OPEN` (`0` sự kiện duyệt thủ công giả mạo), và cơ chế `STALE_SOURCE` của `ReviewStore` hoạt động đúng thiết kế khi mã nguồn bị thay đổi. | **Không** chứng minh đã có chuyên gia con người thực sự thực hiện quy trình duyệt cảnh báo trên 10 lượt chạy thực nghiệm (thực tế `human_events_count = 0` trên cả 10 DB). |
| **`C08`** (`guided_llm_confounder_and_zero_label_leakage`) | Quét toàn bộ `evidence` và prompt tái tạo của các lượt chạy `v2.1` để tìm các khóa nhãn chuẩn bị cấm (`ground_truth`, `expected_label`, `owasp_label`, `is_vulnerable`, v.v.); đồng thời đếm tỷ lệ trùng khớp giữa `heuristic_signals.recommended_status` và phán quyết thô của Qwen trên 3 tập `v2.1`. | 10 tệp `runs/*/assessments.jsonl` (đặc biệt 3 tập Nhánh C `v2.1`: `dev16_armC_v2_1`, `heldout40_armC`, `real_projects_armC`). | **Độc lập 100%** (`audit_guided_llm_confounder` trong `server_forensic_gates.py` và `scan_json_for_forbidden_label_keys`). | Chứng minh **không có rò rỉ trực tiếp khóa nhãn chuẩn (`0` leak hits)** vào `evidence` hay prompt; đồng thời **chứng minh và định lượng thành công biến nhiễu**: `heuristic_signals.recommended_status` được truyền vào prompt Nhánh C và trùng khớp `76/76` (`100%`) với đầu ra của Qwen. | **`C08 PASS` tuyệt đối KHÔNG chứng minh Nhánh C không bị dẫn dắt!** Ngược lại, `C08 PASS` nghĩa là công cụ kiểm toán đã phát hiện, ghi nhận đầy đủ biến nhiễu `76/76` (`100%`) và xác nhận không có rò rỉ nhãn chuẩn thô. |
| **`C09`** (`metrics_recomputation_alignment`) | Tự tính lại từ đầu các chỉ số `tp_kept_supported`, `fp_proposed_refuted`, `undetermined`, `citation_matched`, `drop_fp` precision/recall, `keep_tp_only` precision/recall, `latency_ms` (mean/median/p95/min/max/total) và đối chiếu với `score_pilot.evaluate_pilot()`. | 10 tệp `runs/*/assessments.jsonl`, `labels_development.json`, `labels_heldout.json`, `PAIRED_EVALUATION.csv`. | **Độc lập 100%** ở hàm `_compute_bucket_metrics()`, và đối chiếu chéo với `v2.evaluation.score_pilot.evaluate_pilot()` của code production. | Chứng minh mọi con số thống kê trong báo cáo kiểm toán (`9/20`, `7/20`, `20/33`, `20/20`, `17/20`, `9/40`, `421.00s`, `301.06s`) khớp hoàn toàn với dữ liệu JSONL gốc và khớp với `score_pilot.py`. | **Không** chứng minh khả năng khái quát hóa thống kê ra ngoài mẫu thực nghiệm nhỏ (`n = 40` held-out, `n = 20` real projects), và **không** chứng minh hệ thống giảm được FP trên mã nguồn thực tế (`0/4` FP được bác bỏ trên `real_projects`). |

---

## 5. Giới Hạn Xác Thực Của Ollama Runtime Và Prompt

1. **Giới hạn xác thực Ollama Runtime (`OLLAMA_SELF_REPORTED_LOCAL_HTTP_UNATTESTED`):**
   - Trong `164` bản ghi thuộc 7 lượt chạy có cấu hình gọi LLM (`stage2_dev16_baseline_v1_0`, `stage3_dev16_armC_evidence_llm`, `stage3_dev16_armC_v2_1_evidence_llm`, `stage3_dev16_armD_llm_ablation`, `stage4_heldout40_armC_evidence_llm`, `stage4_heldout40_armD_llm_ablation`, `stage5_real_projects_armC_evidence_llm`), có **`158/164`** bản ghi lưu đối tượng `raw_response` hoàn chỉnh với `http_status = 200`, `done = true`, `done_reason = "stop"`, `eval_count > 0`, `model = "qwen3.5:9b-q4_K_M"`, và `runtime.response_json_sha256` khớp 100% (`158/158`) khi băm lại `raw_response`.
   - Riêng **`6/16`** bản ghi CWE-22 tại `stage2_dev16_baseline_v1_0` không gọi HTTP tới Ollama vì bị chốt chặn tiền xử lý (`PRE_LLM_EVIDENCE_GUARD_FALLBACK`) dừng sớm do cấu trúc `CliCall` của OpenGrep chưa được hỗ trợ ở phiên bản `v1.0`.
   - Tuy nhiên, toàn bộ thông tin `raw_response` và `runtime` đều do tiến trình client Python cục bộ ghi lại từ phản hồi HTTP không ký số tại `http://127.0.0.1:11434`. Không có proxy ký nhận độc lập, không có bản chụp gói tin mạng (pcap) hay log hệ thống ngoài tiến trình, và không có mã băm trọng số mô hình (`model digest`) được ghim cứng trong từng dòng JSONL. Do đó, mức độ xác thực runtime bắt buộc phân loại là **`OLLAMA_SELF_REPORTED_LOCAL_HTTP_UNATTESTED`** (`independently_verified_model_runtime = false`).

2. **Giới hạn xác thực Prompt (`PROMPT_NOT_ATTESTED`):**
   - Không có tệp `assessments.jsonl` hay `review.sqlite` nào trong cả 10 lượt chạy lưu nguyên văn chuỗi văn bản prompt (`messages[0].content`, `messages[1].content`) đã gửi cho Ollama. Vì vậy, trạng thái xác thực nguyên văn prompt trên toàn bộ 10 lượt chạy là **`PROMPT_NOT_ATTESTED`**.
   - **Điểm phân biệt kỹ thuật quan trọng giữa các lượt chạy:**
     - Trên **4 lượt chạy khóa `v2.1`** (`stage3_dev16_armC_v2_1_evidence_llm` `16/16`, `stage4_heldout40_armC_evidence_llm` `40/40`, `stage4_heldout40_armD_llm_ablation` `40/40`, `stage5_real_projects_armC_evidence_llm` `20/20`), trường `runtime.request_payload_sha256` khớp **`116/116` (`100%`)** với mã băm SHA-256 của kết quả hàm `v2.triage.ollama.request_payload(evidence, model)` hiện tại. Điều này chứng minh xác định (deterministic) cấu trúc prompt của `116` bản ghi `v2.1` khi đối chiếu kèm mã nguồn `v2/triage/ollama.py`.
     - Ngược lại, trên **3 lượt chạy lịch sử trước `v2.1`** (`stage2_dev16_baseline_v1_0` có `10/16` bản ghi lưu `request_payload_sha256`, `stage3_dev16_armC_evidence_llm` `16/16`, `stage3_dev16_armD_llm_ablation` `16/16`), `request_payload_sha256` khớp **`0/42`** với hàm `request_payload()` hiện tại (do template prompt trong `v2/triage/ollama.py` đã thay đổi giữa các bước phát triển Stage 2/3 trước khi khóa `v2.1`, và phiên bản hàm tạo prompt cũ không được lưu kèm trong từng bản ghi).

---

## 6. Phân Tích Biến Nhiễu Dẫn Dắt LLM (`Heuristic Steering`) Ở Nhánh Kết Hợp (Arm C)

### 6.1. Cơ chế truyền tín hiệu trong mã nguồn (`heuristics.py` -> `ollama.py`)
- Trong `v2/triage/ollama.py` (dòng 56-68), khi `triage_mode` khác `"llm"` (tức ở chế độ mặc định `"evidence+llm"` của Nhánh C), hàm `_prompt_evidence(evidence)` trích xuất `evidence["heuristic_signals"]` và gắn vào khóa `"evidence_signals"` bên trong khối JSON gửi trực tiếp vào prompt cho Qwen:
  ```python
  signals = evidence.get("heuristic_signals")
  if isinstance(signals, dict):
      compact["evidence_signals"] = signals
  ```
- Khối `heuristic_signals` (được sinh bởi `extract_evidence_signals()` trong `v2/triage/heuristics.py`, dòng 516-616) không chỉ chứa thông tin dòng chảy dữ liệu thô (`intra_method_flow`, `callee_method_flow`, `sanitizers`, `guards`) mà còn chứa sẵn **kết luận phán quyết và trích dẫn gợi ý**:
  1. `recommended_status`: Giá trị `"SUPPORTED"` hoặc `"REFUTED"` đã được bộ quy tắc tĩnh tính sẵn.
  2. `recommendation_reason`: Câu giải thích lý do vì sao nên chọn `SUPPORTED` hoặc `REFUTED`.
  3. `candidate_citations`: Danh sách đối tượng trích dẫn hoàn chỉnh (`path`, `start_line`, `end_line`, `quote`, `sha256`) đã được trích xuất sẵn từ tệp nguồn.
- Hơn nữa, prompt hệ thống trong `v2/triage/ollama.py` (dòng 24-40) chỉ thị rõ: *"If `evidence_signals` is present in the evidence JSON, carefully inspect: `callee_method_flow`, `intra_method_flow`, `sanitizers`, `guards`, and `candidate_citations`."*

### 6.2. Sự bất đối xứng giữa Nhánh B (`--mode heuristic`) và `heuristic_signals` trong Nhánh C (`--mode evidence+llm`)
Một phát hiện kỹ thuật cốt lõi giải thích vì sao Nhánh B có `24/40 UNDETERMINED` trong khi `heuristic_signals` bên trong Nhánh C lại đạt `40/40` (`100%`) trên `heldout_set_40`:
- Trong `v2/triage/heuristics.py`, hàm `evaluate_heuristic()` (dùng cho Nhánh B `--mode heuristic`, dòng 482-513) cố tình **giữ lại không kết luận (`UNDETERMINED`)** đối với mọi mẫu có lời gọi phương thức nội bộ (`callee_flow`), danh sách (`list_index_constant_safe` / `list_index_tainted`) hoặc bản đồ (`map_key_safe_constant` / `map_key_tainted_value`). Do đó, trên `heldout_set_40`, Nhánh B chỉ quyết định các mẫu nội hàm đơn giản (`9/20 TP` là `SUPPORTED`, `7/20 FP` là `REFUTED`, và đẩy `24/40` mẫu còn lại sang `UNDETERMINED`).
- Thế nhưng, hàm `extract_evidence_signals()` (chạy ngầm để tạo `heuristic_signals` cho Nhánh C, dòng 574-605) lại **đã giải quyết dứt điểm toàn bộ 5 mẫu giả lập của OWASP Benchmark** (bao gồm cả `callee_flow`, `list_index_*`, `map_key_*`, `constant_source_override` từ `SeparateClassRequest.getTheValue`, `switch_constant_override`, và `arithmetic_constant_override` `(7 * 42) - num > 200` vs `(7 * 18) + num > 200`) để gán thẳng vào `heuristic_signals.recommended_status`!

### 6.3. Bằng chứng định lượng trên cả 3 tập dữ liệu (`76/76 = 100%` đồng thuận)
Khi kiểm tra toàn bộ `76` bản ghi thuộc 3 lượt chạy Nhánh C phiên bản khóa `v2.1` (`10_guided_llm_confounder_audit.json`):

| Tập dữ liệu (Nhánh C `v2.1`) | Số cảnh báo (`n`) | Độ chính xác của riêng `heuristic_signals.recommended_status` so với Ground Truth | Tỷ lệ Qwen (`raw_qwen_status`) đồng thuận với `heuristic_signals.recommended_status` | Số trường hợp Qwen tự sửa sai hoặc bất đồng với `recommended_status` |
|---|---:|---|---|---:|
| `stage3_dev16_armC_v2_1_evidence_llm` | `16` (`8 TP, 8 FP`) | `16/16` (`100.0%`: `8 SUPPORTED`, `8 REFUTED`) | **`16/16` (`100.0%`)** | `0/16` |
| `stage4_heldout40_armC_evidence_llm` | `40` (`20 TP, 20 FP`) | `40/40` (`100.0%`: `20 SUPPORTED`, `20 REFUTED`) | **`40/40` (`100.0%`)** | `0/40` |
| `stage5_real_projects_armC_evidence_llm` | `20` (`16 TP, 4 FP`) | `16/20` (`80.0%`: gán `20/20 SUPPORTED`, sai cả `4/4 FP`) | **`20/20` (`100.0%`)** | `0/20` |
| **Tổng cộng (`3` tập `v2.1`)** | **`76`** | **`72/76` (`94.7%`)** | **`76/76` (`100.0%`)** | **`0/76`** |

### 6.4. Phân biệt tương quan (Correlation) và nhân quả (Causation)
- **Hiện tượng quan sát được (FACT):**
  1. Khi **có** `evidence_signals` trong prompt (Nhánh C): Qwen xuất phán quyết trùng khớp `76/76` (`100%`) với `heuristic_signals.recommended_status`. Ở `heldout_set_40`, vì `heuristic_signals.recommended_status` đúng `40/40`, Nhánh C đạt `40/40` (`100%`). Ở `real_projects`, vì `heuristic_signals.recommended_status` mặc định trả về `20/20 SUPPORTED` (do không nhận diện được `action.replace('\'', '"')`, `@Pattern` liên tệp và chốt chặn `getCanonicalPath()` ở dòng `64 > sink_line 63`), Qwen cũng trả về `20/20 SUPPORTED` (`0/4` FP được bác bỏ).
  2. Khi **bỏ** `evidence_signals` khỏi prompt (Nhánh D `--mode llm` trên `heldout_set_40`): Qwen trả về thô **`40/40 SUPPORTED`** (tức `0/20` FP được bác bỏ, tỷ lệ bác bỏ FP = `0%`), sau đó bộ kiểm chứng trích dẫn hậu kiểm hạ `9/40` bản ghi (`3 TP + 6 FP`) xuống `UNDETERMINED` do trích dẫn sai dòng/mã băm.
- **Kết luận nhân quả khoa học (`CONFOUNDED`):**
  - Thiết kế thực nghiệm hiện tại bị **nhiễu hoàn toàn (confounded)** giữa hai yếu tố được thêm đồng thời từ Nhánh D sang Nhánh C: (a) việc cung cấp ngữ cảnh dòng chảy dữ liệu mở rộng (`callee_method_flow`, `intra_method_flow`) và (b) việc mớm sẵn đáp án `recommended_status` + `recommendation_reason` + `candidate_citations` đã giải xong bằng biểu thức chính quy chuyên biệt cho OWASP Benchmark.
  - Vì không có nhánh thực nghiệm đối chứng nào cung cấp `callee_method_flow` / `intra_method_flow` mà **ẩn/xóa** `recommended_status` và `recommendation_reason`, bằng chứng hiện tại **KHÔNG chứng minh được đóng góp suy luận độc lập của Qwen (`qwen3.5:9b-q4_K_M`)** trong kết quả `20/20 TP` và `20/20 FP` trên `heldout_set_40`.

---

## 7. Đánh Giá 56 Nhãn OWASP Benchmark v1.2 Và 4 Nhãn FP Thủ Công Trên Dự Án Thực Tế

### 7.1. Kiểm toán 56 nhãn OWASP Benchmark v1.2: Tách biệt độ khớp nhãn (`56/56`) và lỗi giải thích cơ chế Java trong `labels_*.json` / `LABELING_PROTOCOL.md`

1. **Độ khớp nhãn `ground_truth` và `cwe` so với đáp án gốc OWASP (`VERIFIED 56/56`):**
   - Đối chiếu trực tiếp với tệp `expectedresults-1.2.csv` (`SHA-256 = 1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`) của OWASP Benchmark v1.2:
     - `dev_set_16` (`labels_development.json`): **`16/16`** khớp nhãn (`8 TRUE_POSITIVE`, `8 FALSE_POSITIVE`) và **`16/16`** khớp CWE (`6 CWE-22`, `10 CWE-89`).
     - `heldout_set_40` (`labels_heldout.json`): **`40/40`** khớp nhãn (`20 TRUE_POSITIVE`, `20 FALSE_POSITIVE`) và **`40/40`** khớp CWE (`20 CWE-22`, `20 CWE-89`).
   - Toàn bộ `56/56` tệp `.java` chỉ phát sinh đúng `1` cảnh báo OpenGrep trên mỗi tệp tại đúng dòng sink thực tế, nên nhãn mức testcase của OWASP tương đương 1-1 với nhãn mức cảnh báo (`finding-level`) trên tập 56 tệp này.

2. **Phát hiện các lời giải thích cơ chế Java bị sai hoặc thiếu trong `labels_development.json`, `labels_heldout.json` và `LABELING_PROTOCOL.md`:**
   Mặc dù nhãn `TRUE_POSITIVE` / `FALSE_POSITIVE` đúng 100%, việc đọc kiểm tra trực tiếp mã nguồn Java của cả 56 tệp phát hiện **9 trường hợp** mà trường văn bản `annotator_rationale` / `sanitizer_or_reason` trong `labels_*.json` hoặc `LABELING_PROTOCOL.md` mô tả **sai hoặc thiếu** cơ chế Java thực tế:

| Tệp Benchmark (Tập / Chỉ số) | Nhãn OWASP & CWE | Nội dung ghi trong `labels_*.json` / `LABELING_PROTOCOL.md` | Sự thật trong mã nguồn Java trên đĩa (`sources/`) | Phân loại mức độ lỗi giải thích |
|---|---|---|---|---|
| `BenchmarkTest01746.java` (`heldout_set_40`, `#38`) | `FALSE_POSITIVE` (`CWE-22`) | `labels_heldout.json` (dòng 707-708) ghi: `sanitizer_or_reason = "arithmetic_ternary_constant_branch"` và giải thích rằng dòng 96 tính `(7 * 18) + num > 200` (với `num = 106`) luôn `true` nên gán chuỗi hằng cho `bar`. | Tại `BenchmarkTest01746.java` dòng 94-96, mã thực tế là `int num = 106; bar = (7 * 42) - num > 200 ? "This should never happen" : param;`. Phép tính `(7 * 42) - 106 = 294 - 106 = 188 > 200` là **`false`**, nên toán tử 3 ngôi chọn **`param`** (nhánh truyền dữ liệu, KHÔNG phải nhánh hằng số)! Lý do thực sự khiến `BenchmarkTest01746` là `FALSE_POSITIVE` nằm ở dòng 45: `String param = scr.getTheValue("BenchmarkTest01746");` gọi `SeparateClassRequest.getTheValue(...)` luôn trả về hằng số `"bar"`. | **Sai bản chất cơ chế Java** (Nhãn `FALSE_POSITIVE` vẫn đúng nhờ dòng 45 `scr.getTheValue`). |
| `BenchmarkTest01752.java` (`heldout_set_40`, `#39`) | `FALSE_POSITIVE` (`CWE-22`) | `labels_heldout.json` (dòng 725-726) ghi: `sanitizer_or_reason = "benchmark_safe_construction_non_exploitable"` và giải thích rằng giá trị tới sink dòng 60 đã bị ghi đè/trung hòa trong `Test.doSomething`. | Tại `BenchmarkTest01752.java` dòng 78-82, `Test.doSomething` đưa `param` vào `map11351.put("keyB-11351", param)` rồi lấy ra chính **`map11351.get("keyB-11351")`** (tức trả về `param`, KHÔNG phải khóa an toàn `"keyA-11351"`!). Lý do thực sự khiến `BenchmarkTest01752` là `FALSE_POSITIVE` cũng nằm ở dòng 45: `scr.getTheValue("BenchmarkTest01752")` luôn trả về hằng số `"bar"`. | **Sai bản chất cơ chế Java** (Nhãn `FALSE_POSITIVE` vẫn đúng nhờ dòng 45 `scr.getTheValue`). |
| `BenchmarkTest00863.java` (`dev_set_16`, `#10`) | `FALSE_POSITIVE` (`CWE-22`) | `labels_development.json` (dòng 203-204) và `LABELING_PROTOCOL.md` (dòng 27) ghi: `external_thing_interface_constant_return` (`ThingInterface.doSomething` ghi đè `bar` bằng hằng số). | Trong OWASP Benchmark, `Thing1` và `Thing2` truyền nguyên vẹn tham số đầu vào. Lý do thực sự khiến `BenchmarkTest00863` là `FALSE_POSITIVE` nằm ở dòng 45: `scr.getTheValue("BenchmarkTest00863")` trả về hằng số `"bar"`. | **Giải thích sai hàm trung hòa** (Nhãn `FALSE_POSITIVE` vẫn đúng nhờ dòng 45 `scr.getTheValue`). |
| `BenchmarkTest00864.java` (`heldout_set_40`, `#17`) | `FALSE_POSITIVE` (`CWE-22`) | `labels_heldout.json` (dòng 329-330) ghi dòng 44 là `"HTTP input read"` và chỉ nêu cơ chế `valuesList.remove(0)` + `valuesList.get(1)` tại dòng 56. | Tệp này có **2 tầng an toàn độc lập**: vừa gọi `scr.getTheValue("BenchmarkTest00864")` tại dòng 45 (trả về hằng `"bar"`), vừa dùng `valuesList.remove(0)` + `valuesList.get(1)` tại dòng 54-56 (trả về `"moresafe"`). | **Giải thích thiếu 1 trong 2 tầng an toàn** (Nhãn `FALSE_POSITIVE` hoàn toàn đúng). |
| `BenchmarkTest00062.java` (`heldout`, `#06`), `BenchmarkTest01006.java` (`heldout`, `#25`), `BenchmarkTest01156.java` (`heldout`, `#32`) | `TRUE_POSITIVE` (`CWE-22` / `CWE-89`) | `labels_heldout.json` ghi `sanitizer_or_reason = "no_sanitizer_direct_or_intrafile_taint_flow"` (`Direct flow from source to sink without sanitization`). | Trong cả 3 tệp, `param` không đi trực tiếp mà được đưa vào `HashMap` qua `map.put("keyB-...", param)` rồi lấy lại qua `map.get("keyB-...")` (tức lấy lại nhánh chứa `param` bị nhiễm, đối lập với các mẫu FP lấy `"keyA-..."`). | **Mô tả chung chung, bỏ sót bước truyền qua `HashMap` `keyB`** (Nhãn `TRUE_POSITIVE` hoàn toàn đúng). |
| `BenchmarkTest00950.java` (`dev_set_16`, `#11`) & `BenchmarkTest00949.java` (`heldout_set_40`, `#18`) | `TRUE_POSITIVE` (`CWE-22`) | `labels_*.json` ghi `sanitizer_or_reason = "no_sanitizer_direct_or_intrafile_taint_flow"`. | Trong cả 2 tệp, `param` đi qua lớp nội bộ `new Test().doSomething(request, param)`, tại đó phép toán `(7 * 42) - 106 = 188 > 200` là `false` nên trả về `param` tới sink. | **Mô tả chung chung, bỏ sót nhánh toán tử 3 ngôi trong inner class** (Nhãn `TRUE_POSITIVE` hoàn toàn đúng). |

---

### 7.2. Kiểm toán sâu 4 nhãn `FALSE_POSITIVE` thủ công trên dự án thực tế (`#08`, `#09`, `#10`, `#15`)

Trên tập `real_projects` (`20` cảnh báo OpenGrep trên `8` tệp = `12` vị trí mã nguồn độc lập), có `16` cảnh báo được gán nhãn thủ công là `TRUE_POSITIVE` (`9` vị trí mã nguồn có dòng chảy cộng chuỗi SQL/Path trực tiếp không qua bước kiểm tra nào) và `4` cảnh báo được gán nhãn thủ công là `FALSE_POSITIVE` (`#08`, `#09`, `#10`, `#15` tương ứng `3` vị trí mã nguồn). Dưới đây là hồ sơ kiểm toán 7 điểm bắt buộc cho từng cảnh báo trong 4 cảnh báo này:

#### Trường hợp 1 & 2: Cảnh báo `#08` và `#09` (`WebGoat/SqlInjectionLesson8.java:154` và `:158`)
- **Mã cảnh báo (`alert_id`):**
  - `#08`: `41975fb00201f31b7b59a72907dc1f84e18b5df6287f7c92a49bf368fb983862` (quy tắc `tainted-sql-string`, dòng `154`, `CWE-89`)
  - `#09`: `e5e0e4f6215c2c04ff542d4149123a6f1b819b658122f9cd0b3fd625fcbbff46` (quy tắc `formatted-sql-string`, dòng `158`, `CWE-89`)
- **(1) Đường đi dữ liệu từ source đến sink:**
  - Tại `SqlInjectionLesson8.java` dòng 59: phương thức controller `completed(@RequestParam String name, @RequestParam String auth_tan)` nhận 2 tham số HTTP từ người dùng.
  - Dòng 65-70: phương thức `injectableQueryConfidentiality(String name, String auth_tan)` ghép chuỗi trực tiếp `name` và `auth_tan` vào biến `query = "SELECT * FROM employees WHERE last_name = '" + name + "' AND auth_tan = '" + auth_tan + "'"` (hai cảnh báo `#06` và `#07` tại dòng 70 và 73 là `TRUE_POSITIVE` rõ ràng).
  - Dòng 77: gọi `log(connection, query);` truyền chuỗi `query` (chứa `name` và `auth_tan` chưa làm sạch) vào tham số `String action` của `public static void log(Connection connection, String action)` (dòng 147).
  - Dòng 148: thực thi `action = action.replace('\'', '"');` (thay mọi ký tự nháy đơn `'` bằng nháy kép `"`).
  - Dòng 154 (sink của `#08`): tạo câu lệnh `String logQuery = "INSERT INTO access_log (time, action) VALUES ('" + time + "', '" + action + "')";`.
  - Dòng 158 (sink của `#09`): thực thi `statement.executeUpdate(logQuery);`.
- **(2) Điều kiện bảo mật thật sự:**
  - Trong câu lệnh `INSERT INTO access_log (time, action) VALUES ('...', '<action>')`, tham số `action` nằm trong cặp dấu nháy đơn `'...'`. Việc thay thế mọi ký tự `'` thành `"` tại dòng 148 ngăn chặn việc đóng sớm chuỗi literal nháy đơn **với điều kiện** hệ quản trị cơ sở dữ liệu tuân thủ chuẩn SQL (chỉ thoát nháy đơn bằng `''` và không coi dấu gạch chéo ngược `\` là ký tự thoát). Trong ngữ cảnh bài học WebGoat, `connection` trỏ tới cơ sở dữ liệu HSQLDB nội bộ mặc định không bật backslash escaping.
- **(3) Khả năng tồn tại đường gọi khác hoặc điều kiện môi trường làm phát sinh lỗ hổng:**
  - Phương thức `public static void log(Connection connection, String action)` (dòng 147) có phạm vi truy cập `public static` và nhận một đối tượng `java.sql.Connection` bất kỳ. Nếu phương thức này được gọi với một kết nối MySQL/MariaDB ở chế độ mặc định (bật backslash escaping, tức `NO_BACKSLASH_ESCAPES` tắt), kẻ tấn công truyền chuỗi kết thúc bằng `\'` sẽ được dòng 148 biến thành `\"`, hoặc lợi dụng `\` để thoát ký tự giới hạn chuỗi tùy ngữ cảnh ghép chuỗi. Ngoài ra, đây là biện pháp lọc ký tự thủ công thay vì dùng `PreparedStatement`.
- **(4) Phiên bản file, SHA-256 và dòng mã liên quan:**
  - Tệp: `sources/real_projects/WebGoat/SqlInjectionLesson8.java` (khớp 100% với commit WebGoat `5357a65e054976cd7d79b81ef3906ded050ed921`).
  - SHA-256: `0f4fb25948f5a60df9eb52e3a4be275cf31a7ee7f79a5cf309893d7f29d187e4` (`6,010` bytes, các dòng `59`, `65-77`, `147-159`).
- **(5) Lập luận ủng hộ nhãn `FALSE_POSITIVE`:**
  - Trong ứng dụng WebGoat thực tế tại commit được ghim, kết nối truyền vào `log(connection, query)` là HSQLDB chuẩn; mọi ký tự `'` trong `action` đã bị thay bằng `"` ở dòng 148 ngay trước dòng 154/158 nên không thể thoát khỏi literal `'...'` của câu lệnh `INSERT`.
- **(6) Phản ví dụ / lập luận phản biện chống lại nhãn `FALSE_POSITIVE` tuyệt đối:**
  - `action.replace('\'', '"')` không phải là tham số hóa truy vấn (`PreparedStatement`) và không phải là bộ mã hóa SQL chuẩn; tính an toàn phụ thuộc hoàn toàn vào cấu hình dialect của `Connection` truyền vào hàm `public static log(...)`.
- **(7) Mức độ tin cậy và điều còn thiếu để xác nhận chắc chắn:**
  - **Phân loại:** **`CONDITIONAL` (Độ tin cậy: `MEDIUM`)**.
  - **Điều kiện cần ghi rõ trong báo cáo:** Chỉ được tính là `FALSE_POSITIVE` khi gắn kèm điều kiện môi trường HSQLDB mặc định của WebGoat; nếu đánh giá độc lập ở mức hàm thư viện `public static log(Connection, String)` không biết trước cấu hình `Connection`, phải xếp vào diện phụ thuộc cấu hình dialect.

---

#### Trường hợp 3: Cảnh báo `#10` (`WebGoat/UserService.java:52`)
- **Mã cảnh báo (`alert_id`):** `697b8709bd8fb2d14a9a9d82132e33be55c504cd4d5fffa552707784ca53b6aa` (quy tắc `spring-sqli`, dòng `52`, `CWE-89`)
- **(1) Đường đi dữ liệu từ source đến sink:**
  - Tại `UserService.java` dòng 39: phương thức `public void addUser(String username, String password)` khởi tạo `WebGoatUser(username, password)` và gọi `createLessonsForUser(webGoatUser)` tại dòng 47.
  - Dòng 49-52: phương thức `private void createLessonsForUser(WebGoatUser webGoatUser)` thực thi sink DDL:
    `jdbcTemplate.execute("CREATE SCHEMA \"" + webGoatUser.getUsername() + "\" authorization dba");` (dòng 52).
- **(2) Điều kiện bảo mật thật sự:**
  - Bên trong `UserService.java` (và cả `WebGoatUser.java`) **hoàn toàn không có bất kỳ bước kiểm tra hay làm sạch nào** đối với `username`.
  - Ràng buộc duy nhất tồn tại ở một lớp khác (ngoài 8 tệp được quét trong `sources/real_projects/`): tại `RegistrationController.java` (dòng 42), luồng đăng ký biểu mẫu `registration(@ModelAttribute("userForm") @Valid UserForm userForm, ...)` kiểm tra Bean Validation trên lớp `UserForm.java` (dòng 20): `@Pattern(regexp = "[a-z0-9-]*", message = "{username.pattern}")`. Biểu thức chính quy `[a-z0-9-]*` chặn ký tự nháy kép `"`, ngăn chặn việc thoát khỏi định danh `"..."` trong câu lệnh `CREATE SCHEMA` khi đi qua đường `/register.mvc`.
- **(3) Khả năng tồn tại đường gọi khác làm phát sinh lỗ hổng (Phản ví dụ thực tế trong kho WebGoat):**
  - Phương thức `UserService.addUser(String username, String password)` là `public`!
  - Kiểm tra trực tiếp kho mã nguồn `WebGoat` (`5357a65e054976cd7d79b81ef3906ded050ed921`) tại `RegistrationController.java` dòng 54 phát hiện phương thức thứ hai:
    `public String registrationOAUTH(Authentication authentication, ...) { userService.addUser(authentication.getName(), UUID.randomUUID().toString()); ... }`
  - Luồng `registrationOAUTH` gọi thẳng `userService.addUser(authentication.getName(), ...)` mà **KHÔNG đi qua `UserForm` và KHÔNG có kiểm tra `@Pattern("[a-z0-9-]*")`**! Bất kỳ caller nào gọi `addUser(...)` với chuỗi `username` chứa dấu nháy kép `"` đều gây ra lỗi/tiêm lệnh SQL trực tiếp tại dòng 52 (`CREATE SCHEMA "..."`).
  - Ngoài ra, các tài liệu bàn giao trước đây (`REAL_PROJECT_EVALUATION.md`, `POST_REPORT_IMPLEMENTATION_HANDOVER.md`) đã ghi nhầm rằng `@Pattern` nằm trong `WebGoatUser.java`, trong khi thực tế nó nằm ở `UserForm.java:20`.
- **(4) Phiên bản file, SHA-256 và dòng mã liên quan:**
  - Tệp quét: `sources/real_projects/WebGoat/UserService.java`, SHA-256: `9208dc9bd384f84eb6c993db226c0c7e73d5f12a0895eb9915926845ff7c8865` (`2,431` bytes, dòng `39-53`).
  - Tệp liên quan trong kho WSL WebGoat (`5357a65e054976cd7d79b81ef3906ded050ed921`): `UserForm.java` (dòng 20) và `RegistrationController.java` (dòng 42 và dòng 54).
- **(5) Lập luận ủng hộ nhãn `FALSE_POSITIVE`:**
  - Nếu chỉ xét luồng đăng ký tài khoản thông thường qua biểu mẫu web (`RegistrationController.registration`), `@Valid UserForm` chỉ cho phép `[a-z0-9-]*` nên không thể chứa ký tự `"` để phá vỡ `CREATE SCHEMA "..."`.
- **(6) Phản ví dụ / lập luận phản biện chống lại nhãn `FALSE_POSITIVE`:**
  - Ở cấp độ phương thức `UserService.addUser(String, String)` và tệp `UserService.java` được đưa vào tập quét, mã nguồn ghép chuỗi trực tiếp biến `username` vào câu lệnh DDL mà không có chốt chặn nội bộ, và tồn tại ít nhất một điểm gọi khác (`registrationOAUTH`) trong cùng ứng dụng không qua `UserForm`. Trong phân tích bảo mật tĩnh (SAST), việc thiếu kiểm tra tại sink/service và phụ thuộc vào một trong nhiều controller caller thường được phân loại là điểm yếu thiết kế (hoặc `TRUE_POSITIVE` tiềm ẩn nếu caller mới/OAuth principal chứa ký tự đặc biệt).
- **(7) Mức độ tin cậy và điều còn thiếu để xác nhận chắc chắn:**
  - **Phân loại:** **`LABEL_REVIEW_REQUIRED` (Độ tin cậy của nhãn FP: `LOW` / `CONDITIONAL`)**.
  - **Yêu cầu xử lý:** Bắt buộc sửa lỗi chú thích nhầm `WebGoatUser.java` thành `UserForm.java:20` trong tài liệu, và không được dùng `#10` làm mẫu chuẩn `FALSE_POSITIVE` tuyệt đối nếu không khóa rõ giả định chỉ xét điểm vào `RegistrationController.registration`.

---

#### Trường hợp 4: Cảnh báo `#15` (`demo/UserDao.java:63`) - Hạ mức độ tin cậy và phân tích kỹ thuật `getCanonicalPath().startsWith(BASE_DIR)`
- **Mã cảnh báo (`alert_id`):** `ab5968a5159a5b6fdbf898359ec391c0748db1157cf6705434fb56dc921f22e9` (quy tắc `httpservlet-path-traversal`, dòng `63`, `CWE-22`)
- **(1) Đường đi dữ liệu từ source đến sink:**
  - Tại `sources/real_projects/demo/UserDao.java`:
    - Dòng 17: khai báo hằng số `private static final String BASE_DIR = "/var/app/files/";` (có ký tự `/` ở cuối chuỗi).
    - Dòng 61-62: phương thức `public File open(HttpServletRequest request) throws IOException` đọc tham số HTTP: `String fileName = request.getParameter("f");`.
    - Dòng 63 (dòng bị quy tắc `httpservlet-path-traversal` báo cảnh báo): khởi tạo đối tượng `File f = new File(BASE_DIR + fileName);` (chưa thực hiện đọc/ghi đĩa tại dòng 63).
    - Dòng 64-66: thực hiện kiểm tra đường dẫn:
      ```java
      if (!f.getCanonicalPath().startsWith(BASE_DIR)) {
          throw new IOException("blocked");
      }
      ```
    - Dòng 67: `return f;`.
- **(2) Phân tích kỹ thuật chuyên sâu về `f.getCanonicalPath().startsWith(BASE_DIR)` (Theo yêu cầu Mục V):**
  1. **Tại sao mẫu `getCanonicalPath().startsWith(baseDir)` nói chung là một mẫu kiểm tra mong manh (fragile pattern):**
     - Trong chuẩn bảo mật Java (CERT FIO16-J / OWASP Path Traversal), cách kiểm tra chuẩn mực là chuẩn hóa cả thư mục gốc lẫn tệp đích và so sánh theo thành phần đường dẫn (`Path base = Paths.get(BASE_DIR).toRealPath(); Path target = base.resolve(fileName).toRealPath(); if (!target.startsWith(base)) ...`) hoặc so sánh chuỗi với `canonicalBase + File.separator`.
     - Khi lập trình viên chỉ viết `f.getCanonicalPath().startsWith(BASE_DIR)` bằng phép so sánh tiền tố chuỗi (`String.startsWith`), nếu `BASE_DIR` được khai báo là `"/var/app/files"` (không có dấu `/` ở cuối), kẻ tấn công truyền `fileName = "../files_secret/key.txt"` sẽ tạo ra `canonicalPath = "/var/app/files_secret/key.txt"`, vốn vẫn thỏa mãn `.startsWith("/var/app/files")` (**lỗ hổng vượt qua tiền tố thư mục anh em - sibling-prefix bypass**).
  2. **Hành vi cụ thể trong `demo/UserDao.java` (dòng 17 và 63-64):**
     - Trong tệp `UserDao.java` cụ thể này, dòng 17 khai báo `BASE_DIR = "/var/app/files/"` **có sẵn dấu gạch chéo `/` ở cuối**.
     - Trên hệ điều hành POSIX/Linux (nơi `File.separatorChar == '/'`) và khi `/var/app/files` là một thư mục thật (không phải symlink), `f.getCanonicalPath()` trả về chuỗi tuyệt đối đã loại bỏ `.` và `..` và không có dấu `/` ở cuối đối với tên thư mục. Do đó:
       - Một tệp con hợp lệ `/var/app/files/a.txt` luôn bắt đầu bằng `"/var/app/files/"` (`true`).
       - Một thư mục anh em `/var/app/files_sibling/a.txt` bắt đầu bằng `"/var/app/files_"` nên `.startsWith("/var/app/files/")` trả về `false` (bị chặn).
       - Trường hợp `fileName = ""` hoặc `"."` có `canonicalPath = "/var/app/files"` (thiếu dấu `/` cuối) nên `.startsWith("/var/app/files/")` cũng trả về `false` (bị chặn).
- **(3) Các điều kiện môi trường và phản ví dụ khiến mẫu này thất bại hoặc tiềm ẩn rủi ro:**
  1. **Lệch hệ điều hành thực thi (Windows `ADMIN-PC` so với POSIX):** Toàn bộ thực nghiệm trên máy chủ `ADMIN-PC` chạy trên Windows. Trên Windows, `new File("/var/app/files/" + fileName).getCanonicalPath()` trả về đường dẫn có ký tự ổ đĩa và dấu gạch chéo ngược `\` (ví dụ `"C:\\var\\app\\files\\..."`). Chuỗi này **không bao giờ** bắt đầu bằng `"/var/app/files/"`! Tức là nếu chạy đoạn mã này trên JVM Windows của `ADMIN-PC`, hàm `open()` ném `IOException("blocked")` với 100% đầu vào (hỏng chức năng hoàn toàn do dùng chuỗi cứng `"/"` thay vì `File.separator` / `Path`).
  2. **Trường hợp `/var/app/files` là symlink trên Linux:** Vì dòng 64 chỉ gọi `f.getCanonicalPath()` mà **không gọi `new File(BASE_DIR).getCanonicalPath()`**, nếu trong môi trường triển khai Linux thư mục `/var/app/files` là một symbolic link trỏ tới `/srv/storage/files`, thì `f.getCanonicalPath()` sẽ phân giải symlink thành `"/srv/storage/files/..."`, không khớp với hằng chuỗi `BASE_DIR = "/var/app/files/"`.
  3. **Trả về đối tượng `File f` chưa chuẩn hóa tại dòng 67 (Cửa sổ TOCTOU):** Dòng 67 trả về `return f;` (chứa đường dẫn tương đối chưa chuẩn hóa `"/var/app/files/" + fileName`) thay vì `return f.getCanonicalFile();`. Nếu caller sau đó mở `f` trong một môi trường có thể tạo/đổi symlink giữa thời điểm kiểm tra dòng 64 và thời điểm mở tệp thực sự, tồn tại cửa sổ tranh chấp thời gian kiểm tra - thời gian sử dụng (TOCTOU).
- **(4) Phiên bản file, SHA-256 và dòng mã liên quan:**
  - Tệp: `sources/real_projects/demo/UserDao.java` (`2,216` bytes, dòng `17`, `61-67`).
  - SHA-256: `6c890fc869f74cdceb6bd8f73e04be4fc7ffb4defdab008c098642e146be1d24` (khớp với bản gốc trong `ntk-thesis-v2.zip` sau chuẩn hóa LF `c5c20cb72dd3d673e28931a753fa4bc3b97875c24a84fc6a09a43072df71b27e`).
- **(5) Lập luận ủng hộ nhãn `FALSE_POSITIVE`:**
  - Tệp `demo/UserDao.java` là một tệp mẫu tổng hợp (synthetic demo fixture) được thiết kế có chủ đích gồm 2 phương thức SQLi lỗi (`findUnsafe`, `findViaHelper`) và 1 phương thức `open()` minh họa chốt chặn `getCanonicalPath().startsWith(BASE_DIR)` ngay sau `new File(...)` trước khi trả về `File`. Trên môi trường giả định POSIX với thư mục thật `/var/app/files/`, dấu `/` cuối chuỗi `BASE_DIR` chặn được `../` và sibling-prefix bypass.
- **(6) Phản ví dụ / lập luận phản biện chống lại nhãn `FALSE_POSITIVE` mức `HIGH` vô điều kiện:**
  - Việc quy tắc tĩnh `httpservlet-path-traversal` cảnh báo tại dòng 63 (`new File(BASE_DIR + fileName)`) là có cơ sở vì dòng 63 nối chuỗi trực tiếp trước khi kiểm tra, còn bản thân phép kiểm tra dòng 64 dùng `String.startsWith(BASE_DIR)` trên chuỗi cứng POSIX thay vì `Path.toRealPath().startsWith(realBase)` và trả về `f` chưa chuẩn hóa.
- **(7) Mức độ tin cậy cập nhật và điều còn thiếu:**
  - **Phân loại cập nhật:** Hạ từ `HIGH` xuống **`CONDITIONAL` (Độ tin cậy: `MEDIUM`, phụ thuộc giả định môi trường POSIX với `/var/app/files` không phải symlink và giả định caller không chịu rủi ro TOCTOU)**.

---

## 8. Danh Sách Lỗi Đã Sửa, Lỗi Còn Tồn Tại Và Mức Độ Ảnh Hưởng

### 8.1. Các lỗi đã được Javis phát hiện và khắc phục trong nhánh `v2/javis-benchmark`
1. **Sửa lỗi ghi nhầm số liệu Nhánh B trong bản tóm tắt văn xuôi đầu tiên (`SERVER_FORENSIC_AUDIT_SUMMARY_20261112.md` & `SERVER_FORENSIC_AUDIT_RECEIPT_20261112.json`):**
   - *Mô tả:* Bản tóm tắt văn xuôi đầu tiên từng ghi nhầm Nhánh B (`heuristic`) trên `heldout_set_40` là `8/20 TP`, `8/20 FP`, `drop_fp` precision `20/32 (62.5%)`, trong khi bảng CSV/JSON tái tính (`07_independent_metrics_recomputation.csv`) và `PAIRED_EVALUATION.csv` là `9/20 TP`, `7/20 FP`, `drop_fp` precision `20/33 (60.6%)`.
   - *Trạng thái:* **Đã sửa triệt để** trên cả `audit_server_forensic_receipt.py`, `SERVER_FORENSIC_AUDIT_SUMMARY_20261112.md`, `SERVER_FORENSIC_AUDIT_RECEIPT_20261112.json` và biên bản này.
2. **Bổ sung cơ chế Fail-Closed 9 cổng (`C01`-`C09`) và bộ 26 kiểm thử đơn vị + phản thực tế (`test_audit_server_forensic_receipt.py`):**
   - *Mô tả:* Tách biệt rõ `PASS` (`exit 0`), `FAIL` (`exit 1`), `INCOMPLETE` (`exit 2`), chặn mọi hành vi ép buộc `PASS` (`force_pass_attempt_blocked = True`), kiểm tra 1-1 SARIF bằng multiset không phụ thuộc thứ tự, và kiểm tra từng ô `1,080` ô của `PAIRED_EVALUATION.csv`.
   - *Trạng thái:* **Đã hoàn thành và kiểm chứng (`26 passed`)**.
3. **Hạ mức độ tin cậy nhãn thủ công `#15` (`UserDao.java:63`) và `#10` (`UserService.java:52`), đồng thời ghi nhận đầy đủ 9 lỗi giải thích cơ chế Java trong `labels_*.json`:**
   - *Mô tả:* Cập nhật `REAL_PROJECT_MANUAL_LABELS` và `audit_ground_truth_labels()` trong `v2/evaluation/audit_server_forensic_receipt.py` để phản ánh chính xác mức `CONDITIONAL_MEDIUM` cho `#15`, `#08`, `#09`, `LABEL_REVIEW_REQUIRED_LOW` cho `#10`, và xuất bảng 9 lỗi giải thích cơ chế Java trong `06_owasp_and_manual_ground_truth_audit.json/.md`.
   - *Trạng thái:* **Đã hoàn thành và chạy lại kiểm toán (`exit_code = 0`)**.

### 8.2. Các lỗi và hạn chế còn tồn tại trong kho đồ án (Ngoài phạm vi sửa trực tiếp của Javis trong G0)

| Mã vấn đề | Mô tả vấn đề còn tồn tại | Vị trí tệp liên quan | Mức độ ảnh hưởng | Đơn vị chịu trách nhiệm xử lý |
|---|---|---|---|---|
| **ISS-01** | **Biến nhiễu dẫn dắt LLM (`Heuristic Steering`) trong Nhánh C:** `v2/triage/ollama.py` truyền `heuristic_signals` (gồm `recommended_status`, `recommendation_reason`, `candidate_citations`) vào prompt `evidence_signals`. Qwen đồng thuận `76/76` (`100%`). Không thể tách biệt đóng góp độc lập của Qwen với bộ biểu thức chính quy trong `heuristics.py`. | `v2/triage/ollama.py` (dòng 56-68), `v2/triage/heuristics.py` (dòng 516-616), báo cáo Chương 4 | **CRITICAL (Phương pháp luận khoa học)** | `Codex` (thiết kế ablation không mớm `recommended_status`) & `Antigravity` (diễn giải trung thực trong luận văn) |
| **ISS-02** | **Chênh lệch bất đối xứng giữa Nhánh B (`evaluate_heuristic`) và `extract_evidence_signals` trong Nhánh C:** Nhánh B trả về `UNDETERMINED` cho `24/40` mẫu có `callee_flow` / `list` / `map`, nhưng `extract_evidence_signals` lại giải sẵn toàn bộ `40/40` mẫu đó thành `recommended_status` trước khi gọi Qwen ở Nhánh C. | `v2/triage/heuristics.py` (dòng 482-513 so với dòng 574-605) | **HIGH (Công bằng khi so sánh Arm B vs Arm C)** | `Codex` & `Antigravity` |
| **ISS-03** | **Tỷ lệ bác bỏ FP trên mã nguồn dự án thực tế bằng `0%` (`0/4` FP được bác bỏ):** Cả Nhánh B và Nhánh C đều trả về `20/20 SUPPORTED` trên `real_projects` do không xử lý được kiểm tra sau dòng sink (`UserDao.java:64 > 63`), kiểm tra liên tệp (`UserForm.java:20`) và `action.replace('\'', '"')`. | `v2/triage/heuristics.py` (dòng 433 `if ln_no <= sink_line:`), `v2/docs/thesis/CHUONG_4_THUC_NGHIEM_VA_DANH_GIA.md` | **HIGH (Giới hạn thực nghiệm bên ngoài OWASP)** | `Codex` (mở rộng cửa sổ post-sink ở G1) & `Antigravity` (ghi rõ giới hạn ở G3) |
| **ISS-04** | **9 trường hợp giải thích sai/thiếu cơ chế Java trong `labels_development.json`, `labels_heldout.json` và `LABELING_PROTOCOL.md`:** Đặc biệt `BenchmarkTest01746.java` (ghi nhầm `(7*18)+num > 200` trong khi code là `(7*42)-num > 200` chọn `param`), `BenchmarkTest01752.java` (ghi nhầm `Test.doSomething` ghi đè trong khi `map.get("keyB-11351")` lấy lại `param`), và `BenchmarkTest00863.java` (ghi nhầm `ThingInterface` trả về hằng số thay vì `scr.getTheValue`). | `v2/evaluation/post_report/labels_heldout.json` (dòng 707, 725, 329, ...), `labels_development.json` (dòng 203), `LABELING_PROTOCOL.md` (dòng 27) | **MEDIUM (Độ chính xác của thuyết minh dữ liệu; không làm đổi nhãn TP/FP)** | `Antigravity` / `Codex` (cập nhật trường `annotator_rationale` nếu mở khóa hoặc ghi đính chính tại phụ lục G3) |
| **ISS-05** | **Sai lệch số liệu và mã băm trong tài liệu bàn giao Stage 7 / dự thảo Chương 4:** Ghi nhầm `14` quy tắc thay vì `9`; ghi nhầm SHA-256 của `dev_set_16` là `c1be1d5e...` thay vì `ecc1fa46...`; ghi nhầm SHA-256 của `expectedresults-1.2.csv` là `353762c7...` thay vì `1809f6a6...`; ghi nhầm `opengrep.exe` là bridge sang WSL `~/.opengrep/cli/latest/opengrep`; ghi nhầm `@Pattern` nằm ở `WebGoatUser.java` thay vì `UserForm.java:20`. | `v2/docs/POST_REPORT_IMPLEMENTATION_HANDOVER.md`, `v2/docs/POST_REPORT_BASELINE_AUDIT.md`, `v2/docs/thesis/CHUONG_4_THUC_NGHIEM_VA_DANH_GIA.md` | **MEDIUM (Nhất quán tài liệu)** | `Antigravity` (đính chính trong đợt đồng bộ tài liệu G3) |
| **ISS-06** | **Không lưu nguyên văn chuỗi prompt (`PROMPT_NOT_ATTESTED`) và runtime chỉ ở mức tự báo cáo (`OLLAMA_SELF_REPORTED_LOCAL_HTTP_UNATTESTED`):** JSONL chỉ lưu `request_payload_sha256` (khớp `116/116` bản ghi `v2.1`, khớp `0/42` bản ghi cũ trước `v2.1`). | `v2/triage/ollama.py`, `runs/*/assessments.jsonl` | **LOW-MEDIUM (Khả năng kiểm chứng độc lập không cần code tạo prompt)** | `Codex` (tùy chọn lưu kèm `prompt_messages` hoặc `model_digest` ở G1 nếu chạy bổ sung) |

---

## 9. Danh Sách Việc Cần Xử Lý Ở G1 Hoặc G3 (Backlog)

### 9.1. Backlog đề xuất cho Giai đoạn G1 (Kỹ thuật / Thực nghiệm bổ sung - `Codex` chủ trì, `Javis` hậu kiểm)
1. **Thực nghiệm tách biến nhiễu (Unsteered Evidence Ablation - Ưu tiên số 1 nếu muốn chứng minh đóng góp độc lập của Qwen):**
   - Tạo chế độ chạy thử nghiệm mà trong đó `_prompt_evidence()` giữ nguyên `snapshots`, `dataflow`, `intra_method_flow`, `callee_method_flow` nhưng **loại bỏ hoàn toàn** `recommended_status`, `recommendation_reason` và `candidate_citations` khỏi `evidence_signals` trước khi gửi cho Qwen (`qwen3.5:9b-q4_K_M`).
   - Hoặc bổ sung cột đánh giá trực tiếp bộ quy tắc đầy đủ (`extract_evidence_signals.recommended_status` không gọi LLM) bên cạnh Nhánh B để hội đồng thấy rõ bộ quy tắc tĩnh đầy đủ đạt `40/40` trên OWASP Benchmark với độ trễ `~0 ms` so với `421.00 giây` của Nhánh C.
2. **Khắc phục giới hạn cửa sổ sau dòng sink (`post-sink guard`) cho CWE-22:**
   - Trong `v2/triage/heuristics.py` (dòng 433), mở rộng phạm vi quét chốt chặn `getCanonicalPath()` / `toRealPath()` thêm vài dòng ngay sau `sink_line` trong cùng phương thức trước khi đối tượng `File`/`Path` được mở luồng I/O hoặc trả về.
3. **Lưu trữ đầy đủ nguyên văn prompt / model digest (nếu chạy lượt thực nghiệm mới):**
   - Ghi trực tiếp `request_payload` (hoặc tệp `prompts.jsonl` đi kèm) và `model_digest` từ API `/api/show` của Ollama để nâng mức xác thực từ `PROMPT_NOT_ATTESTED` lên `PROMPT_ATTESTED`.

### 9.2. Backlog bắt buộc cho Giai đoạn G3 (Đồng bộ tài liệu & Luận văn - `Antigravity` chủ trì)
1. **Đính chính toàn bộ mã băm và số lượng quy tắc trong tài liệu Chương 4 & Handover:**
   - Sửa `14 quy tắc` thành **`9 quy tắc`** (`2` CWE-22 + `7` CWE-89, SHA-256 `4d12f6deabee1bcf17f1bcce845f05eaf84b312ee13aa6a9cd9721ea879695f9`).
   - Sửa SHA-256 bản quét `dev_set_16` từ `c1be1d5e...` thành **`ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f`**.
   - Sửa SHA-256 của `expectedresults-1.2.csv` từ `353762c7...` thành **`1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`**.
   - Sửa mô tả binary OpenGrep: cả 3 bản quét chính đều chạy bằng binary Windows native `opengrep.exe` (`v1.25.0`, SHA-256 `b010709b...`), không phải script bridge sang `~/.opengrep/cli/latest/opengrep`.
2. **Đính chính thuyết minh cơ chế Java cho các mẫu OWASP và 4 mẫu dự án thực tế:**
   - Ghi rõ lý do thực sự khiến `BenchmarkTest01746.java`, `BenchmarkTest01752.java` và `BenchmarkTest00863.java` là `FALSE_POSITIVE` nằm ở `SeparateClassRequest.getTheValue(...)` (dòng 45 trả về hằng `"bar"`), không phải do toán tử 3 ngôi `(7 * 42) - num > 200` hay `ThingInterface` hay `map11351.get("keyB-11351")`.
   - Sửa chú thích `#10` (`UserService.java:52`): `@Pattern(regexp = "[a-z0-9-]*")` nằm tại `UserForm.java:20` (được gọi bởi `RegistrationController.registration`), không phải `WebGoatUser.java`, và bổ sung lưu ý đường gọi `registrationOAUTH` không qua `UserForm`.
   - Ghi rõ các điều kiện của `#08/#09` (phụ thuộc dialect HSQLDB không bật backslash escape) và `#15` (`UserDao.java:63`, phụ thuộc dấu `/` cuối chuỗi `BASE_DIR` trên môi trường POSIX, không tương thích dấu `\` trên Windows và chưa chuẩn hóa `BASE_DIR` nếu là symlink).
3. **Tuân thủ nghiêm ngặt quy tắc diễn giải khoa học đối với kết quả Nhánh C (`40/40`) và Nhánh D (`9/40` hạ cấp):**
   - Trình bày rõ trong luận văn rằng kết quả `20/20 TP` và `20/20 FP` của Nhánh C trên `heldout_set_40` là kết quả của **hệ thống kết hợp có truyền `evidence_signals` (`recommended_status` đạt sẵn `40/40`)**, không được viết thành khẳng định Qwen độc lập suy luận giải quyết 100% cảnh báo.
   - Khi nhắc tới con số `9/40` và `6/40` ở Nhánh D (`stage4_heldout40_armD_llm_ablation`), luôn ghi rõ: `9/40` là **tổng số cảnh báo** bị bộ kiểm chứng trích dẫn hạ từ `SUPPORTED` xuống `UNDETERMINED` (`3 TP + 6 FP`), còn `6/40` (tức `6/20` FP) là phần cảnh báo dương tính giả nằm trong 9 cảnh báo đó.

---

## 10. Lệnh Kiểm Tra Đã Chạy, Exit Code, Đường Dẫn Biên Nhận Và Kết Luận Cuối Cùng 4 Trục

### 10.1. Các lệnh kiểm tra thực tế đã chạy và mã thoát (`exit_code`)

| STT | Lệnh thực thi (tại `C:\Users\Admin\ntk-thesis-v2\javis`) | Mã thoát (`exit_code`) | Kết quả thực tế quan sát được |
|---:|---|---:|---|
| 1 | `python v2/evaluation/audit_server_forensic_receipt.py` | **`0`** | `status = PASS`, `passed_criteria_count = 9/9`, `zero_mutation_verified = true` (`263/263` tệp lịch sử bất biến), `paired_csv_discrepancies = 0`, `temp_sqlite_lifecycle_passed = true`, `guided_llm_concordance = 76/76` |
| 2 | `python -m pytest v2/evaluation/tests/test_audit_server_forensic_receipt.py -q` | **`0`** | **`26 passed`** (gồm 8 unit test, 2 baseline sandbox test và đủ 16 bài kiểm thử phản thực tế `cf01`..`cf16` xác nhận `FAIL -> exit 1`, `INCOMPLETE -> exit 2`, `force_pass_attempt_blocked = True`) |
| 3 | `python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests -q` | **`0`** | **`226 passed`** (toàn bộ kiểm thử của kho chạy xanh 100%, không gây hồi quy) |
| 4 | `python scripts/verify-repository.py` | **`0`** | `OK: repository verification passed.` |
| 5 | `git diff --check` | **`0`** | Không có lỗi khoảng trắng hoặc xung đột định dạng |

### 10.2. Đường dẫn biên nhận kiểm toán

1. **Trong kho Git (`v2/javis-benchmark` tại `C:\Users\Admin\ntk-thesis-v2\javis`):**
   - Biên bản bàn giao cuối cùng G0 (tệp này): `v2/evaluation/post_report_audit/G0_SERVER_FINAL_HANDOFF.md`
   - Tóm tắt JSON bàn giao cuối cùng G0 (đã lọc đường dẫn riêng tư): `v2/evaluation/post_report_audit/G0_SERVER_FINAL_HANDOFF_SUMMARY.json`
   - Công cụ kiểm toán độc lập & cổng fail-closed:
     - `v2/evaluation/audit_server_forensic_receipt.py`
     - `v2/evaluation/server_forensic_gates.py`
     - `v2/evaluation/server_forensic_helpers.py`
     - `v2/evaluation/tests/test_audit_server_forensic_receipt.py`
   - Biên nhận tóm tắt đã đồng bộ:
     - `v2/evaluation/post_report_audit/SERVER_FORENSIC_AUDIT_SUMMARY_20261112.md`
     - `v2/evaluation/post_report_audit/SERVER_FORENSIC_AUDIT_RECEIPT_20261112.json`
2. **Trong thư mục bằng chứng kiểm toán trên máy chủ (`C:\Users\Admin\ntk-thesis-v2\evidence\server_forensic_audit_failclosed_20261112\` - ngoài Git):**
   - `00_pre_audit_sha256_snapshot.json` & `immutability_verification.json`
   - `01_file_inventory_sha256.json` / `.csv` / `.md`
   - `02_raw_opengrep_scans_receipt.json` / `.md`
   - `03_ollama_10_assessments_receipt.json` / `.md`
   - `04_raw_vs_post_validator_comparison.csv` / `.md`
   - `05_historical_ground_truth_verifier_audit.json` / `.md`
   - `06_owasp_and_manual_ground_truth_audit.json` / `.csv` / `.md`
   - `07_independent_metrics_recomputation.json` / `.csv` / `.md`
   - `08_paired_evaluation_per_alert_audit.json` / `.csv` / `.md`
   - `10_guided_llm_confounder_audit.json` / `.md`
   - `11_fail_closed_gate_verdict.json` / `.md`

---

### 10.3. KẾT LUẬN CUỐI CÙNG TÁCH BIỆT 4 TRỤC ĐỘC LẬP (MỤC VIII)

| Trục đánh giá | Phán quyết chính thức | Giải thích ngắn gọn & Giới hạn chứng cứ |
|---|---|---|
| **A. Kiểm toán kỹ thuật hiện vật trên máy chủ (`Technical Server Audit`)** | **`PASS`** (`9/9` tiêu chí `C01`-`C09`, `exit_code = 0`) | Toàn bộ `263` tệp bằng chứng lịch sử nguyên vẹn tuyệt đối (`zero_mutation_verified = true`); 3 bản quét OpenGrep (`16`, `40`, `20` cảnh báo) khớp SHA-256 và khớp 1-1 với SARIF trên bộ `9` quy tắc YAML (`4d12f6de...`); 10 tệp `assessments.jsonl` (`240` bản ghi), 6 tệp checkpoint (`148` bản ghi) và 10 tệp `review.sqlite` hợp lệ 100%; `240/240` trích dẫn khớp mã nguồn trên đĩa; `1,080/1,080` ô của `PAIRED_EVALUATION.csv` khớp tuyệt đối với dữ liệu thô; kiểm thử vòng đời `STALE_SOURCE` trên bản sao tạm đạt `5/5` bước. Giới hạn: runtime ở mức `OLLAMA_SELF_REPORTED_LOCAL_HTTP_UNATTESTED` và prompt ở mức `PROMPT_NOT_ATTESTED` (khớp `request_payload_sha256` `116/116` trên 4 lượt chạy `v2.1`). |
| **B. Xác thực nhãn chuẩn thủ công & OWASP (`Ground Truth Attestation`)** | **`VERIFIED` (cho 56 nhãn OWASP) / `CONDITIONAL` & `LABEL_REVIEW_REQUIRED` (cho 4 nhãn FP thủ công & văn bản giải thích)** | **1. Nhãn OWASP (`56/56`):** `VERIFIED` cho giá trị nhãn (`TRUE_POSITIVE`/`FALSE_POSITIVE`) và `CWE` (`16/16` dev + `40/40` held-out khớp 100% với `expectedresults-1.2.csv` `1809f6a6...`, `0` giao tập, `STRICT_LOCK` `4fb55637...`). Tuy nhiên, có **9 mục giải thích văn xuôi** trong `labels_*.json` / `LABELING_PROTOCOL.md` mô tả sai/thiếu cơ chế Java (`BenchmarkTest01746`, `01752`, `00863`, `00864`, `00062`, `01006`, `01156`, `00949`, `00950`).<br>**2. Bốn nhãn FP thủ công trên `real_projects`:** `#08` và `#09` (`SqlInjectionLesson8.java:154,158`) đạt mức **`CONDITIONAL` (`MEDIUM`)** (an toàn trong HSQLDB mặc định của WebGoat nhưng phụ thuộc dialect không bật backslash escape); `#15` (`demo/UserDao.java:63`) hạ xuống mức **`CONDITIONAL` (`MEDIUM`)** (an toàn trên POSIX khi `/var/app/files/` là thư mục thật có dấu `/` cuối, nhưng thất bại trên Windows do dấu `\`, không chuẩn hóa `BASE_DIR` nếu là symlink và trả về `File f` chưa canonicalize); `#10` (`UserService.java:52`) xếp mức **`LABEL_REVIEW_REQUIRED` (`LOW`)** (phụ thuộc caller `RegistrationController.registration` qua `UserForm.java:20`, trong khi `registrationOAUTH` gọi trực tiếp `addUser` không kiểm tra). |
| **C. Chứng minh đóng góp độc lập của Qwen (`Independent Contribution of Qwen`)** | **`CONFOUNDED`** (Bị nhiễu bởi `heuristic_signals` truyền vào prompt Nhánh C) | Ở Nhánh C (`--mode evidence+llm`), hàm `ollama.py` truyền toàn bộ `heuristic_signals` (bao gồm `recommended_status`, `recommendation_reason`, `candidate_citations`) vào `evidence_signals` trong prompt. Trên cả 3 tập `v2.1` (`76` cảnh báo), đầu ra của Qwen trùng khớp **`76/76` (`100%`)** với `heuristic_signals.recommended_status` (kể cả khi `recommended_status` đúng `40/40` trên `heldout_set_40` và khi `recommended_status` sai `4/4` FP trên `real_projects`). Khi bỏ `evidence_signals` ở Nhánh D (`--mode llm`), Qwen trả về thô `40/40 SUPPORTED` (`0/20` FP được bác bỏ). Do đó, chưa thể quy kết kết quả `40/40` ở Nhánh C cho năng lực suy luận độc lập của Qwen. |
| **D. Điều kiện còn lại để đóng G0 cùng `Codex` và `Antigravity`** | **Sẵn sàng đóng G0 về mặt kiểm toán máy chủ khi 3 bên khóa nhận thức chung về A, B, C** | 1. **Về phía `Javis`:** Đã hoàn tất 100% nghĩa vụ kiểm toán máy chủ, cung cấp biên nhận `9/9 PASS` kèm giới hạn phạm vi rõ ràng tại tệp này.<br>2. **Về phía `Codex`:** Ghi nhận phát hiện `CONFOUNDED` (`ISS-01`, `ISS-02`) và giới hạn post-sink (`ISS-03`) để quyết định ở G1 xem có chạy thêm nhánh đối chứng ẩn `recommended_status` hay giữ nguyên hiện vật và báo cáo trung thực.<br>3. **Về phía `Antigravity`:** Khi tổng hợp tài liệu ở G3, bắt buộc cập nhật các lỗi văn bản/mã băm (`ISS-04`, `ISS-05`: `9` rules, hash `ecc1fa46...`, hash `1809f6a6...`, `UserForm.java:20`, giải thích `BenchmarkTest01746/01752/00863`, và điều kiện của `#08, #09, #10, #15`) và không tuyên bố Qwen độc lập đạt 100% nếu chưa có thực nghiệm tách biến nhiễu ở G1. |
