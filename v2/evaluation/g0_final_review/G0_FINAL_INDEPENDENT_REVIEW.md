# G0 — Kiểm định độc lập cuối cùng hồ sơ Codex/JavisOS (Antigravity)

- **Ngày:** 13/11/2026 · **Nhánh:** `v2/antigravity-review` · **Người thực hiện:** Antigravity
- **Đối tượng kiểm định (chỉ đọc):** 24 tệp `codex-publish-20261113/v2/crosscheck/` (chưa commit trên `v2/codex-core`). SHA-256 của 7 tệp quyết định được ghim trong [review_codex_g0.py](review_codex_g0.py); thư mục Codex được băm trước/sau mọi lần chạy và **không thay đổi** (24/24 tệp, không sinh `__pycache__`).
- **Kết luận (mục 7):** **`READY_FOR_G1_WITH_DISCLOSED_LIMITATIONS`**

> [!IMPORTANT]
> **Giới hạn quyền đọc:** quy định workspace bổ sung chỉ cấp `antigravity/`, `_advisor_sources/`, `codex-publish-20261113/`. Gói dữ liệu riêng `…\OpenGrep-Private-Evidence\NTK-G0-Private-20261112` **không** nằm trong danh sách đó nên tôi **không đọc**. Mọi kết luận cần raw (289 tệp, 240 assessments, SQLite, checkpoint, trace) do Antigravity đánh dấu **`NOT_VERIFIED`**: tôi kiểm logic của bộ công cụ Codex, chạy lại bộ test, đối chiếu nội bộ với bảng công khai và kiểm lại nguồn OWASP/WebGoat công khai, nhưng **không** tái chạy `audit_raw_bundle.py` trên raw. Biên nhận của Codex/JavisOS không được dùng thay cho bằng chứng độc lập.

---

## 1. Những gì Codex thực sự đã hoàn thành (đã kiểm)

| Hạng mục | Cách Antigravity kiểm | Kết quả |
|---|---|---|
| Bộ test Codex | `python -X utf8 -B -m unittest discover -s <codex>/v2/crosscheck -t <codex>/v2/crosscheck` (chạy từ thư mục scratch, không ghi vào Codex) | **43/43 OK, exit 0** |
| SHA mã trong `G0_FINAL_RESOLUTION.json["code_sha256"]` | So với tệp thực tế | 6/6 khớp |
| Metric held-out A/B/C/D (ma trận nhãn × trạng thái sau validator, trạng thái raw C/D, tổng latency C/D) | `consistency_with_public()`: so `heldout_metrics` của Codex với `PAIRED_EVALUATION.csv` + `labels_heldout.json` công khai (Git `86636b9`) | **0 sai lệch** (A 20/0/0·20/0/0; B 9/0/11·0/7/13; C 20/0/0·0/20/0; D 17/0/3·14/0/6; raw D 40 S; C 421000 ms; D 301062 ms) |
| Thiết kế tái tính | Đọc `audit_raw_bundle.py`/`recompute.py` | Metric tính từ raw assessments + nhãn OWASP, so với CSV công bố **sau** khi tính (`audit_raw_bundle.py:566-589`, `recompute.py:235-284`); raw và post-validator tách riêng (`audit_raw_bundle.py:412-431`); latency Arm B (hằng `0.0`) bị loại khỏi phép đo (`:440-443`) |
| Nguồn OWASP | `verify_owasp_public.py` tải trực tiếp commit `8b67a88d`, tính git-blob | 61/61 blob khớp `owasp_reference_blobs.json`; CSV chuẩn SHA-256 `1809f6a6…` |
| 9 cơ chế Java trong `G0_ERRATA.md` | So từng số dòng với nguồn OWASP công khai | **9/9 đúng** (00863, 01746, 01752, 00864, 00062, 01006, 01156, 00949, 00950; xem 4.3) |
| Đồng thuận raw C ↔ `recommended_status` 76/76 | Đọc mã tính (`audit_raw_bundle.py:426-428, 660-662`) | Cách tính đúng; số liệu cần raw → `NOT_VERIFIED` bởi Antigravity, nhất quán với dẫn xuất từ nguồn cho 56 alert OWASP ở kiểm toán trước |

## 2. Điểm mù đã khắc phục được bằng chứng

| Mục | Trước | Bằng chứng mới | Trạng thái |
|---|---|---|---|
| 56 nhãn OWASP | Codex xác minh trên bản trong gói | Tải công khai: **56/56** khớp CWE, TP/FP, category, `source_sha256` (28 TP/28 FP); exit 0 | Đã xác minh độc lập |
| Nguồn 4 nhãn FP thủ công | Codex: "gói không có UserForm/caller" | WebGoat công khai `5357a65e` và `UserDao.java` trong `opengrep-triage.zip` **trùng SHA-256** với nguồn đã quét (3/3) | Đã xác minh danh tính nguồn |
| OLD-004 stale-source | INCOMPLETE | Chạy `test_human_review_negative_suite.py` trên **đúng mã lịch sử** `git archive 86636b9`: 16/16 OK, gồm `test_05/06/07/12` (từ chối `confirm-false` khi nguồn/trace bị sửa/xóa/sai hash) | B: năng lực của mã lịch sử đã kiểm; lần thử lịch sử không có |
| OLD-001 checkpoint | INCOMPLETE | `git show <c>:v2/triage/cli.py`: `--checkpoint` xuất hiện **lần đầu ở `8a1ef91`** (0 lần ở `30f6094`, `38d8769`, `6649493`); `PROMPT_VERSION_MANIFEST.json` mô tả v1.0-baseline là cấu hình trước Stage 2 | B: vắng checkpoint nhất quán với lịch sử mã; phiên bản mã thực chạy không có argv |
| OLD-024 thời điểm khóa | INCOMPLETE | `git merge-base --is-ancestor 38d8769 e5e60ea` exit 0; `git diff 38d8769 86636b9 -- labels_heldout.* heldout_alerts.json heldout_strict_lock_manifest.json` rỗng; `git diff 8a1ef91 e5e60ea -- v2/triage` chỉ thêm một tệp test | B: thứ tự DAG và việc không sửa nhãn/mã sau khóa đã chứng minh; giờ đồng hồ thật (timestamp commit cục bộ tự khai) không chứng thực được → C |

## 3. Điểm mù không thể khắc phục vì thiếu chứng cứ lịch sử

| ID | Phân loại | Lý do | Xử lý chính thức đề xuất |
|---|---|---|---|
| OLD-001 checkpoint_absent | **B** | Như mục 2; checkpoint chỉ phục vụ chạy tiếp, không phải chứng cứ kết quả; chỉ thuộc dev v1.0, không vào metric held-out | Giữ giới hạn, ghi "vắng do lịch sử mã, phiên bản chạy không chứng thực" |
| OLD-004 historical_stale_source_demo | **B** | Mã `86636b9` có chốt chặn (đã chạy); transcript 13 bước không có thao tác này | Giữ giới hạn; G1 ghi log lần thử thật |
| OLD-023 lock_config_null | **C** | `config_file/config_sha256 = null`; `PROMPT_VERSION_MANIFEST.json` (commit `8a1ef91`, trước `e5e60ea` trong DAG) chỉ là tham chiếu, không băm vào khóa, không có digest model/mã | Không lập khóa hồi tố; công bố |
| OLD-024 pre_run_lock_time | **B + C** | Như mục 2 | Công bố: "thứ tự DAG đã kiểm, thời điểm tuyệt đối không chứng thực" |
| OLD-028 manual_ground_truth | **D** | Nhãn tác giả; cần chuyên gia và cấu hình triển khai (xem 5.3) | Loại 20 nhãn khỏi GT đã kiểm chứng (Codex đã làm) |
| Raw tái chạy bởi Antigravity | — | Không được cấp quyền đọc gói riêng | `NOT_VERIFIED` (Antigravity); cấp quyền nếu cần kiểm chéo thứ hai |

Không tạo lại hiện vật lịch sử nào.

## 4. Lỗi mới phát hiện và kiểm thử chứng minh

Kiểm thử: [test_review_codex_g0.py](test_review_codex_g0.py) (11 test, đọc Codex ở chế độ chỉ đọc). Bản vá đề xuất cho Codex (không áp vào worktree Codex): [PROPOSED_resolve_g0_acceptance.patch](PROPOSED_resolve_g0_acceptance.patch).

### 4.1. Logic nghiệm thu (`resolve_g0.py`)

| # | Lỗi | Vị trí | Test | Ảnh hưởng tới kết luận hiện tại |
|---|---|---|---|---|
| L1 | **`G0_AUDIT_COMPLETED` là hằng `True`**, không tính từ điều kiện nào; `axes`, `conditions`, `git`, `additional_review_rows`, `additional_peer_errata` cũng là chuỗi/số viết cứng | `resolve_g0.py:164-184` | `test_05` (AST) | Trả lời câu II.1: không có điều kiện. `axes`/`conditions` không tự cập nhật khi đầu vào thay đổi |
| L2 | **CONDITIONAL không tái lập được từ tệp công bố.** `acceptance()` nhận `audit.private.json` (không công bố, chỉ có 2 FAIL). Đưa `criteria`+`register` **đã công bố** trong `G0_RAW_INDEPENDENT_VERDICT.json` (6 FAIL) vào cùng hàm → **BLOCKED** | `resolve_g0.py:65-76, 162` | `test_01` | Bốn FAIL (2 rationale Java, 2 số liệu Arm D trong tài liệu) lọt qua cổng chỉ vì không nằm trong register raw, trong khi hai FAIL thời gian lại phải miễn trừ theo tên trường → quy tắc không nhất quán |
| L3 | `acceptance()` **không yêu cầu** chính các run held-out B/C/D: run C `INCOMPLETE` + aggregate `INCOMPLETE` vẫn ra CONDITIONAL | `resolve_g0.py:66-67` | `test_02` | Không đổi kết quả thực tế (cả ba run held-out đều PASS trong verdict); là lỗ hổng phòng thủ |
| L4 | Bỏ qua `exit_code` và danh sách `missing` của raw audit | `resolve_g0.py:65-76` | `test_03` | Raw exit 2 vẫn CONDITIONAL; đã công bố trong md, nhưng không do mã kiểm |
| L5 | `classify()` gán **mọi** FAIL là `ERRATA_ISSUED`, kể cả FAIL nhãn GT, không kiểm có errata | `resolve_g0.py:38-39` | `test_04` | Không xảy ra trên dữ liệu thật; nguy hiểm khi dùng lại |
| L6 | Hai hồ sơ cùng bộ công bố mâu thuẫn: `G0_RAW_INDEPENDENT_VERDICT.json` ghi `g0_acceptance = INCOMPLETE`, 36 test; `README.md` ghi "G0 INCOMPLETE", 36 test; `G0_FINAL_RESOLUTION.*` ghi CONDITIONAL, 43 test | các tệp nêu | `test_06` | Người đọc GitHub thấy hai phán quyết; cần ghi chú "đã được thay thế" |

Câu II.5: `G0_FINAL_RESOLUTION.md:135` nói rõ exit 0 của `resolve_g0.py` chỉ là xuất tài liệu và nêu raw exit 2 → **không** bị hiểu nhầm trong văn bản. Câu II.6: không thấy số liệu công bố được dùng làm đáp án trong `audit_raw_bundle.py`; 18 hàng PASS `OLD-040…057` có `expected = actual = số phép so` (tự quy chiếu, không phải bằng chứng đối chiếu; chi tiết nằm trong `audit.private.json` không công bố).

**Bản vá đề xuất** (đã kiểm trên bản sao trong scratch): (a) thêm 3 run held-out vào danh sách bắt buộc; (b) danh sách FAIL-tài-liệu tường minh gồm cả 4 hàng rationale/Arm D; (c) chặn INCOMPLETE của aggregate nếu không phải latency; (d) chạy cùng quy tắc trên cả register raw và register lịch sử; (e) `classify()` trả `UNRESOLVED_FAIL` cho FAIL ngoài danh sách; (f) `G0_AUDIT_COMPLETED` tính bằng "không có UNRESOLVED_FAIL", thêm `open_criteria_derived`. Kết quả: `git apply` exit 0; **45/45** test Codex (43 cũ + 2 mới) OK; trên verdict công bố cho **CONDITIONAL** (kết luận không đổi, nay tái lập được); các phản ví dụ L3/L5 → BLOCKED/UNRESOLVED_FAIL.

### 4.2. Register 65 hàng

| Nhóm | Số | Đánh giá |
|---|---:|---|
| PASS | 20 | 18 hàng là số phép so theo tiêu chí (tự quy chiếu, xem trên); 2 hàng rà soát luồng 01752/00864 khớp nguồn công khai |
| ERRATA_ISSUED (6 FAIL cũ) | 6 | Giá trị đính chính đúng (latency 181.70/9.09; Arm D 6S/4U và 8S/2U khớp CSV công khai; 00863/01746 đúng). **Chưa sửa** ở bất kỳ tài liệu công bố nào: errata chỉ nằm trong thư mục chưa commit, `CHUONG_4`/`PAIRED_EVALUATION.md` vẫn sai → trạng thái thực là "errata đã soạn, chờ duyệt". FAIL gốc vẫn giữ trong `before` |
| ERRATA_ISSUED (8 NEW_REVIEW) | 8 | 7 cơ chế Java đúng nguồn; hash peer sai được ghi đúng |
| NOT_MEASURED | 19 | Đúng bản chất (không có mẫu đo). **Thiếu errata**: `METRICS_BY_CWE.csv` (0.0 ms cho A/B), `PAIRED_EVALUATION.md:31` ("<15 ms"), `CHUONG_4:59`, `POST_REPORT_IMPLEMENTATION_HANDOVER.md:115` vẫn trình bày như số đo → đổi nghĩa chỉ số. Cần errata E1 |
| REFERENCE_AVAILABLE_LIMITED / PROMPT_NOT_ATTESTED | 2 / 1 | Mô tả đúng giới hạn; không nâng thành PASS |
| CONDITIONAL / LABEL_REVIEW_REQUIRED | 3 / 1 | Đúng mức chắc chắn (xem 5.3) |
| INCOMPLETE | 5 | Xem mục 3 |

**Errata còn thiếu** (đã biết, có nguồn, chưa vào register/errata Codex): E1 latency A/B (trên); E2 `REAL_PROJECT_EVALUATION.md:37,60` và `CHUONG_4:82` đặt `@Pattern` ở `WebGoatUser.java` — sai (5.3); E3 `POST_REPORT_IMPLEMENTATION_HANDOVER.md:122,124` lấy `BenchmarkTest00002`/`00033` (đều `true` trong CSV chuẩn) làm ví dụ FP; `CASE_STUDIES_CWE22_CWE89.md` mô tả 01110/01215 là list/HashMap trong khi mã là `switch(switchTarget)` (d.107/110, d.82/85); `POST_REPORT_IMPLEMENTATION_HANDOVER.md:80` và `CHUONG_4:7` ghi 14 rule, tệp thật có 9; `CHUONG_4:14` ghi sai `scan_sha256` dev. Câu "đã phân loại toàn bộ vấn đề trong phạm vi" (`G0_FINAL_RESOLUTION.md:6`) vì vậy là quá rộng.

### 4.3. Antigravity tự đính chính

Đối chiếu nguồn công khai cho thấy chính hồ sơ Antigravity trước đây có sai sót (đã thêm cảnh báo đính chính ở đầu từng tệp, không xóa lịch sử):

- `audit_20261112/DISCREPANCY_AND_EVIDENCE_AUDIT.md:44` mô tả `UserDao.java` bằng mã không tồn tại (`Path target = baseDir.resolve(...)`); `:74` gọi tệp là "tự viết nội bộ" trong khi nó lấy từ `opengrep-triage.zip` của giảng viên.
- `audit_20261112/OWASP_GROUND_TRUTH_AUDIT_56.md:83`: tên phương thức là `open`, không phải `readSafe`.
- `audit_20261112/G0_BLIND_SPOT_REMEDIATION_AND_LOCK_ERRATA.md` bảng mục 3: số dòng/sink của 01746, 01752, 00863, 00864 sai (Codex đúng: 01752 put d.80/get d.82, sink d.60–61).
- Nhận định trong biên bản trò chuyện trước (không commit): "#08/#09 khai thác được trên MySQL" và "#15 có thể vượt tiền tố anh em" **là sai** — sau `replace('\'','"')` không còn dấu nháy đơn nào để đóng chuỗi; `BASE_DIR` kết thúc bằng `/`.

Không sai sót nào ở trên làm đổi nhãn hay metric.

## 5. Độ tin cậy của các kết luận G0

### 5.1. Ground Truth OWASP và metric

- 56 nhãn: **đã xác minh độc lập** từ nguồn công khai. Đính chính Java của Codex: **chính xác**.
- Metric A/B/C/D: cùng một hàm `recompute.metrics()` cho mọi nhánh; A là placeholder giữ tất cả; B không có latency đo. Ma trận khớp CSV công khai (replay). Raw-level: `NOT_VERIFIED` (Antigravity).
- Raw Qwen và post-validator tách riêng (D raw 40 S → post 31 S/9 U do trích dẫn, 9/9 lý do "citation does not match").
- Steering 76/76 và Arm C: hồ sơ ghi `LLM_CONTRIBUTION = CONFOUNDED`, không tuyên bố năng lực độc lập của Qwen. **Trung thực.**

### 5.2. Thời gian dự án/demo

181.70 s / 9.09 s là tổng/trung bình `elapsed_seconds` từng alert, không phải đồng hồ đầu-cuối. Hồ sơ đã ghi đúng.

### 5.3. Bốn nhãn FP thủ công (nguồn trùng SHA với bản đã quét)

| # | Sự kiện mã nguồn | Mức chắc chắn hợp lý | Codex |
|---|---|---|---|
| #08/#09 `SqlInjectionLesson8.java:148→154→158` | `action.replace('\'','"')` trước khi nối vào `VALUES ('…', '` + action + `')`. Không còn dấu `'` để đóng chuỗi; `\` cuối chuỗi (MySQL bật escape) chỉ làm câu lệnh lỗi cú pháp | FP khá vững về injection; vẫn phụ thuộc dialect/charset → CONDITIONAL là thận trọng | Đúng |
| #10 `UserService.java:52` | `@Pattern("[a-z0-9-]*")` nằm ở **`UserForm.java:19`**, không ở `WebGoatUser.java` (không có `@Pattern`). Có **hai caller** của `addUser`: `RegistrationController.java:44` (qua `@Valid UserForm`) và **`:54` OAuth** `addUser(authentication.getName(), …)` **không qua validator** → `CREATE SCHEMA "…"` | Nhãn FP **không được nguồn chứng minh**; phụ thuộc ràng buộc tên của OAuth provider | LABEL_REVIEW_REQUIRED đúng; lý do lịch sử (E2) sai |
| #15 `UserDao.java:63` | `BASE_DIR = "/var/app/files/"` (d.17, có `/` cuối); `getCanonicalPath().startsWith(BASE_DIR)` d.64 trước `return f` | Chặn tiền tố đúng; còn TOCTOU/symlink-swap và caller → CONDITIONAL hợp lý | Đúng |

Nhóm 20 nhãn đã bị loại khỏi GT đã kiểm chứng, nên phát hiện #10 **không** đổi metric held-out; nó chỉ củng cố việc không được dùng "0/4 FP lọc được" làm chỉ số chuẩn.

## 6. An toàn công bố 24 tệp

Quét: [review_codex_g0.py](review_codex_g0.py) `publication_scan()` (+ quét mẫu bí mật). **Không** có raw response, mảng `messages`/prompt, token, mật khẩu, email, SQLite nhị phân. `ground_truth_56.csv` chứa dòng sink OWASP (mã công khai). Tên tệp `review.sqlite` chỉ là tham chiếu trong mã. `.gitignore` chặn output riêng.

**11 dòng chứa đường dẫn tuyệt đối** (yêu cầu nêu 10; tôi đếm 11 dòng):

| Tệp:dòng | Nội dung cũ | Đề xuất mới | Cá nhân/riêng tư | Ảnh hưởng tái lập |
|---|---|---|---|---|
| `FINDINGS.md:83` | `C:\Users\<USER>\AppData\Local\Temp\ntk-crosscheck-followup-7005…\audit.json` | `<PRIVATE_OUTPUT>\audit.json` (kèm SHA nếu có) | Tên tài khoản `HP`; thư mục tạm | Không (đường dẫn tạm đã mất giá trị) |
| `G0_RAW_INDEPENDENT_VERDICT.json:23` | `C:\\Users\\<USER>\\AppData\\Local\\Temp\\ntk-g0-final-2370…\\audit.private.json` | `"<PRIVATE_OUTPUT>/audit.private.json"` như `G0_FINAL_RESOLUTION.json` đã làm | Như trên | Không; giữ SHA `40e945a5…` ở md |
| `G0_RAW_INDEPENDENT_VERDICT.md:13` | `C:\Users\<USER>\Downloads\OpenGrep-Private-Evidence\NTK-G0-Private-20261112` | `$env:NTK_G0_PRIVATE_PACKAGE` (gói riêng, SHA archive `4664dcdb…`) | **Chỉ tới vị trí dữ liệu riêng** trên laptop cá nhân | Không, nếu giữ SHA archive |
| `G0_RAW_INDEPENDENT_VERDICT.md:226` | `$pkg = 'C:\Users\<USER>\Downloads\…'` | `$pkg = $env:NTK_G0_PRIVATE_PACKAGE` | Như trên | Không |
| `G0_RAW_INDEPENDENT_VERDICT.md:235` | `…\Temp\ntk-public-lock-5e9gy5_a` | `<PUBLIC_EXPORT_DIR>` (7 tệp từ `git show 86636b9:…`) | Tài khoản `HP` | Không |
| `G0_RAW_INDEPENDENT_VERDICT.md:236` | `…\Temp\ntk-g0-final-2370…\audit.private.json` | `<PRIVATE_OUTPUT>\audit.private.json` | Tài khoản `HP` | Không |
| `README.md:27` | `$pkg = 'C:\Users\<USER>\Downloads\…'` | `$pkg = $env:NTK_G0_PRIVATE_PACKAGE` | Vị trí dữ liệu riêng | Không |
| `TRANSFER_REQUEST.md:6` | `C:\Users\<USER>\Downloads\…` | `<NTK_G0_PRIVATE_PACKAGE>` | Vị trí dữ liệu riêng | Không |
| `TRANSFER_REQUEST.md:59,61,64` | `C:\Users\<SERVER_USER>\ntk-thesis-v2\…` (E, F, W trên máy chủ) | `<SERVER_EVIDENCE_E>`, `<SERVER_EVIDENCE_F>`, `<SERVER_WORKTREE_W>` | Tài khoản máy chủ `Admin`; đường dẫn này **đã công khai** trong `DATASET_PROVENANCE.json` của `86636b9` | Thấp; JavisOS vẫn có ghi chú nội bộ |

Đổi `G0_RAW_INDEPENDENT_VERDICT.json` sẽ đổi SHA của tệp này (không tệp công bố nào ghim SHA đó; test của tôi ghim để nhận diện phiên bản đã rà và sẽ cập nhật). Đồng thời nên thêm dòng đầu "đã được thay thế bởi G0_FINAL_RESOLUTION.md" vào `README.md` và `G0_RAW_INDEPENDENT_VERDICT.*` (L6).

**Đánh giá:** an toàn để đẩy **sau khi** thay 8 dòng chứa `C:\Users\<USER>\…` (khuyến nghị cả 3 dòng `Admin`) và thêm ghi chú thay thế. Không có rủi ro lộ dữ liệu thô hay prompt.

## 7. Lỗi thực sự chặn G1 và kết luận

**Không có lỗi đã xác minh nào làm sai Ground Truth OWASP hoặc metric held-out được G0 sử dụng.** Các lỗi tìm thấy nằm ở logic cổng nghiệm thu (không đổi kết quả trên dữ liệu thật; đã có bản vá + test), ở tài liệu lịch sử (errata còn thiếu) và ở an toàn công bố.

Điều kiện kèm theo (không phải nghiên cứu G0 vô thời hạn):
1. Trước khi đẩy 24 tệp: thay các đường dẫn `C:\Users\<USER>\…`, thêm ghi chú thay thế (mục 6).
2. Trước khi dùng lại `resolve_g0.py`: áp bản vá L1–L5 hoặc tương đương (Codex quyết định).
3. Trước khi công bố quyển/báo cáo: bổ sung errata E1–E3; đổi "ERRATA_ISSUED" thành "đã duyệt" chỉ sau khi giảng viên chấp nhận.
4. Giữ các giới hạn B/C/D ở mục 3; G1 phải lưu prompt, argv, checkpoint và khóa cấu hình ngay từ đầu.
5. Nếu cần kiểm chéo raw lần hai, cấp quyền đọc gói riêng cho Antigravity.

**Kết luận: `READY_FOR_G1_WITH_DISCLOSED_LIMITATIONS`.** Đây không phải quyết định nghiệm thu G0 (thuộc giảng viên) và không chứng minh Qwen cải thiện so với OpenGrep-only.

---

## Phụ lục — Lệnh, mã thoát, bằng chứng

| Lệnh | Exit | Kết quả |
|---|---:|---|
| `python -X utf8 -B -m unittest discover -s <codex>/v2/crosscheck -t <codex>/v2/crosscheck` | 0 | 43/43 OK; thư mục Codex không đổi |
| `python -X utf8 -B -m unittest discover -s v2/evaluation/g0_final_review -p test_review_codex_g0.py` | 0 | 11/11 OK (phản ví dụ L1–L6, metric khớp, quét công bố, quy tắc đề xuất) |
| `python -X utf8 -B v2/evaluation/g0_final_review/review_codex_g0.py` | 2 | Đúng hợp đồng: có lỗi (acceptance công bố BLOCKED ≠ CONDITIONAL; 11 đường dẫn tuyệt đối) |
| `python -X utf8 -B v2/evaluation/g0_final_review/verify_owasp_public.py --cache <ngoài repo> --codex-reference <codex>/owasp_reference_blobs.json` | 0 | 56/56 nhãn; 61/61 blob |
| `python -X utf8 -B v2/evaluation/g0_final_review/verify_manual_fp_sources.py --advisor-zip <_advisor_sources>/opengrep-triage.zip` | 0 | 3/3 danh tính nguồn khớp; dữ kiện mục 5.3 |
| `git apply PROPOSED_resolve_g0_acceptance.patch` trên bản sao scratch + test Codex | 0 / 0 | 45/45 OK; verdict công bố → CONDITIONAL |
| `python -B -m unittest discover -s v2/triage/tests -p test_human_review_negative_suite.py` trên `git archive 86636b9` | 0 | 16/16 OK |
| `git merge-base --is-ancestor 38d8769 e5e60ea` | 0 | Khóa held-out là tổ tiên của commit kết quả |

Output chi tiết (JSON) nằm ngoài repository trong thư mục scratch của phiên làm việc; không commit nguồn WebGoat/OWASP đã tải, không commit nội dung `opengrep-triage.zip`.
