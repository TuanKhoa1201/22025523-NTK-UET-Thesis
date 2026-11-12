# G0 — Kiểm toán độc lập bản v2.2 và mức sẵn sàng an toàn trước khi tích hợp thử nghiệm G1

- **Phạm vi:** Java, CWE-22 và CWE-89; OpenGrep + Qwen cục bộ qua Ollama. Đây là kiểm toán **hợp đồng đầu vào, cổng kiểm chứng và tính đóng an toàn**, không phải benchmark mới, không đo độ chính xác của Qwen.
- **Người thực hiện:** Antigravity, nhánh `v2/antigravity-review`.
- **Kết luận cuối (mục 11):** **`READY_FOR_G1`** — chỉ theo nghĩa các chốt chặn kỹ thuật cần cho tích hợp thử nghiệm đã được xác minh ở mức kiểm thử tổng hợp/replay. **Không** có nghĩa Qwen đã được chứng minh tốt hơn OpenGrep-only, và **không** phải quyết định nghiệm thu G0 (thuộc về giảng viên).

> [!IMPORTANT]
> Mọi kết quả trong tài liệu này là **test synthetic** (fixture Java tự viết) hoặc **test replay** (tái dựng payload/verifier từ mã nguồn). **Không có test runtime nào gọi Qwen thật** trong lượt kiểm toán này. Kết quả v2.1 lịch sử không được dùng làm bằng chứng hiệu năng của v2.2.

---

## 1. HEAD và commit

| Mục | Giá trị |
|---|---|
| Nhánh làm việc | `v2/antigravity-review` (theo dõi `origin/v2/antigravity-review`) |
| HEAD khi bắt đầu | `03cd8726bcab4ce88d1d136d56194dd1e6542c52` — working tree sạch, không có stash, không có thay đổi chưa commit |
| Commit thực nghiệm v2.1 (lịch sử) | `86636b9de22e59efcca2d3786434727c6ae082e4` |
| Commit v2.2 thực sự tồn tại | `03cd872` (duy nhất; có `HEURISTIC_VERSION = "v2.2-flow-grounded"`, `PROMPT_VERSION = "v2.2-cwe22-cwe89-neutral"`) |
| Nhánh khác (chỉ đọc, không sửa) | `origin/v2/javis-benchmark` = `955edab`, `origin/v2/codex-core` = `8db7daf` |
| Commit của lượt kiểm toán này | xem thông điệp commit tiếng Việt ngay sau tài liệu này trên cùng nhánh |

## 2. Tình trạng mã v2.2 thực tế (tại `03cd872`, trước lượt vá này)

Đã xác nhận bằng hiện vật, không giả định:

- `v2/triage/heuristics.py`: `_FlowAnalyzer` theo dõi trạng thái từng biến (`TAINTED`, `SAFE_CONST`, `SANITIZED_CWE22/89`, `UNKNOWN`), hợp nhất nhánh bảo thủ, gọi helper cùng tệp tối đa 3 bước, lớp ngoài tệp → `UNKNOWN` và ghi `unresolved_calls`.
- `v2/triage/ollama.py`: `neutralize_evidence_signals()` là **danh sách đen** (chỉ loại 7 khóa trong `STEERING_SIGNAL_KEYS`); `inspect_citations_provenance()` tách 3 tầng citation; `legacy_v2_1_request_payload()` chỉ dùng cho đối chiếu băm lịch sử.
- `v2/triage/java_context.py`: callee có `owner_class`, chuỗi gọi tối đa 3 bước.
- 10 fixture `CE01..CE10` + `test_blind_spot_regressions.py` (19 test).
- Kiểm thử nền tại `03cd872` (chạy lại trong lượt này): `v2/triage/tests` 110 test OK (1 skip do quyền symlink Windows), `v2/evaluation/tests` 44 OK, `test_independent_audit` 22 OK.

## 3. Danh sách thay đổi so với v2.1 (`86636b9` → `03cd872`, và phần bổ sung của lượt này)

### 3.1. `86636b9` → `03cd872` (đã có trước lượt này)

`git diff --stat 86636b9 03cd872`: 28 tệp, +10451/−504. Thay đổi mã sản xuất: `heuristics.py` (+2014 dòng thay đổi), `java_context.py` (162), `ollama.py` (432), `verify_evidence_audit.py` (70). Không có thay đổi nào trong `v2/evaluation/post_report/`, `v2/demo/`, `v2/evaluation/smoke_evidence/` (đã kiểm tra `git diff --stat 86636b9 -- <các thư mục đó>` rỗng) — nhãn, raw evidence và số liệu lịch sử được giữ nguyên.

### 3.2. Lượt kiểm toán này (vá tối thiểu, chỉ các lỗi trực tiếp làm yếu cổng kiểm chứng)

| Tệp | Thay đổi | Lý do (lỗi đã tái hiện) |
|---|---|---|
| [ollama.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/ollama.py#L28-L84) | `PROMPT_VERSION` → `v2.2.1-cwe22-cwe89-whitelist`; thêm hai hợp đồng `blind` / `neutral_hints`; whitelist có kiểm tra kiểu | P1, P2 (mục 4) |
| [ollama.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/ollama.py#L428-L527) | `neutralize_evidence_signals()` dựng lại từ đầu theo whitelist; `_java_context_summary()` chiếu trường; `assert_prompt_contract()` kiểm tra payload cuối, sai → `EvidenceError` → `UNDETERMINED` | P1, P2 |
| [ollama.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/ollama.py#L388-L407) | Cổng `REFUTED`: chặn khi thiếu `heuristic_signals`, và khi luồng chưa quyết định có **bất kỳ** lời gọi chưa giải được (không chỉ `missing_helper_implementation`) | G1, G2 (mục 6) |
| [ollama.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/ollama.py#L721-L724) | Ghi `prompt_contract` vào kết quả đánh giá | Truy vết hợp đồng đã dùng |
| [scan_receipt.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/scan_receipt.py#L18-L42) | `json_sarif_disagreement()` + chặn biên nhận khi JSON và SARIF cùng lượt quét báo khác nhau (dòng 133–136) | F2 (mục 7) |
| [capture_fixture.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/tests/capture_fixture.py) | Fixture MOCK sinh SARIF phản chiếu JSON (trước đây luôn là `{"runs":[]}` và vẫn được chấp nhận) | F2 |
| [test_g0_v22_payload_contract.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/tests/test_g0_v22_payload_contract.py) (mới, 16 test) + [PL01_ConstantSwitchPayloadProbe.java](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/tests/fixtures/counterexamples/PL01_ConstantSwitchPayloadProbe.java) (fixture tự viết) | Kiểm thử hồi quy trước/sau | — |
| [test_blind_spot_regressions.py](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/tests/test_blind_spot_regressions.py#L525) | Cập nhật hằng phiên bản prompt | Phiên bản payload đổi phải đổi nhãn phiên bản |

`heuristics.py`, `java_context.py`, `evidence.py`, `store.py`, mọi tệp `post_report`, nhãn và raw evidence **không bị sửa** trong lượt này.

> [!WARNING]
> `scan_receipt.py` và `capture_fixture.py` là mã lõi dùng chung. Thay đổi chỉ nằm trên `v2/antigravity-review`; khi hợp nhất với `v2/codex-core` cần Codex rà soát lại. Phép so sánh JSON/SARIF đã được đối chiếu với **một** cặp JSON/SARIF thật của OpenGrep OSS 1.25.0 trong kho (`v2/demo/smoke_v2_taint_raw.opengrep.{json,sarif}`, 2/2 kết quả khớp). Nếu biên nhận máy chủ dùng URI SARIF tuyệt đối, cổng sẽ đóng an toàn (báo lỗi, đòi quét lại), không im lặng chấp nhận.

---

## 4. Kết quả kiểm tra payload thực sự gửi Qwen

### 4.1. Phương pháp

Truy vết từ `evidence.collect()` → `record["heuristic_signals"]` ([evidence.py:281](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/evidence.py#L279-L283)) → `prompt()` → `request_payload()` → thân JSON trao cho `OllamaClient.request()`. Test `test_06` chặn tại ranh giới HTTP (vá `OllamaClient.request`) và đọc đúng payload mà `analyze()` gửi đi, không chỉ tìm tên biến trong mã nguồn.

### 4.2. Phân tích theo nội dung từng trường (tại `03cd872`)

Payload `evidence_signals` thực tế tại `03cd872` (probe trên CE01/CE03/CE04/CE10/PL01) chứa 10 khóa: `heuristic_version, primary_cwe, source_kind, source_line, sink_line, uses_inner_helper, uses_thing_factory, non_sanitizers_found, unresolved_calls, dead_branch_lines`.

| Trường | Nội dung thực tế | Có làm lộ kết luận heuristic? | `blind` | `neutral_hints` (sau vá) |
|---|---|---|---|---|
| `recommended_status`, `recommendation_reason`, `candidate_citations`, `sanitizers_found`, `intra_procedural_decisive` | Phán quyết, lý do tiếng Việt, trích dẫn dựng sẵn | Có, trực tiếp | Không gửi | Không gửi |
| `intra_method_flow`, `callee_method_flow` | `{"outcome": "SAFE_CONSTANT"/"TAINTED", "mechanism": "switch_constant_char_branch", ...}` | Có — `outcome` tương đương phán quyết | Không gửi | Không gửi |
| **`dead_branch_lines`** | Danh sách dòng heuristic tính là nhánh chết. PL01: `[13]` = đúng dòng `bar = param;` | **Có** — chỉ ra nhánh nhiễm bẩn không chạy, gần như nói thẳng `REFUTED`. **Lọt qua danh sách đen v2.2 (P1)** | Không gửi | Không gửi |
| `non_sanitizers_found` | Heuristic phân loại hàm (ví dụ `URLDecoder.decode` không làm sạch) | Có — phán đoán phân loại nghiêng về `SUPPORTED` | Không gửi | Không gửi |
| `uses_inner_helper`, `uses_thing_factory` | Regex theo tên `doSomething(` / `ThingFactory.createThing(` của OWASP | Gợi ý theo tên benchmark | Không gửi | Không gửi |
| `unresolved_calls` | Mục có `reason` = `missing_helper_implementation` / `max_hop_depth_exceeded`, hoặc mục **không có `reason`** chỉ được ghi khi một định danh `TAINTED` đi vào lời gọi lạ (heuristics.py:752–758) | Mục không `reason` phụ thuộc kết quả taint → lộ; mục `missing_helper` là sự kiện cấu trúc | Không gửi | Chỉ giữ `missing_helper_implementation`, đổi tên `unresolved_external_calls`, chỉ còn `method`/`qualifier`/`line` đã kiểm tra định danh |
| `source_kind` | `HTTP_SERVLET_INPUT` nếu regex thấy API đọc request ở bất kỳ dòng nào trong cửa sổ, ngược lại `METHOD_OR_EXTERNAL_INPUT` | Không mang phán quyết; là sự kiện văn bản (không chứng minh có luồng) | Không gửi | Giữ, bắt buộc thuộc enum |
| `source_line`, `sink_line` | Vị trí từ trace OpenGrep | Không | Không gửi | Giữ, bắt buộc `int ≥ 1` |
| `heuristic_version`, `primary_cwe` | Nhãn phiên bản; CWE đã có ở trường `cwe` | Không cần cho mô hình | Không gửi | Không gửi |
| `java_context_summary` | Trước: sao chép nguyên dict method từ `java_context` | Không mang phán quyết, nhưng trường lạ lồng bên trong sẽ lọt (P2) | Gửi, đã chiếu trường | Gửi, đã chiếu trường |

### 4.3. Hai hợp đồng đầu vào

- **A. `blind`** (`record["prompt_contract"] = "blind"`): chỉ `rule_id, cwe, severity, start, end, snippets, trace_steps, java_context_summary`. Không có `evidence_signals`. Đã xác minh bằng `test_03` (tập khóa chính xác) và `test_06` (payload tại ranh giới HTTP).
- **B. `neutral_hints`** (mặc định): `blind` + `evidence_signals` ⊆ `NEUTRAL_HINT_WHITELIST = (source_line, sink_line, source_kind, unresolved_external_calls)`.
- Hợp đồng không hợp lệ → `UNDETERMINED`, không gửi request (`test_07`).
- `assert_prompt_contract()` quét đệ quy payload cuối: cấm mọi khóa phân tích heuristic ở mọi tầng lồng và cấm token phán quyết (`SUPPORTED`, `REFUTED`, `UNDETERMINED`, `SAFE_CONST`, `TAINTED`, `SANITIZED_CWE…`) ngoài văn bản mã nguồn (`test_05`).

> [!NOTE]
> Hai tên hợp đồng chỉ mô tả **đầu vào**. Chúng không thay đổi cách diễn giải kết quả lịch sử của Arm C (v2.1 đã truyền phán quyết heuristic, kết luận kiểm toán trước giữ nguyên).

### 4.4. Bằng chứng trước/sau (probe replay, cùng một script chạy trên bản lưu trữ `git archive 03cd872` và trên working tree)

| Probe | `03cd872` (trước) | Sau vá |
|---|---|---|
| P1 — PL01 switch hằng: khóa `evidence_signals` được gửi | `dead_branch_lines, heuristic_version, non_sanitizers_found, primary_cwe, sink_line, source_kind, source_line, unresolved_calls, uses_inner_helper, uses_thing_factory` | `sink_line, source_kind, source_line` |
| P2 — cài `{"extra": {"recommended_status": "REFUTED"}}` vào `heuristic_signals` | Lọt vào payload: **True** | **False** |

### 4.5. Giới hạn còn lại của payload

- **Rò rỉ qua chú thích trong mã nguồn OWASP (không do heuristic):** servlet OWASP chứa chú thích như `// condition 'B', which is safe`, `// get the last 'safe' value` (được trích nguyên văn trong `labels_heldout.csv`, ví dụ dòng 10–11). `snippets` gửi mã nguyên văn nên mô hình đọc được gợi ý nhãn này ở **cả** hai hợp đồng. Đây là biến nhiễu đánh giá, không phải lỗi an toàn → chuyển G1 (mục 10).
- `unresolved_external_calls` chỉ ghi lời gọi trên đoạn mã được heuristic đánh giá; nhánh chết bị bỏ qua nên vẫn còn tín hiệu bậc hai rất yếu. `blind` không có rò rỉ này.
- `source_kind` là regex trên toàn cửa sổ, không chứng minh có luồng tới sink.

---

## 5. Kết quả 10 ca phản ví dụ

**Bản chất:** đây là test khả năng chống kết luận sai của công cụ trên fixture tổng hợp, **không** phải Ground Truth thực nghiệm. Ba tầng được kiểm tra riêng: (L1) `extract_evidence_signals` — **không gửi cho mô hình**; (L2) `heuristic_analyze` (Arm B); (L3) `validate_answer()` khi giả định mô hình trả `REFUTED` có trích dẫn hợp lệ dòng sink. Không có Qwen thật.

| Ca | Mã Java và luồng cụ thể | Giả định cần để chứng minh an toàn | Đầu vào đủ chưa | L1 | L2 | L3 (mô hình giả định trả `REFUTED`) | Trạng thái |
|---|---|---|---|---|---|---|---|
| CE01 | `name = request.getParameter` (d.8) → nối vào `executeQuery` (d.10); `Integer.parseInt("7")` chỉ tác động `safeNumber` | `name` phải được ép kiểu/tham số hóa — không có | Đủ (cùng tệp) | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP`, vẫn `OPEN` | Heuristic PASS; tầng mô hình xem O1 |
| CE02 | `new FileInputStream(... + fileName)` d.11 chạy **trước** `FilenameUtils.getName` d.12 | Làm sạch phải đứng trước sink | Đủ | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1 |
| CE03 | `user = "guest_default"` chỉ trong `if` d.9–11, không `else` | Mọi nhánh tới sink phải hằng | Đủ | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1 |
| CE04 | `canonical.startsWith("/reports")` thiếu dấu phân cách → `/reports-private/...` lọt | Tiền tố phải kết thúc bằng phân cách thư mục | Đủ | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1, O11 |
| CE05 | Kiểm tra trên `safeFile`, mở `userFile` | Kiểm tra phải trên chính đối tượng tới sink | Đủ | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1 |
| CE06 | `cleanName = getName(rawPath)` bị bỏ qua; sink dùng `rawPath` | Kết quả làm sạch phải tới sink | Đủ | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1 |
| CE07a | `ExternalUnprovidedHelper.doSomething(param)` — lớp không có mã | Cần mã helper | **Không đủ** | UNDETERMINED | UNDETERMINED | **Bị chặn** → `UNDETERMINED` | PASS |
| CE07b | `new UnsafeHelper().doSomething` (trả `x`) — không được nối nhầm sang `UnusedSafeHelper` trùng tên trả hằng | Phân giải đúng lớp nhận | Đủ | SUPPORTED | UNDETERMINED (do regex `doSomething`) | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1, O5 |
| CE08a | `stepOne → stepTwo` trả nguyên tham số | Đi hết chuỗi gọi | Đủ (2 bước) | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1 |
| CE08b | `hop1 → hop2 → hop3 → hop4` (hop4 nằm ngoài ngân sách 3 bước, không có trong ngữ cảnh) | Cần thấy `hop4` | **Không đủ** | UNDETERMINED (`max_hop_depth_exceeded`) | UNDETERMINED | `03cd872`: **chấp nhận `REFUTED`** (G1). Sau vá: **bị chặn** | **PASS sau vá** |
| CE09 | `path = getName(path)` d.11 rồi bị gán đè `request.getParameter("override")` d.12 | Không bị ghi đè sau làm sạch | Đủ | SUPPORTED | SUPPORTED | Chấp nhận như `PROPOSED_FP` | Heuristic PASS; O1 |
| CE10 | `scr.getTheValue` và `MissingSanitizerHelper.normalizePath` không có mã | Cần mã hai helper | **Không đủ** | UNDETERMINED | UNDETERMINED | Bị chặn khi có `heuristic_signals`; `03cd872` **chấp nhận** khi `heuristic_signals=None` (G2). Sau vá: bị chặn | **PASS sau vá** |

Tóm tắt: ở L1/L2, **0/12 biến thể bị kết luận `REFUTED` sai**; mọi ca thiếu mã đều về `UNDETERMINED`. Ở L3, mọi ca **thiếu bằng chứng** nay đều bị chặn. Với 9 biến thể mà mã **đủ** và luồng nhiễm bẩn được heuristic chứng minh, verifier vẫn chấp nhận một `REFUTED` giả định của mô hình như đề xuất cảnh báo giả (không tự đóng, vẫn chờ người xác nhận) → **NOT_COVERED ở tầng mô hình**, phải đo bằng runtime trong G1 (O1).

Ngoài ra `test_12` là đối chứng không chặn quá tay: PL01 (switch hằng chứng minh được hoàn toàn trong tệp) — `REFUTED` trích dòng sink vẫn được chấp nhận, `requires_human_review = True`.

---

## 6. Kết quả kiểm chứng citation

Ba mức được phân biệt: **nguyên văn hợp lệ** (`citation_in_source` + `citation_in_prompt`), **có liên quan** (`in_relevant_scope` — chỉ theo phạm vi dòng), **đủ chứng minh kết luận** (`supports_security_claim_verified`, luôn `False`, bắt buộc con người).

| # | Tiêu chí | Cơ chế (mã hiện hành) | Kiểm thử | Trạng thái |
|---|---|---|---|---|
| 1 | Đúng tệp Java | `path` phải có trong `record["snapshots"]` | `test_10` (independent), `test_10`/`test_14` | PASS |
| 2 | Đúng phiên bản mã | `check_current(record)` trong `validate_answer` và `analyze` | negative suite `test_05`–`test_07`, `test_12` | PASS |
| 3 | Đúng SHA-256 | `cite.sha256 == snapshot.sha256` | blind-spot `test_07` | PASS |
| 4 | Đúng vị trí dòng | `1 ≤ start ≤ end`, span ≤ 150, mọi dòng tồn tại | blind-spot `test_08`, `test_09` | PASS |
| 5 | Quote khớp chính xác | So khớp nguyên khối đa dòng | negative `test_14`, independent `test_02` | PASS |
| 6 | Dòng có trong ngữ cảnh mô hình nhận | So với `_compact_snippets_for_prompt()` cùng `triage_mode` | blind-spot `test_10`, independent `test_21` | PASS (tái dựng cửa sổ, xem giới hạn dưới) |
| 7 | Liên quan ngữ nghĩa với kết luận | Chỉ kiểm tra **ít nhất một** citation nằm trong method bao / callee / trace ([ollama.py:385](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/ollama.py#L385-L386)) | blind-spot `test_12` | **PARTIAL** — phạm vi, không phải ngữ nghĩa (O6) |
| 8 | Không dùng riêng comment / mã không thực thi | `_is_executable_java_span()` | blind-spot `test_11` | PASS |
| 9 | Không dùng mã nhánh chết | Dựa vào `dead_branch_lines` của heuristic | blind-spot `test_13`, mới `test_13` | **PARTIAL** — PL01: nhánh `default:` (d.19 `bar = param;`) không chạy được nhưng không bị đánh dấu chết; `SUPPORTED` trích d.19 vẫn được chấp nhận (O2). Hướng sai này là giữ cảnh báo, không loại cảnh báo |
| 10 | Không tuyên bố an toàn khi thiếu helper / đường gọi | Cổng `REFUTED` ([ollama.py:388–407](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/ollama.py#L388-L407)) | mới `test_09`–`test_11` | **PASS sau vá** (trước vá: lọt CE08b và trường hợp `heuristic_signals=None`) |

Bằng chứng trước/sau cho mục 10 (cùng probe replay như 4.4):

| Probe | `03cd872` | Sau vá |
|---|---|---|
| G1 — `REFUTED` trên chuỗi > 3 bước (CE08b) | `ACCEPTED REFUTED` | `REJECTED` (call path unresolved) |
| G2 — `REFUTED`, thiếu helper, `heuristic_signals=None` (CE10) | `ACCEPTED REFUTED` | `REJECTED` (flow-completeness analysis unavailable) |
| G3 — `REFUTED`, thiếu helper, có signals (CE10) | `REJECTED` | `REJECTED` |
| C1 — đối chứng PL01 chứng minh được | `ACCEPTED REFUTED` | `ACCEPTED REFUTED` |

**Giới hạn với prompt lịch sử:** prompt thô của 116 lượt gọi v2.1 trên máy chủ **không được lưu** (mã chỉ ghi `request_payload_sha256`, [ollama.py:690](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/ollama.py#L688-L690)). Vì vậy tiêu chí 6 với dữ liệu lịch sử chỉ kiểm được bằng **tái dựng** cửa sổ prompt từ mã, không đọc được văn bản prompt gốc. v2.2.1 vẫn chưa lưu văn bản prompt (O3).

---

## 7. Kết quả kiểm thử fail-closed

| Tình huống | Hành vi kỳ vọng | Kiểm thử (loại) | Trạng thái |
|---|---|---|---|
| Thiếu / hỏng raw scan | Không PASS; `INCOMPLETE`/`FAIL` | independent `test_17`; verify `test_03`, `test_04`, `test_12`; negative `test_16` (synthetic) | PASS |
| **JSON và SARIF mâu thuẫn** | Biên nhận không được xác nhận nguồn | **`03cd872`: NOT_COVERED** — `verify_receipt` chỉ kiểm SARIF có `runs`; chính fixture MOCK dùng `{"runs":[]}` với JSON có kết quả và mọi test vẫn qua (F2). Sau vá: mới `test_14`–`test_16` | **PASS sau vá** (synthetic + 1 cặp thật) |
| Thiếu / sai nhãn | `FAIL` | independent `test_18`, `test_01`, `test_13`; codex `test_6`, `test_16` | PASS |
| Mã nguồn sửa sau khi quét | Từ chối `confirm-false`, đòi quét lại | negative `test_05`–`test_07`, `test_12` | PASS |
| SQLite event/state không nhất quán | `FAIL` | independent `test_19`; verify `test_15` | PASS |
| Ollama HTTP lỗi / JSON hỏng | `UNDETERMINED`, cảnh báo `OPEN` | negative `test_15`, `test_16` | PASS |
| Ollama dừng vì giới hạn độ dài | `UNDETERMINED` | blind-spot `test_14`; independent `test_16` | PASS |
| Citation sai dòng / sai phiên bản | `UNDETERMINED` | negative `test_14`; blind-spot `test_07`–`test_09` | PASS |
| Thiếu input nhưng vẫn PASS | Không bao giờ PASS | independent `test_11`, `test_17` | PASS |
| Ép PASS khi có FAIL/INCOMPLETE | Mã thoát `1`/`2` | independent `test_20`; chạy thật `independent_audit.py` → exit `1` | PASS |
| Payload chứa phán quyết heuristic | `UNDETERMINED`, không gửi request | mới `test_05`, `test_07` | PASS (mới) |

Bất biến:

| Bất biến | Căn cứ | Trạng thái |
|---|---|---|
| Không tự động đóng cảnh báo | `state DEFAULT 'OPEN'` ([store.py:22](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/store.py#L22)); negative `test_01`; codex `test_9` | PASS |
| Chỉ con người xác nhận thật/giả | `decide()` đòi `actor` và `reason` không rỗng ([store.py:65–68](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/store.py#L65-L68)); negative `test_03`, `test_04` | PASS — danh tính `actor` không được xác thực (O7) |
| Nguồn đổi → quét lại trước `confirm-false` | `check_current` + so SHA trong `BEGIN IMMEDIATE` ([store.py:70–88](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/triage/store.py#L70-L88)) | PASS |
| Không sửa JSON/SARIF gốc | `cli.py:72` ghi nguyên byte; verify `test_06` phát hiện raw bị sửa | PASS |
| Không sửa nhãn OWASP cho khớp heuristic | `git diff 86636b9 -- v2/evaluation/post_report` rỗng | PASS |
| Không đoán nhãn theo tên lớp/testcase OWASP | `SeparateClassRequest` → `UNKNOWN` (heuristics.py:692); `getTheValue`/`ThingFactory` không còn sinh phán quyết | PASS cho đoán nhãn; còn quy tắc phụ thuộc định danh OWASP (`guess`/`switchTarget`, `doSomething`) (O5) |

Các test có cài cắm sai lệch và chứng minh bộ kiểm chứng bắt được: mới `test_02`, `test_04`, `test_05`, `test_15`, `test_16`; independent `test_01`–`test_06`, `test_14`; verify `test_05`–`test_11`.

---

## 8. Bảng test, lệnh, exit code và phạm vi

Môi trường: Windows, Python 3.13.3, thư mục `antigravity`, `PYTHONDONTWRITEBYTECODE=1`. Không có `pytest` trong môi trường nên dùng `unittest`.

| Lệnh | Exit | Kết quả | Loại / phạm vi |
|---|---:|---|---|
| `python -B -m unittest discover -s v2/triage/tests` | 0 | 126 test OK, 1 skip (symlink Windows) | synthetic + replay; trước vá 110 |
| `python -B -m unittest discover -s v2/triage/tests -p test_g0_v22_payload_contract.py` | 0 | 16 OK | synthetic + replay (payload, cổng `REFUTED`, JSON/SARIF) |
| `python -B -m unittest discover -s v2/triage/tests -p test_blind_spot_regressions.py` | 0 | 19 OK | synthetic |
| `python -B -m unittest discover -s v2/triage/tests -p test_human_review_negative_suite.py` | 0 | 16 OK | synthetic (SQLite tạm) |
| `python -B -m unittest discover -s v2/evaluation/tests` | 0 | 44 OK | synthetic + fixture |
| `python -B -m unittest v2.evaluation.audit_20261112.test_independent_audit` | 0 | 22 OK | replay trên tệp lịch sử trong Git |
| `python -B -m unittest discover -s v2/baseline/tests` | 0 | 27 OK | synthetic |
| `python -B -m unittest discover -s v2/demo/tests` | 1 | **NOT_RUN** — `ModuleNotFoundError: pytest` (cũng lỗi y hệt trên `03cd872`) | môi trường |
| `python -B v2/evaluation/audit_20261112/independent_audit.py --output-json <scratch ngoài repo>` | 1 | `overall_experimental_claims_status = FAIL` (đúng hợp đồng: luận điểm lịch sử v2.1 bị đánh FAIL) | replay |
| Probe trước/sau (`git archive 03cd872` vs working tree) | 0 / 0 | Bảng 4.4 và 6 | replay |
| `git diff --check` | 0 | sạch | — |

**Không có test runtime nào** (Ollama/Qwen thật, OpenGrep thật) trong lượt này.

**Dữ liệu ngoài phạm vi đọc:** 10 tệp `assessments.jsonl`, raw `opengrep.json`/`opengrep.sarif`, `scan-manifest.json` của các lượt chạy trên máy chủ không nằm trong hai workspace được cấp (`antigravity`, `_advisor_sources`). Ở thư mục cha có `evidence/` và `incoming/` nhưng không thuộc workspace được cấp nên **không đọc**. Do đó việc đối chiếu raw lịch sử từ phía Antigravity vẫn là `NOT_VERIFIED`; kết quả 9/9 cổng của JavisOS và bộ tái tính của Codex **không** được dùng làm bằng chứng độc lập trong tài liệu này.

---

## 9. Các lỗi còn mở và mức độ ảnh hưởng

| Mã | Mô tả | Mức | Ảnh hưởng an toàn |
|---|---|---|---|
| O1 | Verifier không gắn cờ khi mô hình trả `REFUTED` trong khi heuristic chứng minh luồng nhiễm bẩn trong cùng tệp (CE01–CE06, CE07b, CE08a, CE09) | Trung bình | Không tự đóng (vẫn `OPEN`, cần người xác nhận) nhưng chính là nơi phát sinh "lỗ hổng thật bị đề xuất loại nhầm"; phải đo ở G1 |
| O2 | `dead_branch_lines` thiếu nhánh `default:` không chạy được | Trung bình | Hướng giữ cảnh báo; làm yếu tiêu chí citation 9 |
| O3 | Văn bản prompt không được lưu (chỉ SHA-256) | Trung bình | Giảm khả năng kiểm toán thí nghiệm G1 |
| O4 | Chú thích trong servlet OWASP lộ gợi ý nhãn qua `snippets` | Cao (cho giá trị đánh giá) | Không phải lỗi an toàn; làm nhiễu mọi phép đo Qwen trên OWASP |
| O5 | Quy tắc phụ thuộc định danh OWASP: hằng `guess`/`switchTarget` (heuristics.py:55–56), regex `doSomething(`/`ThingFactory` (heuristics.py:1594–1597) chi phối Arm B | Thấp–Trung bình | Không đoán nhãn theo tên lớp, nhưng quá khớp benchmark |
| O6 | Liên quan ngữ nghĩa của citation không được tự động kiểm; chỉ cần một citation trong phạm vi | Thấp | Có `supports_security_claim_verified=False` và cổng người duyệt |
| O7 | `actor` là chuỗi tự do, không xác thực | Thấp | Ngoài phạm vi công cụ CLI cục bộ |
| O8 | `v2/demo/tests` chưa chạy được (thiếu `pytest`) | Thấp | Không kiểm được quality gate demo |
| O9 | Raw evidence máy chủ ngoài workspace được cấp | — | Phần đối chiếu raw lịch sử từ phía Antigravity: `NOT_VERIFIED` |
| O10 | CLI chưa có tùy chọn chọn `prompt_contract` | Trung bình | Chỉ chọn được ở mức record/API |
| O11 | Rule `httpservlet-path-traversal` báo sink tại `new File(...)`; heuristic chỉ xét trước sink nên chốt kiểm tra sau constructor (kể cả đúng chuẩn) bị bỏ qua | Thấp | Hướng giữ cảnh báo (giảm khả năng lọc FP, như `UserDao.java:63`) |
| O12 | Tín hiệu bậc hai còn lại trong `neutral_hints` (mục 4.5) | Thấp | `blind` không có |

Không còn lỗi đã biết nào khiến một cảnh báo bị **tự động** loại bỏ hoặc khiến verifier chấp nhận tuyên bố an toàn khi bằng chứng mã thiếu.

## 10. Những thay đổi cần chuyển sang G1/G3

**G1 (tích hợp thử nghiệm, đo lường):**
1. Lưu văn bản `messages` của từng request (ngoài repo, kèm SHA-256) trước khi chạy bất kỳ thí nghiệm Qwen nào (O3).
2. Thêm tùy chọn CLI chọn `blind` / `neutral_hints`; ghi `prompt_contract` + `PROMPT_VERSION` vào manifest khóa (`config_sha256`) (O10).
3. Thiết kế corpus/tiền xử lý cho O4: che chú thích trong bản sao prompt (với ánh xạ dòng để vẫn kiểm citation trên nguồn gốc) hoặc dùng corpus không có chú thích gợi ý; báo cáo song song có/không che.
4. Báo cáo riêng số `REFUTED` thô của mô hình trên các ca heuristic chứng minh nhiễm bẩn (O1); quyết định có thêm cờ xung đột hay không cần ý kiến giảng viên vì sẽ trộn heuristic vào kết quả cuối.
5. Chạy thực tế v2.2.1 với Qwen cục bộ trên tập khóa mới; chỉ khi đó mới có số liệu hiệu năng.
6. Codex rà soát `scan_receipt.py` khi hợp nhất; thử cổng JSON/SARIF trên biên nhận máy chủ thật.

**G3 (cải thiện phân tích):** hoàn thiện nhánh chết cho `switch/default` (O2); thay quy tắc phụ thuộc định danh OWASP bằng gập hằng tổng quát hoặc bỏ (O5); xét chốt kiểm tra đường dẫn giữa constructor `File` và thao tác I/O thật (O11); kiểm citation theo vai trò (nguồn/biến đổi/sink) thay vì chỉ phạm vi (O6).

## 11. Kết luận khả năng sẵn sàng tích hợp thử nghiệm

**`READY_FOR_G1`**

Căn cứ (chỉ trong phạm vi đã kiểm tra):
- Payload gửi Qwen được xây theo whitelist có kiểm tra kiểu, có cổng kiểm tra đệ quy trước request, và đã được kiểm tại ranh giới HTTP cho cả `blind` lẫn `neutral_hints`; hai đường rò rỉ của v2.2 (`dead_branch_lines`, trường lồng) đã được tái hiện và đóng.
- Verifier không còn chấp nhận `REFUTED` khi mã cần thiết vắng mặt (thiếu helper, vượt độ sâu gọi, thiếu phân tích hoàn chỉnh).
- Biên nhận quét không còn xác nhận nguồn khi JSON và SARIF của cùng lượt quét mâu thuẫn.
- Các bất biến không tự đóng, chỉ người xác nhận, đòi quét lại khi nguồn đổi, mã thoát đóng an toàn đều có kiểm thử và đạt.

Giới hạn bắt buộc đi kèm:
- Không có bằng chứng runtime; **không** có kết luận nào về độ chính xác của Qwen hay việc v2.2.1 tốt hơn v2.1 hoặc OpenGrep-only.
- Các mục G1 số 1–3 (lưu prompt, chọn hợp đồng qua CLI, xử lý chú thích OWASP) phải làm **trước** khi thu số liệu thí nghiệm G1.
- Đối chiếu raw evidence lịch sử từ phía Antigravity vẫn `NOT_VERIFIED` (O9). Quyết định nghiệm thu G0 thuộc giảng viên; tài liệu này không tự tuyên bố nghiệm thu.
