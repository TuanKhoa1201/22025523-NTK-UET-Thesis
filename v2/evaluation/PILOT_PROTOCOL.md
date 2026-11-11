# NTK Thesis V2 — Giao thức Đánh giá Thực nghiệm M4/M5 (Pilot Protocol)

> [!IMPORTANT]
> Tài liệu này quy định giao thức thực nghiệm khóa cứng (Locked Evaluation Protocol) cho **Milestone M4 (Locked Evaluation)** và **Milestone M5 (Benchmark Results)** của NTK Thesis V2. Mọi số liệu trong mẫu bảng dưới đây đang ở trạng thái `PENDING REAL RUN` — tuyệt đối không điền số liệu giả lập (mock/fixture) làm kết quả thực nghiệm.

---

## 1. Mục tiêu Thực nghiệm & Phân tách Hai Bài toán Đánh giá

Theo [`v2/README.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/README.md), [`v2/evaluation/README.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/README.md) và [`v2/docs/TASK_BOARD.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/docs/TASK_BOARD.md):

1. **Mục tiêu cốt lõi**: Đánh giá khách quan hiệu quả và rủi ro của tầng hậu xử lý cục bộ **OpenGrep + Local Qwen (qua Ollama)** so với **OpenGrep đơn lẻ (Standalone Baseline)** trên **cùng một tệp kết quả quét OpenGrep JSON khóa cứng** và **cùng một bộ nhãn cảnh báo độc lập** (quy mô Pilot: **30–60 cảnh báo**).
2. **Phân biệt rõ hai mức đánh giá (bắt buộc báo cáo tách biệt)**:
   - **Đánh giá phân loại trên từng cảnh báo (Per-Alert Triage Evaluation — trọng tâm M4/M5)**: Đầu vào là tập $N$ cảnh báo cố định do OpenGrep sinh ra. Đánh giá khả năng của Qwen trong việc đề xuất lọc cảnh báo giả (`PROPOSED_FP`), giữ lại cảnh báo thật (`KEEP_TP`), hoặc chuyển tiếp sang kiểm tra thủ công (`REVIEW` / `UNDETERMINED`) mà **không tự động ẩn/xóa bất kỳ cảnh báo nào khi chưa có xác nhận của con người (Human-in-the-loop)**.
   - **Đánh giá phát hiện trên toàn bộ tập test-case benchmark (Full Benchmark Test-Case Detection)**: Đánh giá độ phủ phát hiện (Recall / False Negative của chính bộ luật OpenGrep trên tổng số test-case lỗ hổng của tập dữ liệu gốc). Tầng triage chỉ lọc hậu kiểm trên các cảnh báo đã được OpenGrep phát hiện, không thể phục hồi các lỗ hổng mà OpenGrep bỏ sót (False Negatives của trình quét tĩnh).

---

## 2. Thiết kế Hai Nhánh So sánh (Paired Comparison Arms)

Hai nhánh thực nghiệm phải chạy trên **cùng một bản chụp mã nguồn (khóa `source_sha256`)** và **cùng một tệp đầu ra OpenGrep JSON**:

| Tiêu chí | Nhánh A: OpenGrep Đơn lẻ (Baseline) | Nhánh B: OpenGrep + Local Qwen Triage |
|---|---|---|
| **Trình quét tĩnh** | Bản thực thi `opengrep` thật (chứng minh ở M1), bộ rule cố định | Dùng lại **chính xác tệp JSON đầu ra của Nhánh A** (không quét lại với rule khác) |
| **Mô hình suy luận** | Không sử dụng LLM | Local Ollama (`qwen3.5:9b-q4_K_M`, hoặc `4B` nếu công bố rõ theo [`MODEL_POLICY.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/docs/MODEL_POLICY.md)), `context=4096`, JSON có cấu trúc |
| **Cơ chế quyết định** | Mọi cảnh báo OpenGrep đều đòi hỏi kỹ sư xem xét thủ công | Phân loại 3 trạng thái (`TP`, `FP`, `REVIEW`/`UNDETERMINED`) + kiểm chứng trích dẫn dòng mã + cổng phê duyệt của con người |
| **Quy tắc an toàn** | $0$ cảnh báo thật bị lọc nhầm bởi LLM | Cảnh báo thiếu trích dẫn dòng, lệch `source_sha256`, lệch CWE, hoặc lỗi JSON bắt buộc chuyển về `REVIEW` |

---

## 3. Phân tầng Ưu tiên CWE (Java Scope)

Tập cảnh báo Pilot (30–60 cảnh báo) tập trung vào mã nguồn Java và được chia thành 2 tầng báo cáo:

- **Tầng Ưu tiên 1 — Priority Tier 1 (Bắt buộc đầy đủ TP/FP/Ambiguous, chiếm $\ge 70\%$ mẫu Pilot)**:
  - **`CWE-22` (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal)**: Kiểm tra luồng dữ liệu từ HTTP request / tham số đầu vào đến `File`, `Paths.get`, `FileInputStream` và tính hiệu lực của bước chuẩn hóa đường dẫn (`normalize()`, `toRealPath()`, kiểm tra tiền tố thư mục gốc).
  - **`CWE-89` (Improper Neutralization of Special Elements used in an SQL Command / SQL Injection)**: Kiểm tra phép nối chuỗi SQL động trong `Statement.executeQuery/executeUpdate`, `createQuery`, so với truy vấn tham số hóa (`PreparedStatement` với `?` và `setString/setInt`) hoặc kiểm tra kiểu/danh sách trắng chặt chẽ.
- **Tầng Báo cáo Riêng / Smoke Test — Secondary Tier 2 (Chiếm $20\text{–}30\%$ mẫu Pilot)**:
  - **`CWE-78` (OS Command Injection)**: Luồng dữ liệu vào `Runtime.exec`, `ProcessBuilder`.
  - **`CWE-79` (Cross-Site Scripting — XSS)**: Phản xạ dữ liệu đầu vào ra `HttpServletResponse` / JSP / template mà thiếu mã hóa ngữ cảnh HTML/JS.

Mọi bảng kết quả phải hiển thị:
1. Tổng hợp toàn bộ (`ALL`),
2. Tổng hợp riêng nhóm ưu tiên (`PRIORITY: CWE-22, CWE-89`),
3. Tổng hợp riêng nhóm phụ (`SECONDARY: CWE-78, CWE-79`),
4. Chi tiết từng CWE (`CWE-22`, `CWE-89`, `CWE-78`, `CWE-79`).

---

## 4. Thiết kế Dữ liệu Nhãn (Ground-Truth Schema) & Quy tắc Ghép nối

### 4.1. Định dạng Nhãn Khóa cứng (`labels.json`)

Bộ nhãn phải được gán độc lập và khóa cứng (kèm mã băm SHA-256 của tệp nhãn) **trước khi** chạy đánh giá M5 (không tinh chỉnh prompt/tham số trên tập test M4/M5):

```json
{
  "dataset_id": "ntk-v2-pilot-locked-v1",
  "locked_at": "YYYY-MM-DDTHH:MM:SSZ",
  "labels": [
    {
      "alert_id": "repoA:src/main/java/com/example/UserDao.java:55:58:CWE-89:java.sql.sqli",
      "file_path": "src/main/java/com/example/UserDao.java",
      "start_line": 55,
      "end_line": 58,
      "rule_id": "java.sql.sqli",
      "cwe": "CWE-89",
      "source_sha256": "<hex-sha256-of-java-source-file>",
      "ground_truth": "FALSE_POSITIVE",
      "annotator_rationale": "Line 56 uses PreparedStatement with '?' placeholder and line 57 binds userId via ps.setString(1, userId).",
      "annotated_by": "independent-reviewer"
    }
  ]
}
```

Giá trị hợp lệ của `ground_truth`:
- `"TRUE_POSITIVE"`: Có đường truyền dữ liệu (source $\to$ propagation $\to$ sink) thực sự khai thác được hoặc thiếu cơ chế bảo vệ hiệu quả.
- `"FALSE_POSITIVE"`: Mã chết, hằng số tĩnh, hoặc có sanitizer / kiểm tra biên / truy vấn tham số hóa triệt tiêu hoàn toàn lỗ hổng của đúng CWE đang xét.
- `"AMBIGUOUS"`: Mã nguồn thiếu ngữ cảnh liên tệp (ví dụ: hàm sanitizer nằm trong thư viện ngoài không có mã nguồn).

### 4.2. Phương pháp Ghép Cảnh báo với Mã nguồn và CWE

1. **Khóa định danh chuẩn (`alert_id`)**:
   - Ghép chính xác theo `alert_id` định danh duy nhất hoặc khóa chuẩn hóa `"{normalized_file_path}:{start_line}:{end_line}:{normalized_cwe}:{rule_id}"`.
   - Đường dẫn tệp luôn chuẩn hóa dấu phân cách `\` thành `/`.
   - Mã CWE luôn chuẩn hóa về dạng `CWE-<số>` (ví dụ: `"CWE-89: SQL Injection"` $\to$ `"CWE-89"`).
2. **Kiểm tra khớp CWE (`CWE Join Integrity`)**:
   - Cảnh báo OpenGrep, nhãn `ground_truth` và kết quả `triage` phải có cùng mã CWE đã chuẩn hóa.
   - **Sai CWE (`cwe_mismatch`)**: Nếu nhãn hoặc đầu ra của LLM phân tích sai CWE (ví dụ: cảnh báo `CWE-22` nhưng LLM lập luận về mã hóa HTML của `CWE-79`), bộ chấm điểm [`score_pilot.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/score_pilot.py) sẽ ghi nhận lỗi vào `anomalies.cwe_mismatches`, **từ chối tính là đề xuất lọc FP hợp lệ**, và ép trạng thái sang `REVIEW`.
3. **Kiểm tra toàn vẹn mã nguồn (`source_sha256`) và Trích dẫn dòng (`cited_lines`)**:
   - Nếu `source_sha256` lúc triage khác với `source_sha256` trong nhãn/quét tĩnh $\to$ ghi nhận `sha256_mismatches` và ép về `REVIEW`.
   - Mọi kết luận `FP` (`PROPOSED_FP`) từ Qwen bắt buộc có `cited_lines` (danh sách số dòng nguyên dương nằm trong vùng ngữ cảnh `[context_start_line, context_end_line]`) và `rationale` giải thích rõ lý do an toàn. Nếu thiếu $\to$ ghi nhận `ungrounded_fp_overrides` và ép về `REVIEW`.

### 4.3. Xử lý Trùng lặp, Thiếu nhãn, Ca mơ hồ và Lỗi JSON

| Tình huống biên | Quy tắc xử lý trong [`score_pilot.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/score_pilot.py) |
|---|---|
| **Trùng lặp ID (`duplicate_alert_ids`, `duplicate_label_ids`, `duplicate_triage_ids`)** | Giữ bản ghi đầu tiên theo thứ tự xuất hiện để không đếm trùng mẫu số/tử số; ghi toàn bộ ID trùng vào `anomalies.duplicate_*_ids`. |
| **Thiếu nhãn (`unlabeled_alerts`)** | Không loại bỏ âm thầm và không gộp vào TP hay FP; đếm riêng vào `unlabeled_alerts`, đưa vào `anomalies.unlabeled_alert_ids`, và định tuyến kết quả sang `REVIEW`. |
| **Ca mơ hồ (`AMBIGUOUS`)** | Đếm riêng trong `labeled_ambiguous`. Dù LLM trả về `TP` hay `FP`, ca `AMBIGUOUS` vẫn được định tuyến vào `needs_review_on_ambiguous` và không được tính là lọc đúng FP. |
| **JSON lỗi / Đầu ra LLM hỏng (`malformed_triage_records`)** | Bắt ngoại lệ `JSONDecodeError` trên từng dòng JSONL hoặc trường `raw_llm_json`; ghi vào `anomalies.malformed_triage_records`, tính là chưa phủ triage (`triage_covered = False`), và tự động chuyển về `REVIEW`. |
| **Mẫu số bằng 0 (`denominator == 0`)** | Không chia cho 0; trả về `rate = null` trong JSON và hiển thị `"0/0 (N/A)"` trong bảng Markdown. |

---

## 5. Công thức Chỉ số Đánh giá (Metrics Specification)

Với mỗi tập con CWE (hoặc toàn cục):
- $N_{\text{total}}$: Tổng số cảnh báo OpenGrep duy nhất.
- $N_{\text{TP}}$: Số cảnh báo có nhãn `TRUE_POSITIVE` hợp lệ.
- $N_{\text{FP}}$: Số cảnh báo có nhãn `FALSE_POSITIVE` hợp lệ.
- $N_{\text{AMB}}$: Số cảnh báo có nhãn `AMBIGUOUS`.
- $N_{\text{unlabeled}}$: Số cảnh báo thiếu nhãn hoặc lệch CWE/đường dẫn với nhãn.

Các chỉ số bắt buộc báo cáo kèm **tử số và mẫu số (`numerator / denominator`)**:

1. **Tỷ lệ Cảnh báo Giả được Đề xuất Loại đúng (Proposed FP Removal Rate)**:
   $$\text{Proposed FP Removal Rate} = \frac{\text{FP}_{\text{proposed\_drop}}}{N_{\text{FP}}}$$
   Trong đó $\text{FP}_{\text{proposed\_drop}}$ là số cảnh báo có `ground_truth == FALSE_POSITIVE` và `effective_verdict == PROPOSED_FP` (đã vượt qua mọi kiểm tra trích dẫn dòng, CWE, SHA-256).

2. **Tỷ lệ Cảnh báo Thật bị Đề xuất Loại nhầm (Erroneously Proposed TP Removal Rate — Chỉ số An toàn Quan trọng nhất)**:
   $$\text{Erroneous TP Removal Rate} = \frac{\text{TP}_{\text{proposed\_drop}}}{N_{\text{TP}}}$$
   Trong đó $\text{TP}_{\text{proposed\_drop}}$ là số cảnh báo có `ground_truth == TRUE_POSITIVE` nhưng bị mô hình đề xuất là `PROPOSED_FP`. **Bắt buộc luôn ghi rõ cả tử số và mẫu số** (ví dụ: `1/15 (6.7%)`).

3. **Tỷ lệ Cần Xem thêm / Chuyển Con người (`REVIEW` Escalation Rate)**:
   $$\text{Review Escalation Rate} = \frac{N_{\text{review}}}{N_{\text{total}}}$$
   Bao gồm các ca mô hình trả về `REVIEW`/`UNDETERMINED`, các ca `AMBIGUOUS`/`UNLABELED`, và các ca bị cơ chế fail-safe ép về `REVIEW`.

4. **Độ phủ Triage hợp lệ (Triage Coverage)**:
   $$\text{Triage Coverage} = \frac{N_{\text{valid\_triage}}}{N_{\text{total}}}$$
   Tỷ lệ cảnh báo nhận được phản hồi JSON hợp lệ với nhãn quyết định hợp chuẩn từ mô hình.

5. **Thời gian Xử lý (Processing Latency)**:
   - Thời gian quét tĩnh OpenGrep (`scan_time_ms`).
   - Thống kê độ trễ suy luận của Qwen trên từng cảnh báo (`total_ms`, `mean_ms`, `p50_ms` / trung vị, `p95_ms`, `max_ms`).

---

## 6. Lệnh Chạy Công cụ Khóa Tập Dữ liệu (`validate_pilot_lock.py`) & Chấm điểm (`score_pilot.py`)

### 6.1. Kiểm tra và Tạo Manifest Khóa Cứng M4 (`validate_pilot_lock.py`)
```powershell
python v2/evaluation/validate_pilot_lock.py `
  --opengrep <path-to-locked-opengrep.json> `
  --labels <path-to-locked-labels.json> `
  --min-alerts 30 --max-alerts 60 `
  --write-lock <path-to-lock-manifest.json>
```

### 6.2. Chấm điểm Thực nghiệm M5 (`score_pilot.py`)
```powershell
python v2/evaluation/score_pilot.py `
  --opengrep <path-to-locked-opengrep.json> `
  --labels <path-to-locked-labels.json> `
  --triage <path-to-qwen-triage.jsonl> `
  --scan-time-ms <opengrep-time-ms> `
  --output-json <path-to-eval-report.json> `
  --output-md <path-to-eval-report.md>
```

Nếu chạy kiểm thử trên dữ liệu giả lập (Test Fixture), bắt buộc thêm cờ `--fixture` để đóng dấu cảnh báo `SYNTHETIC TEST FIXTURE OUTPUT`.

---

## 7. Mẫu Bảng Kết quả (Blank Templates — Điền sau khi chạy thật ở M5)

> [!NOTE]
> Các bảng dưới đây là **mẫu trống (`PENDING REAL RUN`)** dành cho thực nghiệm M5 sau khi hoàn tất M1 (OpenGrep thật), M2 (Ollama/Qwen thật) và M4 (khóa tập nhãn 30–60 cảnh báo).

### 7.1. Bảng So sánh Tổng thể: OpenGrep Đơn lẻ vs. OpenGrep + Local Qwen

| Chỉ số thực nghiệm | Nhánh A: OpenGrep Đơn lẻ | Nhánh B: OpenGrep + Qwen (`qwen3.5:9b-q4_K_M`) | Ghi chú / Bằng chứng |
|---|---|---|---|
| **Tổng số cảnh báo khóa cứng ($N_{\text{total}}$)** | `PENDING REAL RUN` | `PENDING REAL RUN` | Cùng tệp JSON đầu vào |
| **Số cảnh báo thật ($N_{\text{TP}}$) / giả ($N_{\text{FP}}$) / mơ hồ ($N_{\text{AMB}}$)** | `PENDING REAL RUN` | `PENDING REAL RUN` | Khóa SHA-256 bộ nhãn |
| **Cảnh báo giả được đề xuất loại đúng ($\text{FP}_{\text{proposed\_drop}} / N_{\text{FP}}$)** | `0 / N_FP (0.0%)` | `PENDING REAL RUN` | Cần xác nhận của con người trước khi ẩn |
| **Cảnh báo thật bị đề xuất loại nhầm ($\text{TP}_{\text{proposed\_drop}} / N_{\text{TP}}$)** | `0 / N_TP (0.0%)` | `PENDING REAL RUN` | Ghi rõ tử số / mẫu số |
| **Số cảnh báo chuyển `REVIEW` ($N_{\text{review}} / N_{\text{total}}$)** | `N_total / N_total (100.0%)` | `PENDING REAL RUN` | Gồm cả fail-safe override |
| **Độ phủ phản hồi JSON hợp lệ (`Triage Coverage`)** | `N/A` | `PENDING REAL RUN` | Tính trên $N_{\text{total}}$ |
| **Thời gian xử lý (`Total / Mean / P50 / P95 ms`)** | `PENDING REAL RUN` | `PENDING REAL RUN` | Ghi rõ cấu hình GPU/VRAM/CPU |

### 7.2. Bảng Phân rã Theo CWE & Tầng Ưu tiên (Per-CWE Breakdown)

| Nhóm / CWE | Phân tầng | Tổng cảnh báo | Nhãn TP | Nhãn FP | Nhãn Ambiguous | Đề xuất loại đúng FP (`k / N_FP`) | Đề xuất loại nhầm TP (`k / N_TP`) | Cần xem thêm (`REVIEW`) | Độ phủ Triage | Độ trễ `Mean / P95` (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **`ALL`** | OVERALL | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| **`PRIORITY (CWE-22, CWE-89)`** | PRIORITY_TIER_1 | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-22` (Path Traversal)** | PRIORITY_TIER_1 | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-89` (SQL Injection)** | PRIORITY_TIER_1 | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| **`SECONDARY (CWE-78, CWE-79)`** | SECONDARY_TIER_2 | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-78` (Command Injection)** | SECONDARY_TIER_2 | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| **`CWE-79` (Cross-Site Scripting)** | SECONDARY_TIER_2 | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |

---

## 8. Mẫu Case Study Chi tiết (Điền sau khi chạy thật)

Sử dụng mẫu dưới đây cho ít nhất **4 case study thực tế** trong báo cáo M5/M6:
1. Một ca **True FP** (`CWE-22` hoặc `CWE-89`) được Qwen đề xuất loại đúng với trích dẫn dòng chính xác.
2. Một ca **True TP** (`CWE-22` hoặc `CWE-89`) được Qwen giữ lại đúng (`KEEP_TP`).
3. Một ca **Erroneously Proposed TP Removal** (nếu xảy ra: cảnh báo thật bị đề xuất loại nhầm — phân tích nguyên nhân gốc rễ) hoặc một ca **Sanitizer phức tạp**.
4. Một ca **Fail-safe `REVIEW`** (do thiếu ngữ cảnh liên tệp, lệch trích dẫn dòng, hoặc JSON lỗi được cổng an toàn chặn lại).

```markdown
### Case Study #[Số]: [Tiêu đề ngắn — CWE-XX — Loại ca]

- **Mã cảnh báo (`alert_id`)**: `<PENDING REAL RUN>`
- **Tệp nguồn & Dòng mã**: `<path/to/File.java#L start - L end>` (`source_sha256`: `<sha256>`)
- **Rule OpenGrep (`rule_id`)**: `<rule_id>` — **CWE**: `CWE-XX`
- **Nhãn Ground Truth**: `TRUE_POSITIVE | FALSE_POSITIVE | AMBIGUOUS` (Người gán nhãn: `<id>`)
- **Bằng chứng Mã nguồn (Source / Propagation / Sink hoặc Sanitizer)**:
  - **Source**: Dòng `L...` (`<mô tả nguồn dữ liệu>`)
  - **Propagation / Sanitizer**: Dòng `L...` (`<mô tả bước biến đổi hoặc kiểm tra bảo vệ>`)
  - **Sink**: Dòng `L...` (`<hàm nhạy cảm>`)
- **Đầu ra của Local Qwen (`model_id`, `latency_ms`)**:
  - **Verdict gốc**: `TP | FP | REVIEW`
  - **Trích dẫn dòng (`cited_lines`)**: `[...]`
  - **Lập luận của mô hình (`rationale`)**: `"..."`
- **Kiểm tra Hậu kiểm & Cổng An toàn (`score_pilot.py`)**:
  - **Khớp CWE & SHA-256**: `PASS | FAIL`
  - **Kiểm chứng dòng trích dẫn**: `PASS | FAIL`
  - **Quyết định sau cùng (`effective_verdict`)**: `KEEP_TP | PROPOSED_FP | REVIEW`
  - **Trạng thái xác nhận của con người**: `PENDING_HUMAN_CONFIRMATION`
- **Nhận xét Kỹ thuật**: `<Phân tích vì sao mô hình đúng/sai và vai trò của cổng kiểm chứng>`
```
