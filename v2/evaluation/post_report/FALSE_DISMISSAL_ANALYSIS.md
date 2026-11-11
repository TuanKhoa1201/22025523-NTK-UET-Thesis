# Phân Tích Rủi Ro Loại Nhầm Lỗ Hổng Thật (False Dismissal Analysis)

## 1. Định Nghĩa và Tầm Quan Trọng Trong Bảo Mật Phần Mềm

Trong bài toán hậu xử lý cảnh báo phân tích tĩnh (SAST post-processing/triage), lỗi nguy hiểm nhất không phải là giữ lại một cảnh báo giả (False Positive — chỉ làm tốn thêm thời gian rà soát), mà là **loại nhầm một lỗ hổng thật** (`False Dismissal` hay `erroneously_proposed_fp_on_tp`: cảnh báo có nhãn thực nghiệm `TRUE_POSITIVE` nhưng mô hình lại xếp vào Nhóm 2 `REFUTED` / `PROPOSED_FP`). Nếu một hệ thống tự động ẩn hoặc đóng các cảnh báo này mà không có cơ chế kiểm chứng bằng chứng và phê duyệt của con người, lỗ hổng bảo mật thực tế sẽ lọt qua quy trình kiểm tra.

---

## 2. Kết Quả Thực Nghiệm Về Tỷ Lệ Loại Nhầm TP (`erroneously_proposed_fp_on_tp`)

Trên cả hai tập dữ liệu có nhãn độc lập (`dev_set_16` và `heldout_set_40`):

| Tập dữ liệu & Nhánh thực nghiệm | Tổng số TP (`labeled_tp`) | Số TP bị mô hình trả về `REFUTED` thô (`raw_model_refuted_on_tp`) | Số TP bị đề xuất loại nhầm sau cổng kiểm chứng (`erroneously_proposed_fp_on_tp`) | Số TP được giữ an toàn (`KEEP_TP + REVIEW`) |
|---|---|---|---|---|
| **`dev_set_16` — Exp 1 (`v1.0_baseline`)** | `8` | `0/8 (0.0%)` | **`0/8 (0.0%)`** | `8/8 (100.0%)` (`4 KEEP_TP + 4 REVIEW`) |
| **`dev_set_16` — Exp 2 (`Arm B Heuristic`)** | `8` | `0/8 (0.0%)` | **`0/8 (0.0%)`** | `8/8 (100.0%)` (`4 KEEP_TP + 4 REVIEW`) |
| **`dev_set_16` — Exp 3 (`Arm D LLM Ablation`)** | `8` | `0/8 (0.0%)` | **`0/8 (0.0%)`** | `8/8 (100.0%)` (`7 KEEP_TP + 1 REVIEW`) |
| **`dev_set_16` — Exp 5 (`Arm C v2.1 Frozen`)** | `8` | `0/8 (0.0%)` | **`0/8 (0.0%)`** | `8/8 (100.0%)` (`8 KEEP_TP + 0 REVIEW`) |
| **`heldout_set_40` — Arm A (`OpenGrep Standalone`)** | `20` | `0/20 (0.0%)` | **`0/20 (0.0%)`** | `20/20 (100.0%)` (`20 KEEP`) |
| **`heldout_set_40` — Arm B (`--mode heuristic`)** | `20` | `0/20 (0.0%)` | **`0/20 (0.0%)`** | `20/20 (100.0%)` (`9 KEEP_TP + 11 REVIEW`) |
| **`heldout_set_40` — Arm D (`--mode llm` Ablation)** | `20` | `0/20 (0.0%)` | **`0/20 (0.0%)`** | `20/20 (100.0%)` (`17 KEEP_TP + 3 REVIEW`) |
| **`heldout_set_40` — Arm C (`--mode evidence+llm`)** | `20` | `0/20 (0.0%)` | **`0/20 (0.0%)`** | `20/20 (100.0%)` (`20 KEEP_TP + 0 REVIEW`) |

---

## 3. Ba Lớp Chốt Chặn Kỹ Thuật Ngăn Ngừa Loại Nhầm TP

Sở dĩ hệ thống đạt tỷ lệ `0/20 (0.0%)` TP bị đề xuất loại nhầm trên tập `heldout_set_40` (và `0/8` trên `dev_set_16`) là nhờ thiết kế bảo수 3 lớp:

1. **Lớp 1 — Tín hiệu tĩnh phân biệt rõ cấu trúc an toàn và cấu trúc bảo toàn dữ liệu bẩn (`v2/triage/heuristics.py`):**
   - Đối với cấu trúc `List` (`valuesList.remove(0)`): hàm `extract_evidence_signals` kiểm tra chính xác vị trí phần tử bẩn `param` được thêm vào danh sách và chỉ số `valuesList.get(idx)` sau khi gọi `remove(0)`. Nếu `param` nằm ở chỉ số `0` và bị xóa bởi `remove(0)` thì sinh tín hiệu `fp_signals` (`collection_safe_index_or_remove0`). Ngược lại, nếu phần tử hằng `"safe"` được thêm ở chỉ số `0`, `remove(0)` xóa `"safe"` và đẩy `param` về chỉ số `0` (như trong `BenchmarkTest00103.java` hoặc `BenchmarkTest01304.java`), hệ thống sinh tín hiệu `tp_signals` (`collection_tainted_index_preserved`).
   - Đối với `HashMap` (`map.put` / `map.get`): hệ thống đối chiếu khóa chứa `param` với khóa được lấy ra tại `map.get("key...")`. Chỉ khi hai khóa khác nhau mới sinh `fp_signals`; nếu trùng khóa chứa dữ liệu người dùng thì sinh `tp_signals`.
   - Đối với `CWE-89` (`PreparedStatement`): hệ thống không coi sự xuất hiện của từ khóa `prepareStatement` là an toàn một cách mù quáng, mà kiểm tra xem chuỗi SQL truyền vào có được nối chuỗi động (`+`) hay dùng tham số hóa `?` thực sự.

2. **Lớp 2 — Cổng kiểm chứng bằng chứng trích dẫn (`verify_citations` trong `v2/triage/ollama.py` và `_validate_evidence_grounding` trong `v2/evaluation/score_pilot.py`):**
   - Mọi kết luận `SUPPORTED` hoặc `REFUTED` bắt buộc phải kèm danh sách `citations` có đường dẫn tệp (`path`), dòng bắt đầu/kết thúc (`start_line`, `end_line`), và đoạn trích nguyên văn (`quote`) khớp 100% với tệp nguồn đã xác thực SHA-256.
   - Nếu mô hình trả về `REFUTED` nhưng trích dẫn sai số dòng, sửa đổi nội dung dòng code, hoặc trích dẫn dòng trống/comment, cổng `verify_citations` lập tức hạ cấp kết quả xuống `UNDETERMINED` (`citation_check = NOT_VERIFIED`) và chuyển vào diện bắt buộc rà soát (`REVIEW`).

3. **Lớp 3 — Hàng đợi xác nhận thủ công bất biến (`v2/triage/review.py`):**
   - Ngay cả khi một cảnh báo được xếp vào Nhóm 2 (`REFUTED` / `PROPOSED_FP`) với đầy đủ trích dẫn hợp lệ, trạng thái vận hành trong cơ sở dữ liệu SQLite vẫn là `OPEN` (`auto_dismissed = False`, `human_confirmed = False`). Cảnh báo chỉ chuyển sang `CONFIRMED_FALSE` khi kỹ sư bảo mật thực hiện lệnh `decide` kèm `--reviewer`, `--reason` và `--cite` hợp lệ.
