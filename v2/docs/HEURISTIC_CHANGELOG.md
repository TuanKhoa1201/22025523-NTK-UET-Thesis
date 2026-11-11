# NHẬT KÝ PHIÊN BẢN HEURISTIC & TÍN HIỆU DẪN XUẤT (`HEURISTIC_CHANGELOG`)

- **Giai đoạn:** Stage 3 — Tinh chỉnh Heuristic & Prompt cho `CWE-22` / `CWE-89` trên tập Development (`dev_set_16`, `n = 16`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Bản đầy đủ:** Xem tại [`v2/evaluation/post_report/HEURISTIC_CHANGELOG.md`](../evaluation/post_report/HEURISTIC_CHANGELOG.md).

---

## Tóm tắt

- **Phiên bản khóa cứng (Frozen):** `v2.1-cwe22-cwe89` (trong `v2/triage/heuristics.py`).
- **Tập tinh chỉnh:** Chỉ dùng `SmokeVulnSample.java`, `UserDao.java` và `dev_set_16` (`n = 16`); không chạm vào `heldout_set_40` (`n = 40`).
- **Độ an toàn:** `TP bị đề xuất loại nhầm = 0/8 (0.0%)` trên cả Nhánh B (`heuristic`) và Nhánh C (`evidence+llm`).
