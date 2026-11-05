# EO06 / VNext3.1 dataset provenance and isolation

## Current task

Model input is a Java API/callee context and target CWE. The supervised output is one of `source`, `sink`, `taint-propagator`, `none`, with strict structured-response rules. This is **API-role classification**, not direct binary true-vulnerability prediction.

The production training source `backend/ntk-production-v2/scripts/eo06_main_train_eval_e2e_pipeline.py` contains references to **Track B 781 examples** and **Dev 166 examples** for a four-class role-balanced experiment. The current service also exposes a restricted dataset-catalog implementation with manifest schema `NTK_VERIFIED_DATASET_MANIFEST_V1` and release `VNEXT_3_1_DUAL_TRACK`.

These counts are code/documentation evidence. They do **not** by themselves verify exact contents, provenance, split independence, or final model performance. Cross-check against the privately retained original VNext3.1 manifest and checksums.

## Required audit fields for each dataset release

| Field | Required evidence | Status |
|---|---|---|
| Origin and license | Upstream source names, exact snapshots, usage rights | Verify against offline manifest |
| Label criteria | Definition of all four roles and sink argument mapping | Shared contract in `ntk_iris_shared.py`; assess review protocol |
| Split keys | Family, class, method and prompt-example isolation | Implementation exists; validate exported split manifest |
| Weak/silver labels | Annotation confidence and disagreement/quarantine | Keep separately from human gold |
| Holdouts | Lock dates, sampling rules and duplicate checks | Verify private holdout manifests |
| Integrity | SHA-256 per release and transformation provenance | Record verified hashes only |

## What must not be published unreviewed

Raw private training examples, licensed corpora, model weights, full scanned third-party projects, personal file paths, API credentials and complete raw API prompts. Where publication is disallowed, publish **metadata, hashes, aggregate metrics, scripts and reproducibility contracts**, not private content.

## Historical warning

The older public repository recorded **Dataset V3 family leakage and in-context prompt contamination**. The historical audit is relevant evidence of methodology repair, but do not describe those old V3 defects as automatically persisting in VNext3.1. Conversely, do not assert VNext3.1 is leak-free without verifying its split manifest.

## Đối chiếu dataset trên laptop ngày 05/11/2026

Bốn file JSONL đã được kiểm tra lại bằng SHA-256 và số dòng. Kết quả khớp manifest: Track A 275, Track B 781, Development 166, Quarantine 137. Track A nằm trong Track B; tổng số bản ghi duy nhất là 1.084. API trả manifest hợp lệ và xuất CSV, JSONL, XLSX thành công.

Mã kiểm tra không cần mở dữ liệu: `python3 scripts/verify-private-artifacts.py --dataset-dir /duong/dan/tren/wsl`. Việc này chỉ xác nhận tính nguyên vẹn theo checksum đã công bố, không thay thế đánh giá độc lập chất lượng nhãn và split. Dataset riêng không đưa lên GitHub.
