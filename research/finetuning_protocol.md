# Local Qwen LoRA fine-tuning and model selection

## Current production configuration

- Base: `Qwen/Qwen2.5-Coder-0.5B-Instruct` (the base weights are not in Git).
- Adapter family: EO06 VNext3.1, production arm `eo06_vnext31_trackb_main`.
- Handoff-selected adapter: Epoch 3 best checkpoint; independently verify selection logs and SHA-256 before making a final benchmark claim.
- API-role labels: `source`, `sink`, `taint-propagator`, `none`.
- Source of truth for training/evaluation behavior: `backend/ntk-production-v2/scripts/eo06_main_train_eval_e2e_pipeline.py` and `ntk_iris_shared.py`.
- Deployment: local model inference on ADMIN-PC; no cloud LLM is required for the pipeline.

## Required experiment record

For each arm (base / LoRA epoch / ablation): capture exact base revision, tokenizer revision, adapter checksum, dataset manifest hash, training arguments (LoRA rank, alpha, modules, epochs, seed, LR), environment and GPU, prompt and loss masking, validation selection gate, decoding settings, runtime and epoch metrics. **Do not invent missing hyperparameter values or accuracy figures.**

## Required results

- Independent train/dev/test sample and family counts.
- Per-class precision/recall/F1, macro F1, confusion matrix, abstention/invalid JSON rate.
- Base vs tuned comparison on identical locked examples and prompts.
- Error analysis for sinks, safe patterns, cross-CWE confusion and out-of-distribution APIs.
- Checkpoint selection that does not use the test set as a tuning signal.

## Offline evidence

The `NTK_PRIVATE_REPRO_20261028.tar.gz` and `NTK_PRIVATE_RESULTS_20261028.tar.gz` migration artifacts were retained separately on the development laptop. Their internal manifests, evaluation summaries and hashes require inspection before selecting public evidence files. **Neither archive should be committed wholesale.**

## Historical separation

The older repository's `docs/finetuning/FINAL_MODEL_SELECTION_DECISION.md` reports a previous **1.5B** model. Its results must not be presented as current **0.5B VNext3.1** performance.

## Biên bản kiểm tra ngày 05/11/2026

Manifest backend xác nhận Track B 781 bản ghi, tập Development 166, checkpoint được chọn ở epoch 3 của mô hình `Qwen2.5-Coder-0.5B-Instruct`. Receipt lưu `dev_macro_f1=0.9609474124056009`, `holdout_macro_f1=0.9854132091178436`, `holdout_ece=0.01552490234375`, `holdout_json_valid_rate=1.0` và SHA-256 adapter `176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`.

Đây là số liệu từ biên bản lịch sử đã đọc qua API, **không phải lần đánh giá lại độc lập**. Chỉ số API role classification không thể thay thế kiểm thử end-to-end SAST. Khi chuyển checkpoint sang máy mới, phải đối chiếu checksum và chạy kiểm thử với cùng điều kiện.
