# NTK thesis documentation (production line)

This directory documents the **OpenGrep OSS + OpenJDK 17 JavacTask AST/IRIS-inspired analysis + Qwen2.5-Coder-0.5B-Instruct LoRA** production backend and its React/Vite web frontend.

- [Architecture and processing stages](architecture.md)
- [API and demonstration guide](api_and_demo.md)
- [Requirements-to-evidence matrix](traceability_matrix.md)
- [Known integration issues](known_issues.md)
- [Research methods](../research/README.md)
- [Evaluation and evidence](../evaluation/README.md)

**Evidence policy:** A source file, a successful build, an API health check, a completed scan, and a peer-reviewed benchmark are **different kinds of evidence**. Do not describe one as another. Numerical accuracy, false-positive and false-negative claims require locked gold labels and saved predictions.

**Current vs historical:** Historical CodeQL / Qwen-1.5B / scoring-V2.x reports from the older repository are prior research; they are not measurements of this production release.
