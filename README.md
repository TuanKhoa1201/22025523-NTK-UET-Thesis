# 22025523 - NTK Java Vulnerability Detection Platform

Graduation thesis at VNU University of Engineering and Technology.

Thesis: Phat trien cong cu phat hien lo hong ma nguon ket hop phan tich tinh nguon mo va mo hinh ngon ngu lon.

## Architecture

- OpenGrep OSS: Java vulnerability candidate detection.
- OpenJDK 17 JavacTask AST: program and dataflow analysis.
- IRIS-inspired semantic analysis.
- Locally fine-tuned Qwen2.5-Coder-0.5B-Instruct LoRA.
- Heuristic SAST Evidence Fusion V1.2 and alert triage.
- React/Vite dashboard with 10-stage visualization.

## Supported CWE categories

CWE-022, CWE-078, CWE-079 and CWE-089.

Source coverage does not imply coverage of all vulnerabilities.
SAST scores are heuristic priorities, not CVSS or calibrated probabilities.

## Repository structure

- apps/22025523-thesis/ - React/Vite frontend.
- backend/ntk-production-v2/ - Python API, OpenGrep, AST and LoRA integration.

## Frontend commands

cd apps/22025523-thesis
npm ci
npm run dev

## Development status

Frontend production build and remote backend health check passed.
Full browser-based E2E regression testing remains in progress.
Startup configuration and scan-result readiness issues are under repair.

## Research history

https://github.com/TuanKhoa1201/NTK-UET-Thesis

Frontend migration commit: 804d520
Backend migration commit: a02edc9

The historical repository includes earlier IRIS and CodeQL research.
Current production code is organized separately in this repository.

## Attribution and limitations

See THIRD_PARTY_NOTICES.md and backend/ntk-production-v2/LICENSE.
The project is an academic prototype. Findings require verification.
Private datasets, scan archives and model weights are not bundled.
