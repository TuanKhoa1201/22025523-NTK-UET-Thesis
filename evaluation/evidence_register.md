# Evidence register and current validation status

Status at 2026-10-28 repository initialization. Values here reflect the available handoff and observed local commands; no fresh evaluation run is implied.

| Item | Evidence source | Status / next verification |
|---|---|---|
| Frontend dependencies | `apps/22025523-thesis/package-lock.json` | npm install and Vite production build succeeded on HP laptop; dependency warnings need review |
| Backend API availability | `GET /api/health` on ADMIN-PC | Responded `status: OK`, API V2; not proof of full operation |
| OpenGrep/Java/model paths | API health readiness fields | Reported available; model `NOT_LOADED` during health check; confirm real inference |
| Ten-stage processing | backend code and prior telemetry archive | Re-run controlled scan; validate trace records for each stage |
| Findings persistence and pagination | backend result-index code | Stage-10 completion/index synchronization requires regression |
| EO06 training source | `scripts/eo06_main_train_eval_e2e_pipeline.py` | Available; inspect actual epoch evaluation artifacts before claiming numeric performance |
| VNext3.1 dataset | private reproduction archive and manifest | Metadata/digest and release provenance must be verified before publication |
| Checkpoint selection | private reproduction archive | Adapter selected by earlier handoff; check exact selection criteria and adapter hash |
| Scan evaluation results | private results archive | Select only anonymized aggregate summaries, with corpus provenance and method |
| SAST score correctness | `ntk_iris_shared.py` + `ntk_alert_verification.py` | Formula/source inspected; controlled comparison and sensitivity evaluation pending |

## Local evidence locations (never copy entire directories into Git)

- `NTK_HANDOFF_MANIFEST.json` (handoff source inventory)
- `NTK_HANDOFF_REPORT.md` (handoff context)
- `NTK_PRIVATE_REPRO_20261028.tar.gz` (research/model reproducibility artifacts; private)
- `NTK_PRIVATE_RESULTS_20261028.tar.gz` (scan and evaluation artifacts; private)
- `SHA256SUMS` (bundle integrity verification)

The handoff packages are stored outside the official production Git repository. Before adding any derived aggregate report, remove secrets, absolute personal paths, private source samples and unlicensed contents; record file provenance and transformations.
