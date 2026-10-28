# Known issues and release gates (initial audit)

- **Backend startup script:** `backend/ntk-production-v2/bin/start_ntk_backend.sh` passes `--host` and `--storage-dir`. The production Python CLI was observed to accept `--serve-http` and `--port`, using `NTK_STORAGE_DIR` as an environment variable. Repair and smoke-test the script before running it directly.
- **Stage-10 readiness:** A prior audit observed a transient `COMPLETED` state before scan JSON and SQLite findings indexing were ready. Treat this as a release-blocking consistency issue until reproduced and fixed.
- **Frontend results:** `apps/22025523-thesis/src/services/liveScan.js` reads whole-scan and findings endpoints. Verify pagination and totals against the backend's indexed summaries; do not assume the short response contains all findings.
- **HTTP authorization:** A public Tailscale Funnel route and permissive scan API without authentication are not appropriate for arbitrary external users. Restrict/access-control before public demo.
- **Frontend dependencies:** An October 28 install reported nine npm audit advisories (seven moderate, two high). Review targeted changes; do not auto-force upgrades.
- **Docs/packaging:** The backend handoff README refers to `backend/ntk-production-v2/docs/` (OpenAPI/contract documents), but these were not present in the 40-file public source import. Reconstruct from the actual implementation and verify against responses before declaring an official OpenAPI specification.

These are evidence-backed integration concerns, not proof that every item is still failing on the running ADMIN-PC.
