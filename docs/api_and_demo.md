# API, local demo and reproducibility

## Deployment roles

Laptop HP: React/Vite frontend, Git repository and browser. ADMIN-PC: Python API, OpenGrep, OpenJDK, locally stored Qwen base model and LoRA adapter, GPU execution and persistence. The frontend does not require GPU on the laptop.

## Frontend

```bash
cd apps/22025523-thesis
npm ci
npm run dev
```

On the laptop create an **ignored** `apps/22025523-thesis/.env.local` with `VITE_API_BASE_URL=<authorized backend URL>`. Do not commit that file. The URL becomes visible in built browser JavaScript; use authenticated/restricted network access. Avoid putting bearer tokens in frontend build variables. Do not run `npm audit fix --force` without reviewing the changes.

## Documented endpoints (verify current service before release)

| Endpoint | Intended purpose |
|---|---|
| `GET /api/health` | Report service, model/device readiness and supported endpoints |
| `POST /api/scan-jobs` | Launch an async scan |
| `GET /api/scan-jobs/{job_id}` | Query job and progress |
| `GET /api/scans/{scan_id}/pipeline-trace` | Inspect actual stage telemetry |
| `GET /api/scans/{scan_id}/summary` | Result summary |
| `GET /api/scans/{scan_id}/findings/page` | Paginated findings |
| `GET /api/datasets/manifest` | Expose approved dataset metadata |

Use the backend's current `/api/health` output as the authoritative endpoint list. Avoid assuming every legacy frontend endpoint and data shape matches.

## E2E demonstration acceptance sequence

1. Verify that the API health status is OK and OpenGrep, Java, adapter and base model paths are available.
2. Start React/Vite; confirm the browser reports backend connected (a successful PowerShell health call **alone** does not establish working browser CORS).
3. Scan the bundled *mini-vulnerable-java* fixture or another controlled small Java project.
4. Observe all ten stages from real backend telemetry, not animation-only timers.
5. Wait for persistence and SQLite indexing before displaying `COMPLETED` as ready-to-view.
6. Compare summary counts against **all paginated findings**, including `REPORT`, `REVIEW`, and `SUPPRESS` states.
7. Confirm each finding links to trace, AST evidence, LoRA role classification and scoring breakdown.
8. Repeat after refreshing the page; check persisted history and export output.

## Current verified boundary

On 2026-10-28, the frontend production build succeeded and a remote backend `/api/health` returned `OK`. That does **not yet prove** full browser-based E2E scanning and result integrity. These require the tests above.
