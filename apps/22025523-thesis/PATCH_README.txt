NTK FRONTEND PATCH: IRIS FLOW PROOF STATES

This patch replaces scanner severity presentation with backend IRIS flow proof states.

Changed files:
- src/services/findingPresentation.js
- src/services/scanData.js
- src/services/scanOverview.js
- src/components/results/OverviewCharts.jsx
- src/components/results/FindingsExplorer.jsx
- src/pages/Results.jsx
- src/pages/LiveResults.jsx
- src/styles/results-dashboard.css

Behavior:
- The whole-scan severity chart is replaced by a chart for PROVEN_TAINT, PROVEN_SAFE, and UNKNOWN.
- The findings table column and filter use IRIS proof state instead of scanner severity.
- Finding detail replaces the scanner severity label with the IRIS proof state and an explanation.
- Missing or contradictory proof evidence is displayed as UNKNOWN. The frontend does not infer PROVEN_SAFE from a missing taint path.
- Backend scoring, scanner rules, Qwen inference, and triage decisions are not changed.

Apply:
Extract this ZIP into the ntk-frontend folder and allow the 8 files under src to be overwritten.

Validation:
- 9 proof-state helper cases passed.
- Node syntax checks passed for the modified non-JSX service modules.
- A full Vite production build was not run because dependency installation did not complete in the current environment.
