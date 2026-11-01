# Local thesis demo

From this Windows worktree, start or check the existing demo:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-demo.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-demo.ps1 -CheckOnly
```

The execution policy option applies only to that PowerShell process. The launcher does not install an automatic startup task, change system policy, install dependencies, stop services, or overwrite databases. After reopening Windows, run the first command once. If the correct services already run, it reuses them.

Requirements: the existing Ubuntu-22.04 distribution, Python virtualenv, JDK 17, local model/LoRA/datasets, installed frontend dependencies, and the accepted runtime at `work/acceptance/runtime`. The private local `launch-env.json` records the actual Linux paths. Missing scan/database/checkpoint/configuration causes refusal rather than creation of an empty replacement. A foreign PID, occupied port, or unhealthy existing backend is reported without killing it. Model loading remains lazy until a scan needs inference.

The Windows launcher starts the WSL backend on port 8765 and the existing Windows Vite installation on port 5173, in hidden background processes. PID files and appended backend logs stay in the ignored runtime directory. The original runtime under `/home/tuankhoa/ntk-production-runtime-20261028` is not rewritten. Do not delete `work/acceptance/runtime` before the defense: it is intentionally excluded from Git.

Demo: <http://127.0.0.1:5173/#/results?scan_id=SCAN-20261101164045-3AA266>.

`verify-demo-browser.cjs` uses Node 24's built-in WebSocket and an existing Edge/Chrome CDP endpoint on localhost port 9223. It needs no Playwright/Puppeteer package. It checks the twelve requested pages, captures screenshots, exercises invalid-input validation, Review filters, a real report download, and trace replay without submitting scans. All screenshots, downloaded reports and page text go to ignored `work/final-validation/browser`; they can contain private dataset samples and must not be published.

```powershell
node .\tools\verify-demo-browser.cjs
```

The browser must be launched separately with a private test profile and remote debugging bound to localhost; the verifier never attaches to the user's normal browser profile. Close the temporary test browser after verification. Full reproduction settings and actual test outcomes are in `NTK_FINAL_ACCEPTANCE_REPORT.md`.

## Multi-project and input acceptance

The completed run is documented in `NTK_MULTIPROJECT_ACCEPTANCE_REPORT.md` and its four linked reports. `run_multiproject_acceptance.py` submits real sequential jobs to the isolated API on port 8766 by default (`NTK_E2E_API` override). It expects the verified local `sources.json` inventory under ignored `work/e2e-multiproject-acceptance/`; it checks source bytes against Git objects and archive entries before reuse. Phases are `projects`, `inputs`, and `git-inputs`. `NTK_E2E_RUN_TAG=-postfix` gives reruns separate job/artifact names. Never point experimental runs at the demo store or run CUDA scans concurrently.

`evaluate_benchmark.py` phases `six`, `forty`, and `score` use the pinned public BenchmarkJava source and local selection manifest. Only Java enters inference; CSV truth stays outside. `NTK_EVAL_RUN_TAG=-postfix` retains the frozen baseline and writes separate post-fix records. Selected public cases, source hashes, confusion matrices and all REVIEW conventions are published under `docs/evaluation-20261102`; training overlap is not proven absent. Tests for metric arithmetic run with `python -m unittest discover -s tools/tests -v`.

`verify-input-browser.cjs` uses the existing Edge CDP endpoint and actual frontend 5174/API 8766. It verifies eight project results, empty/safe/unknown states, multipart uploads with a double click, Java-only errors for Git/ZIP, ref/subpath errors, and partial coverage warnings. Logs, ZIPs, screenshots and full responses stay ignored. It requires the local acceptance artifacts from an actual run and does not fabricate completed scans. These tools do not bootstrap services or download/retrain models.
