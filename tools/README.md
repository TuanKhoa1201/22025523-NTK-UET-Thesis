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
