const {test} = require('node:test');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const SRC_ROOT = path.join(__dirname, '../src');

function setupDomGlobals() {
  const mkStorage = () => ({
    _map: new Map(),
    getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
    setItem(k, v) { this._map.set(k, String(v)); },
    removeItem(k) { this._map.delete(k); },
  });
  global.window = {
    setTimeout,
    clearTimeout,
    sessionStorage: mkStorage(),
    localStorage: mkStorage(),
  };
}

async function loadSrcEsm(relPath, replacements = []) {
  let src = fs.readFileSync(path.join(SRC_ROOT, relPath), 'utf8');
  src = src.replace(/import\.meta\.env\?\.VITE_API_BASE_URL/g, '""');
  src = src.replace(/import\.meta\.env\.VITE_API_BASE_URL/g, '""');
  for (const [from, to] of replacements) {
    src = src.replace(from, to);
  }
  return `data:text/javascript;base64,${Buffer.from(`${src}\n// ${Math.random()}`).toString('base64')}`;
}

function startEphemeralServer(tmpRoot) {
  const pyCode = `
import json, pathlib, sys
from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store

root = pathlib.Path(sys.argv[1])
token = "checkpoint-d-node-token-20261117"

def make_scan(name, *, mark_mock=False, validated_status="REFUTED"):
    sub = root / name
    src_dir = sub / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "PathDemo.java"
    code = (
        "package demo;\\n"
        "public class PathDemo {\\n"
        "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\\n"
        '        String p = req.getParameter("p");\\n'
        '        return new java.io.File("/data", p);\\n'
        "    }\\n"
        "}\\n"
        f"// scan: {name}\\n"
    )
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("p")'
    sink_txt = 'new java.io.File("/data", p)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "PathDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "PathDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
    finding = {
        "check_id": "v2.g1.java.cwe22.path-traversal",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": f"CWE-22 test finding ({name})",
            "metadata": {"cwe": ["CWE-22: Path Traversal"]},
            "dataflow_trace": {
                "taint_source": ["CliLoc", [src_loc, src_txt]],
                "taint_sink": ["CliLoc", [sink_loc, sink_txt]],
                "intermediate_vars": [],
            },
        },
    }
    raw_bytes = json.dumps({"results": [finding], "errors": []}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "UNIT_TEST_MOCK_CAPTURE" if mark_mock else "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"PathDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"PathDemo.java": sha}
    ass = {
        "status": validated_status,
        "raw_model_status": validated_status,
        "validated_status": validated_status,
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Report and history verification",
        "fix_suggestion": "Normalize path",
        "citations": [{"path": "PathDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "mock" if mark_mock else "unverified", "model_runtime_verified": False},
    }
    scan_dir = sub / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()
    return scan_dir, bundle["scan_sha256"], bundle["records"][0]["id"]

real_dir, real_scan, real_finding = make_scan("real", mark_mock=False, validated_status="REFUTED")
mock_dir, mock_scan, mock_finding = make_scan("mock", mark_mock=True, validated_status="SUPPORTED")

cfg = ApiConfig(
    host="127.0.0.1",
    port=0,
    data_dir=root / "api_data",
    reviewable_scan_dirs=(real_dir, mock_dir),
    api_token=token,
)
srv = ThesisApiServer(cfg)
host, port = srv.server_address[:2]
print(json.dumps({
    "baseUrl": f"http://{host}:{port}",
    "token": token,
    "realScan": real_scan,
    "realFinding": real_finding,
    "mockScan": mock_scan,
    "mockFinding": mock_finding,
}), flush=True)
srv.serve_forever()
`;
  return new Promise((resolve, reject) => {
    const proc = spawn('python', ['-X', 'utf8', '-B', '-c', pyCode, tmpRoot], {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`Timeout starting server: ${err}`));
    }, 10000);
    proc.stdout.on('data', (chunk) => {
      out += chunk.toString('utf8');
      const nl = out.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timer);
        try {
          resolve({proc, info: JSON.parse(out.slice(0, nl))});
        } catch (e) {
          proc.kill();
          reject(e);
        }
      }
    });
    proc.stderr.on('data', (chunk) => { err += chunk.toString('utf8'); });
  });
}

test('scanHistory distinguishes backend-confirmed scans/jobs (including FAILED/RUNNING without scan_id) from browser cache', async () => {
  setupDomGlobals();
  const fpUrl = await loadSrcEsm('services/findingPresentation.js');
  const sdUrl = await loadSrcEsm('services/scanData.js', [["'./findingPresentation'", `'${fpUrl}'`]]);
  const shUrl = await loadSrcEsm('services/scanHistory.js', [["'./scanData'", `'${sdUrl}'`]]);
  const sh = await import(shUrl);

  sh.upsertHistory({scanId: 'cached-only-1', repoUrl: 'https://github.com/org/cached', status: 'COMPLETED'});
  const cachedList = sh.readHistory();
  assert.equal(cachedList.length, 1);
  assert.equal(cachedList[0].backendConfirmed, false);
  assert.equal(cachedList[0].sourceOrigin, 'BROWSER_CACHE');

  const failedJob = sh.historyRecordFromBackend({
    job_id: 'job-failed-1',
    scan_id: null,
    state: 'FAILED',
    input_mode: 'GITHUB',
    repo_url: 'https://github.com/org/broken',
    error_code: 'OPENGREP_UNAVAILABLE',
    error_message: 'Missing binary',
    created_at: '2026-11-17T10:00:00Z',
  });
  assert.equal(sh.historyKey(failedJob), 'job-failed-1');
  assert.equal(failedJob.status, 'FAILED');
  assert.equal(failedJob.backendConfirmed, true);

  const completedScan = sh.historyRecordFromBackend({
    scan_id: 'scan-real-1',
    data_origin: 'REAL_SCAN',
    total_findings: 4,
    java_files_scanned: 3,
    by_validated_status: {SUPPORTED: 1, REFUTED: 2, UNDETERMINED: 1},
    by_human_review_state: {OPEN: 3, CONFIRMED_TRUE: 1, CONFIRMED_FALSE: 0},
    completed_at: '2026-11-17T11:00:00Z',
  });
  assert.equal(completedScan.confirmedTrue, 1);
  assert.equal(completedScan.openCount, 3);
  assert.equal(completedScan.candidates, 4);

  const mockScan = sh.historyRecordFromBackend({
    scan_id: 'scan-mock-1',
    data_origin: 'MOCK_SYNTHETIC_TEST',
    is_test_or_mock: true,
  });

  const merged = sh.mergeHistoryRecords(cachedList, [failedJob, completedScan, mockScan], []);
  assert.equal(merged.length, 3);
  assert.equal(merged.find((r) => r.scanId === 'scan-real-1').backendConfirmed, true);
  assert.equal(merged.find((r) => r.jobId === 'job-failed-1').backendConfirmed, true);
  assert.equal(merged.find((r) => r.scanId === 'cached-only-1').backendConfirmed, false);
  assert.equal(merged.some((r) => r.scanId === 'scan-mock-1'), false);
});

test('reportModel keeps REFUTED separate from CONFIRMED_FALSE, counts unreviewed OPEN, and blocks mock exports', async () => {
  const rmUrl = await loadSrcEsm('services/reportModel.js');
  const {buildReportViewModel} = await import(rmUrl);

  const realVm = buildReportViewModel({
    report_schema: 'ntk-report-v1',
    generated_at: '2026-11-17T12:00:00Z',
    data_origin: 'REAL_SCAN',
    contains_mock_or_test_data: false,
    scan_summary: {
      scan_id: 'scan-1',
      scan_sha256: 'abc',
      input_mode: 'ZIP',
      file_name: 'app.zip',
      java_files_scanned: 2,
      opengrep_version: '1.25.0',
      rules_sha256: 'def',
      total_findings: 2,
      findings_with_trace: 2,
      validator_downgraded_count: 1,
      matched_citation_count: 1,
      by_cwe: {'CWE-22': 1, 'CWE-89': 1},
      by_validated_status: {SUPPORTED: 0, REFUTED: 1, UNDETERMINED: 1},
      by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      known_analysis_limits: ['Bounded to OpenGrep rules'],
      scan_issues: [],
    },
    audit_trail: {events_count: 0, rejected_decisions_count: 1, events: [], rejected_decisions: [{sequence: 1, rejection_code: 'STALE_SOURCE'}]},
    findings: [
      {
        finding_id: 'f-1',
        cwe: 'CWE-22',
        validated_status: 'REFUTED',
        human_review_state: 'OPEN',
        citation_check: 'MATCHED',
        evidence: {snapshots: {'A.java': {sha256: '111', size: 100}}},
        assessment: {citations: [{path: 'A.java', start_line: 5, quote: 'x', sha256: '111'}]},
      },
      {
        finding_id: 'f-2',
        cwe: 'CWE-89',
        validated_status: 'UNDETERMINED',
        human_review_state: 'OPEN',
        citation_check: 'NONE',
        failure_kind: 'INVALID_CITATION',
        evidence: {snapshots: {'B.java': {sha256: '222', size: 120}}},
        assessment: {citations: []},
      },
    ],
  });

  assert.equal(realVm.isMockOrTest, false);
  assert.equal(realVm.canExportReport, true);
  assert.equal(realVm.qwenStats.refuted, 1);
  assert.equal(realVm.qwenStats.undetermined, 1);
  assert.equal(realVm.humanReviewStats.confirmedFalse, 0);
  assert.equal(realVm.humanReviewStats.unreviewedOpen, 2);
  assert.equal(realVm.humanReviewStats.refutedStillOpen, 1);
  assert.equal(realVm.humanReviewStats.rejectedCount, 1);
  assert.equal(realVm.findingRows[0].snapshots[0].sha256, '111');

  const mockVm = buildReportViewModel({
    data_origin: 'MOCK_SYNTHETIC_TEST',
    contains_mock_or_test_data: true,
    scan_summary: {scan_id: 'mock-1'},
    findings: [],
  });
  assert.equal(mockVm.isMockOrTest, true);
  assert.equal(mockVm.canExportReport, false);
});

test('Frontend api.js + reportModel.js + scanHistory.js against live ThesisApiServer (reports, history, CORS preflight, mock isolation)', async () => {
  setupDomGlobals();
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ntk-cp-d-'));
  const {proc, info} = await startEphemeralServer(tmpRoot);
  try {
    const apiUrl = await loadSrcEsm('services/api.js');
    const rmUrl = await loadSrcEsm('services/reportModel.js');
    const apiMod = await import(apiUrl);
    const {buildReportViewModel} = await import(rmUrl);

    apiMod.setApiBaseUrl(info.baseUrl);
    apiMod.setSessionToken(info.token);

    // 1. CORS preflight for local frontend localhost:5173
    const preflight = await fetch(`${info.baseUrl}/api/scans`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:5173',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Authorization, Content-Type',
      },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), 'http://localhost:5173');
    assert.match(preflight.headers.get('access-control-allow-headers') || '', /Authorization/i);

    // 2. Real scan appears in /api/scans, mock scan is excluded
    const scansRes = await apiMod.api.listScans();
    assert.equal(scansRes.items.length, 1);
    assert.equal(scansRes.items[0].scan_sha256, info.realScan);

    // 3. /api/scans/{realScan}/report returns full report; REFUTED stays OPEN
    const repDoc = await apiMod.api.report(info.realScan);
    const vm = buildReportViewModel(repDoc);
    assert.equal(vm.canExportReport, true);
    assert.equal(vm.qwenStats.refuted, 1);
    assert.equal(vm.humanReviewStats.confirmedFalse, 0);
    assert.equal(vm.humanReviewStats.unreviewedOpen, 1);
    assert.equal(vm.findingRows[0].citations.length, 1);
    assert.equal(vm.findingRows[0].snapshots.length, 1);

    // 4. Mock scan blocked across report & review-history with 403 TEST_DATA_ISOLATED
    await assert.rejects(() => apiMod.api.report(info.mockScan), (err) => err.status === 403 && err.code === 'TEST_DATA_ISOLATED');
    await assert.rejects(() => apiMod.api.scanReviewHistory(info.mockScan), (err) => err.status === 403 && err.code === 'TEST_DATA_ISOLATED');
  } finally {
    proc.kill();
    fs.rmSync(tmpRoot, {recursive: true, force: true});
  }
});

test('Checkpoint D static audit: no legacy scope, no unused legacy deps in package.json, and built Vite bundle leaks no token', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
  for (const removed of ['@questlabs/react-sdk', '@react-three/fiber', '@supabase/supabase-js', 'three', 'xlsx', 'date-fns']) {
    assert.equal(Object.hasOwn(pkg.dependencies, removed), false, `${removed} must be removed from dependencies`);
  }

  const files = [
    'App.jsx',
    'pages/HistoryPage.jsx',
    'pages/ReportsPage.jsx',
    'pages/UtilityPages.jsx',
    'services/scanHistory.js',
    'services/reportModel.js',
  ];
  for (const rel of files) {
    const content = fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');
    assert(!/\bIRIS\b/.test(content), `${rel} must not contain IRIS`);
    assert(!/\bCWSS\b/.test(content), `${rel} must not contain CWSS`);
    assert(!/\bLoRA\b/.test(content), `${rel} must not contain LoRA`);
    assert(!/8780/.test(content), `${rel} must not hard-code port 8780`);
    assert(!/VITE_API_TOKEN/.test(content), `${rel} must not read API token from Vite bundle`);
  }

  const distAssetsDir = path.join(__dirname, '../dist/assets');
  if (fs.existsSync(distAssetsDir)) {
    for (const f of fs.readdirSync(distAssetsDir)) {
      if (f.endsWith('.js')) {
        const js = fs.readFileSync(path.join(distAssetsDir, f), 'utf8');
        assert(!/VITE_API_TOKEN/.test(js), `Built bundle ${f} must not contain VITE_API_TOKEN`);
      }
    }
  }
});
