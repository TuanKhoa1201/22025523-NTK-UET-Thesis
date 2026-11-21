const {test} = require('node:test');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const SRC_ROOT = path.join(__dirname, '../src');

async function loadModules() {
  let apiSrc = fs.readFileSync(path.join(SRC_ROOT, 'services/api.js'), 'utf8');
  apiSrc = apiSrc.replace(/import\.meta\.env\?\.VITE_API_BASE_URL/g, '""');
  apiSrc = apiSrc.replace(/import\.meta\.env\.VITE_API_BASE_URL/g, '""');

  global.window = {
    setTimeout,
    clearTimeout,
    sessionStorage: {
      _map: new Map(),
      getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
      setItem(k, v) { this._map.set(k, String(v)); },
      removeItem(k) { this._map.delete(k); },
    },
    localStorage: {
      getItem() { throw new Error('localStorage must not be used for tokens'); },
      setItem() { throw new Error('localStorage must not be used for tokens'); },
    },
  };

  const apiUrl = `data:text/javascript;base64,${Buffer.from(`${apiSrc}\n// ${Math.random()}`).toString('base64')}`;
  const apiMod = await import(apiUrl);

  const modelSrc = fs
    .readFileSync(path.join(SRC_ROOT, 'services/reviewModel.js'), 'utf8')
    .replace("import {api} from './api';", `import {api} from '${apiUrl}';`);
  const modelMod = await import(
    `data:text/javascript;base64,${Buffer.from(`${modelSrc}\n// ${Math.random()}`).toString('base64')}`
  );
  return {apiMod, modelMod};
}

function startEphemeralReviewServer(tmpRoot) {
  const pyCode = `
import json, pathlib, sys, threading
from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store

root = pathlib.Path(sys.argv[1])
token = "node-e2e-token-20261117"

def make_scan(name, *, validated_status="REFUTED"):
    sub = root / name
    src_dir = sub / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "SqlDemo.java"
    code = (
        "package demo;\\n"
        "public class SqlDemo {\\n"
        "    public void q(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\\n"
        '        String id = req.getParameter("id");\\n'
        '        st.executeQuery("SELECT * FROM t WHERE id=" + id);\\n'
        "    }\\n"
        "}\\n"
        f"// scan: {name}\\n"
    )
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("id")'
    sink_txt = 'st.executeQuery("SELECT * FROM t WHERE id=" + id)'
    col_s = lines[3].index(src_txt) + 1
    col_k = lines[4].index(sink_txt) + 1
    src_loc = {"path": "SqlDemo.java", "start": {"line": 4, "col": col_s}, "end": {"line": 4, "col": col_s + len(src_txt)}}
    sink_loc = {"path": "SqlDemo.java", "start": {"line": 5, "col": col_k}, "end": {"line": 5, "col": col_k + len(sink_txt)}}
    finding = {
        "check_id": "v2.g1.java.cwe89.sqli",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": f"SQLi test finding ({name})",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            "dataflow_trace": {
                "taint_source": ["CliLoc", [src_loc, 'req.getParameter("id")']],
                "taint_sink": ["CliLoc", [sink_loc, 'st.executeQuery("SELECT * FROM t WHERE id=" + id)']],
                "intermediate_vars": [],
            },
        },
    }
    raw_bytes = json.dumps({"results": [finding], "errors": []}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"SqlDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"SqlDemo.java": sha}
    ass = {
        "status": validated_status,
        "raw_model_status": validated_status,
        "validated_status": validated_status,
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Node E2E review test",
        "fix_suggestion": "PreparedStatement",
        "citations": [{"path": "SqlDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "unverified", "model_runtime_verified": False},
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
    return scan_dir, java_file, bundle["scan_sha256"], bundle["records"][0]["id"]

rw_dir, rw_java, rw_scan, rw_finding = make_scan("rw", validated_status="REFUTED")
ro_dir, _, ro_scan, ro_finding = make_scan("ro", validated_status="SUPPORTED")

cfg = ApiConfig(
    host="127.0.0.1",
    port=0,
    data_dir=root / "api_data",
    reviewable_scan_dirs=(rw_dir,),
    readonly_scan_dirs=(ro_dir,),
    api_token=token,
)
srv = ThesisApiServer(cfg)
host, port = srv.server_address[:2]
print(json.dumps({
    "baseUrl": f"http://{host}:{port}",
    "token": token,
    "rwScan": rw_scan,
    "rwFinding": rw_finding,
    "rwJavaPath": str(rw_java),
    "roScan": ro_scan,
    "roFinding": ro_finding,
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
      reject(new Error(`Timed out starting ThesisApiServer. stderr=${err}`));
    }, 10000);

    proc.stdout.on('data', (chunk) => {
      out += chunk.toString('utf8');
      const nl = out.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timer);
        try {
          const info = JSON.parse(out.slice(0, nl));
          resolve({proc, info});
        } catch (e) {
          proc.kill();
          reject(e);
        }
      }
    });
    proc.stderr.on('data', (chunk) => {
      err += chunk.toString('utf8');
    });
    proc.on('exit', (code) => {
      if (code !== null) {
        clearTimeout(timer);
        reject(new Error(`Server exited early with code ${code}: ${err}`));
      }
    });
  });
}

test('validateReviewInput enforces actor & reason constraints and rejects control characters', async () => {
  const {modelMod} = await loadModules();
  assert.equal(modelMod.validateReviewInput({actor: '', reason: 'ok'}).valid, false);
  assert.equal(modelMod.validateReviewInput({actor: '   ', reason: 'ok'}).valid, false);
  assert.equal(modelMod.validateReviewInput({actor: 'alice\nbob', reason: 'ok'}).valid, false);
  assert.equal(modelMod.validateReviewInput({actor: 'a'.repeat(121), reason: 'ok'}).valid, false);
  assert.equal(modelMod.validateReviewInput({actor: 'alice', reason: '   '}).valid, false);
  assert.equal(modelMod.validateReviewInput({actor: 'alice', reason: 'r'.repeat(2001)}).valid, false);

  const ok = modelMod.validateReviewInput({actor: '  reviewer-uet ', reason: '  PreparedStatement verified '});
  assert.equal(ok.valid, true);
  assert.equal(ok.actor, 'reviewer-uet');
  assert.equal(ok.reason, 'PreparedStatement verified');
});

test('submitReviewDecision prevents duplicate submissions and sends only {actor, reason}', async () => {
  const {modelMod} = await loadModules();
  const sentBodies = [];
  let releasePost;
  const pendingPost = new Promise((r) => { releasePost = r; });

  const mockClient = {
    confirmTrue: async (_s, _f, body) => {
      sentBodies.push(body);
      await pendingPost;
      return {human_review_state: 'CONFIRMED_TRUE'};
    },
    confirmFalse: async () => { throw new Error('unused'); },
    reopenFinding: async () => { throw new Error('unused'); },
    findingDetail: async () => ({
      finding_id: 'f-1',
      human_review_state: 'CONFIRMED_TRUE',
      review_events: [{sequence: 1, action: 'confirm-true', actor: 'alice', reason: 'verified'}],
      rejected_decisions: [],
    }),
    findingHistory: async () => ({}),
  };

  const lockSet = new Set();
  const first = modelMod.submitReviewDecision({
    scanId: 'scan-1',
    findingId: 'f-1',
    action: 'confirm-true',
    actor: 'alice',
    reason: 'verified',
    inFlightKeys: lockSet,
    apiClient: mockClient,
  });
  const dup = await modelMod.submitReviewDecision({
    scanId: 'scan-1',
    findingId: 'f-1',
    action: 'confirm-true',
    actor: 'alice',
    reason: 'verified',
    inFlightKeys: lockSet,
    apiClient: mockClient,
  });
  assert.equal(dup.ok, false);
  assert.equal(dup.duplicate, true);
  assert.equal(dup.errorCode, 'DUPLICATE_SUBMISSION');

  releasePost();
  const res = await first;
  assert.equal(res.ok, true);
  assert.deepEqual(sentBodies, [{actor: 'alice', reason: 'verified'}]);
  assert.equal(Object.hasOwn(sentBodies[0], 'source_hash'), false);
  assert.equal(Object.hasOwn(sentBodies[0], 'verified'), false);
});

test('buildAuditTimeline merges applied events and rejected decisions newest-first', async () => {
  const {modelMod} = await loadModules();
  const timeline = modelMod.buildAuditTimeline(
    [
      {
        sequence: 1,
        warning_id: 'w-1',
        actor: 'alice',
        timestamp: '2026-11-17T10:00:00Z',
        action: 'confirm-false',
        reason: 'fp checked',
      },
      {
        sequence: 2,
        warning_id: 'w-1',
        actor: 'bob',
        timestamp: '2026-11-17T10:05:00Z',
        action: 'reopen',
        reason: 'need recheck',
      },
    ],
    [
      {
        sequence: 1,
        warning_id: 'w-1',
        actor: 'alice',
        timestamp: '2026-11-17T10:10:00Z',
        attempted_action: 'confirm-false',
        reason: 'retry after edit',
        rejection_code: 'STALE_SOURCE',
        detail_parsed: {
          mismatched_paths: ['SqlDemo.java'],
          expected_hashes: {'SqlDemo.java': 'aaa'},
          observed_hashes: {'SqlDemo.java': 'bbb'},
        },
      },
    ],
  );
  assert.equal(timeline.length, 3);
  assert.equal(timeline[0].kind, 'REJECTED');
  assert.equal(timeline[0].code, 'STALE_SOURCE');
  assert.deepEqual(timeline[0].mismatchedPaths, ['SqlDemo.java']);
  assert.equal(timeline[1].action, 'reopen');
  assert.equal(timeline[2].action, 'confirm-false');
});

test('Frontend api.js + reviewModel.js end-to-end against real ThesisApiServer (REFUTED->OPEN, confirm-true/false, reopen, 409 STALE_SOURCE, 401/403)', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ntk-cp-c-'));
  const {proc, info} = await startEphemeralReviewServer(tmpRoot);
  try {
    const {apiMod, modelMod} = await loadModules();
    apiMod.setApiBaseUrl(info.baseUrl);
    apiMod.clearSessionToken();

    // 1. Missing Bearer token -> 401 UNAUTHORIZED
    const unauth = await modelMod.submitReviewDecision({
      scanId: info.rwScan,
      findingId: info.rwFinding,
      action: 'confirm-true',
      actor: 'reviewer-uet',
      reason: 'Missing token check',
    });
    assert.equal(unauth.ok, false);
    assert.equal(unauth.status, 401);
    assert.equal(unauth.errorCode, 'UNAUTHORIZED');

    // Attach valid Bearer token
    apiMod.setSessionToken(info.token);

    // 2. Read-only scan -> 403 SCAN_READ_ONLY
    const roRes = await modelMod.submitReviewDecision({
      scanId: info.roScan,
      findingId: info.roFinding,
      action: 'confirm-true',
      actor: 'reviewer-uet',
      reason: 'Readonly check',
    });
    assert.equal(roRes.ok, false);
    assert.equal(roRes.status, 403, `Expected 403 SCAN_READ_ONLY, got ${JSON.stringify(roRes)}`);
    assert.equal(roRes.errorCode, 'SCAN_READ_ONLY');

    // 3. Review queue: Qwen REFUTED must still be OPEN!
    const q0 = await apiMod.api.reviewQueue(info.rwScan, {includeAll: false});
    assert.equal(q0.counts.open_count, 1);
    assert.equal(q0.counts.proposed_refuted_open_count, 1);
    assert.equal(q0.warnings[0].validated_status, 'REFUTED');
    assert.equal(q0.warnings[0].human_review_state, 'OPEN');

    // 4. confirm-true -> CONFIRMED_TRUE
    const resTrue = await modelMod.submitReviewDecision({
      scanId: info.rwScan,
      findingId: info.rwFinding,
      action: 'confirm-true',
      actor: 'reviewer-uet',
      reason: 'String concatenation reaches executeQuery',
    });
    assert.equal(resTrue.ok, true);
    assert.equal(resTrue.detail.human_review_state, 'CONFIRMED_TRUE');

    // 5. confirm-false -> CONFIRMED_FALSE (hidden from default queue, visible when includeAll=true)
    const resFalse = await modelMod.submitReviewDecision({
      scanId: info.rwScan,
      findingId: info.rwFinding,
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Source hash intact check',
      detail: resTrue.detail,
    });
    assert.equal(resFalse.ok, true, `Expected confirm-false ok, got ${JSON.stringify(resFalse)}`);
    assert.equal(resFalse.detail.human_review_state, 'CONFIRMED_FALSE');

    const qDefault = await apiMod.api.reviewQueue(info.rwScan, {includeAll: false});
    assert.equal(qDefault.warnings.length, 0);
    const qAll = await apiMod.api.reviewQueue(info.rwScan, {includeAll: true});
    assert.equal(qAll.warnings.length, 1);
    assert.equal(qAll.warnings[0].human_review_state, 'CONFIRMED_FALSE');

    // 6. reopen -> OPEN
    const resReopen = await modelMod.submitReviewDecision({
      scanId: info.rwScan,
      findingId: info.rwFinding,
      action: 'reopen',
      actor: 'reviewer-lead',
      reason: 'Reopen for STALE_SOURCE verification',
    });
    assert.equal(resReopen.ok, true);
    assert.equal(resReopen.detail.human_review_state, 'OPEN');
    assert.equal(resReopen.detail.review_events.length, 3);

    // 7. Mutate Java file on disk -> 409 STALE_SOURCE, stays OPEN, rejected_decisions recorded
    fs.appendFileSync(info.rwJavaPath, '// modified after scan\n', 'utf8');
    const staleRes = await modelMod.submitReviewDecision({
      scanId: info.rwScan,
      findingId: info.rwFinding,
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Attempt FP confirmation after source drift',
      detail: resReopen.detail,
    });
    assert.equal(staleRes.ok, false);
    assert.equal(staleRes.staleSource, true);
    assert.equal(staleRes.errorCode, 'STALE_SOURCE');
    assert.equal(staleRes.humanReviewState, 'OPEN');
    assert.deepEqual(staleRes.staleDetail.mismatched_paths, ['SqlDemo.java']);
    assert.equal(staleRes.reviewEvents.length, 3);
    assert.equal(staleRes.rejectedDecisions.length, 1);
    assert.equal(staleRes.rejectedDecisions[0].rejection_code, 'STALE_SOURCE');

    // 8. Scan-wide audit history reflects all 3 events + 1 rejected_decision
    const scanHist = await apiMod.api.scanReviewHistory(info.rwScan);
    assert.equal(scanHist.events.length, 3);
    assert.equal(scanHist.rejected_decisions.length, 1);
  } finally {
    proc.kill();
    fs.rmSync(tmpRoot, {recursive: true, force: true});
  }
});

test('Checkpoint C frontend files wire Human Review cleanly without legacy scope or client-side hash trust', () => {
  const files = [
    'App.jsx',
    'pages/ReviewPage.jsx',
    'pages/Results.jsx',
    'pages/UtilityPages.jsx',
    'components/review/HumanReviewPanel.jsx',
    'services/reviewModel.js',
  ];
  for (const rel of files) {
    const content = fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');
    assert(!/\bIRIS\b/.test(content), `${rel} must not contain IRIS`);
    assert(!/\bCWSS\b/.test(content), `${rel} must not contain CWSS`);
    assert(!/\bLoRA\b/.test(content), `${rel} must not contain LoRA`);
    assert(!/8780/.test(content), `${rel} must not hard-code port 8780`);
    assert(!/VITE_API_TOKEN/.test(content), `${rel} must not read API token from Vite env`);
  }

  const appSrc = fs.readFileSync(path.join(SRC_ROOT, 'App.jsx'), 'utf8');
  assert.match(appSrc, /import ReviewPage from '\.\/pages\/ReviewPage'/);
  assert.match(appSrc, /path="\/review"\s+element=\{<ReviewPage \/>\}/);

  const resultsSrc = fs.readFileSync(path.join(SRC_ROOT, 'pages/Results.jsx'), 'utf8');
  assert.match(resultsSrc, /<HumanReviewPanel/);

  const utilSrc = fs.readFileSync(path.join(SRC_ROOT, 'pages/UtilityPages.jsx'), 'utf8');
  assert.equal(/export function Review\b/.test(utilSrc), false);
});
