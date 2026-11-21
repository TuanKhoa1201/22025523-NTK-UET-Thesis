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
    get length() { return this._map.size; },
    key(i) { return [...this._map.keys()][i] ?? null; },
    getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
    setItem(k, v) { this._map.set(k, String(v)); },
    removeItem(k) { this._map.delete(k); },
  });
  global.window = {
    setTimeout,
    clearTimeout,
    sessionStorage: mkStorage(),
    localStorage: {
      getItem() { throw new Error('localStorage must not be used for tokens'); },
      setItem() { throw new Error('localStorage must not be used for tokens'); },
    },
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

function startScenarioServer(tmpRoot) {
  const pyCode = `
import json, pathlib, sys
from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store

root = pathlib.Path(sys.argv[1])
token = "frontend-v2-ui-scenarios-token-20261119"

def make_cwe22_github_scan():
    sub = root / "github_cwe22"
    src_dir = sub / "src" / "main" / "java"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "FileServlet.java"
    code = (
        "package demo;\\n"
        "public class FileServlet {\\n"
        "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\\n"
        '        String p = req.getParameter("file");\\n'
        '        String path = "/var/app/" + p;\\n'
        '        return new java.io.File(path);\\n'
        "    }\\n"
        "}\\n"
    )
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("file")'
    mid_txt = '"/var/app/" + p'
    sink_txt = 'new java.io.File(path)'
    rel_p = "src/main/java/FileServlet.java"
    cs = lines[3].index(src_txt) + 1
    cm = lines[4].index(mid_txt) + 1
    ck = lines[5].index(sink_txt) + 1
    src_loc = {"path": rel_p, "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    mid_loc = {"path": rel_p, "start": {"line": 5, "col": cm}, "end": {"line": 5, "col": cm + len(mid_txt)}}
    sink_loc = {"path": rel_p, "start": {"line": 6, "col": ck}, "end": {"line": 6, "col": ck + len(sink_txt)}}
    finding = {
        "check_id": "v2.g1.java.cwe22.path-traversal",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": "Potential CWE-22 Path Traversal via FileServlet",
            "metadata": {"cwe": ["CWE-22: Path Traversal"]},
            "dataflow_trace": {
                "taint_source": ["CliLoc", [src_loc, src_txt]],
                "intermediate_vars": [{"location": mid_loc, "content": mid_txt}],
                "taint_sink": ["CliLoc", [sink_loc, sink_txt]],
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
        "source_hashes": {rel_p: sha},
    }
    bundle = evidence.collect(raw_bytes, sub, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {rel_p: sha}
    ass = {
        "status": "SUPPORTED",
        "raw_model_status": "SUPPORTED",
        "validated_status": "SUPPORTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "User parameter flows into java.io.File without canonical path check.",
        "fix_suggestion": "Normalize with Path.normalize() and enforce base directory prefix.",
        "citations": [{"path": rel_p, "start_line": 4, "end_line": 6, "quote": "\\n".join(lines[3:6]), "sha256": sha}],
        "citation_check": "MATCHED",
        "citation_provenance": {"matched_count": 1},
        "prompt_version": "blind-v2",
        "model": "qwen3.5:9b-q4_K_M",
        "elapsed_seconds": 6.42,
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "ollama_reported_unattested", "model_runtime_verified": False},
    }
    scan_dir = sub / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
    (scan_dir / "api-scan-meta.json").write_text(json.dumps({
        "input_mode": "GITHUB",
        "repo_url": "https://github.com/example/insecure-java-app",
        "resolved_commit": "7f6b76c5056a82292a87cafa78f922077a211feb",
        "opengrep_version": "1.25.0",
        "java_files_count": 10,
        "total_e2e_duration_ms": 14250.5,
    }), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()
    return scan_dir, java_file, bundle["scan_sha256"], bundle["records"][0]["id"]

def make_empty_scan():
    sub = root / "github_empty"
    src_dir = sub / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "CleanApp.java"
    java_file.write_text("package demo;\\npublic class CleanApp {}\\n", encoding="utf-8")
    raw_bytes = json.dumps({"results": [], "errors": []}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"CleanApp.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"CleanApp.java": sha}
    scan_dir = sub / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
    (scan_dir / "api-scan-meta.json").write_text(json.dumps({
        "input_mode": "GITHUB",
        "repo_url": "https://github.com/example/clean-java-app",
        "opengrep_version": "1.25.0",
        "java_files_count": 4,
    }), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [])
    finally:
        rs.close()
    return scan_dir, bundle["scan_sha256"]

def make_multi_status_and_large_scan():
    sub = root / "multi_scan"
    src_dir = sub / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "VeryLongPackageControllerNameForEdgeCaseValidationTest.java"
    code_lines = ["package demo;", "public class VeryLongPackageControllerNameForEdgeCaseValidationTest {"]
    for i in range(1, 61):
        code_lines.append(f'    void q{i}(java.sql.Statement st, String id) throws Exception {{ st.executeQuery("SELECT * FROM t WHERE id=" + id); }}')
    code_lines.append("}")
    code = "\\n".join(code_lines) + "\\n"
    java_file.write_text(code, encoding="utf-8")
    fname = java_file.name
    sha = evidence.digest(java_file.read_bytes())
    findings = []
    assessments = []
    for i in range(60):
        line_no = 3 + i
        line_txt = code_lines[line_no - 1]
        sink_txt = 'st.executeQuery("SELECT * FROM t WHERE id=" + id)'
        col = line_txt.index(sink_txt) + 1
        loc = {"path": fname, "start": {"line": line_no, "col": col}, "end": {"line": line_no, "col": col + len(sink_txt)}}
        cwe = "CWE-22: Path Traversal" if i % 2 == 0 else "CWE-89: SQL Injection"
        findings.append({
            "check_id": f"v2.g1.java.rule.{i}",
            **loc,
            "extra": {
                "severity": "ERROR",
                "message": ("Long description " * 25) + f"finding #{i}",
                "metadata": {"cwe": [cwe]},
            },
        })
        if i % 3 == 0:
            assessments.append({
                "status": "SUPPORTED",
                "raw_model_status": "SUPPORTED",
                "validated_status": "SUPPORTED",
                "validator_downgraded": False,
                "failure_kind": None,
                "explanation": "Supported explanation " * 12,
                "fix_suggestion": "Use PreparedStatement.",
                "citations": [{"path": fname, "start_line": line_no, "end_line": line_no, "quote": line_txt, "sha256": sha}],
                "citation_check": "MATCHED",
                "requires_human_review": True,
                "security_conclusion_verified": False,
                "analyzed_at": evidence.now(),
                "runtime": {"origin": "ollama_reported_unattested", "model_runtime_verified": False},
            })
        elif i % 3 == 1:
            assessments.append({
                "status": "REFUTED",
                "raw_model_status": "REFUTED",
                "validated_status": "REFUTED",
                "validator_downgraded": False,
                "failure_kind": None,
                "explanation": "Allowlist check observed prior to query.",
                "fix_suggestion": "",
                "citations": [{"path": fname, "start_line": line_no, "end_line": line_no, "quote": line_txt, "sha256": sha}],
                "citation_check": "MATCHED",
                "requires_human_review": True,
                "security_conclusion_verified": False,
                "analyzed_at": evidence.now(),
                "runtime": {"origin": "ollama_reported_unattested", "model_runtime_verified": False},
            })
        else:
            assessments.append({
                "status": "UNDETERMINED",
                "raw_model_status": "REFUTED",
                "validated_status": "UNDETERMINED",
                "validator_downgraded": True,
                "failure_kind": "INVALID_CITATION",
                "explanation": "Downgraded because citation did not match snapshot.",
                "fix_suggestion": "",
                "citations": [],
                "citation_check": "NONE",
                "requires_human_review": True,
                "security_conclusion_verified": False,
                "analyzed_at": evidence.now(),
                "runtime": {"origin": "ollama_reported_unattested", "model_runtime_verified": False},
            })
    raw_bytes = json.dumps({"results": findings, "errors": []}).encode("utf-8")
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {fname: sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {fname: sha}
    scan_dir = sub / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, assessments)
    finally:
        rs.close()
    return scan_dir, bundle["scan_sha256"], [r["id"] for r in bundle["records"][:3]]

cwe22_dir, cwe22_java, cwe22_scan, cwe22_finding = make_cwe22_github_scan()
empty_dir, empty_scan = make_empty_scan()
multi_dir, multi_scan, multi_sample_ids = make_multi_status_and_large_scan()

cfg = ApiConfig(
    host="127.0.0.1",
    port=0,
    data_dir=root / "api_data",
    reviewable_scan_dirs=(cwe22_dir, empty_dir, multi_dir),
    api_token=token,
    read_auth_mode="required",
)
srv = ThesisApiServer(cfg)
host, port = srv.server_address[:2]
print(json.dumps({
    "baseUrl": f"http://{host}:{port}",
    "token": token,
    "cwe22Scan": cwe22_scan,
    "cwe22Finding": cwe22_finding,
    "cwe22Java": str(cwe22_java),
    "emptyScan": empty_scan,
    "multiScan": multi_scan,
    "multiSampleIds": multi_sample_ids,
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
      reject(new Error(`Timeout starting scenario server: ${err}`));
    }, 15000);
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
    proc.on('exit', (code) => {
      if (code !== null) {
        clearTimeout(timer);
        reject(new Error(`Scenario server exited early (${code}): ${err}`));
      }
    });
  });
}

test('Section 8 semantic honesty contract: never mislabel SUPPORTED, REFUTED, MATCHED, NO_FINDINGS, runtime, or OPENGREP_NOT_VERIFIED', async () => {
  const fpUrl = await loadSrcEsm('services/findingPresentation.js');
  const fp = await import(fpUrl);

  const sup = fp.validatedStatusMeta('SUPPORTED');
  assert.doesNotMatch(sup.viLabel, /Đã xác nhận lỗ hổng/i);
  assert.doesNotMatch(sup.summary, /Đã xác nhận lỗ hổng/i);

  const ref = fp.validatedStatusMeta('REFUTED');
  assert.doesNotMatch(ref.viLabel, /Đã loại cảnh báo/i);
  assert.match(ref.summary, /OPEN/);

  const und = fp.validatedStatusMeta('UNDETERMINED');
  assert.equal(und.code, 'UNDETERMINED');

  const matched = fp.citationCheckMeta('MATCHED');
  assert.doesNotMatch(matched.viLabel, /Đã chứng minh lỗ hổng/i);
  assert.match(matched.note, /không đồng nghĩa đã chứng minh lỗ hổng/i);

  assert.match(fp.NO_FINDINGS_NOTICE, /NO_FINDINGS/);
  assert.match(fp.NO_FINDINGS_NOTICE, /không chứng minh mã nguồn hoàn toàn an toàn/i);

  const rtFalse = fp.runtimeVerificationMeta(false);
  assert.equal(rtFalse.verified, false);
  assert.match(rtFalse.label, /Chưa xác thực độc lập/);
  assert.doesNotMatch(rtFalse.label, /Runtime đã được xác minh/i);

  const ogNotVerified = fp.describeOpengrepHealth(
    {available: false, probe_status: 'NOT_VERIFIED', resolved_path: '/usr/bin/opengrep'},
    '1.25.0',
  );
  assert.equal(ogNotVerified.code, 'OPENGREP_NOT_VERIFIED');
  assert.equal(ogNotVerified.tone, 'amber');
  assert.match(ogNotVerified.label, /OPENGREP_NOT_VERIFIED/);
  assert.match(ogNotVerified.detail, /1\.25\.0/);

  const ogUnavailable = fp.describeOpengrepHealth({available: false, probe_status: 'UNAVAILABLE', error: 'missing'});
  assert.equal(ogUnavailable.code, 'OPENGREP_UNAVAILABLE');
  assert.equal(ogUnavailable.tone, 'red');
});

test('Dataflow extraction builds Source -> Intermediate -> Sink from snippets and raw_trace', async () => {
  const fpUrl = await loadSrcEsm('services/findingPresentation.js');
  const fp = await import(fpUrl);

  const fromSnippets = fp.extractDataflowSteps({
    snippets: [
      {role: 'finding', path: 'FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)'},
      {role: 'source', path: 'FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")'},
      {role: 'intermediate', path: 'FileServlet.java', start: {line: 33}, end: {line: 33}, matched: 'String p = base + f'},
      {role: 'sink', path: 'FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)'},
    ],
  });
  assert.deepEqual(fromSnippets.map((s) => s.tag), ['SOURCE', 'INTERMEDIATE', 'SINK']);
  assert.deepEqual(fromSnippets.map((s) => s.startLine), [28, 33, 46]);

  const fromRawTrace = fp.extractDataflowSteps({
    snippets: [],
    raw_trace: {
      taint_source: ['CliLoc', [{path: 'A.java', start: {line: 10}, end: {line: 10}}, 'req.getParameter("id")']],
      intermediate_vars: [{location: {path: 'A.java', start: {line: 12}, end: {line: 12}}, content: 'sql = q + id'}],
      taint_sink: ['CliLoc', [{path: 'A.java', start: {line: 15}, end: {line: 15}}, 'st.executeQuery(sql)']],
    },
  });
  assert.deepEqual(fromRawTrace.map((s) => s.tag), ['SOURCE', 'INTERMEDIATE', 'SINK']);
  assert.equal(fromRawTrace[2].code, 'st.executeQuery(sql)');

  assert.deepEqual(fp.extractDataflowSteps({}), []);
  assert.equal(fp.formatShortHash('a'.repeat(64), 10, 6), `${'a'.repeat(10)}…${'a'.repeat(6)}`);
});

test('Scenarios 1–11 end-to-end against real ephemeral ThesisApiServer (CWE-22 SUPPORTED/MATCHED, NO_FINDINGS, REFUTED, UNDETERMINED, OPEN, CONFIRMED_TRUE/FALSE, 409 STALE_SOURCE no-retry, 401, network error, 60-finding pagination)', async () => {
  setupDomGlobals();
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ntk-ui-scenarios-'));
  const {proc, info} = await startScenarioServer(tmpRoot);
  try {
    const apiUrl = await loadSrcEsm('services/api.js');
    const fpUrl = await loadSrcEsm('services/findingPresentation.js');
    const sdUrl = await loadSrcEsm('services/scanData.js', [["'./findingPresentation'", `'${fpUrl}'`]]);
    const rmUrl = await loadSrcEsm('services/reviewModel.js', [["'./api'", `'${apiUrl}'`]]);

    const apiMod = await import(apiUrl);
    const fpMod = await import(fpUrl);
    const sdMod = await import(sdUrl);
    const rmMod = await import(rmUrl);

    apiMod.setApiBaseUrl(info.baseUrl);
    apiMod.clearSessionToken();

    // Scenario 9: Missing / wrong Bearer Token -> 401 UNAUTHORIZED & AUTH_REQUIRED health
    const unauthHealth = await apiMod.api.health();
    assert.equal(unauthHealth.status, 'AUTH_REQUIRED');

    apiMod.setSessionToken('wrong-token-value');
    await assert.rejects(
      () => apiMod.api.scanSummary(info.cwe22Scan),
      (err) => err.status === 401 && err.code === 'UNAUTHORIZED',
    );

    // Valid session token
    apiMod.setSessionToken(info.token);

    // Scenario 1 + 5 + 6: GitHub CWE-22, Qwen SUPPORTED, Citation MATCHED, Human Review OPEN, Source->Intermediate->Sink
    const detail1 = await apiMod.api.findingDetail(info.cwe22Scan, info.cwe22Finding);
    assert.equal(detail1.cwe, 'CWE-22');
    assert.equal(detail1.validated_status, 'SUPPORTED');
    assert.equal(detail1.citation_check, 'MATCHED');
    assert.equal(detail1.human_review_state, 'OPEN');
    assert.equal(detail1.assessment.runtime.model_runtime_verified, false);
    const traceSteps = fpMod.extractDataflowSteps(detail1.evidence);
    assert.deepEqual(traceSteps.map((s) => s.tag), ['SOURCE', 'INTERMEDIATE', 'SINK']);

    // Scenario 2: GitHub E2E with 0 findings (NO_FINDINGS)
    const emptySummary = await apiMod.api.scanSummary(info.emptyScan);
    assert.equal(emptySummary.total_findings, 0);
    const emptyPage = await apiMod.api.findingsPage(info.emptyScan, {page: 1, pageSize: 50});
    assert.equal(emptyPage.findings.length, 0);

    // Scenario 3 + 4 + 11: Multi-status (SUPPORTED, REFUTED, UNDETERMINED+downgraded) & 60 findings + long text/paths
    const allMulti = await apiMod.api.allFindingsPages(info.multiScan, {includeConfirmedFalse: true});
    assert.equal(allMulti.complete, true);
    assert.equal(allMulti.items.length, 60);
    const normalizedMulti = allMulti.items.map(sdMod.normalizeFinding);
    assert.equal(normalizedMulti.filter((r) => r.validatedStatus === 'SUPPORTED').length, 20);
    assert.equal(normalizedMulti.filter((r) => r.validatedStatus === 'REFUTED').length, 20);
    assert.equal(normalizedMulti.filter((r) => r.validatedStatus === 'UNDETERMINED').length, 20);
    assert.equal(normalizedMulti.filter((r) => r.validatorDowngraded).length, 20);
    assert.equal(normalizedMulti.every((r) => r.humanReviewState === 'OPEN'), true);

    // Scenario 7: CONFIRMED_TRUE & CONFIRMED_FALSE & REOPEN
    const tRes = await rmMod.submitReviewDecision({
      scanId: info.cwe22Scan,
      findingId: info.cwe22Finding,
      action: 'confirm-true',
      actor: 'reviewer-uet',
      reason: 'Confirmed unsanitized File path concatenation',
    });
    assert.equal(tRes.ok, true);
    assert.equal(tRes.detail.human_review_state, 'CONFIRMED_TRUE');

    const fRes = await rmMod.submitReviewDecision({
      scanId: info.cwe22Scan,
      findingId: info.cwe22Finding,
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Verifying confirm-false with intact SHA-256',
      detail: tRes.detail,
    });
    assert.equal(fRes.ok, true);
    assert.equal(fRes.detail.human_review_state, 'CONFIRMED_FALSE');

    const rRes = await rmMod.submitReviewDecision({
      scanId: info.cwe22Scan,
      findingId: info.cwe22Finding,
      action: 'reopen',
      actor: 'reviewer-uet',
      reason: 'Reopen before STALE_SOURCE drift test',
    });
    assert.equal(rRes.ok, true);
    assert.equal(rRes.detail.human_review_state, 'OPEN');

    // Scenario 8: HTTP 409 STALE_SOURCE — keeps OPEN, records rejected_decisions, NEVER auto-retries!
    fs.appendFileSync(info.cwe22Java, '// mutated after scan\n', 'utf8');
    let confirmFalsePostCount = 0;
    const countedClient = {
      ...apiMod.api,
      confirmFalse: async (...args) => {
        confirmFalsePostCount += 1;
        return apiMod.api.confirmFalse(...args);
      },
    };
    const staleRes = await rmMod.submitReviewDecision({
      scanId: info.cwe22Scan,
      findingId: info.cwe22Finding,
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Attempting FP confirmation after source drift',
      detail: rRes.detail,
      apiClient: countedClient,
    });
    assert.equal(confirmFalsePostCount, 1, 'Must never auto-retry confirm-false after 409 STALE_SOURCE');
    assert.equal(staleRes.ok, false);
    assert.equal(staleRes.staleSource, true);
    assert.equal(staleRes.errorCode, 'STALE_SOURCE');
    assert.equal(staleRes.humanReviewState, 'OPEN');
    assert.deepEqual(staleRes.staleDetail.mismatched_paths, ['src/main/java/FileServlet.java']);
    assert.equal(staleRes.rejectedDecisions.length, 1);

    // Scenario 10: API unreachable / network failure
    apiMod.setApiBaseUrl('http://127.0.0.1:1');
    const offline = await apiMod.checkBackend();
    assert.equal(offline.connected, false);
  } finally {
    proc.kill();
    fs.rmSync(tmpRoot, {recursive: true, force: true});
  }
});

test('Scenario 12 & visual system audit: every icon resolves cleanly, CSS tokens/responsive/a11y intact, zero legacy leakage', async () => {
  const safeIconSrc = fs.readFileSync(path.join(SRC_ROOT, 'common/SafeIcon.jsx'), 'utf8');
  const fiIcons = await import('react-icons/fi');
  const aliasMatch = safeIconSrc.match(/ICON_ALIASES\s*=\s*Object\.freeze\(\{([\s\S]*?)\}\)/);
  assert(aliasMatch, 'SafeIcon.jsx must define ICON_ALIASES');
  const aliases = {};
  for (const m of aliasMatch[1].matchAll(/(\w+)\s*:\s*'(\w+)'/g)) {
    aliases[m[1]] = m[2];
  }

  const walk = (dir) => {
    const out = [];
    for (const ent of fs.readdirSync(dir, {withFileTypes: true})) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) out.push(...walk(p));
      else if (/\.(js|jsx)$/.test(ent.name)) out.push(p);
    }
    return out;
  };

  const usedIcons = new Set();
  for (const filePath of walk(SRC_ROOT)) {
    const text = fs.readFileSync(filePath, 'utf8');
    for (const m of text.matchAll(/<Icon\s+name="([A-Za-z0-9]+)"/g)) {
      usedIcons.add(m[1]);
    }
    for (const m of text.matchAll(/icon:\s*'([A-Za-z0-9]+)'/g)) {
      usedIcons.add(m[1]);
    }
    for (const m of text.matchAll(/\['\/[^']*',\s*'[^']+',\s*'([A-Za-z0-9]+)'\]/g)) {
      usedIcons.add(m[1]);
    }
    // Static scope guard across all src JS/JSX
    assert(!/\bIRIS\b/.test(text), `${filePath} must not reference IRIS`);
    assert(!/\bCWSS\b/.test(text), `${filePath} must not reference CWSS`);
    assert(!/\bLoRA\b/.test(text), `${filePath} must not reference LoRA`);
    assert(!/\bCodeQL\b/.test(text), `${filePath} must not reference CodeQL`);
    assert(!/\bOrchestrator\b/.test(text), `${filePath} must not reference Orchestrator`);
    assert(!/VITE_API_TOKEN/.test(text), `${filePath} must not reference VITE_API_TOKEN`);
  }

  for (const name of usedIcons) {
    const direct = fiIcons[`Fi${name}`];
    const mapped = aliases[name] && fiIcons[`Fi${aliases[name]}`];
    assert(direct || mapped, `Icon "${name}" must map to a valid react-icons/fi component (no fallback warning triangle)`);
  }

  const css = fs.readFileSync(path.join(SRC_ROOT, 'styles/v2-monochrome-system.css'), 'utf8');
  for (const token of ['#0B0C0F', '#17191E', '#202228', '#44464D', '#F5F5F6', '#B4B7BE']) {
    assert(css.includes(token), `v2-monochrome-system.css must define required palette color ${token}`);
  }
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /@media\s*\(max-width:\s*768px\)/);
  assert.match(css, /overflow-wrap:\s*anywhere/);
  assert.match(css, /ntk-p11-specular-waves\.svg/);
});


test('P1 regression: Bearer Token is strictly bound to API origin across port, host, scheme, reset, invalid URL, in-flight abort, and 401/403', async () => {
  setupDomGlobals();
  const prevFetch = global.fetch;
  const seen = [];
  const tokenA = 'mock-origin-a-token-111111';
  const tokenB = 'mock-origin-b-token-222222';
  const tokenC = 'mock-origin-c-token-333333';

  let customHandler = null;
  global.fetch = async (url, options = {}) => {
    seen.push({url, headers: {...(options.headers || {})}});
    if (customHandler) return customHandler(url, options);
    return new Response(JSON.stringify({status: 'OK'}), {status: 200});
  };

  try {
    const apiUrl = await loadSrcEsm('services/api.js');
    const apiMod = await import(apiUrl);

    // 1. Origin A + token A -> request to A carries Authorization: Bearer tokenA
    apiMod.setApiBaseUrl('http://127.0.0.1:18765');
    apiMod.setSessionToken(tokenA);
    assert.equal(apiMod.hasSessionToken(), true);
    assert.equal(apiMod.getSessionTokenOrigin(), 'http://127.0.0.1:18765');
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:18765/api/health');
    assert.equal(seen.at(-1).headers.Authorization, `Bearer ${tokenA}`);

    // Confirm token was NEVER written to sessionStorage (localStorage throws on access)
    for (const val of global.window.sessionStorage._map.values()) {
      assert(!String(val).includes(tokenA), 'sessionStorage must never contain session token');
    }

    // 2. Re-apply same origin (trailing slash normalized) -> keeps token A bound to A
    apiMod.setApiBaseUrl('http://127.0.0.1:18765/');
    assert.equal(apiMod.hasSessionToken(), true);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, `Bearer ${tokenA}`);

    // 3. Switch A -> B (different port) WITHOUT supplying token B -> MUST NOT send token A to B
    apiMod.setApiBaseUrl('http://127.0.0.1:18766');
    assert.equal(apiMod.hasSessionToken(), false);
    assert.equal(apiMod.getSessionTokenOrigin(), '');
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:18766/api/health');
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // 4. Return to Origin A after token was cleared -> MUST NOT auto-restore token A
    apiMod.setApiBaseUrl('http://127.0.0.1:18765');
    assert.equal(apiMod.hasSessionToken(), false);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // 5. Switch A (token A) -> B AND supply token B -> ONLY token B sent to B
    apiMod.setSessionToken(tokenA);
    apiMod.setApiBaseUrl('http://127.0.0.1:18766');
    apiMod.setSessionToken(tokenB);
    assert.equal(apiMod.hasSessionToken(), true);
    assert.equal(apiMod.getSessionTokenOrigin(), 'http://127.0.0.1:18766');
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:18766/api/health');
    assert.equal(seen.at(-1).headers.Authorization, `Bearer ${tokenB}`);

    // 6. Change hostname (127.0.0.1 -> localhost) -> origin change clears token
    apiMod.setApiBaseUrl('http://localhost:18766');
    assert.equal(apiMod.hasSessionToken(), false);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // 7. Change scheme (http -> https) -> origin change clears token
    apiMod.setSessionToken(tokenC);
    assert.equal(apiMod.hasSessionToken(), true);
    apiMod.setApiBaseUrl('https://localhost:18766');
    assert.equal(apiMod.hasSessionToken(), false);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // 8. resetApiBaseUrl() to default origin -> clears token bound to previous origin
    apiMod.setSessionToken(tokenC);
    assert.equal(apiMod.hasSessionToken(), true);
    const restored = apiMod.resetApiBaseUrl();
    assert.equal(restored, 'http://127.0.0.1:18765');
    assert.equal(apiMod.hasSessionToken(), false);
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:18765/api/health');
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // 9. Invalid URLs throw BEFORE mutating state and issue ZERO fetch calls
    apiMod.setSessionToken(tokenA);
    const beforeInvalidCount = seen.length;
    for (const bad of ['', 'not-a-url', 'ftp://127.0.0.1:18765', 'http://127.0.0.1:8765', 'http://user:pass@127.0.0.1:18765']) {
      assert.throws(() => apiMod.setApiBaseUrl(bad));
    }
    assert.equal(seen.length, beforeInvalidCount, 'Invalid URL must not emit any HTTP request');
    assert.equal(apiMod.getApiBaseUrl(), 'http://127.0.0.1:18765');
    assert.equal(apiMod.hasSessionToken(), true);

    // 10. In-flight request on Origin A is aborted cleanly when switching to Origin B
    customHandler = (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        reject(new DOMException('Aborted', 'AbortError'));
      }, {once: true});
    });
    const inFlight = apiMod.api.health();
    apiMod.setApiBaseUrl('http://127.0.0.1:18766');
    await assert.rejects(
      () => inFlight,
      (err) => err instanceof apiMod.ApiError && err.abortedByConfigChange === true && err.timedOut === false,
    );
    customHandler = null;
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:18766/api/health');
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // 11. HTTP 401 and 403 surface clear errors without leaking token value
    apiMod.setSessionToken(tokenB);
    customHandler = async () => new Response(JSON.stringify({error_code: 'UNAUTHORIZED', error_message: 'Bad token'}), {status: 401});
    await assert.rejects(
      () => apiMod.api.listScans(),
      (err) => err instanceof apiMod.ApiError && err.status === 401 && !err.message.includes(tokenB),
    );
    customHandler = async () => new Response(JSON.stringify({error_code: 'SCAN_READ_ONLY', error_message: 'Readonly'}), {status: 403});
    await assert.rejects(
      () => apiMod.api.confirmTrue('scan-1', 'f-1', {actor: 'rev', reason: 'check'}),
      (err) => err instanceof apiMod.ApiError && err.status === 403 && !err.message.includes(tokenB),
    );
  } finally {
    global.fetch = prevFetch;
  }
});

test('P2 regression: strict dataflow validation rejects malformed snippets/raw_trace, falls back cleanly, and reports partial evidence honestly', async () => {
  const fpUrl = await loadSrcEsm('services/findingPresentation.js');
  const fp = await import(fpUrl);

  const validRawTrace = {
    taint_source: ['CliLoc', [{path: 'src/main/java/FileServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 25}}, 'req.getParameter("f")']],
    intermediate_vars: [
      {location: {path: 'src/main/java/FileServlet.java', start: {line: 33, col: 1}, end: {line: 33, col: 30}}, content: 'String p = base + f'},
    ],
    taint_sink: ['CliLoc', [{path: 'src/main/java/FileServlet.java', start: {line: 46, col: 1}, end: {line: 46, col: 20}}, 'new File(p)']],
  };

  // 1. Standard FileServlet.java evidence (Source 28 -> Intermediate 33 -> Sink 46)
  const stdEvidence = {
    snippets: [
      {role: 'finding', path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)'},
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 25}, matched: 'req.getParameter("f")'},
      {role: 'intermediate', path: 'src/main/java/FileServlet.java', start: {line: 33, col: 1}, end: {line: 33, col: 30}, matched: 'String p = base + f'},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46, col: 1}, end: {line: 46, col: 20}, matched: 'new File(p)'},
    ],
    raw_trace: validRawTrace,
  };
  const stdAnalysis = fp.analyzeDataflow(stdEvidence);
  assert.equal(stdAnalysis.source, 'snippets');
  assert.equal(stdAnalysis.completeness, 'COMPLETE');
  assert.deepEqual(stdAnalysis.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['INTERMEDIATE', 33], ['SINK', 46]]);

  // 2. Empty snippets, valid raw_trace -> falls back to raw_trace
  const emptySnipRes = fp.analyzeDataflow({snippets: [], raw_trace: validRawTrace});
  assert.equal(emptySnipRes.source, 'raw_trace');
  assert.equal(emptySnipRes.completeness, 'COMPLETE');
  assert.deepEqual(emptySnipRes.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['INTERMEDIATE', 33], ['SINK', 46]]);

  // 3. Exact Codex counterexample: malformed snippets MUST NOT mask valid raw_trace
  const codexCounterexample = {
    snippets: [
      {role: 'source'},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: '46'}},
    ],
    raw_trace: validRawTrace,
  };
  const frozenBefore = JSON.stringify(codexCounterexample);
  const codexRes = fp.analyzeDataflow(codexCounterexample);
  assert.equal(codexRes.source, 'raw_trace');
  assert.equal(codexRes.completeness, 'COMPLETE');
  assert.equal(codexRes.droppedSnippetCount, 2);
  assert.deepEqual(codexRes.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['INTERMEDIATE', 33], ['SINK', 46]]);
  assert.equal(JSON.stringify(codexCounterexample), frozenBefore, 'Raw evidence must never be mutated');

  // 4. Invalid line numbers in snippets (0, negative, null, NaN, float, string, reversed end/col) -> ALL rejected
  const badSnippets = [
    {role: 'source', path: 'A.java', start: {line: 0}, end: {line: 0}},
    {role: 'source', path: 'A.java', start: {line: -3}, end: {line: 5}},
    {role: 'source', path: 'A.java', start: {line: 10}, end: {line: -1}},
    {role: 'source', path: 'A.java', start: {line: 10}, end: {line: 8}},
    {role: 'intermediate', path: 'A.java', start: {line: null}, end: {line: 12}},
    {role: 'intermediate', path: 'A.java', start: {line: Number.NaN}, end: {line: 12}},
    {role: 'intermediate', path: 'A.java', start: {line: 12.5}, end: {line: 13}},
    {role: 'sink', path: 'A.java', start: {line: '46'}, end: {line: '46'}},
    {role: 'sink', path: 'A.java', start: {line: 46, col: 10}, end: {line: 46, col: 5}},
    {role: 'sink', path: '', start: {line: 46}, end: {line: 46}},
    null,
    42,
  ];
  const allBadRes = fp.analyzeDataflow({snippets: badSnippets, raw_trace: null});
  assert.deepEqual(allBadRes.steps, []);
  assert.equal(allBadRes.completeness, 'NONE');
  assert.equal(allBadRes.hadInvalidInput, true);

  // 5. Partial valid snippet (only Source 28, malformed Sink) + valid complete raw_trace -> uses complete raw_trace
  const partialSnipWithValidRaw = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")'},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: '46'}},
    ],
    raw_trace: validRawTrace,
  });
  assert.equal(partialSnipWithValidRaw.source, 'raw_trace');
  assert.equal(partialSnipWithValidRaw.completeness, 'COMPLETE');
  assert.deepEqual(partialSnipWithValidRaw.steps.map((s) => s.startLine), [28, 33, 46]);

  // 6. Genuine partial evidence (only valid Source 28, no Sink anywhere) -> marked PARTIAL, never fabricates Sink
  const partialOnly = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")'},
    ],
    raw_trace: null,
  });
  assert.equal(partialOnly.completeness, 'PARTIAL');
  assert.equal(partialOnly.hasSource, true);
  assert.equal(partialOnly.hasSink, false);
  assert.equal(partialOnly.steps.length, 1);
  assert.equal(partialOnly.steps[0].tag, 'SOURCE');

  // 7. Malformed raw_trace nodes -> rejected cleanly, never emit empty/broken steps
  const badRawRes = fp.analyzeDataflow({
    snippets: [],
    raw_trace: {
      taint_source: ['CliLoc', [{path: '', start: {line: 0}, end: {line: -1}}, 'bad']],
      intermediate_vars: [{location: {path: 'A.java', start: {line: '12'}}, content: 'x'}, 'not-an-obj'],
      taint_sink: ['CliLoc', [{start: {line: 46}}, 'missing path']],
    },
  });
  assert.deepEqual(badRawRes.steps, []);
  assert.equal(badRawRes.completeness, 'NONE');
  assert.equal(badRawRes.hadInvalidInput, true);

  // 8. Completely empty / invalid top-level inputs -> [] and NONE
  for (const emptyEv of [undefined, null, {}, {snippets: [], raw_trace: null}, 'invalid', 123]) {
    const r = fp.analyzeDataflow(emptyEv);
    assert.deepEqual(r.steps, []);
    assert.equal(r.completeness, 'NONE');
    assert.deepEqual(fp.extractDataflowSteps(emptyEv), []);
  }
});

test('Problem A regression: HTTP 401/403 untrusted error JSON/text never reflects Bearer Token or unknown server error details to UI or logs', async () => {
  setupDomGlobals();
  const prevFetch = global.fetch;
  const prevLog = console.log;
  const prevWarn = console.warn;
  const prevErr = console.error;
  const loggedText = [];
  const captureLog = (...args) => loggedText.push(args.map((a) => String(a)).join(' '));
  console.log = captureLog;
  console.warn = captureLog;
  console.error = captureLog;

  const mockToken = 'MOCK_SECRET_TOKEN';
  let fetchCount = 0;
  let nextResponse = null;
  const seenRequests = [];

  global.fetch = async (url, options = {}) => {
    fetchCount += 1;
    seenRequests.push({url, method: options.method || 'GET', headers: {...(options.headers || {})}});
    return nextResponse();
  };

  try {
    const apiUrl = await loadSrcEsm('services/api.js');
    const apiMod = await import(apiUrl);
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:18765', token: mockToken});

    // 1. Exact prompt counterexample: HTTP 403 JSON with unknown code, message, and detail echoing token
    fetchCount = 0;
    nextResponse = () => new Response(JSON.stringify({
      code: 'UNKNOWN_AUTH_ERROR',
      message: `Authorization failed: Bearer ${mockToken}`,
      detail: mockToken,
    }), {status: 403, headers: {'Content-Type': 'application/json'}});

    await assert.rejects(
      () => apiMod.api.health(),
      (err) => {
        assert(err instanceof apiMod.ApiError);
        assert.equal(err.status, 403);
        assert.match(err.message, /403/);
        assert(!err.message.includes(mockToken), 'Error message must never contain token');
        assert(!err.message.includes('UNKNOWN_AUTH_ERROR'), 'Unknown server error code must not be reflected');
        assert(!err.message.includes('Authorization failed'), 'Untrusted server error message must not be reflected');
        assert(!String(err).includes(mockToken), 'String(error) must never contain token');
        assert(!JSON.stringify(err.payload || {}).includes(mockToken), 'Error payload must be sanitized');
        assert.deepEqual(err.payload, {error_code: 'FORBIDDEN'});
        return true;
      },
    );
    assert.equal(fetchCount, 1, 'Must never auto-retry HTTP 403');

    // 2. Exact Codex re-audit counterexample: HTTP 403 with error_code=FORBIDDEN and token in error_message
    fetchCount = 0;
    nextResponse = () => new Response(JSON.stringify({
      error_code: 'FORBIDDEN',
      error_message: `Rejected header Authorization: Bearer ${mockToken}`,
    }), {status: 403, headers: {'Content-Type': 'application/json'}});

    await assert.rejects(
      () => apiMod.api.listScans(),
      (err) => err instanceof apiMod.ApiError
        && err.status === 403
        && /403/.test(err.message)
        && !err.message.includes(mockToken)
        && !JSON.stringify(err.payload || {}).includes(mockToken),
    );
    assert.equal(fetchCount, 1);

    // 3. HTTP 403 non-JSON proxy/HTML body echoing token
    nextResponse = () => new Response(
      `<html><body>403 Forbidden: Bearer ${mockToken}</body></html>`,
      {status: 403, headers: {'Content-Type': 'text/html'}},
    );
    await assert.rejects(
      () => apiMod.api.health(),
      (err) => err instanceof apiMod.ApiError
        && err.status === 403
        && /403/.test(err.message)
        && !err.message.includes(mockToken)
        && !err.message.includes('<html>'),
    );

    // 4. Allowlisted HTTP 403 codes keep their contract error_code while NEVER echoing server error_message/token
    for (const allowedCode of ['SCAN_READ_ONLY', 'TEST_DATA_ISOLATED', 'CORS_ORIGIN_FORBIDDEN']) {
      nextResponse = () => new Response(JSON.stringify({
        error_code: allowedCode,
        error_message: `Leaked secret ${mockToken}`,
        detail: mockToken,
      }), {status: 403, headers: {'Content-Type': 'application/json'}});

      await assert.rejects(
        () => apiMod.api.scanSummary('scan-1'),
        (err) => err instanceof apiMod.ApiError
          && err.status === 403
          && err.code === allowedCode
          && /403/.test(err.message)
          && !err.message.includes(mockToken)
          && !JSON.stringify(err.payload || {}).includes(mockToken),
      );
    }

    // 5. HTTP 401 with unmapped error_code echoing token -> fixed safe 401 message + sanitized payload
    nextResponse = () => new Response(JSON.stringify({
      error_code: 'UNMAPPED_401_REASON',
      error_message: `Invalid token ${mockToken}`,
      detail: `Bearer ${mockToken}`,
    }), {status: 401, headers: {'Content-Type': 'application/json'}});

    await assert.rejects(
      () => apiMod.api.findingDetail('scan-1', 'finding-1'),
      (err) => err instanceof apiMod.ApiError
        && err.status === 401
        && err.code === 'UNAUTHORIZED'
        && /401/.test(err.message)
        && !err.message.includes(mockToken)
        && !err.message.includes('UNMAPPED_401_REASON')
        && !JSON.stringify(err.payload || {}).includes(mockToken),
    );

    // 6. Non-auth HTTP 500 error still reports API error safely while scrubbing active token
    nextResponse = () => new Response(JSON.stringify({
      error_code: 'INTERNAL_FAILURE',
      error_message: `Debug trace with ${mockToken}`,
    }), {status: 500, headers: {'Content-Type': 'application/json'}});

    await assert.rejects(
      () => apiMod.api.scanSummary('scan-1'),
      (err) => err instanceof apiMod.ApiError
        && err.status === 500
        && err.message.includes('INTERNAL_FAILURE')
        && !err.message.includes(mockToken),
    );

    // 7. Switching to Origin B never sends MOCK_SECRET_TOKEN, and token never enters storage or console logs
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:18766', token: ''});
    nextResponse = () => new Response(JSON.stringify({status: 'OK'}), {status: 200});
    await apiMod.api.health();
    assert.equal(seenRequests.at(-1).url, 'http://127.0.0.1:18766/api/health');
    assert.equal(seenRequests.at(-1).headers.Authorization, undefined);

    for (const val of global.window.sessionStorage._map.values()) {
      assert(!String(val).includes(mockToken), 'sessionStorage must never contain token');
    }
    assert(!loggedText.join('\n').includes(mockToken), 'Frontend console logs must never contain token');
  } finally {
    global.fetch = prevFetch;
    console.log = prevLog;
    console.warn = prevWarn;
    console.error = prevErr;
  }
});

test('Problem B regression: switching API origin mid-flight aborts cleanly, clears stale origin state, discards late responses, and reloads on new origin without leaking tokens or POSTs', async () => {
  setupDomGlobals();
  const prevFetch = global.fetch;
  const requests = [];
  let handler = null;

  global.fetch = async (url, options = {}) => {
    requests.push({url, method: options.method || 'GET', headers: {...(options.headers || {})}});
    return handler(url, options);
  };

  try {
    const apiUrl = await loadSrcEsm('services/api.js');
    const apiMod = await import(apiUrl);

    const tokenB = 'MOCK_ORIGIN_B_TOKEN';
    const tokenA = 'MOCK_ORIGIN_A_TOKEN';
    const configEvents = [];
    const unsubscribe = apiMod.subscribeApiConfig((ev) => configEvents.push(ev));

    // Seed Origin B with tokenB and origin-scoped sessionStorage cache
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:18766', token: tokenB});
    global.window.sessionStorage.setItem('22025523-scan-id', 'scan-origin-b');
    global.window.sessionStorage.setItem('22025523-active-job', 'job-origin-b');
    global.window.sessionStorage.setItem('22025523-live-dataset:http://127.0.0.1:18766:scan-origin-b', '{"stale":true}');
    configEvents.length = 0;

    // 1. Start in-flight GET finding on Origin B, then switch to Origin A WITHOUT token
    handler = (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        reject(new DOMException('Aborted', 'AbortError'));
      }, {once: true});
    });

    const inFlightB = apiMod.api.findingDetail('scan-origin-b', 'finding-b');
    const switchResult = apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:18765', token: ''});

    // Abort is explicitly flagged as abortedByConfigChange (UI hooks ignore it instead of showing load error)
    await assert.rejects(
      () => inFlightB,
      (err) => err instanceof apiMod.ApiError && err.abortedByConfigChange === true,
    );

    // Single atomic config notification; token cleared; origin-scoped sessionStorage wiped
    assert.equal(configEvents.length, 1);
    assert.equal(configEvents[0].origin, 'http://127.0.0.1:18765');
    assert.equal(configEvents[0].previousOrigin, 'http://127.0.0.1:18766');
    assert.equal(configEvents[0].originChanged, true);
    assert.equal(configEvents[0].hasToken, false);
    assert.equal(switchResult.tokenClearedByOriginChange, true);
    assert.equal(apiMod.hasSessionToken(), false);
    assert.equal(global.window.sessionStorage.getItem('22025523-scan-id'), null);
    assert.equal(global.window.sessionStorage.getItem('22025523-active-job'), null);
    assert.equal(global.window.sessionStorage.getItem('22025523-live-dataset:http://127.0.0.1:18766:scan-origin-b'), null);

    // Reload against Origin A without token -> MUST NOT carry tokenB; 401 produces safe auth error
    handler = async () => new Response(JSON.stringify({error_code: 'UNAUTHORIZED', error_message: 'Missing auth'}), {status: 401});
    await assert.rejects(
      () => apiMod.api.findingDetail('scan-origin-b', 'finding-b'),
      (err) => err instanceof apiMod.ApiError && err.status === 401 && !err.message.includes(tokenB),
    );
    assert.equal(requests.at(-1).url, 'http://127.0.0.1:18765/api/scans/scan-origin-b/findings/finding-b');
    assert.equal(requests.at(-1).headers.Authorization, undefined);

    // 2. Atomic origin switch + new token -> single revision bump, only tokenA sent to Origin A, finding loads cleanly
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:18766', token: tokenB});
    configEvents.length = 0;
    const atomicSwitch = apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:18765', token: tokenA});
    assert.equal(configEvents.length, 1, 'Atomic URL+token update must fire exactly one config revision');
    assert.equal(atomicSwitch.hasToken, true);
    assert.equal(apiMod.getSessionTokenOrigin(), 'http://127.0.0.1:18765');

    handler = async () => new Response(JSON.stringify({
      finding_id: 'finding-a',
      scan_id: 'scan-a',
      cwe: 'CWE-22',
      validated_status: 'SUPPORTED',
    }), {status: 200});
    const detailA = await apiMod.api.findingDetail('scan-a', 'finding-a');
    assert.equal(detailA.finding_id, 'finding-a');
    assert.equal(requests.at(-1).url, 'http://127.0.0.1:18765/api/scans/scan-a/findings/finding-a');
    assert.equal(requests.at(-1).headers.Authorization, `Bearer ${tokenA}`);

    // 3. Late-resolving response from old origin (even if transport ignores AbortSignal) MUST be discarded
    let resolveLateA;
    handler = () => new Promise((resolve) => {
      resolveLateA = resolve;
    });
    const stalePromise = apiMod.api.findingDetail('scan-a', 'finding-a');
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:18766', token: ''});
    resolveLateA(new Response(JSON.stringify({finding_id: 'stale-from-origin-a'}), {status: 200}));
    await assert.rejects(
      () => stalePromise,
      (err) => err instanceof apiMod.ApiError && err.abortedByConfigChange === true,
    );

    // 4. Zero POST requests emitted automatically during origin switches
    assert.equal(requests.filter((r) => r.method !== 'GET').length, 0, 'Origin changes must never trigger POST calls');

    // 5. Verify React views wire apiOrigin/apiRevision and ignore abortedByConfigChange & late responses
    for (const rel of [
      'components/layout/AppShell.jsx',
      'pages/Results.jsx',
      'services/scanOverview.js',
      'services/liveScan.js',
      'pages/ReviewPage.jsx',
      'pages/ReportsPage.jsx',
      'pages/HistoryPage.jsx',
      'pages/StatusPage.jsx',
      'pages/Scanner.jsx',
    ]) {
      const code = fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');
      assert(code.includes('abortedByConfigChange'), `${rel} must ignore abortedByConfigChange on origin switch`);
      assert(code.includes('getApiOrigin'), `${rel} must guard async responses against active API origin`);
    }
    const resultsCode = fs.readFileSync(path.join(SRC_ROOT, 'pages/Results.jsx'), 'utf8');
    assert(resultsCode.includes('apiRevision'), 'Results.jsx must reload when apiRevision changes');
    assert(resultsCode.includes('key={`${authSessionScope}:${scanId}:${id}`}'), 'FindingDetail must reset state on apiOrigin/authSessionScope change');

    unsubscribe();
  } finally {
    global.fetch = prevFetch;
  }
});

test('Problem C regression: valid endpoint-only snippets never mask richer raw_trace Intermediate steps, deduplicate cleanly, and never fabricate Intermediates', async () => {
  const fpUrl = await loadSrcEsm('services/findingPresentation.js');
  const fp = await import(fpUrl);

  // Under v2/triage/evidence.py (lines 124-128, 158-159), snippet.sha256 is the FULL-FILE SHA-256
  // of the `.java` file at scan time; all valid snippets of the same file in one scan share `shaFile`.
  const shaFile = 'a'.repeat(64);
  const shaOtherFile = 'b'.repeat(64);
  const fullRawTrace = {
    taint_source: ['CliLoc', [{path: 'src/main/java/FileServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 25}}, 'req.getParameter("f")']],
    intermediate_vars: [
      {location: {path: 'src/main/java/FileServlet.java', start: {line: 33, col: 1}, end: {line: 33, col: 30}}, content: 'String p = base + f'},
    ],
    taint_sink: ['CliLoc', [{path: 'src/main/java/FileServlet.java', start: {line: 46, col: 1}, end: {line: 46, col: 20}}, 'new File(p)']],
  };

  // 1. Exact Codex re-audit counterexample: valid endpoint-only snippets [SOURCE:28, SINK:46] + valid raw_trace [SOURCE:28, INTERMEDIATE:33, SINK:46]
  const codexEndpointOnly = {
    snippets: [
      {role: 'finding', path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)', sha256: shaFile},
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 25}, matched: 'req.getParameter("f")', sha256: shaFile},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46, col: 1}, end: {line: 46, col: 20}, matched: 'new File(p)', sha256: shaFile},
    ],
    raw_trace: fullRawTrace,
  };
  const beforeSnapshot = JSON.stringify(codexEndpointOnly);
  const res1 = fp.analyzeDataflow(codexEndpointOnly);
  assert.equal(res1.completeness, 'COMPLETE');
  assert.equal(res1.hasSource, true);
  assert.equal(res1.hasIntermediate, true);
  assert.equal(res1.hasSink, true);
  assert.equal(res1.droppedSnippetCount, 0);
  assert.deepEqual(
    res1.steps.map((s) => [s.tag, s.path, s.startLine]),
    [
      ['SOURCE', 'src/main/java/FileServlet.java', 28],
      ['INTERMEDIATE', 'src/main/java/FileServlet.java', 33],
      ['SINK', 'src/main/java/FileServlet.java', 46],
    ],
  );
  assert.equal(res1.steps[0].sha256, shaFile, 'Enriched source step must retain full-file snippet SHA-256');
  assert.equal(res1.steps[1].sha256, '', 'Raw-trace-only intermediate must not fabricate a hash');
  assert.equal(res1.steps[2].sha256, shaFile, 'Enriched sink step must retain full-file snippet SHA-256');
  assert.equal(JSON.stringify(codexEndpointOnly), beforeSnapshot, 'Original evidence must never be mutated');

  // 1b. Cross-file flow retains distinct per-file SHA-256 cleanly; same-file differing full-file hashes flag shaConflict.
  const crossFileFlow = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/SourceServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 25}, matched: 'req.getParameter("f")', sha256: shaFile},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46, col: 1}, end: {line: 46, col: 20}, matched: 'new File(p)', sha256: shaOtherFile},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [{path: 'src/main/java/SourceServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 25}}, 'req.getParameter("f")']],
      intermediate_vars: [],
      taint_sink: ['CliLoc', [{path: 'src/main/java/FileServlet.java', start: {line: 46, col: 1}, end: {line: 46, col: 20}}, 'new File(p)']],
    },
  });
  assert.equal(crossFileFlow.steps[0].sha256, shaFile);
  assert.equal(crossFileFlow.steps[1].sha256, shaOtherFile);
  assert.equal(crossFileFlow.steps[0].shaConflict, false);
  assert.equal(crossFileFlow.steps[1].shaConflict, false);

  const sameFileDisagreement = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 25}, matched: 'req.getParameter("f")', sha256: shaFile},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46, col: 1}, end: {line: 46, col: 20}, matched: 'new File(p)', sha256: shaOtherFile},
    ],
    raw_trace: fullRawTrace,
  });
  assert(sameFileDisagreement.steps.every((s) => s.shaConflict === true && s.sha256 === ''), 'Two different full-file SHA-256 values on the same file/version must flag conflict');

  // 2. Multiple valid Intermediates in raw_trace (including same-line SOURCE + INTERMEDIATE)
  const multiIntermRes = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")'},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)'},
    ],
    raw_trace: {
      taint_source: fullRawTrace.taint_source,
      intermediate_vars: [
        {location: {path: 'src/main/java/FileServlet.java', start: {line: 28, col: 16}, end: {line: 28, col: 17}}, content: 'f'},
        {location: {path: 'src/main/java/FileServlet.java', start: {line: 33, col: 1}, end: {line: 33, col: 30}}, content: 'String p = base + f'},
        {location: {path: 'src/main/java/FileServlet.java', start: {line: 40, col: 1}, end: {line: 40, col: 25}}, content: 'String target = p'},
      ],
      taint_sink: fullRawTrace.taint_sink,
    },
  });
  assert.equal(multiIntermRes.completeness, 'COMPLETE');
  assert.deepEqual(
    multiIntermRes.steps.map((s) => [s.tag, s.startLine]),
    [['SOURCE', 28], ['INTERMEDIATE', 28], ['INTERMEDIATE', 33], ['INTERMEDIATE', 40], ['SINK', 46]],
  );

  // 3. Absolute raw_trace paths vs relative snippet paths are merged ONLY when the evidence proves the
  //    source root (snippet raw_path === <root>/<path>). Suffix similarity alone is not proof (see Problem C2 tests).
  const absRawTrace = {
    taint_source: ['CliLoc', [{path: '/tmp/scan_work/repo/src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}}, 'req.getParameter("f")']],
    intermediate_vars: [
      {location: {path: '/tmp/scan_work/repo/src/main/java/FileServlet.java', start: {line: 33}, end: {line: 33}}, content: 'String p = base + f'},
    ],
    taint_sink: ['CliLoc', [{path: '/tmp/scan_work/repo/src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}}, 'new File(p)']],
  };
  const absVsRelRes = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', raw_path: '/tmp/scan_work/repo/src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")', sha256: shaFile},
      {role: 'sink', path: 'src/main/java/FileServlet.java', raw_path: '/tmp/scan_work/repo/src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)', sha256: shaFile},
    ],
    raw_trace: absRawTrace,
  });
  assert.equal(absVsRelRes.steps.length, 3);
  assert.deepEqual(absVsRelRes.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['INTERMEDIATE', 33], ['SINK', 46]]);
  assert.deepEqual(absVsRelRes.steps.map((s) => s.path), Array(3).fill('src/main/java/FileServlet.java'));
  assert.equal(absVsRelRes.steps[1].fileIdentity, 'REPOSITORY_RELATIVE', 'Intermediate mapped through the proven source root');

  const noProvenanceRes = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")', sha256: shaFile},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)', sha256: shaFile},
    ],
    raw_trace: absRawTrace,
  });
  assert.equal(noProvenanceRes.steps.length, 5, 'Without a proven root, suffix-equal paths stay separate');
  for (const step of noProvenanceRes.steps.filter((s) => s.path.startsWith('/tmp/'))) {
    assert.equal(step.sha256, '', 'Unmapped raw-trace step must never borrow a snippet hash');
    assert.equal(step.fileIdentity, 'UNMAPPED_RAW_PATH');
  }

  // 4. Snippets richer than endpoint-only raw_trace -> keeps snippets without dropping Intermediate
  const snipRicherRes = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")'},
      {role: 'intermediate', path: 'src/main/java/FileServlet.java', start: {line: 33}, end: {line: 33}, matched: 'String p = base + f'},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)'},
    ],
    raw_trace: {
      taint_source: fullRawTrace.taint_source,
      intermediate_vars: [],
      taint_sink: fullRawTrace.taint_sink,
    },
  });
  assert.equal(snipRicherRes.source, 'snippets');
  assert.deepEqual(snipRicherRes.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['INTERMEDIATE', 33], ['SINK', 46]]);

  // 5. Both snippets and raw_trace hold distinct valid Intermediate steps -> merged cleanly with zero duplicate endpoints
  const mergedBothRes = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")', sha256: shaFile},
      {role: 'intermediate', path: 'src/main/java/FileServlet.java', start: {line: 30}, end: {line: 30}, matched: 'String clean = f.trim()'},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)', sha256: shaFile},
    ],
    raw_trace: fullRawTrace,
  });
  assert.equal(mergedBothRes.source, 'merged');
  assert.equal(mergedBothRes.completeness, 'COMPLETE');
  assert.equal(mergedBothRes.steps.filter((s) => s.tag === 'SOURCE').length, 1);
  assert.equal(mergedBothRes.steps.filter((s) => s.tag === 'SINK').length, 1);
  assert.equal(mergedBothRes.steps.filter((s) => s.tag === 'INTERMEDIATE').length, 2);

  // 6. Genuine direct Source -> Sink (no Intermediate anywhere) -> COMPLETE, hasIntermediate=false, never fabricates Intermediate
  const directRes = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")'},
      {role: 'sink', path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(req.getParameter("f"))'},
    ],
    raw_trace: {
      taint_source: fullRawTrace.taint_source,
      intermediate_vars: [],
      taint_sink: ['CliLoc', [{path: 'src/main/java/FileServlet.java', start: {line: 46}, end: {line: 46}}, 'new File(req.getParameter("f"))']],
    },
  });
  assert.equal(directRes.completeness, 'COMPLETE');
  assert.equal(directRes.hasIntermediate, false);
  assert.deepEqual(directRes.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['SINK', 46]]);

  // 7. Valid endpoint-only snippets + malformed raw_trace -> keeps valid snippets cleanly
  const validSnipBadRaw = fp.analyzeDataflow({
    snippets: codexEndpointOnly.snippets,
    raw_trace: {
      taint_source: ['CliLoc', [{path: '', start: {line: 0}}, 'bad']],
      intermediate_vars: [{location: {path: 'src/main/java/FileServlet.java', start: {line: '33'}}, content: 'bad'}],
      taint_sink: ['CliLoc', [{start: {line: -5}}, 'bad']],
    },
  });
  assert.equal(validSnipBadRaw.source, 'snippets');
  assert.equal(validSnipBadRaw.completeness, 'COMPLETE');
  assert.equal(validSnipBadRaw.hadInvalidInput, true);
  assert.deepEqual(validSnipBadRaw.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['SINK', 46]]);

  // 8. Partial across both sources (Source 28 in snippets + Intermediate 33 in raw_trace, no Sink) -> PARTIAL
  const partialMerged = fp.analyzeDataflow({
    snippets: [
      {role: 'source', path: 'src/main/java/FileServlet.java', start: {line: 28}, end: {line: 28}, matched: 'req.getParameter("f")'},
    ],
    raw_trace: {
      taint_source: null,
      intermediate_vars: fullRawTrace.intermediate_vars,
      taint_sink: null,
    },
  });
  assert.equal(partialMerged.completeness, 'PARTIAL');
  assert.equal(partialMerged.hasSource, true);
  assert.equal(partialMerged.hasIntermediate, true);
  assert.equal(partialMerged.hasSink, false);
  assert.deepEqual(partialMerged.steps.map((s) => [s.tag, s.startLine]), [['SOURCE', 28], ['INTERMEDIATE', 33]]);
});
