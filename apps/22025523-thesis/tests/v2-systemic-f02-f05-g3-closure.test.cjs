// Systemic adversarial verification for Mechanism A (Health Evidence Lifecycle: F02-A, F02-B & blind spots)
// and Mechanism B (REST Wire Data Integrity & Durable Normalized Propagation: F05-A, G3-F01 & sibling blind spots).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const esbuild = require('esbuild');

const APP_ROOT = path.resolve(__dirname, '..');

async function loadModule(relPath) {
  const full = path.join(APP_ROOT, relPath);
  const built = await esbuild.build({
    entryPoints: [full],
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    write: false,
    mainFields: ['module', 'main'],
    plugins: [{
      name: 'stub-react-router',
      setup(build) {
        build.onResolve({filter: /^(react|react-router-dom)$/}, (args) => ({path: args.path, namespace: 'stub'}));
        build.onLoad({filter: /.*/, namespace: 'stub'}, () => ({
          contents: 'export const useEffect = () => {}; export const useMemo = (fn) => fn(); export const useState = (v) => [v, () => {}]; export const useSearchParams = () => [new URLSearchParams()];',
          loader: 'js',
        }));
      },
    }],
  });
  const code = built.outputFiles[0].text;
  return import(`data:text/javascript;base64,${Buffer.from(code, 'utf8').toString('base64')}`);
}

function loadRawEsm(relPath) {
  const full = path.join(APP_ROOT, relPath);
  const code = fs.readFileSync(full, 'utf8');
  return import(`data:text/javascript;base64,${Buffer.from(code, 'utf8').toString('base64')}`);
}

function mkStorage() {
  const map = new Map();
  return {
    _map: map,
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(String(k), String(v)); },
    removeItem(k) { map.delete(String(k)); },
    clear() { map.clear(); },
  };
}

function createFakeClock(startMs = Date.parse('2026-11-25T12:00:00.000Z')) {
  let current = startMs;
  let nextId = 1;
  const timers = new Map();
  return {
    now: () => current,
    setTimer(fn, ms) {
      const id = nextId++;
      timers.set(id, {id, fn, at: current + Math.max(0, ms)});
      return id;
    },
    clearTimer(id) {
      timers.delete(id);
    },
    activeTimerIds() {
      return [...timers.keys()];
    },
    advance(ms) {
      current += ms;
      while (true) {
        const due = [...timers.values()].filter((t) => t.at <= current).sort((a, b) => a.at - b.at || a.id - b.id);
        if (due.length === 0) break;
        const first = due[0];
        timers.delete(first.id);
        first.fn();
      }
    },
  };
}

async function withRawHttpServer(handler, fn) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const {port} = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    return await fn(baseUrl);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('Mechanism A (F02-A): authenticated expired probe replay across reload -> AUTH_REQUIRED (HTTP 200 and HTTP 401) -> re-entry, token isolation, and exact timer preservation', async () => {
  const prevWindow = global.window;
  const prevSession = global.sessionStorage;
  const storage = mkStorage();
  global.sessionStorage = storage;
  global.window = {
    location: {origin: 'http://127.0.0.1:19850', hostname: '127.0.0.1'},
    sessionStorage: storage,
    setTimeout: global.setTimeout,
    clearTimeout: global.clearTimeout,
  };

  try {
    const apiMod = await loadRawEsm('src/services/api.js');
    const hm = await loadModule('src/services/healthMonitor.js');
    const fp = await loadRawEsm('src/services/findingPresentation.js');

    const TOKEN_A = 'operator-secret-token-alpha-9911';
    const TOKEN_B = 'operator-secret-token-beta-7733';
    apiMod.setApiBaseUrl('http://127.0.0.1:19851');

    const clock = createFakeClock(Date.parse('2026-11-25T13:00:00.000Z'));
    const t0 = clock.now();
    const expiredBody = {
      status: 'OK',
      service: 'v2-api',
      api_version: '2.0',
      contract_schema: 'v2',
      auth_required: true,
      authenticated: true,
      checked_at: new Date(t0).toISOString(),
      opengrep: {
        available: true,
        runtime_verified: true,
        probe_status: 'VERIFIED',
        health_state: 'VERIFIED',
        verification_level: 'SCAN_VERIFIED',
        probe_in_progress: false,
        deferred_by_active_scan: false,
        binary_present: true,
        version: '1.25.0',
        ttl_seconds: 2,
        probed_at: new Date(t0).toISOString(),
        expires_at: new Date(t0 + 2000).toISOString(),
        process_instance_id: 'proc-auth-1',
        probe_execution_identity_sha256: 'a'.repeat(64),
      },
      ollama: {reachable: true, model_installed: true, model: 'qwen3.5:9b'},
      rules: {available: true, name: 'v2-java', priority_cwes: ['CWE-22', 'CWE-89']},
      git_available: true,
      degraded_reasons: [],
    };

    // 1. Authenticate with TOKEN_A, receive valid 2s probe, let it expire passively.
    apiMod.setSessionToken(TOKEN_A);
    let currentAuthMode = 'VERIFIED_BODY';
    const fetchHealth = async () => {
      if (currentAuthMode === 'AUTH_200') {
        return {status: 'AUTH_REQUIRED', auth_required: true, authenticated: false, degraded_reasons: ['AUTH_REQUIRED']};
      }
      if (currentAuthMode === 'AUTH_401') {
        throw new apiMod.ApiError('Thiếu hoặc sai API Bearer Token phiên (HTTP 401).', {status: 401, payload: {error_code: 'UNAUTHORIZED'}});
      }
      return expiredBody;
    };

    const mon1 = hm.createHealthMonitor({
      fetchHealth,
      now: clock.now,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
      retryDelaysMs: [],
    });
    await mon1.checkNow({force: true});
    assert.equal(fp.classifyBackendHealthState(mon1.getSnapshot().backend, {nowMs: clock.now()}).ogInfo.healthState, 'VERIFIED');

    // Assert zero raw Bearer token leakage in sessionStorage
    for (const [k, v] of storage._map.entries()) {
      assert.equal(String(k).includes(TOKEN_A), false);
      assert.equal(String(v).includes(TOKEN_A), false, 'Bearer token must NEVER appear in sessionStorage');
    }

    clock.advance(2500);
    assert.equal(mon1.getSnapshot().backend.ttlExpired, true);
    assert.equal(fp.classifyBackendHealthState(mon1.getSnapshot().backend, {nowMs: clock.now()}).ogInfo.healthState, 'EXPIRED');
    mon1.dispose();

    // 2. Simulate full browser reload: RAM token cleared, only sessionStorage survives.
    apiMod.setSessionToken('');
    const mon2 = hm.createHealthMonitor({
      fetchHealth,
      now: clock.now,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
      retryDelaysMs: [],
    });

    // 2a. First load receives HTTP 200 AUTH_REQUIRED
    currentAuthMode = 'AUTH_200';
    await mon2.checkNow({force: true});
    assert.equal(mon2.getSnapshot().backend.status, 'AUTH_REQUIRED');

    // Re-enter exact same TOKEN_A; server replays exact expired probe body (even with clock still before server's fake expires_at if clock were rewound, or normal elapsed time)
    apiMod.setSessionToken(TOKEN_A);
    currentAuthMode = 'VERIFIED_BODY';
    await mon2.checkNow({force: true});
    const afterReentry200 = fp.classifyBackendHealthState(mon2.getSnapshot().backend, {nowMs: clock.now()});
    assert.equal(afterReentry200.ogInfo.isVerified, false, 'F02-A (HTTP 200 AUTH_REQUIRED): expired probe MUST NOT resurrect VERIFIED');
    assert.equal(afterReentry200.ogInfo.healthState, 'EXPIRED');

    // 2b. Repeat with HTTP 401 AUTH_REQUIRED path
    apiMod.setSessionToken('');
    currentAuthMode = 'AUTH_401';
    await mon2.checkNow({force: true});
    assert.equal(mon2.getSnapshot().backend.status, 'AUTH_REQUIRED');

    apiMod.setSessionToken(TOKEN_A);
    currentAuthMode = 'VERIFIED_BODY';
    await mon2.checkNow({force: true});
    const afterReentry401 = fp.classifyBackendHealthState(mon2.getSnapshot().backend, {nowMs: clock.now()});
    assert.equal(afterReentry401.ogInfo.isVerified, false, 'F02-A (HTTP 401): expired probe MUST NOT resurrect VERIFIED');
    assert.equal(afterReentry401.ogInfo.healthState, 'EXPIRED');

    // 3. Even if backend sends a spoofed future expires_at on the EXACT same proof signature after reload:
    const spoofedReplay = {
      ...expiredBody,
      checked_at: new Date(clock.now()).toISOString(),
      opengrep: {
        ...expiredBody.opengrep,
        // Exact same probed_at + expires_at -> same proof signature (clamped in ledger to t0 + 2000 <= clock.now())
        ttl_seconds: 600,
      },
    };
    const mon3 = hm.createHealthMonitor({
      fetchHealth: async () => spoofedReplay,
      now: clock.now,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
      retryDelaysMs: [],
    });
    await mon3.checkNow({force: true});
    assert.equal(fp.classifyBackendHealthState(mon3.getSnapshot().backend, {nowMs: clock.now()}).ogInfo.isVerified, false, 'Replayed signature with mutated ttl_seconds must stay EXPIRED');
    mon3.dispose();

    // 4. Genuine brand-new probe on TOKEN_A MUST recover cleanly to VERIFIED!
    const tNew = clock.now();
    const freshProbe = {
      ...expiredBody,
      checked_at: new Date(tNew).toISOString(),
      opengrep: {
        ...expiredBody.opengrep,
        probed_at: new Date(tNew).toISOString(),
        expires_at: new Date(tNew + 5000).toISOString(),
        ttl_seconds: 5,
      },
    };
    const mon4 = hm.createHealthMonitor({
      fetchHealth: async () => freshProbe,
      now: clock.now,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
      retryDelaysMs: [],
    });
    await mon4.checkNow({force: true});
    assert.equal(fp.classifyBackendHealthState(mon4.getSnapshot().backend, {nowMs: clock.now()}).ogInfo.healthState, 'VERIFIED', 'Brand-new fresh probe MUST recover VERIFIED');

    // 5. Exact TTL timer handle preservation when an older server snapshot arrives during same-scope refresh!
    const timerIdsBefore = clock.activeTimerIds();
    assert.equal(timerIdsBefore.length, 1, 'Exactly one TTL timer should be armed');
    const originalTimerId = timerIdsBefore[0];

    let returnOlder = false;
    const mon5 = hm.createHealthMonitor({
      fetchHealth: async () => (returnOlder ? expiredBody : freshProbe),
      now: clock.now,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
      retryDelaysMs: [],
    });
    mon4.dispose();
    await mon5.checkNow({force: true});
    const armedIds = clock.activeTimerIds();
    assert.equal(armedIds.length, 1);
    const preservedTimerHandle = armedIds[0];
    assert.notEqual(preservedTimerHandle, originalTimerId);

    returnOlder = true;
    await mon5.checkNow({force: true, preserveStatus: true});
    assert.deepEqual(clock.activeTimerIds(), [preservedTimerHandle], 'Exact active TTL timer handle must be preserved uninterrupted when older snapshot is ignored');
    assert.equal(mon5.getSnapshot().meta.staleSnapshotIgnored, true);
    assert.equal(fp.classifyBackendHealthState(mon5.getSnapshot().backend, {nowMs: clock.now()}).ogInfo.healthState, 'VERIFIED');

    // 6. Token switch isolation: TOKEN_B gets its own ledger scope (zero leakage of TOKEN_B into storage)
    apiMod.setSessionToken(TOKEN_B);
    for (const [k, v] of storage._map.entries()) {
      assert.equal(String(k).includes(TOKEN_B), false);
      assert.equal(String(v).includes(TOKEN_B), false);
    }
    mon5.dispose();
    mon2.dispose();
  } finally {
    global.window = prevWindow;
    global.sessionStorage = prevSession;
  }
});

test('Mechanism A (F02-B & blind spots): checked_at < probed_at, malformed checked_at, expires_at - checked_at > ttl, and duplicate /api/health wire keys all fail closed', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const hm = await loadModule('src/services/healthMonitor.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');

  const nowMs = Date.parse('2026-11-25T14:00:00.000Z');
  const baseOg = {
    available: true,
    runtime_verified: true,
    probe_status: 'VERIFIED',
    health_state: 'VERIFIED',
    verification_level: 'SCAN_VERIFIED',
    probe_in_progress: false,
    deferred_by_active_scan: false,
    binary_present: true,
    version: '1.25.0',
    ttl_seconds: 60,
    probed_at: new Date(nowMs - 1000).toISOString(),
    expires_at: new Date(nowMs + 59000).toISOString(),
  };

  // Positive control: probed_at <= checked_at < expires_at -> VERIFIED
  const validRes = hm.classifyHealthResponse(
    {status: 'OK', checked_at: new Date(nowMs).toISOString(), opengrep: baseOg, degraded_reasons: []},
    {nowMs, receivedAtMs: nowMs},
  );
  assert.equal(validRes.status, 'CONNECTED');
  assert.equal(validRes.opengrepVerified, true);
  assert.equal(fp.classifyBackendHealthState(validRes, {nowMs}).ogInfo.healthState, 'VERIFIED');

  // F02-B: checked_at strictly earlier than probed_at -> NEVER VERIFIED
  const f02bRes = hm.classifyHealthResponse(
    {
      status: 'OK',
      checked_at: new Date(nowMs - 5000).toISOString(),
      opengrep: {
        ...baseOg,
        probed_at: new Date(nowMs).toISOString(),
        expires_at: new Date(nowMs + 60000).toISOString(),
      },
      degraded_reasons: [],
    },
    {nowMs, receivedAtMs: nowMs},
  );
  assert.equal(f02bRes.opengrepVerified, false, 'F02-B: checked_at < probed_at MUST NOT be VERIFIED');
  assert.equal(f02bRes.status, 'DEGRADED');
  assert.equal(fp.classifyBackendHealthState(f02bRes, {nowMs}).ogInfo.isVerified, false);

  // Blind spot: malformed checked_at string -> NEVER silently ignore and promote VERIFIED
  const badCheckedAtRes = hm.classifyHealthResponse(
    {status: 'OK', checked_at: 'not-an-iso-date', opengrep: baseOg, degraded_reasons: []},
    {nowMs, receivedAtMs: nowMs},
  );
  assert.equal(badCheckedAtRes.opengrepVerified, false, 'Malformed checked_at MUST NOT promote VERIFIED');
  assert.equal(badCheckedAtRes.serverCheckedAtMalformed, true);
  assert.equal(fp.classifyBackendHealthState(badCheckedAtRes, {nowMs}).ogInfo.isVerified, false);

  // Blind spot: probed_at missing and (expires_at - checked_at) > ttl_seconds * 1000 -> contradictory
  const impossibleTtlWindow = hm.classifyHealthResponse(
    {
      status: 'OK',
      checked_at: new Date(nowMs).toISOString(),
      opengrep: {
        ...baseOg,
        probed_at: null,
        ttl_seconds: 10,
        expires_at: new Date(nowMs + 60000).toISOString(),
      },
      degraded_reasons: [],
    },
    {nowMs, receivedAtMs: nowMs},
  );
  assert.equal(impossibleTtlWindow.opengrepVerified, false, 'expires_at - checked_at > ttl_seconds MUST fail closed');

  // Blind spot: duplicate wire keys on root /api/health (`"opengrep"` or `"checked_at"`)
  const dupRootRaw = `{"status":"OK","checked_at":"${new Date(nowMs - 5000).toISOString()}","checked_at":"${new Date(nowMs).toISOString()}","opengrep":${JSON.stringify(baseOg)},"degraded_reasons":[]}`;
  const dupRootParsed = apiMod.parseJsonWithWireIntegrity(dupRootRaw);
  const dupRootRes = hm.classifyHealthResponse(dupRootParsed, {nowMs, receivedAtMs: nowMs});
  assert.equal(dupRootRes.opengrepVerified, false, 'Duplicate checked_at wire key on /api/health must fail closed');
  assert.equal(dupRootRes.healthWireMalformed, true);

  // Blind spot: duplicate wire key inside opengrep (`"probe_status":"FAILED","probe_status":"VERIFIED"`)
  const dupOgRaw = `{"status":"OK","checked_at":"${new Date(nowMs).toISOString()}","opengrep":{"available":true,"runtime_verified":true,"probe_status":"FAILED","probe_status":"VERIFIED","health_state":"VERIFIED","verification_level":"SCAN_VERIFIED","probe_in_progress":false,"binary_present":true,"ttl_seconds":60,"probed_at":"${new Date(nowMs - 1000).toISOString()}","expires_at":"${new Date(nowMs + 59000).toISOString()}"},"degraded_reasons":[]}`;
  const dupOgParsed = apiMod.parseJsonWithWireIntegrity(dupOgRaw);
  const dupOgRes = hm.classifyHealthResponse(dupOgParsed, {nowMs, receivedAtMs: nowMs});
  assert.equal(dupOgRes.opengrepVerified, false, 'Duplicate probe_status wire key inside opengrep must fail closed');
  // Even after shallow-copying or JSON round-tripping sanitized backend.health.opengrep, malformed flag survives!
  const copiedOg = JSON.parse(JSON.stringify(dupOgRes.health.opengrep));
  assert.equal(fp.describeOpengrepHealth(copiedOg, null, {nowMs}).isVerified, false);
});

test('Mechanism B (F05-A, G3-F01 & sibling REST integrity): duplicate containers, Unicode escapes, copy/JSON durability, tamper resistance, liveScan/reportModel, and byte-identical report downloads', async () => {
  const prevWindow = global.window;
  const prevSession = global.sessionStorage;
  const storage = mkStorage();
  global.sessionStorage = storage;
  global.window = {
    location: {origin: 'http://127.0.0.1:19860', hostname: '127.0.0.1'},
    sessionStorage: storage,
    setTimeout: global.setTimeout,
    clearTimeout: global.clearTimeout,
  };

  try {
    const apiMod = await loadRawEsm('src/services/api.js');
    const jm = await loadRawEsm('src/services/jobModel.js');
    const lsp = await loadModule('src/components/scanner/liveStagePresentation.js');
    const fp = await loadRawEsm('src/services/findingPresentation.js');
    const ls = await loadModule('src/services/liveScan.js');
    const rm = await loadRawEsm('src/services/reportModel.js');

    // 1. F05-A: Unicode-escaped duplicate `stages` container (`"sta\u0067es":[], "stages":[...]`)
    const dupStagesRaw = '{"job_id":"j-dup","scan_id":"s-dup","state":"COMPLETED","sta\\u0067es":[],"stages":[{"stage_number":5,"stage_key":"CITATION_VALIDATION","state":"COMPLETED","summary_metadata":{"total_checked":4,"matched_count":4,"invalid_count":0,"not_verified_count":0}}]}';
    const dupStagesJob = apiMod.parseJsonWithWireIntegrity(dupStagesRaw);
    const resolvedDupStages = jm.resolveStages(dupStagesJob, {hasScanId: true});
    const stage5Dup = resolvedDupStages.find((s) => s.number === 5);
    assert.ok(stage5Dup.wireIntegrity?.conflictingStagesContainer, 'jobModel must materialize conflictingStagesContainer');
    for (const variant of [
      ['original', stage5Dup],
      ['stageShallowCopy', {...stage5Dup}],
      ['summaryShallowCopy', {...stage5Dup, summary: {...stage5Dup.summary}}],
      ['jsonRoundTrip', JSON.parse(JSON.stringify(stage5Dup))],
    ]) {
      for (const mode of ['LIVE', 'PLAYBACK']) {
        const tel = lsp.resolveStage05CitationTelemetry({mode, stage: variant[1]});
        assert.notEqual(tel.aggregateStatus, 'ALL_MATCHED', `Duplicate stages (${mode} ${variant[0]}) MUST NEVER be ALL_MATCHED`);
        assert.equal(tel.aggregateStatus, 'CONFLICT', `Duplicate stages (${mode} ${variant[0]}) must be CONFLICT`);
      }
    }

    // 2. F05-A: Wire precision-loss decimal `"total_checked":4.0000000000000001` durability across copy / JSON round-trip
    const wireDecRaw = '{"job_id":"j-dec","scan_id":"s-dec","state":"COMPLETED","stages":[{"stage_number":5,"stage_key":"CITATION_VALIDATION","state":"COMPLETED","summary_metadata":{"total_checked":4.0000000000000001,"matched_count":4,"invalid_count":0,"not_verified_count":0}}]}';
    const wireDecJob = apiMod.parseJsonWithWireIntegrity(wireDecRaw);
    const stage5Dec = jm.resolveStages(wireDecJob, {hasScanId: true}).find((s) => s.number === 5);
    for (const [label, candidate] of [
      ['original', stage5Dec],
      ['stageShallowCopy', {...stage5Dec}],
      ['summaryShallowCopy', {...stage5Dec, summary: {...stage5Dec.summary}}],
      ['jsonRoundTrip', JSON.parse(JSON.stringify(stage5Dec))],
    ]) {
      for (const mode of ['LIVE', 'PLAYBACK']) {
        const tel = lsp.resolveStage05CitationTelemetry({mode, stage: candidate});
        assert.equal(tel.aggregateStatus, 'MALFORMED', `Wire decimal (${mode} ${label}) must remain MALFORMED`);
      }
      const countCheck = apiMod.readStrictWireSafeInt(candidate.summary, 'total_checked');
      assert.equal(countCheck.valid, false, `readStrictWireSafeInt (${label}) must remain invalid`);
      assert.equal(countCheck.reason, 'NON_INTEGER_WIRE_NUMBER');
    }

    // 3. Anti-tamper: injected `{wireIntegrity: {valid: true}}` must NEVER override invalid data
    const tamperedStage = {
      ...stage5Dec,
      wireIntegrity: {valid: true, conflict: false, malformed: false},
    };
    assert.equal(lsp.resolveStage05CitationTelemetry({mode: 'LIVE', stage: tamperedStage}).aggregateStatus, 'MALFORMED', 'Taint-only sentinel must resist forged wireIntegrity.valid=true');

    // 4. Positive control: clean valid Stage 05 stays ALL_MATCHED with zero extra sentinel fields
    const cleanRaw = '{"job_id":"j-ok","scan_id":"s-ok","state":"COMPLETED","stages":[{"stage_number":5,"stage_key":"CITATION_VALIDATION","state":"COMPLETED","summary_metadata":{"total_checked":4,"matched_count":4,"invalid_count":0,"not_verified_count":0}}]}';
    const stage5Clean = jm.resolveStages(apiMod.parseJsonWithWireIntegrity(cleanRaw), {hasScanId: true}).find((s) => s.number === 5);
    assert.equal(stage5Clean.wireIntegrity, undefined);
    assert.equal(Object.hasOwn(stage5Clean.summary, '__wireIntegrity'), false);
    assert.equal(lsp.resolveStage05CitationTelemetry({mode: 'LIVE', stage: stage5Clean}).aggregateStatus, 'ALL_MATCHED');
    assert.equal(lsp.resolveStage05CitationTelemetry({mode: 'PLAYBACK', stage: stage5Clean}).aggregateStatus, 'ALL_MATCHED');

    // 5. G3-F01: duplicate `opengrep_paths_telemetry_status` (direct & Unicode-escaped & parent containers)
    const g3Cases = [
      ['status-duplicate', '{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"MISSING_PATHS_TELEMETRY","opengrep_paths_telemetry_status":"VERIFIED"}'],
      ['status-unicode-dup', '{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_stat\\u0075s":"MISSING_PATHS_TELEMETRY","opengrep_paths_telemetry_status":"VERIFIED"}'],
      ['scanned-decimal', '{"java_files_inventory":498,"java_files_opengrep_scanned":389.00000000000001,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"}'],
      ['duplicate-manifest-container', '{"scan_manifest":{"java_files_inventory":10,"java_files_opengrep_scanned":1,"java_files_opengrep_ignored":9,"opengrep_paths_telemetry_status":"MISSING_PATHS_TELEMETRY"},"scan_manifest":{"java_files_inventory":19,"java_files_opengrep_scanned":19,"java_files_opengrep_ignored":0,"opengrep_paths_telemetry_status":"VERIFIED"}}'],
      ['duplicate-paths-container', '{"scan_manifest":{"java_files_inventory":19,"java_files_opengrep_scanned":19,"java_files_opengrep_ignored":0,"opengrep_paths_telemetry_status":"VERIFIED","paths":{"scanned_count":1},"paths":{"scanned_count":19}}}'],
    ];
    for (const [name, raw] of g3Cases) {
      const parsed = apiMod.parseJsonWithWireIntegrity(raw);
      const res = fp.resolveJavaFileCounts(parsed);
      assert.equal(res.hasVerifiedScanned, false, `G3 case ${name} MUST NOT report hasVerifiedScanned=true`);
      assert.equal(res.hasInvalidFields, true, `G3 case ${name} must report hasInvalidFields=true`);
      assert.equal(res.scannedCount, null, `G3 case ${name} must drop scannedCount to null`);
      if (name !== 'scanned-decimal') {
        assert.equal(res.isInconsistent, true, `G3 case ${name} must report isInconsistent=true`);
      }
    }

    // 6. G3 positive controls: JVL (19/19/0) and WebGoat (498/389/109)
    const jvlCov = fp.resolveJavaFileCounts(apiMod.parseJsonWithWireIntegrity('{"java_files_inventory":19,"java_files_opengrep_scanned":19,"java_files_opengrep_ignored":0,"opengrep_paths_telemetry_status":"VERIFIED"}'));
    assert.equal(jvlCov.hasVerifiedScanned, true);
    assert.equal(jvlCov.isInconsistent, false);
    assert.equal(jvlCov.inventoryCount, 19);
    assert.equal(jvlCov.scannedCount, 19);
    assert.equal(jvlCov.ignoredCount, 0);

    const webgoatCov = fp.resolveJavaFileCounts(apiMod.parseJsonWithWireIntegrity('{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"}'));
    assert.equal(webgoatCov.hasVerifiedScanned, true);
    assert.equal(webgoatCov.isInconsistent, false);
    assert.equal(webgoatCov.inventoryCount, 498);
    assert.equal(webgoatCov.scannedCount, 389);
    assert.equal(webgoatCov.ignoredCount, 109);

    // 7. Sibling REST integrity: liveScan & reportModel & raw byte-identical report download over loopback HTTP
    const dupSummary = apiMod.parseJsonWithWireIntegrity('{"scan_id":"s1","total_findings":1,"by_validated_status":{"SUPPORTED":9,"SUPPORTED":1,"REFUTED":0,"UNDETERMINED":0},"by_human_review_state":{"OPEN":1,"CONFIRMED_TRUE":0,"CONFIRMED_FALSE":0}}');
    const cleanPage = apiMod.parseJsonWithWireIntegrity('{"scan_id":"s1","total_count":1,"total_matching":1,"page":1,"page_size":50,"total_pages":1,"has_more":false,"findings":[{"finding_id":"f1","validated_status":"SUPPORTED","human_review_state":"OPEN"}]}');
    const scanCheck = ls.validateScanCountersAndPagination(dupSummary, cleanPage);
    assert.equal(scanCheck.valid, false);
    assert.equal(scanCheck.reason, 'DUPLICATE_WIRE_KEY');

    const dupReport = apiMod.parseJsonWithWireIntegrity('{"scan_summary":{"scan_id":"other"},"scan_summary":{"scan_id":"s1","total_findings":0},"findings":[]}');
    const repCheck = rm.validateReportForScan(dupReport, 's1');
    assert.equal(repCheck.valid, false);
    assert.equal(repCheck.reason, 'DUPLICATE_WIRE_KEY');

    // Byte-identical report export preservation over raw loopback HTTP
    const rawReportText = JSON.stringify({
      report_schema: 'v2-report',
      data_origin: 'REAL_SCAN',
      scan_provenance: {origin: 'REAL_SCAN', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
      scan_summary: {
        scan_id: 'scan-byte-1',
        data_origin: 'REAL_SCAN',
        scan_provenance: {origin: 'REAL_SCAN', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
        total_findings: 0,
        java_files_inventory: 19,
        java_files_opengrep_scanned: 19,
        java_files_opengrep_ignored: 0,
        opengrep_paths_telemetry_status: 'VERIFIED',
        by_validated_status: {SUPPORTED: 0, REFUTED: 0, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        by_cwe: {},
      },
      findings: [],
      audit_trail: {events: [], rejected_decisions: [], events_count: 0, rejected_decisions_count: 0},
    });
    const expectedSha = crypto.createHash('sha256').update(rawReportText, 'utf8').digest('hex');

    await withRawHttpServer((req, res) => {
      if (req.url === '/api/scans/scan-byte-1/report') {
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(rawReportText);
        return;
      }
      res.writeHead(404, {'Content-Type': 'application/json'});
      res.end('{"error_code":"NOT_FOUND"}');
    }, async (baseUrl) => {
      apiMod.setApiBaseUrl(baseUrl);
      const reportObj = await apiMod.api.report('scan-byte-1');
      assert.equal(rm.validateReportForScan(reportObj, 'scan-byte-1').valid, true);
      const vm = rm.buildReportViewModel(reportObj, {expectedScanId: 'scan-byte-1'});
      assert.equal(vm.isVerifiedRealScan, true);
      const reserialized = JSON.stringify(reportObj);
      const actualSha = crypto.createHash('sha256').update(reserialized, 'utf8').digest('hex');
      assert.equal(actualSha, expectedSha, 'Clean report object from api.report() must remain 100% byte-identical with zero injected properties');
    });
  } finally {
    global.window = prevWindow;
    global.sessionStorage = prevSession;
  }
});
