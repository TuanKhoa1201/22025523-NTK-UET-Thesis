// Deterministic invariant verification suite for:
// 1. P1-HEALTH-01 class: persistent deterministic observation ordering across reload (including
//    2, 3+ probes in the exact same millisecond, with/without probed_at, timer preservation,
//    exact deadline expiry, legacy & corrupted ledger handling, storage errors, scope isolation).
// 2. P1-COVERAGE-01 class: complete nested coverage evidence tree REST integrity (invalidIntFields
//    at arbitrary depth/arrays, reserved metadata, duplicates, wrong types, precision loss,
//    exact 4-way wire/normalized/shallow/JSON parity, History/Findings/Reports parity, positive
//    controls JVL 19/19/0 & WebGoat 498/389/109, timing floats, and unrelated sibling isolation).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const esbuild = require('esbuild');

const appDir = path.resolve(__dirname, '..');
let moduleCounter = 0;

async function loadRawEsm(relPath) {
  const full = path.join(appDir, relPath);
  const src = fs.readFileSync(full, 'utf8');
  moduleCounter += 1;
  const dataUrl = `data:text/javascript;base64,${Buffer.from(`${src}\n// #${moduleCounter}`).toString('base64')}`;
  return import(dataUrl);
}

async function loadModule(relPath) {
  const built = await esbuild.build({
    entryPoints: [path.join(appDir, relPath)],
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    write: false,
    mainFields: ['module', 'main'],
  });
  moduleCounter += 1;
  const dataUrl = `data:text/javascript;base64,${Buffer.from(`${built.outputFiles[0].text}\n// #${moduleCounter}`).toString('base64')}`;
  return import(dataUrl);
}

async function loadSharedApiAndHealth() {
  const built = await esbuild.build({
    stdin: {
      contents: `
        export * as apiMod from './src/services/api.js';
        export * as hm from './src/services/healthMonitor.js';
      `,
      resolveDir: appDir,
      loader: 'js',
    },
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    write: false,
    mainFields: ['module', 'main'],
  });
  moduleCounter += 1;
  const dataUrl = `data:text/javascript;base64,${Buffer.from(`${built.outputFiles[0].text}\n// #${moduleCounter}`).toString('base64')}`;
  return import(dataUrl);
}

function mkStorage(overrides = {}) {
  const map = new Map();
  return {
    _map: map,
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(k, String(v)); },
    removeItem(k) { map.delete(k); },
    ...overrides,
  };
}

async function withWindow(sessionStorageDescriptor, fn) {
  const prevWin = globalThis.window;
  const win = {};
  Object.defineProperty(win, 'sessionStorage', {configurable: true, enumerable: true, ...sessionStorageDescriptor});
  globalThis.window = win;
  try {
    return await fn(win);
  } finally {
    if (prevWin === undefined) delete globalThis.window;
    else globalThis.window = prevWin;
  }
}

const iso = (ms) => new Date(ms).toISOString();

function makeHealthBody({
  status = 'OK',
  checkedAt,
  proc = 'proc-same-ms',
  exec = 'a',
  probedAt,
  expiresAt,
  ttl = 30,
  ogPatch = {},
}) {
  return {
    status,
    ...(checkedAt !== undefined ? {checked_at: iso(checkedAt)} : {}),
    opengrep: {
      available: true,
      runtime_verified: true,
      probe_status: 'VERIFIED',
      health_state: 'VERIFIED',
      verification_level: 'SCAN_VERIFIED',
      process_instance_id: proc,
      probe_execution_identity_sha256: exec.repeat(64),
      binary_identity_sha256: 'b'.repeat(64),
      rules_sha256: 'c'.repeat(64),
      ...(probedAt !== undefined ? {probed_at: iso(probedAt)} : {}),
      expires_at: iso(expiresAt),
      ttl_seconds: ttl,
      ...ogPatch,
    },
  };
}

function assertAllHealthSurfaces(fp, backend, nowMs, {verified, expired}) {
  const view = fp.classifyBackendHealthState(backend, {nowMs});
  assert.equal(Boolean(view.ogInfo?.isVerified), verified, `StatusPage ogInfo.isVerified=${view.ogInfo?.isVerified}`);
  assert.equal(Boolean(view.ogInfo?.ttlExpired), expired, `StatusPage ogInfo.ttlExpired=${view.ogInfo?.ttlExpired}`);
  if (verified) {
    assert.match(view.pillLabel, /OPENGREP VERIFIED/i);
    assert.match(view.sidebarLabel, /OpenGrep đã xác minh/i);
  } else if (expired) {
    assert.match(view.pillLabel, /EXPIRED/i);
    assert.match(view.sidebarLabel, /EXPIRED/i);
  } else {
    assert.doesNotMatch(view.pillLabel, /OPENGREP VERIFIED/i);
    assert.doesNotMatch(view.sidebarLabel, /OpenGrep đã xác minh/i);
  }
}

test('P1-HEALTH-01 ordering: deterministic same-millisecond order survives reload for 2 and 3+ probes (with/without probed_at), preserves timer, expires at exact deadline, and blocks stale resurrection', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const hm = await loadModule('src/services/healthMonitor.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');

  const T = Date.parse('2026-11-26T00:00:00.000Z');
  let now = T;
  let currentRaw = '';
  const storage = mkStorage();
  const activeTimers = new Map();
  let nextTimerId = 1;

  const mkMonitor = (scope = 'scope-same-ms') => hm.createHealthMonitor({
    storage,
    getScopeKey: () => scope,
    fetchHealth: async () => apiMod.parseJsonWithWireIntegrity(currentRaw),
    now: () => now,
    retryDelaysMs: [],
    setTimer: (fn, ms) => {
      const id = nextTimerId;
      nextTimerId += 1;
      activeTimers.set(id, {id, fn, ms});
      return id;
    },
    clearTimer: (id) => {
      activeTimers.delete(id);
    },
  });

  // --- Scenario A: Codex exact counterexample (2 unanchored probes in same millisecond T across reload) ---
  const m1 = mkMonitor();
  const oldA = makeHealthBody({checkedAt: T, exec: 'a', expiresAt: T - 1000, ttl: 2});
  const freshB = makeHealthBody({checkedAt: T, exec: 'd', expiresAt: T + 12000, ttl: 30});
  const replayA = makeHealthBody({checkedAt: T, exec: 'a', expiresAt: T + 15000, ttl: 30});

  currentRaw = JSON.stringify(oldA);
  await m1.checkNow({force: true});
  assertAllHealthSurfaces(fp, m1.getSnapshot().backend, now, {verified: false, expired: true});
  assert.equal(m1.getSnapshot().backend.expiresAtMs, T - 1000);

  currentRaw = JSON.stringify(freshB);
  await m1.checkNow({force: true});
  assertAllHealthSurfaces(fp, m1.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m1.getSnapshot().backend.expiresAtMs, T + 12000);
  assert.equal(activeTimers.size, 1);
  const timerBeforeReload = [...activeTimers.keys()][0];

  currentRaw = JSON.stringify(replayA);
  await m1.checkNow({force: true});
  assertAllHealthSurfaces(fp, m1.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m1.getSnapshot().backend.expiresAtMs, T + 12000);
  assert.equal(m1.getSnapshot().meta.staleSnapshotIgnored, true);
  assert.equal(activeTimers.has(timerBeforeReload), true, 'timer preserved before reload');
  m1.dispose();
  activeTimers.clear();

  // Verify ledger contains deterministic monotonic firstSeenSeq & nextOrderSeq without raw tokens
  const rawLedger = storage.getItem('22025523-health-proof-ledger-v1');
  assert.ok(rawLedger);
  assert.equal(/Bearer|Authorization/i.test(rawLedger), false);
  const parsedLedger = JSON.parse(rawLedger);
  const scopeObj = parsedLedger.scopes['custom|scope-same-ms'];
  assert.equal(scopeObj.nextOrderSeq, 2);
  const seqValues = Object.values(scopeObj.proofs).map((p) => p.firstSeenSeq).sort((a, b) => a - b);
  assert.deepEqual(seqValues, [1, 2]);

  // Reload (new monitor reading same storage) STILL at millisecond T
  const m2 = mkMonitor();
  currentRaw = JSON.stringify(freshB);
  await m2.checkNow({force: true});
  assertAllHealthSurfaces(fp, m2.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m2.getSnapshot().backend.expiresAtMs, T + 12000);
  assert.equal(activeTimers.size, 1);
  const timerAfterReload = [...activeTimers.keys()][0];

  // Replay oldA after reload -> MUST stay VERIFIED on all 3 surfaces, keep deadline and exact timer!
  currentRaw = JSON.stringify(replayA);
  await m2.checkNow({force: true});
  assertAllHealthSurfaces(fp, m2.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m2.getSnapshot().backend.expiresAtMs, T + 12000);
  assert.equal(m2.getSnapshot().meta.staleSnapshotIgnored, true);
  assert.equal(activeTimers.has(timerAfterReload), true, 'timer preserved after reload');
  assert.equal(activeTimers.size, 1);

  // --- Scenario B: 3rd and 4th probes in the SAME millisecond T across another reload ---
  const freshC = makeHealthBody({checkedAt: T, exec: 'e', expiresAt: T + 18000, ttl: 30});
  currentRaw = JSON.stringify(freshC);
  await m2.checkNow({force: true});
  assertAllHealthSurfaces(fp, m2.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m2.getSnapshot().backend.expiresAtMs, T + 18000);
  m2.dispose();
  activeTimers.clear();

  const m3 = mkMonitor();
  // Read freshC after 2nd reload; replay both B (seq=2, still unexpired!) and A (seq=1) -> C & timer preserved!
  currentRaw = JSON.stringify(freshC);
  await m3.checkNow({force: true});
  const timerC = [...activeTimers.keys()][0];
  for (const older of [freshB, replayA, makeHealthBody({checkedAt: T, exec: 'd', expiresAt: T + 99000, ttl: 99})]) {
    currentRaw = JSON.stringify(older);
    await m3.checkNow({force: true});
    assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: true, expired: false});
    assert.equal(m3.getSnapshot().backend.expiresAtMs, T + 18000, 'C deadline preserved against A & B replays');
    assert.equal(activeTimers.has(timerC), true, 'C timer never replaced');
  }

  // Add 4th probe D AFTER reload in the EXACT same millisecond T -> gets seq=4 > 3!
  const freshD = makeHealthBody({checkedAt: T, exec: 'f', expiresAt: T + 20000, ttl: 30});
  currentRaw = JSON.stringify(freshD);
  await m3.checkNow({force: true});
  assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m3.getSnapshot().backend.expiresAtMs, T + 20000);
  const timerD = [...activeTimers.keys()][0];

  // Replay C (seq=3) after D (seq=4) -> D preserved!
  currentRaw = JSON.stringify(freshC);
  await m3.checkNow({force: true});
  assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m3.getSnapshot().backend.expiresAtMs, T + 20000);
  assert.equal(activeTimers.has(timerD), true);

  // Passive expiry of D at exact deadline T + 20000
  now = T + 20000;
  activeTimers.get(timerD).fn();
  assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: false, expired: true});
  assert.equal(m3.getSnapshot().backend.expiresAtMs, T + 20000);

  // Even after D expires, replaying older A/B/C with shifted deadlines MUST NEVER resurrect VERIFIED!
  for (const staleExec of ['a', 'd', 'e', 'f']) {
    currentRaw = JSON.stringify(makeHealthBody({checkedAt: now, exec: staleExec, expiresAt: now + 60000, ttl: 60}));
    await m3.checkNow({force: true});
    assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: false, expired: true});
  }

  // Genuine new execution WITH probed_at recovers cleanly
  const freshG = makeHealthBody({checkedAt: now, exec: '9', probedAt: now, expiresAt: now + 25000, ttl: 25});
  currentRaw = JSON.stringify(freshG);
  await m3.checkNow({force: true});
  assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m3.getSnapshot().backend.expiresAtMs, now + 25000);
  const timerG = [...activeTimers.keys()][0];

  // Unseen unanchored probe (no probed_at) after anchored freshG is NOT assumed newer by client order!
  currentRaw = JSON.stringify(makeHealthBody({checkedAt: now, exec: '8', expiresAt: now + 90000, ttl: 90}));
  await m3.checkNow({force: true});
  assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(m3.getSnapshot().backend.expiresAtMs, now + 25000, 'anchored freshG preserved over unseen unanchored');
  assert.equal(activeTimers.has(timerG), true);

  // Once anchored freshG expires, an unseen unanchored probe MUST fail closed to UNVERIFIED (not VERIFIED)
  now += 25000;
  activeTimers.get(timerG).fn();
  assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: false, expired: true});
  currentRaw = JSON.stringify(makeHealthBody({checkedAt: now, exec: '7', expiresAt: now + 90000, ttl: 90}));
  await m3.checkNow({force: true});
  assertAllHealthSurfaces(fp, m3.getSnapshot().backend, now, {verified: false, expired: false});
  m3.dispose();
  activeTimers.clear();

  // --- Scenario C: Two probes WITH probed_at observed in same ms -> probed_at order + reload ---
  const mAnchored = mkMonitor('scope-anchored-same-ms');
  const tA = T + 100000;
  now = tA;
  const pOlder = makeHealthBody({checkedAt: tA, exec: '1', probedAt: tA - 5000, expiresAt: tA - 1000, ttl: 4});
  const pNewer = makeHealthBody({checkedAt: tA, exec: '2', probedAt: tA, expiresAt: tA + 15000, ttl: 15});
  currentRaw = JSON.stringify(pOlder);
  await mAnchored.checkNow({force: true});
  assertAllHealthSurfaces(fp, mAnchored.getSnapshot().backend, now, {verified: false, expired: true});
  currentRaw = JSON.stringify(pNewer);
  await mAnchored.checkNow({force: true});
  assertAllHealthSurfaces(fp, mAnchored.getSnapshot().backend, now, {verified: true, expired: false});
  mAnchored.dispose();
  activeTimers.clear();

  const mAnchoredReload = mkMonitor('scope-anchored-same-ms');
  currentRaw = JSON.stringify(pNewer);
  await mAnchoredReload.checkNow({force: true});
  const tNewer = [...activeTimers.keys()][0];
  currentRaw = JSON.stringify(makeHealthBody({checkedAt: tA, exec: '1', probedAt: tA - 5000, expiresAt: tA + 60000, ttl: 60}));
  await mAnchoredReload.checkNow({force: true});
  assertAllHealthSurfaces(fp, mAnchoredReload.getSnapshot().backend, now, {verified: true, expired: false});
  assert.equal(mAnchoredReload.getSnapshot().backend.expiresAtMs, tA + 15000);
  assert.equal(activeTimers.has(tNewer), true);
  mAnchoredReload.dispose();
});

test('P1-HEALTH-01 ledger safety: legacy ledger compatibility, corrupted/wrong-type ledger fail-closed, storage read/write failure, and URL/auth scope isolation', async () => {
  const fp = await loadRawEsm('src/services/findingPresentation.js');

  // 1. Corrupted / wrong-type ledger entries (including bad firstSeenSeq / nextOrderSeq / latestAcceptedProof)
  const badLedgers = [
    ['corrupt-firstSeenSeq-zero', JSON.stringify({v: 1, scopes: {s1: {proofs: {p1: {expiresAtMs: Date.now() + 5000, firstSeenAtMs: Date.now(), firstSeenSeq: 0}}}}})],
    ['corrupt-firstSeenSeq-str', JSON.stringify({v: 1, scopes: {s1: {proofs: {p1: {expiresAtMs: Date.now() + 5000, firstSeenAtMs: Date.now(), firstSeenSeq: '1'}}}}})],
    ['corrupt-firstSeenSeq-float', JSON.stringify({v: 1, scopes: {s1: {proofs: {p1: {expiresAtMs: Date.now() + 5000, firstSeenAtMs: Date.now(), firstSeenSeq: 1.5}}}}})],
    ['corrupt-nextOrderSeq-neg', JSON.stringify({v: 1, scopes: {s1: {nextOrderSeq: -1, proofs: {}}}})],
    ['corrupt-latestAccepted-shape', JSON.stringify({v: 1, scopes: {s1: {latestAcceptedProof: {sig: '', firstSeenAtMs: Date.now()}, proofs: {}}}})],
    ['corrupt-proofs-array', JSON.stringify({v: 1, scopes: {s1: {proofs: []}}})],
  ];
  for (const [label, badJson] of badLedgers) {
    await withWindow({value: mkStorage()}, async (win) => {
      win.sessionStorage.setItem('22025523-health-proof-ledger-v1', badJson);
      const hm = await loadModule('src/services/healthMonitor.js');
      const now = Date.now();
      let payload = makeHealthBody({exec: 'a', probedAt: now, expiresAt: now + 30000, ttl: 30}); // missing checked_at
      const mon = hm.createHealthMonitor({fetchHealth: async () => payload, retryDelaysMs: []});
      await mon.checkNow({force: true});
      assert.equal(mon.getSnapshot().backend.opengrepVerified, false, `${label}: unstamped gated`);
      assertAllHealthSurfaces(fp, mon.getSnapshot().backend, now, {verified: false, expired: false});
      // Server-anchored valid probe still recovers cleanly
      payload = makeHealthBody({checkedAt: now, exec: 'b', probedAt: now, expiresAt: now + 30000, ttl: 30});
      await mon.checkNow({force: true});
      assertAllHealthSurfaces(fp, mon.getSnapshot().backend, now, {verified: true, expired: false});
      mon.dispose();
    });
  }

  // 2. Valid legacy v1 ledger (omitting firstSeenSeq) restores clamped expiry safely without marking storage untrusted
  await withWindow({value: mkStorage()}, async (win) => {
    const {apiMod, hm} = await loadSharedApiAndHealth();
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19981', token: ''});
    const scopeKey = apiMod.getHealthPersistenceScopeKey();
    const now = Date.now();
    const sigA = `u:|proc-leg|${'a'.repeat(64)}|${'b'.repeat(64)}|${'c'.repeat(64)}`;
    win.sessionStorage.setItem('22025523-health-proof-ledger-v1', JSON.stringify({
      v: 1,
      scopes: {
        [scopeKey]: {
          latestProbedAtMs: null,
          latestServerExpiresAtMs: now - 1000,
          latestProcessInstanceId: 'proc-leg',
          updatedAtMs: now,
          proofs: {[sigA]: {expiresAtMs: now - 1000, firstSeenAtMs: now}},
        },
      },
    }));
    let payload = makeHealthBody({checkedAt: now, proc: 'proc-leg', exec: 'a', expiresAt: now + 30000, ttl: 30});
    const mon = hm.createHealthMonitor({fetchHealth: async () => payload, retryDelaysMs: []});
    await mon.checkNow({force: true});
    assertAllHealthSurfaces(fp, mon.getSnapshot().backend, now, {verified: false, expired: true});
    assert.equal(mon.getSnapshot().backend.expiresAtMs, now - 1000, 'legacy clamped deadline preserved');

    // URL change & auth token change isolate scopes and never leak raw token to storage
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19982', token: 'secret-token-never-stored-9999'});
    payload = makeHealthBody({checkedAt: now, proc: 'proc-leg', exec: 'a', expiresAt: now + 30000, ttl: 30});
    await mon.checkNow({force: true});
    assertAllHealthSurfaces(fp, mon.getSnapshot().backend, now, {verified: true, expired: false});
    for (const [k, v] of win.sessionStorage._map.entries()) {
      assert.equal(`${k}${v}`.includes('secret-token-never-stored-9999'), false, 'raw token never written to storage');
    }
    mon.dispose();
  });

  // 3. Storage getItem/setItem throwing still clamps same-ms order in RAM and gates unanchored proofs
  for (const brokenMethod of ['getItem', 'setItem']) {
    await withWindow({value: mkStorage({[brokenMethod]() { throw new DOMException('blocked', 'SecurityError'); }})}, async () => {
      const hm = await loadModule('src/services/healthMonitor.js');
      const T = Date.now();
      let payload = makeHealthBody({exec: '1', probedAt: T, expiresAt: T + 30000, ttl: 30}); // missing checked_at
      const mon = hm.createHealthMonitor({fetchHealth: async () => payload, now: () => T, retryDelaysMs: []});
      await mon.checkNow({force: true});
      assertAllHealthSurfaces(fp, mon.getSnapshot().backend, T, {verified: false, expired: false});

      payload = makeHealthBody({checkedAt: T, exec: 'a', expiresAt: T - 1000, ttl: 2});
      await mon.checkNow({force: true});
      assertAllHealthSurfaces(fp, mon.getSnapshot().backend, T, {verified: false, expired: true});

      payload = makeHealthBody({checkedAt: T, exec: 'd', expiresAt: T + 20000, ttl: 30});
      await mon.checkNow({force: true});
      assertAllHealthSurfaces(fp, mon.getSnapshot().backend, T, {verified: true, expired: false});

      payload = makeHealthBody({checkedAt: T, exec: 'a', expiresAt: T + 30000, ttl: 30});
      await mon.checkNow({force: true});
      assertAllHealthSurfaces(fp, mon.getSnapshot().backend, T, {verified: true, expired: false});
      assert.equal(mon.getSnapshot().backend.expiresAtMs, T + 20000, `${brokenMethod}: RAM same-ms clamp holds`);
      mon.dispose();
    });
  }
});

test('P1-COVERAGE-01 nested tree integrity: invalidIntFields at all nesting depths/arrays, duplicates, wrong types, exact 4-way + 3-page parity, timing floats, and unrelated sibling isolation', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  const sh = await loadModule('src/services/scanHistory.js');
  const parse = apiMod.parseJsonWithWireIntegrity;
  const normalize = apiMod.materializeNormalizedTelemetry;

  const WG = '"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"';
  const JVL = '"java_files_inventory":19,"java_files_opengrep_scanned":19,"java_files_opengrep_ignored":0,"opengrep_paths_telemetry_status":"VERIFIED"';

  const makeViews = (raw) => {
    const wire = parse(raw);
    const norm = normalize(wire).value;
    return [
      ['wire', wire],
      ['normalized', norm],
      ['shallow', {...norm}],
      ['json', JSON.parse(JSON.stringify(norm))],
    ];
  };

  const assertCase = (label, rawSummary, rawJob, expectedVerified, expectedCounts = null) => {
    const sumViews = makeViews(rawSummary);
    const jobViews = rawJob ? makeViews(rawJob) : sumViews.map(([k]) => [k, null]);
    const results = [];
    for (let i = 0; i < sumViews.length; i += 1) {
      const [kind, sumVal] = sumViews[i];
      const jobVal = jobViews[i][1];
      const res = fp.resolveJavaFileCounts(sumVal, jobVal);
      results.push({kind, status: res.coverageStatus, verified: res.hasVerifiedScanned, scanned: res.scannedCount});
      assert.equal(res.hasVerifiedScanned, expectedVerified, `${label} [${kind}] expected verified=${expectedVerified}, got ${res.coverageStatus}/${res.canonicalCoverageProblem}`);
      if (expectedVerified) {
        assert.equal(res.coverageStatus, 'VERIFIED', `${label} [${kind}]`);
        assert.deepEqual([res.inventoryCount, res.scannedCount, res.ignoredCount], expectedCounts, `${label} [${kind}]`);
      } else {
        assert.equal(res.scannedCount, null, `${label} [${kind}] scanned must be hidden`);
        assert.equal(res.ignoredCount, null, `${label} [${kind}] ignored must be hidden`);
      }
    }
    // 4-way status parity
    assert.equal(new Set(results.map((r) => `${r.verified}|${r.scanned}`)).size, 1, `${label}: 4-way parity mismatch: ${JSON.stringify(results)}`);

    // History & Reports parity (when summary-only)
    if (!rawJob) {
      const hist = sh.historyRecordFromBackend(parse(rawSummary.replace(/^\{/, '{"scan_id":"cov-nested-1",')), {
        origin: 'http://127.0.0.1:19983',
        sessionScope: 's',
      });
      assert.equal(Boolean(hist.javaCounts?.hasVerifiedScanned), expectedVerified, `${label} [history]`);
      const rep = parse(`{"scan_summary":${rawSummary},"findings":[]}`);
      assert.equal(fp.resolveJavaFileCounts(rep.scan_summary).hasVerifiedScanned, expectedVerified, `${label} [reports]`);
    }
  };

  // Positive controls (JVL 19/19/0, WebGoat 498/389/109, timing floats, nullable optional fields, unrelated sibling errors)
  assertCase('jvl-valid', `{${JVL}}`, '', true, [19, 19, 0]);
  assertCase('webgoat-valid', `{${WG}}`, '', true, [498, 389, 109]);
  assertCase('timing-floats-and-null-optional', `{${WG},"scan_manifest":{"duration_s":1.42,"elapsed_ms":12.5}}`, '{"stages":[{"summary_metadata":null},{"summary_metadata":{"opengrep_timing":{"elapsed_seconds":2.35,"parse_ms":0.0}}}]}', true, [498, 389, 109]);
  assertCase('null-opengrep-timing', `{${WG}}`, '{"stages":[{"summary_metadata":null},{"summary_metadata":{"opengrep_timing":null}}]}', true, [498, 389, 109]);
  assertCase('unrelated-sibling-precision-and-dup-and-reserved', `{${WG},"other_unrelated_section":{"__wireIntegrity":null,"z":1,"z":2,"nested":{"java_files_inventory_count":498.00000000000000001}}}`, '', true, [498, 389, 109]);
  assertCase('unrelated-direct-precision-field', `{${WG},"unrelated_score":12.00000000000000001}`, '', true, [498, 389, 109]);

  // Codex verbatim counterexamples + deep multi-level nested invalidIntFields & precision traps
  assertCase('codex-nested-paths-precision', `{${WG},"scan_manifest":{"paths":{"scanned_java_files_count":389.00000000000000001}}}`, '', false);
  assertCase('codex-nested-manifest-precision', `{${WG},"scan_manifest":{"nested":{"java_files_inventory_count":498.00000000000000001}}}`, '', false);
  assertCase('codex-stage1-nested-precision', `{${WG}}`, '{"stages":[{},{"summary_metadata":{"nested":{"java_files_inventory_count":498.00000000000000001}}}]}', false);
  assertCase('manifest-paths-deep-3-level', `{${WG},"manifest":{"paths":{"deep":{"level3":{"ignored_files":109.00000000000000001}}}}}`, '', false);
  assertCase('manifest-nested-array-precision', `{${WG},"scan_manifest":{"buckets":[{"scanned_count":389.00000000000000001}]}}`, '', false);
  assertCase('manifest-paths-arbitrary-key-precision-loss', `{${WG},"scan_manifest":{"paths":{"custom_metric":389.00000000000000001}}}`, '', false);
  assertCase('manifest-paths-arbitrary-key-unsafe-int', `{${WG},"scan_manifest":{"paths":{"custom_metric":9007199254740993}}}`, '', false);
  assertCase('manifest-paths-count-key-float', `{${WG},"scan_manifest":{"paths":{"scanned_count":389.5}}}`, '', false);
  assertCase('manifest-paths-count-key-negative', `{${WG},"scan_manifest":{"paths":{"scanned_count":-1}}}`, '', false);
  assertCase('manifest-paths-count-key-neg-zero', `{${WG},"scan_manifest":{"paths":{"scanned_count":-0}}}`, '', false);
  assertCase('provenance-nested-precision', `{${WG},"scan_provenance":{"stats":{"scanned_java_files_count":389.00000000000000001}}}`, '', false);
  assertCase('stage0-nested-precision', `{${WG}}`, '{"stages":[{"summary_metadata":{"nested":{"java_files_count":498.00000000000000001}}},{}]}', false);
  assertCase('opengrep-timing-nested-precision', `{${WG}}`, '{"stages":[{},{"summary_metadata":{"opengrep_timing":{"scanned_java_files_count":389.00000000000000001}}}]}', false);

  // Structural / duplicate / reserved / conflict / non-closing / missing-canonical negatives
  assertCase('scan-manifest-reserved-null', `{${WG},"scan_manifest":{"__wireIntegrity":null}}`, '', false);
  assertCase('scan-manifest-reserved-forged-clean', `{${WG},"scan_manifest":{"__wireIntegrity":{"hasMalformed":false,"hasConflict":false}}}`, '', false);
  assertCase('manifest-paths-duplicate-conflict', `{${WG},"scan_manifest":{"paths":{"x":1,"x":2}}}`, '', false);
  assertCase('manifest-paths-duplicate-unicode', `{${WG},"scan_manifest":{"paths":{"scann\\u0065d":389,"scanned":389}}}`, '', false);
  assertCase('manifest-wrong-type-array', `{${WG},"scan_manifest":[]}`, '', false);
  assertCase('paths-wrong-type-bool', `{${WG},"scan_manifest":{"paths":false}}`, '', false);
  assertCase('job-stages-wrong-type', `{${WG}}`, '{"stages":false}', false);
  assertCase('job-stage0-wrong-type', `{${WG}}`, '{"stages":[false,{}]}', false);
  assertCase('job-stage1-wrong-type', `{${WG}}`, '{"stages":[{},"bad"]}', false);
  assertCase('conflicting-containers', `{${WG},"manifest":{"java_files_opengrep_scanned":388}}`, '', false);
  assertCase('non-closing-sum', `{${WG.replace('109', '108')}}`, '', false);
  assertCase('missing-canonical-alias-only', `{${WG.replace('java_files_opengrep_scanned', 'opengrep_scanned_java_files')}}`, '', false);
});

test('Preaudit blind-spot closure: backward clock steps, MAX_SEEN_PROOF_SIGNATURES eviction protection, semantic multi-container coverage, and F05 Citation 5-way parity', async () => {
  const {apiMod, hm} = await loadSharedApiAndHealth();
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  const jm = await loadRawEsm('src/services/jobModel.js');
  const lsp = await loadModule('src/components/scanner/liveStagePresentation.js');
  const parse = (raw) => apiMod.parseJsonWithWireIntegrity(raw);

  // 1. Health: A & B same ms -> reload -> C accepted -> replay A & B preserves C, exact deadline & timer
  {
    const st = mkStorage();
    const T0 = Date.parse('2026-11-25T10:00:00.000Z');
    const timers1 = new Map();
    let tid1 = 1;
    let nextResp = null;
    const mkMon = () => hm.createHealthMonitor({
      storage: st,
      getScopeKey: () => 'preaudit-a',
      fetchHealth: async () => nextResp,
      now: () => T0,
      setTimer: (fn, ms) => { const id = tid1++; timers1.set(id, {id, fn, ms}); return id; },
      clearTimer: (id) => { timers1.delete(id); },
      retryDelaysMs: [],
    });
    const mkP = (execChar, expIso, chkIso = '2026-11-25T10:00:00.000Z') => parse(JSON.stringify({
      status: 'OK',
      ...(chkIso ? {checked_at: chkIso} : {}),
      opengrep: {
        available: true,
        runtime_verified: true,
        probe_status: 'VERIFIED',
        health_state: 'VERIFIED',
        verification_level: 'SCAN_VERIFIED',
        process_instance_id: 'proc-preaudit',
        probe_execution_identity_sha256: execChar.repeat(64),
        binary_identity_sha256: 'b'.repeat(64),
        rules_sha256: 'c'.repeat(64),
        expires_at: expIso,
        ttl_seconds: 30,
      },
    }));

    let mon = mkMon();
    nextResp = mkP('a', '2026-11-25T09:59:59.000Z');
    await mon.checkNow({force: true});
    nextResp = mkP('b', '2026-11-25T10:00:10.000Z');
    await mon.checkNow({force: true});
    mon.dispose();

    // Reload -> accept C -> replay A and B (must not displace C or cancel C's timer)
    mon = mkMon();
    nextResp = mkP('c', '2026-11-25T10:00:20.000Z');
    await mon.checkNow({force: true});
    const timerBefore = [...timers1.keys()];
    assert.equal(timerBefore.length, 1);

    nextResp = mkP('a', '2026-11-25T10:00:25.000Z');
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, true);
    assert.equal(mon.getSnapshot().backend.expiresAtMs, T0 + 20000);
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
    assert.deepEqual([...timers1.keys()], timerBefore);
    assertAllHealthSurfaces(fp, mon.getSnapshot().backend, T0, {verified: true, expired: false});

    nextResp = mkP('b', '2026-11-25T10:00:25.000Z');
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, true);
    assert.equal(mon.getSnapshot().backend.expiresAtMs, T0 + 20000);
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
    assert.deepEqual([...timers1.keys()], timerBefore);
    assertAllHealthSurfaces(fp, mon.getSnapshot().backend, T0, {verified: true, expired: false});
    mon.dispose();

    // 2. Client clock steps BACKWARD 5s (NTP adjustment): old A (seq 1) NEVER overwrites newer B (seq 2),
    //    and latestAcceptedProof advances cleanly to B so B stays VERIFIED after reload.
    const stClock = mkStorage();
    let nowMs = T0 + 5000;
    const timers2 = new Map();
    let tid2 = 1;
    const mkMonClock = () => hm.createHealthMonitor({
      storage: stClock,
      getScopeKey: () => 'preaudit-clock',
      fetchHealth: async () => nextResp,
      now: () => nowMs,
      setTimer: (fn, ms) => { const id = tid2++; timers2.set(id, {id, fn, ms}); return id; },
      clearTimer: (id) => { timers2.delete(id); },
      retryDelaysMs: [],
    });
    mon = mkMonClock();
    nextResp = mkP('a', '2026-11-25T09:59:59.000Z');
    await mon.checkNow({force: true});
    nowMs = T0; // step backward 5s
    nextResp = mkP('b', '2026-11-25T10:00:15.000Z');
    await mon.checkNow({force: true});
    const bTimer = [...timers2.keys()];
    assert.equal(mon.getSnapshot().backend.opengrepVerified, true);
    assert.equal(bTimer.length, 1);

    nextResp = mkP('a', '2026-11-25T10:00:25.000Z');
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, true, 'Backward clock step must not let old A overwrite B');
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
    assert.deepEqual([...timers2.keys()], bTimer);

    mon.dispose();
    mon = mkMonClock();
    nextResp = mkP('b', '2026-11-25T10:00:15.000Z');
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, true, 'B must remain VERIFIED after reload');
    nextResp = mkP('a', '2026-11-25T10:00:25.000Z');
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, true, 'Old A replay after reload must stay ignored despite backward clock step');
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
    mon.dispose();

    // 3. Backward 60s clock step + reload: previously expired unanchored probe stays EXPIRED (tombstone)
    const stBack60 = mkStorage();
    nowMs = T0 + 60000;
    mon = hm.createHealthMonitor({
      storage: stBack60,
      getScopeKey: () => 'preaudit-back60',
      fetchHealth: async () => nextResp,
      now: () => nowMs,
      setTimer: () => 1,
      clearTimer: () => {},
      retryDelaysMs: [],
    });
    nextResp = mkP('a', '2026-11-25T10:00:59.000Z', null);
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.ttlExpired, true);
    mon.dispose();
    nowMs = T0;
    mon = hm.createHealthMonitor({
      storage: stBack60,
      getScopeKey: () => 'preaudit-back60',
      fetchHealth: async () => nextResp,
      now: () => nowMs,
      setTimer: () => 1,
      clearTimer: () => {},
      retryDelaysMs: [],
    });
    nextResp = mkP('a', '2026-11-25T10:00:59.000Z', null);
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, false);
    assert.equal(mon.getSnapshot().backend.ttlExpired, true);
    mon.dispose();

    // 4. MAX_SEEN_PROOF_SIGNATURES eviction protection in sessionStorage:
    //    65 expired probes must NOT evict latestAcceptedProof A or allow A to resurrect after reload.
    const stEvict = mkStorage();
    nowMs = T0;
    const mkMonEvict = () => hm.createHealthMonitor({
      storage: stEvict,
      getScopeKey: () => 'preaudit-evict',
      fetchHealth: async () => nextResp,
      now: () => nowMs,
      setTimer: () => 1,
      clearTimer: () => {},
      retryDelaysMs: [],
    });
    mon = mkMonEvict();
    nextResp = mkP('1', '2026-11-25T10:00:20.000Z');
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, true);
    for (let i = 1; i <= 65; i += 1) {
      const id = i.toString(16).padStart(64, 'e');
      nextResp = parse(JSON.stringify({
        status: 'OK',
        checked_at: '2026-11-25T10:00:25.000Z',
        opengrep: {
          available: true, runtime_verified: true, probe_status: 'VERIFIED',
          health_state: 'VERIFIED', verification_level: 'SCAN_VERIFIED',
          process_instance_id: 'proc-preaudit',
          probe_execution_identity_sha256: id,
          binary_identity_sha256: 'b'.repeat(64), rules_sha256: 'c'.repeat(64),
          expires_at: '2026-11-25T10:00:21.000Z', ttl_seconds: 30,
        },
      }));
      await mon.checkNow({force: true});
    }
    mon.dispose();
    nowMs = T0 + 25000;
    mon = mkMonEvict();
    nextResp = mkP('1', '2026-11-25T10:00:50.000Z', '2026-11-25T10:00:25.000Z');
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.opengrepVerified, false, 'Eviction must never allow expired latestAcceptedProof A to resurrect');
    assert.equal(mon.getSnapshot().backend.ttlExpired, true);
    assert.equal(mon.getSnapshot().backend.expiresAtMs, T0 + 20000);
    mon.dispose();
  }

  // 5. Coverage semantic conflicts across summary vs scan_manifest, scan_provenance, and reordered job.stages
  {
    const base = {
      java_files_inventory: 498,
      java_files_opengrep_scanned: 389,
      java_files_opengrep_ignored: 109,
      opengrep_paths_telemetry_status: 'VERIFIED',
    };
    const assert4 = (rawSum, rawJob, expectedStatus) => {
      const sRaw = parse(rawSum);
      const sNorm = apiMod.materializeNormalizedTelemetry(sRaw).value;
      const jRaw = rawJob ? parse(rawJob) : null;
      const jNorm = jRaw ? apiMod.materializeNormalizedTelemetry(jRaw).value : null;
      const reps = [
        fp.resolveJavaFileCounts(sRaw, jRaw),
        fp.resolveJavaFileCounts(sNorm, jNorm),
        fp.resolveJavaFileCounts({...sNorm}, jNorm ? {...jNorm} : null),
        fp.resolveJavaFileCounts(JSON.parse(JSON.stringify(sNorm)), jNorm ? JSON.parse(JSON.stringify(jNorm)) : null),
      ];
      for (const r of reps) {
        assert.equal(r.coverageStatus, expectedStatus);
        assert.equal(r.hasVerifiedScanned, expectedStatus === 'VERIFIED');
      }
    };
    assert4(JSON.stringify({...base, scan_manifest: {java_files_inventory: 498, java_files_opengrep_scanned: 390, java_files_opengrep_ignored: 108, opengrep_paths_telemetry_status: 'VERIFIED'}}), '', 'INCONSISTENT');
    assert4(JSON.stringify({...base, scan_provenance: {java_files_inventory: 499, scanned_java_files_count: 389, ignored_java_files_count: 109}}), '', 'INCONSISTENT');
    assert4(
      JSON.stringify(base),
      JSON.stringify({stages: [
        {stage_number: 2, stage_key: 'OPENGREP_SCAN', summary_metadata: {java_files_inventory: 498, java_files_opengrep_scanned: 390, java_files_opengrep_ignored: 108}},
        {stage_number: 1, stage_key: 'INTAKE_VALIDATION', summary_metadata: {java_files_count: 498}},
      ]}),
      'INCONSISTENT',
    );
    assert4(JSON.stringify({java_files_inventory: 19, java_files_opengrep_scanned: 19, java_files_opengrep_ignored: 0, opengrep_paths_telemetry_status: 'VERIFIED'}), '', 'VERIFIED');
  }

  // 6. F05 Citation 5-way parity (rawDirect === resolved === stageShallow === summaryShallow === jsonRoundTrip)
  //    across LIVE and PLAYBACK, including nested precision loss, nested duplicates, and valid decimal floats.
  {
    const assertCit5Way = (rawJobStr, expectedStatus) => {
      const rawJob = parse(rawJobStr);
      const st5 = jm.resolveStages(rawJob)[4];
      const candidates = [
        {cat: 'COMPLETED', summary: rawJob.stages[0].summary_metadata},
        st5,
        {...st5},
        {...st5, summary: st5.summary && typeof st5.summary === 'object' ? {...st5.summary} : st5.summary},
        JSON.parse(JSON.stringify(st5)),
      ];
      for (const mode of ['LIVE', 'PLAYBACK']) {
        for (const cand of candidates) {
          const tel = lsp.resolveStage05CitationTelemetry({mode, stage: cand});
          assert.equal(tel.aggregateStatus, expectedStatus, `mode=${mode} expected=${expectedStatus} got=${tel.aggregateStatus}`);
        }
      }
    };
    assertCit5Way('{"stages":[{"stage_no":5,"status":"COMPLETED","summary_metadata":{"matched_count":4,"invalid_count":0,"not_verified_count":0,"total_checked":4,"elapsed_seconds":1.42,"parse_ms":12.5,"zero_f":0.0,"whole_f":1.0}}]}', 'ALL_MATCHED');
    assertCit5Way('{"stages":[{"stage_no":5,"status":"COMPLETED","summary_metadata":{"matched_count":4,"invalid_count":0,"not_verified_count":0,"total_checked":4,"nested":{"metric":1.0000000000000001}}}]}', 'MALFORMED');
    assertCit5Way('{"stages":[{"stage_no":5,"status":"COMPLETED","summary_metadata":{"matched_count":4,"invalid_count":0,"not_verified_count":0,"total_checked":4,"nested":{"k":1,"k":2}}}]}', 'CONFLICT');
    assertCit5Way('{"stages":[{"stage_no":5,"status":"COMPLETED","summary_metadata":{"matched_count":4,"total_checked":4}}]}', 'PARTIAL');
  }
});
