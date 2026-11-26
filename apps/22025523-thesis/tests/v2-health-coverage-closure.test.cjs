// Root-cause invariant test matrix for P1-HEALTH-01 (decoupled deadline recording for
// initially-expired & valid probes) and P1-COVERAGE-01 (uniform REST integrity across all
// participating coverage containers on wire, normalized, shallow copy, and JSON round-trip).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const esbuild = require('esbuild');

const APP_ROOT = path.resolve(__dirname, '..');
let bust = 0;

async function loadModule(relPath) {
  const built = await esbuild.build({
    entryPoints: [path.join(APP_ROOT, relPath)],
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
  bust += 1;
  return import(`data:text/javascript;base64,${Buffer.from(`${built.outputFiles[0].text}\n// ${bust}`, 'utf8').toString('base64')}`);
}

async function loadRawEsm(relPath) {
  bust += 1;
  const code = `${fs.readFileSync(path.join(APP_ROOT, relPath), 'utf8')}\n// ${bust}`;
  return import(`data:text/javascript;base64,${Buffer.from(code, 'utf8').toString('base64')}`);
}

function mkStorage(overrides = {}) {
  const map = new Map();
  return {
    _map: map,
    get length() { return map.size; },
    key(i) { return [...map.keys()][i] ?? null; },
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(String(k), String(v)); },
    removeItem(k) { map.delete(String(k)); },
    ...overrides,
  };
}

function withWindow(descriptor, fn) {
  const prev = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const win = {
    location: {origin: 'http://127.0.0.1:19980', hostname: '127.0.0.1'},
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
  };
  Object.defineProperty(win, 'sessionStorage', {configurable: true, ...descriptor});
  Object.defineProperty(globalThis, 'window', {configurable: true, writable: true, value: win});
  return Promise.resolve().then(() => fn(win)).finally(() => {
    if (prev) Object.defineProperty(globalThis, 'window', prev);
    else delete globalThis.window;
  });
}

const iso = (ms) => new Date(ms).toISOString();
const BASE_OG = {
  available: true,
  runtime_verified: true,
  probe_status: 'VERIFIED',
  health_state: 'VERIFIED',
  verification_level: 'SCAN_VERIFIED',
  version: '1.25.0',
  process_instance_id: 'fixture-process',
  probe_execution_identity_sha256: 'a'.repeat(64),
  binary_identity_sha256: 'b'.repeat(64),
  rules_sha256: 'c'.repeat(64),
};

function healthPayload({
  status = 'OK',
  checked,
  probed,
  expires,
  ttl = 2,
  ogPatch = {},
} = {}) {
  const og = {...BASE_OG, ttl_seconds: ttl, ...ogPatch};
  if (expires !== undefined) og.expires_at = iso(expires);
  if (probed !== undefined) og.probed_at = iso(probed);
  const out = {status, opengrep: og, degraded_reasons: []};
  if (checked !== undefined) out.checked_at = iso(checked);
  return out;
}

function assertHealthSurfaces(fp, backend, nowMs, {verified, expired}) {
  const view = fp.classifyBackendHealthState(backend, {nowMs});
  const headerVerified = /OPENGREP VERIFIED/.test(view.pillLabel);
  const sidebarVerified = /OpenGrep đã xác minh/.test(view.sidebarLabel);
  const statusVerified = Boolean(view.ogInfo?.isVerified);
  assert.equal(headerVerified, verified, `Header verified mismatch: ${view.pillLabel}`);
  assert.equal(sidebarVerified, verified, `Sidebar verified mismatch: ${view.sidebarLabel}`);
  assert.equal(statusVerified, verified, `StatusPage verified mismatch: ${view.ogInfo?.label}`);
  if (expired !== undefined) {
    const headerExpired = /EXPIRED/.test(view.pillLabel);
    const sidebarExpired = /EXPIRED/.test(view.sidebarLabel);
    const statusExpired = view.ogInfo?.healthState === 'EXPIRED';
    assert.equal(headerExpired, expired, `Header EXPIRED mismatch: ${view.pillLabel}`);
    assert.equal(sidebarExpired, expired, `Sidebar EXPIRED mismatch: ${view.sidebarLabel}`);
    assert.equal(statusExpired, expired, `StatusPage EXPIRED mismatch: ${view.ogInfo?.healthState}`);
  }
  return view;
}

test('P1-HEALTH-01: initially-expired probe (with/without probed_at, OK/DEGRADED) clamps deadline across refresh & reload, recovers only on new proof', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const hm = await loadModule('src/services/healthMonitor.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');

  const matrix = [
    {label: 'unanchored-OK-expired-by-time', anchored: false, status: 'OK', ogPatch: {}},
    {label: 'anchored-OK-expired-by-time', anchored: true, status: 'OK', ogPatch: {}},
    {label: 'unanchored-DEGRADED-explicit-EXPIRED', anchored: false, status: 'DEGRADED', ogPatch: {probe_status: 'EXPIRED', health_state: 'EXPIRED', available: false, runtime_verified: false}},
    {label: 'anchored-DEGRADED-explicit-EXPIRED', anchored: true, status: 'DEGRADED', ogPatch: {probe_status: 'EXPIRED', health_state: 'EXPIRED', available: false, runtime_verified: false}},
    {label: 'unanchored-OK-no-checked_at', anchored: false, status: 'OK', ogPatch: {}, omitChecked: true},
    {label: 'anchored-OK-no-checked_at', anchored: true, status: 'OK', ogPatch: {}, omitChecked: true},
  ];

  for (const cfg of matrix) {
    const t0 = Date.parse('2026-11-25T10:00:00.000Z');
    let now = t0;
    let rawJson = '';
    const storage = mkStorage();
    const timers = [];
    const cleared = [];
    const mk = () => hm.createHealthMonitor({
      storage,
      getScopeKey: () => `scope:${cfg.label}`,
      fetchHealth: async () => apiMod.parseJsonWithWireIntegrity(rawJson),
      now: () => now,
      setTimer: (fn, ms) => {
        const id = timers.length + 1;
        timers.push({id, fn, ms});
        return id;
      },
      clearTimer: (id) => cleared.push(id),
      retryDelaysMs: [],
    });

    const m1 = mk();
    const firstProbed = cfg.anchored ? t0 - 3000 : undefined;
    // 1. First observation is ALREADY expired (expires_at = t0 - 1000).
    rawJson = JSON.stringify(healthPayload({
      status: cfg.status,
      checked: cfg.omitChecked ? undefined : t0,
      probed: firstProbed,
      expires: t0 - 1000,
      ttl: 2,
      ogPatch: cfg.ogPatch,
    }));
    await m1.checkNow({force: true});
    assertHealthSurfaces(fp, m1.getSnapshot().backend, now, {verified: false, expired: true});
    assert.equal(m1.getSnapshot().backend.expiresAtMs, t0 - 1000, `${cfg.label}: records tightest deadline`);

    // 2. Same probe identity mutates expires_at & TTL forward -> MUST stay EXPIRED on all 3 surfaces,
    //    and deadline MUST stay monotonically non-increasing (never extended, may only tighten).
    now = t0 + 1000;
    let tightestDeadline = t0 - 1000;
    for (const [expDelta, ttl] of [[10000, 10], [60000, 60], [1000, 1], [30000, 30]]) {
      rawJson = JSON.stringify(healthPayload({
        status: 'OK',
        checked: cfg.omitChecked ? undefined : now,
        probed: firstProbed,
        expires: now + expDelta,
        ttl,
      }));
      await m1.checkNow({force: true});
      assertHealthSurfaces(fp, m1.getSnapshot().backend, now, {verified: false, expired: true});
      const currentDeadline = m1.getSnapshot().backend.expiresAtMs;
      assert.ok(
        typeof currentDeadline === 'number' && currentDeadline <= tightestDeadline,
        `${cfg.label}: deadline must stay monotonically non-increasing (${currentDeadline} <= ${tightestDeadline})`,
      );
      tightestDeadline = currentDeadline;
      assert.equal(
        Date.parse(m1.getSnapshot().backend.health?.opengrep?.expires_at),
        tightestDeadline,
        `${cfg.label}: health.opengrep.expires_at matches clamped deadline`,
      );
    }
    m1.dispose();

    // 3. Reload (new monitor sharing persisted ledger) with mutated expires_at/TTL -> MUST stay EXPIRED.
    const m2 = mk();
    rawJson = JSON.stringify(healthPayload({
      status: 'OK',
      checked: cfg.omitChecked ? undefined : now,
      probed: firstProbed,
      expires: now + 30000,
      ttl: 30,
    }));
    await m2.checkNow({force: true});
    assertHealthSurfaces(fp, m2.getSnapshot().backend, now, {verified: false, expired: true});
    assert.equal(m2.getSnapshot().backend.expiresAtMs, tightestDeadline, `${cfg.label}: reload keeps clamped deadline`);

    // 4. Malformed payload arrives -> fails closed, does NOT poison recovery when real new probe arrives.
    rawJson = JSON.stringify({
      status: 'OK',
      checked_at: 'not-a-timestamp',
      opengrep: {...BASE_OG, probed_at: iso(now + 999999), expires_at: iso(now + 1999999), ttl_seconds: 999},
    });
    await m2.checkNow({force: true});
    assertHealthSurfaces(fp, m2.getSnapshot().backend, now, {verified: false});

    // 5. Genuine new probe (new probed_at + distinct execution identity) recovers VERIFIED cleanly.
    const timersBeforeFresh = timers.length;
    rawJson = JSON.stringify(healthPayload({
      status: 'OK',
      checked: cfg.omitChecked ? undefined : now,
      probed: now,
      expires: now + 10000,
      ttl: 10,
      ogPatch: {probe_execution_identity_sha256: 'd'.repeat(64)},
    }));
    await m2.checkNow({force: true});
    assertHealthSurfaces(fp, m2.getSnapshot().backend, now, {verified: true, expired: false});
    assert.equal(m2.getSnapshot().backend.expiresAtMs, now + 10000);
    assert.ok(timers.length > timersBeforeFresh, `${cfg.label}: fresh probe armed TTL timer`);
    const freshTimerId = timers[timers.length - 1].id;

    // 6. Old initially-expired probe arrives AFTER fresh probe (even at SAME millisecond `now`)
    //    -> MUST preserve fresh probe AND MUST NOT cancel fresh probe's active TTL timer!
    rawJson = JSON.stringify(healthPayload({
      status: 'OK',
      checked: cfg.omitChecked ? undefined : now,
      probed: firstProbed,
      expires: now + 90000,
      ttl: 90,
    }));
    await m2.checkNow({force: true, preserveStatus: true});
    assertHealthSurfaces(fp, m2.getSnapshot().backend, now, {verified: true, expired: false});
    assert.equal(m2.getSnapshot().backend.expiresAtMs, now + 10000, `${cfg.label}: fresh deadline preserved`);
    assert.equal(cleared.includes(freshTimerId), false, `${cfg.label}: fresh TTL timer not cancelled`);

    m2.dispose();
  }
});

test('P1-HEALTH-01: unanchored initially-expired probe recovers when server starts emitting probed_at or distinct execution digest, and enforces storage/clock invariants', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const hm = await loadModule('src/services/healthMonitor.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');

  // A. Same config digests, first unanchored expired -> mutated unanchored blocked -> new probed_at recovers
  const t0 = Date.parse('2026-11-25T11:00:00.000Z');
  let now = t0;
  let rawJson = '';
  const storage = mkStorage();
  const mon = hm.createHealthMonitor({
    storage,
    getScopeKey: () => 'scope:upgrade-to-probed',
    fetchHealth: async () => apiMod.parseJsonWithWireIntegrity(rawJson),
    now: () => now,
    setTimer: () => 1,
    clearTimer: () => {},
    retryDelaysMs: [],
  });
  rawJson = JSON.stringify(healthPayload({checked: t0, expires: t0 - 500, ttl: 2}));
  await mon.checkNow({force: true});
  assertHealthSurfaces(fp, mon.getSnapshot().backend, now, {verified: false, expired: true});

  now = t0 + 1000;
  rawJson = JSON.stringify(healthPayload({checked: now, expires: now + 20000, ttl: 20}));
  await mon.checkNow({force: true});
  assertHealthSurfaces(fp, mon.getSnapshot().backend, now, {verified: false, expired: true});

  // Same digests, now with real probed_at -> distinct probe run -> recovers!
  rawJson = JSON.stringify(healthPayload({checked: now, probed: now, expires: now + 20000, ttl: 20}));
  await mon.checkNow({force: true});
  assertHealthSurfaces(fp, mon.getSnapshot().backend, now, {verified: true, expired: false});

  // Shortening deadline on same probe tightens monotonically, never extends back
  rawJson = JSON.stringify(healthPayload({checked: now, probed: now, expires: now + 5000, ttl: 5}));
  await mon.checkNow({force: true});
  assert.equal(mon.getSnapshot().backend.expiresAtMs, now + 5000);
  rawJson = JSON.stringify(healthPayload({checked: now, probed: now, expires: now + 25000, ttl: 25}));
  await mon.checkNow({force: true});
  assert.equal(mon.getSnapshot().backend.expiresAtMs, now + 5000);
  mon.dispose();

  // B. Storage unavailable / write error: first response gated when unstamped; initially-expired still clamped in RAM!
  const throwingSet = {value: mkStorage({setItem() { throw new DOMException('denied', 'QuotaExceededError'); }})};
  await withWindow(throwingSet, async () => {
    const hmWin = await loadModule('src/services/healthMonitor.js');
    const fpWin = await loadRawEsm('src/services/findingPresentation.js');
    const baseNow = Date.now();
    let payload = healthPayload({expires: baseNow + 30000, ttl: 30}); // unstamped (no checked_at)
    const mWin = hmWin.createHealthMonitor({fetchHealth: async () => payload, retryDelaysMs: []});
    // First unstamped response gated immediately despite write-only failure
    await mWin.checkNow({force: true});
    assertHealthSurfaces(fpWin, mWin.getSnapshot().backend, Date.now(), {verified: false});

    // Initially expired (stamped) -> recorded in RAM even when storage throws
    const tExp = Date.now();
    payload = healthPayload({checked: tExp, expires: tExp - 2000, ttl: 2, ogPatch: {probe_execution_identity_sha256: 'e'.repeat(64)}});
    await mWin.checkNow({force: true});
    assertHealthSurfaces(fpWin, mWin.getSnapshot().backend, Date.now(), {verified: false, expired: true});

    // Same identity shifted forward with checked_at in same session -> STILL blocked by RAM ledger!
    const tShift = Date.now();
    payload = healthPayload({checked: tShift, expires: tShift + 30000, ttl: 30, ogPatch: {probe_execution_identity_sha256: 'e'.repeat(64)}});
    await mWin.checkNow({force: true});
    assertHealthSurfaces(fpWin, mWin.getSnapshot().backend, Date.now(), {verified: false, expired: true});

    // Distinct new stamped execution -> recovers VERIFIED
    const tNew = Date.now();
    payload = healthPayload({checked: tNew, probed: tNew, expires: tNew + 30000, ttl: 30, ogPatch: {probe_execution_identity_sha256: 'f'.repeat(64)}});
    await mWin.checkNow({force: true});
    assertHealthSurfaces(fpWin, mWin.getSnapshot().backend, Date.now(), {verified: true, expired: false});
    mWin.dispose();
  });
});

test('P1-COVERAGE-01: uniform REST integrity across all participating coverage containers (wire/normalized/copy/JSON) and History/Findings/Reports parity', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  const sh = await loadModule('src/services/scanHistory.js');
  const parse = apiMod.parseJsonWithWireIntegrity;

  const WG = '"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"';
  const JVL = '"java_files_inventory":19,"java_files_opengrep_scanned":19,"java_files_opengrep_ignored":0,"opengrep_paths_telemetry_status":"VERIFIED"';

  function checkAllRepresentations(raw, {expectedVerified, expectedCounts = null, label, rawJob = null}) {
    const wire = parse(raw);
    const norm = apiMod.materializeNormalizedTelemetry(wire).value;
    const shallow = {...norm};
    const roundTrip = JSON.parse(JSON.stringify(norm));

    const jobWire = rawJob ? parse(rawJob) : null;
    const jobNorm = jobWire ? apiMod.materializeNormalizedTelemetry(jobWire).value : null;
    const jobShallow = jobNorm ? {...jobNorm} : null;
    const jobRoundTrip = jobNorm ? JSON.parse(JSON.stringify(jobNorm)) : null;

    const results = [
      ['wire', fp.resolveJavaFileCounts(wire, jobWire)],
      ['normalized', fp.resolveJavaFileCounts(norm, jobNorm)],
      ['shallow', fp.resolveJavaFileCounts(shallow, jobShallow)],
      ['json', fp.resolveJavaFileCounts(roundTrip, jobRoundTrip)],
    ];

    // Strict 4-way parity: wire, normalized, shallow copy, and JSON round-trip MUST agree!
    const [firstName, firstRes] = results[0];
    for (const [kind, r] of results) {
      assert.equal(r.hasVerifiedScanned, expectedVerified, `${label} [${kind}] verified=${r.hasVerifiedScanned} problem=${r.canonicalCoverageProblem}`);
      assert.equal(r.coverageStatus, firstRes.coverageStatus, `${label} [${kind}] status ${r.coverageStatus} !== ${firstName} ${firstRes.coverageStatus}`);
      assert.equal(r.scannedCount, firstRes.scannedCount, `${label} [${kind}] scannedCount mismatch vs ${firstName}`);
      assert.equal(r.ignoredCount, firstRes.ignoredCount, `${label} [${kind}] ignoredCount mismatch vs ${firstName}`);
      if (expectedVerified && expectedCounts) {
        assert.deepEqual([r.inventoryCount, r.scannedCount, r.ignoredCount], expectedCounts, `${label} [${kind}] counts`);
      } else if (!expectedVerified) {
        assert.equal(r.scannedCount, null, `${label} [${kind}] scanned must be hidden`);
        assert.equal(r.ignoredCount, null, `${label} [${kind}] ignored must be hidden`);
      }
    }

    if (!rawJob) {
      // History path (scanHistory.historyRecordFromBackend)
      const histItem = parse(raw.replace(/^\{/, '{"scan_id":"scan-cov-parity",'));
      const histRec = sh.historyRecordFromBackend(histItem, {origin: 'http://127.0.0.1:19981', sessionScope: 's1'});
      assert.equal(Boolean(histRec.javaCounts?.hasVerifiedScanned), expectedVerified, `${label} [history]`);
      if (!expectedVerified && histRec.javaCounts) {
        assert.equal(histRec.javaCounts.scannedCount, null, `${label} [history scanned null]`);
      }
      // Reports path (report.scan_summary)
      const reportDoc = parse(`{"scan_summary":${raw},"findings":[]}`);
      const repRes = fp.resolveJavaFileCounts(reportDoc.scan_summary);
      assert.equal(repRes.hasVerifiedScanned, expectedVerified, `${label} [reports]`);
      assert.equal(repRes.coverageStatus, firstRes.coverageStatus, `${label} [reports status parity]`);
      if (!expectedVerified) assert.equal(repRes.scannedCount, null, `${label} [reports scanned null]`);
    }
  }

  // 1. Positive controls: WebGoat & JVL valid canonical records
  checkAllRepresentations(`{${WG}}`, {expectedVerified: true, expectedCounts: [498, 389, 109], label: 'webgoat-valid'});
  checkAllRepresentations(`{${JVL}}`, {expectedVerified: true, expectedCounts: [19, 19, 0], label: 'jvl-valid'});
  checkAllRepresentations(`{${WG},"java_files_scanned":498,"scan_manifest":{"paths":{"scanned":[],"ignored":[]}}}`, {
    expectedVerified: false, // paths length 0 conflicts with 389/109!
    label: 'webgoat-conflicting-empty-paths',
  });
  checkAllRepresentations(`{${WG},"java_files_scanned":498,"scan_manifest":{"version":"1"}}`, {
    expectedVerified: true,
    expectedCounts: [498, 389, 109],
    label: 'webgoat-with-clean-manifest',
  });

  // 2. Codex P1-COVERAGE-01 exact counterexamples & sibling participating-container corruptions
  checkAllRepresentations(`{${WG},"scan_manifest":{"__wireIntegrity":null}}`, {expectedVerified: false, label: 'manifest-reserved-null'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"unrelated":1,"unrelated":2}}`, {expectedVerified: false, label: 'manifest-duplicate-conflicting'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"unrelated":1,"unrelated":1}}`, {expectedVerified: false, label: 'manifest-duplicate-equal'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"unrelat\\u0065d":1,"unrelated":2}}`, {expectedVerified: false, label: 'manifest-duplicate-unicode'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"__wireIntegrity":{"hasMalformed":false,"hasConflict":false}}}`, {expectedVerified: false, label: 'manifest-reserved-forged-clean'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"__wireIntegrity":42}}`, {expectedVerified: false, label: 'manifest-reserved-number'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"__wireIntegrity":{"duplicateKeyPaths":7}}}`, {expectedVerified: false, label: 'manifest-reserved-bad-shape'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"__wireIntegrity":null,"__wireIntegrity":{"hasMalformed":true}}}`, {expectedVerified: false, label: 'manifest-reserved-duplicate'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"paths":{"__wireIntegrity":null}}}`, {expectedVerified: false, label: 'manifest-paths-reserved-null'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"paths":{"a":1,"a":2}}}`, {expectedVerified: false, label: 'manifest-paths-duplicate'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"nested":{"k":1,"k":2}}}`, {expectedVerified: false, label: 'manifest-nested-duplicate'});
  checkAllRepresentations(`{${WG},"scan_manifest":[]}`, {expectedVerified: false, label: 'manifest-corrupt-array'});
  checkAllRepresentations(`{${WG},"scan_manifest":"corrupt"}`, {expectedVerified: false, label: 'manifest-corrupt-string'});
  checkAllRepresentations(`{${WG},"scan_manifest":{},"manifest":{"__wireIntegrity":null}}`, {expectedVerified: false, label: 'alt-manifest-reserved-null-when-scan_manifest-present'});
  checkAllRepresentations(`{${WG},"scan_manifest":{},"manifest":{"java_files_opengrep_scanned":100}}`, {expectedVerified: false, label: 'alt-manifest-conflicting-count'});
  checkAllRepresentations(`{${WG},"scan_provenance":{"__wireIntegrity":null}}`, {expectedVerified: false, label: 'scan_provenance-reserved-null'});
  checkAllRepresentations(`{${WG},"scan_provenance":{"origin":"REAL","origin":"MOCK"}}`, {expectedVerified: false, label: 'scan_provenance-duplicate'});

  // 3. Corrupt main container + valid secondary container -> MUST reject!
  checkAllRepresentations(`{"__wireIntegrity":null,"scan_manifest":{${WG}}}`, {expectedVerified: false, label: 'corrupt-root-reserved-valid-manifest'});
  checkAllRepresentations(`{"scan_id":"a","scan_id":"b","scan_manifest":{${WG}}}`, {expectedVerified: false, label: 'corrupt-root-duplicate-valid-manifest'});
  checkAllRepresentations(`{"__wireIntegrity":{"hasMalformed":true},"scan_manifest":{${WG}}}`, {expectedVerified: false, label: 'corrupt-root-taint-valid-manifest'});
  // Clean root + canonical inside clean scan_manifest -> POSITIVE control
  checkAllRepresentations(`{"scan_manifest":{${WG}}}`, {expectedVerified: true, expectedCounts: [498, 389, 109], label: 'clean-root-canonical-in-manifest'});

  // 4. Job stage participating containers
  checkAllRepresentations(`{${WG}}`, {
    expectedVerified: false,
    label: 'job-stage2-meta-reserved-null',
    rawJob: '{"stages":[{"summary_metadata":{}},{"summary_metadata":{"__wireIntegrity":null}}]}',
  });
  checkAllRepresentations(`{${WG}}`, {
    expectedVerified: false,
    label: 'job-stage2-timing-duplicate',
    rawJob: '{"stages":[{"summary_metadata":{}},{"summary_metadata":{"opengrep_timing":{"x":1,"x":2}}}]}',
  });
  checkAllRepresentations(`{${WG}}`, {
    expectedVerified: false,
    label: 'job-stage1-meta-duplicate',
    rawJob: '{"stages":[{"summary_metadata":{"a":1,"a":2}},{"summary_metadata":{}}]}',
  });
  checkAllRepresentations(`{${WG}}`, {
    expectedVerified: true,
    expectedCounts: [498, 389, 109],
    label: 'job-clean-stages',
    rawJob: '{"stages":[{"summary_metadata":{"java_files_count":498}},{"summary_metadata":{"opengrep_timing":{"duration_ms":120.5}}}]}',
  });

  // 5. Missing canonical, aliases, non-closing, precision loss, conflicting sources
  checkAllRepresentations('{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"}', {expectedVerified: false, label: 'alias-replaces-ignored'});
  checkAllRepresentations('{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":108,"opengrep_paths_telemetry_status":"VERIFIED"}', {expectedVerified: false, label: 'non-closing-sum'});
  checkAllRepresentations('{"java_files_inventory":498,"java_files_opengrep_scanned":389.000000000000000000001,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"}', {expectedVerified: false, label: 'wire-precision-loss-rounds-to-389'});
  checkAllRepresentations('{"java_files_inventory":498,"java_files_opengrep_scanned":9007199254740993,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"}', {expectedVerified: false, label: 'wire-unsafe-integer'});
  checkAllRepresentations(`{${WG},"scan_manifest":{"java_files_opengrep_scanned":388}}`, {expectedVerified: false, label: 'conflicting-manifest-scanned'});

  // 6. Isolation positive controls: unrelated non-coverage sibling subtrees / scalar floats
  //    MUST NOT falsely reject valid canonical coverage on wire, normalized, copy, or JSON!
  checkAllRepresentations(`{${WG},"other_unrelated_section":{"note":1,"note":2}}`, {
    expectedVerified: true,
    expectedCounts: [498, 389, 109],
    label: 'unrelated-sibling-duplicate-isolated',
  });
  checkAllRepresentations(`{${WG},"other_unrelated_section":{"__wireIntegrity":null}}`, {
    expectedVerified: true,
    expectedCounts: [498, 389, 109],
    label: 'unrelated-sibling-reserved-isolated',
  });
  checkAllRepresentations(`{${WG},"total_e2e_duration_ms":1234.5,"unrelated_metric_count":1.5}`, {
    expectedVerified: true,
    expectedCounts: [498, 389, 109],
    label: 'unrelated-float-scalars-isolated',
  });

  // 7. Adversarial combo: root untrusted __wireIntegrity + unrelated sibling duplicate -> STILL REJECTED on all 4 views!
  checkAllRepresentations(`{${WG},"__wireIntegrity":{"hasMalformed":true},"other_unrelated_section":{"note":1,"note":2}}`, {
    expectedVerified: false,
    label: 'root-untrusted-taint-plus-unrelated-sibling-still-rejected',
  });
});
