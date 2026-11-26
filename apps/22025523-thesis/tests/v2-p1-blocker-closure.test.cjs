// Targeted tests for the four P1 blockers from the final independent audit:
// A) F02 same-probe TTL change must never resurrect or extend an expired probe.
// B) G3-F01 canonical coverage must be complete, valid and closed before "actually scanned" is shown.
// C) F02 denied/broken sessionStorage must not blank the app or grant unanchored VERIFIED.
// D) F05 malformed reserved `__wireIntegrity` metadata must not throw and must stay MALFORMED.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const esbuild = require('esbuild');

const APP_ROOT = path.resolve(__dirname, '..');
let bustSeq = 0;

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
  bustSeq += 1;
  const code = `${built.outputFiles[0].text}\n// bust ${bustSeq}`;
  return import(`data:text/javascript;base64,${Buffer.from(code, 'utf8').toString('base64')}`);
}

async function loadRawEsm(relPath) {
  bustSeq += 1;
  const code = `${fs.readFileSync(path.join(APP_ROOT, relPath), 'utf8')}\n// bust ${bustSeq}`;
  return import(`data:text/javascript;base64,${Buffer.from(code, 'utf8').toString('base64')}`);
}

function mkStorage() {
  const map = new Map();
  return {
    _map: map,
    get length() { return map.size; },
    key(i) { return [...map.keys()][i] ?? null; },
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(String(k), String(v)); },
    removeItem(k) { map.delete(String(k)); },
    clear() { map.clear(); },
  };
}

function createFakeClock(startMs) {
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
    clearTimer(id) { timers.delete(id); },
    activeTimerIds() { return [...timers.keys()]; },
    advance(ms) {
      current += ms;
      for (;;) {
        const due = [...timers.values()].filter((t) => t.at <= current).sort((a, b) => a.at - b.at || a.id - b.id);
        if (!due.length) break;
        timers.delete(due[0].id);
        due[0].fn();
      }
    },
  };
}

function withWindow(storageDescriptor, fn) {
  const prev = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const win = {
    location: {origin: 'http://127.0.0.1:19950', hostname: '127.0.0.1'},
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
  };
  Object.defineProperty(win, 'sessionStorage', {configurable: true, ...storageDescriptor});
  Object.defineProperty(globalThis, 'window', {configurable: true, writable: true, value: win});
  const restore = () => {
    if (prev) Object.defineProperty(globalThis, 'window', prev);
    else delete globalThis.window;
  };
  return Promise.resolve().then(() => fn(win)).finally(restore);
}

const PROOF = {
  available: true,
  runtime_verified: true,
  probe_status: 'VERIFIED',
  health_state: 'VERIFIED',
  verification_level: 'SCAN_VERIFIED',
  version: '1.25.0',
  process_instance_id: 'p1-proc',
};

function healthBody(t, {ttl, expiresMs, checkedMs, probedMs = t} = {}) {
  return {
    status: 'OK',
    ...(checkedMs === null ? {} : {checked_at: new Date(checkedMs ?? t).toISOString()}),
    opengrep: {
      ...PROOF,
      probed_at: new Date(probedMs).toISOString(),
      expires_at: new Date(expiresMs).toISOString(),
      ttl_seconds: ttl,
    },
    degraded_reasons: [],
  };
}

test('Blocker A (F02): same probe with changed TTL / expires_at never resurrects or extends; new probe recovers; old probe never overrides new', async () => {
  const hm = await loadModule('src/services/healthMonitor.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  const t0 = Date.parse('2026-11-25T10:00:00.000Z');
  const clock = createFakeClock(t0);
  const storage = mkStorage();
  let body = null;
  const mk = () => hm.createHealthMonitor({
    fetchHealth: async () => JSON.parse(JSON.stringify(body)),
    getScopeKey: () => 'scope-p1-a',
    storage,
    now: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    retryDelaysMs: [],
  });
  const view = (m) => fp.classifyBackendHealthState(m.getSnapshot().backend, {nowMs: clock.now()});
  const allNotVerified = (v) => !v.ogInfo.isVerified && !/OPENGREP VERIFIED/.test(v.pillLabel) && !/OpenGrep đã xác minh/.test(v.sidebarLabel);

  // Codex fixture shape: server clock +60s, expires_at fixed far away, ttl 2 then 30.
  const skew = 60000;
  const proofT = t0 + skew;
  const base = {ttl: 2, probedMs: proofT - 100, expiresMs: proofT + 35000, checkedMs: proofT};
  body = healthBody(proofT, base);
  const m = mk();
  await m.checkNow({force: true});
  assert.equal(view(m).ogInfo.isVerified, true);
  const firstDeadline = m.getSnapshot().backend.expiresAtMs;
  assert.ok(firstDeadline <= t0 + 2000, 'deadline clamped by ttl 2s');

  // 2. TTL increased BEFORE expiry on the same probe: deadline must not move later.
  clock.advance(500);
  body = healthBody(proofT, {...base, ttl: 30});
  await m.checkNow({force: true});
  assert.equal(m.getSnapshot().backend.expiresAtMs, firstDeadline, 'same probe TTL increase must not extend deadline');

  // 3. TTL decreased on the same probe: never later than the earlier deadline.
  body = healthBody(proofT, {...base, ttl: 1});
  await m.checkNow({force: true});
  assert.ok(m.getSnapshot().backend.expiresAtMs <= firstDeadline);
  const tightened = m.getSnapshot().backend.expiresAtMs;

  // Passive expiry.
  clock.advance(3000);
  assert.ok(allNotVerified(view(m)));
  assert.equal(view(m).ogInfo.healthState, 'EXPIRED');

  // 1. TTL 2 -> 30 AFTER expiry on the same probe: stays not verified on all consumers.
  body = healthBody(proofT, {...base, ttl: 30});
  await m.checkNow({force: true});
  assert.ok(allNotVerified(view(m)), 'same expired probe with larger TTL must not resurrect');
  // Same probed_at with a later expires_at is still the same probe.
  body = healthBody(proofT, {...base, ttl: 30, expiresMs: proofT + 600000});
  await m.checkNow({force: true});
  assert.ok(allNotVerified(view(m)), 'same expired probe with later expires_at must not resurrect');
  assert.ok(tightened <= firstDeadline);

  // 6. Reload (new monitor, same persisted ledger) + identical replay with larger TTL: still not verified.
  m.dispose();
  const m2 = mk();
  body = healthBody(proofT, {...base, ttl: 30});
  await m2.checkNow({force: true});
  assert.ok(allNotVerified(view(m2)), 'reload must not resurrect the expired probe');

  // 4. Genuinely new probe recovers VERIFIED.
  const t1 = clock.now() + skew;
  const fresh = {ttl: 30, probedMs: t1 - 50, expiresMs: t1 + 30000, checkedMs: t1};
  body = healthBody(t1, fresh);
  await m2.checkNow({force: true});
  assert.equal(view(m2).ogInfo.isVerified, true, 'new probe must verify');
  const timers = clock.activeTimerIds();
  assert.equal(timers.length, 1);

  // 5. Older probe arriving after the newer one keeps the newer state and the exact timer handle.
  body = healthBody(proofT, {...base, ttl: 300, expiresMs: proofT + 900000, checkedMs: t1});
  await m2.checkNow({force: true, preserveStatus: true});
  assert.equal(view(m2).ogInfo.isVerified, true);
  assert.deepEqual(clock.activeTimerIds(), timers, 'timer of the newer probe must be preserved');
  assert.equal(m2.getSnapshot().meta.staleSnapshotIgnored, true);
  m2.dispose();

  // Signature excludes deadline attributes.
  const evA = fp.resolveOpengrepExpiryEvidence(healthBody(proofT, base).opengrep, t0, {serverCheckedAtMs: proofT});
  const evB = fp.resolveOpengrepExpiryEvidence(healthBody(proofT, {...base, ttl: 30, expiresMs: proofT + 99000}).opengrep, t0, {serverCheckedAtMs: proofT});
  assert.equal(
    hm.buildProbeProofSignature(healthBody(proofT, base).opengrep, evA),
    hm.buildProbeProofSignature(healthBody(proofT, {...base, ttl: 30}).opengrep, evB),
  );
});

test('Blocker B (G3-F01): canonical coverage gate (status + three valid counts + closed sum) across model and History', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  const sh = await loadModule('src/services/scanHistory.js');
  const parse = apiMod.parseJsonWithWireIntegrity;
  const rec = (inv, sc, ig, status = 'VERIFIED') => JSON.stringify({
    ...(inv === undefined ? {} : {java_files_inventory: inv}),
    ...(sc === undefined ? {} : {java_files_opengrep_scanned: sc}),
    ...(ig === undefined ? {} : {java_files_opengrep_ignored: ig}),
    ...(status === null ? {} : {opengrep_paths_telemetry_status: status}),
  });
  const positives = [
    ['jvl', rec(19, 19, 0), [19, 19, 0]],
    ['webgoat', rec(498, 389, 109), [498, 389, 109]],
    ['other-valid', rec(1234, 1000, 234), [1234, 1000, 234]],
    ['zero', rec(0, 0, 0), [0, 0, 0]],
  ];
  for (const [id, raw, counts] of positives) {
    const r = fp.resolveJavaFileCounts(parse(raw));
    assert.equal(r.hasVerifiedScanned, true, id);
    assert.equal(r.coverageStatus, 'VERIFIED', id);
    assert.deepEqual([r.inventoryCount, r.scannedCount, r.ignoredCount], counts, id);
  }
  const negatives = [
    ['missing-status', rec(498, 389, 109, null)],
    ['missing-ignored', rec(498, 389, undefined)],
    ['missing-inventory', rec(undefined, 389, 109)],
    ['missing-scanned', rec(498, undefined, 109)],
    ['null-ignored', '{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":null,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['undercount', rec(498, 389, 108)],
    ['overcount', rec(498, 389, 110)],
    ['scanned-over-inventory', rec(10, 11, 0)],
    ['unicode-dup-ignored-equal', '{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"java_files_opengrep_ignor\\u0065d":109,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['unicode-dup-ignored-conflict', '{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":108,"java_files_opengrep_ignor\\u0065d":109,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['rounded-ignored', '{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109.000000000000001,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['rounded-inventory', '{"java_files_inventory":498.00000000000001,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['unsafe-int', '{"java_files_inventory":9007199254740993,"java_files_opengrep_scanned":9007199254740992,"java_files_opengrep_ignored":1,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['missing-paths-telemetry', rec(498, 389, 109, 'MISSING_PATHS_TELEMETRY')],
    ['unknown-status', rec(498, 389, 109, 'OK')],
    ['legacy-only', '{"java_files_scanned":498,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['legacy-plus-partial', '{"java_files_scanned":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED"}'],
    ['dup-status', '{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"MISSING_PATHS_TELEMETRY","opengrep_paths_telemetry_status":"VERIFIED"}'],
  ];
  for (const [id, raw] of negatives) {
    const r = fp.resolveJavaFileCounts(parse(raw));
    assert.equal(r.hasVerifiedScanned, false, id);
    assert.equal(r.scannedCount, null, `${id}: scanned must not be presented`);
    assert.equal(r.ignoredCount, null, `${id}: ignored must not be presented`);
    assert.notEqual(r.primaryLabel, 'Tệp Java thực quét (OpenGrep)', id);
    assert.equal(String(r.summaryNote).includes('Thực quét: 389'), false, id);
  }
  // null is never turned into 0
  const nullIgnored = fp.resolveJavaFileCounts(parse(negatives.find((n) => n[0] === 'null-ignored')[1]));
  assert.equal(nullIgnored.rawCounts.ignored, null);
  // Legacy keeps inventory semantics
  const legacy = fp.resolveJavaFileCounts(parse('{"java_files_scanned":498}'));
  assert.equal(legacy.inventoryCount, 498);
  assert.equal(legacy.inventoryFromLegacy, true);
  assert.equal(legacy.coverageStatus, 'INVENTORY_ONLY');

  // History uses the same normalizer
  const hist = sh.historyRecordFromBackend(parse('{"scan_id":"s-g3","java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109}'), {origin: 'http://127.0.0.1:19951', sessionScope: 's'});
  assert.equal(hist.javaCounts.hasVerifiedScanned, false);
  assert.equal(hist.javaCounts.scannedCount, null);
  assert.equal(hist.javaCounts.coverageStatus, 'UNVERIFIED');
  const histOk = sh.historyRecordFromBackend(parse(`{"scan_id":"s-g3b",${rec(498, 389, 109).slice(1)}`), {origin: 'http://127.0.0.1:19951', sessionScope: 's'});
  assert.equal(histOk.javaCounts.scannedCount, 389);
});

test('Blocker C (F02): denied, throwing, corrupted and normal sessionStorage', async () => {
  const deniedGetter = {get() { throw new DOMException('denied', 'SecurityError'); }};

  // C1. Throwing getter: modules import, scope key works, helpers degrade to null/false.
  await withWindow(deniedGetter, async () => {
    const apiMod = await loadRawEsm('src/services/api.js');
    assert.equal(apiMod.getSessionStorageSafe(), null);
    assert.equal(apiMod.safeSessionGet('x'), null);
    assert.equal(apiMod.safeSessionSet('x', '1'), false);
    assert.equal(apiMod.safeSessionRemove('x'), false);
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19952', token: 'p1-denied-token-value'});
    const key = apiMod.getHealthPersistenceScopeKey();
    assert.match(key, /\|auth:[0-9a-f]{32}$/);
    assert.equal(key.includes('p1-denied-token-value'), false);
    const ls = await loadModule('src/services/liveScan.js');
    assert.equal(ls.clearStaleActiveScanId('abc'), false);
  });

  // C2. Default-path monitor with throwing getter: VERIFIED only when server-anchored (checked_at present).
  for (const [label, descriptor, setup] of [
    ['getter-throws', deniedGetter, null],
    ['getItem-throws', {value: {getItem() { throw new Error('read'); }, setItem() {}, removeItem() {}}}, null],
    ['setItem-throws', {value: {getItem: () => null, setItem() { throw new DOMException('q', 'QuotaExceededError'); }, removeItem() {}}}, null],
    ['corrupted-ledger', {value: mkStorage()}, (s) => s.setItem('22025523-health-proof-ledger-v1', '{not json')],
  ]) {
    await withWindow(descriptor, async (win) => {
      if (setup) setup(win.sessionStorage);
      const hm = await loadModule('src/services/healthMonitor.js');
      const fp = await loadRawEsm('src/services/findingPresentation.js');
      const now = Date.now();
      let body = healthBody(now, {ttl: 60, expiresMs: now + 60000, checkedMs: null});
      const mon = hm.createHealthMonitor({fetchHealth: async () => body, retryDelaysMs: []});
      await mon.checkNow({force: true});
      // The conservative gate must apply on the very first response (no later poll needed).
      assert.equal(fp.classifyBackendHealthState(mon.getSnapshot().backend).ogInfo.isVerified, false, `${label}: unanchored proof must not verify`);
      body = healthBody(Date.now(), {ttl: 60, expiresMs: Date.now() + 60000});
      await mon.checkNow({force: true});
      assert.equal(fp.classifyBackendHealthState(mon.getSnapshot().backend).ogInfo.isVerified, true, `${label}: server-anchored fresh probe can verify`);
      mon.dispose();
    });
  }

  // C3. Normal storage keeps the previous behaviour (unanchored but fresh proof verifies; ledger written).
  await withWindow({value: mkStorage()}, async (win) => {
    const hm = await loadModule('src/services/healthMonitor.js');
    const fp = await loadRawEsm('src/services/findingPresentation.js');
    const now = Date.now();
    const mon = hm.createHealthMonitor({fetchHealth: async () => healthBody(now, {ttl: 60, expiresMs: now + 60000, checkedMs: null}), retryDelaysMs: []});
    await mon.checkNow({force: true});
    assert.equal(fp.classifyBackendHealthState(mon.getSnapshot().backend).ogInfo.isVerified, true);
    assert.ok(win.sessionStorage.getItem('22025523-health-proof-ledger-v1'));
    for (const [k, v] of win.sessionStorage._map.entries()) {
      assert.equal(/Bearer|Authorization/.test(`${k}${v}`), false);
    }
    mon.dispose();
  });
});

test('Blocker D (F05): malformed reserved __wireIntegrity never throws and never yields ALL_MATCHED', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const jm = await loadRawEsm('src/services/jobModel.js');
  const lsp = await loadModule('src/components/scanner/liveStagePresentation.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  const ls = await loadModule('src/services/liveScan.js');
  const clean = '"matched_count":4,"invalid_count":0,"not_verified_count":0,"total_checked":4';
  const rounded = '"matched_count":4,"invalid_count":0,"not_verified_count":0,"total_checked":4.0000000000000001';
  const reserved = ['null', '"x"', '42', 'true', '[]', '[1,2]', '{}', '{"valid":true}', '{"duplicateKeyPaths":42}',
    '{"duplicateKeys":[1]}', '{"duplicateKeys":{"a":5}}', '{"duplicateKeys":"x"}', '{"invalidFields":"x"}',
    '{"invalidFields":[1]}', '{"hasMalformed":"yes"}', '{"scannerError":1}'];
  const stageFor = (meta) => jm.resolveStages(apiMod.parseJsonWithWireIntegrity(`{"stages":[{"stage_no":5,"status":"COMPLETED","summary_metadata":{${meta}}}]}`))[4];
  const variants = (s) => [s, {...s}, {...s, summary: {...s.summary}}, structuredClone(s), JSON.parse(JSON.stringify(s))];
  for (const body of [clean, rounded]) {
    for (const r of reserved) {
      let stage;
      assert.doesNotThrow(() => { stage = stageFor(`${body},"__wireIntegrity":${r}`); }, r);
      for (const v of variants(stage)) {
        for (const mode of ['LIVE', 'PLAYBACK']) {
          let status;
          assert.doesNotThrow(() => { status = lsp.resolveStage05CitationTelemetry({mode, stage: v}).aggregateStatus; }, `${mode} ${r}`);
          assert.equal(status, 'MALFORMED', `${mode} ${body === clean ? 'clean' : 'rounded'} ${r}`);
        }
      }
    }
  }
  // Positive control: clean counts without the reserved key stay ALL_MATCHED, no extra properties.
  const ok = stageFor(clean);
  assert.equal(Object.hasOwn(ok.summary, '__wireIntegrity'), false);
  for (const v of variants(ok)) {
    for (const mode of ['LIVE', 'PLAYBACK']) {
      assert.equal(lsp.resolveStage05CitationTelemetry({mode, stage: v}).aggregateStatus, 'ALL_MATCHED');
    }
  }
  // Readers on raw objects with malformed reserved metadata do not throw.
  for (const r of reserved) {
    const obj = apiMod.parseJsonWithWireIntegrity(`{"total_findings":1,"__wireIntegrity":${r}}`);
    assert.doesNotThrow(() => apiMod.getWireObjectIntegrity(obj));
    assert.doesNotThrow(() => apiMod.getWireDuplicateKeyInfo(obj, 'total_findings'));
    assert.doesNotThrow(() => apiMod.readStrictWireSafeInt(obj, 'total_findings'));
    assert.doesNotThrow(() => apiMod.materializeNormalizedTelemetry(obj));
    assert.equal(apiMod.getWireObjectIntegrity(obj).materialized.hasMalformed, true, r);
    assert.doesNotThrow(() => fp.resolveJavaFileCounts(apiMod.parseJsonWithWireIntegrity(`{"java_files_inventory":1,"__wireIntegrity":${r}}`)));
    assert.doesNotThrow(() => ls.validateScanCountersAndPagination(obj, {findings: [], total_count: 1}));
  }
});
