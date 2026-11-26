// Invariant matrices for the two remaining root-cause groups:
// A) Health lifecycle: probe identity, deadline monotonicity, storage/ledger gate, consumer parity.
// B) REST integrity + canonical coverage gate across wire / normalize / copy / JSON and History/Findings/Reports.
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
  const win = {location: {origin: 'http://127.0.0.1:19970', hostname: '127.0.0.1'}, setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout};
  Object.defineProperty(win, 'sessionStorage', {configurable: true, ...descriptor});
  Object.defineProperty(globalThis, 'window', {configurable: true, writable: true, value: win});
  return Promise.resolve().then(() => fn(win)).finally(() => {
    if (prev) Object.defineProperty(globalThis, 'window', prev);
    else delete globalThis.window;
  });
}

const iso = (ms) => new Date(ms).toISOString();
const PROOF = {available: true, runtime_verified: true, probe_status: 'VERIFIED', health_state: 'VERIFIED', verification_level: 'SCAN_VERIFIED', version: '1.25.0', process_instance_id: 'inv-proc', probe_execution_identity_sha256: 'a'.repeat(64)};
function body({probed, expires, ttl, checked, exec, proc} = {}) {
  const og = {...PROOF, expires_at: iso(expires), ttl_seconds: ttl};
  if (probed !== undefined) og.probed_at = iso(probed);
  if (exec) og.probe_execution_identity_sha256 = exec;
  if (proc) og.process_instance_id = proc;
  const b = {status: 'OK', opengrep: og, degraded_reasons: []};
  if (checked !== undefined) b.checked_at = checked === 'bad' ? 'not-a-time' : iso(checked);
  return b;
}

function consumerParity(fp, backend, nowMs) {
  const v = fp.classifyBackendHealthState(backend, {nowMs});
  const header = /OPENGREP VERIFIED/.test(v.pillLabel);
  const sidebar = /OpenGrep đã xác minh/.test(v.sidebarLabel);
  const status = v.ogInfo.isVerified;
  assert.equal(header, status, `header vs status: ${v.pillLabel}`);
  assert.equal(sidebar, status, `sidebar vs status: ${v.sidebarLabel}`);
  return status;
}

test('A — probe identity and deadline monotonicity matrix (probed_at present/absent x expires x ttl, refresh/reload, old/new)', async () => {
  const hm = await loadModule('src/services/healthMonitor.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  let cases = 0;
  for (const anchored of [true, false]) {
    for (const checkedMode of ['present', 'absent']) {
      for (const expiresMode of ['same', 'increase', 'decrease']) {
        for (const ttlMode of ['same', 'increase', 'decrease']) {
          let now = Date.parse('2026-11-25T08:00:00.000Z');
          const storage = mkStorage();
          let payload;
          const mk = () => hm.createHealthMonitor({fetchHealth: async () => JSON.parse(JSON.stringify(payload)), getScopeKey: () => 'inv-scope', storage, now: () => now, setTimer: () => 1, clearTimer: () => {}, retryDelaysMs: []});
          const skew = 60000;
          const t0 = now + skew;
          const base = {probed: anchored ? t0 - 100 : undefined, expires: t0 + 2900, ttl: 3, checked: checkedMode === 'present' ? t0 : undefined};
          const variant = (extra) => {
            const expires = expiresMode === 'same' ? base.expires : expiresMode === 'increase' ? base.expires + 60000 : base.expires - 1000;
            const ttl = ttlMode === 'same' ? base.ttl : ttlMode === 'increase' ? 90 : 1;
            return body({...base, expires, ttl, ...extra});
          };
          const m = mk();
          payload = body(base);
          await m.checkNow({force: true});
          assert.equal(consumerParity(fp, m.getSnapshot().backend, now), true, `initial verified ${anchored} ${checkedMode}`);
          const firstDeadline = m.getSnapshot().backend.expiresAtMs;
          // Before expiry: same probe with changed deadline attributes never extends.
          now += 500;
          payload = variant({checked: checkedMode === 'present' ? t0 + 500 : undefined});
          await m.checkNow({force: true});
          const d = m.getSnapshot().backend.expiresAtMs;
          if (d !== null) assert.ok(d <= firstDeadline, `deadline not extended ${anchored}/${checkedMode}/${expiresMode}/${ttlMode}`);
          // After expiry: refresh + reload never resurrect.
          now += 4000;
          payload = variant({checked: checkedMode === 'present' ? t0 + 4500 : undefined});
          await m.checkNow({force: true});
          assert.equal(consumerParity(fp, m.getSnapshot().backend, now), false, `refresh resurrected ${anchored}/${checkedMode}/${expiresMode}/${ttlMode}`);
          m.dispose();
          const m2 = mk();
          await m2.checkNow({force: true});
          assert.equal(consumerParity(fp, m2.getSnapshot().backend, now), false, `reload resurrected ${anchored}/${checkedMode}/${expiresMode}/${ttlMode}`);
          // Evidence of a new run recovers: new probed_at, or a distinct execution identity when unanchored.
          const t1 = now + skew;
          payload = anchored
            ? body({probed: t1 - 50, expires: t1 + 30000, ttl: 30, checked: checkedMode === 'present' ? t1 : undefined})
            : body({expires: t1 + 30000, ttl: 30, checked: checkedMode === 'present' ? t1 : undefined, exec: 'f'.repeat(64)});
          await m2.checkNow({force: true});
          assert.equal(consumerParity(fp, m2.getSnapshot().backend, now), true, `new probe must recover ${anchored}/${checkedMode}`);
          // Old probe arriving after the new one never overrides it.
          payload = body({...base, expires: base.expires + 900000, ttl: 900, checked: checkedMode === 'present' ? t1 : undefined});
          await m2.checkNow({force: true, preserveStatus: true});
          assert.equal(consumerParity(fp, m2.getSnapshot().backend, now), true, `old probe overrode new ${anchored}/${checkedMode}`);
          m2.dispose();
          cases += 1;
        }
      }
    }
  }
  assert.equal(cases, 36);
});

test('A — server clock skew, contradictory/malformed checked_at, scope change', async () => {
  const hm = await loadModule('src/services/healthMonitor.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  let now = Date.parse('2026-11-25T09:00:00.000Z');
  let payload;
  let scope = 'scope-1';
  const m = hm.createHealthMonitor({fetchHealth: async () => payload, getScopeKey: () => scope, storage: mkStorage(), now: () => now, setTimer: () => 1, clearTimer: () => {}, retryDelaysMs: []});
  const check = async (p) => { payload = p; await m.checkNow({force: true}); return consumerParity(fp, m.getSnapshot().backend, now); };
  // Small negative skew and zero / positive skew are accepted (server-anchored remaining window).
  for (const skew of [-5000, 0, 120000]) {
    const t = now + skew;
    assert.equal(await check(body({probed: t - 10, expires: t + 30000, ttl: 30, checked: t, exec: `s${skew}`.padEnd(64, '0'), proc: `p${skew}`})), true, `skew ${skew} valid`);
    now += 10;
  }
  // Existing conservative behaviour (unchanged this round): if the server clock is behind by more
  // than the validity window, the absolute expires_at is already past on the client and the probe is
  // not verified.
  {
    const t = now - 120000;
    assert.equal(await check(body({probed: t - 10, expires: t + 30000, ttl: 30, checked: t, exec: 'n'.repeat(64), proc: 'p-neg'})), false, 'skew -120s beyond window');
  }
  const t = now;
  assert.equal(await check(body({probed: t, expires: t + 30000, ttl: 30, checked: t - 5000, exec: 'c'.repeat(64), proc: 'p-c'})), false, 'checked_at < probed_at');
  assert.equal(await check(body({probed: t - 10, expires: t + 30000, ttl: 30, checked: 'bad', exec: 'd'.repeat(64), proc: 'p-d'})), false, 'malformed checked_at');
  assert.equal(await check(body({probed: t - 40000, expires: t - 10000, ttl: 30, checked: t, exec: 'e'.repeat(64), proc: 'p-e'})), false, 'server says expired');
  assert.equal(await check(body({probed: t + 10, expires: t, ttl: 30, checked: t + 20, exec: '1'.repeat(64), proc: 'p-1'})), false, 'expires <= probed');
  // Scope change: proof memory does not leak; a valid probe in the new scope verifies.
  scope = 'scope-2';
  assert.equal(await check(body({probed: t - 10, expires: t + 30000, ttl: 30, checked: t, exec: '2'.repeat(64)})), true, 'new scope valid');
});

test('A — storage gate applies on the first response for every failure mode; normal storage keeps working', async () => {
  const denied = {get() { throw new DOMException('denied', 'SecurityError'); }};
  const throwing = (method) => ({value: mkStorage({[method]() { throw new DOMException(method, 'SecurityError'); }})});
  const modes = [
    ['property-denied', denied, null, true],
    ['getItem-throws', throwing('getItem'), null, true],
    ['setItem-throws', throwing('setItem'), null, true],
    ['removeItem-throws', throwing('removeItem'), null, true],
    ['corrupted-json', {value: mkStorage()}, (s) => s.setItem('22025523-health-proof-ledger-v1', '{bad'), true],
    ['wrong-schema', {value: mkStorage()}, (s) => s.setItem('22025523-health-proof-ledger-v1', JSON.stringify({v: 2, scopes: {}})), true],
    ['missing-ledger-normal', {value: mkStorage()}, null, false],
  ];
  for (const [label, descriptor, setup, gated] of modes) {
    await withWindow(descriptor, async (win) => {
      if (setup) setup(win.sessionStorage);
      const hm = await loadModule('src/services/healthMonitor.js');
      const fp = await loadRawEsm('src/services/findingPresentation.js');
      const t = Date.now();
      let payload = body({probed: t - 100, expires: t + 30000, ttl: 30});
      const mon = hm.createHealthMonitor({fetchHealth: async () => payload, retryDelaysMs: []});
      await mon.checkNow({force: true});
      assert.equal(consumerParity(fp, mon.getSnapshot().backend, Date.now()), !gated, `${label}: first unstamped response`);
      payload = body({probed: Date.now() - 100, expires: Date.now() + 30000, ttl: 30, checked: Date.now(), exec: '9'.repeat(64)});
      await mon.checkNow({force: true});
      assert.equal(consumerParity(fp, mon.getSnapshot().backend, Date.now()), true, `${label}: stamped fresh probe`);
      // A different backend process reporting an already-expired run (by server clock) is not verified.
      const stale = Date.now() - 20000;
      payload = body({probed: stale, expires: stale + 2000, ttl: 2, checked: Date.now(), exec: '8'.repeat(64), proc: 'other-process'});
      await mon.checkNow({force: true});
      assert.equal(consumerParity(fp, mon.getSnapshot().backend, Date.now()), false, `${label}: server-expired probe`);
      mon.dispose();
      if (!gated) {
        for (const [k, v] of win.sessionStorage._map.entries()) assert.equal(/Bearer|Authorization/.test(k + v), false);
      }
    });
  }
});

test('B — canonical coverage gate matrix over wire / normalize / copy / JSON and the three page paths', async () => {
  const apiMod = await loadRawEsm('src/services/api.js');
  const fp = await loadRawEsm('src/services/findingPresentation.js');
  const sh = await loadModule('src/services/scanHistory.js');
  const parse = apiMod.parseJsonWithWireIntegrity;
  const CANON = ['java_files_inventory', 'java_files_opengrep_scanned', 'java_files_opengrep_ignored', 'opengrep_paths_telemetry_status'];
  const rec = (inv, sc, ig) => ({java_files_inventory: inv, java_files_opengrep_scanned: sc, java_files_opengrep_ignored: ig, opengrep_paths_telemetry_status: 'VERIFIED'});
  const views = (raw) => {
    const wire = parse(raw);
    const norm = apiMod.materializeNormalizedTelemetry(wire).value;
    return {wire, normalized: norm, shallow: {...norm}, json: JSON.parse(JSON.stringify(norm))};
  };
  const expectAll = (raw, expected, label, counts) => {
    for (const [kind, value] of Object.entries(views(raw))) {
      const r = fp.resolveJavaFileCounts(value);
      assert.equal(r.hasVerifiedScanned, expected, `${label} [${kind}] ${r.canonicalCoverageProblem}`);
      if (expected) assert.deepEqual([r.inventoryCount, r.scannedCount, r.ignoredCount], counts, `${label} [${kind}]`);
      else assert.equal(r.scannedCount, null, `${label} [${kind}] scanned hidden`);
    }
    // History uses the same resolver on the list item
    const hist = sh.historyRecordFromBackend(parse(raw.replace(/^\{/, '{"scan_id":"s-inv",')), {origin: 'http://127.0.0.1:19971', sessionScope: 's'});
    assert.equal(Boolean(hist.javaCounts?.hasVerifiedScanned), expected, `${label} [history]`);
    // Reports read scan_summary from the report document
    const report = parse(`{"scan_summary":${raw},"findings":[]}`);
    assert.equal(fp.resolveJavaFileCounts(report.scan_summary).hasVerifiedScanned, expected, `${label} [reports]`);
  };
  // Positive controls (no hardcoded constants inside the resolver; several distinct records)
  for (const [inv, sc, ig] of [[19, 19, 0], [498, 389, 109], [1234, 1000, 234], [0, 0, 0], [7, 0, 7]]) {
    expectAll(JSON.stringify(rec(inv, sc, ig)), true, `valid ${inv}/${sc}/${ig}`, [inv, sc, ig]);
  }
  const valid = rec(498, 389, 109);
  // Each canonical key missing
  for (const k of CANON) { const p = {...valid}; delete p[k]; expectAll(JSON.stringify(p), false, `missing ${k}`); }
  // Each canonical key replaced by every alias (same value), and canonical + alias (consistent / conflicting)
  const ALIASES = {
    java_files_inventory: ['java_files_inventory_count', 'java_files_count'],
    java_files_opengrep_scanned: ['opengrep_scanned_java_files', 'java_files_actually_scanned', 'scanned_java_files_count'],
    java_files_opengrep_ignored: ['java_files_ignored', 'opengrep_ignored_java_files', 'ignored_java_files_count'],
  };
  for (const [k, aliases] of Object.entries(ALIASES)) {
    for (const a of aliases) {
      const replaced = {...valid, [a]: valid[k]}; delete replaced[k];
      expectAll(JSON.stringify(replaced), false, `${a} replaces ${k}`);
      expectAll(JSON.stringify({...valid, [a]: valid[k]}), true, `${k} + consistent ${a}`, [498, 389, 109]);
      expectAll(JSON.stringify({...valid, [a]: valid[k] + 1}), false, `${k} + conflicting ${a}`);
    }
  }
  // Paths arrays alone never satisfy canonical presence
  expectAll(JSON.stringify({java_files_inventory: 4, opengrep_paths_telemetry_status: 'VERIFIED', scan_manifest: {paths: {scanned: ['a', 'b', 'c'], ignored: ['d']}}}), false, 'paths only');
  // Status variants
  for (const st of [null, 123, true, 'MISSING_PATHS_TELEMETRY', 'INCONSISTENT_TELEMETRY', 'OK', '']) {
    expectAll(JSON.stringify({...valid, opengrep_paths_telemetry_status: st}), false, `status ${JSON.stringify(st)}`);
  }
  // Count variants (raw lexemes for precision traps)
  for (const v of ['-1', 'null', 'true', '"109"', '109.5', '109.000000000000001', '1.09e2', '9007199254740993', '[]', '{}']) {
    const raw = `{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":${v},"opengrep_paths_telemetry_status":"VERIFIED"}`;
    const ok = v === '1.09e2'; // exact integer lexeme in exponent form is a valid safe integer
    expectAll(raw, ok, `ignored ${v}`, ok ? [498, 389, 109] : undefined);
  }
  // Sum mismatch (under / over) and scanned > inventory
  for (const [inv, sc, ig] of [[498, 389, 108], [498, 389, 110], [10, 11, 0]]) expectAll(JSON.stringify(rec(inv, sc, ig)), false, `sum ${inv}/${sc}/${ig}`);
  // Duplicate keys: each canonical (plain and Unicode-escaped), __wireIntegrity, unrelated key in the same container
  const vraw = JSON.stringify(valid);
  for (const k of CANON) {
    const val = JSON.stringify(valid[k]);
    expectAll(vraw.replace(/^\{/, `{"${k}":${val},`), false, `dup equal ${k}`);
    const esc = k.replace(/e/, '\\u0065');
    expectAll(vraw.replace(/^\{/, `{"${esc}":${val},`), false, `dup unicode ${k}`);
  }
  for (const reserved of ['"__wireIntegrity":null,"__wireIntegrity":{"hasMalformed":true}', '"__wireIntegrity":{}', '"__wireIntegrity":{"hasMalformed":false,"hasConflict":false}', '"__wireIntegrity":42', '"__wireIntegrity":[]', '"__wireIntegrity":{"duplicateKeyPaths":7}', '"__wirIntegrity":1,"__wir\\u0049ntegrity":2']) {
    expectAll(vraw.replace(/^\{/, `{${reserved},`), false, `reserved ${reserved}`);
  }
  expectAll(vraw.replace(/^\{/, '{"scan_id":"a","scan_id":"b",'), false, 'unrelated duplicate in coverage container');
  // Canonical record inside scan_manifest; parent container duplicated
  expectAll(JSON.stringify({scan_manifest: valid}), true, 'canonical in scan_manifest', [498, 389, 109]);
  expectAll(`{"scan_manifest":${JSON.stringify(rec(10, 1, 9))},"scan_manifest":${vraw}}`, false, 'duplicate scan_manifest');
  // Legacy semantics preserved: inventory only, never scanned
  const legacy = fp.resolveJavaFileCounts(parse('{"java_files_scanned":498,"opengrep_paths_telemetry_status":"VERIFIED"}'));
  assert.equal(legacy.inventoryCount, 498);
  assert.equal(legacy.inventoryFromLegacy, true);
  assert.equal(legacy.hasVerifiedScanned, false);
  // Canonical + legacy java_files_scanned (real backend contract payload) verifies
  expectAll(JSON.stringify({...valid, java_files_scanned: 498}), true, 'backend contract valid payload', [498, 389, 109]);
});
