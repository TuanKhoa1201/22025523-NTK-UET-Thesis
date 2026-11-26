// Dedicated closure regression suite for remaining independent re-audit blockers F02 and F05.
// Covers general invariants and edge boundaries beyond the specific counterexample payloads:
//   - F02: Verifiable server-grounded expiry requirement (probed_at / expires_at / positive ttl_seconds),
//     rejection of missing-expiry, TTL-only without probe timestamp, probed_at-only, ttl_seconds <= 0,
//     malformed types/dates, contradictory expires_at <= probed_at, passive expiry with 0 HTTP requests,
//     non-extension on identical or canonically-equivalent replay, anti-resurrection on older probed_at
//     or expires_at-only snapshots, valid fresh probe recovery, API DEGRADED decoupling (OLLAMA_UNREACHABLE),
//     uniform Header/Sidebar/StatusPage rendering, and scope/URL/token switch isolation.
//   - F05: Safe integer enforcement (Number.isSafeInteger) & BigInt exact sum checks across LIVE & PLAYBACK,
//     exact MAX_SAFE_INTEGER boundary, above-limit rounding traps (2^53 / 2^53+1 / 1e20), sum overflow,
//     negative/decimal/string/boolean/null/missing/contradictory counts, preservation of INVALID layers
//     (PATH, LINE, QUOTE, SHA-256), and shared liveScan / findingPresentation count validators.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const esbuild = require('esbuild');

const APP_ROOT = path.join(__dirname, '..');
const SRC_ROOT = path.join(APP_ROOT, 'src');

function mkStorage() {
  return {
    _map: new Map(),
    get length() { return this._map.size; },
    key(i) { return [...this._map.keys()][i] ?? null; },
    getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
    setItem(k, v) { this._map.set(k, String(v)); },
    removeItem(k) { this._map.delete(k); },
  };
}

async function bundleAndImport(relPath) {
  const entry = path.join(SRC_ROOT, relPath);
  const built = await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    mainFields: ['module', 'main'],
    loader: {'.jsx': 'jsx', '.js': 'js'},
    jsx: 'automatic',
    define: {
      'import.meta.env': JSON.stringify({MODE: 'test', DEV: false, PROD: true}),
      'process.env.NODE_ENV': JSON.stringify('test'),
    },
  });
  const code = built.outputFiles[0].text;
  const dataUrl = `data:text/javascript;base64,${Buffer.from(`${code}\n// ${Math.random()}`, 'utf8').toString('base64')}`;
  return import(dataUrl);
}

function makeClockAndTimers(startMs = Date.parse('2026-11-25T10:00:00Z')) {
  let fakeNow = startMs;
  const timers = [];
  let nextId = 1;
  return {
    now: () => fakeNow,
    advance: (ms) => { fakeNow += ms; },
    timers,
    setTimer: (fn, ms) => {
      const id = nextId++;
      timers.push({id, fn, ms, cleared: false, ran: false});
      return id;
    },
    clearTimer: (id) => {
      const entry = timers.find((t) => t.id === id);
      if (entry) entry.cleared = true;
    },
    fireAllActive() {
      const active = timers.filter((t) => !t.cleared && !t.ran);
      for (const entry of active) {
        entry.ran = true;
        entry.fn();
      }
      return active.length;
    },
  };
}

test('F02 closure: verifiable expiry basis required across Header, Sidebar, and StatusPage under OK and DEGRADED', async () => {
  const prevWindow = global.window;
  const prevSession = global.sessionStorage;
  global.sessionStorage = mkStorage();
  global.window = {
    location: {origin: 'http://127.0.0.1:19500', hostname: '127.0.0.1'},
    sessionStorage: global.sessionStorage,
  };

  try {
    const fp = await bundleAndImport('services/findingPresentation.js');
    const hm = await bundleAndImport('services/healthMonitor.js');
    const statusPage = await bundleAndImport('pages/StatusPage.jsx');

    const t0 = Date.parse('2026-11-25T10:00:00Z');
    const baseProof = {
      available: true,
      runtime_verified: true,
      probe_status: 'VERIFIED',
      health_state: 'VERIFIED',
      probe_in_progress: false,
      version: '1.25.0',
    };

    const assertNotVerifiedEverywhere = (payload, label) => {
      const classified = hm.classifyHealthResponse(payload, {nowMs: t0, receivedAtMs: t0});
      assert.equal(classified.opengrepVerified, false, `${label}: opengrepVerified must be false`);
      assert.notEqual(classified.status, 'CONNECTED', `${label}: status must never be CONNECTED`);
      const view = fp.classifyBackendHealthState(classified, {nowMs: t0});
      assert.equal(view.ogInfo.isVerified, false, `${label}: view.ogInfo.isVerified must be false`);
      assert(!/OPENGREP VERIFIED/i.test(view.pillLabel), `${label}: Header must not show VERIFIED (${view.pillLabel})`);
      assert(!/OpenGrep đã xác minh|(?<!NOT_)VERIFIED/i.test(view.sidebarLabel), `${label}: Sidebar must not show VERIFIED (${view.sidebarLabel})`);
      const rows = statusPage.buildHealthStatusRows(classified, null, null, {});
      const ogRow = rows.find((r) => r.name.includes('OpenGrep Active Health Probe'));
      assert(!/^Đã xác minh · VERIFIED/.test(ogRow.value), `${label}: StatusPage must not show VERIFIED (${ogRow.value})`);
      return {classified, view, ogRow};
    };

    // 1. Missing ALL expiry evidence (Codex F02 counterexample #1) under both OK and DEGRADED
    for (const status of ['OK', 'DEGRADED']) {
      const {classified, view} = assertNotVerifiedEverywhere({
        status,
        degraded_reasons: status === 'DEGRADED' ? ['OLLAMA_UNREACHABLE'] : [],
        ollama: {reachable: status === 'OK'},
        opengrep: {...baseProof},
      }, `missing-all-expiry-${status}`);
      assert.equal(classified.expiresAtMs, null);
      assert.equal(view.ogInfo.healthState, 'NOT_VERIFIED');
      assert.equal(view.ogInfo.code, 'OPENGREP_NOT_VERIFIED');
    }

    // 2. TTL-only WITHOUT probed_at or expires_at (Codex F02 counterexample #2) under both OK and DEGRADED
    for (const status of ['OK', 'DEGRADED']) {
      const {classified, view} = assertNotVerifiedEverywhere({
        status,
        degraded_reasons: status === 'DEGRADED' ? ['OLLAMA_UNREACHABLE'] : [],
        ollama: {reachable: status === 'OK'},
        opengrep: {...baseProof, ttl_seconds: 2},
      }, `ttl-only-unanchored-${status}`);
      assert.equal(classified.expiresAtMs, null);
      assert.equal(view.ogInfo.healthState, 'NOT_VERIFIED');
    }

    // 3. probed_at-only WITHOUT expires_at or ttl_seconds -> cannot determine expiry
    assertNotVerifiedEverywhere({
      status: 'OK',
      opengrep: {...baseProof, probed_at: new Date(t0).toISOString()},
    }, 'probed-at-only');

    // 4. TTL === 0, negative, wrong types, overflow, invalid dates, contradictory expires_at <= probed_at, bad verification_level
    for (const [name, ogPatch] of [
      ['ttl-zero-with-stamps', {probed_at: new Date(t0).toISOString(), expires_at: new Date(t0 + 5000).toISOString(), ttl_seconds: 0}],
      ['ttl-zero-only', {ttl_seconds: 0}],
      ['ttl-negative', {probed_at: new Date(t0).toISOString(), expires_at: new Date(t0 + 5000).toISOString(), ttl_seconds: -2}],
      ['ttl-string', {probed_at: new Date(t0).toISOString(), expires_at: new Date(t0 + 5000).toISOString(), ttl_seconds: '2'}],
      ['ttl-boolean', {probed_at: new Date(t0).toISOString(), ttl_seconds: true}],
      ['ttl-NaN', {probed_at: new Date(t0).toISOString(), ttl_seconds: Number.NaN}],
      ['ttl-Infinity', {probed_at: new Date(t0).toISOString(), ttl_seconds: Number.POSITIVE_INFINITY}],
      ['ttl-overflow', {probed_at: new Date(t0).toISOString(), ttl_seconds: 1e308}],
      ['bad-probed-at', {probed_at: 'not-a-date', ttl_seconds: 30}],
      ['calendar-rollover-probed-at', {probed_at: '2026-02-31T10:00:00Z', ttl_seconds: 30}],
      ['date-only-expires-at', {expires_at: '2026-12-01'}],
      ['numeric-expires-at', {expires_at: t0 + 5000}],
      ['contradictory-expires-before-probed', {probed_at: new Date(t0 + 5000).toISOString(), expires_at: new Date(t0 + 2000).toISOString()}],
      ['contradictory-expires-equal-probed', {probed_at: new Date(t0 + 5000).toISOString(), expires_at: new Date(t0 + 5000).toISOString()}],
      ['non-verified-level', {probed_at: new Date(t0).toISOString(), expires_at: new Date(t0 + 5000).toISOString(), ttl_seconds: 5, verification_level: 'SCAN_EXECUTED'}],
    ]) {
      assertNotVerifiedEverywhere({
        status: 'DEGRADED',
        degraded_reasons: ['OLLAMA_UNREACHABLE'],
        opengrep: {...baseProof, ...ogPatch},
      }, name);
    }

    // 5. Real backend startup NOT_VERIFIED with probed_at=null, expires_at=null, ttl_seconds=300 emits ZERO false schema warnings
    const startupRes = hm.classifyHealthResponse({
      status: 'DEGRADED',
      degraded_reasons: ['OPENGREP_NOT_VERIFIED'],
      opengrep: {
        available: false,
        runtime_verified: false,
        probe_status: 'NOT_VERIFIED',
        health_state: 'NOT_VERIFIED',
        probe_in_progress: true,
        probed_at: null,
        expires_at: null,
        ttl_seconds: 300,
      },
    }, {nowMs: t0, receivedAtMs: t0});
    assert.equal(startupRes.schemaWarnings.length, 0, 'Startup NOT_VERIFIED with null timestamps must not trigger schemaWarnings');
    assert.equal(hm.shouldAutoRecheckHealth(startupRes.health, {nowMs: t0}), true);

    // 6. Valid server-grounded expiry forms ALL verify cleanly:
    //    (a) probed_at + expires_at + ttl_seconds (full backend shape)
    //    (b) probed_at + ttl_seconds (no expires_at)
    //    (c) expires_at only (no probed_at/ttl_seconds)
    for (const [label, ogPatch, expectedDeadline] of [
      ['full-backend', {probed_at: new Date(t0).toISOString(), expires_at: new Date(t0 + 3000).toISOString(), ttl_seconds: 3}, t0 + 3000],
      ['probed-plus-ttl', {probed_at: new Date(t0).toISOString(), ttl_seconds: 2.5}, t0 + 2500],
      ['expires-at-only', {expires_at: new Date(t0 + 4000).toISOString()}, t0 + 4000],
    ]) {
      const okRes = hm.classifyHealthResponse({
        status: 'OK',
        opengrep: {...baseProof, ...ogPatch},
      }, {nowMs: t0, receivedAtMs: t0});
      assert.equal(okRes.status, 'CONNECTED', `${label} should be CONNECTED`);
      assert.equal(okRes.opengrepVerified, true, `${label} should be opengrepVerified`);
      assert.equal(okRes.expiresAtMs, expectedDeadline, `${label} deadline mismatch`);
      assert.equal(okRes.ttlExpired, false);
    }
  } finally {
    global.window = prevWindow;
    global.sessionStorage = prevSession;
  }
});

test('F02 closure: healthMonitor blocks unstamped TTL replay, enforces passive expiry, blocks stale/equivalent replays & older polls, recovers on fresh probe, and isolates scopes', async () => {
  const fp = await bundleAndImport('services/findingPresentation.js');
  const hm = await bundleAndImport('services/healthMonitor.js');

  const clock = makeClockAndTimers();
  const baseProof = {
    available: true,
    runtime_verified: true,
    probe_status: 'VERIFIED',
    health_state: 'VERIFIED',
    probe_in_progress: false,
    version: '1.25.0',
  };

  let requests = 0;
  let scope = 'http://127.0.0.1:19510|http://127.0.0.1:19510|session-A';
  let currentPayload = {
    status: 'DEGRADED',
    degraded_reasons: ['OLLAMA_UNREACHABLE'],
    ollama: {reachable: false},
    opengrep: {...baseProof, ttl_seconds: 2},
  };

  const monitor = hm.createHealthMonitor({
    getScopeKey: () => scope,
    now: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    fetchHealth: async () => {
      requests += 1;
      return JSON.parse(JSON.stringify(currentPayload));
    },
  });

  // 1. Unstamped TTL-only payload NEVER becomes VERIFIED, arms 0 TTL timers, and stays NOT_VERIFIED on refresh
  await monitor.checkNow();
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false);
  assert.equal(monitor.getSnapshot().backend.expiresAtMs, null);
  assert.equal(monitor.hasPendingTtlTimer(), false);
  clock.advance(2500);
  await monitor.checkNow({force: true, preserveStatus: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false);
  assert.equal(monitor.getSnapshot().backend.expiresAtMs, null);

  // 2. Valid stamped probe under DEGRADED (OLLAMA_UNREACHABLE) -> VERIFIED, then passive expiry with 0 HTTP calls
  const t1 = clock.now();
  const stampedA = {
    status: 'DEGRADED',
    degraded_reasons: ['OLLAMA_UNREACHABLE'],
    ollama: {reachable: false},
    opengrep: {
      ...baseProof,
      probed_at: new Date(t1 + 60000).toISOString(), // +60s server clock skew to prove clamping
      expires_at: new Date(t1 + 62000).toISOString(),
      ttl_seconds: 2,
      process_instance_id: 'proc-1',
      probe_execution_identity_sha256: 'a'.repeat(64),
    },
  };
  currentPayload = stampedA;
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true);
  assert.equal(monitor.getSnapshot().backend.expiresAtMs, t1 + 2000);
  assert.equal(monitor.hasPendingTtlTimer(), true);

  const reqBeforePassiveExpiry = requests;
  clock.advance(2000);
  clock.fireAllActive();
  assert.equal(requests, reqBeforePassiveExpiry, 'Passive expiry must issue 0 HTTP requests');
  const expiredSnap = monitor.getSnapshot();
  assert.equal(expiredSnap.backend.ttlExpired, true);
  assert.equal(expiredSnap.backend.opengrepVerified, false);
  const expiredView = fp.classifyBackendHealthState(expiredSnap.backend, {nowMs: clock.now()});
  assert.match(expiredView.pillLabel, /EXPIRED/);
  assert.match(expiredView.sidebarLabel, /EXPIRED/);
  assert.equal(expiredView.ogInfo.healthState, 'EXPIRED');

  // 3. Refresh replaying the EXACT same expired snapshot (and equivalent ISO +00:00 formatting + changed checked_at) stays EXPIRED
  clock.advance(500);
  await monitor.checkNow({force: true, preserveStatus: true});
  assert.equal(monitor.getSnapshot().backend.ttlExpired, true);
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false);
  assert.equal(monitor.hasPendingTtlTimer(), false);

  currentPayload = {
    ...stampedA,
    // Keep server clock consistent with +60s server skew (probed_at <= checked_at < expires_at)
    // so only canonical proof-signature clamping catches the equivalent ISO +00:00 replay.
    checked_at: new Date(t1 + 60500).toISOString(),
    opengrep: {
      ...stampedA.opengrep,
      probed_at: stampedA.opengrep.probed_at.replace('Z', '+00:00'),
      expires_at: stampedA.opengrep.expires_at.replace('Z', '+00:00'),
    },
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.ttlExpired, true, 'Canonical equivalent ISO replay must remain EXPIRED');
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false);

  // 4. Malformed future snapshot MUST NOT poison watermark for a genuinely fresh probe
  currentPayload = {
    status: 'OK',
    opengrep: {
      ...baseProof,
      probed_at: new Date(t1 + 999999999).toISOString(),
      expires_at: new Date(t1 + 999999999 + 5000).toISOString(),
      ttl_seconds: 0, // invalid!
    },
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false);

  // 5. Genuinely new valid probe after expiry cleanly recovers to VERIFIED
  const t2 = clock.now();
  currentPayload = {
    status: 'DEGRADED',
    degraded_reasons: ['OLLAMA_UNREACHABLE'],
    ollama: {reachable: false},
    opengrep: {
      ...baseProof,
      probed_at: new Date(t2 + 65000).toISOString(),
      expires_at: new Date(t2 + 68000).toISOString(),
      ttl_seconds: 3,
      process_instance_id: 'proc-1',
      probe_execution_identity_sha256: 'a'.repeat(64),
    },
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true);
  assert.equal(monitor.getSnapshot().backend.ttlExpired, false);
  assert.equal(monitor.hasPendingTtlTimer(), true);

  // 6. Older snapshot (probed_at < latest) arriving via poll MUST preserve fresher probe while still valid,
  //    and MUST NEVER resurrect VERIFIED once the fresher probe expires.
  const freshDeadline = monitor.getSnapshot().backend.expiresAtMs;
  currentPayload = {
    ...stampedA,
    opengrep: {
      ...stampedA.opengrep,
      expires_at: new Date(t2 + 90000).toISOString(),
      ttl_seconds: 30,
    },
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.ttlExpired, false);
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true);
  assert.equal(monitor.getSnapshot().backend.expiresAtMs, freshDeadline);
  assert.equal(monitor.hasPendingTtlTimer(), true);
  clock.advance(3000);
  clock.fireAllActive();
  assert.equal(monitor.getSnapshot().backend.ttlExpired, true);
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.ttlExpired, true);
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false);

  // 7. expires_at-only preservation while fresh & anti-resurrection after expiry when probed_at is absent
  const t3 = clock.now();
  scope = 'http://127.0.0.1:19520|http://127.0.0.1:19520|session-B';
  currentPayload = {
    status: 'OK',
    opengrep: {...baseProof, expires_at: new Date(t3 + 10000).toISOString()},
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true);
  const bDeadline = monitor.getSnapshot().backend.expiresAtMs;
  // Older expires_at-only snapshot while fresh -> preserves newer deadline!
  currentPayload = {
    status: 'OK',
    opengrep: {...baseProof, expires_at: new Date(t3 + 5000).toISOString()},
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true);
  assert.equal(monitor.getSnapshot().backend.expiresAtMs, bDeadline);
  // After expiry -> older expires_at-only snapshot with future expiry stays EXPIRED / never resurrects!
  clock.advance(10000);
  clock.fireAllActive();
  assert.equal(monitor.getSnapshot().backend.ttlExpired, true);
  currentPayload = {
    status: 'OK',
    opengrep: {...baseProof, expires_at: new Date(t3 + 5000).toISOString()},
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.ttlExpired, true);
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false);

  // 8. Same scope after expiry: an expires_at-only snapshot with a LATER deadline is not evidence of
  //    a new probe run (no probed_at, same identity) and must stay unverified (P1-A invariant).
  //    Evidence of a new run (probed_at, or a different probe_execution_identity_sha256) recovers.
  const t4 = clock.now();
  currentPayload = {
    status: 'OK',
    opengrep: {...baseProof, expires_at: new Date(t4 + 20000).toISOString()},
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, false, 'later deadline alone must not resurrect');
  currentPayload = {
    status: 'OK',
    opengrep: {...baseProof, probe_execution_identity_sha256: 'e'.repeat(64), expires_at: new Date(t4 + 20000).toISOString()},
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true, 'distinct execution identity is a new probe');
  currentPayload = {
    status: 'OK',
    opengrep: {...baseProof, probed_at: new Date(t4).toISOString(), expires_at: new Date(t4 + 20000).toISOString()},
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true, 'probed_at anchored probe verifies');
  // Scope/URL/token switch resets proof memory so session-C does not inherit session-B watermarks or expired state
  scope = 'http://127.0.0.1:19530|http://127.0.0.1:19530|session-C';
  currentPayload = {
    status: 'OK',
    opengrep: {...baseProof, expires_at: new Date(t4 + 4000).toISOString()},
  };
  await monitor.checkNow({force: true});
  assert.equal(monitor.getSnapshot().backend.status, 'CONNECTED');
  assert.equal(monitor.getSnapshot().backend.opengrepVerified, true);
  assert.equal(monitor.hasPendingTtlTimer(), true);

  monitor.dispose();
  assert.equal(monitor.hasPendingTtlTimer(), false);
});

test('F05 closure: safe integer validation, BigInt sum boundaries, and fail-closed citation parity across LIVE, PLAYBACK, liveScan, and findingPresentation', async () => {
  const lsp = await bundleAndImport('components/scanner/liveStagePresentation.js');
  const liveScan = await bundleAndImport('services/liveScan.js');
  const fp = await bundleAndImport('services/findingPresentation.js');

  const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 9007199254740991

  for (const mode of ['LIVE', 'PLAYBACK']) {
    const resolve = (summary, cat = 'COMPLETED') => lsp.resolveStage05CitationTelemetry({mode, stage: {cat, summary}});

    // 1. Exact Codex counterexamples (parsed from raw JSON wire format!) -> MALFORMED, never ALL_MATCHED
    const codexFull = JSON.parse('{"matched_count":9007199254740992,"invalid_count":0,"not_verified_count":0,"total_checked":9007199254740993}');
    const resCodexFull = resolve(codexFull);
    assert.equal(resCodexFull.aggregateStatus, 'MALFORMED', `${mode}: unsafe counterexample must be MALFORMED`);
    assert.notEqual(resCodexFull.aggregateStatus, 'ALL_MATCHED');
    assert(resCodexFull.checks.every((c) => c.status === 'MALFORMED' && !c.isVerifiedMatch));

    const codexMinimal = JSON.parse('{"matched_count":9007199254740992,"total_checked":9007199254740993}');
    const resCodexMinimal = resolve(codexMinimal);
    assert.equal(resCodexMinimal.aggregateStatus, 'MALFORMED', `${mode}: minimal unsafe counterexample must be MALFORMED`);
    assert.notEqual(resCodexMinimal.aggregateStatus, 'ALL_MATCHED');

    // 2. Exact MAX_SAFE_INTEGER boundary (valid safe integer)
    const atMaxSafe = resolve({matched_count: MAX_SAFE, invalid_count: 0, not_verified_count: 0, total_checked: MAX_SAFE});
    assert.equal(atMaxSafe.aggregateStatus, 'ALL_MATCHED', `${mode}: MAX_SAFE_INTEGER valid equal counts should pass`);
    assert.equal(atMaxSafe.counts.isComplete, true);

    const mixedAtMaxSafe = resolve({matched_count: MAX_SAFE - 1, invalid_count: 1, not_verified_count: 0, total_checked: MAX_SAFE});
    assert.equal(mixedAtMaxSafe.aggregateStatus, 'MIXED', `${mode}: MAX_SAFE_INTEGER-1 + 1 == MAX_SAFE_INTEGER should be MIXED`);

    // 3. Above MAX_SAFE_INTEGER (various forms) -> MALFORMED, never ALL_MATCHED
    for (const aboveCase of [
      {matched_count: MAX_SAFE + 1, invalid_count: 0, not_verified_count: 0, total_checked: MAX_SAFE + 1},
      {matched_count: MAX_SAFE, invalid_count: 0, not_verified_count: 0, total_checked: MAX_SAFE + 1},
      {matched_count: 1e20, invalid_count: 0, not_verified_count: 0, total_checked: 1e20},
      {matched_count: Number.POSITIVE_INFINITY, invalid_count: 0, not_verified_count: 0, total_checked: Number.POSITIVE_INFINITY},
      {matched_count: 3, invalid_count: 0, not_verified_count: MAX_SAFE + 2, total_checked: 3},
    ]) {
      const r = resolve(aboveCase);
      assert.notEqual(r.aggregateStatus, 'ALL_MATCHED');
      assert.equal(r.aggregateStatus, 'MALFORMED', `${mode}: above-safe case ${JSON.stringify(aboveCase)} must be MALFORMED`);
    }

    // 4. Safe integers whose sum overflows MAX_SAFE_INTEGER (BigInt exact check!)
    const overflowConflict = resolve({matched_count: MAX_SAFE, invalid_count: 1, not_verified_count: 0, total_checked: MAX_SAFE});
    assert.equal(overflowConflict.aggregateStatus, 'CONFLICT', `${mode}: MAX_SAFE + 1 > MAX_SAFE must be CONFLICT`);
    const overflowConflictNv = resolve({matched_count: MAX_SAFE, invalid_count: 0, not_verified_count: 1, total_checked: MAX_SAFE});
    assert.equal(overflowConflictNv.aggregateStatus, 'CONFLICT', `${mode}: MAX_SAFE + 1 (not_verified) > MAX_SAFE must be CONFLICT`);
    const overflowNoTotal = resolve({matched_count: 5000000000000000, invalid_count: 0, not_verified_count: 5000000000000000});
    assert.equal(overflowNoTotal.aggregateStatus, 'MALFORMED', `${mode}: sum exceeding MAX_SAFE_INTEGER without total must be MALFORMED`);
    assert.notEqual(overflowNoTotal.aggregateStatus, 'ALL_MATCHED');

    // 5. Unsafe count paired with valid invalid_count > 0 MUST NOT hide INVALID or produce ALL_MATCHED
    const unsafeWithInvalid = resolve({
      matched_count: MAX_SAFE + 1,
      invalid_count: 1,
      not_verified_count: 0,
      total_checked: MAX_SAFE + 1,
    });
    assert.equal(unsafeWithInvalid.aggregateStatus, 'INVALID');
    assert.notEqual(unsafeWithInvalid.aggregateStatus, 'ALL_MATCHED');

    // 6. Negative, decimal, string, boolean, NaN, object, array counts -> NEVER coerced, NEVER ALL_MATCHED
    for (const badType of [
      {matched_count: -1, invalid_count: 0, not_verified_count: 0, total_checked: -1},
      {matched_count: 1.5, invalid_count: 0, not_verified_count: 0, total_checked: 1.5},
      {matched_count: 3, invalid_count: 0.5, not_verified_count: 0, total_checked: 3},
      {matched_count: '3', invalid_count: 0, not_verified_count: 0, total_checked: '3'},
      {matched_count: true, invalid_count: false, not_verified_count: false, total_checked: true},
      {matched_count: Number.NaN, invalid_count: 0, not_verified_count: 0, total_checked: 1},
      {matched_count: [3], invalid_count: 0, not_verified_count: 0, total_checked: 3},
      {matched_count: {valueOf: () => 3}, invalid_count: 0, not_verified_count: 0, total_checked: 3},
    ]) {
      const r = resolve(badType);
      assert.notEqual(r.aggregateStatus, 'ALL_MATCHED', `${mode}: badType ${JSON.stringify(badType)} must never be ALL_MATCHED`);
      assert(['MALFORMED', 'CONFLICT'].includes(r.aggregateStatus));
    }

    // 7. Missing / null fields NEVER defaulted to 0 and NEVER ALL_MATCHED
    for (const missingCase of [
      {matched_count: 3, invalid_count: null, not_verified_count: 0, total_checked: 3},
      {matched_count: 3, invalid_count: 0, not_verified_count: null, total_checked: 3},
      {matched_count: 3, invalid_count: 0, not_verified_count: 0, total_checked: null},
      {matched_count: null, invalid_count: 0, not_verified_count: 0, total_checked: 3},
    ]) {
      const r = resolve(missingCase);
      assert.equal(r.aggregateStatus, 'PARTIAL', `${mode}: missing/null field must stay PARTIAL`);
      assert.notEqual(r.aggregateStatus, 'ALL_MATCHED');
    }

    // 8. Zero total_checked -> NO_FINDINGS, never ALL_MATCHED
    assert.equal(resolve({matched_count: 0, invalid_count: 0, not_verified_count: 0, total_checked: 0}).aggregateStatus, 'NO_FINDINGS');

    // 9. Per-layer INVALID rules (PATH, LINE, QUOTE, SHA-256) remain intact
    for (const layer of ['path', 'line', 'quote', 'sha256']) {
      const r = resolve({
        matched_count: 3,
        invalid_count: 0,
        not_verified_count: 0,
        total_checked: 3,
        citation_checks: {[layer]: 'INVALID'},
      });
      assert.equal(r.aggregateStatus, 'CONFLICT');
      assert.equal(r.checks.find((c) => c.key === layer).status, 'INVALID');
      assert(r.checks.filter((c) => c.key !== layer).every((c) => c.status === 'NO_DATA'));
    }

    // 10. Normal valid payloads continue to work identically in LIVE and PLAYBACK
    const normal = resolve({matched_count: 5, invalid_count: 0, not_verified_count: 0, total_checked: 5});
    assert.equal(normal.aggregateStatus, 'ALL_MATCHED');
    assert(normal.checks.every((c) => c.status === 'AGGREGATE_MATCHED'));
  }

  // 11. Shared count validators in liveScan & findingPresentation also enforce Number.isSafeInteger
  const unsafeScanSummary = JSON.parse('{"total_findings":9007199254740993,"matched_citation_count":9007199254740992}');
  const liveVal = liveScan.validateScanCountersAndPagination(unsafeScanSummary, {findings: [], total_count: 9007199254740992});
  assert.equal(liveVal.valid, false, 'liveScan must reject unsafe integer totals/citation counts');

  const unsafeJava = fp.resolveJavaFileCounts(JSON.parse('{"java_files_inventory_count":9007199254740992,"opengrep_scanned_java_files":9007199254740993}'));
  assert.equal(unsafeJava.inventoryCount, null);
  assert.equal(unsafeJava.scannedCount, null);
  assert.equal(unsafeJava.hasInvalidFields, true);
});
