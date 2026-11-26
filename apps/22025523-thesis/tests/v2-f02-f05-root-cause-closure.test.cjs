// Root-cause adversarial verification suite for F02 (health probe evidence lifecycle),
// F05 (REST-boundary JSON numeric & duplicate-key integrity), and Backend G3 contract compatibility.
// Uses a real loopback raw HTTP server (127.0.0.1:0) for wire-level F05 tests so raw JSON byte
// representations (e.g. 1.0000000000000001, 1e-325, -0, duplicate wire keys) are transmitted verbatim
// across the HTTP boundary before reaching api.js -> normalization -> cache -> LIVE/PLAYBACK UI.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const esbuild = require('esbuild');

const APP_ROOT = path.join(__dirname, '..');
const SRC_ROOT = path.join(APP_ROOT, 'src');

function mkStorage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    _map: map,
    get length() { return map.size; },
    key(i) { return [...map.keys()][i] ?? null; },
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(k, String(v)); },
    removeItem(k) { map.delete(k); },
    clear() { map.clear(); },
  };
}

function mkThrowingStorage() {
  return {
    get length() { throw new Error('SecurityError: storage blocked'); },
    key() { throw new Error('SecurityError: storage blocked'); },
    getItem() { throw new Error('SecurityError: storage blocked'); },
    setItem() { throw new Error('QuotaExceededError: storage blocked'); },
    removeItem() { throw new Error('SecurityError: storage blocked'); },
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

const BASE_VERIFIED_OG = {
  available: true,
  runtime_verified: true,
  probe_status: 'VERIFIED',
  health_state: 'VERIFIED',
  verification_level: 'SCAN_VERIFIED',
  process_instance_id: 'proc-root-1',
  probe_execution_identity_sha256: 'a'.repeat(64),
  binary_identity_sha256: 'b'.repeat(64),
  rules_sha256: 'c'.repeat(64),
};

test('F02 root-cause matrix: older snapshot preservation, out-of-order responses, reload anti-resurrection, clock skew, storage resilience, and scope isolation', async () => {
  const prevWindow = global.window;
  const prevSession = global.sessionStorage;
  const sharedStorage = mkStorage();
  global.sessionStorage = sharedStorage;
  global.window = {
    location: {origin: 'http://127.0.0.1:19800', hostname: '127.0.0.1'},
    sessionStorage: sharedStorage,
    setTimeout: global.setTimeout,
    clearTimeout: global.clearTimeout,
  };

  try {
    const apiMod = await bundleAndImport('services/api.js');
    const hm = await bundleAndImport('services/healthMonitor.js');
    const fp = await bundleAndImport('services/findingPresentation.js');
    const statusPage = await bundleAndImport('pages/StatusPage.jsx');

    // 1. Exact Codex F02.1 scenario: DEGRADED (OLLAMA_UNREACHABLE) with fresh 300s OpenGrep probe,
    //    then manual refresh receives 10s-older snapshot -> MUST preserve newer probe, deadline, timer,
    //    and identical Header/Sidebar/StatusPage views.
    const clock1 = makeClockAndTimers(Date.parse('2026-11-25T10:00:00Z'));
    const t0 = clock1.now();
    const newerPayload = {
      status: 'DEGRADED',
      degraded_reasons: ['OLLAMA_UNREACHABLE'],
      ollama: {reachable: false},
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t0 - 1000).toISOString(),
        expires_at: new Date(t0 + 299000).toISOString(),
        ttl_seconds: 300,
      },
    };
    const olderPayload = {
      status: 'DEGRADED',
      degraded_reasons: ['OLLAMA_UNREACHABLE'],
      ollama: {reachable: false},
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t0 - 11000).toISOString(),
        expires_at: new Date(t0 + 289000).toISOString(),
        ttl_seconds: 300,
      },
    };
    let nextPayload = newerPayload;
    let scope1 = 'http://127.0.0.1:19801|http://127.0.0.1:19801|anon';
    const mon1 = hm.createHealthMonitor({
      fetchHealth: async () => nextPayload,
      getScopeKey: () => scope1,
      storage: sharedStorage,
      now: clock1.now,
      setTimer: clock1.setTimer,
      clearTimer: clock1.clearTimer,
      retryDelaysMs: [],
    });

    await mon1.checkNow({force: true});
    const beforeSnap = mon1.getSnapshot();
    const beforeView = fp.classifyBackendHealthState(beforeSnap.backend, {nowMs: clock1.now()});
    const beforeOgRow = statusPage.buildHealthStatusRows(beforeSnap.backend, null, null, {}, beforeView).find((r) => r.name.includes('OpenGrep Active Health Probe'));
    assert.equal(beforeSnap.backend.status, 'DEGRADED');
    assert.equal(beforeSnap.backend.opengrepVerified, true);
    assert.equal(beforeSnap.backend.ttlExpired, false);
    assert.equal(beforeSnap.backend.expiresAtMs, t0 + 299000);
    assert.equal(mon1.hasPendingTtlTimer(), true);
    assert.equal(beforeView.ogInfo.isVerified, true);
    assert.match(beforeOgRow.value, /^Đã xác minh · VERIFIED/);

    // Manual refresh gets 10s-older snapshot while fresher probe has ~298s left
    clock1.advance(1000);
    nextPayload = olderPayload;
    await mon1.checkNow({force: true});
    const afterSnap = mon1.getSnapshot();
    const afterView = fp.classifyBackendHealthState(afterSnap.backend, {nowMs: clock1.now()});
    const afterOgRow = statusPage.buildHealthStatusRows(afterSnap.backend, null, null, {}, afterView).find((r) => r.name.includes('OpenGrep Active Health Probe'));
    assert.equal(afterSnap.backend.status, 'DEGRADED');
    assert.equal(afterSnap.backend.opengrepVerified, true);
    assert.equal(afterSnap.backend.ttlExpired, false);
    assert.equal(afterSnap.backend.expiresAtMs, t0 + 299000, 'Deadline must stay anchored to the fresher probe');
    assert.equal(afterSnap.meta.staleSnapshotIgnored, true);
    assert.equal(mon1.hasPendingTtlTimer(), true, 'Active TTL timer for fresher probe must remain armed');
    assert.equal(afterView.ogInfo.isVerified, true);
    assert.equal(afterView.pillLabel, beforeView.pillLabel);
    assert.equal(afterView.sidebarLabel, beforeView.sidebarLabel);
    assert.equal(afterOgRow.value, beforeOgRow.value);
    assert.equal(afterOgRow.detail, beforeOgRow.detail);

    // Passive expiry at the fresher probe's actual deadline -> EXPIRED without any HTTP request
    clock1.advance(298000);
    clock1.fireAllActive();
    assert.equal(mon1.getSnapshot().backend.ttlExpired, true);
    assert.equal(mon1.getSnapshot().backend.opengrepVerified, false);
    const expView = fp.classifyBackendHealthState(mon1.getSnapshot().backend, {nowMs: clock1.now()});
    const expRow = statusPage.buildHealthStatusRows(mon1.getSnapshot().backend, null, null, {}, expView).find((r) => r.name.includes('OpenGrep Active Health Probe'));
    assert.equal(expView.ogInfo.healthState, 'EXPIRED');
    assert.match(expRow.value, /EXPIRED/);

    // After passive expiry, older snapshot must NEVER resurrect VERIFIED
    await mon1.checkNow({force: true});
    assert.equal(mon1.getSnapshot().backend.ttlExpired, true);
    assert.equal(mon1.getSnapshot().backend.opengrepVerified, false);

    // Brand-new probe recovers VERIFIED cleanly
    const tRecover = clock1.now();
    nextPayload = {
      status: 'OK',
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(tRecover).toISOString(),
        expires_at: new Date(tRecover + 60000).toISOString(),
        ttl_seconds: 60,
        probe_execution_identity_sha256: 'd'.repeat(64),
      },
    };
    await mon1.checkNow({force: true});
    assert.equal(mon1.getSnapshot().backend.status, 'CONNECTED');
    assert.equal(mon1.getSnapshot().backend.opengrepVerified, true);
    assert.equal(mon1.getSnapshot().backend.expiresAtMs, tRecover + 60000);
    mon1.dispose();

    // 2. Exact Codex F02.2 scenario: +60s forward server clock skew, TTL 2s:
    //    VERIFIED -> passive EXPIRED -> refresh EXPIRED -> simulated reload (new monitor sharing storage) -> STILL EXPIRED!
    //    Also tests reload WHILE STILL VALID -> stays VERIFIED with exact remaining clamped deadline (no TTL extension!).
    const reloadStorage = mkStorage();
    const clock2 = makeClockAndTimers(Date.parse('2026-11-25T11:00:00Z'));
    const t2 = clock2.now();
    const skewPayload = {
      status: 'DEGRADED',
      degraded_reasons: ['OLLAMA_UNREACHABLE'],
      ollama: {reachable: false},
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t2 + 60000).toISOString(),
        expires_at: new Date(t2 + 62000).toISOString(),
        ttl_seconds: 2,
      },
    };
    const scope2 = 'http://127.0.0.1:19802|http://127.0.0.1:19802|anon';
    const mkMon2 = (payloadGetter) => hm.createHealthMonitor({
      fetchHealth: async () => payloadGetter(),
      getScopeKey: () => scope2,
      storage: reloadStorage,
      now: clock2.now,
      setTimer: clock2.setTimer,
      clearTimer: clock2.clearTimer,
      retryDelaysMs: [],
    });

    const m2a = mkMon2(() => skewPayload);
    await m2a.checkNow({force: true});
    assert.equal(m2a.getSnapshot().backend.opengrepVerified, true);
    assert.equal(m2a.getSnapshot().backend.expiresAtMs, t2 + 2000, 'Forward skew clamped to receivedAt + ttl_seconds');

    // Duplicate refresh at t+1s -> NO TTL extension (deadline stays t2 + 2000)
    clock2.advance(1000);
    await m2a.checkNow({force: true});
    assert.equal(m2a.getSnapshot().backend.opengrepVerified, true);
    assert.equal(m2a.getSnapshot().backend.expiresAtMs, t2 + 2000, 'Duplicate refresh must not extend TTL');

    // Simulated reload WHILE STILL VALID (at t+1s, 1s left) -> stays VERIFIED with remaining 1s, NO TTL extension
    m2a.dispose();
    const m2b = mkMon2(() => skewPayload);
    await m2b.checkNow({force: true});
    assert.equal(m2b.getSnapshot().backend.opengrepVerified, true);
    assert.equal(m2b.getSnapshot().backend.expiresAtMs, t2 + 2000, 'Reload while valid must preserve clamped deadline');
    assert.equal(m2b.hasPendingTtlTimer(), true);

    // Advance 1s -> passive expiry
    clock2.advance(1000);
    clock2.fireAllActive();
    assert.equal(m2b.getSnapshot().backend.ttlExpired, true);
    assert.equal(m2b.getSnapshot().backend.opengrepVerified, false);

    // Refresh while expired -> stays EXPIRED
    clock2.advance(500);
    await m2b.checkNow({force: true});
    assert.equal(m2b.getSnapshot().backend.ttlExpired, true);
    assert.equal(m2b.getSnapshot().backend.opengrepVerified, false);

    // Simulated reload AFTER EXPIRY -> MUST STAY EXPIRED (zero resurrection!)
    m2b.dispose();
    clock2.advance(500);
    const m2c = mkMon2(() => skewPayload);
    await m2c.checkNow({force: true});
    assert.equal(m2c.getSnapshot().backend.ttlExpired, true, 'Reload replay of expired +60s skewed snapshot must stay EXPIRED');
    assert.equal(m2c.getSnapshot().backend.opengrepVerified, false);

    // Brand-new probe after reload recovers VERIFIED cleanly
    const freshAfterReload = {
      status: 'DEGRADED',
      degraded_reasons: ['OLLAMA_UNREACHABLE'],
      ollama: {reachable: false},
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t2 + 65000).toISOString(),
        expires_at: new Date(t2 + 70000).toISOString(),
        ttl_seconds: 5,
        probe_execution_identity_sha256: 'e'.repeat(64),
      },
    };
    const m2d = mkMon2(() => freshAfterReload);
    m2c.dispose();
    await m2d.checkNow({force: true});
    assert.equal(m2d.getSnapshot().backend.opengrepVerified, true);
    assert.equal(m2d.getSnapshot().backend.ttlExpired, false);
    m2d.dispose();

    // 3. Server clock BEHIND client (-60s):
    //    (a) 300s TTL -> expires_at = t - 60 + 300 = t + 240s > t -> VERIFIED bounded at t + 240s
    //    (b) 10s TTL -> expires_at = t - 60 + 10 = t - 50s <= t -> fail-closed EXPIRED
    const clock3 = makeClockAndTimers(Date.parse('2026-11-25T12:00:00Z'));
    const t3 = clock3.now();
    const behindValid = hm.classifyHealthResponse({
      status: 'OK',
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t3 - 60000).toISOString(),
        expires_at: new Date(t3 + 240000).toISOString(),
        ttl_seconds: 300,
      },
    }, {nowMs: t3, receivedAtMs: t3});
    assert.equal(behindValid.opengrepVerified, true);
    assert.equal(behindValid.expiresAtMs, t3 + 240000);

    const behindExpired = hm.classifyHealthResponse({
      status: 'OK',
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t3 - 60000).toISOString(),
        expires_at: new Date(t3 - 50000).toISOString(),
        ttl_seconds: 10,
      },
    }, {nowMs: t3, receivedAtMs: t3});
    assert.equal(behindExpired.opengrepVerified, false);
    assert.equal(behindExpired.ttlExpired, true);

    // Server checked_at >= expires_at enforces server expiry even with +60s forward skew & no storage!
    const serverCheckedExpired = hm.classifyHealthResponse({
      status: 'OK',
      checked_at: new Date(t3 + 65000).toISOString(),
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t3 + 60000).toISOString(),
        expires_at: new Date(t3 + 62000).toISOString(),
        ttl_seconds: 2,
      },
    }, {nowMs: t3, receivedAtMs: t3, serverCheckedAtMs: t3 + 65000});
    assert.equal(serverCheckedExpired.opengrepVerified, false);
    assert.equal(serverCheckedExpired.ttlExpired, true);

    // 4. Out-of-order response completion + unmount/dispose during in-flight request
    let resolveReq1;
    let resolveReq2;
    let reqCount = 0;
    const clock4 = makeClockAndTimers(Date.parse('2026-11-25T13:00:00Z'));
    const t4 = clock4.now();
    const mon4 = hm.createHealthMonitor({
      fetchHealth: () => {
        reqCount += 1;
        if (reqCount === 1) return new Promise((r) => { resolveReq1 = r; });
        return new Promise((r) => { resolveReq2 = r; });
      },
      getScopeKey: () => 'http://127.0.0.1:19804|http://127.0.0.1:19804|anon',
      storage: null,
      now: clock4.now,
      setTimer: clock4.setTimer,
      clearTimer: clock4.clearTimer,
      retryDelaysMs: [],
    });
    const p1 = mon4.checkNow({force: true});
    const p2 = mon4.checkNow({force: true});
    resolveReq2({
      status: 'OK',
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t4).toISOString(),
        expires_at: new Date(t4 + 30000).toISOString(),
        ttl_seconds: 30,
      },
    });
    await p2;
    assert.equal(mon4.getSnapshot().backend.opengrepVerified, true);
    assert.equal(mon4.getSnapshot().backend.expiresAtMs, t4 + 30000);
    // Late req1 resolves with stale/error payload -> MUST be ignored
    resolveReq1({
      status: 'DEGRADED',
      opengrep: {
        ...BASE_VERIFIED_OG,
        probed_at: new Date(t4 - 10000).toISOString(),
        expires_at: new Date(t4 - 5000).toISOString(),
        ttl_seconds: 5,
      },
    });
    await p1;
    assert.equal(mon4.getSnapshot().backend.status, 'CONNECTED');
    assert.equal(mon4.getSnapshot().backend.opengrepVerified, true);
    assert.equal(mon4.getSnapshot().backend.expiresAtMs, t4 + 30000);

    // Unmount during in-flight request -> late response does not mutate disposed monitor
    let resolveReq3;
    const emittedAfterDispose = [];
    const monDispose = hm.createHealthMonitor({
      fetchHealth: () => new Promise((r) => { resolveReq3 = r; }),
      getScopeKey: () => 'http://127.0.0.1:19805|http://127.0.0.1:19805|anon',
      storage: null,
      onStateChange: (s) => emittedAfterDispose.push(s.backend.status),
      now: clock4.now,
      setTimer: clock4.setTimer,
      clearTimer: clock4.clearTimer,
      retryDelaysMs: [],
    });
    const p3 = monDispose.checkNow({force: true});
    const countBeforeDispose = emittedAfterDispose.length;
    monDispose.dispose();
    resolveReq3({status: 'OK', opengrep: {...BASE_VERIFIED_OG, probed_at: new Date(t4).toISOString(), expires_at: new Date(t4 + 30000).toISOString(), ttl_seconds: 30}});
    await p3;
    assert.equal(emittedAfterDispose.length, countBeforeDispose);
    mon4.dispose();

    // 5. Missing expiry, TTL-only, invalid timestamps, TTL <= 0 / wrong type -> fail-closed (never VERIFIED)
    for (const badOg of [
      {...BASE_VERIFIED_OG}, // missing all expiry fields
      {...BASE_VERIFIED_OG, ttl_seconds: 300}, // TTL only, no timestamp anchor
      {...BASE_VERIFIED_OG, probed_at: 'not-a-date', expires_at: 'also-bad', ttl_seconds: 300},
      {...BASE_VERIFIED_OG, probed_at: new Date(t4).toISOString(), expires_at: new Date(t4).toISOString(), ttl_seconds: 0},
      {...BASE_VERIFIED_OG, probed_at: new Date(t4).toISOString(), expires_at: new Date(t4 + 10000).toISOString(), ttl_seconds: -5},
      {...BASE_VERIFIED_OG, probed_at: new Date(t4).toISOString(), expires_at: new Date(t4 + 10000).toISOString(), ttl_seconds: '300'},
      {...BASE_VERIFIED_OG, probed_at: new Date(t4 + 5000).toISOString(), expires_at: new Date(t4).toISOString(), ttl_seconds: 10},
    ]) {
      const classified = hm.classifyHealthResponse({status: 'OK', opengrep: badOg}, {nowMs: t4, receivedAtMs: t4});
      assert.equal(classified.opengrepVerified, false, `Must reject invalid/unanchored expiry: ${JSON.stringify(badOg)}`);
    }

    // 6. HTTP 401/403/500/timeout/disconnect clear active VERIFIED state & timers immediately
    for (const errObj of [
      Object.assign(new Error('Unauthorized'), {status: 401}),
      Object.assign(new Error('Forbidden'), {status: 403}),
      Object.assign(new Error('Server Error'), {status: 500}),
      Object.assign(new Error('Request timed out'), {code: 'TIMEOUT'}),
      new TypeError('Failed to fetch'),
    ]) {
      let shouldThrow = false;
      const monErr = hm.createHealthMonitor({
        fetchHealth: async () => {
          if (shouldThrow) throw errObj;
          return {
            status: 'OK',
            opengrep: {
              ...BASE_VERIFIED_OG,
              probed_at: new Date(t4).toISOString(),
              expires_at: new Date(t4 + 60000).toISOString(),
              ttl_seconds: 60,
            },
          };
        },
        getScopeKey: () => `http://127.0.0.1:19810|err|${errObj.status || errObj.code || 'net'}`,
        storage: null,
        now: clock4.now,
        setTimer: clock4.setTimer,
        clearTimer: clock4.clearTimer,
        retryDelaysMs: [],
      });
      await monErr.checkNow({force: true});
      assert.equal(monErr.getSnapshot().backend.opengrepVerified, true);
      assert.equal(monErr.hasPendingTtlTimer(), true);
      shouldThrow = true;
      await monErr.checkNow({force: true});
      assert.equal(monErr.getSnapshot().backend.opengrepVerified, false);
      assert.equal(monErr.hasPendingTtlTimer(), false);
      assert.equal(monErr.getSnapshot().backend.status, errObj.status === 401 ? 'AUTH_REQUIRED' : 'ERROR');
      monErr.dispose();
    }

    // 7. Storage unavailable (throwing), corrupted JSON, and tampered future deadline -> never crash, never extend TTL or grant VERIFIED
    const throwingMon = hm.createHealthMonitor({
      fetchHealth: async () => ({
        status: 'OK',
        opengrep: {
          ...BASE_VERIFIED_OG,
          probed_at: new Date(t4).toISOString(),
          expires_at: new Date(t4 + 30000).toISOString(),
          ttl_seconds: 30,
        },
      }),
      getScopeKey: () => 'http://127.0.0.1:19820|throw|anon',
      storage: mkThrowingStorage(),
      now: clock4.now,
      setTimer: clock4.setTimer,
      clearTimer: clock4.clearTimer,
      retryDelaysMs: [],
    });
    await throwingMon.checkNow({force: true});
    assert.equal(throwingMon.getSnapshot().backend.opengrepVerified, true);
    throwingMon.dispose();

    const corruptStorage = mkStorage({[apiMod.HEALTH_PROOF_LEDGER_STORAGE_KEY]: '{broken json!!!'});
    const corruptMon = hm.createHealthMonitor({
      fetchHealth: async () => ({
        status: 'OK',
        opengrep: {
          ...BASE_VERIFIED_OG,
          probed_at: new Date(t4).toISOString(),
          expires_at: new Date(t4 + 15000).toISOString(),
          ttl_seconds: 15,
        },
      }),
      getScopeKey: () => 'http://127.0.0.1:19821|corrupt|anon',
      storage: corruptStorage,
      now: clock4.now,
      setTimer: clock4.setTimer,
      clearTimer: clock4.clearTimer,
      retryDelaysMs: [],
    });
    await corruptMon.checkNow({force: true});
    assert.equal(corruptMon.getSnapshot().backend.opengrepVerified, true);
    corruptMon.dispose();

    // Tampered storage claiming huge future deadline cannot extend rawDeadline
    const sigTamper = hm.buildProbeProofSignature(
      {...BASE_VERIFIED_OG, probed_at: new Date(t4).toISOString(), expires_at: new Date(t4 + 5000).toISOString(), ttl_seconds: 5},
      fp.resolveOpengrepExpiryEvidence(
        {...BASE_VERIFIED_OG, probed_at: new Date(t4).toISOString(), expires_at: new Date(t4 + 5000).toISOString(), ttl_seconds: 5},
        t4,
      ),
    );
    const tamperScope = 'http://127.0.0.1:19822|tamper|anon';
    const tamperedStorage = mkStorage({
      [apiMod.HEALTH_PROOF_LEDGER_STORAGE_KEY]: JSON.stringify({
        v: 1,
        scopes: {
          [`custom|${tamperScope}`]: {
            latestProbedAtMs: null,
            latestServerExpiresAtMs: null,
            latestProcessInstanceId: '',
            updatedAtMs: t4,
            proofs: {
              [sigTamper]: {expiresAtMs: t4 + 999999999, firstSeenAtMs: t4 - 1000},
            },
          },
        },
      }),
    });
    const tamperMon = hm.createHealthMonitor({
      fetchHealth: async () => ({
        status: 'OK',
        opengrep: {
          ...BASE_VERIFIED_OG,
          probed_at: new Date(t4).toISOString(),
          expires_at: new Date(t4 + 5000).toISOString(),
          ttl_seconds: 5,
        },
      }),
      getScopeKey: () => tamperScope,
      storage: tamperedStorage,
      now: clock4.now,
      setTimer: clock4.setTimer,
      clearTimer: clock4.clearTimer,
      retryDelaysMs: [],
    });
    await tamperMon.checkNow({force: true});
    assert.equal(tamperMon.getSnapshot().backend.expiresAtMs, t4 + 5000, 'Tampered storage cannot extend deadline beyond rawDeadline');
    tamperMon.dispose();

    // 8. API URL switch and Bearer token set/switch/clear bind salted non-reversible HMAC scope
    //    for anti-replay across reload -> AUTH_REQUIRED -> same-token re-entry, isolate distinct
    //    tokens/URLs/anon sessions, and NEVER leak the Bearer token into sessionStorage.
    apiMod.setApiBaseUrl('http://127.0.0.1:19830');
    const anonKey1 = apiMod.getHealthPersistenceScopeKey();
    assert.ok(anonKey1 && anonKey1.includes('http://127.0.0.1:19830') && anonKey1.endsWith('|anon'));
    sharedStorage.setItem(apiMod.HEALTH_PROOF_LEDGER_STORAGE_KEY, JSON.stringify({v: 1, scopes: {[anonKey1]: {proofs: {}}}}));

    const secretToken = 'super-secret-bearer-token-987654321';
    apiMod.setSessionToken(secretToken);
    const authKey1 = apiMod.getHealthPersistenceScopeKey();
    assert.ok(authKey1 && authKey1.includes('|auth:'), 'Authenticated sessions must use salted opaque HMAC ledger key');
    assert.equal(authKey1.includes(secretToken), false, 'Persistence scope key must NEVER contain raw Bearer token');
    assert.notEqual(authKey1, anonKey1, 'Authenticated ledger key must isolate from anonymous ledger key');
    for (const [k, v] of sharedStorage._map.entries()) {
      assert.equal(String(k).includes(secretToken), false);
      assert.equal(String(v).includes(secretToken), false, 'Bearer token must NEVER appear in sessionStorage');
    }

    // Re-entering the exact same token after reload/AUTH_REQUIRED must map to the identical salted scope key
    apiMod.setSessionToken('');
    const anonKey2 = apiMod.getHealthPersistenceScopeKey();
    assert.equal(anonKey2, anonKey1, 'Anonymous scope key remains stable for same URL/origin');
    apiMod.setSessionToken(secretToken);
    assert.equal(apiMod.getHealthPersistenceScopeKey(), authKey1, 'Same token re-entry must re-bind to identical anti-replay scope');

    // Switching to a different token must isolate into a distinct scope key
    const otherToken = 'different-operator-token-123456789';
    apiMod.setSessionToken(otherToken);
    const authKey2 = apiMod.getHealthPersistenceScopeKey();
    assert.ok(authKey2 && authKey2.includes('|auth:'));
    assert.notEqual(authKey2, authKey1, 'Different Bearer token must isolate persistence scope');
    assert.equal(authKey2.includes(otherToken), false);

    apiMod.setSessionToken('');
    apiMod.setApiBaseUrl('http://127.0.0.1:19831');
    const anonKey3 = apiMod.getHealthPersistenceScopeKey();
    assert.notEqual(anonKey3, anonKey2, 'Switching API URL must isolate persistence scope');
  } finally {
    global.window = prevWindow;
    global.sessionStorage = prevSession;
  }
});

test('F05 root-cause matrix over REAL raw loopback HTTP: wire decimals, precision traps, duplicate keys, MAX_SAFE_INTEGER, cache parity, and byte-identical report preservation', async () => {
  const prevWindow = global.window;
  const prevSession = global.sessionStorage;
  const storage = mkStorage();
  global.sessionStorage = storage;
  global.window = {
    location: {origin: 'http://127.0.0.1:19900', hostname: '127.0.0.1'},
    sessionStorage: storage,
    setTimeout: global.setTimeout,
    clearTimeout: global.clearTimeout,
  };

  const routes = new Map();
  const buildJobRaw = (stage5MetaRaw, {stage5RawOverride = null, state = 'COMPLETED'} = {}) => {
    const stage5Obj = stage5RawOverride || `{"stage_number":5,"stage_key":"CITATION_VALIDATION","state":"COMPLETED","duration_ms":null,"summary_metadata":${stage5MetaRaw}}`;
    return `{
      "job_id":"job-f05-test",
      "scan_id":"scan-f05-test",
      "state":"${state}",
      "active_stage":5,
      "non_overlapping_integration_gate_ms":142,
      "stages":[
        {"stage_number":1,"stage_key":"INTAKE_VALIDATION","state":"COMPLETED","duration_ms":10,"summary_metadata":{"java_files_count":12}},
        {"stage_number":2,"stage_key":"OPENGREP_SCAN","state":"COMPLETED","duration_ms":50,"summary_metadata":{"java_files_inventory":12,"java_files_opengrep_scanned":10,"java_files_opengrep_ignored":2,"opengrep_paths_telemetry_status":"VERIFIED"}},
        {"stage_number":3,"stage_key":"EVIDENCE_COLLECTION","state":"COMPLETED","duration_ms":20,"summary_metadata":{}},
        {"stage_number":4,"stage_key":"QWEN_INFERENCE","state":"COMPLETED","duration_ms":100,"summary_metadata":{}},
        ${stage5Obj},
        {"stage_number":6,"stage_key":"REVIEW_STORE_COMMIT","state":"COMPLETED","duration_ms":15,"summary_metadata":{}}
      ]
    }`;
  };

  await withRawHttpServer((req, res) => {
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
    const entry = routes.get(req.url) || routes.get(pathname);
    if (!entry) {
      res.writeHead(404, {'Content-Type': 'application/json'});
      res.end('{"error_code":"NOT_FOUND"}');
      return;
    }
    res.writeHead(entry.status || 200, {'Content-Type': 'application/json; charset=utf-8'});
    res.end(entry.rawBody);
  }, async (baseUrl) => {
    try {
      storage.setItem('ntk-api-base-url', baseUrl);
      const apiMod = await bundleAndImport('services/api.js');
      const jobModel = await bundleAndImport('services/jobModel.js');
      const lsp = await bundleAndImport('components/scanner/liveStagePresentation.js');
      const liveScan = await bundleAndImport('services/liveScan.js');
      const fp = await bundleAndImport('services/findingPresentation.js');

      apiMod.setApiBaseUrl(baseUrl);

      const fetchAndResolveStage5 = async (routePath, rawBody) => {
        // Proof that raw HTTP payload preserves exact wire representation before sending
        routes.set(routePath, {status: 200, rawBody});
        const jobDoc = await apiMod.api.scanJob(routePath.replace('/api/scan-jobs/', ''));
        const stages = jobModel.resolveStages(jobDoc);
        const stage5 = stages[4];
        const liveRes = lsp.resolveStage05CitationTelemetry({mode: 'LIVE', stage: stage5});
        const playbackRes = lsp.resolveStage05CitationTelemetry({mode: 'PLAYBACK', stage: stage5});
        assert.equal(liveRes.aggregateStatus, playbackRes.aggregateStatus, `LIVE vs PLAYBACK mismatch for ${routePath}`);
        assert.deepEqual(
          liveRes.checks.map((c) => c.status),
          playbackRes.checks.map((c) => c.status),
          `Per-layer LIVE vs PLAYBACK parity mismatch for ${routePath}`,
        );
        return {jobDoc, stage5, liveRes, playbackRes};
      };

      // 1. Wire precision-loss decimals & unsafe integers sent verbatim over raw HTTP -> MUST be MALFORMED (NEVER ALL_MATCHED / AGGREGATE_MATCHED)
      const wireMalformedPayloads = [
        ['codex-wire-decimal', '{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":1.0000000000000001}'],
        ['wire-below-one-round-up', '{"matched_count":0.99999999999999999,"invalid_count":0,"not_verified_count":0,"total_checked":1}'],
        ['wire-underflow-to-zero', '{"matched_count":1,"invalid_count":1e-325,"not_verified_count":0,"total_checked":1}'],
        ['wire-exp-decimal-round', '{"matched_count":1000000000000000,"invalid_count":0,"not_verified_count":0,"total_checked":1.0000000000000001e15}'],
        ['wire-max-safe-plus-eps', '{"matched_count":9007199254740991,"invalid_count":0,"not_verified_count":0,"total_checked":9007199254740991.0000000000000001}'],
        ['wire-signed-zero', '{"matched_count":1,"invalid_count":-0,"not_verified_count":0,"total_checked":1}'],
        ['wire-negative', '{"matched_count":1,"invalid_count":-1,"not_verified_count":0,"total_checked":1}'],
        ['wire-normal-decimal', '{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":1.5}'],
        ['wire-unsafe-pair', '{"matched_count":9007199254740992,"invalid_count":0,"not_verified_count":0,"total_checked":9007199254740993}'],
        ['wire-unsafe-exp', '{"matched_count":9.007199254740992e15,"invalid_count":0,"not_verified_count":0,"total_checked":9.007199254740992e15}'],
        ['wire-huge-exp', '{"matched_count":1e20,"invalid_count":0,"not_verified_count":0,"total_checked":1e20}'],
        ['wire-overflow-exp', '{"matched_count":1e500,"invalid_count":0,"not_verified_count":0,"total_checked":1e500}'],
        ['wire-sum-overflow', '{"matched_count":9007199254740991,"invalid_count":0,"not_verified_count":1}'],
        ['wire-unicode-key-decimal', '{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total\\u005fchecked":1.0000000000000001}'],
        ['wire-null-count', '{"matched_count":1,"invalid_count":null,"not_verified_count":0,"total_checked":1}'],
        ['wire-bool-count', '{"matched_count":1,"invalid_count":false,"not_verified_count":0,"total_checked":1}'],
        ['wire-string-count', '{"matched_count":"1","invalid_count":0,"not_verified_count":0,"total_checked":1}'],
        ['wire-object-count', '{"matched_count":1,"invalid_count":{},"not_verified_count":0,"total_checked":1}'],
        ['wire-array-count', '{"matched_count":1,"invalid_count":[],"not_verified_count":0,"total_checked":1}'],
      ];

      for (const [id, rawMeta] of wireMalformedPayloads) {
        const rawJob = buildJobRaw(rawMeta);
        assert.equal(rawJob.includes(rawMeta), true, `Raw HTTP payload must contain verbatim lexeme for ${id}`);
        const {liveRes} = await fetchAndResolveStage5(`/api/scan-jobs/${id}`, rawJob);
        assert.notEqual(liveRes.aggregateStatus, 'ALL_MATCHED', `${id} must NEVER produce ALL_MATCHED`);
        assert.equal(
          liveRes.checks.every((c) => c.status !== 'AGGREGATE_MATCHED' && c.status !== 'MATCHED'),
          true,
          `${id} must NEVER produce AGGREGATE_MATCHED or MATCHED pills`,
        );
        if (id !== 'wire-null-count') {
          assert.equal(liveRes.aggregateStatus, 'MALFORMED', `${id} must be MALFORMED`);
        } else {
          // null for an optional/missing required field fails closed as PARTIAL (never defaulted to 0)
          assert.equal(liveRes.aggregateStatus, 'PARTIAL', `${id} must stay PARTIAL, never default null to 0`);
        }
      }

      // 2. Duplicate conflicting wire keys (counts, Unicode-escaped duplicate key, citation_checks layer, summary_metadata) -> CONFLICT
      const wireConflictPayloads = [
        ['dup-invalid-count', buildJobRaw('{"matched_count":1,"invalid_count":2,"invalid_count":0,"not_verified_count":0,"total_checked":1}')],
        ['dup-unicode-total', buildJobRaw('{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":2,"total\\u005fchecked":1}')],
        ['dup-layer-conflict', buildJobRaw('{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":1,"citation_checks":{"path":"INVALID","path":"MATCHED","line":"MATCHED","quote":"MATCHED","sha256":"MATCHED"}}')],
        ['dup-summary-meta', buildJobRaw('{}', {stage5RawOverride: '{"stage_number":5,"stage_key":"CITATION_VALIDATION","state":"COMPLETED","duration_ms":null,"summary_metadata":{"invalid_count":2},"summary_metadata":{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":1}}'})],
        ['sum-mismatch', buildJobRaw('{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":2}')],
        ['overall-vs-path-invalid', buildJobRaw('{"citation_status":"MATCHED","matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":1,"checks":{"path":"INVALID","line":"MATCHED","quote":"MATCHED","sha256":"MATCHED"}}')],
        ['overall-vs-line-invalid', buildJobRaw('{"citation_status":"MATCHED","checks":{"path":"MATCHED","line":"INVALID","quote":"MATCHED","sha256":"MATCHED"}}')],
        ['overall-vs-quote-invalid', buildJobRaw('{"citation_status":"MATCHED","checks":{"path":"MATCHED","line":"MATCHED","quote":"INVALID","sha256":"MATCHED"}}')],
        ['overall-vs-sha256-invalid', buildJobRaw('{"citation_status":"MATCHED","checks":{"path":"MATCHED","line":"MATCHED","quote":"MATCHED","sha256":"INVALID"}}')],
      ];
      for (const [id, rawJob] of wireConflictPayloads) {
        const {liveRes} = await fetchAndResolveStage5(`/api/scan-jobs/${id}`, rawJob);
        assert.equal(liveRes.aggregateStatus, 'CONFLICT', `${id} must fail-closed as CONFLICT`);
        assert.equal(liveRes.hasBackendEvidence, true);
      }

      // 3. Valid controls, zero/NO_FINDINGS, INVALID, NOT_VERIFIED, PARTIAL (missing each field), NO_DATA
      const validCases = [
        ['valid-all-matched', '{"matched_count":3,"invalid_count":0,"not_verified_count":0,"total_checked":3}', 'ALL_MATCHED'],
        ['valid-max-safe', '{"matched_count":9007199254740991,"invalid_count":0,"not_verified_count":0,"total_checked":9007199254740991}', 'ALL_MATCHED'],
        ['valid-exact-exp', '{"matched_count":9.007199254740991e15,"invalid_count":0,"not_verified_count":0,"total_checked":9007199254740991}', 'ALL_MATCHED'],
        ['valid-zero-no-findings', '{"matched_count":0,"invalid_count":0,"not_verified_count":0,"total_checked":0}', 'NO_FINDINGS'],
        ['valid-invalid', '{"matched_count":0,"invalid_count":1,"not_verified_count":0,"total_checked":1}', 'INVALID'],
        ['valid-mixed', '{"matched_count":2,"invalid_count":1,"not_verified_count":0,"total_checked":3}', 'MIXED'],
        ['valid-not-verified', '{"matched_count":0,"invalid_count":0,"not_verified_count":2,"total_checked":2}', 'NOT_VERIFIED'],
        ['missing-matched', '{"invalid_count":0,"not_verified_count":0,"total_checked":1}', 'PARTIAL'],
        ['missing-invalid', '{"matched_count":1,"not_verified_count":0,"total_checked":1}', 'PARTIAL'],
        ['missing-not-verified', '{"matched_count":1,"invalid_count":0,"total_checked":1}', 'PARTIAL'],
        ['missing-total', '{"matched_count":1,"invalid_count":0,"not_verified_count":0}', 'PARTIAL'],
        ['no-telemetry', 'null', 'NO_DATA'],
      ];
      for (const [id, rawMeta, expected] of validCases) {
        const {liveRes, stage5} = await fetchAndResolveStage5(`/api/scan-jobs/${id}`, buildJobRaw(rawMeta));
        assert.equal(liveRes.aggregateStatus, expected, `${id} expected ${expected}, got ${liveRes.aggregateStatus}`);
        // Also confirm Stage 5 duration_ms: null is preserved as null (not 0) & non_overlapping_integration_gate_ms doesn't break anything
        assert.equal(stage5.duration, null);
      }

      // 4. Malformed / truncated JSON over raw HTTP -> rejected with ApiError
      routes.set('/api/scan-jobs/truncated-json', {status: 200, rawBody: '{"job_id":"x","stages":[{"stage_number":5'});
      await assert.rejects(
        () => apiMod.api.scanJob('truncated-json'),
        (err) => err && err.name === 'ApiError',
        'Truncated JSON must reject cleanly at REST decode boundary',
      );

      // 5. Cache path parity (liveScan.loadLiveScan -> RAM liveDatasetCache):
      //    (a) wire-decimal total_findings in /api/scans/{id} MUST fail-closed (reject with INVALID_TOTAL_FINDINGS
      //        and NEVER pollute liveDatasetCache), on both first and repeated calls.
      const rawBadScanSummary = '{"scan_id":"scan-wire-cache","total_findings":1.0000000000000001,"by_validated_status":{"SUPPORTED":1,"REFUTED":0,"UNDETERMINED":0},"by_human_review_state":{"OPEN":1,"CONFIRMED_TRUE":0,"CONFIRMED_FALSE":0}}';
      const rawBadFindingsPage = '{"scan_id":"scan-wire-cache","findings":[{"finding_id":"f-1","validated_status":"SUPPORTED","human_review_state":"OPEN"}],"total_count":1,"total_matching":1,"page":1,"page_size":200,"total_pages":1,"has_more":false}';
      routes.set('/api/scans/scan-wire-cache', {status: 200, rawBody: rawBadScanSummary});
      routes.set('/api/scans/scan-wire-cache/findings', {status: 200, rawBody: rawBadFindingsPage});
      await assert.rejects(
        () => liveScan.loadLiveScan('scan-wire-cache'),
        (err) => err && err.code === 'INVALID_TOTAL_FINDINGS',
        'Wire-decimal total_findings must fail-closed with INVALID_TOTAL_FINDINGS',
      );
      await assert.rejects(
        () => liveScan.loadLiveScan('scan-wire-cache'),
        (err) => err && err.code === 'INVALID_TOTAL_FINDINGS',
        'Repeated load must still fail-closed (never cached)',
      );
      //    (b) Valid integer scan succeeds and caches cleanly
      const rawGoodScanSummary = '{"scan_id":"scan-valid-cache","total_findings":1,"by_validated_status":{"SUPPORTED":1,"REFUTED":0,"UNDETERMINED":0},"by_human_review_state":{"OPEN":1,"CONFIRMED_TRUE":0,"CONFIRMED_FALSE":0}}';
      const rawGoodFindingsPage = '{"scan_id":"scan-valid-cache","findings":[{"finding_id":"f-1","validated_status":"SUPPORTED","human_review_state":"OPEN"}],"total_count":1,"total_matching":1,"page":1,"page_size":200,"total_pages":1,"has_more":false}';
      routes.set('/api/scans/scan-valid-cache', {status: 200, rawBody: rawGoodScanSummary});
      routes.set('/api/scans/scan-valid-cache/findings', {status: 200, rawBody: rawGoodFindingsPage});
      const goodFirst = await liveScan.loadLiveScan('scan-valid-cache');
      const goodSecond = await liveScan.loadLiveScan('scan-valid-cache');
      assert.equal(goodFirst.counts.total, 1);
      assert.equal(goodSecond.counts.total, 1);

      // 6. Unsigned report JSON byte-for-byte preservation (WeakMap adds ZERO properties)
      const originalReportObj = {
        scan_summary: {scan_id: 'scan-unsigned-1', total_findings: 2, data_origin: 'REAL_SCAN'},
        findings: [
          {finding_id: 'f1', scan_id: 'scan-unsigned-1', cwe_id: 'CWE-89', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
          {finding_id: 'f2', scan_id: 'scan-unsigned-1', cwe_id: 'CWE-22', validated_status: 'UNDETERMINED', human_review_state: 'OPEN'},
        ],
        report_integrity: {signed: false},
      };
      const expectedPretty = JSON.stringify(originalReportObj, null, 2);
      routes.set('/api/scans/scan-unsigned-1/report', {status: 200, rawBody: expectedPretty});
      const fetchedReport = await apiMod.api.report('scan-unsigned-1');
      assert.equal(JSON.stringify(fetchedReport, null, 2), expectedPretty, 'Wire integrity metadata must NEVER mutate exported report JSON bytes');

      // 7. Backend G3 Contract Compatibility: Java file telemetry & opengrep_paths_telemetry_status
      const g3Verified = fp.resolveJavaFileCounts({
        java_files_inventory: 45,
        java_files_opengrep_scanned: 40,
        java_files_opengrep_ignored: 5,
        opengrep_paths_telemetry_status: 'VERIFIED',
      });
      assert.equal(g3Verified.inventoryCount, 45);
      assert.equal(g3Verified.scannedCount, 40);
      assert.equal(g3Verified.ignoredCount, 5);
      assert.equal(g3Verified.hasVerifiedScanned, true);
      assert.equal(g3Verified.isInconsistent, false);

      const g3MissingTelemetry = fp.resolveJavaFileCounts({
        java_files_inventory: 45,
        java_files_opengrep_scanned: null,
        java_files_opengrep_ignored: null,
        opengrep_paths_telemetry_status: 'MISSING_PATHS_TELEMETRY',
      });
      assert.equal(g3MissingTelemetry.inventoryCount, 45);
      assert.equal(g3MissingTelemetry.scannedCount, null, 'Missing scanned count must stay null, never 0');
      assert.equal(g3MissingTelemetry.ignoredCount, null, 'Missing ignored count must stay null, never 0');
      assert.equal(g3MissingTelemetry.hasVerifiedScanned, false);
      assert.equal(g3MissingTelemetry.isInconsistent, false);

      const g3MissingContradiction = fp.resolveJavaFileCounts({
        java_files_inventory: 45,
        java_files_opengrep_scanned: 40,
        java_files_opengrep_ignored: 5,
        opengrep_paths_telemetry_status: 'MISSING_PATHS_TELEMETRY',
      });
      assert.equal(g3MissingContradiction.isInconsistent, true);
      assert.equal(g3MissingContradiction.hasVerifiedScanned, false);

      const g3Inconsistent = fp.resolveJavaFileCounts({
        java_files_inventory: 45,
        java_files_opengrep_scanned: 40,
        java_files_opengrep_ignored: 5,
        opengrep_paths_telemetry_status: 'INCONSISTENT_TELEMETRY',
      });
      assert.equal(g3Inconsistent.isInconsistent, true);
      assert.equal(g3Inconsistent.hasVerifiedScanned, false);
      assert.match(g3Inconsistent.inconsistencyReason, /INCONSISTENT_TELEMETRY/);

      const g3LegacyOnly = fp.resolveJavaFileCounts({java_files_scanned: 45});
      assert.equal(g3LegacyOnly.inventoryCount, 45);
      assert.equal(g3LegacyOnly.inventoryFromLegacy, true);
      assert.equal(g3LegacyOnly.scannedCount, null, 'Legacy java_files_scanned must NEVER be treated as verified opengrep scanned');
      assert.equal(g3LegacyOnly.hasVerifiedScanned, false);

      // Wire-decimal in G3 Java counts via raw HTTP -> rejected as invalid
      const rawBadG3Job = buildJobRaw('{"matched_count":1,"invalid_count":0,"not_verified_count":0,"total_checked":1}')
        .replace('"java_files_opengrep_scanned":10', '"java_files_opengrep_scanned":10.0000000000000001');
      routes.set('/api/scan-jobs/g3-wire-decimal', {status: 200, rawBody: rawBadG3Job});
      const badG3JobDoc = await apiMod.api.scanJob('g3-wire-decimal');
      const badG3Java = fp.resolveJavaFileCounts(null, badG3JobDoc);
      assert.equal(badG3Java.hasInvalidFields, true, 'Wire-decimal java_files_opengrep_scanned must be flagged invalid');
      assert.equal(badG3Java.scannedCount, null);
    } finally {
      global.window = prevWindow;
      global.sessionStorage = prevSession;
    }
  });
});
