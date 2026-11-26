// Comprehensive invariant & state-matrix regression suite for final repair of F02, F03, and F05.
// Keeps all 9 prior test files untouched while thoroughly testing generalized state matrices:
//   - F02: OpenGrep probe TTL lifecycle independent of overall API OK/DEGRADED status, Ollama
//     reachable/unreachable decoupling, passive expiry without interaction, anti-TTL-extension,
//     anti-resurrection from stale/older snapshots, no VERIFIED inference from available=true,
//     polling failure, valid probe recovery, and API URL/auth session switch isolation.
//   - F03: Full `architecture` normalization + related health boolean flags against valid true/false,
//     missing/null, truthy strings ("false"/"true"), numbers, arrays, null-prototype & broken-toPrimitive
//     objects ({toString:null, valueOf:null}), single-field and multi-field simultaneous corruption.
//   - F05: Fail-closed Stage 05 citation telemetry across LIVE & PLAYBACK: per-layer INVALID (PATH,
//     LINE, QUOTE, SHA-256) contradicting aggregate MATCHED, missing each required aggregate count,
//     null/missing/0/malformed values, complete ALL_MATCHED, MIXED, NO_FINDINGS, and PREVIEW separation.
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

test('F02 matrix: OpenGrep TTL expires passively under BOTH OK and DEGRADED (OLLAMA_UNREACHABLE), without extending TTL or resurrecting old snapshots', async () => {
  const fp = await bundleAndImport('services/findingPresentation.js');
  const hm = await bundleAndImport('services/healthMonitor.js');

  function makeClockAndTimers(startMs = 1795600000000) {
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
      fireNextActive() {
        const active = timers.find((t) => !t.cleared && !t.ran);
        assert(active, 'Expected an active scheduled timer');
        active.ran = true;
        active.fn();
        return active;
      },
    };
  }

  // 1. Both OK (Ollama reachable) and DEGRADED (OLLAMA_UNREACHABLE) with VERIFIED OpenGrep probe
  for (const overallStatus of ['OK', 'DEGRADED']) {
    const clock = makeClockAndTimers();
    const t0 = clock.now();
    const initialPayload = {
      status: overallStatus,
      degraded_reasons: overallStatus === 'DEGRADED' ? ['OLLAMA_UNREACHABLE'] : [],
      write_auth_configured: true,
      ollama: {reachable: overallStatus === 'OK', error: overallStatus === 'DEGRADED' ? 'connection refused' : null},
      opengrep: {
        available: true,
        runtime_verified: true,
        probe_status: 'VERIFIED',
        health_state: 'VERIFIED',
        probe_in_progress: false,
        version: '1.25.0',
        probed_at: new Date(t0).toISOString(),
        expires_at: new Date(t0 + 1800).toISOString(),
        ttl_seconds: 1.8,
      },
    };
    let nextPayload = initialPayload;
    let shouldFail = false;
    let scope = `http://127.0.0.1:19100|http://127.0.0.1:19100|${overallStatus}`;
    const emitted = [];

    const monitor = hm.createHealthMonitor({
      getScopeKey: () => scope,
      now: clock.now,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
      fetchHealth: async () => {
        if (shouldFail) throw new Error('network down');
        return nextPayload;
      },
      onStateChange: (snap) => emitted.push(snap),
    });

    // Before TTL: OpenGrep is VERIFIED, TTL timer MUST be armed regardless of OK vs DEGRADED
    await monitor.checkNow();
    const beforeExpiry = monitor.getSnapshot();
    const beforeView = fp.classifyBackendHealthState(beforeExpiry.backend, {nowMs: clock.now()});
    assert.equal(beforeExpiry.backend.status, overallStatus === 'OK' ? 'CONNECTED' : 'DEGRADED');
    assert.equal(beforeView.ogInfo.isVerified, true, `Before TTL OpenGrep must be VERIFIED under ${overallStatus}`);
    assert.equal(beforeView.ogInfo.healthState, 'VERIFIED');
    assert.equal(monitor.hasPendingTtlTimer(), true, `TTL timer MUST be scheduled under ${overallStatus}`);
    if (overallStatus === 'DEGRADED') {
      assert.deepEqual(beforeView.degradedReasons, ['OLLAMA_UNREACHABLE']);
      // Ollama failure must NOT misclassify OpenGrep as unavailable
      assert.notEqual(beforeView.ogInfo.code, 'OPENGREP_UNAVAILABLE');
    }

    // Just before deadline (t0 + 1799ms): still VERIFIED
    clock.advance(1799);
    const stillValidView = fp.classifyBackendHealthState(monitor.getSnapshot().backend, {nowMs: clock.now()});
    assert.equal(stillValidView.ogInfo.isVerified, true);

    // At deadline (t0 + 1800ms): passive timer fires with 0 user interaction & 0 extra requests
    clock.advance(1);
    clock.fireNextActive();
    const afterExpiry = monitor.getSnapshot();
    const afterView = fp.classifyBackendHealthState(afterExpiry.backend, {nowMs: clock.now()});
    assert.equal(afterExpiry.backend.status, 'DEGRADED');
    assert.equal(afterExpiry.backend.ttlExpired, true);
    assert.equal(afterExpiry.meta.ttlExpired, true);
    assert.equal(afterView.ogInfo.isVerified, false);
    assert.equal(afterView.ogInfo.healthState, 'EXPIRED');
    assert.equal(afterExpiry.backend.health.opengrep.runtime_verified, false);
    assert(!/VERIFIED/i.test(afterView.pillLabel), `Header must not show VERIFIED after expiry: ${afterView.pillLabel}`);
    assert(!/VERIFIED|đã xác minh/i.test(afterView.sidebarLabel), `Sidebar must not show VERIFIED after expiry: ${afterView.sidebarLabel}`);
    assert(!/VERIFIED|Đã xác minh/i.test(afterView.ogInfo.label), `StatusPage OpenGrep row must not show VERIFIED after expiry: ${afterView.ogInfo.label}`);
    assert(afterView.degradedReasons.includes('OPENGREP_PROBE_EXPIRED'));
    if (overallStatus === 'DEGRADED') {
      assert(afterView.degradedReasons.includes('OLLAMA_UNREACHABLE'), 'Original OLLAMA_UNREACHABLE reason must be preserved');
      assert.equal(afterExpiry.backend.health.ollama.reachable, false);
    }

    // Replay the exact same expired stamped snapshot -> MUST stay EXPIRED (no TTL extension)
    clock.advance(700);
    await monitor.checkNow({force: true});
    const afterReplay = monitor.getSnapshot();
    assert.equal(afterReplay.backend.ttlExpired, true);
    assert.equal(fp.classifyBackendHealthState(afterReplay.backend, {nowMs: clock.now()}).ogInfo.isVerified, false);
    assert.equal(monitor.hasPendingTtlTimer(), false);

    // Recovery with a brand-new valid probe snapshot -> transitions back to VERIFIED with fresh TTL timer
    const tFresh = clock.now();
    nextPayload = {
      ...initialPayload,
      opengrep: {
        ...initialPayload.opengrep,
        probed_at: new Date(tFresh).toISOString(),
        expires_at: new Date(tFresh + 2000).toISOString(),
        ttl_seconds: 2,
      },
    };
    await monitor.checkNow({force: true});
    const recovered = monitor.getSnapshot();
    assert.equal(recovered.backend.ttlExpired, false);
    assert.equal(fp.classifyBackendHealthState(recovered.backend, {nowMs: clock.now()}).ogInfo.isVerified, true);
    assert.equal(monitor.hasPendingTtlTimer(), true);

    // Older snapshot arriving while newer probe (tFresh) is STILL FRESH must preserve tFresh (never overwrite with EXPIRED),
    // and AFTER tFresh expires passively, the older snapshot (even with future expires_at) must NEVER resurrect VERIFIED.
    nextPayload = {
      ...initialPayload,
      opengrep: {
        ...initialPayload.opengrep,
        probed_at: new Date(t0).toISOString(),
        expires_at: new Date(tFresh + 99999).toISOString(),
        ttl_seconds: 99,
      },
    };
    await monitor.checkNow({force: true});
    const preservedFresh = monitor.getSnapshot();
    assert.equal(preservedFresh.backend.ttlExpired, false);
    assert.equal(preservedFresh.backend.opengrepVerified, true);
    assert.equal(preservedFresh.backend.expiresAtMs, recovered.backend.expiresAtMs);
    assert.equal(monitor.hasPendingTtlTimer(), true);

    clock.advance(2000);
    clock.fireNextActive();
    assert.equal(monitor.getSnapshot().backend.ttlExpired, true);
    await monitor.checkNow({force: true});
    const antiRes = monitor.getSnapshot();
    assert.equal(antiRes.backend.ttlExpired, true);
    assert.equal(fp.classifyBackendHealthState(antiRes.backend, {nowMs: clock.now()}).ogInfo.isVerified, false);

    // Polling error clears VERIFIED & TTL timer safely
    shouldFail = true;
    await monitor.checkNow({force: true});
    assert.equal(monitor.getSnapshot().backend.status, 'ERROR');
    assert.equal(monitor.hasPendingTtlTimer(), false);

    // Scope switch (API URL or auth token change) resets proof memory & cancels prior timers cleanly
    shouldFail = false;
    scope = `http://127.0.0.1:19200|http://127.0.0.1:19200|new-token-${overallStatus}`;
    const tNewScope = clock.now();
    nextPayload = {
      ...initialPayload,
      opengrep: {
        ...initialPayload.opengrep,
        probed_at: new Date(tNewScope).toISOString(),
        expires_at: new Date(tNewScope + 1500).toISOString(),
        ttl_seconds: 1.5,
      },
    };
    await monitor.checkNow({force: true});
    assert.equal(monitor.hasPendingTtlTimer(), true);
    monitor.dispose();
    assert.equal(monitor.hasPendingTtlTimer(), false);
  }

  // 2. Clock-skew replay guard: server clock ahead of client clock must NOT extend TTL on replay
  //    even when an intervening network error occurs between initial response and replay.
  const skewClock = makeClockAndTimers(1795600000000);
  const skewedProbedAt = new Date(skewClock.now() + 60000).toISOString();
  const skewedExpiresAt = new Date(skewClock.now() + 62000).toISOString();
  let skewFail = false;
  const skewMonitor = hm.createHealthMonitor({
    getScopeKey: () => 'skew-scope',
    now: skewClock.now,
    setTimer: skewClock.setTimer,
    clearTimer: skewClock.clearTimer,
    fetchHealth: async () => {
      if (skewFail) throw new Error('transient');
      return {
        status: 'DEGRADED',
        degraded_reasons: ['OLLAMA_UNREACHABLE'],
        opengrep: {
          available: true,
          runtime_verified: true,
          probe_status: 'VERIFIED',
          health_state: 'VERIFIED',
          probed_at: skewedProbedAt,
          expires_at: skewedExpiresAt,
          ttl_seconds: 2,
        },
      };
    },
  });
  await skewMonitor.checkNow();
  assert.equal(skewMonitor.hasPendingTtlTimer(), true);
  skewClock.advance(2500);
  skewClock.fireNextActive();
  assert.equal(skewMonitor.getSnapshot().backend.ttlExpired, true);
  // Intervening error
  skewFail = true;
  await skewMonitor.checkNow({force: true});
  assert.equal(skewMonitor.getSnapshot().backend.status, 'ERROR');
  // Replaying exact same skewed snapshot MUST stay EXPIRED (no TTL extension from new receive time)
  skewFail = false;
  await skewMonitor.checkNow({force: true});
  assert.equal(skewMonitor.getSnapshot().backend.ttlExpired, true);
  assert.equal(fp.classifyBackendHealthState(skewMonitor.getSnapshot().backend, {nowMs: skewClock.now()}).ogInfo.isVerified, false);
  skewMonitor.dispose();

  // 3. OpenGrep non-verified/pending/unavailable/malformed & available=true alone NEVER yield VERIFIED;
  //    Ollama unreachable with missing opengrep does NOT falsely declare OpenGrep unavailable.
  const ollamaOnlyDegraded = hm.classifyHealthResponse({
    status: 'DEGRADED',
    degraded_reasons: ['OLLAMA_UNREACHABLE'],
    ollama: {reachable: false, error: 'timeout'},
  });
  assert.equal(ollamaOnlyDegraded.status, 'DEGRADED');
  assert.equal(fp.describeOpengrepHealth(ollamaOnlyDegraded.health.opengrep).code, 'UNKNOWN');

  for (const og of [
    {available: true},
    {available: true, probe_status: 'NOT_VERIFIED', probe_in_progress: true},
    {available: false, probe_status: 'UNAVAILABLE', binary_present: false},
    {available: 'true', runtime_verified: true, probe_status: 'VERIFIED'},
    {available: true, runtime_verified: 'true', probe_status: 'VERIFIED'},
    {available: true, runtime_verified: true, probe_status: 'VERIFIED', ttl_seconds: -5},
    {available: true, runtime_verified: true, probe_status: 'VERIFIED', expires_at: 'not-a-date'},
    'not-an-object',
  ]) {
    const info = fp.describeOpengrepHealth(og);
    assert.equal(info.isVerified, false, `Must never infer VERIFIED for ${JSON.stringify(og)}`);
  }

  // 4. OK with non-opengrep schema warning STILL enforces OpenGrep TTL timer
  const warnClock = makeClockAndTimers();
  const tw = warnClock.now();
  const warnMonitor = hm.createHealthMonitor({
    getScopeKey: () => 'warn-scope',
    now: warnClock.now,
    setTimer: warnClock.setTimer,
    clearTimer: warnClock.clearTimer,
    fetchHealth: async () => ({
      status: 'OK',
      architecture: {static_engine: 'OpenGrep', cloud_llm_enabled: {toString: null, valueOf: null}},
      opengrep: {
        available: true,
        runtime_verified: true,
        probe_status: 'VERIFIED',
        health_state: 'VERIFIED',
        probed_at: new Date(tw).toISOString(),
        expires_at: new Date(tw + 1500).toISOString(),
        ttl_seconds: 1.5,
      },
    }),
  });
  await warnMonitor.checkNow();
  assert.equal(warnMonitor.getSnapshot().backend.status, 'DEGRADED');
  assert.equal(warnMonitor.hasPendingTtlTimer(), true, 'Schema warning on architecture must not disable OpenGrep TTL timer');
  warnClock.advance(1600);
  warnClock.fireNextActive();
  assert.equal(warnMonitor.getSnapshot().backend.ttlExpired, true);
  warnMonitor.dispose();
});

test('F03 matrix: architecture and health boolean normalization handles valid true/false, null/missing, string "false", numbers, arrays, and broken-toPrimitive objects without throwing', async () => {
  const prevWindow = global.window;
  const prevSession = global.sessionStorage;
  global.sessionStorage = mkStorage();
  global.window = {
    location: {origin: 'http://127.0.0.1:19400', hostname: '127.0.0.1'},
    sessionStorage: global.sessionStorage,
  };

  try {
    const fp = await bundleAndImport('services/findingPresentation.js');
    const hm = await bundleAndImport('services/healthMonitor.js');
    const statusPage = await bundleAndImport('pages/StatusPage.jsx');

    const hostileObj = {toString: null, valueOf: null};
    const nullProtoObj = Object.create(null);
    const throwingToPrim = {[Symbol.toPrimitive]() { throw new TypeError('hostile primitive'); }};

    // 1. Valid safe architecture preserves exact true/false and verifies safe policy
    const validHealth = {
      status: 'OK',
      auth_required: false,
      authenticated: false,
      write_auth_configured: true,
      git_available: true,
      ollama: {reachable: true, model_installed: true, requested_model: 'qwen3.5:9b'},
      rules: {available: true, name: 'java_cwe22_cwe89.yml', priority_cwes: ['CWE-22', 'CWE-89']},
      opengrep: {
        available: true,
        runtime_verified: true,
        probe_status: 'VERIFIED',
        health_state: 'VERIFIED',
        probed_at: new Date(Date.now()).toISOString(),
        expires_at: new Date(Date.now() + 300000).toISOString(),
        ttl_seconds: 300,
      },
      architecture: {
        static_engine: 'OpenGrep',
        llm_engine: 'Qwen3.5-9B via Local Ollama',
        priority_cwes: ['CWE-22', 'CWE-89'],
        cloud_llm_enabled: false,
        human_review_required: true,
        stale_source_guard_enabled: true,
      },
    };
    const validClassified = hm.classifyHealthResponse(validHealth);
    assert.equal(validClassified.status, 'CONNECTED');
    assert.equal(validClassified.schemaWarnings.length, 0);
    const validArch = fp.normalizeHealthArchitecture(validClassified.health.architecture);
    assert.equal(validArch.verifiedSafePolicy, true);
    assert.equal(validArch.fields.cloud_llm_enabled.value, false);
    assert.equal(validArch.fields.human_review_required.value, true);
    assert.equal(validArch.fields.stale_source_guard_enabled.value, true);
    const validRows = statusPage.buildHealthStatusRows(validClassified, null, null, {});
    const validArchRow = validRows.find((r) => r.name.includes('Chính sách kiến trúc'));
    assert.equal(validArchRow.value, 'Cloud LLM: false · Human Review: true · STALE_SOURCE Guard: true');
    assert.equal(validArchRow.tone, 'blue');

    // 2. Valid unsafe booleans preserved verbatim (not coerced) and flagged amber
    const unsafeArch = fp.normalizeHealthArchitecture({
      static_engine: 'OpenGrep',
      cloud_llm_enabled: true,
      human_review_required: false,
      stale_source_guard_enabled: false,
    });
    assert.equal(unsafeArch.verifiedSafePolicy, false);
    assert.equal(unsafeArch.hasUnsafePolicyValue, true);
    assert.equal(unsafeArch.fields.cloud_llm_enabled.value, true);
    assert.equal(unsafeArch.fields.human_review_required.value, false);
    assert.equal(unsafeArch.fields.stale_source_guard_enabled.value, false);

    // 3. Single-field malformed sweep across EVERY architecture field and EVERY hostile/wrong type
    const badValues = ['false', 'true', '', 0, 1, [], ['true'], {}, hostileObj, nullProtoObj, throwingToPrim];
    for (const field of ['cloud_llm_enabled', 'human_review_required', 'stale_source_guard_enabled']) {
      for (const badVal of badValues) {
        const raw = {
          status: 'OK',
          opengrep: {available: true},
          architecture: {
            static_engine: 'OpenGrep',
            cloud_llm_enabled: false,
            human_review_required: true,
            stale_source_guard_enabled: true,
            [field]: badVal,
          },
        };
        const classified = hm.classifyHealthResponse(raw);
        assert.equal(classified.status, 'DEGRADED');
        assert(classified.architectureInvalidFields.includes(field), `Expected ${field} invalid for ${typeof badVal}`);
        assert(classified.schemaWarnings.some((w) => w.includes(`architecture.${field}`)));
        // Neither Header/Sidebar view nor StatusPage rows may throw, and "false" must NEVER become true
        const view = fp.classifyBackendHealthState(classified);
        assert(view.schemaWarnings.length > 0);
        const rows = statusPage.buildHealthStatusRows(classified, null, null, {});
        const archRow = rows.find((r) => r.name.includes('Chính sách kiến trúc'));
        assert(archRow.value.includes('sai kiểu'), `Expected sai kiểu for ${field}=${typeof badVal}: got ${archRow.value}`);
        assert.equal(archRow.tone, 'amber');
        // Also verify direct unsanitized buildHealthStatusRows does NOT throw
        const rawRows = statusPage.buildHealthStatusRows({status: 'DEGRADED', health: raw}, null, null, {});
        assert(rawRows.find((r) => r.name.includes('Chính sách kiến trúc')).value.includes('sai kiểu'));
      }
    }

    // 4. Non-boolean architecture fields (static_engine, llm_engine, priority_cwes) malformed
    for (const badStr of [123, true, false, [], {}, hostileObj, '   ']) {
      const norm = fp.normalizeHealthArchitecture({
        static_engine: badStr,
        llm_engine: badStr,
        priority_cwes: badStr,
        cloud_llm_enabled: false,
        human_review_required: true,
        stale_source_guard_enabled: true,
      });
      assert.equal(norm.hasInvalidFields, true);
      assert.equal(norm.verifiedSafePolicy, false);
    }

    // 5. Multiple fields corrupted simultaneously + non-object architecture + truthy "false" on top-level/ollama/rules booleans
    const multiBadHealth = {
      status: 'OK',
      auth_required: 'false',
      authenticated: 'false',
      write_auth_configured: 'false',
      git_available: 'false',
      ollama: {reachable: 'false', model_installed: hostileObj, requested_model: 'qwen3.5:9b'},
      rules: {available: 'false', priority_cwes: 'CWE-89'},
      opengrep: {available: true},
      architecture: {
        static_engine: hostileObj,
        llm_engine: [],
        priority_cwes: {a: 1},
        cloud_llm_enabled: hostileObj,
        human_review_required: 'false',
        stale_source_guard_enabled: 1,
      },
    };
    const multiClassified = hm.classifyHealthResponse(multiBadHealth);
    assert.equal(multiClassified.status, 'DEGRADED');
    const multiView = fp.classifyBackendHealthState(multiClassified);
    assert.equal(multiView.authenticated, false, '"false" string must NEVER make authenticated=true');
    const multiRows = statusPage.buildHealthStatusRows(multiClassified, null, null, {});
    assert.equal(multiRows.find((r) => r.name.includes('Git CLI')).value, 'Dữ liệu trạng thái Git sai kiểu');
    assert.equal(multiRows.find((r) => r.name.includes('Ollama cục bộ')).value, 'Dữ liệu trạng thái Ollama sai kiểu');
    assert.equal(multiRows.find((r) => r.name.includes('Tập luật OpenGrep')).value, 'Dữ liệu trạng thái tập luật sai kiểu');
    assert.equal(
      multiRows.find((r) => r.name.includes('Chính sách kiến trúc')).value,
      'Cloud LLM: sai kiểu · Human Review: sai kiểu · STALE_SOURCE Guard: sai kiểu',
    );

    // 6. Missing / null / empty architecture never claims verified safe policy
    for (const missingArch of [undefined, null, {}, {static_engine: 'OpenGrep', cloud_llm_enabled: null}]) {
      const c = hm.classifyHealthResponse({status: 'OK', architecture: missingArch});
      const norm = fp.normalizeHealthArchitecture(c.health.architecture);
      assert.equal(norm.verifiedSafePolicy, false);
      const rows = statusPage.buildHealthStatusRows(c, null, null, {});
      const row = rows.find((r) => r.name.includes('Chính sách kiến trúc'));
      assert(!/API xác nhận/i.test(row.detail), `Missing architecture must not claim verified policy: ${row.detail}`);
    }

    // 7. Non-object architecture (array, string, number, boolean)
    for (const badContainer of ['OpenGrep', 42, true, []]) {
      const c = hm.classifyHealthResponse({status: 'OK', architecture: badContainer});
      assert.equal(c.architectureMalformed, true);
      const rows = statusPage.buildHealthStatusRows(c, null, null, {});
      assert.equal(rows.find((r) => r.name.includes('Chính sách kiến trúc')).value, 'Dữ liệu architecture sai định dạng');
    }
  } finally {
    global.window = prevWindow;
    global.sessionStorage = prevSession;
  }
});

test('F05 matrix: Stage 05 citation telemetry is fail-closed across LIVE and PLAYBACK for invalid layers, contradictions, partial aggregates, malformed data, and zero findings', async () => {
  const lsp = await bundleAndImport('components/scanner/liveStagePresentation.js');

  for (const mode of ['LIVE', 'PLAYBACK']) {
    const resolve = (summary, cat = 'COMPLETED') => lsp.resolveStage05CitationTelemetry({mode, stage: {cat, summary}});

    // 1. Every single layer (PATH, LINE, QUOTE, SHA-256) INVALID while overall_status reports MATCHED -> CONFLICT, never ALL_MATCHED
    for (const [layerKey, expectedBadgeKey] of [['path', 'path'], ['line', 'line'], ['quote', 'quote'], ['sha256', 'sha256'], ['sha-256', 'sha256']]) {
      const res = resolve({overall_status: 'MATCHED', citation_checks: {[layerKey]: 'INVALID'}});
      assert.equal(res.aggregateStatus, 'CONFLICT', `${mode} ${layerKey}=INVALID + overall=MATCHED must be CONFLICT`);
      assert.notEqual(res.aggregateStatus, 'ALL_MATCHED');
      assert.equal(res.checks.find((c) => c.key === expectedBadgeKey).status, 'INVALID');
      assert.equal(res.checks.find((c) => c.key === expectedBadgeKey).badgeText, 'INVALID ✕');
      // Missing sibling layers MUST stay NO_DATA, never AGGREGATE_MATCHED ("ĐÃ ĐỐI CHIẾU") or MATCH ✓
      for (const other of res.checks.filter((c) => c.key !== expectedBadgeKey)) {
        assert.equal(other.status, 'NO_DATA', `${mode} missing layer ${other.key} must stay NO_DATA, got ${other.status}`);
        assert.equal(other.badgeText, 'CHƯA CÓ DỮ LIỆU');
        assert.equal(other.isVerifiedMatch, false);
      }
    }

    // 2. Per-layer INVALID/NOT_VERIFIED contradicting complete matched counts -> CONFLICT
    const layerVsCounts = resolve({
      matched_count: 4,
      invalid_count: 0,
      not_verified_count: 0,
      total_checked: 4,
      citation_checks: {quote: 'INVALID'},
    });
    assert.equal(layerVsCounts.aggregateStatus, 'CONFLICT');
    assert.equal(layerVsCounts.checks.find((c) => c.key === 'quote').status, 'INVALID');
    assert.equal(layerVsCounts.checks.find((c) => c.key === 'path').status, 'NO_DATA');

    const notVerifiedVsCounts = resolve({
      matched_count: 4,
      invalid_count: 0,
      not_verified_count: 0,
      total_checked: 4,
      citation_checks: {sha256: 'NOT_VERIFIED'},
    });
    assert.equal(notVerifiedVsCounts.aggregateStatus, 'CONFLICT');

    // 3. Complete per-layer MATCHED contradicting INVALID/MIXED counts or INVALID overall -> CONFLICT
    const allLayersVsInvalidCount = resolve({
      checks: {path: 'MATCHED', line: 'MATCHED', quote: 'MATCHED', sha256: 'MATCHED'},
      matched_count: 2,
      invalid_count: 1,
      not_verified_count: 0,
      total_checked: 3,
    });
    assert.equal(allLayersVsInvalidCount.aggregateStatus, 'CONFLICT');

    const allCountsVsInvalidOverall = resolve({
      matched_count: 3,
      invalid_count: 0,
      not_verified_count: 0,
      total_checked: 3,
      overall_status: 'INVALID',
    });
    assert.equal(allCountsVsInvalidOverall.aggregateStatus, 'CONFLICT');

    // 4. Arithmetic count contradictions -> CONFLICT
    for (const badMath of [
      {matched_count: 4, invalid_count: 1, not_verified_count: 0, total_checked: 4},
      {matched_count: 1, invalid_count: 0, not_verified_count: 0, total_checked: 3},
      {matched_count: 1, invalid_count: 0, not_verified_count: 0, total_checked: 0},
      {matched_count: 2, citations_matched: 1, invalid_count: 0, not_verified_count: 0, total_checked: 2},
    ]) {
      const res = resolve(badMath);
      assert.equal(res.aggregateStatus, 'CONFLICT', `${mode} badMath ${JSON.stringify(badMath)} must be CONFLICT`);
    }

    // 5. Missing EACH required aggregate field one-by-one MUST NOT default to 0 or ALL_MATCHED
    for (const partial of [
      {matched_count: 1, invalid_count: 0},
      {matched_count: 3, invalid_count: 0, total_checked: 3},
      {matched_count: 3, not_verified_count: 0, total_checked: 3},
      {matched_count: 3, invalid_count: 0, not_verified_count: 0},
      {invalid_count: 0, not_verified_count: 0, total_checked: 3},
      {matched_count: 3},
      {overall_status: 'MATCHED'},
      {overall_status: 'MATCHED', citation_checks: {path: 'MATCHED'}},
      {citation_checks: {path: 'MATCHED', line: 'MATCHED'}},
    ]) {
      const res = resolve(partial);
      assert.equal(res.aggregateStatus, 'PARTIAL', `${mode} partial ${JSON.stringify(partial)} must be PARTIAL, got ${res.aggregateStatus}`);
      assert.notEqual(res.aggregateStatus, 'ALL_MATCHED');
      assert(res.checks.every((c) => c.status !== 'AGGREGATE_MATCHED'));
    }

    // 6. Null, missing, empty, validator_status-only -> NO_DATA (or CHECKING when RUNNING)
    for (const empty of [null, undefined, {}, {validator_status: 'OK'}, {checks: {}}, {matched_count: null, invalid_count: null, total_checked: null}]) {
      const done = resolve(empty, 'COMPLETED');
      assert.equal(done.aggregateStatus, 'NO_DATA');
      assert.equal(done.hasBackendEvidence, false);
      assert(done.checks.every((c) => !c.isVerifiedMatch));

      const running = resolve(empty, 'RUNNING');
      assert.equal(running.aggregateStatus, 'CHECKING');
      assert.equal(running.hasBackendEvidence, false);
    }

    // 7. Malformed values never become 0 or ALL_MATCHED
    for (const malformed of [
      {matched_count: '3', invalid_count: '0', not_verified_count: '0', total_checked: '3'},
      {matched_count: 3, invalid_count: -1, not_verified_count: 0, total_checked: 3},
      {matched_count: 3, invalid_count: {}, not_verified_count: 0, total_checked: 3},
      {checks: 'MATCHED'},
      {checks: {path: 'MATCHED', line: 'MATCHED', quote: 'MATCHED', sha256: 'BOGUS'}},
      {overall_status: 'UNKNOWN_FUTURE_CODE'},
    ]) {
      const res = resolve(malformed);
      assert.notEqual(res.aggregateStatus, 'ALL_MATCHED', `${mode} malformed ${JSON.stringify(malformed)} must never be ALL_MATCHED`);
      assert(['MALFORMED', 'CONFLICT'].includes(res.aggregateStatus), `Got ${res.aggregateStatus} for ${JSON.stringify(malformed)}`);
    }

    // 8. Zero findings / citations -> NO_FINDINGS (NOT ALL_MATCHED!)
    const zeroFindings = resolve({matched_count: 0, invalid_count: 0, not_verified_count: 0, total_checked: 0});
    assert.equal(zeroFindings.aggregateStatus, 'NO_FINDINGS');
    assert.notEqual(zeroFindings.aggregateStatus, 'ALL_MATCHED');
    assert(zeroFindings.checks.every((c) => c.status === 'NO_DATA' && !c.isVerifiedMatch));

    // 9. Mixed results -> MIXED
    const mixed = resolve({matched_count: 2, invalid_count: 1, total_checked: 3});
    assert.equal(mixed.aggregateStatus, 'MIXED');
    assert(mixed.checks.every((c) => !c.isVerifiedMatch));

    // 10. All valid & complete -> ALL_MATCHED
    const completeCounts = resolve({matched_count: 8, invalid_count: 0, not_verified_count: 0, total_checked: 8});
    assert.equal(completeCounts.aggregateStatus, 'ALL_MATCHED');
    assert.equal(completeCounts.counts.isComplete, true);
    assert(completeCounts.checks.every((c) => c.status === 'AGGREGATE_MATCHED' && !c.isVerifiedMatch));

    const completePerLayer = resolve({
      checks: {path: 'MATCHED', line: 'MATCHED', quote: 'MATCHED', sha256: 'MATCHED'},
    });
    assert.equal(completePerLayer.aggregateStatus, 'ALL_MATCHED');
    assert(completePerLayer.checks.every((c) => c.status === 'MATCHED' && c.badgeText === 'MATCH ✓' && c.isVerifiedMatch));

    const completeBoth = resolve({
      matched_count: 8,
      invalid_count: 0,
      not_verified_count: 0,
      total_checked: 8,
      overall_status: 'MATCHED',
      citation_checks: {path: 'MATCHED', line: 'MATCHED', quote: 'MATCHED', sha256: 'MATCHED'},
    });
    assert.equal(completeBoth.aggregateStatus, 'ALL_MATCHED');
    assert(completeBoth.checks.every((c) => c.isVerifiedMatch));
  }

  // 11. PREVIEW stays clearly illustrative and never emits verified MATCH ✓
  const preview = lsp.resolveStage05CitationTelemetry({
    mode: 'PREVIEW',
    stage: {cat: 'COMPLETED', summary: {checks: {path: 'MATCHED', line: 'MATCHED', quote: 'MATCHED', sha256: 'MATCHED'}}},
  });
  assert.equal(preview.isIllustrative, true);
  assert.equal(preview.aggregateStatus, 'PREVIEW');
  assert(preview.checks.every((c) => !c.isVerifiedMatch && c.badgeText === 'MINH HỌA'));
});
