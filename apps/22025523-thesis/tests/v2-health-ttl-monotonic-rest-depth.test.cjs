const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {pathToFileURL} = require('node:url');
const {registerHooks} = require('node:module');

registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (err) {
      if ((specifier.startsWith('./') || specifier.startsWith('../')) && !path.extname(specifier)) {
        return nextResolve(`${specifier}.js`, context);
      }
      throw err;
    }
  },
});

const SRC_ROOT = path.resolve(__dirname, '..', 'src');

function loadModule(relPath) {
  return import(pathToFileURL(path.join(SRC_ROOT, relPath)).href);
}

// Deterministic dual-clock + real executing timer scheduler:
// - wallNow can step forward or backward independently (NTP / OS clock step).
// - monoNow advances strictly monotonically with elapsed time.
// - setTimer stores exact monotonic due timestamps, executes callbacks when due,
//   and records full set/clear/fire history (never a no-op ID stub).
function createDualClockScheduler(initialWallMs, initialMonoMs = 1000) {
  let wallMs = initialWallMs;
  let monoMs = initialMonoMs;
  let nextId = 1;
  const activeTimers = new Map();
  const allTimers = new Map();
  const history = [];

  return {
    wallNow: () => wallMs,
    monoNow: () => monoMs,
    elapsed: () => monoMs - initialMonoMs,
    shiftWall: (deltaMs) => { wallMs += deltaMs; },
    setWall: (ms) => { wallMs = ms; },
    setTimer: (fn, delayMs) => {
      const id = nextId++;
      const dueMono = monoMs + Math.max(0, Number(delayMs) || 0);
      const entry = {id, fn, delayMs, dueMono, cancelled: false, fired: false};
      activeTimers.set(id, entry);
      allTimers.set(id, entry);
      history.push({op: 'set', id, delayMs, atElapsed: monoMs - initialMonoMs, dueElapsed: dueMono - initialMonoMs});
      return id;
    },
    clearTimer: (id) => {
      const entry = activeTimers.get(id);
      if (entry) {
        entry.cancelled = true;
        activeTimers.delete(id);
        history.push({op: 'clear', id, atElapsed: monoMs - initialMonoMs});
      }
    },
    advanceElapsed: (ms) => {
      const targetMono = monoMs + ms;
      while (true) {
        let next = null;
        for (const t of activeTimers.values()) {
          if (t.dueMono <= targetMono && (!next || t.dueMono < next.dueMono || (t.dueMono === next.dueMono && t.id < next.id))) {
            next = t;
          }
        }
        if (!next) break;
        const step = next.dueMono - monoMs;
        monoMs = next.dueMono;
        wallMs += step;
        activeTimers.delete(next.id);
        next.fired = true;
        history.push({op: 'fire', id: next.id, atElapsed: monoMs - initialMonoMs});
        next.fn();
      }
      const rem = targetMono - monoMs;
      if (rem > 0) {
        monoMs += rem;
        wallMs += rem;
      }
    },
    invokeRecordedCallback: (id) => {
      const entry = allTimers.get(id);
      if (entry) entry.fn();
    },
    activeTimerIds: () => [...activeTimers.keys()],
    activeTimers: () => [...activeTimers.values()].map((t) => ({id: t.id, delayMs: t.delayMs, dueElapsed: t.dueMono - initialMonoMs})),
    history: () => [...history],
  };
}

function createMemoryStorage({throwOnGet = false, throwOnSet = false} = {}) {
  const store = new Map();
  return {
    getItem(key) {
      if (throwOnGet) throw new Error('STORAGE_READ_BLOCKED');
      return store.has(key) ? store.get(key) : null;
    },
    setItem(key, val) {
      if (throwOnSet) throw new Error('STORAGE_WRITE_BLOCKED');
      store.set(String(key), String(val));
    },
    removeItem(key) {
      if (throwOnSet) throw new Error('STORAGE_REMOVE_BLOCKED');
      store.delete(String(key));
    },
    dump: () => Object.fromEntries(store.entries()),
  };
}

function makeProbe(baseMs, {
  status = 'OK',
  ttlSec = 20,
  expiresOffsetMs = 20000,
  checkedOffsetMs = 0,
  probedOffsetMs = 0,
  includeCheckedAt = true,
  includeProbedAt = true,
  exec = 'a'.repeat(64),
  proc = 'proc-mono-1',
  bin = '1'.repeat(64),
  rules = '2'.repeat(64),
  ogPatch = {},
} = {}) {
  const og = {
    available: true,
    runtime_verified: true,
    probe_status: 'VERIFIED',
    health_state: 'VERIFIED',
    verification_level: 'SCAN_VERIFIED',
    ...(proc !== null && proc !== undefined ? {process_instance_id: proc} : {}),
    ...(exec !== null && exec !== undefined ? {probe_execution_identity_sha256: exec} : {}),
    ...(bin !== null && bin !== undefined ? {binary_identity_sha256: bin} : {}),
    ...(rules !== null && rules !== undefined ? {rules_sha256: rules} : {}),
    ...(includeProbedAt ? {probed_at: new Date(baseMs + probedOffsetMs).toISOString()} : {}),
    expires_at: new Date(baseMs + expiresOffsetMs).toISOString(),
    ttl_seconds: ttlSec,
    ...ogPatch,
  };
  return {
    status,
    ...(includeCheckedAt ? {checked_at: new Date(baseMs + checkedOffsetMs).toISOString()} : {}),
    opengrep: og,
  };
}

function assertAllThreeHealthSurfaces(fp, backend, nowMs, {verified, expired}) {
  const view = fp.classifyBackendHealthState(backend, {nowMs});
  const statusOg = fp.describeOpengrepHealth(backend.health?.opengrep || {}, null, {
    nowMs,
    snapshotReceivedAtMs: backend.receivedAtMs ?? null,
    expiresAtMs: backend.expiresAtMs ?? null,
    serverCheckedAtMs: backend.serverCheckedAtMs ?? null,
    forceExpired: Boolean(backend.ttlExpired),
  });
  assert.equal(Boolean(backend.opengrepVerified), verified);
  assert.equal(Boolean(backend.ttlExpired), expired);
  assert.equal(Boolean(view.ogInfo?.isVerified), verified);
  assert.equal(Boolean(statusOg.isVerified), verified);
  if (verified) {
    assert.match(view.pillLabel, /OPENGREP VERIFIED/i);
    assert.match(view.sidebarLabel, /OpenGrep đã xác minh/i);
    assert.equal(statusOg.healthState, 'VERIFIED');
  } else if (expired) {
    assert.match(view.pillLabel, /EXPIRED/i);
    assert.match(view.sidebarLabel, /EXPIRED/i);
    assert.equal(statusOg.healthState, 'EXPIRED');
  } else {
    assert.doesNotMatch(view.pillLabel, /OPENGREP VERIFIED/i);
    assert.doesNotMatch(view.sidebarLabel, /OpenGrep đã xác minh/i);
    assert.notEqual(statusOg.healthState, 'VERIFIED');
  }
}

function buildNestedJson(levels, leafInner) {
  let s = leafInner;
  for (let i = levels; i >= 1; i -= 1) s = `{"l${i}":${s}}`;
  return s;
}

function drillNested(obj, levels) {
  let cur = obj;
  for (let i = 1; i <= levels; i += 1) {
    if (!cur || typeof cur !== 'object') return null;
    cur = cur[`l${i}`];
  }
  return cur;
}

test('P1-HEALTH-TTL-ROLLBACK: monotonic TTL invariant across same-probe replay, rollback, tightening, extension, repeated rollback, and clock jumps', async () => {
  const hm = await loadModule('services/healthMonitor.js');
  const fp = await loadModule('services/findingPresentation.js');
  const T0 = Date.parse('2026-11-26T00:00:00.000Z');

  // 1. Exact replay after -5s wall rollback at t=10s -> keeps timer #1, expires at exact 20,000ms (NOT 25,000ms)
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    let payload = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000});
    let expiredAt = null;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => 'mono-case-1',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
      onStateChange: (s) => {
        if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
      },
    });
    await mon.checkNow({force: true});
    assert.deepEqual(clk.activeTimerIds(), [1]);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});

    clk.advanceElapsed(10000);
    clk.shiftWall(-5000);
    await mon.checkNow({force: true});
    assert.deepEqual(clk.activeTimerIds(), [1], 'Same probe replay must keep original timer handle untouched');
    assert.equal(clk.activeTimers()[0].dueElapsed, 20000);

    clk.advanceElapsed(9999);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
    clk.advanceElapsed(1); // elapsed = 20,000ms while wall is still T0+15,000ms
    assert.equal(expiredAt, 20000, 'Must expire at exact 20,000ms elapsed, not 25,000ms');
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
    assert.deepEqual(clk.activeTimerIds(), []);

    // Fresh distinct probe B recovers VERIFIED with full new 20s TTL
    payload = makeProbe(T0 + 21000, {ttlSec: 20, expiresOffsetMs: 20000, exec: 'b'.repeat(64)});
    clk.advanceElapsed(1000);
    await mon.checkNow({force: true});
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
    assert.equal(clk.activeTimers().length, 1);
    assert.equal(clk.activeTimers()[0].delayMs, 20000);
    mon.dispose();
  }

  // 2. Shortened deadline by 1s after -5s rollback -> tightens monotonic deadline to 19,000ms (NOT 24,000ms)
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    let payload = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000});
    let expiredAt = null;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => 'mono-case-2',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
      onStateChange: (s) => {
        if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
      },
    });
    await mon.checkNow({force: true});
    clk.advanceElapsed(10000);
    clk.shiftWall(-5000);
    payload = makeProbe(T0, {ttlSec: 19, expiresOffsetMs: 19000});
    await mon.checkNow({force: true});
    assert.equal(clk.activeTimers().length, 1);
    assert.equal(clk.activeTimers()[0].dueElapsed, 19000);
    clk.advanceElapsed(8999);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
    clk.advanceElapsed(1);
    assert.equal(expiredAt, 19000, 'Tightened deadline after rollback must expire at 19,000ms, never 24,000ms');
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
    mon.dispose();
  }

  // 3. Same probe with extended deadline/TTL + repeated consecutive rollbacks -> never extends beyond 20,000ms
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    let payload = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000});
    let expiredAt = null;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => 'mono-case-3',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
      onStateChange: (s) => {
        if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
      },
    });
    await mon.checkNow({force: true});
    for (const stepMs of [5000, 5000, 5000]) {
      clk.advanceElapsed(stepMs);
      clk.shiftWall(-5000);
      payload = makeProbe(T0, {ttlSec: 60, expiresOffsetMs: 60000});
      await mon.checkNow({force: true});
      assert.deepEqual(clk.activeTimerIds(), [1], 'Repeated rollback + extended TTL must keep timer #1 untouched');
      assert.equal(clk.activeTimers()[0].dueElapsed, 20000);
    }
    clk.advanceElapsed(5000); // elapsed = 20,000ms
    assert.equal(expiredAt, 20000);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
    mon.dispose();
  }

  // 4. Clock fast-forward (+15s at t=2s) then rollback (-10s at t=4s) -> stays tightened at elapsed 5s, never rebounds
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    const payload = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000});
    let expiredAt = null;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => 'mono-case-4',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
      onStateChange: (s) => {
        if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
      },
    });
    await mon.checkNow({force: true});
    clk.advanceElapsed(2000);
    clk.shiftWall(15000); // wall = T0+17s, only 3s remaining -> tightens mono deadline to elapsed 5s
    await mon.checkNow({force: true});
    assert.equal(clk.activeTimers()[0].dueElapsed, 5000);
    clk.advanceElapsed(2000); // elapsed = 4s
    clk.shiftWall(-10000); // wall = T0+9s
    await mon.checkNow({force: true});
    assert.equal(clk.activeTimers()[0].dueElapsed, 5000, 'Rollback after forward jump must not rebound tightened TTL');
    clk.advanceElapsed(1000); // elapsed = 5s
    assert.equal(expiredAt, 5000);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
    mon.dispose();
  }

  // 5. Codex positive controls: rollback without refresh, rollback with current server checked_at, stable clock replay
  for (const mode of ['no-refresh', 'current-checked-at', 'stable-clock']) {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    let payload = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0});
    let expiredAt = null;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => `mono-ctrl-${mode}`,
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
      onStateChange: (s) => {
        if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
      },
    });
    await mon.checkNow({force: true});
    clk.advanceElapsed(10000);
    if (mode !== 'stable-clock') clk.shiftWall(-5000);
    if (mode === 'current-checked-at') {
      payload = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 10000});
      await mon.checkNow({force: true});
    } else if (mode === 'stable-clock') {
      await mon.checkNow({force: true});
    }
    clk.advanceElapsed(10000);
    assert.equal(expiredAt, 20000, `Control ${mode} must expire at exact 20,000ms`);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
    mon.dispose();
  }
});

test('P1-HEALTH-TTL-ROLLBACK lifecycle: in-flight expiry, stale callback isolation, older probe protection, reload + rollback, storage blocked, cancel/dispose/scope switch', async () => {
  const hm = await loadModule('services/healthMonitor.js');
  const fp = await loadModule('services/findingPresentation.js');
  const T0 = Date.parse('2026-11-26T00:00:00.000Z');

  // 1. TTL expires while refresh is in-flight -> immediately marks expired tombstone; late replay stays EXPIRED
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    let resolvePending = null;
    let callNum = 0;
    const probeA = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000});
    const mon = hm.createHealthMonitor({
      fetchHealth: () => {
        callNum += 1;
        if (callNum === 1) return Promise.resolve(structuredClone(probeA));
        return new Promise((resolve) => { resolvePending = resolve; });
      },
      getScopeKey: () => 'inflight-exp',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
    });
    await mon.checkNow({force: true});
    clk.advanceElapsed(19000);
    clk.shiftWall(-5000);
    const pendingPromise = mon.checkNow({force: true, preserveStatus: false});
    assert.equal(mon.getSnapshot().backend.status, 'CHECKING');
    clk.advanceElapsed(1000); // elapsed = 20,000ms while request is STILL pending!
    assert.equal(mon.getSnapshot().backend.ttlExpired, true, 'In-flight refresh must not mask TTL expiry');
    assert.equal(mon.getSnapshot().backend.opengrepVerified, false);
    resolvePending(structuredClone(probeA));
    await pendingPromise;
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
    mon.dispose();
  }

  // 2. Stale callback from old probe A invoked AFTER probe B accepted + older probe A poll never cancels B's timer
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    const probeA = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000, exec: 'a'.repeat(64)});
    const probeB = makeProbe(T0 + 5000, {ttlSec: 20, expiresOffsetMs: 20000, exec: 'b'.repeat(64)});
    let currentPayload = probeA;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(currentPayload),
      getScopeKey: () => 'stale-cb-and-old-poll',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
    });
    await mon.checkNow({force: true});
    const timerAId = clk.activeTimerIds()[0];
    clk.advanceElapsed(5000);
    currentPayload = probeB;
    await mon.checkNow({force: true});
    const timerBId = clk.activeTimerIds()[0];
    assert.notEqual(timerBId, timerAId);
    // Simulate a late/stale callback from timerA firing after probeB was accepted
    clk.invokeRecordedCallback(timerAId);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
    assert.deepEqual(clk.activeTimerIds(), [timerBId]);
    // Older probeA poll arrives while B is active -> must keep B's exact timer untouched
    currentPayload = probeA;
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
    assert.deepEqual(clk.activeTimerIds(), [timerBId]);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
    mon.dispose();
  }

  // 3. Normal reload BEFORE expiry (no rollback) preserves remaining TTL; normal reload AFTER expiry stays EXPIRED
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    const probeA = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000});
    const mk = () => hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(probeA),
      getScopeKey: () => 'normal-reload',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
    });
    let mon = mk();
    await mon.checkNow({force: true});
    clk.advanceElapsed(8000);
    mon.dispose(); // normal reload at t=8s with no rollback

    // New document with reset monotonic clock (starts at 0)
    const clk2 = createDualClockScheduler(clk.wallNow(), 0);
    mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(probeA),
      getScopeKey: () => 'normal-reload',
      storage,
      now: clk2.wallNow,
      monotonicNow: clk2.monoNow,
      setTimer: clk2.setTimer,
      clearTimer: clk2.clearTimer,
      retryDelaysMs: [],
    });
    await mon.checkNow({force: true});
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk2.wallNow(), {verified: true, expired: false});
    assert.equal(clk2.activeTimers()[0].delayMs, 12000, 'Normal reload before expiry retains exact 12s remaining');
    clk2.advanceElapsed(12000);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk2.wallNow(), {verified: false, expired: true});
    mon.dispose();

    // Reload after expiry -> stays EXPIRED
    const clk3 = createDualClockScheduler(clk2.wallNow() + 1000, 0);
    mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(probeA),
      getScopeKey: () => 'normal-reload',
      storage,
      now: clk3.wallNow,
      monotonicNow: clk3.monoNow,
      setTimer: clk3.setTimer,
      clearTimer: clk3.clearTimer,
      retryDelaysMs: [],
    });
    await mon.checkNow({force: true});
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk3.wallNow(), {verified: false, expired: true});
    mon.dispose();
  }

  // 4. Reload combined with clock rollback -> fails closed conservatively on stale replay, recovers on fresh probe B
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    const probeA = makeProbe(T0, {ttlSec: 20, expiresOffsetMs: 20000, exec: 'a'.repeat(64)});
    const mon1 = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(probeA),
      getScopeKey: () => 'rollback-reload',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
    });
    await mon1.checkNow({force: true});
    clk.advanceElapsed(8000);
    clk.shiftWall(-5000); // rollback before reload
    mon1.dispose();

    // New document after reload with fresh monotonic origin
    const clk2 = createDualClockScheduler(clk.wallNow(), 0);
    let payload = probeA;
    const mon2 = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => 'rollback-reload',
      storage,
      now: clk2.wallNow,
      monotonicNow: clk2.monoNow,
      setTimer: clk2.setTimer,
      clearTimer: clk2.clearTimer,
      retryDelaysMs: [],
    });
    await mon2.checkNow({force: true});
    assertAllThreeHealthSurfaces(fp, mon2.getSnapshot().backend, clk2.wallNow(), {verified: false, expired: true});
    // Fresh distinct probe B recovers VERIFIED
    payload = makeProbe(clk2.wallNow(), {ttlSec: 20, expiresOffsetMs: 20000, exec: 'b'.repeat(64)});
    await mon2.checkNow({force: true});
    assertAllThreeHealthSurfaces(fp, mon2.getSnapshot().backend, clk2.wallNow(), {verified: true, expired: false});
    assert.equal(clk2.activeTimers()[0].delayMs, 20000);
    mon2.dispose();
  }

  // 5. Storage blocked/throwing + cancel/scope switch/request error clear timers cleanly
  {
    const clk = createDualClockScheduler(T0);
    let scope = 'url-a|origin-a|sess-1';
    let failNext = false;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => {
        if (failNext) throw Object.assign(new Error('HTTP 401'), {status: 401});
        return makeProbe(clk.wallNow(), {ttlSec: 20, expiresOffsetMs: 20000});
      },
      getScopeKey: () => scope,
      storage: createMemoryStorage({throwOnGet: true, throwOnSet: true}),
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
    });
    await mon.checkNow({force: true});
    assert.equal(clk.activeTimerIds().length, 1);
    failNext = true;
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().backend.status, 'AUTH_REQUIRED');
    assert.deepEqual(clk.activeTimerIds(), [], 'Auth/network error must clear active TTL timer');
    failNext = false;
    await mon.checkNow({force: true});
    assert.equal(clk.activeTimerIds().length, 1);
    scope = 'url-b|origin-b|sess-2';
    await mon.checkNow({force: true});
    assert.equal(clk.activeTimerIds().length, 1);
    mon.cancel();
    assert.deepEqual(clk.activeTimerIds(), [], 'cancel() must clear active TTL timer');
    assert.doesNotThrow(() => mon.dispose());
  }
});

test('Probe execution identity vs deadline ordering matrix (includeProbedAt=true/false, stable & rollback, tighten/multi-tighten/extend/server-EXPIRED/reload/older-other-probe/weak-identity)', async () => {
  const hm = await loadModule('services/healthMonitor.js');
  const fp = await loadModule('services/findingPresentation.js');
  const T0 = Date.parse('2026-11-26T00:00:00.000Z');

  for (const includeProbedAt of [true, false]) {
    const modeTag = includeProbedAt ? 'with-probed-at' : 'without-probed-at';

    // 1. Exact replay, single tightening, repeated tightening, extension attempt (both stable clock and -5s rollback)
    for (const rollbackMs of [0, 5000]) {
      const clkTag = `${modeTag}-rb${rollbackMs}`;

      // 1a. Exact replay keeps timer #1 untouched and expires at 20,000ms
      {
        const clk = createDualClockScheduler(T0);
        const storage = createMemoryStorage();
        let payload = makeProbe(T0, {includeProbedAt, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0});
        let expiredAt = null;
        const mon = hm.createHealthMonitor({
          fetchHealth: async () => structuredClone(payload),
          getScopeKey: () => `matrix-replay-${clkTag}`,
          storage,
          now: clk.wallNow,
          monotonicNow: clk.monoNow,
          setTimer: clk.setTimer,
          clearTimer: clk.clearTimer,
          retryDelaysMs: [],
          onStateChange: (s) => {
            if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
          },
        });
        await mon.checkNow({force: true});
        assert.deepEqual(clk.activeTimerIds(), [1]);
        clk.advanceElapsed(10000);
        if (rollbackMs) clk.shiftWall(-rollbackMs);
        payload = makeProbe(T0, {includeProbedAt, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 10000});
        await mon.checkNow({force: true});
        assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, false, `${clkTag}: replay not misclassified as stale`);
        assert.deepEqual(clk.activeTimerIds(), [1], `${clkTag}: exact replay keeps timer #1`);
        assert.equal(clk.activeTimers()[0].dueElapsed, 20000);
        clk.advanceElapsed(9999);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
        clk.advanceElapsed(1);
        assert.equal(expiredAt, 20000, `${clkTag}: exact replay expires at 20,000ms`);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
        mon.dispose();
      }

      // 1b. Single tightening (20s -> 19s) — covers ChatGPT CE1 (rollback) and CE2 (no rollback)
      {
        const clk = createDualClockScheduler(T0);
        const storage = createMemoryStorage();
        let payload = makeProbe(T0, {includeProbedAt, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0});
        let expiredAt = null;
        const mon = hm.createHealthMonitor({
          fetchHealth: async () => structuredClone(payload),
          getScopeKey: () => `matrix-tighten-${clkTag}`,
          storage,
          now: clk.wallNow,
          monotonicNow: clk.monoNow,
          setTimer: clk.setTimer,
          clearTimer: clk.clearTimer,
          retryDelaysMs: [],
          onStateChange: (s) => {
            if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
          },
        });
        await mon.checkNow({force: true});
        assert.deepEqual(clk.activeTimerIds(), [1]);
        clk.advanceElapsed(10000);
        if (rollbackMs) clk.shiftWall(-rollbackMs);
        payload = makeProbe(T0, {includeProbedAt, ttlSec: 19, expiresOffsetMs: 19000, checkedOffsetMs: 10000});
        await mon.checkNow({force: true});
        assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, false, `${clkTag}: tightened deadline must not be ignored as OLDER`);
        assert.deepEqual(clk.activeTimerIds(), [2], `${clkTag}: tightened deadline replaces timer #1 with timer #2`);
        assert.equal(clk.activeTimers()[0].dueElapsed, 19000);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
        clk.advanceElapsed(8999);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
        clk.advanceElapsed(1);
        assert.equal(expiredAt, 19000, `${clkTag}: tightened deadline must expire at exact 19,000ms`);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
        assert.deepEqual(clk.activeTimerIds(), []);
        mon.dispose();
      }

      // 1c. Multiple tightenings (20s -> 19s -> 17s) followed by extension attempt (60s) -> stays clamped at 17,000ms
      {
        const clk = createDualClockScheduler(T0);
        const storage = createMemoryStorage();
        let payload = makeProbe(T0, {includeProbedAt, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0});
        let expiredAt = null;
        const mon = hm.createHealthMonitor({
          fetchHealth: async () => structuredClone(payload),
          getScopeKey: () => `matrix-multitighten-${clkTag}`,
          storage,
          now: clk.wallNow,
          monotonicNow: clk.monoNow,
          setTimer: clk.setTimer,
          clearTimer: clk.clearTimer,
          retryDelaysMs: [],
          onStateChange: (s) => {
            if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
          },
        });
        await mon.checkNow({force: true});
        clk.advanceElapsed(10000);
        if (rollbackMs) clk.shiftWall(-rollbackMs);
        payload = makeProbe(T0, {includeProbedAt, ttlSec: 19, expiresOffsetMs: 19000, checkedOffsetMs: 10000});
        await mon.checkNow({force: true});
        assert.deepEqual(clk.activeTimerIds(), [2]);
        assert.equal(clk.activeTimers()[0].dueElapsed, 19000);

        clk.advanceElapsed(2000); // elapsed = 12,000ms
        payload = makeProbe(T0, {includeProbedAt, ttlSec: 17, expiresOffsetMs: 17000, checkedOffsetMs: 12000});
        await mon.checkNow({force: true});
        assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, false);
        assert.deepEqual(clk.activeTimerIds(), [3]);
        assert.equal(clk.activeTimers()[0].dueElapsed, 17000);

        // Extension attempt to 60s MUST NOT extend or replace timer #3
        clk.advanceElapsed(1000); // elapsed = 13,000ms
        payload = makeProbe(T0, {includeProbedAt, ttlSec: 60, expiresOffsetMs: 60000, checkedOffsetMs: 13000});
        await mon.checkNow({force: true});
        assert.deepEqual(clk.activeTimerIds(), [3], `${clkTag}: extension attempt keeps timer #3 untouched`);
        assert.equal(clk.activeTimers()[0].dueElapsed, 17000);

        clk.advanceElapsed(4000); // elapsed = 17,000ms
        assert.equal(expiredAt, 17000, `${clkTag}: multi-tightened probe expires at 17,000ms`);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
        mon.dispose();
      }

      // 1d. Server reports DEGRADED + EXPIRED at 19s (covers ChatGPT CE3) -> EXPIRED immediately, tombstone blocks replay, fresh probe B recovers
      {
        const clk = createDualClockScheduler(T0);
        const storage = createMemoryStorage();
        let payload = makeProbe(T0, {includeProbedAt, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0});
        let expiredAt = null;
        const mon = hm.createHealthMonitor({
          fetchHealth: async () => structuredClone(payload),
          getScopeKey: () => `matrix-server-expired-${clkTag}`,
          storage,
          now: clk.wallNow,
          monotonicNow: clk.monoNow,
          setTimer: clk.setTimer,
          clearTimer: clk.clearTimer,
          retryDelaysMs: [],
          onStateChange: (s) => {
            if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
          },
        });
        await mon.checkNow({force: true});
        assert.deepEqual(clk.activeTimerIds(), [1]);
        clk.advanceElapsed(19000);
        if (rollbackMs) clk.shiftWall(-rollbackMs);
        payload = makeProbe(T0, {
          status: 'DEGRADED',
          includeProbedAt,
          ttlSec: 20,
          expiresOffsetMs: 19000,
          checkedOffsetMs: 19000,
          ogPatch: {
            available: false,
            runtime_verified: false,
            probe_status: 'EXPIRED',
            health_state: 'EXPIRED',
          },
        });
        await mon.checkNow({force: true});
        assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, false, `${clkTag}: server EXPIRED must not be ignored as stale`);
        assert.equal(expiredAt, 19000, `${clkTag}: server EXPIRED takes effect immediately at 19,000ms`);
        assert.deepEqual(clk.activeTimerIds(), [], `${clkTag}: server EXPIRED clears active TTL timer`);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});

        // Replaying same probe A with extended deadline MUST NEVER resurrect VERIFIED
        payload = makeProbe(T0, {includeProbedAt, ttlSec: 60, expiresOffsetMs: 60000, checkedOffsetMs: 19000});
        await mon.checkNow({force: true});
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
        assert.deepEqual(clk.activeTimerIds(), []);

        // Fresh distinct probe B recovers VERIFIED with exact new TTL
        payload = makeProbe(T0 + 20000, {
          includeProbedAt,
          ttlSec: 20,
          expiresOffsetMs: 20000,
          checkedOffsetMs: 0,
          exec: 'b'.repeat(64),
        });
        clk.advanceElapsed(1000); // elapsed = 20,000ms
        await mon.checkNow({force: true});
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
        assert.equal(clk.activeTimers().length, 1);
        assert.equal(clk.activeTimers()[0].dueElapsed, 40000);
        const timerBId = clk.activeTimerIds()[0];

        // Replay of older probe A while probe B is active MUST NOT displace B or cancel B's timer
        payload = makeProbe(T0, {includeProbedAt, ttlSec: 60, expiresOffsetMs: 60000, checkedOffsetMs: 20000});
        await mon.checkNow({force: true});
        assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true, `${clkTag}: older probe A ignored while B active`);
        assert.deepEqual(clk.activeTimerIds(), [timerBId]);
        assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
        mon.dispose();
      }
    }

    // 2. Reload with valid persisted ledger: tightened deadline, server EXPIRED, and older distinct probe rejection
    {
      const clk1 = createDualClockScheduler(T0);
      const storage = createMemoryStorage();
      let payload = makeProbe(T0, {includeProbedAt, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0});
      const mon1 = hm.createHealthMonitor({
        fetchHealth: async () => structuredClone(payload),
        getScopeKey: () => `matrix-reload-${modeTag}`,
        storage,
        now: clk1.wallNow,
        monotonicNow: clk1.monoNow,
        setTimer: clk1.setTimer,
        clearTimer: clk1.clearTimer,
        retryDelaysMs: [],
      });
      await mon1.checkNow({force: true});
      clk1.advanceElapsed(8000);
      mon1.dispose(); // writes checkpointRemainingMs = 12,000 and latestProofSig

      // 2a. After reload at t=8s, same probe with shortened 19s deadline stays VERIFIED for 11,000ms (expires at total 19s)
      const clk2 = createDualClockScheduler(clk1.wallNow(), 0);
      payload = makeProbe(T0, {includeProbedAt, ttlSec: 19, expiresOffsetMs: 19000, checkedOffsetMs: 8000});
      let expiredAt2 = null;
      const mon2 = hm.createHealthMonitor({
        fetchHealth: async () => structuredClone(payload),
        getScopeKey: () => `matrix-reload-${modeTag}`,
        storage,
        now: clk2.wallNow,
        monotonicNow: clk2.monoNow,
        setTimer: clk2.setTimer,
        clearTimer: clk2.clearTimer,
        retryDelaysMs: [],
        onStateChange: (s) => {
          if (s.backend.ttlExpired && expiredAt2 === null) expiredAt2 = clk2.elapsed();
        },
      });
      await mon2.checkNow({force: true});
      assert.equal(mon2.getSnapshot().meta.staleSnapshotIgnored, false, `${modeTag}: reload same-probe tighten not treated as OLDER`);
      assertAllThreeHealthSurfaces(fp, mon2.getSnapshot().backend, clk2.wallNow(), {verified: true, expired: false});
      assert.equal(clk2.activeTimers().length, 1);
      assert.equal(clk2.activeTimers()[0].delayMs, 11000, `${modeTag}: reload tightened budget is exact 11,000ms`);

      // 2b. Older distinct probe Z (different exec digest, earlier expires=15s) MUST be ignored while A is active
      const timerAfterReload = clk2.activeTimerIds()[0];
      payload = makeProbe(T0, {
        includeProbedAt,
        probedOffsetMs: -5000,
        ttlSec: 15,
        expiresOffsetMs: 15000,
        checkedOffsetMs: 8000,
        exec: 'c'.repeat(64),
      });
      await mon2.checkNow({force: true});
      assert.equal(mon2.getSnapshot().meta.staleSnapshotIgnored, true, `${modeTag}: older distinct probe Z ignored`);
      assert.deepEqual(clk2.activeTimerIds(), [timerAfterReload]);
      assertAllThreeHealthSurfaces(fp, mon2.getSnapshot().backend, clk2.wallNow(), {verified: true, expired: false});

      clk2.advanceElapsed(11000);
      assert.equal(expiredAt2, 11000, `${modeTag}: expires at exact 8s + 11s = 19s total`);
      assertAllThreeHealthSurfaces(fp, mon2.getSnapshot().backend, clk2.wallNow(), {verified: false, expired: true});
      mon2.dispose();
    }

    // 3. Different older probe (both VERIFIED and EXPIRED) MUST NEVER displace active probe A
    {
      const clk = createDualClockScheduler(T0);
      const storage = createMemoryStorage();
      let payload = makeProbe(T0, {includeProbedAt, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0, exec: 'a'.repeat(64)});
      const mon = hm.createHealthMonitor({
        fetchHealth: async () => structuredClone(payload),
        getScopeKey: () => `matrix-older-other-${modeTag}`,
        storage,
        now: clk.wallNow,
        monotonicNow: clk.monoNow,
        setTimer: clk.setTimer,
        clearTimer: clk.clearTimer,
        retryDelaysMs: [],
      });
      await mon.checkNow({force: true});
      assert.deepEqual(clk.activeTimerIds(), [1]);
      clk.advanceElapsed(5000);

      // Older distinct probe B (VERIFIED with earlier deadline)
      payload = makeProbe(T0, {includeProbedAt, probedOffsetMs: -2000, ttlSec: 15, expiresOffsetMs: 15000, checkedOffsetMs: 5000, exec: 'b'.repeat(64)});
      await mon.checkNow({force: true});
      assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
      assert.deepEqual(clk.activeTimerIds(), [1]);
      assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});

      // Older distinct probe B (DEGRADED + EXPIRED with earlier deadline)
      payload = makeProbe(T0, {
        status: 'DEGRADED',
        includeProbedAt,
        probedOffsetMs: -2000,
        ttlSec: 15,
        expiresOffsetMs: 15000,
        checkedOffsetMs: 5000,
        exec: 'b'.repeat(64),
        ogPatch: {available: false, runtime_verified: false, probe_status: 'EXPIRED', health_state: 'EXPIRED'},
      });
      await mon.checkNow({force: true});
      assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
      assert.deepEqual(clk.activeTimerIds(), [1]);
      assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
      mon.dispose();
    }
  }

  // 4. Negative controls: signatures lacking reliable execution identity MUST NEVER bypass OLDER protection
  const weakCases = [
    {label: 'process-only-no-exec', init: {proc: 'proc-weak', exec: null, bin: null, rules: null}, next: {proc: 'proc-weak', exec: null, bin: null, rules: null}},
    {label: 'proc-bin-rules-no-exec', init: {proc: 'proc-weak', exec: null, bin: '1'.repeat(64), rules: '2'.repeat(64)}, next: {proc: 'proc-weak', exec: null, bin: '1'.repeat(64), rules: '2'.repeat(64)}},
    {label: 'non-sha256-exec', init: {proc: 'proc-weak', exec: 'not-a-sha256-digest'}, next: {proc: 'proc-weak', exec: 'not-a-sha256-digest'}},
    {label: 'exec-without-proc', init: {proc: null, exec: 'a'.repeat(64)}, next: {proc: null, exec: 'a'.repeat(64)}},
    {label: 'changed-binary-digest', init: {proc: 'proc-weak', exec: 'a'.repeat(64), bin: '1'.repeat(64)}, next: {proc: 'proc-weak', exec: 'a'.repeat(64), bin: '9'.repeat(64)}},
  ];
  for (const wc of weakCases) {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    let payload = makeProbe(T0, {includeProbedAt: false, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0, ...wc.init});
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => `weak-${wc.label}`,
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
    });
    await mon.checkNow({force: true});
    assert.deepEqual(clk.activeTimerIds(), [1], `${wc.label}: initial probe verified`);
    clk.advanceElapsed(10000);
    payload = makeProbe(T0, {includeProbedAt: false, ttlSec: 15, expiresOffsetMs: 15000, checkedOffsetMs: 10000, ...wc.next});
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true, `${wc.label}: weak/mismatched unanchored identity must still be treated as OLDER`);
    assert.deepEqual(clk.activeTimerIds(), [1], `${wc.label}: active timer preserved`);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
    mon.dispose();
  }

  // 5. Second unanchored probe B accepted with equal/later deadline, then B tightened, then old A replayed
  {
    const clk = createDualClockScheduler(T0);
    const storage = createMemoryStorage();
    let payload = makeProbe(T0, {includeProbedAt: false, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 0, exec: 'a'.repeat(64)});
    let expiredAt = null;
    const mon = hm.createHealthMonitor({
      fetchHealth: async () => structuredClone(payload),
      getScopeKey: () => 'unanchored-second-probe-tighten',
      storage,
      now: clk.wallNow,
      monotonicNow: clk.monoNow,
      setTimer: clk.setTimer,
      clearTimer: clk.clearTimer,
      retryDelaysMs: [],
      onStateChange: (s) => {
        if (s.backend.ttlExpired && expiredAt === null) expiredAt = clk.elapsed();
      },
    });
    await mon.checkNow({force: true});
    clk.advanceElapsed(2000);
    // Distinct probe B with equal expires=20s accepted as newer observation (seq=2)
    payload = makeProbe(T0, {includeProbedAt: false, ttlSec: 20, expiresOffsetMs: 20000, checkedOffsetMs: 2000, exec: 'b'.repeat(64)});
    await mon.checkNow({force: true});
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: true, expired: false});
    const timerB = clk.activeTimerIds()[0];
    // Tighten probe B to 18s (must NOT be rejected against probe A's watermark!)
    clk.advanceElapsed(3000); // elapsed = 5,000ms
    payload = makeProbe(T0, {includeProbedAt: false, ttlSec: 18, expiresOffsetMs: 18000, checkedOffsetMs: 5000, exec: 'b'.repeat(64)});
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, false, 'Tightening newly accepted unanchored probe B must succeed');
    assert.notEqual(clk.activeTimerIds()[0], timerB);
    assert.equal(clk.activeTimers()[0].dueElapsed, 18000);
    const timerB2 = clk.activeTimerIds()[0];
    // Replay old probe A (even with extended deadline) -> MUST stay ignored and keep B's tightened timer
    payload = makeProbe(T0, {includeProbedAt: false, ttlSec: 60, expiresOffsetMs: 60000, checkedOffsetMs: 5000, exec: 'a'.repeat(64)});
    await mon.checkNow({force: true});
    assert.equal(mon.getSnapshot().meta.staleSnapshotIgnored, true);
    assert.deepEqual(clk.activeTimerIds(), [timerB2]);
    clk.advanceElapsed(13000); // elapsed = 18,000ms
    assert.equal(expiredAt, 18000);
    assertAllThreeHealthSurfaces(fp, mon.getSnapshot().backend, clk.wallNow(), {verified: false, expired: true});
    mon.dispose();
  }
});

test('REST deep nesting integrity (depths 15, 16, 17, 20, 64, 125, 128, 129, 132): api.js, Coverage 4-way, Stage 5 Citation 5-way, sibling isolation, and unsigned report byte identity', async () => {
  const apiMod = await loadModule('services/api.js');
  const fpMod = await loadModule('services/findingPresentation.js');
  const jmMod = await loadModule('services/jobModel.js');
  const lsMod = await loadModule('components/scanner/liveStagePresentation.js');

  assert.equal(apiMod.WIRE_MAX_SCAN_DEPTH, 128);

  // 1. Precision-loss counter at depths 15, 16, 17, 20, 64, 125, 128, 129, 132
  for (const d of [15, 16, 17, 20, 64, 125, 128, 129, 132]) {
    const manifestFrag = buildNestedJson(d, '{"scanned_java_files_count":389.00000000000000001}');
    const rawText = `{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED","scan_manifest":${manifestFrag}}`;
    const parsed = apiMod.parseJsonWithWireIntegrity(rawText);
    const mat = apiMod.materializeNormalizedTelemetry(parsed);
    assert.equal(mat.hasMalformed, true, `materializeNormalizedTelemetry must detect violation at depth ${d}`);

    const jsonRt = JSON.parse(JSON.stringify(mat.value));
    if (d <= 125) {
      const rawLeaf = drillNested(parsed.scan_manifest, d);
      const rtLeaf = drillNested(jsonRt.scan_manifest, d);
      assert.equal(apiMod.readStrictWireSafeInt(rawLeaf, 'scanned_java_files_count').valid, false, `raw leaf invalid at depth ${d}`);
      assert.equal(apiMod.readStrictWireSafeInt(rtLeaf, 'scanned_java_files_count').valid, false, `round-trip leaf invalid at depth ${d}`);
    } else {
      // Beyond scanner depth limit: normalized subtree replaces over-depth tail with sentinel so unverified rounded int is unreachable
      const rtLeaf = drillNested(jsonRt.scan_manifest, d);
      assert.ok(
        rtLeaf === null || rtLeaf === undefined || apiMod.isWireInvalidSentinel(rtLeaf),
        `over-depth tail at depth ${d} must be unreachable or a wire-invalid sentinel, got ${JSON.stringify(rtLeaf)}`,
      );
      if (rtLeaf !== null && rtLeaf !== undefined) {
        assert.equal(apiMod.readStrictWireSafeInt(rtLeaf, 'scanned_java_files_count').valid, false);
      }
    }

    // Coverage 4-way parity: raw, normalized, shallow, JSON round-trip ALL reject VERIFIED
    const covs = [
      fpMod.resolveJavaFileCounts(parsed),
      fpMod.resolveJavaFileCounts(mat.value),
      fpMod.resolveJavaFileCounts({...mat.value}),
      fpMod.resolveJavaFileCounts(jsonRt),
    ];
    for (const c of covs) {
      assert.notEqual(c.coverageStatus, 'VERIFIED', `Coverage must reject precision-loss / over-depth at depth ${d}`);
      assert.equal(c.scannedCount, null);
    }

    // Stage 5 Citation 5-way parity across LIVE & PLAYBACK
    const citFrag = buildNestedJson(d, '{"nested_count":1.0000000000000001}');
    const jobText = `{"job_id":"job-d","state":"COMPLETED","stages":[{"stage_number":5,"stage_key":"CITATION_VALIDATION","status":"COMPLETED","summary_metadata":{"matched_count":3,"invalid_count":0,"not_verified_count":0,"total_checked":3,"deep":${citFrag}}}]}`;
    const jobRaw = apiMod.parseJsonWithWireIntegrity(jobText);
    const rawStage = jobRaw.stages[0];
    const resolved5 = jmMod.resolveStages(jobRaw).find((s) => s.number === 5);
    for (const mode of ['LIVE', 'PLAYBACK']) {
      const statuses = [
        lsMod.resolveStage05CitationTelemetry({mode, stage: {summary: rawStage.summary_metadata}}).aggregateStatus,
        lsMod.resolveStage05CitationTelemetry({mode, stage: resolved5}).aggregateStatus,
        lsMod.resolveStage05CitationTelemetry({mode, stage: {...resolved5}}).aggregateStatus,
        lsMod.resolveStage05CitationTelemetry({mode, stage: {...resolved5, summary: {...resolved5.summary}}}).aggregateStatus,
        lsMod.resolveStage05CitationTelemetry({mode, stage: JSON.parse(JSON.stringify(resolved5))}).aggregateStatus,
      ];
      assert.ok(statuses.every((s) => s === 'MALFORMED'), `Stage 5 Citation (${mode}) at depth ${d} must be MALFORMED across all 5 views, got ${JSON.stringify(statuses)}`);
    }
  }

  // 2. Report wrapper blind spot: report.scan_summary.scan_manifest at total JSON depth 129
  {
    const manifest127 = buildNestedJson(127, '{"scanned_java_files_count":389.00000000000000001}');
    const reportText = `{"scan_summary":{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED","scan_manifest":${manifest127}},"findings":[]}`;
    const parsedReport = apiMod.parseJsonWithWireIntegrity(reportText);
    const sum = parsedReport.scan_summary;
    const matSum = apiMod.materializeNormalizedTelemetry(sum);
    assert.equal(matSum.hasMalformed, true);
    for (const rep of [sum, matSum.value, {...matSum.value}, JSON.parse(JSON.stringify(matSum.value))]) {
      assert.notEqual(fpMod.resolveJavaFileCounts(rep).coverageStatus, 'VERIFIED');
    }
  }

  // 3. Unrelated sibling isolation (depths 17, 20, 130) + valid timing decimals + JVL 19/19/0 & WebGoat 498/389/109 + Citation ALL_MATCHED
  {
    for (const d of [17, 20, 130]) {
      const sibBad = buildNestedJson(d, '{"bad_count":1.0000000000000001}');
      const wgText = `{"java_files_inventory":498,"java_files_opengrep_scanned":389,"java_files_opengrep_ignored":109,"opengrep_paths_telemetry_status":"VERIFIED","scan_manifest":{"elapsed_seconds":1.42,"timing":{"duration_ms":12.75}},"unrelated_sibling":${sibBad}}`;
      const wgParsed = apiMod.parseJsonWithWireIntegrity(wgText);
      const wgMat = apiMod.materializeNormalizedTelemetry(wgParsed);
      for (const rep of [wgParsed, wgMat.value, {...wgMat.value}, JSON.parse(JSON.stringify(wgMat.value))]) {
        const cov = fpMod.resolveJavaFileCounts(rep);
        assert.equal(cov.coverageStatus, 'VERIFIED', `Unrelated sibling at depth ${d} must not taint valid WebGoat coverage`);
        assert.equal(cov.inventoryCount, 498);
        assert.equal(cov.scannedCount, 389);
        assert.equal(cov.ignoredCount, 109);
      }
    }

    const jvlText = '{"java_files_inventory":19,"java_files_opengrep_scanned":19,"java_files_opengrep_ignored":0,"opengrep_paths_telemetry_status":"VERIFIED","scan_manifest":{"elapsed_seconds":0.85}}';
    const jvlParsed = apiMod.parseJsonWithWireIntegrity(jvlText);
    const jvlMat = apiMod.materializeNormalizedTelemetry(jvlParsed);
    assert.equal(jvlMat.value, jvlParsed, 'Clean JVL payload must not be mutated or given __wireIntegrity');
    const jvlCov = fpMod.resolveJavaFileCounts(jvlParsed);
    assert.equal(jvlCov.coverageStatus, 'VERIFIED');
    assert.deepEqual([jvlCov.inventoryCount, jvlCov.scannedCount, jvlCov.ignoredCount], [19, 19, 0]);

    const cleanCitJob = apiMod.parseJsonWithWireIntegrity('{"job_id":"j-ok","state":"COMPLETED","stages":[{"stage_number":5,"stage_key":"CITATION_VALIDATION","status":"COMPLETED","summary_metadata":{"matched_count":3,"invalid_count":0,"not_verified_count":0,"total_checked":3,"elapsed_seconds":1.42,"deep":{"l1":{"l2":{"duration_ms":2.5}}}}}]}');
    const cleanResolved5 = jmMod.resolveStages(cleanCitJob).find((s) => s.number === 5);
    assert.equal(lsMod.resolveStage05CitationTelemetry({mode: 'LIVE', stage: cleanResolved5}).aggregateStatus, 'ALL_MATCHED');
    assert.equal(lsMod.resolveStage05CitationTelemetry({mode: 'PLAYBACK', stage: cleanResolved5}).aggregateStatus, 'ALL_MATCHED');
  }

  // 4. Unsigned preserved JVL & WebGoat report JSON byte identity
  const preservedDir = 'C:/NTK-G1/Frontend-Product-Finalization/20261125/preserved-reports';
  if (fs.existsSync(preservedDir)) {
    for (const [fname, expectedSha] of [
      ['jvl-d607f976-report.json', 'd2a5e56e95f29a394f06a354931f68aabf77048750f6ed7f46dfb34991b26737'],
      ['webgoat-8dfa7413-report.json', '4006e4b605150ce122a0fdd975dff96b4cd22022d1ad1f84b40e736bf86fd714'],
    ]) {
      const full = path.join(preservedDir, fname);
      if (!fs.existsSync(full)) continue;
      const rawText = fs.readFileSync(full, 'utf8');
      const parsed = apiMod.parseJsonWithWireIntegrity(rawText);
      const mat = apiMod.materializeNormalizedTelemetry(parsed);
      assert.equal(mat.value, parsed, `${fname} must stay untouched by materializeNormalizedTelemetry`);
      assert.equal(mat.hasMalformed, false);
      assert.equal(mat.hasConflict, false);
      assert.equal(crypto.createHash('sha256').update(rawText).digest('hex'), expectedSha);
    }
  }
});
