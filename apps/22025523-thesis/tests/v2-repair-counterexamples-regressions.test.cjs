// Regression and variant counterexample suite for Frontend Product Finalization Repair.
// Covers all 8 Codex findings (F01-F08) plus generalized variant counterexamples across:
//   - Stage B: Java counts (strict typing, no legacy promotion, no derived subtraction/addition,
//     zeros, nulls, negatives, wrong types, contradictions, History unification) & F08 unknown statuses.
//   - Stage C: Health TTL expiry without interaction, stale probed_at non-extension, explicit VERIFIED
//     proof, scope/token/unmount timer & fetch cancellation, malformed payload resilience.
//   - Stage D: Human Review decoupling, STALE_SOURCE preservation, post-mutation refresh failure,
//     delayed/cross-scope discard, zero unintended POST retries.
//   - Stage E: Stage 05 citation telemetry separation (PREVIEW / LIVE / PLAYBACK, no evidence,
//     INVALID, NOT_VERIFIED, MIXED, explicit per-check proof).
//   - Stage F: Playhead separation & polling monotonicity (updated_at, revision, terminal immutability,
//     non-masking of FAILED/CANCELLED/COMPLETED, defensive stage/progress checks, job switching).
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
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
    platform: 'neutral',
    mainFields: ['module', 'main'],
    define: {
      'import.meta.env': JSON.stringify({MODE: 'test', DEV: false, PROD: true}),
    },
  });
  const code = built.outputFiles[0].text;
  const dataUrl = `data:text/javascript;base64,${Buffer.from(`${code}\n// ${Math.random()}`, 'utf8').toString('base64')}`;
  return import(dataUrl);
}

test('Stage B (F01 + F08): Java counts full matrix (missing, partial, zero, malformed, contradictory, history sync) and unknown statuses', async () => {
  const fp = await bundleAndImport('services/findingPresentation.js');
  const sh = await bundleAndImport('services/scanHistory.js');

  // 1. Legacy-only inventory
  const legacyOnly = fp.resolveJavaFileCounts({java_files_scanned: 19});
  assert.deepEqual([legacyOnly.inventoryCount, legacyOnly.scannedCount, legacyOnly.ignoredCount], [19, null, null]);
  assert.equal(legacyOnly.hasVerifiedScanned, false);
  assert.equal(legacyOnly.isInconsistent, false);
  assert.equal(legacyOnly.inventoryFromLegacy, true);

  // 2. Codex incremental rollout: inventory + legacy java_files_scanned + ignored (NO explicit actual scanned)
  //    Canonical coverage contract (P1 blocker round): without status + all three closed counts the
  //    breakdown is never presented; raw values stay in rawCounts.
  const incremental = fp.resolveJavaFileCounts({
    java_files_inventory_count: 498,
    java_files_scanned: 498,
    java_files_ignored: 109,
  });
  assert.deepEqual([incremental.inventoryCount, incremental.scannedCount, incremental.ignoredCount], [498, null, null]);
  assert.deepEqual(incremental.rawCounts, {inventory: 498, scanned: null, ignored: 109});
  assert.equal(incremental.hasVerifiedScanned, false);
  assert.equal(incremental.isInconsistent, false);
  assert.equal(incremental.coverageStatus, 'UNVERIFIED');
  assert.match(incremental.summaryNote, /chưa xác minh/);

  // 3. No derived subtraction when ignored is omitted (and never verified without the full record)
  const noIgnored = fp.resolveJavaFileCounts({
    java_files_inventory_count: 30,
    opengrep_scanned_java_files: 20,
  });
  assert.deepEqual([noIgnored.inventoryCount, noIgnored.scannedCount, noIgnored.ignoredCount], [30, null, null]);
  assert.deepEqual(noIgnored.rawCounts, {inventory: 30, scanned: 20, ignored: null});
  assert.equal(noIgnored.hasVerifiedScanned, false);
  assert.equal(noIgnored.isInconsistent, false);

  // 4. No derived addition when inventory is omitted (and never verified without the full record)
  const noInventory = fp.resolveJavaFileCounts({
    opengrep_scanned_java_files: 12,
    java_files_ignored: 4,
  });
  assert.deepEqual([noInventory.inventoryCount, noInventory.scannedCount, noInventory.ignoredCount], [null, null, null]);
  assert.deepEqual(noInventory.rawCounts, {inventory: null, scanned: 12, ignored: 4});
  assert.equal(noInventory.hasVerifiedScanned, false);
  assert.equal(noInventory.isInconsistent, false);

  // 5. Explicit zeros preserved accurately (canonical VERIFIED closed 0/0/0) — zeros without status,
  //    or with aliases instead of the canonical keys, stay unverified
  const explicitZeros = fp.resolveJavaFileCounts({
    java_files_inventory: 0,
    java_files_opengrep_scanned: 0,
    java_files_opengrep_ignored: 0,
    opengrep_paths_telemetry_status: 'VERIFIED',
  });
  assert.deepEqual([explicitZeros.inventoryCount, explicitZeros.scannedCount, explicitZeros.ignoredCount], [0, 0, 0]);
  assert.equal(explicitZeros.hasVerifiedScanned, true);
  assert.equal(explicitZeros.isInconsistent, false);
  assert.equal(explicitZeros.primaryValue, 0);
  const zerosAlias = fp.resolveJavaFileCounts({
    java_files_inventory_count: 0,
    opengrep_scanned_java_files: 0,
    java_files_ignored: 0,
    opengrep_paths_telemetry_status: 'VERIFIED',
  });
  assert.equal(zerosAlias.hasVerifiedScanned, false);
  assert.equal(zerosAlias.scannedCount, null);
  assert.equal(zerosAlias.inventoryCount, 0);
  const zerosNoStatus = fp.resolveJavaFileCounts({
    java_files_inventory_count: 0,
    opengrep_scanned_java_files: 0,
    java_files_ignored: 0,
  });
  assert.equal(zerosNoStatus.hasVerifiedScanned, false);
  assert.equal(zerosNoStatus.scannedCount, null);
  assert.equal(zerosNoStatus.inventoryCount, 0);

  // 6. All missing / null / empty
  for (const empty of [null, undefined, {}, {java_files_inventory_count: null, opengrep_scanned_java_files: null, java_files_ignored: null}]) {
    const res = fp.resolveJavaFileCounts(empty);
    assert.deepEqual([res.inventoryCount, res.scannedCount, res.ignoredCount], [null, null, null]);
    assert.equal(res.hasVerifiedScanned, false);
    assert.equal(res.isInconsistent, false);
    assert.match(res.summaryNote, /Chưa có số liệu/);
  }

  // 7. Malformed types & negative/float values never become 0
  for (const malformed of [
    {java_files_inventory_count: ' ', opengrep_scanned_java_files: [], java_files_ignored: null},
    {java_files_inventory_count: '', opengrep_scanned_java_files: '12', java_files_ignored: true},
    {java_files_inventory_count: -5, opengrep_scanned_java_files: 1.5, java_files_ignored: Number.NaN},
    {java_files_inventory_count: {}, opengrep_scanned_java_files: Number.POSITIVE_INFINITY, java_files_ignored: -1},
    {scan_manifest: {paths: {scanned: [123, ''], ignored: 'not-array'}}},
  ]) {
    const res = fp.resolveJavaFileCounts(malformed);
    assert.deepEqual([res.inventoryCount, res.scannedCount, res.ignoredCount], [null, null, null]);
    assert.equal(res.hasVerifiedScanned, false);
    assert.equal(res.hasInvalidFields, true);
  }

  // 8. Contradictory metrics flagged as inconsistent and never self-corrected
  const conflict1 = fp.resolveJavaFileCounts({
    java_files_inventory_count: 5,
    opengrep_scanned_java_files: 9,
    java_files_ignored: 3,
  });
  assert.deepEqual([conflict1.inventoryCount, conflict1.scannedCount, conflict1.ignoredCount], [5, null, null]);
  assert.equal(conflict1.isInconsistent, true);
  assert.equal(conflict1.hasVerifiedScanned, false);
  assert.deepEqual(conflict1.rawCounts, {inventory: 5, scanned: 9, ignored: 3});

  const conflict2 = fp.resolveJavaFileCounts({
    java_files_inventory_count: 10,
    opengrep_scanned_java_files: 7,
    java_files_ignored: 5,
  });
  assert.deepEqual([conflict2.inventoryCount, conflict2.scannedCount, conflict2.ignoredCount], [10, null, null]);
  assert.equal(conflict2.isInconsistent, true);

  const conflict3 = fp.resolveJavaFileCounts({
    java_files_inventory_count: 10,
    java_files_ignored: 12,
  });
  assert.deepEqual([conflict3.inventoryCount, conflict3.scannedCount, conflict3.ignoredCount], [10, null, null]);
  assert.equal(conflict3.isInconsistent, true);

  const intraConflict = fp.resolveJavaFileCounts({
    java_files_inventory_count: 10,
    java_files_count: 20,
  });
  assert.equal(intraConflict.isInconsistent, true);
  assert.equal(intraConflict.inventoryCount, null);

  // 9. History unification via historyRecordFromBackend (same normalizer; canonical closed VERIFIED record)
  const histRec = sh.historyRecordFromBackend({
    scan_id: 'scan-hist-1',
    java_files_inventory: 250,
    java_files_opengrep_scanned: 210,
    java_files_opengrep_ignored: 40,
    opengrep_paths_telemetry_status: 'VERIFIED',
  }, {origin: 'http://127.0.0.1:19001', sessionScope: 's1'});
  assert.equal(histRec.javaCounts.inventoryCount, 250);
  assert.equal(histRec.javaCounts.scannedCount, 210);
  assert.equal(histRec.javaCounts.ignoredCount, 40);
  assert.equal(histRec.javaCounts.hasVerifiedScanned, true);
  const histAlias = sh.historyRecordFromBackend({
    scan_id: 'scan-hist-3',
    java_files_inventory: 250,
    java_files_opengrep_scanned: 210,
    java_files_ignored: 40,
    opengrep_paths_telemetry_status: 'VERIFIED',
  }, {origin: 'http://127.0.0.1:19001', sessionScope: 's1'});
  assert.equal(histAlias.javaCounts.scannedCount, null, 'alias for ignored never satisfies canonical gate');
  assert.equal(histAlias.javaCounts.hasVerifiedScanned, false);
  const histNoStatus = sh.historyRecordFromBackend({
    scan_id: 'scan-hist-2',
    java_files_inventory_count: 250,
    opengrep_scanned_java_files: 210,
    java_files_ignored: 40,
  }, {origin: 'http://127.0.0.1:19001', sessionScope: 's1'});
  assert.equal(histNoStatus.javaCounts.inventoryCount, 250);
  assert.equal(histNoStatus.javaCounts.scannedCount, null);
  assert.equal(histNoStatus.javaCounts.hasVerifiedScanned, false);

  // 10. F08: Unknown validated_status and human_review_state keep raw code distinct from UNDETERMINED/OPEN
  const futureVal = fp.validatedStatusMeta('FUTURE_STATE');
  assert.equal(futureVal.code, 'FUTURE_STATE');
  assert.equal(futureVal.isUnknown, true);
  assert.notEqual(futureVal.code, 'UNDETERMINED');

  const futureHuman = fp.humanReviewMeta('SECOND_REVIEW_REQUIRED');
  assert.equal(futureHuman.code, 'SECOND_REVIEW_REQUIRED');
  assert.equal(futureHuman.isUnknown, true);
  assert.notEqual(futureHuman.code, 'OPEN');

  assert.equal(fp.validatedStatusMeta('').code, 'UNKNOWN');
  assert.equal(fp.humanReviewMeta(null).code, 'UNKNOWN');
});

test('Stage C (F02 + F03): Health TTL expiry without interaction, stale snapshot non-extension, explicit proof, scope cancel, and malformed payloads', async () => {
  const fp = await bundleAndImport('services/findingPresentation.js');
  const hm = await bundleAndImport('services/healthMonitor.js');

  // 1. Strict explicit proof required for VERIFIED
  assert.equal(fp.describeOpengrepHealth({available: true}).isVerified, false);
  assert.equal(fp.describeOpengrepHealth({available: true, probe_in_progress: true}).isVerified, false);
  assert.equal(fp.describeOpengrepHealth({available: true, runtime_verified: false, probe_status: 'VERIFIED'}).isVerified, false);
  assert.equal(fp.describeOpengrepHealth({available: true, probe_status: 'VERIFIED', probe_in_progress: true}).isVerified, false);
  assert.equal(fp.describeOpengrepHealth({available: true, binary_present: false, probe_status: 'VERIFIED'}).isVerified, false);
  assert.equal(fp.describeOpengrepHealth({available: true, runtime_verified: true, probe_status: 'VERIFIED', health_state: 'VERIFIED'}).isVerified, false);
  const stampedT0 = 1_700_000_000_000;
  assert.equal(fp.describeOpengrepHealth({
    available: true,
    runtime_verified: true,
    probe_status: 'VERIFIED',
    health_state: 'VERIFIED',
    probed_at: new Date(stampedT0).toISOString(),
    expires_at: new Date(stampedT0 + 300000).toISOString(),
    ttl_seconds: 300,
  }, null, {nowMs: stampedT0}).isVerified, true);

  // 2. Malformed payloads never throw and never self-promote to VERIFIED
  for (const malformed of [
    {status: 'OK', degraded_reasons: 'invalid-list', opengrep: {available: true}},
    {status: 'OK', degraded_reasons: 42, opengrep: 'string-instead-of-object'},
    {status: 'DEGRADED', degraded_reasons: {nested: true}, rules: {priority_cwes: 'CWE-89'}},
  ]) {
    const classified = hm.classifyHealthResponse(malformed);
    assert.equal(classified.status, 'DEGRADED');
    assert.equal(Array.isArray(classified.health.degraded_reasons), true);
    assert(classified.schemaWarnings.length > 0);
    const view = fp.classifyBackendHealthState(classified);
    assert(!view.pillLabel.includes('VERIFIED'));
    assert.equal(Array.isArray(view.degradedReasons), true);
  }
  for (const invalidEnvelope of [null, undefined, [], 'OK', 123, {status: 'BOGUS'}]) {
    const res = hm.classifyHealthResponse(invalidEnvelope);
    assert.equal(res.status, 'ERROR');
  }

  // 3. TTL expiry automatically clears VERIFIED without user interaction or navigation
  let fakeNow = 1_700_000_000_000;
  const timers = [];
  let nextTimerId = 1;
  const setTimer = (fn, ms) => {
    const id = nextTimerId++;
    timers.push({id, fn, ms, cleared: false, ran: false});
    return id;
  };
  const clearTimer = (id) => {
    const entry = timers.find((t) => t.id === id);
    if (entry) entry.cleared = true;
  };

  let scope = 'http://127.0.0.1:19010|http://127.0.0.1:19010|s1';
  const observedStates = [];
  const monitor = hm.createHealthMonitor({
    getScopeKey: () => scope,
    now: () => fakeNow,
    setTimer,
    clearTimer,
    fetchHealth: async () => ({
      status: 'OK',
      opengrep: {
        available: true,
        runtime_verified: true,
        probe_status: 'VERIFIED',
        health_state: 'VERIFIED',
        ttl_seconds: 1,
        probed_at: new Date(fakeNow).toISOString(),
      },
    }),
    onStateChange: (snap) => observedStates.push(fp.classifyBackendHealthState(snap.backend, {nowMs: fakeNow}).pillLabel),
  });

  await monitor.checkNow();
  assert.equal(monitor.getSnapshot().backend.status, 'CONNECTED');
  assert.match(fp.classifyBackendHealthState(monitor.getSnapshot().backend, {nowMs: fakeNow}).pillLabel, /OPENGREP VERIFIED/);
  assert.equal(monitor.hasPendingTtlTimer(), true);

  // Advance clock past TTL and fire TTL timer -> VERIFIED cleared immediately
  fakeNow += 1200;
  const ttlTimer = timers.find((t) => !t.cleared && !t.ran);
  assert(ttlTimer);
  ttlTimer.ran = true;
  ttlTimer.fn();
  const afterExpiry = monitor.getSnapshot();
  assert.equal(afterExpiry.backend.status, 'DEGRADED');
  assert.equal(afterExpiry.meta.ttlExpired, true);
  assert(!fp.classifyBackendHealthState(afterExpiry.backend, {nowMs: fakeNow}).pillLabel.includes('VERIFIED'));
  assert.match(fp.classifyBackendHealthState(afterExpiry.backend, {nowMs: fakeNow}).pillLabel, /EXPIRED/);

  // 4. Re-receiving an already-expired probed_at snapshot NEVER falsely extends TTL
  const staleProbedAt = new Date(fakeNow - 5000).toISOString();
  const staleMonitor = hm.createHealthMonitor({
    getScopeKey: () => scope,
    now: () => fakeNow,
    setTimer,
    clearTimer,
    fetchHealth: async () => ({
      status: 'OK',
      opengrep: {
        available: true,
        runtime_verified: true,
        probe_status: 'VERIFIED',
        health_state: 'VERIFIED',
        ttl_seconds: 2,
        probed_at: staleProbedAt,
      },
    }),
  });
  await staleMonitor.checkNow();
  assert.equal(staleMonitor.getSnapshot().backend.status, 'DEGRADED');
  assert.equal(staleMonitor.getSnapshot().meta.ttlExpired, true);
  assert.equal(staleMonitor.hasPendingTtlTimer(), false);
  staleMonitor.dispose();

  // 5. Scope switch / dispose cancels pending TTL timer cleanly
  timers.length = 0;
  await monitor.checkNow({force: true});
  assert.equal(monitor.hasPendingTtlTimer(), true);
  monitor.dispose();
  assert.equal(monitor.hasPendingTtlTimer(), false);
  assert(timers.every((t) => t.cleared));
});

test('Stage D (F04): Human Review 409 STALE_SOURCE isolation, post-mutation refresh failure, late response discard, and decoupled ReviewPage', async () => {
  const prevFetch = global.fetch;
  const prevWindow = global.window;
  const prevSession = global.sessionStorage;
  const prevLocal = global.localStorage;

  global.sessionStorage = mkStorage();
  global.localStorage = mkStorage();
  global.window = {
    location: {origin: 'http://127.0.0.1:4173', hostname: '127.0.0.1'},
    sessionStorage: global.sessionStorage,
    localStorage: global.localStorage,
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
  };

  try {
    const entryCode = `
      export * as apiMod from ${JSON.stringify(path.join(SRC_ROOT, 'services/api.js'))};
      export * as reviewMod from ${JSON.stringify(path.join(SRC_ROOT, 'services/reviewModel.js'))};
    `;
    const built = await esbuild.build({
      stdin: {contents: entryCode, resolveDir: SRC_ROOT, loader: 'js'},
      bundle: true,
      write: false,
      format: 'esm',
      platform: 'neutral',
      mainFields: ['module', 'main'],
      define: {'import.meta.env': JSON.stringify({MODE: 'test', DEV: false, PROD: true})},
    });
    const {apiMod, reviewMod} = await import(
      `data:text/javascript;base64,${Buffer.from(`${built.outputFiles[0].text}\n// ${Math.random()}`, 'utf8').toString('base64')}`,
    );

    const shaOrig = 'a'.repeat(64);
    const validDetail = {
      scan_id: 'scan-r',
      finding_id: 'find-1',
      human_review_state: 'CONFIRMED_TRUE',
      review_events: [{sequence: 1, action: 'confirm-true', actor: 'a', reason: 'prev', timestamp: '2026-11-25T00:00:00Z'}],
      rejected_decisions: [],
      evidence: {
        id: 'find-1',
        issues: [],
        scan_provenance: {source_capture_verified: true},
        snapshots: {'Example.java': {sha256: shaOrig}},
      },
    };

    // 1. POST 409 STALE_SOURCE + findingHistory 500 -> preserves previous state, prior events, 409 rejected, flags historyRefreshFailed, 0 extra POST
    let postCalls = 0;
    const staleRes = await reviewMod.submitReviewDecision({
      scanId: 'scan-r',
      findingId: 'find-1',
      action: 'confirm-false',
      actor: 'reviewer',
      reason: 'checking drift handling',
      detail: validDetail,
      apiClient: {
        confirmFalse: async () => {
          postCalls += 1;
          throw Object.assign(new Error('Source drift'), {
            status: 409,
            code: 'STALE_SOURCE',
            payload: {
              scan_id: 'scan-r',
              finding_id: 'find-1',
              stale_source: {mismatched_paths: ['Example.java']},
              rejected_decisions: [{sequence: 1, rejection_code: 'STALE_SOURCE', attempted_action: 'confirm-false'}],
            },
          });
        },
        findingHistory: async () => {
          throw Object.assign(new Error('History 500'), {status: 500});
        },
      },
    });
    assert.equal(postCalls, 1);
    assert.equal(staleRes.ok, false);
    assert.equal(staleRes.staleSource, true);
    assert.equal(staleRes.humanReviewState, 'CONFIRMED_TRUE');
    assert.equal(staleRes.reviewEvents.length, 1);
    assert.equal(staleRes.rejectedDecisions.length, 1);
    assert.equal(staleRes.historyRefreshFailed, true);

    // 2. POST confirm-true succeeds, but follow-up findingDetail fails -> distinguishes mutatedOnServer + refreshFailed, 0 retry POST
    postCalls = 0;
    const partialRes = await reviewMod.submitReviewDecision({
      scanId: 'scan-r',
      findingId: 'find-1',
      action: 'confirm-true',
      actor: 'reviewer',
      reason: 'confirming true positive',
      detail: validDetail,
      apiClient: {
        confirmTrue: async () => {
          postCalls += 1;
          return {scan_id: 'scan-r', finding_id: 'find-1'};
        },
        findingDetail: async () => {
          throw Object.assign(new Error('Readback 500'), {status: 500});
        },
      },
    });
    assert.equal(postCalls, 1);
    assert.equal(partialRes.ok, false);
    assert.equal(partialRes.mutatedOnServer, true);
    assert.equal(partialRes.refreshFailed, true);
    assert.equal(partialRes.errorCode, 'POST_MUTATION_REFRESH_FAILED');

    // 3. Session/token switch during in-flight default api review submission discards late response
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19020', token: 'tok-1'});
    let resolveHistory;
    global.fetch = async (url, init = {}) => {
      if (init.method === 'POST') {
        return new Response(JSON.stringify({
          error_code: 'STALE_SOURCE',
          scan_id: 'scan-r',
          finding_id: 'find-1',
          human_review_state: 'OPEN',
        }), {status: 409, headers: {'Content-Type': 'application/json'}});
      }
      return new Promise((resolve) => { resolveHistory = resolve; });
    };
    const pending = reviewMod.submitReviewDecision({
      scanId: 'scan-r',
      findingId: 'find-1',
      action: 'confirm-false',
      actor: 'reviewer',
      reason: 'switching session mid-flight',
      detail: validDetail,
    });
    await new Promise((r) => setTimeout(r, 20));
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19020', token: 'tok-2'});
    if (resolveHistory) {
      resolveHistory(new Response(JSON.stringify({scan_id: 'scan-r', finding_id: 'find-1', events: [], rejected_decisions: []}), {status: 200}));
    }
    const abortedRes = await pending;
    assert.equal(abortedRes.ok, false);
    assert.equal(abortedRes.abortedByConfigChange, true);

    // 4. Static guard: ReviewPage decouples queue & history (no Promise.all coupling) and keeps same-scope guard
    const reviewPageSrc = fs.readFileSync(path.join(SRC_ROOT, 'pages/ReviewPage.jsx'), 'utf8');
    assert(!reviewPageSrc.includes('Promise.all(['), 'ReviewPage must not couple reviewQueue and scanReviewHistory with Promise.all');
    assert(reviewPageSrc.includes('review-history-sync-error'));
    assert(reviewPageSrc.includes('review-queue-sync-error'));
  } finally {
    global.fetch = prevFetch;
    global.window = prevWindow;
    global.sessionStorage = prevSession;
    global.localStorage = prevLocal;
  }
});

test('Stage E (F05): Stage 05 citation telemetry never fabricates MATCH ✓ without explicit backend evidence', async () => {
  const lsp = await bundleAndImport('components/scanner/liveStagePresentation.js');

  // 1. PREVIEW mode -> illustrative only, zero MATCH ✓
  const preview = lsp.resolveStage05CitationTelemetry({mode: 'PREVIEW', stage: null});
  assert.equal(preview.isIllustrative, true);
  assert.equal(preview.checks.filter((c) => c.badgeText.includes('MATCH ✓')).length, 0);

  // 2. LIVE RUNNING with no metadata -> CHECKING, zero MATCH ✓
  const liveRunning = lsp.resolveStage05CitationTelemetry({
    mode: 'LIVE',
    stage: {cat: 'RUNNING', summary: null},
  });
  assert.equal(liveRunning.aggregateStatus, 'CHECKING');
  assert.equal(liveRunning.hasBackendEvidence, false);
  assert.equal(liveRunning.checks.filter((c) => c.badgeText.includes('MATCH ✓')).length, 0);

  // 3. PLAYBACK COMPLETED with no metadata -> NO_DATA, never assumes all citations matched
  const completedNoMeta = lsp.resolveStage05CitationTelemetry({
    mode: 'PLAYBACK',
    stage: {cat: 'COMPLETED', summary: null},
  });
  assert.equal(completedNoMeta.aggregateStatus, 'NO_DATA');
  assert.equal(completedNoMeta.checks.filter((c) => c.badgeText.includes('MATCH ✓')).length, 0);

  // 4. INVALID citation outcome
  const invalidOnly = lsp.resolveStage05CitationTelemetry({
    mode: 'PLAYBACK',
    stage: {cat: 'DEGRADED', summary: {matched_count: 0, invalid_count: 4, total_findings: 4}},
  });
  assert.equal(invalidOnly.aggregateStatus, 'INVALID');
  assert.equal(invalidOnly.checks.filter((c) => c.badgeText.includes('MATCH ✓')).length, 0);
  assert(invalidOnly.checks.every((c) => c.status === 'INVALID'));

  // 5. NOT_VERIFIED citation outcome
  const notVerified = lsp.resolveStage05CitationTelemetry({
    mode: 'PLAYBACK',
    stage: {cat: 'DEGRADED', summary: {matched_count: 0, not_verified_count: 5, total_findings: 5}},
  });
  assert.equal(notVerified.aggregateStatus, 'NOT_VERIFIED');
  assert.equal(notVerified.checks.filter((c) => c.badgeText.includes('MATCH ✓')).length, 0);

  // 6. Mixed outcomes (WebGoat-like: 9 MATCHED, 4 INVALID, 1 NOT_VERIFIED)
  const mixed = lsp.resolveStage05CitationTelemetry({
    mode: 'PLAYBACK',
    stage: {cat: 'DEGRADED', summary: {matched_count: 9, invalid_count: 4, not_verified_count: 1, total_findings: 14}},
  });
  assert.equal(mixed.aggregateStatus, 'MIXED');
  assert.equal(mixed.checks.filter((c) => c.badgeText.includes('MATCH ✓')).length, 0);

  // 7. Explicit per-check backend evidence -> reflects exact check-by-check proof
  const perCheck = lsp.resolveStage05CitationTelemetry({
    mode: 'LIVE',
    stage: {
      cat: 'COMPLETED',
      summary: {checks: {path: 'MATCHED', line: 'MATCHED', quote: 'INVALID', sha256: 'MATCHED'}},
    },
  });
  assert.equal(perCheck.aggregateStatus, 'MIXED');
  assert.equal(perCheck.checks.find((c) => c.key === 'path').badgeText, 'MATCH ✓');
  assert.equal(perCheck.checks.find((c) => c.key === 'quote').badgeText, 'INVALID ✕');
  assert.equal(perCheck.checks.filter((c) => c.badgeText === 'MATCH ✓').length, 3);
});

test('Stage F (F06 + F07): Polling monotonicity rejects older snapshots, preserves terminal states, never masks FAILED/CANCELLED, and resets on job switch', async () => {
  const jm = await bundleAndImport('services/jobModel.js');

  const mkJob = (patch = {}) => ({
    job_id: 'job-1',
    state: 'RUNNING',
    active_stage: 5,
    updated_at: '2026-11-25T00:00:10Z',
    stages: [
      {stage_no: 1, status: 'COMPLETED'},
      {stage_no: 2, status: 'COMPLETED'},
      {stage_no: 3, status: 'COMPLETED'},
      {stage_no: 4, status: 'COMPLETED'},
      {stage_no: 5, status: 'RUNNING'},
    ],
    ...patch,
  });

  // 1. Codex F07: stage 5 at 00:00:10Z followed by stage 2 at 00:00:00Z -> REJECTED
  const stage5 = mkJob();
  const staleStage2 = mkJob({
    active_stage: 2,
    updated_at: '2026-11-25T00:00:00Z',
    stages: [{stage_no: 1, status: 'COMPLETED'}, {stage_no: 2, status: 'RUNNING'}],
  });
  const r1 = jm.shouldAcceptJobSnapshot(stage5, staleStage2, {expectedJobId: 'job-1'});
  assert.equal(r1.accept, false);
  assert.equal(r1.reason, 'OLDER_TIMESTAMP');

  // 2. Explicit revision ordering takes precedence
  const rev5 = mkJob({revision: 5, updated_at: '2026-11-25T00:00:10Z'});
  const rev3 = mkJob({revision: 3, updated_at: '2026-11-25T00:00:20Z'});
  assert.equal(jm.shouldAcceptJobSnapshot(rev5, rev3, {expectedJobId: 'job-1'}).accept, false);
  const rev6 = mkJob({revision: 6, active_stage: 6});
  assert.equal(jm.shouldAcceptJobSnapshot(rev5, rev6, {expectedJobId: 'job-1'}).accept, true);

  // 3. Missing updated_at & revision: defensive stage/state/progress monotonicity prevents backward jump
  const noTsStage4 = mkJob({updated_at: undefined, active_stage: 4, progress: {processed_findings: 5, total_findings: 10}});
  const noTsStage2 = mkJob({updated_at: undefined, active_stage: 2});
  assert.equal(jm.shouldAcceptJobSnapshot(noTsStage4, noTsStage2).accept, false);
  const noTsQueued = mkJob({updated_at: undefined, state: 'QUEUED', active_stage: 1});
  assert.equal(jm.shouldAcceptJobSnapshot(noTsStage4, noTsQueued).accept, false);
  const noTsLowerProgress = mkJob({updated_at: undefined, active_stage: 4, progress: {processed_findings: 3, total_findings: 10}});
  assert.equal(jm.shouldAcceptJobSnapshot(noTsStage4, noTsLowerProgress).accept, false);
  const noTsHigherProgress = mkJob({updated_at: undefined, active_stage: 4, progress: {processed_findings: 6, total_findings: 10}});
  assert.equal(jm.shouldAcceptJobSnapshot(noTsStage4, noTsHigherProgress).accept, true);

  // 4. Terminal states (COMPLETED / FAILED / CANCELLED) are never masked by clock skew on updated_at
  for (const terminalState of ['COMPLETED', 'FAILED', 'CANCELLED']) {
    const term = mkJob({state: terminalState, active_stage: 6, scan_id: 'scan-1', updated_at: '2026-11-25T00:00:00Z'});
    const res = jm.shouldAcceptJobSnapshot(stage5, term, {expectedJobId: 'job-1'});
    assert.equal(res.accept, true, `Must never mask ${terminalState} transition`);
  }

  // 5. Completed job is NEVER overwritten by stale RUNNING snapshot
  const completed = mkJob({state: 'COMPLETED', active_stage: 6, scan_id: 'scan-1', updated_at: '2026-11-25T00:00:20Z'});
  const lateRunning = mkJob({state: 'RUNNING', active_stage: 5, updated_at: '2026-11-25T00:00:30Z'});
  assert.equal(jm.shouldAcceptJobSnapshot(completed, lateRunning, {expectedJobId: 'job-1'}).accept, false);

  // 6. Switching to a brand new job_id resets cleanly (never locks timeline)
  const newJob = mkJob({job_id: 'job-2', state: 'QUEUED', active_stage: 1, updated_at: '2026-11-25T00:00:00Z'});
  assert.equal(jm.shouldAcceptJobSnapshot(completed, newJob, {expectedJobId: 'job-2'}).accept, true);

  // 7. Mismatched expectedJobId is rejected
  assert.equal(jm.shouldAcceptJobSnapshot(stage5, newJob, {expectedJobId: 'job-1'}).accept, false);
});
