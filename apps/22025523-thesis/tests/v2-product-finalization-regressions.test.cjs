// Comprehensive regression test suite for Frontend Product Finalization (Phases B, C, D, E, F).
// Covers:
//   - Stage B: 6-stage timeline geometry (playhead start/mid/end, resize/zoom, multi-row),
//     PREVIEW/LIVE/PLAYBACK separation, unambiguous duration formatting, zero fake telemetry %,
//     no timeout_seconds as E2E duration, COMPLETED/FAILED/CANCELLED/DEGRADED stages.
//   - Stage C: Downgrade reasons (INVALID_CITATION, UNVERIFIED_HELPER_FLOW, UNVERIFIED_REFUTATION,
//     missing reason, NONE suppression), MATCHED vs UNDETERMINED semantics, Java inventory vs
//     OpenGrep actually-scanned vs ignored separation without hardcoding.
//   - Stage D: Active OpenGrep health probe (VERIFIED, PROBE_IN_PROGRESS, EXPIRED, PROBE_TIMEOUT,
//     ENGINE_MISSING, AUTH_REQUIRED), bounded auto-recheck, single-flight, slow/out-of-order
//     response discard, token/base-URL switch timer & fetch cancellation, no self-promotion,
//     removal of outdated health check copy, shared Header/Sidebar/StatusPage source of truth.
//   - Stage E: Human Review (CONFIRMED_TRUE, CONFIRMED_FALSE, REOPEN, 409 STALE_SOURCE keeping
//     state intact & emitting 0 retries, rejected decisions, audit history reload, report export
//     preserving independently_attested=false / model_runtime_verified=false /
//     security_conclusion_verified=false).
//
// Runs strictly offline using in-process mocks (zero real network, zero ADMIN-PC traffic).
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

test('Stage B1/B3/B4: duration formatting, extreme stage durations, missing telemetry, duration=0, and no timeout as E2E', async () => {
  const re = await bundleAndImport('components/scanner/remotionEngine.js');
  const jm = await bundleAndImport('services/jobModel.js');

  // Unambiguous duration formatting (must NEVER display 32 ms as "32,000 ms")
  assert.equal(re.formatDurationMs(0), '0 ms');
  assert.equal(re.formatDurationMs(32), '32 ms');
  assert.equal(re.formatDurationMs(999), '999 ms');
  assert.match(re.formatDurationMs(1500), /^1[.,]5 giây$/);
  assert.equal(re.formatDurationMs(185300), '3 phút 5 giây');
  assert.equal(re.formatDurationMs(185300, {compact: true}), '3p 05s');
  assert.equal(re.formatDurationMs(null), 'Chưa có số liệu thời lượng');
  assert.equal(re.formatDurationMs(undefined), 'Chưa có số liệu thời lượng');
  assert.equal(re.formatDurationMs(NaN), 'Chưa có số liệu thời lượng');
  assert.equal(re.formatDurationMs(-5), 'Chưa có số liệu thời lượng');
  // jobModel.fmtMs stays 100% consistent with remotionEngine.formatDurationMs
  assert.equal(jm.fmtMs(32), re.formatDurationMs(32));
  assert.equal(jm.fmtMs(1500), re.formatDurationMs(1500));
  assert.equal(jm.fmtMs(185300), re.formatDurationMs(185300));
  assert.equal(jm.fmtMs(null), 'Chưa có số liệu thời lượng');

  // Extreme WebGoat-like stage durations + missing Stage 5 + 0 ms Stage 6 + timeout_seconds=600
  const rawJob = {
    job_id: 'job-extreme-1',
    state: 'COMPLETED',
    timeout_seconds: 600,
    total_e2e_duration_ms: 185300,
    stages: [
      {stage_number: 1, stage_key: 'INTAKE_VALIDATION', state: 'COMPLETED', duration_ms: 18},
      {stage_number: 2, stage_key: 'OPENGREP_SCAN', state: 'COMPLETED', duration_ms: 4200},
      {stage_number: 3, stage_key: 'EVIDENCE_COLLECTION', state: 'COMPLETED', duration_ms: 32},
      {stage_number: 4, stage_key: 'QWEN_INFERENCE', state: 'COMPLETED', duration_ms: 175000},
      {stage_number: 5, stage_key: 'CITATION_VALIDATION', state: 'DEGRADED', duration_ms: null},
      {stage_number: 6, stage_key: 'REVIEW_STORE_COMMIT', state: 'COMPLETED', duration_ms: 0},
    ],
  };

  const stages = jm.resolveStages(rawJob);
  assert.equal(stages[4].cat, 'DEGRADED');
  assert.equal(stages[4].label, 'Hoàn tất (có hạ cấp)');
  assert.equal(stages[4].duration, null);
  assert.equal(stages[5].duration, 0);

  // Authoritative E2E duration must use real API E2E ms, never 600_000 ms timeout
  assert.equal(re.resolveAuthoritativeE2eMs({liveJob: rawJob}), 185300);
  const jobWithOnlyTimeout = {state: 'COMPLETED', timeout_seconds: 600, stages: []};
  assert.equal(re.resolveAuthoritativeE2eMs({liveJob: jobWithOnlyTimeout}), null);

  // Strict 3-mode separation (PREVIEW / LIVE / PLAYBACK)
  assert.equal(re.resolveTimelineMode({liveJob: null, live: null, running: false}), re.TIMELINE_MODES.PREVIEW);
  assert.equal(re.resolveTimelineMode({liveJob: {state: 'QUEUED'}}), re.TIMELINE_MODES.LIVE);
  assert.equal(re.resolveTimelineMode({liveJob: {state: 'RUNNING'}}), re.TIMELINE_MODES.LIVE);
  assert.equal(re.resolveTimelineMode({liveJob: {state: 'COMPLETED'}}), re.TIMELINE_MODES.PLAYBACK);
  assert.equal(re.resolveTimelineMode({liveJob: {state: 'FAILED'}}), re.TIMELINE_MODES.PLAYBACK);
  assert.equal(re.resolveTimelineMode({liveJob: {state: 'CANCELLED'}}), re.TIMELINE_MODES.PLAYBACK);

  const timeline = re.buildStageTimeline(stages, {
    mode: re.TIMELINE_MODES.PLAYBACK,
    totalE2eMs: 185300,
  });
  assert.equal(timeline.segments.length, 6);
  // Stage 5 missing duration -> NEVER fabricate 8% / 9% / 17% sharePct!
  assert.equal(timeline.segments[4].hasMeasuredDuration, false);
  assert.equal(timeline.segments[4].measuredMs, null);
  assert.equal(timeline.segments[4].sharePct, null);
  assert.equal(re.resolveStageTrackSubLabel(timeline.segments[4], re.TIMELINE_MODES.PLAYBACK), 'chưa đo thời lượng');

  // Stage 6 duration === 0 -> hasMeasuredDuration true, measuredMs 0, sharePct 0 (not fake floor %)
  assert.equal(timeline.segments[5].hasMeasuredDuration, true);
  assert.equal(timeline.segments[5].measuredMs, 0);
  assert.equal(timeline.segments[5].sharePct, 0);
  assert.equal(re.resolveStageTrackSubLabel(timeline.segments[5], re.TIMELINE_MODES.PLAYBACK), '0 ms');

  // Stage 4 dominant -> real sharePct ~94.4%
  assert.equal(timeline.segments[3].hasMeasuredDuration, true);
  assert.equal(Math.round(timeline.segments[3].sharePct), 94);

  // Visual readability floor keeps all 6 segments clickable (> 0 visualPct summing to 100)
  const sumVisual = timeline.segments.reduce((acc, s) => acc + s.visualPct, 0);
  assert(Math.abs(sumVisual - 100) < 0.05);
  assert(timeline.segments.every((s) => s.visualPct >= 7));

  // Clock must be monotonic and NEVER exceed authoritative E2E ms (fixes 03:05.3 / 02:59.3 & 00:14 / 00:02)
  let prevMs = -1;
  for (let f = 0; f < timeline.totalFrames; f += 7) {
    const ms = re.frameToBackendMs(timeline, f, {totalE2eMs: 185300});
    assert(ms >= prevMs, `frameToBackendMs must be monotonic (${ms} < ${prevMs})`);
    assert(ms <= 185300, `frameToBackendMs must not exceed totalE2eMs (${ms})`);
    prevMs = ms;
  }
  assert.equal(re.frameToBackendMs(timeline, timeline.totalFrames - 1, {totalE2eMs: 185300}), 185300);

  // LIVE mode unrun stages must NEVER show fake percentages
  const liveStages = jm.resolveStages({
    state: 'RUNNING',
    active_stage: 2,
    stages: [
      {stage_number: 1, stage_key: 'INTAKE_VALIDATION', state: 'COMPLETED', duration_ms: 25},
      {stage_number: 2, stage_key: 'OPENGREP_SCAN', state: 'RUNNING', duration_ms: null},
    ],
  });
  const liveTimeline = re.buildStageTimeline(liveStages, {mode: re.TIMELINE_MODES.LIVE});
  assert.equal(re.resolveStageTrackSubLabel(liveTimeline.segments[0], re.TIMELINE_MODES.LIVE), '25 ms');
  assert.equal(re.resolveStageTrackSubLabel(liveTimeline.segments[1], re.TIMELINE_MODES.LIVE), 'đang chạy…');
  for (let i = 2; i < 6; i += 1) {
    const lbl = re.resolveStageTrackSubLabel(liveTimeline.segments[i], re.TIMELINE_MODES.LIVE);
    assert(!lbl.includes('%'), `Unrun LIVE stage ${i + 1} must not show fake %: got "${lbl}"`);
    assert.equal(liveTimeline.segments[i].sharePct, null);
  }
});

test('Stage B1: playhead geometry aligns to DOM segment boxes across start/mid/end, gaps/padding, resize, zoom, and multi-row grids', async () => {
  const re = await bundleAndImport('components/scanner/remotionEngine.js');
  const jm = await bundleAndImport('services/jobModel.js');

  const stages = jm.resolveStages({
    state: 'COMPLETED',
    stages: [
      {stage_number: 1, stage_key: 'INTAKE_VALIDATION', state: 'COMPLETED', duration_ms: 20},
      {stage_number: 2, stage_key: 'OPENGREP_SCAN', state: 'COMPLETED', duration_ms: 5000},
      {stage_number: 3, stage_key: 'EVIDENCE_COLLECTION', state: 'COMPLETED', duration_ms: 40},
      {stage_number: 4, stage_key: 'QWEN_INFERENCE', state: 'COMPLETED', duration_ms: 150000},
      {stage_number: 5, stage_key: 'CITATION_VALIDATION', state: 'DEGRADED', duration_ms: null},
      {stage_number: 6, stage_key: 'REVIEW_STORE_COMMIT', state: 'COMPLETED', duration_ms: 10},
    ],
  });
  const timeline = re.buildStageTimeline(stages, {mode: re.TIMELINE_MODES.PLAYBACK, totalE2eMs: 156000});

  const makeBoxes = (scale) => {
    const widths = [110, 140, 110, 392, 110, 110].map((w) => w * scale);
    const pad = 4 * scale;
    const gap = 4 * scale;
    let x = pad;
    const segmentRects = widths.map((w) => {
      const box = {left: x, right: x + w, width: w, top: pad, height: 48 * scale};
      x += w + gap;
      return box;
    });
    return {containerWidth: x - gap + pad, segmentRects};
  };

  for (const scale of [1, 0.75, 1.25, 1.5]) {
    const dom = makeBoxes(scale);
    // Start frame = 0 -> exact start of segment 0 (clamped inside border by 1px)
    const startGeom = re.computePlayheadGeometry({
      segmentRects: dom.segmentRects,
      containerWidth: dom.containerWidth,
      frameLoc: re.resolveFrameLocation(timeline, 0),
      timeline,
    });
    assert.equal(startGeom.measured, true);
    assert.equal(startGeom.isMultiRow, false);
    assert(Math.abs(startGeom.leftPx - (dom.segmentRects[0].left + 1)) < 0.05);

    // Every stage start and midpoint stays strictly inside its own DOM segment box
    for (const seg of timeline.segments) {
      const box = dom.segmentRects[seg.index];
      const atStart = re.computePlayheadGeometry({
        segmentRects: dom.segmentRects,
        containerWidth: dom.containerWidth,
        frameLoc: re.resolveFrameLocation(timeline, seg.fromFrame),
        timeline,
      });
      assert(atStart.leftPx >= box.left && atStart.leftPx <= box.left + 1.5, `Stage ${seg.index} start mismatch at scale ${scale}`);

      const midFrame = seg.fromFrame + (seg.durationInFrames - 1) * 0.5;
      const atMid = re.computePlayheadGeometry({
        segmentRects: dom.segmentRects,
        containerWidth: dom.containerWidth,
        frameLoc: re.resolveFrameLocation(timeline, midFrame),
        timeline,
      });
      const expectedMid = box.left + box.width * 0.5;
      assert(Math.abs(atMid.leftPx - expectedMid) < 0.5, `Stage ${seg.index} mid mismatch at scale ${scale}`);
      assert(atMid.leftPx >= box.left && atMid.leftPx <= box.right);
    }

    // Exact end frame = totalFrames - 1 -> right edge of last segment, never overflows container
    const endGeom = re.computePlayheadGeometry({
      segmentRects: dom.segmentRects,
      containerWidth: dom.containerWidth,
      frameLoc: re.resolveFrameLocation(timeline, timeline.totalFrames - 1),
      timeline,
    });
    const lastBox = dom.segmentRects[5];
    assert(Math.abs(endGeom.leftPx - (lastBox.right - 1)) < 0.5, `End playhead must reach lastBox.right (${endGeom.leftPx} vs ${lastBox.right})`);
    assert(endGeom.leftPx <= dom.containerWidth - 1);
  }

  // Multi-row responsive grid (3 columns x 2 rows, e.g. 768px viewport)
  const multiRowRects = [
    {left: 4, right: 218, width: 214, top: 4, height: 48},
    {left: 222, right: 436, width: 214, top: 4, height: 48},
    {left: 440, right: 654, width: 214, top: 4, height: 48},
    {left: 4, right: 218, width: 214, top: 56, height: 48},
    {left: 222, right: 436, width: 214, top: 56, height: 48},
    {left: 440, right: 654, width: 214, top: 56, height: 48},
  ];
  const row2Stage = timeline.segments[4]; // Stage 5 on row 2 col 2
  const row2Mid = re.computePlayheadGeometry({
    segmentRects: multiRowRects,
    containerWidth: 660,
    frameLoc: re.resolveFrameLocation(timeline, row2Stage.fromFrame + (row2Stage.durationInFrames - 1) * 0.5),
    timeline,
  });
  assert.equal(row2Mid.measured, true);
  assert.equal(row2Mid.isMultiRow, true);
  assert.equal(row2Mid.topPx, 56);
  assert.equal(row2Mid.heightPx, 48);
  assert(row2Mid.leftPx >= 222 && row2Mid.leftPx <= 436);
});

test('Stage B: CANCELLED and FAILED job stage resolution marks active/failed/not-run accurately', async () => {
  const jm = await bundleAndImport('services/jobModel.js');

  const failedJob = {
    state: 'FAILED',
    active_stage: 2,
    failed_stage: 'OPENGREP_SCAN',
    stages: [
      {stage_number: 1, stage_key: 'INTAKE_VALIDATION', state: 'COMPLETED', duration_ms: 15},
      {stage_number: 2, stage_key: 'OPENGREP_SCAN', state: 'FAILED', duration_ms: 900, error: 'binary crashed'},
    ],
  };
  const failedStages = jm.resolveStages(failedJob);
  assert.equal(failedStages[0].cat, 'COMPLETED');
  assert.equal(failedStages[1].cat, 'FAILED');
  assert.equal(failedStages[2].cat, 'NOT_RUN');
  assert.equal(jm.currentStageIndex(failedJob), 1);

  const cancelledJob = {
    state: 'CANCELED',
    active_stage: 4,
    stages: [
      {stage_number: 1, stage_key: 'INTAKE_VALIDATION', state: 'COMPLETED', duration_ms: 15},
      {stage_number: 2, stage_key: 'OPENGREP_SCAN', state: 'COMPLETED', duration_ms: 2100},
      {stage_number: 3, stage_key: 'EVIDENCE_COLLECTION', state: 'COMPLETED', duration_ms: 35},
      {stage_number: 4, stage_key: 'QWEN_INFERENCE', state: 'RUNNING', duration_ms: null},
    ],
  };
  assert.equal(jm.jobState(cancelledJob), 'CANCELLED');
  const cancelledStages = jm.resolveStages(cancelledJob);
  assert.equal(cancelledStages[3].cat, 'CANCELLED');
  assert.equal(cancelledStages[4].cat, 'NOT_RUN');
  assert.equal(cancelledStages[5].cat, 'NOT_RUN');
  assert.equal(jm.currentStageIndex(cancelledJob), 3);
});

test('Stage C1/C2/C3: downgrade reason breakdown (WebGoat pattern), NONE suppression, MATCHED semantics, and Java inventory vs scanned/ignored', async () => {
  const fp = await bundleAndImport('services/findingPresentation.js');

  // NONE must never be surfaced as a downgrade code
  assert.equal(fp.normalizeFailureKind('NONE'), '');
  assert.equal(fp.normalizeFailureKind('none'), '');
  assert.equal(fp.normalizeFailureKind(null), '');
  assert.equal(fp.normalizeFailureKind('UNVERIFIED_HELPER_FLOW'), 'UNVERIFIED_HELPER_FLOW');

  // Known codes + MATCHED nuance + unknown code + missing code (no fabrication)
  const helperInfo = fp.describeDowngradeReason('UNVERIFIED_HELPER_FLOW', 'helper call unresolved', 'MATCHED');
  assert.equal(helperInfo.code, 'UNVERIFIED_HELPER_FLOW');
  assert.match(helperInfo.viLabel, /hàm trợ giúp|helper/i);
  assert.match(helperInfo.matchedCitationNote, /MATCHED/);
  assert.match(helperInfo.matchedCitationNote, /TP hay FP/);

  const citationInfo = fp.describeDowngradeReason('INVALID_CITATION', 'line mismatch', 'NOT_VERIFIED');
  assert.equal(citationInfo.code, 'INVALID_CITATION');
  assert.match(citationInfo.viLabel, /Trích dẫn/i);
  assert.equal(citationInfo.matchedCitationNote, '');

  const refuteInfo = fp.describeDowngradeReason('UNVERIFIED_REFUTATION', 'refutation not proven', 'NOT_VERIFIED');
  assert.equal(refuteInfo.code, 'UNVERIFIED_REFUTATION');
  assert.match(refuteInfo.viLabel, /REFUTED/i);

  const missingInfo = fp.describeDowngradeReason('', '', 'NOT_VERIFIED');
  assert.equal(missingInfo.hasCode, false);
  assert.match(missingInfo.viLabel, /Chưa có thông tin chi tiết/);

  const customInfo = fp.describeDowngradeReason('NEW_VALIDATOR_RULE', 'custom detail', 'MATCHED');
  assert.equal(customInfo.code, 'NEW_VALIDATOR_RULE');
  assert.match(customInfo.viLabel, /NEW_VALIDATOR_RULE/);

  // WebGoat-shaped 14 findings: 1 SUPPORTED + 13 UNDETERMINED (8 UNVERIFIED_HELPER_FLOW w/ MATCHED, 4 INVALID_CITATION, 1 UNVERIFIED_REFUTATION)
  const webgoatRows = [
    {validatedStatus: 'SUPPORTED', citationCheck: 'MATCHED', validatorDowngraded: false, failureKind: 'NONE'},
    ...Array.from({length: 8}, () => ({
      validatedStatus: 'UNDETERMINED',
      citationCheck: 'MATCHED',
      validatorDowngraded: true,
      failureKind: 'UNVERIFIED_HELPER_FLOW',
    })),
    ...Array.from({length: 4}, () => ({
      validatedStatus: 'UNDETERMINED',
      citationCheck: 'NOT_VERIFIED',
      validatorDowngraded: true,
      failureKind: 'INVALID_CITATION',
    })),
    {
      validatedStatus: 'UNDETERMINED',
      rawModelStatus: 'REFUTED',
      citationCheck: 'NOT_VERIFIED',
      validatorDowngraded: true,
      failureKind: 'UNVERIFIED_REFUTATION',
    },
  ];
  const summary = fp.summarizeDowngradeReasons(webgoatRows);
  assert.equal(summary.totalDowngraded, 13);
  assert.equal(summary.matchedButUndeterminedCount, 8);
  assert.equal(summary.missingReasonCount, 0);
  assert.deepEqual(
    summary.items.map((x) => [x.code, x.count]),
    [
      ['UNVERIFIED_HELPER_FLOW', 8],
      ['INVALID_CITATION', 4],
      ['UNVERIFIED_REFUTATION', 1],
    ],
  );

  // Java file counts: inventory-only API must NOT label as "Tệp Java đã quét" or hardcode 389/109
  const inventoryOnly = fp.resolveJavaFileCounts({java_files_scanned: 498});
  assert.equal(inventoryOnly.hasVerifiedScanned, false);
  assert.equal(inventoryOnly.inventoryCount, 498);
  assert.equal(inventoryOnly.scannedCount, null);
  assert.equal(inventoryOnly.ignoredCount, null);
  assert.equal(inventoryOnly.primaryLabel, 'Tệp Java trong inventory');
  assert.equal(inventoryOnly.primaryValue, 498);

  // Explicit OpenGrep breakdown IS separated accurately when the canonical record is complete
  // (four canonical keys + status VERIFIED + closed counts). Without status, or with any canonical
  // key replaced by an alias carrying the same number, it is never presented as verified.
  const withManifest = fp.resolveJavaFileCounts({
    java_files_inventory: 498,
    java_files_opengrep_scanned: 389,
    java_files_opengrep_ignored: 109,
    opengrep_paths_telemetry_status: 'VERIFIED',
  });
  assert.equal(withManifest.hasVerifiedScanned, true);
  assert.equal(withManifest.inventoryCount, 498);
  assert.equal(withManifest.scannedCount, 389);
  assert.equal(withManifest.ignoredCount, 109);
  assert.equal(withManifest.primaryLabel, 'Tệp Java thực quét (OpenGrep)');
  assert.equal(withManifest.primaryValue, 389);
  const withManifestNoStatus = fp.resolveJavaFileCounts({
    java_files_inventory: 498,
    java_files_opengrep_scanned: 389,
    java_files_opengrep_ignored: 109,
  });
  assert.equal(withManifestNoStatus.hasVerifiedScanned, false);
  assert.equal(withManifestNoStatus.scannedCount, null);
  assert.equal(withManifestNoStatus.primaryLabel, 'Tệp Java trong inventory');
  for (const [canonicalKey, aliasKey] of [
    ['java_files_inventory', 'java_files_count'],
    ['java_files_opengrep_scanned', 'opengrep_scanned_java_files'],
    ['java_files_opengrep_ignored', 'java_files_ignored'],
  ]) {
    const payload = {
      java_files_inventory: 498,
      java_files_opengrep_scanned: 389,
      java_files_opengrep_ignored: 109,
      opengrep_paths_telemetry_status: 'VERIFIED',
    };
    payload[aliasKey] = payload[canonicalKey];
    delete payload[canonicalKey];
    const aliasOnly = fp.resolveJavaFileCounts(payload);
    assert.equal(aliasOnly.hasVerifiedScanned, false, `${aliasKey} must not replace ${canonicalKey}`);
    assert.equal(aliasOnly.scannedCount, null);
  }

  // Manifest paths array variant: canonical counts present and consistent with paths -> verified;
  // paths alone (no canonical scanned/ignored) with closed sum and VERIFIED -> never verified
  const withPaths = fp.resolveJavaFileCounts({
    java_files_inventory: 4,
    java_files_opengrep_scanned: 3,
    java_files_opengrep_ignored: 1,
    opengrep_paths_telemetry_status: 'VERIFIED',
    scan_manifest: {paths: {scanned: ['A.java', 'B.java', 'C.java'], ignored: ['D.java']}},
  });
  assert.equal(withPaths.hasVerifiedScanned, true);
  assert.equal(withPaths.scannedCount, 3);
  assert.equal(withPaths.ignoredCount, 1);
  assert.equal(withPaths.inventoryCount, 4);
  const pathsOnlyClosed = fp.resolveJavaFileCounts({
    java_files_inventory: 4,
    opengrep_paths_telemetry_status: 'VERIFIED',
    scan_manifest: {paths: {scanned: ['A.java', 'B.java', 'C.java'], ignored: ['D.java']}},
  });
  assert.equal(pathsOnlyClosed.hasVerifiedScanned, false);
  assert.equal(pathsOnlyClosed.scannedCount, null);
  assert.equal(pathsOnlyClosed.inventoryCount, 4);
  // Not closed (3 + 1 != 10) and no status: never verified
  const withPathsOpen = fp.resolveJavaFileCounts({
    java_files_count: 10,
    scan_manifest: {paths: {scanned: ['A.java', 'B.java', 'C.java'], ignored: ['D.java']}},
  });
  assert.equal(withPathsOpen.hasVerifiedScanned, false);
  assert.equal(withPathsOpen.scannedCount, null);
  assert.equal(withPathsOpen.inventoryCount, 10);
});

test('Stage D: active health probe states, TTL EXPIRED->VERIFIED auto-recheck, bounded retries, single-flight, slow/out-of-order discard, and scope switch cancellation', async () => {
  const fp = await bundleAndImport('services/findingPresentation.js');
  const hm = await bundleAndImport('services/healthMonitor.js');

  // 1. Contract classification across all OpenGrep active probe states
  const validT0 = Date.now();
  const validProbeProof = {
    available: true,
    runtime_verified: true,
    probe_status: 'VERIFIED',
    health_state: 'VERIFIED',
    probe_in_progress: false,
    version: '1.25.0',
    probed_at: new Date(validT0).toISOString(),
    expires_at: new Date(validT0 + 300000).toISOString(),
    ttl_seconds: 300,
  };
  assert.equal(fp.describeOpengrepHealth(validProbeProof, null, {nowMs: validT0}).isVerified, true);
  assert.equal(fp.describeOpengrepHealth({available: true, probe_status: 'VERIFIED', health_state: 'VERIFIED', version: '1.25.0'}).isVerified, false);
  assert.equal(fp.describeOpengrepHealth({available: false, probe_status: 'NOT_VERIFIED', probe_in_progress: true}).healthState, 'PROBE_IN_PROGRESS');
  assert.equal(fp.describeOpengrepHealth({available: false, probe_status: 'EXPIRED', probe_in_progress: true}).healthState, 'EXPIRED');
  assert.equal(fp.describeOpengrepHealth({available: false, probe_status: 'TIMEOUT', health_state: 'PROBE_TIMEOUT'}).healthState, 'PROBE_TIMEOUT');
  assert.equal(fp.describeOpengrepHealth({available: false, binary_present: false, probe_status: 'UNAVAILABLE', health_state: 'ENGINE_MISSING'}).healthState, 'ENGINE_MISSING');

  // Never self-promote to VERIFIED if status=OK contradicts opengrep fields
  const fakeOk = hm.classifyHealthResponse({
    status: 'OK',
    opengrep: {available: false, probe_status: 'NOT_VERIFIED', probe_in_progress: true},
  });
  assert.equal(fakeOk.status, 'DEGRADED');
  const fakeView = fp.classifyBackendHealthState(fakeOk);
  assert(!fakeView.pillLabel.includes('VERIFIED'));

  // 2. Bounded auto-recheck: EXPIRED (probe_in_progress=true) -> VERIFIED automatically
  const timers = [];
  let timerIdSeq = 0;
  const setTimer = (fn, ms) => {
    timerIdSeq += 1;
    const entry = {id: timerIdSeq, fn, ms, cleared: false};
    timers.push(entry);
    return entry.id;
  };
  const clearTimer = (id) => {
    const entry = timers.find((t) => t.id === id);
    if (entry) entry.cleared = true;
  };

  let calls = 0;
  let scope = 'http://127.0.0.1:18765|http://127.0.0.1:18765|anon';
  const monitor = hm.createHealthMonitor({
    getScopeKey: () => scope,
    retryDelaysMs: [100, 200, 300],
    setTimer,
    clearTimer,
    fetchHealth: async () => {
      calls += 1;
      if (calls === 1) {
        return {
          status: 'DEGRADED',
          degraded_reasons: ['OPENGREP_NOT_VERIFIED'],
          opengrep: {available: false, probe_status: 'EXPIRED', probe_in_progress: true},
        };
      }
      const recoveredAt = Date.now();
      return {
        status: 'OK',
        degraded_reasons: [],
        opengrep: {
          available: true,
          runtime_verified: true,
          probe_status: 'VERIFIED',
          health_state: 'VERIFIED',
          probe_in_progress: false,
          version: '1.25.0',
          probed_at: new Date(recoveredAt).toISOString(),
          expires_at: new Date(recoveredAt + 300000).toISOString(),
          ttl_seconds: 300,
        },
      };
    },
  });

  // Single-flight coalescing: two concurrent non-forced calls produce 1 request
  const p1 = monitor.checkNow();
  const p2 = monitor.checkNow();
  await Promise.all([p1, p2]);
  assert.equal(calls, 1);
  assert.equal(monitor.getSnapshot().backend.status, 'DEGRADED');
  assert.equal(monitor.getSnapshot().meta.autoRechecking, true);
  assert.equal(monitor.hasPendingTimer(), true);

  // Fire timer #1 -> transitions cleanly to CONNECTED + VERIFIED, stops retry timers, and arms passive TTL timer
  const firstTimer = timers.find((t) => !t.cleared);
  assert(firstTimer);
  firstTimer.fn();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(calls, 2);
  assert.equal(monitor.getSnapshot().backend.status, 'CONNECTED');
  assert.equal(monitor.getSnapshot().meta.autoRechecking, false);
  assert.equal(monitor.hasPendingRetryTimer(), false);
  assert.equal(monitor.hasPendingTtlTimer(), true);
  assert.match(fp.classifyBackendHealthState(monitor.getSnapshot().backend).pillLabel, /OPENGREP VERIFIED/);
  monitor.dispose();

  // 3. Bounded retry cap: never polls infinitely when probe_in_progress stays true
  timers.length = 0;
  let capCalls = 0;
  const capMonitor = hm.createHealthMonitor({
    getScopeKey: () => scope,
    retryDelaysMs: [10, 20],
    setTimer,
    clearTimer,
    fetchHealth: async () => {
      capCalls += 1;
      return {
        status: 'DEGRADED',
        degraded_reasons: ['OPENGREP_NOT_VERIFIED'],
        opengrep: {available: false, probe_status: 'NOT_VERIFIED', probe_in_progress: true},
      };
    },
  });
  await capMonitor.checkNow();
  assert.equal(capCalls, 1);
  for (let i = 0; i < 2; i += 1) {
    const active = timers.find((t) => !t.cleared && !t.ran);
    assert(active, `Expected retry timer #${i + 1}`);
    active.ran = true;
    active.fn();
    await new Promise((r) => setTimeout(r, 15));
  }
  assert.equal(capCalls, 3); // 1 initial + 2 retries
  assert.equal(capMonitor.hasPendingTimer(), false);
  assert.equal(capMonitor.getSnapshot().meta.retryExhausted, true);
  capMonitor.dispose();

  // 4. Slow / out-of-order response + scope switch cancels in-flight AbortSignal and pending timers
  timers.length = 0;
  let resolveSlow;
  let firstSignalAborted = false;
  let callIndex = 0;
  const raceMonitor = hm.createHealthMonitor({
    getScopeKey: () => scope,
    retryDelaysMs: [500],
    setTimer,
    clearTimer,
    fetchHealth: ({signal}) => {
      callIndex += 1;
      if (callIndex === 1) {
        signal.addEventListener('abort', () => { firstSignalAborted = true; });
        return new Promise((resolve) => { resolveSlow = resolve; });
      }
      const verifiedNow = Date.now();
      return Promise.resolve({
        status: 'OK',
        degraded_reasons: [],
        opengrep: {
          available: true,
          runtime_verified: true,
          probe_status: 'VERIFIED',
          health_state: 'VERIFIED',
          probe_in_progress: false,
          probed_at: new Date(verifiedNow).toISOString(),
          expires_at: new Date(verifiedNow + 300000).toISOString(),
          ttl_seconds: 300,
        },
      });
    },
  });
  const slowPromise = raceMonitor.checkNow({force: true});
  scope = 'http://127.0.0.1:18770|http://127.0.0.1:18770|tok-2';
  await raceMonitor.checkNow({force: true});
  assert.equal(firstSignalAborted, true, 'Switching scope/force must abort previous in-flight request');
  assert.equal(raceMonitor.getSnapshot().backend.status, 'CONNECTED');
  resolveSlow({
    status: 'DEGRADED',
    degraded_reasons: ['OPENGREP_PROBE_TIMEOUT'],
    opengrep: {available: false, probe_status: 'TIMEOUT', health_state: 'PROBE_TIMEOUT', probe_in_progress: false},
  });
  await slowPromise;
  assert.equal(raceMonitor.getSnapshot().backend.status, 'CONNECTED', 'Late/out-of-order response must never overwrite newer state');
  raceMonitor.dispose();

  // 5. No retries scheduled for terminal error states (PROBE_TIMEOUT / ENGINE_MISSING / AUTH_REQUIRED)
  for (const payload of [
    {status: 'DEGRADED', degraded_reasons: ['OPENGREP_PROBE_TIMEOUT'], opengrep: {available: false, probe_status: 'TIMEOUT', health_state: 'PROBE_TIMEOUT', probe_in_progress: false}},
    {status: 'DEGRADED', degraded_reasons: ['OPENGREP_UNAVAILABLE'], opengrep: {available: false, binary_present: false, probe_status: 'UNAVAILABLE', health_state: 'ENGINE_MISSING', probe_in_progress: false}},
    {status: 'AUTH_REQUIRED', auth_required: true, authenticated: false},
  ]) {
    const m = hm.createHealthMonitor({
      retryDelaysMs: [10],
      setTimer,
      clearTimer,
      fetchHealth: async () => payload,
    });
    await m.checkNow();
    assert.equal(m.hasPendingTimer(), false);
    m.dispose();
  }
});

test('Stage E: Human Review workflow (CONFIRMED_TRUE, CONFIRMED_FALSE, REOPEN, 409 STALE_SOURCE, rejected decisions, reload, report flags)', async () => {
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
    // Bundle api + reviewModel + reportModel together so they share the exact same in-memory token/origin state
    const entryCode = `
      export * as apiMod from ${JSON.stringify(path.join(SRC_ROOT, 'services/api.js'))};
      export * as reviewMod from ${JSON.stringify(path.join(SRC_ROOT, 'services/reviewModel.js'))};
      export * as reportMod from ${JSON.stringify(path.join(SRC_ROOT, 'services/reportModel.js'))};
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
    const {apiMod, reviewMod, reportMod} = await import(
      `data:text/javascript;base64,${Buffer.from(`${built.outputFiles[0].text}\n// ${Math.random()}`, 'utf8').toString('base64')}`,
    );

    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19888', token: 'unit-test-token'});

    const shaOrig = 'a'.repeat(64);
    const shaDrifted = 'b'.repeat(64);
    let currentState = 'OPEN';
    let staleMode = false;
    const auditEvents = [];
    const rejectedDecisions = [];
    let postConfirmFalseCalls = 0;

    const jsonRes = (body, status = 200) => new Response(JSON.stringify(body), {
      status,
      headers: {'Content-Type': 'application/json'},
    });

    global.fetch = async (url, init = {}) => {
      const u = String(url);
      const method = (init.method || 'GET').toUpperCase();
      const body = init.body ? JSON.parse(init.body) : null;

      if (method === 'POST' && u.endsWith('/confirm-true')) {
        currentState = 'CONFIRMED_TRUE';
        auditEvents.push({
          sequence: auditEvents.length + 1,
          action: 'confirm-true',
          previous_state: 'OPEN',
          new_state: 'CONFIRMED_TRUE',
          actor: body.actor,
          reason: body.reason,
          timestamp: '2026-11-25T10:00:00Z',
        });
        return jsonRes({scan_id: 'scan-1', finding_id: 'f-1', human_review_state: currentState, review_events: auditEvents, rejected_decisions: rejectedDecisions});
      }
      if (method === 'POST' && u.endsWith('/reopen')) {
        const prev = currentState;
        currentState = 'OPEN';
        auditEvents.push({
          sequence: auditEvents.length + 1,
          action: 'reopen',
          previous_state: prev,
          new_state: 'OPEN',
          actor: body.actor,
          reason: body.reason,
          timestamp: '2026-11-25T10:01:00Z',
        });
        return jsonRes({scan_id: 'scan-1', finding_id: 'f-1', human_review_state: currentState, review_events: auditEvents, rejected_decisions: rejectedDecisions});
      }
      if (method === 'POST' && u.endsWith('/confirm-false')) {
        postConfirmFalseCalls += 1;
        if (staleMode) {
          const detailParsed = {
            mismatched_paths: ['src/Sql.java'],
            expected_hashes: {'src/Sql.java': shaOrig},
            observed_hashes: {'src/Sql.java': shaDrifted},
          };
          rejectedDecisions.push({
            sequence: rejectedDecisions.length + 1,
            attempted_action: 'confirm-false',
            rejection_code: 'STALE_SOURCE',
            actor: body.actor,
            reason: body.reason,
            timestamp: '2026-11-25T10:02:00Z',
            detail_parsed: detailParsed,
          });
          return jsonRes({
            scan_id: 'scan-1',
            finding_id: 'f-1',
            error_code: 'STALE_SOURCE',
            error_message: 'Mã nguồn đã thay đổi sau thời điểm quét (SHA-256 lệch).',
            human_review_state: 'CONFIRMED_TRUE',
            stale_source: detailParsed,
            review_events: auditEvents,
            rejected_decisions: rejectedDecisions,
          }, 409);
        }
        currentState = 'CONFIRMED_FALSE';
        auditEvents.push({
          sequence: auditEvents.length + 1,
          action: 'confirm-false',
          previous_state: 'OPEN',
          new_state: 'CONFIRMED_FALSE',
          actor: body.actor,
          reason: body.reason,
          timestamp: '2026-11-25T10:03:00Z',
        });
        return jsonRes({scan_id: 'scan-1', finding_id: 'f-1', human_review_state: currentState, review_events: auditEvents, rejected_decisions: rejectedDecisions});
      }
      if (method === 'GET' && u.endsWith('/findings/f-1')) {
        return jsonRes({
          finding_id: 'f-1',
          scan_id: 'scan-1',
          file_path: 'src/Sql.java',
          human_review_state: currentState,
          data_origin: 'REAL_SCAN',
          writable: true,
          scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
          evidence: {
            id: 'f-1',
            snapshots: {'src/Sql.java': {sha256: shaOrig}},
            scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
          },
          review_events: auditEvents,
          rejected_decisions: rejectedDecisions,
        });
      }
      if (method === 'GET' && u.includes('/findings/f-1/history')) {
        return jsonRes({
          scan_id: 'scan-1',
          finding_id: 'f-1',
          human_review_state: currentState,
          events: auditEvents,
          rejected_decisions: rejectedDecisions,
        });
      }
      return jsonRes({error_code: 'NOT_FOUND'}, 404);
    };

    const validDetail = {
      finding_id: 'f-1',
      scan_id: 'scan-1',
      file_path: 'src/Sql.java',
      human_review_state: 'OPEN',
      data_origin: 'REAL_SCAN',
      writable: true,
      scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
      evidence: {
        id: 'f-1',
        snapshots: {'src/Sql.java': {sha256: shaOrig}},
        scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
      },
    };

    // 1. CONFIRMED_TRUE
    const rTrue = await reviewMod.submitReviewDecision({
      scanId: 'scan-1',
      findingId: 'f-1',
      action: 'confirm-true',
      actor: 'reviewer-uet',
      reason: 'Xác nhận trực tiếp nối chuỗi SQL không qua PreparedStatement.',
      detail: validDetail,
    });
    assert.equal(rTrue.ok, true, JSON.stringify(rTrue));
    assert.equal(rTrue.detail.human_review_state, 'CONFIRMED_TRUE');

    // 2. REOPEN
    const rReopen = await reviewMod.submitReviewDecision({
      scanId: 'scan-1',
      findingId: 'f-1',
      action: 'reopen',
      actor: 'reviewer-uet',
      reason: 'Mở lại để kiểm tra bổ sung nguồn dữ liệu đầu vào.',
      detail: {...validDetail, human_review_state: 'CONFIRMED_TRUE'},
    });
    assert.equal(rReopen.ok, true, JSON.stringify(rReopen));
    assert.equal(rReopen.detail.human_review_state, 'OPEN');

    // 3. HTTP 409 STALE_SOURCE on confirm-false -> 0 retries, state stays unchanged, drift diff captured
    currentState = 'CONFIRMED_TRUE';
    staleMode = true;
    const rStale = await reviewMod.submitReviewDecision({
      scanId: 'scan-1',
      findingId: 'f-1',
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Thử xác nhận cảnh báo giả khi mã nguồn đã bị chỉnh sửa trên đĩa.',
      detail: {...validDetail, human_review_state: 'CONFIRMED_TRUE'},
    });
    assert.equal(rStale.ok, false);
    assert.equal(rStale.staleSource, true);
    assert.equal(postConfirmFalseCalls, 1, 'HTTP 409 STALE_SOURCE must never auto-retry');
    assert.equal(rStale.humanReviewState, 'CONFIRMED_TRUE', 'Must preserve prior human_review_state on 409');
    assert.equal(rStale.staleDetail.expected_hashes['src/Sql.java'], shaOrig);
    assert.equal(rStale.staleDetail.observed_hashes['src/Sql.java'], shaDrifted);

    // 4. Reload audit history includes both applied events and rejected STALE_SOURCE decision
    const historyPayload = await apiMod.api.findingHistory('scan-1', 'f-1', {includeRejected: true});
    const timeline = reviewMod.buildAuditTimeline(historyPayload.events, historyPayload.rejected_decisions);
    assert.equal(timeline.length, 3);
    assert(timeline.some((e) => e.kind === 'REJECTED' && e.code === 'STALE_SOURCE'));
    assert(timeline.some((e) => e.kind === 'APPLIED' && e.action === 'confirm-true'));
    assert(timeline.some((e) => e.kind === 'APPLIED' && e.action === 'reopen'));

    // 5. CONFIRMED_FALSE succeeds once source integrity is restored
    currentState = 'OPEN';
    staleMode = false;
    const rFalse = await reviewMod.submitReviewDecision({
      scanId: 'scan-1',
      findingId: 'f-1',
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Đã đối chiếu lại mã nguồn trùng SHA-256 và xác nhận nhánh an toàn.',
      detail: {...validDetail, human_review_state: 'OPEN'},
    });
    assert.equal(rFalse.ok, true);
    assert.equal(rFalse.detail.human_review_state, 'CONFIRMED_FALSE');

    // 6. Report JSON after review preserves attestation & runtime verification flags as false
    const rawReportDoc = {
      report_schema: 'ntk.v2.report.v1',
      data_origin: 'REAL_SCAN',
      model_runtime_verified: false,
      security_conclusion_verified: false,
      scan_provenance: {
        origin: 'recorded_capture_unsigned',
        independently_attested: false,
        source_capture_verified: true,
        exit_capture_verified: true,
        recorded_engine_exit: 0,
      },
      scan_summary: {
        scan_id: 'scan-1',
        data_origin: 'REAL_SCAN',
        qwen_runtime_verified: false,
        model_runtime_verified: false,
        security_conclusion_verified: false,
        scan_provenance: {
          origin: 'recorded_capture_unsigned',
          independently_attested: false,
          source_capture_verified: true,
          exit_capture_verified: true,
          recorded_engine_exit: 0,
        },
        java_files_scanned: 19,
        total_findings: 2,
        by_validated_status: {SUPPORTED: 0, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 1, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 1},
        proposed_refuted_open_count: 1,
      },
      audit_trail: {
        events_count: auditEvents.length,
        rejected_decisions_count: rejectedDecisions.length,
        events: auditEvents,
        rejected_decisions: rejectedDecisions,
      },
      findings: [
        {
          finding_id: 'f-1',
          scan_id: 'scan-1',
          cwe: 'CWE-89',
          validated_status: 'REFUTED',
          human_review_state: 'CONFIRMED_FALSE',
          citation_check: 'MATCHED',
          assessment: {
            validated_status: 'REFUTED',
            security_conclusion_verified: false,
            runtime: {model_runtime_verified: false},
          },
        },
        {
          finding_id: 'f-2',
          scan_id: 'scan-1',
          cwe: 'CWE-22',
          validated_status: 'REFUTED',
          human_review_state: 'OPEN',
          citation_check: 'MATCHED',
          assessment: {
            validated_status: 'REFUTED',
            security_conclusion_verified: false,
            runtime: {model_runtime_verified: false},
          },
        },
      ],
    };
    const report = reportMod.buildReportViewModel(rawReportDoc, {expectedScanId: 'scan-1'});

    assert.equal(report.canExportVerifiedReport, true);
    assert.equal(report.isVerifiedRealScan, true);
    assert.equal(report.qwenStats.runtimeVerified, false);
    assert.equal(report.opengrepStats.provenance.independently_attested, false);
    assert.equal(rawReportDoc.security_conclusion_verified, false);
    assert.equal(report.humanReviewStats.confirmedFalse, 1);
    assert.equal(report.humanReviewStats.unreviewedOpen, 1);
    assert.equal(report.humanReviewStats.refutedStillOpen, 1);
    assert.equal(report.qwenStats.refuted, 2);
    assert.equal(report.humanReviewStats.rejectedCount, 1);
  } finally {
    global.fetch = prevFetch;
    global.window = prevWindow;
    global.sessionStorage = prevSession;
    global.localStorage = prevLocal;
  }
});

test('Static & UI regression guards: outdated health copy removed, Badge forwards className, status tokens nowrap, ReviewPage preserves 409 alert on reload', () => {
  const appShellCode = fs.readFileSync(path.join(SRC_ROOT, 'components/layout/AppShell.jsx'), 'utf8');
  const statusPageCode = fs.readFileSync(path.join(SRC_ROOT, 'pages/StatusPage.jsx'), 'utf8');
  const uiCode = fs.readFileSync(path.join(SRC_ROOT, 'components/common/Ui.jsx'), 'utf8');
  const cssCode = fs.readFileSync(path.join(SRC_ROOT, 'styles/v2-monochrome-system.css'), 'utf8');
  const reviewPageCode = fs.readFileSync(path.join(SRC_ROOT, 'pages/ReviewPage.jsx'), 'utf8');
  const findingsCode = fs.readFileSync(path.join(SRC_ROOT, 'pages/LiveFindings.jsx'), 'utf8');

  // Outdated health check descriptions removed
  assert(!appShellCode.includes('chủ động không gọi binary OpenGrep'));
  assert(!statusPageCode.includes('không chạy thử tiến trình OpenGrep'));
  // Shared health source across AppShell and StatusPage
  assert(appShellCode.includes('createHealthMonitor'));
  assert(statusPageCode.includes('outlet.backend'));

  // Badge forwards className for v2-status-token nowrap protection
  assert(uiCode.includes('className = \'\''));
  assert(cssCode.includes('.badge.v2-status-token'));
  assert(cssCode.includes('word-break: keep-all'));
  assert(cssCode.includes('.v2-rm-playhead:not(.is-measured)'));

  // ReviewPage keeps queue data when refreshing same scope so 409 STALE_SOURCE alert stays mounted
  assert(reviewPageCode.includes('prev.scopeKey === scopeKey'));

  // LiveFindings no longer hardcodes citation-only blame for all UNDETERMINED downgrades
  assert(!findingsCode.includes('bị hạ xuống <code>UNDETERMINED</code> do thiếu trích dẫn'));
});
