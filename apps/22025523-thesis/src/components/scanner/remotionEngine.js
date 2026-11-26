/**
 * Remotion-inspired deterministic animation & timeline engine for the 6-stage backend visualizer.
 * Implements spring() physics, interpolate() multi-stop mapping, strict PREVIEW / LIVE / PLAYBACK
 * mode separation, DOM-measured playhead geometry, and honest backend duration/telemetry formatting.
 */

export const TIMELINE_FPS = 60;
export const DEFAULT_STAGE_FRAMES = 180; // 3.0s per stage in preview mode
export const TOTAL_COMPOSITION_FRAMES = 1080; // 18.0s normalized replay composition

export const TIMELINE_MODES = Object.freeze({
  PREVIEW: 'PREVIEW',
  LIVE: 'LIVE',
  PLAYBACK: 'PLAYBACK',
});

export const Easing = Object.freeze({
  linear: (t) => t,
  easeOutCubic: (t) => 1 - ((1 - t) ** 3),
  easeInOutCubic: (t) => (t < 0.5 ? 4 * t * t * t : 1 - (((-2 * t + 2) ** 3) / 2)),
  easeOutQuart: (t) => 1 - ((1 - t) ** 4),
  easeInOutSine: (t) => -(Math.cos(Math.PI * t) - 1) / 2,
});

/**
 * Physics-based spring solver modeled after Remotion's spring({ frame, fps, config }).
 * Returns a deterministic value starting at 0 and settling at 1.
 */
export function spring({
  frame,
  fps = TIMELINE_FPS,
  delay = 0,
  config = {},
} = {}) {
  const {
    damping = 14,
    stiffness = 120,
    mass = 1,
    overshootClamping = false,
  } = config;

  const tFrame = Number(frame) - Number(delay);
  if (!Number.isFinite(tFrame) || tFrame <= 0) return 0;

  const t = tFrame / Math.max(1, Number(fps) || TIMELINE_FPS);
  const m = Math.max(0.05, mass);
  const k = Math.max(1, stiffness);
  const c = Math.max(0.1, damping);

  const w0 = Math.sqrt(k / m);
  const zeta = c / (2 * Math.sqrt(k * m));

  let value;
  if (zeta < 1) {
    const wd = w0 * Math.sqrt(1 - zeta * zeta);
    const env = Math.exp(-zeta * w0 * t);
    value = 1 - env * (Math.cos(wd * t) + ((zeta * w0) / wd) * Math.sin(wd * t));
  } else if (Math.abs(zeta - 1) < 1e-4) {
    value = 1 - Math.exp(-w0 * t) * (1 + w0 * t);
  } else {
    const r = Math.sqrt(zeta * zeta - 1);
    const r1 = -w0 * (zeta - r);
    const r2 = -w0 * (zeta + r);
    const c2 = r1 / (r1 - r2);
    const c1 = 1 - c2;
    value = 1 - (c1 * Math.exp(r1 * t) + c2 * Math.exp(r2 * t));
  }

  if (overshootClamping) {
    return Math.max(0, Math.min(1, value));
  }
  return Math.abs(1 - value) < 1e-4 && t > 1.2 ? 1 : value;
}

/**
 * Multi-stop interpolation modeled after Remotion's interpolate(input, inputRange, outputRange, options).
 */
export function interpolate(
  input,
  inputRange,
  outputRange,
  {
    extrapolateLeft = 'clamp',
    extrapolateRight = 'clamp',
    easing = Easing.linear,
  } = {},
) {
  if (!Array.isArray(inputRange) || !Array.isArray(outputRange) || inputRange.length < 2 || inputRange.length !== outputRange.length) {
    return outputRange?.[0] ?? 0;
  }
  const value = Number(input);
  if (!Number.isFinite(value)) return outputRange[0];

  const last = inputRange.length - 1;
  if (value <= inputRange[0]) {
    if (extrapolateLeft === 'clamp') return outputRange[0];
    const span = inputRange[1] - inputRange[0];
    if (span === 0) return outputRange[0];
    const ratio = (value - inputRange[0]) / span;
    return outputRange[0] + ratio * (outputRange[1] - outputRange[0]);
  }
  if (value >= inputRange[last]) {
    if (extrapolateRight === 'clamp') return outputRange[last];
    const span = inputRange[last] - inputRange[last - 1];
    if (span === 0) return outputRange[last];
    const ratio = (value - inputRange[last - 1]) / span;
    return outputRange[last - 1] + ratio * (outputRange[last] - outputRange[last - 1]);
  }

  let seg = 0;
  for (let i = 0; i < last; i += 1) {
    if (value >= inputRange[i] && value <= inputRange[i + 1]) {
      seg = i;
      break;
    }
  }
  const span = inputRange[seg + 1] - inputRange[seg];
  const rawProgress = span === 0 ? 0 : (value - inputRange[seg]) / span;
  const eased = typeof easing === 'function' ? easing(rawProgress) : rawProgress;
  return outputRange[seg] + eased * (outputRange[seg + 1] - outputRange[seg]);
}

function finiteNonNegative(value) {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/**
 * Unambiguous Vietnamese duration formatter across ms, seconds, and minutes.
 * Never pads trailing ",000 ms" (e.g. 32 ms stays "32 ms", never "32,000 ms").
 */
export function formatDurationMs(ms, {emptyLabel = 'Chưa có số liệu thời lượng', compact = false} = {}) {
  const n = finiteNonNegative(ms);
  if (n === null) return emptyLabel;
  if (n === 0) return '0 ms';
  if (n < 1000) {
    if (n < 10 && !Number.isInteger(n)) {
      return `${n.toLocaleString('vi-VN', {minimumFractionDigits: 1, maximumFractionDigits: 1})} ms`;
    }
    return `${Math.round(n)} ms`;
  }
  const sec = n / 1000;
  if (sec < 60) {
    return `${sec.toLocaleString('vi-VN', {minimumFractionDigits: 1, maximumFractionDigits: 1})} giây`;
  }
  const totalSec = Math.round(sec);
  const mins = Math.floor(totalSec / 60);
  const rem = totalSec % 60;
  if (compact) {
    return `${mins}p ${String(rem).padStart(2, '0')}s`;
  }
  return rem === 0 ? `${mins} phút` : `${mins} phút ${rem} giây`;
}

/**
 * Formats measured backend stage duration cleanly in Vietnamese.
 */
export function formatCompactDuration(ms) {
  return formatDurationMs(ms, {emptyLabel: '—', compact: true});
}

/**
 * Formats playback timecode MM:SS.d matching Remotion Studio's timeline clock.
 */
export function formatTimecode(ms) {
  const safe = Math.max(0, Number(ms) || 0) / 1000;
  const mins = Math.floor(safe / 60);
  const secs = safe - mins * 60;
  // Guard against floating-point rollover like "00:60.0"
  if (Number(secs.toFixed(1)) >= 60) {
    return `${String(mins + 1).padStart(2, '0')}:00.0`;
  }
  return `${String(mins).padStart(2, '0')}:${secs.toFixed(1).padStart(4, '0')}`;
}

const LIVE_TRACKING_STATES = new Set([
  'SUBMITTING',
  'WAITING_FOR_RESPONSE',
  'QUEUED',
  'RUNNING',
  'LOADING_RESULTS',
  'VERIFYING',
  'INTERRUPTED',
]);

const TERMINAL_PLAYBACK_STATES = new Set([
  'COMPLETED',
  'FAILED',
  'CANCELLED',
  'CANCELED',
  'RESULTS_ERROR',
]);

/**
 * Resolves the authoritative visualizer mode:
 * - PREVIEW: illustrative walk-through before any scan job is active or completed
 * - LIVE: real-time backend tracking while a scan job is queued/running
 * - PLAYBACK: replay / inspection of a finished (COMPLETED / FAILED / CANCELLED) job
 */
export function resolveTimelineMode({liveJob = null, live = null, running = false} = {}) {
  const jobState = String(liveJob?.state || live?.state || '').toUpperCase();
  const liveStage = String(live?.stage || '').toUpperCase();
  if (running || LIVE_TRACKING_STATES.has(jobState) || LIVE_TRACKING_STATES.has(liveStage)) {
    return TIMELINE_MODES.LIVE;
  }
  if (
    live?.resultsReady === true ||
    TERMINAL_PLAYBACK_STATES.has(jobState) ||
    TERMINAL_PLAYBACK_STATES.has(liveStage) ||
    Boolean(liveJob)
  ) {
    return TIMELINE_MODES.PLAYBACK;
  }
  return TIMELINE_MODES.PREVIEW;
}

/**
 * Resolves the authoritative E2E duration in milliseconds from real API fields only.
 * Never uses job_timeout_seconds (e.g. 600s) as measured scan duration.
 */
export function resolveAuthoritativeE2eMs({backendMs = null, liveJob = null} = {}) {
  const direct = finiteNonNegative(backendMs);
  if (direct !== null) return direct;
  const fromJob = finiteNonNegative(liveJob?.total_e2e_duration_ms);
  if (fromJob !== null) return fromJob;
  return null;
}

const EXECUTED_CATS = new Set(['COMPLETED', 'DEGRADED', 'FAILED']);

/**
 * Builds 6-stage timeline segments separating:
 * - Real backend duration_ms (`measuredMs`, strictly null when absent — never fabricated)
 * - Real E2E share (`sharePct`, null whenever `measuredMs === null` or E2E denominator unknown)
 * - Readable visual layout width (`visualPct`, purely for UI clickability — never shown as % share)
 */
export function buildStageTimeline(
  resolvedStages,
  {totalFrames = TOTAL_COMPOSITION_FRAMES, totalE2eMs = null, mode = TIMELINE_MODES.PREVIEW} = {},
) {
  const list = Array.isArray(resolvedStages) && resolvedStages.length > 0 ? resolvedStages : [];
  const count = list.length || 6;
  const normalizedE2eMs = mode === TIMELINE_MODES.PLAYBACK ? finiteNonNegative(totalE2eMs) : null;

  const measuredDurations = list.map((s) => {
    if (mode === TIMELINE_MODES.PREVIEW) return null;
    const explicit = finiteNonNegative(s?.duration);
    if (explicit !== null) return explicit;
    return null;
  });

  const totalMeasuredMs = measuredDurations.reduce((acc, v) => (v !== null ? acc + v : acc), 0);
  const measuredCount = measuredDurations.filter((v) => v !== null).length;
  const hasRealTiming = mode !== TIMELINE_MODES.PREVIEW && (measuredCount > 0 || normalizedE2eMs !== null);
  const positiveMeasuredSum = measuredDurations.reduce((acc, v) => (v !== null && v > 0 ? acc + v : acc), 0);

  // Visual layout weights keep extreme stage durations (e.g. 18ms vs 164s) readable and clickable.
  // These weights are strictly for track layout and are NEVER presented as real timing percentages.
  let visualWeights;
  if (positiveMeasuredSum > 0) {
    const rawShares = measuredDurations.map((d) => {
      if (d === null || d <= 0) return null;
      const linearRatio = d / positiveMeasuredSum;
      const logWeight = Math.log10(d + 10);
      return {linearRatio, logWeight};
    });
    const logSum = rawShares.reduce((acc, item) => acc + (item ? item.logWeight : 1), 0) || 1;
    const blended = rawShares.map((item) => {
      if (!item) return 0.115;
      const logRatio = item.logWeight / logSum;
      return Math.max(0.115, item.linearRatio * 0.52 + logRatio * 0.48);
    });
    const weightSum = blended.reduce((acc, w) => acc + w, 0) || 1;
    visualWeights = blended.map((w) => w / weightSum);
  } else {
    visualWeights = Array.from({length: count}, () => 1 / count);
  }

  // Share % denominator: only valid in PLAYBACK when real E2E duration is known (or all executed stages measured)
  const executedStages = list.filter((s) => EXECUTED_CATS.has(s?.cat));
  const allExecutedMeasured = executedStages.length > 0
    && executedStages.every((s) => finiteNonNegative(s?.duration) !== null);
  const shareDenominatorMs = mode === TIMELINE_MODES.PLAYBACK
    ? (normalizedE2eMs !== null && normalizedE2eMs > 0
      ? normalizedE2eMs
      : (allExecutedMeasured && totalMeasuredMs > 0 ? totalMeasuredMs : null))
    : null;

  let cursor = 0;
  const segments = list.map((stage, idx) => {
    const isLast = idx === count - 1;
    const durationInFrames = isLast
      ? Math.max(1, totalFrames - cursor)
      : Math.max(30, Math.round(visualWeights[idx] * totalFrames));
    const fromFrame = cursor;
    const endFrame = fromFrame + durationInFrames;
    cursor = endFrame;

    const measuredMs = measuredDurations[idx];
    const hasMeasuredDuration = measuredMs !== null;
    const stageExecuted = mode !== TIMELINE_MODES.PREVIEW && EXECUTED_CATS.has(stage?.cat);
    const sharePct = hasMeasuredDuration && shareDenominatorMs !== null && shareDenominatorMs > 0
      ? Math.min(100, (measuredMs / shareDenominatorMs) * 100)
      : (hasMeasuredDuration && normalizedE2eMs === 0 && measuredMs === 0 ? 0 : null);

    return {
      index: idx,
      stage,
      fromFrame,
      endFrame,
      durationInFrames,
      visualPct: (durationInFrames / totalFrames) * 100,
      measuredMs,
      hasMeasuredDuration,
      stageExecuted,
      sharePct,
    };
  });

  return {
    mode,
    totalFrames,
    fps: TIMELINE_FPS,
    totalMeasuredMs,
    totalE2eMs: normalizedE2eMs,
    hasRealTiming,
    isLayoutNormalized: positiveMeasuredSum > 0,
    segments,
  };
}

/**
 * Resolves which stage sequence owns a given global composition frame, plus local frame & 0..1 progress.
 */
export function resolveFrameLocation(timeline, globalFrame) {
  const maxFrame = Math.max(0, (timeline?.totalFrames || TOTAL_COMPOSITION_FRAMES) - 1);
  const clamped = Math.max(0, Math.min(maxFrame, Number(globalFrame) || 0));
  const segments = Array.isArray(timeline?.segments) ? timeline.segments : [];
  for (let i = 0; i < segments.length; i += 1) {
    const seg = segments[i];
    const isLast = i === segments.length - 1;
    if (clamped >= seg.fromFrame && (clamped < seg.endFrame || (isLast && clamped <= seg.endFrame))) {
      const localFrame = clamped - seg.fromFrame;
      const denom = Math.max(1, seg.durationInFrames - 1);
      const localProgress = isLast && clamped >= maxFrame
        ? 1
        : Math.max(0, Math.min(1, localFrame / denom));
      return {
        stageIndex: seg.index,
        segment: seg,
        localFrame,
        localProgress,
        globalProgress: maxFrame > 0 ? clamped / maxFrame : 0,
      };
    }
  }
  const fallback = segments[segments.length - 1];
  return {
    stageIndex: fallback?.index ?? 0,
    segment: fallback,
    localFrame: fallback ? Math.max(0, fallback.durationInFrames - 1) : 0,
    localProgress: 1,
    globalProgress: 1,
  };
}

/**
 * Computes exact pixel geometry of the vertical playhead marker directly from rendered DOM
 * segment boxes (accounting for actual segment widths, flexbox/grid gaps, padding, resize, zoom).
 * Guarantees playhead stays within the active stage span and never overflows the timeline box.
 */
export function computePlayheadGeometry({
  segmentRects = null,
  containerWidth = 0,
  frameLoc = null,
  timeline = null,
  fallbackPadding = 4,
  fallbackGap = 4,
} = {}) {
  const idx = frameLoc?.stageIndex ?? 0;
  const localProgress = Math.max(0, Math.min(1, Number(frameLoc?.localProgress) || 0));
  const rects = Array.isArray(segmentRects) ? segmentRects : [];
  const validRects = rects.filter((r) => r && Number.isFinite(r.left) && Number.isFinite(r.width) && r.width > 0);
  const activeRect = rects[idx];

  if (activeRect && Number.isFinite(activeRect.left) && Number.isFinite(activeRect.width) && activeRect.width > 0 && validRects.length > 0) {
    const firstTop = validRects[0].top ?? 0;
    const isMultiRow = validRects.some((r) => Math.abs((r.top ?? 0) - firstTop) > 6);
    const minLeft = isMultiRow ? activeRect.left + 1 : Math.min(...validRects.map((r) => r.left)) + 1;
    const maxRight = isMultiRow
      ? activeRect.left + activeRect.width - 1
      : Math.max(...validRects.map((r) => r.left + r.width)) - 1;
    const upperContainerBound = Number.isFinite(containerWidth) && containerWidth > 2
      ? Math.min(maxRight, containerWidth - 2)
      : maxRight;
    const safeMin = Math.min(minLeft, upperContainerBound);
    const rawX = activeRect.left + localProgress * activeRect.width;
    const leftPx = Math.max(safeMin, Math.min(upperContainerBound, rawX));

    return {
      measured: true,
      isMultiRow,
      leftPx,
      topPx: isMultiRow && Number.isFinite(activeRect.top) ? activeRect.top : 0,
      heightPx: isMultiRow && Number.isFinite(activeRect.height) && activeRect.height > 0 ? activeRect.height : null,
      leftPct: containerWidth > 0 ? (leftPx / containerWidth) * 100 : 0,
    };
  }

  // Deterministic math fallback for SSR / pre-layout render (accounts for padding & gaps)
  const segments = Array.isArray(timeline?.segments) ? timeline.segments : [];
  const count = segments.length || 6;
  const approxW = containerWidth > 0 ? containerWidth : 1000;
  const totalGaps = Math.max(0, count - 1) * fallbackGap;
  const usableW = Math.max(1, approxW - fallbackPadding * 2 - totalGaps);
  let cursor = fallbackPadding;
  let targetLeft = fallbackPadding;
  let targetWidth = usableW / count;
  for (let i = 0; i < count; i += 1) {
    const w = ((segments[i]?.visualPct ?? (100 / count)) / 100) * usableW;
    if (i === idx) {
      targetLeft = cursor;
      targetWidth = w;
      break;
    }
    cursor += w + fallbackGap;
  }
  const rawX = targetLeft + localProgress * targetWidth;
  const clampedX = Math.max(fallbackPadding + 1, Math.min(approxW - fallbackPadding - 1, rawX));
  return {
    measured: false,
    isMultiRow: false,
    leftPx: clampedX,
    topPx: 0,
    heightPx: null,
    leftPct: (clampedX / approxW) * 100,
  };
}

/**
 * Maps a composition frame to a monotonically non-decreasing playback timestamp in [0, totalE2eMs].
 * In PLAYBACK with real API E2E duration, guarantees current <= totalE2eMs and exact match at end.
 */
export function frameToBackendMs(timeline, globalFrame, {totalE2eMs = null} = {}) {
  const maxFrame = Math.max(1, (timeline?.totalFrames || TOTAL_COMPOSITION_FRAMES) - 1);
  const clamped = Math.max(0, Math.min(maxFrame, Number(globalFrame) || 0));
  const mode = timeline?.mode || TIMELINE_MODES.PREVIEW;

  if (mode === TIMELINE_MODES.PREVIEW) {
    return (clamped / TIMELINE_FPS) * 1000;
  }

  const authoritativeTotal = finiteNonNegative(totalE2eMs) ?? finiteNonNegative(timeline?.totalE2eMs);
  if (authoritativeTotal === null) {
    return null;
  }
  if (authoritativeTotal === 0 || clamped === 0) return 0;
  if (clamped >= maxFrame) return authoritativeTotal;

  const segments = Array.isArray(timeline?.segments) ? timeline.segments : [];
  if (segments.length === 0) return (clamped / maxFrame) * authoritativeTotal;

  // Allocate exact authoritativeTotal across all segments so sum(weights) === authoritativeTotal:
  // measured stages keep their measured proportion; any remaining E2E overhead (e.g. unmeasured Stage 5)
  // is distributed cleanly across executed-without-timing stages or proportionally, never exceeding total.
  const measuredSum = segments.reduce((acc, seg) => acc + (seg.measuredMs !== null && seg.measuredMs > 0 ? seg.measuredMs : 0), 0);
  const unmeasuredExecuted = segments.filter((seg) => seg.stageExecuted && seg.measuredMs === null);
  let stageBudgets;

  if (measuredSum > 0 && measuredSum <= authoritativeTotal) {
    const remainder = authoritativeTotal - measuredSum;
    if (remainder > 0 && unmeasuredExecuted.length > 0) {
      const shareRem = remainder / unmeasuredExecuted.length;
      stageBudgets = segments.map((seg) => {
        if (seg.measuredMs !== null && seg.measuredMs > 0) return seg.measuredMs;
        if (seg.stageExecuted && seg.measuredMs === null) return shareRem;
        return 0;
      });
    } else {
      const scale = authoritativeTotal / measuredSum;
      stageBudgets = segments.map((seg) => (seg.measuredMs !== null && seg.measuredMs > 0 ? seg.measuredMs * scale : 0));
    }
  } else if (measuredSum > authoritativeTotal) {
    // Stage sum slightly exceeds totalE2eMs due to overlap/rounding: normalize strictly within [0, authoritativeTotal]
    const scale = authoritativeTotal / measuredSum;
    stageBudgets = segments.map((seg) => (seg.measuredMs !== null && seg.measuredMs > 0 ? seg.measuredMs * scale : 0));
  } else {
    // No individual stage timing available, only totalE2eMs: distribute by visual frame span
    stageBudgets = segments.map((seg) => (seg.durationInFrames / (timeline.totalFrames || TOTAL_COMPOSITION_FRAMES)) * authoritativeTotal);
  }

  const loc = resolveFrameLocation(timeline, clamped);
  let elapsed = 0;
  for (let i = 0; i < loc.stageIndex; i += 1) {
    elapsed += stageBudgets[i] || 0;
  }
  elapsed += (stageBudgets[loc.stageIndex] || 0) * loc.localProgress;
  return Math.max(0, Math.min(authoritativeTotal, elapsed));
}

/**
 * Honest compact sub-label for each segment in the 6-stage timeline track.
 * Never prints synthetic visualPct (8%, 9%, 17%) as real stage timing.
 */
export function resolveStageTrackSubLabel(seg, mode = TIMELINE_MODES.PREVIEW) {
  if (mode === TIMELINE_MODES.PREVIEW) return 'minh họa';
  if (seg?.measuredMs !== null && seg?.measuredMs !== undefined) {
    return formatDurationMs(seg.measuredMs, {compact: true});
  }
  const cat = seg?.stage?.cat;
  if (cat === 'RUNNING') return 'đang chạy…';
  if (cat === 'SKIPPED') return 'bỏ qua';
  if (cat === 'CANCELLED') return 'đã hủy';
  if (cat === 'FAILED') return 'thất bại';
  if (cat === 'COMPLETED' || cat === 'DEGRADED') return 'chưa đo thời lượng';
  return 'chưa chạy';
}
