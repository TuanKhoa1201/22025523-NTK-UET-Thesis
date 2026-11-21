/**
 * Remotion-inspired deterministic animation & timeline engine for the 6-stage backend visualizer.
 * Implements spring() physics, interpolate() multi-stop mapping, and frame-indexed Sequence ranges
 * synchronized with real backend stage telemetry (duration_ms, active_stage, running_elapsed_ms).
 */

export const TIMELINE_FPS = 60;
export const DEFAULT_STAGE_FRAMES = 180; // 3.0s per stage in preview mode
export const TOTAL_COMPOSITION_FRAMES = 1080; // 18.0s normalized replay composition

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
    // Underdamped spring
    const wd = w0 * Math.sqrt(1 - zeta * zeta);
    const env = Math.exp(-zeta * w0 * t);
    value = 1 - env * (Math.cos(wd * t) + ((zeta * w0) / wd) * Math.sin(wd * t));
  } else if (Math.abs(zeta - 1) < 1e-4) {
    // Critically damped
    value = 1 - Math.exp(-w0 * t) * (1 + w0 * t);
  } else {
    // Overdamped
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

/**
 * Formats measured backend stage duration cleanly in Vietnamese.
 */
export function formatCompactDuration(ms) {
  if (ms === null || ms === undefined || ms === '') return '—';
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1000) {
    return `${n.toLocaleString('vi-VN', {maximumFractionDigits: n < 10 ? 1 : 0})} ms`;
  }
  const sec = n / 1000;
  if (sec < 60) {
    return `${sec.toLocaleString('vi-VN', {minimumFractionDigits: 1, maximumFractionDigits: 1})} giây`;
  }
  const min = Math.floor(sec / 60);
  const rem = Math.round(sec % 60);
  return `${min}p ${String(rem).padStart(2, '0')}s`;
}

/**
 * Formats playback timecode MM:SS.d matching Remotion Studio's timeline clock.
 */
export function formatTimecode(ms) {
  const safe = Math.max(0, Number(ms) || 0) / 1000;
  const mins = Math.floor(safe / 60);
  const secs = safe - mins * 60;
  return `${String(mins).padStart(2, '0')}:${secs.toFixed(1).padStart(4, '0')}`;
}

/**
 * Builds proportional Remotion-style Sequence spans for all 6 backend stages.
 * Preserves 100% real backend duration_ms and sharePct while guaranteeing a readable
 * minimum interactive track width for sub-second stages vs multi-second LLM inference.
 */
export function buildStageTimeline(resolvedStages, {totalFrames = TOTAL_COMPOSITION_FRAMES} = {}) {
  const list = Array.isArray(resolvedStages) && resolvedStages.length > 0 ? resolvedStages : [];
  const count = list.length || 6;

  const measuredDurations = list.map((s) => {
    if (typeof s?.duration === 'number' && Number.isFinite(s.duration) && s.duration >= 0) {
      return s.duration;
    }
    if (s?.cat === 'RUNNING' && typeof s?.elapsed === 'number' && Number.isFinite(s.elapsed) && s.elapsed >= 0) {
      return s.elapsed;
    }
    return null;
  });

  const totalMeasuredMs = measuredDurations.reduce((acc, v) => (v !== null ? acc + v : acc), 0);
  const hasRealTiming = measuredDurations.some((v) => v !== null && v > 0);

  // Compute readable visual weights (real logarithmic-blended proportion with floor so fast stages stay clickable)
  let visualWeights;
  if (hasRealTiming) {
    const rawShares = measuredDurations.map((d) => {
      if (d === null || d <= 0) return 0.08;
      // Blend 55% linear real ratio + 45% log-scaled weight so 70s Qwen doesn't crush 15ms SQLite to 0px
      const linearRatio = d / Math.max(1, totalMeasuredMs);
      const logWeight = Math.log10(d + 10);
      return {linearRatio, logWeight};
    });
    const logSum = rawShares.reduce((acc, item) => acc + (typeof item === 'number' ? item : item.logWeight), 0) || 1;
    const blended = rawShares.map((item) => {
      if (typeof item === 'number') return 0.115;
      const logRatio = item.logWeight / logSum;
      return Math.max(0.115, item.linearRatio * 0.52 + logRatio * 0.48);
    });
    const weightSum = blended.reduce((acc, w) => acc + w, 0) || 1;
    visualWeights = blended.map((w) => w / weightSum);
  } else {
    visualWeights = Array.from({length: count}, () => 1 / count);
  }

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
    const sharePct = hasRealTiming && measuredMs !== null && totalMeasuredMs > 0
      ? (measuredMs / totalMeasuredMs) * 100
      : null;

    return {
      index: idx,
      stage,
      fromFrame,
      endFrame,
      durationInFrames,
      visualPct: (durationInFrames / totalFrames) * 100,
      measuredMs,
      sharePct,
    };
  });

  return {
    totalFrames,
    fps: TIMELINE_FPS,
    totalMeasuredMs,
    hasRealTiming,
    segments,
  };
}

/**
 * Resolves which stage sequence owns a given global composition frame, plus local frame & 0..1 progress.
 */
export function resolveFrameLocation(timeline, globalFrame) {
  const clamped = Math.max(0, Math.min(timeline.totalFrames - 1, Number(globalFrame) || 0));
  for (const seg of timeline.segments) {
    if (clamped >= seg.fromFrame && clamped < seg.endFrame) {
      const localFrame = clamped - seg.fromFrame;
      const localProgress = Math.max(0, Math.min(1, localFrame / Math.max(1, seg.durationInFrames - 1)));
      return {
        stageIndex: seg.index,
        segment: seg,
        localFrame,
        localProgress,
        globalProgress: clamped / Math.max(1, timeline.totalFrames - 1),
      };
    }
  }
  const fallback = timeline.segments[timeline.segments.length - 1];
  return {
    stageIndex: fallback?.index ?? 0,
    segment: fallback,
    localFrame: 0,
    localProgress: 1,
    globalProgress: 1,
  };
}

/**
 * Maps a composition frame back to an honest backend-equivalent timestamp when real stage durations exist.
 */
export function frameToBackendMs(timeline, globalFrame) {
  if (!timeline?.hasRealTiming) {
    return (Math.max(0, Number(globalFrame) || 0) / TIMELINE_FPS) * 1000;
  }
  const loc = resolveFrameLocation(timeline, globalFrame);
  let elapsed = 0;
  for (let i = 0; i < loc.stageIndex; i += 1) {
    const ms = timeline.segments[i]?.measuredMs;
    if (typeof ms === 'number' && Number.isFinite(ms) && ms > 0) {
      elapsed += ms;
    }
  }
  const curMs = loc.segment?.measuredMs;
  if (typeof curMs === 'number' && Number.isFinite(curMs) && curMs > 0) {
    elapsed += curMs * loc.localProgress;
  }
  return elapsed;
}
