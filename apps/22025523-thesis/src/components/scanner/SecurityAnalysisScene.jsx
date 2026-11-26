import {useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState} from 'react';
import {Badge, Icon} from '../common/Ui';
import {scanGuide} from '../../data/scanGuide';
import {resolveStages} from '../../services/jobModel';
import ScanStageVisual from './ScanStageVisual';
import {backendStageStatus, isLiveSessionReady} from './liveStagePresentation';
import {
  TIMELINE_FPS,
  TIMELINE_MODES,
  TOTAL_COMPOSITION_FRAMES,
  buildStageTimeline,
  computePlayheadGeometry,
  formatTimecode,
  frameToBackendMs,
  resolveAuthoritativeE2eMs,
  resolveFrameLocation,
  resolveStageTrackSubLabel,
  resolveTimelineMode,
} from './remotionEngine';

const TOTAL_STAGES = scanGuide.length;

const SHORT_NAMES = [
  'Tiếp nhận',
  'OpenGrep',
  'AST & SHA',
  'Qwen3.5-9B',
  'Trích dẫn',
  'SQLite',
];

function stageClassName(label, cat, isActive, isSelected) {
  const parts = [];
  if (cat === 'COMPLETED' || label.startsWith('Hoàn thành')) parts.push('is-completed');
  else if (cat === 'DEGRADED' || label.startsWith('Hoàn tất (có hạ cấp)')) parts.push('is-degraded');
  else if (cat === 'FAILED' || label.startsWith('Thất bại')) parts.push('is-failed');
  else if (cat === 'SKIPPED' || cat === 'CANCELLED' || label.startsWith('Bỏ qua') || label.startsWith('Đã hủy')) parts.push('is-skipped');
  else if (isActive || cat === 'RUNNING' || label.startsWith('Đang')) parts.push('is-running');
  if (isSelected) parts.push('is-selected');
  return parts.join(' ');
}

function stageTone(label, cat) {
  if (cat === 'COMPLETED' || label.startsWith('Hoàn thành')) return 'green';
  if (cat === 'FAILED' || label.startsWith('Thất bại')) return 'red';
  if (cat === 'DEGRADED' || cat === 'SKIPPED' || cat === 'CANCELLED' || label.startsWith('Hoàn tất (có hạ cấp)') || label.startsWith('Bỏ qua') || label.startsWith('Đã hủy')) return 'amber';
  if (cat === 'RUNNING' || label.startsWith('Đang')) return 'blue';
  return 'neutral';
}

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = (event) => setReduced(Boolean(event.matches));
    mq.addEventListener?.('change', onChange);
    return () => mq.removeEventListener?.('change', onChange);
  }, []);

  return reduced;
}

export default function SecurityAnalysisScene({
  live = null,
  liveJob = null,
  elapsedMs = 0,
  backendMs = null,
  running = false,
  noLlm = false,
}) {
  const reducedMotion = usePrefersReducedMotion();

  const resolvedStages = useMemo(() => {
    if (liveJob) return resolveStages(liveJob);
    if (Array.isArray(live?.stages) && live.stages.length > 0) {
      return resolveStages({
        state: live?.state,
        active_stage: live?.activeStage,
        stages: live.stages,
      });
    }
    return resolveStages(null);
  }, [liveJob, live?.state, live?.activeStage, live?.stages]);

  const mode = useMemo(
    () => resolveTimelineMode({liveJob, live, running}),
    [liveJob, live, running],
  );
  const isLiveMode = mode === TIMELINE_MODES.LIVE;
  const isPlaybackMode = mode === TIMELINE_MODES.PLAYBACK;
  const isPreviewMode = mode === TIMELINE_MODES.PREVIEW;

  const ready = isLiveSessionReady(live);
  const jobState = String(liveJob?.state || live?.state || '').toUpperCase();
  const liveStageStr = String(live?.stage || '').toUpperCase();
  const isFailed = jobState === 'FAILED' || liveStageStr === 'FAILED';
  const isCancelled = jobState === 'CANCELLED' || jobState === 'CANCELED' || liveStageStr === 'CANCELLED';
  const isCompleted = !isLiveMode && !isFailed && !isCancelled && (ready || jobState === 'COMPLETED' || liveStageStr === 'COMPLETED');

  // Authoritative E2E duration strictly from API total_e2e_duration_ms (never job_timeout_seconds)
  const authoritativeE2eMs = useMemo(
    () => (isPlaybackMode ? resolveAuthoritativeE2eMs({backendMs, liveJob}) : null),
    [isPlaybackMode, backendMs, liveJob],
  );

  const timeline = useMemo(
    () => buildStageTimeline(resolvedStages, {
      totalFrames: TOTAL_COMPOSITION_FRAMES,
      totalE2eMs: authoritativeE2eMs,
      mode,
    }),
    [resolvedStages, authoritativeE2eMs, mode],
  );

  const backendStage = Number(live?.activeStage);
  const hasBackendStage = Number.isInteger(backendStage) && backendStage >= 1 && backendStage <= TOTAL_STAGES;

  const backendActiveIndex = hasBackendStage
    ? backendStage - 1
    : isCompleted
      ? TOTAL_STAGES - 1
      : isLiveMode
        ? 0
        : -1;

  // In LIVE mode, user can click a stage card to inspect details (read-only) without mutating backend state.
  const [liveInspectIndex, setLiveInspectIndex] = useState(null);
  const [playing, setPlaying] = useState(false);
  const [globalFrame, setGlobalFrame] = useState(0);
  const [ambientTick, setAmbientTick] = useState(0);
  const lastTerminalSignatureRef = useRef('');

  // Keep live playhead anchored cleanly to the real backend stage & finding progress (never fake completion)
  const computeLiveAnchorFrame = useCallback((stageIdx) => {
    const safeIdx = Math.max(0, Math.min(TOTAL_STAGES - 1, stageIdx));
    const seg = timeline.segments[safeIdx];
    if (!seg) return 0;
    const processed = Number(live?.progress?.processed_findings);
    const totalFindings = Number(live?.progress?.total_findings);
    if (safeIdx === 3 && Number.isFinite(processed) && Number.isFinite(totalFindings) && totalFindings > 0) {
      const ratio = Math.min(0.95, Math.max(0.05, processed / totalFindings));
      return seg.fromFrame + Math.round(ratio * Math.max(1, seg.durationInFrames - 1));
    }
    return seg.fromFrame + Math.round(Math.max(1, seg.durationInFrames - 1) * 0.35);
  }, [timeline, live?.progress?.processed_findings, live?.progress?.total_findings]);

  // Synchronize mode transitions cleanly
  useEffect(() => {
    if (isLiveMode) {
      setPlaying(false);
      lastTerminalSignatureRef.current = '';
      if (backendActiveIndex >= 0) {
        setGlobalFrame(computeLiveAnchorFrame(backendActiveIndex));
      }
      return;
    }
    setLiveInspectIndex(null);

    if (isPlaybackMode) {
      const sig = `${liveJob?.job_id || ''}|${liveJob?.scan_id || ''}|${jobState}|${isCompleted ? 'DONE' : isFailed ? 'FAIL' : isCancelled ? 'CANCEL' : 'TERM'}`;
      if (lastTerminalSignatureRef.current !== sig) {
        lastTerminalSignatureRef.current = sig;
        setPlaying(false);
        if (isCompleted) {
          // Exact end of Stage 6 / end of timeline
          setGlobalFrame(timeline.totalFrames - 1);
        } else if ((isFailed || isCancelled) && backendActiveIndex >= 0) {
          const seg = timeline.segments[backendActiveIndex];
          if (seg) setGlobalFrame(seg.fromFrame + Math.round((seg.durationInFrames - 1) * 0.5));
        }
      }
      return;
    }

    // PREVIEW mode: reset terminal ref
    lastTerminalSignatureRef.current = '';
  }, [isLiveMode, isPlaybackMode, isCompleted, isFailed, isCancelled, backendActiveIndex, timeline, liveJob?.job_id, liveJob?.scan_id, jobState, computeLiveAnchorFrame]);

  // Deterministic 60fps animation loop:
  // - In LIVE mode: only ticks ambient visual motion; NEVER moves playhead out of active backend stage.
  // - In PREVIEW / PLAYBACK when playing: advances globalFrame; in PLAYBACK stops cleanly at exact end.
  useEffect(() => {
    if (reducedMotion) return undefined;
    const shouldTick = isLiveMode || playing;
    if (!shouldTick) return undefined;

    let rafId = 0;
    let lastTs = performance.now();

    const loop = (nowTs) => {
      const dtSec = Math.min(0.1, Math.max(0, (nowTs - lastTs) / 1000));
      lastTs = nowTs;
      const frameDelta = dtSec * TIMELINE_FPS;

      setAmbientTick((prev) => prev + frameDelta);

      if (!isLiveMode && playing) {
        setGlobalFrame((prev) => {
          const maxFrame = timeline.totalFrames - 1;
          const next = prev + frameDelta;
          if (next >= maxFrame) {
            if (isPlaybackMode) {
              setPlaying(false);
              return maxFrame;
            }
            return 0;
          }
          return next;
        });
      }

      rafId = window.requestAnimationFrame(loop);
    };

    rafId = window.requestAnimationFrame(loop);
    return () => window.cancelAnimationFrame(rafId);
  }, [reducedMotion, isLiveMode, isPlaybackMode, playing, timeline.totalFrames]);

  const effectiveGlobalFrame = isLiveMode && backendActiveIndex >= 0
    ? computeLiveAnchorFrame(backendActiveIndex)
    : globalFrame;

  const frameLoc = resolveFrameLocation(timeline, effectiveGlobalFrame);
  const displayIndex = isLiveMode
    ? (liveInspectIndex !== null ? liveInspectIndex : Math.max(0, backendActiveIndex))
    : frameLoc.stageIndex;
  const displaySegment = timeline.segments[displayIndex] || timeline.segments[0];
  const displayStage = resolvedStages[displayIndex] || null;
  const displayStep = scanGuide[displayIndex] || scanGuide[0];

  // Track stage entrance frame so spring() triggers crisply when displayed stage changes
  const [stageResetTick, setStageResetTick] = useState(0);
  const prevDisplayIdxRef = useRef(displayIndex);
  useEffect(() => {
    if (prevDisplayIdxRef.current !== displayIndex) {
      prevDisplayIdxRef.current = displayIndex;
      setStageResetTick(ambientTick);
    }
  }, [displayIndex, ambientTick]);

  const localSceneFrame = isLiveMode
    ? Math.max(0, ambientTick - stageResetTick)
    : frameLoc.localFrame;
  const motionCycle = reducedMotion ? 0.5 : ((ambientTick / (TIMELINE_FPS * 3.2)) % 1);

  // Measure real DOM segment geometry so playhead aligns accurately across unequal widths, gaps, padding, resize & zoom
  const tracksRef = useRef(null);
  const segRefs = useRef([]);
  const [trackMetrics, setTrackMetrics] = useState({containerWidth: 0, containerHeight: 0, segmentRects: []});

  const measureTracks = useCallback(() => {
    const container = tracksRef.current;
    if (!container || typeof container.getBoundingClientRect !== 'function') return;
    const cRect = container.getBoundingClientRect();
    if (!cRect || cRect.width <= 0) return;
    const rects = [];
    for (let i = 0; i < TOTAL_STAGES; i += 1) {
      const el = segRefs.current[i];
      if (!el || typeof el.getBoundingClientRect !== 'function') {
        rects.push(null);
        continue;
      }
      const r = el.getBoundingClientRect();
      rects.push({
        left: r.left - cRect.left,
        top: r.top - cRect.top,
        width: r.width,
        height: r.height,
      });
    }
    setTrackMetrics((prev) => {
      const same = prev.containerWidth === cRect.width
        && prev.containerHeight === cRect.height
        && prev.segmentRects.length === rects.length
        && rects.every((r, idx) => {
          const p = prev.segmentRects[idx];
          if (!r && !p) return true;
          if (!r || !p) return false;
          return Math.abs(r.left - p.left) < 0.5
            && Math.abs(r.top - p.top) < 0.5
            && Math.abs(r.width - p.width) < 0.5
            && Math.abs(r.height - p.height) < 0.5;
        });
      return same ? prev : {containerWidth: cRect.width, containerHeight: cRect.height, segmentRects: rects};
    });
  }, []);

  useLayoutEffect(() => {
    measureTracks();
  }, [measureTracks, timeline, mode]);

  useEffect(() => {
    const container = tracksRef.current;
    if (!container) return undefined;
    let ro = null;
    if (typeof ResizeObserver === 'function') {
      ro = new ResizeObserver(() => measureTracks());
      ro.observe(container);
      for (const el of segRefs.current) {
        if (el) ro.observe(el);
      }
    }
    const onResize = () => measureTracks();
    window.addEventListener?.('resize', onResize);
    window.visualViewport?.addEventListener?.('resize', onResize);
    return () => {
      ro?.disconnect();
      window.removeEventListener?.('resize', onResize);
      window.visualViewport?.removeEventListener?.('resize', onResize);
    };
  }, [measureTracks, timeline]);

  // Reset detail inspection cleanly whenever switching jobs/sessions.
  const jobIdentityKey = `${liveJob?.job_id || ''}|${liveJob?.scan_id || ''}`;
  useEffect(() => {
    setLiveInspectIndex(null);
  }, [jobIdentityKey]);

  // Strict separation:
  // - playheadFrameLoc ALWAYS tracks the backend execution stage in LIVE mode (or playback cursor in PREVIEW/PLAYBACK).
  // - Opening another stage's detail card updates selectedDetailIndex (`liveInspectIndex`) ONLY and NEVER moves the LIVE playhead.
  const playheadFrameLoc = frameLoc;

  const playheadGeom = useMemo(
    () => computePlayheadGeometry({
      segmentRects: trackMetrics.segmentRects,
      containerWidth: trackMetrics.containerWidth,
      containerHeight: trackMetrics.containerHeight,
      frameLoc: playheadFrameLoc,
      timeline,
    }),
    [trackMetrics, playheadFrameLoc, timeline],
  );

  const jumpToStage = useCallback((idx) => {
    const safeIdx = Math.max(0, Math.min(TOTAL_STAGES - 1, idx));
    const seg = timeline.segments[safeIdx];
    if (!seg) return;
    if (isLiveMode) {
      setLiveInspectIndex(safeIdx === backendActiveIndex ? null : safeIdx);
      setStageResetTick(ambientTick);
      return;
    }
    const offset = playing
      ? 0
      : (isCompleted && safeIdx === TOTAL_STAGES - 1
        ? Math.max(0, seg.durationInFrames - 1)
        : Math.round(Math.max(0, seg.durationInFrames - 1) * 0.5));
    setGlobalFrame(Math.min(timeline.totalFrames - 1, seg.fromFrame + offset));
    setStageResetTick(ambientTick);
  }, [timeline, isLiveMode, backendActiveIndex, ambientTick, playing, isCompleted]);

  const handleScrub = (event) => {
    const nextFrame = Math.max(0, Math.min(timeline.totalFrames - 1, Number(event.target.value) || 0));
    if (isLiveMode) {
      // In LIVE mode, scrubbing only inspects stages read-only; never overrides real backend progress
      const loc = resolveFrameLocation(timeline, nextFrame);
      setLiveInspectIndex(loc.stageIndex === backendActiveIndex ? null : loc.stageIndex);
      return;
    }
    setPlaying(false);
    setGlobalFrame(nextFrame);
  };

  const handleTogglePlay = () => {
    if (isLiveMode) return;
    setPlaying((prev) => {
      const next = !prev;
      if (next && globalFrame >= timeline.totalFrames - 2) {
        setGlobalFrame(0);
      }
      return next;
    });
  };

  const handleRelockLive = () => {
    setLiveInspectIndex(null);
  };

  const stageDisplayLabel = (idx) => (
    isPreviewMode ? 'Chế độ xem trước' : backendStageStatus(idx, live)
  );

  // Honest synchronization badge strictly separating PREVIEW / LIVE / PLAYBACK
  const syncMeta = isLiveMode
    ? {
        label: liveInspectIndex !== null
          ? `LIVE · ĐANG XEM GIAI ĐOẠN ${String(liveInspectIndex + 1).padStart(2, '0')}/06 (BACKEND TẠI ${String(Math.max(1, backendActiveIndex + 1)).padStart(2, '0')}/06)`
          : `LIVE · ĐANG ĐỒNG BỘ BACKEND THỰC · GIAI ĐOẠN ${String(Math.max(1, backendActiveIndex + 1)).padStart(2, '0')}/06`,
        tone: 'live',
      }
    : isFailed
      ? {
          label: `PLAYBACK · BACKEND DỪNG TẠI GIAI ĐOẠN ${String(Math.max(1, backendActiveIndex + 1)).padStart(2, '0')}/06 (FAILED)`,
          tone: 'failed',
        }
      : isCancelled
        ? {
            label: `PLAYBACK · PHIÊN ĐÃ HỦY TẠI GIAI ĐOẠN ${String(Math.max(1, backendActiveIndex + 1)).padStart(2, '0')}/06 (CANCELLED)`,
            tone: 'failed',
          }
        : isCompleted
          ? {
              label: authoritativeE2eMs !== null
                ? 'PLAYBACK · ĐỒNG BỘ THỜI LƯỢNG E2E THỰC TỪ API · 6 GIAI ĐOẠN'
                : 'PLAYBACK · PHIÊN ĐÃ HOÀN TẤT (CHƯA CÓ TỔNG THỜI LƯỢNG E2E)',
              tone: 'done',
            }
          : {
              label: 'PREVIEW · XEM TRƯỚC PIPELINE 6 GIAI ĐOẠN (MINH HỌA)',
              tone: 'neutral',
            };

  const playbackCurrentMs = isPlaybackMode
    ? frameToBackendMs(timeline, effectiveGlobalFrame, {totalE2eMs: authoritativeE2eMs})
    : null;
  const previewCurrentMs = isPreviewMode
    ? frameToBackendMs(timeline, effectiveGlobalFrame)
    : 0;
  const effectiveNoLlm = Boolean(noLlm || liveJob?.no_llm);

  // Keep slider aligned with backend execution frame during LIVE (inspection stays read-only via liveInspectIndex).
  const sliderValue = Math.round(effectiveGlobalFrame);

  const playheadStyle = playheadGeom.measured
    ? {
        left: `${playheadGeom.leftPx}px`,
        ...(playheadGeom.isMultiRow && playheadGeom.heightPx !== null
          ? {top: `${playheadGeom.topPx}px`, height: `${playheadGeom.heightPx}px`, bottom: 'auto'}
          : {}),
      }
    : {left: `${playheadGeom.leftPct}%`};

  return (
    <div id="scan-simulation" className="v2-rm-root" data-timeline-mode={mode} aria-live="polite">
      {live?.interrupted && (
        <div className="inline-warning" role="status" style={{marginBottom: '12px'}}>
          <Icon name="AlertTriangle" />Kết nối tạm gián đoạn — đang hiển thị trạng thái đã xác nhận gần nhất từ API.
        </div>
      )}

      {/* 1. Remotion-Style 3D Perspective Stage Theater + Synchronized Chart */}
      <ScanStageVisual
        step={displayStep}
        index={displayIndex}
        stage={displayStage ? {...displayStage, label: stageDisplayLabel(displayIndex)} : null}
        segment={displaySegment}
        mode={mode}
        localFrame={localSceneFrame}
        cycle={motionCycle}
        syncModeLabel={syncMeta.label}
        syncTone={syncMeta.tone}
        liveCounts={ready ? live?.counts : null}
        progress={live?.progress}
        noLlm={effectiveNoLlm}
        reducedMotion={reducedMotion}
      />

      {/* 2. Studio Control Deck & 6-Stage Backend Timeline */}
      <div className="v2-rm-studio-deck">
        <div className="v2-rm-controls-row">
          <div className="v2-rm-transport">
            {isLiveMode ? (
              <span className="v2-rm-live-indicator" role="status">
                <i aria-hidden="true" />
                <span>LIVE · Đang theo dõi tiến trình backend</span>
              </span>
            ) : (
              <button
                type="button"
                className="v2-rm-btn v2-rm-btn--primary"
                onClick={handleTogglePlay}
                disabled={reducedMotion}
                aria-label={playing ? 'Tạm dừng phát lại' : isPlaybackMode ? 'Phát lại 6 giai đoạn' : 'Xem trước mô phỏng 6 giai đoạn'}
              >
                <Icon name={playing ? 'Pause' : 'Play'} />
                <span>
                  {playing
                    ? 'Tạm dừng'
                    : isPlaybackMode
                      ? 'Phát lại 6 giai đoạn'
                      : 'Chạy xem trước'}
                </span>
              </button>
            )}

            <button
              type="button"
              className="v2-rm-btn"
              onClick={() => jumpToStage(displayIndex - 1)}
              disabled={displayIndex <= 0}
              aria-label="Giai đoạn trước"
            >
              <Icon name="ChevronLeft" />
            </button>

            <button
              type="button"
              className="v2-rm-btn"
              onClick={() => jumpToStage(displayIndex + 1)}
              disabled={displayIndex >= TOTAL_STAGES - 1}
              aria-label="Giai đoạn tiếp theo"
            >
              <Icon name="ChevronRight" />
            </button>

            {isLiveMode && liveInspectIndex !== null && (
              <button type="button" className="v2-rm-btn v2-rm-btn--sync" onClick={handleRelockLive}>
                <Icon name="RotateCcw" />
                <span>Quay về tiến trình LIVE</span>
              </button>
            )}
          </div>

          <div className="v2-rm-timecode-readout mono" data-testid="timeline-clock">
            <Icon name="Clock" />
            {isLiveMode ? (
              <span>
                <strong>{formatTimecode(elapsedMs)}</strong>
                <small> · đang theo dõi (LIVE)</small>
              </span>
            ) : isPlaybackMode ? (
              authoritativeE2eMs !== null && playbackCurrentMs !== null ? (
                <span>
                  <strong>{formatTimecode(playbackCurrentMs)}</strong>
                  {Math.round(playbackCurrentMs) < Math.round(authoritativeE2eMs) && <small> (nội suy)</small>}
                  <em> / {formatTimecode(authoritativeE2eMs)}</em>
                  <small> (E2E thực từ API)</small>
                </span>
              ) : (
                <span>
                  <strong>Chưa có tổng thời lượng E2E</strong>
                  <small> · Playback</small>
                </span>
              )
            ) : (
              <span>
                <strong>{formatTimecode(previewCurrentMs)}</strong>
                <em> / {formatTimecode((timeline.totalFrames / TIMELINE_FPS) * 1000)}</em>
                <small> · Xem trước</small>
              </span>
            )}
          </div>
        </div>

        {/* Proportional 6-Stage Sequence Track with DOM-Measured Playhead Needle */}
        <div className="v2-rm-timeline-wrap">
          <div
            ref={tracksRef}
            className="v2-rm-timeline-tracks"
            role="tablist"
            aria-label="Thanh thời gian 6 giai đoạn backend"
          >
            {timeline.segments.map((seg) => {
              const label = stageDisplayLabel(seg.index);
              const catCls = isPreviewMode
                ? 'is-cat-preview'
                : (seg.stage?.cat ? `is-cat-${seg.stage.cat.toLowerCase()}` : 'is-cat-unknown');
              const isSelected = seg.index === displayIndex;
              const isLiveHere = isLiveMode && seg.index === backendActiveIndex;
              const subLabel = resolveStageTrackSubLabel(seg, mode);
              return (
                <button
                  key={scanGuide[seg.index].key}
                  ref={(el) => { segRefs.current[seg.index] = el; }}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  className={`v2-rm-track-seg ${catCls} ${isSelected ? 'is-selected' : ''} ${isLiveHere ? 'is-live' : ''}`}
                  style={{flexBasis: `${seg.visualPct}%`, flexGrow: seg.visualPct}}
                  onClick={() => jumpToStage(seg.index)}
                  title={`Giai đoạn ${String(seg.index + 1).padStart(2, '0')}: ${scanGuide[seg.index].title} (${label})`}
                >
                  <span className="v2-rm-track-top">
                    <b className="mono">{String(seg.index + 1).padStart(2, '0')}</b>
                    <span>{SHORT_NAMES[seg.index]}</span>
                  </span>
                  <span className="v2-rm-track-sub mono">{subLabel}</span>
                </button>
              );
            })}

            <div
              className={`v2-rm-playhead ${playheadGeom.measured ? 'is-measured' : ''} ${playheadGeom.isMultiRow ? 'is-multirow' : ''}`}
              style={playheadStyle}
              data-stage-index={playheadFrameLoc.stageIndex}
              data-backend-stage-index={backendActiveIndex}
              data-selected-stage-index={displayIndex}
              aria-hidden="true"
            >
              <span className="v2-rm-playhead-cap" />
            </div>
          </div>

          <input
            type="range"
            className="v2-rm-scrubber"
            min={0}
            max={timeline.totalFrames - 1}
            step={1}
            value={sliderValue}
            onChange={handleScrub}
            aria-label={isLiveMode ? 'Chọn giai đoạn để xem chi tiết (không thay đổi trạng thái LIVE)' : 'Tua tiến trình 6 giai đoạn backend'}
          />
          {timeline.isLayoutNormalized && (
            <p className="v2-rm-timeline-note">
              Độ rộng ô giai đoạn được chuẩn hóa tối thiểu để dễ quan sát; thời lượng và tỷ trọng E2E chỉ hiển thị khi có số liệu đo thực từ API.
            </p>
          )}
        </div>
      </div>

      {/* 3. Interactive 6-Stage Cards Grid (synced with backend status & clickable to inspect in 3D) */}
      <div className="v2-stage-rail" role="list" aria-label="6 giai đoạn xử lý thực tế trên backend">
        {scanGuide.map((item, index) => {
          const label = stageDisplayLabel(index);
          const seg = timeline.segments[index];
          const cat = isPreviewMode ? 'PREVIEW' : (seg?.stage?.cat || 'UNKNOWN');
          const isDone = !isPreviewMode && (cat === 'COMPLETED' || label.startsWith('Hoàn thành'));
          const isBackendCurrent = !isPreviewMode && index === backendActiveIndex && (hasBackendStage || ready || live?.stage === 'LOADING_RESULTS');
          const isSelected = index === displayIndex;
          const stateCls = stageClassName(label, cat, isBackendCurrent, isSelected);

          return (
            <button
              key={item.key}
              type="button"
              role="listitem"
              className={`v2-stage-item v2-stage-item--interactive ${stateCls}`}
              aria-current={isBackendCurrent ? 'step' : undefined}
              onClick={() => jumpToStage(index)}
            >
              <div className="v2-stage-head">
                <span className="v2-stage-num">
                  {isDone ? <Icon name="Check" /> : String(index + 1).padStart(2, '0')}
                </span>
                <Badge tone={stageTone(label, cat)}>{label}</Badge>
              </div>
              <div className="v2-stage-title">{item.title}</div>
              <div className="v2-stage-meta">
                <span>{item.purpose}</span>
              </div>
              <div className="v2-stage-foot">
                <span className="mono">{item.key}</span>
                {seg?.sharePct !== null && seg?.sharePct !== undefined ? (
                  <span className="mono v2-stage-share">{seg.sharePct.toFixed(1)}% E2E</span>
                ) : !isPreviewMode && (cat === 'COMPLETED' || cat === 'DEGRADED') && !seg?.hasMeasuredDuration ? (
                  <span className="mono v2-stage-share-missing">Chưa có số liệu thời lượng</span>
                ) : null}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
