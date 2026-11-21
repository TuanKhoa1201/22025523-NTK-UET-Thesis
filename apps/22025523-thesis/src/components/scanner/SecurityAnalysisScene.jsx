import {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {Badge, Icon} from '../common/Ui';
import {scanGuide} from '../../data/scanGuide';
import {resolveStages} from '../../services/jobModel';
import ScanStageVisual from './ScanStageVisual';
import {backendStageStatus, isLiveSessionReady} from './liveStagePresentation';
import {
  TIMELINE_FPS,
  TOTAL_COMPOSITION_FRAMES,
  buildStageTimeline,
  formatCompactDuration,
  formatTimecode,
  frameToBackendMs,
  resolveFrameLocation,
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

function stageClassName(label, isActive, isSelected) {
  const parts = [];
  if (label.startsWith('Hoàn thành')) parts.push('is-completed');
  else if (label.startsWith('Thất bại')) parts.push('is-failed');
  else if (label.startsWith('Bỏ qua')) parts.push('is-skipped');
  else if (isActive || label.startsWith('Đang')) parts.push('is-running');
  if (isSelected) parts.push('is-selected');
  return parts.join(' ');
}

function stageTone(label) {
  if (label.startsWith('Hoàn thành')) return 'green';
  if (label.startsWith('Thất bại')) return 'red';
  if (label.startsWith('Bỏ qua')) return 'amber';
  if (label.startsWith('Đang')) return 'blue';
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

  const timeline = useMemo(
    () => buildStageTimeline(resolvedStages, {totalFrames: TOTAL_COMPOSITION_FRAMES}),
    [resolvedStages],
  );

  const backendStage = Number(live?.activeStage);
  const hasBackendStage = Number.isInteger(backendStage) && backendStage >= 1 && backendStage <= TOTAL_STAGES;
  const ready = isLiveSessionReady(live);
  const jobState = String(liveJob?.state || live?.state || '').toUpperCase();
  const liveStageStr = String(live?.stage || '').toUpperCase();

  const isLiveRunning = Boolean(
    running ||
    ['SUBMITTING', 'WAITING_FOR_RESPONSE', 'QUEUED', 'RUNNING', 'LOADING_RESULTS'].includes(liveStageStr) ||
    ['QUEUED', 'RUNNING'].includes(jobState),
  );
  const isFailed = jobState === 'FAILED' || liveStageStr === 'FAILED';
  const isCompleted = ready || jobState === 'COMPLETED' || liveStageStr === 'COMPLETED';

  const backendActiveIndex = hasBackendStage
    ? backendStage - 1
    : isCompleted
      ? TOTAL_STAGES - 1
      : isLiveRunning
        ? 0
        : -1;

  // Controls whether playhead locks to live backend stage or user is manually scrubbing/replaying
  const [followLive, setFollowLive] = useState(true);
  const [playing, setPlaying] = useState(() => !reducedMotion);
  const [globalFrame, setGlobalFrame] = useState(0);
  const [ambientTick, setAmbientTick] = useState(0);
  const lastBackendIdxRef = useRef(-1);

  // When a live scan starts or advances to a new backend stage, snap smoothly when followLive is active
  useEffect(() => {
    if (isLiveRunning) {
      if (lastBackendIdxRef.current !== backendActiveIndex) {
        lastBackendIdxRef.current = backendActiveIndex;
        if (followLive && backendActiveIndex >= 0) {
          const seg = timeline.segments[backendActiveIndex];
          if (seg) {
            setGlobalFrame(seg.fromFrame);
          }
        }
      }
    } else if (isFailed && backendActiveIndex >= 0) {
      const seg = timeline.segments[backendActiveIndex];
      if (seg) {
        setGlobalFrame(seg.fromFrame + Math.round(seg.durationInFrames * 0.5));
      }
      setPlaying(false);
    } else if (isCompleted && lastBackendIdxRef.current !== 999) {
      lastBackendIdxRef.current = 999;
      // On fresh completion, jump to stage 6 (or stay ready for full proportional replay)
      const lastSeg = timeline.segments[TOTAL_STAGES - 1];
      if (lastSeg) setGlobalFrame(lastSeg.fromFrame + Math.round(lastSeg.durationInFrames * 0.65));
      setPlaying(false);
    }
  }, [isLiveRunning, isFailed, isCompleted, backendActiveIndex, followLive, timeline]);

  // Reset followLive automatically whenever a brand-new live run starts
  useEffect(() => {
    if (isLiveRunning) {
      setFollowLive(true);
    }
  }, [isLiveRunning]);

  // Remotion 60fps deterministic animation loop
  useEffect(() => {
    if (reducedMotion) return undefined;

    const shouldTick = isLiveRunning || playing;
    if (!shouldTick) return undefined;

    let rafId = 0;
    let lastTs = performance.now();

    const loop = (nowTs) => {
      const dtSec = Math.min(0.1, Math.max(0, (nowTs - lastTs) / 1000));
      lastTs = nowTs;
      const frameDelta = dtSec * TIMELINE_FPS;

      setAmbientTick((prev) => prev + frameDelta);

      if (isLiveRunning && followLive && backendActiveIndex >= 0) {
        const seg = timeline.segments[backendActiveIndex];
        if (seg) {
          // Advance playhead smoothly inside the active backend stage's track segment
          const processed = Number(live?.progress?.processed_findings);
          const totalFindings = Number(live?.progress?.total_findings);
          const hasRealInnerProgress = backendActiveIndex === 3 && Number.isFinite(processed) && Number.isFinite(totalFindings) && totalFindings > 0;

          setGlobalFrame((prev) => {
            if (hasRealInnerProgress) {
              const target = seg.fromFrame + Math.min(0.95, Math.max(0.08, processed / totalFindings)) * (seg.durationInFrames - 1);
              return prev + (target - prev) * Math.min(1, dtSec * 5);
            }
            const maxLiveFrame = seg.endFrame - 4;
            const next = prev + frameDelta * 0.55;
            if (next < seg.fromFrame) return seg.fromFrame;
            return next >= maxLiveFrame ? seg.fromFrame + seg.durationInFrames * 0.85 : next;
          });
        }
      } else if (playing) {
        setGlobalFrame((prev) => {
          const next = prev + frameDelta;
          return next >= timeline.totalFrames ? 0 : next;
        });
      }

      rafId = window.requestAnimationFrame(loop);
    };

    rafId = window.requestAnimationFrame(loop);
    return () => window.cancelAnimationFrame(rafId);
  }, [reducedMotion, isLiveRunning, followLive, backendActiveIndex, playing, timeline, live?.progress?.processed_findings, live?.progress?.total_findings]);

  const frameLoc = resolveFrameLocation(timeline, globalFrame);
  const displayIndex = isLiveRunning && followLive && backendActiveIndex >= 0
    ? backendActiveIndex
    : frameLoc.stageIndex;
  const displaySegment = timeline.segments[displayIndex] || timeline.segments[0];
  const displayStage = resolvedStages[displayIndex] || null;
  const displayStep = scanGuide[displayIndex] || scanGuide[0];

  // Track stage entrance frame so Remotion spring() triggers crisply every time displayed stage changes
  const [stageResetTick, setStageResetTick] = useState(0);
  const prevDisplayIdxRef = useRef(displayIndex);
  useEffect(() => {
    if (prevDisplayIdxRef.current !== displayIndex) {
      prevDisplayIdxRef.current = displayIndex;
      setStageResetTick(ambientTick);
    }
  }, [displayIndex, ambientTick]);

  const localSceneFrame = isLiveRunning && followLive
    ? Math.max(0, ambientTick - stageResetTick)
    : frameLoc.localFrame;
  const motionCycle = reducedMotion ? 0.5 : ((ambientTick / (TIMELINE_FPS * 3.2)) % 1);

  const jumpToStage = useCallback((idx) => {
    const safeIdx = Math.max(0, Math.min(TOTAL_STAGES - 1, idx));
    const seg = timeline.segments[safeIdx];
    if (!seg) return;
    if (isLiveRunning && safeIdx !== backendActiveIndex) {
      setFollowLive(false);
    }
    const offset = playing
      ? 2
      : Math.min(Math.max(48, Math.round(seg.durationInFrames * 0.4)), Math.max(0, seg.durationInFrames - 2));
    setGlobalFrame(seg.fromFrame + offset);
    setStageResetTick(ambientTick);
  }, [timeline, isLiveRunning, backendActiveIndex, ambientTick, playing]);

  const handleScrub = (event) => {
    const nextFrame = Number(event.target.value);
    if (isLiveRunning) setFollowLive(false);
    setPlaying(false);
    setGlobalFrame(nextFrame);
  };

  const handleTogglePlay = () => {
    if (isLiveRunning && followLive) {
      // Already locked to live backend; clicking toggles preview replay mode or re-locks
      setFollowLive(false);
      setPlaying(true);
      return;
    }
    setPlaying((prev) => {
      const next = !prev;
      if (next && globalFrame >= timeline.totalFrames - 8) {
        setGlobalFrame(0);
      }
      return next;
    });
  };

  const handleRelockLive = () => {
    setFollowLive(true);
    if (backendActiveIndex >= 0 && timeline.segments[backendActiveIndex]) {
      setGlobalFrame(timeline.segments[backendActiveIndex].fromFrame);
    }
  };

  const isIdlePreview = !liveJob && !isLiveRunning && !isCompleted && !isFailed;
  const stageDisplayLabel = (idx) => (isIdlePreview ? 'Sẵn sàng' : backendStageStatus(idx, live));

  // Honest synchronization badge reflecting actual backend state (AGENTS.md compliant)
  const syncMeta = isLiveRunning && followLive
    ? {
        label: `ĐANG ĐỒNG BỘ BACKEND THỰC · GIAI ĐOẠN ${String(Math.max(1, backendActiveIndex + 1)).padStart(2, '0')}/06`,
        tone: 'live',
      }
    : isFailed
      ? {
          label: `BACKEND DỪNG TẠI GIAI ĐOẠN ${String(Math.max(1, backendActiveIndex + 1)).padStart(2, '0')}/06 (FAILED)`,
          tone: 'failed',
        }
      : isCompleted
        ? {
            label: timeline.hasRealTiming
              ? 'ĐỒNG BỘ THỜI LƯỢNG THỰC TỪ API · 6 GIAI ĐOẠN'
              : 'PHIÊN ĐÃ HOÀN TẤT · DỮ LIỆU TỪ API',
            tone: 'done',
          }
        : {
            label: 'XEM TRƯỚC PIPELINE 6 GIAI ĐOẠN',
            tone: 'neutral',
          };

  const totalDisplayMs = backendMs ?? (timeline.hasRealTiming ? timeline.totalMeasuredMs : null);
  const currentDisplayMs = isLiveRunning && followLive
    ? elapsedMs
    : frameToBackendMs(timeline, globalFrame);

  const playheadPct = Math.max(0, Math.min(100, (globalFrame / Math.max(1, timeline.totalFrames - 1)) * 100));
  const effectiveNoLlm = Boolean(noLlm || liveJob?.no_llm);

  return (
    <div id="scan-simulation" className="v2-rm-root" aria-live="polite">
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
        localFrame={localSceneFrame}
        cycle={motionCycle}
        syncModeLabel={syncMeta.label}
        syncTone={syncMeta.tone}
        liveCounts={ready ? live?.counts : null}
        progress={live?.progress}
        noLlm={effectiveNoLlm}
        reducedMotion={reducedMotion}
      />

      {/* 2. Remotion Studio-Style Playback Bar & Proportional 6-Stage Backend Timeline */}
      <div className="v2-rm-studio-deck">
        <div className="v2-rm-controls-row">
          <div className="v2-rm-transport">
            <button
              type="button"
              className="v2-rm-btn v2-rm-btn--primary"
              onClick={handleTogglePlay}
              disabled={reducedMotion}
              aria-label={playing && !(isLiveRunning && followLive) ? 'Tạm dừng mô phỏng' : 'Phát mô phỏng 6 giai đoạn'}
            >
              <Icon name={playing && !(isLiveRunning && followLive) ? 'Pause' : 'Play'} />
              <span>
                {isLiveRunning && followLive
                  ? 'Đang chạy thực'
                  : playing
                    ? 'Tạm dừng'
                    : isCompleted
                      ? 'Phát lại 6 giai đoạn'
                      : 'Chạy mô phỏng'}
              </span>
            </button>

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

            {isLiveRunning && !followLive && (
              <button type="button" className="v2-rm-btn v2-rm-btn--sync" onClick={handleRelockLive}>
                <Icon name="RotateCcw" />
                <span>Đồng bộ tiến trình thực</span>
              </button>
            )}
          </div>

          <div className="v2-rm-timecode-readout mono">
            <Icon name="Clock" />
            {totalDisplayMs !== null ? (
              <span>
                <strong>{formatTimecode(currentDisplayMs)}</strong>
                <em> / {formatTimecode(totalDisplayMs)}</em>
                <small> (API thực)</small>
              </span>
            ) : isLiveRunning ? (
              <span>
                <strong>{formatTimecode(elapsedMs)}</strong>
                <small> · đang theo dõi</small>
              </span>
            ) : (
              <span>
                <strong>{formatTimecode(currentDisplayMs)}</strong>
                <em> / {formatTimecode((timeline.totalFrames / TIMELINE_FPS) * 1000)}</em>
                <small> · 60 FPS</small>
              </span>
            )}
          </div>
        </div>

        {/* Proportional 6-Stage Sequence Track with Playhead Needle */}
        <div className="v2-rm-timeline-wrap">
          <div className="v2-rm-timeline-tracks" role="tablist" aria-label="Thanh thời gian 6 giai đoạn backend">
            {timeline.segments.map((seg) => {
              const label = backendStageStatus(seg.index, live);
              const catCls = seg.stage?.cat ? `is-cat-${seg.stage.cat.toLowerCase()}` : 'is-cat-unknown';
              const isSelected = seg.index === displayIndex;
              const isLiveHere = isLiveRunning && seg.index === backendActiveIndex;
              return (
                <button
                  key={scanGuide[seg.index].key}
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
                  <span className="v2-rm-track-sub mono">
                    {seg.measuredMs !== null
                      ? formatCompactDuration(seg.measuredMs)
                      : seg.stage?.cat === 'RUNNING'
                        ? 'đang chạy…'
                        : seg.stage?.cat === 'SKIPPED'
                          ? 'bỏ qua'
                          : `${Math.round(seg.visualPct)}%`}
                  </span>
                </button>
              );
            })}

            <div className="v2-rm-playhead" style={{left: `${playheadPct}%`}} aria-hidden="true">
              <span className="v2-rm-playhead-cap" />
            </div>
          </div>

          <input
            type="range"
            className="v2-rm-scrubber"
            min={0}
            max={timeline.totalFrames - 1}
            step={1}
            value={Math.round(globalFrame)}
            onChange={handleScrub}
            aria-label="Tua tiến trình 6 giai đoạn backend"
          />
        </div>
      </div>

      {/* 3. Interactive 6-Stage Cards Grid (synced with backend status & clickable to inspect in 3D) */}
      <div className="v2-stage-rail" role="list" aria-label="6 giai đoạn xử lý thực tế trên backend">
        {scanGuide.map((item, index) => {
          const label = stageDisplayLabel(index);
          const isDone = label.startsWith('Hoàn thành');
          const isBackendCurrent = index === backendActiveIndex && (hasBackendStage || ready || live?.stage === 'LOADING_RESULTS');
          const isSelected = index === displayIndex;
          const stateCls = stageClassName(label, isBackendCurrent, isSelected);
          const seg = timeline.segments[index];

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
                <Badge tone={stageTone(label)}>{label}</Badge>
              </div>
              <div className="v2-stage-title">{item.title}</div>
              <div className="v2-stage-meta">
                <span>{item.purpose}</span>
              </div>
              <div className="v2-stage-foot">
                <span className="mono">{item.key}</span>
                {seg?.sharePct !== null && seg?.sharePct !== undefined && (
                  <span className="mono v2-stage-share">{seg.sharePct.toFixed(1)}% E2E</span>
                )}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
