/*
 * P0.13 - presentation-only interpretation of live backend telemetry.
 * A stage-10 duration is NOT proof that the asynchronous job has finished.
 * The scan is complete only after the backend reaches COMPLETED and the
 * matching findings/summary have been loaded for this job.
 */
const DONE = new Set(['COMPLETED', 'COMPLETE', 'SUCCESS', 'SUCCEEDED', 'DONE']);
const ACTIVE = new Set(['RUNNING', 'IN_PROGRESS', 'ACTIVE']);

export function isLiveSessionReady(live) {
  return Boolean(
    live?.resultsReady === true &&
    String(live?.stage || '').toUpperCase() === 'COMPLETED' &&
    String(live?.state || '').toUpperCase() === 'COMPLETED'
  );
}

export function backendStageStatus(index, live) {
  const stages = Array.isArray(live?.stages) ? live.stages : [];
  const stage = stages.find((item, itemIndex) => {
    const value = Number(item?.stage_number ?? item?.stage_no ?? item?.number);
    return Number.isInteger(value) ? value === index + 1 : itemIndex === index;
  });
  const status = String(stage?.state ?? stage?.status ?? '').toUpperCase();
  const jobState = String(live?.state || '').toUpperCase();
  const progress = String(live?.stage || '').toUpperCase();
  const duration = Number(stage?.duration_ms);
  const measured = stage?.duration_ms !== null && stage?.duration_ms !== undefined &&
    Number.isFinite(duration)
    ? ` · ${duration.toLocaleString('vi-VN', {minimumFractionDigits: 3, maximumFractionDigits: 3})} ms`
    : '';

  if (status.includes('FAIL')) return 'Thất bại';
  if (jobState === 'FAILED') {
    const failedAt = Number(live?.activeStage);
    if (index + 1 === failedAt) return `Thất bại${measured}`;
    if (index === 9 && !isLiveSessionReady(live)) return 'Phiên không hoàn tất';
    if (index + 1 > failedAt && !status.includes('SKIP') && !DONE.has(status)) return 'Không chạy (phiên đã thất bại)';
  }
  if (status.includes('SKIP')) return `Bỏ qua${stage?.reason ? ` · ${stage.reason}` : ''}`;

  if (index === 9 && !isLiveSessionReady(live)) {
    // The backend can finish stage 10 while still persisting its scan record.
    // Never freeze the visual stage-10 timer or show a green completion state
    // until the entire job AND its results are confirmed.
    if (progress === 'RESULTS_ERROR') return 'Chưa thể xác nhận kết quả';
    if (progress === 'LOADING_RESULTS' || jobState === 'COMPLETED') return 'Đang xác nhận kết quả';
    if (DONE.has(status) || String(live?.publicationState || '').toUpperCase() === 'PERSISTING_RESULTS') {
      return 'Đang hoàn tất phiên quét';
    }
    if (ACTIVE.has(status) || Number(live?.activeStage) === 10) return 'Đang tổng hợp báo cáo';
    return 'Chưa bắt đầu';
  }

  if (DONE.has(status)) return `Hoàn thành${measured}`;
  if (index === 9 && isLiveSessionReady(live)) return `Hoàn thành${measured}`;
  if (ACTIVE.has(status) || jobState === 'RUNNING' && Number(live?.activeStage) === index + 1) return 'Đang thực thi';
  if (['QUEUED', 'PENDING', 'NOT_STARTED'].includes(status) || jobState === 'QUEUED') return 'Chưa bắt đầu';
  return 'Chưa có telemetry';
}
