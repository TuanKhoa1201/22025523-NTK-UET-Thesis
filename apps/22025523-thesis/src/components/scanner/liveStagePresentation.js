const DONE = new Set(['COMPLETED', 'COMPLETE', 'SUCCESS', 'SUCCEEDED', 'DONE']);
const ACTIVE = new Set(['RUNNING', 'IN_PROGRESS', 'ACTIVE']);
const TOTAL_STAGES = 6;

export function isLiveSessionReady(live) {
  return Boolean(
    live?.resultsReady === true &&
    String(live?.stage || '').toUpperCase() === 'COMPLETED' &&
    String(live?.state || '').toUpperCase() === 'COMPLETED',
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
  const measured = stage?.duration_ms !== null && stage?.duration_ms !== undefined && Number.isFinite(duration)
    ? ` · ${duration.toLocaleString('vi-VN', {minimumFractionDigits: 3, maximumFractionDigits: 3})} ms`
    : '';

  if (status.includes('FAIL')) return 'Thất bại';
  if (jobState === 'FAILED') {
    const failedAt = Number(live?.activeStage);
    if (index + 1 === failedAt) return `Thất bại${measured}`;
    if (index === TOTAL_STAGES - 1 && !isLiveSessionReady(live)) return 'Phiên không hoàn tất';
    if (index + 1 > failedAt && !status.includes('SKIP') && !DONE.has(status)) return 'Không chạy (phiên đã thất bại)';
  }
  if (status.includes('SKIP')) {
    const reason = stage?.reason ?? stage?.summary_metadata?.reason;
    return `Bỏ qua${reason ? ` · ${reason}` : ''}`;
  }

  if (index === TOTAL_STAGES - 1 && !isLiveSessionReady(live)) {
    if (progress === 'RESULTS_ERROR') return 'Chưa thể xác nhận kết quả';
    if (progress === 'LOADING_RESULTS' || jobState === 'COMPLETED') return 'Đang xác nhận kết quả';
    if (ACTIVE.has(status) || Number(live?.activeStage) === TOTAL_STAGES) return 'Đang ghi nhận SQLite';
    return 'Chưa bắt đầu';
  }

  if (DONE.has(status)) return `Hoàn thành${measured}`;
  if (index === TOTAL_STAGES - 1 && isLiveSessionReady(live)) return `Hoàn thành${measured}`;
  if (ACTIVE.has(status) || (jobState === 'RUNNING' && Number(live?.activeStage) === index + 1)) return 'Đang thực thi';
  if (['QUEUED', 'PENDING', 'NOT_STARTED'].includes(status) || jobState === 'QUEUED') return 'Chưa bắt đầu';
  return 'Chưa có telemetry';
}
