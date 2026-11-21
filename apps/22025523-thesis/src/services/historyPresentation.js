// Presentation-only helpers. They never change persisted scan metadata.
// Source text only reflects fields present on the record itself; rows confirmed by the current API
// are never completed with cached or user-typed values (see scanHistory.mergeHistoryRecords).
export function historyProvenanceLabel(record = {}) {
  return record.backendConfirmed
    ? {tone: 'blue', label: 'Thông tin từ API hiện tại'}
    : {tone: 'amber', label: 'Bộ nhớ tạm trình duyệt · chưa xác nhận lại với API'};
}

export function displaySource(record = {}) {
  const mode = String(record.inputMode || '').toUpperCase();
  const fromApi = Boolean(record.backendConfirmed);
  const isZip = mode.includes('ZIP') || (!record.repoUrl && Boolean(record.fileName));
  if (isZip) {
    return {
      type: 'ZIP',
      value: record.fileName || (fromApi ? 'API hiện tại chưa cung cấp tên tệp ZIP' : 'Tệp ZIP'),
      href: null,
    };
  }
  if (record.repoUrl) {
    const value = String(record.repoUrl);
    let href = null;
    try {
      const parsed = new URL(value);
      if (parsed.protocol === 'https:' && ['github.com', 'www.github.com'].includes(parsed.hostname.toLowerCase())) {
        href = parsed.href;
      }
    } catch {
      // A recorded source is still shown as text if it is not a valid GitHub URL.
    }
    return {type: 'GitHub', value, href};
  }
  if (mode.includes('GITHUB')) {
    return {
      type: 'GitHub',
      value: fromApi ? 'Chưa có đường dẫn repository từ API hiện tại' : 'Chưa có đường dẫn repository',
      href: null,
    };
  }
  return {
    type: 'Chưa xác định',
    value: fromApi ? 'Chưa có thông tin nguồn từ API hiện tại' : 'Chưa có thông tin mã nguồn',
    href: null,
  };
}

export function formatScanTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '-';
  return date.toLocaleString('vi-VN', {day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false});
}

// Separate completion time, start time, and local cache time honestly so a startedAt or
// local savedAt timestamp is never presented under the label "Thời điểm hoàn tất".
export function displayHistoryTimestamp(record = {}) {
  if (record.completedAt) {
    return {label: 'Thời điểm hoàn tất', value: formatScanTime(record.completedAt)};
  }
  if (record.startedAt) {
    return {label: 'Thời điểm bắt đầu', value: formatScanTime(record.startedAt)};
  }
  if (!record.backendConfirmed && record.savedAt) {
    return {label: 'Lưu bộ nhớ tạm', value: formatScanTime(record.savedAt)};
  }
  return {label: 'Thời điểm hoàn tất', value: 'Chưa có mốc hoàn tất'};
}

export function formatExecutionTime(value) {
  if (value === null || value === undefined || value === '') return '-';
  const duration = Number(value);
  if (!Number.isFinite(duration) || duration < 0) return '-';
  const seconds = duration / 1000;
  if (seconds < 60) return `${seconds.toLocaleString('vi-VN', {maximumFractionDigits: 1})} giây`;
  const minutes = Math.floor(seconds / 60);
  const remain = Math.round(seconds % 60);
  return remain === 60 ? `${minutes + 1} phút` : `${minutes} phút ${remain} giây`;
}
