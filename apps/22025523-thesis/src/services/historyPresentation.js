// Presentation-only helpers. They never change persisted scan metadata.
export function displaySource(record = {}) {
  const mode = String(record.inputMode || '').toUpperCase();
  const isZip = mode.includes('ZIP') || (!record.repoUrl && Boolean(record.fileName));
  if (isZip) return {type: 'ZIP', value: record.fileName || 'Tệp ZIP', href: null};
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
  if (mode.includes('GITHUB')) return {type: 'GitHub', value: 'Chưa có đường dẫn repository', href: null};
  return {type: 'Chưa xác định', value: 'Chưa có thông tin mã nguồn', href: null};
}

export function formatScanTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '-';
  return date.toLocaleString('vi-VN', {day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false});
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
