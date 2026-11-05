import {useEffect, useState} from 'react';
import {Link} from 'react-router-dom';
import {Card, PageHeader, Badge, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import {ApiError, api} from '../services/api';
import {scanQuery} from '../services/liveScan';
import {readHistory, upsertHistory, historyRecordFromBackend, hideHistoryRecord, readHiddenHistory, restoreHistoryRecord, mergeHistoryRecords} from '../services/scanHistory';
import {displaySource, formatScanTime, formatExecutionTime} from '../services/historyPresentation';


function useAvailability(records) {
  const [map, setMap] = useState({});
  const ids = records.map((item) => item.scanId).join('|');
  useEffect(() => {
    const controller = new AbortController();
    records.forEach((item) => {
      api.scan(item.scanId, {signal: controller.signal, timeoutMs: 15000})
        .then(() => setMap((prev) => ({...prev, [item.scanId]: 'ok'})))
        .catch((error) => {
          if (controller.signal.aborted) return;
          setMap((prev) => ({...prev, [item.scanId]: error instanceof ApiError && error.status === 404 ? 'gone' : 'unknown'}));
        });
    });
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids]);
  return map;
}

function Row({record, availability, onDelete}) {
  const gone = availability === 'gone';
  const traceOnly = String(record.restoration || '').includes('TRACE_ONLY');
  const status = String(record.status || '').toUpperCase();
  const tone = status === 'COMPLETED' ? 'green' : status === 'FAILED' ? 'red' : 'amber';
  const running = ['RUNNING', 'QUEUED'].includes(status);
  const statusLabel = status === 'COMPLETED' ? 'Hoàn tất' : status === 'FAILED' ? 'Thất bại' : running ? 'Đang xử lý' : 'Chưa xác nhận';
  const source = displaySource(record);
  return (
    <Card className="report-row history-compact-row">
      <div className="history-record-copy">
        <div className="history-row-heading">
          <Badge tone={tone}>{statusLabel}</Badge>
          <span className="history-input-mode">Nguồn: {source.type}</span>
        </div>
        <div className="history-source">
          {source.href
            ? <a href={source.href} target="_blank" rel="noopener noreferrer" title={source.value} className="history-source-link">{source.value} <Icon name="ExternalLink" /></a>
            : <strong title={source.value}>{source.value}</strong>}
        </div>
        <dl className="history-time-grid">
          <div><dt>Bắt đầu</dt><dd>{formatScanTime(record.startedAt)}</dd></div>
          <div><dt>Kết thúc</dt><dd>{formatScanTime(record.completedAt)}</dd></div>
          <div><dt>Thời gian thực thi</dt><dd>{formatExecutionTime(record.backendMs)}</dd></div>
        </dl>
        {traceOnly && <p className="history-warning">Phiên này chỉ có dữ liệu tiến trình, chưa có kết quả chi tiết.</p>}
        {gone && <p className="history-warning">Không còn truy cập được phiên này trên backend.</p>}
      </div>
      <div className="history-actions" data-trace-only={traceOnly ? "true" : "false"} aria-label="Thao tác với phiên phân tích">
        {!traceOnly && <Link to={`/findings${scanQuery(record.scanId)}`} className="button-secondary history-action history-action--results">Xem kết quả <Icon name="ArrowRight" /></Link>}
        {!traceOnly && <Link to={`/reports${scanQuery(record.scanId)}`} className="button-secondary history-action history-action--report"><Icon name="FileText" />Báo cáo</Link>}
        <Link to={`/replay?scan=${encodeURIComponent(record.scanId)}`} className="button-secondary history-action history-action--trace"><Icon name="Play" />Xem tiến trình</Link>
        <button className="button-secondary history-delete history-action history-action--hide" type="button" disabled={running} aria-label={`Ẩn phiên phân tích khỏi lịch sử`} onClick={() => onDelete(record)}><Icon name="Trash2" />Ẩn</button>
      </div>
    </Card>
  );
}

function ConfirmHide({record, onCancel, onConfirm}) {
  if (!record) return null;
  const source = displaySource(record);
  return (
    <div className="history-dialog-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onCancel()}>
      <section className="history-dialog card" role="dialog" aria-modal="true" aria-labelledby="history-delete-title">
        <span className="eyebrow">LỊCH SỬ PHÂN TÍCH</span>
        <h2 id="history-delete-title">Ẩn phiên này khỏi lịch sử?</h2>
        <p>Nguồn: <span className="wrap-value">{source.value}</span></p>
        <p>Bắt đầu: {formatScanTime(record.startedAt)}</p>
        <p className="history-dialog-warning">Phiên chỉ được ẩn trên trình duyệt này. Dữ liệu quét vẫn được giữ trên backend.</p>
        <div className="history-dialog-actions">
          <button className="button-secondary" type="button" onClick={onCancel}>Hủy</button>
          <button className="button-secondary history-delete" type="button" onClick={onConfirm}><Icon name="Trash2" />Ẩn phiên</button>
        </div>
      </section>
    </div>
  );
}

export default function HistoryPage() {
  const [records, setRecords] = useState(() => readHistory());
  const [backendRecords, setBackendRecords] = useState([]);
  const [hiddenRecords, setHiddenRecords] = useState(() => readHiddenHistory());
  const [gap, setGap] = useState('');
  const [pendingDelete, setPendingDelete] = useState(null);
  const [notice, setNotice] = useState('');
  const backendIds = new Set(backendRecords.map(record=>record.scanId));
  const availability = useAvailability(records.filter(record=>!backendIds.has(record.scanId)));
  const demo = window.sessionStorage.getItem('22025523-demo-result') === 'true';

  useEffect(() => {
    const controller = new AbortController();
    (async () => {
      let supported = false;
      const received=[];
      for (const load of [api.listScanJobs, api.listScans]) {
        try {
          const result = await load({signal: controller.signal});
          if (!result.supported) continue;
          supported = true;
          if (result.truncated) setGap('Đang hiển thị các phiên gần đây. Một số phiên cũ hơn có thể chưa xuất hiện.');
          result.items.forEach((item) => {
            const scanId = item.scan_id ?? item.id;
            if (!scanId) return;
            const record=historyRecordFromBackend(item);
            received.push(record);
            upsertHistory(record, {authoritative: true});
          });
        } catch {
          /* list endpoint unavailable or network error; cached IDs still shown */
        }
      }
      if (controller.signal.aborted) return;
      if (!supported) setGap('Không thể tải đủ lịch sử từ máy chủ. Các phiên đã lưu trên trình duyệt vẫn được hiển thị.');
      setBackendRecords(received);
      setRecords(mergeHistoryRecords(readHistory(),received,readHiddenHistory()));
      setHiddenRecords(readHiddenHistory());
    })();
    return () => controller.abort();
  }, []);

  const confirmHide = () => {
    if (!pendingDelete) return;
    hideHistoryRecord(pendingDelete);
    setRecords(mergeHistoryRecords(readHistory(),backendRecords,readHiddenHistory()));
    setHiddenRecords(readHiddenHistory());
    setNotice('Đã ẩn phiên này khỏi danh sách. Dữ liệu trên máy chủ không bị xóa.');
    setPendingDelete(null);
  };

  const restore = (scanId) => {
    restoreHistoryRecord(scanId);
    setRecords(mergeHistoryRecords(readHistory(),backendRecords,readHiddenHistory()));
    setHiddenRecords(readHiddenHistory());
    setNotice('Đã khôi phục phiên vào lịch sử.');
  };

  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Lịch sử phân tích" />
      {gap && <DataNotice>{gap}</DataNotice>}
      {notice && <div className="inline-success" role="status">{notice}</div>}
      {records.length === 0
        ? <EmptyState title="Chưa có phiên phân tích" text="Chạy một scan LIVE để phiên được ghi lại tại đây." icon="Clock" />
        : records.map((record) => <Row key={record.scanId} record={record} availability={availability[record.scanId]} onDelete={setPendingDelete} />)}
      {hiddenRecords.length > 0 && (
        <section className="section-block">
          <h2>Đã ẩn trên trình duyệt này</h2>
          <p className="muted-text">Có thể khôi phục các phiên đã ẩn. Dữ liệu quét không bị xóa khỏi máy chủ.</p>
          {hiddenRecords.map((record) => (
            <Card className="report-row history-hidden-row" key={record.scanId}>
              <div className="history-record-copy">
                <Badge tone="neutral">Đã ẩn</Badge>
                <strong className="history-hidden-source">{displaySource(record).value}</strong>
                <p>Bắt đầu: {formatScanTime(record.startedAt)}</p>
              </div>
              <button className="button-secondary" type="button" onClick={() => restore(record.scanId)}><Icon name="RotateCcw" />Khôi phục</button>
            </Card>
          ))}
        </section>
      )}
      {demo && <Card className="report-row"><div><Badge tone="amber">MINH HỌA</Badge><h3>Java Security Sample</h3><p>Phiên demo synthetic, tách biệt khỏi lịch sử LIVE.</p></div><Link to="/results" className="button-secondary">Mở kết quả <Icon name="ArrowRight" /></Link></Card>}
      <ConfirmHide record={pendingDelete} onCancel={() => setPendingDelete(null)} onConfirm={confirmHide} />
    </>
  );
}