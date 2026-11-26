import {useEffect, useState} from 'react';
import {Link, useOutletContext} from 'react-router-dom';
import {Card, PageHeader, Badge, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import {ApiError, api, getApiOrigin, getAuthSessionScope} from '../services/api';
import {formatShortHash, resolveJavaFileCounts} from '../services/findingPresentation';
import {scanQuery} from '../services/liveScan';
import {
  readHistory,
  scopedHistoryKey,
  normalizeApiOrigin,
  hideHistoryRecord,
  readHiddenHistory,
  restoreHistoryRecord,
  mergeHistoryRecords,
} from '../services/scanHistory';
import {syncHistoryFromApi} from '../services/historySync';
import {
  displayHistoryTimestamp,
  displaySource,
  formatExecutionTime,
  historyProvenanceLabel,
} from '../services/historyPresentation';

function useAvailability(records, apiOrigin, authSessionScope, apiRevision) {
  const [map, setMap] = useState({});
  const ids = records.map((item) => item.scanId).filter(Boolean).join('|');
  useEffect(() => {
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    setMap({});
    records.filter((item) => Boolean(item.scanId)).forEach((item) => {
      api.scan(item.scanId, {signal: controller.signal, timeoutMs: 15000})
        .then(() => {
          if (isStale()) return;
          setMap((prev) => ({...prev, [item.scanId]: 'ok'}));
        })
        .catch((error) => {
          if (isStale() || error?.abortedByConfigChange) return;
          setMap((prev) => ({...prev, [item.scanId]: error instanceof ApiError && error.status === 404 ? 'gone' : 'unknown'}));
        });
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [ids, apiOrigin, authSessionScope, apiRevision]);
  return map;
}

function statusMeta(status) {
  const s = String(status || '').toUpperCase();
  if (s === 'COMPLETED') return {tone: 'green', label: 'Hoàn tất'};
  if (s === 'FAILED') return {tone: 'red', label: 'Thất bại'};
  if (s === 'CANCELLED' || s === 'CANCELED') return {tone: 'amber', label: 'Đã hủy'};
  if (s === 'RUNNING') return {tone: 'amber', label: 'Đang chạy'};
  if (s === 'QUEUED') return {tone: 'amber', label: 'Đang chờ'};
  return {tone: 'neutral', label: 'Chưa xác nhận trạng thái'};
}

export function HistoryRow({record, availability, onDelete}) {
  const gone = record.scanId ? availability === 'gone' : false;
  const st = statusMeta(record.status);
  const running = ['RUNNING', 'QUEUED'].includes(String(record.status || '').toUpperCase());
  const source = displaySource(record);
  const provenance = historyProvenanceLabel(record);
  const timestamp = displayHistoryTimestamp(record);
  const hasFindingsCount = record.candidates !== undefined && record.candidates !== null;
  const hasHumanCounts = record.openCount !== undefined || record.confirmedTrue !== undefined || record.confirmedFalse !== undefined;
  const javaCounts = record.javaCounts || (
    record.javaFilesScanned !== undefined
      ? resolveJavaFileCounts({java_files_scanned: record.javaFilesScanned})
      : null
  );
  const showJavaCounts = Boolean(
    javaCounts && (
      javaCounts.inventoryCount !== null
      || javaCounts.scannedCount !== null
      || javaCounts.ignoredCount !== null
      || javaCounts.isInconsistent
      || javaCounts.hasInvalidFields
    ),
  );
  const showJavaBreakdown = Boolean(
    javaCounts && (javaCounts.scannedCount !== null || javaCounts.ignoredCount !== null || javaCounts.isInconsistent || javaCounts.coverageStatus === 'UNVERIFIED'),
  );

  return (
    <Card className="report-row history-compact-row">
      <div className="history-record-copy">
        <div className="history-row-heading" style={{flexWrap: 'wrap', gap: '6px'}}>
          <Badge tone={st.tone}>{st.label}</Badge>
          <Badge tone="blue">Nguồn: {source.type}</Badge>
          {!record.backendConfirmed && <Badge tone={provenance.tone}>{provenance.label}</Badge>}
          {record.qwenInferenceStatus === 'PARTIAL_OR_FAILED' && (
            <Badge tone="amber">Qwen hạn chế / UNDETERMINED</Badge>
          )}
          {record.qwenInferenceStatus === 'DISABLED' && (
            <Badge tone="neutral">Không chạy Qwen</Badge>
          )}
        </div>

        <div className="history-source">
          {source.href
            ? (
              <a href={source.href} target="_blank" rel="noopener noreferrer" title={source.value} className="history-source-link">
                {source.value} <Icon name="ExternalLink" />
              </a>
            )
            : <strong title={source.value} className="wrap-value">{source.value}</strong>}
        </div>

        <dl className="history-time-grid v2-history-meta-grid">
          <div>
            <dt>{record.scanId ? 'Mã phiên' : 'Mã tác vụ'}</dt>
            <dd className="mono" title={record.scanId || record.jobId}>
              {formatShortHash(record.scanId || record.jobId, 14, 8)}
            </dd>
          </div>
          <div><dt>{timestamp.label}</dt><dd>{timestamp.value}</dd></div>
          <div><dt>Thời gian</dt><dd>{formatExecutionTime(record.backendMs)}</dd></div>
          {showJavaCounts && (
            <div>
              <dt>Tệp Java (inventory)</dt>
              <dd>
                {javaCounts.inventoryCount !== null
                  ? javaCounts.inventoryCount
                  : javaCounts.isInconsistent
                    ? 'Không nhất quán'
                    : 'Chưa có số liệu'}
              </dd>
            </div>
          )}
          {showJavaBreakdown && (
            javaCounts.isInconsistent ? (
              <div>
                <dt>OpenGrep thực quét / bỏ qua</dt>
                <dd title={javaCounts.inconsistencyReason}>Không nhất quán</dd>
              </div>
            ) : javaCounts.coverageStatus === 'UNVERIFIED' ? (
              <div>
                <dt>OpenGrep thực quét / bỏ qua</dt>
                <dd title={javaCounts.summaryNote}>Chưa xác minh</dd>
              </div>
            ) : (
              <>
                <div>
                  <dt>OpenGrep thực quét</dt>
                  <dd>{javaCounts.scannedCount !== null ? javaCounts.scannedCount : 'Chưa có số liệu'}</dd>
                </div>
                <div>
                  <dt>Tệp Java bỏ qua</dt>
                  <dd>{javaCounts.ignoredCount !== null ? javaCounts.ignoredCount : 'Chưa có số liệu'}</dd>
                </div>
              </>
            )
          )}
        </dl>

        {hasFindingsCount && (
          <p className="mono" style={{fontSize: '12px', color: 'var(--v2-text-secondary)', margin: '8px 0 2px'}}>
            Cảnh báo: {record.candidates} · AI: SUPPORTED {record.supported ?? 0} · REFUTED {record.refuted ?? 0} · UNDETERMINED {record.undetermined ?? 0}
          </p>
        )}
        {hasHumanCounts && (
          <p className="mono" style={{fontSize: '12px', color: 'var(--v2-text-muted)', margin: '2px 0 0'}}>
            Người kiểm duyệt: OPEN {record.openCount ?? 0} · CONFIRMED_TRUE {record.confirmedTrue ?? 0} · CONFIRMED_FALSE {record.confirmedFalse ?? 0}
          </p>
        )}
        {record.status === 'FAILED' && (record.errorCode || record.errorMessage) && (
          <p className="history-warning">
            Lỗi [{record.errorCode || 'FAILED'}]: {record.errorMessage || 'Quá trình phân tích không hoàn tất.'}
          </p>
        )}
        {gone && <p className="history-warning">Không còn tìm thấy phiên này trên máy chủ API (HTTP 404).</p>}
      </div>

      <div className="history-actions" aria-label="Thao tác với phiên phân tích">
        {record.scanId ? (
          <>
            <Link to={`/findings${scanQuery(record.scanId)}`} className="button-secondary history-action history-action--results">
              Xem kết quả <Icon name="ArrowRight" />
            </Link>
            <Link to={`/review${scanQuery(record.scanId)}`} className="button-secondary history-action history-action--trace">
              <Icon name="Shield" />Kiểm duyệt
            </Link>
            <Link to={`/reports${scanQuery(record.scanId)}`} className="button-secondary history-action history-action--report">
              <Icon name="FileText" />Báo cáo
            </Link>
          </>
        ) : (
          <Link to="/scanner" className="button-secondary history-action history-action--results">
            <Icon name="ScanSearch" />Mở Scanner
          </Link>
        )}
        <button
          className="button-secondary history-delete history-action history-action--hide"
          type="button"
          disabled={running}
          aria-label="Ẩn phiên phân tích khỏi lịch sử trình duyệt"
          onClick={() => onDelete(record)}
        >
          <Icon name="Trash2" />Ẩn
        </button>
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
        <h2 id="history-delete-title">Ẩn phiên này khỏi danh sách trình duyệt?</h2>
        <p>Nguồn: <span className="wrap-value">{source.value}</span></p>
        <p className="history-dialog-warning">Dữ liệu thực trên máy chủ API và SQLite không bị xóa.</p>
        <div className="history-dialog-actions">
          <button className="button-secondary" type="button" onClick={onCancel}>Hủy</button>
          <button className="button-secondary history-delete" type="button" onClick={onConfirm}><Icon name="Trash2" />Ẩn phiên</button>
        </div>
      </section>
    </div>
  );
}

export default function HistoryPage() {
  const outlet = useOutletContext();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const [records, setRecords] = useState(() => readHistory(getApiOrigin(), {sessionScope: getAuthSessionScope()}));
  const [backendRecords, setBackendRecords] = useState([]);
  const [hiddenRecords, setHiddenRecords] = useState(() => readHiddenHistory(getApiOrigin(), {sessionScope: getAuthSessionScope()}));
  const [gap, setGap] = useState('');
  const [authGap, setAuthGap] = useState(false);
  const [pendingDelete, setPendingDelete] = useState(null);
  const [notice, setNotice] = useState('');

  const backendKeys = new Set(backendRecords.map((record) => scopedHistoryKey(record)).filter(Boolean));
  const availability = useAvailability(
    records.filter((record) => !backendKeys.has(scopedHistoryKey(record))),
    apiOrigin,
    authSessionScope,
    apiRevision,
  );

  useEffect(() => {
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    // Drop every row of the previous origin / auth session immediately; only this active
    // auth session's RAM cache (empty on any origin or token switch) is shown until the API answers.
    setBackendRecords([]);
    setRecords(readHistory(requestOrigin, {sessionScope: requestSession}));
    setHiddenRecords(readHiddenHistory(requestOrigin, {sessionScope: requestSession}));
    setPendingDelete(null);
    setNotice('');
    setGap('');
    setAuthGap(false);
    syncHistoryFromApi({
      origin: requestOrigin,
      sessionScope: requestSession,
      signal: controller.signal,
      isCurrent: () => active && getApiOrigin() === requestOrigin && getAuthSessionScope() === requestSession,
    }).then((result) => {
      if (result.stale || isStale()) return;
      if (result.incomplete) {
        setAuthGap(false);
        setGap(
          result.incompleteNotice
          || 'Danh sách lịch sử từ API chưa đầy đủ; các mục bên dưới chỉ gồm các bản ghi hợp lệ đã nhận.',
        );
      } else if (!result.supported) {
        const isAuthError = /401|UNAUTHORIZED|Bearer Token/i.test(result.lastError || '');
        setAuthGap(isAuthError);
        setGap(
          isAuthError
            ? 'Chưa đồng bộ được từ API (Thiếu hoặc sai API Bearer Token)'
            : result.lastError
              ? `Chưa đồng bộ được từ API (${result.lastError}); các mục bên dưới chỉ là bộ nhớ tạm trong phiên hiện tại.`
              : 'Chưa tải được danh sách phiên từ API; các mục bên dưới chỉ là bộ nhớ tạm trong phiên hiện tại.',
        );
      } else {
        setAuthGap(false);
        setGap('');
      }
      setBackendRecords(result.backendRecords);
      setRecords(result.records);
      setHiddenRecords(result.hidden);
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [apiOrigin, authSessionScope, apiRevision]);

  const refreshFromStorage = () => {
    const origin = getApiOrigin();
    const sessionScope = getAuthSessionScope();
    setRecords(mergeHistoryRecords(
      readHistory(origin, {sessionScope}),
      backendRecords.filter((record) => (
        normalizeApiOrigin(record.apiOrigin) === origin &&
        (record.sessionScope || '') === sessionScope
      )),
      readHiddenHistory(origin, {sessionScope}),
      {origin, sessionScope},
    ));
    setHiddenRecords(readHiddenHistory(origin, {sessionScope}));
  };

  const confirmHide = () => {
    if (!pendingDelete) return;
    hideHistoryRecord(pendingDelete);
    refreshFromStorage();
    setNotice('Đã ẩn phiên khỏi danh sách trình duyệt.');
    setPendingDelete(null);
  };

  const restore = (scopedKey) => {
    restoreHistoryRecord(scopedKey);
    refreshFromStorage();
    setNotice('Đã khôi phục phiên vào danh sách.');
  };

  return (
    <>
      <PageHeader
        eyebrow="LỊCH SỬ PHÂN TÍCH"
        title="Các lượt phân tích đã thực hiện"
        actions={<Link to="/scanner" className="button-primary"><Icon name="Plus" />Phiên phân tích mới</Link>}
      />
      {gap && <DataNotice>{gap}</DataNotice>}
      {notice && <div className="inline-success" role="status" style={{marginBottom: '14px'}}><Icon name="Check" />{notice}</div>}
      {records.length === 0
        ? (
          <div className="v2-history-empty-wrap">
            <EmptyState
              title="Chưa có phiên phân tích nào"
              text="Khởi tạo phiên phân tích GitHub hoặc ZIP mới để lưu và theo dõi tại đây."
              icon="Clock"
            />
            {authGap && outlet?.openConnectionPanel && (
              <div className="v2-history-empty-actions">
                <button
                  type="button"
                  className="button-secondary"
                  onClick={outlet.openConnectionPanel}
                >
                  <Icon name="KeyRound" />Cấu hình API / Token
                </button>
              </div>
            )}
          </div>
        )
        : (
          <div style={{display: 'grid', gap: '12px'}}>
            {records.map((record) => (
              <HistoryRow key={scopedHistoryKey(record)} record={record} availability={availability[record.scanId]} onDelete={setPendingDelete} />
            ))}
          </div>
        )}
      {hiddenRecords.length > 0 && (
        <section className="section-block">
          <h2 style={{fontSize: '17px', marginBottom: '12px'}}>Đã ẩn trên trình duyệt này</h2>
          <div style={{display: 'grid', gap: '10px'}}>
            {hiddenRecords.map((record) => (
              <Card className="report-row history-hidden-row" key={scopedHistoryKey(record)}>
                <div className="history-record-copy">
                  <Badge tone="neutral">Đã ẩn</Badge>
                  <strong className="history-hidden-source wrap-value">{displaySource(record).value}</strong>
                </div>
                <button className="button-secondary" type="button" onClick={() => restore(scopedHistoryKey(record))}>
                  <Icon name="RotateCcw" />Khôi phục
                </button>
              </Card>
            ))}
          </div>
        </section>
      )}
      <ConfirmHide record={pendingDelete} onCancel={() => setPendingDelete(null)} onConfirm={confirmHide} />
    </>
  );
}
