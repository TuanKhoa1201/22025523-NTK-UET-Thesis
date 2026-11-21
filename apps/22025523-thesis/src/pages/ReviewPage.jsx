import {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {Link, useNavigate, useOutletContext, useSearchParams} from 'react-router-dom';
import {Badge, Card, DataNotice, EmptyState, Icon, PageHeader, SectionTitle, StatCard} from '../components/common/Ui';
import HumanReviewPanel, {AuditTimeline} from '../components/review/HumanReviewPanel';
import {api, getApiOrigin, getAuthSessionScope} from '../services/api';
import {
  citationCheckTone,
  classifyDataOrigin,
  fileName,
  formatShortHash,
  humanReviewMeta,
  PRIORITY_CWES,
  validatedStatusMeta,
} from '../services/findingPresentation';
import {ACTIVE_KEY, clearStaleActiveScanId, isConfirmedScanNotFoundError, scanQuery} from '../services/liveScan';
import {verifyFindingIdentity, verifyScanPayloadIdentity} from '../services/reviewModel';
import {normalizeFinding} from '../services/scanData';

function ReviewQueueItem({row, scanId, writable, onRefreshAll}) {
  const [expanded, setExpanded] = useState(false);
  const [detailState, setDetailState] = useState({key: '', data: null});
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState('');
  const detailRequestRef = useRef({controller: null, seq: 0});
  const itemKey = `${scanId}::${row.id}`;

  const vMeta = validatedStatusMeta(row.validatedStatus);
  const hMeta = humanReviewMeta(row.humanReviewState);

  useEffect(() => {
    const req = detailRequestRef.current;
    req.seq += 1;
    req.controller?.abort();
    req.controller = null;
    setDetailState({key: '', data: null});
    setDetailError('');
    setLoadingDetail(false);
    return () => {
      req.seq += 1;
      req.controller?.abort();
      req.controller = null;
    };
  }, [itemKey]);

  const loadDetail = useCallback(async () => {
    if (!scanId || !row.id) {
      setDetailState({key: '', data: null});
      setDetailError('Thiếu mã phiên (scan_id) hoặc mã cảnh báo (finding_id); không thể mở kiểm duyệt.');
      return;
    }
    if (row.scanId && row.scanId !== scanId) {
      setDetailState({key: '', data: null});
      setDetailError(`Cảnh báo ${row.id} thuộc phiên ${row.scanId}, không khớp phiên đang chọn (${scanId}); thao tác đã được dừng.`);
      return;
    }
    const req = detailRequestRef.current;
    req.controller?.abort();
    const controller = new AbortController();
    const seq = req.seq + 1;
    req.seq = seq;
    req.controller = controller;

    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    const isStale = () => (
      controller.signal.aborted ||
      req.seq !== seq ||
      getApiOrigin() !== requestOrigin ||
      getAuthSessionScope() !== requestSession
    );
    setLoadingDetail(true);
    setDetailError('');
    setDetailState({key: '', data: null});
    try {
      const doc = await api.findingDetail(scanId, row.id, row.detailUrl, {signal: controller.signal});
      if (isStale()) return;
      const identity = verifyFindingIdentity(doc, scanId, row.id, {requireScanId: true});
      if (!identity.valid) {
        setDetailState({key: '', data: null});
        setDetailError(identity.error);
        return;
      }
      if (classifyDataOrigin(doc).isMockOrTest) {
        setDetailState({key: '', data: null});
        setDetailError('Dữ liệu mô phỏng (mock) bị chặn kiểm duyệt trong giao diện vận hành thực.');
        return;
      }
      setDetailState({key: itemKey, data: doc});
    } catch (err) {
      if (err?.abortedByConfigChange || isStale()) return;
      setDetailState({key: '', data: null});
      setDetailError(err?.message || 'Không thể tải chi tiết cảnh báo từ máy chủ.');
    } finally {
      if (!isStale()) setLoadingDetail(false);
    }
  }, [scanId, row.id, row.scanId, row.detailUrl, itemKey]);

  const verifiedDetail = useMemo(() => {
    if (detailState.key !== itemKey || !detailState.data) return null;
    return verifyFindingIdentity(detailState.data, scanId, row.id, {requireScanId: true}).valid
      ? detailState.data
      : null;
  }, [detailState, itemKey, scanId, row.id]);

  const toggleExpand = () => {
    const next = !expanded;
    setExpanded(next);
    if (next && !verifiedDetail && !loadingDetail) {
      loadDetail();
    }
  };

  return (
    <Card style={{marginBottom: '12px'}}>
      <div style={{display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: '14px', alignItems: 'flex-start'}}>
        <div style={{flex: '1 1 420px', minWidth: 0}}>
          <div style={{display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '8px'}}>
            <Badge tone="blue">{row.cwe}</Badge>
            <Badge tone={vMeta.tone}>AI: {row.validatedStatus}</Badge>
            <Badge tone={hMeta.tone}>Người duyệt: {row.humanReviewState}</Badge>
            <Badge tone={citationCheckTone(row.citationCheck)}>
              Trích dẫn: {row.citationCheck} ({row.citationsCount})
            </Badge>
          </div>
          <h3 style={{margin: '0 0 4px', fontSize: '15.5px', overflowWrap: 'anywhere'}}>{row.title || row.ruleId}</h3>
          <p className="mono wrap-value" style={{fontSize: '12px', color: 'var(--v2-text-secondary)', margin: '0 0 4px'}}>
            {fileName(row.file) || row.file}:{row.line || '-'} · ID {formatShortHash(row.id, 10, 6)}
          </p>
          {row.explanationPreview && (
            <p style={{fontSize: '13px', color: 'var(--v2-text-secondary)', margin: '6px 0 0', overflowWrap: 'anywhere'}}>
              {row.explanationPreview}
            </p>
          )}
        </div>

        <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
          <button type="button" className="button-primary" onClick={toggleExpand}>
            <Icon name="Shield" />{expanded ? 'Thu gọn kiểm duyệt' : 'Kiểm duyệt nhanh'}
          </button>
          <Link
            to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`}
            state={{detailUrl: row.detailUrl}}
            className="button-secondary"
          >
            <span>Chi tiết &amp; mã nguồn</span>
            <Icon name="ArrowRight" />
          </Link>
        </div>
      </div>

      {expanded && (
        <div style={{marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--v2-border-subtle)'}}>
          {loadingDetail && <DataNotice>Đang tải snapshot SHA-256 và lịch sử kiểm duyệt từ API…</DataNotice>}
          {detailError && <div className="inline-error" role="alert"><Icon name="AlertTriangle" />{detailError}</div>}
          {verifiedDetail && (
            <HumanReviewPanel
              scanId={scanId}
              findingId={row.id}
              detail={verifiedDetail}
              writable={writable && verifiedDetail.writable !== false}
              validatedStatus={verifiedDetail.validated_status || row.validatedStatus}
              humanReviewState={verifiedDetail.human_review_state || row.humanReviewState}
              reviewEvents={verifiedDetail.review_events || []}
              rejectedDecisions={verifiedDetail.rejected_decisions || []}
              onUpdated={(updated) => {
                if (updated && typeof updated === 'object') {
                  const hasIdentity = Boolean(updated.scan_id || updated.finding_id || updated.id);
                  if (!hasIdentity || verifyFindingIdentity(updated, scanId, row.id, {requireScanId: Boolean(updated.scan_id)}).valid) {
                    setDetailState((prev) => (
                      prev.key === itemKey && prev.data
                        ? {key: itemKey, data: {...prev.data, ...updated}}
                        : prev
                    ));
                  }
                }
                onRefreshAll();
              }}
            />
          )}
        </div>
      )}
    </Card>
  );
}

function LiveReviewWorkspace({scanId}) {
  const outlet = useOutletContext();
  const navigate = useNavigate();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const [stateFilter, setStateFilter] = useState('');
  const [validatedFilter, setValidatedFilter] = useState('');
  const [cweFilter, setCweFilter] = useState('');
  const [search, setSearch] = useState('');
  const [queueState, setQueueState] = useState({status: 'loading', data: null, error: '', statusCode: null});
  const [historyState, setHistoryState] = useState({status: 'loading', data: null, error: '', statusCode: null});
  const [refreshTick, setRefreshTick] = useState(0);

  const triggerRefresh = useCallback(() => {
    setRefreshTick((v) => v + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    setQueueState({status: 'loading', data: null, error: '', statusCode: null});
    setHistoryState({status: 'loading', data: null, error: '', statusCode: null});

    Promise.all([
      api.reviewQueue(scanId, {includeAll: true}, {signal: controller.signal}),
      api.scanReviewHistory(scanId, {signal: controller.signal}),
    ])
      .then(([queueDoc, historyDoc]) => {
        if (isStale()) return;
        const queueIdentity = verifyScanPayloadIdentity(queueDoc, scanId, {itemsKey: 'warnings'});
        if (!queueIdentity.valid) {
          setQueueState({status: 'error', data: null, error: queueIdentity.error, statusCode: null});
          setHistoryState({status: 'error', data: null, error: queueIdentity.error, statusCode: null});
          return;
        }
        if (classifyDataOrigin(queueDoc).isMockOrTest) {
          const mockMsg = 'Dữ liệu mô phỏng (mock) bị chặn trong hàng đợi kiểm duyệt vận hành thực.';
          setQueueState({status: 'error', data: null, error: mockMsg, statusCode: 403});
          setHistoryState({status: 'error', data: null, error: mockMsg, statusCode: 403});
          return;
        }
        try {
          window.sessionStorage.setItem(ACTIVE_KEY, scanId);
        } catch {
          /* optional sessionStorage update */
        }
        setQueueState({status: 'ready', data: queueDoc, error: '', statusCode: null});

        const historyIdentity = verifyScanPayloadIdentity(historyDoc, scanId);
        if (!historyIdentity.valid) {
          setHistoryState({status: 'error', data: null, error: historyIdentity.error, statusCode: null});
        } else {
          setHistoryState({status: 'ready', data: historyDoc, error: '', statusCode: null});
        }
      })
      .catch((err) => {
        if (isStale() || err?.abortedByConfigChange) return;
        const statusCode = err?.status ?? null;
        const errorCode = err?.code ?? err?.payload?.error_code ?? null;
        if (isConfirmedScanNotFoundError(err)) {
          clearStaleActiveScanId(scanId, requestSession);
        }
        setQueueState({status: 'error', data: null, error: err?.message || 'Không tải được hàng đợi kiểm duyệt.', statusCode, errorCode});
        setHistoryState({status: 'error', data: null, error: err?.message || 'Không tải được lịch sử kiểm duyệt.', statusCode, errorCode});
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [scanId, refreshTick, apiOrigin, authSessionScope, apiRevision]);

  const queueData = queueState.data;
  const queueOriginInfo = useMemo(() => (queueData ? classifyDataOrigin(queueData) : null), [queueData]);
  const counts = queueData?.counts || {};
  const writable = queueData?.writable !== false;
  const rows = useMemo(
    () => (Array.isArray(queueData?.warnings) ? queueData.warnings.map(normalizeFinding) : []),
    [queueData],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rows.filter((row) => {
      if (stateFilter && row.humanReviewState !== stateFilter) return false;
      if (validatedFilter && row.validatedStatus !== validatedFilter) return false;
      if (cweFilter && row.cwe !== cweFilter) return false;
      if (q) {
        const hay = `${row.id} ${row.cwe} ${row.file} ${row.ruleId} ${row.title}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rows, stateFilter, validatedFilter, cweFilter, search]);

  const cweOptions = useMemo(
    () => [...new Set([...PRIORITY_CWES, ...rows.map((r) => r.cwe).filter(Boolean)])],
    [rows],
  );

  return (
    <>
      <PageHeader
        eyebrow="HUMAN REVIEW & SOURCE DRIFT"
        title="Hàng đợi xác minh cảnh báo"
        actions={(
          <button type="button" className="button-secondary" onClick={triggerRefresh}>
            <Icon name="RotateCcw" />Làm mới
          </button>
        )}
      />

      {queueState.status === 'loading' && <DataNotice>Đang tải hàng đợi Human Review từ SQLite…</DataNotice>}
      {queueState.status === 'error' && (
        <>
          <EmptyState title="Không tải được hàng đợi kiểm duyệt" text={queueState.error} icon="AlertTriangle" />
          <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px'}}>
            <button type="button" className="button-primary" onClick={triggerRefresh}>Thử lại</button>
            {(queueState.statusCode === 401 || queueState.statusCode === 403 || /UNAUTHORIZED|Bearer Token|HTTP 401|HTTP 403/i.test(queueState.error || '')) && (
              <button type="button" className="button-secondary" onClick={() => outlet?.openConnectionPanel?.()}>
                <Icon name="KeyRound" />Nhập Bearer Token phiên
              </button>
            )}
            {queueState.statusCode === 404 && (
              <button
                type="button"
                className="button-secondary"
                onClick={() => {
                  if (queueState.errorCode === 'SCAN_NOT_FOUND') {
                    clearStaleActiveScanId(scanId);
                  }
                  navigate('/history', {replace: true});
                }}
              >
                <Icon name="ArrowLeft" />Chọn phiên trên API hiện tại
              </button>
            )}
          </div>
        </>
      )}

      {queueData && (
        <>
          {queueOriginInfo?.isUnverified && !queueOriginInfo.isMockOrTest && (
            <DataNotice>
              Nguồn gốc dữ liệu phiên quét là <code>{queueOriginInfo.code}</code> ({queueOriginInfo.label}); chưa có đủ bằng chứng xác minh phiên quét thực.
            </DataNotice>
          )}
          {!writable && (
            <DataNotice>
              Thư mục phiên quét ở chế độ chỉ đọc (<code>SCAN_READ_ONLY</code>). Bạn có thể xem hàng đợi và lịch sử, nhưng không thể ghi quyết định mới.
            </DataNotice>
          )}

          <div className="stats-grid">
            <StatCard label="Chờ kiểm duyệt (OPEN)" value={counts.open_count ?? 0} note="Chưa có quyết định con người" icon="Eye" />
            <StatCard label="REFUTED đang mở" value={counts.proposed_refuted_open_count ?? 0} note="AI nghi giả, vẫn chờ xác nhận" icon="AlertTriangle" />
            <StatCard label="UNDETERMINED đang mở" value={counts.undetermined_open_count ?? 0} note="Chưa đủ bằng chứng" icon="HelpCircle" />
            <StatCard
              label="Đã xác nhận (Thật / Giả)"
              value={`${counts.confirmed_true_count ?? 0} / ${counts.confirmed_false_count ?? 0}`}
              note={`Tổng ${counts.total_in_scan ?? rows.length} cảnh báo trong phiên`}
              icon="ShieldCheck"
            />
          </div>

          <section className="section-block">
            <SectionTitle title="Danh sách cảnh báo cần kiểm duyệt" />
            <Card className="v2-review-filter-card" style={{marginBottom: '14px'}}>
              <div className="v2-review-toolbar">
                <div className="ntk-p05-input-group v2-review-status-field">
                  <span>Trạng thái</span>
                  <div className="v2-review-status-group" role="group" aria-label="Lọc theo trạng thái người kiểm duyệt">
                    {[
                      ['', 'Tất cả trong hàng đợi'],
                      ['CONFIRMED_TRUE', 'CONFIRMED_TRUE'],
                      ['CONFIRMED_FALSE', 'CONFIRMED_FALSE'],
                    ].map(([val, label]) => (
                      <button
                        key={label}
                        type="button"
                        className={`v2-filter-pill v2-review-status-pill ${stateFilter === val ? 'active' : ''}`}
                        onClick={() => setStateFilter(val)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <label className="ntk-p05-input-group v2-review-search-field">
                  <span>Tìm kiếm</span>
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Mã cảnh báo, tệp Java, rule…"
                  />
                </label>
                <label className="ntk-p05-input-group v2-review-select-field">
                  <span>Loại CWE</span>
                  <select value={cweFilter} onChange={(e) => setCweFilter(e.target.value)}>
                    <option value="">Tất cả CWE</option>
                    {cweOptions.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </label>
                <label className="ntk-p05-input-group v2-review-select-field">
                  <span>Nhận định Qwen</span>
                  <select value={validatedFilter} onChange={(e) => setValidatedFilter(e.target.value)}>
                    <option value="">Tất cả</option>
                    <option value="SUPPORTED">SUPPORTED</option>
                    <option value="REFUTED">REFUTED</option>
                    <option value="UNDETERMINED">UNDETERMINED</option>
                  </select>
                </label>
              </div>
            </Card>

            {filtered.length === 0 ? (
              <EmptyState
                title="Không có cảnh báo khớp bộ lọc"
                text="Thay đổi bộ lọc trạng thái, loại CWE, nhận định Qwen hoặc từ khóa tìm kiếm để xem các cảnh báo khác."
              />
            ) : (
              filtered.map((row) => (
                <ReviewQueueItem
                  key={row.id}
                  row={row}
                  scanId={scanId}
                  writable={writable}
                  onRefreshAll={triggerRefresh}
                />
              ))
            )}
          </section>

          <section className="section-block">
            <SectionTitle
              title="Nhật ký kiểm duyệt toàn phiên (SQLite Audit Trail)"
              text="Ghi nhận đầy đủ confirm-true, confirm-false, reopen và các quyết định bị từ chối."
            />
            <Card>
              {historyState.status === 'loading' && <DataNotice>Đang tải nhật ký sự kiện kiểm duyệt…</DataNotice>}
              {historyState.status === 'error' && <div className="inline-error">{historyState.error}</div>}
              {historyState.data && (
                <AuditTimeline
                  events={historyState.data.events}
                  rejectedDecisions={historyState.data.rejected_decisions}
                  showWarningId
                />
              )}
            </Card>
          </section>
        </>
      )}
    </>
  );
}

export default function ReviewPage() {
  const outlet = useOutletContext();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const scanId = params.get('scan_id') || window.sessionStorage.getItem(ACTIVE_KEY) || '';
  const [scans, setScans] = useState({status: 'idle', items: [], error: '', statusCode: null});

  useEffect(() => {
    if (scanId) return undefined;
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    setScans({status: 'loading', items: [], error: '', statusCode: null});
    api.listScans({signal: controller.signal})
      .then((res) => {
        if (isStale()) return;
        const safeItems = (res.items || []).filter(
          (scan) => scan && typeof scan === 'object' && typeof scan.scan_id === 'string' && scan.scan_id.trim() && !classifyDataOrigin(scan).isMockOrTest,
        );
        setScans({status: 'ready', items: safeItems, error: '', statusCode: null});
      })
      .catch((err) => {
        if (isStale() || err?.abortedByConfigChange) return;
        setScans({status: 'error', items: [], error: err?.message || 'Không tải được danh sách phiên quét.', statusCode: err?.status ?? null});
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [scanId, apiOrigin, authSessionScope, apiRevision]);

  if (scanId) return <LiveReviewWorkspace key={`${authSessionScope}:${scanId}`} scanId={scanId} />;

  return (
    <>
      <PageHeader
        eyebrow="HUMAN REVIEW"
        title="Xác minh cảnh báo"
        description="Chọn một phiên quét để mở hàng đợi Human Review và đối chiếu lịch sử kiểm duyệt SQLite."
      />
      {scans.status === 'loading' && <DataNotice>Đang tải danh sách phiên quét từ API…</DataNotice>}
      {scans.status === 'error' && (
        <>
          <DataNotice>Không tải được danh sách phiên quét: {scans.error}</DataNotice>
          {(scans.statusCode === 401 || scans.statusCode === 403 || /UNAUTHORIZED|Bearer Token|HTTP 401|HTTP 403/i.test(scans.error || '')) && (
            <button type="button" className="button-secondary" onClick={() => outlet?.openConnectionPanel?.()}>
              <Icon name="KeyRound" />Nhập Bearer Token phiên
            </button>
          )}
        </>
      )}
      {scans.status === 'ready' && scans.items.length > 0 ? (
        scans.items.map((scan) => {
          const scanOrigin = classifyDataOrigin(scan);
          return (
            <Card key={scan.scan_id} className="v2-scan-picker-row">
              <div className="v2-scan-picker-info">
                <Badge tone={scanOrigin.tone}>{scanOrigin.label}</Badge>
                <h3 className="mono">{scan.repo_url || scan.file_name || scan.scan_id}</h3>
                <p>
                  OPEN: {scan.by_human_review_state?.OPEN ?? 0} · CONFIRMED_TRUE: {scan.by_human_review_state?.CONFIRMED_TRUE ?? 0} ·
                  CONFIRMED_FALSE: {scan.by_human_review_state?.CONFIRMED_FALSE ?? 0}
                </p>
              </div>
              <button
                type="button"
                className="button-secondary"
                onClick={() => navigate(`/review${scanQuery(scan.scan_id)}`)}
              >
                Mở hàng đợi <Icon name="ArrowRight" />
              </button>
            </Card>
          );
        })
      ) : scans.status === 'ready' ? (
        <EmptyState
          title="Chưa có phiên quét nào"
          text="Mở Phân tích dự án để chạy quét mã nguồn Java trước khi kiểm duyệt."
        />
      ) : null}
    </>
  );
}
