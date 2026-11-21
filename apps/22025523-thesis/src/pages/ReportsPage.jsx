import {useEffect, useMemo, useRef, useState} from 'react';
import {Link, useNavigate, useOutletContext} from 'react-router-dom';
import {Badge, Card, DataNotice, EmptyState, Icon, PageHeader, SectionTitle, StatCard} from '../components/common/Ui';
import {AuditTimeline} from '../components/review/HumanReviewPanel';
import {api, getApiOrigin, getAuthSessionScope} from '../services/api';
import {
  citationCheckTone,
  humanReviewMeta,
  NO_FINDINGS_NOTICE,
  runtimeVerificationMeta,
  validatedStatusMeta,
} from '../services/findingPresentation';
import {clearStaleActiveScanId, isConfirmedScanNotFoundError, scanQuery, useScanSelection} from '../services/liveScan';
import {buildReportViewModel, validateReportForScan} from '../services/reportModel';

function saveJson(name, payload) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'}));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function selectEffectiveReportState(reportState, {reportKey, scanId}) {
  if (reportState && reportState.key === reportKey && reportState.scanId === scanId) {
    return reportState;
  }
  return {
    key: reportKey,
    scanId,
    status: scanId ? 'loading' : 'idle',
    data: null,
    error: '',
    statusCode: null,
  };
}

export function createReportLoadRunner({
  apiClient = api,
  getOrigin = getApiOrigin,
  getSession = getAuthSessionScope,
  onNotFound = clearStaleActiveScanId,
  onState,
} = {}) {
  let seq = 0;
  let activeController = null;
  return {
    load(scanId, reportKey) {
      seq += 1;
      const reqSeq = seq;
      activeController?.abort();
      activeController = null;
      if (!scanId) {
        onState?.({key: '', scanId: '', status: 'idle', data: null, error: '', statusCode: null});
        return {cancel: () => {}, promise: Promise.resolve({status: 'idle'})};
      }
      const controller = new AbortController();
      activeController = controller;
      const requestOrigin = getOrigin();
      const requestSession = getSession();
      let active = true;
      const isStale = () => (
        !active ||
        controller.signal.aborted ||
        seq !== reqSeq ||
        getOrigin() !== requestOrigin ||
        getSession() !== requestSession
      );
      onState?.({
        key: reportKey,
        scanId,
        status: 'loading',
        data: null,
        error: '',
        statusCode: null,
      });
      const promise = apiClient.report(scanId, {signal: controller.signal})
        .then((doc) => {
          if (isStale()) return {stale: true};
          const identity = validateReportForScan(doc, scanId);
          if (!identity.valid) {
            const next = {
              key: reportKey,
              scanId,
              status: 'error',
              data: null,
              error: identity.error,
              statusCode: null,
            };
            onState?.(next);
            return next;
          }
          const next = {
            key: reportKey,
            scanId,
            status: 'ready',
            data: doc,
            error: '',
            statusCode: null,
          };
          onState?.(next);
          return next;
        })
        .catch((err) => {
          if (isStale() || err?.abortedByConfigChange) return {stale: true};
          const statusCode = err?.status ?? null;
          const errorCode = err?.code ?? err?.payload?.error_code ?? null;
          if (isConfirmedScanNotFoundError(err)) {
            onNotFound?.(scanId, requestSession);
          }
          const next = {
            key: reportKey,
            scanId,
            status: 'error',
            data: null,
            error: err?.message || 'Không tải được báo cáo từ API.',
            statusCode,
            errorCode,
          };
          onState?.(next);
          return next;
        });
      return {
        cancel: () => {
          active = false;
          controller.abort();
        },
        promise,
      };
    },
    cancelAll() {
      seq += 1;
      activeController?.abort();
      activeController = null;
    },
  };
}

export default function ReportsPage() {
  const outlet = useOutletContext();
  const navigate = useNavigate();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const sel = useScanSelection(apiRevision);
  const reportKey = sel.scanId ? `${authSessionScope}|${apiOrigin}|${apiRevision}|${sel.scanId}` : '';
  const [reportState, setReportState] = useState({
    key: '',
    scanId: '',
    status: 'idle',
    data: null,
    error: '',
    statusCode: null,
  });
  const runnerRef = useRef(null);
  if (!runnerRef.current) {
    runnerRef.current = createReportLoadRunner({onState: setReportState});
  }

  useEffect(() => {
    const task = runnerRef.current.load(sel.scanId, reportKey);
    return () => {
      task.cancel();
    };
  }, [sel.scanId, reportKey, apiOrigin, authSessionScope, apiRevision]);

  const effectiveReport = selectEffectiveReportState(reportState, {reportKey, scanId: sel.scanId});

  const verifiedReportData = useMemo(() => {
    if (effectiveReport.status !== 'ready' || !sel.scanId || effectiveReport.scanId !== sel.scanId) {
      return null;
    }
    return validateReportForScan(effectiveReport.data, sel.scanId).valid ? effectiveReport.data : null;
  }, [effectiveReport, sel.scanId]);

  const model = useMemo(
    () => (verifiedReportData ? buildReportViewModel(verifiedReportData, {expectedScanId: sel.scanId}) : null),
    [verifiedReportData, sel.scanId],
  );

  const canDownloadReport = Boolean(
    model &&
    model.isVerifiedRealScan &&
    !model.isMockOrTest &&
    model.canExportReport &&
    model.canExportVerifiedReport &&
    verifiedReportData &&
    effectiveReport.status === 'ready' &&
    effectiveReport.key === reportKey &&
    effectiveReport.scanId === sel.scanId,
  );

  if (sel.mode !== 'live') {
    return (
      <>
        <PageHeader eyebrow="BÁO CÁO PHÂN TÍCH" title="Báo cáo phiên quét" />
        <EmptyState
          title="Chưa chọn phiên phân tích"
          text="Chọn một phiên từ Lịch sử phân tích để xem báo cáo OpenGrep, Qwen, trích dẫn SHA-256 và lịch sử kiểm duyệt Human Review."
          icon="FileText"
        />
        <div style={{marginTop: '12px'}}>
          <Link className="button-secondary" to="/history">Chọn phiên phân tích <Icon name="ArrowRight" /></Link>
        </div>
      </>
    );
  }

  if (effectiveReport.status === 'loading' || (sel.status === 'loading' && effectiveReport.status === 'idle')) {
    return (
      <>
        <PageHeader eyebrow="BÁO CÁO PHÂN TÍCH" title="Báo cáo phiên quét" description={`Phiên quét: ${sel.scanId}`} />
        <DataNotice>Đang tải báo cáo chi tiết, bằng chứng trích dẫn và lịch sử kiểm duyệt từ API…</DataNotice>
      </>
    );
  }

  if (effectiveReport.status === 'error') {
    const needsAuth = effectiveReport.statusCode === 401 || effectiveReport.statusCode === 403 || /UNAUTHORIZED|Bearer Token|HTTP 401|HTTP 403/i.test(effectiveReport.error || '');
    return (
      <>
        <PageHeader eyebrow="BÁO CÁO PHÂN TÍCH" title="Báo cáo phiên quét" description={`Phiên quét: ${sel.scanId}`} />
        <EmptyState title="Không tải được báo cáo từ API" text={effectiveReport.error} icon="AlertTriangle" />
        <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px'}}>
          {needsAuth && (
            <button type="button" className="button-secondary" onClick={() => outlet?.openConnectionPanel?.()}>
              <Icon name="KeyRound" />Nhập Bearer Token phiên
            </button>
          )}
          {effectiveReport.statusCode === 404 && (
            <button
              type="button"
              className="button-secondary"
              onClick={() => {
                if (effectiveReport.errorCode === 'SCAN_NOT_FOUND') {
                  clearStaleActiveScanId(sel.scanId);
                }
                navigate('/history', {replace: true});
              }}
            >
              <Icon name="ArrowLeft" />Chọn phiên trên API hiện tại
            </button>
          )}
        </div>
      </>
    );
  }

  if (!model) return null;

  if (model.isMockOrTest) {
    return (
      <>
        <PageHeader eyebrow="BÁO CÁO PHÂN TÍCH" title="Báo cáo phiên quét" description={`Phiên quét: ${sel.scanId}`} />
        <EmptyState
          title="Dữ liệu mô phỏng (mock) bị chặn xuất báo cáo"
          text="Hệ thống không xuất dữ liệu synthetic/mock thành bằng chứng vận hành thực."
          icon="ShieldAlert"
        />
      </>
    );
  }

  const rtMeta = runtimeVerificationMeta(model.qwenStats.runtimeVerified);

  return (
    <>
      <PageHeader
        eyebrow="BÁO CÁO PHÂN TÍCH & AUDIT TRAIL"
        title="Báo cáo phiên quét"
        description={`Phiên ${model.scanInfo.scanId} · Xuất lúc ${model.generatedAt || '-'}`}
        actions={(
          <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
            <Link to={`/findings${scanQuery(sel.scanId)}`} className="button-secondary">
              Xem cảnh báo <Icon name="ArrowRight" />
            </Link>
            <Link to={`/review${scanQuery(sel.scanId)}`} className="button-secondary">
              <Icon name="Shield" />Hàng đợi Human Review
            </Link>
            <button
              type="button"
              className="button-primary"
              disabled={!canDownloadReport}
              onClick={() => {
                if (!canDownloadReport) return;
                if (!validateReportForScan(verifiedReportData, sel.scanId).valid) return;
                const latestModel = buildReportViewModel(verifiedReportData, {expectedScanId: sel.scanId});
                if (
                  !latestModel ||
                  latestModel.isMockOrTest ||
                  !latestModel.isVerifiedRealScan ||
                  !latestModel.canExportReport ||
                  !latestModel.canExportVerifiedReport
                ) {
                  return;
                }
                saveJson(`${sel.scanId}-report.json`, verifiedReportData);
              }}
            >
              <Icon name="FileText" />Tải báo cáo JSON
            </button>
          </div>
        )}
      />

      <DataNotice>
        Nguyên tắc báo cáo: nhận định <strong>REFUTED</strong> từ Qwen3.5-9B <strong>không phải</strong>{' '}
        <strong>CONFIRMED_FALSE</strong>; cảnh báo chỉ được xác nhận giả khi người kiểm duyệt quyết định và mã nguồn khớp SHA-256.
      </DataNotice>
      {model.isUnverified && (
        <DataNotice>
          Nguồn gốc dữ liệu báo cáo là <code>{model.dataOrigin}</code> ({model.provenanceStatus?.reason || 'UNVERIFIED_ORIGIN'}): chưa đủ bằng chứng xác minh phiên quét thực, hệ thống khóa xuất báo cáo như dữ liệu đã xác minh.
        </DataNotice>
      )}

      <div className="stats-grid" style={{marginTop: '14px'}}>
        <StatCard label="Cảnh báo OpenGrep" value={model.opengrepStats.totalFindings} note={`${model.opengrepStats.findingsWithTrace} có dataflow trace`} icon="Bug" />
        <StatCard label="Qwen: SUPPORTED / REFUTED" value={`${model.qwenStats.supported} / ${model.qwenStats.refuted}`} note={`Hạ cấp: ${model.qwenStats.downgradedCount} · Khớp trích dẫn: ${model.qwenStats.matchedCitations}`} icon="Cpu" />
        <StatCard label="Trạng thái UNDETERMINED" value={model.qwenStats.undetermined} note="Chưa đủ bằng chứng — giữ nguyên" icon="HelpCircle" />
        <StatCard label="Chờ duyệt (OPEN)" value={model.humanReviewStats.unreviewedOpen} note={`REFUTED còn OPEN: ${model.humanReviewStats.refutedStillOpen ?? 'Chưa xác định'} · Thật ${model.humanReviewStats.confirmedTrue} · Giả ${model.humanReviewStats.confirmedFalse}`} icon="Eye" />
      </div>

      <section className="section-block">
        <SectionTitle title="1. Thông tin lượt quét, nguồn Java & phạm vi CWE" />
        <Card>
          <div className="thesis-grid">
            <div><span>MÃ PHIÊN (SCAN ID)</span><strong className="mono">{model.scanInfo.scanId}</strong></div>
            <div><span>SCAN SHA-256</span><strong className="mono">{model.scanInfo.scanSha256}</strong></div>
            <div><span>NGUỒN DỮ LIỆU</span><strong>{model.dataOrigin}</strong></div>
            <div><span>NGUỒN MÃ JAVA ({model.scanInfo.inputMode})</span><strong className="mono">{model.scanInfo.sourceTarget}</strong></div>
            {model.scanInfo.resolvedCommit && <div><span>COMMIT SHA</span><strong className="mono">{model.scanInfo.resolvedCommit}</strong></div>}
            <div><span>SỐ TỆP JAVA ĐÃ QUÉT</span><strong>{model.scanInfo.javaFilesScanned}</strong></div>
            <div><span>OPENGREP VERSION</span><strong className="mono">{model.scanInfo.opengrepVersion}</strong></div>
            <div><span>RULES SHA-256</span><strong className="mono">{model.scanInfo.rulesSha256}</strong></div>
            <div><span>TRẠNG THÁI RUNTIME QWEN</span><strong>{rtMeta.label}</strong></div>
          </div>
          <div style={{marginTop: '14px', display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center'}}>
            <span style={{fontSize: '13px', color: 'var(--v2-text-secondary)'}}>Phạm vi CWE phát hiện:</span>
            {model.cweBreakdown.length === 0 ? (
              <Badge tone="neutral">Không có cảnh báo (NO_FINDINGS)</Badge>
            ) : (
              model.cweBreakdown.map(([cwe, count]) => (
                <Badge key={cwe} tone={cwe === 'CWE-22' || cwe === 'CWE-89' ? 'blue' : 'neutral'}>
                  {cwe}: {count}
                </Badge>
              ))
            )}
          </div>
        </Card>
      </section>

      <section className="section-block">
        <SectionTitle
          title="2. Chi tiết cảnh báo, trích dẫn & mã băm SHA-256"
          text="Ghi nhận đầy đủ nhận định Qwen, trích dẫn mã nguồn, snapshot SHA-256 và quyết định của người kiểm duyệt."
        />
        {model.findingRows.length === 0 ? (
          <Card><p className="muted-text" style={{margin: 0}}>{NO_FINDINGS_NOTICE}</p></Card>
        ) : (
          <div style={{display: 'grid', gap: '12px'}}>
            {model.findingRows.map((row) => (
              <Card key={row.id}>
                <div style={{display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: '8px', marginBottom: '8px'}}>
                  <div style={{display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center'}}>
                    <Badge tone="blue">{row.cwe}</Badge>
                    <Badge tone={validatedStatusMeta(row.validatedStatus).tone}>AI: {row.validatedStatus}</Badge>
                    <Badge tone={humanReviewMeta(row.humanReviewState).tone}>Người duyệt: {row.humanReviewState}</Badge>
                    <Badge tone={citationCheckTone(row.citationCheck)}>Trích dẫn: {row.citationCheck}</Badge>
                  </div>
                  <Link to={`/finding/${encodeURIComponent(row.id)}${scanQuery(sel.scanId)}`} className="button-secondary button-compact">
                    Mở chi tiết <Icon name="ArrowRight" />
                  </Link>
                </div>
                <p className="mono wrap-value" style={{fontSize: '12px', color: 'var(--v2-text-secondary)', margin: '4px 0'}}>
                  {row.id} · {row.ruleId} · {row.filePath}:{row.startLine}
                </p>
                {row.failureKind && (
                  <p style={{fontSize: '12px', color: 'var(--v2-warn-text)', margin: '4px 0'}}>
                    Lý do kiểm chứng / hạ cấp: {row.failureKind}
                  </p>
                )}
                {row.citations.length > 0 && (
                  <div style={{marginTop: '10px', display: 'grid', gap: '8px'}}>
                    <strong style={{fontSize: '12px', color: 'var(--v2-silver)'}}>Trích dẫn đã ghi nhận:</strong>
                    {row.citations.map((c, idx) => (
                      <div key={`${row.id}-cite-${idx}`} style={{fontSize: '12px'}}>
                        <span className="mono">{c.path}:{c.startLine}{c.endLine && c.endLine !== c.startLine ? `-${c.endLine}` : ''}</span>
                        {' · '}
                        <span className="mono wrap-value" style={{color: 'var(--v2-text-muted)'}}>SHA-256: {c.sha256 || 'thiếu'}</span>
                        {c.quote && <pre className="v2-pre-block" style={{marginTop: '6px'}}><code>{c.quote}</code></pre>}
                      </div>
                    ))}
                  </div>
                )}
                {row.snapshots.length > 0 && (
                  <p className="mono wrap-value" style={{marginTop: '10px', marginBottom: 0, fontSize: '11.5px', color: 'var(--v2-text-muted)'}}>
                    Source Snapshots SHA-256: {row.snapshots.map((s) => `${s.path} (${s.sha256})`).join(' · ')}
                  </p>
                )}
              </Card>
            ))}
          </div>
        )}
      </section>

      <section className="section-block">
        <SectionTitle
          title={`3. Lịch sử quyết định Human Review (${model.humanReviewStats.eventsCount} sự kiện · ${model.humanReviewStats.rejectedCount} từ chối)`}
        />
        <Card>
          <AuditTimeline events={model.events} rejectedDecisions={model.rejectedDecisions} showWarningId />
        </Card>
      </section>

      <section className="section-block">
        <SectionTitle title="4. Giới hạn và lỗi của lượt phân tích" />
        <Card>
          {model.stageStatuses && (
            <details className="v2-sub-details" style={{marginBottom: '12px'}}>
              <summary>Trạng thái các chặng pipeline (stage_statuses)</summary>
              <div className="v2-sub-details-body">
                <pre className="v2-pre-block"><code>{JSON.stringify(model.stageStatuses, null, 2)}</code></pre>
              </div>
            </details>
          )}
          {model.scanIssues.length > 0 && (
            <div style={{marginBottom: '12px'}}>
              <strong style={{color: 'var(--v2-danger-text)'}}>Lỗi / cảnh báo thu thập bằng chứng:</strong>
              <ul>
                {model.scanIssues.map((issue, idx) => <li key={`issue-${idx}`}>{String(issue)}</li>)}
              </ul>
            </div>
          )}
          {model.pairedPilotExportError && (
            <p className="inline-error">Lỗi xuất paired pilot export: {model.pairedPilotExportError}</p>
          )}
          <strong style={{display: 'block', marginBottom: '6px'}}>Giới hạn phân tích đã công bố:</strong>
          <ul style={{margin: 0, paddingLeft: '20px', color: 'var(--v2-text-secondary)'}}>
            {model.limits.map((lim, idx) => <li key={`lim-${idx}`}>{lim}</li>)}
          </ul>
        </Card>
      </section>
    </>
  );
}
