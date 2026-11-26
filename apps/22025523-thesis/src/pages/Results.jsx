import {useCallback, useEffect, useState} from 'react';
import {Link, useLocation, useNavigate, useOutletContext, useParams, useSearchParams} from 'react-router-dom';
import {Card, PageHeader, Badge, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import HumanReviewPanel from '../components/review/HumanReviewPanel';
import {ACTIVE_KEY, clearStaleActiveScanId, scanQuery} from '../services/liveScan';
import {api, getApiBaseUrl, getApiOrigin, getAuthSessionScope, safeSessionGet} from '../services/api';
import {verifyFindingIdentity} from '../services/reviewModel';
import {LiveFindings as LiveDashboard} from './LiveFindings';
import {
  analyzeDataflow,
  citationCheckMeta,
  citationCheckTone,
  classifyDataOrigin,
  describeDowngradeReason,
  fileName,
  findReportedId,
  firstText,
  formatShortHash,
  getCweGuide,
  humanReviewMeta,
  normalizeFailureKind,
  resolveFindingSourceHash,
  resolveSnippetHashStatus,
  runtimeVerificationMeta,
  validatedStatusMeta,
} from '../services/findingPresentation';

function useActiveScanId() {
  const [params] = useSearchParams();
  return params.get('scan_id') || safeSessionGet(ACTIVE_KEY) || '';
}

function useRemote(load, deps) {
  const [state, setState] = useState({status: 'loading', data: null, error: '', statusCode: null, errorCode: null});
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const requestBaseUrl = getApiBaseUrl();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => (
      !active
      || controller.signal.aborted
      || getApiBaseUrl() !== requestBaseUrl
      || getApiOrigin() !== requestOrigin
      || getAuthSessionScope() !== requestSession
    );
    setState({status: 'loading', data: null, error: '', statusCode: null, errorCode: null});
    load(controller.signal)
      .then((data) => {
        if (isStale()) return;
        setState({status: 'success', data, error: '', statusCode: null, errorCode: null});
      })
      .catch((error) => {
        if (isStale() || error?.abortedByConfigChange) {
          return;
        }
        setState({
          status: 'error',
          data: null,
          error: error?.message || 'Không thể tải dữ liệu từ API.',
          statusCode: error?.status ?? null,
          errorCode: error?.code ?? null,
        });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [...deps, attempt]);
  const retry = useCallback(() => setAttempt((value) => value + 1), []);
  return [state, retry];
}

function CopyHashButton({value, label = 'Sao chép SHA-256'}) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  const copy = () => {
    navigator.clipboard?.writeText(value).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    }).catch(() => {});
  };
  return (
    <button type="button" className="button-secondary button-compact" onClick={copy} aria-label={label}>
      <Icon name={copied ? 'Check' : 'Copy'} />
      <span>{copied ? 'Đã chép' : 'Sao chép'}</span>
    </button>
  );
}

export function FindingPrimaryHashField({primaryHash}) {
  const info = primaryHash || {
    status: 'UNVERIFIED',
    sha256: '',
    conflictingHashes: [],
    tone: 'neutral',
    label: 'Chưa có SHA-256',
    reason: '',
  };
  if (info.sha256) {
    return (
      <div data-testid="finding-primary-sha" data-hash-status={info.status}>
        <div style={{display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center'}}>
          <code title={info.sha256}>{formatShortHash(info.sha256, 14, 8)}</code>
          <CopyHashButton value={info.sha256} />
          <Badge tone={info.tone || 'neutral'}>{info.label}</Badge>
        </div>
        {info.reason && (
          <span className="panel-note" style={{fontSize: '12px', display: 'block', marginTop: '4px'}}>
            {info.reason}
          </span>
        )}
      </div>
    );
  }
  return (
    <div data-testid="finding-primary-sha" data-hash-status={info.status}>
      <div style={{display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center'}}>
        <Badge tone={info.tone || 'amber'}>{info.label || 'Chưa xác minh'}</Badge>
      </div>
      {info.reason && (
        <span className="panel-note" style={{fontSize: '12px', display: 'block', marginTop: '4px'}}>
          {info.reason}
        </span>
      )}
      {info.status === 'CONFLICT' && Array.isArray(info.conflictingHashes) && info.conflictingHashes.length > 0 && (
        <span className="panel-note mono" style={{fontSize: '11.5px', display: 'block', marginTop: '4px'}}>
          Giá trị mâu thuẫn: {info.conflictingHashes.map((h) => formatShortHash(h, 8, 6)).join(' ≠ ')}
        </span>
      )}
    </div>
  );
}

export function SnippetViewer({snippet, evidence}) {
  const [showFullHash, setShowFullHash] = useState(false);
  const lines = Array.isArray(snippet?.lines) ? snippet.lines : [];
  const startLine = Number(snippet?.start?.line);
  const endLine = Number(snippet?.end?.line);
  const matched = snippet?.matched;
  const roleLabel = String(snippet?.role || 'snippet').toUpperCase();
  const hashInfo = resolveSnippetHashStatus(snippet, evidence);
  const displayPath = hashInfo.displayPath || snippet?.path || '-';

  return (
    <section className="v2-code-card" aria-label={`Đoạn mã ${displayPath}`}>
      <div className="v2-code-header">
        <div className="v2-code-meta">
          <Badge tone={roleLabel === 'SINK' || roleLabel === 'FINDING' ? 'red' : 'blue'}>{roleLabel}</Badge>
          <span className="mono v2-code-path">{displayPath}</span>
          {Number.isFinite(startLine) && (
            <span className="mono" style={{color: 'var(--v2-text-secondary)'}}>
              dòng {startLine}{Number.isFinite(endLine) && endLine !== startLine ? `–${endLine}` : ''}
            </span>
          )}
        </div>
        <div style={{display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap'}}>
          {hashInfo.status !== 'UNVERIFIED' && (
            <Badge tone={hashInfo.tone}>{hashInfo.label}</Badge>
          )}
          {hashInfo.sha256 && (
            <>
              <button
                type="button"
                className="button-secondary button-compact mono"
                onClick={() => setShowFullHash((v) => !v)}
                title="Nhấn để xem đầy đủ SHA-256"
              >
                SHA-256: {showFullHash ? 'Thu gọn' : formatShortHash(hashInfo.sha256, 10, 6)}
              </button>
              <CopyHashButton value={hashInfo.sha256} />
            </>
          )}
        </div>
      </div>

      {hashInfo.status === 'CONFLICT' && hashInfo.conflictingHashes.length > 0 && (
        <div className="v2-hash-bar mono">
          <span className="v2-hash-text">
            Xung đột SHA-256 trên cùng tệp ({hashInfo.conflictingHashes.length} giá trị khác nhau; không hiển thị hash xác minh):{' '}
            {hashInfo.conflictingHashes.map((h) => formatShortHash(h, 8, 6)).join(' ≠ ')}
          </span>
        </div>
      )}

      {showFullHash && hashInfo.sha256 && (
        <div className="v2-hash-bar mono">
          <span className="v2-hash-text">SHA-256 đầy đủ ({hashInfo.label}): {hashInfo.sha256}</span>
        </div>
      )}

      {lines.length > 0 ? (
        <div className="v2-code-lines">
          {lines.map((entry) => {
            const ln = Number(entry?.line);
            const highlight = Number.isFinite(startLine) && Number.isFinite(endLine) && ln >= startLine && ln <= endLine;
            return (
              <div key={`${displayPath}-${ln}`} className={`v2-code-line ${highlight ? 'is-highlight' : ''}`}>
                <span className="v2-line-no">{ln}</span>
                <span className="v2-line-code">{entry?.text ?? ''}</span>
              </div>
            );
          })}
        </div>
      ) : matched ? (
        <pre className="v2-pre-block" style={{border: 'none', borderRadius: 0}}><code>{matched}</code></pre>
      ) : (
        <p className="panel-note" style={{padding: '14px 16px', margin: 0}}>
          API không trả về các dòng mã chi tiết cho đoạn trích này.
        </p>
      )}
    </section>
  );
}

export function DataflowTraceSection({dataflow}) {
  const steps = Array.isArray(dataflow?.steps) ? dataflow.steps : [];
  const completeness = dataflow?.completeness || (steps.length ? 'PARTIAL' : 'NONE');

  if (!steps.length || completeness === 'NONE') {
    return (
      <Card title="5. Luồng dữ liệu (Dataflow)">
        <p className="panel-note" style={{margin: 0}}>
          {dataflow?.hadInvalidInput
            ? 'Dữ liệu dataflow trace trong bằng chứng bị thiếu hoặc sai định dạng vị trí/số dòng nên hệ thống không hiển thị bước suy diễn. Bạn có thể kiểm tra dữ liệu gốc ở mục 8 (Chi tiết kỹ thuật mở rộng).'
            : 'OpenGrep không ghi nhận dataflow trace chi tiết cho cảnh báo này. Vui lòng đối chiếu trực tiếp đoạn mã nguồn Java và ngữ cảnh phương thức ở mục trên.'}
        </p>
      </Card>
    );
  }

  const isPartial = completeness === 'PARTIAL';
  const title = isPartial
    ? '5. Bằng chứng luồng dữ liệu (một phần)'
    : dataflow.hasIntermediate
      ? '5. Luồng dữ liệu Source → Intermediate → Sink'
      : '5. Luồng dữ liệu Source → Sink';

  const missingParts = [];
  if (!dataflow.hasSource) missingParts.push('điểm nguồn SOURCE');
  if (!dataflow.hasSink) missingParts.push('điểm thực thi SINK');

  return (
    <Card
      title={title}
      action={isPartial ? <Badge tone="amber">Bằng chứng một phần</Badge> : undefined}
    >
      {isPartial && (
        <div className="inline-warning" role="status" style={{marginTop: 0, marginBottom: '14px'}}>
          <Icon name="AlertTriangle" />
          <span>
            Chỉ ghi nhận một phần luồng dữ liệu (thiếu {missingParts.join(' và ')}); chưa đủ căn cứ để khẳng định chuỗi Source → Sink hoàn chỉnh.
            Kiểm tra thêm bằng chứng gốc tại mục 8.
          </span>
        </div>
      )}
      {!isPartial && (dataflow.source === 'raw_trace' || dataflow.source === 'merged') && dataflow.droppedSnippetCount > 0 && (
        <p className="panel-note" style={{marginTop: 0, marginBottom: '12px', fontSize: '12px'}}>
          Đã bỏ qua {dataflow.droppedSnippetCount} mục snippet thiếu vị trí/số dòng hợp lệ và hiển thị luồng hợp lệ từ <code>raw_trace</code>. Dữ liệu gốc vẫn giữ nguyên ở mục 8.
        </p>
      )}
      <div className="v2-flow-list" role="list" aria-label="Các bước luồng dữ liệu đã kiểm tra vị trí">
        {steps.map((step, idx) => {
          const isLast = idx === steps.length - 1;
          const badgeTone = step.role === 'sink' ? 'red' : step.role === 'source' ? 'blue' : 'neutral';
          return (
            <div
              key={`${step.role}-${step.fileIdentityKey || step.path}-${step.startLine}-${step.startCol ?? ''}-${idx}`}
              role="listitem"
              className={`v2-flow-step v2-flow-step--${step.role}`}
            >
              <div className="v2-flow-rail" aria-hidden="true">
                <span className="v2-flow-dot">{idx + 1}</span>
                {!isLast && <span className="v2-flow-line" />}
              </div>
              <div className="v2-flow-card">
                <div className="v2-flow-head">
                  <div style={{display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center'}}>
                    <Badge tone={badgeTone}>{step.tag}</Badge>
                    <strong style={{fontSize: '13px'}}>{step.label}</strong>
                  </div>
                  <span className="mono wrap-value" style={{fontSize: '12px', color: 'var(--v2-text-secondary)'}}>
                    {step.path}:{step.startLine}{step.startCol ? `:${step.startCol}` : ''}
                    {step.endLine > step.startLine ? `–${step.endLine}${step.endCol ? `:${step.endCol}` : ''}` : ''}
                    {step.endLine === step.startLine && step.startCol && step.endCol ? `–${step.endCol}` : ''}
                  </span>
                </div>
                {step.pathConflict && (
                  <p className="panel-note" style={{margin: '0 0 6px', fontSize: '12px'}}>
                    Trường path và raw_path khai báo mâu thuẫn nhau; hệ thống không tự chọn một trường và không gắn SHA-256.
                  </p>
                )}
                {step.mappingConflict && (
                  <p className="panel-note" style={{margin: '0 0 6px', fontSize: '12px'}}>
                    Đường dẫn nằm trong vùng ánh xạ path_mappings có nhiều thư mục đích mâu thuẫn; hệ thống giữ nguyên đường dẫn gốc, không áp dụng mapping cha làm fallback và không gắn SHA-256.
                  </p>
                )}
                {step.fileIdentity === 'UNMAPPED_RAW_PATH' && !step.mappingConflict && !step.pathConflict && (
                  <p className="panel-note" style={{margin: '0 0 6px', fontSize: '12px'}}>
                    Đường dẫn gốc từ OpenGrep chưa được ánh xạ chắc chắn vào thư mục mã nguồn của phiên quét; không gắn SHA-256 cho bước này.
                  </p>
                )}
                {step.fileIdentity === 'SCOPED_ABSOLUTE_ROOT' && (
                  <p className="panel-note" style={{margin: '0 0 6px', fontSize: '12px'}}>
                    Bằng chứng ghi nhận nhiều thư mục gốc mã nguồn khác nhau; bước được giữ danh tính tách biệt theo đường dẫn tuyệt đối.
                  </p>
                )}
                {step.shaConflict && (
                  <p className="panel-note" style={{margin: '0 0 6px', fontSize: '12px'}}>
                    Phát hiện xung đột SHA-256 trên cùng tệp/phiên bản nguồn ({step.conflictingHashes?.length || 2} giá trị khác nhau); không hiển thị hash chưa nhất quán.
                  </p>
                )}
                {step.ambiguousMatch && (
                  <p className="panel-note" style={{margin: '0 0 6px', fontSize: '12px'}}>
                    Bằng chứng thiếu cột nên không thể ghép duy nhất với bước tương ứng ở nguồn còn lại; bước được giữ riêng để kiểm tra thủ công.
                  </p>
                )}
                {step.code && <pre className="v2-flow-code"><code>{step.code}</code></pre>}
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function LiveDetailPage({scanId, id, detailUrl}) {
  const outlet = useOutletContext();
  const navigate = useNavigate();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const [detailState, retryDetail] = useRemote(
    (signal) => api.findingDetail(scanId, id, detailUrl, {signal}),
    [scanId, id, detailUrl, apiOrigin, authSessionScope, apiRevision],
  );
  const [serverOverride, setServerOverride] = useState(null);

  useEffect(() => {
    setServerOverride(null);
  }, [scanId, id, apiOrigin, authSessionScope, apiRevision]);

  useEffect(() => {
    if (detailState.status === 'error' && detailState.statusCode === 404 && detailState.errorCode === 'SCAN_NOT_FOUND') {
      clearStaleActiveScanId(scanId, authSessionScope);
    }
  }, [detailState.status, detailState.statusCode, detailState.errorCode, scanId, authSessionScope]);

  const rawDetail = detailState.status === 'success' ? detailState.data : null;
  const identityCheck = rawDetail ? verifyFindingIdentity(rawDetail, scanId, id, {requireScanId: true}) : null;
  const mismatch = Boolean(rawDetail && !identityCheck?.valid);
  const safeOverride = serverOverride && typeof serverOverride === 'object'
    && (!serverOverride.scan_id || serverOverride.scan_id === scanId)
    && (!findReportedId(serverOverride) || findReportedId(serverOverride) === id)
    ? serverOverride
    : null;
  const validDetail = rawDetail && !mismatch ? {...rawDetail, ...(safeOverride || {})} : null;
  const originInfo = classifyDataOrigin(validDetail);
  const isMockData = originInfo.isMockOrTest;

  const evidence = validDetail?.evidence || {};
  const assessment = validDetail?.assessment || {};
  const snippets = Array.isArray(evidence.snippets) ? evidence.snippets : [];
  const snapshots = evidence.snapshots && typeof evidence.snapshots === 'object' ? evidence.snapshots : {};
  const citations = Array.isArray(assessment.citations) ? assessment.citations : [];
  const reviewEvents = Array.isArray(validDetail?.review_events) ? validDetail.review_events : [];
  const rejectedDecisions = Array.isArray(validDetail?.rejected_decisions) ? validDetail.rejected_decisions : [];

  const guide = getCweGuide(validDetail?.cwe);
  const validatedStatus = String(validDetail?.validated_status ?? assessment.validated_status ?? 'UNDETERMINED').toUpperCase();
  const rawModelStatus = validDetail?.raw_model_status ?? assessment.raw_model_status ?? null;
  const humanState = String(validDetail?.human_review_state ?? 'OPEN').toUpperCase();
  const vMeta = validatedStatusMeta(validatedStatus);
  const hMeta = humanReviewMeta(humanState);
  const citationCheck = String(validDetail?.citation_check ?? assessment.citation_check ?? 'NOT_VERIFIED').toUpperCase();
  const cMeta = citationCheckMeta(citationCheck);
  const rtMeta = runtimeVerificationMeta(assessment.runtime?.model_runtime_verified);
  const downgraded = Boolean(validDetail?.validator_downgraded ?? assessment.validator_downgraded);
  const failureKind = normalizeFailureKind(validDetail?.failure_kind ?? assessment.failure_kind);
  const rawDowngradeReason = validDetail?.downgrade_reason ?? assessment.downgrade_reason ?? '';
  const downgradeInfo = (downgraded || failureKind)
    ? describeDowngradeReason(failureKind, rawDowngradeReason, citationCheck)
    : null;
  const filePath = firstText(validDetail?.file_path, evidence.path, evidence.raw_path);
  const lineNumber = firstText(validDetail?.start_line, evidence?.start?.line);
  const endLineNumber = firstText(validDetail?.end_line, evidence?.end?.line);
  const ruleId = firstText(validDetail?.rule_id, evidence.rule_id);
  // Resolve primary source hash through the exact same grounded File Identity and File Hash
  // Ledger used by Dataflow — never fall back to an unscoped relative snapshot across roots.
  const primaryHash = resolveFindingSourceHash(validDetail);
  const dataflow = analyzeDataflow(evidence);
  const findingSnippets = snippets.filter((s) => String(s?.role || '').toLowerCase() === 'finding');
  const displaySnippets = findingSnippets.length > 0 ? findingSnippets : snippets;
  const back = `/findings${scanQuery(scanId)}`;

  return (
    <div className="ntk-p06-detail">
      <PageHeader
        eyebrow="CHI TIẾT CẢNH BÁO & BẰNG CHỨNG"
        title={validDetail ? `${guide.code} · ${guide.title}` : 'Chi tiết cảnh báo'}
        description={validDetail ? `${filePath ? fileName(filePath) : 'Java'}${lineNumber ? ` · dòng ${lineNumber}` : ''} · ${id}` : undefined}
        actions={(
          <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
            <Link to={back} className="button-secondary"><Icon name="ArrowLeft" /> Quay lại danh sách</Link>
            <Link to={`/review${scanQuery(scanId)}`} className="button-secondary"><Icon name="Shield" /> Hàng đợi kiểm duyệt</Link>
          </div>
        )}
      />

      {detailState.status === 'loading' && <DataNotice>Đang tải bằng chứng, trích dẫn mã nguồn và SHA-256 từ API…</DataNotice>}
      {detailState.status === 'error' && (
        <>
          <EmptyState title="Không tải được chi tiết cảnh báo" text={detailState.error} icon="AlertTriangle" />
          <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px'}}>
            <button type="button" className="button-primary" onClick={retryDetail}>Thử lại</button>
            {(detailState.statusCode === 401 || detailState.statusCode === 403 || /UNAUTHORIZED|Bearer Token|HTTP 401|HTTP 403/i.test(detailState.error || '')) && (
              <button type="button" className="button-secondary" onClick={() => outlet?.openConnectionPanel?.()}>
                <Icon name="KeyRound" />Nhập Bearer Token phiên
              </button>
            )}
            {detailState.statusCode === 404 && (
              <button
                type="button"
                className="button-secondary"
                onClick={() => {
                  if (detailState.errorCode === 'SCAN_NOT_FOUND') {
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
      {mismatch && (
        <>
          <EmptyState
            title="Định danh phiên hoặc cảnh báo không khớp"
            text={identityCheck?.error || 'API trả về mã phiên hoặc mã cảnh báo khác với mục đang mở; dữ liệu không được hiển thị.'}
            icon="AlertTriangle"
          />
          <button type="button" className="button-secondary" onClick={retryDetail}>Tải lại</button>
        </>
      )}
      {isMockData && (
        <EmptyState
          title="Dữ liệu mô phỏng (mock) bị chặn"
          text="Không hiển thị dữ liệu thử nghiệm mock như kết quả vận hành thực."
          icon="ShieldAlert"
        />
      )}

      {validDetail && !isMockData && (
        <div className="v2-detail-stack">
          {/* 1. Tóm tắt lỗ hổng */}
          <Card className="v2-summary-card">
            <div className="v2-summary-top">
              <div className="v2-summary-badges">
                <Badge tone="blue">{guide.code}</Badge>
                <Badge tone="neutral">Severity: {validDetail.severity || 'WARNING'}</Badge>
                <Badge tone={originInfo.tone}>{originInfo.label}</Badge>
              </div>
              <span className="mono" style={{fontSize: '12px', color: 'var(--v2-text-muted)'}}>
                1. Tóm tắt lỗ hổng
              </span>
            </div>
            <h2>{guide.title}</h2>
            <p>{validDetail.message || guide.description}</p>

            {validatedStatus === 'UNDETERMINED' && (
              <div className="inline-warning">
                <Icon name="Info" />
                <span>
                  Cảnh báo đang ở trạng thái <strong>UNDETERMINED</strong>
                  {downgraded ? ' (đã bị bộ kiểm chứng hạ cấp)' : ''}
                  {downgradeInfo ? (
                    <>
                      {' '}· {downgradeInfo.viLabel}
                      {downgradeInfo.hasCode ? <> (<code>{downgradeInfo.code}</code>)</> : ''}
                    </>
                  ) : ''}.
                  {downgradeInfo?.rawDetail ? ` Chi tiết từ backend: ${downgradeInfo.rawDetail}` : ''}
                  {downgradeInfo?.matchedCitationNote ? ` ${downgradeInfo.matchedCitationNote}` : ''}
                  {' '}Hệ thống giữ lại cảnh báo để người kiểm duyệt xem xét mã nguồn gốc.
                </span>
              </div>
            )}
            {validatedStatus === 'REFUTED' && humanState === 'OPEN' && (
              <div className="inline-warning">
                <Icon name="Info" />
                <span>
                  Qwen3.5-9B đề xuất <strong>REFUTED</strong> (nghi ngờ cảnh báo giả), nhưng cảnh báo vẫn ở trạng thái <strong>OPEN</strong> cho tới khi người kiểm duyệt xác nhận.
                </span>
              </div>
            )}

            <div className="v2-dual-status">
              <div className="v2-status-box">
                <span className="v2-status-kicker">Nhận định AI (Qwen3.5-9B · Đã kiểm chứng)</span>
                <div className="v2-status-box-row">
                  <Badge tone={vMeta.tone} className="v2-status-token">{validatedStatus}</Badge>
                  <span className="v2-status-box-title">{vMeta.viLabel}</span>
                </div>
                {rawModelStatus && String(rawModelStatus).toUpperCase() !== validatedStatus && (
                  <p className="mono" style={{fontSize: '12px', marginBottom: '6px'}}>
                    Nhận định thô Qwen: <strong>{String(rawModelStatus).toUpperCase()}</strong> → Sau kiểm chứng: <strong>{validatedStatus}</strong>
                  </p>
                )}
                <p>{vMeta.summary}</p>
              </div>
              <div className="v2-status-box v2-status-box--human">
                <span className="v2-status-kicker">Quyết định của người kiểm duyệt</span>
                <div className="v2-status-box-row">
                  <Badge tone={hMeta.tone} className="v2-status-token">{humanState}</Badge>
                  <span className="v2-status-box-title">{hMeta.viLabel}</span>
                </div>
                <p>{hMeta.summary}</p>
              </div>
            </div>
          </Card>

          {/* 2. Tệp Java và số dòng */}
          <Card title="2. Tệp Java & vị trí mã nguồn">
            <div className="v2-location-grid">
              <div className="v2-kv-item">
                <span>Đường dẫn tệp Java</span>
                <strong className="mono">{filePath || 'Chưa xác định'}</strong>
                {primaryHash.resolvedPath && primaryHash.resolvedPath !== filePath && (
                  <span className="mono panel-note" style={{fontSize: '11.5px', display: 'block', marginTop: '2px'}}>
                    {primaryHash.resolvedPath}
                  </span>
                )}
              </div>
              <div className="v2-kv-item">
                <span>Số dòng phát hiện</span>
                <strong className="mono">
                  Dòng {lineNumber || '-'}{endLineNumber && endLineNumber !== lineNumber ? `–${endLineNumber}` : ''}
                </strong>
              </div>
              <div className="v2-kv-item">
                <span>Quy tắc OpenGrep (rule_id)</span>
                <strong className="mono">{ruleId || '-'}</strong>
              </div>
              <div className="v2-kv-item">
                <span>SHA-256 tệp nguồn lúc quét</span>
                <FindingPrimaryHashField primaryHash={primaryHash} />
              </div>
            </div>
          </Card>

          {/* 3. Nhận định Qwen */}
          <Card title="3. Nhận định Qwen3.5-9B (cục bộ qua Ollama)">
            <div style={{display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center', marginBottom: '12px'}}>
              <Badge tone={vMeta.tone}>Trạng thái kiểm chứng: {validatedStatus}</Badge>
              <Badge tone={cMeta.tone}>Trích dẫn: {citationCheck} · {cMeta.viLabel}</Badge>
              <Badge tone={rtMeta.tone}>{rtMeta.label}</Badge>
            </div>

            {rawModelStatus && String(rawModelStatus).toUpperCase() !== validatedStatus && (
              <div className="inline-warning" style={{marginTop: 0, marginBottom: '12px'}}>
                <Icon name="AlertTriangle" />
                <span>
                  Phản hồi thô của Qwen là <strong>{String(rawModelStatus).toUpperCase()}</strong> nhưng đã bị bộ kiểm chứng hạ cấp về{' '}
                  <strong>{validatedStatus}</strong>
                  {downgradeInfo
                    ? <> — {downgradeInfo.viLabel}{downgradeInfo.hasCode ? <> (<code>{downgradeInfo.code}</code>)</> : ''}</>
                    : ''}.
                  {downgradeInfo?.rawDetail ? ` Chi tiết: ${downgradeInfo.rawDetail}` : ''}
                </span>
              </div>
            )}

            <p style={{margin: '0 0 10px', color: 'var(--v2-text)', overflowWrap: 'anywhere'}}>
              {assessment.explanation || 'Chưa có giải thích từ Qwen (mô hình không chạy hoặc không trả về giải thích hợp lệ).'}
            </p>
            <p className="panel-note" style={{margin: '0 0 10px', fontSize: '12.5px'}}>
              {cMeta.note}
            </p>
            <div className="v2-location-grid" style={{paddingTop: '12px', borderTop: '1px solid var(--v2-border-subtle)'}}>
              <div className="v2-kv-item">
                <span>Mô hình</span>
                <strong className="mono">{assessment.model || 'Không chạy LLM (no_llm)'}</strong>
              </div>
              <div className="v2-kv-item">
                <span>Thời gian suy luận</span>
                <strong className="mono">
                  {Number.isFinite(Number(assessment.elapsed_seconds))
                    ? `${Number(assessment.elapsed_seconds).toFixed(2)} giây`
                    : '—'}
                </strong>
              </div>
              <div className="v2-kv-item">
                <span>Hợp đồng kiểm chứng</span>
                <strong className="mono">{assessment.prompt_version || 'blind'}</strong>
              </div>
            </div>
          </Card>

          {/* 4. Trích dẫn mã nguồn */}
          <Card title="4. Trích dẫn mã nguồn & đoạn mã Java gốc">
            <div style={{display: 'grid', gap: '16px'}}>
              <div>
                <h4 style={{fontSize: '13.5px', fontWeight: 650, color: 'var(--v2-silver)', margin: '0 0 10px'}}>
                  Trích dẫn được Qwen viện dẫn ({citations.length})
                </h4>
                {citations.length === 0 ? (
                  <p className="panel-note" style={{margin: 0}}>
                    Không có trích dẫn hợp lệ nào được ghi nhận ({citationCheck}{failureKind ? ` · ${failureKind}` : ''}).
                  </p>
                ) : (
                  <div style={{display: 'grid', gap: '10px'}}>
                    {citations.map((cite, idx) => (
                      <div key={`${cite.path}-${cite.start_line}-${idx}`} className="v2-code-card">
                        <div className="v2-code-header">
                          <div className="v2-code-meta">
                            <Badge tone={citationCheckTone(citationCheck)}>{citationCheck}</Badge>
                            <span className="mono v2-code-path">
                              {cite.path}:{cite.start_line}{cite.end_line && cite.end_line !== cite.start_line ? `–${cite.end_line}` : ''}
                            </span>
                          </div>
                          {cite.sha256 && <CopyHashButton value={cite.sha256} label="Sao chép Citation SHA-256" />}
                        </div>
                        <div className="v2-hash-bar mono">
                          <span className="v2-hash-text">Citation SHA-256: {cite.sha256 || 'Thiếu SHA-256'}</span>
                        </div>
                        <pre className="v2-pre-block" style={{border: 'none', borderRadius: 0}}><code>{cite.quote || ''}</code></pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <h4 style={{fontSize: '13.5px', fontWeight: 650, color: 'var(--v2-silver)', margin: '0 0 10px'}}>
                  Đoạn mã Java gốc chụp tại thời điểm quét ({displaySnippets.length})
                </h4>
                {displaySnippets.length === 0 ? (
                  <p className="panel-note" style={{margin: 0}}>Không có snippet mã nguồn trong hồ sơ bằng chứng.</p>
                ) : (
                  <div style={{display: 'grid', gap: '12px'}}>
                    {displaySnippets.map((snippet, idx) => (
                      <SnippetViewer key={`${snippet.role}-${snippet.path}-${idx}`} snippet={snippet} evidence={evidence} />
                    ))}
                  </div>
                )}
              </div>
            </div>
          </Card>

          {/* 5. Luồng Source -> Intermediate -> Sink */}
          <DataflowTraceSection dataflow={dataflow} />

          {/* 6. Hướng khắc phục */}
          <Card title="6. Hướng khắc phục & đối chiếu an toàn">
            <div style={{display: 'grid', gap: '12px'}}>
              {assessment.fix_suggestion && (
                <div className="v2-status-box">
                  <span className="v2-status-kicker">Gợi ý tham khảo từ Qwen (chỉ hiển thị, chưa tự áp dụng)</span>
                  <p style={{color: 'var(--v2-text)', fontSize: '13.5px', overflowWrap: 'anywhere'}}>
                    {assessment.fix_suggestion}
                  </p>
                </div>
              )}
              {guide.suggestion && (
                <div className="v2-status-box">
                  <span className="v2-status-kicker">Nguyên tắc phòng chống chuẩn · {guide.code}</span>
                  <p style={{color: 'var(--v2-text-secondary)', fontSize: '13.5px'}}>{guide.suggestion}</p>
                </div>
              )}
              {!assessment.fix_suggestion && !guide.suggestion && (
                <p className="panel-note" style={{margin: 0}}>
                  Chưa có gợi ý khắc phục tự động; vui lòng kiểm tra luồng dữ liệu trực tiếp trong mã nguồn Java.
                </p>
              )}
            </div>
          </Card>

          {/* 7. Human Review */}
          <section aria-label="7. Human Review">
            <HumanReviewPanel
              key={`${scanId}:${id}`}
              scanId={scanId}
              findingId={id}
              detail={validDetail}
              writable={validDetail.writable !== false}
              validatedStatus={validatedStatus}
              humanReviewState={humanState}
              reviewEvents={reviewEvents}
              rejectedDecisions={rejectedDecisions}
              onUpdated={(updated) => {
                if (updated && typeof updated === 'object') {
                  const hasIdentity = Boolean(updated.scan_id || updated.finding_id || updated.id);
                  if (!hasIdentity || verifyFindingIdentity(updated, scanId, id, {requireScanId: Boolean(updated.scan_id)}).valid) {
                    setServerOverride((prev) => ({...(prev || {}), ...updated}));
                  }
                }
              }}
            />
          </section>

          {/* 8. Chi tiết kỹ thuật mở rộng (bảo toàn nguyên vẹn 100% bằng chứng gốc) */}
          <details className="v2-accordion">
            <summary>
              <span>
                <Icon name="Layers" />
                8. Chi tiết kỹ thuật mở rộng (SHA-256 Snapshots, Dataflow, Java Context, Prompt/Runtime Provenance, SQLite &amp; Raw Metadata)
              </span>
              <Icon name="ChevronDown" />
            </summary>
            <div className="v2-accordion-body">
              <details className="v2-sub-details" open>
                <summary>Bảng toàn vẹn tệp nguồn — Source Snapshots SHA-256 ({Object.keys(snapshots).length} tệp)</summary>
                <div className="v2-sub-details-body">
                  {Object.keys(snapshots).length === 0 ? (
                    <p className="panel-note" style={{margin: 0}}>Chưa ghi nhận snapshot SHA-256.</p>
                  ) : (
                    <div className="table-wrap">
                      <table>
                        <thead><tr><th>Đường dẫn tương đối (.java)</th><th>SHA-256</th><th>Kích thước (bytes)</th></tr></thead>
                        <tbody>
                          {Object.entries(snapshots).map(([snapPath, snapMeta]) => (
                            <tr key={snapPath}>
                              <td className="mono wrap-value">{snapPath}</td>
                              <td className="mono wrap-value">{snapMeta?.sha256 || '-'}</td>
                              <td className="mono">{snapMeta?.size ?? '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </details>

              {snippets.length > displaySnippets.length && (
                <details className="v2-sub-details">
                  <summary>Toàn bộ snippet nguồn trong bằng chứng ({snippets.length} đoạn)</summary>
                  <div className="v2-sub-details-body" style={{display: 'grid', gap: '10px'}}>
                    {snippets.map((snippet, idx) => (
                      <SnippetViewer key={`all-${snippet.role}-${snippet.path}-${idx}`} snippet={snippet} evidence={evidence} />
                    ))}
                  </div>
                </details>
              )}

              <details className="v2-sub-details">
                <summary>Trích dẫn &amp; Prompt Provenance (citation_provenance, prompt_version)</summary>
                <div className="v2-sub-details-body">
                  <pre className="v2-pre-block">
                    <code>{JSON.stringify({
                      citation_check: citationCheck,
                      citations,
                      citation_provenance: assessment.citation_provenance ?? null,
                      prompt_version: assessment.prompt_version ?? null,
                      analyzed_at: assessment.analyzed_at ?? null,
                      elapsed_seconds: assessment.elapsed_seconds ?? null,
                    }, null, 2)}</code>
                  </pre>
                </div>
              </details>

              <details className="v2-sub-details">
                <summary>Trạng thái Model &amp; Runtime (model_runtime_verified, HTTP capture hashes)</summary>
                <div className="v2-sub-details-body">
                  <pre className="v2-pre-block">
                    <code>{JSON.stringify({
                      model: assessment.model ?? null,
                      transport: assessment.transport ?? null,
                      runtime: assessment.runtime ?? null,
                      security_conclusion_verified: assessment.security_conclusion_verified ?? false,
                    }, null, 2)}</code>
                  </pre>
                </div>
              </details>

              <details className="v2-sub-details">
                <summary>Dataflow Trace gốc từ OpenGrep (raw_trace)</summary>
                <div className="v2-sub-details-body">
                  <pre className="v2-pre-block">
                    <code>{JSON.stringify(evidence.raw_trace ?? null, null, 2)}</code>
                  </pre>
                </div>
              </details>

              <details className="v2-sub-details">
                <summary>Ngữ cảnh cấu trúc phương thức Java (java_context)</summary>
                <div className="v2-sub-details-body">
                  <pre className="v2-pre-block">
                    <code>{JSON.stringify(evidence.java_context ?? null, null, 2)}</code>
                  </pre>
                </div>
              </details>

              <details className="v2-sub-details">
                <summary>Lịch sử SQLite nguyên bản (review_events: {reviewEvents.length} · rejected_decisions: {rejectedDecisions.length})</summary>
                <div className="v2-sub-details-body">
                  <pre className="v2-pre-block">
                    <code>{JSON.stringify({review_events: reviewEvents, rejected_decisions: rejectedDecisions}, null, 2)}</code>
                  </pre>
                </div>
              </details>

              <details className="v2-sub-details">
                <summary>Raw Metadata &amp; Scan Provenance</summary>
                <div className="v2-sub-details-body">
                  <pre className="v2-pre-block">
                    <code>{JSON.stringify({
                      finding_id: validDetail.finding_id,
                      alert_id: evidence.alert_id ?? validDetail.alert_id,
                      scan_id: validDetail.scan_id,
                      scan_sha256: evidence.scan_sha256 ?? validDetail.scan_sha256,
                      schema_version: evidence.schema_version,
                      collected_at: evidence.collected_at,
                      scan_provenance: evidence.scan_provenance ?? null,
                      evidence_issues: evidence.issues ?? [],
                    }, null, 2)}</code>
                  </pre>
                </div>
              </details>
            </div>
          </details>
        </div>
      )}
    </div>
  );
}

export function Results() {
  const outlet = useOutletContext();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const scanId = useActiveScanId();
  const navigate = useNavigate();
  const [scansState, setScansState] = useState({status: 'idle', items: [], error: '', statusCode: null});

  useEffect(() => {
    if (scanId) return undefined;
    const controller = new AbortController();
    const requestBaseUrl = getApiBaseUrl();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => (
      !active
      || controller.signal.aborted
      || getApiBaseUrl() !== requestBaseUrl
      || getApiOrigin() !== requestOrigin
      || getAuthSessionScope() !== requestSession
    );
    setScansState({status: 'loading', items: [], error: '', statusCode: null, incompleteNotice: ''});
    api.listScans({signal: controller.signal})
      .then((res) => {
        if (isStale()) return;
        const safeItems = (res.items || []).filter(
          (scan) => scan && typeof scan === 'object' && typeof scan.scan_id === 'string' && scan.scan_id.trim() && !classifyDataOrigin(scan).isMockOrTest,
        );
        const incompleteNotice = !res.supported || res.valid === false || res.truncated || res.countConsistent === false || (res.invalidItemCount ?? 0) > 0
          ? `Danh sách phiên phân tích từ API có thể chưa đầy đủ (${res.invalidReason || 'INCOMPLETE_LIST'}).`
          : '';
        setScansState({status: 'ready', items: safeItems, error: '', statusCode: null, incompleteNotice});
      })
      .catch((err) => {
        if (isStale() || err?.abortedByConfigChange) return;
        setScansState({status: 'error', items: [], error: err?.message || 'Không thể tải danh sách phiên phân tích.', statusCode: err?.status ?? null, incompleteNotice: ''});
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [scanId, apiOrigin, authSessionScope, apiRevision]);

  if (scanId) return <LiveDashboard key={`${authSessionScope}:${scanId}`} scanId={scanId} />;

  return (
    <>
      <PageHeader
        eyebrow="KẾT QUẢ PHÁT HIỆN"
        title="Chọn phiên phân tích"
        description="Mở một phiên quét có sẵn trên máy chủ API hoặc bắt đầu phân tích dự án Java mới."
        actions={<Link to="/scanner" className="button-primary"><Icon name="Plus" />Phiên phân tích mới</Link>}
      />
      {scansState.status === 'loading' && <DataNotice>Đang tải danh sách phiên phân tích từ API…</DataNotice>}
      {scansState.status === 'error' && (
        <>
          <DataNotice>Không tải được danh sách phiên phân tích: {scansState.error}</DataNotice>
          {(scansState.statusCode === 401 || scansState.statusCode === 403 || /UNAUTHORIZED|Bearer Token|HTTP 401|HTTP 403/i.test(scansState.error || '')) && (
            <button type="button" className="button-secondary" onClick={() => outlet?.openConnectionPanel?.()}>
              <Icon name="KeyRound" />Nhập Bearer Token phiên
            </button>
          )}
        </>
      )}
      {scansState.status === 'ready' && scansState.incompleteNotice && (
        <DataNotice>{scansState.incompleteNotice}</DataNotice>
      )}
      {scansState.status === 'ready' && scansState.items.length > 0 ? (
        <section className="section-block" style={{marginTop: '16px'}}>
          {scansState.items.map((scan) => {
            const scanOrigin = classifyDataOrigin(scan);
            return (
              <Card key={scan.scan_id} className="v2-scan-picker-row">
                <div className="v2-scan-picker-info">
                  <div style={{display: 'flex', flexWrap: 'wrap', gap: '6px', alignItems: 'center'}}>
                    <Badge tone="blue">{scan.input_mode || 'SCAN'}</Badge>
                    <Badge tone={scanOrigin.tone}>{scanOrigin.label}</Badge>
                  </div>
                  <h3 className="mono">{scan.repo_url || scan.file_name || scan.scan_id}</h3>
                  <p>
                    {scan.total_findings ?? '—'} cảnh báo · Qwen: SUPPORTED {scan.by_validated_status?.SUPPORTED ?? '—'},
                    REFUTED {scan.by_validated_status?.REFUTED ?? '—'}, UNDETERMINED {scan.by_validated_status?.UNDETERMINED ?? '—'} ·
                    OPEN {scan.by_human_review_state?.OPEN ?? '—'}
                  </p>
                </div>
                <button
                  type="button"
                  className="button-secondary"
                  onClick={() => navigate(`/findings${scanQuery(scan.scan_id)}`)}
                >
                  Mở kết quả <Icon name="ArrowRight" />
                </button>
              </Card>
            );
          })}
        </section>
      ) : scansState.status === 'ready' ? (
        <EmptyState
          title="Chưa có phiên phân tích nào"
          text="Nhập URL GitHub hoặc tải tệp ZIP ở trang Phân tích dự án để khởi tạo phiên quét đầu tiên."
          icon="ScanSearch"
        />
      ) : null}
    </>
  );
}

export function FindingDetail() {
  const outlet = useOutletContext();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const scanId = useActiveScanId();
  const location = useLocation();
  const routeParams = useParams();
  const id = routeParams.id || decodeURIComponent(
    (typeof window !== 'undefined' ? window.location.hash : '').split('?')[0].split('/').pop() || '',
  );

  if (!scanId || !id) {
    return (
      <>
        <PageHeader title="Chi tiết cảnh báo" description="Chưa có phiên phân tích hoặc cảnh báo hợp lệ." />
        <EmptyState
          title={!scanId ? 'Thiếu mã phiên (scan_id)' : 'Thiếu mã cảnh báo (finding_id)'}
          text="Mở danh sách cảnh báo từ một phiên quét hợp lệ trên máy chủ API hiện tại để xem trích dẫn, luồng dữ liệu và mã nguồn Java."
          icon="Inbox"
        />
        <div style={{marginTop: '12px'}}>
          <Link to="/history" className="button-secondary">
            <Icon name="ArrowLeft" />Chọn phiên phân tích
          </Link>
        </div>
      </>
    );
  }
  return <LiveDetailPage key={`${authSessionScope}:${scanId}:${id}`} scanId={scanId} id={id} detailUrl={location.state?.detailUrl} />;
}
