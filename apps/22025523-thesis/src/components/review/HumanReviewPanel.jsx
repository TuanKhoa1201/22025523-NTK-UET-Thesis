import {useEffect, useRef, useState} from 'react';
import {useOutletContext} from 'react-router-dom';
import {Badge, Card, DataNotice, Icon} from '../common/Ui';
import {hasSessionToken} from '../../services/api';
import {humanReviewMeta, resolveFindingSourceHash, validatedStatusMeta} from '../../services/findingPresentation';
import {
  buildAuditTimeline,
  evaluateSourceDriftReadiness,
  submitReviewDecision,
  validateReviewInput,
  verifyFindingIdentity,
} from '../../services/reviewModel';

const ACTION_LABELS = {
  'confirm-true': 'Xác nhận thật (CONFIRMED_TRUE)',
  'confirm-false': 'Xác nhận giả (CONFIRMED_FALSE)',
  reopen: 'Mở lại (OPEN)',
};

export function AuditTimeline({events = [], rejectedDecisions = [], showWarningId = false}) {
  const entries = buildAuditTimeline(events, rejectedDecisions);
  if (entries.length === 0) {
    return <p className="muted-text" style={{margin: 0}}>Chưa có quyết định kiểm duyệt hoặc lượt bị từ chối nào được ghi nhận trong SQLite.</p>;
  }

  return (
    <div className="v2-audit-list">
      {entries.map((entry) => {
        const isRejected = entry.kind === 'REJECTED';
        const tone = isRejected
          ? 'red'
          : entry.action === 'confirm-false'
            ? 'green'
            : entry.action === 'confirm-true'
              ? 'red'
              : 'blue';

        return (
          <div key={entry.key} className={`v2-audit-item ${isRejected ? 'is-rejected' : ''}`}>
            <div className="v2-audit-head">
              <div className="v2-audit-meta">
                <Badge tone={tone}>
                  {isRejected ? `BỊ TỪ CHỐI · ${entry.code}` : ACTION_LABELS[entry.action] || entry.action}
                </Badge>
                {showWarningId && entry.warningId && (
                  <span className="mono wrap-value" style={{fontSize: '12px', color: 'var(--v2-silver)'}}>{entry.warningId}</span>
                )}
                <span>Người kiểm duyệt: <strong>{entry.actor}</strong></span>
              </div>
              <span className="mono v2-audit-time">{entry.timestamp}</span>
            </div>
            <p className="v2-audit-reason">Lý do: {entry.reason}</p>
            {isRejected && entry.mismatchedPaths?.length > 0 && (
              <p className="mono wrap-value" style={{fontSize: '12px', color: 'var(--v2-danger-text)', margin: '6px 0 0'}}>
                Tệp bị thay đổi hoặc thiếu: {entry.mismatchedPaths.join(', ')}
              </p>
            )}
            {(entry.expectedHashes || entry.observedHashes) && (
              <details className="v2-sub-details" style={{marginTop: '8px'}}>
                <summary>Đối chiếu SHA-256 lúc quét vs lúc kiểm duyệt</summary>
                <div className="v2-sub-details-body">
                  <pre className="v2-pre-block">
                    <code>{JSON.stringify({expected: entry.expectedHashes, observed: entry.observedHashes}, null, 2)}</code>
                  </pre>
                </div>
              </details>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function HumanReviewPanel({
  scanId,
  findingId,
  detail = null,
  writable = true,
  validatedStatus = 'UNDETERMINED',
  humanReviewState = 'OPEN',
  reviewEvents = [],
  rejectedDecisions = [],
  onUpdated,
}) {
  const outlet = useOutletContext();
  const backendHealth = outlet?.backend?.health;
  const [actor, setActor] = useState('');
  const [reason, setReason] = useState('');
  const [submittingAction, setSubmittingAction] = useState('');
  const [feedback, setFeedback] = useState(null);
  const [staleInfo, setStaleInfo] = useState(null);
  const [localEvents, setLocalEvents] = useState(null);
  const [localRejected, setLocalRejected] = useState(null);
  const inFlightRef = useRef(new Set());

  useEffect(() => {
    setLocalEvents(null);
  }, [reviewEvents]);

  useEffect(() => {
    setLocalRejected(null);
  }, [rejectedDecisions]);

  const effectiveEvents = localEvents ?? reviewEvents;
  const effectiveRejected = localRejected ?? rejectedDecisions;
  const vMeta = validatedStatusMeta(validatedStatus);
  const hMeta = humanReviewMeta(humanReviewState);
  const tokenPresent = hasSessionToken();
  const writeConfigured = backendHealth?.write_auth_configured !== false;
  const identityCheck = verifyFindingIdentity(detail, scanId, findingId, {requireScanId: true});
  const hashConflict = Boolean(detail && resolveFindingSourceHash(detail).status === 'CONFLICT');
  const driftReadiness = evaluateSourceDriftReadiness(detail, {hashConflict});
  const canReview = writable && identityCheck.valid;
  const canConfirmFalse = canReview && driftReadiness.canConfirmFalse;

  const handleAction = async (action) => {
    setFeedback(null);
    setStaleInfo(null);

    if (!identityCheck.valid) {
      setFeedback({type: 'error', message: identityCheck.error});
      return;
    }

    if (action === 'confirm-false' && !driftReadiness.canConfirmFalse) {
      setFeedback({
        type: 'error',
        message: `Chưa đủ điều kiện kiểm tra source drift để xác nhận cảnh báo giả: ${driftReadiness.summary}`,
      });
      return;
    }

    const check = validateReviewInput({actor, reason});
    if (!check.valid) {
      setFeedback({type: 'error', message: check.error});
      return;
    }

    setSubmittingAction(action);
    const result = await submitReviewDecision({
      scanId,
      findingId,
      action,
      actor,
      reason,
      detail,
      hashConflict,
      inFlightKeys: inFlightRef.current,
    });
    setSubmittingAction('');

    if (result.ok) {
      const updatedIdentity = verifyFindingIdentity(result.detail, scanId, findingId, {requireScanId: true});
      if (!updatedIdentity.valid) {
        setFeedback({type: 'error', message: updatedIdentity.error});
        return;
      }
      setLocalEvents(result.detail?.review_events ?? null);
      setLocalRejected(result.detail?.rejected_decisions ?? null);
      setReason('');
      setFeedback({
        type: 'success',
        message: `Đã ghi nhận quyết định kiểm duyệt vào SQLite: ${result.detail?.human_review_state || ''}.`,
      });
      onUpdated?.(result.detail);
      return;
    }

    if (result.staleSource) {
      // Never auto-retry on 409 STALE_SOURCE; preserve exact server state (typically OPEN).
      setStaleInfo({
        message: result.message,
        humanReviewState: result.humanReviewState,
        staleDetail: result.staleDetail,
      });
      setLocalEvents(result.reviewEvents);
      setLocalRejected(result.rejectedDecisions);
      onUpdated?.({
        human_review_state: result.humanReviewState,
        review_events: result.reviewEvents,
        rejected_decisions: result.rejectedDecisions,
      });
      return;
    }

    if (result.abortedByConfigChange) return;

    setFeedback({type: 'error', message: result.message});
    if (result.status === 401) {
      outlet?.openConnectionPanel?.();
    }
  };

  const busy = Boolean(submittingAction);
  const mismatchedPaths = staleInfo?.staleDetail?.mismatched_paths || [];
  const expectedHashes = staleInfo?.staleDetail?.expected_hashes || {};
  const observedHashes = staleInfo?.staleDetail?.observed_hashes || {};

  return (
    <Card title="Quyết định của người kiểm duyệt (Human Review)">
      <div className="v2-dual-status" style={{marginTop: 0, paddingTop: 0, borderTop: 'none', marginBottom: '14px'}}>
        <div className="v2-status-box">
          <span className="v2-status-kicker">Nhận định AI (Qwen3.5-9B · Đề xuất)</span>
          <div className="v2-status-box-row">
            <Badge tone={vMeta.tone}>{validatedStatus}</Badge>
            <span className="v2-status-box-title">{vMeta.viLabel}</span>
          </div>
          <p>{vMeta.summary}</p>
        </div>
        <div className="v2-status-box v2-status-box--human">
          <span className="v2-status-kicker">Quyết định con người (SQLite · Chính thức)</span>
          <div className="v2-status-box-row">
            <Badge tone={hMeta.tone}>{humanReviewState}</Badge>
            <span className="v2-status-box-title">{hMeta.viLabel}</span>
          </div>
          <p>{hMeta.summary}</p>
        </div>
      </div>

      {validatedStatus === 'REFUTED' && humanReviewState === 'OPEN' && (
        <DataNotice>
          AI nhận định cảnh báo có thể không chính xác (<strong>REFUTED</strong>), nhưng hệ thống không tự loại bỏ. Cảnh báo vẫn giữ trạng thái <strong>OPEN</strong> cho tới khi bạn xác nhận và máy chủ kiểm tra toàn vẹn SHA-256 thành công.
        </DataNotice>
      )}
      {validatedStatus === 'UNDETERMINED' && (
        <DataNotice>
          Trạng thái AI là <strong>UNDETERMINED</strong> (chưa đủ bằng chứng hoặc trích dẫn chưa khớp). Cảnh báo được giữ nguyên để kiểm tra trực tiếp mã nguồn Java.
        </DataNotice>
      )}
      {!identityCheck.valid && (
        <div className="inline-error" role="alert">
          <Icon name="AlertTriangle" />
          <span>{identityCheck.error}</span>
        </div>
      )}
      {identityCheck.valid && writable && !driftReadiness.canConfirmFalse && (
        <DataNotice>
          Chưa đủ điều kiện kiểm tra source drift nên thao tác xác nhận cảnh báo giả (<code>CONFIRMED_FALSE</code>) đang bị khóa:{' '}
          {driftReadiness.summary}
        </DataNotice>
      )}
      {!writable && (
        <DataNotice>
          Phiên quét nằm trong vùng chỉ đọc (<code>SCAN_READ_ONLY</code>); không thể gửi quyết định kiểm duyệt mới.
        </DataNotice>
      )}
      {writable && (!tokenPresent || !writeConfigured) && (
        <DataNotice>
          <span style={{display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center'}}>
            <span>
              {!writeConfigured
                ? 'Máy chủ API chưa cấu hình NTK_API_TOKEN nên các thao tác ghi đang bị khóa.'
                : 'Cần Bearer Token phiên để ghi quyết định lên API (trường actor chỉ dùng để ghi nhận nhật ký audit).'}
            </span>
            {!tokenPresent && (
              <button
                type="button"
                className="button-secondary button-compact"
                onClick={() => outlet?.openConnectionPanel?.()}
              >
                <Icon name="KeyRound" />Nhập Bearer Token phiên
              </button>
            )}
          </span>
        </DataNotice>
      )}

      <div className="v2-review-form">
        <label className="v2-field-group">
          <span>Người kiểm duyệt (actor ghi vào nhật ký audit, bắt buộc)</span>
          <input
            type="text"
            value={actor}
            maxLength={120}
            disabled={busy || !canReview}
            onChange={(e) => setActor(e.target.value)}
            placeholder="Ví dụ: reviewer-uet"
            aria-label="Người kiểm duyệt (actor)"
          />
        </label>

        <label className="v2-field-group">
          <span>Lý do kiểm duyệt (reason, bắt buộc)</span>
          <textarea
            rows={3}
            value={reason}
            maxLength={2000}
            disabled={busy || !canReview}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Ghi rõ căn cứ từ dòng mã Java thật, luồng dữ liệu hoặc biện pháp làm sạch đầu vào…"
            aria-label="Lý do kiểm duyệt (reason)"
          />
        </label>

        <div className="v2-review-actions">
          <button
            type="button"
            className="button-primary"
            disabled={busy || !canReview}
            onClick={() => handleAction('confirm-true')}
          >
            <Icon name="ShieldAlert" />
            {submittingAction === 'confirm-true' ? 'Đang gửi xác nhận thật…' : 'Xác nhận cảnh báo thật (CONFIRMED_TRUE)'}
          </button>
          <button
            type="button"
            className="button-secondary"
            disabled={busy || !canConfirmFalse}
            onClick={() => handleAction('confirm-false')}
          >
            <Icon name="ShieldCheck" />
            {submittingAction === 'confirm-false' ? 'Đang kiểm tra SHA-256 & gửi…' : 'Xác nhận cảnh báo giả (CONFIRMED_FALSE)'}
          </button>
          <button
            type="button"
            className="button-secondary"
            disabled={busy || !canReview}
            onClick={() => handleAction('reopen')}
          >
            <Icon name="RotateCcw" />
            {submittingAction === 'reopen' ? 'Đang mở lại…' : 'Mở lại chờ duyệt (OPEN)'}
          </button>
        </div>
      </div>

      {feedback?.type === 'success' && (
        <div className="inline-success" role="status">
          <Icon name="Check" /><span>{feedback.message}</span>
        </div>
      )}
      {feedback?.type === 'error' && (
        <div className="inline-error" role="alert">
          <Icon name="AlertTriangle" /><span>{feedback.message}</span>
        </div>
      )}

      {staleInfo && (
        <div className="v2-stale-alert" role="alert">
          <h4>
            <Icon name="AlertTriangle" />
            HTTP 409 STALE_SOURCE — Mã nguồn đã thay đổi, từ chối xác nhận cảnh báo giả
          </h4>
          <p>
            Máy chủ phát hiện mã nguồn Java đã thay đổi hoặc bị thiếu so với mã băm SHA-256 lúc quét.
            Hệ thống không tự gửi lại và giữ nguyên trạng thái cảnh báo ở <strong>{staleInfo.humanReviewState}</strong>.
            Quyết định bị từ chối đã được ghi vào nhật ký kiểm toán bên dưới.
          </p>
          {mismatchedPaths.length > 0 && (
            <div className="v2-hash-diff-grid">
              {mismatchedPaths.map((p) => (
                <div className="v2-hash-diff-row" key={p}>
                  <strong className="mono">{p}</strong>
                  <code style={{color: 'var(--v2-text-secondary)'}}>SHA-256 lúc quét: {expectedHashes[p] || '—'}</code>
                  <code style={{color: 'var(--v2-danger-text)'}}>SHA-256 hiện tại: {observedHashes[p] || '—'}</code>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{marginTop: '22px', paddingTop: '16px', borderTop: '1px solid var(--v2-border-subtle)'}}>
        <h3 style={{fontSize: '14.5px', fontWeight: 650, margin: '0 0 12px'}}>
          Lịch sử kiểm duyệt SQLite &amp; Quyết định bị từ chối ({effectiveEvents.length} sự kiện · {effectiveRejected.length} từ chối)
        </h3>
        <AuditTimeline events={effectiveEvents} rejectedDecisions={effectiveRejected} />
      </div>
    </Card>
  );
}
