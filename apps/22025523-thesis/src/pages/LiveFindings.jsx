import {useMemo} from 'react';
import {Link, useNavigate, useOutletContext} from 'react-router-dom';
import {PageHeader, StatCard, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import FindingsExplorer from '../components/results/FindingsExplorer';
import OverviewCharts from '../components/results/OverviewCharts';
import {
  classifyDataOrigin,
  NO_FINDINGS_NOTICE,
  resolveJavaFileCounts,
  summarizeDowngradeReasons,
} from '../services/findingPresentation';
import {clearStaleActiveScanId, scanQuery} from '../services/liveScan';
import {useScanOverview, buildAggregates} from '../services/scanOverview';
import '../styles/results-dashboard.css';

const n = (v) => (v === undefined || v === null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
const fmt = (v) => (v === null ? '—' : v.toLocaleString('vi-VN'));

function Kpis({summary, rows, agg}) {
  const byValidated = summary?.by_validated_status || {};
  const byHuman = summary?.by_human_review_state || {};
  const byCwe = summary?.by_cwe || {};

  const javaCounts = resolveJavaFileCounts(summary);
  const total = n(summary?.total_findings) ?? (agg ? rows.length : null);
  const cwe22 = n(byCwe['CWE-22']) ?? (agg ? rows.filter((r) => r.cwe === 'CWE-22').length : null);
  const cwe89 = n(byCwe['CWE-89']) ?? (agg ? rows.filter((r) => r.cwe === 'CWE-89').length : null);

  const supported = n(byValidated.SUPPORTED) ?? (agg ? rows.filter((r) => r.validatedStatus === 'SUPPORTED').length : null);
  const refuted = n(byValidated.REFUTED) ?? (agg ? rows.filter((r) => r.validatedStatus === 'REFUTED').length : null);
  const undetermined = n(byValidated.UNDETERMINED) ?? (agg ? rows.filter((r) => r.validatedStatus === 'UNDETERMINED').length : null);

  const openCount = n(byHuman.OPEN) ?? (agg ? rows.filter((r) => r.humanReviewState === 'OPEN').length : null);
  const confirmedTrue = n(byHuman.CONFIRMED_TRUE) ?? (agg ? rows.filter((r) => r.humanReviewState === 'CONFIRMED_TRUE').length : null);
  const confirmedFalse = n(byHuman.CONFIRMED_FALSE) ?? (agg ? rows.filter((r) => r.humanReviewState === 'CONFIRMED_FALSE').length : null);

  const javaDisplayValue = javaCounts.isInconsistent
    ? (javaCounts.inventoryCount !== null ? `${fmt(javaCounts.inventoryCount)} (không nhất quán)` : 'Không nhất quán')
    : javaCounts.primaryValue !== null
      ? fmt(javaCounts.primaryValue)
      : 'Chưa có số liệu';

  return (
    <div className="stats-grid v2-results-kpis">
      <StatCard
        label={javaCounts.primaryLabel}
        value={javaDisplayValue}
        note={javaCounts.summaryNote}
        icon="Code"
      />
      <StatCard
        label="Tổng cảnh báo OpenGrep"
        value={fmt(total)}
        note={`CWE-22: ${fmt(cwe22)} · CWE-89: ${fmt(cwe89)}`}
        icon="Bug"
      />
      <div className="stat-card">
        <div className="stat-icon tone-blue"><Icon name="Cpu" /></div>
        <div className="stat-label">Nhận định Qwen</div>
        <strong>{`${fmt(supported)} / ${fmt(refuted)} / ${fmt(undetermined)}`}</strong>
        <small className="v2-kpi-note-single-line">Supported / Refuted / Undetermined</small>
      </div>
      <StatCard
        label="Người kiểm duyệt"
        value={openCount !== null ? `${fmt(openCount)} OPEN` : '—'}
        note={`Xác nhận thật: ${fmt(confirmedTrue)} · Xác nhận giả: ${fmt(confirmedFalse)}`}
        icon="Shield"
      />
    </div>
  );
}

export function LiveFindings({scanId}) {
  const outlet = useOutletContext();
  const navigate = useNavigate();
  const [state, retry] = useScanOverview(scanId, outlet?.apiRevision ?? 0);
  const data = state.data;
  const agg = useMemo(() => (data?.complete ? buildAggregates(data.rows) : null), [data]);

  const header = (
    <PageHeader
      eyebrow="KẾT QUẢ PHÁT HIỆN"
      title="Kết quả phát hiện & kiểm chứng"
      description={scanId ? `Phiên quét: ${scanId}` : 'Chọn một phiên phân tích để xem danh sách cảnh báo.'}
      actions={(
        <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
          {scanId && (
            <Link to={`/review${scanQuery(scanId)}`} className="button-secondary">
              <Icon name="Shield" />Hàng đợi kiểm duyệt
            </Link>
          )}
          <Link to="/scanner" className="button-primary">
            <Icon name="Plus" />Phiên phân tích mới
          </Link>
        </div>
      )}
    />
  );

  if (!scanId) {
    return (
      <>
        {header}
        <EmptyState
          title="Chưa chọn phiên phân tích"
          text="Hãy khởi tạo phiên phân tích mới hoặc chọn một phiên từ Lịch sử phân tích."
          icon="Inbox"
        />
      </>
    );
  }

  if (state.status === 'loading') {
    const p = state.progress;
    return (
      <>
        {header}
        <DataNotice>
          Đang tải toàn bộ cảnh báo từ API{p ? ` (${p.loaded.toLocaleString('vi-VN')}${p.total ? ` / ${p.total.toLocaleString('vi-VN')}` : ''})` : ''}…
        </DataNotice>
      </>
    );
  }

  if (state.status === 'error') {
    const needsAuth = state.statusCode === 401 || state.statusCode === 403 || /UNAUTHORIZED|Bearer Token|HTTP 401|HTTP 403/i.test(state.error || '');
    return (
      <>
        {header}
        <EmptyState title="Không tải được kết quả từ API" text={state.error} icon="AlertTriangle" />
        <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px'}}>
          <button type="button" className="button-primary" onClick={retry}>Thử lại</button>
          {needsAuth && (
            <button type="button" className="button-secondary" onClick={() => outlet?.openConnectionPanel?.()}>
              <Icon name="KeyRound" />Nhập Bearer Token phiên
            </button>
          )}
          {state.statusCode === 404 && (
            <button
              type="button"
              className="button-secondary"
              onClick={() => {
                if (state.errorCode === 'SCAN_NOT_FOUND') {
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
    );
  }

  const summary = data.summary;
  const originInfo = classifyDataOrigin(summary);
  const downgradedSummary = summarizeDowngradeReasons(data.rows);
  const downgradedCount = Number(summary?.validator_downgraded_count ?? downgradedSummary.totalDowngraded ?? 0);

  return (
    <>
      {header}
      {originInfo.isUnverified && !originInfo.isMockOrTest && (
        <DataNotice>
          Nguồn gốc phiên quét hiện là <code>{originInfo.code}</code> ({originInfo.label}); chưa có đủ bằng chứng xác minh capture cho dữ liệu quét thực (<code>REAL_SCAN</code>).
        </DataNotice>
      )}
      {downgradedCount > 0 && (
        <DataNotice>
          <span>
            Có <strong>{downgradedCount}</strong> cảnh báo bị bộ kiểm chứng hạ cấp về <strong>UNDETERMINED</strong>
            {downgradedSummary.items.length > 0 ? (
              <>
                {' '}theo nguyên nhân thực tế từ API:{' '}
                {downgradedSummary.items.map((item, idx) => (
                  <span key={item.code}>
                    {idx > 0 ? '; ' : ''}
                    <strong>{item.count}</strong> × {item.viLabel} (<code>{item.code}</code>)
                  </span>
                ))}
                {downgradedSummary.missingReasonCount > 0 && (
                  <span>; <strong>{downgradedSummary.missingReasonCount}</strong> × chưa có mã nguyên nhân chi tiết từ API</span>
                )}
                .
              </>
            ) : (
              ' (API chưa cung cấp mã nguyên nhân hạ cấp chi tiết).'
            )}
            {downgradedSummary.matchedButUndeterminedCount > 0 && (
              <>
                {' '}Lưu ý: có <strong>{downgradedSummary.matchedButUndeterminedCount}</strong> cảnh báo đạt trích dẫn khớp mã nguồn (<code>MATCHED</code>) nhưng vẫn ở trạng thái <strong>UNDETERMINED</strong> vì chưa kiểm chứng đủ luồng dữ liệu/hàm trợ giúp hoặc lập luận bảo mật.
              </>
            )}
          </span>
        </DataNotice>
      )}

      <Kpis summary={summary} rows={data.rows} agg={agg} />

      {!data.complete && (
        <div style={{marginTop: '14px'}}>
          <DataNotice>
            Mới tải {data.rows.length.toLocaleString('vi-VN')}{data.total ? ` / ${data.total.toLocaleString('vi-VN')}` : ''} cảnh báo. {data.reason}{' '}
            <button type="button" className="button-secondary button-compact" onClick={retry}>Tải lại</button>
          </DataNotice>
        </div>
      )}

      {agg && data.rows.length > 0 && <OverviewCharts agg={agg} />}

      {data.complete && data.rows.length === 0 && (
        <div style={{marginTop: '18px'}}>
          <EmptyState
            title="Không phát hiện cảnh báo (NO_FINDINGS)"
            text={NO_FINDINGS_NOTICE}
            icon="ShieldCheck"
          />
        </div>
      )}

      {data.complete && data.rows.length > 0 && (
        <FindingsExplorer rows={data.rows} scanId={scanId} />
      )}
    </>
  );
}
