import {useCallback, useEffect, useState} from 'react';
import {useOutletContext} from 'react-router-dom';
import {Card, PageHeader, Badge, DataNotice, Icon} from '../components/common/Ui';
import {api, getApiBaseUrl, getApiOrigin, getAuthSessionScope} from '../services/api';
import {describeOpengrepHealth, formatShortHash} from '../services/findingPresentation';

const MISSING = 'API chưa cung cấp';

function buildRows(health, model, recentOpengrepVersion) {
  const status = String(health?.status || '').toUpperCase();
  const og = health?.opengrep || {};
  const ol = model?.ollama || health?.ollama || {};
  const rules = health?.rules || {};
  const arch = health?.architecture || {};
  const ogInfo = describeOpengrepHealth(og, recentOpengrepVersion);
  const qwenModelName = ol.requested_model || ol.model;

  return [
    {
      name: 'Địa chỉ API đang cấu hình',
      value: getApiBaseUrl(),
      tone: 'blue',
      detail: 'Có thể thay đổi qua nút Cấu hình API / Token trên thanh tiêu đề.',
    },
    {
      name: 'Trạng thái API (/api/health)',
      value: health
        ? `${status} · ${health.service || 'api'} v${health.api_version || '?'} · schema ${health.contract_schema || '?'}`
        : 'Chưa nhận được phản hồi',
      tone: status === 'OK' ? 'green' : status === 'DEGRADED' || status === 'AUTH_REQUIRED' ? 'amber' : 'red',
      detail: health?.degraded_reasons?.length
        ? `degraded_reasons: ${health.degraded_reasons.join(', ')}`
        : '',
    },
    {
      name: 'Xác thực phiên (Bearer Token)',
      value: health?.auth_required
        ? health.authenticated
          ? 'Đã xác thực phiên'
          : 'AUTH_REQUIRED — cần nhập token phiên'
        : health?.write_auth_configured
          ? 'Đã cấu hình NTK_API_TOKEN trên máy chủ'
          : 'Chưa cấu hình NTK_API_TOKEN (thao tác ghi bị khóa)',
      tone: health?.authenticated || health?.write_auth_configured ? 'green' : 'amber',
      detail: 'Bearer Token chỉ lưu trong bộ nhớ RAM của tab hiện tại, không ghi vào localStorage.',
    },
    {
      name: 'OpenGrep (Static Analysis Engine)',
      value: ogInfo.label,
      tone: ogInfo.tone,
      detail: ogInfo.detail,
    },
    {
      name: 'Ollama cục bộ (/api/model)',
      value: ol.reachable === undefined
        ? MISSING
        : ol.reachable
          ? `Đang kết nối (${ol.endpoint || '127.0.0.1:11434'})`
          : `Mất kết nối (${ol.error || ol.endpoint || 'unreachable'})`,
      tone: ol.reachable ? 'green' : ol.reachable === false ? 'red' : 'neutral',
      detail: ol.installed_models_count !== undefined && ol.installed_models_count !== null
        ? `Số mô hình ghi nhận trong /api/tags: ${ol.installed_models_count}`
        : '',
    },
    {
      name: 'Mô hình Qwen3.5-9B',
      value: qwenModelName === undefined
        ? MISSING
        : `${qwenModelName} · ${ol.model_installed ? 'Có trong /api/tags của Ollama' : 'Chưa tìm thấy trong /api/tags'}`,
      tone: ol.model_installed ? 'green' : qwenModelName ? 'amber' : 'neutral',
      detail: ol.model_digest
        ? `Digest Ollama báo cáo: ${formatShortHash(ol.model_digest, 16, 10)} (chưa chứng thực độc lập ở tầng vận chuyển).`
        : '',
    },
    {
      name: 'Tập luật OpenGrep & CWE trọng tâm',
      value: rules.available
        ? `${rules.name} · ${(rules.priority_cwes || ['CWE-22', 'CWE-89']).join(', ')}`
        : MISSING,
      tone: rules.available ? 'green' : 'neutral',
      detail: rules.sha256 ? `Rules SHA-256: ${rules.sha256}` : '',
    },
    {
      name: 'Git CLI (tải mã nguồn GitHub)',
      value: health?.git_available === undefined ? MISSING : health.git_available ? 'Khả dụng' : 'Không khả dụng',
      tone: health?.git_available ? 'green' : 'amber',
      detail: '',
    },
    {
      name: 'Chính sách kiến trúc & an toàn',
      value: arch.static_engine
        ? `Cloud LLM: ${String(arch.cloud_llm_enabled)} · Human Review: ${String(arch.human_review_required)} · STALE_SOURCE Guard: ${String(arch.stale_source_guard_enabled)}`
        : MISSING,
      tone: 'blue',
      detail: 'Toàn bộ phân tích tĩnh và suy luận LLM chạy cục bộ; cảnh báo giả yêu cầu xác nhận của người kiểm duyệt.',
    },
  ];
}

export default function StatusPage() {
  const outlet = useOutletContext();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const [health, setHealth] = useState(null);
  const [model, setModel] = useState(null);
  const [recentOpengrepVersion, setRecentOpengrepVersion] = useState(null);
  const [errors, setErrors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshedAt, setRefreshedAt] = useState('');
  const [manualTick, setManualTick] = useState(0);

  const handleManualRefresh = useCallback(() => {
    setManualTick((v) => v + 1);
    outlet?.refreshBackend?.();
  }, [outlet]);

  useEffect(() => {
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;

    setLoading(true);
    setHealth(null);
    setModel(null);
    setRecentOpengrepVersion(null);
    setErrors([]);

    (async () => {
      const failures = [];
      let hData = null;
      try {
        hData = await api.health({signal: controller.signal});
        if (isStale()) return;
        setHealth(hData);
      } catch (err) {
        if (isStale() || err?.abortedByConfigChange) return;
        failures.push(`/api/health: ${err.message}`);
      }

      if (hData?.status === 'AUTH_REQUIRED') {
        setModel(null);
        setRecentOpengrepVersion(null);
        failures.push('Cần nhập Bearer Token phiên để đọc /api/model và trạng thái chi tiết.');
      } else if (hData) {
        try {
          const mData = await api.model({signal: controller.signal});
          if (isStale()) return;
          setModel(mData);
        } catch (err) {
          if (isStale() || err?.abortedByConfigChange) return;
          failures.push(`/api/model: ${err.message}`);
        }
        try {
          const scansRes = await api.listScans({signal: controller.signal});
          if (isStale()) return;
          const latestWithVersion = (scansRes?.items || []).find((s) => Boolean(s?.opengrep_version));
          setRecentOpengrepVersion(latestWithVersion?.opengrep_version || null);
        } catch (err) {
          if (isStale() || err?.abortedByConfigChange) return;
          setRecentOpengrepVersion(null);
        }
      }

      if (isStale()) return;
      setErrors(failures);
      setRefreshedAt(new Date().toLocaleString('vi-VN'));
      setLoading(false);
    })();

    return () => {
      active = false;
      controller.abort();
    };
  }, [apiOrigin, authSessionScope, apiRevision, manualTick]);

  const rows = buildRows(health, model, recentOpengrepVersion);
  const degradedReasons = Array.isArray(health?.degraded_reasons) ? health.degraded_reasons : [];

  return (
    <>
      <PageHeader
        eyebrow="TRẠNG THÁI HỆ THỐNG"
        title="Kết nối API & công cụ thực thi"
        description="Kiểm tra trực tiếp API backend, OpenGrep, dịch vụ Ollama cục bộ, mô hình Qwen3.5-9B và mã băm tập luật."
        actions={(
          <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
            <button type="button" className="button-secondary" onClick={() => outlet?.openConnectionPanel?.()}>
              <Icon name="KeyRound" />Đổi URL / Token
            </button>
            <button type="button" className="button-primary" onClick={handleManualRefresh} disabled={loading}>
              <Icon name="RotateCcw" />{loading ? 'Đang kiểm tra…' : 'Làm mới'}
            </button>
          </div>
        )}
      />

      <DataNotice>
        Trạng thái phản ánh kết quả thực tế từ <code>/api/health</code> và <code>/api/model</code>.
        Toàn bộ suy luận chạy cục bộ qua Ollama, không gọi mô hình đám mây.
      </DataNotice>

      {refreshedAt && <p className="panel-note">Kiểm tra gần nhất: {refreshedAt}</p>}

      {degradedReasons.length > 0 && (
        <div className="inline-warning" role="status" style={{marginBottom: '14px'}}>
          <Icon name="AlertTriangle" />
          <div>
            <strong>Cảnh báo từ /api/health (<code>degraded_reasons</code>): {degradedReasons.join(', ')}</strong>
            {degradedReasons.includes('OPENGREP_NOT_VERIFIED') && (
              <p style={{margin: '4px 0 0', fontSize: '12.5px'}}>
                <code>OPENGREP_NOT_VERIFIED</code> cho biết health check không chạy thử tiến trình OpenGrep nhằm giữ phản hồi nhanh và an toàn.
                Trạng thái này khác với lỗi thiếu binary (<code>OPENGREP_UNAVAILABLE</code>) và tách biệt với các lượt quét OpenGrep thực tế đã hoàn thành
                {recentOpengrepVersion ? ` (phiên bản ghi nhận từ lượt quét gần nhất: ${recentOpengrepVersion})` : ''}.
              </p>
            )}
          </div>
        </div>
      )}

      {errors.map((message) => (
        <div className="inline-error" role="alert" key={message} style={{marginBottom: '12px'}}>
          <Icon name="AlertTriangle" /><span>{message}</span>
        </div>
      ))}

      <Card className="status-table">
        {rows.map((row) => {
          const dotClass = row.tone === 'green' ? 'online' : row.tone === 'amber' ? 'dot-warn' : row.tone === 'red' ? 'dot-error' : '';
          return (
            <div className="system-row" key={row.name}>
              <div className="v2-system-row-left">
                <span className={`status-dot ${dotClass}`} aria-hidden="true" />
                <div>
                  <strong>{row.name}</strong>
                  {row.detail && <span className="v2-system-detail">{row.detail}</span>}
                </div>
              </div>
              <Badge tone={row.tone}>{row.value}</Badge>
            </div>
          );
        })}
      </Card>
    </>
  );
}
