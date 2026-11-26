import {useCallback, useEffect, useRef, useState} from 'react';
import {useOutletContext} from 'react-router-dom';
import {Card, PageHeader, Badge, DataNotice, Icon} from '../components/common/Ui';
import {api, getApiBaseUrl, getApiOrigin, getAuthSessionScope} from '../services/api';
import {
  classifyBackendHealthState,
  describeOpengrepHealth,
  formatShortHash,
  normalizeDegradedReasons,
  normalizeHealthArchitecture,
  parseStrictBoolean,
} from '../services/findingPresentation';
import {createHealthMonitor} from '../services/healthMonitor';

const MISSING = 'API chưa cung cấp';

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function safeScalarText(value, fallback = '') {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return fallback;
}

function formatIsoOrEmpty(value) {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return '';
  } else if (typeof value !== 'string' || !value.trim()) {
    return '';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('vi-VN');
}

function formatBooleanPolicyToken(field) {
  if (field?.state === 'VALID') return field.value ? 'true' : 'false';
  if (field?.state === 'INVALID') return 'sai kiểu';
  return 'chưa cung cấp';
}

function buildArchitectureRow(health, backend) {
  const archInfo = normalizeHealthArchitecture(health?.architecture, {
    preValidatedInvalidFields: backend?.architectureInvalidFields,
    preValidatedMalformed: Boolean(backend?.architectureMalformed),
  });

  if (archInfo.malformed) {
    return {
      archInfo,
      row: {
        name: 'Chính sách kiến trúc & an toàn',
        value: 'Dữ liệu architecture sai định dạng',
        tone: 'amber',
        detail: 'Trường architecture từ /api/health sai kiểu đối tượng; không tự xác minh chính sách an toàn.',
      },
    };
  }

  if (!archInfo.present || !archInfo.hasAnyData) {
    return {
      archInfo,
      row: {
        name: 'Chính sách kiến trúc & an toàn',
        value: MISSING,
        tone: 'neutral',
        detail: 'API chưa cung cấp metadata chính sách kiến trúc; không tự khẳng định chính sách an toàn đã được xác minh.',
      },
    };
  }

  const cloudText = formatBooleanPolicyToken(archInfo.fields.cloud_llm_enabled);
  const reviewText = formatBooleanPolicyToken(archInfo.fields.human_review_required);
  const staleText = formatBooleanPolicyToken(archInfo.fields.stale_source_guard_enabled);
  const engineParts = [
    archInfo.fields.static_engine.state === 'VALID' ? archInfo.fields.static_engine.value : null,
    archInfo.fields.llm_engine.state === 'VALID' ? archInfo.fields.llm_engine.value : null,
  ].filter(Boolean);
  const value = `Cloud LLM: ${cloudText} · Human Review: ${reviewText} · STALE_SOURCE Guard: ${staleText}`;

  let tone = 'blue';
  let detail;
  if (archInfo.hasInvalidFields) {
    tone = 'amber';
    detail = `Một số trường trong architecture sai kiểu dữ liệu (${archInfo.invalidFields.join(', ')}); không thể xác minh đầy đủ chính sách an toàn.`;
  } else if (archInfo.hasUnsafePolicyValue) {
    tone = 'amber';
    detail = 'Một hoặc nhiều cờ chính sách an toàn khác cấu hình cục bộ mặc định; cần kiểm tra lại cấu hình máy chủ API.';
  } else if (archInfo.hasMissingSafetyFlags) {
    tone = 'amber';
    detail = `API chưa cung cấp đầy đủ các cờ chính sách an toàn (${archInfo.missingSafetyFlags.join(', ')}); không tự khẳng định đã xác minh.`;
  } else {
    detail = engineParts.length > 0
      ? `API xác nhận chính sách cục bộ (${engineParts.join(' · ')}): không dùng Cloud LLM, cảnh báo giả yêu cầu xác nhận của người kiểm duyệt.`
      : 'API xác nhận toàn bộ phân tích tĩnh và suy luận LLM chạy cục bộ; cảnh báo giả yêu cầu xác nhận của người kiểm duyệt.';
  }

  return {
    archInfo,
    row: {
      name: 'Chính sách kiến trúc & an toàn',
      value,
      tone,
      detail,
    },
  };
}

export function buildHealthStatusRows(backend, model, recentOpengrepVersion, healthMeta, precomputedView = null) {
  const health = isPlainObject(backend?.health) ? backend.health : null;
  const invalidBoolSet = new Set(Array.isArray(backend?.invalidBooleanFields) ? backend.invalidBooleanFields : []);
  const view = precomputedView || classifyBackendHealthState(backend);
  const status = safeScalarText(health?.status).toUpperCase();
  const og = isPlainObject(health?.opengrep) ? health.opengrep : {};
  const useModelOllama = isPlainObject(model?.ollama);
  const ol = useModelOllama ? model.ollama : (isPlainObject(health?.ollama) ? health.ollama : {});
  const rules = isPlainObject(health?.rules) ? health.rules : {};
  const ogInfo = (precomputedView?.ogInfo && !recentOpengrepVersion)
    ? precomputedView.ogInfo
    : describeOpengrepHealth(health?.opengrep, recentOpengrepVersion, {
        snapshotReceivedAtMs: backend?.receivedAtMs ?? null,
        expiresAtMs: backend?.expiresAtMs ?? healthMeta?.expiresAtMs ?? null,
        serverCheckedAtMs: backend?.serverCheckedAtMs ?? null,
        serverCheckedAtMalformed: Boolean(backend?.serverCheckedAtMalformed),
        forceExpired: Boolean(backend?.ttlExpired || healthMeta?.ttlExpired || precomputedView?.ogInfo?.ttlExpired),
      });
  const qwenModelName = safeScalarText(ol.requested_model) || safeScalarText(ol.model) || undefined;
  const reasonsCheck = normalizeDegradedReasons(health?.degraded_reasons);
  const degradedReasons = reasonsCheck.reasons;
  const priorityCwes = Array.isArray(rules.priority_cwes) && rules.priority_cwes.length > 0
    ? rules.priority_cwes.filter((item) => typeof item === 'string' && item.trim())
    : ['CWE-22', 'CWE-89'];

  const authRequired = parseStrictBoolean(health?.auth_required, {wasInvalid: invalidBoolSet.has('auth_required')});
  const authenticated = parseStrictBoolean(health?.authenticated, {wasInvalid: invalidBoolSet.has('authenticated')});
  const writeAuthConfigured = parseStrictBoolean(health?.write_auth_configured, {wasInvalid: invalidBoolSet.has('write_auth_configured')});
  const gitAvailable = parseStrictBoolean(health?.git_available, {wasInvalid: invalidBoolSet.has('git_available')});
  const ollamaReachable = parseStrictBoolean(ol.reachable, {wasInvalid: !useModelOllama && invalidBoolSet.has('ollama.reachable')});
  const ollamaModelInstalled = parseStrictBoolean(ol.model_installed, {wasInvalid: !useModelOllama && invalidBoolSet.has('ollama.model_installed')});
  const rulesAvailable = parseStrictBoolean(rules.available, {wasInvalid: invalidBoolSet.has('rules.available')});

  const ogExtraDetails = [];
  if (ogInfo.detail) ogExtraDetails.push(ogInfo.detail);
  const ogExpiresText = formatIsoOrEmpty(og.expires_at);
  const metaExpiresText = formatIsoOrEmpty(backend?.expiresAtMs ?? healthMeta?.expiresAtMs);
  if (ogExpiresText) ogExtraDetails.push(`Hết hạn TTL: ${ogExpiresText}`);
  else if (metaExpiresText) ogExtraDetails.push(`Hết hạn TTL: ${metaExpiresText}`);
  if (healthMeta?.autoRechecking) {
    ogExtraDetails.push(`Đang tự động kiểm tra lại kết quả active probe (${healthMeta.retryAttempt}/${healthMeta.maxRetries})…`);
  } else if (healthMeta?.retryExhausted && og.probe_in_progress === true) {
    ogExtraDetails.push('Đã hết số lần tự kiểm tra lại cho phiên này; bấm "Làm mới" để kiểm tra tiếp.');
  }

  const apiStatusValue = backend?.status === 'CHECKING'
    ? 'Đang kiểm tra /api/health…'
    : backend?.status === 'ERROR'
      ? `Không thể kết nối (${safeScalarText(backend.error, 'NETWORK_ERROR')})`
      : health
        ? `${status || 'UNKNOWN'} · ${safeScalarText(health.service, 'api')} v${safeScalarText(health.api_version, '?')} · schema ${safeScalarText(health.contract_schema, '?')}`
        : 'Chưa nhận được phản hồi';

  const apiStatusTone = view.status === 'CONNECTED'
    ? 'green'
    : view.status === 'DEGRADED' || view.status === 'AUTH_REQUIRED' || view.status === 'CHECKING'
      ? 'amber'
      : 'red';

  const authRow = (() => {
    if (view.status === 'AUTH_REQUIRED' || (authRequired.value === true && authenticated.value !== true)) {
      return {value: 'AUTH_REQUIRED — cần nhập token phiên', tone: 'amber'};
    }
    if (authRequired.malformed || authenticated.malformed || writeAuthConfigured.malformed) {
      return {value: 'Trạng thái xác thực sai kiểu dữ liệu', tone: 'amber'};
    }
    if (authRequired.value === true && authenticated.value === true) {
      return {value: 'Đã xác thực phiên (authenticated = true)', tone: 'green'};
    }
    if (writeAuthConfigured.value === true) {
      return {value: 'Đã cấu hình NTK_API_TOKEN trên máy chủ', tone: 'green'};
    }
    if (writeAuthConfigured.value === false) {
      return {value: 'Chưa cấu hình NTK_API_TOKEN (thao tác ghi bị khóa)', tone: 'amber'};
    }
    if (health) {
      return {value: MISSING, tone: 'neutral'};
    }
    return {value: MISSING, tone: 'amber'};
  })();

  const ollamaRow = (() => {
    if (ollamaReachable.malformed) {
      return {value: 'Dữ liệu trạng thái Ollama sai kiểu', tone: 'amber'};
    }
    if (ollamaReachable.state === 'MISSING') {
      return {value: MISSING, tone: 'neutral'};
    }
    if (ollamaReachable.value === true) {
      return {value: `Đang kết nối (${safeScalarText(ol.endpoint, '127.0.0.1:11434')})`, tone: 'green'};
    }
    return {value: `Mất kết nối (${safeScalarText(ol.error) || safeScalarText(ol.endpoint) || 'unreachable'})`, tone: 'red'};
  })();

  const qwenRow = (() => {
    if (qwenModelName === undefined) {
      return {value: MISSING, tone: ollamaModelInstalled.malformed ? 'amber' : 'neutral'};
    }
    if (ollamaModelInstalled.malformed) {
      return {value: `${qwenModelName} · trạng thái cài đặt sai kiểu`, tone: 'amber'};
    }
    if (ollamaModelInstalled.value === true) {
      return {value: `${qwenModelName} · Có trong /api/tags của Ollama`, tone: 'green'};
    }
    if (ollamaModelInstalled.value === false) {
      return {value: `${qwenModelName} · Chưa tìm thấy trong /api/tags`, tone: 'amber'};
    }
    return {value: `${qwenModelName} · Chưa có trạng thái /api/tags`, tone: 'amber'};
  })();

  const rulesRow = (() => {
    if (rulesAvailable.malformed) {
      return {value: 'Dữ liệu trạng thái tập luật sai kiểu', tone: 'amber'};
    }
    if (rulesAvailable.value === true) {
      return {value: `${safeScalarText(rules.name, 'ruleset')} · ${priorityCwes.join(', ')}`, tone: 'green'};
    }
    if (rulesAvailable.value === false) {
      return {value: 'Tập luật không khả dụng', tone: 'red'};
    }
    return {value: MISSING, tone: 'neutral'};
  })();

  const gitRow = (() => {
    if (gitAvailable.malformed) {
      return {value: 'Dữ liệu trạng thái Git sai kiểu', tone: 'amber'};
    }
    if (gitAvailable.state === 'MISSING') {
      return {value: MISSING, tone: 'neutral'};
    }
    return gitAvailable.value === true
      ? {value: 'Khả dụng', tone: 'green'}
      : {value: 'Không khả dụng', tone: 'amber'};
  })();

  const {row: architectureRow} = buildArchitectureRow(health, backend);

  return [
    {
      name: 'Địa chỉ API đang cấu hình',
      value: getApiBaseUrl(),
      tone: 'blue',
      detail: 'Có thể thay đổi qua nút Cấu hình API / Token trên thanh tiêu đề.',
    },
    {
      name: 'Trạng thái API (/api/health)',
      value: apiStatusValue,
      tone: apiStatusTone,
      detail: [
        view.reachable ? 'API reachable' : 'API chưa reachable',
        degradedReasons.length ? `degraded_reasons: ${degradedReasons.join(', ')}` : '',
        reasonsCheck.malformed ? 'degraded_reasons từ API không đúng kiểu mảng' : '',
      ].filter(Boolean).join(' · '),
    },
    {
      name: 'Xác thực phiên (Bearer Token)',
      value: authRow.value,
      tone: authRow.tone,
      detail: 'Bearer Token chỉ lưu trong bộ nhớ RAM của tab hiện tại, không ghi vào localStorage.',
    },
    {
      name: 'OpenGrep Active Health Probe',
      value: ogInfo.label,
      tone: ogInfo.tone,
      detail: ogExtraDetails.join(' · '),
    },
    {
      name: 'Ollama cục bộ (/api/model)',
      value: ollamaRow.value,
      tone: ollamaRow.tone,
      detail: typeof ol.installed_models_count === 'number' && Number.isFinite(ol.installed_models_count)
        ? `Số mô hình ghi nhận trong /api/tags: ${ol.installed_models_count}`
        : '',
    },
    {
      name: 'Mô hình Qwen3.5-9B',
      value: qwenRow.value,
      tone: qwenRow.tone,
      detail: safeScalarText(ol.model_digest)
        ? `Digest Ollama báo cáo: ${formatShortHash(ol.model_digest, 16, 10)} (chưa chứng thực độc lập ở tầng vận chuyển).`
        : '',
    },
    {
      name: 'Tập luật OpenGrep & CWE trọng tâm',
      value: rulesRow.value,
      tone: rulesRow.tone,
      detail: safeScalarText(rules.sha256) ? `Rules SHA-256: ${safeScalarText(rules.sha256)}` : '',
    },
    {
      name: 'Git CLI (tải mã nguồn GitHub)',
      value: gitRow.value,
      tone: gitRow.tone,
      detail: '',
    },
    architectureRow,
  ];
}

export default function StatusPage() {
  const outlet = useOutletContext();
  const hasSharedOutlet = Boolean(outlet && outlet.backend);
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;

  const [standaloneBackend, setStandaloneBackend] = useState({status: 'CHECKING', health: null, error: ''});
  const [standaloneMeta, setStandaloneMeta] = useState({
    autoRechecking: false,
    retryAttempt: 0,
    maxRetries: 0,
    retryExhausted: false,
    lastCheckedAt: null,
    inFlight: false,
  });
  const standaloneMonitorRef = useRef(null);

  const [model, setModel] = useState(null);
  const [recentOpengrepVersion, setRecentOpengrepVersion] = useState(null);
  const [auxErrors, setAuxErrors] = useState([]);
  const [auxLoading, setAuxLoading] = useState(false);
  const [manualTick, setManualTick] = useState(0);

  const backend = hasSharedOutlet ? outlet.backend : standaloneBackend;
  const healthMeta = hasSharedOutlet ? outlet.healthMeta : standaloneMeta;
  const health = isPlainObject(backend?.health) ? backend.health : null;
  const healthView = (hasSharedOutlet && outlet.healthView) ? outlet.healthView : classifyBackendHealthState(backend);
  const ogInfo = health && Object.hasOwn(health, 'opengrep') && health.opengrep !== null && health.opengrep !== undefined
    ? describeOpengrepHealth(health.opengrep, recentOpengrepVersion, {
        snapshotReceivedAtMs: backend?.receivedAtMs ?? null,
        expiresAtMs: backend?.expiresAtMs ?? healthMeta?.expiresAtMs ?? null,
        serverCheckedAtMs: backend?.serverCheckedAtMs ?? null,
        serverCheckedAtMalformed: Boolean(backend?.serverCheckedAtMalformed),
        forceExpired: Boolean(backend?.ttlExpired || healthMeta?.ttlExpired),
      })
    : null;

  // Standalone fallback ONLY if StatusPage is rendered outside AppShell.
  useEffect(() => {
    if (hasSharedOutlet) return undefined;
    const monitor = createHealthMonitor({
      onStateChange: (snapshot) => {
        setStandaloneBackend(snapshot.backend);
        setStandaloneMeta(snapshot.meta);
      },
    });
    standaloneMonitorRef.current = monitor;
    monitor.checkNow({force: true});
    return () => {
      if (standaloneMonitorRef.current === monitor) {
        standaloneMonitorRef.current = null;
      }
      monitor.dispose();
    };
  }, [hasSharedOutlet, apiOrigin, authSessionScope, apiRevision]);

  const handleManualRefresh = useCallback(() => {
    setManualTick((v) => v + 1);
    if (hasSharedOutlet) {
      outlet.refreshBackend?.();
    } else {
      standaloneMonitorRef.current?.checkNow({force: true, preserveStatus: false});
    }
  }, [hasSharedOutlet, outlet]);

  // Reset auxiliary data strictly on scope/config change (R01 isolation).
  useEffect(() => {
    setModel(null);
    setRecentOpengrepVersion(null);
    setAuxErrors([]);
  }, [apiOrigin, authSessionScope, apiRevision]);

  const backendStatus = backend?.status;
  useEffect(() => {
    if (backendStatus !== 'CONNECTED' && backendStatus !== 'DEGRADED') {
      setAuxLoading(false);
      if (backendStatus === 'AUTH_REQUIRED') {
        setModel(null);
        setRecentOpengrepVersion(null);
        setAuxErrors(['Cần nhập Bearer Token phiên để đọc /api/model và trạng thái chi tiết.']);
      } else if (backendStatus === 'ERROR' && safeScalarText(backend?.error)) {
        setAuxErrors([`/api/health: ${safeScalarText(backend.error)}`]);
      } else {
        setAuxErrors([]);
      }
      return undefined;
    }

    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;

    setAuxLoading(true);
    setAuxErrors([]);

    (async () => {
      const failures = [];
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
        const latestWithVersion = (scansRes?.items || []).find((s) => Boolean(safeScalarText(s?.opengrep_version)));
        setRecentOpengrepVersion(safeScalarText(latestWithVersion?.opengrep_version) || null);
      } catch (err) {
        if (isStale() || err?.abortedByConfigChange) return;
        setRecentOpengrepVersion(null);
      }
      if (isStale()) return;
      setAuxErrors(failures);
      setAuxLoading(false);
    })();

    return () => {
      active = false;
      controller.abort();
    };
  }, [backendStatus, apiOrigin, authSessionScope, apiRevision, manualTick, backend?.error]);

  const rows = buildHealthStatusRows(backend, model, recentOpengrepVersion, healthMeta, healthView);
  const archInfo = normalizeHealthArchitecture(health?.architecture, {
    preValidatedInvalidFields: backend?.architectureInvalidFields,
    preValidatedMalformed: Boolean(backend?.architectureMalformed),
  });
  const degradedReasons = healthView.degradedReasons;
  const schemaWarnings = healthView.schemaWarnings || [];
  const loading = backendStatus === 'CHECKING' || Boolean(healthMeta?.inFlight) || auxLoading;
  const refreshedAt = healthMeta?.lastCheckedAt ? new Date(healthMeta.lastCheckedAt).toLocaleString('vi-VN') : '';

  return (
    <>
      <PageHeader
        eyebrow="TRẠNG THÁI HỆ THỐNG"
        title="Kết nối API & công cụ thực thi"
        description="Đồng bộ trực tiếp trạng thái /api/health (gồm active health probe OpenGrep theo TTL), dịch vụ Ollama cục bộ, mô hình Qwen3.5-9B và mã băm tập luật."
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
        Trạng thái trên thanh tiêu đề, thanh điều hướng và trang này dùng chung một kết quả từ <code>/api/health</code>:{' '}
        <strong>{healthView.pillLabel}</strong>.{' '}
        {archInfo.verifiedSafePolicy
          ? 'Chính sách kiến trúc từ API xác nhận toàn bộ suy luận chạy cục bộ qua Ollama, không gọi mô hình đám mây.'
          : 'Xem mục Chính sách kiến trúc & an toàn bên dưới để đối chiếu trạng thái các cờ chính sách do API trả về.'}
      </DataNotice>

      {refreshedAt && (
        <p className="panel-note">
          Kiểm tra gần nhất: {refreshedAt}
          {healthMeta?.autoRechecking && ` · Đang tự kiểm tra lại active probe (${healthMeta.retryAttempt}/${healthMeta.maxRetries})…`}
        </p>
      )}

      {schemaWarnings.length > 0 && (
        <div className="inline-warning" role="status" style={{marginBottom: '14px'}}>
          <Icon name="AlertTriangle" />
          <div>
            <strong>Cảnh báo định dạng phản hồi <code>/api/health</code>:</strong>{' '}
            <span>{schemaWarnings.join(' ')}</span>
          </div>
        </div>
      )}

      {degradedReasons.length > 0 && (
        <div
          className={ogInfo?.tone === 'red' ? 'inline-error' : 'inline-warning'}
          role="status"
          style={{marginBottom: '14px'}}
        >
          <Icon name="AlertTriangle" />
          <div>
            <strong>Cảnh báo từ /api/health (<code>degraded_reasons</code>): {degradedReasons.join(', ')}</strong>
            {ogInfo && !ogInfo.isVerified && (
              <p style={{margin: '4px 0 0', fontSize: '12.5px'}}>
                {ogInfo.label}. {ogInfo.detail}
                {healthMeta?.autoRechecking && (
                  <span> Hệ thống đang tự kiểm tra lại có giới hạn ({healthMeta.retryAttempt}/{healthMeta.maxRetries}) mà không cần tải lại trang.</span>
                )}
              </p>
            )}
          </div>
        </div>
      )}

      {auxErrors.map((message) => (
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
