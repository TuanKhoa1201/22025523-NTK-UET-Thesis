import {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {NavLink, Outlet, useLocation} from 'react-router-dom';
import {Icon} from '../common/Ui';
import UETLogo from '../common/UETLogo';
import {navGroups} from '../../data/research';
import {
  api,
  clearSessionToken,
  configureApiConnection,
  getApiBaseUrl,
  getApiConfigRevision,
  getApiOrigin,
  getAuthSessionScope,
  hasSessionToken,
  resetApiBaseUrl,
  subscribeApiConfig,
} from '../../services/api';
import {classifyBackendHealthState} from '../../services/findingPresentation';
import {createHealthMonitor, DEFAULT_PROBE_RETRY_DELAYS_MS} from '../../services/healthMonitor';

const SUB_ROUTE_LABELS = Object.freeze({
  '/findings': 'Kết quả phát hiện',
  '/results': 'Kết quả phát hiện',
  '/review': 'Xác minh cảnh báo',
  '/reports': 'Báo cáo',
});

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [backend, setBackend] = useState({status: 'CHECKING', health: null, error: ''});
  const [healthMeta, setHealthMeta] = useState({
    autoRechecking: false,
    retryAttempt: 0,
    maxRetries: DEFAULT_PROBE_RETRY_DELAYS_MS.length,
    retryExhausted: false,
    lastCheckedAt: null,
    inFlight: false,
  });
  const monitorRef = useRef(null);
  const [apiConfig, setApiConfig] = useState(() => ({
    baseUrl: getApiBaseUrl(),
    origin: getApiOrigin(),
    sessionScope: getAuthSessionScope(),
    revision: getApiConfigRevision(),
  }));
  const [showConnPanel, setShowConnPanel] = useState(false);
  const [apiUrlInput, setApiUrlInput] = useState(() => getApiBaseUrl());
  const [tokenInput, setTokenInput] = useState('');
  const [tokenActive, setTokenActive] = useState(() => hasSessionToken());
  const [connError, setConnError] = useState('');
  const [connNotice, setConnNotice] = useState('');

  const location = useLocation();
  const isHistorySubRoute =
    location.pathname === '/findings' ||
    location.pathname === '/results' ||
    location.pathname === '/review' ||
    location.pathname === '/reports' ||
    location.pathname.startsWith('/finding/');
  const navigationPath = isHistorySubRoute ? '/history' : location.pathname;
  const current = navGroups.flatMap((group) => group.items).find(([path]) => path === location.pathname);
  const breadcrumbLabel =
    current?.[1] ||
    (location.pathname.startsWith('/finding/')
      ? 'Chi tiết cảnh báo'
      : SUB_ROUTE_LABELS[location.pathname] || 'Tổng quan');

  const refreshBackend = useCallback(() => {
    monitorRef.current?.checkNow({force: true, preserveStatus: false});
  }, []);

  useEffect(() => subscribeApiConfig((event) => {
    setApiConfig({
      baseUrl: getApiBaseUrl(),
      origin: event.origin,
      sessionScope: event.sessionScope,
      revision: event.revision,
    });
    setTokenActive(event.hasToken);
    if (event.baseUrlChanged || event.originChanged) {
      setApiUrlInput(getApiBaseUrl());
    }
  }), []);

  useEffect(() => {
    const requestBaseUrl = getApiBaseUrl();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    setTokenActive(hasSessionToken());
    const monitor = createHealthMonitor({
      fetchHealth: async (opts) => {
        try {
          return await api.health(opts);
        } catch (error) {
          if (
            error?.abortedByConfigChange
            || getApiBaseUrl() !== requestBaseUrl
            || getApiOrigin() !== requestOrigin
            || getAuthSessionScope() !== requestSession
          ) {
            throw error;
          }
          throw error;
        }
      },
      onStateChange: (snapshot) => {
        if (
          getApiBaseUrl() !== requestBaseUrl
          || getApiOrigin() !== requestOrigin
          || getAuthSessionScope() !== requestSession
        ) return;
        setBackend(snapshot.backend);
        setHealthMeta(snapshot.meta);
        if (snapshot.backend.status === 'AUTH_REQUIRED') {
          setShowConnPanel(true);
        }
      },
    });
    monitorRef.current = monitor;
    monitor.checkNow({force: true});
    return () => {
      if (monitorRef.current === monitor) {
        monitorRef.current = null;
      }
      monitor.dispose();
    };
  }, [apiConfig.revision]);

  const applyConnectionSettings = (event) => {
    event.preventDefault();
    setConnError('');
    setConnNotice('');
    try {
      const result = configureApiConnection({baseUrl: apiUrlInput, token: tokenInput});
      setApiUrlInput(result.baseUrl);
      if (tokenInput.trim()) setTokenInput('');
      setTokenActive(result.hasToken);
      if (result.tokenClearedByOriginChange) {
        setConnNotice(
          'Đã đổi sang origin API khác; Bearer Token và dữ liệu đệm của phiên cũ đã bị xóa để không gửi sang origin mới. Nhập token mới nếu máy chủ yêu cầu xác thực.',
        );
      } else if (result.sessionChanged && !result.originChanged) {
        setConnNotice('Đã chuyển sang phiên xác thực mới; dữ liệu đệm của phiên trước đã được xóa để tránh lẫn phiên.');
      }
    } catch (error) {
      setConnError(error.message);
    }
  };

  const handleClearToken = () => {
    setTokenInput('');
    setConnNotice('');
    clearSessionToken();
  };

  const handleResetUrl = () => {
    const previousOrigin = getApiOrigin();
    const hadToken = hasSessionToken();
    const restored = resetApiBaseUrl();
    setApiUrlInput(restored);
    setTokenInput('');
    setConnError('');
    if (getApiOrigin() !== previousOrigin && hadToken && !hasSessionToken()) {
      setConnNotice('Đã đặt lại về origin API mặc định và xóa Bearer Token của origin trước đó.');
    } else {
      setConnNotice('');
    }
  };

  const connected = backend.status === 'CONNECTED' || backend.status === 'DEGRADED';
  const healthView = useMemo(() => classifyBackendHealthState(backend), [backend]);
  const degradedReasons = healthView.degradedReasons;
  const schemaWarnings = healthView.schemaWarnings || [];
  const ogInfo = healthView.ogInfo;

  const pillLabel = healthView.pillLabel;
  const pillClass = healthView.pillClass;
  const sidebarDotClass = healthView.sidebarDotClass;
  const sidebarStatusLabel = healthView.sidebarLabel;
  const pillTitle = [
    pillLabel,
    degradedReasons.length ? `degraded_reasons: ${degradedReasons.join(', ')}` : '',
    healthMeta.autoRechecking ? `Đang tự kiểm tra lại active probe (${healthMeta.retryAttempt}/${healthMeta.maxRetries})` : '',
  ].filter(Boolean).join(' · ');

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <a className="skip-link" href="#ntk-main">Đi tới nội dung chính</a>
      <aside className="sidebar" aria-label="Điều hướng chính">
        <NavLink to="/" className="brand">
          <UETLogo />
          {!collapsed && <span><b>22025523</b><small>BẢO MẬT MÃ NGUỒN</small></span>}
        </NavLink>
        <nav className="sidebar-nav" aria-label="Danh mục trang">
          {navGroups.map((group, groupIndex) => (
            <div className="nav-group" key={group.title || `group-${groupIndex}`}>
              {!collapsed && group.title && <div className="nav-group-title">{group.title}</div>}
              {group.items.map(([path, label, icon]) => (
                <NavLink
                  end={path === '/'}
                  to={path}
                  key={path}
                  title={collapsed ? label : undefined}
                  className={({isActive}) => `nav-item ${isActive || path === navigationPath ? 'active' : ''}`}
                >
                  <Icon name={icon} /><span>{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status" title={sidebarStatusLabel}>
            <span className={`status-dot ${sidebarDotClass}`} aria-hidden="true" />
            {!collapsed && <span>{sidebarStatusLabel}</span>}
          </div>
          <button
            className="collapse-button"
            type="button"
            aria-label={collapsed ? 'Mở rộng menu' : 'Thu gọn menu'}
            onClick={() => setCollapsed(!collapsed)}
          >
            <Icon name={collapsed ? 'PanelLeftOpen' : 'PanelLeftClose'} />
            <span>{!collapsed && 'Thu gọn menu'}</span>
          </button>
        </div>
      </aside>
      <div className="main-area">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>22025523</span><Icon name="ChevronRight" />
            <strong>{breadcrumbLabel}</strong>
          </div>
          <div className="topbar-actions">
            <button
              type="button"
              className="button-secondary button-compact"
              onClick={() => setShowConnPanel((prev) => !prev)}
              aria-expanded={showConnPanel}
              title="Cấu hình địa chỉ API và Bearer Token phiên"
            >
              <Icon name="KeyRound" />
              <span>{tokenActive ? 'API · Đã nạp token' : 'Cấu hình API / Token'}</span>
            </button>
            <span
              className={`connection-pill ${pillClass}`}
              title={pillTitle}
            >
              <i aria-hidden="true" />{pillLabel}
            </span>
          </div>
        </header>
        {showConnPanel && (
          <section className="v2-conn-drawer" aria-label="Cấu hình kết nối API và phiên làm việc">
            <form className="v2-conn-form" onSubmit={applyConnectionSettings}>
              <label className="v2-conn-field">
                <span>Địa chỉ API Backend</span>
                <input
                  type="url"
                  value={apiUrlInput}
                  onChange={(e) => setApiUrlInput(e.target.value)}
                  placeholder="http://127.0.0.1:18765"
                  aria-label="Địa chỉ API Backend"
                />
              </label>
              <label className="v2-conn-field">
                <span>Bearer Token phiên</span>
                <input
                  type="password"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder={tokenActive ? 'Đã nạp token cho origin hiện tại (nhập mới để thay)' : 'Nhập API Bearer Token…'}
                  autoComplete="off"
                  aria-label="API Bearer Token phiên"
                />
              </label>
              <div className="v2-conn-actions">
                <button type="submit" className="button-primary">Áp dụng &amp; Kiểm tra</button>
                {tokenActive && (
                  <button type="button" className="button-secondary" onClick={handleClearToken}>Xóa token</button>
                )}
                <button type="button" className="button-secondary" onClick={handleResetUrl}>Đặt lại URL</button>
                <button type="button" className="button-secondary" onClick={() => setShowConnPanel(false)}>Đóng</button>
              </div>
            </form>
            {connError && <div className="inline-error" role="alert"><Icon name="AlertTriangle" />{connError}</div>}
            {connNotice && <p className="v2-conn-note is-warn" role="status">{connNotice}</p>}
            {backend.status === 'AUTH_REQUIRED' && (
              <p className="v2-conn-note is-warn">
                API đang yêu cầu xác thực. Nhập Bearer Token phiên để đọc dữ liệu và thực hiện thao tác ghi.
              </p>
            )}
            {schemaWarnings.length > 0 && (
              <p className="v2-conn-note is-warn" role="status">
                Cảnh báo định dạng <code>/api/health</code>: {schemaWarnings.join(' ')}
              </p>
            )}
            {backend.status === 'DEGRADED' && degradedReasons.length > 0 && (
              <p className={`v2-conn-note ${ogInfo?.tone === 'red' ? 'is-error' : 'is-warn'}`}>
                Cảnh báo từ <code>/api/health</code> (<code>degraded_reasons</code>):{' '}
                <strong>{degradedReasons.join(', ')}</strong>.
                {ogInfo && !ogInfo.isVerified && (
                  <span>
                    {' '}{ogInfo.label}. {ogInfo.detail}
                    {healthMeta.autoRechecking && (
                      <span> Đang tự kiểm tra lại có giới hạn ({healthMeta.retryAttempt}/{healthMeta.maxRetries})…</span>
                    )}
                  </span>
                )}
              </p>
            )}
            {backend.status === 'ERROR' && backend.error && (
              <p className="v2-conn-note is-error" role="alert">
                API ({getApiBaseUrl()}): {backend.error}
              </p>
            )}
          </section>
        )}
        <main id="ntk-main" className="content-area">
          <Outlet context={{
            backend,
            healthMeta,
            healthView,
            refreshBackend,
            openConnectionPanel: () => setShowConnPanel(true),
            connected,
            apiOrigin: apiConfig.origin,
            authSessionScope: apiConfig.sessionScope,
            apiRevision: apiConfig.revision,
          }} />
          <footer className="footer">
            <span>22025523 <b>·</b> OpenGrep + Qwen3.5-9B + Citation/SHA-256 + Human Review</span>
            <NavLink to="/about">Giới thiệu đề tài <Icon name="ArrowUpRight" /></NavLink>
          </footer>
        </main>
      </div>
    </div>
  );
}
