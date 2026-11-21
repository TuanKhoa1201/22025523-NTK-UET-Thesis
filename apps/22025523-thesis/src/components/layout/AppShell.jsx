import {useCallback, useEffect, useState} from 'react';
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

const SUB_ROUTE_LABELS = Object.freeze({
  '/findings': 'Kết quả phát hiện',
  '/results': 'Kết quả phát hiện',
  '/review': 'Xác minh cảnh báo',
  '/reports': 'Báo cáo',
});

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [backend, setBackend] = useState({status: 'CHECKING', health: null, error: ''});
  const [probeTick, setProbeTick] = useState(0);
  const [apiConfig, setApiConfig] = useState(() => ({
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
    setProbeTick((value) => value + 1);
  }, []);

  useEffect(() => subscribeApiConfig((event) => {
    setApiConfig({origin: event.origin, sessionScope: event.sessionScope, revision: event.revision});
    setTokenActive(event.hasToken);
    if (event.baseUrlChanged || event.originChanged) {
      setApiUrlInput(getApiBaseUrl());
    }
  }), []);

  useEffect(() => {
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    setTokenActive(hasSessionToken());
    setBackend((prev) => ({...prev, status: 'CHECKING', error: ''}));
    api.health({signal: controller.signal, timeoutMs: 5000})
      .then((health) => {
        if (isStale()) return;
        const rawStatus = String(health?.status || '').toUpperCase();
        if (rawStatus === 'AUTH_REQUIRED') {
          setBackend({status: 'AUTH_REQUIRED', health, error: ''});
          setShowConnPanel(true);
        } else if (rawStatus === 'OK' || rawStatus === 'DEGRADED') {
          setBackend({status: rawStatus === 'OK' ? 'CONNECTED' : 'DEGRADED', health, error: ''});
        } else {
          setBackend({status: 'ERROR', health, error: 'Phản hồi /api/health không hợp lệ.'});
        }
      })
      .catch((error) => {
        if (isStale() || error?.abortedByConfigChange) return;
        if (error?.status === 401) {
          setBackend({status: 'AUTH_REQUIRED', health: null, error: error?.message || 'Yêu cầu Bearer Token hợp lệ (HTTP 401).'});
          setShowConnPanel(true);
        } else {
          setBackend({status: 'ERROR', health: null, error: error?.message || 'Không thể kết nối máy chủ API.'});
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [probeTick, apiConfig.revision]);

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
  const degradedReasons = Array.isArray(backend.health?.degraded_reasons) ? backend.health.degraded_reasons : [];
  const onlyOpengrepHealthUnverified =
    backend.status === 'DEGRADED' &&
    degradedReasons.length === 1 &&
    degradedReasons[0] === 'OPENGREP_NOT_VERIFIED';

  const pillLabel = {
    CHECKING: 'ĐANG KIỂM TRA API',
    CONNECTED: 'KẾT NỐI THỰC',
    DEGRADED: onlyOpengrepHealthUnverified ? 'API SẴN SÀNG · CHƯA PROBE OPENGREP' : 'API HẠN CHẾ',
    AUTH_REQUIRED: 'CẦN TOKEN PHIÊN',
    ERROR: 'API KHÔNG KHẢ DỤNG',
  }[backend.status] || 'CHƯA KẾT NỐI';

  const pillClass = backend.status === 'CONNECTED'
    ? 'connected'
    : backend.status === 'DEGRADED' || backend.status === 'AUTH_REQUIRED'
      ? 'pill-warn'
      : backend.status === 'ERROR'
        ? 'pill-error'
        : '';

  const sidebarDotClass = backend.status === 'CONNECTED'
    ? 'online'
    : backend.status === 'DEGRADED' || backend.status === 'AUTH_REQUIRED'
      ? 'dot-warn'
      : backend.status === 'ERROR'
        ? 'dot-error'
        : '';

  const sidebarStatusLabel = {
    CHECKING: 'Đang kiểm tra API',
    CONNECTED: 'API đã sẵn sàng',
    DEGRADED: onlyOpengrepHealthUnverified ? 'API kết nối (OPENGREP_NOT_VERIFIED)' : 'API hoạt động hạn chế',
    AUTH_REQUIRED: 'Cần nhập Bearer Token',
    ERROR: 'API chưa kết nối',
  }[backend.status] || 'API chưa kết nối';

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
              title={degradedReasons.length ? `degraded_reasons: ${degradedReasons.join(', ')}` : pillLabel}
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
            {backend.status === 'DEGRADED' && degradedReasons.length > 0 && (
              <p className="v2-conn-note is-warn">
                Cảnh báo từ <code>/api/health</code> (<code>degraded_reasons</code>):{' '}
                <strong>{degradedReasons.join(', ')}</strong>.
                {degradedReasons.includes('OPENGREP_NOT_VERIFIED') && (
                  <span>
                    {' '}Lưu ý: <code>OPENGREP_NOT_VERIFIED</code> cho biết health check chủ động không gọi binary OpenGrep; phiên bản OpenGrep được xác minh khi chạy lượt quét thực tế.
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
