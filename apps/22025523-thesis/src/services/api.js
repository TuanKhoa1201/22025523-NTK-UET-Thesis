const STORAGE_API_URL_KEY = 'ntk-api-base-url';
const ACTIVE_SCAN_STORAGE_KEY = '22025523-scan-id';
const LIVE_DATASET_CACHE_PREFIX = '22025523-live-dataset:';
const LIVE_SCAN_HISTORY_STORAGE_KEY = '22025523-live-scan-history';
const ACTIVE_JOB_STORAGE_KEY = '22025523-active-job';
const ACTIVE_JOB_STARTED_KEY = '22025523-active-job-started';
const FORBIDDEN_PORTS = new Set([8765]);
const DEFAULT_SUGGESTED_API_URL = 'http://127.0.0.1:18765';

const SAFE_401_MESSAGES = Object.freeze({
  UNAUTHORIZED: 'Thiếu hoặc sai API Bearer Token phiên (HTTP 401). Vui lòng nhập token hợp lệ trên thanh kết nối.',
});

const SAFE_403_MESSAGES = Object.freeze({
  CORS_ORIGIN_FORBIDDEN: 'Origin của trình duyệt chưa nằm trong NTK_CORS_ORIGINS của API (HTTP 403). [CORS_ORIGIN_FORBIDDEN]',
  SCAN_READ_ONLY: 'Phiên quét nằm trong vùng chỉ đọc; không cho phép thay đổi quyết định kiểm duyệt (HTTP 403). [SCAN_READ_ONLY]',
  TEST_DATA_ISOLATED: 'Dữ liệu mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực (HTTP 403). [TEST_DATA_ISOLATED]',
  READ_ONLY_PROXY: 'API / proxy hiện tại chỉ cho phép đọc nên không thể thực hiện thao tác ghi (HTTP 403). [READ_ONLY_PROXY]',
  READ_ONLY: 'API / proxy hiện tại chỉ cho phép đọc nên không thể thực hiện thao tác ghi (HTTP 403). [READ_ONLY]',
  WRITE_FORBIDDEN: 'API / proxy hiện tại từ chối thao tác ghi (HTTP 403). [WRITE_FORBIDDEN]',
  WRITE_DISABLED: 'API / proxy hiện tại đã khóa thao tác ghi (HTTP 403). [WRITE_DISABLED]',
});

const GITHUB_SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const COMMIT_SHA_RE = /^[0-9a-fA-F]{7,40}$/;

export function validateGithubRepoUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return {valid: false, canonicalUrl: '', owner: '', repo: '', error: 'Liên kết GitHub không được để trống.'};
  }
  const cleaned = rawUrl.trim();
  if (cleaned.length > 300) {
    return {valid: false, canonicalUrl: '', owner: '', repo: '', error: 'Liên kết GitHub vượt quá 300 ký tự cho phép.'};
  }
  for (let i = 0; i < cleaned.length; i += 1) {
    const code = cleaned.charCodeAt(i);
    if (code < 32 || /\s/.test(cleaned[i])) {
      return {valid: false, canonicalUrl: '', owner: '', repo: '', error: 'Liên kết GitHub chứa ký tự điều khiển hoặc khoảng trắng không hợp lệ.'};
    }
  }
  if (!/^https:\/\//i.test(cleaned)) {
    return {valid: false, canonicalUrl: '', owner: '', repo: '', error: 'Chỉ chấp nhận kho mã nguồn HTTPS công khai trên github.com.'};
  }
  const afterScheme = cleaned.slice(8);
  const slashIdx = afterScheme.indexOf('/');
  const rawAuthority = slashIdx === -1 ? afterScheme : afterScheme.slice(0, slashIdx);
  const rawRest = slashIdx === -1 ? '' : afterScheme.slice(slashIdx);
  if (rawAuthority.includes('@') || rawAuthority.includes(':')) {
    return {
      valid: false,
      canonicalUrl: '',
      owner: '',
      repo: '',
      error: 'Liên kết GitHub không được chứa thông tin xác thực hoặc cổng.',
    };
  }
  if (rawAuthority.toLowerCase() !== 'github.com') {
    return {
      valid: false,
      canonicalUrl: '',
      owner: '',
      repo: '',
      error: 'Chỉ chấp nhận kho mã nguồn HTTPS công khai trên github.com.',
    };
  }
  if (rawRest.includes('?') || rawRest.includes('#')) {
    return {
      valid: false,
      canonicalUrl: '',
      owner: '',
      repo: '',
      error: 'Liên kết GitHub không được chứa query hoặc fragment.',
    };
  }
  if (rawRest.includes('\\') || rawRest.includes('//')) {
    return {
      valid: false,
      canonicalUrl: '',
      owner: '',
      repo: '',
      error: 'Đường dẫn kho GitHub không hợp lệ.',
    };
  }
  const parts = rawRest.split('/').filter(Boolean);
  if (parts.length !== 2) {
    return {
      valid: false,
      canonicalUrl: '',
      owner: '',
      repo: '',
      error: 'Liên kết GitHub phải có dạng https://github.com/<owner>/<repo>.',
    };
  }
  const owner = parts[0];
  const rawRepo = parts[1];
  const repo = rawRepo.endsWith('.git') ? rawRepo.slice(0, -4) : rawRepo;
  if (
    !owner ||
    !repo ||
    owner === '.' ||
    owner === '..' ||
    repo === '.' ||
    repo === '..' ||
    owner.startsWith('-') ||
    repo.startsWith('-') ||
    !GITHUB_SEGMENT_RE.test(owner) ||
    !GITHUB_SEGMENT_RE.test(repo)
  ) {
    return {
      valid: false,
      canonicalUrl: '',
      owner: '',
      repo: '',
      error: 'Tên chủ sở hữu hoặc tên repository GitHub không hợp lệ.',
    };
  }
  // Keep rawRepo untouched (do not strip `.git` on the client) so only backend intake strips `.git` once;
  // this keeps frontend validation idempotent and prevents `.git.git` from being stripped twice.
  return {
    valid: true,
    canonicalUrl: `https://github.com/${owner}/${rawRepo}`,
    owner,
    repo,
    error: '',
  };
}

export function validateCommitSha(rawCommitSha) {
  if (rawCommitSha === undefined || rawCommitSha === null) {
    return {valid: true, normalized: undefined, error: ''};
  }
  if (typeof rawCommitSha !== 'string') {
    return {
      valid: false,
      normalized: '',
      error: 'Commit SHA phải là chuỗi hexadecimal dài 7–40 ký tự (không nhập tên nhánh); để trống để dùng nhánh mặc định.',
    };
  }
  const cleaned = rawCommitSha.trim();
  if (!cleaned) {
    return {valid: true, normalized: undefined, error: ''};
  }
  if (!COMMIT_SHA_RE.test(cleaned)) {
    return {
      valid: false,
      normalized: '',
      error: 'Commit SHA không hợp lệ. Chỉ chấp nhận chuỗi hexadecimal dài 7–40 ký tự (không nhập tên nhánh như main); để trống để dùng nhánh mặc định.',
    };
  }
  return {valid: true, normalized: cleaned.toLowerCase(), error: ''};
}

let sessionToken = '';
let sessionTokenOrigin = '';
let apiConfigRevision = 0;
let authSessionSeq = 1;
const inFlightRequests = new Set();
const configListeners = new Set();

function extractOrigin(rawUrl) {
  const parsed = new URL(String(rawUrl || '').trim());
  return parsed.origin;
}

function buildAuthSessionScope(baseUrl, seq) {
  return `${baseUrl}#s${seq}`;
}

function notifyConfigChange(detail) {
  apiConfigRevision += 1;
  const event = {
    baseUrl: apiBaseUrl,
    origin: extractOrigin(apiBaseUrl),
    sessionScope: authSessionScope,
    revision: apiConfigRevision,
    hasToken: hasSessionToken(),
    baseUrlChanged: false,
    originChanged: false,
    tokenChanged: false,
    sessionChanged: false,
    ...detail,
  };
  for (const listener of [...configListeners]) {
    try {
      listener(event);
    } catch {
      /* isolate subscriber failures */
    }
  }
  return event;
}

function clearSessionScopedStorage() {
  if (typeof window === 'undefined' || !window.sessionStorage) return;
  try {
    window.sessionStorage.removeItem(ACTIVE_SCAN_STORAGE_KEY);
    window.sessionStorage.removeItem(ACTIVE_JOB_STORAGE_KEY);
    window.sessionStorage.removeItem(ACTIVE_JOB_STARTED_KEY);
    window.sessionStorage.removeItem(LIVE_SCAN_HISTORY_STORAGE_KEY);
    if (typeof window.sessionStorage.length === 'number' && typeof window.sessionStorage.key === 'function') {
      const toRemove = [];
      for (let i = 0; i < window.sessionStorage.length; i += 1) {
        const key = window.sessionStorage.key(i);
        if (key && key.startsWith(LIVE_DATASET_CACHE_PREFIX)) toRemove.push(key);
      }
      toRemove.forEach((key) => window.sessionStorage.removeItem(key));
    }
  } catch {
    /* optional sessionStorage cleanup */
  }
}

function rotateAuthSession(baseUrl) {
  authSessionSeq += 1;
  authSessionScope = buildAuthSessionScope(baseUrl, authSessionSeq);
  clearSessionScopedStorage();
  abortInFlightRequests();
}

function abortInFlightRequests() {
  for (const entry of [...inFlightRequests]) {
    entry.markConfigChange();
    entry.controller.abort();
  }
  inFlightRequests.clear();
}

function scrubToken(text, activeToken) {
  const raw = String(text || '');
  if (!raw || !activeToken) return raw;
  return raw.split(activeToken).join('[REDACTED]');
}

function buildSafeAuthError(status, payload) {
  const rawCode = typeof payload?.error_code === 'string' ? payload.error_code.trim().toUpperCase() : '';
  if (status === 401) {
    const safeCode = rawCode === 'UNAUTHORIZED' ? 'UNAUTHORIZED' : 'UNAUTHORIZED';
    return {
      message: SAFE_401_MESSAGES.UNAUTHORIZED,
      payload: {error_code: safeCode},
    };
  }
  if (rawCode && Object.hasOwn(SAFE_403_MESSAGES, rawCode)) {
    return {
      message: SAFE_403_MESSAGES[rawCode],
      payload: {error_code: rawCode},
    };
  }
  return {
    message: 'Yêu cầu bị máy chủ từ chối quyền truy cập (HTTP 403). Kiểm tra cấu hình xác thực hoặc quyền phiên làm việc.',
    payload: {error_code: 'FORBIDDEN'},
  };
}

function normalizeApiUrl(rawUrl) {
  const raw = String(rawUrl || '').trim();
  if (!raw) {
    throw new Error('URL API không được để trống.');
  }
  for (let i = 0; i < raw.length; i += 1) {
    const code = raw.charCodeAt(i);
    if (code < 32 || code === 127 || /\s/.test(raw[i])) {
      throw new Error('URL API không được chứa khoảng trắng hoặc ký tự điều khiển.');
    }
  }
  if (raw.includes('?') || raw.includes('#')) {
    throw new Error('URL API không được chứa query string (?) hoặc fragment (#).');
  }
  const cleaned = raw.replace(/\/+$/, '');
  if (!cleaned) {
    throw new Error('URL API không được để trống.');
  }
  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch {
    throw new Error('URL API không hợp lệ. Ví dụ: http://127.0.0.1:18765');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('URL API chỉ hỗ trợ giao thức http:// hoặc https://.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('URL API không được chứa thông tin xác thực nhúng trong đường dẫn.');
  }
  if (parsed.search || parsed.hash) {
    throw new Error('URL API không được chứa query string (?) hoặc fragment (#).');
  }
  const port = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));
  if (FORBIDDEN_PORTS.has(port)) {
    throw new Error(`Cổng ${port} bị cấm theo chính sách bảo mật của dự án.`);
  }
  const normalizedPath = parsed.pathname.replace(/\/+$/, '');
  return `${parsed.origin}${normalizedPath}`;
}

function initialApiBaseUrl() {
  const fromEnv = typeof import.meta !== 'undefined' ? import.meta.env?.VITE_API_BASE_URL : '';
  if (fromEnv) {
    try {
      return normalizeApiUrl(fromEnv);
    } catch {
      /* fallback below */
    }
  }
  if (typeof window !== 'undefined' && window.sessionStorage) {
    const saved = window.sessionStorage.getItem(STORAGE_API_URL_KEY);
    if (saved) {
      try {
        return normalizeApiUrl(saved);
      } catch {
        window.sessionStorage.removeItem(STORAGE_API_URL_KEY);
      }
    }
  }
  return DEFAULT_SUGGESTED_API_URL;
}

let apiBaseUrl = initialApiBaseUrl();
let authSessionScope = buildAuthSessionScope(apiBaseUrl, authSessionSeq);
// On fresh page load / reload, purge any stale sessionStorage scan, job, or cached result markers
// from an earlier authenticated session (RAM token is already empty after reload).
clearSessionScopedStorage();

export function getApiBaseUrl() {
  return apiBaseUrl;
}

export function getApiOrigin() {
  return extractOrigin(apiBaseUrl);
}

export function getAuthSessionScope() {
  return authSessionScope;
}

export function getApiConfigRevision() {
  return apiConfigRevision;
}

export function subscribeApiConfig(listener) {
  if (typeof listener !== 'function') return () => {};
  configListeners.add(listener);
  return () => configListeners.delete(listener);
}

export function getSessionTokenOrigin() {
  return hasSessionToken() ? sessionTokenOrigin : '';
}

export function configureApiConnection({baseUrl, token = ''} = {}) {
  const normalized = normalizeApiUrl(baseUrl);
  const previousBaseUrl = apiBaseUrl;
  const previousOrigin = extractOrigin(previousBaseUrl);
  const previousToken = hasSessionToken() ? sessionToken : '';
  const nextOrigin = extractOrigin(normalized);
  const baseUrlChanged = normalized !== previousBaseUrl;
  const originChanged = nextOrigin !== previousOrigin;
  const cleanedToken = String(token || '').trim();
  const nextToken = originChanged ? cleanedToken : (cleanedToken || previousToken);
  const tokenChanged = nextToken !== previousToken;
  const sessionChanged = baseUrlChanged || originChanged || tokenChanged;

  apiBaseUrl = normalized;
  if (typeof window !== 'undefined' && window.sessionStorage) {
    window.sessionStorage.setItem(STORAGE_API_URL_KEY, normalized);
  }

  if (sessionChanged) {
    rotateAuthSession(normalized);
  }

  if (nextToken) {
    sessionToken = nextToken;
    sessionTokenOrigin = nextOrigin;
  } else {
    sessionToken = '';
    sessionTokenOrigin = '';
  }

  const event = notifyConfigChange({
    previousBaseUrl,
    baseUrl: normalized,
    baseUrlChanged,
    previousOrigin,
    originChanged,
    tokenChanged,
    sessionChanged,
    sessionScope: authSessionScope,
    tokenClearedByOriginChange: originChanged && Boolean(previousToken) && !cleanedToken,
  });

  return {
    baseUrl: normalized,
    origin: nextOrigin,
    baseUrlChanged,
    originChanged,
    tokenChanged,
    sessionChanged,
    sessionScope: authSessionScope,
    hasToken: hasSessionToken(),
    tokenClearedByOriginChange: event.tokenClearedByOriginChange,
    revision: event.revision,
  };
}

export function setApiBaseUrl(rawUrl) {
  const normalized = normalizeApiUrl(rawUrl);
  const previousBaseUrl = apiBaseUrl;
  const previousOrigin = extractOrigin(previousBaseUrl);
  const hadToken = hasSessionToken();
  const nextOrigin = extractOrigin(normalized);
  const baseUrlChanged = normalized !== previousBaseUrl;
  const originChanged = nextOrigin !== previousOrigin;
  const sessionChanged = baseUrlChanged || originChanged;

  apiBaseUrl = normalized;
  if (typeof window !== 'undefined' && window.sessionStorage) {
    window.sessionStorage.setItem(STORAGE_API_URL_KEY, normalized);
  }
  if (originChanged) {
    sessionToken = '';
    sessionTokenOrigin = '';
  }
  if (sessionChanged) {
    rotateAuthSession(normalized);
  }
  notifyConfigChange({
    previousBaseUrl,
    baseUrl: normalized,
    baseUrlChanged,
    previousOrigin,
    originChanged,
    tokenChanged: originChanged && hadToken,
    sessionChanged,
    sessionScope: authSessionScope,
  });
  return normalized;
}

export function resetApiBaseUrl() {
  const previousBaseUrl = apiBaseUrl;
  const previousOrigin = extractOrigin(previousBaseUrl);
  const hadToken = hasSessionToken();
  if (typeof window !== 'undefined' && window.sessionStorage) {
    window.sessionStorage.removeItem(STORAGE_API_URL_KEY);
  }
  apiBaseUrl = initialApiBaseUrl();
  const nextOrigin = extractOrigin(apiBaseUrl);
  const baseUrlChanged = apiBaseUrl !== previousBaseUrl;
  const originChanged = nextOrigin !== previousOrigin;
  const sessionChanged = baseUrlChanged || originChanged;
  if (originChanged) {
    sessionToken = '';
    sessionTokenOrigin = '';
  }
  if (sessionChanged) {
    rotateAuthSession(apiBaseUrl);
  }
  notifyConfigChange({
    previousBaseUrl,
    baseUrl: apiBaseUrl,
    baseUrlChanged,
    previousOrigin,
    originChanged,
    tokenChanged: originChanged && hadToken,
    sessionChanged,
    sessionScope: authSessionScope,
  });
  return apiBaseUrl;
}

export function setSessionToken(token) {
  const cleaned = String(token || '').trim();
  const currentBaseUrl = apiBaseUrl;
  const currentOrigin = extractOrigin(currentBaseUrl);
  const previousToken = hasSessionToken() ? sessionToken : '';
  const tokenChanged = cleaned !== previousToken;
  if (tokenChanged) {
    rotateAuthSession(currentBaseUrl);
  }
  if (cleaned) {
    sessionToken = cleaned;
    sessionTokenOrigin = currentOrigin;
  } else {
    sessionToken = '';
    sessionTokenOrigin = '';
  }
  notifyConfigChange({
    previousBaseUrl: currentBaseUrl,
    baseUrl: currentBaseUrl,
    baseUrlChanged: false,
    previousOrigin: currentOrigin,
    originChanged: false,
    tokenChanged,
    sessionChanged: tokenChanged,
    sessionScope: authSessionScope,
  });
  return hasSessionToken();
}

export function clearSessionToken() {
  const currentBaseUrl = apiBaseUrl;
  const currentOrigin = extractOrigin(currentBaseUrl);
  const hadToken = hasSessionToken();
  sessionToken = '';
  sessionTokenOrigin = '';
  if (hadToken) {
    rotateAuthSession(currentBaseUrl);
  }
  notifyConfigChange({
    previousBaseUrl: currentBaseUrl,
    baseUrl: currentBaseUrl,
    baseUrlChanged: false,
    previousOrigin: currentOrigin,
    originChanged: false,
    tokenChanged: hadToken,
    sessionChanged: hadToken,
    sessionScope: authSessionScope,
  });
}

export function hasSessionToken() {
  return Boolean(sessionToken && sessionTokenOrigin && sessionTokenOrigin === extractOrigin(apiBaseUrl));
}

export class ApiError extends Error {
  constructor(message, {status, timedOut = false, abortedByConfigChange = false, cause, payload} = {}) {
    super(message, {cause});
    this.name = 'ApiError';
    this.status = status;
    this.timedOut = timedOut;
    this.abortedByConfigChange = abortedByConfigChange;
    this.payload = payload;
    this.code = payload?.error_code;
  }
}

export function inputErrorMessage(payload) {
  const code = payload?.error_code || payload?.stage_error_code;
  const detail = payload?.error_message || payload?.stage_error_message || 'Không thể xử lý yêu cầu trên API.';
  const mapped = {
    UNAUTHORIZED: 'Thiếu hoặc sai API Bearer Token phiên. Vui lòng nhập token hợp lệ trên thanh kết nối.',
    AUTH_TOKEN_NOT_CONFIGURED: 'Máy chủ API chưa cấu hình NTK_API_TOKEN nên các thao tác ghi bị khóa.',
    CORS_ORIGIN_FORBIDDEN: 'Origin của trình duyệt chưa nằm trong NTK_CORS_ORIGINS của API.',
    TEST_DATA_ISOLATED: 'Dữ liệu mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực.',
    SCAN_READ_ONLY: 'Phiên quét nằm trong vùng chỉ đọc; không cho phép thay đổi quyết định kiểm duyệt.',
    STALE_SOURCE: 'Mã nguồn Java đã thay đổi so với thời điểm quét (STALE_SOURCE); từ chối xác nhận cảnh báo giả.',
    NO_JAVA_FILES_FOUND: 'Không tìm thấy tệp .java hợp lệ trong phạm vi mã nguồn đã cung cấp.',
    NO_JAVA_FILES_IN_ZIP: 'Tệp ZIP không chứa mã nguồn Java (.java) hợp lệ.',
    INVALID_GITHUB_URL: 'Liên kết GitHub không hợp lệ. Chỉ chấp nhận https://github.com/<owner>/<repo> công khai.',
    INVALID_COMMIT_SHA: 'Commit SHA phải gồm 7–40 ký tự hexadecimal (không nhập tên nhánh); để trống để dùng nhánh mặc định.',
    INVALID_ZIP_ARCHIVE: 'Tệp tải lên không phải định dạng ZIP hợp lệ.',
    EMPTY_ZIP_ARCHIVE: 'Tệp ZIP rỗng. Vui lòng chọn tệp chứa mã nguồn Java.',
    INVALID_ZIP_FILENAME: 'Chỉ chấp nhận tệp nén có phần mở rộng .zip.',
    MAX_ZIP_UPLOAD_BYTES_EXCEEDED: 'Tệp ZIP vượt quá dung lượng tải lên cho phép của API.',
    TOO_MANY_CONCURRENT_SCANS: 'Hệ thống đang đạt giới hạn số phiên quét đồng thời/xếp hàng. Vui lòng chờ phiên hiện tại hoàn tất.',
    OPENGREP_UNAVAILABLE: 'Không tìm thấy hoặc không thể chạy binary OpenGrep trên máy chủ API.',
    OLLAMA_UNREACHABLE: 'Không kết nối được dịch vụ Ollama cục bộ trên máy chủ API.',
    QWEN_MODEL_NOT_INSTALLED: 'Mô hình Qwen3.5-9B chưa được cài đặt trong Ollama cục bộ.',
  }[code];
  const message = mapped || detail;
  const formatted = code ? `${message} [${code}]` : message;
  return scrubToken(formatted, sessionToken);
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 15000;
  const fetchOptions = {...options};
  delete fetchOptions.timeoutMs;
  let didTimeout = false;
  let abortedByConfigChange = false;
  const timeout = window.setTimeout(() => {
    didTimeout = true;
    controller.abort();
  }, timeoutMs);
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, {once: true});

  const inFlightEntry = {
    controller,
    markConfigChange: () => {
      abortedByConfigChange = true;
    },
  };
  inFlightRequests.add(inFlightEntry);

  const baseSnapshot = apiBaseUrl;
  const sessionScopeSnapshot = authSessionScope;
  const tokenSnapshot = sessionToken;
  const tokenOriginSnapshot = sessionTokenOrigin;
  const safeRelativePath = typeof path === 'string' && path.startsWith('/') && !path.startsWith('//');
  const fullUrl = safeRelativePath ? `${baseSnapshot}${path}` : '';
  let baseOrigin = '';
  let targetOrigin = '';
  try {
    baseOrigin = extractOrigin(baseSnapshot);
    targetOrigin = safeRelativePath ? extractOrigin(fullUrl) : '';
  } catch {
    baseOrigin = '';
    targetOrigin = '';
  }

  if (!safeRelativePath || !baseOrigin || !targetOrigin || targetOrigin !== baseOrigin) {
    inFlightRequests.delete(inFlightEntry);
    window.clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
    throw new ApiError('Đường dẫn yêu cầu API không hợp lệ hoặc vượt khỏi origin đã cấu hình.');
  }

  const isStaleConfig = () => abortedByConfigChange
    || authSessionScope !== sessionScopeSnapshot
    || apiBaseUrl !== baseSnapshot
    || (baseOrigin && extractOrigin(apiBaseUrl) !== baseOrigin);

  const canAttachSessionToken = Boolean(
    tokenSnapshot &&
    tokenOriginSnapshot &&
    baseOrigin &&
    targetOrigin &&
    tokenOriginSnapshot === baseOrigin &&
    tokenOriginSnapshot === targetOrigin,
  );

  const headers = {
    ...(options.body instanceof FormData ? {} : {'Content-Type': 'application/json'}),
    ...(canAttachSessionToken ? {Authorization: `Bearer ${tokenSnapshot}`} : {}),
    ...options.headers,
  };

  try {
    const response = await fetch(fullUrl, {
      ...fetchOptions,
      signal: controller.signal,
      headers,
    });

    if (isStaleConfig()) {
      throw new ApiError('Cấu hình kết nối hoặc phiên xác thực API đã thay đổi khi yêu cầu đang thực thi.', {
        abortedByConfigChange: true,
      });
    }

    if (!response.ok) {
      const rawBody = await response.text();
      if (isStaleConfig()) {
        throw new ApiError('Cấu hình kết nối hoặc phiên xác thực API đã thay đổi khi yêu cầu đang thực thi.', {
          abortedByConfigChange: true,
        });
      }
      let payload;
      try {
        payload = JSON.parse(rawBody);
      } catch {
        /* non-JSON response */
      }

      // Handle HTTP 401/403 strictly with static allowlisted messages so untrusted
      // server/proxy error text can never echo Bearer credentials to the UI.
      if (response.status === 401 || response.status === 403) {
        const safeAuth = buildSafeAuthError(response.status, payload);
        throw new ApiError(safeAuth.message, {
          status: response.status,
          payload: safeAuth.payload,
        });
      }

      const rawMessage = payload
        ? inputErrorMessage(payload)
        : rawBody || `Yêu cầu thất bại (${response.status})`;
      throw new ApiError(scrubToken(rawMessage, tokenSnapshot), {
        status: response.status,
        payload,
      });
    }
    if (response.status === 204) return null;

    const text = await response.text();
    if (isStaleConfig()) {
      throw new ApiError('Cấu hình kết nối hoặc phiên xác thực API đã thay đổi khi yêu cầu đang thực thi.', {
        abortedByConfigChange: true,
      });
    }
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (didTimeout) {
      throw new ApiError('Máy chủ API không phản hồi trong thời gian cho phép.', {timedOut: true, cause: error});
    }
    if (abortedByConfigChange) {
      throw new ApiError('Cấu hình origin API đã thay đổi khi yêu cầu đang thực thi.', {abortedByConfigChange: true, cause: error});
    }
    throw error;
  } finally {
    inFlightRequests.delete(inFlightEntry);
    window.clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
  }
}

function invalidListResult(
  invalidReason,
  {totalCountProvided = false, endpointStatus = 'INVALID_PAYLOAD', httpStatus = null} = {},
) {
  return {
    supported: false,
    valid: false,
    invalidReason,
    endpointStatus,
    httpStatus,
    items: [],
    rawItemCount: 0,
    invalidItemCount: 0,
    totalCount: 0,
    declaredTotalCount: null,
    totalCountProvided,
    totalCountValid: false,
    countConsistent: false,
    truncated: false,
  };
}

const VALID_JOB_STATES = new Set(['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED']);

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validateScanListItem(item) {
  if (!isPlainObject(item)) return {valid: false, key: ''};
  const scanId = typeof item.scan_id === 'string' ? item.scan_id.trim() : '';
  const fallbackId = (
    !scanId &&
    typeof item.scan_sha256 === 'string' && item.scan_sha256.trim() &&
    typeof item.id === 'string' && item.id.trim() &&
    !item.job_id
  ) ? item.id.trim() : '';
  const key = scanId || fallbackId;
  return key ? {valid: true, key} : {valid: false, key: ''};
}

function validateJobListItem(item) {
  if (!isPlainObject(item)) return {valid: false, key: ''};
  const jobId = typeof item.job_id === 'string' ? item.job_id.trim() : '';
  const state = typeof (item.state ?? item.job_state ?? item.status) === 'string'
    ? String(item.state ?? item.job_state ?? item.status).trim().toUpperCase()
    : '';
  if (!jobId || !VALID_JOB_STATES.has(state)) return {valid: false, key: ''};
  if (state === 'COMPLETED') {
    const scanId = typeof item.scan_id === 'string' ? item.scan_id.trim() : '';
    if (!scanId) return {valid: false, key: ''};
  }
  return {valid: true, key: jobId};
}

function inspectListItems(rawItems, validator) {
  const validItems = [];
  const seenKeys = new Set();
  let invalidItemCount = 0;
  let duplicateKeyCount = 0;
  for (let i = 0; i < rawItems.length; i += 1) {
    const item = rawItems[i];
    const check = validator(item);
    if (!check.valid) {
      invalidItemCount += 1;
      continue;
    }
    if (seenKeys.has(check.key)) {
      duplicateKeyCount += 1;
      continue;
    }
    seenKeys.add(check.key);
    validItems.push(item);
  }
  return {validItems, invalidItemCount, duplicateKeyCount};
}

function finalizeListObjectResult(data, rawItems, format, validator) {
  const totalCountProvided = Object.hasOwn(data, 'total_count') && data.total_count !== undefined;
  const totalCountValid = (
    totalCountProvided &&
    typeof data.total_count === 'number' &&
    Number.isInteger(data.total_count) &&
    data.total_count >= 0
  );
  const declaredTotalCount = totalCountValid ? data.total_count : null;
  const {validItems, invalidItemCount, duplicateKeyCount} = inspectListItems(rawItems, validator);
  const declaredTruncated = Boolean(
    data.truncated === true ||
    data.has_more === true ||
    data.next_cursor ||
    data.next_page ||
    (typeof data.total_pages === 'number' && Number.isFinite(data.total_pages) && data.total_pages > 1) ||
    (typeof data.page === 'number' && Number.isFinite(data.page) && data.page > 1) ||
    (typeof data.limit === 'number' && Number.isFinite(data.limit) && data.limit >= 0 && totalCountValid && declaredTotalCount > data.limit),
  );
  const truncated = declaredTruncated || (totalCountValid && declaredTotalCount > rawItems.length);
  const countConsistent = (
    totalCountValid &&
    declaredTotalCount === rawItems.length &&
    declaredTotalCount === validItems.length &&
    invalidItemCount === 0 &&
    duplicateKeyCount === 0 &&
    !declaredTruncated
  );
  const invalidReason = !totalCountProvided
    ? 'MISSING_TOTAL_COUNT'
    : !totalCountValid
      ? 'INVALID_TOTAL_COUNT'
      : declaredTruncated
        ? 'TRUNCATED_LIST'
        : declaredTotalCount !== rawItems.length
          ? 'COUNT_MISMATCH'
          : invalidItemCount > 0
            ? 'INVALID_LIST_ITEMS'
            : duplicateKeyCount > 0
              ? 'DUPLICATE_LIST_ITEMS'
              : '';
  return {
    supported: true,
    valid: invalidReason === '',
    invalidReason,
    endpointStatus: invalidReason === '' ? 'OK' : 'INCOMPLETE',
    httpStatus: 200,
    format,
    items: validItems,
    rawItemCount: rawItems.length,
    invalidItemCount,
    duplicateKeyCount,
    totalCount: totalCountValid ? declaredTotalCount : validItems.length,
    declaredTotalCount,
    totalCountProvided,
    totalCountValid,
    countConsistent,
    truncated,
  };
}

// Strict parser exclusively for GET /api/scan-jobs (v2/api/jobs.py: {"total_count": N, "jobs": [...]}).
// Never accepts raw arrays, {items}, error payloads, or missing/inconsistent total_count.
export function parseScanJobsListResponse(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return invalidListResult('INVALID_LIST_PAYLOAD');
  }
  const hasCount = Object.hasOwn(data, 'total_count') && data.total_count !== undefined;
  if (data.error || data.error_code) {
    return invalidListResult('UPSTREAM_ERROR_PAYLOAD', {totalCountProvided: hasCount});
  }
  const rawItems = data.jobs;
  if (!Array.isArray(rawItems)) {
    return invalidListResult('MISSING_OR_INVALID_LIST_ARRAY', {totalCountProvided: hasCount});
  }
  return finalizeListObjectResult(data, rawItems, 'contract', validateJobListItem);
}

// Read-only history parser for GET /api/scans: accepts canonical {scans: [...]},
// legacy direct JSON array [...], and legacy {items: [...]}, while rejecting error/malformed payloads
// and validating each item so null/empty/corrupt records never cause TypeError or silent false-complete syncs.
export function parseHistoryListResponse(data, itemsKey = 'scans') {
  if (Array.isArray(data)) {
    const {validItems, invalidItemCount, duplicateKeyCount} = inspectListItems(data, validateScanListItem);
    const invalidReason = invalidItemCount > 0
      ? 'INVALID_LIST_ITEMS'
      : duplicateKeyCount > 0
        ? 'DUPLICATE_LIST_ITEMS'
        : '';
    return {
      supported: true,
      valid: invalidReason === '',
      invalidReason,
      endpointStatus: invalidReason === '' ? 'OK' : 'INCOMPLETE',
      httpStatus: 200,
      format: 'legacy_array',
      items: validItems,
      rawItemCount: data.length,
      invalidItemCount,
      duplicateKeyCount,
      totalCount: data.length,
      declaredTotalCount: null,
      totalCountProvided: false,
      totalCountValid: false,
      countConsistent: invalidReason === '',
      truncated: false,
    };
  }
  if (!data || typeof data !== 'object') {
    return invalidListResult('INVALID_LIST_PAYLOAD');
  }
  const hasCount = Object.hasOwn(data, 'total_count') && data.total_count !== undefined;
  if (data.error || data.error_code) {
    return invalidListResult('UPSTREAM_ERROR_PAYLOAD', {totalCountProvided: hasCount});
  }
  if (Array.isArray(data[itemsKey])) {
    return finalizeListObjectResult(data, data[itemsKey], 'contract', validateScanListItem);
  }
  if (Array.isArray(data.items)) {
    return finalizeListObjectResult(data, data.items, 'legacy_items', validateScanListItem);
  }
  return invalidListResult('MISSING_OR_INVALID_LIST_ARRAY', {totalCountProvided: hasCount});
}

export function parseListResponse(data, itemsKey) {
  return itemsKey === 'jobs'
    ? parseScanJobsListResponse(data)
    : parseHistoryListResponse(data, itemsKey);
}

async function listEndpoint(path, parser, options = {}) {
  try {
    const data = await request(path, {...options, timeoutMs: 15000});
    return parser(data);
  } catch (error) {
    if (error instanceof ApiError && [404, 405, 501].includes(error.status)) {
      return invalidListResult(`HTTP_${error.status}`, {
        endpointStatus: 'UNSUPPORTED',
        httpStatus: error.status,
      });
    }
    throw error;
  }
}

function buildFindingsQuery(params = {}) {
  const qs = new URLSearchParams();
  const page = params.page ?? 1;
  const pageSize = params.pageSize ?? params.page_size ?? 50;
  qs.set('page', String(page));
  qs.set('page_size', String(pageSize));
  if (params.cwe) qs.set('cwe', String(params.cwe));
  if (params.query) qs.set('query', String(params.query));
  if (params.file) qs.set('file', String(params.file));
  if (params.validatedStatus || params.validated_status) {
    qs.set('validated_status', String(params.validatedStatus || params.validated_status));
  }
  if (params.humanReviewState || params.human_review_state) {
    qs.set('human_review_state', String(params.humanReviewState || params.human_review_state));
  }
  if (params.includeConfirmedFalse !== undefined || params.include_confirmed_false !== undefined) {
    const include = params.includeConfirmedFalse ?? params.include_confirmed_false;
    qs.set('include_confirmed_false', include ? 'true' : 'false');
  }
  return qs.toString();
}

function nonNegativeIntOrNull(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

function isNonEmptyPageMarker(value) {
  return value !== undefined && value !== null && value !== false && value !== '';
}

async function allFindingsPages(scanId, params = {}, options = {}) {
  const {onProgress, ...rest} = options;
  const pageSize = 200;
  const items = [];
  const seenIds = new Set();
  let total = null;
  let totalMatching = null;
  let summaryMeta = null;
  let hasInvalidFindingsArray = false;
  let paginationInconsistent = false;
  let invalidItemsInPages = false;
  let expectedTotalPages = null;
  let expectedTarget = null;
  let reachedEndCleanly = false;

  for (let page = 1; page <= 100; page += 1) {
    const query = buildFindingsQuery({...params, page, pageSize});
    const response = await request(
      `/api/scans/${encodeURIComponent(scanId)}/findings?${query}`,
      {...rest, timeoutMs: 60000},
    );
    if (response?.scan_id !== scanId) {
      throw new ApiError('Phản hồi danh sách cảnh báo không khớp scan_id đã chọn.');
    }
    summaryMeta = response;
    if (!Array.isArray(response?.findings)) {
      hasInvalidFindingsArray = true;
      break;
    }
    const list = response.findings;
    for (let i = 0; i < list.length; i += 1) {
      const entry = list[i];
      if (!isPlainObject(entry)) {
        invalidItemsInPages = true;
        continue;
      }
      const rawId = entry.finding_id ?? entry.id;
      const fid = typeof rawId === 'string'
        ? rawId.trim()
        : typeof rawId === 'number' && Number.isFinite(rawId)
          ? String(rawId)
          : '';
      if (!fid || seenIds.has(fid)) {
        invalidItemsInPages = true;
      } else {
        seenIds.add(fid);
      }
    }
    items.push(...list);

    const matching = response.total_matching !== undefined && response.total_matching !== null
      ? nonNegativeIntOrNull(response.total_matching)
      : null;
    const countTotal = response.total_count !== undefined && response.total_count !== null
      ? nonNegativeIntOrNull(response.total_count)
      : null;
    if (
      (response.total_matching !== undefined && response.total_matching !== null && matching === null) ||
      (response.total_count !== undefined && response.total_count !== null && countTotal === null)
    ) {
      paginationInconsistent = true;
      break;
    }
    if (matching !== null) totalMatching = matching;
    if (countTotal !== null) total = countTotal;
    if (totalMatching !== null && total !== null && totalMatching > total) {
      paginationInconsistent = true;
      break;
    }

    const rawTotalPages = response.total_pages;
    const totalPages = rawTotalPages !== undefined && rawTotalPages !== null ? nonNegativeIntOrNull(rawTotalPages) : null;
    if (rawTotalPages !== undefined && rawTotalPages !== null && totalPages === null) {
      paginationInconsistent = true;
      break;
    }
    const rawRespPage = response.page;
    const respPage = rawRespPage !== undefined && rawRespPage !== null ? nonNegativeIntOrNull(rawRespPage) : null;
    if (rawRespPage !== undefined && rawRespPage !== null && (respPage === null || respPage < 1 || respPage !== page)) {
      paginationInconsistent = true;
      break;
    }
    const rawRespSize = response.page_size;
    const respSize = rawRespSize !== undefined && rawRespSize !== null ? nonNegativeIntOrNull(rawRespSize) : null;
    if (rawRespSize !== undefined && rawRespSize !== null && (respSize === null || respSize < 1)) {
      paginationInconsistent = true;
      break;
    }

    const pageTarget = totalMatching ?? total;
    if (expectedTarget === null && pageTarget !== null) {
      expectedTarget = pageTarget;
    } else if (expectedTarget !== null && pageTarget !== null && pageTarget !== expectedTarget) {
      paginationInconsistent = true;
      break;
    }
    if (expectedTotalPages === null && totalPages !== null) {
      expectedTotalPages = totalPages;
    } else if (expectedTotalPages !== null && totalPages !== null && totalPages !== expectedTotalPages) {
      paginationInconsistent = true;
      break;
    }

    const hasMoreFlag = response.has_more === true;
    const isTruncated = response.truncated === true;
    const hasNextPage = isNonEmptyPageMarker(response.next_page);
    const hasNextCursor = isNonEmptyPageMarker(response.next_cursor);
    const hasContinuation = hasMoreFlag || hasNextPage || hasNextCursor;

    let nextPageInvalid = false;
    if (hasNextPage) {
      const nextNum = typeof response.next_page === 'number'
        ? response.next_page
        : typeof response.next_page === 'string' && /^\d+$/.test(response.next_page.trim())
          ? Number(response.next_page.trim())
          : null;
      if (nextNum !== null && (nextNum <= page || (totalPages !== null && nextNum > totalPages))) {
        nextPageInvalid = true;
      }
    }

    const pageCountConflict = Boolean(
      isTruncated ||
      nextPageInvalid ||
      (pageTarget === 0 && ((totalPages !== null && totalPages > 1) || hasContinuation || list.length > 0)) ||
      (pageTarget !== null && pageTarget > 0 && (
        (totalPages !== null && (
          totalPages < 1 ||
          page > totalPages ||
          (respSize !== null && totalPages !== Math.ceil(pageTarget / respSize)) ||
          (page >= totalPages && hasContinuation) ||
          (page < totalPages && response.has_more === false) ||
          (page < totalPages && list.length === 0)
        )) ||
        (items.length > pageTarget) ||
        (totalPages === null && items.length >= pageTarget && hasContinuation)
      )),
    );

    if (pageCountConflict || invalidItemsInPages) {
      paginationInconsistent = paginationInconsistent || pageCountConflict;
      break;
    }
    if (onProgress) onProgress({loaded: items.length, total: pageTarget});
    if (!list.length) {
      reachedEndCleanly = pageTarget === 0 && !hasContinuation;
      break;
    }
    if ((totalPages !== null && totalPages >= 1) ? page >= totalPages : (totalMatching !== null && items.length >= totalMatching && !hasContinuation)) {
      reachedEndCleanly = true;
      break;
    }
  }

  const targetCount = totalMatching ?? total;
  return {
    items,
    total,
    totalMatching,
    meta: summaryMeta,
    hasFindingsArray: !hasInvalidFindingsArray,
    paginationInconsistent,
    invalidItemsInPages,
    complete: (
      !hasInvalidFindingsArray &&
      !paginationInconsistent &&
      !invalidItemsInPages &&
      reachedEndCleanly &&
      targetCount !== null &&
      items.length === targetCount
    ),
  };
}

export const api = {
  health: (options = {}) => request('/api/health', options),
  model: (options = {}) => request('/api/model', options),
  createZipJob: (file, options = {}, {noLlm = false} = {}) => {
    const body = new FormData();
    body.append('file', file, file.name);
    if (noLlm) body.append('no_llm', 'true');
    return request('/api/scan-jobs', {...options, method: 'POST', body, timeoutMs: 60000});
  },
  createScanJob: (repoUrl, commitSha, options = {}, {noLlm = false} = {}) => {
    const urlCheck = validateGithubRepoUrl(repoUrl);
    if (!urlCheck.valid) {
      return Promise.reject(new ApiError(`${urlCheck.error} [INVALID_GITHUB_URL]`, {
        status: 400,
        payload: {error_code: 'INVALID_GITHUB_URL', error_message: urlCheck.error},
      }));
    }
    const shaCheck = validateCommitSha(commitSha);
    if (!shaCheck.valid) {
      return Promise.reject(new ApiError(`${shaCheck.error} [INVALID_COMMIT_SHA]`, {
        status: 400,
        payload: {error_code: 'INVALID_COMMIT_SHA', error_message: shaCheck.error},
      }));
    }
    const body = {
      repo_url: urlCheck.canonicalUrl,
      ...(shaCheck.normalized ? {commit_sha: shaCheck.normalized} : {}),
      ...(noLlm ? {no_llm: true} : {}),
    };
    return request('/api/scan-jobs', {
      ...options,
      method: 'POST',
      timeoutMs: 30000,
      body: JSON.stringify(body),
    });
  },
  scanJob: (jobId, options = {}) => request(`/api/scan-jobs/${encodeURIComponent(jobId)}`, {
    ...options,
    timeoutMs: 15000,
  }),
  listScanJobs: (options = {}) => listEndpoint('/api/scan-jobs', parseScanJobsListResponse, options),
  listScans: (options = {}) => listEndpoint('/api/scans', (data) => parseHistoryListResponse(data, 'scans'), options),
  scan: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}`, options),
  scanSummary: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}`, {
    ...options,
    timeoutMs: 30000,
  }),
  findingsPage: (scanId, params = {}, options = {}) => {
    const query = buildFindingsQuery(params);
    return request(`/api/scans/${encodeURIComponent(scanId)}/findings?${query}`, {
      ...options,
      timeoutMs: 30000,
    });
  },
  allFindingsPages,
  findingDetail: (scanId, findingId, detailUrl, options = {}) => {
    const canonicalPath = `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`;
    const rawPath = `/api/scans/${scanId}/findings/${findingId}`;
    const safePath = typeof detailUrl === 'string' && (detailUrl === canonicalPath || detailUrl === rawPath)
      ? detailUrl
      : canonicalPath;
    return request(safePath, {...options, timeoutMs: 30000});
  },
  reviewQueue: (scanId, {includeAll = false} = {}, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/review-queue?include_all=${includeAll ? 'true' : 'false'}`,
    {...options, timeoutMs: 30000},
  ),
  findingHistory: (scanId, findingId, {includeRejected = true} = {}, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/history?include_rejected=${includeRejected ? 'true' : 'false'}`,
    {...options, timeoutMs: 30000},
  ),
  scanReviewHistory: (scanId, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/review-history`,
    {...options, timeoutMs: 30000},
  ),
  confirmTrue: (scanId, findingId, {actor, reason}, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/confirm-true`,
    {...options, method: 'POST', body: JSON.stringify({actor, reason}), timeoutMs: 30000},
  ),
  confirmFalse: (scanId, findingId, {actor, reason}, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/confirm-false`,
    {...options, method: 'POST', body: JSON.stringify({actor, reason}), timeoutMs: 30000},
  ),
  reopenFinding: (scanId, findingId, {actor, reason}, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/reopen`,
    {...options, method: 'POST', body: JSON.stringify({actor, reason}), timeoutMs: 30000},
  ),
  report: (scanId, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/report`,
    {...options, timeoutMs: 60000},
  ),
};

export async function checkBackend() {
  try {
    const status = await api.health();
    return {connected: status?.status === 'OK' || status?.status === 'DEGRADED', status};
  } catch (error) {
    return {connected: false, error: error.message};
  }
}
