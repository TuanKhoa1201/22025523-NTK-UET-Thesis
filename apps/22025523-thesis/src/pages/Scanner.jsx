import {useEffect, useRef, useState} from 'react';
import {Link, useOutletContext} from 'react-router-dom';
import {Badge, Card, PageHeader, Icon} from '../components/common/Ui';
import SecurityAnalysisScene from '../components/scanner/SecurityAnalysisScene';
import {CoveragePanel, FailureDetails, StageTiming} from '../components/scanner/JobPanels';
import {
  api,
  getApiOrigin,
  getAuthSessionScope,
  hasSessionToken,
  inputErrorMessage,
  validateCommitSha,
  validateGithubRepoUrl,
} from '../services/api';
import {NO_FINDINGS_NOTICE} from '../services/findingPresentation';
import {currentStageIndex, resolveStages} from '../services/jobModel';
import {
  clearStaleActiveScanId,
  isConfirmedScanNotFoundError,
  loadLiveScan,
  scanQuery,
} from '../services/liveScan';
import {readHistory, upsertHistory} from '../services/scanHistory';

const JOB_KEY = '22025523-active-job';
const TERMINAL_OR_IDLE_JOB_STATES = new Set(['IDLE', 'COMPLETED', 'FAILED', 'RESULTS_ERROR', 'NOT_FOUND']);

export {validateCommitSha, validateGithubRepoUrl};

function formatElapsed(ms) {
  const sec = Math.max(0, Number(ms) || 0) / 1000;
  if (sec < 60) return `${sec.toLocaleString('vi-VN', {minimumFractionDigits: 1, maximumFractionDigits: 1})} giây`;
  const m = Math.floor(sec / 60);
  const rem = Math.round(sec % 60);
  return `${m} phút ${rem} giây`;
}

export function formatFileSize(bytes) {
  const size = Number(bytes);
  if (!Number.isFinite(size) || size < 0) return '0 KB';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

export function isValidGithubRepoUrl(rawUrl) {
  return validateGithubRepoUrl(rawUrl).valid;
}

export function validateZipSelection(selectedFile, maxBytes) {
  if (!selectedFile) return {valid: false, error: ''};
  if (!/\.zip$/i.test(String(selectedFile.name || ''))) {
    return {valid: false, error: 'Chỉ hỗ trợ tệp định dạng .zip chứa mã nguồn Java.'};
  }
  if (typeof selectedFile.size === 'number' && selectedFile.size <= 0) {
    return {valid: false, error: 'Tệp ZIP rỗng. Vui lòng chọn tệp chứa mã nguồn Java.'};
  }
  const limit = Number(maxBytes) > 0 ? Number(maxBytes) : 25 * 1024 * 1024;
  if (typeof selectedFile.size === 'number' && selectedFile.size > limit) {
    return {
      valid: false,
      error: `Tệp ZIP vượt giới hạn ${Math.round(limit / 1024 / 1024)} MB [MAX_ZIP_UPLOAD_BYTES_EXCEEDED].`,
    };
  }
  return {valid: true, error: ''};
}

export async function validateZipSignature(selectedFile) {
  if (!selectedFile) return {valid: false, error: ''};
  if (typeof selectedFile.size === 'number' && selectedFile.size < 4) {
    return {
      valid: false,
      error: 'Tệp tải lên không phải định dạng ZIP hợp lệ (thiếu chữ ký đầu tệp PK) [INVALID_ZIP_ARCHIVE].',
    };
  }
  if (typeof selectedFile.slice !== 'function') {
    return {valid: true, error: ''};
  }
  try {
    const headSlice = selectedFile.slice(0, 4);
    let buffer;
    if (typeof headSlice.arrayBuffer === 'function') {
      buffer = await headSlice.arrayBuffer();
    } else if (typeof FileReader !== 'undefined') {
      buffer = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error || new Error('read failed'));
        reader.readAsArrayBuffer(headSlice);
      });
    } else {
      return {valid: true, error: ''};
    }
    const bytes = new Uint8Array(buffer);
    const isLocalFileHeader = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
    const isEmptyArchiveHeader = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x05 && bytes[3] === 0x06;
    if (!isLocalFileHeader && !isEmptyArchiveHeader) {
      return {
        valid: false,
        error: 'Tệp tải lên không phải định dạng ZIP hợp lệ (thiếu chữ ký đầu tệp PK) [INVALID_ZIP_ARCHIVE].',
      };
    }
    return {valid: true, error: ''};
  } catch {
    return {
      valid: false,
      error: 'Không thể đọc phần đầu tệp ZIP để kiểm tra định dạng [INVALID_ZIP_ARCHIVE].',
    };
  }
}

export function isJobBlockingNewScan(trackingState) {
  const normalized = String(trackingState || 'IDLE').toUpperCase();
  return !TERMINAL_OR_IDLE_JOB_STATES.has(normalized);
}

export function isJobDiscoveryBlocking({
  jobId = '',
  backendStatus = 'CHECKING',
  trackingState = 'IDLE',
  discoveryScope = '',
  jobDiscovery = null,
} = {}) {
  if (jobId) return false;
  if (isJobBlockingNewScan(trackingState)) return false;
  const status = String(backendStatus || 'CHECKING').toUpperCase();
  if (!['CONNECTED', 'DEGRADED'].includes(status)) return false;
  if (!jobDiscovery || typeof jobDiscovery !== 'object') return true;
  if (discoveryScope && jobDiscovery.scope !== discoveryScope) return true;
  return jobDiscovery.status !== 'DONE';
}

const KNOWN_JOB_STATES = new Set(['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED']);

export function validateScanJobsListResponse(res) {
  if (!res || typeof res !== 'object') {
    return {
      valid: false,
      reason: 'INVALID_RESPONSE',
      error: 'Phản hồi danh sách job từ API không hợp lệ. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
    };
  }
  if (!res.supported) {
    return {
      valid: false,
      reason: res.invalidReason || 'UNSUPPORTED_LIST_ENDPOINT',
      error: 'API / proxy không hỗ trợ hoặc trả phản hồi danh sách job không hợp lệ (/api/scan-jobs). Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
    };
  }
  if (res.valid === false || res.truncated === true || res.countConsistent === false) {
    return {
      valid: false,
      reason: res.invalidReason || 'INCONSISTENT_JOB_LIST',
      error: 'Danh sách job từ API thiếu trường bắt buộc, bị cắt bớt hoặc mâu thuẫn total_count. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
    };
  }
  if (!Array.isArray(res.items)) {
    return {
      valid: false,
      reason: 'MISSING_OR_INVALID_JOBS_ARRAY',
      error: 'Phản hồi danh sách job thiếu mảng jobs hợp lệ. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
    };
  }
  const declaredTotal = res.declaredTotalCount !== undefined ? res.declaredTotalCount : res.totalCount;
  if (
    typeof declaredTotal !== 'number' ||
    !Number.isInteger(declaredTotal) ||
    declaredTotal < 0 ||
    declaredTotal !== res.items.length
  ) {
    return {
      valid: false,
      reason: 'COUNT_MISMATCH',
      error: 'Số lượng job trong phản hồi không khớp total_count từ backend. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
    };
  }
  const seenIds = new Set();
  for (let i = 0; i < res.items.length; i += 1) {
    const item = res.items[i];
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return {
        valid: false,
        reason: 'INVALID_JOB_ITEM',
        error: 'Danh sách job chứa phần tử không hợp lệ. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
      };
    }
    const id = typeof item.job_id === 'string' ? item.job_id.trim() : '';
    const st = typeof item.state === 'string' ? item.state.trim().toUpperCase() : '';
    if (!id || !KNOWN_JOB_STATES.has(st)) {
      return {
        valid: false,
        reason: 'INVALID_JOB_ITEM_SCHEMA',
        error: 'Danh sách job chứa bản ghi thiếu job_id hoặc trạng thái không hợp lệ. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
      };
    }
    if (seenIds.has(id)) {
      return {
        valid: false,
        reason: 'DUPLICATE_JOB_ID',
        error: 'Danh sách job chứa mã job_id bị trùng lặp nên chưa đủ tin cậy. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
      };
    }
    seenIds.add(id);
    if (st === 'COMPLETED') {
      const scanId = typeof item.scan_id === 'string' ? item.scan_id.trim() : '';
      if (!scanId) {
        return {
          valid: false,
          reason: 'COMPLETED_JOB_MISSING_SCAN_ID',
          error: 'Danh sách job có bản ghi COMPLETED thiếu scan_id hợp lệ. Tạm khóa tạo lượt quét mới để tránh chạy trùng phiên.',
        };
      }
    }
  }
  return {valid: true, reason: '', error: ''};
}

export function classifyJobPollResponse(job, expectedJobId) {
  const expected = typeof expectedJobId === 'string' ? expectedJobId.trim() : '';
  const actual = typeof job?.job_id === 'string' ? job.job_id.trim() : '';
  if (!job || typeof job !== 'object' || !expected || !actual || actual !== expected) {
    return {
      kind: 'MISMATCH',
      trackingState: 'INTERRUPTED',
      clearStoredJob: false,
      retryPoll: true,
    };
  }
  const state = String(job.state || '').toUpperCase();
  if (state === 'QUEUED' || state === 'RUNNING') {
    return {
      kind: 'ACTIVE',
      state,
      trackingState: state,
      clearStoredJob: false,
      retryPoll: true,
    };
  }
  if (state === 'COMPLETED') {
    const scanId = typeof job.scan_id === 'string' ? job.scan_id.trim() : '';
    if (!scanId) {
      return {
        kind: 'MISMATCH',
        trackingState: 'INTERRUPTED',
        clearStoredJob: false,
        retryPoll: true,
      };
    }
    return {
      kind: 'COMPLETED',
      state,
      trackingState: 'LOADING_RESULTS',
      clearStoredJob: true,
      retryPoll: false,
    };
  }
  if (state === 'FAILED') {
    return {
      kind: 'FAILED',
      state,
      trackingState: 'FAILED',
      clearStoredJob: true,
      retryPoll: false,
    };
  }
  return {
    kind: 'UNKNOWN',
    state,
    trackingState: 'UNKNOWN',
    clearStoredJob: false,
    retryPoll: true,
  };
}

export function classifyJobPollError(failure) {
  const code = String(failure?.code || failure?.payload?.error_code || '').trim().toUpperCase();
  if (failure?.status === 404 && code === 'JOB_NOT_FOUND') {
    return {
      kind: 'NOT_FOUND',
      trackingState: 'NOT_FOUND',
      clearStoredJob: true,
      retryPoll: false,
    };
  }
  if (failure?.status === 404) {
    return {
      kind: 'PROXY_OR_ROUTE_BLOCKED',
      trackingState: 'INTERRUPTED',
      clearStoredJob: false,
      retryPoll: false,
    };
  }
  if (failure?.status === 401 || failure?.status === 403) {
    return {
      kind: 'AUTH_ERROR',
      trackingState: 'INTERRUPTED',
      clearStoredJob: false,
      retryPoll: false,
    };
  }
  return {
    kind: 'TRANSIENT',
    trackingState: 'INTERRUPTED',
    clearStoredJob: false,
    retryPoll: true,
  };
}

export function detectReadOnlyHealth(health) {
  if (!health || typeof health !== 'object') return false;
  if (health.read_only === true || health.readonly === true) return true;
  if (health.write_enabled === false || health.allow_write === false) return true;
  if (/read[_-]?only/i.test(String(health.proxy_mode || health.access_mode || health.mode || ''))) return true;
  if (Array.isArray(health.degraded_reasons)) {
    return health.degraded_reasons.some((reason) => /READ_ONLY|READONLY|WRITE_DISABLED/i.test(String(reason || '')));
  }
  return false;
}

export function isReadOnlyWriteError(failure) {
  if (!failure) return false;
  if (failure.status === 405 || failure.status === 501) return true;
  const code = String(failure.code || failure.payload?.error_code || '').toUpperCase();
  if (/READ_ONLY|READONLY|METHOD_NOT_ALLOWED|WRITE_DISABLED|WRITE_FORBIDDEN/.test(code)) return true;
  const msg = String(failure.message || '');
  return /read[- ]?only|chỉ đọc|method not allowed/i.test(msg);
}

const READ_ONLY_PROXY_NOTICE =
  'Hệ thống đang kết nối qua API / proxy chỉ đọc nên chưa thể tạo lượt quét mới. Để chạy phân tích mới, hãy chuyển sang địa chỉ API hỗ trợ ghi trong mục Cấu hình API / Token.';

export function evaluateWritePermission({backend, hasToken, readOnlyDetected = false} = {}) {
  const health = backend?.health || null;
  const status = String(backend?.status || 'CHECKING').toUpperCase();
  const degradedReasons = Array.isArray(health?.degraded_reasons) ? health.degraded_reasons : [];

  if (readOnlyDetected || detectReadOnlyHealth(health)) {
    return {allowed: false, kind: 'READ_ONLY_PROXY', message: READ_ONLY_PROXY_NOTICE};
  }
  if (status === 'CHECKING') {
    return {
      allowed: false,
      kind: 'CHECKING',
      message: 'Đang kiểm tra kết nối API. Vui lòng thử lại sau giây lát.',
    };
  }
  if (
    health?.write_auth_configured === false ||
    degradedReasons.some((reason) => String(reason || '').toUpperCase() === 'WRITE_AUTH_TOKEN_NOT_CONFIGURED')
  ) {
    return {
      allowed: false,
      kind: 'AUTH_TOKEN_NOT_CONFIGURED',
      message: 'Máy chủ API chưa cấu hình NTK_API_TOKEN nên thao tác tạo lượt quét mới đang bị khóa an toàn [AUTH_TOKEN_NOT_CONFIGURED].',
    };
  }
  if (status === 'AUTH_REQUIRED') {
    return {
      allowed: false,
      kind: 'MISSING_BEARER_TOKEN',
      message: hasToken
        ? 'Bearer Token phiên hiện tại không được API chấp nhận (HTTP 401) [UNAUTHORIZED]. Vui lòng cập nhật token hợp lệ trong mục Cấu hình API / Token.'
        : 'API yêu cầu Bearer Token phiên trước khi khởi tạo lượt phân tích mới [UNAUTHORIZED]. Vui lòng nhập token trong mục Cấu hình API / Token.',
    };
  }
  if (health?.write_auth_required === true && (!hasToken || health?.authenticated === false)) {
    return {
      allowed: false,
      kind: 'MISSING_BEARER_TOKEN',
      message: hasToken
        ? 'Bearer Token phiên hiện tại chưa được máy chủ xác thực quyền ghi [UNAUTHORIZED]. Vui lòng kiểm tra lại token trong mục Cấu hình API / Token.'
        : 'API yêu cầu Bearer Token phiên trước khi khởi tạo lượt phân tích mới [UNAUTHORIZED]. Vui lòng nhập token trong mục Cấu hình API / Token.',
    };
  }
  if (!['CONNECTED', 'DEGRADED'].includes(status)) {
    return {
      allowed: false,
      kind: 'API_UNREACHABLE',
      message: 'Chưa kết nối được tới máy chủ API. Kiểm tra cấu hình URL/Token ở thanh trên.',
    };
  }
  return {allowed: true, kind: 'ALLOWED', message: ''};
}

export async function runGuardedZipSubmission({
  file,
  getOrigin = getApiOrigin,
  getSession = getAuthSessionScope,
  getHasToken = hasSessionToken,
  getBackend = () => ({status: 'CHECKING', health: null}),
  getReadOnlyDetected = () => false,
  isCancelled = () => false,
  validateSignature = validateZipSignature,
  submitZip,
} = {}) {
  const initialOrigin = getOrigin();
  const initialSession = getSession();
  const initialPerm = evaluateWritePermission({
    backend: getBackend(),
    hasToken: getHasToken(),
    readOnlyDetected: getReadOnlyDetected(),
  });
  if (!initialPerm.allowed) {
    return {
      ok: false,
      aborted: false,
      kind: initialPerm.kind,
      error: initialPerm.message,
      origin: initialOrigin,
      sessionScope: initialSession,
    };
  }
  const sigCheck = await validateSignature(file);
  if (isCancelled() || getOrigin() !== initialOrigin || getSession() !== initialSession) {
    return {
      ok: false,
      aborted: true,
      kind: 'CONFIG_CHANGED',
      error: 'Cấu hình kết nối hoặc phiên xác thực API đã thay đổi trong lúc kiểm tra tệp ZIP. Đã hủy gửi yêu cầu cũ.',
      origin: initialOrigin,
      sessionScope: initialSession,
    };
  }
  const latestPerm = evaluateWritePermission({
    backend: getBackend(),
    hasToken: getHasToken(),
    readOnlyDetected: getReadOnlyDetected(),
  });
  if (!latestPerm.allowed) {
    return {
      ok: false,
      aborted: true,
      kind: latestPerm.kind,
      error: latestPerm.message,
      origin: initialOrigin,
      sessionScope: initialSession,
    };
  }
  if (!sigCheck.valid) {
    return {
      ok: false,
      aborted: false,
      kind: 'INVALID_ZIP_ARCHIVE',
      error: sigCheck.error,
      origin: initialOrigin,
      sessionScope: initialSession,
    };
  }
  if (typeof submitZip !== 'function') {
    return {
      ok: true,
      aborted: false,
      kind: 'READY',
      error: '',
      origin: initialOrigin,
      sessionScope: initialSession,
    };
  }
  const result = await submitZip({origin: initialOrigin, sessionScope: initialSession});
  if (isCancelled() || getOrigin() !== initialOrigin || getSession() !== initialSession) {
    return {
      ok: false,
      aborted: true,
      kind: 'CONFIG_CHANGED',
      error: 'Cấu hình kết nối hoặc phiên xác thực API đã thay đổi trong lúc gửi tệp ZIP.',
      origin: initialOrigin,
      sessionScope: initialSession,
    };
  }
  return {
    ok: true,
    aborted: false,
    kind: 'SUBMITTED',
    error: '',
    result,
    origin: initialOrigin,
    sessionScope: initialSession,
  };
}

function clearStoredJobIfMatch(targetJobId) {
  if (!targetJobId || typeof window === 'undefined' || !window.sessionStorage) return;
  try {
    if (window.sessionStorage.getItem(JOB_KEY) === targetJobId) {
      window.sessionStorage.removeItem(JOB_KEY);
      window.sessionStorage.removeItem(`${JOB_KEY}-started`);
    }
  } catch {
    /* optional sessionStorage cleanup */
  }
}

export default function Scanner() {
  const outlet = useOutletContext();
  const apiOrigin = outlet?.apiOrigin || getApiOrigin();
  const authSessionScope = outlet?.authSessionScope || getAuthSessionScope();
  const apiRevision = outlet?.apiRevision ?? 0;
  const backend = outlet?.backend ?? {status: 'CHECKING', health: null};
  const [tab, setTab] = useState('github');
  const [url, setUrl] = useState('');
  const [urlTouched, setUrlTouched] = useState(false);
  const [commitSha, setCommitSha] = useState('');
  const [noLlm, setNoLlm] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [pipelineOpen, setPipelineOpen] = useState(true);
  const [file, setFile] = useState(null);
  const [zipSigStatus, setZipSigStatus] = useState('idle');
  const [isDragging, setIsDragging] = useState(false);
  const [readOnlyDetected, setReadOnlyDetected] = useState(false);
  const [error, setError] = useState('');
  const [elapsedMs, setElapsedMs] = useState(0);
  const [jobId, setJobId] = useState(() => (
    typeof window !== 'undefined' && window.sessionStorage ? window.sessionStorage.getItem(JOB_KEY) || '' : ''
  ));
  const [jobTrackingState, setJobTrackingState] = useState(() => (
    typeof window !== 'undefined' && window.sessionStorage?.getItem(JOB_KEY) ? 'VERIFYING' : 'IDLE'
  ));
  const [liveStatus, setLiveStatus] = useState(() => (
    typeof window !== 'undefined' && window.sessionStorage?.getItem(JOB_KEY)
      ? 'Đang xác minh trạng thái phiên phân tích đang theo dõi từ máy chủ API…'
      : ''
  ));
  const [liveStage, setLiveStage] = useState(() => (
    typeof window !== 'undefined' && window.sessionStorage?.getItem(JOB_KEY) ? 'VERIFYING' : 'IDLE'
  ));
  const [backendMs, setBackendMs] = useState(null);
  const [liveScanId, setLiveScanId] = useState('');
  const [liveCounts, setLiveCounts] = useState(null);
  const [liveJob, setLiveJob] = useState(null);
  const [interrupted, setInterrupted] = useState(false);
  const discoveryScope = `${authSessionScope}|${apiOrigin}|${apiRevision}`;
  const [jobDiscovery, setJobDiscovery] = useState({scope: '', status: 'PENDING', error: ''});

  const busy = isJobBlockingNewScan(jobTrackingState);
  const discoveryBlocking = isJobDiscoveryBlocking({
    jobId,
    backendStatus: backend.status,
    trackingState: jobTrackingState,
    discoveryScope,
    jobDiscovery,
  });

  const timerRef = useRef(null);
  const startRef = useRef(
    typeof window !== 'undefined' && window.sessionStorage
      ? Number(window.sessionStorage.getItem(`${JOB_KEY}-started`)) || 0
      : 0,
  );
  const requestRef = useRef(null);
  const pendingRef = useRef(false);
  const zipCheckSeqRef = useRef(0);
  const submitSeqRef = useRef(0);
  const mountEpochRef = useRef(0);
  const isMountedRef = useRef(false);
  const backendRef = useRef(backend);
  backendRef.current = backend;
  const readOnlyRef = useRef(readOnlyDetected);
  readOnlyRef.current = readOnlyDetected;
  const inputRef = useRef(null);
  const statusSectionRef = useRef(null);
  const mountedSessionRef = useRef(authSessionScope);

  useEffect(() => {
    if (mountedSessionRef.current === authSessionScope) return;
    mountedSessionRef.current = authSessionScope;
    submitSeqRef.current += 1;
    zipCheckSeqRef.current += 1;
    window.clearInterval(timerRef.current);
    timerRef.current = null;
    startRef.current = 0;
    requestRef.current?.abort();
    requestRef.current = null;
    pendingRef.current = false;
    setError('');
    setReadOnlyDetected(false);
    setInterrupted(false);
    setJobId('');
    setJobTrackingState('IDLE');
    setJobDiscovery({scope: '', status: 'PENDING', error: ''});
    setLiveJob(null);
    setLiveScanId('');
    setLiveCounts(null);
    setLiveStage('IDLE');
    setLiveStatus('');
    setBackendMs(null);
    setElapsedMs(0);
  }, [authSessionScope]);

  useEffect(() => {
    setReadOnlyDetected(false);
  }, [apiOrigin]);

  // React StrictMode-safe mount lifecycle: each mount gets a fresh epoch so replay restores
  // mounted state while permanently invalidating async callbacks from any cancelled mount.
  useEffect(() => {
    const epoch = mountEpochRef.current + 1;
    mountEpochRef.current = epoch;
    isMountedRef.current = true;
    return () => {
      if (mountEpochRef.current === epoch) {
        isMountedRef.current = false;
      }
      submitSeqRef.current += 1;
      zipCheckSeqRef.current += 1;
      window.clearInterval(timerRef.current);
      timerRef.current = null;
      requestRef.current?.abort();
      requestRef.current = null;
      pendingRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (!jobId || !startRef.current || timerRef.current) return;
    setElapsedMs(Math.max(0, Date.now() - startRef.current));
    timerRef.current = window.setInterval(() => {
      setElapsedMs(Math.max(0, Date.now() - startRef.current));
    }, 250);
  }, [jobId]);

  const scrollToStatus = () => {
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => statusSectionRef.current?.scrollIntoView?.({behavior: 'smooth', block: 'nearest'}));
    }
  };

  // Poll and verify active/restored jobId. Never unlock scan creation or clear JOB_KEY until API
  // confirms terminal state (COMPLETED / FAILED) or explicit 404 (job no longer exists).
  useEffect(() => {
    if (!jobId) return undefined;
    const controller = new AbortController();
    const jobOrigin = getApiOrigin();
    const jobSession = getAuthSessionScope();
    let stopped = false;
    let pollTimer;
    const isStale = () => stopped || getApiOrigin() !== jobOrigin || getAuthSessionScope() !== jobSession;

    setJobTrackingState((prev) => (prev === 'QUEUED' || prev === 'RUNNING' ? prev : 'VERIFYING'));

    const poll = async () => {
      try {
        const job = await api.scanJob(jobId, {signal: controller.signal});
        if (isStale()) return;
        const outcome = classifyJobPollResponse(job, jobId);
        if (outcome.kind === 'MISMATCH') {
          setInterrupted(true);
          setJobTrackingState(outcome.trackingState);
          setLiveStatus('Phản hồi trạng thái job không khớp mã tác vụ hoặc thiếu định danh bắt buộc. Đang kiểm tra lại…');
          pollTimer = window.setTimeout(poll, 1500);
          return;
        }
        setInterrupted(false);
        setLiveJob(job);
        const state = outcome.state;
        if (state && state !== 'COMPLETED') setLiveStage(state);
        if (job?.scan_id) {
          window.sessionStorage.setItem('22025523-scan-id', job.scan_id);
          setLiveScanId(job.scan_id);
        }
        if (outcome.kind === 'ACTIVE') {
          if (!startRef.current) {
            const parsedStart = Date.parse(job.started_at || job.created_at || '');
            startRef.current = Number.isFinite(parsedStart) && parsedStart > 0 ? parsedStart : Date.now();
            window.sessionStorage.setItem(`${JOB_KEY}-started`, String(startRef.current));
          }
          if (!timerRef.current) {
            setElapsedMs(Math.max(0, Date.now() - startRef.current));
            timerRef.current = window.setInterval(() => {
              setElapsedMs(Math.max(0, Date.now() - startRef.current));
            }, 250);
          }
          setJobTrackingState(outcome.trackingState);
          setLiveStage(state);
          setLiveStatus(
            state === 'QUEUED'
              ? 'Phiên quét đang chờ trong hàng đợi máy chủ API…'
              : `Đang phân tích trên máy chủ · Giai đoạn ${job.active_stage || '?'}/6`,
          );
          pollTimer = window.setTimeout(poll, 750);
          return;
        }
        if (outcome.kind === 'COMPLETED') {
          setJobTrackingState(outcome.trackingState);
          setLiveStage('LOADING_RESULTS');
          setLiveStatus('API đã hoàn tất 6 giai đoạn. Đang đọc kết quả từ SQLite…');
          if (outcome.clearStoredJob) clearStoredJobIfMatch(jobId);
          if (!job.scan_id) {
            window.clearInterval(timerRef.current);
            timerRef.current = null;
            setLiveStage('RESULTS_ERROR');
            setJobTrackingState('RESULTS_ERROR');
            setLiveStatus('Job kết thúc nhưng thiếu mã phiên (scan_id).');
            setError('API báo COMPLETED nhưng không trả về scan_id hợp lệ.');
            return;
          }
          try {
            const data = await loadLiveScan(job.scan_id, controller.signal);
            if (isStale()) return;
            if (data.incomplete || !Number.isInteger(data.counts?.total)) {
              throw new Error('Phản hồi kết quả quét thiếu danh sách findings hoặc tổng số cảnh báo hợp lệ.');
            }
            const total = data.scan?.total_e2e_duration_ms ?? job.total_e2e_duration_ms;
            setBackendMs(typeof total === 'number' && Number.isFinite(total) ? total : null);
            setLiveCounts(data.counts);
            window.clearInterval(timerRef.current);
            timerRef.current = null;
            if (startRef.current) setElapsedMs(Math.max(0, Date.now() - startRef.current));
            else if (typeof total === 'number' && Number.isFinite(total)) setElapsedMs(total);
            setLiveStage('COMPLETED');
            setJobTrackingState('COMPLETED');
            setLiveStatus(
              data.counts.confirmedNoFindings === true && data.counts.total === 0
                ? 'Phân tích hoàn tất: 0 cảnh báo trong phạm vi tập luật hiện tại (NO_FINDINGS).'
                : `Phân tích hoàn tất (${data.counts.total} cảnh báo). Sẵn sàng đối chiếu bằng chứng và kiểm duyệt.`,
            );
          } catch (failure) {
            if (isStale() || controller.signal.aborted || failure?.abortedByConfigChange) return;
            window.clearInterval(timerRef.current);
            timerRef.current = null;
            setLiveStage('RESULTS_ERROR');
            setJobTrackingState('RESULTS_ERROR');
            setLiveStatus('Job đã hoàn tất nhưng chưa tải được kết quả chi tiết.');
            setError(`Không thể tải kết quả phiên ${job.scan_id}: ${failure.message}`);
          }
          return;
        }
        if (outcome.kind === 'FAILED') {
          if (outcome.clearStoredJob) clearStoredJobIfMatch(jobId);
          window.clearInterval(timerRef.current);
          timerRef.current = null;
          if (startRef.current) setElapsedMs(Math.max(0, Date.now() - startRef.current));
          setLiveStage('FAILED');
          setJobTrackingState(outcome.trackingState);
          setLiveStatus('Phiên phân tích thất bại.');
          setError(inputErrorMessage(job));
          if (job.scan_id) upsertHistory({scanId: job.scan_id, jobId: job.job_id, status: 'FAILED'}, {origin: jobOrigin, sessionScope: jobSession});
          return;
        }
        setJobTrackingState(outcome.trackingState);
        setLiveStatus('Đang chờ trạng thái hợp lệ từ máy chủ API…');
        pollTimer = window.setTimeout(poll, 1500);
      } catch (failure) {
        if (isStale() || controller.signal.aborted || failure?.abortedByConfigChange) return;
        const errOutcome = classifyJobPollError(failure);
        if (errOutcome.kind === 'NOT_FOUND') {
          if (errOutcome.clearStoredJob) clearStoredJobIfMatch(jobId);
          window.clearInterval(timerRef.current);
          timerRef.current = null;
          startRef.current = 0;
          setInterrupted(false);
          setLiveJob(null);
          setJobId('');
          setLiveStage('IDLE');
          setJobTrackingState(errOutcome.trackingState);
          setLiveStatus('Phiên phân tích trước đó không còn tồn tại trên máy chủ API (HTTP 404). Bạn có thể tạo phiên phân tích mới.');
          return;
        }
        setInterrupted(true);
        setJobTrackingState(errOutcome.trackingState);
        if (!errOutcome.retryPoll) {
          setLiveStatus(
            errOutcome.kind === 'PROXY_OR_ROUTE_BLOCKED'
              ? 'Endpoint kiểm tra trạng thái job bị từ chối hoặc chưa khả dụng (HTTP 404). Hệ thống giữ khóa tác vụ cũ để tránh tạo trùng phiên phân tích.'
              : `Không thể xác minh trạng thái phiên phân tích đang theo dõi: ${failure.message}`,
          );
          return;
        }
        setLiveStatus(`Mất kết nối tạm thời khi theo dõi tiến trình: ${failure.message}`);
        pollTimer = window.setTimeout(poll, 1500);
      }
    };

    poll();
    return () => {
      stopped = true;
      window.clearTimeout(pollTimer);
      controller.abort();
    };
  }, [jobId]);

  // Discover an already QUEUED/RUNNING job on the backend when returning without JOB_KEY in sessionStorage.
  // Keep scan creation locked until backend explicitly confirms no active job is running.
  useEffect(() => {
    if (jobId || busy || pendingRef.current) return undefined;
    if (!['CONNECTED', 'DEGRADED'].includes(backend.status)) return undefined;
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    let retryTimer;
    const isStale = () => (
      !active ||
      controller.signal.aborted ||
      pendingRef.current ||
      getApiOrigin() !== requestOrigin ||
      getAuthSessionScope() !== requestSession
    );

    const checkActiveJobs = () => {
      if (isStale()) return;
      setJobDiscovery({scope: discoveryScope, status: 'CHECKING', error: ''});
      api.listScanJobs({signal: controller.signal})
        .then((res) => {
          if (isStale()) return;
          const validation = validateScanJobsListResponse(res);
          if (!validation.valid) {
            setJobDiscovery({
              scope: discoveryScope,
              status: 'ERROR',
              error: validation.error,
            });
            return;
          }
          const activeJob = res.items.find((item) => {
            const st = String(item.state || '').trim().toUpperCase();
            return st === 'QUEUED' || st === 'RUNNING';
          });
          if (!activeJob) {
            setJobDiscovery({scope: discoveryScope, status: 'DONE', error: ''});
            return;
          }
          const activeJobId = activeJob.job_id.trim();
          const activeState = String(activeJob.state).trim().toUpperCase();
          const startedAtMs = Date.parse(activeJob.started_at || activeJob.created_at || '');
          if (Number.isFinite(startedAtMs) && startedAtMs > 0) {
            startRef.current = startedAtMs;
            window.sessionStorage.setItem(`${JOB_KEY}-started`, String(startedAtMs));
          }
          window.sessionStorage.setItem(JOB_KEY, activeJobId);
          setJobDiscovery({scope: discoveryScope, status: 'DONE', error: ''});
          setLiveJob(activeJob);
          setLiveStage(activeState);
          setJobTrackingState(activeState);
          setJobId(activeJobId);
        })
        .catch((failure) => {
          if (isStale() || failure?.abortedByConfigChange) return;
          setJobDiscovery({
            scope: discoveryScope,
            status: 'ERROR',
            error: `Không thể xác minh danh sách job đang chạy: ${failure?.message || 'Lỗi kết nối API'}. Đang thử lại…`,
          });
          if (![401, 403, 404, 405].includes(failure?.status)) {
            retryTimer = window.setTimeout(checkActiveJobs, 2000);
          }
        });
    };

    checkActiveJobs();

    return () => {
      active = false;
      window.clearTimeout(retryTimer);
      controller.abort();
    };
  }, [jobId, busy, backend.status, discoveryScope]);

  useEffect(() => {
    if (jobId || busy || pendingRef.current || jobTrackingState === 'FAILED' || liveStage === 'FAILED') return undefined;
    const scanId = window.sessionStorage.getItem('22025523-scan-id');
    if (!scanId) return undefined;
    const controller = new AbortController();
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || controller.signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    setLiveScanId(scanId);
    loadLiveScan(scanId, controller.signal)
      .then((data) => {
        if (isStale()) return;
        setLiveCounts(data.counts);
        setLiveStage('COMPLETED');
        const total = data.scan?.total_e2e_duration_ms;
        setBackendMs(typeof total === 'number' && Number.isFinite(total) ? total : null);
        if (typeof total === 'number' && Number.isFinite(total)) setElapsedMs(total);
        const persistedJobId = data.scan?.job_id;
        if (persistedJobId) {
          api.scanJob(persistedJobId, {signal: controller.signal})
            .then((jobDoc) => {
              if (!isStale() && jobDoc && typeof jobDoc === 'object') {
                setLiveJob(jobDoc);
              }
            })
            .catch(() => {});
        }
      })
      .catch((failure) => {
        if (isStale() || failure?.abortedByConfigChange) return;
        if (isConfirmedScanNotFoundError(failure)) {
          clearStaleActiveScanId(scanId, requestSession);
          setLiveScanId('');
          return;
        }
        setError(failure.message);
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [jobId, busy, jobTrackingState, liveStage, apiOrigin, authSessionScope]);

  const uploadLimit = backend.health?.source_inventory_limits?.max_zip_upload_bytes ?? 25 * 1024 * 1024;
  const maxZipMb = Math.max(1, Math.round(uploadLimit / 1024 / 1024));
  const writePerm = evaluateWritePermission({
    backend,
    hasToken: hasSessionToken(),
    readOnlyDetected,
  });
  const isReadOnlyProxy = writePerm.kind === 'READ_ONLY_PROXY';
  const showWriteAuthWarning = writePerm.kind === 'MISSING_BEARER_TOKEN' || writePerm.kind === 'AUTH_TOKEN_NOT_CONFIGURED';
  const trimmedUrl = url.trim();
  const githubCheck = validateGithubRepoUrl(trimmedUrl);
  const githubUrlValid = githubCheck.valid;
  const githubPrefixMismatch =
    Boolean(trimmedUrl) &&
    !trimmedUrl.toLowerCase().startsWith('https://github.com/'.slice(0, Math.min(trimmedUrl.length, 19)));
  const githubInlineError =
    tab === 'github' && trimmedUrl && !githubUrlValid && (urlTouched || githubPrefixMismatch)
      ? githubCheck.error
      : '';
  const commitShaCheck = validateCommitSha(commitSha);
  const commitShaInlineError =
    tab === 'github' && commitSha.trim() && !commitShaCheck.valid
      ? commitShaCheck.error
      : '';
  const zipValidation = validateZipSelection(file, uploadLimit);
  const zipReady = zipValidation.valid && zipSigStatus === 'valid';
  const hasValidSource = tab === 'github' ? (githubUrlValid && commitShaCheck.valid) : zipReady;
  const canSubmit = !busy && !discoveryBlocking && writePerm.allowed && hasValidSource;
  const activeError = error || (tab === 'zip' ? zipValidation.error : (!advancedOpen ? commitShaInlineError : ''));
  const advancedSummaryTag = [
    noLlm ? 'Chỉ OpenGrep' : '',
    tab === 'github' && commitSha.trim() ? 'Có Commit SHA' : '',
  ].filter(Boolean).join(' · ');

  const handleTabSwitch = (nextTab) => {
    if (nextTab === tab) return;
    setTab(nextTab);
    setError('');
    setIsDragging(false);
  };

  const applySelectedFile = (candidate) => {
    if (!candidate) return;
    const seq = zipCheckSeqRef.current + 1;
    zipCheckSeqRef.current = seq;
    const checkEpoch = mountEpochRef.current;
    const checkOrigin = getApiOrigin();
    const checkSession = getAuthSessionScope();
    const check = validateZipSelection(candidate, uploadLimit);
    if (!check.valid) {
      setFile(null);
      setZipSigStatus('invalid');
      setError(check.error);
      return;
    }
    setFile(candidate);
    setZipSigStatus('checking');
    setError('');
    validateZipSignature(candidate).then((sigCheck) => {
      if (
        !isMountedRef.current ||
        mountEpochRef.current !== checkEpoch ||
        zipCheckSeqRef.current !== seq ||
        getApiOrigin() !== checkOrigin ||
        getAuthSessionScope() !== checkSession
      ) {
        return;
      }
      if (!sigCheck.valid) {
        setFile(null);
        setZipSigStatus('invalid');
        setError(sigCheck.error);
        return;
      }
      setZipSigStatus('valid');
      setError('');
    });
  };

  const handleFileInputChange = (event) => {
    const selected = event.target.files?.[0] || null;
    event.target.value = '';
    if (selected) applySelectedFile(selected);
  };

  const handleClearFile = () => {
    zipCheckSeqRef.current += 1;
    setFile(null);
    setZipSigStatus('idle');
    setError('');
    if (inputRef.current) inputRef.current.value = '';
  };

  const startLive = async () => {
    if (pendingRef.current || busy || discoveryBlocking) {
      setError(
        discoveryBlocking
          ? (jobDiscovery.error || 'Đang kiểm tra danh sách job đang chạy trên API. Vui lòng chờ xác minh hoàn tất trước khi tạo lượt quét mới.')
          : 'Đang có phiên phân tích hoạt động hoặc đang xác minh trạng thái job trước đó. Vui lòng chờ hoàn tất trước khi tạo lượt quét mới.',
      );
      return;
    }
    setError('');
    if (!writePerm.allowed) {
      setError(writePerm.message);
      setLiveStatus(writePerm.message);
      if (writePerm.kind === 'MISSING_BEARER_TOKEN') {
        outlet?.openConnectionPanel?.();
      }
      return;
    }
    if (tab === 'zip') {
      if (!file) {
        setError('Vui lòng chọn tệp .zip chứa mã nguồn Java.');
        return;
      }
      const check = validateZipSelection(file, uploadLimit);
      if (!check.valid) {
        setError(check.error);
        return;
      }
    }
    if (tab === 'github') {
      if (!githubCheck.valid) {
        setUrlTouched(true);
        setError(githubCheck.error || 'Nhập URL repository GitHub hợp lệ (ví dụ: https://github.com/owner/repo).');
        return;
      }
      if (!commitShaCheck.valid) {
        setAdvancedOpen(true);
        setError(commitShaCheck.error);
        return;
      }
    }

    const submitEpoch = mountEpochRef.current;
    const submitSeq = submitSeqRef.current + 1;
    submitSeqRef.current = submitSeq;
    pendingRef.current = true;
    const isSubmitCancelled = () => (
      !isMountedRef.current ||
      mountEpochRef.current !== submitEpoch ||
      submitSeqRef.current !== submitSeq
    );

    const controller = new AbortController();
    requestRef.current = controller;
    let requestOrigin = getApiOrigin();
    let requestSession = getAuthSessionScope();
    const startedAt = new Date().toISOString();

    const beginSubmissionUi = () => {
      setJobTrackingState('SUBMITTING');
      setPipelineOpen(true);
      setLiveJob(null);
      setJobId('');
      setLiveCounts(null);
      setLiveScanId('');
      setLiveStatus('Đang gửi yêu cầu phân tích tới máy chủ API…');
      setLiveStage('SUBMITTING');
      setBackendMs(null);
      setElapsedMs(0);
      startRef.current = Date.now();
      window.clearInterval(timerRef.current);
      timerRef.current = window.setInterval(() => setElapsedMs(Date.now() - startRef.current), 250);
      scrollToStatus();
    };

    try {
      let result;
      if (tab === 'zip') {
        const zipOutcome = await runGuardedZipSubmission({
          file,
          getOrigin: getApiOrigin,
          getSession: getAuthSessionScope,
          getHasToken: hasSessionToken,
          getBackend: () => backendRef.current,
          getReadOnlyDetected: () => readOnlyRef.current,
          isCancelled: isSubmitCancelled,
          submitZip: async ({origin, sessionScope}) => {
            requestOrigin = origin;
            requestSession = sessionScope;
            setZipSigStatus('valid');
            beginSubmissionUi();
            setLiveStage('WAITING_FOR_RESPONSE');
            setJobTrackingState('WAITING_FOR_RESPONSE');
            return api.createZipJob(file, {signal: controller.signal}, {noLlm});
          },
        });
        if (!zipOutcome.ok) {
          if (zipOutcome.aborted) {
            if (!isSubmitCancelled()) {
              setError(zipOutcome.error);
              setLiveStatus(zipOutcome.error);
              if (zipOutcome.kind === 'MISSING_BEARER_TOKEN') {
                outlet?.openConnectionPanel?.();
              }
            }
            return;
          }
          if (zipOutcome.kind === 'INVALID_ZIP_ARCHIVE') {
            setFile(null);
            setZipSigStatus('invalid');
          }
          setError(zipOutcome.error);
          if (zipOutcome.kind !== 'INVALID_ZIP_ARCHIVE') {
            setLiveStatus(zipOutcome.error);
            if (zipOutcome.kind === 'MISSING_BEARER_TOKEN') {
              outlet?.openConnectionPanel?.();
            }
          }
          return;
        }
        result = zipOutcome.result;
      } else {
        beginSubmissionUi();
        setLiveStage('WAITING_FOR_RESPONSE');
        setJobTrackingState('WAITING_FOR_RESPONSE');
        result = await api.createScanJob(trimmedUrl, commitShaCheck.normalized, {signal: controller.signal}, {noLlm});
      }

      const acceptedJobId = typeof result?.job_id === 'string' ? result.job_id.trim() : '';
      if (!acceptedJobId) {
        throw new Error('API không trả về job_id hợp lệ.');
      }
      if (isSubmitCancelled() || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession) return;
      const acceptedState = String(result.state || 'QUEUED').toUpperCase();
      window.sessionStorage.setItem(JOB_KEY, acceptedJobId);
      window.sessionStorage.setItem(`${JOB_KEY}-started`, String(startRef.current));
      if (result.scan_id) {
        window.sessionStorage.setItem('22025523-scan-id', result.scan_id);
        setLiveScanId(result.scan_id);
        // User-entered source is stored only as browser cache for THIS auth session; never shown as API data.
        upsertHistory({
          scanId: result.scan_id,
          jobId: acceptedJobId,
          repoUrl: tab === 'github' ? (result.repo_url || trimmedUrl) : undefined,
          fileName: tab === 'zip' ? file.name : undefined,
          inputMode: tab === 'zip' ? 'ZIP' : 'GITHUB',
          startedAt,
          status: acceptedState,
        }, {origin: requestOrigin, sessionScope: requestSession});
      }
      setJobTrackingState(acceptedState);
      setJobId(acceptedJobId);
      setLiveJob(result);
      setLiveStage(acceptedState);
      setLiveStatus('Đã tiếp nhận job phân tích trên API.');
    } catch (failure) {
      if (!isSubmitCancelled() && !controller.signal.aborted && !failure?.abortedByConfigChange) {
        if (isReadOnlyWriteError(failure)) {
          setReadOnlyDetected(true);
          setError(READ_ONLY_PROXY_NOTICE);
          setLiveStatus('API / proxy hiện tại chỉ cho phép đọc nên chưa thể tạo lượt quét mới.');
        } else {
          setError(failure.message || 'Không thể khởi tạo phiên phân tích trên API.');
          setLiveStatus('Khởi tạo phiên phân tích thất bại.');
        }
        setLiveStage('FAILED');
        setJobTrackingState('FAILED');
        window.clearInterval(timerRef.current);
        timerRef.current = null;
        if (failure.status === 401) outlet?.openConnectionPanel?.();
      }
    } finally {
      if (submitSeqRef.current === submitSeq) {
        pendingRef.current = false;
        requestRef.current = null;
      }
    }
  };

  const discoveryErrorActive = discoveryBlocking && jobDiscovery.scope === discoveryScope && jobDiscovery.status === 'ERROR';

  const statusMessage = liveStatus || (discoveryBlocking
    ? (discoveryErrorActive
      ? jobDiscovery.error
      : 'Đang kiểm tra xem có phiên phân tích nào đang chạy trên máy chủ API…')
    : liveStage === 'COMPLETED'
      ? 'Đã tải kết quả phiên quét gần nhất từ API.'
      : ({
          CHECKING: 'Đang kiểm tra kết nối tới máy chủ API…',
          CONNECTED: 'API sẵn sàng tiếp nhận dự án Java để phân tích.',
          DEGRADED: 'API đã kết nối (xem Trạng thái hệ thống để đối chiếu chi tiết health check).',
          AUTH_REQUIRED: 'Vui lòng nhập Bearer Token phiên ở thanh trên trước khi chạy phân tích.',
          ERROR: 'Chưa kết nối được máy chủ API. Kiểm tra địa chỉ API ở thanh trên.',
        }[backend.status] || 'Chưa có phiên phân tích đang chạy.'));

  const statusChip = liveStage === 'COMPLETED' ? {label: 'Hoàn tất', tone: 'green'}
    : liveStage === 'FAILED' || liveStage === 'RESULTS_ERROR' ? {label: 'Thất bại', tone: 'red'}
      : jobTrackingState === 'INTERRUPTED' ? {label: 'Mất kết nối tạm thời', tone: 'amber'}
        : jobTrackingState === 'VERIFYING' ? {label: 'Đang xác minh', tone: 'blue'}
          : discoveryBlocking
            ? (discoveryErrorActive ? {label: 'Chưa xác minh job', tone: 'amber'} : {label: 'Đang kiểm tra', tone: 'blue'})
            : liveStage === 'QUEUED' ? {label: 'Đang xếp hàng', tone: 'amber'}
              : busy || ['RUNNING', 'SUBMITTING', 'WAITING_FOR_RESPONSE', 'LOADING_RESULTS'].includes(liveStage)
                ? {label: 'Đang phân tích', tone: 'blue'}
                : {label: 'Sẵn sàng', tone: 'neutral'};

  const resolvedStages = resolveStages(liveJob);
  const completedStagesCount = resolvedStages.filter((s) => s.cat === 'COMPLETED' || s.cat === 'SKIPPED').length;
  const stageIndex = currentStageIndex(liveJob);
  const activeStage = stageIndex === null ? null : stageIndex + 1;
  const jobFailed = String(liveJob?.state || '').toUpperCase() === 'FAILED';
  const progressPct = liveStage === 'COMPLETED'
    ? 100
    : liveJob
      ? Math.min(96, Math.max(8, Math.round((completedStagesCount / 6) * 100)))
      : busy ? 10 : 0;

  const latest = readHistory(apiOrigin, {sessionScope: authSessionScope}).find((record) => record.status === 'COMPLETED');
  const resultId = liveScanId || latest?.scanId || '';
  const processed = liveJob?.progress?.processed_findings;
  const totalFindings = liveJob?.progress?.total_findings;

  return (
    <>
      <PageHeader
        eyebrow="PHÂN TÍCH MÃ NGUỒN"
        title="Phân tích dự án Java"
        description="Nhập liên kết GitHub công khai hoặc tải tệp ZIP để chạy OpenGrep, suy luận Qwen3.5-9B cục bộ qua Ollama, kiểm chứng trích dẫn SHA-256 và đưa vào hàng đợi Human Review."
      />

      <div className="v2-scanner-grid">
        <div>
          <Card className="scanner-input-card v2-intake-card">
            <form
              className="v2-intake-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (canSubmit) startLive();
              }}
              noValidate
            >
              {/* Bước 1: Chọn nguồn mã */}
              <div className="v2-intake-tabs-row">
                <div className="v2-tab-switcher v2-tab-switcher--balanced" role="tablist" aria-label="Chọn nguồn mã Java">
                  <button
                    type="button"
                    role="tab"
                    id="scan-tab-github"
                    aria-selected={tab === 'github'}
                    aria-controls="scan-panel-source"
                    className={tab === 'github' ? 'active' : ''}
                    disabled={busy}
                    onClick={() => handleTabSwitch('github')}
                  >
                    <Icon name="Github" />
                    <span>GitHub</span>
                  </button>
                  <button
                    type="button"
                    role="tab"
                    id="scan-tab-zip"
                    aria-selected={tab === 'zip'}
                    aria-controls="scan-panel-source"
                    className={tab === 'zip' ? 'active' : ''}
                    disabled={busy}
                    onClick={() => handleTabSwitch('zip')}
                  >
                    <Icon name="Archive" />
                    <span>Tệp ZIP</span>
                  </button>
                </div>
              </div>

              {/* Bước 2: Nhập GitHub hoặc tải ZIP */}
              <div
                id="scan-panel-source"
                role="tabpanel"
                aria-labelledby={tab === 'github' ? 'scan-tab-github' : 'scan-tab-zip'}
                className="v2-intake-source-panel"
              >
                {tab === 'github' ? (
                  <div className="v2-source-block">
                    <div className="v2-intake-field-head">
                      <label htmlFor="repo-url">Liên kết repository GitHub</label>
                      <span className="v2-intake-meta">HTTPS công khai · Java</span>
                    </div>
                    <div className={`v2-repo-input ${githubInlineError ? 'is-invalid' : ''}`}>
                      <Icon name="Github" />
                      <input
                        id="repo-url"
                        type="url"
                        value={url}
                        disabled={busy}
                        onChange={(event) => {
                          setUrl(event.target.value);
                          if (error) setError('');
                        }}
                        onBlur={() => {
                          if (url.trim()) setUrlTouched(true);
                        }}
                        placeholder="https://github.com/owner/repository"
                        aria-describedby="repo-url-help"
                        aria-invalid={Boolean(githubInlineError)}
                        autoComplete="url"
                        spellCheck={false}
                      />
                      {url && !busy && (
                        <button
                          type="button"
                          className="v2-input-clear"
                          aria-label="Xóa liên kết GitHub"
                          onClick={() => {
                            setUrl('');
                            setUrlTouched(false);
                            setError('');
                          }}
                        >
                          <Icon name="X" />
                        </button>
                      )}
                    </div>
                    {githubInlineError ? (
                      <p id="repo-url-help" className="v2-field-error" role="alert">
                        <Icon name="AlertTriangle" />
                        <span>{githubInlineError}</span>
                      </p>
                    ) : (
                      <p id="repo-url-help" className="v2-field-hint">
                        <Icon name="Info" />
                        <span>Nhập URL repository GitHub công khai (<code>https://github.com/owner/repo</code>).</span>
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="v2-source-block">
                    <div className="v2-intake-field-head">
                      <label htmlFor="zip-file-input">Tệp mã nguồn ZIP</label>
                      <span className="v2-intake-meta">Định dạng .zip · Tối đa {maxZipMb} MB</span>
                    </div>
                    <input
                      id="zip-file-input"
                      ref={inputRef}
                      type="file"
                      accept=".zip,application/zip"
                      hidden
                      disabled={busy}
                      onChange={handleFileInputChange}
                    />
                    {file ? (
                      <div
                        className={`v2-zip-selected ${isDragging ? 'is-dragging' : ''}`}
                        onDragOver={(event) => {
                          event.preventDefault();
                          if (!busy) setIsDragging(true);
                        }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={(event) => {
                          event.preventDefault();
                          setIsDragging(false);
                          if (!busy) applySelectedFile(event.dataTransfer.files?.[0] || null);
                        }}
                      >
                        <div className="v2-zip-file-info">
                          <span className="v2-zip-file-icon" aria-hidden="true">
                            <Icon name="FileArchive" />
                          </span>
                          <div className="v2-zip-file-meta">
                            <strong title={file.name}>{file.name}</strong>
                            <span>
                              {formatFileSize(file.size)} · {zipSigStatus === 'checking' ? 'Đang kiểm tra chữ ký tệp ZIP…' : 'Đã sẵn sàng phân tích'}
                            </span>
                          </div>
                        </div>
                        <div className="v2-zip-file-actions">
                          <button
                            type="button"
                            className="button-secondary button-compact"
                            disabled={busy}
                            onClick={() => inputRef.current?.click()}
                          >
                            <Icon name="RefreshCw" />Thay tệp
                          </button>
                          <button
                            type="button"
                            className="button-secondary button-compact"
                            disabled={busy}
                            aria-label="Gỡ tệp ZIP đã chọn"
                            onClick={handleClearFile}
                          >
                            <Icon name="X" />
                          </button>
                        </div>
                      </div>
                    ) : (
                      <button
                        type="button"
                        className={`v2-zip-dropzone ${isDragging ? 'is-dragging' : ''}`}
                        disabled={busy}
                        onClick={() => inputRef.current?.click()}
                        onDragOver={(event) => {
                          event.preventDefault();
                          if (!busy) setIsDragging(true);
                        }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={(event) => {
                          event.preventDefault();
                          setIsDragging(false);
                          if (!busy) applySelectedFile(event.dataTransfer.files?.[0] || null);
                        }}
                      >
                        <span className="v2-zip-drop-icon" aria-hidden="true">
                          <Icon name="UploadCloud" />
                        </span>
                        <strong className="v2-zip-drop-title">Kéo thả tệp ZIP vào đây</strong>
                        <span className="v2-zip-drop-sub">hoặc chọn tệp .zip chứa mã nguồn Java từ thiết bị</span>
                        <span className="button-secondary button-compact v2-zip-drop-cta">Chọn tệp ZIP</span>
                      </button>
                    )}
                  </div>
                )}
              </div>

              {/* Bước 3: Tùy chọn nâng cao (thống nhất cho cả GitHub và ZIP, mặc định thu gọn) */}
              <div className={`v2-advanced-box ${advancedOpen ? 'is-open' : ''}`}>
                <button
                  type="button"
                  className="v2-advanced-toggle"
                  aria-expanded={advancedOpen}
                  aria-controls="scanner-advanced-panel"
                  onClick={() => setAdvancedOpen((prev) => !prev)}
                >
                  <span className="v2-advanced-toggle-left">
                    <Icon name="Sliders" />
                    <span>Tùy chọn nâng cao</span>
                    {advancedSummaryTag && (
                      <span className="v2-advanced-pill">{advancedSummaryTag}</span>
                    )}
                  </span>
                  <Icon name="ChevronDown" className="v2-advanced-chevron" />
                </button>

                {advancedOpen && (
                  <div id="scanner-advanced-panel" className="v2-advanced-body">
                    {tab === 'github' && (
                      <div className="v2-field-group">
                        <label htmlFor="commit-sha-input">Commit SHA (không bắt buộc)</label>
                        <input
                          id="commit-sha-input"
                          type="text"
                          value={commitSha}
                          disabled={busy}
                          onChange={(event) => {
                            setCommitSha(event.target.value);
                            if (error) setError('');
                          }}
                          placeholder="Ví dụ: 7f6b76c hoặc 7f6b76c5056a82292a87cafa78f922077a211feb"
                          aria-describedby="commit-sha-help"
                          aria-invalid={Boolean(commitShaInlineError)}
                          spellCheck={false}
                        />
                        {commitShaInlineError ? (
                          <p id="commit-sha-help" className="v2-field-error" role="alert">
                            <Icon name="AlertTriangle" />
                            <span>{commitShaInlineError}</span>
                          </p>
                        ) : (
                          <p id="commit-sha-help" className="v2-field-hint">
                            <Icon name="Info" />
                            <span>Để trống để quét nhánh mặc định của repository. Chỉ chấp nhận mã Commit SHA hexadecimal dài 7–40 ký tự.</span>
                          </p>
                        )}
                      </div>
                    )}

                    <fieldset className="v2-mode-fieldset" disabled={busy}>
                      <legend>Chế độ phân tích</legend>
                      <div className="v2-mode-options" role="radiogroup" aria-label="Chế độ phân tích">
                        <label className={`v2-mode-option ${!noLlm ? 'is-selected' : ''}`}>
                          <input
                            type="radio"
                            name="scanner-analysis-mode"
                            value="hybrid"
                            checked={!noLlm}
                            onChange={() => setNoLlm(false)}
                          />
                          <span className="v2-mode-copy">
                            <strong>OpenGrep + Qwen3.5-9B (Mặc định)</strong>
                          </span>
                        </label>
                        <label className={`v2-mode-option ${noLlm ? 'is-selected' : ''}`}>
                          <input
                            type="radio"
                            name="scanner-analysis-mode"
                            value="opengrep_only"
                            checked={noLlm}
                            onChange={() => setNoLlm(true)}
                          />
                          <span className="v2-mode-copy">
                            <strong>Chỉ sử dụng OpenGrep (Chế độ đối chứng)</strong>
                          </span>
                        </label>
                      </div>
                    </fieldset>
                  </div>
                )}
              </div>

              {isReadOnlyProxy && (
                <div className="inline-warning v2-readonly-notice" role="status">
                  <Icon name="Lock" />
                  <span>{READ_ONLY_PROXY_NOTICE}</span>
                </div>
              )}

              {!isReadOnlyProxy && showWriteAuthWarning && (
                <div className="inline-warning" role="status">
                  <Icon name="Lock" />
                  <span style={{display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center'}}>
                    <span>{writePerm.message}</span>
                    {writePerm.kind === 'MISSING_BEARER_TOKEN' && outlet?.openConnectionPanel && (
                      <button
                        type="button"
                        className="button-secondary button-compact"
                        onClick={() => outlet.openConnectionPanel()}
                      >
                        <Icon name="KeyRound" />Nhập Bearer Token phiên
                      </button>
                    )}
                  </span>
                </div>
              )}

              {activeError && !isReadOnlyProxy && !showWriteAuthWarning && (
                <div className="inline-error" role="alert">
                  <Icon name="AlertTriangle" />
                  <span>{activeError}</span>
                </div>
              )}

              {/* Bước 4: Bắt đầu phân tích */}
              <div className="v2-intake-submit-bar">
                <span className="v2-intake-mode-summary">
                  {noLlm ? 'Chế độ: Chỉ sử dụng OpenGrep (đối chứng)' : 'Chế độ: OpenGrep + Qwen3.5-9B'}
                </span>
                <button
                  type="submit"
                  className="button-primary v2-intake-submit-btn"
                  disabled={!canSubmit}
                >
                  <Icon name="ScanSearch" />
                  {busy
                    ? (jobTrackingState === 'VERIFYING' ? 'Đang xác minh job…' : 'Đang phân tích…')
                    : discoveryBlocking
                      ? 'Đang kiểm tra job…'
                      : 'Bắt đầu phân tích'}
                  <Icon name="ArrowRight" />
                </button>
              </div>
            </form>
          </Card>
        </div>

        <section ref={statusSectionRef} className="card" aria-live="polite">
          <div className="v2-status-card-header">
            <h2>Tiến trình phiên phân tích</h2>
            <Badge tone={statusChip.tone}>{statusChip.label}</Badge>
          </div>
          <p className="panel-note" style={{margin: 0}}>{statusMessage}</p>

          {(busy || liveJob || liveStage === 'COMPLETED' || liveStage === 'FAILED') && (
            <div className="v2-progress-track" role="progressbar" aria-valuenow={progressPct} aria-valuemin={0} aria-valuemax={100}>
              <div className={`v2-progress-fill ${liveStage === 'FAILED' ? 'is-failed' : ''}`} style={{width: `${progressPct}%`}} />
            </div>
          )}

          {interrupted && (
            <div className="inline-warning">
              <Icon name="AlertTriangle" />Kết nối tạm gián đoạn. Hệ thống đang tự kết nối lại tới API…
            </div>
          )}

          <div className="v2-scanner-metrics">
            <div className="v2-mini-metric">
              <span>Giai đoạn hiện tại</span>
              <strong>{liveStage === 'COMPLETED' ? '6 / 6' : activeStage ? `${activeStage} / 6` : '—'}</strong>
            </div>
            <div className="v2-mini-metric">
              <span>{backendMs !== null ? 'Thời gian E2E (API)' : 'Thời gian theo dõi'}</span>
              <strong>{backendMs !== null ? formatElapsed(backendMs) : elapsedMs > 0 ? formatElapsed(elapsedMs) : '—'}</strong>
            </div>
            {Number.isFinite(Number(totalFindings)) && liveStage !== 'COMPLETED' && (
              <div className="v2-mini-metric" style={{gridColumn: '1 / -1'}}>
                <span>Tiến độ phân tích cảnh báo</span>
                <strong>{processed ?? 0} / {totalFindings} cảnh báo</strong>
              </div>
            )}
            {liveStage === 'COMPLETED' && liveCounts && (
              <>
                <div className="v2-mini-metric">
                  <span>Tổng cảnh báo</span>
                  <strong>{Number.isInteger(liveCounts.total) ? liveCounts.total : '—'}</strong>
                </div>
                <div className="v2-mini-metric">
                  <span>Chờ kiểm duyệt (OPEN)</span>
                  <strong>{Number.isInteger(liveCounts.open) ? liveCounts.open : '—'}</strong>
                </div>
              </>
            )}
          </div>

          {liveStage === 'COMPLETED' && liveCounts && (liveCounts.incomplete || !Number.isInteger(liveCounts.total)) && (
            <div className="inline-warning">
              <Icon name="AlertTriangle" />Dữ liệu cảnh báo từ API chưa đầy đủ nên chưa thể xác nhận tổng số cảnh báo hoặc trạng thái không có cảnh báo.
            </div>
          )}

          {liveStage === 'COMPLETED' && liveCounts && liveCounts.confirmedNoFindings === true && liveCounts.total === 0 && (
            <p className="panel-note" style={{marginTop: '12px', fontSize: '12.5px'}}>{NO_FINDINGS_NOTICE}</p>
          )}

          {liveStage === 'COMPLETED' && liveCounts && !liveCounts.incomplete && Number.isInteger(liveCounts.total) && liveCounts.total > 0 && (
            <div style={{display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '12px'}}>
              <Badge tone="red">SUPPORTED: {liveCounts.supported ?? '—'}</Badge>
              <Badge tone="amber">REFUTED (Qwen): {liveCounts.refuted ?? '—'}</Badge>
              <Badge tone="amber">REFUTED (giữ OPEN): {Number.isInteger(liveCounts.refutedOpen) ? liveCounts.refutedOpen : 'Chưa xác định'}</Badge>
              <Badge tone="neutral">UNDETERMINED: {liveCounts.undetermined ?? '—'}</Badge>
            </div>
          )}

          {liveStage === 'COMPLETED' && liveCounts && Number.isInteger(liveCounts.undetermined) && liveCounts.undetermined > 0 && (
            <div className="inline-warning">
              <Icon name="Info" />Có {liveCounts.undetermined} cảnh báo ở trạng thái UNDETERMINED — được giữ lại để người kiểm duyệt xem trực tiếp.
            </div>
          )}

          {resultId && liveStage !== 'FAILED' && (
            <div style={{display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '16px'}}>
              <Link className="button-primary" to={`/findings${scanQuery(resultId)}`}>
                {liveScanId ? 'Xem kết quả phát hiện' : 'Mở phiên gần nhất'} <Icon name="ArrowRight" />
              </Link>
              <Link className="button-secondary" to={`/review${scanQuery(resultId)}`}>
                <Icon name="Shield" />Hàng đợi kiểm duyệt
              </Link>
            </div>
          )}
        </section>
      </div>

      {jobFailed && (
        <div className="section-block">
          <FailureDetails job={liveJob} />
        </div>
      )}

      <section className="section-block">
        <details
          className="v2-accordion"
          open={pipelineOpen}
          onToggle={(event) => setPipelineOpen(event.currentTarget.open)}
        >
          <summary>
            <span><Icon name="Layers" />Chi tiết 6 giai đoạn backend (OpenGrep · Qwen3.5-9B · SHA-256 · SQLite)</span>
            <Icon name="ChevronDown" />
          </summary>
          <div className="v2-accordion-body">
            <SecurityAnalysisScene
              live={{
                stage: liveStage,
                state: String(liveJob?.state || liveStage).toUpperCase(),
                activeStage: ['COMPLETED', 'LOADING_RESULTS', 'RESULTS_ERROR'].includes(liveStage) ? 6 : activeStage,
                stages: liveJob?.stages || [],
                counts: liveCounts,
                progress: liveJob?.progress,
                resultsReady: liveStage === 'COMPLETED' && liveCounts !== null && Boolean(liveScanId),
                interrupted,
              }}
              liveJob={liveJob}
              elapsedMs={elapsedMs}
              backendMs={backendMs}
              running={busy}
              noLlm={Boolean(liveJob?.no_llm ?? (busy ? noLlm : false))}
            />

            {(liveJob || liveScanId) && (
              <details className="v2-sub-details">
                <summary>Thông số kỹ thuật, thời lượng từng chặng &amp; provenance phiên quét</summary>
                <div className="v2-sub-details-body">
                  {liveScanId && (
                    <p className="panel-note" style={{marginTop: '6px'}}>
                      Mã phiên (<code>scan_id</code>): <code className="wrap-value">{liveScanId}</code>
                    </p>
                  )}
                  {liveJob && <StageTiming job={liveJob} />}
                  {liveJob && <CoveragePanel job={liveJob} />}
                </div>
              </details>
            )}
          </div>
        </details>
      </section>
    </>
  );
}
