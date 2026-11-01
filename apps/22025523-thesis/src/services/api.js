const baseUrl = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8765').replace(/\/$/, '');

export class ApiError extends Error {
  constructor(message, {status, timedOut = false, cause, payload} = {}) {
    super(message, {cause});
    this.name = 'ApiError';
    this.status = status;
    this.timedOut = timedOut;
    this.payload = payload;
    this.code = payload?.error_code;
  }
}

export function inputErrorMessage(payload) {
  const code = payload?.error_code || payload?.stage_error_code;
  const detail = payload?.error_message || payload?.stage_error_message || 'Không thể phân tích dữ liệu đầu vào.';
  const message = ['NO_JAVA_FILES_FOUND','NO_JAVA_FILES_IN_ZIP','NO_JAVA_FILES_MATCHED_FILTERS'].includes(code)
    ? 'Không tìm thấy mã nguồn Java trong phạm vi đã cung cấp. NTK hiện hỗ trợ Java cho CWE-22, CWE-78, CWE-79 và CWE-89.'
    : code === 'JAVA_SYNTAX_ERROR'
      ? 'Mã nguồn .java có lỗi cú pháp hoặc không phải Java hợp lệ; không thể kết luận về lỗ hổng.'
      : detail;
  return code ? `${message} [${code}]` : message;
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 10000;
  const fetchOptions = {...options};
  delete fetchOptions.timeoutMs;
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, {once: true});

  try {
    const response = await fetch(`${baseUrl}${path}`, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        ...(options.body instanceof FormData ? {} : {'Content-Type': 'application/json'}),
        ...options.headers
      }
    });

    if (!response.ok) {
      const message = await response.text();
      let payload;
      try { payload = JSON.parse(message); } catch { /* non-JSON gateway error */ }
      throw new ApiError(payload ? inputErrorMessage(payload) : message || `Yêu cầu thất bại (${response.status})`, {status: response.status, payload});
    }
    if (response.status === 204) return null;

    const text = await response.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted && !options.signal?.aborted) {
      throw new ApiError('Máy chủ không phản hồi trong thời gian cho phép.', {timedOut: true, cause: error});
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
  }
}

async function requestFile(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs ?? 60000);
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, {once: true});

  try {
    const response = await fetch(`${baseUrl}${path}`, {
      signal: controller.signal,
      headers: options.headers
    });
    if (!response.ok) {
      const message = await response.text();
      throw new ApiError(message || `Tải tệp thất bại (${response.status})`, {status: response.status});
    }
    return {
      blob: await response.blob(),
      contentType: response.headers.get('content-type') || '',
      disposition: response.headers.get('content-disposition') || ''
    };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted && !options.signal?.aborted) {
      throw new ApiError('Máy chủ không phản hồi trong thời gian cho phép.', {timedOut: true, cause: error});
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
  }
}

async function optionalList(path, options = {}) {
  try {
    const data = await request(path, {...options, timeoutMs: 15000});
    const items = Array.isArray(data)
      ? data
      : data?.jobs ?? data?.scans ?? data?.items ?? data?.results ?? data?.data?.jobs ?? data?.data?.scans;
    return {supported: Array.isArray(items), items: Array.isArray(items) ? items : [],
      totalPages: Number(data?.total_pages) || 1};
  } catch (error) {
    if (error instanceof ApiError && [404, 405, 501].includes(error.status)) {
      return {supported: false, items: []};
    }
    throw error;
  }
}

async function scanHistory(options) {
  const items=[];
  // Only lightweight scan summaries; never full finding payloads. Bound the
  // number of requests and disclose truncation instead of hiding old scans.
  const maxPages=20;
  for(let page=1;page<=maxPages;page+=1){
    const result=await optionalList(`/api/scans?page=${page}&page_size=100`,options);
    if(!result.supported)return {...result,items};
    items.push(...result.items);
    if(page>=result.totalPages)return {supported:true,items,truncated:false};
  }
  return {supported:true,items,truncated:true};
}

// CWSS Inference V2 is independent from legacy /cwss/page (V1).
// Ranking sorts by CWSS rather than the indexed findings order. Never join rows
// by page position: locate each requested finding by its stable finding_id.
async function cwssV2ForFindingIds(scanId, findingIds, options = {}) {
  const ids = [...new Set((findingIds || []).filter((id) => typeof id === 'string' && id))];
  if (!ids.length) return {status: 'OK', scan_id: scanId, assessments: [], requested_count: 0, matched_count: 0};
  const wanted = new Set(ids);
  const found = new Map();
  const pageSize = 200;
  for (let page = 1; page <= 40 && found.size < wanted.size; page += 1) {
    const response = await request(
      `/api/scans/${encodeURIComponent(scanId)}/cwss/v1/ranking?mode=CWSS_AUTO_COMPLETE&page=${page}&page_size=${pageSize}`,
      {...options, timeoutMs: options.timeoutMs ?? 60000}
    );
    if (response?.scan_id !== scanId || response?.requested_mode !== 'CWSS_AUTO_COMPLETE' || !Array.isArray(response?.findings)) {
      throw new ApiError('CWSS V2 ranking response failed contract checks.');
    }
    for (const item of response.findings) {
      if (!wanted.has(item?.finding_id)) continue;
      if (item.inference_version !== 'NTK_CWSS_INFERENCE_V2' || !item.metric_assessments || Object.keys(item.metric_assessments).length !== 16) {
        throw new ApiError('A ranking item is missing its 16-metric CWSS V2 provenance.');
      }
      found.set(item.finding_id, item);
    }
    const total = Number(response.total_matching);
    if (!response.findings.length || (Number.isFinite(total) && page * pageSize >= total)) break;
  }
  return {
    status: found.size === wanted.size ? 'OK' : 'INCOMPLETE',
    scan_id: scanId,
    inference_version: 'NTK_CWSS_INFERENCE_V2',
    requested_count: wanted.size,
    matched_count: found.size,
    assessments: [...found].map(([finding_id, cwss]) => ({finding_id, cwss}))
  };
}

async function cwssV2Finding(scanId, findingId, options = {}) {
  const response = await request(
    `/api/scans/${encodeURIComponent(scanId)}/cwss/v1/findings/${encodeURIComponent(findingId)}/automatic`,
    {...options, timeoutMs: options.timeoutMs ?? 60000}
  );
  const result = response?.auto_complete;
  if (response?.scan_id !== scanId || response?.finding_id !== findingId || result?.inference_version !== 'NTK_CWSS_INFERENCE_V2' || Object.keys(result?.metric_assessments || {}).length !== 16) {
    throw new ApiError('Finding CWSS_AUTO_COMPLETE is not a valid V2 16-metric assessment.');
  }
  return result;
}

// Explicitly hypothetical V2 scenario, computed by the local Python CWSS engine.
// Client never supplies arbitrary metric codes and never changes triage.
const SCENARIO_PROFILE = 'BUSINESS_CRITICAL_INTERNET_FACING';
async function cwssV2ScenarioPage(scanId, page = 1, pageSize = 50, options = {}) {
  const path = `/api/scans/${encodeURIComponent(scanId)}/cwss/v2/scenario?profile=${SCENARIO_PROFILE}&page=${page}&page_size=${pageSize}`;
  const response = await request(path, {...options, timeoutMs: options.timeoutMs ?? 60000});
  if (response?.status !== 'OK' || response?.scan_id !== scanId ||
      response?.scenario_id !== SCENARIO_PROFILE || response?.hypothetical !== true ||
      response?.verified_deployment !== false || Number(response?.page) !== page ||
      !Array.isArray(response?.assessments)) {
    throw new ApiError('CWSS V2 conditional scenario response is invalid.');
  }
  for (const entry of response.assessments) {
    const score = entry?.cwss;
    if (!entry?.finding_id || score?.finding_id !== entry.finding_id ||
        score?.inference_version !== 'NTK_CWSS_INFERENCE_V2' ||
        score?.reference_profile !== SCENARIO_PROFILE ||
        Object.keys(score?.metric_assessments || {}).length !== 16) {
      throw new ApiError('CWSS V2 scenario lacks valid metric provenance.');
    }
  }
  return response;
}
async function cwssV2ScenarioFinding(scanId, findingId, options = {}) {
  const path = `/api/scans/${encodeURIComponent(scanId)}/cwss/v2/scenario?profile=${SCENARIO_PROFILE}&finding_id=${encodeURIComponent(findingId)}`;
  const response = await request(path, {...options, timeoutMs: options.timeoutMs ?? 60000});
  const entry = Array.isArray(response?.assessments) ? response.assessments.find((row) => row?.finding_id === findingId) : null;
  if (response?.scan_id !== scanId || response?.hypothetical !== true ||
      response?.verified_deployment !== false || !entry?.cwss ||
      entry.cwss.inference_version !== 'NTK_CWSS_INFERENCE_V2' ||
      Object.keys(entry.cwss.metric_assessments || {}).length !== 16) {
    throw new ApiError('CWSS V2 hypothetical finding response is invalid.');
  }
  return entry.cwss;
}

export const api = {
  createZipJob: (file, options = {}) => {
    const body = new FormData();
    body.append('file', file, file.name);
    // Binary endpoint is asynchronous and enforces archive limits server-side.
    return request('/api/scan-jobs', {...options, method:'POST', body, timeoutMs:60000});
  },
  cwssV2ScenarioPage,
  cwssV2ScenarioFinding,
  cwssV2ForFindingIds,
  cwssV2Finding,
  health: (options) => request('/api/health', options),
  model: (options) => request('/api/model', options),
  startGithubScan: (repositoryUrl, commitSha, options = {}) => {
    const body = {repo_url: repositoryUrl};
    if (commitSha) body.commit_sha = commitSha;
    return request('/api/scans', {
      ...options,
      method: 'POST',
      timeoutMs: 15 * 60 * 1000,
      body: JSON.stringify(body)
    });
  },
  createScanJob: (repoUrl, commitSha, options = {}, configuration = {}) => {
    const body = {
      repo_url: repoUrl,
      ...(commitSha ? {commit_sha: commitSha} : {}),
      ...Object.fromEntries(Object.entries(configuration).filter(([, value]) => value !== undefined && value !== ''))
    };
    return request('/api/scan-jobs', {
      ...options,
      method: 'POST',
      timeoutMs: 30000,
      body: JSON.stringify(body)
    });
  },
  scanJob: (jobId, options = {}) => request(`/api/scan-jobs/${encodeURIComponent(jobId)}`, {
    ...options,
    timeoutMs: 15000
  }),
  listScanJobs: (options) => optionalList('/api/scan-jobs', options),
  listScans: (options) => scanHistory(options),
  cwssPage: (scanId, page = 1, pageSize = 50, options = {}) => request(
    `/api/scans/${encodeURIComponent(scanId)}/cwss/page?page=${page}&page_size=${pageSize}`,
    {...options, timeoutMs: 30000}
  ),
  pipelineTrace: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}/pipeline-trace`, {
    ...options,
    timeoutMs: 30000
  }),
  scan: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}`, options),
  scanSummary: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}/summary`, {
    ...options,
    timeoutMs: 30000
  }),
  findingsPage: (scanId, page = 1, pageSize = 50, options = {}) => {
    const {decision, ...rest} = options;
    const filter = decision ? `&decision=${encodeURIComponent(decision)}` : '';
    return request(
      `/api/scans/${encodeURIComponent(scanId)}/findings/page?page=${page}&page_size=${pageSize}${filter}`,
      {...rest, timeoutMs: 30000}
    );
  },
  findingDetail: (scanId, findingId, detailUrl, options = {}) => request(
    typeof detailUrl === 'string' && detailUrl.startsWith('/api/')
      ? detailUrl
      : `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`,
    {...options, timeoutMs: 30000}
  ),
  findings: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}/findings`, {
    ...options,
    timeoutMs: options.timeoutMs ?? 60000
  }),
  finding: (id, options) => request(`/api/findings/${encodeURIComponent(id)}`, options),
  report: (scanId, options) => request(`/api/scans/${encodeURIComponent(scanId)}/report?format=json`, options),
  datasetManifest: (options = {}) => request('/api/datasets/manifest', {...options, timeoutMs: 30000}),
  datasetRecords: (datasetId, params = {}, options = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') query.set(key, String(value));
    });
    return request(`/api/datasets/${encodeURIComponent(datasetId)}/records?${query}`, {
      ...options,
      timeoutMs: 30000
    });
  },
  datasetExport: (datasetId, format, options = {}) => requestFile(
    `/api/datasets/${encodeURIComponent(datasetId)}/export?format=${encodeURIComponent(format)}`,
    options
  )
};

export async function checkBackend() {
  try {
    const status = await api.health();
    return {connected: true, status};
  } catch (error) {
    return {connected: false, error: error.message};
  }
}
