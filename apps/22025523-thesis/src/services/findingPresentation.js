// Presentation-only helpers. No scoring, triage, or evidence inference happens here.
export const CWE_GUIDES = Object.freeze({
  'CWE-22': {
    title: 'Truy cập đường dẫn không an toàn',
    description: 'Dữ liệu đầu vào có thể ảnh hưởng đến đường dẫn tệp mà ứng dụng sử dụng.',
    suggestion: 'Kiểm tra cách chuẩn hóa đường dẫn, giới hạn thư mục được phép truy cập và chặn đường dẫn thoát ra ngoài thư mục gốc.'
  },
  'CWE-78': {
    title: 'Nguy cơ chèn lệnh hệ điều hành',
    description: 'Đầu vào có thể ảnh hưởng đến câu lệnh được thực thi trên hệ điều hành.',
    suggestion: 'Tránh ghép trực tiếp đầu vào vào lệnh shell; ưu tiên API không gọi shell và kiểm soát chặt các tham số.'
  },
  'CWE-79': {
    title: 'Nguy cơ chèn mã vào trang web (XSS)',
    description: 'Dữ liệu không tin cậy có thể được đưa vào nội dung hiển thị trên trình duyệt.',
    suggestion: 'Mã hóa đầu ra theo đúng ngữ cảnh HTML/JavaScript, hạn chế HTML tùy ý và kiểm tra dữ liệu đầu vào.'
  },
  'CWE-89': {
    title: 'Nguy cơ chèn câu lệnh SQL',
    description: 'Đầu vào có thể ảnh hưởng đến cấu trúc truy vấn cơ sở dữ liệu.',
    suggestion: 'Sử dụng truy vấn có tham số (PreparedStatement) thay vì ghép chuỗi SQL trực tiếp từ đầu vào.'
  }
});

export function readableText(value) {
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return '';
}

export function firstText(...values) {
  return values.map(readableText).find(Boolean) || '';
}

export function getCweGuide(value) {
  const match = readableText(value).toUpperCase().match(/CWE[-_]?0*(22|78|79|89)(?!\d)/);
  const code = match ? `CWE-${match[1]}` : readableText(value);
  return {code: code || 'Chưa xác định CWE', ...(CWE_GUIDES[code] || {
    title: 'Cảnh báo cần kiểm tra',
    description: 'Cần đọc bằng chứng của công cụ để xác định phạm vi cảnh báo.',
    suggestion: ''
  })};
}

export function fileName(path) {
  return readableText(path).replaceAll('\\', '/').split('/').pop() || '';
}

export function validCwssScore(assessment) {
  const value = assessment?.cwss_score;
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null;
}

export const IRIS_PROOF_STATES = Object.freeze(['PROVEN_TAINT', 'PROVEN_SAFE', 'UNKNOWN']);

// Read only the proof state reported by the backend. Never infer PROVEN_SAFE
// from a missing taint path or from taint_reaches_sink === false alone.
export function irisProofState(raw) {
  const evidence = raw?.iris_evidence && typeof raw.iris_evidence === 'object' ? raw.iris_evidence : {};

  // /findings/page intentionally returns a compact projection: it omits the
  // nested iris_evidence object but keeps source_sink_trace_status at top level.
  // Full finding/detail records keep the same value inside iris_evidence.
  const traceValues = [evidence.source_sink_trace_status, raw?.source_sink_trace_status]
    .filter((value) => typeof value === 'string' && value.trim())
    .map((value) => value.trim().toUpperCase());
  const uniqueTraces = [...new Set(traceValues)];
  if (uniqueTraces.length > 1) return 'UNKNOWN';
  const trace = uniqueTraces[0] || '';

  const stateValues = [evidence.flow_proof_state, raw?.flow_proof_state]
    .filter((value) => typeof value === 'string' && value.trim())
    .map((value) => value.trim().toUpperCase());
  const uniqueStates = [...new Set(stateValues)];
  if (uniqueStates.length > 1) return 'UNKNOWN';
  const state = uniqueStates[0] || '';

  const reachValues = [evidence.taint_reaches_sink, raw?.taint_reaches_sink]
    .filter((value) => typeof value === 'boolean');
  if (new Set(reachValues).size > 1) return 'UNKNOWN';
  const reachesSink = reachValues.length ? reachValues[0] : undefined;

  const safeTrace = ['SAFE_CONSTANT_OR_PARAMETERIZED', 'SAFE_SANITIZED_OR_GUARDED'].includes(trace);

  // Prefer the backend's explicit proof state when present. Contradictory
  // evidence is downgraded to UNKNOWN rather than guessed or silently chosen.
  if (IRIS_PROOF_STATES.includes(state)) {
    if (state === 'PROVEN_TAINT' && (reachesSink === false || safeTrace)) return 'UNKNOWN';
    if (state === 'PROVEN_SAFE' && (reachesSink === true || trace === 'VERIFIED_TAINT_FLOW')) return 'UNKNOWN';
    return state;
  }

  // Compact /findings/page contract: map only the backend's explicit proof
  // trace enums. A missing path or an intraprocedural limit is NOT proof-safe.
  if (trace === 'VERIFIED_TAINT_FLOW') {
    return reachesSink === false ? 'UNKNOWN' : 'PROVEN_TAINT';
  }
  if (safeTrace) {
    return reachesSink === true ? 'UNKNOWN' : 'PROVEN_SAFE';
  }

  // Preserve the legacy explicit proof field only when corroborated by its
  // required evidence. This is not a fallback to scanner severity or absence
  // of a trace.
  const legacy = firstText(raw?.iris_proof).toUpperCase();
  if (legacy === 'PROVEN_TAINT' && reachesSink === true && !safeTrace) return 'PROVEN_TAINT';
  if (legacy === 'PROVEN_SAFE' && safeTrace && reachesSink !== true) return 'PROVEN_SAFE';

  // Partial traces, no-flow-within-limited-scope, and all unrecognized states
  // remain UNKNOWN. Never infer PROVEN_SAFE from absence of taint evidence.
  return 'UNKNOWN';
}

export function irisProofTone(value) {
  if (value === 'PROVEN_TAINT') return 'red';
  if (value === 'PROVEN_SAFE') return 'green';
  return 'amber';
}

export function irisProofExplanation(value) {
  if (value === 'PROVEN_TAINT') {
    return 'Backend ghi nhận dữ liệu đầu vào đi tới thao tác nhạy cảm. Điều này chưa tự chứng minh khai thác thành công.';
  }
  if (value === 'PROVEN_SAFE') {
    return 'Backend ghi nhận dấu vết xử lý an toàn trong phạm vi đường đi đã phân tích. Điều này không chứng minh toàn bộ ứng dụng an toàn.';
  }
  return 'Chưa đủ bằng chứng IRIS hoặc dữ liệu không thống nhất để đưa ra kết luận.';
}

export const TRIAGE_GUIDE = Object.freeze({
  REPORT: 'Ưu tiên kiểm tra và xử lý cảnh báo này.',
  REVIEW: 'Cần xem xét thêm bằng chứng trước khi đưa ra kết luận.',
  SUPPRESS: 'Cảnh báo đang được giảm ưu tiên theo quy tắc xử lý; không đồng nghĩa đã xác nhận là cảnh báo giả.'
});

export function triageExplanation(value) {
  return TRIAGE_GUIDE[readableText(value).toUpperCase()] || 'Chưa có quyết định xử lý từ backend.';
}

export function roleDescription(raw) {
  const role = firstText(
    raw?.llm_api_role?.role, raw?.llm_api_role?.predicted_role, raw?.llm_api_role,
    raw?.api_role?.role, raw?.api_role, raw?.role?.label, raw?.role
  ).toLowerCase();
  const descriptions = {
    source: 'Điểm nhận dữ liệu đầu vào',
    sink: 'Điểm sử dụng dữ liệu nhạy cảm',
    'taint-propagator': 'Thành phần truyền dữ liệu',
    none: 'Không thuộc ba vai trò trên'
  };
  return role ? {code: role, text: descriptions[role] || role} : null;
}

export function irisDescription(raw) {
  const evidence = raw?.iris_evidence && typeof raw.iris_evidence === 'object' ? raw.iris_evidence : {};
  const overall = firstText(raw?.iris_proof, raw?.iris_status).toUpperCase();
  const flow = firstText(evidence?.flow_proof_state, evidence?.iris_proof, evidence?.proof).toUpperCase();
  const trace = firstText(evidence?.source_sink_trace_status, raw?.source_sink_trace_status).toUpperCase();
  const reachesSink = evidence?.taint_reaches_sink;
  const labels = {
    PROVEN_TAINT: 'Có bằng chứng dữ liệu đầu vào đi tới thao tác nhạy cảm',
    PROVEN_SAFE: 'Có bằng chứng xử lý an toàn trong phạm vi phân tích',
    UNKNOWN: 'Chưa đủ bằng chứng để kết luận',
    IRIS_PARTIAL: 'Phân tích chưa đầy đủ',
    IRIS_UNAVAILABLE: 'Chưa có kết quả từ IRIS gốc'
  };
  const flowState = labels[flow] ? flow :
    (trace === 'VERIFIED_TAINT_FLOW' && reachesSink === true ? 'PROVEN_TAINT' : '');
  const contradictoryFlow = (flowState === 'PROVEN_TAINT' && reachesSink === false) ||
    (flowState === 'PROVEN_SAFE' && (reachesSink === true || trace === 'VERIFIED_TAINT_FLOW'));
  const conflict = contradictoryFlow || (['PROVEN_SAFE', 'PROVEN_TAINT'].includes(overall) &&
    ['PROVEN_SAFE', 'PROVEN_TAINT'].includes(flowState) && overall !== flowState);
  const proof = conflict ? 'CONFLICT' : (flowState || overall || firstText(evidence?.analysis_status).toUpperCase());
  if (!proof && !Object.keys(evidence).length) return null;

  const parser = firstText(evidence?.ast_parser_engine);
  const isJavacAst = parser === 'OPENJDK17_JAVAC_TASK_AST';
  const target = evidence?.target_callee_identity;
  const targetName = target && typeof target === 'object' ?
    [firstText(target.class), firstText(target.method)].filter(Boolean).join('.') : '';
  const origin = isJavacAst
    ? 'Nguồn: phân tích cấu trúc Java (javac/AST) do backend cung cấp, không tự coi là IRIS gốc đã xác minh.'
    : 'Nguồn: bằng chứng phân tích do backend cung cấp.';

  let detail = '';
  if (conflict) detail = 'Các trạng thái bằng chứng không thống nhất; cần mở dữ liệu gốc để đối chiếu.';
  else if (flowState === 'PROVEN_TAINT') detail =
    `Backend ghi nhận đường đi của dữ liệu đầu vào tới thao tác nhạy cảm${targetName ? ` (${targetName})` : ''}. Điều này chưa tự chứng minh khai thác thành công.`;
  else if (flowState === 'PROVEN_SAFE') detail =
    'Trong phạm vi đường đi đã xét, backend ghi nhận dấu vết xử lý an toàn; không bảo đảm toàn bộ ứng dụng an toàn.';
  else if (reachesSink === false) detail =
    'Chưa thấy dữ liệu đầu vào đi tới thao tác nhạy cảm trong phần được phân tích; cần kiểm tra thêm.';
  else detail = 'Chưa có kết luận rõ ràng từ bằng chứng luồng dữ liệu của bản ghi này.';

  const text = conflict ? 'Bằng chứng phân tích chưa thống nhất' :
    (labels[proof] || 'Có dữ liệu phân tích, cần kiểm tra thêm');
  return {code: proof || 'UNSPECIFIED', text, detail, origin};
}

export function sourceSnippet(raw) {
  const context = raw?.source_context || raw?.code_context;
  return firstText(
    raw?.matched_code, raw?.code_snippet, raw?.source_excerpt, raw?.snippet,
    context?.matched_code, context?.code, context?.snippet
  );
}

export function backendRecommendation(raw) {
  return firstText(raw?.remediation, raw?.recommendation, raw?.fix_suggestion);
}

export function findReportedId(detail) {
  const nested = detail?.finding && typeof detail.finding === 'object' ? detail.finding : {};
  return firstText(detail?.finding_id, nested?.finding_id, detail?.candidate_id, nested?.candidate_id);
}
