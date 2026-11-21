// Presentation helpers for v2/api findings, citations, dataflow trace, SHA-256 integrity,
// health status semantics, and Human Review states.

export const PRIORITY_CWES = Object.freeze(['CWE-22', 'CWE-89']);

export const CWE_GUIDES = Object.freeze({
  'CWE-22': {
    title: 'Truy cập đường dẫn không an toàn (Path Traversal)',
    description: 'Dữ liệu đầu vào có thể ảnh hưởng đến đường dẫn tệp mà ứng dụng Java đọc hoặc ghi.',
    suggestion: 'Chuẩn hóa đường dẫn bằng Path.normalize() / getCanonicalPath(), kiểm tra tiền tố thư mục gốc hợp lệ (kèm File.separator) và chặn ký tự điều hướng "..".',
  },
  'CWE-89': {
    title: 'Nguy cơ chèn câu lệnh SQL (SQL Injection)',
    description: 'Dữ liệu đầu vào chưa tham số hóa có thể làm thay đổi cấu trúc truy vấn cơ sở dữ liệu.',
    suggestion: 'Sử dụng truy vấn có tham số (PreparedStatement / JDBC parameter binding) thay vì nối chuỗi SQL trực tiếp.',
  },
  'CWE-78': {
    title: 'Nguy cơ chèn lệnh hệ điều hành (OS Command Injection)',
    description: 'Đầu vào có thể ảnh hưởng đến lệnh được thực thi trên hệ điều hành.',
    suggestion: 'Tránh gọi shell trực tiếp từ chuỗi ghép nối; tách tham số qua ProcessBuilder và kiểm tra danh sách cho phép.',
  },
  'CWE-79': {
    title: 'Nguy cơ chèn mã vào trang web (XSS)',
    description: 'Dữ liệu không tin cậy có thể được đưa vào nội dung HTML/JavaScript trả về trình duyệt.',
    suggestion: 'Mã hóa đầu ra theo đúng ngữ cảnh HTML/JavaScript và tránh chèn trực tiếp chuỗi đầu vào.',
  },
});

export function readableText(value) {
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return '';
}

export function firstText(...values) {
  return values.map(readableText).find(Boolean) || '';
}

export function normCwe(value) {
  const raw = Array.isArray(value) ? value[0] : value;
  const match = readableText(raw).toUpperCase().match(/CWE[-_]?0*(\d+)/);
  return match ? `CWE-${parseInt(match[1], 10)}` : readableText(raw) || 'Chưa rõ';
}

export function getCweGuide(value) {
  const code = normCwe(value);
  return {
    code,
    ...(CWE_GUIDES[code] || {
      title: 'Cảnh báo cần kiểm tra bằng chứng',
      description: 'Cần đối chiếu đoạn mã nguồn Java thật, luồng dữ liệu và trích dẫn đã kiểm chứng.',
      suggestion: '',
    }),
  };
}

export function fileName(path) {
  return readableText(path).replaceAll('\\', '/').split('/').pop() || '';
}

export function formatShortHash(hash, head = 12, tail = 8) {
  const clean = readableText(hash);
  if (!clean) return 'Chưa có';
  if (clean.length <= head + tail + 3) return clean;
  return `${clean.slice(0, head)}…${clean.slice(-tail)}`;
}

export const VALIDATED_STATUSES = Object.freeze(['SUPPORTED', 'REFUTED', 'UNDETERMINED']);

export const VALIDATED_STATUS_META = Object.freeze({
  SUPPORTED: {
    code: 'SUPPORTED',
    label: 'SUPPORTED',
    viLabel: 'AI đánh giá có cơ sở',
    tone: 'red',
    summary: 'AI nhận định cảnh báo có cơ sở dựa trên trích dẫn mã nguồn và SHA-256 hợp lệ. Đây là đề xuất của mô hình, chưa phải quyết định xác nhận cuối cùng của con người.',
  },
  REFUTED: {
    code: 'REFUTED',
    label: 'REFUTED',
    viLabel: 'AI nghi ngờ cảnh báo giả',
    tone: 'amber',
    summary: 'AI nhận định cảnh báo có thể không chính xác kèm trích dẫn hợp lệ. Cảnh báo chưa bị loại và vẫn giữ trạng thái OPEN cho tới khi người kiểm duyệt xác nhận.',
  },
  UNDETERMINED: {
    code: 'UNDETERMINED',
    label: 'UNDETERMINED',
    viLabel: 'Chưa đủ bằng chứng',
    tone: 'neutral',
    summary: 'Chưa đủ bằng chứng để kết luận, trích dẫn chưa vượt qua bước kiểm chứng hoặc Qwen chưa chạy. Cảnh báo được giữ lại để kiểm tra trực tiếp.',
  },
});

export function validatedStatusMeta(status) {
  const key = readableText(status).toUpperCase();
  return VALIDATED_STATUS_META[key] || VALIDATED_STATUS_META.UNDETERMINED;
}

export const HUMAN_REVIEW_STATES = Object.freeze(['OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE']);

export const HUMAN_REVIEW_META = Object.freeze({
  OPEN: {
    code: 'OPEN',
    label: 'OPEN',
    viLabel: 'Chờ kiểm duyệt',
    tone: 'blue',
    summary: 'Đang chờ người kiểm duyệt đối chiếu mã nguồn Java và đưa ra quyết định cuối cùng.',
  },
  CONFIRMED_TRUE: {
    code: 'CONFIRMED_TRUE',
    label: 'CONFIRMED_TRUE',
    viLabel: 'Người duyệt xác nhận thật',
    tone: 'red',
    summary: 'Người kiểm duyệt đã xác nhận đây là cảnh báo thật và ghi nhận vào nhật ký SQLite.',
  },
  CONFIRMED_FALSE: {
    code: 'CONFIRMED_FALSE',
    label: 'CONFIRMED_FALSE',
    viLabel: 'Người duyệt xác nhận giả',
    tone: 'green',
    summary: 'Người kiểm duyệt đã xác nhận cảnh báo giả sau khi máy chủ kiểm tra toàn vẹn SHA-256 mã nguồn.',
  },
});

export function humanReviewMeta(state) {
  const key = readableText(state).toUpperCase();
  return HUMAN_REVIEW_META[key] || HUMAN_REVIEW_META.OPEN;
}

export function citationCheckTone(check) {
  const key = readableText(check).toUpperCase();
  if (key === 'MATCHED') return 'green';
  if (key === 'NONE' || key === 'NOT_VERIFIED') return 'amber';
  return 'red';
}

export function citationCheckMeta(check) {
  const key = readableText(check).toUpperCase() || 'NOT_VERIFIED';
  if (key === 'MATCHED') {
    return {
      code: 'MATCHED',
      tone: 'green',
      viLabel: 'Trích dẫn khớp mã nguồn',
      note: 'Vị trí dòng, đoạn trích và SHA-256 khớp tệp nguồn lúc quét; chỉ chứng thực trích dẫn, không đồng nghĩa đã chứng minh lỗ hổng.',
    };
  }
  if (key === 'NONE' || key === 'NOT_VERIFIED') {
    return {
      code: key,
      tone: 'amber',
      viLabel: 'Chưa có trích dẫn hợp lệ',
      note: 'Chưa ghi nhận trích dẫn mã nguồn vượt qua bước đối chiếu; giữ cảnh báo để kiểm tra thủ công.',
    };
  }
  return {
    code: key,
    tone: 'red',
    viLabel: 'Trích dẫn không khớp',
    note: 'Đoạn trích do mô hình trả về không khớp mã nguồn hoặc SHA-256 gốc.',
  };
}

export const NO_FINDINGS_NOTICE =
  'OpenGrep không ghi nhận cảnh báo nào thuộc phạm vi tập luật hiện tại (NO_FINDINGS). Kết quả này chỉ phản ánh phạm vi quy tắc đã chạy và không chứng minh mã nguồn hoàn toàn an toàn.';

const MOCK_ORIGIN_RE = /(?:^|[_-])(MOCK|SYNTHETIC|UNIT_TEST_MOCK_CAPTURE)(?:$|[_-])/i;
const UNVERIFIED_PROVENANCE_ORIGIN_RE = /(?:^|[_-])(COLLECTION_ONLY|DECLARED_ONLY|IMPORTED|UNVERIFIED|UNKNOWN|MANUAL_IMPORT)(?:$|[_-])/i;

function pushEvidenceProvenanceObjects(ev, out) {
  if (!isPlainObject(ev)) return;
  out.push(ev, ev.metadata, ev.scan_provenance, ev.scan_provenance?.metadata, ev.java_context?.metadata);
  if (isPlainObject(ev.raw_finding)) {
    out.push(ev.raw_finding.metadata, ev.raw_finding.extra?.metadata);
  }
  if (Array.isArray(ev.snippets)) {
    for (let i = 0; i < ev.snippets.length; i += 1) {
      const s = ev.snippets[i];
      if (isPlainObject(s)) out.push(s, s.metadata);
    }
  }
  if (isPlainObject(ev.snapshots)) {
    for (const meta of Object.values(ev.snapshots)) {
      if (isPlainObject(meta)) out.push(meta, meta.metadata);
    }
  }
}

function pushAssessmentProvenanceObjects(ass, out) {
  if (!isPlainObject(ass)) return;
  out.push(ass, ass.metadata, ass.runtime, ass.runtime?.metadata, ass.runtime_metadata, ass.citation_provenance);
  if (Array.isArray(ass.citations)) {
    for (let i = 0; i < ass.citations.length; i += 1) {
      const c = ass.citations[i];
      if (isPlainObject(c)) out.push(c, c.metadata);
    }
  }
}

function collectStructuredProvenanceObjects(record) {
  const out = [];
  if (!isPlainObject(record)) return out;
  out.push(record, record.metadata, record.scan_provenance, record.scan_provenance?.metadata, record.runtime, record.runtime_summary);
  if (isPlainObject(record.scan_summary)) {
    out.push(
      record.scan_summary,
      record.scan_summary.metadata,
      record.scan_summary.scan_provenance,
      record.scan_summary.scan_provenance?.metadata,
      record.scan_summary.runtime_summary,
    );
  }
  if (isPlainObject(record.finding)) {
    out.push(
      record.finding,
      record.finding.metadata,
      record.finding.scan_provenance,
      record.finding.scan_provenance?.metadata,
      record.finding.scan_summary,
      record.finding.scan_summary?.metadata,
    );
    pushEvidenceProvenanceObjects(record.finding.evidence, out);
    pushAssessmentProvenanceObjects(record.finding.assessment, out);
  }
  pushEvidenceProvenanceObjects(record.evidence, out);
  pushAssessmentProvenanceObjects(record.assessment, out);
  for (const list of [record.findings, record.warnings]) {
    if (Array.isArray(list)) {
      for (let i = 0; i < list.length; i += 1) {
        const item = list[i];
        if (!isPlainObject(item)) continue;
        out.push(
          item,
          item.metadata,
          item.scan_provenance,
          item.scan_provenance?.metadata,
          item.scan_summary,
          item.scan_summary?.metadata,
        );
        pushEvidenceProvenanceObjects(item.evidence, out);
        pushAssessmentProvenanceObjects(item.assessment, out);
      }
    }
  }
  return out.filter(isPlainObject);
}

function hasMockSignalInObject(obj) {
  if (!isPlainObject(obj)) return false;
  if (
    obj.is_test_or_mock === true ||
    obj.contains_mock_or_test_data === true ||
    obj.mock === true ||
    obj.is_mock === true ||
    obj.synthetic === true ||
    obj.is_synthetic === true
  ) {
    return true;
  }
  const mockRecords = obj.mock_records ?? obj.runtime_summary?.mock_records;
  if (typeof mockRecords === 'number' && Number.isFinite(mockRecords) && mockRecords > 0) {
    return true;
  }
  const originCandidates = [
    obj.data_origin,
    obj.origin,
    obj.scan_provenance?.origin,
    obj.runtime?.origin,
  ];
  return originCandidates.some((val) => {
    const clean = readableText(val).toUpperCase();
    return Boolean(clean && (clean === 'MOCK_SYNTHETIC_TEST' || clean === 'MOCK_TEST' || MOCK_ORIGIN_RE.test(clean)));
  });
}

function validateCaptureProvenance(prov) {
  if (!isPlainObject(prov)) {
    return {
      verified: false,
      captureRecorded: false,
      sourceVerified: false,
      engineSucceeded: false,
      reason: 'MISSING_SCAN_PROVENANCE',
    };
  }
  const hasOriginField = prov.origin !== undefined && prov.origin !== null;
  const provOrigin = hasOriginField ? readableText(prov.origin).toUpperCase() : '';
  const originAcceptable = !hasOriginField || (Boolean(provOrigin) && !UNVERIFIED_PROVENANCE_ORIGIN_RE.test(provOrigin));
  const sourceVerified = prov.source_capture_verified === true;
  const exitCaptureRecorded = prov.exit_capture_verified === true;
  const hasIntExit = typeof prov.recorded_engine_exit === 'number' && Number.isInteger(prov.recorded_engine_exit);
  const engineSucceeded = hasIntExit && prov.recorded_engine_exit === 0;
  const captureRecorded = exitCaptureRecorded && hasIntExit && originAcceptable;

  if (!originAcceptable) {
    return {verified: false, captureRecorded, sourceVerified, engineSucceeded, reason: 'UNVERIFIED_PROVENANCE_ORIGIN'};
  }
  if (!sourceVerified || !exitCaptureRecorded) {
    return {verified: false, captureRecorded, sourceVerified, engineSucceeded, reason: 'UNVERIFIED_CAPTURE_FLAGS'};
  }
  if (!hasIntExit) {
    return {verified: false, captureRecorded: false, sourceVerified, engineSucceeded: false, reason: 'MISSING_RECORDED_ENGINE_EXIT'};
  }
  if (!engineSucceeded) {
    return {verified: false, captureRecorded: true, sourceVerified, engineSucceeded: false, reason: 'ENGINE_EXIT_NONZERO'};
  }
  return {
    verified: true,
    captureRecorded: true,
    sourceVerified: true,
    engineSucceeded: true,
    reason: 'VERIFIED_CAPTURE_PROVENANCE',
  };
}

function collectDeclaredDataOrigins(objects) {
  const origins = [];
  for (let i = 0; i < objects.length; i += 1) {
    const obj = objects[i];
    if (!isPlainObject(obj)) continue;
    for (const candidate of [obj.data_origin, obj.metadata?.data_origin]) {
      if (candidate === undefined || candidate === null) continue;
      if (typeof candidate !== 'string') {
        return {origins, invalid: true};
      }
      const norm = candidate.trim().toUpperCase();
      if (norm) origins.push(norm);
    }
  }
  return {origins, invalid: false};
}

export function classifyDataOrigin(record) {
  const mkUnverified = (reason = 'UNVERIFIED_ORIGIN', flags = {}) => ({
    code: 'UNVERIFIED_ORIGIN',
    label: 'Chưa xác minh nguồn gốc (UNVERIFIED_ORIGIN)',
    tone: 'amber',
    isMockOrTest: false,
    isVerifiedRealScan: false,
    isUnverified: true,
    captureRecorded: Boolean(flags.captureRecorded),
    sourceVerified: Boolean(flags.sourceVerified),
    engineSucceeded: Boolean(flags.engineSucceeded),
    reason,
  });
  if (!isPlainObject(record)) return mkUnverified('INVALID_RECORD');

  // 1. Mock / synthetic detection across all structured backend provenance layers (including evidence.snippets[].metadata).
  const structuredObjects = collectStructuredProvenanceObjects(record);
  if (structuredObjects.some(hasMockSignalInObject)) {
    return {
      code: 'MOCK_SYNTHETIC_TEST',
      label: 'MOCK_SYNTHETIC_TEST',
      tone: 'red',
      isMockOrTest: true,
      isVerifiedRealScan: false,
      isUnverified: true,
      captureRecorded: false,
      sourceVerified: false,
      engineSucceeded: false,
      reason: 'MOCK_OR_SYNTHETIC_DETECTED',
    };
  }

  // 2. Collect declared data_origin values at top level and across components so explicit child contradictions never pass.
  const topDeclared = collectDeclaredDataOrigins([record, record.scan_summary, record.evidence, record.assessment]);
  const componentObjects = [];
  if (isPlainObject(record.finding)) {
    componentObjects.push(record.finding, record.finding.evidence, record.finding.assessment, record.finding.scan_summary);
  }
  for (const list of [record.findings, record.warnings]) {
    if (Array.isArray(list)) {
      for (let i = 0; i < list.length; i += 1) {
        const item = list[i];
        if (!isPlainObject(item)) continue;
        componentObjects.push(item, item.evidence, item.assessment, item.scan_summary);
      }
    }
  }
  const componentDeclared = collectDeclaredDataOrigins(componentObjects);
  if (topDeclared.invalid || componentDeclared.invalid) return mkUnverified('INVALID_DATA_ORIGIN_FIELD');
  const topUnique = [...new Set(topDeclared.origins)];
  if (topUnique.length === 0) return mkUnverified('MISSING_DATA_ORIGIN');
  const uniqueOrigins = [...new Set([...topUnique, ...componentDeclared.origins])];
  if (uniqueOrigins.length > 1) return mkUnverified('CONFLICTING_DATA_ORIGIN');

  const rawOrigin = uniqueOrigins[0];

  // 3. REAL_SCAN must NEVER self-attest: verify capture recorded, source integrity, and clean engine exit === 0.
  if (rawOrigin === 'REAL_SCAN') {
    const provCandidates = [];
    for (const candidate of [
      record.scan_provenance,
      record.scan_summary?.scan_provenance,
      record.evidence?.scan_provenance,
      record.finding?.scan_provenance,
      record.finding?.evidence?.scan_provenance,
      record.finding?.scan_summary?.scan_provenance,
    ]) {
      if (candidate !== undefined && candidate !== null) {
        provCandidates.push(candidate);
      }
    }
    for (const list of [record.findings, record.warnings]) {
      if (Array.isArray(list)) {
        for (const item of list) {
          if (isPlainObject(item)) {
            if (item.scan_provenance !== undefined && item.scan_provenance !== null) provCandidates.push(item.scan_provenance);
            if (item.evidence?.scan_provenance !== undefined && item.evidence?.scan_provenance !== null) provCandidates.push(item.evidence.scan_provenance);
            if (item.scan_summary?.scan_provenance !== undefined && item.scan_summary?.scan_provenance !== null) provCandidates.push(item.scan_summary.scan_provenance);
          }
        }
      }
    }
    if (provCandidates.length === 0) {
      return mkUnverified('MISSING_SCAN_PROVENANCE');
    }
    for (const prov of provCandidates) {
      const check = validateCaptureProvenance(prov);
      if (!check.verified) {
        return mkUnverified(check.reason, check);
      }
    }
    return {
      code: 'REAL_SCAN',
      label: 'REAL_SCAN',
      tone: 'neutral',
      isMockOrTest: false,
      isVerifiedRealScan: true,
      isUnverified: false,
      captureRecorded: true,
      sourceVerified: true,
      engineSucceeded: true,
      reason: 'VERIFIED_CAPTURE_PROVENANCE',
    };
  }

  return {
    code: rawOrigin,
    label: rawOrigin,
    tone: 'amber',
    isMockOrTest: false,
    isVerifiedRealScan: false,
    isUnverified: true,
    captureRecorded: false,
    sourceVerified: false,
    engineSucceeded: false,
    reason: 'NON_REAL_OR_IMPORTED_ORIGIN',
  };
}

export function runtimeVerificationMeta(verified) {
  if (verified === true) {
    return {
      verified: true,
      tone: 'green',
      label: 'Runtime đã xác thực (model_runtime_verified = true)',
    };
  }
  return {
    verified: false,
    tone: 'amber',
    label: 'Chưa xác thực độc lập (model_runtime_verified = false)',
  };
}

export function describeOpengrepHealth(og = {}, recentVerifiedVersion = null) {
  const probeStatus = readableText(og?.probe_status).toUpperCase();
  if (og?.available === true) {
    return {
      code: 'OPENGREP_AVAILABLE',
      tone: 'green',
      label: `Khả dụng (${og.version || og.executable || og.binary || 'opengrep'})`,
      detail: og.resolved_path ? `Đường dẫn: ${og.resolved_path}` : '',
    };
  }
  if (probeStatus === 'NOT_VERIFIED') {
    const recentNote = recentVerifiedVersion
      ? ` Phiên bản OpenGrep từ lượt quét gần nhất: ${recentVerifiedVersion} (tách biệt với health check).`
      : '';
    return {
      code: 'OPENGREP_NOT_VERIFIED',
      tone: 'amber',
      label: 'Chưa xác minh trên /api/health (OPENGREP_NOT_VERIFIED)',
      detail:
        'Endpoint /api/health chủ động không khởi chạy binary OpenGrep để kiểm tra phiên bản; ' +
        'binary được xác minh thực tế khi chạy scan job.' +
        (og.resolved_path ? ` Đường dẫn phát hiện: ${og.resolved_path}.` : '') +
        recentNote,
    };
  }
  if (og?.available === false || probeStatus === 'UNAVAILABLE') {
    return {
      code: 'OPENGREP_UNAVAILABLE',
      tone: 'red',
      label: `Không khả dụng (${og.error || og.executable || og.binary || 'OPENGREP_UNAVAILABLE'})`,
      detail: 'Không tìm thấy hoặc không thể chạy binary OpenGrep trên máy chủ API.',
    };
  }
  return {
    code: 'UNKNOWN',
    tone: 'neutral',
    label: 'API chưa cung cấp',
    detail: '',
  };
}

export function findReportedId(detail) {
  const nested = detail?.finding && typeof detail.finding === 'object' ? detail.finding : {};
  return firstText(detail?.finding_id, detail?.id, nested?.finding_id, nested?.id);
}

const TRACE_ROLE_META = Object.freeze({
  source: {role: 'source', tag: 'SOURCE', label: 'Nguồn dữ liệu (Source)'},
  intermediate: {role: 'intermediate', tag: 'INTERMEDIATE', label: 'Trung gian (Intermediate)'},
  sink: {role: 'sink', tag: 'SINK', label: 'Điểm thực thi (Sink)'},
});

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isPositiveInt(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : '';
}

function validateTraceRange(start, end) {
  if (!isPlainObject(start) || !isPositiveInt(start.line)) return null;
  if (start.col !== undefined && start.col !== null && !isPositiveInt(start.col)) return null;

  const startLine = start.line;
  const startCol = isPositiveInt(start.col) ? start.col : null;
  let endLine = startLine;
  let endCol = null;
  if (end !== undefined) {
    if (!isPlainObject(end) || !isPositiveInt(end.line) || end.line < startLine) return null;
    if (end.col !== undefined && end.col !== null && !isPositiveInt(end.col)) return null;
    if (end.line === startLine && startCol !== null && isPositiveInt(end.col) && end.col < startCol) {
      return null;
    }
    endLine = end.line;
    endCol = isPositiveInt(end.col) ? end.col : null;
  }

  return {startLine, endLine, startCol, endCol};
}

// ---------------------------------------------------------------------------------------------
// File identity, path mappings, and decoupled SHA-256 integrity ledger
//
// File identity, step location, and hash evidence are strictly decoupled:
//   - File identity is grounded independently of display path (exact normalised equality;
//     never suffix, basename, code text, or SHA-256 equality).
//   - Conflicting child `path_mappings` entries are preserved as explicit conflict markers so
//     paths inside a conflicting child prefix NEVER fall back to a parent mapping.
//   - Hash validation & conflict detection run in a file+version+scope ledger independently of
//     step deduplication, so two snippets on the same file/version with different code text
//     cannot hide a SHA-256 conflict, and downstream merge/enrichment can never restore a
//     single hash onto a conflicted file.
//   - Both Finding Detail primary SHA-256 (`resolveFindingSourceHash`), snippet cards
//     (`resolveSnippetHashStatus`), and Dataflow (`analyzeDataflow`) share the exact same
//     File Identity and File Hash Ledger.
// ---------------------------------------------------------------------------------------------

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;

function normalizeValidSha256(value) {
  const clean = nonEmptyString(value);
  if (!clean || !SHA256_HEX_RE.test(clean)) return '';
  return clean.toLowerCase();
}

function resolveHashScope(entry) {
  const raw = nonEmptyString(entry?.hash_scope ?? entry?.sha256_scope ?? entry?.hashScope).toLowerCase();
  return raw || 'file';
}

function resolveSourceVersion(entry, fallbackVersion = 'scan') {
  return firstText(
    entry?.source_version,
    entry?.sourceVersion,
    entry?.revision,
    entry?.commit,
    fallbackVersion,
    'scan',
  );
}

// Structured canonicalizer for Windows/POSIX/UNC/relative source paths.
// Canonicalizes equivalent separators (`\` -> `/`, repeated `/`), leading/internal/trailing `.`
// current-directory segments, and Windows drive-letter casing (`c:/` -> `C:/`) while preserving
// directory/filename case and UNC `//server/share` roots.
// Does NOT blindly collapse `..` segments across potential symlinks or mapping boundaries;
// instead flags `hasParentTraversal` / `hasUnsupportedDriveRelative` explicitly.
function parseStructuredSourcePath(value) {
  const raw = nonEmptyString(value).replaceAll('\\', '/');
  if (!raw) {
    return {
      canonical: '',
      rootPrefix: '',
      segments: [],
      isAbsolute: false,
      hasParentTraversal: false,
      hasUnsupportedDriveRelative: false,
    };
  }

  if (/^[A-Za-z]:(?!\/)/.test(raw)) {
    return {
      canonical: `${raw[0].toUpperCase()}:${raw.slice(2)}`,
      rootPrefix: '',
      segments: [raw],
      isAbsolute: false,
      hasParentTraversal: raw.split('/').includes('..'),
      hasUnsupportedDriveRelative: true,
    };
  }

  let rootPrefix = '';
  let isAbsolute = false;
  let tail = raw;

  if (/^[A-Za-z]:\//.test(raw)) {
    rootPrefix = `${raw[0].toUpperCase()}:/`;
    isAbsolute = true;
    tail = raw.slice(2).replace(/^\/+/, '');
  } else if (raw.startsWith('//') && !raw.startsWith('///')) {
    const uncMatch = /^\/\/([^/]+)\/+([^/]+)(?:\/+(.*))?$/.exec(raw);
    if (uncMatch) {
      rootPrefix = `//${uncMatch[1]}/${uncMatch[2]}`;
      isAbsolute = true;
      tail = uncMatch[3] || '';
    } else {
      rootPrefix = '/';
      isAbsolute = true;
      tail = raw.replace(/^\/+/, '');
    }
  } else if (raw.startsWith('/')) {
    rootPrefix = '/';
    isAbsolute = true;
    tail = raw.replace(/^\/+/, '');
  }

  const rawSegments = tail ? tail.split(/\/+/) : [];
  const segments = [];
  let hasParentTraversal = rootPrefix.startsWith('//')
    && rootPrefix.slice(2).split('/').some((part) => part === '.' || part === '..');
  let hasUnsupportedDriveRelative = false;

  for (const seg of rawSegments) {
    if (!seg || seg === '.') continue;
    if (seg === '..') hasParentTraversal = true;
    if (!isAbsolute && segments.length === 0 && /^[A-Za-z]:/.test(seg)) {
      hasUnsupportedDriveRelative = true;
    }
    segments.push(seg);
  }

  let canonical = '';
  if (isAbsolute) {
    if (rootPrefix === '/' || /^[A-Za-z]:\/$/.test(rootPrefix)) {
      canonical = segments.length > 0 ? `${rootPrefix}${segments.join('/')}` : rootPrefix;
    } else {
      canonical = segments.length > 0 ? `${rootPrefix}/${segments.join('/')}` : rootPrefix;
    }
  } else if (hasUnsupportedDriveRelative && segments.length > 0 && /^[A-Za-z]:$/.test(segments[0])) {
    canonical = `./${segments.join('/')}`;
  } else {
    canonical = segments.join('/');
  }

  return {
    canonical,
    rootPrefix,
    segments,
    isAbsolute,
    hasParentTraversal,
    hasUnsupportedDriveRelative,
  };
}

function normalizeTracePath(value) {
  return parseStructuredSourcePath(value).canonical;
}

function isAbsoluteTracePath(p) {
  return /^(\/|[A-Za-z]:\/)/.test(p);
}

function hasUnsafePathSegments(value) {
  const parsed = parseStructuredSourcePath(value);
  return Boolean(parsed.hasParentTraversal || parsed.hasUnsupportedDriveRelative);
}

// Used ONLY for asymmetric conflict detection on paths containing `..`:
// if lexical collapse hits a mapping conflict or disputed candidate, preserve `MAPPING_CONFLICT`;
// never used to grant `SNAPSHOT_MATCHED` or merge files across unverified `..` segments.
function tryCollapseDotDotForConflictCheck(value) {
  const parsed = parseStructuredSourcePath(value);
  if (!parsed.canonical || parsed.hasUnsupportedDriveRelative) {
    return {escapedRoot: true, collapsed: ''};
  }
  if (!parsed.hasParentTraversal) {
    return {escapedRoot: false, collapsed: parsed.canonical};
  }
  const stack = [];
  for (const seg of parsed.segments) {
    if (seg === '..') {
      if (stack.length === 0) return {escapedRoot: true, collapsed: ''};
      stack.pop();
    } else {
      stack.push(seg);
    }
  }
  if (parsed.isAbsolute) {
    if (parsed.rootPrefix === '/' || /^[A-Za-z]:\/$/.test(parsed.rootPrefix)) {
      return {
        escapedRoot: false,
        collapsed: stack.length > 0 ? `${parsed.rootPrefix}${stack.join('/')}` : parsed.rootPrefix,
      };
    }
    return {
      escapedRoot: false,
      collapsed: stack.length > 0 ? `${parsed.rootPrefix}/${stack.join('/')}` : parsed.rootPrefix,
    };
  }
  return {escapedRoot: false, collapsed: stack.join('/')};
}

function normalizeRootPath(value) {
  const parsed = parseStructuredSourcePath(value);
  if (!parsed.canonical || !parsed.isAbsolute || parsed.hasParentTraversal || parsed.hasUnsupportedDriveRelative) {
    return '';
  }
  return parsed.canonical;
}

function isDriveOrUnixRoot(prefix) {
  return prefix === '/' || /^[A-Za-z]:\/$/.test(prefix);
}

function pathMatchesPrefix(pathValue, prefix) {
  if (!pathValue || !prefix) return false;
  if (isDriveOrUnixRoot(prefix)) return pathValue.startsWith(prefix);
  return pathValue === prefix || pathValue.startsWith(`${prefix}/`);
}

function rewriteWithPrefix(pathValue, from, to) {
  if (pathValue === from) return normalizeTracePath(to);
  if (isDriveOrUnixRoot(from)) {
    const tail = pathValue.slice(from.length);
    return normalizeTracePath(to.endsWith('/') ? `${to}${tail}` : `${to}/${tail}`);
  }
  const suffix = pathValue.slice(from.length); // begins with '/'
  return normalizeTracePath(to.endsWith('/') ? `${to}${suffix.slice(1)}` : `${to}${suffix}`);
}

function stripRootPrefix(absPath, rootPath) {
  if (!absPath || !rootPath || absPath === rootPath || !pathMatchesPrefix(absPath, rootPath)) return '';
  if (isDriveOrUnixRoot(rootPath)) return absPath.slice(rootPath.length);
  return absPath.slice(rootPath.length + 1);
}

function joinRootAndRel(rootPath, relPath) {
  if (!rootPath) return normalizeTracePath(relPath);
  if (!relPath) return normalizeTracePath(rootPath);
  return normalizeTracePath(rootPath.endsWith('/') ? `${rootPath}${relPath}` : `${rootPath}/${relPath}`);
}

function parsePathMappings(rawMappings) {
  if (!Array.isArray(rawMappings)) return [];
  const targetsByFrom = new Map();
  for (const entry of rawMappings) {
    if (!isPlainObject(entry)) continue;
    const from = normalizeRootPath(entry.from);
    const to = normalizeRootPath(entry.to);
    if (!from || !to) continue;
    if (!targetsByFrom.has(from)) targetsByFrom.set(from, new Set());
    targetsByFrom.get(from).add(to);
  }
  // Preserve conflicting prefixes in the sorted table (longest prefix first) so a conflicting
  // child mapping blocks fallback to any broader parent mapping.
  return [...targetsByFrom.entries()]
    .map(([from, targetSet]) => {
      const targets = [...targetSet].sort();
      return {
        from,
        to: targets.length === 1 ? targets[0] : '',
        conflicting: targets.length > 1,
        targets,
      };
    })
    .sort((a, b) => (b.from.length - a.from.length) || a.from.localeCompare(b.from));
}

function absEndsWithRelative(absPath, relPath) {
  if (!absPath || !relPath || !isAbsoluteTracePath(absPath) || isAbsoluteTracePath(relPath)) return false;
  if (absPath.endsWith(`/${relPath}`)) return true;
  if (/^[A-Za-z]:\//.test(absPath) && absPath.length === 3 + relPath.length && absPath.slice(3) === relPath) {
    return true;
  }
  return false;
}

function deriveRootFromAbsAndRel(absPath, relPath) {
  if (!absEndsWithRelative(absPath, relPath)) return '';
  if (absPath.endsWith(`/${relPath}`)) {
    const prefix = absPath.slice(0, absPath.length - relPath.length - 1);
    if (!prefix) return '/';
    if (/^[A-Za-z]:$/.test(prefix)) return `${prefix.toUpperCase()}/`;
    return normalizeRootPath(prefix);
  }
  return `${absPath[0].toUpperCase()}:/`;
}

function applyPathMappingsDetailed(pathValue, mappings) {
  const normVal = normalizeTracePath(pathValue);
  if (!normVal || !isAbsoluteTracePath(normVal) || !mappings.length) {
    return {
      path: normVal,
      mapped: false,
      ambiguous: false,
      matchedPrefix: '',
      matchedTarget: '',
      conflictingTargets: [],
    };
  }

  // If `normVal` contains `..`, NEVER rewrite it into a clean mapped path across a mapping
  // boundary; however, DO preserve `ambiguous: true` if either `normVal` or its lexical
  // collapse hits a conflicting mapping prefix.
  if (hasUnsafePathSegments(normVal)) {
    for (const entry of mappings) {
      if (!pathMatchesPrefix(normVal, entry.from)) continue;
      if (entry.conflicting) {
        return {
          path: normVal,
          mapped: false,
          ambiguous: true,
          matchedPrefix: entry.from,
          matchedTarget: '',
          conflictingTargets: [...entry.targets],
        };
      }
      break;
    }
    const collapsed = tryCollapseDotDotForConflictCheck(normVal);
    if (!collapsed.escapedRoot && collapsed.collapsed && !hasUnsafePathSegments(collapsed.collapsed)) {
      const collapsedRes = applyPathMappingsDetailed(collapsed.collapsed, mappings);
      if (collapsedRes.ambiguous) {
        return {
          path: collapsed.collapsed,
          mapped: false,
          ambiguous: true,
          matchedPrefix: collapsedRes.matchedPrefix,
          matchedTarget: '',
          conflictingTargets: [...collapsedRes.conflictingTargets],
        };
      }
    }
    return {
      path: normVal,
      mapped: false,
      ambiguous: false,
      matchedPrefix: '',
      matchedTarget: '',
      conflictingTargets: [],
    };
  }

  for (const entry of mappings) {
    if (!pathMatchesPrefix(normVal, entry.from)) continue;
    if (entry.conflicting) {
      // Most specific matching prefix has conflicting targets: stop and do NOT fall back to parent.
      return {
        path: normVal,
        mapped: false,
        ambiguous: true,
        matchedPrefix: entry.from,
        matchedTarget: '',
        conflictingTargets: [...entry.targets],
      };
    }
    return {
      path: rewriteWithPrefix(normVal, entry.from, entry.to),
      mapped: true,
      ambiguous: false,
      matchedPrefix: entry.from,
      matchedTarget: entry.to,
      conflictingTargets: [],
    };
  }
  return {
    path: normVal,
    mapped: false,
    ambiguous: false,
    matchedPrefix: '',
    matchedTarget: '',
    conflictingTargets: [],
  };
}

function resolveEffectiveMappedRoot(mappedAbs, normRoot, fullMapRes, pathMappings) {
  if (!mappedAbs || !isAbsoluteTracePath(mappedAbs)) return '';
  if (normRoot) {
    const rootMapRes = applyPathMappingsDetailed(normRoot, pathMappings);
    if (!rootMapRes.ambiguous) {
      const mappedRoot = normalizeRootPath(rootMapRes.path);
      if (mappedRoot && mappedAbs !== mappedRoot && pathMatchesPrefix(mappedAbs, mappedRoot)) {
        return mappedRoot;
      }
    }
  }
  if (fullMapRes?.mapped && fullMapRes.matchedTarget
    && mappedAbs !== fullMapRes.matchedTarget && pathMatchesPrefix(mappedAbs, fullMapRes.matchedTarget)) {
    return fullMapRes.matchedTarget;
  }
  return '';
}

// Validates that an absolute path (`absPath`) genuinely belongs under an entity's declared
// `normRoot` — either directly inside `normRoot`, via a valid non-conflicting mapping of
// `normRoot` (not shadowed by a child mapping), or via a unique valid child mapping under
// `normRoot`. Preserves `MAPPING_CONFLICT` whenever a conflicting mapping at or under
// `normRoot` targets `absPath`, and flags `OUTSIDE_ROOT` otherwise.
function validateAbsoluteAgainstDeclaredRoot(absPath, normRoot, pathMappings) {
  const normAbs = normalizeTracePath(absPath);
  const cleanRoot = normalizeRootPath(normRoot);
  if (!normAbs || !cleanRoot || !isAbsoluteTracePath(normAbs)) {
    return {status: 'OUTSIDE_ROOT', effectiveMappedRoot: '', effectiveRel: ''};
  }
  if (hasUnsafePathSegments(normAbs) || hasUnsafePathSegments(cleanRoot)) {
    return {status: 'UNSAFE', effectiveMappedRoot: '', effectiveRel: ''};
  }

  const absMapRes = applyPathMappingsDetailed(normAbs, pathMappings);
  if (absMapRes.ambiguous) {
    return {
      status: 'MAPPING_CONFLICT',
      rawFullPath: normAbs,
      conflictingTargets: [...absMapRes.conflictingTargets],
    };
  }
  const mappedAbs = absMapRes.path;

  // 1) Direct containment inside unmapped `cleanRoot`.
  if (normAbs !== cleanRoot && pathMatchesPrefix(normAbs, cleanRoot)) {
    const effectiveMappedRoot = resolveEffectiveMappedRoot(mappedAbs, cleanRoot, absMapRes, pathMappings);
    return {
      status: 'VALID',
      effectiveMappedRoot,
      effectiveRel: effectiveMappedRoot ? stripRootPrefix(mappedAbs, effectiveMappedRoot) : '',
    };
  }

  // 2) Conflicting mapping at or below `cleanRoot` whose targets include `mappedAbs`:
  //    preserve `MAPPING_CONFLICT` rather than downgrading to `OUTSIDE_ROOT`.
  for (const entry of pathMappings) {
    if (!entry.conflicting || !pathMatchesPrefix(entry.from, cleanRoot)) continue;
    for (const target of entry.targets) {
      if (mappedAbs !== target && pathMatchesPrefix(mappedAbs, target)) {
        return {
          status: 'MAPPING_CONFLICT',
          rawFullPath: rewriteWithPrefix(mappedAbs, target, entry.from),
          conflictingTargets: [...entry.targets],
        };
      }
    }
  }

  // 3) Conflicting mapping covering `cleanRoot` (or an ancestor of `cleanRoot`).
  const rootMapRes = applyPathMappingsDetailed(cleanRoot, pathMappings);
  if (rootMapRes.ambiguous && rootMapRes.matchedPrefix) {
    for (const target of rootMapRes.conflictingTargets) {
      const projectedRoot = rewriteWithPrefix(cleanRoot, rootMapRes.matchedPrefix, target);
      if (projectedRoot && mappedAbs !== projectedRoot && pathMatchesPrefix(mappedAbs, projectedRoot)) {
        return {
          status: 'MAPPING_CONFLICT',
          rawFullPath: rewriteWithPrefix(mappedAbs, projectedRoot, cleanRoot),
          conflictingTargets: [...rootMapRes.conflictingTargets],
        };
      }
    }
  }

  // 4) Unique valid child mapping under `cleanRoot` whose target contains `mappedAbs`
  //    and round-trips forward cleanly without ambiguity or shadowing.
  const validChildMatches = [];
  for (const entry of pathMappings) {
    if (entry.conflicting || entry.from === cleanRoot || !pathMatchesPrefix(entry.from, cleanRoot)) continue;
    if (!entry.to || mappedAbs === entry.to || !pathMatchesPrefix(mappedAbs, entry.to)) continue;
    const candidateRaw = rewriteWithPrefix(mappedAbs, entry.to, entry.from);
    const fwdMap = applyPathMappingsDetailed(candidateRaw, pathMappings);
    if (!fwdMap.ambiguous && fwdMap.mapped && fwdMap.matchedPrefix === entry.from && fwdMap.path === mappedAbs) {
      validChildMatches.push({entry, candidateRaw});
    }
  }
  if (validChildMatches.length === 1) {
    const {entry} = validChildMatches[0];
    const effectiveMappedRoot = resolveEffectiveMappedRoot(
      mappedAbs,
      cleanRoot,
      {mapped: true, matchedTarget: entry.to},
      pathMappings,
    );
    return {
      status: 'VALID',
      effectiveMappedRoot,
      effectiveRel: effectiveMappedRoot ? stripRootPrefix(mappedAbs, effectiveMappedRoot) : '',
    };
  }
  if (validChildMatches.length > 1) {
    return {status: 'OUTSIDE_ROOT', effectiveMappedRoot: '', effectiveRel: ''};
  }

  // 5) Mapped `cleanRoot` containment: verify forward-mapping `cleanRoot + relUnderMapped`
  //    neither hits a conflicting child mapping nor gets shadowed by a different child mapping.
  if (!rootMapRes.ambiguous) {
    const mappedRoot = normalizeRootPath(rootMapRes.path);
    if (mappedRoot && mappedAbs !== mappedRoot && pathMatchesPrefix(mappedAbs, mappedRoot)) {
      const relUnderMapped = stripRootPrefix(mappedAbs, mappedRoot);
      const candidateRaw = joinRootAndRel(cleanRoot, relUnderMapped);
      const fwdMap = applyPathMappingsDetailed(candidateRaw, pathMappings);
      if (fwdMap.ambiguous) {
        return {
          status: 'MAPPING_CONFLICT',
          rawFullPath: candidateRaw,
          conflictingTargets: [...fwdMap.conflictingTargets],
        };
      }
      if (fwdMap.path === mappedAbs) {
        return {
          status: 'VALID',
          effectiveMappedRoot: mappedRoot,
          effectiveRel: relUnderMapped,
        };
      }
    }
  }

  return {status: 'OUTSIDE_ROOT', effectiveMappedRoot: '', effectiveRel: ''};
}

// Unified path input classifier: NEVER assumes `path` is relative or only `raw_path` is absolute,
// and NEVER ignores `root + relativePath` or `root + absolutePath` provenance constraints.
// Detects mapping conflicts on the full source path AND contradictory `(path, raw_path, root)`
// combinations before any downstream ledger lookup.
function classifyEntityPathInputs({declaredPath, rawPath, declaredRoot}, pathMappings) {
  const normPath = normalizeTracePath(declaredPath);
  const normRaw = normalizeTracePath(rawPath);
  const normRoot = normalizeRootPath(declaredRoot);
  const pathIsAbs = Boolean(normPath && isAbsoluteTracePath(normPath));
  const rawIsAbs = Boolean(normRaw && isAbsoluteTracePath(normRaw));

  let pathConflict = false;
  let rootMappingConflict = null;
  let explicitRawAbs = '';
  let declaredRel = '';
  const absoluteCandidates = [];

  if (pathIsAbs) absoluteCandidates.push(normPath);
  if (rawIsAbs) absoluteCandidates.push(normRaw);

  // Determine the relative path candidate (if any) BEFORE resolving absolute candidates so
  // `normRoot + rel` is ALWAYS evaluated against `path_mappings` on the full source path.
  const relCandidate = (!pathIsAbs && normPath)
    ? normPath
    : (!rawIsAbs && normRaw ? normRaw : '');

  let rootFullMapped = null;
  if (normRoot && relCandidate) {
    const rawRootFull = joinRootAndRel(normRoot, relCandidate);
    const rootFullMapRes = applyPathMappingsDetailed(rawRootFull, pathMappings);
    if (rootFullMapRes.ambiguous) {
      // Conflicting mapping on `root + relativePath` MUST be preserved even when `raw_path` is present.
      rootMappingConflict = {
        rawFullPath: rawRootFull,
        conflictingTargets: [...rootFullMapRes.conflictingTargets],
      };
    } else {
      rootFullMapped = {rawFullPath: rawRootFull, mappedPath: rootFullMapRes.path, mapRes: rootFullMapRes};
    }
  }

  if (pathIsAbs && rawIsAbs) {
    const mapPath = applyPathMappingsDetailed(normPath, pathMappings);
    const mapRaw = applyPathMappingsDetailed(normRaw, pathMappings);
    if (normPath !== normRaw && (mapPath.ambiguous || mapRaw.ambiguous || mapPath.path !== mapRaw.path)) {
      pathConflict = true;
    } else {
      explicitRawAbs = normRaw;
    }
  } else if (rawIsAbs && normPath && !pathIsAbs) {
    const mapRaw = applyPathMappingsDetailed(normRaw, pathMappings);
    if (rootMappingConflict) {
      explicitRawAbs = normRaw;
      declaredRel = normPath;
    } else if (rootFullMapped) {
      if (mapRaw.ambiguous) {
        rootMappingConflict = {rawFullPath: normRaw, conflictingTargets: [...mapRaw.conflictingTargets]};
      } else if (mapRaw.path !== rootFullMapped.mappedPath) {
        pathConflict = true;
      } else {
        explicitRawAbs = normRaw;
        declaredRel = normPath;
      }
    } else {
      const endsUnmapped = absEndsWithRelative(normRaw, normPath);
      const endsMapped = !mapRaw.ambiguous && absEndsWithRelative(mapRaw.path, normPath);
      if (!endsUnmapped && !endsMapped) {
        pathConflict = true;
      } else {
        explicitRawAbs = normRaw;
        declaredRel = normPath;
      }
    }
  } else if (pathIsAbs && normRaw && !rawIsAbs) {
    const mapPath = applyPathMappingsDetailed(normPath, pathMappings);
    if (rootMappingConflict) {
      explicitRawAbs = normPath;
      declaredRel = normRaw;
    } else if (rootFullMapped) {
      if (mapPath.ambiguous) {
        rootMappingConflict = {rawFullPath: normPath, conflictingTargets: [...mapPath.conflictingTargets]};
      } else if (mapPath.path !== rootFullMapped.mappedPath) {
        pathConflict = true;
      } else {
        explicitRawAbs = normPath;
        declaredRel = normRaw;
      }
    } else {
      const endsUnmapped = absEndsWithRelative(normPath, normRaw);
      const endsMapped = !mapPath.ambiguous && absEndsWithRelative(mapPath.path, normRaw);
      if (!endsUnmapped && !endsMapped) {
        pathConflict = true;
      } else {
        explicitRawAbs = normPath;
        declaredRel = normRaw;
      }
    }
  } else if (!pathIsAbs && !rawIsAbs && normPath && normRaw) {
    if (normPath !== normRaw) {
      pathConflict = true;
    } else {
      declaredRel = normPath;
    }
  } else if (pathIsAbs) {
    explicitRawAbs = normPath;
  } else if (rawIsAbs) {
    explicitRawAbs = normRaw;
  } else {
    declaredRel = normPath || normRaw;
  }

  // When an entity declares BOTH `root` and an absolute path without a relative path,
  // verify that the absolute path actually belongs to `root` (directly or via valid `path_mappings`).
  let validatedAbsRoot = null;
  let outsideRootCandidate = '';
  if (!pathConflict && !rootMappingConflict && normRoot && explicitRawAbs && !declaredRel) {
    const rootCheck = validateAbsoluteAgainstDeclaredRoot(explicitRawAbs, normRoot, pathMappings);
    if (rootCheck.status === 'MAPPING_CONFLICT') {
      rootMappingConflict = {
        rawFullPath: rootCheck.rawFullPath,
        conflictingTargets: [...rootCheck.conflictingTargets],
      };
    } else if (rootCheck.status === 'OUTSIDE_ROOT') {
      outsideRootCandidate = explicitRawAbs;
      pathConflict = true;
      explicitRawAbs = '';
    } else if (rootCheck.status === 'VALID') {
      validatedAbsRoot = rootCheck;
    }
  }

  return {
    normPath,
    normRaw,
    normRoot,
    explicitRawAbs,
    declaredRel,
    pathConflict,
    rootMappingConflict,
    rootFullMapped,
    validatedAbsRoot,
    outsideRootCandidate,
    absoluteCandidates,
  };
}

function collectRawTracePaths(rawTrace, out) {
  if (!isPlainObject(rawTrace)) return;
  const visitNode = (node, depth = 0) => {
    if (!node || depth > 16) return;
    if (Array.isArray(node) && node.length === 2 && node[0] === 'CliLoc') {
      const payload = node[1];
      if (Array.isArray(payload) && payload.length === 2 && isPlainObject(payload[0])) {
        const p = normalizeTracePath(payload[0].path);
        if (p) out.push(p);
      }
      return;
    }
    if (Array.isArray(node) && node.length === 2 && node[0] === 'CliCall') {
      const payload = node[1];
      if (Array.isArray(payload) && payload.length === 3) {
        const [callSite, callSteps, inner] = payload;
        if (Array.isArray(callSite) && callSite.length === 2 && isPlainObject(callSite[0])) {
          const p = normalizeTracePath(callSite[0].path);
          if (p) out.push(p);
        }
        if (Array.isArray(callSteps)) {
          callSteps.forEach((st) => {
            if (isPlainObject(st) && isPlainObject(st.location)) {
              const p = normalizeTracePath(st.location.path);
              if (p) out.push(p);
            }
          });
        }
        visitNode(inner, depth + 1);
      }
    }
  };
  visitNode(rawTrace.taint_source);
  if (Array.isArray(rawTrace.intermediate_vars)) {
    rawTrace.intermediate_vars.forEach((iv) => {
      if (isPlainObject(iv) && isPlainObject(iv.location)) {
        const p = normalizeTracePath(iv.location.path);
        if (p) out.push(p);
      }
    });
  }
  visitNode(rawTrace.taint_sink);
}

function buildPathContext(evidence, detail = null) {
  const pathMappings = parsePathMappings(evidence.path_mappings);
  const declaredRoots = new Set();
  const rawRootsByMappedRoot = new Map();
  const findingDisputedAbsoluteCandidates = new Map();
  const findingDisputedRelativePaths = new Map();
  const findingPathConflictedAbsoluteCandidates = new Set();
  const observedAbsoluteRecords = [];
  const rawToRelative = new Map();
  const absToProvenRoot = new Map();
  const conflictingRawPaths = new Set();
  let hasAmbiguousRootMapping = false;
  let hasContradictoryPathPair = false;

  const addPathConflictedAbs = (candidatePath) => {
    const normAbs = normalizeTracePath(candidatePath);
    if (!normAbs || !isAbsoluteTracePath(normAbs) || hasUnsafePathSegments(normAbs)) return;
    findingPathConflictedAbsoluteCandidates.add(normAbs);
    const mappedRes = applyPathMappingsDetailed(normAbs, pathMappings);
    if (!mappedRes.ambiguous && mappedRes.path && isAbsoluteTracePath(mappedRes.path)) {
      findingPathConflictedAbsoluteCandidates.add(mappedRes.path);
    }
  };

  const recordFindingPathConflictedCandidates = (classified) => {
    if (!classified?.pathConflict) return;
    for (const cand of classified.absoluteCandidates) {
      if (cand) addPathConflictedAbs(cand);
    }
    if (classified.rootFullMapped?.mappedPath) {
      addPathConflictedAbs(classified.rootFullMapped.mappedPath);
    }
  };

  const recordProvenanceClaim = (mappedAbs, effectiveMappedRoot, effectiveRel) => {
    if (!mappedAbs || !isAbsoluteTracePath(mappedAbs)) return;
    if (effectiveMappedRoot) {
      const prevRoot = absToProvenRoot.get(mappedAbs);
      if (prevRoot !== undefined && prevRoot !== effectiveMappedRoot) {
        conflictingRawPaths.add(mappedAbs);
      } else {
        absToProvenRoot.set(mappedAbs, effectiveMappedRoot);
      }
    }
    if (effectiveRel && !isAbsoluteTracePath(effectiveRel)) {
      const prevRel = rawToRelative.get(mappedAbs);
      if (prevRel !== undefined && prevRel !== effectiveRel) {
        conflictingRawPaths.add(mappedAbs);
      } else {
        rawToRelative.set(mappedAbs, effectiveRel);
      }
    }
  };

  const addDisputedAbs = (candidatePath, conflictInfo) => {
    const normAbs = normalizeTracePath(candidatePath);
    if (!normAbs || !isAbsoluteTracePath(normAbs) || hasUnsafePathSegments(normAbs)) return;
    findingDisputedAbsoluteCandidates.set(normAbs, conflictInfo);
    const mappedRes = applyPathMappingsDetailed(normAbs, pathMappings);
    if (!mappedRes.ambiguous && mappedRes.path && isAbsoluteTracePath(mappedRes.path)) {
      findingDisputedAbsoluteCandidates.set(mappedRes.path, conflictInfo);
    }
  };

  const recordFindingDisputedCandidate = (classified) => {
    if (!classified?.rootMappingConflict) return;
    const rawFullPath = normalizeTracePath(classified.rootMappingConflict.rawFullPath);
    const conflictInfo = {
      rawFullPath,
      conflictingTargets: [...classified.rootMappingConflict.conflictingTargets],
    };
    if (classified.declaredRel && !isAbsoluteTracePath(classified.declaredRel)) {
      findingDisputedRelativePaths.set(classified.declaredRel, conflictInfo);
    }
    // Project the full equivalence class of candidate paths for this unresolved mapping conflict:
    // 1) the unmapped source path itself;
    // 2) every conflicting child target rewrite (`C:/checkout-A/...`, `C:/checkout-B/...`);
    // 3) any broader non-conflicting parent rewrite (`C:/mount/branch/...`);
    // 4) any explicit absolute candidate (`evidence.raw_path` / `path`) and its mapped form.
    if (rawFullPath && isAbsoluteTracePath(rawFullPath)) {
      addDisputedAbs(rawFullPath, conflictInfo);
      const fullMap = applyPathMappingsDetailed(rawFullPath, pathMappings);
      if (fullMap.ambiguous && fullMap.matchedPrefix) {
        for (const target of fullMap.conflictingTargets) {
          addDisputedAbs(rewriteWithPrefix(rawFullPath, fullMap.matchedPrefix, target), conflictInfo);
        }
        for (const entry of pathMappings) {
          if (entry.conflicting || entry.from === fullMap.matchedPrefix) continue;
          if (pathMatchesPrefix(rawFullPath, entry.from)) {
            addDisputedAbs(rewriteWithPrefix(rawFullPath, entry.from, entry.to), conflictInfo);
          }
        }
      }
    }
    if (classified.explicitRawAbs) addDisputedAbs(classified.explicitRawAbs, conflictInfo);
    for (const cand of classified.absoluteCandidates) {
      if (cand) addDisputedAbs(cand, conflictInfo);
    }
  };

  const recordRootMapping = (rawRootNorm) => {
    const cleanRawRoot = normalizeRootPath(rawRootNorm);
    if (!cleanRawRoot) return;
    const mappedRes = applyPathMappingsDetailed(cleanRawRoot, pathMappings);
    if (mappedRes.ambiguous) {
      hasAmbiguousRootMapping = true;
      return;
    }
    const mappedRoot = normalizeRootPath(mappedRes.path);
    if (!mappedRoot) return;
    declaredRoots.add(mappedRoot);
    if (!rawRootsByMappedRoot.has(mappedRoot)) rawRootsByMappedRoot.set(mappedRoot, new Set());
    rawRootsByMappedRoot.get(mappedRoot).add(cleanRawRoot);
  };

  const recordAbsoluteCandidate = (absPath) => {
    const normAbs = normalizeTracePath(absPath);
    if (!normAbs || !isAbsoluteTracePath(normAbs)) return;
    const mappedRes = applyPathMappingsDetailed(normAbs, pathMappings);
    observedAbsoluteRecords.push({
      rawAbs: normAbs,
      mappedAbs: mappedRes.ambiguous ? normAbs : mappedRes.path,
      ambiguous: mappedRes.ambiguous,
    });
  };

  const registerEntity = (pathValue, rawValue, rootValue, {isFinding = false} = {}) => {
    if (rootValue) recordRootMapping(rootValue);

    const classified = classifyEntityPathInputs({
      declaredPath: pathValue,
      rawPath: rawValue,
      declaredRoot: rootValue,
    }, pathMappings);

    classified.absoluteCandidates.forEach(recordAbsoluteCandidate);

    if (classified.rootMappingConflict) {
      // Preserve the finding's exact disputed absolute candidate(s) within this single evidence
      // context so snippets, snapshots, and raw_trace entries referencing that same disputed path
      // in absolute-only form cannot bypass the unresolved mapping conflict.
      if (isFinding) recordFindingDisputedCandidate(classified);
      // Do not derive a trusted root from an absolute path that bypasses a conflicting root+path mapping.
      return;
    }

    if (classified.pathConflict) {
      if (!rootValue && evRoot) {
        const withEvRoot = classifyEntityPathInputs({
          declaredPath: pathValue,
          rawPath: rawValue,
          declaredRoot: evRoot,
        }, pathMappings);
        if (!withEvRoot.pathConflict && !withEvRoot.rootMappingConflict) {
          return;
        }
      }
      // Even when an entity's own `raw_path` contradicts its `root + relativePath`,
      // preserve its `(root, relativePath)` provenance claim on `rootFullMapped` so a
      // contradictory `raw_path` on a competing snippet can NEVER silence a root conflict.
      if (!hasUnsafePathSegments(pathValue) && !hasUnsafePathSegments(rootValue)
        && classified.normRoot && classified.rootFullMapped?.mappedPath) {
        const mappedAbs = classified.rootFullMapped.mappedPath;
        if (isAbsoluteTracePath(mappedAbs)) {
          const effectiveMappedRoot = resolveEffectiveMappedRoot(
            mappedAbs,
            classified.normRoot,
            classified.rootFullMapped.mapRes,
            pathMappings,
          );
          const effectiveRel = effectiveMappedRoot
            ? stripRootPrefix(mappedAbs, effectiveMappedRoot)
            : classified.declaredRel;
          recordProvenanceClaim(mappedAbs, effectiveMappedRoot, effectiveRel);
        }
      }
      if (isFinding) {
        recordFindingPathConflictedCandidates(classified);
      } else if (classified.outsideRootCandidate) {
        addPathConflictedAbs(classified.outsideRootCandidate);
      }
      hasContradictoryPathPair = true;
      return;
    }

    if (hasUnsafePathSegments(pathValue) || hasUnsafePathSegments(rawValue) || hasUnsafePathSegments(rootValue)) {
      return;
    }

    // Record canonical provenance claims `(mappedAbs -> effectiveMappedRoot, effectiveRel)`
    // uniformly whether `raw_path` is present OR omitted (`root + relativePath`), so adding
    // or removing a redundant `raw_path` NEVER alters provenance conflict detection.
    if (classified.explicitRawAbs) {
      const rawMapRes = applyPathMappingsDetailed(classified.explicitRawAbs, pathMappings);
      if (rawMapRes.ambiguous) {
        // Never derive a trusted source root from a path under a conflicting mapping prefix.
        return;
      }
      const mappedAbs = rawMapRes.path;
      const rel = classified.declaredRel;
      if (mappedAbs && isAbsoluteTracePath(mappedAbs)) {
        if (classified.normRoot && rel && !isAbsoluteTracePath(rel)) {
          const effectiveMappedRoot = resolveEffectiveMappedRoot(
            mappedAbs,
            classified.normRoot,
            classified.rootFullMapped?.mapRes || rawMapRes,
            pathMappings,
          );
          const effectiveRel = effectiveMappedRoot ? stripRootPrefix(mappedAbs, effectiveMappedRoot) : rel;
          recordProvenanceClaim(mappedAbs, effectiveMappedRoot, effectiveRel);
        } else if (classified.normRoot) {
          const effectiveMappedRoot = classified.validatedAbsRoot?.effectiveMappedRoot
            || resolveEffectiveMappedRoot(mappedAbs, classified.normRoot, rawMapRes, pathMappings);
          const effectiveRel = classified.validatedAbsRoot?.effectiveRel
            || (effectiveMappedRoot ? stripRootPrefix(mappedAbs, effectiveMappedRoot) : '');
          recordProvenanceClaim(mappedAbs, effectiveMappedRoot, effectiveRel);
        } else if (rel && !isAbsoluteTracePath(rel)) {
          const derivedMappedRoot = deriveRootFromAbsAndRel(mappedAbs, rel);
          const derivedRawRoot = deriveRootFromAbsAndRel(classified.explicitRawAbs, rel);
          recordProvenanceClaim(mappedAbs, derivedMappedRoot, rel);
          if (derivedMappedRoot) {
            declaredRoots.add(derivedMappedRoot);
            if (!rawRootsByMappedRoot.has(derivedMappedRoot)) rawRootsByMappedRoot.set(derivedMappedRoot, new Set());
            rawRootsByMappedRoot.get(derivedMappedRoot).add(derivedRawRoot || derivedMappedRoot);
          }
        }
      }
    } else if (classified.normRoot && classified.declaredRel && !isAbsoluteTracePath(classified.declaredRel) && classified.rootFullMapped) {
      const mappedAbs = classified.rootFullMapped.mappedPath;
      if (mappedAbs && isAbsoluteTracePath(mappedAbs)) {
        const effectiveMappedRoot = resolveEffectiveMappedRoot(
          mappedAbs,
          classified.normRoot,
          classified.rootFullMapped.mapRes,
          pathMappings,
        );
        const effectiveRel = effectiveMappedRoot
          ? stripRootPrefix(mappedAbs, effectiveMappedRoot)
          : classified.declaredRel;
        recordProvenanceClaim(mappedAbs, effectiveMappedRoot, effectiveRel);
      }
    }
  };

  // Register finding-level paths (including detail.file_path when provided alongside evidence)
  const evRoot = evidence.root ?? evidence.source_root;
  if (detail && nonEmptyString(detail.file_path) && nonEmptyString(evidence.path)) {
    const detailPathNorm = normalizeTracePath(detail.file_path);
    const evPathNorm = normalizeTracePath(evidence.path);
    if (detailPathNorm !== evPathNorm) {
      // Check if one is absolute and the other is a consistent relative path; otherwise flag conflict.
      const pairCheck = classifyEntityPathInputs({
        declaredPath: detailPathNorm,
        rawPath: evPathNorm,
        declaredRoot: evRoot,
      }, pathMappings);
      pairCheck.absoluteCandidates.forEach(recordAbsoluteCandidate);
      if (pairCheck.rootMappingConflict) recordFindingDisputedCandidate(pairCheck);
      if (pairCheck.pathConflict) {
        recordFindingPathConflictedCandidates(pairCheck);
        hasContradictoryPathPair = true;
      }
    }
  }
  registerEntity(firstText(detail?.file_path, evidence.path), evidence.raw_path, evRoot, {isFinding: true});
  if (nonEmptyString(evidence.path) && nonEmptyString(detail?.file_path) && normalizeTracePath(evidence.path) !== normalizeTracePath(detail.file_path)) {
    registerEntity(evidence.path, evidence.raw_path, evRoot, {isFinding: true});
  }

  if (Array.isArray(evidence.snippets)) {
    evidence.snippets.forEach((snip) => {
      if (isPlainObject(snip)) {
        registerEntity(snip.path, snip.raw_path, snip.root ?? snip.source_root);
      }
    });
  }

  if (isPlainObject(evidence.snapshots)) {
    for (const snapKey of Object.keys(evidence.snapshots)) {
      const normKey = normalizeTracePath(snapKey);
      if (normKey && isAbsoluteTracePath(normKey)) {
        recordAbsoluteCandidate(normKey);
      }
    }
  }

  const tracePaths = [];
  collectRawTracePaths(evidence.raw_trace, tracePaths);
  tracePaths.forEach((p) => {
    if (isAbsoluteTracePath(p)) recordAbsoluteCandidate(p);
  });

  const hasMultipleRoots = declaredRoots.size > 1;
  const hasConflictingRawPaths = conflictingRawPaths.size > 0;
  const singleProvenRoot = declaredRoots.size === 1 && !hasConflictingRawPaths && !hasAmbiguousRootMapping
    ? [...declaredRoots][0]
    : '';

  const singleRawRoots = singleProvenRoot
    ? [...(rawRootsByMappedRoot.get(singleProvenRoot) || [singleProvenRoot])].sort()
    : [];

  // An evidence bundle only proves a single exclusive root when EVERY observed absolute path
  // (from `path`, `raw_path`, `snapshots`, or `raw_trace`) belongs inside `singleProvenRoot`
  // (or inside its unmapped `singleRawRoots`, where child mapping rules handle sub-prefixes).
  // We NEVER fabricate a fake root from suffix/basename of an external absolute path; instead
  // we mark `hasExternalAbsolutePath` so unscoped relative snapshots cannot bind to `singleProvenRoot`.
  const observedAbsolutePaths = new Set(observedAbsoluteRecords.map((r) => r.mappedAbs));
  let hasExternalAbsolutePath = false;
  for (const rec of observedAbsoluteRecords) {
    const insideMappedRoot = Boolean(
      singleProvenRoot && rec.mappedAbs !== singleProvenRoot && pathMatchesPrefix(rec.mappedAbs, singleProvenRoot),
    );
    const insideUnmappedRoot = Boolean(
      singleRawRoots.some((rr) => rec.rawAbs !== rr && pathMatchesPrefix(rec.rawAbs, rr)),
    );
    if (!insideMappedRoot && !insideUnmappedRoot) {
      hasExternalAbsolutePath = true;
      break;
    }
  }

  const canBindRelativeSnapshot = !hasMultipleRoots
    && !hasExternalAbsolutePath
    && !hasConflictingRawPaths
    && !hasAmbiguousRootMapping
    && !hasContradictoryPathPair;

  const explicitEvidenceRawRoot = normalizeRootPath(evRoot);
  return {
    pathMappings,
    declaredRoots,
    rawRootsByMappedRoot,
    findingDisputedAbsoluteCandidates,
    findingDisputedRelativePaths,
    findingPathConflictedAbsoluteCandidates,
    conflictingRawPaths,
    explicitEvidenceRawRoot,
    observedAbsolutePaths,
    hasMultipleRoots,
    hasExternalAbsolutePath,
    hasConflictingRawPaths,
    hasAmbiguousRootMapping,
    hasContradictoryPathPair,
    singleProvenRoot,
    singleRawRoots,
    canBindRelativeSnapshot,
  };
}

function resolveMappedFullAbsolutePath(rawFullPath, declaredRel, rawStepRoot, ctx, validatedEffectiveRoot = '') {
  const fullMapRes = applyPathMappingsDetailed(rawFullPath, ctx.pathMappings);
  if (fullMapRes.ambiguous) {
    return {
      path: rawFullPath,
      root: '',
      relativePath: '',
      absolutePath: rawFullPath,
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: `UNMAPPED_CONFLICT:${rawFullPath}`,
      mappingConflict: true,
      pathConflict: false,
      conflictingMappingTargets: [...fullMapRes.conflictingTargets],
    };
  }

  const mappedAbs = fullMapRes.path;
  if (ctx.singleProvenRoot && mappedAbs !== ctx.singleProvenRoot && pathMatchesPrefix(mappedAbs, ctx.singleProvenRoot)) {
    const derivedRel = stripRootPrefix(mappedAbs, ctx.singleProvenRoot);
    if (declaredRel && declaredRel !== derivedRel) {
      return {
        path: mappedAbs,
        root: '',
        relativePath: '',
        absolutePath: mappedAbs,
        fileIdentity: 'UNMAPPED_RAW_PATH',
        fileIdentityKey: `ABS:${mappedAbs}`,
        mappingConflict: false,
        pathConflict: false,
        conflictingMappingTargets: [],
      };
    }
    return {
      path: derivedRel,
      root: ctx.singleProvenRoot,
      relativePath: derivedRel,
      absolutePath: mappedAbs,
      fileIdentity: 'REPOSITORY_RELATIVE',
      fileIdentityKey: `ROOT:${ctx.singleProvenRoot}|${derivedRel}`,
      mappingConflict: false,
      pathConflict: false,
      conflictingMappingTargets: [],
    };
  }

  let ownRoot = '';
  if (fullMapRes.mapped && fullMapRes.matchedTarget && mappedAbs !== fullMapRes.matchedTarget && pathMatchesPrefix(mappedAbs, fullMapRes.matchedTarget)) {
    ownRoot = fullMapRes.matchedTarget;
  } else if (declaredRel && absEndsWithRelative(mappedAbs, declaredRel)) {
    ownRoot = deriveRootFromAbsAndRel(mappedAbs, declaredRel);
  } else if (validatedEffectiveRoot && mappedAbs !== validatedEffectiveRoot && pathMatchesPrefix(mappedAbs, validatedEffectiveRoot)) {
    ownRoot = validatedEffectiveRoot;
  } else if (rawStepRoot) {
    const mappedStepRootRes = applyPathMappingsDetailed(rawStepRoot, ctx.pathMappings);
    if (!mappedStepRootRes.ambiguous) {
      const mappedStepRoot = normalizeRootPath(mappedStepRootRes.path);
      if (mappedStepRoot && mappedAbs !== mappedStepRoot && pathMatchesPrefix(mappedAbs, mappedStepRoot)) {
        ownRoot = mappedStepRoot;
      }
    }
  }
  const scopedRel = ownRoot ? stripRootPrefix(mappedAbs, ownRoot) : '';
  const isScopedRoot = Boolean(ownRoot && (ctx.hasMultipleRoots || fullMapRes.mapped || rawStepRoot));
  return {
    path: mappedAbs,
    root: ownRoot,
    relativePath: scopedRel,
    absolutePath: mappedAbs,
    fileIdentity: isScopedRoot ? 'SCOPED_ABSOLUTE_ROOT' : 'UNMAPPED_RAW_PATH',
    fileIdentityKey: `ABS:${mappedAbs}`,
    mappingConflict: false,
    pathConflict: false,
    conflictingMappingTargets: [],
  };
}

function checkInheritedSourceRootConflict(absResolved, declaredRel, ctx, rawInputAbs = '') {
  // Even when a snippet or snapshot entry omits `root` and supplies a post-mapping `raw_path`
  // (e.g. `C:/mount/branch/...` or `C:/checkout-A/...`), verify whether the corresponding
  // unmapped source path under the context's proven source root hits a conflicting mapping
  // or matches the finding's own disputed absolute candidate within this evidence context.
  const absPath = absResolved.absolutePath || absResolved.path;
  if (!absPath || !isAbsoluteTracePath(absPath)) return null;

  // 1) Check mapped roots whose unmapped source root(s) are known (`rawRootsByMappedRoot`).
  for (const [mappedRoot, rawRootSet] of ctx.rawRootsByMappedRoot.entries()) {
    if (absPath === mappedRoot || !pathMatchesPrefix(absPath, mappedRoot)) continue;
    const relUnderMapped = stripRootPrefix(absPath, mappedRoot);
    if (!relUnderMapped) continue;
    for (const rawRoot of rawRootSet) {
      if (!rawRoot || rawRoot === mappedRoot) continue;
      const candidateSourcePath = joinRootAndRel(rawRoot, relUnderMapped);
      const mapRes = applyPathMappingsDetailed(candidateSourcePath, ctx.pathMappings);
      if (mapRes.ambiguous) {
        return {
          path: candidateSourcePath,
          root: '',
          relativePath: '',
          absolutePath: candidateSourcePath,
          fileIdentity: 'UNMAPPED_RAW_PATH',
          fileIdentityKey: `UNMAPPED_CONFLICT:${candidateSourcePath}`,
          mappingConflict: true,
          pathConflict: false,
          conflictingMappingTargets: [...mapRes.conflictingTargets],
        };
      }
    }
  }

  // 2) If evidence declares an unmapped root (e.g. `/mnt/shared`) and this entity also carries
  //    a relative path whose `evidence.root + relativePath` hits a conflicting child mapping
  //    whose conflicting targets include `absPath` (e.g. `C:/checkout-A/...`), preserve conflict.
  if (ctx.explicitEvidenceRawRoot && declaredRel) {
    const candidateSourcePath = joinRootAndRel(ctx.explicitEvidenceRawRoot, declaredRel);
    const mapRes = applyPathMappingsDetailed(candidateSourcePath, ctx.pathMappings);
    if (mapRes.ambiguous && mapRes.conflictingTargets.some((t) => absPath === t || pathMatchesPrefix(absPath, t))) {
      return {
        path: candidateSourcePath,
        root: '',
        relativePath: '',
        absolutePath: candidateSourcePath,
        fileIdentity: 'UNMAPPED_RAW_PATH',
        fileIdentityKey: `UNMAPPED_CONFLICT:${candidateSourcePath}`,
        mappingConflict: true,
        pathConflict: false,
        conflictingMappingTargets: [...mapRes.conflictingTargets],
      };
    }
  }

  // 3) If the finding itself hit a mapping conflict on `root + relativePath` while declaring an
  //    explicit absolute candidate (e.g. `evidence.raw_path`), preserve that exact MAPPING_CONFLICT
  //    for any snippet, snapshot, or raw_trace entry in the same evidence context that references
  //    that exact disputed absolute path without independent root provenance.
  const disputed = ctx.findingDisputedAbsoluteCandidates?.get(absPath)
    || (rawInputAbs ? ctx.findingDisputedAbsoluteCandidates?.get(rawInputAbs) : null);
  if (disputed) {
    return {
      path: disputed.rawFullPath,
      root: '',
      relativePath: '',
      absolutePath: disputed.rawFullPath,
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: `UNMAPPED_CONFLICT:${disputed.rawFullPath}`,
      mappingConflict: true,
      pathConflict: false,
      conflictingMappingTargets: [...disputed.conflictingTargets],
    };
  }

  return null;
}

function finalizeResolvedIdentity(resolved, normRoot, ctx, rawInputAbs = '') {
  if (!resolved || resolved.mappingConflict || resolved.pathConflict) {
    return resolved;
  }
  const resolvedAbs = resolved.absolutePath || (isAbsoluteTracePath(resolved.path) ? resolved.path : '');
  if (!resolvedAbs) return resolved;

  if (ctx.conflictingRawPaths?.has(resolvedAbs)) {
    return {
      path: resolvedAbs,
      root: '',
      relativePath: '',
      absolutePath: '',
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: `PATH_CONFLICT:PROVENANCE:${resolvedAbs}`,
      mappingConflict: false,
      pathConflict: true,
      conflictingMappingTargets: [],
    };
  }

  if (!normRoot || normRoot === ctx.explicitEvidenceRawRoot) {
    if (ctx.findingPathConflictedAbsoluteCandidates?.has(resolvedAbs)
      || (rawInputAbs && ctx.findingPathConflictedAbsoluteCandidates?.has(rawInputAbs))) {
      return {
        path: resolvedAbs,
        root: '',
        relativePath: '',
        absolutePath: '',
        fileIdentity: 'UNMAPPED_RAW_PATH',
        fileIdentityKey: `PATH_CONFLICT:FINDING:${resolvedAbs}`,
        mappingConflict: false,
        pathConflict: true,
        conflictingMappingTargets: [],
      };
    }
  }

  return resolved;
}

function resolveEntityFileIdentity({declaredPath, rawPath, declaredRoot}, ctx) {
  const classified = classifyEntityPathInputs({declaredPath, rawPath, declaredRoot}, ctx.pathMappings);
  const {
    normPath,
    normRaw,
    normRoot,
    explicitRawAbs,
    declaredRel,
    pathConflict,
    rootMappingConflict,
    validatedAbsRoot,
  } = classified;

  if (!normPath && !normRaw) {
    return {
      path: '',
      root: '',
      relativePath: '',
      absolutePath: '',
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: '',
      mappingConflict: false,
      pathConflict: false,
      conflictingMappingTargets: [],
    };
  }

  // Mapping conflict detected on the full `root + relativePath` source path MUST be preserved
  // even when `raw_path` (parent-mapped or pointing to one conflicting target) is also present.
  if (rootMappingConflict) {
    return {
      path: rootMappingConflict.rawFullPath,
      root: '',
      relativePath: '',
      absolutePath: rootMappingConflict.rawFullPath,
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: `UNMAPPED_CONFLICT:${rootMappingConflict.rawFullPath}`,
      mappingConflict: true,
      pathConflict: false,
      conflictingMappingTargets: [...rootMappingConflict.conflictingTargets],
    };
  }

  // Paths containing `..` or drive-relative prefixes (`C:foo`) cannot be safely canonicalized
  // without filesystem symlink/CWD resolution:
  //   1) If lexical collapse targets a mapping conflict or disputed candidate, preserve `MAPPING_CONFLICT`.
  //   2) Otherwise reject verification explicitly via `PATH_CONFLICT` so `..` can NEVER escape root,
  //      merge distinct files, or restore `SNAPSHOT_MATCHED` / `DECLARED_BY_SNIPPET`.
  if (hasUnsafePathSegments(declaredPath) || hasUnsafePathSegments(rawPath) || hasUnsafePathSegments(declaredRoot)) {
    const cPath = declaredPath ? tryCollapseDotDotForConflictCheck(declaredPath) : {escapedRoot: false, collapsed: ''};
    const cRaw = rawPath ? tryCollapseDotDotForConflictCheck(rawPath) : {escapedRoot: false, collapsed: ''};
    const cRoot = declaredRoot ? tryCollapseDotDotForConflictCheck(declaredRoot) : {escapedRoot: false, collapsed: ''};
    if (!cPath.escapedRoot && !cRaw.escapedRoot && !cRoot.escapedRoot && (cPath.collapsed || cRaw.collapsed)) {
      const collapsedIdentity = resolveEntityFileIdentity({
        declaredPath: cPath.collapsed,
        rawPath: cRaw.collapsed,
        declaredRoot: cRoot.collapsed,
      }, ctx);
      if (collapsedIdentity.mappingConflict) {
        return collapsedIdentity;
      }
    }
    const unsafeDisplay = normPath || normRaw || nonEmptyString(declaredPath) || nonEmptyString(rawPath);
    return {
      path: unsafeDisplay,
      root: '',
      relativePath: '',
      absolutePath: '',
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: `PATH_CONFLICT:UNSAFE:${unsafeDisplay}`,
      mappingConflict: false,
      pathConflict: true,
      conflictingMappingTargets: [],
    };
  }

  if (pathConflict) {
    // If this entity omitted `root`, check whether `evidence.root + relativePath` actually hit
    // a conflicting child mapping whose targets contain the supplied absolute path (e.g. C:/checkout-A/...),
    // so the snippet preserves the exact same `MAPPING_CONFLICT` diagnosis as the finding.
    if (!normRoot && ctx.explicitEvidenceRawRoot) {
      const relPart = (normPath && !isAbsoluteTracePath(normPath))
        ? normPath
        : (normRaw && !isAbsoluteTracePath(normRaw) ? normRaw : '');
      const absPart = (normRaw && isAbsoluteTracePath(normRaw))
        ? normRaw
        : (normPath && isAbsoluteTracePath(normPath) ? normPath : '');
      if (relPart && absPart) {
        const candidateSourcePath = joinRootAndRel(ctx.explicitEvidenceRawRoot, relPart);
        const mapRes = applyPathMappingsDetailed(candidateSourcePath, ctx.pathMappings);
        if (mapRes.ambiguous && mapRes.conflictingTargets.some((t) => absPart === t || pathMatchesPrefix(absPart, t))) {
          return {
            path: candidateSourcePath,
            root: '',
            relativePath: '',
            absolutePath: candidateSourcePath,
            fileIdentity: 'UNMAPPED_RAW_PATH',
            fileIdentityKey: `UNMAPPED_CONFLICT:${candidateSourcePath}`,
            mappingConflict: true,
            pathConflict: false,
            conflictingMappingTargets: [...mapRes.conflictingTargets],
          };
        }
        const absMapped = applyPathMappingsDetailed(absPart, ctx.pathMappings);
        if (!mapRes.ambiguous && mapRes.mapped && !absMapped.ambiguous && mapRes.path === absMapped.path) {
          const inheritedResolved = resolveMappedFullAbsolutePath(candidateSourcePath, relPart, ctx.explicitEvidenceRawRoot, ctx);
          if (inheritedResolved.mappingConflict) return inheritedResolved;
          const inheritedConflict = checkInheritedSourceRootConflict(inheritedResolved, relPart, ctx, absPart);
          if (inheritedConflict) return inheritedConflict;
          return finalizeResolvedIdentity(inheritedResolved, normRoot, ctx, absPart);
        }
      }
    }
    const displayConflict = normPath && normRaw
      ? `${normPath} ≠ ${normRaw}`
      : (normRoot && (normPath || normRaw) ? `${normRoot} ∌ ${normPath || normRaw}` : (normPath || normRaw));
    return {
      path: normPath || normRaw,
      root: '',
      relativePath: '',
      absolutePath: '',
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: `PATH_CONFLICT:${displayConflict}`,
      mappingConflict: false,
      pathConflict: true,
      conflictingMappingTargets: [],
    };
  }

  // Case 1: Explicit absolute path (from either `raw_path` OR `path`)
  if (explicitRawAbs) {
    const absResolved = resolveMappedFullAbsolutePath(
      explicitRawAbs,
      declaredRel,
      normRoot,
      ctx,
      validatedAbsRoot?.effectiveMappedRoot || '',
    );
    if (absResolved.mappingConflict) return absResolved;
    if (!normRoot || normRoot === ctx.explicitEvidenceRawRoot) {
      const inheritedConflict = checkInheritedSourceRootConflict(absResolved, declaredRel, ctx, explicitRawAbs);
      if (inheritedConflict) return inheritedConflict;
    }
    return finalizeResolvedIdentity(absResolved, normRoot, ctx, explicitRawAbs);
  }

  // Case 2: Relative path with an explicit unmapped entity root (`snip.root` / `evidence.root`):
  // Join the UNMAPPED root + relative path FIRST, then evaluate path_mappings on the FULL path
  // so conflicting (or valid) child mappings are ALWAYS checked before rewriting!
  if (normRoot) {
    const rawFullPath = joinRootAndRel(normRoot, declaredRel);
    const resolved = resolveMappedFullAbsolutePath(rawFullPath, declaredRel, normRoot, ctx);
    return finalizeResolvedIdentity(resolved, normRoot, ctx, rawFullPath);
  }

  // Case 3: Relative-only path in a multi-root or external-absolute-path bundle -> unscoped/ambiguous
  if (ctx.hasMultipleRoots || ctx.hasExternalAbsolutePath) {
    // If there is no multi-root ambiguity and this exact relative path is the finding's own
    // disputed `root + relativePath` mapping conflict, preserve MAPPING_CONFLICT instead of
    // allowing a relative-only snippet to report DECLARED_BY_SNIPPET.
    if (!ctx.hasMultipleRoots && declaredRel) {
      const disputedRel = ctx.findingDisputedRelativePaths?.get(declaredRel);
      if (disputedRel) {
        return {
          path: disputedRel.rawFullPath,
          root: '',
          relativePath: '',
          absolutePath: disputedRel.rawFullPath,
          fileIdentity: 'UNMAPPED_RAW_PATH',
          fileIdentityKey: `UNMAPPED_CONFLICT:${disputedRel.rawFullPath}`,
          mappingConflict: true,
          pathConflict: false,
          conflictingMappingTargets: [...disputedRel.conflictingTargets],
        };
      }
    }
    return {
      path: declaredRel,
      root: '',
      relativePath: declaredRel,
      absolutePath: '',
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: `UNSCOPED_REL:${declaredRel}`,
      mappingConflict: false,
      pathConflict: false,
      conflictingMappingTargets: [],
    };
  }

  // Case 4: Relative-only path under a single proven root:
  // ALWAYS join the UNMAPPED source root(s) with `declaredRel` FIRST and evaluate path_mappings
  // on the full original path (never `map(root) + rel`, which bypasses child mappings!).
  if (ctx.singleProvenRoot) {
    const rawRoots = ctx.singleRawRoots.length ? ctx.singleRawRoots : [ctx.singleProvenRoot];
    const resolvedCandidates = rawRoots.map((rawRoot) => {
      const rawFullPath = joinRootAndRel(rawRoot, declaredRel);
      return resolveMappedFullAbsolutePath(rawFullPath, declaredRel, rawRoot, ctx);
    });
    const firstConflict = resolvedCandidates.find((r) => r.mappingConflict);
    if (firstConflict) return firstConflict;
    const uniqueKeys = new Set(resolvedCandidates.map((r) => r.fileIdentityKey));
    if (uniqueKeys.size > 1) {
      const firstPath = joinRootAndRel(rawRoots[0], declaredRel);
      return {
        path: firstPath,
        root: '',
        relativePath: '',
        absolutePath: firstPath,
        fileIdentity: 'UNMAPPED_RAW_PATH',
        fileIdentityKey: `UNMAPPED_CONFLICT:${firstPath}`,
        mappingConflict: true,
        pathConflict: false,
        conflictingMappingTargets: resolvedCandidates.map((r) => r.absolutePath || r.path).sort(),
      };
    }
    return finalizeResolvedIdentity(resolvedCandidates[0], '', ctx);
  }

  return {
    path: declaredRel,
    root: '',
    relativePath: declaredRel,
    absolutePath: '',
    fileIdentity: 'REPOSITORY_RELATIVE',
    fileIdentityKey: `REL:${declaredRel}`,
    mappingConflict: false,
    pathConflict: false,
    conflictingMappingTargets: [],
  };
}

function makeHashLedgerKey(fileIdentityKey, sourceVersion, hashScope, spanSuffix = '') {
  return hashScope === 'file'
    ? `${fileIdentityKey}\u0000${sourceVersion}\u0000file`
    : `${fileIdentityKey}\u0000${sourceVersion}\u0000${hashScope}\u0000${spanSuffix}`;
}

function formatSpanKey(start, end) {
  const range = validateTraceRange(start, end);
  if (!range) return '';
  return `${range.startLine}:${range.startCol ?? ''}-${range.endLine}:${range.endCol ?? ''}`;
}

function buildFileHashLedger(evidence, ctx) {
  const defaultVersion = resolveSourceVersion(evidence, 'scan');
  const buckets = new Map();
  const ambiguousRelativeSnapshots = new Set();

  const ensureBucket = (key, fileIdentityKey, sourceVersion, hashScope) => {
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = {
        fileIdentityKey,
        sourceVersion,
        hashScope,
        hashes: new Set(),
        snapshotHashes: new Set(),
        snippetHashes: new Set(),
        groundedSnippetHashes: new Set(),
        invalidFormatSeen: false,
      };
      buckets.set(key, bucket);
    }
    return bucket;
  };

  // 1) Index source snapshots (strictly full-file scope unless snapshot specifies otherwise)
  if (isPlainObject(evidence.snapshots)) {
    for (const [snapKey, snapMeta] of Object.entries(evidence.snapshots)) {
      if (!isPlainObject(snapMeta)) continue;
      if (hasUnsafePathSegments(snapKey)) continue;
      const normKey = normalizeTracePath(snapKey);
      if (!normKey) continue;
      const scope = resolveHashScope(snapMeta);
      const version = resolveSourceVersion(snapMeta, defaultVersion);
      const rawSha = nonEmptyString(snapMeta.sha256);
      const validSha = normalizeValidSha256(rawSha);

      if (isAbsoluteTracePath(normKey)) {
        const id = resolveEntityFileIdentity({declaredPath: normKey, rawPath: normKey, declaredRoot: ''}, ctx);
        if (id.mappingConflict || id.pathConflict) continue;
        const key = makeHashLedgerKey(id.fileIdentityKey, version, scope);
        const bucket = ensureBucket(key, id.fileIdentityKey, version, scope);
        if (validSha) {
          bucket.hashes.add(validSha);
          bucket.snapshotHashes.add(validSha);
        } else if (rawSha) {
          bucket.invalidFormatSeen = true;
        }
      } else if (ctx.canBindRelativeSnapshot) {
        const id = resolveEntityFileIdentity({declaredPath: normKey, rawPath: '', declaredRoot: ''}, ctx);
        if (id.mappingConflict || id.pathConflict) continue;
        const key = makeHashLedgerKey(id.fileIdentityKey, version, scope);
        const bucket = ensureBucket(key, id.fileIdentityKey, version, scope);
        if (validSha) {
          bucket.hashes.add(validSha);
          bucket.snapshotHashes.add(validSha);
        } else if (rawSha) {
          bucket.invalidFormatSeen = true;
        }
      } else {
        // Multi-root, external absolute path, or ambiguous/conflicting context:
        // unscoped relative snapshot CANNOT be bound to any root.
        ambiguousRelativeSnapshots.add(normKey);
      }
    }
  }

  // 2) Index ALL snippets (finding, source, intermediate, sink) independently of step deduplication
  //    or code text so differing text variants on the same file+version NEVER hide a hash conflict.
  if (Array.isArray(evidence.snippets)) {
    for (const snip of evidence.snippets) {
      if (!isPlainObject(snip)) continue;
      const declaredPath = normalizeTracePath(snip.path);
      const rawPath = normalizeTracePath(snip.raw_path);
      const declaredRoot = normalizeRootPath(snip.root ?? snip.source_root);
      if (!declaredPath && !rawPath) continue;
      if (snip.start !== undefined && !validateTraceRange(snip.start, snip.end)) continue;

      const id = resolveEntityFileIdentity({declaredPath, rawPath, declaredRoot}, ctx);
      if (id.mappingConflict || id.pathConflict) continue;

      const scope = resolveHashScope(snip);
      const version = resolveSourceVersion(snip, defaultVersion);
      const rawSha = nonEmptyString(snip.sha256);
      const validSha = normalizeValidSha256(rawSha);
      const spanSuffix = scope === 'file' ? '' : formatSpanKey(snip.start, snip.end);
      const key = makeHashLedgerKey(id.fileIdentityKey, version, scope, spanSuffix);
      const bucket = ensureBucket(key, id.fileIdentityKey, version, scope);
      const hasExplicitRootProvenance = Boolean(rawPath || declaredRoot || isAbsoluteTracePath(declaredPath));

      if (validSha) {
        bucket.hashes.add(validSha);
        bucket.snippetHashes.add(validSha);
        if (hasExplicitRootProvenance) bucket.groundedSnippetHashes.add(validSha);
      } else if (rawSha) {
        bucket.invalidFormatSeen = true;
      }
    }
  }

  // 3) Finalize deterministic order-independent conflict status per bucket
  const finalized = new Map();
  for (const [key, bucket] of buckets.entries()) {
    const sortedHashes = [...bucket.hashes].sort();
    const hasConflict = sortedHashes.length > 1;
    finalized.set(key, {
      ...bucket,
      hasConflict,
      conflictingHashes: hasConflict ? sortedHashes : [],
      resolvedSha256: hasConflict ? '' : (sortedHashes[0] || ''),
    });
  }

  return {
    defaultVersion,
    ambiguousRelativeSnapshots,
    getBucket(fileIdentityKey, sourceVersion = defaultVersion, hashScope = 'file', spanSuffix = '') {
      if (!fileIdentityKey) return null;
      return finalized.get(makeHashLedgerKey(fileIdentityKey, sourceVersion, hashScope, spanSuffix)) || null;
    },
  };
}

function buildValidatedTraceStep({role, path, rawPath, root, start, end, code, sha256, hashScope, sourceVersion, lines, origin}) {
  const roleKey = nonEmptyString(role).toLowerCase();
  const meta = TRACE_ROLE_META[roleKey];
  if (!meta) return null;

  const declaredPath = normalizeTracePath(path);
  const declaredRaw = normalizeTracePath(rawPath);
  const declaredRoot = normalizeRootPath(root);
  if (!declaredPath && !declaredRaw) return null;

  const range = validateTraceRange(start, end);
  if (!range) return null;

  const cleanLines = Array.isArray(lines)
    ? lines.filter((entry) => isPlainObject(entry) && isPositiveInt(entry.line) && typeof entry.text === 'string')
    : [];

  const rawSha = nonEmptyString(sha256);
  const validSha = normalizeValidSha256(rawSha);

  return {
    ...meta,
    path: declaredPath || declaredRaw,
    root: '',
    relativePath: '',
    absolutePath: '',
    fileIdentity: 'UNMAPPED_RAW_PATH',
    fileIdentityKey: '',
    mappingConflict: false,
    pathConflict: false,
    conflictingMappingTargets: [],
    startLine: range.startLine,
    endLine: range.endLine,
    startCol: range.startCol,
    endCol: range.endCol,
    code: typeof code === 'string' ? code.trim() : '',
    sha256: validSha,
    shaConflict: false,
    conflictingHashes: [],
    hashStatus: validSha ? 'DECLARED_BY_SNIPPET' : (rawSha ? 'INVALID_FORMAT' : 'UNVERIFIED'),
    lines: cleanLines,
    _origin: origin,
    _declaredPath: declaredPath,
    _rawPath: origin === 'raw_trace' ? declaredPath : declaredRaw,
    _declaredRoot: declaredRoot,
    _rawSha: rawSha,
    _hashScope: hashScope || 'file',
    _sourceVersion: sourceVersion || '',
  };
}

function parseTraceNode(node, role, state, depth = 0) {
  if (node === undefined || node === null) return;
  if (depth > 16) {
    state.droppedCount += 1;
    return;
  }
  const pushLocation = (stepRole, loc, code) => {
    const step = isPlainObject(loc)
      ? buildValidatedTraceStep({role: stepRole, path: loc.path, start: loc.start, end: loc.end, code, origin: 'raw_trace'})
      : null;
    if (step) state.steps.push(step);
    else state.droppedCount += 1;
  };
  if (Array.isArray(node) && node.length === 2 && node[0] === 'CliLoc') {
    const payload = node[1];
    if (Array.isArray(payload) && payload.length === 2 && isPlainObject(payload[0])) {
      pushLocation(role, payload[0], payload[1]);
    } else {
      state.droppedCount += 1;
    }
    return;
  }
  if (Array.isArray(node) && node.length === 2 && node[0] === 'CliCall') {
    const payload = node[1];
    if (Array.isArray(payload) && payload.length === 3) {
      const [callSite, callSteps, inner] = payload;
      const pushCallAndSteps = () => {
        if (Array.isArray(callSite) && callSite.length === 2 && isPlainObject(callSite[0])) {
          pushLocation('intermediate', callSite[0], callSite[1]);
        } else if (callSite !== undefined && callSite !== null) {
          state.droppedCount += 1;
        }
        if (Array.isArray(callSteps)) {
          callSteps.forEach((st) => {
            if (isPlainObject(st) && isPlainObject(st.location)) pushLocation('intermediate', st.location, st.content);
            else state.droppedCount += 1;
          });
        } else if (callSteps !== undefined && callSteps !== null) {
          state.droppedCount += 1;
        }
      };
      if (role === 'source') {
        parseTraceNode(inner, 'source', state, depth + 1);
        pushCallAndSteps();
      } else {
        pushCallAndSteps();
        parseTraceNode(inner, role, state, depth + 1);
      }
      return;
    }
  }
  state.droppedCount += 1;
}

// ---------------------------------------------------------------------------------------------
// Step identity
//
// A step is identified by:
//   role + grounded File Identity (root/absolute-aware) + full span (start/end line AND column
//   when known) + normalised code.
// Two steps with the same relative path from different source roots have DIFFERENT File
// Identities and are NEVER deduplicated or merged.
// Two steps on the same line with different columns are DIFFERENT steps.
// Hash conflict detection is decoupled into `buildFileHashLedger` so differing code variants on
// the same file/version are preserved as distinct steps while STILL flagging `shaConflict: true`.
// ---------------------------------------------------------------------------------------------

function normalizeCode(code) {
  return typeof code === 'string' ? code.replace(/\s+/g, ' ').trim() : '';
}

function attachFileIdentity(steps, ctx) {
  return steps.map((step) => {
    const id = resolveEntityFileIdentity({
      declaredPath: step._declaredPath,
      rawPath: step._rawPath,
      declaredRoot: step._declaredRoot,
    }, ctx);
    if (id.mappingConflict || id.pathConflict) {
      return {
        ...step,
        ...id,
        sha256: '',
        shaConflict: false,
        conflictingHashes: [],
        hashStatus: id.mappingConflict ? 'MAPPING_CONFLICT' : 'PATH_CONFLICT',
      };
    }
    return {
      ...step,
      ...id,
    };
  });
}

function applyHashLedgerToStep(step, ledger, {allowOwnHash = true} = {}) {
  if (step.mappingConflict || step.pathConflict) {
    return {
      ...step,
      sha256: '',
      shaConflict: false,
      conflictingHashes: [],
      hashStatus: step.mappingConflict ? 'MAPPING_CONFLICT' : 'PATH_CONFLICT',
    };
  }
  const version = step._sourceVersion || ledger.defaultVersion;
  const scope = step._hashScope || 'file';
  const spanSuffix = scope === 'file'
    ? ''
    : `${step.startLine}:${step.startCol ?? ''}-${step.endLine}:${step.endCol ?? ''}`;
  const bucket = ledger.getBucket(step.fileIdentityKey, version, scope, spanSuffix);

  if (bucket?.hasConflict) {
    return {
      ...step,
      sha256: '',
      shaConflict: true,
      conflictingHashes: [...bucket.conflictingHashes],
      hashStatus: 'CONFLICT',
    };
  }
  if (bucket?.invalidFormatSeen) {
    return {
      ...step,
      sha256: '',
      shaConflict: false,
      conflictingHashes: [],
      hashStatus: 'INVALID_FORMAT',
    };
  }
  if (!allowOwnHash) {
    return {
      ...step,
      sha256: '',
      shaConflict: false,
      conflictingHashes: [],
      hashStatus: 'UNVERIFIED',
    };
  }
  if (step._rawSha && !step.sha256) {
    return {
      ...step,
      sha256: '',
      shaConflict: false,
      conflictingHashes: [],
      hashStatus: 'INVALID_FORMAT',
    };
  }
  if (!step.sha256) {
    return {
      ...step,
      sha256: '',
      shaConflict: false,
      conflictingHashes: [],
      hashStatus: 'UNVERIFIED',
    };
  }
  if (scope !== 'file') {
    return {
      ...step,
      hashStatus: 'DECLARED_NON_FILE_SCOPE',
    };
  }
  const matchedSnapshot = Boolean(bucket && bucket.snapshotHashes.has(step.sha256));
  return {
    ...step,
    hashStatus: matchedSnapshot ? 'SNAPSHOT_MATCHED' : 'DECLARED_BY_SNIPPET',
  };
}

function exactStepKey(step) {
  return [
    step.role,
    step.fileIdentityKey,
    step.startLine,
    step.startCol ?? '',
    step.endLine,
    step.endCol ?? '',
    normalizeCode(step.code),
  ].join('\u0000');
}

function mergeHashesOnSameLocation(existing, incoming) {
  const hashSet = new Set([
    ...(Array.isArray(existing.conflictingHashes) ? existing.conflictingHashes : []),
    ...(Array.isArray(incoming.conflictingHashes) ? incoming.conflictingHashes : []),
    ...(existing.sha256 ? [existing.sha256] : []),
    ...(incoming.sha256 ? [incoming.sha256] : []),
  ]);
  if (existing.shaConflict || incoming.shaConflict || hashSet.size > 1) {
    existing.sha256 = '';
    existing.shaConflict = true;
    existing.conflictingHashes = [...hashSet].sort();
    existing.hashStatus = 'CONFLICT';
  } else if (!existing.sha256 && incoming.sha256) {
    existing.sha256 = incoming.sha256;
    existing.hashStatus = incoming.hashStatus || existing.hashStatus;
  }
}

function deduplicateExact(steps) {
  const seen = new Map();
  const unique = [];
  for (const step of steps) {
    const key = exactStepKey(step);
    const existing = seen.get(key);
    if (!existing) {
      const copy = {
        ...step,
        conflictingHashes: [...(step.conflictingHashes || [])],
        conflictingMappingTargets: [...(step.conflictingMappingTargets || [])],
      };
      seen.set(key, copy);
      unique.push(copy);
    } else {
      mergeHashesOnSameLocation(existing, step);
      if (!existing.lines.length && step.lines.length) existing.lines = step.lines;
    }
  }
  return unique;
}

function sameFile(a, b) {
  if (a.mappingConflict || b.mappingConflict || a.pathConflict || b.pathConflict) return false;
  if (!a.fileIdentityKey || !b.fileIdentityKey || a.fileIdentityKey !== b.fileIdentityKey) return false;
  if (a.absolutePath && b.absolutePath && a.absolutePath !== b.absolutePath) return false;
  return true;
}

function spanRelation(a, b) {
  if (a.role !== b.role || a.startLine !== b.startLine || a.endLine !== b.endLine) return 'none';
  if (!sameFile(a, b)) return 'none';
  const codeA = normalizeCode(a.code);
  const codeB = normalizeCode(b.code);
  const fullCols = a.startCol !== null && b.startCol !== null && a.endCol !== null && b.endCol !== null;
  if (a.startCol !== null && b.startCol !== null && a.startCol !== b.startCol) return 'none';
  if (a.endCol !== null && b.endCol !== null && a.endCol !== b.endCol) return 'none';
  if (fullCols) {
    if (codeA && codeB && codeA !== codeB) return 'none';
    return 'exact';
  }
  if (!codeA || !codeB || codeA !== codeB) return 'none';
  return 'loose';
}

function mergeSteps(step, snippetStep) {
  const mergedConflicts = [...new Set([
    ...(Array.isArray(step.conflictingHashes) ? step.conflictingHashes : []),
    ...(Array.isArray(snippetStep.conflictingHashes) ? snippetStep.conflictingHashes : []),
  ])].sort();
  const hasConflict = Boolean(step.shaConflict || snippetStep.shaConflict || mergedConflicts.length > 1);
  const hasMappingConflict = Boolean(step.mappingConflict || snippetStep.mappingConflict);
  const hasPathConflict = Boolean(step.pathConflict || snippetStep.pathConflict);
  return {
    ...step,
    path: snippetStep.path || step.path,
    root: snippetStep.root || step.root,
    relativePath: snippetStep.relativePath || step.relativePath,
    absolutePath: snippetStep.absolutePath || step.absolutePath,
    fileIdentity: snippetStep.fileIdentity || step.fileIdentity,
    fileIdentityKey: snippetStep.fileIdentityKey || step.fileIdentityKey,
    mappingConflict: hasMappingConflict,
    pathConflict: hasPathConflict,
    conflictingMappingTargets: hasMappingConflict
      ? [...new Set([...(step.conflictingMappingTargets || []), ...(snippetStep.conflictingMappingTargets || [])])].sort()
      : [],
    startCol: step.startCol ?? snippetStep.startCol,
    endCol: step.endCol ?? snippetStep.endCol,
    code: step.code || snippetStep.code,
    // Downstream merge/enrichment must NEVER restore a hash onto a conflicted or unmapped file.
    sha256: (hasConflict || hasMappingConflict || hasPathConflict) ? '' : (snippetStep.sha256 || ''),
    shaConflict: hasConflict,
    conflictingHashes: hasConflict ? mergedConflicts : [],
    hashStatus: hasMappingConflict
      ? 'MAPPING_CONFLICT'
      : hasPathConflict
        ? 'PATH_CONFLICT'
        : hasConflict
          ? 'CONFLICT'
          : (snippetStep.hashStatus || step.hashStatus || 'UNVERIFIED'),
    lines: snippetStep.lines.length ? snippetStep.lines : step.lines,
    evidenceSources: ['raw_trace', 'snippets'],
  };
}

function pairSnippetsWithRawTrace(snipSteps, rawSteps) {
  const rawToSnip = new Map();
  const snipToRaw = new Map();
  const ambiguous = new Set();

  // 1) exact span matches (columns on both sides)
  snipSteps.forEach((s, si) => {
    rawSteps.forEach((r, ri) => {
      if (rawToSnip.has(ri) || snipToRaw.has(si)) return;
      if (spanRelation(s, r) === 'exact') {
        rawToSnip.set(ri, si);
        snipToRaw.set(si, ri);
      }
    });
  });

  // 2) loose matches (a side lacks columns): only when unique in both directions
  snipSteps.forEach((s, si) => {
    if (snipToRaw.has(si)) return;
    const candidates = rawSteps
      .map((r, ri) => ({r, ri}))
      .filter(({r, ri}) => !rawToSnip.has(ri) && spanRelation(s, r) !== 'none');
    if (candidates.length === 0) return;
    if (candidates.length > 1) {
      ambiguous.add(`s${si}`);
      candidates.forEach(({ri}) => ambiguous.add(`r${ri}`));
      return;
    }
    const {r, ri} = candidates[0];
    const reverse = snipSteps.filter((other, oi) => !snipToRaw.has(oi) && spanRelation(other, r) !== 'none');
    if (reverse.length !== 1) {
      ambiguous.add(`s${si}`);
      ambiguous.add(`r${ri}`);
      return;
    }
    rawToSnip.set(ri, si);
    snipToRaw.set(si, ri);
  });

  return {rawToSnip, snipToRaw, ambiguous};
}

function stripInternalStepFields(step) {
  const {
    _origin: _o,
    _declaredPath: _d,
    _rawPath: _r,
    _declaredRoot: _dr,
    _rawSha: _rs,
    _hashScope: _hs,
    _sourceVersion: _sv,
    ...clean
  } = step;
  return {
    ...clean,
    lines: Array.isArray(clean.lines) ? clean.lines.map((entry) => ({...entry})) : [],
    conflictingHashes: Array.isArray(clean.conflictingHashes) ? [...clean.conflictingHashes] : [],
    conflictingMappingTargets: Array.isArray(clean.conflictingMappingTargets) ? [...clean.conflictingMappingTargets] : [],
    evidenceSources: Array.isArray(clean.evidenceSources) ? [...clean.evidenceSources] : [],
    ambiguousMatch: Boolean(clean.ambiguousMatch),
    shaConflict: Boolean(clean.shaConflict),
    mappingConflict: Boolean(clean.mappingConflict),
    pathConflict: Boolean(clean.pathConflict),
  };
}

function parseSnippetTraceSteps(snippets, defaultVersion) {
  if (!Array.isArray(snippets)) return {steps: [], droppedCount: 0};
  const steps = [];
  let droppedCount = 0;

  for (const snip of snippets) {
    if (!isPlainObject(snip)) {
      droppedCount += 1;
      continue;
    }
    const role = nonEmptyString(snip.role).toLowerCase();
    if (!role || role === 'finding') continue;
    if (!TRACE_ROLE_META[role]) continue;

    const step = buildValidatedTraceStep({
      role,
      path: snip.path,
      rawPath: snip.raw_path,
      root: snip.root ?? snip.source_root,
      start: snip.start,
      end: snip.end,
      code: snip.matched,
      sha256: snip.sha256,
      hashScope: resolveHashScope(snip),
      sourceVersion: resolveSourceVersion(snip, defaultVersion),
      lines: snip.lines,
      origin: 'snippets',
    });
    if (step) steps.push(step);
    else droppedCount += 1;
  }

  return {steps, droppedCount};
}

function parseRawTraceSteps(rawTrace) {
  if (rawTrace === undefined || rawTrace === null) return {steps: [], droppedCount: 0};
  if (!isPlainObject(rawTrace)) return {steps: [], droppedCount: 1};

  const state = {steps: [], droppedCount: 0};
  parseTraceNode(rawTrace.taint_source, 'source', state);

  if (rawTrace.intermediate_vars !== undefined && rawTrace.intermediate_vars !== null) {
    if (!Array.isArray(rawTrace.intermediate_vars)) {
      state.droppedCount += 1;
    } else {
      rawTrace.intermediate_vars.forEach((iv) => {
        const step = isPlainObject(iv) && isPlainObject(iv.location)
          ? buildValidatedTraceStep({
            role: 'intermediate',
            path: iv.location.path,
            start: iv.location.start,
            end: iv.location.end,
            code: iv.content,
            origin: 'raw_trace',
          })
          : null;
        if (step) state.steps.push(step);
        else state.droppedCount += 1;
      });
    }
  }

  parseTraceNode(rawTrace.taint_sink, 'sink', state);
  return {steps: state.steps, droppedCount: state.droppedCount};
}

const ROLE_ORDER = ['source', 'intermediate', 'sink'];

function orderByRole(steps) {
  return ROLE_ORDER.flatMap((role) => steps.filter((s) => s.role === role));
}

export function resolveFindingSourceHash(detailOrEvidence) {
  const isDetail = isPlainObject(detailOrEvidence) && isPlainObject(detailOrEvidence.evidence);
  const detail = isDetail ? detailOrEvidence : null;
  const evidence = isDetail ? detailOrEvidence.evidence : (isPlainObject(detailOrEvidence) ? detailOrEvidence : {});

  const declaredPath = firstText(detail?.file_path, evidence.path);
  const declaredRawPath = firstText(evidence.raw_path);
  const declaredRoot = firstText(evidence.root, evidence.source_root);

  if (!declaredPath && !declaredRawPath) {
    return {
      status: 'UNVERIFIED',
      sha256: '',
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: 'UNMAPPED_RAW_PATH',
      fileIdentityKey: '',
      resolvedPath: '',
      tone: 'neutral',
      label: 'Chưa có SHA-256',
      reason: 'Cảnh báo chưa có đường dẫn tệp nguồn để đối chiếu SHA-256.',
    };
  }

  const ctx = buildPathContext(evidence, detail);
  const ledger = buildFileHashLedger(evidence, ctx);

  // Check ALL pairwise combinations among (detail.file_path, evidence.path, evidence.raw_path):
  // never hide a contradiction between evidence.path and evidence.raw_path behind detail.file_path.
  const detailPathNorm = normalizeTracePath(detail?.file_path);
  const evPathNorm = normalizeTracePath(evidence.path);
  const evRawNorm = normalizeTracePath(evidence.raw_path);
  const findingPairsToCheck = [
    [evPathNorm, evRawNorm],
    [detailPathNorm, evPathNorm],
    [detailPathNorm, evRawNorm],
  ];
  for (const [left, right] of findingPairsToCheck) {
    if (!left || !right || left === right) continue;
    const pairCheck = classifyEntityPathInputs({
      declaredPath: left,
      rawPath: right,
      declaredRoot,
    }, ctx.pathMappings);
    if (pairCheck.rootMappingConflict) {
      return {
        status: 'MAPPING_CONFLICT',
        sha256: '',
        conflictingHashes: [],
        verifiedAgainstSnapshot: false,
        fileIdentity: 'UNMAPPED_RAW_PATH',
        fileIdentityKey: `UNMAPPED_CONFLICT:${pairCheck.rootMappingConflict.rawFullPath}`,
        resolvedPath: pairCheck.rootMappingConflict.rawFullPath,
        tone: 'amber',
        label: 'Chưa xác minh (mapping mâu thuẫn)',
        reason: 'Đường dẫn tệp nguồn nằm trong prefix path_mappings có nhiều đích mâu thuẫn; không tự liên kết SHA-256.',
      };
    }
    if (pairCheck.pathConflict) {
      return {
        status: 'PATH_CONFLICT',
        sha256: '',
        conflictingHashes: [],
        verifiedAgainstSnapshot: false,
        fileIdentity: 'UNMAPPED_RAW_PATH',
        fileIdentityKey: `PATH_CONFLICT:${left} ≠ ${right}`,
        resolvedPath: left,
        tone: 'amber',
        label: 'Chưa xác minh (đường dẫn mâu thuẫn)',
        reason: 'Các trường đường dẫn của cảnh báo (file_path / path / raw_path) mâu thuẫn nhau; không tự chọn một trường để liên kết SHA-256.',
      };
    }
  }

  const effectiveRawPath = declaredRawPath
    || (evPathNorm && isAbsoluteTracePath(evPathNorm) && detailPathNorm && !isAbsoluteTracePath(detailPathNorm) ? evPathNorm : '');
  const findingId = resolveEntityFileIdentity({
    declaredPath,
    rawPath: effectiveRawPath,
    declaredRoot,
  }, ctx);

  if (findingId.pathConflict) {
    return {
      status: 'PATH_CONFLICT',
      sha256: '',
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'amber',
      label: 'Chưa xác minh (đường dẫn mâu thuẫn)',
      reason: 'Các khai báo nguồn (root / path / raw_path) của cảnh báo mâu thuẫn nhau hoặc nằm ngoài phạm vi root hợp lệ; không tự chọn một nguồn để liên kết SHA-256.',
    };
  }

  if (findingId.mappingConflict) {
    return {
      status: 'MAPPING_CONFLICT',
      sha256: '',
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'amber',
      label: 'Chưa xác minh (mapping mâu thuẫn)',
      reason: 'Đường dẫn tệp nguồn nằm trong prefix path_mappings có nhiều đích mâu thuẫn; không tự liên kết SHA-256.',
    };
  }

  if ((ctx.hasMultipleRoots || ctx.hasExternalAbsolutePath) && findingId.fileIdentity === 'UNMAPPED_RAW_PATH' && !findingId.absolutePath) {
    return {
      status: 'UNVERIFIED',
      sha256: '',
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'amber',
      label: 'Chưa xác minh (thiếu root)',
      reason: 'Bằng chứng chứa nhiều thư mục gốc hoặc đường dẫn tuyệt đối ngoài root nhưng cảnh báo không khai báo đường dẫn tuyệt đối/root để phân định tệp.',
    };
  }

  const version = resolveSourceVersion(evidence, 'scan');
  const bucket = ledger.getBucket(findingId.fileIdentityKey, version, 'file');
  const relCandidate = findingId.relativePath
    || (!isAbsoluteTracePath(normalizeTracePath(declaredPath)) ? normalizeTracePath(declaredPath) : '');
  const hasAmbiguousRelSnapshot = Boolean(relCandidate && ledger.ambiguousRelativeSnapshots.has(relCandidate));

  // 1) File-level hash conflict always wins: never present one conflicting hash as primary.
  if (bucket?.hasConflict) {
    return {
      status: 'CONFLICT',
      sha256: '',
      conflictingHashes: [...bucket.conflictingHashes],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'red',
      label: 'Xung đột SHA-256',
      reason: `Phát hiện ${bucket.conflictingHashes.length} giá trị SHA-256 khác nhau cho cùng tệp nguồn và phiên bản; không chọn một giá trị làm hash xác minh.`,
    };
  }

  if (bucket?.invalidFormatSeen) {
    return {
      status: 'INVALID_FORMAT',
      sha256: '',
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'amber',
      label: 'SHA-256 sai định dạng',
      reason: 'Giá trị SHA-256 trong bằng chứng không đúng định dạng 64 ký tự hex; không dùng làm bằng chứng xác minh.',
    };
  }

  // 2) Grounded snapshot entry proven to match this finding's exact File Identity.
  if (bucket && bucket.snapshotHashes.size === 1) {
    const snapSha = [...bucket.snapshotHashes][0];
    return {
      status: 'SNAPSHOT_MATCHED',
      sha256: snapSha,
      conflictingHashes: [],
      verifiedAgainstSnapshot: true,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'green',
      label: 'Khớp snapshot tệp nguồn',
      reason: 'SHA-256 khớp source snapshot do máy chủ ghi nhận cho đúng danh tính tệp (frontend không đọc trực tiếp bytes tệp trên đĩa).',
    };
  }

  // 3) Multi-root / external absolute path / contradictory evidence with ONLY an unscoped relative snapshot -> ambiguous; NEVER pick it.
  if (hasAmbiguousRelSnapshot) {
    return {
      status: 'AMBIGUOUS_SNAPSHOT',
      sha256: '',
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'amber',
      label: 'Chưa xác minh (snapshot mơ hồ)',
      reason: 'Source snapshot chỉ có khóa đường dẫn tương đối trong khi bằng chứng chứa nhiều thư mục gốc hoặc đường dẫn tuyệt đối chưa phân định; không thể quy thuộc snapshot cho đúng tệp của cảnh báo.',
    };
  }

  // 4) No snapshot available: allow a unique snippet-declared full-file hash ONLY when bound to
  //    the finding's exact grounded File Identity (if finding declares raw_path/root/absolute path,
  //    snippets lacking explicit root provenance are rejected).
  const requiresExplicitRootMatch = Boolean(effectiveRawPath || declaredRoot || isAbsoluteTracePath(normalizeTracePath(declaredPath)));
  const candidateSet = requiresExplicitRootMatch
    ? bucket?.groundedSnippetHashes
    : bucket?.snippetHashes;
  if (candidateSet && candidateSet.size === 1) {
    const declaredSha = [...candidateSet][0];
    return {
      status: 'DECLARED_BY_SNIPPET',
      sha256: declaredSha,
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'neutral',
      label: 'Khai báo bởi snippet (chưa đối chiếu snapshot)',
      reason: 'Giá trị SHA-256 do snippet cùng danh tính tệp khai báo; chưa có bản ghi source snapshot tương ứng để đối chiếu độc lập.',
    };
  }

  if (bucket?.invalidFormatSeen) {
    return {
      status: 'INVALID_FORMAT',
      sha256: '',
      conflictingHashes: [],
      verifiedAgainstSnapshot: false,
      fileIdentity: findingId.fileIdentity,
      fileIdentityKey: findingId.fileIdentityKey,
      resolvedPath: findingId.path,
      tone: 'amber',
      label: 'SHA-256 sai định dạng',
      reason: 'Giá trị SHA-256 trong bằng chứng không đúng định dạng 64 ký tự hex; không dùng làm bằng chứng xác minh.',
    };
  }

  return {
    status: 'UNVERIFIED',
    sha256: '',
    conflictingHashes: [],
    verifiedAgainstSnapshot: false,
    fileIdentity: findingId.fileIdentity,
    fileIdentityKey: findingId.fileIdentityKey,
    resolvedPath: findingId.path,
    tone: 'neutral',
    label: 'Chưa có SHA-256',
    reason: 'Không có source snapshot hoặc snippet cùng danh tính tệp cung cấp SHA-256 hợp lệ cho cảnh báo này.',
  };
}

export function resolveSnippetHashStatus(snippet, detailOrEvidence = {}) {
  const isDetail = isPlainObject(detailOrEvidence) && isPlainObject(detailOrEvidence.evidence);
  const detail = isDetail ? detailOrEvidence : null;
  const safeEvidence = isDetail
    ? detailOrEvidence.evidence
    : (isPlainObject(detailOrEvidence) ? detailOrEvidence : {});
  const ctx = buildPathContext(safeEvidence, detail);
  const ledger = buildFileHashLedger(safeEvidence, ctx);
  const id = resolveEntityFileIdentity({
    declaredPath: snippet?.path,
    rawPath: snippet?.raw_path,
    declaredRoot: snippet?.root ?? snippet?.source_root,
  }, ctx);
  const displayPath = (id.fileIdentity === 'SCOPED_ABSOLUTE_ROOT' || id.fileIdentity === 'UNMAPPED_RAW_PATH')
    ? (id.path || readableText(snippet?.path) || '-')
    : (id.path || readableText(snippet?.path) || '-');

  if (id.pathConflict) {
    return {
      status: 'PATH_CONFLICT',
      sha256: '',
      conflictingHashes: [],
      tone: 'amber',
      label: 'Đường dẫn mâu thuẫn',
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }

  if (id.mappingConflict) {
    return {
      status: 'MAPPING_CONFLICT',
      sha256: '',
      conflictingHashes: [],
      tone: 'amber',
      label: 'Mapping mâu thuẫn',
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }

  const rawSha = nonEmptyString(snippet?.sha256);
  const validSha = normalizeValidSha256(rawSha);
  const scope = resolveHashScope(snippet);
  const version = resolveSourceVersion(snippet, ledger.defaultVersion);
  const spanSuffix = scope === 'file' ? '' : formatSpanKey(snippet?.start, snippet?.end);
  const bucket = ledger.getBucket(id.fileIdentityKey, version, scope, spanSuffix);

  if (bucket?.hasConflict) {
    return {
      status: 'CONFLICT',
      sha256: '',
      conflictingHashes: [...bucket.conflictingHashes],
      tone: 'red',
      label: 'Xung đột SHA-256',
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }
  if (bucket?.invalidFormatSeen || (rawSha && !validSha)) {
    return {
      status: 'INVALID_FORMAT',
      sha256: '',
      conflictingHashes: [],
      tone: 'amber',
      label: 'SHA-256 sai định dạng',
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }
  if (!validSha) {
    return {
      status: 'UNVERIFIED',
      sha256: '',
      conflictingHashes: [],
      tone: 'neutral',
      label: 'Chưa có SHA-256',
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }
  if (scope !== 'file') {
    return {
      status: 'DECLARED_NON_FILE_SCOPE',
      sha256: validSha,
      conflictingHashes: [],
      tone: 'neutral',
      label: `Khai báo (${scope})`,
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }
  if (bucket && bucket.snapshotHashes.has(validSha)) {
    return {
      status: 'SNAPSHOT_MATCHED',
      sha256: validSha,
      conflictingHashes: [],
      tone: 'green',
      label: 'Khớp snapshot',
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }
  const relCandidate = id.relativePath || (!isAbsoluteTracePath(normalizeTracePath(snippet?.path)) ? normalizeTracePath(snippet?.path) : '');
  if (relCandidate && ledger.ambiguousRelativeSnapshots.has(relCandidate)) {
    return {
      status: 'DECLARED_BY_SNIPPET',
      sha256: validSha,
      conflictingHashes: [],
      tone: 'amber',
      label: 'Khai báo snippet · snapshot mơ hồ',
      displayPath,
      fileIdentity: id.fileIdentity,
    };
  }
  return {
    status: 'DECLARED_BY_SNIPPET',
    sha256: validSha,
    conflictingHashes: [],
    tone: 'neutral',
    label: 'Khai báo snippet',
    displayPath,
    fileIdentity: id.fileIdentity,
  };
}

export function analyzeDataflow(detailOrEvidence) {
  const isDetail = isPlainObject(detailOrEvidence) && isPlainObject(detailOrEvidence.evidence);
  const detail = isDetail ? detailOrEvidence : null;
  const evidence = isDetail ? detailOrEvidence.evidence : detailOrEvidence;
  if (!isPlainObject(evidence)) {
    return {
      steps: [],
      source: 'none',
      completeness: 'NONE',
      hasSource: false,
      hasIntermediate: false,
      hasSink: false,
      droppedSnippetCount: 0,
      droppedRawTraceCount: 0,
      ambiguousStepCount: 0,
      hadInvalidInput: false,
    };
  }

  const ctx = buildPathContext(evidence, detail);
  const ledger = buildFileHashLedger(evidence, ctx);
  const snipRes = parseSnippetTraceSteps(evidence.snippets, ledger.defaultVersion);
  const rawRes = parseRawTraceSteps(evidence.raw_trace);
  // Assign grounded File Identity AND decoupled file-level SHA-256 ledger status BEFORE any
  // deduplication or pairing so different roots never collide and different code variants on
  // the same file/version NEVER hide a SHA-256 conflict.
  const snipSteps = deduplicateExact(
    attachFileIdentity(snipRes.steps, ctx).map((step) => applyHashLedgerToStep(step, ledger, {allowOwnHash: true})),
  ).map((step) => ({...step, evidenceSources: ['snippets']}));
  // raw_trace never carries hashes; propagate conflict markers only (never fabricate a hash).
  const rawSteps = deduplicateExact(
    attachFileIdentity(rawRes.steps, ctx).map((step) => applyHashLedgerToStep(step, ledger, {allowOwnHash: false})),
  ).map((step) => ({...step, lines: [], evidenceSources: ['raw_trace']}));

  let source = 'none';
  let chosen = [];
  let ambiguousStepCount = 0;

  if (snipSteps.length === 0 && rawSteps.length === 0) {
    source = 'none';
  } else if (snipSteps.length === 0) {
    source = 'raw_trace';
    chosen = rawSteps;
  } else if (rawSteps.length === 0) {
    source = 'snippets';
    chosen = snipSteps;
  } else {
    const {rawToSnip, snipToRaw, ambiguous} = pairSnippetsWithRawTrace(snipSteps, rawSteps);
    const allRawCovered = rawSteps.every((_, ri) => rawToSnip.has(ri));
    const allSnipCovered = snipSteps.every((_, si) => snipToRaw.has(si));

    if (allRawCovered) {
      source = 'snippets';
      chosen = snipSteps.map((s, si) => (
        snipToRaw.has(si)
          ? mergeSteps(rawSteps[snipToRaw.get(si)], s)
          : {...s, ambiguousMatch: ambiguous.has(`s${si}`)}
      ));
    } else {
      source = allSnipCovered ? 'raw_trace' : 'merged';
      const fromRaw = rawSteps.map((r, ri) => (
        rawToSnip.has(ri)
          ? mergeSteps(r, snipSteps[rawToSnip.get(ri)])
          : {...r, ambiguousMatch: ambiguous.has(`r${ri}`)}
      ));
      const snippetOnly = snipSteps
        .map((s, si) => ({s, si}))
        .filter(({si}) => !snipToRaw.has(si))
        .map(({s, si}) => ({...s, ambiguousMatch: ambiguous.has(`s${si}`)}));
      chosen = [...fromRaw, ...snippetOnly];
    }
    ambiguousStepCount = chosen.filter((s) => s.ambiguousMatch).length;
  }

  const steps = orderByRole(chosen).map(stripInternalStepFields);
  const hasSource = steps.some((s) => s.role === 'source');
  const hasIntermediate = steps.some((s) => s.role === 'intermediate');
  const hasSink = steps.some((s) => s.role === 'sink');
  const completeness = steps.length === 0
    ? 'NONE'
    : (hasSource && hasSink)
      ? 'COMPLETE'
      : 'PARTIAL';

  return {
    steps,
    source,
    completeness,
    hasSource,
    hasIntermediate,
    hasSink,
    droppedSnippetCount: snipRes.droppedCount,
    droppedRawTraceCount: rawRes.droppedCount,
    ambiguousStepCount,
    hadInvalidInput: snipRes.droppedCount > 0 || rawRes.droppedCount > 0,
  };
}

export function extractDataflowSteps(evidence) {
  return analyzeDataflow(evidence).steps;
}
