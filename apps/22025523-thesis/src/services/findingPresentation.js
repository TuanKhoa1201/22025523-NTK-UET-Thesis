// Presentation helpers for v2/api findings, citations, dataflow trace, SHA-256 integrity,
// health status semantics, and Human Review states.

const WIRE_INTEGRITY_REGISTRY_SYM = Symbol.for('22025523.restJsonWireIntegrity.v1');

function isWireInvalidSentinel(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) && value.__wireInvalid === true);
}

const FALLBACK_STRICT_INT_KEY_RE = /(?:^|_)(?:count|total|checked|findings|files|scanned|ignored|inventory|matched|invalid|not_verified|unverified|open|pages|page|page_size|limit|citations_matched|citations_invalid|citations_not_verified|citations_total)$/i;

function isWireInvalidIntAnomaly(key, wireIntErr, rawVal) {
  if (!wireIntErr) return false;
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.isWireInvalidIntAnomaly === 'function') {
    return reg.isWireInvalidIntAnomaly(key, wireIntErr, rawVal);
  }
  if (FALLBACK_STRICT_INT_KEY_RE.test(key)) return true;
  if (wireIntErr.reason === 'UNSAFE_INTEGER_WIRE_NUMBER') return true;
  if (wireIntErr.reason === 'NON_INTEGER_WIRE_NUMBER' && typeof rawVal === 'number' && Number.isSafeInteger(rawVal)) {
    return true;
  }
  return false;
}

function getWireMaxScanDepth() {
  const max = globalThis[WIRE_INTEGRITY_REGISTRY_SYM]?.WIRE_MAX_SCAN_DEPTH;
  return Number.isSafeInteger(max) && max > 0 ? max : 128;
}

function getWireObjectIntegrity(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.getWireObjectIntegrity === 'function') return reg.getWireObjectIntegrity(obj);
  const weak = reg?.objects?.get(obj) || null;
  const mat = !Array.isArray(obj) && obj.__wireIntegrity && typeof obj.__wireIntegrity === 'object' ? obj.__wireIntegrity : null;
  if (!weak && !mat) return null;
  return {
    scannerError: Boolean(weak?.scannerError || mat?.scannerError),
    depthExceeded: Boolean(weak?.depthExceeded),
    hasDepthExceededSubtree: Boolean(weak?.hasDepthExceededSubtree || weak?.depthExceeded),
    duplicateKeys: weak?.duplicateKeys || null,
    invalidIntFields: weak?.invalidIntFields || null,
    materialized: mat,
  };
}

function getWireDuplicateKeyInfo(obj, key) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.getWireDuplicateKeyInfo === 'function') return reg.getWireDuplicateKeyInfo(obj, key);
  const meta = reg?.objects?.get(obj);
  if (meta?.scannerError) return {count: 2, conflicting: true, scannerError: true};
  if (meta?.duplicateKeys?.get(key)) return meta.duplicateKeys.get(key);
  const mat = obj.__wireIntegrity && typeof obj.__wireIntegrity === 'object' ? obj.__wireIntegrity : null;
  if (mat?.scannerError) return {count: 2, conflicting: true, scannerError: true};
  if (mat?.duplicateKeys && typeof mat.duplicateKeys === 'object' && !Array.isArray(mat.duplicateKeys) && Object.hasOwn(mat.duplicateKeys, key)) {
    return {count: Number(mat.duplicateKeys[key]?.count) || 2, conflicting: Boolean(mat.duplicateKeys[key]?.conflicting)};
  }
  const val = Object.hasOwn(obj, key) ? obj[key] : undefined;
  if (isWireInvalidSentinel(val) && (val.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY' || val.kind === 'DUPLICATE_WIRE_KEY')) {
    return {count: 2, conflicting: val.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY'};
  }
  return null;
}

function readStrictWireSafeInt(obj, key) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return {present: false, valid: true, value: null, conflict: false, malformed: false, reason: ''};
  }
  if (isWireInvalidSentinel(obj)) {
    const isConflict = obj.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY';
    return {present: true, valid: false, value: null, conflict: isConflict, malformed: !isConflict, reason: String(obj.reason || obj.kind || 'WIRE_INVALID_CONTAINER')};
  }
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.readStrictWireSafeInt === 'function') return reg.readStrictWireSafeInt(obj, key);
  const wire = reg?.objects?.get(obj);
  const mat = obj.__wireIntegrity && typeof obj.__wireIntegrity === 'object' ? obj.__wireIntegrity : null;
  if (wire?.scannerError || wire?.depthExceeded || mat?.scannerError) {
    return {present: true, valid: false, value: null, conflict: false, malformed: true, reason: 'WIRE_SCANNER_ERROR'};
  }
  const dup = getWireDuplicateKeyInfo(obj, key);
  if (dup) {
    return {
      present: true,
      valid: false,
      value: null,
      conflict: Boolean(dup.conflicting),
      malformed: !dup.conflicting,
      reason: dup.conflicting ? 'DUPLICATE_CONFLICTING_WIRE_KEY' : 'DUPLICATE_WIRE_KEY',
    };
  }
  const wireInvalid = wire?.invalidIntFields?.get(key);
  if (wireInvalid) {
    return {present: true, valid: false, value: null, conflict: false, malformed: true, reason: wireInvalid.reason, raw: wireInvalid.raw};
  }
  if (!Object.hasOwn(obj, key)) {
    return {present: false, valid: true, value: null, conflict: false, malformed: false, reason: ''};
  }
  const value = obj[key];
  if (isWireInvalidSentinel(value)) {
    const isConflict = value.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY';
    return {
      present: true,
      valid: false,
      value: null,
      conflict: isConflict,
      malformed: !isConflict,
      reason: String(value.reason || value.kind || 'INVALID_WIRE_NUMBER'),
      ...(value.raw !== undefined ? {raw: String(value.raw)} : {}),
    };
  }
  if (value === undefined || value === null) {
    return {present: false, valid: true, value: null, conflict: false, malformed: false, reason: ''};
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
    return {present: true, valid: false, value: null, conflict: false, malformed: true, reason: 'INVALID_SAFE_INTEGER'};
  }
  return {present: true, valid: true, value, conflict: false, malformed: false, reason: ''};
}

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
    viLabel: 'AI đánh giá cảnh báo có cơ sở',
    tone: 'red',
    summary: 'AI đánh giá cảnh báo có cơ sở dựa trên trích dẫn mã nguồn và SHA-256 hợp lệ. Đây là nhận định đề xuất của mô hình, chưa phải quyết định xác nhận cuối cùng của con người.',
  },
  REFUTED: {
    code: 'REFUTED',
    label: 'REFUTED',
    viLabel: 'AI đề xuất cảnh báo giả (chờ kiểm duyệt)',
    tone: 'amber',
    summary: 'AI đề xuất cảnh báo có thể là giả kèm trích dẫn hợp lệ. Cảnh báo chưa bị loại bỏ và vẫn giữ trạng thái OPEN trong hàng đợi cho tới khi người kiểm duyệt xác nhận.',
  },
  UNDETERMINED: {
    code: 'UNDETERMINED',
    label: 'UNDETERMINED',
    viLabel: 'Chưa đủ bằng chứng để kết luận',
    tone: 'neutral',
    summary: 'Chưa đủ bằng chứng để kết luận (do chưa kiểm chứng đủ luồng dữ liệu/hàm trợ giúp, trích dẫn chưa hợp lệ, lập luận bác bỏ chưa đủ chứng minh hoặc Qwen chưa chạy). Cảnh báo được giữ lại để kiểm tra trực tiếp.',
  },
});

export const DOWNGRADE_REASON_META = Object.freeze({
  INVALID_CITATION: {
    code: 'INVALID_CITATION',
    viLabel: 'Trích dẫn thiếu hoặc không khớp mã nguồn/SHA-256',
    note: 'Mô hình không cung cấp trích dẫn hợp lệ hoặc đoạn trích không khớp tệp, số dòng, nội dung hoặc SHA-256 nguồn lúc quét.',
  },
  UNVERIFIED_HELPER_FLOW: {
    code: 'UNVERIFIED_HELPER_FLOW',
    viLabel: 'Chưa kiểm chứng được luồng qua hàm trợ giúp (helper flow)',
    note: 'Cảnh báo có thể đã khớp trích dẫn mã nguồn (MATCHED) nhưng vẫn bị hạ cấp vì còn lời gọi hàm/luồng dữ liệu phụ thuộc chưa kiểm chứng độc lập.',
  },
  UNVERIFIED_REFUTATION: {
    code: 'UNVERIFIED_REFUTATION',
    viLabel: 'Đề xuất bác bỏ (REFUTED) chưa đủ chứng minh bảo mật độc lập',
    note: 'Mô hình đề xuất REFUTED nhưng hệ thống chưa có chứng minh độc lập đủ điều kiện an toàn nên giữ cảnh báo ở UNDETERMINED.',
  },
  INVALID_SCHEMA: {
    code: 'INVALID_SCHEMA',
    viLabel: 'Phản hồi mô hình sai cấu trúc hoặc mâu thuẫn trạng thái',
    note: 'Phản hồi JSON từ mô hình không đáp ứng hợp đồng kiểm chứng hoặc có trường trạng thái mâu thuẫn.',
  },
  PROMPT_TOO_LARGE: {
    code: 'PROMPT_TOO_LARGE',
    viLabel: 'Ngữ cảnh vượt giới hạn kích thước prompt an toàn',
    note: 'Hồ sơ bằng chứng vượt ngưỡng kích thước prompt cho phép nên không thể suy luận đầy đủ.',
  },
  JOB_TIMEOUT: {
    code: 'JOB_TIMEOUT',
    viLabel: 'Vượt giới hạn thời gian xử lý của phiên quét',
    note: 'Phiên quét chạm ngưỡng thời gian tối đa trước khi hoàn tất suy luận cho cảnh báo này.',
  },
  RESOURCE_BLOCKED: {
    code: 'RESOURCE_BLOCKED',
    viLabel: 'Tạm dừng do giới hạn tài nguyên hoặc kết nối cục bộ',
    note: 'Dịch vụ suy luận cục bộ không sẵn sàng hoặc bị giới hạn tài nguyên tại thời điểm xử lý.',
  },
  DISABLED: {
    code: 'DISABLED',
    viLabel: 'Chế độ đối chứng chỉ chạy OpenGrep (no_llm)',
    note: 'Phiên quét chủ động bỏ qua bước suy luận Qwen theo cấu hình người dùng.',
  },
});

export function normalizeFailureKind(value) {
  const clean = readableText(value).toUpperCase();
  if (!clean || clean === 'NONE' || clean === 'NULL') return '';
  return clean;
}

export function describeDowngradeReason(failureKind, downgradeReason = '', citationCheck = '') {
  const code = normalizeFailureKind(failureKind);
  const rawDetail = readableText(downgradeReason);
  const citNorm = readableText(citationCheck).toUpperCase();
  const matchedCitationNote = citNorm === 'MATCHED'
    ? 'Trích dẫn khớp mã nguồn (MATCHED), nhưng chỉ chứng minh trích dẫn khớp nguồn chứ chưa chứng minh cảnh báo là TP hay FP.'
    : '';

  if (code && Object.hasOwn(DOWNGRADE_REASON_META, code)) {
    const base = DOWNGRADE_REASON_META[code];
    return {
      code,
      hasCode: true,
      viLabel: base.viLabel,
      note: base.note,
      rawDetail,
      matchedCitationNote,
    };
  }
  if (code) {
    return {
      code,
      hasCode: true,
      viLabel: `Nguyên nhân kiểm chứng khác (${code})`,
      note: 'Mã nguyên nhân kỹ thuật do bộ kiểm chứng backend trả về.',
      rawDetail,
      matchedCitationNote,
    };
  }
  return {
    code: '',
    hasCode: false,
    viLabel: 'Chưa có thông tin chi tiết về nguyên nhân hạ cấp từ API',
    note: rawDetail || 'API không cung cấp mã nguyên nhân hạ cấp cụ thể; hệ thống không tự suy diễn nguyên nhân.',
    rawDetail,
    matchedCitationNote,
  };
}

export function summarizeDowngradeReasons(rows = []) {
  const list = Array.isArray(rows) ? rows : [];
  const countsByCode = new Map();
  let totalDowngraded = 0;
  let missingReasonCount = 0;
  let matchedButUndeterminedCount = 0;

  for (let i = 0; i < list.length; i += 1) {
    const row = list[i];
    if (!row || typeof row !== 'object') continue;
    const valStatus = readableText(row.validatedStatus ?? row.validated_status ?? row.assessment?.validated_status).toUpperCase();
    const citCheck = readableText(row.citationCheck ?? row.citation_check ?? row.assessment?.citation_check).toUpperCase();
    const isDowngraded = Boolean(row.validatorDowngraded ?? row.validator_downgraded ?? row.assessment?.validator_downgraded);
    if (valStatus === 'UNDETERMINED' && citCheck === 'MATCHED') {
      matchedButUndeterminedCount += 1;
    }
    if (!isDowngraded) continue;
    totalDowngraded += 1;
    const code = normalizeFailureKind(row.failureKind ?? row.failure_kind ?? row.assessment?.failure_kind);
    if (!code) {
      missingReasonCount += 1;
    } else {
      countsByCode.set(code, (countsByCode.get(code) || 0) + 1);
    }
  }

  const items = [...countsByCode.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([code, count]) => {
      const info = describeDowngradeReason(code);
      return {code, count, viLabel: info.viLabel, note: info.note};
    });

  return {
    totalDowngraded,
    missingReasonCount,
    matchedButUndeterminedCount,
    items,
  };
}

function strictNonNegativeInt(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) return null;
  return value === 0 ? 0 : value;
}

function strictPathArrayCount(value) {
  if (!Array.isArray(value)) return {valid: false, count: null};
  const unique = new Set();
  for (let i = 0; i < value.length; i += 1) {
    const item = value[i];
    if (typeof item !== 'string' || !item.trim()) {
      return {valid: false, count: null};
    }
    unique.add(item.trim());
  }
  return {valid: true, count: unique.size};
}

function resolveMetricFromCandidates(candidates) {
  const validValues = [];
  const invalidFields = [];
  let wireConflict = false;
  for (let i = 0; i < candidates.length; i += 1) {
    const {name, value, isPathArray, sourceObj, sourceKey} = candidates[i];
    if (isPathArray) {
      if (sourceObj && sourceKey) {
        const dup = getWireDuplicateKeyInfo(sourceObj, sourceKey);
        if (dup) {
          if (dup.conflicting) wireConflict = true;
          invalidFields.push(name);
          continue;
        }
      }
      if (value === undefined || value === null) continue;
      const parsed = strictPathArrayCount(value);
      if (parsed.valid) validValues.push({name, value: parsed.count});
      else invalidFields.push(name);
      continue;
    }
    if (sourceObj && sourceKey) {
      const wireCheck = readStrictWireSafeInt(sourceObj, sourceKey);
      if (!wireCheck.present) continue;
      if (wireCheck.valid && wireCheck.value !== null) {
        validValues.push({name, value: wireCheck.value});
      } else {
        if (wireCheck.conflict) wireConflict = true;
        invalidFields.push(name);
      }
      continue;
    }
    if (value === undefined || value === null) continue;
    const parsed = strictNonNegativeInt(value);
    if (parsed !== null) validValues.push({name, value: parsed});
    else invalidFields.push(name);
  }
  if (wireConflict) {
    return {value: null, conflict: true, invalidFields, values: validValues};
  }
  if (validValues.length === 0) {
    return {value: null, conflict: false, invalidFields, values: []};
  }
  const uniqueVals = [...new Set(validValues.map((entry) => entry.value))];
  if (uniqueVals.length > 1) {
    return {value: null, conflict: true, invalidFields, values: validValues};
  }
  return {value: uniqueVals[0], conflict: false, invalidFields, values: validValues};
}

function formatCountOrMissing(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value.toLocaleString('vi-VN')
    : 'Chưa có số liệu';
}

const CANONICAL_COVERAGE_COUNT_KEYS = Object.freeze([
  'java_files_inventory',
  'java_files_opengrep_scanned',
  'java_files_opengrep_ignored',
]);
const CANONICAL_COVERAGE_STATUS_KEY = 'opengrep_paths_telemetry_status';
const COVERAGE_PARTICIPATING_KEYS = Object.freeze(new Set([
  ...CANONICAL_COVERAGE_COUNT_KEYS,
  CANONICAL_COVERAGE_STATUS_KEY,
  'java_files_inventory_count',
  'java_files_count',
  'java_files_scanned',
  'opengrep_scanned_java_files',
  'java_files_actually_scanned',
  'scanned_java_files_count',
  'java_files_ignored',
  'opengrep_ignored_java_files',
  'ignored_java_files_count',
  'scan_manifest',
  'manifest',
  'scan_provenance',
  'paths',
  'scanned',
  'ignored',
  'opengrep_timing',
]));
const COVERAGE_ROOT_CHILD_PREFIXES = Object.freeze(['scan_manifest', 'manifest', 'scan_provenance']);

function isDirectKeyPath(fieldPath) {
  return typeof fieldPath === 'string' && fieldPath.length > 0 && !fieldPath.includes('.') && !fieldPath.includes('[');
}

function pathMatchesAnyPrefix(fieldPath, prefixes) {
  if (typeof fieldPath !== 'string' || !fieldPath || !Array.isArray(prefixes) || prefixes.length === 0) return false;
  return prefixes.some((prefix) => (
    fieldPath === prefix
    || fieldPath.startsWith(`${prefix}.`)
    || fieldPath.startsWith(`${prefix}[`)
  ));
}

function isCorruptCoverageSubcontainer(value) {
  if (value === undefined || value === null) return false;
  return !isPlainObject(value) || isWireInvalidSentinel(value);
}

function subtreeHasWireAnomaly(root, depth = 0, seen = new Set()) {
  if (!root || typeof root !== 'object') return false;
  if (depth > getWireMaxScanDepth()) return true;
  if (seen.has(root)) return false;
  seen.add(root);
  if (isWireInvalidSentinel(root)) return true;
  const integ = getWireObjectIntegrity(root);
  if (integ) {
    if (integ.scannerError || integ.depthExceeded || integ.hasDepthExceededSubtree) return true;
    if (integ.duplicateKeys instanceof Map && integ.duplicateKeys.size > 0) return true;
    if (integ.hasDuplicateKeyInSubtree) return true;
    if (integ.invalidIntFields instanceof Map && integ.invalidIntFields.size > 0) {
      for (const [k, err] of integ.invalidIntFields.entries()) {
        if (isWireInvalidIntAnomaly(k, err, root[k])) return true;
      }
    }
    const mat = integ.materialized;
    if (mat && typeof mat === 'object') {
      if (mat.scannerError === true || mat.hasMalformed === true || mat.hasConflict === true) return true;
      if (mat.duplicateKeys && typeof mat.duplicateKeys === 'object' && Object.keys(mat.duplicateKeys).length > 0) return true;
      if (Array.isArray(mat.duplicateKeyPaths) && mat.duplicateKeyPaths.length > 0) return true;
      if (Array.isArray(mat.invalidFields) && mat.invalidFields.length > 0) return true;
    }
  }
  if (Array.isArray(root)) {
    for (let i = 0; i < root.length; i += 1) {
      if (subtreeHasWireAnomaly(root[i], depth + 1, seen)) return true;
    }
    return false;
  }
  const keys = Object.keys(root);
  for (let i = 0; i < keys.length; i += 1) {
    const k = keys[i];
    if (k === '__wireIntegrity') continue;
    if (subtreeHasWireAnomaly(root[k], depth + 1, seen)) return true;
  }
  return false;
}

function summaryRootHasCoverageWireAnomaly(obj) {
  if (!obj || typeof obj !== 'object') return false;
  if (isWireInvalidSentinel(obj)) return true;
  const integ = getWireObjectIntegrity(obj);
  if (!integ) return false;
  if (integ.scannerError) return true;
  if (integ.duplicateKeys instanceof Map && integ.duplicateKeys.size > 0) return true;
  const mat = integ.materialized;
  if (!mat || typeof mat !== 'object') return false;
  if (mat.scannerError === true) return true;
  if (mat.duplicateKeys && typeof mat.duplicateKeys === 'object' && Object.keys(mat.duplicateKeys).length > 0) return true;
  const dupPaths = Array.isArray(mat.duplicateKeyPaths) ? mat.duplicateKeyPaths : [];
  const invFields = Array.isArray(mat.invalidFields) ? mat.invalidFields : [];
  if (dupPaths.some((p) => isDirectKeyPath(p) || pathMatchesAnyPrefix(p, COVERAGE_ROOT_CHILD_PREFIXES))) return true;
  if (invFields.some((p) => p === '__wireIntegrity' || COVERAGE_PARTICIPATING_KEYS.has(p) || pathMatchesAnyPrefix(p, COVERAGE_ROOT_CHILD_PREFIXES))) {
    return true;
  }
  if (dupPaths.length === 0 && invFields.length === 0 && (mat.hasMalformed === true || mat.hasConflict === true)) {
    return true;
  }
  // If the summary carries `hasMalformed: true` without any own/child invalidFields explaining it,
  // check whether a recorded non-coverage duplicate child actually flagged `hasMalformed: true`;
  // if none did, the malformed flag came from an untrusted reserved `__wireIntegrity` on `sum` itself.
  if (mat.hasMalformed === true && invFields.length === 0 && dupPaths.length > 0) {
    const explainedByChild = dupPaths.some((p) => {
      const topKey = String(p).split(/[.[]/, 1)[0];
      const child = topKey && Object.hasOwn(obj, topKey) ? obj[topKey] : null;
      return Boolean(child && typeof child === 'object' && getWireObjectIntegrity(child)?.materialized?.hasMalformed === true);
    });
    if (!explainedByChild) return true;
  }
  return false;
}

// Verifies the canonical coverage record AND uniform REST integrity across every participating
// coverage container (summary root, scan_manifest / manifest and their subtrees, scan_provenance,
// and job stage metadata) identically on raw wire objects, materialized copies, shallow copies,
// and JSON round-trips — without letting unrelated non-coverage sibling subtrees reject valid data.
function checkCanonicalCoverageSource(canonicalContainers, resolved, {
  summaryRoot = null,
  participatingSubcontainers = [],
  rawSubcontainerSlots = [],
  jobAncestors = [],
} = {}) {
  const keys = [...CANONICAL_COVERAGE_COUNT_KEYS, CANONICAL_COVERAGE_STATUS_KEY];
  if (summaryRoot && summaryRootHasCoverageWireAnomaly(summaryRoot)) {
    return {ok: false, problem: 'CANONICAL_CONTAINER_WIRE_ANOMALY'};
  }
  if (rawSubcontainerSlots.some(isCorruptCoverageSubcontainer)) {
    return {ok: false, problem: 'PARTICIPATING_CONTAINER_INVALID'};
  }
  if (participatingSubcontainers.some((sub) => subtreeHasWireAnomaly(sub))) {
    return {ok: false, problem: 'PARTICIPATING_CONTAINER_WIRE_ANOMALY'};
  }
  if (jobAncestors.some((anc) => Boolean(getWireObjectIntegrity(anc)?.scannerError))) {
    return {ok: false, problem: 'PARTICIPATING_CONTAINER_WIRE_ANOMALY'};
  }
  const source = canonicalContainers.find((obj) => isPlainObject(obj) && keys.every((k) => Object.hasOwn(obj, k)));
  if (!source) return {ok: false, problem: 'MISSING_CANONICAL_FIELDS'};
  if (keys.some((k) => getWireDuplicateKeyInfo(source, k))) return {ok: false, problem: 'CANONICAL_DUPLICATE_KEY'};
  const counts = CANONICAL_COVERAGE_COUNT_KEYS.map((k) => readStrictWireSafeInt(source, k));
  if (counts.some((c) => !c.present || !c.valid || c.value === null)) return {ok: false, problem: 'INVALID_CANONICAL_COUNT'};
  const status = source[CANONICAL_COVERAGE_STATUS_KEY];
  if (typeof status !== 'string' || status.trim().toUpperCase() !== 'VERIFIED') return {ok: false, problem: 'CANONICAL_STATUS_NOT_VERIFIED'};
  if (counts[0].value !== resolved.inventoryCount || counts[1].value !== resolved.scannedCount || counts[2].value !== resolved.ignoredCount) {
    return {ok: false, problem: 'CANONICAL_DIFFERS_FROM_RESOLVED'};
  }
  return {ok: true, problem: ''};
}

/**
 * Separates Java file inventory, OpenGrep actually-scanned files, and ignored files strictly
 * from verified API / scan-manifest fields.
 * - Never hardcodes numbers.
 * - Never treats legacy `summary.java_files_scanned` (which represents Java inventory in v2/api)
 *   as OpenGrep actually-scanned files.
 * - Never derives missing counts by subtraction or addition.
 * - Preserves 0 as valid measurement, null/missing as "Chưa có số liệu", and flags malformed
 *   types or cross-metric contradictions without self-correcting them.
 */
function extractExplicitCoverageStageNumber(stage) {
  if (!isPlainObject(stage)) return null;
  const rawNum = stage.stage_number ?? stage.stage_no ?? stage.number;
  if (typeof rawNum === 'number' && Number.isInteger(rawNum) && rawNum >= 1 && rawNum <= 6) return rawNum;
  if (typeof rawNum === 'string' && /^[1-6]$/.test(rawNum.trim())) return Number(rawNum.trim());
  const rawKey = stage.stage_key ?? stage.key ?? stage.stage_id;
  if (typeof rawKey === 'string') {
    const k = rawKey.trim().toUpperCase();
    if (k === 'INTAKE_VALIDATION') return 1;
    if (k === 'OPENGREP_SCAN') return 2;
    if (k === 'EVIDENCE_COLLECTION') return 3;
    if (k === 'QWEN_INFERENCE') return 4;
    if (k === 'CITATION_VALIDATION') return 5;
    if (k === 'REVIEW_STORE_COMMIT') return 6;
  }
  return null;
}

function resolveCoverageJobStage(stages, targetNumber, fallbackIndex) {
  if (!Array.isArray(stages)) return null;
  const matched = stages.find((st) => extractExplicitCoverageStageNumber(st) === targetNumber);
  if (matched) return matched;
  const fallback = stages[fallbackIndex];
  if (!isPlainObject(fallback)) return null;
  const fallbackExplicit = extractExplicitCoverageStageNumber(fallback);
  return fallbackExplicit === null || fallbackExplicit === targetNumber ? fallback : null;
}

export function resolveJavaFileCounts(summary = null, job = null) {
  const sum = isPlainObject(summary) ? summary : {};
  const scanManifestObj = isPlainObject(sum.scan_manifest) && !isWireInvalidSentinel(sum.scan_manifest)
    ? sum.scan_manifest
    : null;
  const altManifestObj = isPlainObject(sum.manifest) && !isWireInvalidSentinel(sum.manifest) && sum.manifest !== scanManifestObj
    ? sum.manifest
    : null;
  const manifestContainers = [scanManifestObj, altManifestObj].filter(Boolean);
  const manifest = scanManifestObj || altManifestObj || {};
  const provObj = isPlainObject(sum.scan_provenance) && !isWireInvalidSentinel(sum.scan_provenance) ? sum.scan_provenance : null;
  const prov = provObj || {};
  const stage1Obj = resolveCoverageJobStage(job?.stages, 1, 0);
  const stage2Obj = resolveCoverageJobStage(job?.stages, 2, 1);
  const stage1MetaObj = isPlainObject(stage1Obj?.summary_metadata) && !isWireInvalidSentinel(stage1Obj.summary_metadata)
    ? stage1Obj.summary_metadata
    : null;
  const stage2MetaObj = isPlainObject(stage2Obj?.summary_metadata) && !isWireInvalidSentinel(stage2Obj.summary_metadata)
    ? stage2Obj.summary_metadata
    : null;
  const stage1Meta = stage1MetaObj || {};
  const stage2Meta = stage2MetaObj || {};
  const ogTimingObj = isPlainObject(stage2Meta.opengrep_timing) && !isWireInvalidSentinel(stage2Meta.opengrep_timing)
    ? stage2Meta.opengrep_timing
    : null;
  const ogTiming = ogTimingObj || {};
  const manifestPathsEntries = manifestContainers
    .map((m) => ({
      container: m,
      label: m === scanManifestObj ? 'scan_manifest' : 'manifest',
      paths: isPlainObject(m.paths) && !isWireInvalidSentinel(m.paths) ? m.paths : null,
    }));

  const inventoryRes = resolveMetricFromCandidates([
    {name: 'java_files_inventory_count', value: sum.java_files_inventory_count, sourceObj: sum, sourceKey: 'java_files_inventory_count'},
    {name: 'java_files_inventory', value: sum.java_files_inventory, sourceObj: sum, sourceKey: 'java_files_inventory'},
    {name: 'java_files_count', value: sum.java_files_count, sourceObj: sum, sourceKey: 'java_files_count'},
    ...manifestContainers.flatMap((m) => {
      const prefix = m === scanManifestObj ? 'scan_manifest' : 'manifest';
      return [
        {name: `${prefix}.java_files_inventory_count`, value: m.java_files_inventory_count, sourceObj: m, sourceKey: 'java_files_inventory_count'},
        {name: `${prefix}.java_files_inventory`, value: m.java_files_inventory, sourceObj: m, sourceKey: 'java_files_inventory'},
        {name: `${prefix}.java_files_count`, value: m.java_files_count, sourceObj: m, sourceKey: 'java_files_count'},
      ];
    }),
    {name: 'scan_provenance.java_files_inventory_count', value: prov.java_files_inventory_count, sourceObj: prov, sourceKey: 'java_files_inventory_count'},
    {name: 'scan_provenance.java_files_inventory', value: prov.java_files_inventory, sourceObj: prov, sourceKey: 'java_files_inventory'},
    {name: 'scan_provenance.java_files_count', value: prov.java_files_count, sourceObj: prov, sourceKey: 'java_files_count'},
    {name: 'job.stages[0].summary_metadata.java_files_inventory_count', value: stage1Meta.java_files_inventory_count, sourceObj: stage1Meta, sourceKey: 'java_files_inventory_count'},
    {name: 'job.stages[0].summary_metadata.java_files_inventory', value: stage1Meta.java_files_inventory, sourceObj: stage1Meta, sourceKey: 'java_files_inventory'},
    {name: 'job.stages[0].summary_metadata.java_files_count', value: stage1Meta.java_files_count, sourceObj: stage1Meta, sourceKey: 'java_files_count'},
    {name: 'job.stages[1].summary_metadata.java_files_inventory_count', value: stage2Meta.java_files_inventory_count, sourceObj: stage2Meta, sourceKey: 'java_files_inventory_count'},
    {name: 'job.stages[1].summary_metadata.java_files_inventory', value: stage2Meta.java_files_inventory, sourceObj: stage2Meta, sourceKey: 'java_files_inventory'},
    {name: 'job.stages[1].summary_metadata.java_files_count', value: stage2Meta.java_files_count, sourceObj: stage2Meta, sourceKey: 'java_files_count'},
  ]);

  const scannedRes = resolveMetricFromCandidates([
    {name: 'java_files_opengrep_scanned', value: sum.java_files_opengrep_scanned, sourceObj: sum, sourceKey: 'java_files_opengrep_scanned'},
    {name: 'opengrep_scanned_java_files', value: sum.opengrep_scanned_java_files, sourceObj: sum, sourceKey: 'opengrep_scanned_java_files'},
    {name: 'java_files_actually_scanned', value: sum.java_files_actually_scanned, sourceObj: sum, sourceKey: 'java_files_actually_scanned'},
    {name: 'scanned_java_files_count', value: sum.scanned_java_files_count, sourceObj: sum, sourceKey: 'scanned_java_files_count'},
    ...manifestPathsEntries.flatMap(({container: m, label: prefix, paths}) => [
      {name: `${prefix}.java_files_opengrep_scanned`, value: m.java_files_opengrep_scanned, sourceObj: m, sourceKey: 'java_files_opengrep_scanned'},
      {name: `${prefix}.opengrep_scanned_java_files`, value: m.opengrep_scanned_java_files, sourceObj: m, sourceKey: 'opengrep_scanned_java_files'},
      {name: `${prefix}.scanned_java_files_count`, value: m.scanned_java_files_count, sourceObj: m, sourceKey: 'scanned_java_files_count'},
      {name: `${prefix}.java_files_actually_scanned`, value: m.java_files_actually_scanned, sourceObj: m, sourceKey: 'java_files_actually_scanned'},
      ...(paths ? [{name: `${prefix}.paths.scanned`, value: paths.scanned, isPathArray: true, sourceObj: paths, sourceKey: 'scanned'}] : []),
    ]),
    {name: 'scan_provenance.java_files_opengrep_scanned', value: prov.java_files_opengrep_scanned, sourceObj: prov, sourceKey: 'java_files_opengrep_scanned'},
    {name: 'scan_provenance.scanned_java_files_count', value: prov.scanned_java_files_count, sourceObj: prov, sourceKey: 'scanned_java_files_count'},
    {name: 'job.stages[1].summary_metadata.java_files_opengrep_scanned', value: stage2Meta.java_files_opengrep_scanned, sourceObj: stage2Meta, sourceKey: 'java_files_opengrep_scanned'},
    {name: 'job.stages[1].summary_metadata.opengrep_timing.scanned_java_files_count', value: ogTiming.scanned_java_files_count, sourceObj: ogTiming, sourceKey: 'scanned_java_files_count'},
  ]);

  const ignoredRes = resolveMetricFromCandidates([
    {name: 'java_files_opengrep_ignored', value: sum.java_files_opengrep_ignored, sourceObj: sum, sourceKey: 'java_files_opengrep_ignored'},
    {name: 'java_files_ignored', value: sum.java_files_ignored, sourceObj: sum, sourceKey: 'java_files_ignored'},
    {name: 'opengrep_ignored_java_files', value: sum.opengrep_ignored_java_files, sourceObj: sum, sourceKey: 'opengrep_ignored_java_files'},
    {name: 'ignored_java_files_count', value: sum.ignored_java_files_count, sourceObj: sum, sourceKey: 'ignored_java_files_count'},
    ...manifestPathsEntries.flatMap(({container: m, label: prefix, paths}) => [
      {name: `${prefix}.java_files_opengrep_ignored`, value: m.java_files_opengrep_ignored, sourceObj: m, sourceKey: 'java_files_opengrep_ignored'},
      {name: `${prefix}.java_files_ignored`, value: m.java_files_ignored, sourceObj: m, sourceKey: 'java_files_ignored'},
      {name: `${prefix}.ignored_java_files_count`, value: m.ignored_java_files_count, sourceObj: m, sourceKey: 'ignored_java_files_count'},
      ...(paths ? [{name: `${prefix}.paths.ignored`, value: paths.ignored, isPathArray: true, sourceObj: paths, sourceKey: 'ignored'}] : []),
    ]),
    {name: 'scan_provenance.java_files_opengrep_ignored', value: prov.java_files_opengrep_ignored, sourceObj: prov, sourceKey: 'java_files_opengrep_ignored'},
    {name: 'scan_provenance.ignored_java_files_count', value: prov.ignored_java_files_count, sourceObj: prov, sourceKey: 'ignored_java_files_count'},
    {name: 'job.stages[1].summary_metadata.java_files_opengrep_ignored', value: stage2Meta.java_files_opengrep_ignored, sourceObj: stage2Meta, sourceKey: 'java_files_opengrep_ignored'},
    {name: 'job.stages[1].summary_metadata.opengrep_timing.ignored_java_files_count', value: ogTiming.ignored_java_files_count, sourceObj: ogTiming, sourceKey: 'ignored_java_files_count'},
  ]);

  const legacyRes = resolveMetricFromCandidates([
    {name: 'java_files_scanned', value: sum.java_files_scanned, sourceObj: sum, sourceKey: 'java_files_scanned'},
  ]);

  const validTelemetryStatuses = new Set(['VERIFIED', 'MISSING_PATHS_TELEMETRY', 'INCONSISTENT_TELEMETRY']);
  const containerWireConflicts = [];
  const checkContainerWire = (obj, key, label) => {
    if (!obj || typeof obj !== 'object') return;
    if (getWireObjectIntegrity(obj)?.scannerError) {
      containerWireConflicts.push(`${label} (WIRE_SCANNER_ERROR)`);
      return;
    }
    const dup = getWireDuplicateKeyInfo(obj, key);
    if (dup) {
      containerWireConflicts.push(label);
    }
  };
  checkContainerWire(sum, 'scan_manifest', 'scan_manifest');
  checkContainerWire(sum, 'manifest', 'manifest');
  checkContainerWire(sum, 'scan_provenance', 'scan_provenance');
  for (const {container: m, label: prefix} of manifestPathsEntries) {
    checkContainerWire(m, 'paths', `${prefix}.paths`);
  }
  checkContainerWire(job, 'stages', 'job.stages');
  checkContainerWire(stage1Obj, 'summary_metadata', 'job.stages[0].summary_metadata');
  checkContainerWire(stage2Obj, 'summary_metadata', 'job.stages[1].summary_metadata');
  checkContainerWire(stage2Meta, 'opengrep_timing', 'job.stages[1].summary_metadata.opengrep_timing');
  if (getWireObjectIntegrity(sum)?.scannerError) containerWireConflicts.push('summary');
  for (const {container: m, label: prefix} of manifestPathsEntries) {
    if (getWireObjectIntegrity(m)?.scannerError) containerWireConflicts.push(prefix);
  }
  if (getWireObjectIntegrity(stage2Meta)?.scannerError) containerWireConflicts.push('job.stages[1].summary_metadata');

  const telemetryStatusCandidates = [
    {name: 'opengrep_paths_telemetry_status', val: sum.opengrep_paths_telemetry_status, sourceObj: sum, sourceKey: 'opengrep_paths_telemetry_status'},
    ...manifestContainers.map((m) => ({
      name: `${m === scanManifestObj ? 'scan_manifest' : 'manifest'}.opengrep_paths_telemetry_status`,
      val: m.opengrep_paths_telemetry_status,
      sourceObj: m,
      sourceKey: 'opengrep_paths_telemetry_status',
    })),
    {name: 'job.stages[1].summary_metadata.opengrep_paths_telemetry_status', val: stage2Meta.opengrep_paths_telemetry_status, sourceObj: stage2Meta, sourceKey: 'opengrep_paths_telemetry_status'},
  ];
  const parsedTelemetryStatuses = [];
  const invalidTelemetryStatusFields = [];
  let telemetryStatusWireConflict = false;
  for (const item of telemetryStatusCandidates) {
    const dupStatus = getWireDuplicateKeyInfo(item.sourceObj, item.sourceKey);
    if (dupStatus) {
      telemetryStatusWireConflict = true;
      invalidTelemetryStatusFields.push(item.name);
      continue;
    }
    if (isWireInvalidSentinel(item.val)) {
      telemetryStatusWireConflict = true;
      invalidTelemetryStatusFields.push(item.name);
      continue;
    }
    if (item.val === undefined || item.val === null) continue;
    if (typeof item.val !== 'string') {
      invalidTelemetryStatusFields.push(item.name);
      continue;
    }
    const norm = item.val.trim().toUpperCase();
    if (!validTelemetryStatuses.has(norm)) {
      invalidTelemetryStatusFields.push(item.name);
      continue;
    }
    parsedTelemetryStatuses.push(norm);
  }
  const uniqueTelemetryStatuses = [...new Set(parsedTelemetryStatuses)];
  const telemetryStatusConflict = telemetryStatusWireConflict || uniqueTelemetryStatuses.length > 1;
  const telemetryStatus = (!telemetryStatusConflict && uniqueTelemetryStatuses.length === 1) ? uniqueTelemetryStatuses[0] : null;

  const invalidFields = [
    ...inventoryRes.invalidFields,
    ...scannedRes.invalidFields,
    ...ignoredRes.invalidFields,
    ...legacyRes.invalidFields,
    ...invalidTelemetryStatusFields,
    ...containerWireConflicts,
  ];
  const hasInvalidFields = invalidFields.length > 0;

  // Legacy `summary.java_files_scanned` only represents Java inventory in v2/api/service.py;
  // it is NEVER promoted to OpenGrep actually-scanned files.
  const hasExplicitInventory = inventoryRes.value !== null || inventoryRes.conflict;
  const inventoryFromLegacy = !hasExplicitInventory && legacyRes.value !== null;
  let inventoryCount = inventoryRes.conflict
    ? null
    : (inventoryRes.value !== null ? inventoryRes.value : legacyRes.value);
  let scannedCount = scannedRes.conflict ? null : scannedRes.value;
  let ignoredCount = ignoredRes.conflict ? null : ignoredRes.value;

  const rawCounts = {
    inventory: inventoryCount,
    scanned: scannedCount,
    ignored: ignoredCount,
  };

  const inconsistencyReasons = [];
  if (inventoryRes.conflict) {
    inconsistencyReasons.push('Các trường inventory tệp Java từ API có giá trị mâu thuẫn nhau.');
  }
  if (scannedRes.conflict) {
    inconsistencyReasons.push('Các trường số tệp OpenGrep thực quét từ API có giá trị mâu thuẫn nhau.');
  }
  if (ignoredRes.conflict) {
    inconsistencyReasons.push('Các trường số tệp Java bỏ qua từ API có giá trị mâu thuẫn nhau.');
  }
  if (containerWireConflicts.length > 0) {
    inconsistencyReasons.push(`Phản hồi JSON chứa khóa trùng lặp tại vùng dữ liệu tệp Java (${[...new Set(containerWireConflicts)].join(', ')}).`);
  }
  if (telemetryStatusConflict) {
    inconsistencyReasons.push('Trạng thái opengrep_paths_telemetry_status mâu thuẫn hoặc trùng khóa tại biên REST.');
  }

  let hasCrossMetricConflict = false;
  if (containerWireConflicts.length > 0 || telemetryStatus === 'INCONSISTENT_TELEMETRY' || telemetryStatusConflict || invalidTelemetryStatusFields.length > 0) {
    hasCrossMetricConflict = true;
    if (telemetryStatus === 'INCONSISTENT_TELEMETRY') {
      inconsistencyReasons.push('API báo opengrep_paths_telemetry_status = INCONSISTENT_TELEMETRY.');
    } else if (invalidTelemetryStatusFields.length > 0) {
      inconsistencyReasons.push('Trường opengrep_paths_telemetry_status từ API không hợp lệ.');
    }
  }
  if (telemetryStatus === 'MISSING_PATHS_TELEMETRY' && (scannedCount !== null || ignoredCount !== null)) {
    hasCrossMetricConflict = true;
    inconsistencyReasons.push('API báo opengrep_paths_telemetry_status = MISSING_PATHS_TELEMETRY nhưng vẫn có số liệu thực quét/bỏ qua.');
  }
  if (inventoryCount !== null && scannedCount !== null && scannedCount > inventoryCount) {
    hasCrossMetricConflict = true;
    inconsistencyReasons.push(`Số tệp thực quét (${scannedCount}) vượt quá tổng inventory (${inventoryCount}).`);
  }
  if (inventoryCount !== null && ignoredCount !== null && ignoredCount > inventoryCount) {
    hasCrossMetricConflict = true;
    inconsistencyReasons.push(`Số tệp bỏ qua (${ignoredCount}) vượt quá tổng inventory (${inventoryCount}).`);
  }
  if (
    inventoryCount !== null
    && scannedCount !== null
    && ignoredCount !== null
    && (BigInt(scannedCount) + BigInt(ignoredCount)) > BigInt(inventoryCount)
  ) {
    hasCrossMetricConflict = true;
    inconsistencyReasons.push(
      `Tổng thực quét (${scannedCount}) + bỏ qua (${ignoredCount}) = ${(BigInt(scannedCount) + BigInt(ignoredCount)).toString()} vượt quá inventory (${inventoryCount}).`,
    );
  }

  if (
    telemetryStatus === 'VERIFIED'
    && inventoryCount !== null
    && scannedCount !== null
    && ignoredCount !== null
    && (BigInt(scannedCount) + BigInt(ignoredCount)) !== BigInt(inventoryCount)
    && !hasCrossMetricConflict
  ) {
    hasCrossMetricConflict = true;
    inconsistencyReasons.push(
      `API báo VERIFIED nhưng thực quét (${scannedCount}) + bỏ qua (${ignoredCount}) = ${(BigInt(scannedCount) + BigInt(ignoredCount)).toString()} không bằng inventory (${inventoryCount}).`,
    );
  }

  // Canonical coverage is accepted as a single record: status, inventory, scanned and ignored must
  // all be present, valid at the REST boundary, and closed (scanned + ignored === inventory).
  // Anything less is never presented as a verified "actually scanned" count. Legacy
  // `java_files_scanned` stays inventory-only and can never satisfy this gate.
  // The four canonical keys must exist verbatim on ONE source container, AND every container
  // participating in coverage resolution (summary root, scan_manifest/manifest & their subtrees,
  // scan_provenance, job stage metadata) must satisfy the exact same REST integrity standard on
  // wire objects, normalized copies, shallow spreads, and JSON round-trips.
  const participatingSubcontainers = [
    ...manifestContainers,
    ...manifestPathsEntries.map((entry) => entry.paths).filter(Boolean),
    provObj,
    stage1MetaObj,
    stage2MetaObj,
    ogTimingObj,
  ].filter(Boolean);
  const rawSubcontainerSlots = [
    sum.scan_manifest,
    sum.manifest,
    ...manifestContainers.map((m) => m.paths),
    sum.scan_provenance,
    ...(job && Object.hasOwn(job, 'stages') && job.stages !== undefined && job.stages !== null && !Array.isArray(job.stages)
      ? [job.stages]
      : []),
    ...(Array.isArray(job?.stages) ? [job.stages[0], job.stages[1]] : []),
    stage1Obj?.summary_metadata,
    stage2Obj?.summary_metadata,
    stage2MetaObj?.opengrep_timing,
  ];
  const canonicalCheck = checkCanonicalCoverageSource(
    [sum, ...manifestContainers, stage2MetaObj].filter(Boolean),
    {inventoryCount, scannedCount, ignoredCount},
    {
      summaryRoot: isPlainObject(summary) ? summary : null,
      participatingSubcontainers,
      rawSubcontainerSlots,
      jobAncestors: [job, stage1Obj, stage2Obj].filter(Boolean),
    },
  );
  const canonicalVerified = Boolean(
    !hasCrossMetricConflict
    && !hasInvalidFields
    && canonicalCheck.ok
    && telemetryStatus === 'VERIFIED'
    && !inventoryFromLegacy
    && inventoryCount !== null
    && scannedCount !== null
    && ignoredCount !== null
    && scannedCount <= inventoryCount
    && (BigInt(scannedCount) + BigInt(ignoredCount)) === BigInt(inventoryCount),
  );

  if (hasCrossMetricConflict || !canonicalVerified) {
    // Reject contradictory or unverified OpenGrep breakdown rather than presenting it as verified,
    // auto-correcting it, or deriving a missing count.
    scannedCount = null;
    ignoredCount = null;
  }

  const isInconsistent = inconsistencyReasons.length > 0;
  const inconsistencyReason = inconsistencyReasons.join(' ');
  const hasVerifiedScanned = !isInconsistent && canonicalVerified && scannedCount !== null;
  const hasExplicitBreakdown = hasVerifiedScanned;
  const hasUnverifiedBreakdown = !isInconsistent && !hasVerifiedScanned
    && (rawCounts.scanned !== null || rawCounts.ignored !== null || scannedRes.invalidFields.length > 0 || ignoredRes.invalidFields.length > 0);
  const coverageStatus = isInconsistent
    ? 'INCONSISTENT'
    : hasVerifiedScanned
      ? 'VERIFIED'
      : hasUnverifiedBreakdown
        ? 'UNVERIFIED'
        : inventoryCount !== null
          ? 'INVENTORY_ONLY'
          : 'MISSING';

  let primaryLabel = 'Tệp Java trong inventory';
  let primaryValue = inventoryCount;
  if (isInconsistent) {
    primaryLabel = 'Tệp Java (không nhất quán)';
    primaryValue = inventoryCount;
  } else if (hasVerifiedScanned) {
    primaryLabel = 'Tệp Java thực quét (OpenGrep)';
    primaryValue = scannedCount;
  }

  let summaryNote;
  if (isInconsistent) {
    summaryNote = `Số liệu tệp Java không nhất quán (không tự sửa): ${inconsistencyReason}`;
  } else if (hasVerifiedScanned) {
    summaryNote = [
      `Inventory: ${formatCountOrMissing(inventoryCount)}`,
      `Thực quét: ${formatCountOrMissing(scannedCount)}`,
      `Bỏ qua: ${formatCountOrMissing(ignoredCount)}`,
    ].join(' · ');
  } else if (hasUnverifiedBreakdown) {
    summaryNote = inventoryCount !== null
      ? `Inventory: ${formatCountOrMissing(inventoryCount)} · Độ phủ OpenGrep chưa xác minh (thiếu hoặc không hợp lệ trạng thái/bộ đếm, hoặc không khép kín) — không hiển thị số tệp thực quét`
      : 'Độ phủ OpenGrep chưa xác minh (thiếu hoặc không hợp lệ trạng thái/bộ đếm) — không hiển thị số tệp thực quét';
  } else if (inventoryCount !== null && ignoredCount !== null) {
    summaryNote = `Inventory: ${formatCountOrMissing(inventoryCount)} · Thực quét: Chưa có số liệu · Bỏ qua: ${formatCountOrMissing(ignoredCount)}`;
  } else if (inventoryCount !== null) {
    summaryNote = 'API hiện chỉ cung cấp tổng inventory .java (chưa tách số tệp OpenGrep thực quét / bỏ qua)';
  } else if (ignoredCount !== null) {
    summaryNote = `Inventory: Chưa có số liệu · Thực quét: Chưa có số liệu · Bỏ qua: ${formatCountOrMissing(ignoredCount)}`;
  } else if (hasInvalidFields) {
    summaryNote = 'Chưa có số liệu tệp Java hợp lệ (trường từ API sai kiểu dữ liệu)';
  } else {
    summaryNote = 'Chưa có số liệu tệp Java từ API';
  }

  return {
    inventoryCount,
    scannedCount,
    ignoredCount,
    inventoryFromLegacy,
    hasVerifiedScanned,
    hasExplicitBreakdown,
    coverageStatus,
    canonicalCoverageProblem: canonicalVerified ? '' : (canonicalCheck.ok ? 'GATE_CONDITIONS_NOT_MET' : canonicalCheck.problem),
    isInconsistent,
    inconsistencyReason,
    hasInvalidFields,
    invalidFields,
    rawCounts,
    primaryLabel,
    primaryValue,
    summaryNote,
  };
}

export function validatedStatusMeta(status) {
  const key = readableText(status).toUpperCase();
  if (key && Object.hasOwn(VALIDATED_STATUS_META, key)) {
    return VALIDATED_STATUS_META[key];
  }
  if (!key) {
    return {
      code: 'UNKNOWN',
      label: 'UNKNOWN',
      viLabel: 'Chưa có trạng thái nhận định từ API',
      tone: 'neutral',
      isUnknown: true,
      summary: 'API chưa cung cấp trạng thái nhận định hợp lệ; cảnh báo được giữ lại để kiểm tra thủ công.',
    };
  }
  return {
    code: key,
    label: key,
    viLabel: `Trạng thái chưa nhận diện (${key})`,
    tone: 'neutral',
    isUnknown: true,
    summary: `Backend trả về mã trạng thái chưa thuộc hợp đồng hiện hành (${key}). Giữ nguyên mã gốc thay vì tự ánh xạ sang UNDETERMINED.`,
  };
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
  if (key && Object.hasOwn(HUMAN_REVIEW_META, key)) {
    return HUMAN_REVIEW_META[key];
  }
  if (!key) {
    return {
      code: 'UNKNOWN',
      label: 'UNKNOWN',
      viLabel: 'Chưa có trạng thái kiểm duyệt',
      tone: 'neutral',
      isUnknown: true,
      summary: 'API chưa cung cấp trạng thái Human Review hợp lệ.',
    };
  }
  return {
    code: key,
    label: key,
    viLabel: `Trạng thái kiểm duyệt chưa nhận diện (${key})`,
    tone: 'neutral',
    isUnknown: true,
    summary: `Backend trả về mã trạng thái kiểm duyệt chưa thuộc hợp đồng hiện hành (${key}). Giữ nguyên mã gốc thay vì tự ánh xạ sang OPEN.`,
  };
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

export function parseStrictBoolean(value, {wasInvalid = false} = {}) {
  if (wasInvalid) {
    return {state: 'INVALID', value: null, malformed: true};
  }
  if (value === undefined || value === null) {
    return {state: 'MISSING', value: null, malformed: false};
  }
  if (typeof value === 'boolean') {
    return {state: 'VALID', value, malformed: false};
  }
  return {state: 'INVALID', value: null, malformed: true};
}

function parseStrictNonEmptyString(value, {wasInvalid = false} = {}) {
  if (wasInvalid) {
    return {state: 'INVALID', value: null, malformed: true};
  }
  if (value === undefined || value === null) {
    return {state: 'MISSING', value: null, malformed: false};
  }
  if (typeof value === 'string' && value.trim()) {
    return {state: 'VALID', value: value.trim(), malformed: false};
  }
  return {state: 'INVALID', value: null, malformed: true};
}

function parseStrictStringArray(value, {wasInvalid = false} = {}) {
  if (wasInvalid) {
    return {state: 'INVALID', value: null, malformed: true};
  }
  if (value === undefined || value === null) {
    return {state: 'MISSING', value: null, malformed: false};
  }
  if (!Array.isArray(value)) {
    return {state: 'INVALID', value: null, malformed: true};
  }
  const items = [];
  for (let i = 0; i < value.length; i += 1) {
    const item = value[i];
    if (typeof item !== 'string' || !item.trim()) {
      return {state: 'INVALID', value: null, malformed: true};
    }
    items.push(item.trim());
  }
  return {state: 'VALID', value: items, malformed: false};
}

const ARCHITECTURE_BOOLEAN_FIELDS = Object.freeze([
  'cloud_llm_enabled',
  'human_review_required',
  'stale_source_guard_enabled',
]);

const ARCHITECTURE_STRING_FIELDS = Object.freeze([
  'static_engine',
  'llm_engine',
]);

/**
 * Validates and normalizes `health.architecture` strictly without calling `String()` or
 * truthiness coercion on arbitrary values (preventing crashes from objects with null
 * `toString`/`valueOf` and preventing `"false"` from being treated as `true`).
 */
export function normalizeHealthArchitecture(
  rawArchitecture,
  {preValidatedInvalidFields = null, preValidatedMalformed = false} = {},
) {
  const invalidSet = new Set(Array.isArray(preValidatedInvalidFields) ? preValidatedInvalidFields : []);

  if (preValidatedMalformed || (rawArchitecture !== undefined && rawArchitecture !== null && !isPlainObject(rawArchitecture))) {
    const fields = {
      static_engine: {state: 'INVALID', value: null, malformed: true},
      llm_engine: {state: 'INVALID', value: null, malformed: true},
      priority_cwes: {state: 'INVALID', value: null, malformed: true},
      cloud_llm_enabled: {state: 'INVALID', value: null, malformed: true},
      human_review_required: {state: 'INVALID', value: null, malformed: true},
      stale_source_guard_enabled: {state: 'INVALID', value: null, malformed: true},
    };
    return {
      present: false,
      malformed: true,
      hasAnyData: true,
      sanitized: {},
      fields,
      invalidFields: ['architecture'],
      missingSafetyFlags: [...ARCHITECTURE_BOOLEAN_FIELDS],
      hasInvalidFields: true,
      hasMissingSafetyFlags: true,
      verifiedSafePolicy: false,
      hasUnsafePolicyValue: false,
      schemaWarnings: ['Trường architecture từ /api/health không đúng định dạng đối tượng.'],
    };
  }

  if (rawArchitecture === undefined || rawArchitecture === null) {
    const fields = {
      static_engine: {state: 'MISSING', value: null, malformed: false},
      llm_engine: {state: 'MISSING', value: null, malformed: false},
      priority_cwes: {state: 'MISSING', value: null, malformed: false},
      cloud_llm_enabled: {state: 'MISSING', value: null, malformed: false},
      human_review_required: {state: 'MISSING', value: null, malformed: false},
      stale_source_guard_enabled: {state: 'MISSING', value: null, malformed: false},
    };
    return {
      present: false,
      malformed: false,
      hasAnyData: false,
      sanitized: null,
      fields,
      invalidFields: [],
      missingSafetyFlags: [...ARCHITECTURE_BOOLEAN_FIELDS],
      hasInvalidFields: false,
      hasMissingSafetyFlags: true,
      verifiedSafePolicy: false,
      hasUnsafePolicyValue: false,
      schemaWarnings: [],
    };
  }

  const fields = {};
  const sanitized = {};
  const invalidFields = [];
  const schemaWarnings = [];

  for (const key of ARCHITECTURE_STRING_FIELDS) {
    const parsed = parseStrictNonEmptyString(
      Object.hasOwn(rawArchitecture, key) ? rawArchitecture[key] : undefined,
      {wasInvalid: invalidSet.has(key)},
    );
    fields[key] = parsed;
    sanitized[key] = parsed.value;
    if (parsed.malformed) {
      invalidFields.push(key);
      schemaWarnings.push(`Trường architecture.${key} từ /api/health sai kiểu chuỗi hợp lệ.`);
    }
  }

  const priorityCwes = parseStrictStringArray(
    Object.hasOwn(rawArchitecture, 'priority_cwes') ? rawArchitecture.priority_cwes : undefined,
    {wasInvalid: invalidSet.has('priority_cwes')},
  );
  fields.priority_cwes = priorityCwes;
  sanitized.priority_cwes = priorityCwes.value;
  if (priorityCwes.malformed) {
    invalidFields.push('priority_cwes');
    schemaWarnings.push('Trường architecture.priority_cwes từ /api/health không đúng định dạng mảng chuỗi.');
  }

  const missingSafetyFlags = [];
  for (const key of ARCHITECTURE_BOOLEAN_FIELDS) {
    const parsed = parseStrictBoolean(
      Object.hasOwn(rawArchitecture, key) ? rawArchitecture[key] : undefined,
      {wasInvalid: invalidSet.has(key)},
    );
    fields[key] = parsed;
    sanitized[key] = parsed.value;
    if (parsed.malformed) {
      invalidFields.push(key);
      schemaWarnings.push(`Trường architecture.${key} từ /api/health sai kiểu boolean.`);
    } else if (parsed.state === 'MISSING') {
      missingSafetyFlags.push(key);
    }
  }

  const hasInvalidFields = invalidFields.length > 0;
  const hasMissingSafetyFlags = missingSafetyFlags.length > 0;
  const hasAnyData = Object.values(fields).some((entry) => entry.state !== 'MISSING');
  const hasUnsafePolicyValue = (
    fields.cloud_llm_enabled.value === true
    || fields.human_review_required.value === false
    || fields.stale_source_guard_enabled.value === false
  );
  const verifiedSafePolicy = (
    !hasInvalidFields
    && !hasMissingSafetyFlags
    && fields.cloud_llm_enabled.value === false
    && fields.human_review_required.value === true
    && fields.stale_source_guard_enabled.value === true
  );

  return {
    present: true,
    malformed: false,
    hasAnyData,
    sanitized,
    fields,
    invalidFields,
    missingSafetyFlags,
    hasInvalidFields,
    hasMissingSafetyFlags,
    verifiedSafePolicy,
    hasUnsafePolicyValue,
    schemaWarnings,
  };
}

export function normalizeDegradedReasons(raw) {
  if (raw === undefined || raw === null) {
    return {reasons: [], malformed: false};
  }
  if (!Array.isArray(raw)) {
    return {reasons: [], malformed: true};
  }
  const reasons = [];
  let malformed = false;
  for (let i = 0; i < raw.length; i += 1) {
    const item = raw[i];
    if (typeof item === 'string' && item.trim()) {
      reasons.push(item.trim());
    } else if (item !== null && item !== undefined) {
      malformed = true;
    }
  }
  return {reasons, malformed};
}

const ISO_8601_DATETIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/i;

export function parseOpengrepTimestampMs(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  const match = ISO_8601_DATETIME_RE.exec(trimmed);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const tz = match[8];
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  // Reject calendar rollovers such as 2026-02-31 or 2026-04-31.
  const utcCheck = new Date(Date.UTC(year, month - 1, day));
  if (
    utcCheck.getUTCFullYear() !== year
    || utcCheck.getUTCMonth() !== month - 1
    || utcCheck.getUTCDate() !== day
  ) {
    return null;
  }
  if (tz.toUpperCase() !== 'Z') {
    const tzHour = Number(tz.slice(1, 3));
    const tzMin = Number(tz.slice(4, 6));
    if (tzHour > 23 || tzMin > 59) return null;
  }
  const parsed = Date.parse(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseStrictPositiveTtlSeconds(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return null;
  const ttlMs = value * 1000;
  if (!Number.isFinite(ttlMs) || ttlMs > Number.MAX_SAFE_INTEGER) return null;
  return value;
}

/**
 * Resolves verifiable server-grounded expiry evidence for an OpenGrep active probe snapshot
 * using only real backend fields (`probed_at`, `expires_at`, `ttl_seconds`).
 *
 * Invariants:
 * - `ttl_seconds` MUST be a strictly positive finite number (> 0); 0, negative, string,
 *   boolean, NaN, Infinity, or overflow values are marked malformed.
 * - `probed_at` and `expires_at`, when present, MUST be valid ISO-8601 timestamps with timezone.
 * - Never fabricates a probe deadline from relative `ttl_seconds` + `receivedAtMs` alone when
 *   both `probed_at` and `expires_at` are missing.
 * - Once a server timestamp (`expires_at` or `probed_at`) anchors validity, `receivedAtMs + ttl`
 *   (and `receivedAtMs + (expires_at - probed_at)`) is applied strictly as a fail-closed upper bound
 *   to clamp forward server clock skew.
 */
export function resolveOpengrepExpiryEvidence(
  og,
  receivedAtMs = null,
  {serverCheckedAtMs = null, serverCheckedAtMalformed = false, rootHealthObj = null} = {},
) {
  if (!isPlainObject(og)) {
    return {
      expiresAtMs: null,
      serverExpiresAtMs: null,
      hasVerifiableBasis: false,
      basis: 'NONE',
      contradictory: false,
      malformed: false,
      expiredByServerClock: false,
      probedAtMs: null,
      explicitExpiresMs: null,
      ttlSeconds: null,
    };
  }
  const hasDuplicateExpiryKey = Boolean(
    serverCheckedAtMalformed
    || getWireDuplicateKeyInfo(og, 'probed_at')
    || getWireDuplicateKeyInfo(og, 'expires_at')
    || getWireDuplicateKeyInfo(og, 'ttl_seconds')
    || getWireObjectIntegrity(og)?.scannerError
    || (rootHealthObj && (
      getWireDuplicateKeyInfo(rootHealthObj, 'opengrep')
      || getWireDuplicateKeyInfo(rootHealthObj, 'checked_at')
      || getWireDuplicateKeyInfo(rootHealthObj, 'status')
      || getWireObjectIntegrity(rootHealthObj)?.scannerError
    )),
  );
  if (hasDuplicateExpiryKey) {
    return {
      expiresAtMs: null,
      serverExpiresAtMs: null,
      hasVerifiableBasis: false,
      basis: 'MALFORMED',
      contradictory: false,
      malformed: true,
      expiredByServerClock: false,
      probedAtMs: null,
      explicitExpiresMs: null,
      ttlSeconds: null,
    };
  }

  const hasProbedAtField = og.probed_at !== undefined && og.probed_at !== null;
  const hasExpiresAtField = og.expires_at !== undefined && og.expires_at !== null;
  const hasTtlField = og.ttl_seconds !== undefined && og.ttl_seconds !== null;

  const probedAtMs = hasProbedAtField ? parseOpengrepTimestampMs(og.probed_at) : null;
  const explicitExpiresMs = hasExpiresAtField ? parseOpengrepTimestampMs(og.expires_at) : null;
  const ttlSeconds = hasTtlField ? parseStrictPositiveTtlSeconds(og.ttl_seconds) : null;

  const malformed = (
    (hasProbedAtField && probedAtMs === null)
    || (hasExpiresAtField && explicitExpiresMs === null)
    || (hasTtlField && ttlSeconds === null)
  );
  if (malformed) {
    return {
      expiresAtMs: null,
      serverExpiresAtMs: null,
      hasVerifiableBasis: false,
      basis: 'MALFORMED',
      contradictory: false,
      malformed: true,
      expiredByServerClock: false,
      probedAtMs,
      explicitExpiresMs,
      ttlSeconds,
    };
  }

  if (explicitExpiresMs !== null && probedAtMs !== null && explicitExpiresMs <= probedAtMs) {
    return {
      expiresAtMs: explicitExpiresMs,
      serverExpiresAtMs: explicitExpiresMs,
      hasVerifiableBasis: false,
      basis: 'CONTRADICTORY',
      contradictory: true,
      malformed: false,
      expiredByServerClock: false,
      probedAtMs,
      explicitExpiresMs,
      ttlSeconds,
    };
  }

  const candidates = [];
  let basis = 'NONE';
  const safeReceivedAt = (typeof receivedAtMs === 'number' && Number.isFinite(receivedAtMs)) ? receivedAtMs : null;
  const safeServerCheckedAt = (typeof serverCheckedAtMs === 'number' && Number.isFinite(serverCheckedAtMs)) ? serverCheckedAtMs : null;

  // Fail-closed on contradictory server clock order:
  // Backend creates `checked_at` AFTER obtaining the OpenGrep probe snapshot (`probed_at <= checked_at`).
  // A response claiming `checked_at < probed_at` (or remaining server life > ttl_seconds) is
  // temporally contradictory and MUST NEVER be promoted to VERIFIED.
  if (safeServerCheckedAt !== null && probedAtMs !== null && safeServerCheckedAt < probedAtMs) {
    return {
      expiresAtMs: null,
      serverExpiresAtMs: explicitExpiresMs,
      hasVerifiableBasis: false,
      basis: 'CONTRADICTORY',
      contradictory: true,
      malformed: false,
      expiredByServerClock: false,
      probedAtMs,
      explicitExpiresMs,
      ttlSeconds,
    };
  }
  if (
    safeServerCheckedAt !== null
    && probedAtMs === null
    && explicitExpiresMs !== null
    && ttlSeconds !== null
    && (explicitExpiresMs - safeServerCheckedAt) > Math.round(ttlSeconds * 1000)
  ) {
    return {
      expiresAtMs: null,
      serverExpiresAtMs: explicitExpiresMs,
      hasVerifiableBasis: false,
      basis: 'CONTRADICTORY',
      contradictory: true,
      malformed: false,
      expiredByServerClock: false,
      probedAtMs,
      explicitExpiresMs,
      ttlSeconds,
    };
  }

  const derivedServerExpiresMs = (probedAtMs !== null && ttlSeconds !== null && Number.isFinite(probedAtMs + ttlSeconds * 1000))
    ? Math.round(probedAtMs + ttlSeconds * 1000)
    : null;
  const serverExpiresAtMs = explicitExpiresMs !== null && derivedServerExpiresMs !== null
    ? Math.min(explicitExpiresMs, derivedServerExpiresMs)
    : (explicitExpiresMs ?? derivedServerExpiresMs);

  if (explicitExpiresMs !== null) {
    candidates.push(explicitExpiresMs);
    basis = probedAtMs !== null ? 'PROBED_AND_EXPIRES_AT' : 'EXPIRES_AT';
    if (safeReceivedAt !== null && probedAtMs !== null) {
      const windowMs = explicitExpiresMs - probedAtMs;
      if (Number.isFinite(windowMs) && windowMs > 0) {
        const skewBound = safeReceivedAt + windowMs;
        if (Number.isFinite(skewBound)) candidates.push(skewBound);
      }
    }
  }

  if (derivedServerExpiresMs !== null) {
    candidates.push(derivedServerExpiresMs);
    if (basis === 'NONE') basis = 'PROBED_AT_PLUS_TTL';
  }

  if (candidates.length > 0 && ttlSeconds !== null && safeReceivedAt !== null) {
    const ttlMs = ttlSeconds * 1000;
    const receivedBound = safeReceivedAt + ttlMs;
    if (Number.isFinite(receivedBound)) {
      candidates.push(receivedBound);
    }
  }

  // When server provides `checked_at` alongside server-stamped expiry, tighten the remaining
  // validity window purely on server time (clock-skew immune) and immediately expire if
  // `checked_at >= serverExpiresAtMs`.
  let expiredByServerClock = false;
  if (safeServerCheckedAt !== null && serverExpiresAtMs !== null) {
    if (safeServerCheckedAt >= serverExpiresAtMs) {
      expiredByServerClock = true;
      if (safeReceivedAt !== null) {
        candidates.push(safeReceivedAt);
      }
    } else if (safeReceivedAt !== null && (probedAtMs === null || safeServerCheckedAt >= probedAtMs)) {
      const serverRemainingMs = serverExpiresAtMs - safeServerCheckedAt;
      if (Number.isFinite(serverRemainingMs) && serverRemainingMs >= 0) {
        const serverRemainingBound = safeReceivedAt + serverRemainingMs;
        if (Number.isFinite(serverRemainingBound)) candidates.push(serverRemainingBound);
      }
    }
  }

  if (candidates.length === 0) {
    return {
      expiresAtMs: null,
      serverExpiresAtMs: null,
      hasVerifiableBasis: false,
      basis: hasTtlField ? 'TTL_ONLY_UNANCHORED' : (hasProbedAtField ? 'PROBED_AT_ONLY' : 'NONE'),
      contradictory: false,
      malformed: false,
      expiredByServerClock: false,
      probedAtMs,
      explicitExpiresMs,
      ttlSeconds,
    };
  }

  const expiresAtMs = Math.min(...candidates);
  if (!Number.isFinite(expiresAtMs)) {
    return {
      expiresAtMs: null,
      serverExpiresAtMs: null,
      hasVerifiableBasis: false,
      basis: 'MALFORMED',
      contradictory: false,
      malformed: true,
      expiredByServerClock: false,
      probedAtMs,
      explicitExpiresMs,
      ttlSeconds,
    };
  }

  return {
    expiresAtMs,
    serverExpiresAtMs,
    hasVerifiableBasis: true,
    basis,
    contradictory: false,
    malformed: false,
    expiredByServerClock,
    probedAtMs,
    explicitExpiresMs,
    ttlSeconds,
  };
}

export function resolveOpengrepExpiresAtMs(og, receivedAtMs = null, options = {}) {
  const evidence = resolveOpengrepExpiryEvidence(og, receivedAtMs, options);
  return evidence.hasVerifiableBasis ? evidence.expiresAtMs : null;
}

export function describeOpengrepHealth(og = {}, recentVerifiedVersion = null, options = {}) {
  if (og !== null && og !== undefined && !isPlainObject(og)) {
    return {
      code: 'OPENGREP_NOT_VERIFIED',
      healthState: 'MALFORMED',
      tone: 'amber',
      isVerified: false,
      probeInProgress: false,
      deferredByActiveScan: false,
      ttlExpired: false,
      expiresAtMs: null,
      malformed: true,
      label: 'Dữ liệu probe OpenGrep không đúng định dạng',
      detail: 'Trường opengrep từ /api/health sai kiểu dữ liệu; không thể xác minh trạng thái engine.',
    };
  }
  const safe = isPlainObject(og) ? og : {};
  const probeStatus = typeof safe.probe_status === 'string' ? safe.probe_status.trim().toUpperCase() : '';
  const healthState = typeof safe.health_state === 'string' ? safe.health_state.trim().toUpperCase() : '';
  const hasVerificationLevelField = safe.verification_level !== undefined && safe.verification_level !== null;
  const verificationLevel = typeof safe.verification_level === 'string' ? safe.verification_level.trim().toUpperCase() : '';
  const probeInProgress = safe.probe_in_progress === true;
  const deferredByActiveScan = safe.deferred_by_active_scan === true;
  const binaryPresent = typeof safe.binary_present === 'boolean' ? safe.binary_present : undefined;

  const nowMs = typeof options.nowMs === 'number' && Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const snapshotReceivedAtMs = typeof options.snapshotReceivedAtMs === 'number' && Number.isFinite(options.snapshotReceivedAtMs)
    ? options.snapshotReceivedAtMs
    : null;
  const serverCheckedAtMs = typeof options.serverCheckedAtMs === 'number' && Number.isFinite(options.serverCheckedAtMs)
    ? options.serverCheckedAtMs
    : null;
  const serverCheckedAtMalformed = Boolean(options.serverCheckedAtMalformed);
  const rootHealthObj = options.rootHealthObj || null;
  const expiryEvidence = resolveOpengrepExpiryEvidence(safe, snapshotReceivedAtMs, {
    serverCheckedAtMs,
    serverCheckedAtMalformed,
    rootHealthObj,
  });

  const hasDuplicateOgKey = Boolean(
    getWireDuplicateKeyInfo(safe, 'available')
    || getWireDuplicateKeyInfo(safe, 'runtime_verified')
    || getWireDuplicateKeyInfo(safe, 'probe_status')
    || getWireDuplicateKeyInfo(safe, 'health_state')
    || getWireDuplicateKeyInfo(safe, 'verification_level')
    || getWireDuplicateKeyInfo(safe, 'probe_in_progress')
    || getWireDuplicateKeyInfo(safe, 'deferred_by_active_scan')
    || getWireDuplicateKeyInfo(safe, 'binary_present')
    || getWireDuplicateKeyInfo(safe, 'process_instance_id')
    || getWireDuplicateKeyInfo(safe, 'probe_execution_identity_sha256')
    || getWireDuplicateKeyInfo(safe, 'binary_identity_sha256')
    || getWireDuplicateKeyInfo(safe, 'rules_sha256')
    || getWireDuplicateKeyInfo(safe, '__wireIntegrity')
    || getWireObjectIntegrity(safe)?.scannerError,
  );

  const hasMalformedOpengrepFields = (
    hasDuplicateOgKey
    || (safe.available !== undefined && safe.available !== null && typeof safe.available !== 'boolean')
    || (safe.runtime_verified !== undefined && safe.runtime_verified !== null && typeof safe.runtime_verified !== 'boolean')
    || (safe.probe_in_progress !== undefined && safe.probe_in_progress !== null && typeof safe.probe_in_progress !== 'boolean')
    || (safe.deferred_by_active_scan !== undefined && safe.deferred_by_active_scan !== null && typeof safe.deferred_by_active_scan !== 'boolean')
    || (safe.binary_present !== undefined && safe.binary_present !== null && typeof safe.binary_present !== 'boolean')
    || (safe.probe_status !== undefined && safe.probe_status !== null && typeof safe.probe_status !== 'string')
    || (safe.health_state !== undefined && safe.health_state !== null && typeof safe.health_state !== 'string')
    || (hasVerificationLevelField && !verificationLevel)
    || expiryEvidence.malformed
    || (expiryEvidence.contradictory && !(expiryEvidence.explicitExpiresMs !== null && nowMs >= expiryEvidence.explicitExpiresMs))
    || safe.malformed === true
  );
  const ttlSeconds = expiryEvidence.ttlSeconds;
  const canaryMs = (
    typeof safe.canary_duration_ms === 'number' && Number.isFinite(safe.canary_duration_ms) && safe.canary_duration_ms >= 0
  ) ? safe.canary_duration_ms : null;
  const resolvedPath = readableText(safe.resolved_path);
  const versionText = readableText(safe.version) || readableText(safe.executable) || readableText(safe.binary);
  const errorText = readableText(safe.error);
  const probedAtText = readableText(safe.probed_at);
  const safeRecentVersion = readableText(recentVerifiedVersion);

  const rawExpiresAtMs = expiryEvidence.hasVerifiableBasis
    ? expiryEvidence.expiresAtMs
    : (expiryEvidence.contradictory ? expiryEvidence.explicitExpiresMs : null);
  const optionExpiresAtMs = typeof options.expiresAtMs === 'number' && Number.isFinite(options.expiresAtMs)
    ? options.expiresAtMs
    : null;
  const expiresAtMs = rawExpiresAtMs !== null && optionExpiresAtMs !== null
    ? Math.min(rawExpiresAtMs, optionExpiresAtMs)
    : (rawExpiresAtMs ?? optionExpiresAtMs);
  const ttlExpired = Boolean(
    options.forceExpired === true
    || safe.ttl_expired_locally === true
    || expiryEvidence.expiredByServerClock === true
    || probeStatus === 'EXPIRED'
    || healthState === 'EXPIRED'
    || (expiresAtMs !== null && nowMs >= expiresAtMs),
  );

  // Strict fail-closed verification contract:
  // - Never self-attest VERIFIED from `available: true` alone without explicit backend probe proof.
  // - Never mark VERIFIED without verifiable server-anchored expiry evidence (`expires_at`, or
  //   `probed_at` + strictly positive `ttl_seconds`) that has not yet expired.
  // - Never mark VERIFIED while probe_in_progress is true, runtime_verified is false,
  //   binary_present is false, fields are malformed, status/timestamps contradict VERIFIED,
  //   or TTL has expired.
  const hasExplicitVerificationProof = (
    safe.runtime_verified === true
    || probeStatus === 'VERIFIED'
    || healthState === 'VERIFIED'
  );
  const noVerificationContradiction = (
    !hasMalformedOpengrepFields
    && !expiryEvidence.contradictory
    && safe.available === true
    && safe.runtime_verified !== false
    && !probeInProgress
    && (!probeStatus || probeStatus === 'VERIFIED')
    && (!healthState || healthState === 'VERIFIED')
    && (!verificationLevel || verificationLevel === 'SCAN_VERIFIED')
    && binaryPresent !== false
  );
  const hasVerifiableExpiry = Boolean(
    expiryEvidence.hasVerifiableBasis
    && !expiryEvidence.contradictory
    && expiresAtMs !== null
    && Number.isFinite(expiresAtMs),
  );
  const isVerified = hasExplicitVerificationProof && noVerificationContradiction && hasVerifiableExpiry && !ttlExpired;

  if (isVerified) {
    const details = [];
    if (resolvedPath) details.push(`Đường dẫn: ${resolvedPath}`);
    if (canaryMs !== null) details.push(`Canary probe: ${Math.round(canaryMs)} ms`);
    if (ttlSeconds !== null) details.push(`TTL snapshot: ${Math.round(ttlSeconds)}s`);
    if (probedAtText) details.push(`Kiểm tra lúc: ${probedAtText}`);
    return {
      code: 'OPENGREP_AVAILABLE',
      healthState: 'VERIFIED',
      tone: 'green',
      isVerified: true,
      probeInProgress: false,
      deferredByActiveScan: false,
      ttlExpired: false,
      expiresAtMs,
      malformed: false,
      label: `Đã xác minh · VERIFIED (${versionText || 'opengrep'})`,
      detail: details.join(' · '),
    };
  }

  if (probeStatus === 'TIMEOUT' || healthState === 'PROBE_TIMEOUT') {
    return {
      code: 'OPENGREP_PROBE_TIMEOUT',
      healthState: 'PROBE_TIMEOUT',
      tone: 'red',
      isVerified: false,
      probeInProgress,
      deferredByActiveScan,
      ttlExpired: false,
      expiresAtMs,
      malformed: hasMalformedOpengrepFields,
      label: 'Quá thời gian active probe OpenGrep (PROBE_TIMEOUT)',
      detail: errorText || 'Tiến trình active health probe OpenGrep vượt ngưỡng timeout cấu hình và đã được dừng an toàn.',
    };
  }

  if (healthState === 'ENGINE_MISSING' || (binaryPresent === false && (probeStatus === 'UNAVAILABLE' || safe.available === false))) {
    return {
      code: 'OPENGREP_UNAVAILABLE',
      healthState: 'ENGINE_MISSING',
      tone: 'red',
      isVerified: false,
      probeInProgress: false,
      deferredByActiveScan: false,
      ttlExpired: false,
      expiresAtMs,
      malformed: hasMalformedOpengrepFields,
      label: `Thiếu binary OpenGrep · ENGINE_MISSING (${errorText || versionText || 'OPENGREP_UNAVAILABLE'})`,
      detail: errorText || 'Không tìm thấy binary OpenGrep hợp lệ trên máy chủ API.',
    };
  }

  if (ttlExpired) {
    const expiryDetail = probeInProgress
      ? 'Snapshot active probe OpenGrep đã hết hạn TTL và đang tự động chạy lại ở nền.'
      : deferredByActiveScan
        ? 'Snapshot active probe OpenGrep đã hết hạn TTL; đang hoãn chạy lại vì có phiên quét thực tế đang chạy.'
        : 'Snapshot active probe OpenGrep đã hết hạn TTL và cần kiểm tra lại (không còn hiệu lực VERIFIED).';
    return {
      code: 'OPENGREP_PROBE_EXPIRED',
      healthState: 'EXPIRED',
      tone: 'amber',
      isVerified: false,
      probeInProgress,
      deferredByActiveScan,
      ttlExpired: true,
      expiresAtMs,
      malformed: hasMalformedOpengrepFields,
      label: probeInProgress
        ? 'Snapshot OpenGrep hết TTL · Đang chạy lại probe (EXPIRED)'
        : 'Snapshot OpenGrep đã hết TTL (EXPIRED)',
      detail: expiryDetail + (resolvedPath ? ` Đường dẫn: ${resolvedPath}.` : ''),
    };
  }

  if (hasMalformedOpengrepFields) {
    return {
      code: 'OPENGREP_NOT_VERIFIED',
      healthState: 'MALFORMED',
      tone: 'amber',
      isVerified: false,
      probeInProgress,
      deferredByActiveScan,
      ttlExpired: false,
      expiresAtMs,
      malformed: true,
      label: 'Dữ liệu probe OpenGrep không đúng định dạng',
      detail: 'Một hoặc nhiều trường trong opengrep từ /api/health sai kiểu dữ liệu hoặc thời hạn không hợp lệ; không công nhận trạng thái VERIFIED.',
    };
  }

  if (
    probeStatus === 'NOT_VERIFIED'
    || healthState === 'NOT_VERIFIED'
    || probeInProgress
    || (safe.available === true && !hasExplicitVerificationProof)
    || (safe.available === true && safe.runtime_verified === false)
    || (hasExplicitVerificationProof && !hasVerifiableExpiry)
    || (hasExplicitVerificationProof && verificationLevel && verificationLevel !== 'SCAN_VERIFIED')
  ) {
    const recentNote = safeRecentVersion
      ? ` Phiên bản OpenGrep ghi nhận từ lượt quét gần nhất: ${safeRecentVersion} (tách biệt với snapshot health probe).`
      : '';
    const baseDetail = probeInProgress
      ? 'Backend đang chạy active health probe (phiên bản + Java canary) ở tiến trình nền để xác minh OpenGrep; giao diện sẽ tự kiểm tra lại có giới hạn.'
      : deferredByActiveScan
        ? 'Active health probe OpenGrep đang tạm hoãn vì máy chủ đang chạy lượt quét thực tế.'
        : (hasExplicitVerificationProof && !hasVerifiableExpiry)
          ? (expiryEvidence.basis === 'TTL_ONLY_UNANCHORED'
              ? 'Snapshot OpenGrep chỉ có ttl_seconds nhưng thiếu mốc thời gian (probed_at / expires_at) nên không đủ căn cứ xác định thời điểm probe và hạn hiệu lực; giữ trạng thái chưa xác minh.'
              : expiryEvidence.basis === 'PROBED_AT_ONLY'
                ? 'Snapshot OpenGrep chỉ có probed_at nhưng thiếu thời hạn hiệu lực (expires_at / ttl_seconds); giữ trạng thái chưa xác minh.'
                : 'Snapshot OpenGrep thiếu bằng chứng thời hạn hiệu lực có thể kiểm chứng (probed_at / expires_at / ttl_seconds); không công nhận VERIFIED.')
          : 'Active health probe OpenGrep chưa có bằng chứng VERIFIED rõ ràng từ API (không tự suy diễn từ cờ available).';
    return {
      code: 'OPENGREP_NOT_VERIFIED',
      healthState: probeInProgress ? 'PROBE_IN_PROGRESS' : 'NOT_VERIFIED',
      tone: 'amber',
      isVerified: false,
      probeInProgress,
      deferredByActiveScan,
      ttlExpired: false,
      expiresAtMs,
      malformed: false,
      label: probeInProgress
        ? 'Đang chạy active probe OpenGrep (OPENGREP_NOT_VERIFIED)'
        : 'Chưa xác minh active probe OpenGrep (OPENGREP_NOT_VERIFIED)',
      detail: baseDetail
        + (resolvedPath ? ` Đường dẫn phát hiện: ${resolvedPath}.` : '')
        + recentNote,
    };
  }

  if (['CANARY_FAILED', 'RULES_INVALID', 'CLEANUP_FAILED', 'SHUTTING_DOWN', 'FAILED'].includes(probeStatus) || ['CANARY_FAILED', 'RULES_INVALID', 'CLEANUP_FAILED', 'SHUTTING_DOWN', 'PROBE_FAILED'].includes(healthState)) {
    const stateCode = healthState || probeStatus || 'PROBE_FAILED';
    return {
      code: 'OPENGREP_UNAVAILABLE',
      healthState: stateCode,
      tone: 'red',
      isVerified: false,
      probeInProgress: false,
      deferredByActiveScan: false,
      ttlExpired: false,
      expiresAtMs,
      malformed: false,
      label: `Lỗi xác minh OpenGrep (${stateCode})`,
      detail: errorText || `Active health probe OpenGrep thất bại với trạng thái ${stateCode}.`,
    };
  }

  if (safe.available === false || probeStatus === 'UNAVAILABLE') {
    return {
      code: 'OPENGREP_UNAVAILABLE',
      healthState: binaryPresent === false ? 'ENGINE_MISSING' : 'PROBE_FAILED',
      tone: 'red',
      isVerified: false,
      probeInProgress: false,
      deferredByActiveScan: false,
      ttlExpired: false,
      expiresAtMs,
      malformed: false,
      label: `Không khả dụng (${errorText || versionText || 'OPENGREP_UNAVAILABLE'})`,
      detail: errorText || 'Không tìm thấy hoặc không thể chạy binary OpenGrep trên máy chủ API.',
    };
  }

  return {
    code: 'UNKNOWN',
    healthState: 'UNKNOWN',
    tone: 'neutral',
    isVerified: false,
    probeInProgress: false,
    deferredByActiveScan: false,
    ttlExpired: false,
    expiresAtMs,
    malformed: false,
    label: 'API chưa cung cấp',
    detail: '',
  };
}

const OPENGREP_DEGRADED_REASONS = new Set([
  'OPENGREP_NOT_VERIFIED',
  'OPENGREP_PROBE_EXPIRED',
  'OPENGREP_PROBE_TIMEOUT',
  'OPENGREP_UNAVAILABLE',
]);

/**
 * Unified backend health presentation model shared across AppShell header, sidebar,
 * connection drawer, and StatusPage so all surfaces always agree on the exact API + probe state.
 */
export function classifyBackendHealthState(backend = {}, options = {}) {
  const rawStatus = readableText(backend?.status).toUpperCase() || 'CHECKING';
  const health = isPlainObject(backend?.health) ? backend.health : null;
  const reasonsCheck = normalizeDegradedReasons(health?.degraded_reasons);
  const degradedReasons = reasonsCheck.reasons;
  const hasOpengrepField = Boolean(health && Object.hasOwn(health, 'opengrep') && health.opengrep !== null && health.opengrep !== undefined);
  const hasCheckedAtField = Boolean(health && health.checked_at !== undefined && health.checked_at !== null);
  const parsedHealthCheckedAt = hasCheckedAtField ? parseOpengrepTimestampMs(health.checked_at) : null;
  const serverCheckedAtMalformed = Boolean(
    options.serverCheckedAtMalformed
    || backend?.serverCheckedAtMalformed
    || (hasCheckedAtField && parsedHealthCheckedAt === null)
    || (health && getWireDuplicateKeyInfo(health, 'checked_at')),
  );
  const ogInfo = hasOpengrepField
    ? describeOpengrepHealth(health.opengrep, null, {
        nowMs: options.nowMs,
        snapshotReceivedAtMs: options.snapshotReceivedAtMs ?? backend?.receivedAtMs ?? null,
        expiresAtMs: options.expiresAtMs ?? backend?.expiresAtMs ?? null,
        serverCheckedAtMs: options.serverCheckedAtMs ?? backend?.serverCheckedAtMs ?? parsedHealthCheckedAt,
        serverCheckedAtMalformed,
        rootHealthObj: health,
        forceExpired: Boolean(options.forceExpired || backend?.ttlExpired),
      })
    : null;
  const archInfo = health
    ? normalizeHealthArchitecture(health.architecture, {
        preValidatedInvalidFields: backend?.architectureInvalidFields,
        preValidatedMalformed: Boolean(backend?.architectureMalformed),
      })
    : null;
  const probeInProgress = Boolean(ogInfo?.probeInProgress);
  const schemaWarnings = [...new Set([
    ...(Array.isArray(backend?.schemaWarnings) ? backend.schemaWarnings : []),
    ...(reasonsCheck.malformed ? ['Trường degraded_reasons từ /api/health sai kiểu dữ liệu (cần mảng).'] : []),
    ...(ogInfo?.malformed ? ['Trường opengrep từ /api/health sai kiểu dữ liệu.'] : []),
    ...(archInfo?.schemaWarnings || []),
  ])];

  // Never keep CONNECTED when opengrep payload is present and unverified/expired/malformed.
  const effectiveStatus = (
    rawStatus === 'CONNECTED' && ((ogInfo && !ogInfo.isVerified) || schemaWarnings.length > 0)
  ) ? 'DEGRADED' : rawStatus;

  const onlyOpengrepReason = effectiveStatus === 'DEGRADED'
    && ogInfo
    && (
      degradedReasons.length === 0
      || degradedReasons.every((r) => OPENGREP_DEGRADED_REASONS.has(String(r || '').toUpperCase()))
    );

  if (effectiveStatus === 'CHECKING') {
    return {
      status: effectiveStatus,
      reachable: false,
      authenticated: false,
      probeInProgress: false,
      pillLabel: 'ĐANG KIỂM TRA API',
      pillClass: '',
      sidebarDotClass: '',
      sidebarLabel: 'Đang kiểm tra API',
      ogInfo: null,
      degradedReasons: [],
      schemaWarnings: [],
    };
  }
  if (effectiveStatus === 'AUTH_REQUIRED') {
    return {
      status: effectiveStatus,
      reachable: true,
      authenticated: false,
      probeInProgress: false,
      pillLabel: 'CẦN TOKEN PHIÊN',
      pillClass: 'pill-warn',
      sidebarDotClass: 'dot-warn',
      sidebarLabel: 'API kết nối · Cần Bearer Token',
      ogInfo: null,
      degradedReasons,
      schemaWarnings,
    };
  }
  if (effectiveStatus === 'ERROR') {
    return {
      status: effectiveStatus,
      reachable: false,
      authenticated: false,
      probeInProgress: false,
      pillLabel: 'API KHÔNG KHẢ DỤNG',
      pillClass: 'pill-error',
      sidebarDotClass: 'dot-error',
      sidebarLabel: 'API chưa kết nối',
      ogInfo: null,
      degradedReasons: [],
      schemaWarnings,
    };
  }
  if (effectiveStatus === 'CONNECTED') {
    return {
      status: effectiveStatus,
      reachable: true,
      authenticated: health?.authenticated === true,
      probeInProgress: false,
      pillLabel: ogInfo?.isVerified ? 'API SẴN SÀNG · OPENGREP VERIFIED' : 'KẾT NỐI THỰC',
      pillClass: 'connected',
      sidebarDotClass: 'online',
      sidebarLabel: ogInfo?.isVerified ? 'API & OpenGrep đã xác minh' : 'API đã sẵn sàng',
      ogInfo,
      degradedReasons: [],
      schemaWarnings: [],
    };
  }

  // DEGRADED
  let pillLabel = 'API HẠN CHẾ';
  let sidebarLabel = 'API hoạt động hạn chế';
  if (onlyOpengrepReason && ogInfo) {
    if (ogInfo.healthState === 'PROBE_IN_PROGRESS' || (ogInfo.healthState === 'EXPIRED' && probeInProgress)) {
      pillLabel = 'API KẾT NỐI · ĐANG PROBE OPENGREP';
      sidebarLabel = 'Đang chạy active probe OpenGrep…';
    } else if (ogInfo.healthState === 'EXPIRED') {
      pillLabel = 'API KẾT NỐI · PROBE HẾT TTL (EXPIRED)';
      sidebarLabel = 'OpenGrep probe hết TTL (EXPIRED)';
    } else if (ogInfo.healthState === 'PROBE_TIMEOUT') {
      pillLabel = 'API HẠN CHẾ · PROBE_TIMEOUT';
      sidebarLabel = 'OpenGrep quá thời gian probe';
    } else if (ogInfo.healthState === 'ENGINE_MISSING') {
      pillLabel = 'API HẠN CHẾ · ENGINE_MISSING';
      sidebarLabel = 'Thiếu binary OpenGrep';
    } else if (ogInfo.code === 'OPENGREP_NOT_VERIFIED') {
      pillLabel = 'API SẴN SÀNG · CHƯA XÁC MINH OPENGREP';
      sidebarLabel = 'API kết nối (OPENGREP_NOT_VERIFIED)';
    }
  } else if (ogInfo?.healthState === 'EXPIRED') {
    pillLabel = probeInProgress
      ? 'API HẠN CHẾ · ĐANG PROBE LẠI (EXPIRED)'
      : 'API HẠN CHẾ · PROBE HẾT TTL (EXPIRED)';
    sidebarLabel = 'API hạn chế · OpenGrep hết TTL (EXPIRED)';
  }
  return {
    status: 'DEGRADED',
    reachable: true,
    authenticated: health?.authenticated === true,
    probeInProgress,
    pillLabel,
    pillClass: ogInfo?.tone === 'red' && onlyOpengrepReason ? 'pill-error' : 'pill-warn',
    sidebarDotClass: ogInfo?.tone === 'red' && onlyOpengrepReason ? 'dot-error' : 'dot-warn',
    sidebarLabel,
    ogInfo,
    degradedReasons,
    schemaWarnings,
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
