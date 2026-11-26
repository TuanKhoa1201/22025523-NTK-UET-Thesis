// REST-boundary JSON wire integrity analyzer (shared across standalone ESM & bundled modules
// via Symbol.for without mutating raw parsed JS objects, keeping JSON.stringify() byte-identical
// for unsigned report downloads while enabling durable normalized taint materialization for UI/cache).
const WIRE_INTEGRITY_REGISTRY_SYM = Symbol.for('22025523.restJsonWireIntegrity.v1');
const wireRegistry = globalThis[WIRE_INTEGRITY_REGISTRY_SYM] || (globalThis[WIRE_INTEGRITY_REGISTRY_SYM] = {
  objects: new WeakMap(),
  stages: new WeakMap(),
});
const WIRE_MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const WIRE_MAX_SAFE_DIGITS = 16n;
export const WIRE_MAX_SCAN_DEPTH = 128;
const WIRE_MAX_DUP_PATHS = 24;
const WIRE_CATCH_PROPAGATE_MAX_DEPTH = 3;
const WIRE_CATCH_PROPAGATE_MAX_NODES = 512;
const WIRE_UNSIGNED_JSON_NUMBER_RE = /^(0|[1-9]\d*)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/;

const WIRE_STRICT_INT_COUNT_KEY_RE = /(?:^|_)(?:count|total|checked|findings|files|scanned|ignored|inventory|matched|invalid|not_verified|unverified|open|pages|page|page_size|limit|citations_matched|citations_invalid|citations_not_verified|citations_total)$/i;
const WIRE_EXACT_INT_COUNT_KEYS = new Set([
  'matched_count', 'matched_citation_count', 'citations_matched',
  'invalid_count', 'invalid_citation_count', 'citations_invalid',
  'not_verified_count', 'unverified_citation_count', 'citations_not_verified',
  'total_checked', 'total_findings', 'citations_total', 'total_count', 'total_matching',
  'total_pages', 'page', 'page_size', 'limit',
  'java_files_inventory', 'java_files_inventory_count', 'java_files_count', 'java_files_scanned',
  'java_files_opengrep_scanned', 'opengrep_scanned_java_files', 'java_files_actually_scanned', 'scanned_java_files_count',
  'java_files_opengrep_ignored', 'java_files_ignored', 'opengrep_ignored_java_files', 'ignored_java_files_count',
  'proposed_refuted_open_count', 'open_count', 'findings_with_trace', 'validator_downgraded_count',
  'SUPPORTED', 'REFUTED', 'UNDETERMINED', 'OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE',
]);

export function isWireInvalidSentinel(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) && value.__wireInvalid === true);
}

// Single source of truth shared by materializeNormalizedTelemetry and coverage tree checks:
// flags any strict integer/count key with a non-integer/unsafe/negative wire lexeme, PLUS any
// key whose JSON number silently rounded to a safe integer (precision loss like 389.00000000000000001)
// or exceeded MAX_SAFE_INTEGER, while preserving legitimate finite decimal metrics (e.g. elapsed_seconds: 1.42).
export function isWireInvalidIntAnomaly(key, wireIntErr, rawVal) {
  if (!wireIntErr) return false;
  if (WIRE_EXACT_INT_COUNT_KEYS.has(key) || WIRE_STRICT_INT_COUNT_KEY_RE.test(key)) {
    return true;
  }
  if (wireIntErr.reason === 'UNSAFE_INTEGER_WIRE_NUMBER') {
    return true;
  }
  if (
    wireIntErr.reason === 'NON_INTEGER_WIRE_NUMBER'
    && typeof rawVal === 'number'
    && Number.isSafeInteger(rawVal)
  ) {
    return true;
  }
  return false;
}

export function verifyExactNonNegativeSafeIntLexeme(raw) {
  if (typeof raw !== 'string' || !raw) {
    return {valid: false, value: null, reason: 'INVALID_WIRE_NUMBER_TOKEN', raw: String(raw ?? '')};
  }
  if (raw.charCodeAt(0) === 45) {
    return {valid: false, value: null, reason: 'NEGATIVE_OR_SIGNED_ZERO_WIRE_NUMBER', raw};
  }
  const match = WIRE_UNSIGNED_JSON_NUMBER_RE.exec(raw);
  if (!match) {
    return {valid: false, value: null, reason: 'INVALID_WIRE_NUMBER_TOKEN', raw};
  }
  const intPart = match[1];
  const fracPart = match[2] || '';
  const expStr = match[3] || '';
  const combined = intPart + fracPart;
  let firstNonZero = -1;
  for (let i = 0; i < combined.length; i += 1) {
    if (combined.charCodeAt(i) !== 48) {
      firstNonZero = i;
      break;
    }
  }
  if (firstNonZero === -1) {
    return {valid: true, value: 0, reason: '', raw};
  }
  let lastNonZero = combined.length - 1;
  while (lastNonZero > firstNonZero && combined.charCodeAt(lastNonZero) === 48) {
    lastNonZero -= 1;
  }
  const sigDigits = combined.slice(firstNonZero, lastNonZero + 1);
  const trailingZeros = (combined.length - 1) - lastNonZero;
  let expBig = 0n;
  if (expStr) {
    try {
      expBig = BigInt(expStr);
    } catch {
      return {valid: false, value: null, reason: 'UNVERIFIABLE_EXPONENT_WIRE_NUMBER', raw};
    }
  }
  const netExp = expBig - BigInt(fracPart.length) + BigInt(trailingZeros);
  if (netExp < 0n) {
    return {valid: false, value: null, reason: 'NON_INTEGER_WIRE_NUMBER', raw};
  }
  const totalDigits = BigInt(sigDigits.length) + netExp;
  if (totalDigits > WIRE_MAX_SAFE_DIGITS) {
    return {valid: false, value: null, reason: 'UNSAFE_INTEGER_WIRE_NUMBER', raw};
  }
  const intBig = BigInt(sigDigits + '0'.repeat(Number(netExp)));
  if (intBig > WIRE_MAX_SAFE_BIGINT) {
    return {valid: false, value: null, reason: 'UNSAFE_INTEGER_WIRE_NUMBER', raw};
  }
  return {valid: true, value: Number(intBig), reason: '', raw};
}

function createWireJsonScanner(text) {
  const len = text.length;
  let pos = 0;
  const skipWs = () => {
    while (pos < len) {
      const c = text.charCodeAt(pos);
      if (c === 32 || c === 9 || c === 10 || c === 13) pos += 1;
      else break;
    }
  };
  const scanStringSlice = () => {
    const start = pos;
    if (text.charCodeAt(pos) !== 34) throw new Error('Expected quote');
    pos += 1;
    while (pos < len) {
      const ch = text.charCodeAt(pos);
      if (ch === 92) { pos += 2; continue; }
      if (ch === 34) { pos += 1; return text.slice(start, pos); }
      pos += 1;
    }
    throw new Error('Unterminated string');
  };
  const scanNumberSlice = () => {
    const start = pos;
    if (text.charCodeAt(pos) === 45) pos += 1;
    while (pos < len) {
      const c = text.charCodeAt(pos);
      if ((c >= 48 && c <= 57) || c === 46 || c === 101 || c === 69 || c === 43 || c === 45) pos += 1;
      else break;
    }
    return text.slice(start, pos);
  };
  // Iteratively skips any valid JSON value beyond WIRE_MAX_SCAN_DEPTH without recursion so
  // over-depth subtrees are flagged fail-closed in-place instead of aborting the whole scan
  // and leaving sibling or child containers untagged.
  const skipOverDepthValue = () => {
    skipWs();
    const start = pos;
    const ch = text.charCodeAt(pos);
    if (ch === 34) return scanStringSlice();
    if (ch === 45 || (ch >= 48 && ch <= 57)) return scanNumberSlice();
    if (ch === 116) { pos += 4; return text.slice(start, pos); }
    if (ch === 102) { pos += 5; return text.slice(start, pos); }
    if (ch === 110) { pos += 4; return text.slice(start, pos); }
    if (ch !== 123 && ch !== 91) throw new Error(`Unexpected token at ${pos}`);
    let nesting = 0;
    let inString = false;
    while (pos < len) {
      const c = text.charCodeAt(pos);
      if (inString) {
        if (c === 92) { pos += 2; continue; }
        if (c === 34) inString = false;
        pos += 1;
        continue;
      }
      if (c === 34) {
        inString = true;
        pos += 1;
        continue;
      }
      if (c === 123 || c === 91) {
        nesting += 1;
      } else if (c === 125 || c === 93) {
        nesting -= 1;
        if (nesting === 0) {
          pos += 1;
          return text.slice(start, pos);
        }
        if (nesting < 0) throw new Error(`Unexpected closing delimiter at ${pos}`);
      }
      pos += 1;
    }
    throw new Error('Unterminated over-depth JSON container');
  };
  const scanValue = (depth) => {
    if (depth > WIRE_MAX_SCAN_DEPTH) {
      const rawSlice = skipOverDepthValue();
      return {
        kind: 'overdepth',
        rawSlice,
        meta: {
          kind: 'overdepth',
          depthExceeded: true,
          hasDepthExceededSubtree: true,
          hasDupSubtree: false,
          hasConflictDupSubtree: false,
          dupPaths: [],
          depthExceededPaths: ['__wireDepthExceeded'],
        },
      };
    }
    skipWs();
    const start = pos;
    const ch = text.charCodeAt(pos);
    if (ch === 123) return scanObject(depth + 1);
    if (ch === 91) return scanArray(depth + 1);
    if (ch === 34) return {kind: 'string', rawSlice: scanStringSlice(), meta: null};
    if (ch === 45 || (ch >= 48 && ch <= 57)) return {kind: 'number', rawSlice: scanNumberSlice(), meta: null};
    if (ch === 116) { pos += 4; return {kind: 'boolean', rawSlice: text.slice(start, pos), meta: null}; }
    if (ch === 102) { pos += 5; return {kind: 'boolean', rawSlice: text.slice(start, pos), meta: null}; }
    if (ch === 110) { pos += 4; return {kind: 'null', rawSlice: text.slice(start, pos), meta: null}; }
    throw new Error(`Unexpected token at ${pos}`);
  };
  const scanArray = (depth) => {
    const start = pos;
    pos += 1;
    skipWs();
    let childMetas = null;
    let hasDupSubtree = false;
    let hasConflictDupSubtree = false;
    let hasDepthExceededSubtree = false;
    const dupPaths = [];
    const depthExceededPaths = [];
    let index = 0;
    if (pos < len && text.charCodeAt(pos) !== 93) {
      while (pos < len) {
        const val = scanValue(depth);
        if (val.meta) {
          if (!childMetas) childMetas = new Map();
          childMetas.set(index, val.meta);
          if (val.meta.hasDupSubtree) hasDupSubtree = true;
          if (val.meta.hasConflictDupSubtree) hasConflictDupSubtree = true;
          if (val.meta.hasDepthExceededSubtree || val.meta.depthExceeded) hasDepthExceededSubtree = true;
          if (val.meta.dupPaths && dupPaths.length < WIRE_MAX_DUP_PATHS) {
            for (const dp of val.meta.dupPaths) {
              if (dupPaths.length >= WIRE_MAX_DUP_PATHS) break;
              dupPaths.push(`[${index}].${dp}`);
            }
          }
          if (val.meta.depthExceededPaths && depthExceededPaths.length < WIRE_MAX_DUP_PATHS) {
            for (const dep of val.meta.depthExceededPaths) {
              if (depthExceededPaths.length >= WIRE_MAX_DUP_PATHS) break;
              depthExceededPaths.push(`[${index}].${dep}`);
            }
          }
        }
        index += 1;
        skipWs();
        const next = text.charCodeAt(pos);
        if (next === 44) { pos += 1; continue; }
        if (next === 93) break;
        throw new Error(`Expected , or ] at ${pos}`);
      }
    }
    if (text.charCodeAt(pos) !== 93) throw new Error('Unterminated array');
    pos += 1;
    return {
      kind: 'array',
      rawSlice: text.slice(start, pos),
      meta: childMetas
        ? {kind: 'array', childMetas, hasDupSubtree, hasConflictDupSubtree, hasDepthExceededSubtree, dupPaths, depthExceededPaths}
        : null,
    };
  };
  const scanObject = (depth) => {
    const start = pos;
    pos += 1;
    skipWs();
    const seenKeys = new Map();
    let invalidIntFields = null;
    let duplicateKeys = null;
    let childMetas = null;
    let hasDupSubtree = false;
    let hasConflictDupSubtree = false;
    let hasDepthExceededSubtree = false;
    const dupPaths = [];
    const depthExceededPaths = [];
    if (pos < len && text.charCodeAt(pos) !== 125) {
      while (pos < len) {
        skipWs();
        const rawKeySlice = scanStringSlice();
        const decodedKey = JSON.parse(rawKeySlice);
        skipWs();
        if (text.charCodeAt(pos) !== 58) throw new Error(`Expected : at ${pos}`);
        pos += 1;
        const val = scanValue(depth);
        const valCanonical = val.kind === 'string' ? JSON.parse(val.rawSlice) : val.rawSlice.trim();
        const prevSeen = seenKeys.get(decodedKey);
        if (prevSeen) {
          prevSeen.count += 1;
          if (prevSeen.firstCanonical !== valCanonical) prevSeen.conflicting = true;
          if (!duplicateKeys) duplicateKeys = new Map();
          duplicateKeys.set(decodedKey, {count: prevSeen.count, conflicting: prevSeen.conflicting});
          hasDupSubtree = true;
          if (prevSeen.conflicting) hasConflictDupSubtree = true;
          if (dupPaths.length < WIRE_MAX_DUP_PATHS && !dupPaths.includes(decodedKey)) {
            dupPaths.push(decodedKey);
          }
        } else {
          seenKeys.set(decodedKey, {count: 1, firstCanonical: valCanonical, conflicting: false});
        }
        if (val.kind === 'number') {
          const check = verifyExactNonNegativeSafeIntLexeme(val.rawSlice);
          if (!check.valid) {
            if (!invalidIntFields) invalidIntFields = new Map();
            invalidIntFields.set(decodedKey, {raw: val.rawSlice, reason: check.reason});
          } else if (invalidIntFields && !prevSeen) {
            invalidIntFields.delete(decodedKey);
          }
        } else if (val.kind === 'overdepth') {
          if (!invalidIntFields) invalidIntFields = new Map();
          invalidIntFields.set(decodedKey, {raw: val.rawSlice, reason: 'WIRE_MAX_SCAN_DEPTH_EXCEEDED'});
        }
        if (val.meta) {
          if (!childMetas) childMetas = new Map();
          childMetas.set(decodedKey, val.meta);
          if (val.meta.hasDupSubtree) hasDupSubtree = true;
          if (val.meta.hasConflictDupSubtree) hasConflictDupSubtree = true;
          if (val.meta.hasDepthExceededSubtree || val.meta.depthExceeded) hasDepthExceededSubtree = true;
          if (val.meta.dupPaths && dupPaths.length < WIRE_MAX_DUP_PATHS) {
            for (const dp of val.meta.dupPaths) {
              if (dupPaths.length >= WIRE_MAX_DUP_PATHS) break;
              const prefix = dp.startsWith('[') ? `${decodedKey}${dp}` : `${decodedKey}.${dp}`;
              if (!dupPaths.includes(prefix)) dupPaths.push(prefix);
            }
          }
          if (val.meta.depthExceededPaths && depthExceededPaths.length < WIRE_MAX_DUP_PATHS) {
            for (const dep of val.meta.depthExceededPaths) {
              if (depthExceededPaths.length >= WIRE_MAX_DUP_PATHS) break;
              const prefix = dep.startsWith('[') ? `${decodedKey}${dep}` : `${decodedKey}.${dep}`;
              if (!depthExceededPaths.includes(prefix)) depthExceededPaths.push(prefix);
            }
          }
        } else if (childMetas && childMetas.has(decodedKey)) {
          childMetas.delete(decodedKey);
        }
        skipWs();
        const next = text.charCodeAt(pos);
        if (next === 44) { pos += 1; continue; }
        if (next === 125) break;
        throw new Error(`Expected , or } at ${pos}`);
      }
    }
    if (text.charCodeAt(pos) !== 125) throw new Error('Unterminated object');
    pos += 1;
    const hasOwn = Boolean((invalidIntFields && invalidIntFields.size > 0) || (duplicateKeys && duplicateKeys.size > 0));
    const hasChild = Boolean(childMetas && childMetas.size > 0);
    return {
      kind: 'object',
      rawSlice: text.slice(start, pos),
      meta: (hasOwn || hasChild || hasDepthExceededSubtree)
        ? {
            kind: 'object',
            invalidIntFields,
            duplicateKeys,
            childMetas,
            hasDupSubtree,
            hasConflictDupSubtree,
            hasDepthExceededSubtree,
            dupPaths,
            depthExceededPaths,
          }
        : null,
    };
  };
  return {
    scanRoot() {
      const res = scanValue(0);
      skipWs();
      if (pos !== len) throw new Error(`Trailing content at ${pos}`);
      return res;
    },
  };
}

function attachWireMetaTree(node, metaNode) {
  if (!node || typeof node !== 'object' || !metaNode) return;
  if (metaNode.kind === 'overdepth') {
    wireRegistry.objects.set(node, {
      invalidIntFields: new Map(),
      duplicateKeys: new Map(),
      hasDuplicateKeyInSubtree: false,
      hasConflictingDuplicateKeyInSubtree: false,
      duplicateKeyPaths: [],
      scannerError: true,
      depthExceeded: true,
      hasDepthExceededSubtree: true,
      depthExceededPaths: ['__wireDepthExceeded'],
    });
    return;
  }
  if (metaNode.kind === 'array' && Array.isArray(node)) {
    if (metaNode.hasDupSubtree || metaNode.hasDepthExceededSubtree) {
      wireRegistry.objects.set(node, {
        invalidIntFields: new Map(),
        duplicateKeys: new Map(),
        hasDuplicateKeyInSubtree: Boolean(metaNode.hasDupSubtree),
        hasConflictingDuplicateKeyInSubtree: Boolean(metaNode.hasConflictDupSubtree),
        duplicateKeyPaths: metaNode.dupPaths || [],
        scannerError: false,
        depthExceeded: false,
        hasDepthExceededSubtree: Boolean(metaNode.hasDepthExceededSubtree),
        depthExceededPaths: metaNode.depthExceededPaths || [],
      });
    }
    if (metaNode.childMetas) {
      for (const [idx, childMeta] of metaNode.childMetas.entries()) {
        attachWireMetaTree(node[idx], childMeta);
      }
    }
    return;
  }
  if (metaNode.kind === 'object' && !Array.isArray(node)) {
    const hasOwn = Boolean(
      (metaNode.invalidIntFields && metaNode.invalidIntFields.size > 0)
      || (metaNode.duplicateKeys && metaNode.duplicateKeys.size > 0)
      || metaNode.hasDupSubtree
      || metaNode.hasDepthExceededSubtree,
    );
    if (hasOwn) {
      wireRegistry.objects.set(node, {
        invalidIntFields: metaNode.invalidIntFields || new Map(),
        duplicateKeys: metaNode.duplicateKeys || new Map(),
        hasDuplicateKeyInSubtree: Boolean(metaNode.hasDupSubtree),
        hasConflictingDuplicateKeyInSubtree: Boolean(metaNode.hasConflictDupSubtree),
        duplicateKeyPaths: metaNode.dupPaths || [],
        scannerError: false,
        depthExceeded: false,
        hasDepthExceededSubtree: Boolean(metaNode.hasDepthExceededSubtree),
        depthExceededPaths: metaNode.depthExceededPaths || [],
      });
    }
    if (metaNode.childMetas) {
      for (const [key, childMeta] of metaNode.childMetas.entries()) {
        if (Object.hasOwn(node, key)) attachWireMetaTree(node[key], childMeta);
      }
    }
  }
}

function markScannerErrorBounded(root) {
  const queue = [{node: root, depth: 0}];
  const seen = new Set();
  let tagged = 0;
  while (queue.length > 0 && tagged < WIRE_CATCH_PROPAGATE_MAX_NODES) {
    const {node, depth} = queue.shift();
    if (!node || typeof node !== 'object' || seen.has(node)) continue;
    seen.add(node);
    tagged += 1;
    wireRegistry.objects.set(node, {
      invalidIntFields: new Map(),
      duplicateKeys: new Map(),
      hasDuplicateKeyInSubtree: false,
      hasConflictingDuplicateKeyInSubtree: false,
      duplicateKeyPaths: [],
      scannerError: true,
      depthExceeded: false,
      hasDepthExceededSubtree: false,
      depthExceededPaths: [],
    });
    if (depth >= WIRE_CATCH_PROPAGATE_MAX_DEPTH) continue;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length && tagged + queue.length < WIRE_CATCH_PROPAGATE_MAX_NODES; i += 1) {
        if (node[i] && typeof node[i] === 'object') queue.push({node: node[i], depth: depth + 1});
      }
    } else {
      const keys = Object.keys(node);
      for (let i = 0; i < keys.length && tagged + queue.length < WIRE_CATCH_PROPAGATE_MAX_NODES; i += 1) {
        const v = node[keys[i]];
        if (v && typeof v === 'object') queue.push({node: v, depth: depth + 1});
      }
    }
  }
}

export function parseJsonWithWireIntegrity(rawText) {
  const parsed = JSON.parse(rawText);
  if (parsed && typeof parsed === 'object') {
    try {
      const scanned = createWireJsonScanner(rawText).scanRoot();
      if (scanned.meta) attachWireMetaTree(parsed, scanned.meta);
    } catch {
      markScannerErrorBounded(parsed);
    }
  }
  return parsed;
}

// `__wireIntegrity` is a reserved key. The frontend writes it only after verification, and only
// to carry taint (never validity). The same key can also arrive inside untrusted REST data, so it
// is read through this type-checked view: wrong shapes never throw, never grant validity, and are
// themselves treated as malformed. A present block without any taint flag is also treated as a
// reserved-key collision from untrusted input (frontend-generated blocks always carry a flag).
function readMaterializedIntegrity(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj) || !Object.hasOwn(obj, '__wireIntegrity')) return null;
  const raw = obj.__wireIntegrity;
  const malformedView = {
    scannerError: false,
    hasConflict: false,
    hasMalformed: true,
    duplicateKeys: {},
    duplicateKeyPaths: [],
    invalidFields: ['__wireIntegrity'],
  };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return malformedView;
  const isStrList = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');
  let shapeOk = true;
  for (const f of ['scannerError', 'hasConflict', 'hasMalformed']) {
    if (raw[f] !== undefined && typeof raw[f] !== 'boolean') shapeOk = false;
  }
  for (const f of ['duplicateKeyPaths', 'invalidFields']) {
    if (raw[f] !== undefined && !isStrList(raw[f])) shapeOk = false;
  }
  const duplicateKeys = {};
  if (raw.duplicateKeys !== undefined) {
    if (raw.duplicateKeys && typeof raw.duplicateKeys === 'object' && !Array.isArray(raw.duplicateKeys)) {
      for (const [k, info] of Object.entries(raw.duplicateKeys)) {
        const okInfo = info && typeof info === 'object' && !Array.isArray(info);
        if (!okInfo) shapeOk = false;
        duplicateKeys[k] = {count: okInfo && Number.isSafeInteger(info.count) && info.count >= 2 ? info.count : 2, conflicting: Boolean(okInfo && info.conflicting === true)};
      }
    } else {
      shapeOk = false;
    }
  }
  if (!shapeOk) return {...malformedView, duplicateKeys};
  const view = {
    scannerError: raw.scannerError === true,
    hasConflict: raw.hasConflict === true,
    hasMalformed: raw.hasMalformed === true,
    duplicateKeys,
    duplicateKeyPaths: isStrList(raw.duplicateKeyPaths) ? raw.duplicateKeyPaths.slice(0, WIRE_MAX_DUP_PATHS) : [],
    invalidFields: isStrList(raw.invalidFields) ? raw.invalidFields.slice(0, WIRE_MAX_DUP_PATHS) : [],
  };
  if (!view.scannerError && !view.hasConflict && !view.hasMalformed && Object.keys(duplicateKeys).length === 0) {
    return {...malformedView};
  }
  return view;
}

export function getWireObjectIntegrity(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const fromWeak = wireRegistry.objects.get(obj) || null;
  const mat = readMaterializedIntegrity(obj);
  if (!fromWeak && !mat) return null;
  return {
    scannerError: Boolean(fromWeak?.scannerError || mat?.scannerError),
    depthExceeded: Boolean(fromWeak?.depthExceeded),
    hasDepthExceededSubtree: Boolean(fromWeak?.hasDepthExceededSubtree || fromWeak?.depthExceeded),
    depthExceededPaths: fromWeak?.depthExceededPaths || [],
    duplicateKeys: fromWeak?.duplicateKeys || null,
    invalidIntFields: fromWeak?.invalidIntFields || null,
    materialized: mat,
    hasDuplicateKeyInSubtree: Boolean(fromWeak?.hasDuplicateKeyInSubtree || mat?.hasConflict || (mat && Object.keys(mat.duplicateKeys).length > 0)),
    hasConflictingDuplicateKeyInSubtree: Boolean(fromWeak?.hasConflictingDuplicateKeyInSubtree || mat?.hasConflict),
    duplicateKeyPaths: fromWeak?.duplicateKeyPaths || mat?.duplicateKeyPaths || [],
  };
}

export function getWireDuplicateKeyInfo(obj, key) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const fromWeak = wireRegistry.objects.get(obj);
  if (fromWeak?.scannerError) return {count: 2, conflicting: true, scannerError: true};
  const weakDup = fromWeak?.duplicateKeys?.get(key);
  if (weakDup) return weakDup;
  const mat = readMaterializedIntegrity(obj);
  if (mat?.scannerError) return {count: 2, conflicting: true, scannerError: true};
  if (mat && Object.hasOwn(mat.duplicateKeys, key)) {
    const entry = mat.duplicateKeys[key];
    return {count: entry.count, conflicting: entry.conflicting};
  }
  const val = Object.hasOwn(obj, key) ? obj[key] : undefined;
  if (isWireInvalidSentinel(val) && (val.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY' || val.kind === 'DUPLICATE_WIRE_KEY')) {
    return {count: 2, conflicting: val.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY'};
  }
  return null;
}

export function readStrictWireSafeInt(obj, key) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return {present: false, valid: true, value: null, conflict: false, malformed: false, reason: ''};
  }
  if (isWireInvalidSentinel(obj)) {
    const isConflict = obj.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY';
    return {
      present: true,
      valid: false,
      value: null,
      conflict: isConflict,
      malformed: !isConflict,
      reason: String(obj.reason || obj.kind || 'WIRE_INVALID_CONTAINER'),
    };
  }
  const wire = wireRegistry.objects.get(obj);
  const mat = readMaterializedIntegrity(obj);
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
    return {
      present: true,
      valid: false,
      value: null,
      conflict: false,
      malformed: true,
      reason: wireInvalid.reason,
      raw: wireInvalid.raw,
    };
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

/**
 * Produces a durable normalized copy of a telemetry/summary object where any wire-level
 * anomalies (rounded non-integer count lexemes, unsafe integers, -0, duplicate keys,
 * scanner errors, or over-depth subtrees exceeding WIRE_MAX_SCAN_DEPTH) are materialized
 * directly as self-describing invalid sentinels and taint metadata so shallow spreads ({...obj}),
 * deep clones, React state updates, cache storage, or JSON.parse(JSON.stringify(obj)) round-trips
 * can NEVER erase a wire violation or rehabilitate invalid data into ALL_MATCHED / VERIFIED.
 * Clean valid payloads within WIRE_MAX_SCAN_DEPTH receive ZERO extra properties.
 */
export function materializeNormalizedTelemetry(value, depth = 0, ancestors = new Set()) {
  if (value === null || value === undefined || typeof value !== 'object') {
    return {value, hasConflict: false, hasMalformed: false, duplicateKeys: [], invalidFields: []};
  }
  if (ancestors.has(value)) {
    return {value, hasConflict: false, hasMalformed: false, duplicateKeys: [], invalidFields: []};
  }
  const weak = wireRegistry.objects.get(value);
  if (depth > WIRE_MAX_SCAN_DEPTH || weak?.depthExceeded) {
    return {
      value: {
        __wireInvalid: true,
        kind: 'WIRE_DEPTH_EXCEEDED',
        reason: 'WIRE_MAX_SCAN_DEPTH_EXCEEDED',
      },
      hasConflict: false,
      hasMalformed: true,
      duplicateKeys: [],
      invalidFields: ['__wireDepthExceeded'],
      depthExceeded: true,
    };
  }
  if (Array.isArray(value)) {
    ancestors.add(value);
    try {
      let anyChange = false;
      let hasConflict = false;
      let hasMalformed = Boolean(weak?.scannerError || weak?.hasDepthExceededSubtree);
      const duplicateKeys = [];
      const invalidFields = [];
      if (weak?.hasDepthExceededSubtree) invalidFields.push('__wireDepthExceeded');
      const nextArr = value.map((item) => {
        const res = materializeNormalizedTelemetry(item, depth + 1, ancestors);
        if (res.value !== item) anyChange = true;
        if (res.hasConflict) hasConflict = true;
        if (res.hasMalformed) hasMalformed = true;
        duplicateKeys.push(...res.duplicateKeys);
        invalidFields.push(...res.invalidFields);
        return res.value;
      });
      return {value: anyChange ? nextArr : value, hasConflict, hasMalformed, duplicateKeys, invalidFields};
    } finally {
      ancestors.delete(value);
    }
  }
  if (isWireInvalidSentinel(value)) {
    const isConflict = value.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY';
    return {
      value: {...value},
      hasConflict: isConflict,
      hasMalformed: !isConflict,
      duplicateKeys: isConflict || value.kind === 'DUPLICATE_WIRE_KEY' ? [String(value.key || '')] : [],
      invalidFields: !isConflict ? [String(value.key || '')] : [],
    };
  }
  const existingMat = readMaterializedIntegrity(value);
  const ownDupMap = {};
  const ownDupKeys = [];
  const ownInvalidFields = existingMat?.invalidFields.includes('__wireIntegrity') ? ['__wireIntegrity'] : [];
  let hasConflict = Boolean(existingMat?.hasConflict || weak?.scannerError);
  let hasMalformed = Boolean(existingMat?.hasMalformed || weak?.scannerError || weak?.hasDepthExceededSubtree);

  if (weak?.duplicateKeys) {
    for (const [k, info] of weak.duplicateKeys.entries()) {
      ownDupMap[k] = {count: info.count, conflicting: Boolean(info.conflicting)};
      ownDupKeys.push(k);
      if (info.conflicting) hasConflict = true;
      else hasMalformed = true;
    }
  }
  if (existingMat) {
    for (const [k, info] of Object.entries(existingMat.duplicateKeys)) {
      if (!Object.hasOwn(ownDupMap, k)) {
        ownDupMap[k] = {count: info.count, conflicting: info.conflicting};
        ownDupKeys.push(k);
        if (info.conflicting) hasConflict = true;
        else hasMalformed = true;
      }
    }
  }

  let needsMaterialization = Boolean(
    weak?.scannerError
    || weak?.hasDepthExceededSubtree
    || existingMat?.scannerError
    || ownDupKeys.length > 0
    || existingMat?.hasConflict
    || existingMat?.hasMalformed,
  );

  const out = {};
  const keys = Object.keys(value);
  ancestors.add(value);
  try {
    for (let i = 0; i < keys.length; i += 1) {
      const k = keys[i];
      if (k === '__wireIntegrity') continue;
      const rawVal = value[k];
      if (Object.hasOwn(ownDupMap, k)) {
        const dupInfo = ownDupMap[k];
        out[k] = {
          __wireInvalid: true,
          kind: dupInfo.conflicting ? 'DUPLICATE_CONFLICTING_WIRE_KEY' : 'DUPLICATE_WIRE_KEY',
          key: k,
          reason: dupInfo.conflicting ? 'DUPLICATE_CONFLICTING_WIRE_KEY' : 'DUPLICATE_WIRE_KEY',
        };
        needsMaterialization = true;
        continue;
      }
      const wireIntErr = weak?.invalidIntFields?.get(k);
      if (isWireInvalidIntAnomaly(k, wireIntErr, rawVal)) {
        out[k] = {
          __wireInvalid: true,
          kind: 'INVALID_WIRE_INT',
          key: k,
          reason: wireIntErr.reason,
          raw: wireIntErr.raw,
        };
        ownInvalidFields.push(k);
        hasMalformed = true;
        needsMaterialization = true;
        continue;
      }
      const child = materializeNormalizedTelemetry(rawVal, depth + 1, ancestors);
      out[k] = child.value;
      if (child.value !== rawVal) needsMaterialization = true;
      if (child.hasConflict) hasConflict = true;
      if (child.hasMalformed) hasMalformed = true;
      for (const dk of child.duplicateKeys) ownDupKeys.push(`${k}.${dk}`);
      for (const ik of child.invalidFields) ownInvalidFields.push(`${k}.${ik}`);
    }
  } finally {
    ancestors.delete(value);
  }

  if (weak?.hasDepthExceededSubtree && Array.isArray(weak.depthExceededPaths)) {
    for (const dep of weak.depthExceededPaths) {
      if (!ownInvalidFields.includes(dep)) ownInvalidFields.push(dep);
    }
  }

  if (!needsMaterialization && !hasConflict && !hasMalformed) {
    return {value, hasConflict: false, hasMalformed: false, duplicateKeys: [], invalidFields: []};
  }

  out.__wireIntegrity = {
    scannerError: Boolean(weak?.scannerError || existingMat?.scannerError),
    hasConflict,
    hasMalformed,
    duplicateKeys: ownDupMap,
    duplicateKeyPaths: [...new Set([...ownDupKeys, ...(existingMat ? existingMat.duplicateKeyPaths : [])])].slice(0, WIRE_MAX_DUP_PATHS),
    invalidFields: [...new Set([...ownInvalidFields, ...(existingMat ? existingMat.invalidFields : [])])].slice(0, WIRE_MAX_DUP_PATHS),
  };
  return {
    value: out,
    hasConflict,
    hasMalformed,
    duplicateKeys: ownDupKeys,
    invalidFields: ownInvalidFields,
  };
}

// Expose shared helpers on the global registry so standalone ESM modules with zero relative
// imports (jobModel.js, findingPresentation.js, reportModel.js) use the exact same rules.
wireRegistry.WIRE_MAX_SCAN_DEPTH = WIRE_MAX_SCAN_DEPTH;
wireRegistry.isWireInvalidSentinel = isWireInvalidSentinel;
wireRegistry.isWireInvalidIntAnomaly = isWireInvalidIntAnomaly;
wireRegistry.getWireObjectIntegrity = getWireObjectIntegrity;
wireRegistry.getWireDuplicateKeyInfo = getWireDuplicateKeyInfo;
wireRegistry.readStrictWireSafeInt = readStrictWireSafeInt;
wireRegistry.materializeNormalizedTelemetry = materializeNormalizedTelemetry;

const STORAGE_API_URL_KEY = 'ntk-api-base-url';
export const HEALTH_PROOF_LEDGER_STORAGE_KEY = '22025523-health-proof-ledger-v1';
export const HEALTH_SCOPE_EPOCH_STORAGE_KEY = '22025523-health-scope-epoch-v1';
export const HEALTH_LEDGER_SALT_STORAGE_KEY = '22025523-health-ledger-salt-v1';
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
  const storage = getSessionStorageSafe();
  if (!storage) return;
  try {
    storage.removeItem(ACTIVE_SCAN_STORAGE_KEY);
    storage.removeItem(ACTIVE_JOB_STORAGE_KEY);
    storage.removeItem(ACTIVE_JOB_STARTED_KEY);
    storage.removeItem(LIVE_SCAN_HISTORY_STORAGE_KEY);
    if (typeof storage.length === 'number' && typeof storage.key === 'function') {
      const toRemove = [];
      for (let i = 0; i < storage.length; i += 1) {
        const key = storage.key(i);
        if (key && key.startsWith(LIVE_DATASET_CACHE_PREFIX)) toRemove.push(key);
      }
      toRemove.forEach((key) => storage.removeItem(key));
    }
  } catch {
    /* optional sessionStorage cleanup */
  }
}

// Storage access guards. In some browser configurations even reading `window.sessionStorage`
// throws (SecurityError), so the property access itself is wrapped, not only getItem/setItem.
// Storage is optional: callers treat `null`/`false` as "unavailable" and keep working in RAM.
export function getSessionStorageSafe() {
  try {
    if (typeof window === 'undefined' || !window) return null;
    const storage = window.sessionStorage;
    return storage && typeof storage.getItem === 'function' ? storage : null;
  } catch {
    return null;
  }
}

export function safeSessionGet(key) {
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  try {
    const value = storage.getItem(key);
    return typeof value === 'string' ? value : null;
  } catch {
    return null;
  }
}

export function safeSessionSet(key, value) {
  const storage = getSessionStorageSafe();
  if (!storage) return false;
  try {
    storage.setItem(key, String(value));
    return true;
  } catch {
    return false;
  }
}

export function safeSessionRemove(key) {
  const storage = getSessionStorageSafe();
  if (!storage) return false;
  try {
    storage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

// Pure-JS FIPS 180-4 SHA-256 + RFC 2104 HMAC-SHA-256 used strictly to derive an irreversible,
// per-tab randomly-salted scope bucket identifier for non-sensitive monotonic health expiry metadata.
// Bearer Tokens remain RAM-only and are NEVER stored in sessionStorage/localStorage.
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function utf8Bytes(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  const encoded = unescape(encodeURIComponent(str));
  const out = new Uint8Array(encoded.length);
  for (let i = 0; i < encoded.length; i += 1) out[i] = encoded.charCodeAt(i);
  return out;
}

function sha256Bytes(data) {
  const bytes = data instanceof Uint8Array ? data : utf8Bytes(String(data || ''));
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const buf = new Uint8Array(paddedLen);
  buf.set(bytes);
  buf[bytes.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667; let h1 = 0xbb67ae85; let h2 = 0x3c6ef372; let h3 = 0xa54ff53a;
  let h4 = 0x510e527f; let h5 = 0x9b05688c; let h6 = 0x1f83d9ab; let h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i += 1) w[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i += 1) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0; let b = h1; let c = h2; let d = h3;
    let e = h4; let f = h5; let g = h6; let h = h7;
    for (let i = 0; i < 64; i += 1) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const digest = new Uint8Array(32);
  const dv = new DataView(digest.buffer);
  dv.setUint32(0, h0, false); dv.setUint32(4, h1, false); dv.setUint32(8, h2, false); dv.setUint32(12, h3, false);
  dv.setUint32(16, h4, false); dv.setUint32(20, h5, false); dv.setUint32(24, h6, false); dv.setUint32(28, h7, false);
  return digest;
}

function hmacSha256Hex(keyStr, msgStr) {
  let keyBytes = utf8Bytes(keyStr);
  if (keyBytes.length > 64) keyBytes = sha256Bytes(keyBytes);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i += 1) {
    const k = i < keyBytes.length ? keyBytes[i] : 0;
    ipad[i] = k ^ 0x36;
    opad[i] = k ^ 0x5c;
  }
  const msgBytes = utf8Bytes(msgStr);
  const innerBuf = new Uint8Array(64 + msgBytes.length);
  innerBuf.set(ipad, 0);
  innerBuf.set(msgBytes, 64);
  const innerHash = sha256Bytes(innerBuf);
  const outerBuf = new Uint8Array(64 + 32);
  outerBuf.set(opad, 0);
  outerBuf.set(innerHash, 64);
  const outerHash = sha256Bytes(outerBuf);
  let hex = '';
  for (let i = 0; i < outerHash.length; i += 1) hex += outerHash[i].toString(16).padStart(2, '0');
  return hex;
}

let memoryTabSalt = '';

function randomSaltHex() {
  const bytes = new Uint8Array(16);
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i += 1) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function readOrCreateHealthLedgerSalt() {
  const existing = safeSessionGet(HEALTH_LEDGER_SALT_STORAGE_KEY);
  if (typeof existing === 'string' && /^[0-9a-f]{32}$/.test(existing)) {
    memoryTabSalt = existing;
    return existing;
  }
  // When storage is unavailable the salt stays RAM-only for this page load (random, never a
  // constant). The health ledger cannot persist in that case either, so nothing is lost.
  if (getSessionStorageSafe()) {
    const generated = randomSaltHex();
    if (safeSessionSet(HEALTH_LEDGER_SALT_STORAGE_KEY, generated)) {
      memoryTabSalt = generated;
      return generated;
    }
  }
  if (!memoryTabSalt) memoryTabSalt = randomSaltHex();
  return memoryTabSalt;
}

export function clearHealthProofLedgerStorage({bumpEpoch = false} = {}) {
  safeSessionRemove(HEALTH_PROOF_LEDGER_STORAGE_KEY);
  if (bumpEpoch) {
    const current = Number.parseInt(safeSessionGet(HEALTH_SCOPE_EPOCH_STORAGE_KEY) || '1', 10);
    const next = Number.isSafeInteger(current) && current >= 1 && current < 1000000000 ? current + 1 : 2;
    safeSessionSet(HEALTH_SCOPE_EPOCH_STORAGE_KEY, String(next));
  }
}

export function getHealthPersistenceScopeKey() {
  // Bind non-sensitive monotonic anti-replay metadata to (apiBaseUrl, origin, auth-session).
  // - Unauthenticated sessions use `v2|<baseUrl>|<origin>|anon`.
  // - Authenticated sessions use `v2|<baseUrl>|<origin>|auth:<salted-hmac-128bit>` where the
  //   tag is computed with an ephemeral per-tab random salt in sessionStorage. The Bearer Token
  //   itself stays strictly in RAM and is NEVER written to storage.
  // - Surviving Page.reload -> AUTH_REQUIRED -> re-entry of the same token prevents expired-probe
  //   resurrection while strictly isolating different URLs, origins, anon vs auth, and different tokens.
  let origin = '';
  try {
    origin = extractOrigin(apiBaseUrl);
  } catch {
    return null;
  }
  if (!apiBaseUrl || !origin) return null;
  if (!hasSessionToken()) {
    return `v2|${apiBaseUrl}|${origin}|anon`;
  }
  const salt = readOrCreateHealthLedgerSalt();
  const authTag = hmacSha256Hex(salt, `health-ledger-v2\0${apiBaseUrl}\0${origin}\0${sessionToken}`).slice(0, 32);
  return `v2|${apiBaseUrl}|${origin}|auth:${authTag}`;
}

function rotateAuthSession(baseUrl) {
  authSessionSeq += 1;
  authSessionScope = buildAuthSessionScope(baseUrl, authSessionSeq);
  clearSessionScopedStorage();
  // Intentionally do NOT wipe HEALTH_PROOF_LEDGER_STORAGE_KEY here: the ledger is strictly
  // monotonic/restrictive and isolated per (baseUrl, origin, salted-auth-tag), so reload ->
  // AUTH_REQUIRED -> token re-entry preserves expired-probe anti-resurrection without sharing
  // proofs across different URLs or different tokens.
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
  const saved = safeSessionGet(STORAGE_API_URL_KEY);
  if (saved) {
    try {
      return normalizeApiUrl(saved);
    } catch {
      safeSessionRemove(STORAGE_API_URL_KEY);
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
  safeSessionSet(STORAGE_API_URL_KEY, normalized);

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
  safeSessionSet(STORAGE_API_URL_KEY, normalized);
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
  safeSessionRemove(STORAGE_API_URL_KEY);
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
        payload = parseJsonWithWireIntegrity(rawBody);
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
    const contentType = String(response.headers?.get?.('content-type') || '').toLowerCase();
    try {
      return parseJsonWithWireIntegrity(text);
    } catch (parseErr) {
      const trimmed = text.trim();
      if (contentType.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
        throw new ApiError('Phản hồi JSON từ máy chủ API không hợp lệ hoặc bị cắt cụt.', {
          status: response.status,
          payload: {error_code: 'INVALID_JSON'},
          cause: parseErr,
        });
      }
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

const VALID_JOB_STATES = new Set(['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'CANCELED']);

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
  const hasDuplicateListContainerKey = Boolean(
    getWireObjectIntegrity(data)?.scannerError
    || ['jobs', 'scans', 'items', 'findings', 'warnings', 'total_count', 'truncated', 'has_more', 'total_pages', 'page', 'limit']
      .some((k) => Boolean(getWireDuplicateKeyInfo(data, k))),
  );
  if (hasDuplicateListContainerKey) {
    return invalidListResult('DUPLICATE_WIRE_KEY', {
      totalCountProvided: Object.hasOwn(data, 'total_count') && data.total_count !== undefined,
      endpointStatus: 'INCOMPLETE',
      httpStatus: 200,
    });
  }
  const totalCountProvided = Object.hasOwn(data, 'total_count') && data.total_count !== undefined;
  const totalCheck = readStrictWireSafeInt(data, 'total_count');
  const totalCountValid = Boolean(totalCountProvided && totalCheck.present && totalCheck.valid && totalCheck.value !== null);
  const declaredTotalCount = totalCountValid ? totalCheck.value : null;
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

function nonNegativeIntOrNull(value, obj = null, key = '') {
  if (obj && key) {
    const check = readStrictWireSafeInt(obj, key);
    return check.present && check.valid ? check.value : null;
  }
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0) ? value : null;
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
    const pageWireIntegrity = getWireObjectIntegrity(response);
    const hasDuplicatePageKey = Boolean(
      pageWireIntegrity?.scannerError
      || ['findings', 'scan_id', 'total_count', 'total_matching', 'total_pages', 'page', 'page_size', 'has_more', 'truncated', 'next_page', 'next_cursor']
        .some((k) => Boolean(getWireDuplicateKeyInfo(response, k))),
    );
    if (hasDuplicatePageKey) {
      paginationInconsistent = true;
      break;
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
      ? nonNegativeIntOrNull(response.total_matching, response, 'total_matching')
      : null;
    const countTotal = response.total_count !== undefined && response.total_count !== null
      ? nonNegativeIntOrNull(response.total_count, response, 'total_count')
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
    const totalPages = rawTotalPages !== undefined && rawTotalPages !== null ? nonNegativeIntOrNull(rawTotalPages, response, 'total_pages') : null;
    if (rawTotalPages !== undefined && rawTotalPages !== null && totalPages === null) {
      paginationInconsistent = true;
      break;
    }
    const rawRespPage = response.page;
    const respPage = rawRespPage !== undefined && rawRespPage !== null ? nonNegativeIntOrNull(rawRespPage, response, 'page') : null;
    if (rawRespPage !== undefined && rawRespPage !== null && (respPage === null || respPage < 1 || respPage !== page)) {
      paginationInconsistent = true;
      break;
    }
    const rawRespSize = response.page_size;
    const respSize = rawRespSize !== undefined && rawRespSize !== null ? nonNegativeIntOrNull(rawRespSize, response, 'page_size') : null;
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

Object.defineProperty(api, 'getScopeSnapshot', {
  value: () => ({
    baseUrl: getApiBaseUrl(),
    origin: getApiOrigin(),
    sessionScope: getAuthSessionScope(),
  }),
  enumerable: false,
});

export async function checkBackend() {
  try {
    const status = await api.health();
    return {connected: status?.status === 'OK' || status?.status === 'DEGRADED', status};
  } catch (error) {
    return {connected: false, error: error.message};
  }
}
