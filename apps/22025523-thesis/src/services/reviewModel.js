import {api} from './api';

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;

function readableId(value) {
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return '';
}

export function extractFindingId(doc) {
  if (!doc || typeof doc !== 'object') return '';
  const nested = doc.finding && typeof doc.finding === 'object' ? doc.finding : {};
  return readableId(doc.finding_id) || readableId(doc.id) || readableId(nested.finding_id) || readableId(nested.id);
}

export function verifyFindingIdentity(doc, expectedScanId, expectedFindingId, {requireScanId = true} = {}) {
  const wantScan = readableId(expectedScanId);
  const wantFinding = readableId(expectedFindingId);
  if (!wantScan || !wantFinding) {
    return {
      valid: false,
      scanId: '',
      findingId: '',
      reason: 'MISSING_EXPECTED_IDENTITY',
      error: 'Thiếu mã phiên (scan_id) hoặc mã cảnh báo (finding_id) đang chọn.',
    };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return {
      valid: false,
      scanId: '',
      findingId: '',
      reason: 'INVALID_PAYLOAD',
      error: 'Phản hồi chi tiết cảnh báo từ API không hợp lệ.',
    };
  }
  const gotScan = readableId(doc.scan_id);
  const gotFinding = extractFindingId(doc);
  const evidenceFinding = readableId(doc.evidence?.id);

  if (requireScanId && !gotScan) {
    return {
      valid: false,
      scanId: '',
      findingId: gotFinding,
      reason: 'MISSING_SCAN_ID',
      error: 'Phản hồi cảnh báo thiếu mã phiên (scan_id); hệ thống dừng hiển thị bằng chứng và không cho phép kiểm duyệt.',
    };
  }
  if (gotScan && gotScan !== wantScan) {
    return {
      valid: false,
      scanId: gotScan,
      findingId: gotFinding,
      reason: 'SCAN_ID_MISMATCH',
      error: `Phản hồi cảnh báo thuộc phiên ${gotScan}, không khớp phiên đang chọn (${wantScan}); hệ thống dừng hiển thị bằng chứng và không cho phép kiểm duyệt.`,
    };
  }
  if (!gotFinding) {
    return {
      valid: false,
      scanId: gotScan,
      findingId: '',
      reason: 'MISSING_FINDING_ID',
      error: 'Phản hồi thiếu mã cảnh báo (finding_id); hệ thống dừng hiển thị bằng chứng và không cho phép kiểm duyệt.',
    };
  }
  if (gotFinding !== wantFinding) {
    return {
      valid: false,
      scanId: gotScan,
      findingId: gotFinding,
      reason: 'FINDING_ID_MISMATCH',
      error: `Mã cảnh báo phản hồi (${gotFinding}) không khớp cảnh báo đang chọn (${wantFinding}); hệ thống dừng hiển thị bằng chứng và không cho phép kiểm duyệt.`,
    };
  }
  if (evidenceFinding && evidenceFinding !== wantFinding) {
    return {
      valid: false,
      scanId: gotScan,
      findingId: gotFinding,
      reason: 'EVIDENCE_ID_MISMATCH',
      error: `Mã cảnh báo trong hồ sơ bằng chứng (${evidenceFinding}) không khớp cảnh báo đang chọn (${wantFinding}); hệ thống dừng hiển thị bằng chứng và không cho phép kiểm duyệt.`,
    };
  }
  return {valid: true, scanId: gotScan, findingId: gotFinding, reason: '', error: ''};
}

export function verifyScanPayloadIdentity(doc, expectedScanId, {itemsKey = null} = {}) {
  const wantScan = readableId(expectedScanId);
  if (!wantScan) {
    return {valid: false, scanId: '', reason: 'MISSING_EXPECTED_SCAN_ID', error: 'Thiếu mã phiên (scan_id) đang chọn.'};
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return {valid: false, scanId: '', reason: 'INVALID_PAYLOAD', error: 'Phản hồi dữ liệu phiên quét từ API không hợp lệ.'};
  }
  const gotScan = readableId(doc.scan_id);
  if (!gotScan) {
    return {
      valid: false,
      scanId: '',
      reason: 'MISSING_SCAN_ID',
      error: 'Phản hồi từ API thiếu mã phiên (scan_id); thao tác kiểm duyệt đã được dừng để tránh nhầm phiên.',
    };
  }
  if (gotScan !== wantScan) {
    return {
      valid: false,
      scanId: gotScan,
      reason: 'SCAN_ID_MISMATCH',
      error: `Phản hồi thuộc phiên ${gotScan}, không khớp phiên đang chọn (${wantScan}); thao tác kiểm duyệt đã được dừng.`,
    };
  }
  if (itemsKey && Array.isArray(doc[itemsKey])) {
    for (const item of doc[itemsKey]) {
      if (!item || typeof item !== 'object') {
        return {
          valid: false,
          scanId: gotScan,
          reason: 'INVALID_FINDING_ROW',
          error: 'Danh sách cảnh báo chứa bản ghi không hợp lệ; thao tác kiểm duyệt đã được dừng.',
        };
      }
      const itemId = extractFindingId(item);
      if (!itemId) {
        return {
          valid: false,
          scanId: gotScan,
          reason: 'MISSING_ROW_FINDING_ID',
          error: 'Danh sách cảnh báo chứa mục thiếu mã cảnh báo (finding_id); thao tác kiểm duyệt đã được dừng.',
        };
      }
      const itemScan = readableId(item.scan_id);
      if (itemScan && itemScan !== wantScan) {
        return {
          valid: false,
          scanId: gotScan,
          reason: 'ROW_SCAN_ID_MISMATCH',
          error: `Cảnh báo ${itemId} thuộc phiên ${itemScan}, không khớp phiên đang chọn (${wantScan}); thao tác kiểm duyệt đã được dừng.`,
        };
      }
    }
  }
  return {valid: true, scanId: gotScan, reason: '', error: ''};
}

export function evaluateSourceDriftReadiness(detail, {hashConflict = false} = {}) {
  const reasons = [];
  if (!detail || typeof detail !== 'object') {
    const msg = 'Chưa tải được dữ liệu bằng chứng chi tiết của cảnh báo để kiểm tra source drift.';
    return {canConfirmFalse: false, reasons: [msg], summary: msg};
  }
  const evidence = detail.evidence && typeof detail.evidence === 'object' ? detail.evidence : null;
  if (!evidence) {
    const msg = 'Thiếu hồ sơ bằng chứng (evidence) cần thiết để kiểm tra source drift.';
    return {canConfirmFalse: false, reasons: [msg], summary: msg};
  }
  const evidenceIssues = [
    ...(Array.isArray(evidence.issues) ? evidence.issues : []),
    ...(Array.isArray(detail.evidence_issues) ? detail.evidence_issues : []),
  ].filter(Boolean);
  if (evidenceIssues.length > 0 || Number(detail.evidence_issues_count || 0) > 0) {
    reasons.push('Hồ sơ bằng chứng chưa đầy đủ (evidence.issues khác rỗng); cần quét lại trước khi xác nhận cảnh báo giả.');
  }
  const provenance = evidence.scan_provenance && typeof evidence.scan_provenance === 'object'
    ? evidence.scan_provenance
    : null;
  if (!provenance || provenance.source_capture_verified !== true) {
    reasons.push('Thiếu xác minh chụp mã nguồn lúc quét (source_capture_verified != true).');
  }
  const snapshots = evidence.snapshots && typeof evidence.snapshots === 'object' && !Array.isArray(evidence.snapshots)
    ? evidence.snapshots
    : null;
  const snapshotEntries = snapshots ? Object.entries(snapshots) : [];
  if (snapshotEntries.length === 0) {
    reasons.push('Thiếu snapshot SHA-256 của tệp mã nguồn để kiểm tra source drift.');
  } else {
    const invalidSnapshot = snapshotEntries.some(([, meta]) => {
      const sha = typeof meta?.sha256 === 'string' ? meta.sha256.trim() : '';
      return !SHA256_HEX_RE.test(sha);
    });
    if (invalidSnapshot) {
      reasons.push('Snapshot nguồn có mã băm SHA-256 thiếu hoặc không hợp lệ.');
    }
  }
  if (hashConflict) {
    reasons.push('Phát hiện xung đột SHA-256 trong bằng chứng nguồn; không cho phép xác nhận cảnh báo giả.');
  }
  return {
    canConfirmFalse: reasons.length === 0,
    reasons,
    summary: reasons.join(' '),
  };
}

export function validateReviewInput({actor, reason}) {
  const cleanActor = typeof actor === 'string' ? actor.trim() : '';
  const cleanReason = typeof reason === 'string' ? reason.trim() : '';

  if (!cleanActor || cleanActor.length > 120) {
    return {valid: false, error: 'Tên người kiểm duyệt (actor) bắt buộc từ 1 đến 120 ký tự.'};
  }
  for (let i = 0; i < cleanActor.length; i += 1) {
    if (cleanActor.charCodeAt(i) < 32) {
      return {valid: false, error: 'Tên người kiểm duyệt không được chứa ký tự điều khiển.'};
    }
  }
  if (!cleanReason || cleanReason.length > 2000) {
    return {valid: false, error: 'Lý do kiểm duyệt (reason) không được để trống (tối đa 2000 ký tự).'};
  }
  return {valid: true, actor: cleanActor, reason: cleanReason, error: ''};
}

export async function submitReviewDecision({
  scanId,
  findingId,
  action,
  actor,
  reason,
  detail = null,
  hashConflict = false,
  inFlightKeys,
  apiClient = api,
}) {
  if (!scanId || !findingId) {
    return {ok: false, errorCode: 'MISSING_TARGET', message: 'Thiếu scan_id hoặc finding_id.'};
  }
  if (action === 'confirm-false' && (!detail || typeof detail !== 'object' || Array.isArray(detail))) {
    return {
      ok: false,
      errorCode: 'MISSING_FINDING_DETAIL',
      message: 'Thiếu dữ liệu bằng chứng chi tiết (detail) của cảnh báo để kiểm tra định danh và source drift trước khi xác nhận cảnh báo giả.',
    };
  }
  if (detail !== null && detail !== undefined) {
    const preIdentity = verifyFindingIdentity(detail, scanId, findingId, {requireScanId: true});
    if (!preIdentity.valid) {
      return {ok: false, errorCode: preIdentity.reason || 'FINDING_IDENTITY_MISMATCH', message: preIdentity.error};
    }
    if (action === 'confirm-false') {
      const driftCheck = evaluateSourceDriftReadiness(detail, {hashConflict});
      if (!driftCheck.canConfirmFalse) {
        return {
          ok: false,
          errorCode: 'SOURCE_DRIFT_PRECONDITION_UNMET',
          message: `Chưa đủ điều kiện kiểm tra source drift để xác nhận cảnh báo giả: ${driftCheck.summary}`,
        };
      }
    }
  }
  const validation = validateReviewInput({actor, reason});
  if (!validation.valid) {
    return {ok: false, errorCode: 'VALIDATION_ERROR', message: validation.error};
  }

  const lockKey = `${scanId}::${findingId}`;
  if (inFlightKeys?.has(lockKey)) {
    return {
      ok: false,
      duplicate: true,
      errorCode: 'DUPLICATE_SUBMISSION',
      message: 'Yêu cầu kiểm duyệt cho cảnh báo này đang được xử lý. Vui lòng chờ phản hồi từ máy chủ.',
    };
  }

  const actionFn = {
    'confirm-true': apiClient.confirmTrue,
    'confirm-false': apiClient.confirmFalse,
    reopen: apiClient.reopenFinding,
  }[action];

  if (!actionFn) {
    return {ok: false, errorCode: 'INVALID_REVIEW_ACTION', message: `Hành động không hợp lệ: ${action}`};
  }

  const requireScanIdOnRefresh = apiClient === api || Boolean(detail);

  inFlightKeys?.add(lockKey);
  try {
    // Only send {actor, reason}; server enforces auth & SHA-256 source drift checks.
    const mutated = await actionFn(scanId, findingId, {actor: validation.actor, reason: validation.reason});
    if (mutated && typeof mutated === 'object') {
      const mutatedScan = readableId(mutated.scan_id);
      const mutatedFinding = extractFindingId(mutated);
      if ((mutatedScan && mutatedScan !== readableId(scanId)) || (mutatedFinding && mutatedFinding !== readableId(findingId))) {
        return {
          ok: false,
          errorCode: 'FINDING_IDENTITY_MISMATCH',
          message: 'Phản hồi sau khi ghi quyết định kiểm duyệt không khớp phiên hoặc cảnh báo đang chọn.',
        };
      }
    }
    // Always re-read authoritative state from server after mutation.
    const refreshed = await apiClient.findingDetail(scanId, findingId);
    const postIdentity = verifyFindingIdentity(refreshed, scanId, findingId, {requireScanId: requireScanIdOnRefresh});
    if (!postIdentity.valid) {
      return {
        ok: false,
        errorCode: postIdentity.reason || 'FINDING_IDENTITY_MISMATCH',
        message: postIdentity.error,
      };
    }
    return {ok: true, detail: refreshed};
  } catch (error) {
    const payload = error?.payload || {};
    const code = error?.code || payload?.error_code || 'API_ERROR';
    if (error?.status === 409 && code === 'STALE_SOURCE') {
      const payloadScan = readableId(payload.scan_id);
      const payloadFinding = readableId(payload.finding_id);
      if ((payloadScan && payloadScan !== readableId(scanId)) || (payloadFinding && payloadFinding !== readableId(findingId))) {
        return {
          ok: false,
          staleSource: false,
          errorCode: 'FINDING_IDENTITY_MISMATCH',
          message: 'Phản hồi lỗi STALE_SOURCE không khớp phiên hoặc cảnh báo đang chọn.',
        };
      }
      let refreshedHistory = null;
      try {
        const candidateHistory = await apiClient.findingHistory(scanId, findingId, {includeRejected: true});
        const histScan = readableId(candidateHistory?.scan_id);
        const histFinding = readableId(candidateHistory?.finding_id);
        if ((!histScan || histScan === readableId(scanId)) && (!histFinding || histFinding === readableId(findingId))) {
          refreshedHistory = candidateHistory;
        }
      } catch {
        /* fallback to 409 payload's review_events / rejected_decisions */
      }
      return {
        ok: false,
        staleSource: true,
        errorCode: 'STALE_SOURCE',
        message: error.message,
        humanReviewState: refreshedHistory?.human_review_state || payload.human_review_state || 'OPEN',
        staleDetail: payload.stale_source || null,
        reviewEvents: refreshedHistory?.events || payload.review_events || [],
        rejectedDecisions: refreshedHistory?.rejected_decisions || payload.rejected_decisions || [],
      };
    }
    return {
      ok: false,
      staleSource: false,
      abortedByConfigChange: Boolean(error?.abortedByConfigChange),
      status: error?.status,
      errorCode: code,
      message: error?.message || 'Không thể gửi quyết định kiểm duyệt tới máy chủ API.',
    };
  } finally {
    inFlightKeys?.delete(lockKey);
  }
}

export function buildAuditTimeline(events = [], rejectedDecisions = []) {
  const applied = (Array.isArray(events) ? events : []).map((ev) => ({
    kind: 'APPLIED',
    key: `ev-${ev.sequence ?? `${ev.timestamp}-${ev.action}`}`,
    sequence: Number(ev.sequence ?? 0),
    warningId: ev.warning_id,
    actor: ev.actor,
    timestamp: ev.timestamp,
    action: ev.action,
    reason: ev.reason,
    code: null,
    expectedHashes: ev.source_version_parsed || null,
    observedHashes: ev.observed_version_parsed || null,
    evidenceSha256: ev.evidence_sha256 || null,
  }));

  const rejected = (Array.isArray(rejectedDecisions) ? rejectedDecisions : []).map((rj) => ({
    kind: 'REJECTED',
    key: `rj-${rj.sequence ?? `${rj.timestamp}-${rj.attempted_action}`}`,
    sequence: Number(rj.sequence ?? 0),
    warningId: rj.warning_id,
    actor: rj.actor,
    timestamp: rj.timestamp,
    action: rj.attempted_action,
    reason: rj.reason,
    code: rj.rejection_code || 'STALE_SOURCE',
    expectedHashes: rj.source_version_parsed || rj.detail_parsed?.expected_hashes || null,
    observedHashes: rj.observed_version_parsed || rj.detail_parsed?.observed_hashes || null,
    mismatchedPaths: rj.detail_parsed?.mismatched_paths || [],
    detailMessage: rj.detail_parsed?.message || '',
  }));

  return [...applied, ...rejected].sort((a, b) => {
    const tA = Date.parse(a.timestamp || '') || 0;
    const tB = Date.parse(b.timestamp || '') || 0;
    if (tA !== tB) return tB - tA;
    return b.sequence - a.sequence;
  });
}
