// Pure report view-model builder for GET /api/scans/{scan_id}/report.

export function validateReportForScan(reportDoc, expectedScanId) {
  const expected = typeof expectedScanId === 'string' ? expectedScanId.trim() : '';
  if (!expected) {
    return {
      valid: false,
      scanId: '',
      reason: 'MISSING_EXPECTED_SCAN_ID',
      error: 'Thiếu mã phiên quét (scan_id) đang chọn.',
    };
  }
  if (!reportDoc || typeof reportDoc !== 'object' || Array.isArray(reportDoc)) {
    return {
      valid: false,
      scanId: '',
      reason: 'INVALID_REPORT_PAYLOAD',
      error: 'Phản hồi báo cáo từ API không hợp lệ.',
    };
  }
  const summary = reportDoc.scan_summary && typeof reportDoc.scan_summary === 'object' && !Array.isArray(reportDoc.scan_summary)
    ? reportDoc.scan_summary
    : null;
  if (!summary) {
    return {
      valid: false,
      scanId: '',
      reason: 'MISSING_REPORT_SUMMARY',
      error: 'Phản hồi báo cáo thiếu trường scan_summary hợp lệ; dữ liệu không được hiển thị hoặc tải xuống.',
    };
  }
  if (typeof summary.scan_id !== 'string' || !summary.scan_id.trim()) {
    return {
      valid: false,
      scanId: '',
      reason: 'MISSING_REPORT_SCAN_ID',
      error: 'Phản hồi báo cáo thiếu scan_summary.scan_id hợp lệ; dữ liệu không được hiển thị hoặc tải xuống.',
    };
  }
  const returnedScanId = summary.scan_id.trim();
  if (returnedScanId !== expected) {
    return {
      valid: false,
      scanId: returnedScanId,
      reason: 'SCAN_ID_MISMATCH',
      error: `Phản hồi báo cáo thuộc phiên ${returnedScanId}, không khớp phiên đang chọn (${expected}); dữ liệu không được hiển thị hoặc tải xuống.`,
    };
  }
  if (reportDoc.scan_id !== undefined && (typeof reportDoc.scan_id !== 'string' || reportDoc.scan_id.trim() !== expected)) {
    return {
      valid: false,
      scanId: typeof reportDoc.scan_id === 'string' ? reportDoc.scan_id.trim() : '',
      reason: 'SCAN_ID_MISMATCH',
      error: `Trường scan_id của báo cáo không khớp phiên đang chọn (${expected}); dữ liệu không được hiển thị hoặc tải xuống.`,
    };
  }
  if (!Array.isArray(reportDoc.findings)) {
    return {
      valid: false,
      scanId: returnedScanId,
      reason: 'INVALID_FINDINGS_LIST',
      error: 'Phản hồi báo cáo thiếu danh sách findings hợp lệ; dữ liệu không được hiển thị hoặc tải xuống.',
    };
  }
  for (let i = 0; i < reportDoc.findings.length; i += 1) {
    const f = reportDoc.findings[i];
    if (!f || typeof f !== 'object' || Array.isArray(f)) {
      return {
        valid: false,
        scanId: returnedScanId,
        reason: 'INVALID_FINDING_ENTRY',
        error: `Cảnh báo #${i + 1} trong báo cáo có cấu trúc không hợp lệ; dữ liệu không được hiển thị hoặc tải xuống.`,
      };
    }
    if (f.scan_id === undefined || f.scan_id === null) {
      return {
        valid: false,
        scanId: returnedScanId,
        reason: 'MISSING_FINDING_SCAN_ID',
        error: `Cảnh báo #${i + 1} trong báo cáo thiếu mã phiên (scan_id); dữ liệu không được hiển thị hoặc tải xuống.`,
      };
    }
    if (typeof f.scan_id !== 'string') {
      return {
        valid: false,
        scanId: returnedScanId,
        reason: 'INVALID_FINDING_SCAN_ID',
        error: `Cảnh báo #${i + 1} trong báo cáo có trường scan_id sai kiểu dữ liệu; dữ liệu không được hiển thị hoặc tải xuống.`,
      };
    }
    const findingScanId = f.scan_id.trim();
    if (!findingScanId) {
      return {
        valid: false,
        scanId: returnedScanId,
        reason: 'MISSING_FINDING_SCAN_ID',
        error: `Cảnh báo #${i + 1} trong báo cáo có trường scan_id rỗng; dữ liệu không được hiển thị hoặc tải xuống.`,
      };
    }
    if (findingScanId !== expected) {
      return {
        valid: false,
        scanId: returnedScanId,
        reason: 'FINDING_SCAN_ID_MISMATCH',
        error: `Báo cáo chứa cảnh báo thuộc phiên khác (${findingScanId}); dữ liệu không được hiển thị hoặc tải xuống.`,
      };
    }
  }
  return {valid: true, scanId: returnedScanId, reason: '', error: ''};
}

const REPORT_MOCK_ORIGIN_RE = /(?:^|[_-])(MOCK|SYNTHETIC|UNIT_TEST_MOCK_CAPTURE)(?:$|[_-])/i;
const REPORT_UNVERIFIED_PROV_RE = /(?:^|[_-])(COLLECTION_ONLY|DECLARED_ONLY|IMPORTED|UNVERIFIED|UNKNOWN|MANUAL_IMPORT)(?:$|[_-])/i;
const REPORT_EXPLICIT_VALIDATED = new Set(['SUPPORTED', 'REFUTED', 'UNDETERMINED']);
const REPORT_EXPLICIT_HUMAN = new Set(['OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE']);

function isPlainReportObj(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function reportPushEvidenceObjects(ev, out) {
  if (!isPlainReportObj(ev)) return;
  out.push(ev, ev.metadata, ev.scan_provenance, ev.scan_provenance?.metadata, ev.java_context?.metadata);
  if (isPlainReportObj(ev.raw_finding)) {
    out.push(ev.raw_finding.metadata, ev.raw_finding.extra?.metadata);
  }
  if (Array.isArray(ev.snippets)) {
    for (let i = 0; i < ev.snippets.length; i += 1) {
      const s = ev.snippets[i];
      if (isPlainReportObj(s)) out.push(s, s.metadata);
    }
  }
  if (isPlainReportObj(ev.snapshots)) {
    for (const meta of Object.values(ev.snapshots)) {
      if (isPlainReportObj(meta)) out.push(meta, meta.metadata);
    }
  }
}

function reportPushAssessmentObjects(ass, out) {
  if (!isPlainReportObj(ass)) return;
  out.push(ass, ass.metadata, ass.runtime, ass.runtime?.metadata, ass.runtime_metadata, ass.citation_provenance);
  if (Array.isArray(ass.citations)) {
    for (let i = 0; i < ass.citations.length; i += 1) {
      const c = ass.citations[i];
      if (isPlainReportObj(c)) out.push(c, c.metadata);
    }
  }
}

function collectReportProvenanceObjects(reportDoc, summary, findings) {
  const out = [
    reportDoc,
    reportDoc.metadata,
    reportDoc.scan_provenance,
    reportDoc.scan_provenance?.metadata,
    summary,
    summary.metadata,
    summary.scan_provenance,
    summary.scan_provenance?.metadata,
    summary.runtime_summary,
  ];
  for (let i = 0; i < findings.length; i += 1) {
    const f = findings[i];
    if (!isPlainReportObj(f)) continue;
    out.push(
      f,
      f.metadata,
      f.scan_provenance,
      f.scan_provenance?.metadata,
      f.scan_summary,
      f.scan_summary?.metadata,
      f.scan_summary?.scan_provenance,
      f.scan_summary?.scan_provenance?.metadata,
    );
    reportPushEvidenceObjects(f.evidence, out);
    reportPushAssessmentObjects(f.assessment, out);
  }
  return out.filter(isPlainReportObj);
}

function collectReportDeclaredOrigins(objects) {
  const origins = [];
  for (let i = 0; i < objects.length; i += 1) {
    const obj = objects[i];
    if (!isPlainReportObj(obj)) continue;
    for (const candidate of [obj.data_origin, obj.metadata?.data_origin]) {
      if (candidate === undefined || candidate === null) continue;
      if (typeof candidate !== 'string') {
        return {origins, invalid: true};
      }
      const normalized = candidate.trim().toUpperCase();
      if (normalized) origins.push(normalized);
    }
  }
  return {origins, invalid: false};
}

function reportHasMockSignal(obj) {
  if (!isPlainReportObj(obj)) return false;
  if (
    obj.is_test_or_mock === true ||
    obj.contains_mock_or_test_data === true ||
    obj.mock === true ||
    obj.is_mock === true ||
    obj.synthetic === true ||
    obj.is_synthetic === true
  ) return true;
  const mockRecords = obj.mock_records ?? obj.runtime_summary?.mock_records;
  if (typeof mockRecords === 'number' && Number.isFinite(mockRecords) && mockRecords > 0) return true;
  return [obj.data_origin, obj.origin, obj.scan_provenance?.origin, obj.runtime?.origin].some((val) => {
    const clean = typeof val === 'string' ? val.trim().toUpperCase() : '';
    return Boolean(clean && (clean === 'MOCK_SYNTHETIC_TEST' || clean === 'MOCK_TEST' || REPORT_MOCK_ORIGIN_RE.test(clean)));
  });
}

function validateReportCaptureProvenance(prov) {
  if (!isPlainReportObj(prov)) {
    return {verified: false, captureRecorded: false, sourceVerified: false, engineSucceeded: false, reason: 'MISSING_SCAN_PROVENANCE'};
  }
  const hasOriginField = prov.origin !== undefined && prov.origin !== null;
  const po = hasOriginField && typeof prov.origin === 'string' ? prov.origin.trim().toUpperCase() : '';
  const originAcceptable = !hasOriginField || (Boolean(po) && !REPORT_UNVERIFIED_PROV_RE.test(po));
  const sourceVerified = prov.source_capture_verified === true;
  const exitCaptured = prov.exit_capture_verified === true;
  const hasIntExit = typeof prov.recorded_engine_exit === 'number' && Number.isInteger(prov.recorded_engine_exit);
  const engineSucceeded = hasIntExit && prov.recorded_engine_exit === 0;
  const captureRecorded = exitCaptured && hasIntExit && originAcceptable;

  if (!originAcceptable) return {verified: false, captureRecorded, sourceVerified, engineSucceeded, reason: 'UNVERIFIED_PROVENANCE_ORIGIN'};
  if (!sourceVerified || !exitCaptured) return {verified: false, captureRecorded, sourceVerified, engineSucceeded, reason: 'UNVERIFIED_CAPTURE_FLAGS'};
  if (!hasIntExit) return {verified: false, captureRecorded: false, sourceVerified, engineSucceeded: false, reason: 'MISSING_RECORDED_ENGINE_EXIT'};
  if (!engineSucceeded) return {verified: false, captureRecorded: true, sourceVerified, engineSucceeded: false, reason: 'ENGINE_EXIT_NONZERO'};
  return {verified: true, captureRecorded: true, sourceVerified: true, engineSucceeded: true, reason: 'VERIFIED_CAPTURE_PROVENANCE'};
}

function resolveReportProvenance(reportDoc, summary, findings) {
  if (collectReportProvenanceObjects(reportDoc, summary, findings).some(reportHasMockSignal)) {
    return {
      dataOrigin: 'MOCK_SYNTHETIC_TEST',
      isMockOrTest: true,
      isVerifiedRealScan: false,
      explicitProvenanceFailure: true,
      captureRecorded: false,
      sourceVerified: false,
      engineSucceeded: false,
      reason: 'MOCK_OR_SYNTHETIC_DETECTED',
    };
  }
  const topDeclared = collectReportDeclaredOrigins([reportDoc, summary]);
  const componentObjects = [];
  for (let i = 0; i < findings.length; i += 1) {
    const f = findings[i];
    if (!isPlainReportObj(f)) continue;
    componentObjects.push(f, f.evidence, f.assessment, f.scan_summary);
  }
  const componentDeclared = collectReportDeclaredOrigins(componentObjects);
  if (topDeclared.invalid || componentDeclared.invalid) {
    return {
      dataOrigin: 'UNVERIFIED_ORIGIN',
      isMockOrTest: false,
      isVerifiedRealScan: false,
      explicitProvenanceFailure: true,
      captureRecorded: false,
      sourceVerified: false,
      engineSucceeded: false,
      reason: 'INVALID_DATA_ORIGIN_FIELD',
    };
  }
  const topUnique = [...new Set(topDeclared.origins)];
  const componentUnique = [...new Set(componentDeclared.origins)];
  if (topUnique.length === 0) {
    return {
      dataOrigin: 'UNVERIFIED_ORIGIN',
      isMockOrTest: false,
      isVerifiedRealScan: false,
      explicitProvenanceFailure: componentUnique.some((origin) => origin !== 'REAL_SCAN'),
      captureRecorded: false,
      sourceVerified: false,
      engineSucceeded: false,
      reason: 'MISSING_DATA_ORIGIN',
    };
  }
  const unique = [...new Set([...topUnique, ...componentUnique])];
  if (unique.length > 1) {
    return {
      dataOrigin: 'UNVERIFIED_ORIGIN',
      isMockOrTest: false,
      isVerifiedRealScan: false,
      explicitProvenanceFailure: true,
      captureRecorded: false,
      sourceVerified: false,
      engineSucceeded: false,
      reason: 'CONFLICTING_DATA_ORIGIN',
    };
  }
  const rawOrigin = unique[0];
  if (rawOrigin === 'REAL_SCAN') {
    const provs = [reportDoc.scan_provenance, summary.scan_provenance];
    for (let i = 0; i < findings.length; i += 1) {
      const f = findings[i];
      if (isPlainReportObj(f)) {
        provs.push(f.scan_provenance, f.evidence?.scan_provenance, f.scan_summary?.scan_provenance);
      }
    }
    const presentProvs = provs.filter((p) => p !== undefined && p !== null);
    if (presentProvs.length === 0) {
      return {
        dataOrigin: 'UNVERIFIED_ORIGIN',
        isMockOrTest: false,
        isVerifiedRealScan: false,
        explicitProvenanceFailure: false,
        captureRecorded: false,
        sourceVerified: false,
        engineSucceeded: false,
        reason: 'MISSING_SCAN_PROVENANCE',
      };
    }
    for (let i = 0; i < presentProvs.length; i += 1) {
      const check = validateReportCaptureProvenance(presentProvs[i]);
      if (!check.verified) {
        return {
          dataOrigin: 'UNVERIFIED_ORIGIN',
          isMockOrTest: false,
          isVerifiedRealScan: false,
          explicitProvenanceFailure: true,
          captureRecorded: check.captureRecorded,
          sourceVerified: check.sourceVerified,
          engineSucceeded: check.engineSucceeded,
          reason: check.reason,
        };
      }
    }
    return {
      dataOrigin: 'REAL_SCAN',
      isMockOrTest: false,
      isVerifiedRealScan: true,
      explicitProvenanceFailure: false,
      captureRecorded: true,
      sourceVerified: true,
      engineSucceeded: true,
      reason: 'VERIFIED_CAPTURE_PROVENANCE',
    };
  }
  return {
    dataOrigin: rawOrigin,
    isMockOrTest: false,
    isVerifiedRealScan: false,
    explicitProvenanceFailure: true,
    captureRecorded: false,
    sourceVerified: false,
    engineSucceeded: false,
    reason: 'NON_REAL_OR_IMPORTED_ORIGIN',
  };
}

function inspectReportFindingsForRefutedOpen(findings) {
  if (!Array.isArray(findings)) {
    return {validIds: false, hasAllExplicitStatuses: false, obsRefOpen: 0, obsNonRefOpen: 0, obsRefNonOpen: 0, obsOpenNonRef: 0};
  }
  const seenIds = new Set();
  let validIds = true;
  let hasAllExplicitStatuses = true;
  let obsRefOpen = 0;
  let obsNonRefOpen = 0;
  let obsRefNonOpen = 0;
  let obsOpenNonRef = 0;
  for (let i = 0; i < findings.length; i += 1) {
    const f = findings[i];
    if (!isPlainReportObj(f)) {
      validIds = false;
      hasAllExplicitStatuses = false;
      continue;
    }
    const rawId = f.finding_id ?? f.id;
    const id = typeof rawId === 'string'
      ? rawId.trim()
      : typeof rawId === 'number' && Number.isFinite(rawId)
        ? String(rawId)
        : '';
    if (!id || seenIds.has(id)) {
      validIds = false;
    } else {
      seenIds.add(id);
    }
    const ass = isPlainReportObj(f.assessment) ? f.assessment : {};
    const rawVal = f.validated_status ?? ass.validated_status ?? ass.status;
    const validated = typeof rawVal === 'string' ? rawVal.trim().toUpperCase() : '';
    const hasVal = REPORT_EXPLICIT_VALIDATED.has(validated);
    if (!hasVal) hasAllExplicitStatuses = false;

    const rawHuman = f.human_review_state ?? f.state;
    const human = typeof rawHuman === 'string' ? rawHuman.trim().toUpperCase() : '';
    const hasHuman = REPORT_EXPLICIT_HUMAN.has(human);
    if (!hasHuman) hasAllExplicitStatuses = false;

    if (hasVal && hasHuman) {
      if (validated === 'REFUTED' && human === 'OPEN') {
        obsRefOpen += 1;
      } else {
        obsNonRefOpen += 1;
        if (validated === 'REFUTED') obsRefNonOpen += 1;
        if (human === 'OPEN') obsOpenNonRef += 1;
      }
    } else if (hasVal && validated !== 'REFUTED') {
      obsNonRefOpen += 1;
      if (hasHuman && human === 'OPEN') obsOpenNonRef += 1;
    } else if (hasHuman && human !== 'OPEN') {
      obsNonRefOpen += 1;
      if (hasVal && validated === 'REFUTED') obsRefNonOpen += 1;
    }
  }
  return {validIds, hasAllExplicitStatuses, obsRefOpen, obsNonRefOpen, obsRefNonOpen, obsOpenNonRef};
}

function resolveReportRefutedStillOpen(findings, totalFindings, refutedCount, openCount, rawSummaryRefutedOpen) {
  if (!Number.isInteger(totalFindings) || totalFindings < 0) return null;
  const insp = inspectReportFindingsForRefutedOpen(findings);
  if (!insp.validIds) return null;

  const isFullList = Array.isArray(findings) && findings.length === totalFindings;
  const computedExact = isFullList && insp.hasAllExplicitStatuses ? insp.obsRefOpen : null;

  if (rawSummaryRefutedOpen !== undefined && rawSummaryRefutedOpen !== null) {
    if (typeof rawSummaryRefutedOpen !== 'number' || !Number.isInteger(rawSummaryRefutedOpen) || rawSummaryRefutedOpen < 0) {
      return null;
    }
    const upperBound = Math.min(
      totalFindings,
      Math.max(0, refutedCount - insp.obsRefNonOpen),
      Math.max(0, openCount - insp.obsOpenNonRef),
      Math.max(0, totalFindings - insp.obsNonRefOpen),
    );
    const lowerBound = Math.max(0, refutedCount + openCount - totalFindings, insp.obsRefOpen);
    if (rawSummaryRefutedOpen < lowerBound || rawSummaryRefutedOpen > upperBound) return null;
    if (isFullList && !insp.hasAllExplicitStatuses) return null;
    if (computedExact !== null && rawSummaryRefutedOpen !== computedExact) return null;
    return rawSummaryRefutedOpen;
  }

  return computedExact;
}

export function buildReportViewModel(reportDoc, {expectedScanId} = {}) {
  if (!reportDoc || typeof reportDoc !== 'object') return null;
  if (expectedScanId !== undefined && !validateReportForScan(reportDoc, expectedScanId).valid) {
    return null;
  }

  const summary = isPlainReportObj(reportDoc.scan_summary) ? reportDoc.scan_summary : {};
  const byValidated = isPlainReportObj(summary.by_validated_status) ? summary.by_validated_status : {};
  const byHuman = isPlainReportObj(summary.by_human_review_state) ? summary.by_human_review_state : {};
  const byCwe = isPlainReportObj(summary.by_cwe) ? summary.by_cwe : {};
  const auditTrail = isPlainReportObj(reportDoc.audit_trail) ? reportDoc.audit_trail : {};
  const findings = Array.isArray(reportDoc.findings) ? reportDoc.findings : [];

  const prov = resolveReportProvenance(reportDoc, summary, findings);
  const {dataOrigin, isMockOrTest, isVerifiedRealScan} = prov;

  const totalFindings = Number(summary.total_findings ?? findings.length);
  const supportedCount = Number(byValidated.SUPPORTED ?? 0);
  const refutedCount = Number(byValidated.REFUTED ?? 0);
  const undeterminedCount = Number(byValidated.UNDETERMINED ?? 0);

  const openCount = Number(byHuman.OPEN ?? 0);
  const confirmedTrueCount = Number(byHuman.CONFIRMED_TRUE ?? 0);
  const confirmedFalseCount = Number(byHuman.CONFIRMED_FALSE ?? 0);

  const refutedStillOpenCount = resolveReportRefutedStillOpen(
    findings,
    totalFindings,
    refutedCount,
    openCount,
    summary.proposed_refuted_open_count,
  );

  const scanIssues = Array.isArray(summary.scan_issues) ? summary.scan_issues : [];
  const limits = Array.isArray(summary.known_analysis_limits) ? summary.known_analysis_limits : [];
  const stageStatuses = summary.stage_statuses && typeof summary.stage_statuses === 'object' ? summary.stage_statuses : null;

  const events = Array.isArray(auditTrail.events) ? auditTrail.events : [];
  const rejectedDecisions = Array.isArray(auditTrail.rejected_decisions) ? auditTrail.rejected_decisions : [];

  const findingRows = findings.map((f) => {
    const ev = f?.evidence || {};
    const ass = f?.assessment || {};
    const citations = Array.isArray(ass.citations) ? ass.citations : [];
    const snapshots = ev.snapshots && typeof ev.snapshots === 'object' ? ev.snapshots : {};
    return {
      id: f.finding_id || f.id,
      cwe: f.cwe || 'Chưa rõ',
      ruleId: f.rule_id || ev.rule_id || '-',
      filePath: f.file_path || ev.path || '-',
      startLine: f.start_line ?? ev.start?.line ?? '-',
      validatedStatus: String(f.validated_status || ass.validated_status || 'UNDETERMINED').toUpperCase(),
      rawModelStatus: f.raw_model_status || ass.raw_model_status || null,
      validatorDowngraded: Boolean(f.validator_downgraded ?? ass.validator_downgraded),
      failureKind: f.failure_kind || ass.failure_kind || null,
      citationCheck: String(f.citation_check || ass.citation_check || 'NOT_VERIFIED').toUpperCase(),
      humanReviewState: String(f.human_review_state || 'OPEN').toUpperCase(),
      citations: citations.map((c) => ({
        path: c.path,
        startLine: c.start_line,
        endLine: c.end_line,
        quote: c.quote,
        sha256: c.sha256,
      })),
      snapshots: Object.entries(snapshots).map(([snapPath, meta]) => ({
        path: snapPath,
        sha256: meta?.sha256 || '-',
        size: meta?.size ?? null,
      })),
    };
  });

  return {
    isMockOrTest,
    isVerifiedRealScan,
    isUnverified: !isVerifiedRealScan,
    provenanceStatus: {
      captureRecorded: prov.captureRecorded,
      sourceVerified: prov.sourceVerified,
      engineSucceeded: prov.engineSucceeded,
      reason: prov.reason,
    },
    canExportReport: !isMockOrTest && !prov.explicitProvenanceFailure,
    canExportVerifiedReport: isVerifiedRealScan && !isMockOrTest,
    dataOrigin,
    generatedAt: reportDoc.generated_at || null,
    reportSchema: reportDoc.report_schema || null,
    scanInfo: {
      scanId: summary.scan_id || '-',
      scanSha256: summary.scan_sha256 || '-',
      inputMode: summary.input_mode || '-',
      sourceTarget: summary.repo_url || summary.file_name || 'Thư mục quét cục bộ',
      resolvedCommit: summary.resolved_commit || null,
      javaFilesScanned: summary.java_files_scanned ?? '-',
      opengrepVersion: summary.opengrep_version || '-',
      rulesSha256: summary.rules_sha256 || '-',
      promptContract: summary.prompt_contract || 'blind',
      collectedAt: summary.collected_at || null,
      e2eMs: summary.total_e2e_duration_ms ?? null,
    },
    cweBreakdown: Object.entries(byCwe),
    opengrepStats: {
      totalFindings,
      findingsWithTrace: Number(summary.findings_with_trace ?? 0),
      provenance: summary.scan_provenance || {},
    },
    qwenStats: {
      supported: supportedCount,
      refuted: refutedCount,
      undetermined: undeterminedCount,
      downgradedCount: Number(summary.validator_downgraded_count ?? 0),
      matchedCitations: Number(summary.matched_citation_count ?? 0),
      runtimeVerified: Boolean(summary.qwen_runtime_verified),
    },
    humanReviewStats: {
      unreviewedOpen: openCount,
      confirmedTrue: confirmedTrueCount,
      confirmedFalse: confirmedFalseCount,
      refutedStillOpen: refutedStillOpenCount,
      eventsCount: Number(auditTrail.events_count ?? events.length),
      rejectedCount: Number(auditTrail.rejected_decisions_count ?? rejectedDecisions.length),
    },
    events,
    rejectedDecisions,
    findingRows,
    scanIssues,
    limits,
    stageStatuses,
    pairedPilotExport: reportDoc.paired_pilot_export || null,
    pairedPilotExportError: reportDoc.paired_pilot_export_error || null,
  };
}
