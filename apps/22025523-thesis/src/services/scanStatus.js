// Read IRIS status from backend's recorded Stage 05 telemetry; no local guesswork.
export function readIrisTraceStatus(trace, scanId) {
  if (!scanId || trace?.scan_id !== scanId) return null;
  const stages = trace?.stages ?? trace?.pipeline_trace?.stages ?? trace?.trace?.stages;
  if (!Array.isArray(stages)) return null;
  const irisStage = stages.find((stage) => Number(stage?.number ?? stage?.stage_number) === 5);
  const meta = irisStage?.summary_metadata;
  const status = meta?.original_iris_analysis_status;
  if (typeof status !== 'string' || !/^[A-Z][A-Z0-9_]{1,63}$/.test(status)) return null;
  const codes = meta?.original_iris_reason_codes;
  return {
    status,
    reasonCodes: Array.isArray(codes) ? codes.filter((code) => typeof code === 'string' && /^[A-Z][A-Z0-9_]{1,95}$/.test(code)).slice(0, 8) : []
  };
}
