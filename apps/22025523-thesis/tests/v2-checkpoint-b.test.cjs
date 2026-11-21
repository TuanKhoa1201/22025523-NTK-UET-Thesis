const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC_ROOT = path.join(__dirname, '../src');

async function loadEsmFromSrc(relPath, fetcher, envOverride = '""') {
  let source = fs.readFileSync(path.join(SRC_ROOT, relPath), 'utf8');
  source = source.replace(/import\.meta\.env\?\.VITE_API_BASE_URL/g, envOverride);
  source = source.replace(/import\.meta\.env\.VITE_API_BASE_URL/g, envOverride);
  global.window = {
    setTimeout,
    clearTimeout,
    sessionStorage: {
      _map: new Map(),
      getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
      setItem(k, v) { this._map.set(k, String(v)); },
      removeItem(k) { this._map.delete(k); },
    },
    localStorage: {
      getItem() { throw new Error('localStorage must not be used for tokens'); },
      setItem() { throw new Error('localStorage must not be used for tokens'); },
    },
  };
  if (fetcher) global.fetch = fetcher;
  return import(`data:text/javascript;base64,${Buffer.from(`${source}\n// ${Math.random()}`).toString('base64')}`);
}

test('API adapter uses configurable URL (suggested 18765), rejects port 8765, and never hard-codes 8780', async () => {
  const mod = await loadEsmFromSrc('services/api.js', async () => new Response('{}', {status: 200}));
  assert.equal(mod.getApiBaseUrl(), 'http://127.0.0.1:18765');
  assert.throws(() => mod.setApiBaseUrl('http://127.0.0.1:8765'), /8765/);
  assert.throws(() => mod.setApiBaseUrl('ftp://127.0.0.1:18765'), /http/);
  const updated = mod.setApiBaseUrl('https://100.64.0.10:18765/');
  assert.equal(updated, 'https://100.64.0.10:18765');
  assert.equal(mod.getApiBaseUrl(), 'https://100.64.0.10:18765');
});

test('Session Bearer token is kept in memory only, attached as Authorization header, and never written to storage', async () => {
  const seen = [];
  const mod = await loadEsmFromSrc('services/api.js', async (url, options) => {
    seen.push({url, headers: options.headers});
    return new Response(JSON.stringify({status: 'OK'}), {status: 200});
  });

  assert.equal(mod.hasSessionToken(), false);
  await mod.api.health();
  assert.equal(seen[0].headers.Authorization, undefined);

  mod.setSessionToken('secret-session-token-123456');
  assert.equal(mod.hasSessionToken(), true);
  await mod.api.health();
  assert.equal(seen[1].headers.Authorization, 'Bearer secret-session-token-123456');

  mod.clearSessionToken();
  assert.equal(mod.hasSessionToken(), false);
  await mod.api.health();
  assert.equal(seen[2].headers.Authorization, undefined);
});

test('Scan job creation and findings filter contract match v2/api', async () => {
  const calls = [];
  const mod = await loadEsmFromSrc('services/api.js', async (url, options) => {
    calls.push({url, method: options.method || 'GET', body: options.body, headers: options.headers});
    if (url.includes('/findings')) {
      return new Response(JSON.stringify({
        scan_id: 'scan-1',
        page: 1,
        page_size: 50,
        total_pages: 1,
        total_count: 1,
        total_matching: 1,
        findings: [{finding_id: 'f-1', cwe: 'CWE-89', validated_status: 'UNDETERMINED', human_review_state: 'OPEN'}],
      }), {status: 200});
    }
    return new Response(JSON.stringify({job_id: 'job-1', state: 'QUEUED'}), {status: 202});
  });

  const file = new File(['zipdata'], 'project.zip', {type: 'application/zip'});
  const zipJob = await mod.api.createZipJob(file, {}, {noLlm: true});
  assert.equal(zipJob.job_id, 'job-1');
  assert.equal(calls[0].method, 'POST');
  assert(calls[0].body instanceof FormData);
  assert.equal(calls[0].headers['Content-Type'], undefined);

  await mod.api.createScanJob('https://github.com/org/repo', 'a'.repeat(40), {}, {noLlm: false});
  assert.equal(JSON.parse(calls[1].body).repo_url, 'https://github.com/org/repo');
  assert.equal(JSON.parse(calls[1].body).commit_sha, 'a'.repeat(40));

  const page = await mod.api.findingsPage('scan-1', {
    cwe: 'CWE-22',
    validatedStatus: 'UNDETERMINED',
    humanReviewState: 'OPEN',
    query: 'FileController',
    includeConfirmedFalse: true,
  });
  assert.equal(page.findings.length, 1);
  const parsed = new URL(calls[2].url);
  assert.equal(parsed.pathname, '/api/scans/scan-1/findings');
  assert.equal(parsed.searchParams.get('cwe'), 'CWE-22');
  assert.equal(parsed.searchParams.get('validated_status'), 'UNDETERMINED');
  assert.equal(parsed.searchParams.get('human_review_state'), 'OPEN');
  assert.equal(parsed.searchParams.get('query'), 'FileController');
  assert.equal(parsed.searchParams.get('include_confirmed_false'), 'true');
});

test('inputErrorMessage maps v2/api error codes accurately', async () => {
  const mod = await loadEsmFromSrc('services/api.js');
  assert.match(mod.inputErrorMessage({error_code: 'UNAUTHORIZED'}), /Bearer Token/);
  assert.match(mod.inputErrorMessage({error_code: 'STALE_SOURCE'}), /STALE_SOURCE/);
  assert.match(mod.inputErrorMessage({error_code: 'OPENGREP_UNAVAILABLE'}), /OpenGrep/);
  assert.match(mod.inputErrorMessage({error_code: 'OLLAMA_UNREACHABLE'}), /Ollama/);
});

test('jobModel models the exact 6 stages from v2/api/jobs.py', async () => {
  const mod = await loadEsmFromSrc('services/jobModel.js');
  assert.equal(mod.STAGES.length, 6);
  assert.deepEqual(mod.STAGES.map(([k]) => k), [
    'INTAKE_VALIDATION',
    'OPENGREP_SCAN',
    'EVIDENCE_COLLECTION',
    'QWEN_INFERENCE',
    'CITATION_VALIDATION',
    'REVIEW_STORE_COMMIT',
  ]);

  const stages = mod.resolveStages({
    state: 'FAILED',
    active_stage: 2,
    stages: [
      {stage_number: 1, stage_key: 'INTAKE_VALIDATION', state: 'COMPLETED', duration_ms: 12.5},
      {stage_number: 2, stage_key: 'OPENGREP_SCAN', state: 'FAILED', error: '[OPENGREP_UNAVAILABLE] missing'},
    ],
  });
  assert.equal(stages[0].cat, 'COMPLETED');
  assert.equal(stages[1].cat, 'FAILED');
  assert.equal(stages[2].cat, 'NOT_RUN');
  assert.equal(mod.currentStageIndex({state: 'FAILED', active_stage: 2, stages: [{stage_number: 2, state: 'FAILED'}]}), 1);
});

test('Frontend product flow excludes IRIS, CWSS, LoRA, Dataset Explorer, and hard-coded port 8780', () => {
  const filesToCheck = [
    'App.jsx',
    'data/research.js',
    'data/scanGuide.js',
    'components/layout/AppShell.jsx',
    'services/api.js',
    'pages/Overview.jsx',
    'pages/Architecture.jsx',
    'pages/StatusPage.jsx',
    'pages/Scanner.jsx',
    'pages/LiveFindings.jsx',
    'pages/Results.jsx',
    'pages/HistoryPage.jsx',
    'pages/UtilityPages.jsx',
  ];

  for (const rel of filesToCheck) {
    const content = fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');
    assert(!/\bIRIS\b/.test(content), `${rel} must not contain IRIS`);
    assert(!/\bCWSS\b/.test(content), `${rel} must not contain CWSS`);
    assert(!/\bLoRA\b/.test(content), `${rel} must not contain LoRA`);
    assert(!/DatasetExplorer|\/dataset|\/scoring|\/replay/.test(content), `${rel} must not contain legacy routes`);
    assert(!/8780/.test(content), `${rel} must not hard-code port 8780`);
    assert(!/VITE_API_TOKEN/.test(content), `${rel} must not read API token from Vite bundle env`);
  }
});
