"""OFFLINE_SYNTHETIC / MOCK_HTTP controls for the canonical citation contract.

No scanner or Ollama endpoint is called. Optional artifacts are private test receipts.
"""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from v2.triage import evidence, ollama


class CanonicalCitationContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.name = 'Demo1TruePositive.java'
        self.raw_path = '/mnt/c/synthetic-source/' + self.name
        self.source = ROOT / 'v2/g1_integration/demo_fixtures' / self.name
        (self.root / self.name).write_bytes(self.source.read_bytes())
        self.lines = self.source.read_text(encoding='utf-8').splitlines()
        def loc(line, text):
            col = self.lines[line - 1].index(text) + 1
            return dict(path=self.raw_path, start=dict(line=line, col=col),
                        end=dict(line=line, col=col + len(text)))
        src = loc(23, 'req.getParameter("file")')
        sink = loc(25, 'new FileInputStream(targetPath)')
        finding = dict(check_id='synthetic.cwe22', **sink, extra=dict(
            severity='ERROR', metadata={'cwe': ['CWE-22']}, dataflow_trace=dict(
                taint_source=['CliLoc', [src, 'req.getParameter("file")']],
                taint_sink=['CliLoc', [sink, 'new FileInputStream(targetPath)']], intermediate_vars=[])))
        self.raw = json.dumps(dict(results=[finding], errors=[])).encode()
        provenance = dict(source_capture_verified=True, exit_capture_verified=True,
                          origin='UNIT_TEST_MOCK_CAPTURE',
                          source_hashes={self.name: evidence.digest(self.source.read_bytes())})
        self.bundle = evidence.collect(self.raw, self.root, engine_exit=0,
            path_maps=[f'/mnt/c/synthetic-source={self.root}'], scan_provenance=provenance)
        self.rec = self.bundle['records'][0]
        self.assertFalse(self.rec['issues'], self.rec['issues'])
        self.sha = self.rec['snapshots'][self.name]['sha256']

    def save(self, label, data):
        if os.environ.get('C3_REGRESSION_ARTIFACTS'):
            out = Path(os.environ['C3_REGRESSION_ARTIFACTS'])
            out.mkdir(parents=True, exist_ok=True)
            (out / (self._testMethodName + '-' + label + '.json')).write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

    def answer(self, start=25, end=25, **changes):
        cite = dict(path=self.name, start_line=start, end_line=end,
                    quote='\n'.join(self.lines[start - 1:end]), sha256=self.sha)
        cite.update(changes)
        return dict(status='SUPPORTED', explanation='Synthetic citation control only',
                    fix_suggestion='', citations=[cite])

    def analyze(self, answer):
        client = ollama.OllamaClient(runtime_origin='mock')
        response = dict(model=client.model, done=True, mock_test_fixture=True,
                        message={'content': json.dumps(answer)})
        with patch.object(client, 'request', return_value=response) as http:
            out = client.analyze(self.rec)
        self.assertEqual(http.call_count, 1)
        self.save('response-' + str(getattr(self, 'case', 'default')), dict(
            evidence_kind='MOCK_HTTP', raw=response, result=out, fixture_sha256=self.sha))
        return out

    def positive_payload(self, mode, contract):
        self.rec.update(triage_mode=mode, prompt_contract=contract)
        before = copy.deepcopy(self.bundle)
        request = ollama.request_payload(self.rec, 'synthetic-model')
        payload = json.loads(request['messages'][1]['content'])
        self.assertGreater(len(payload['snippets']), 0)
        for snip in payload['snippets']:
            self.assertNotIn('raw_path', snip)
            self.assertEqual(snip['path'], self.name)
            self.assertEqual(snip['sha256'], self.sha)
        for step in payload.get('trace_steps', []):
            self.assertEqual(step['path'], self.name)
        ollama.assert_prompt_contract(payload, contract)
        self.assertEqual(self.bundle, before)
        self.assertEqual(self.rec['raw_finding']['path'], self.raw_path)
        self.assertTrue(any(s['raw_path'] == self.raw_path for s in self.rec['snippets']))
        out = self.analyze(self.answer())
        self.assertEqual(out['validated_status'], 'SUPPORTED')
        self.assertTrue(out['runtime']['answer_validated'])
        self.assertFalse(out['security_conclusion_verified'])
        self.save('payload', dict(request=request,
            request_sha256=evidence.digest(json.dumps(request).encode()),
            evidence_before_sha256=evidence.digest(json.dumps(before, sort_keys=True).encode()),
            evidence_after_sha256=evidence.digest(json.dumps(self.bundle, sort_keys=True).encode())))

    def test_p01_llm_blind(self):
        self.positive_payload('llm', 'blind')

    def test_p01_llm_neutral_hints(self):
        self.positive_payload('llm', 'neutral_hints')

    def test_p01_evidence_blind(self):
        self.positive_payload('evidence+llm', 'blind')

    def test_p01_evidence_neutral_hints(self):
        self.positive_payload('evidence+llm', 'neutral_hints')

    def test_p02_p03_injected_old_producer_rejected_before_http(self):
        original = ollama._project_snippet
        def old_producer(*args, **kwargs):
            return dict(original(*args, **kwargs), raw_path=self.raw_path)
        for mode in ('llm', 'evidence+llm'):
            for contract in ('blind', 'neutral_hints'):
                with self.subTest(mode=mode, contract=contract):
                    self.rec.update(triage_mode=mode, prompt_contract=contract)
                    client = ollama.OllamaClient(runtime_origin='mock')
                    with patch.object(ollama, '_project_snippet', side_effect=old_producer), \
                            patch.object(client, 'request') as http:
                        out = client.analyze(self.rec)
                    http.assert_not_called()
                    self.assertEqual(out['failure_kind'], 'PROMPT_CONTRACT_VIOLATION')
                    self.assertFalse(out['runtime']['request_attempted'])
                    self.save(mode.replace('+', '_') + '-' + contract, out)

    def test_q01_q03_exact_inclusive_quotes_accepted(self):
        for start, end in ((25, 25), (23, 24), (23, 25)):
            with self.subTest(start=start, end=end):
                self.case = f'{start}-{end}'
                out = self.analyze(self.answer(start, end))
                self.assertEqual(out['validated_status'], 'SUPPORTED')
                self.assertTrue(out['citation_provenance']['citation_in_prompt'])
                self.assertFalse(out['citation_provenance']['supports_security_claim_verified'])

    def test_q02_incomplete_reordered_extra_or_trimmed_quotes_rejected(self):
        spans = self.lines[22:25]
        quotes = ['\n'.join(spans[:2]), '\n'.join([spans[0], spans[2]]),
                  '\n'.join(reversed(spans)), '\n'.join(spans + [self.lines[25]]),
                  '\n'.join(spans).lstrip()]
        for i, quote in enumerate(quotes):
            with self.subTest(case=i):
                self.case = i
                out = self.analyze(self.answer(23, 25, quote=quote))
                self.assertEqual(out['validated_status'], 'UNDETERMINED')
                self.assertEqual(out['failure_kind'], 'INVALID_CITATION')
                self.assertFalse(out['runtime']['answer_validated'])

    def test_p05_h01_paths_and_hashes_not_repaired(self):
        for i, changes in enumerate(({'path': self.raw_path}, {'path': 'Other.java'},
                                    {'sha256': '0' * 64},
                                    {'sha256': evidence.digest(b'other source')})):
            with self.subTest(changes=changes):
                self.case = i
                answer = self.answer(**changes)
                before = copy.deepcopy(answer)
                out = self.analyze(answer)
                self.assertEqual(answer, before)
                self.assertEqual(out['validated_status'], 'UNDETERMINED')
                self.assertEqual(out['failure_kind'], 'INVALID_CITATION')

    def test_q04_invalid_ranges_rejected(self):
        for i, (start, end) in enumerate(((25, 23), (True, 25), (0, 25), (999, 999), (1, 153))):
            with self.subTest(start=start, end=end):
                self.case = i
                answer = self.answer(start_line=start, end_line=end)
                out = self.analyze(answer)
                self.assertEqual(out['failure_kind'], 'INVALID_CITATION')

    def test_q05_snapshot_line_absent_from_compacted_prompt_rejected(self):
        self.rec['triage_mode'] = 'llm'
        # Explicit synthetic full-source snapshot, bound to the same real fixture bytes/hash.
        self.rec['snapshots'][self.name]['lines'] = list(self.lines)
        # The finding window [22, 28] excludes this executable line in another method.
        answer = self.answer(19, 19)
        prov = ollama.inspect_citations_provenance(answer['citations'], self.rec)
        self.assertTrue(prov['citation_in_source'])
        self.assertTrue(prov['citation_posthoc_only'])
        out = self.analyze(answer)
        self.assertEqual(out['failure_kind'], 'INVALID_CITATION')


if __name__ == '__main__':
    unittest.main()
