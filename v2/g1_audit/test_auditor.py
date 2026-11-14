"""Synthetic adversarial tests for the independent auditor itself."""
import json
from pathlib import Path
import tempfile
import unittest
from audit import Audit, inside, load, sha


class AuditorChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.audit = Audit(self.root, self.root)

    def write(self, name, value):
        p = self.root / name; p.parent.mkdir(exist_ok=True, parents=True)
        p.write_text(json.dumps(value), encoding='utf-8'); return p

    def test_duplicate_keys_rejected(self):
        p = self.root / 'x.json'; p.write_text('{"status":1,"status":2}')
        with self.assertRaises(ValueError): load(p)

    def test_traversal_rejected(self):
        with self.assertRaises((ValueError, FileNotFoundError)): inside(self.root, '../outside')

    def test_missing_artifact_incomplete(self):
        self.audit.check('manifest', self.audit.manifest)
        self.assertEqual(self.audit.checks[0]['status'], 'INCOMPLETE')

    def test_malformed_artifact_fail(self):
        p = self.root / 'engine'; p.mkdir(); (p/'scan-manifest.json').write_text('{')
        self.audit.check('manifest', self.audit.manifest)
        self.assertEqual(self.audit.checks[0]['status'], 'FAIL')

    def test_empty_sarif_cannot_hide_finding(self):
        self.write('input.opengrep.json', {'results':[dict(check_id='r',path='P.java',start={'line':1},end={'line':1})]})
        self.write('engine/opengrep.sarif', {'runs':[{'results':[]}]})
        with self.assertRaises(ValueError): self.audit.sarif()

    def test_mock_engine_cannot_pass_manifest(self):
        from artifact_fixture import Fixture
        fixture = Fixture(self.root)
        fixture.manifest['runs']['version']['argv'] = ['MOCK_ENGINE','--version']
        fixture.write('engine/version.command.json', ['MOCK_ENGINE','--version']); fixture.rehash()
        self.audit.check('manifest', self.audit.manifest)
        self.assertEqual(self.audit.checks[-1]['status'],'FAIL')

    def test_reencoded_handoff_rejected(self):
        self.write('input.opengrep.json', {'results':[]})
        p = self.root / 'engine'; p.mkdir(); (p/'opengrep.json').write_text('{"results":[]}')
        with self.assertRaises(ValueError): self.audit.identity()

    def test_false_state_is_not_model_status(self):
        from artifact_fixture import Fixture
        fixture = Fixture(self.root)
        fixture.rows[0]['assessment']['status'] = 'CONFIRMED_FALSE'
        fixture.write('assessments.jsonl', b''.join(json.dumps(row).encode()+b'\n' for row in fixture.rows))
        with self.assertRaises(ValueError): self.audit.runtime()


if __name__ == '__main__': unittest.main()
