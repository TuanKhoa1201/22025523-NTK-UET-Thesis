"""A declared Java inventory must survive scanner default ignore policies."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ntk_web_backend_service as service


class OpenGrepInventoryCoverageTests(unittest.TestCase):
    def test_real_scanner_includes_java_in_test_directory_and_respects_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            safe=root/'src/main/java/Plain.java';safe.parent.mkdir(parents=True)
            safe.write_text('class Plain { int value(){return 1;} }')
            sink=root/'src/test/java/CommandTest.java';sink.parent.mkdir(parents=True)
            sink.write_text('class CommandTest { void run() throws Exception {\n'
                            'Runtime.getRuntime().exec("fixed command");\n}}')
            cfg=service.NtkWebBackendConfig(javac_bin='/usr/lib/jvm/java-17-openjdk-amd64/bin/javac')
            raw={}
            def local_contract(cwe, identity):
                return json.dumps({**identity,'type':'sink','sink_args':['arg0']}),0.1
            result=service.scan_java_sources_and_triage(root,config=cfg,compile_check=False,
                raw_opengrep_sink=raw,custom_llm_callable=local_contract)
            self.assertEqual(result['status'],'OK')
            self.assertEqual(result['opengrep_candidate_count'],1)
            self.assertEqual(result['coverage_diagnostics']['opengrep_java_files_scanned'],2)
            self.assertEqual(len(raw['results']),1)
            self.assertTrue(raw['results'][0]['path'].endswith('src/test/java/CommandTest.java'))
            with patch.object(service,'run_llm_inference_for_identities',side_effect=AssertionError('Unexpected inference')):
                filtered=service.scan_java_sources_and_triage(root,config=cfg,compile_check=False,
                    file_allowlist=['src/main/java/Plain.java'])
            self.assertEqual(filtered['status'],'OK')
            self.assertEqual(filtered['opengrep_candidate_count'],0)
            self.assertEqual(filtered['coverage_diagnostics']['opengrep_java_files_scanned'],1)
