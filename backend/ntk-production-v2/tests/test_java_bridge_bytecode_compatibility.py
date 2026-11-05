"""Keep NTK Javac AST bridge bytecode executable on Java 17."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import ntk_alert_verification as triage


class Java17BridgeCompatibilityTests(unittest.TestCase):
    def test_stale_jdk21_bytecode_triggers_release17_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'NtkJavacAstExtractor.java'
            source.write_text('public class NtkJavacAstExtractor {}')
            main = root / 'NtkJavacAstExtractor.class'
            inner = root / 'NtkJavacAstExtractor$1MethodBodyVisitor.class'

            def classfile(major):
                return bytes.fromhex('CAFEBABE') + b'\x00\x00' + major.to_bytes(2, 'big') + b'placeholder'

            for dest in (main, inner):
                dest.write_bytes(classfile(65))

            invoked = []
            def fake_compile(cmd, **kwargs):
                invoked.append(cmd)
                for dest in (main,inner):
                    dest.write_bytes(classfile(61))
                return SimpleNamespace(returncode=0,stdout='',stderr='')

            with patch.object(triage, 'JAVAC_BRIDGE_DIR', root), \
                 patch.object(triage, 'JAVAC_BRIDGE_JAVA', source), \
                 patch.object(triage, 'JAVAC_BRIDGE_CLASS', main), \
                 patch.object(triage.subprocess, 'run', side_effect=fake_compile):
                self.assertTrue(triage.ensure_javac_ast_bridge_compiled('/usr/bin/javac'))
                self.assertEqual(len(invoked),1)
                self.assertEqual(invoked[0][1:3],['--release','17'])
                self.assertTrue(triage.ensure_javac_ast_bridge_compiled('/usr/bin/javac'))
                self.assertEqual(len(invoked),1, 'Valid Java17 classes must not be rebuilt')

    def test_compiler_emits_java17_bytecode(self):
        compiler=shutil.which('javac')
        if not compiler:
            self.skipTest('javac not installed')
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            source=directory/'T.java'
            source.write_text('public class T {}')
            proc=subprocess.run([compiler,'--release','17','-d',tmp,str(source)],
                                capture_output=True,text=True,check=False,timeout=30)
            self.assertEqual(proc.returncode,0,proc.stderr)
            header=(directory/'T.class').read_bytes()[:8]
            self.assertEqual(header[:4],bytes.fromhex('CAFEBABE'))
            self.assertEqual(int.from_bytes(header[6:8],'big'),61)

if __name__=='__main__':unittest.main()
