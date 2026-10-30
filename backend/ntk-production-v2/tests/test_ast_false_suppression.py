"""Real Javac AST regressions, synthetic Java and a validated role stub (no LLM)."""
import functools
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ntk_alert_verification as av
import ntk_iris_shared as shared


class FalseSuppressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        java, javac = shutil.which('java'), shutil.which('javac')
        if not java or not javac:
            raise unittest.SkipTest('A full JDK is required for AST regression tests')
        tmp = tempfile.TemporaryDirectory(prefix='ntk_ast_regression_')
        cls.addClassCleanup(tmp.cleanup)
        bridge = Path(tmp.name)
        subprocess.run([javac, '--release', '17', '-d', str(bridge),
                        str(av.JAVAC_BRIDGE_JAVA)], check=True, capture_output=True)
        original_parse = av.parse_java_source_with_javac_ast
        for ctx in (
            patch.object(av, 'JAVAC_BRIDGE_DIR', bridge),
            patch.object(av, 'JAVAC_BRIDGE_CLASS', bridge / 'NtkJavacAstExtractor.class'),
            patch.object(av, '_JAVAC_AST_CACHE', {}),
            patch.object(av, 'parse_java_source_with_javac_ast',
                         functools.partial(original_parse, java_bin=java, javac_bin=javac)),
        ):
            ctx.start()
            cls.addClassCleanup(ctx.stop)

    def decision(self, body, helpers=''):
        source = ('class Example {\n void run(HttpServletRequest request) throws Exception {\n'
                  + body + '\n }\n' + helpers + '\n}\n')
        line = next(i for i, s in enumerate(source.splitlines(), 1) if '// SINK' in s)
        analysis = av.analyze_java_site_ast_and_taint(source, 'Example.java', line, 78)
        self.assertEqual(analysis.ast_parser_engine, 'OPENJDK17_JAVAC_TASK_AST')
        pred = shared.parse_and_validate_callee_json(json.dumps({
            **analysis.target_callee_identity, 'type': 'sink', 'sink_args': ['arg0']}),
            expected_identity=analysis.target_callee_identity, cwe=78)
        self.assertTrue(pred.strict_valid, pred.abstain_reason)
        result = av.verify_and_triage_finding('synthetic', 78, 'Example.java', line,
                                            'synthetic.exec', 'ERROR', .7, analysis, pred)
        return result.decision

    def test_helper_reads_request_field(self):
        self.assertEqual(self.decision(''' input = request;
 String value = this.getTheValue();
 Runtime.getRuntime().exec(value); // SINK''', ''' HttpServletRequest input;
 String getTheValue() { return input.getParameter("cmd"); }'''), 'REVIEW')

    def test_missing_helper_source(self):
        self.assertEqual(self.decision(''' String value = External.getTheValue();
 Runtime.getRuntime().exec(value); // SINK'''), 'REVIEW')

    def test_ambiguous_helper_overload(self):
        self.assertNotEqual(self.decision(''' String value = this.getTheValue(request);
 Runtime.getRuntime().exec(value); // SINK''', '''
 String getTheValue(Object input) { return "echo fixed"; }
 String getTheValue(HttpServletRequest input) { return input.getParameter("cmd"); }'''), 'SUPPRESS')

    def test_proven_helper_constant_independent_of_name(self):
        for name in ('getTheValue', 'fixedValue'):
            with self.subTest(name=name):
                self.assertEqual(self.decision(f''' String value = this.{name}();
 Runtime.getRuntime().exec(value); // SINK''',
                    f' String {name}() {{ return "echo fixed"; }}'), 'SUPPRESS')

    def test_array_writes_cannot_release_constant_proof(self):
        for mutation in ('args[2] = request.getParameter("cmd");',
                         'args[index] = request.getParameter("cmd");',
                         'args[2] += request.getParameter("cmd");',
                         'if (request != null) { args[2] = request.getParameter("cmd"); }',
                         'String[] alias = args; alias[2] = request.getParameter("cmd");',
                         'String[] alias = args; String[] other = alias; other[2] = request.getParameter("cmd");',
                         'java.util.Arrays.fill(args, request.getParameter("cmd"));',
                         'Object saved = new Holder(args); External.mutate(saved);',
                         'this.saved = args; External.mutate(this);',
                         'External.mutate(args);'):
            with self.subTest(mutation=mutation):
                self.assertEqual(self.decision(''' int index = 2;
 String[] args = new String[]{"sh", "-c", "echo fixed"};
 ''' + mutation + '''
 Runtime.getRuntime().exec(args); // SINK'''), 'REVIEW')

    def test_helper_returning_array_does_not_hide_mutation(self):
        self.assertNotEqual(self.decision('''
 String[] args = new String[]{"sh", "-c", "echo fixed"};
 String[] copy = forward(args);
 args[2] = request.getParameter("cmd");
 Runtime.getRuntime().exec(copy); // SINK''',
            ' String[] forward(String[] value) { return value; }'), 'SUPPRESS')

    def test_write_after_array_alias_snapshot(self):
        self.assertNotEqual(self.decision('''
 String[] args = new String[]{"sh", "-c", "echo fixed"};
 String[] copy = args;
 args[2] = request.getParameter("cmd");
 Runtime.getRuntime().exec(copy); // SINK'''), 'SUPPRESS')

    def test_inferred_array_type_with_helper_initializer(self):
        for mutation in ('args[0] = request.getParameter("cmd");', 'External.mutate(args);'):
            with self.subTest(mutation=mutation):
                self.assertEqual(self.decision('''
 var args = fixedArray();
 ''' + mutation + '''
 Runtime.getRuntime().exec(args); // SINK''',
                    ' String[] fixedArray() { return new String[]{"echo fixed"}; }'), 'REVIEW')

    def test_sanitizer_in_old_initializer_cannot_release_mutated_array(self):
        self.assertEqual(self.decision('''
 String[] args = new String[]{ESAPI.encoder().encodeForOS(new UnixCodec(), "echo fixed")};
 args[0] = request.getParameter("cmd");
 Runtime.getRuntime().exec(args); // SINK'''), 'REVIEW')

    def test_constant_array_without_mutation(self):
        self.assertEqual(self.decision(''' String[] args = new String[]{"echo", "fixed"};
 Runtime.getRuntime().exec(args); // SINK'''), 'SUPPRESS')

    def test_unrelated_array_write_preserves_constant_proof(self):
        self.assertEqual(self.decision(''' String[] args = new String[]{"echo", "fixed"};
 String[] other = new String[]{"unused"};
 other[0] = request.getParameter("cmd");
 Runtime.getRuntime().exec(args); // SINK'''), 'SUPPRESS')

    def test_mutation_after_sink_does_not_invalidate_prior_proof(self):
        self.assertEqual(self.decision(''' String[] args = new String[]{"echo", "fixed"};
 Runtime.getRuntime().exec(args); // SINK
 args[0] = request.getParameter("cmd");'''), 'SUPPRESS')

    def test_tainted_array_initializer_retains_alert(self):
        self.assertEqual(self.decision(''' String[] args = new String[]{"sh", "-c", request.getParameter("cmd")};
 Runtime.getRuntime().exec(args); // SINK'''), 'REPORT')

    def test_direct_flow_and_literal_controls(self):
        self.assertEqual(self.decision(''' String value = request.getParameter("cmd");
 Runtime.getRuntime().exec(value); // SINK'''), 'REPORT')
        self.assertEqual(self.decision(''' Runtime.getRuntime().exec("echo fixed"); // SINK'''), 'SUPPRESS')
