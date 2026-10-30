"""Synthetic Java AST/triage regressions; no dataset, model, or ground truth names."""
import json
import tempfile
import unittest
from pathlib import Path

import test_ast_false_suppression as regression
import ntk_alert_verification as av
import ntk_iris_shared as shared


class EvidenceStateTests(unittest.TestCase):
    setUpClass = classmethod(regression.FalseSuppressionTests.setUpClass.__func__)

    def analyze(self, body, helpers='', cwe=78, files=None, imports=''):
        source = (imports + 'class Example {\n void run(HttpServletRequest request) throws Exception {\n'
                  + body + '\n }\n}\n' + helpers + '\n')
        line = next(i for i, s in enumerate(source.splitlines(), 1) if '// SINK' in s)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'Example.java'
            path.write_text(source)
            for name, text in (files or {}).items():
                helper_path = Path(tmp) / name
                helper_path.parent.mkdir(parents=True, exist_ok=True)
                helper_path.write_text(text)
            analysis = av.analyze_java_site_ast_and_taint(source, str(path), line, cwe)
        args = ['arg0'] if shared.extract_formal_params_from_signature(
            analysis.target_callee_identity['signature']) else ['this']
        pred = shared.parse_and_validate_callee_json(json.dumps({
            **analysis.target_callee_identity, 'type': 'sink', 'sink_args': args}),
            expected_identity=analysis.target_callee_identity, cwe=cwe)
        self.assertTrue(pred.strict_valid, pred.abstain_reason)
        result = av.verify_and_triage_finding('synthetic', cwe, str(path), line,
                                             'synthetic', 'ERROR', .7, analysis, pred)
        return analysis, result

    def check(self, decision, *args, **kwargs):
        analysis, result = self.analyze(*args, **kwargs)
        self.assertEqual(result.decision, decision, analysis)
        self.assertEqual(analysis.flow_proof_state, {
            'REVIEW': 'UNKNOWN', 'REPORT': 'PROVEN_TAINT', 'SUPPRESS': 'PROVEN_SAFE'}[decision])
        self.assertEqual(result.iris_evidence['flow_proof_state'], analysis.flow_proof_state)
        if decision == 'REVIEW':
            self.assertFalse(analysis.taint_reaches_sink)
            self.assertNotEqual(analysis.source_sink_trace_status, 'VERIFIED_TAINT_FLOW')
            self.assertFalse(result.iris_evidence['explicit_ast_release_verified'])
        if decision == 'REPORT':
            self.assertTrue(analysis.taint_reaches_sink)
        return analysis, result

    def test_missing_helper_with_request_is_unknown(self):
        self.check('REVIEW', '''String value = External.value(request);
 Runtime.getRuntime().exec(value); // SINK''')

    def test_unknown_outer_call_does_not_inherit_nested_source(self):
        self.check('REVIEW', '''String value = External.value(request.getParameter("cmd"));
 Runtime.getRuntime().exec(value); // SINK''')

    def test_constructor_request_is_not_helper_return_taint(self):
        self.check('REVIEW', '''String value = new Missing(request).value();
 ProcessBuilder pb = new ProcessBuilder(value);
 pb.start(); // SINK''')

    def test_cross_class_return_evidence(self):
        for ret, expected in [('"echo fixed"', 'SUPPRESS'),
                              ('input.getParameter("cmd")', 'REPORT'),
                              ('External.value(input)', 'REVIEW')]:
            with self.subTest(ret=ret):
                self.check(expected, '''Helper h = new Helper();
 String value = h.value(request);
 Runtime.getRuntime().exec(value); // SINK''',
                           'class Helper { String value(HttpServletRequest input) { return ' + ret + '; } }')

    def test_cross_file_source_resolution(self):
        for ret, expected in [('"echo fixed"', 'SUPPRESS'),
                              ('input.getParameter("cmd")', 'REPORT')]:
            with self.subTest(ret=ret):
                self.check(expected, '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(request)); // SINK''', files={
                    'Helper.java': 'class Helper { String value(HttpServletRequest input) { return ' + ret + '; } }'})

    def test_receiver_constructor_state_is_unknown(self):
        self.check('REVIEW', '''Helper h = new Helper(request);
 Runtime.getRuntime().exec(h.value()); // SINK''', '''class Helper {
 HttpServletRequest saved;
 Helper(HttpServletRequest input) { saved = input; }
 String value() { return saved.getParameter("cmd"); }
}''')

    def test_constant_return_ignores_constructor_input(self):
        self.check('SUPPRESS', '''Helper h = new Helper(request);
 Runtime.getRuntime().exec(h.value()); // SINK''', '''class Helper {
 Helper(HttpServletRequest input) {}
 String value() { return "echo fixed"; }
}''')

    def test_ambiguous_overloads_are_unknown(self):
        self.check('REVIEW', '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(request)); // SINK''', '''class Helper {
 String value(Object input) { return "echo fixed"; }
 String value(HttpServletRequest input) { return input.getParameter("cmd"); }
}''')

    def test_arity_distinguishes_helpers(self):
        helper = '''class Helper {
 String value() { return "echo fixed"; }
 String value(HttpServletRequest input) { return input.getParameter("cmd"); }
}'''
        for arg, expected in [('', 'SUPPRESS'), ('request', 'REPORT')]:
            self.check(expected, f'''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value({arg})); // SINK''', helper)

    def test_all_return_paths_need_proof(self):
        self.check('REVIEW', '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(request)); // SINK''', '''class Helper {
 String value(HttpServletRequest input) {
 if (input != null) { return "echo fixed"; }
 return External.value(input);
 }
}''')

    def test_branch_taint_does_not_prove_return_path(self):
        self.check('REVIEW', '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(request)); // SINK''', '''class Helper {
 String value(HttpServletRequest input) {
 if (External.flag()) { return input.getParameter("cmd"); }
 return "echo fixed";
 }
}''')

    def test_unknown_array_with_request_cannot_verify(self):
        self.check('REVIEW', '''String[] args = new String[]{External.value(request)};
 External.mutate(args);
 ProcessBuilder pb = new ProcessBuilder(args);
 pb.start(); // SINK''')

    def test_unknown_mutation_cannot_prove_or_release(self):
        self.check('REVIEW', '''String[] args = new String[]{request.getParameter("cmd")};
 External.mutate(args);
 Runtime.getRuntime().exec(args); // SINK''')

    def test_real_array_initializer_taint_still_reports(self):
        self.check('REPORT', '''String[] args = new String[]{"sh", "-c", request.getParameter("cmd")};
 Runtime.getRuntime().exec(args); // SINK''')

    def test_independent_taint_survives_unknown_concat_operand(self):
        self.check('REPORT', '''String value = request.getParameter("cmd") + External.value(request);
 Runtime.getRuntime().exec(value); // SINK''')

    def test_prepared_noarg_identity_and_receiver_coverage(self):
        for sql, expected in [('"select 1"', 'SUPPRESS'),
                              ('request.getParameter("sql")', 'REPORT'),
                              ('External.value(request)', 'REVIEW')]:
            with self.subTest(sql=sql):
                a, _ = self.check(expected, f'''PreparedStatement ps = conn.prepareStatement({sql});
 ps.executeQuery(); // SINK''', cwe=89)
                self.assertEqual(a.ast_overloaded_signature, 'ResultSet executeQuery()')
                self.assertEqual(a.target_callee_identity['signature'], a.ast_overloaded_signature)
                self.assertEqual(a.target_callee_identity['class'], 'PreparedStatement')
                if expected == 'SUPPRESS':
                    self.assertEqual(a.ast_evidence.covered_sink_args, ('this',))

    def test_statement_string_and_prepared_string_overloads(self):
        for typ in ('Statement', 'PreparedStatement'):
            a, _ = self.check('REPORT', f'''{typ} ps = conn.createStatement();
 ps.executeQuery(request.getParameter("sql")); // SINK''', cwe=89)
            self.assertEqual(a.target_callee_identity['signature'], 'ResultSet executeQuery(String sql)')

    def test_unresolved_noarg_receiver_cannot_release(self):
        self.check('REVIEW', '''PreparedStatement ps = External.statement(request);
 ps.executeQuery(); // SINK''', cwe=89)

    def test_prepared_branch_templates_need_receiver_proof(self):
        self.check('REVIEW', '''PreparedStatement ps = conn.prepareStatement("select 1");
 if (External.flag()) { ps = conn.prepareStatement(request.getParameter("sql")); }
 ps.executeQuery(); // SINK''', cwe=89)

    def test_prepared_alias_uses_receiver_state(self):
        self.check('REPORT', '''PreparedStatement ps = conn.prepareStatement(request.getParameter("sql"));
 PreparedStatement alias = ps;
 alias.executeQuery(); // SINK''', cwe=89)

    def test_transform_name_is_not_a_helper_contract(self):
        for expr in ('External.trim(request)', 'External.get(request)',
                     'External.value(request).trim()', 'new Missing(request).toString()'):
            with self.subTest(expr=expr):
                self.check('REVIEW', f'''String value = {expr};
 Runtime.getRuntime().exec(value); // SINK''')

    def test_nested_sanitizer_in_unknown_call_cannot_release(self):
        self.check('REVIEW', '''String value = External.value(
 ESAPI.encoder().encodeForOS(new UnixCodec(), request.getParameter("cmd")));
 Runtime.getRuntime().exec(value); // SINK''')

    def test_independent_taint_with_unknown_sanitized_operand_reports(self):
        self.check('REPORT', '''String value = request.getParameter("cmd") + External.value(
 ESAPI.encoder().encodeForOS(new UnixCodec(), request.getParameter("other")));
 Runtime.getRuntime().exec(value); // SINK''')

    def test_known_string_transforms_preserve_taint(self):
        self.check('REPORT', '''String value = request.getParameter("cmd").trim();
 Runtime.getRuntime().exec(value); // SINK''')

    def test_helper_must_not_release_unknown_parameter(self):
        self.check('REVIEW', '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(External.value(request))); // SINK''',
                   'class Helper { String value(String input) { return input; } }')

    def test_sql_method_return_types_and_noarg_coverage(self):
        for method, ret in [('executeUpdate', 'int'), ('execute', 'boolean'), ('addBatch', 'void')]:
            with self.subTest(method=method):
                a, _ = self.check('REPORT', f'''PreparedStatement ps = conn.prepareStatement(request.getParameter("sql"));
 ps.{method}(); // SINK''', cwe=89)
                self.assertEqual(a.target_callee_identity['method'], method)
                self.assertEqual(a.target_callee_identity['signature'], f'{ret} {method}()')
                self.assertEqual(a.ast_evidence.covered_sink_args, ('this',))

    def test_prepared_receiver_snapshot_precedes_sql_reassignment(self):
        self.check('REPORT', '''String sql = request.getParameter("sql");
 PreparedStatement ps = conn.prepareStatement(sql);
 sql = "select 1";
 ps.executeQuery(); // SINK''', cwe=89)

    def test_prepared_alias_snapshot_precedes_receiver_reassignment(self):
        self.check('REPORT', '''PreparedStatement ps = conn.prepareStatement(request.getParameter("sql"));
 PreparedStatement alias = ps;
 ps = conn.prepareStatement("select 1");
 alias.executeQuery(); // SINK''', cwe=89)

    def test_prepared_receiver_escape_through_alias_is_unknown(self):
        self.check('REVIEW', '''PreparedStatement ps = conn.prepareStatement("select 1");
 PreparedStatement alias = ps;
 External.mutate(alias);
 ps.executeQuery(); // SINK''', cwe=89)

    def test_missing_sink_slot_coverage_cannot_report_or_suppress(self):
        from dataclasses import replace
        a, _ = self.analyze('Runtime.getRuntime().exec(request.getParameter("cmd")); // SINK')
        a = replace(a, ast_evidence=shared.AstReleaseEvidence(ast_parser_engine=a.ast_parser_engine))
        pred = shared.parse_and_validate_callee_json(json.dumps({
            **a.target_callee_identity, 'type': 'sink', 'sink_args': ['arg0']}),
            expected_identity=a.target_callee_identity, cwe=78)
        r = av.verify_and_triage_finding('synthetic', 78, 'Example.java', 3, 'synthetic', 'ERROR', .7, a, pred)
        self.assertEqual(r.decision, 'REVIEW')

    def test_helper_dependency_content_and_presence_invalidate_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'Example.java'
            source = 'class Example { Helper h = new Helper(); }'
            path.write_text(source)
            missing = av.java_source_dependency_fingerprint(source, str(path))
            helper = Path(tmp) / 'Helper.java'
            helper.write_text('class Helper { String value() { return "fixed"; } }')
            safe = av.java_source_dependency_fingerprint(source, str(path))
            helper.write_text('class Helper { String value(String input) { return input; } }')
            tainted = av.java_source_dependency_fingerprint(source, str(path))
            self.assertEqual(len({missing, safe, tainted}), 3)

    def test_guarded_only_helper_return_does_not_prove_reachability(self):
        self.check('REVIEW', '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(request)); // SINK''', '''class Helper {
 String value(HttpServletRequest input) {
 if (External.flag()) { return input.getParameter("cmd"); }
 throw new IllegalStateException();
 }
}''')

    def test_array_overload_identity_matches_ast(self):
        a, _ = self.check('REPORT', '''String[] args = new String[]{request.getParameter("cmd")};
 Runtime.getRuntime().exec(args); // SINK''')
        self.assertEqual(a.ast_overloaded_signature, 'Process exec(String[] cmdarray)')
        self.assertEqual(a.target_callee_identity['signature'], a.ast_overloaded_signature)

    def test_unknown_constructor_is_not_value_propagation(self):
        self.check('REVIEW', '''String value = String.valueOf(new Missing(request));
 Runtime.getRuntime().exec(value); // SINK''')

    def test_imported_helper_uses_its_own_source_and_return_path(self):
        for ret, expected in [('"echo fixed"', 'SUPPRESS'),
                              ('input.getParameter("cmd")', 'REPORT'),
                              ('External.value(input)', 'REVIEW')]:
            with self.subTest(ret=ret):
                self.check(expected, '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(request)); // SINK''',
                           imports='import support.Helper;\n', files={
                               'support/Helper.java': 'package support; class Helper { '
                               'String value(HttpServletRequest input) { return ' + ret + '; } }'})

    def test_global_ast_cache_is_not_helper_resolution_evidence(self):
        av.parse_java_source_with_javac_ast(
            'class Helper { String value(HttpServletRequest input) { return "fixed"; } }',
            'unrelated/Helper.java')
        self.check('REVIEW', '''Helper h = new Helper();
 Runtime.getRuntime().exec(h.value(request)); // SINK''')
