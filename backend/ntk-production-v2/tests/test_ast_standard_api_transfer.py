"""Standard API transfers require identity, overload and source provenance."""
import unittest
import test_ast_evidence_states as evidence


class StandardApiTransferTests(unittest.TestCase):
    setUpClass = classmethod(evidence.EvidenceStateTests.setUpClass.__func__)
    analyze = evidence.EvidenceStateTests.analyze
    check = evidence.EvidenceStateTests.check

    def test_url_decode_real_sources_and_overloads(self):
        for api, imports in [('java.net.URLDecoder', ''), ('URLDecoder', 'import java.net.URLDecoder;\n')]:
            for enc in ('"UTF-8"', 'java.nio.charset.StandardCharsets.UTF_8'):
                with self.subTest(api=api, enc=enc):
                    a, r = self.check('REPORT', f'''String param = request.getParameter("cmd");
 String value = {api}.decode(param, {enc});
 Runtime.getRuntime().exec(value); // SINK''', imports=imports)
                    self.assertEqual(a.sanitizer_status, 'NONE_DETECTED')
                    self.assertFalse(r.iris_evidence['explicit_ast_release_verified'])
                    self.assertTrue(any('API_TAINT_TRANSFER:java.net.URLDecoder::' in s for s in a.taint_trace_steps))

    def test_decode_inline_header_to_sql(self):
        self.check('REPORT', '''String sql = java.net.URLDecoder.decode(request.getHeader("query"), "UTF-8");
 Statement st = conn.createStatement();
 st.executeQuery(sql); // SINK''', cwe=89)

    def test_decode_constant_input_and_literal_control(self):
        self.check('SUPPRESS', '''String value = java.net.URLDecoder.decode("echo+fixed", "UTF-8");
 Runtime.getRuntime().exec(value); // SINK''')
        self.check('SUPPRESS', 'Runtime.getRuntime().exec("echo fixed"); // SINK')

    def test_decode_unknown_input_remains_unknown(self):
        self.check('REVIEW', '''String param = External.value(request);
 String value = java.net.URLDecoder.decode(param, "UTF-8");
 Runtime.getRuntime().exec(value); // SINK''')

    def test_decode_unverified_signature_remains_unknown(self):
        for expr in ('java.net.URLDecoder.decode(request, "UTF-8")',
                     'java.net.URLDecoder.decode(request.getParameter("cmd"), 42)',
                     'URLDecoder.decode(request.getParameter("cmd"), "UTF-8")'):
            self.check('REVIEW', f'Runtime.getRuntime().exec({expr}); // SINK')

    def test_custom_decode_is_not_standard_api(self):
        for expr in ('External.decode(request.getParameter("cmd"), "UTF-8")',
                     'decoder.decode(request.getParameter("cmd"), "UTF-8")'):
            self.check('REVIEW', f'''Missing decoder = new Missing(request);
 Runtime.getRuntime().exec({expr}); // SINK''')

    def test_import_shadow_does_not_select_jdk_model(self):
        self.check('REVIEW', '''Missing URLDecoder = new Missing(request);
 Runtime.getRuntime().exec(URLDecoder.decode(request.getParameter("cmd"), "UTF-8")); // SINK''',
                   imports='import java.net.URLDecoder;\n')

    def test_header_enumeration_provenance_and_decode(self):
        for decl in ('java.util.Enumeration<String>', 'var'):
            self.check('REPORT', f'''{decl} values = request.getHeaders("cmd");
 String param = values.nextElement();
 String value = java.net.URLDecoder.decode(param, "UTF-8");
 Runtime.getRuntime().exec(value); // SINK''')

    def test_header_enumeration_alias_and_inline(self):
        self.check('REPORT', '''java.util.Enumeration<String> values = request.getHeaders("cmd");
 java.util.Enumeration<String> alias = values;
 Runtime.getRuntime().exec(alias.nextElement()); // SINK''')
        self.check('REPORT', 'Runtime.getRuntime().exec(request.getHeaders("cmd").nextElement()); // SINK')

    def test_custom_and_unknown_next_element(self):
        for init in ('External.headers(request)', 'new Missing(request)'):
            self.check('REVIEW', f'''java.util.Enumeration<String> values = {init};
 Runtime.getRuntime().exec(values.nextElement()); // SINK''')
        self.check('REVIEW', 'Runtime.getRuntime().exec(External.nextElement(request)); // SINK')

    def test_header_enumeration_escape_or_ambiguous_origin(self):
        for mutation in ('External.mutate(values);',
                         'if (External.flag()) { values = External.headers(request); }'):
            self.check('REVIEW', f'''java.util.Enumeration<String> values = request.getHeaders("cmd");
 {mutation}
 Runtime.getRuntime().exec(values.nextElement()); // SINK''')

    def test_custom_source_getheaders_is_not_servlet_provenance(self):
        self.check('REVIEW', '''Missing source = new Missing(request);
 java.util.Enumeration<String> values = source.getHeaders("cmd");
 Runtime.getRuntime().exec(values.nextElement()); // SINK''')

    def test_decoded_literal_value_is_the_proof_value(self):
        a, _ = self.check('SUPPRESS', '''String value = java.net.URLDecoder.decode("echo+fixed", "UTF-8");
 Runtime.getRuntime().exec(value); // SINK''')
        self.assertEqual(a.ast_evidence.ast_proof_node, 'LITERAL:echo fixed')

    def test_unknown_encoding_does_not_release_constant(self):
        self.check('REVIEW', '''String encoding = External.encoding(request);
 String value = java.net.URLDecoder.decode("echo+fixed", encoding);
 Runtime.getRuntime().exec(value); // SINK''')

    def test_custom_charset_is_not_jdk_overload(self):
        self.check('REVIEW', '''Charset encoding = new Charset();
 String value = java.net.URLDecoder.decode(request.getParameter("cmd"), encoding);
 Runtime.getRuntime().exec(value); // SINK''')

    def test_header_enumeration_field_and_constructor_escape(self):
        for escape in ('this.saved = values;', 'Object holder = new Holder(values);'):
            self.check('REVIEW', f'''java.util.Enumeration<String> values = request.getHeaders("cmd");
 {escape}
 Runtime.getRuntime().exec(values.nextElement()); // SINK''')
