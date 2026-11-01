"""Production decisions and payloads cannot depend on legacy numeric scoring."""
import json
import unittest
from unittest.mock import patch
import ntk_alert_verification as av
import ntk_iris_shared as shared
import test_ast_false_suppression as bridge


class EvidencePolicyTests(unittest.TestCase):
    setUpClass = classmethod(bridge.FalseSuppressionTests.setUpClass.__func__)

    def test_production_never_calls_legacy_scorer_and_preserves_decisions(self):
        bodies = [
            ('String value=request.getParameter("cmd");', 'REPORT'),
            ('String value="fixed";', 'SUPPRESS'),
            ('String value=External.getValue();', 'REVIEW'),
        ]
        for body, expected in bodies:
            source = ('class Example { void run(HttpServletRequest request) throws Exception {\n'
                      + body + '\nRuntime.getRuntime().exec(value);\n}}')
            analysis = av.analyze_java_site_ast_and_taint(source, 'Example.java', 3, 78)
            prediction = shared.parse_and_validate_callee_json(json.dumps({
                **analysis.target_callee_identity, 'type': 'sink', 'sink_args': ['arg0']}),
                expected_identity=analysis.target_callee_identity, cwe=78)
            for base in (0.0, 0.7, 1.0):
                with patch.object(shared, 'evaluate_bounded_safety_floor', side_effect=AssertionError('Legacy scorer called')):
                    result = av.verify_and_triage_finding(
                        'FINDING-POLICY', 78, 'Example.java', 3, 'test', 'ERROR', base,
                        analysis, prediction, legacy_score_compatibility=False).to_dict()
                self.assertEqual(result['decision'], expected)
                self.assertIsNone(result['confidence_score'])
                self.assertIsNone(result['final_heuristic_score'])
                self.assertFalse(result['fusion_score_breakdown']['numeric_score_used_for_decision'])
                self.assertEqual(result['review_status'], 'NOT_REVIEWED')
                self.assertTrue(av.validate_finding_schema_v2_dict(result)[0])

