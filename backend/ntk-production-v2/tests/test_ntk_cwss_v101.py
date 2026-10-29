"""CWSS 1.0.1 exact MITRE calculation examples + strict evidence safety tests."""
import unittest
from ntk_cwss_v101 import score_codes, score_finding, default_metric_codes, recommend_finding_confidence


class CwssMITRETests(unittest.TestCase):
    def test_mitre_business_critical_example_92_point_6(self):
        codes = {
            'TI':'H', 'AP':'A', 'AL':'A', 'IC':'N', 'FC':'T',
            'RP':'L', 'RL':'A', 'AV':'I', 'AS':'N', 'IN':'T', 'SC':'A',
            'BI':'C', 'DI':'H', 'EX':'H', 'EC':'N', 'P':'NA',
        }
        r=score_codes(codes, fill_unknown=False)
        self.assertAlmostEqual(r['base_finding_subscore'],96.0)
        self.assertAlmostEqual(r['attack_surface_subscore'],.965)
        self.assertAlmostEqual(r['environment_subscore'],1.0)
        self.assertEqual(r['cwss_score'],92.6)

    def test_mitre_wiki_example_51_point_1(self):
        codes = {
            'TI':'M', 'AP':'A', 'AL':'A', 'IC':'N', 'FC':'T',
            'RP':'RU', 'RL':'A', 'AV':'I', 'AS':'W', 'IN':'A', 'SC':'NA',
            'BI':'L', 'DI':'NA', 'EX':'NA', 'EC':'N', 'P':'NA',
        }
        r=score_codes(codes, fill_unknown=False)
        self.assertAlmostEqual(r['base_finding_subscore'],84)
        self.assertAlmostEqual(r['attack_surface_subscore'],.935)
        self.assertAlmostEqual(r['environment_subscore'],.65)
        self.assertEqual(r['cwss_score'],51.1)

    def test_zero_technical_impact_zeros_score(self):
        self.assertEqual(score_codes({'TI':'N'})['cwss_score'],0.0)

    def test_zero_business_impact_zeros_score(self):
        self.assertEqual(score_codes({'BI':'N'})['cwss_score'],0.0)

    def test_complete_internal_control_zeros_score(self):
        self.assertEqual(score_codes({'IC':'C'})['cwss_score'],0.0)

    def test_fc_proven_false_not_equivalent_to_cwss_zero(self):
        # CWSS total cannot be thresholded to determine TP vs FP.
        r=score_codes({'FC':'F'})
        self.assertGreater(r['cwss_score'],0.0)

    def test_missing_context_remains_unknown_not_auto_na(self):
        r=score_codes({})
        self.assertEqual(r['unknown_metric_count'],15)
        self.assertEqual(r['factor_codes']['P'],'NA')
        self.assertEqual(r['factor_codes']['BI'],'UK')
        self.assertEqual(r['factor_codes']['AV'],'U')
        self.assertEqual(r['assessment_status'],'PROVISIONAL_MISSING_CONTEXT')
        self.assertIn('FC:UK,0.5',r['vector'])

    def test_refuse_made_up_factor_codes(self):
        with self.assertRaises(ValueError):
            score_codes({'FC':'0.85'})
        with self.assertRaises(ValueError):
            score_codes({'fake':'H'})

    def test_all_four_cwes_support_independent_context(self):
        for cwe in (22,78,79,89):
            r=score_finding({'cwe':f'CWE-{cwe:03d}', 'decision':'REVIEW'})
            self.assertEqual(r['cwe'],f'CWE-{cwe:03d}')
            self.assertEqual(r['factor_codes']['TI'],'UK')
            self.assertEqual(r['existing_ntk_triage_decision_unchanged'],'REVIEW')

    def test_override_needs_evidence_source(self):
        f={'cwe':'CWE-078'}
        with self.assertRaises(ValueError):
            score_finding(f,metric_overrides={'TI':{'code':'H'}})
        r=score_finding(f,metric_overrides={'TI':{'code':'H','source':'REVIEWED_SOURCE',
                'evidence':'Privilege and technical impact assessed manually'}})
        self.assertEqual(r['factor_codes']['TI'],'H')
        self.assertEqual(r['metric_sources']['TI'],'REVIEWED_SOURCE')

    def test_automatic_taint_is_only_recommendation(self):
        f={'cwe':'CWE-089','decision':'REPORT','review_status':'NOT_REVIEWED',
           'iris_evidence':{'ast_parser_engine':'OPENJDK17_JAVAC_TASK_AST',
                           'source_sink_trace_status':'VERIFIED_TAINT_FLOW',
                           'taint_reaches_sink':True,
                           'taint_trace_steps':['SOURCE_PARAM:q','db.query(q)']},
           'llm_api_role':{'predicted_role':'sink','strict_json_valid':True}}
        r=score_finding(f)
        self.assertEqual(r['fc_recommendation_not_proof']['suggested_code'],'LT')
        self.assertEqual(r['factor_codes']['FC'],'UK')

    def test_manual_tp_still_not_automatically_attacker_reachable(self):
        f={'cwe':'CWE-022','review_status':'CONFIRMED_TRUE_POSITIVE'}
        self.assertEqual(recommend_finding_confidence(f)['suggested_code'],'LT')


if __name__=='__main__':
    unittest.main()
