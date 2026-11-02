import copy
import unittest
from ntk_scan_aggregates import summarize,METRICS


class WholeScanAggregationTests(unittest.TestCase):
    def test_aggregates_beyond_page_size_without_changing_review(self):
        findings=[{'finding_id':str(i),'decision':'REVIEW','cwe_id':89,
            'cwss':{'cwss_score':float(i),'reference_profile':'GENERAL_JAVA',
                'metric_assessments':{m:{'provenance':{'source':'unit-test'}} for m in METRICS}}} for i in range(60)]
        before=copy.deepcopy(findings);result=summarize(findings)
        self.assertEqual(result['finding_count'],60)
        self.assertEqual(result['decisions'],{'REVIEW':60})
        self.assertEqual(result['cwss_complete_16_metric_provenance_count'],60)
        self.assertEqual(result['cwss_by_profile']['GENERAL_JAVA']['mean'],29.5)
        self.assertEqual(findings,before)

    def test_zero_findings_do_not_create_scores(self):
        result=summarize([])
        self.assertEqual(result['finding_count'],0)
        self.assertEqual(result['cwss_by_profile'],{})
        self.assertEqual(result['top_priority_findings'],[])

    def test_invalid_scores_and_missing_metric_provenance_remain_visible(self):
        result=summarize([{'cwss':{'cwss_score':float('nan')}},{'cwss':{'cwss_score':101}}])
        self.assertEqual(result['cwss_by_profile'],{})
        self.assertEqual(result['cwss_missing_or_incomplete_metric_provenance_count'],2)
