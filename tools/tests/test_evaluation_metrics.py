"""Check declared REVIEW conventions independently of scanner outputs."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evaluate_benchmark import metrics


class EvaluationMetricsTests(unittest.TestCase):
    def test_review_conventions_and_nonzero_confusion_cells(self):
        result=metrics([True,False,False,True,True,False],
                       ['POSITIVE','POSITIVE','NEGATIVE','NEGATIVE','REVIEW','REVIEW'])
        self.assertAlmostEqual(result['review_rate'],1/3)
        self.assertAlmostEqual(result['automatic_decision_coverage'],2/3)
        for policy,expected in [('selective_decided_only',(1,1,1,1)),
                                ('report_only_review_as_negative',(1,1,2,2)),
                                ('retain_review_as_positive',(2,2,1,1))]:
            row=result[policy]
            self.assertEqual(tuple(row[k] for k in ['TP','FP','TN','FN']),expected)
        self.assertAlmostEqual(result['report_only_review_as_negative']['F1'],.4)

    def test_undefined_precision_and_decided_metrics_are_not_fabricated(self):
        result=metrics([True,False],['REVIEW','REVIEW'])
        self.assertEqual(result['automatic_decision_coverage'],0)
        for key in ['precision','recall','FPR','F1']:
            self.assertIsNone(result['selective_decided_only'][key])


if __name__=='__main__':unittest.main()
