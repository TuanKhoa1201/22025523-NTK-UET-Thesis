import unittest
import resolve_g0 as r


class ResolutionTests(unittest.TestCase):
    def test_missing_required_checks_cannot_be_conditionally_accepted(self):
        self.assertEqual(r.acceptance({'criteria':{},'register':[]},{'rows_columns_equal':True}),'BLOCKED')

    def test_critical_fail_and_changed_csv_block_acceptance(self):
        keys=('transfer_integrity','scan_development','scan_heldout','scan_manual','owasp_labels_and_sources','heldout_published_comparison','immutability')
        a={'criteria':dict.fromkeys(keys,'PASS'),'register':[]}
        self.assertEqual(r.acceptance(a,{'rows_columns_equal':False}),'BLOCKED')
        a['register']=[{'status':'FAIL','criterion':'scan_heldout','field':'sha256'}]
        self.assertEqual(r.acceptance(a,{'rows_columns_equal':True}),'BLOCKED')

    def test_newline_and_bom_are_not_identical_bytes(self):
        x=r.compare_csv(b'alert_id,x\na,1\n',b'\xef\xbb\xbfalert_id,x\r\na,1\r\n')
        self.assertTrue(x['rows_columns_equal']);self.assertFalse(x['byte_equal'])

    def test_swapped_values_same_total_are_different(self):
        x=r.compare_csv(b'alert_id,x\na,1\nb,2\n',b'alert_id,x\na,2\nb,1\n')
        self.assertFalse(x['rows_columns_equal'])

    def test_order_independent_duplicate_rejected(self):
        self.assertTrue(r.compare_csv(b'alert_id,x\na,1\nb,2\n',b'alert_id,x\nb,2\na,1\n')['rows_columns_equal'])
        with self.assertRaises(ValueError):r.compare_csv(b'alert_id,x\na,1\na,1\n',b'alert_id,x\na,1\n')

    def test_errata_does_not_turn_failure_into_pass(self):
        row={'status':'FAIL'}
        self.assertEqual(r.classify(row)[0],'UNRESOLVED_FAIL');self.assertEqual(row['status'],'FAIL')

    def test_missing_timing_checkpoint_and_prompt_not_excused(self):
        row={'status':'INCOMPLETE','criterion':'heldout_aggregate_comparison','field':'missing_evidence','actual':''}
        self.assertEqual(r.classify(row)[0],'NOT_MEASURED')
        row.update(criterion='old_run',field='checkpoint_absent')
        self.assertEqual(r.classify(row)[0],'INCOMPLETE')
        row.update(actual='Original request absent')
        self.assertEqual(r.classify(row)[0],'PROMPT_NOT_ATTESTED')


if __name__=='__main__':unittest.main()
