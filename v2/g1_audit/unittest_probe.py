"""Structured unittest subprocess receipt; test results never inferred from prose."""
import argparse
import json
from pathlib import Path
import sys
import unittest


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}

    def addSuccess(self, test):
        super().addSuccess(test); self.outcomes.setdefault(test.id(), 'PASS')

    def addFailure(self, test, err):
        super().addFailure(test, err); self.outcomes[test.id()] = 'FAIL'

    def addError(self, test, err):
        super().addError(test, err); self.outcomes[test.id()] = 'ERROR'

    def addSkip(self, test, reason):
        super().addSkip(test, reason); self.outcomes[test.id()] = 'SKIP'

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err); self.outcomes[test.id()] = 'XFAIL'

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test); self.outcomes[test.id()] = 'XPASS'

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None: self.outcomes[test.id()] = 'FAIL'


def run(start, pattern, receipt):
    sys.path.insert(0, str(Path.cwd()))
    loader = unittest.TestLoader()
    suite = loader.discover(start, pattern=pattern)
    discovered = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    counts = {k:list(result.outcomes.values()).count(k) for k in ('PASS','FAIL','ERROR','SKIP','XFAIL','XPASS')}
    valid = (discovered > 0 and result.testsRun == discovered == sum(counts.values())
             and not loader.errors and result.wasSuccessful())
    payload = dict(schema='ntk-unittest-receipt-1', discovered=discovered, run=result.testsRun,
                   counts=counts, outcomes=result.outcomes, import_errors=len(loader.errors), successful=valid)
    Path(receipt).write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return 0 if valid else 1


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--start', required=True); p.add_argument('--pattern', required=True); p.add_argument('--receipt', required=True)
    a = p.parse_args(); raise SystemExit(run(a.start, a.pattern, a.receipt))
