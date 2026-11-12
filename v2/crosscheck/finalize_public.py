"""Reproduce the disposition using published receipts; never recompute raw evidence."""
import csv
import json
from pathlib import Path
import resolve_g0 as r

ROOT = Path(__file__).parent


def load(name):
    return json.loads((ROOT/name).read_text(encoding='utf-8'))


def derive():
    raw = load('G0_RAW_INDEPENDENT_VERDICT.json')
    report = load('G0_FINAL_RESOLUTION.json')
    entries = load('G0_ERRATA_REGISTER.json')
    audit = dict(raw, exit_code=raw['automated_audit_exit_code'],
                 limitations_recorded=bool(raw.get('register_counts', {}).get('INCOMPLETE')))
    verdict = r.acceptance(audit, report['paired_comparison'], entries)
    return {'AUDIT_EXECUTION_COMPLETED': r.execution_completed(audit),
            'G0_ACCEPTANCE': verdict,
            'READY_FOR_G1': 'CONDITIONAL' if verdict in ('PASS', 'CONDITIONAL') else 'NO'}


if __name__ == '__main__':
    print(json.dumps(derive(), indent=2))
