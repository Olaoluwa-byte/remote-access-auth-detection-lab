"""Evaluate fixtures against independent expected results and export SPL inputs."""
import argparse
import hashlib
import json
from pathlib import Path
from .model import evaluate, load_lookups, prepare, read_events, write_csv, write_json


def validate(root, output):
    root, output = Path(root), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    events = read_events(root / 'fixtures/evaluation.jsonl')
    tables = load_lookups(root / 'lookups')
    actual = evaluate(events, tables)
    expected = json.loads((root / 'fixtures/expected.json').read_text())['cases']
    by_id = {r['event_id']:r for r in actual}
    if len({r['event_id'] for r in expected}) != len(expected):
        raise ValueError('duplicate expected ID')
    records = []
    for case in expected:
        wanted = {k:v for k,v in case.items() if k != 'case'}
        got = {k:by_id.get(case['event_id'], {}).get(k) for k in wanted}
        records.append({'case':case['case'], 'expected':wanted, 'actual':got, 'passed':wanted == got})
    passed = all(r['passed'] for r in records) and set(by_id) == {r['event_id'] for r in expected}
    hashes = {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
              for folder in ('fixtures','lookups') for p in sorted((root/folder).glob('*'))}
    report = {'passed':passed, 'total':len(records), 'passed_cases':sum(r['passed'] for r in records),
              'input_records':len(events), 'unique_events':len(actual), 'cases':records,
              'input_sha256':hashes, 'splunk_runtime_verified':False}
    write_json(output / 'acceptance.json', report)
    write_json(output / 'actual.json', actual)
    normalized = prepare(events)
    write_csv(output / 'c07_evaluation.csv', normalized,
              ['event_id','valid','parse_error','event_epoch','event_time','gateway_id','user',
               'src_ip','result','auth_method','mfa_result','mfa_known','mfa_note','session_id','occurrences'])
    write_csv(output / 'c07_expected.csv', expected,
              ['event_id','case','disposition','exception_id','exception_applied','occurrences',
               'baseline_unknown','method_deviation','policy_unknown','policy_violation','mfa_violation','telemetry_unknown','failed_mfa_on_success','mfa_note'])
    print(json.dumps({k:report[k] for k in ('passed','total','passed_cases','input_records','unique_events','splunk_runtime_verified')}, sort_keys=True))
    return passed


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path('.'))
    p.add_argument('--output', type=Path, default=Path('build'))
    a = p.parse_args()
    raise SystemExit(0 if validate(a.root, a.output) else 1)
