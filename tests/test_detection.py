import copy
import csv
import json
import random
import tempfile
import unittest
from pathlib import Path
from c07.generate import generate
from c07.model import (build_baseline, canonical, evaluate, load_lookups, load_table,
                       normalize, parse_time, prepare, read_events)
from c07.validate import validate

ROOT = Path(__file__).resolve().parents[1]


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = read_events(ROOT / 'fixtures/evaluation.jsonl')
        self.training = read_events(ROOT / 'fixtures/training.jsonl')
        self.tables = load_lookups(ROOT / 'lookups')
        self.expected = json.loads((ROOT / 'fixtures/expected.json').read_text())['cases']
        self.actual = {r['event_id']:r for r in evaluate(self.events, self.tables)}

    def test_all_hand_authored_case_expectations(self):
        for expected in self.expected:
            with self.subTest(case=expected['case']):
                got = self.actual[expected['event_id']]
                for key, value in expected.items():
                    if key != 'case':
                        self.assertEqual(got[key], value, key)

    def test_seed_and_reference_are_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp)/'a', Path(tmp)/'b'
            generate(a); generate(b)
            for file in a.rglob('*'):
                if file.is_file():
                    relative = file.relative_to(a)
                    self.assertEqual(file.read_bytes(), (b/relative).read_bytes())
                    self.assertEqual(file.read_bytes(), (ROOT/relative).read_bytes())

    def test_other_seed_and_time_preserve_expected_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            generate(tmp, seed=42, reference='2025-01-01T00:00:00Z')
            self.assertTrue(validate(tmp, Path(tmp)/'output'))

    def test_shuffled_input_same_decisions(self):
        shuffled = copy.deepcopy(self.events)
        random.Random(98).shuffle(shuffled)
        self.assertEqual(evaluate(self.events, self.tables), evaluate(shuffled, self.tables))

    def test_duplicate_collapse_preserves_count(self):
        duplicate = next(c for c in self.expected if c['case']=='exact_duplicate')
        self.assertEqual(self.actual[duplicate['event_id']]['occurrences'], 2)
        self.assertEqual(len(self.actual), len(self.expected))

    def test_conflicting_duplicate_fails_closed(self):
        event = copy.deepcopy(self.training[0]); changed = dict(event, auth_method='local')
        with self.assertRaisesRegex(ValueError, 'conflicting duplicate'):
            prepare([event, changed])

    def test_duplicate_training_does_not_inflate_baseline(self):
        cutoff = '2026-11-12T10:00:00Z'
        self.assertEqual(build_baseline(self.training, cutoff),
                         build_baseline(self.training + self.training, cutoff))

    def test_test_events_cannot_train_baseline(self):
        value = next(e for e in self.events if e.get('auth_method')=='local' and e.get('user')=='alice')
        with self.assertRaises(ValueError):
            build_baseline(self.training + [value], '2026-11-12T10:00:00Z')

    def test_evaluation_never_changes_lookups(self):
        before = {p:p.read_bytes() for p in (ROOT/'lookups').glob('*.csv')}
        snapshot = copy.deepcopy(self.tables)
        evaluate(self.events, self.tables)
        self.assertEqual(self.tables, snapshot)
        self.assertEqual(before, {p:p.read_bytes() for p in before})

    def test_baseline_rebuild_matches_frozen_csv(self):
        rows = build_baseline(self.training, '2026-11-12T10:00:00Z')
        for row in rows:
            saved = self.tables[0][row['gateway_id'], row['user']]
            self.assertEqual({k:str(v) for k,v in row.items()}, saved)

    def test_no_expected_labels_in_event_inputs(self):
        forbidden = {'case','label','attack','expected','disposition','policy_violation'}
        for event in self.events + self.training:
            self.assertFalse(set(event) & forbidden)
        # Generator identities and event IDs do not encode the ground-truth label.
        self.assertTrue(all(e['event_id'].startswith('e') for e in self.events))

    def test_untrusted_extra_field_cannot_override_policy(self):
        event = dict(self.training[0], event_id='injected', require_mfa=0)
        self.assertEqual(evaluate([event], self.tables)[0]['disposition'], 'invalid')

    def test_no_identity_or_event_id_silent_loss(self):
        for ident in (None, '', ['bad'], 'bad|id'):
            with self.subTest(ident=ident), self.assertRaises(ValueError):
                prepare([dict(self.training[0], event_id=ident)])

    def test_invalid_json_and_duplicate_json_keys_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'input.jsonl'
            for text in ('{not json}', '{"event_id":"a","event_id":"b"}'):
                path.write_text(text+'\n')
                with self.assertRaises(ValueError):
                    read_events(path)

    def test_schema_normalization_and_scalar_validation(self):
        for field in ('user','gateway_id','auth_method','result','session_id','event_time','src_ip'):
            with self.subTest(field=field):
                self.assertEqual(normalize(dict(self.training[0], **{field:['value']}))['valid'], 0)

    def test_missing_unknown_mfa_never_passes(self):
        for mfa in (None, '', 'unknown', 'nonsense', True, ['passed']):
            event = dict(self.training[0], event_time='2026-11-12T12:00:00Z', mfa_result=mfa)
            got = evaluate([event], self.tables)[0]
            self.assertEqual(got['mfa_violation'], 1)
            self.assertEqual(got['telemetry_unknown'], 1)
            self.assertEqual(got['disposition'], 'alert')

    def test_unknown_baseline_does_not_disable_policy(self):
        tables = ({}, self.tables[1], {})
        event = dict(self.training[0], event_time='2026-11-12T12:00:00Z', auth_method='local')
        got = evaluate([event], tables)[0]
        self.assertEqual(got['baseline_unknown'], 1)
        self.assertEqual(got['policy_violation'], 1)
        self.assertEqual(got['disposition'], 'alert')

    def test_exception_cannot_hide_unknown_mfa(self):
        event = dict(self.training[0], user='carol', auth_method='local',
                     mfa_result='unknown', event_time='2026-11-12T12:00:00Z')
        got = evaluate([event], self.tables)[0]
        self.assertEqual(got['exception_applied'], 1)
        self.assertEqual(got['disposition'], 'alert')

    def test_lookup_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'lookup.csv'
            path.write_text('gateway_id,user\ngw-east,alice\ngw-east,alice\n')
            with self.assertRaisesRegex(ValueError, 'duplicate lookup'):
                load_table(path, ('gateway_id','user'))

    def test_strict_utc_timestamp_contract(self):
        for value in ('2026-02-30T00:00:00Z','2026-01-01T00:00:00',
                      '2026-01-01T00:00:00+00:00','2026-01-01T00:00:00.5Z', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_time(value)

    def test_export_does_not_leak_ground_truth_into_spl_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(validate(ROOT, tmp))
            with (Path(tmp)/'c07_evaluation.csv').open() as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), len(self.expected))
            self.assertFalse({'case','disposition','expected','policy_violation'} & set(rows[0]))
            self.assertTrue((Path(tmp)/'c07_expected.csv').exists())


    def test_failed_mfa_success_cannot_be_waived(self):
        for user, gateway, method in [('carol','gw-east','local'),
                                      ('new-user','gw-east','saml'),
                                      ('alice','gw-west','local')]:
            event = dict(self.training[0], user=user, gateway_id=gateway,
                         auth_method=method, mfa_result='failed',
                         event_time='2026-11-12T12:00:00Z')
            got = evaluate([event], self.tables)[0]
            self.assertEqual(got['failed_mfa_on_success'], 1)
            self.assertEqual(got['disposition'], 'alert')
            got = evaluate([dict(event, result='failure')], self.tables)[0]
            self.assertEqual(got['failed_mfa_on_success'], 0)
            self.assertEqual(got['disposition'], 'failed_login')

    def test_training_rejects_failed_mfa_success(self):
        event = dict(self.training[0], mfa_result='failed')
        with self.assertRaisesRegex(ValueError, 'failed MFA'):
            build_baseline([event], '2026-11-12T10:00:00Z')
        self.assertEqual(build_baseline([dict(event, result='failure')],
                                       '2026-11-12T10:00:00Z'), [])
        self.assertEqual(len(build_baseline([dict(event, mfa_result='not_performed')],
                                           '2026-11-12T10:00:00Z')), 1)

    def test_unicode_rejected_before_normalization(self):
        for field, value in [('user','\u212aate'), ('user','\u00a0alice'),
                             ('gateway_id','gw-east\u00a0'),
                             ('auth_method','saml\u00a0'), ('result','success\u00a0')]:
            with self.subTest(field=field):
                self.assertEqual(normalize(dict(self.training[0], **{field:value}))['valid'], 0)
        for digits in ('０１２３４５６７８９','٠١٢٣٤٥٦٧٨٩'):
            value = '2026-11-12T12:00:00Z'.translate(str.maketrans('0123456789', digits))
            with self.assertRaises(ValueError):
                parse_time(value)

    def test_mfa_notes_are_bounded_and_distinguishable(self):
        for value, note in [('passed','none'), ('unknown','explicit_unknown'),
                            ('bypassed','unsupported'), (None,'wrong_type'),
                            (['passed'],'wrong_type'), ('','unsupported')]:
            got = normalize(dict(self.training[0], mfa_result=value))
            self.assertEqual(got['mfa_note'], note)
        event = dict(self.training[0]); del event['mfa_result']
        self.assertEqual(normalize(event)['mfa_note'], 'missing')

    def test_lookup_threshold_controls_evaluation(self):
        tables = copy.deepcopy(self.tables)
        tables[0]['gw-east','alice']['minimum_samples'] = '4'
        event = dict(self.training[0], event_time='2026-11-12T12:00:00Z')
        self.assertEqual(evaluate([event], tables)[0]['baseline_unknown'], 1)
        tables[0]['gw-east','alice']['minimum_samples'] = '3'
        self.assertEqual(evaluate([event], tables)[0]['baseline_unknown'], 0)

    def test_independent_baseline_oracle(self):
        # Literal expected training summary; not derived by build_baseline.
        expected = {('gw-east','alice'):('3','saml'), ('gw-east','bob'):('3','saml'),
                    ('gw-east','carol'):('3','saml'), ('gw-east','dave'):('3','local'),
                    ('gw-east','no-policy'):('3','saml'), ('gw-east','sparse'):('1','saml'),
                    ('gw-west','alice'):('3','local')}
        self.assertEqual(set(self.tables[0]), set(expected))
        for key, (count, methods) in expected.items():
            row = self.tables[0][key]
            self.assertEqual((row['sample_count'], row['observed_methods']), (count, methods))
            self.assertEqual(row['minimum_samples'], '3')
            self.assertEqual(row['baseline_cutoff_epoch'], '1794477600')


if __name__ == '__main__':
    unittest.main()
