"""Deterministic synthetic fixtures; expectations authored separately from evaluator."""
import argparse
import copy
import datetime as dt
import json
import random
from pathlib import Path
from .model import FLAGS, build_baseline, canonical, iso, parse_time, write_csv, write_json

DEFAULT_TIME = '2026-11-12T12:00:00Z'


def generate(destination, seed=7, reference=DEFAULT_TIME):
    root = Path(destination)
    (root / 'fixtures').mkdir(parents=True, exist_ok=True)
    (root / 'lookups').mkdir(parents=True, exist_ok=True)
    now = parse_time(reference)
    epoch = int(now.timestamp())
    rng = random.Random(seed)
    sequence = 0

    def event(user='alice', method='saml', mfa='passed', gateway='gw-east', offset=0):
        nonlocal sequence
        sequence += 1
        return {'schema_version': 1, 'event_id': 'e%04d' % sequence,
                'event_time': iso(now + dt.timedelta(seconds=offset)),
                'gateway_id': gateway, 'user': user, 'auth_method': method,
                'mfa_result': mfa, 'result': 'success',
                'src_ip': '192.0.2.' + str(rng.randint(1, 254)),
                'session_id': 's%04d' % sequence}

    training = []
    for user, method, gateway, count in [
        ('alice', 'saml', 'gw-east', 3), ('bob', 'saml', 'gw-east', 3),
        ('carol', 'saml', 'gw-east', 3), ('dave', 'local', 'gw-east', 3),
        ('sparse', 'saml', 'gw-east', 1), ('alice', 'local', 'gw-west', 3),
        ('no-policy', 'saml', 'gw-east', 3),
    ]:
        for i in range(count):
            training.append(event(user, method, gateway=gateway, offset=-86400-i*60))
    evaluation, expected = [], []

    def case(name, value, disposition, bits=(0, 0, 0, 0, 0, 0), exception='', occurrences=1, failed_mfa=0, note='none'):
        evaluation.append(value)
        expected.append(dict(event_id=value['event_id'], case=name,
                             disposition=disposition, exception_id=exception,
                             exception_applied=int(bool(exception)), occurrences=occurrences,
                             mfa_note=note, failed_mfa_on_success=failed_mfa,
                             **dict(zip(FLAGS[:6], bits))))

    case('normal_saml_mfa', event(), 'normal')
    case('unapproved_local', event(method='local', mfa='not_performed'), 'alert', (0,1,0,1,1,0))
    case('saml_mfa_failed', event(mfa='failed'), 'alert', (0,0,0,0,1,0), failed_mfa=1)
    value = event(); del value['mfa_result']
    case('missing_mfa', value, 'alert', (0,0,0,0,1,1), note='missing')
    case('unknown_mfa', event(mfa='unknown'), 'alert', (0,0,0,0,1,1), note='explicit_unknown')
    value = event(method='local', mfa='failed'); value['result'] = 'failure'
    case('failed_login_out_of_detection_scope', value, 'failed_login')
    case('approved_migration', event(user='bob', method='local'), 'excepted', (0,1,0,1,0,0), 'migration-1')
    case('break_glass', event(user='carol', method='local', mfa='not_performed'), 'excepted', (0,1,0,1,1,0), 'breakglass-1')
    case('expired_exception', event(user='bob', method='local', offset=3600), 'alert', (0,1,0,1,0,0))
    case('exception_start_inclusive', event(user='bob', method='local', offset=-3600), 'excepted', (0,1,0,1,0,0), 'migration-1')
    case('before_exception', event(user='bob', method='local', offset=-3601), 'alert', (0,1,0,1,0,0))
    case('unknown_identity', event(user='new-user'), 'review', (1,0,1,0,0,0))
    case('same_identity_other_gateway', event(method='local', mfa='not_performed', gateway='gw-west'), 'normal')
    case('sparse_baseline', event(user='sparse'), 'review', (1,0,0,0,0,0))
    case('observed_does_not_override_policy', event(user='dave', method='local'), 'alert', (0,0,0,1,0,0))
    case('allowed_but_unobserved_method', event(method='certificate'), 'alert', (0,1,0,0,0,0))
    value = event(); del value['user']
    case('missing_identity', value, 'invalid')
    value = event(); value['event_time'] = '2026-02-30T12:00:00Z'
    case('malformed_timestamp', value, 'invalid')
    value = event()
    case('exact_duplicate', value, 'normal', occurrences=2)
    evaluation.append(copy.deepcopy(value))
    value = event(); value['user'] = ' ALICE '; value['auth_method'] = ' SAML '
    case('normalization', value, 'normal')
    case('method_exception_does_not_waive_mfa', event(user='bob', method='local', mfa='failed'), 'alert', (0,1,0,1,1,0), 'migration-1', failed_mfa=1)
    case('exception_is_gateway_scoped', event(user='bob', method='local', gateway='gw-west'), 'review', (1,0,1,0,0,0))
    case('exception_is_method_scoped', event(user='bob', method='oidc'), 'alert', (0,1,0,1,0,0))
    case('unknown_policy', event(user='no-policy'), 'review', (0,0,1,0,0,0))
    case('prebaseline_event', event(offset=-7201), 'review', (1,0,0,0,0,0))
    value = event(); value['mfa_result'] = ['passed', 'failed']
    case('multivalue_mfa_unknown', value, 'alert', (0,0,0,0,1,1), note='wrong_type')
    value = event(); value['auth_method'] = ['saml', 'local']
    case('multivalue_method_invalid', value, 'invalid')
    value = event(); value['src_ip'] = '8.8.8.8'
    case('nonfictional_ip_rejected', value, 'invalid')
    value = event(); value['schema_version'] = True
    case('boolean_schema_rejected', value, 'invalid')
    case('unknown_mfa_without_requirement', event(method='local', mfa='unknown', gateway='gw-west'), 'review', (0,0,0,0,0,1), note='explicit_unknown')
    case('failed_mfa_breakglass', event(user='carol', method='local', mfa='failed'), 'alert',
         (0,1,0,1,1,0), 'breakglass-1', failed_mfa=1)
    case('failed_mfa_no_policy', event(user='new-user', mfa='failed'), 'alert',
         (1,0,1,0,0,0), failed_mfa=1)
    case('failed_mfa_optional_policy', event(gateway='gw-west', method='local', mfa='failed'),
         'alert', failed_mfa=1)
    case('unknown_mfa_breakglass', event(user='carol', method='local', mfa='unknown'),
         'alert', (0,1,0,1,1,1), 'breakglass-1', note='explicit_unknown')
    case('exact_baseline_cutoff', event(offset=-7200), 'normal')
    case('last_second_of_exception', event(user='bob', method='local', offset=3599),
         'excepted', (0,1,0,1,0,0), 'migration-1')
    case('unsupported_mfa_note', event(mfa='bypassed'), 'alert', (0,0,0,0,1,1), note='unsupported')
    value = event(); value['mfa_result'] = None
    case('null_mfa_note', value, 'alert', (0,0,0,0,1,1), note='wrong_type')
    value = event(); value['event_time'] = value['event_time'].translate(str.maketrans('0123456789','０１２３４５６７８９'))
    case('unicode_timestamp', value, 'invalid')
    value = event(); value['user'] = '\u212aate'
    case('kelvin_identifier_rejected', value, 'invalid')
    rng.shuffle(evaluation)
    for name, values in [('training', training), ('evaluation', evaluation)]:
        (root / 'fixtures' / (name + '.jsonl')).write_text(''.join(canonical(v)+'\n' for v in values))
    write_json(root / 'fixtures/expected.json', {'seed': seed, 'reference_time': reference,
               'cases': sorted(expected, key=lambda e:e['event_id'])})
    baseline = build_baseline(training, iso(now-dt.timedelta(hours=2)))
    write_csv(root / 'lookups/c07_baseline.csv', baseline,
              ['gateway_id','user','sample_count','minimum_samples','observed_methods','baseline_cutoff_epoch'])
    policy = [{'gateway_id':'gw-east','user':user,'allowed_methods':methods,'require_mfa':1}
              for user, methods in [('alice','certificate|saml'),('bob','saml'),('carol','saml'),('dave','saml'),('sparse','saml')]]
    policy.append({'gateway_id':'gw-west','user':'alice','allowed_methods':'local','require_mfa':0})
    write_csv(root / 'lookups/c07_policy.csv', policy, ['gateway_id','user','allowed_methods','require_mfa'])
    exceptions = [dict(gateway_id='gw-east', user=user, auth_method='local', exception_id=ident,
                       reason=reason, valid_from_epoch=epoch-3600, valid_to_epoch=epoch+3600,
                       allow_method=1, waive_mfa=waive)
                  for user, ident, reason, waive in [
                      ('bob','migration-1','Approved fictional enrollment transition',0),
                      ('carol','breakglass-1','Approved fictional recovery exercise',1)]]
    write_csv(root / 'lookups/c07_exceptions.csv', exceptions,
              ['gateway_id','user','auth_method','exception_id','reason','valid_from_epoch','valid_to_epoch','allow_method','waive_mfa'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--reference-time', default=DEFAULT_TIME)
    args = parser.parse_args()
    # Refuse accidental replacement of fixtures or authoritative lookups.
    if any((args.output / name).exists() for name in ('fixtures','lookups')):
        parser.error('output must not already contain fixtures or lookups')
    generate(args.output, args.seed, args.reference_time)
