"""Strict offline adapter and reference decision model. Standard library only."""
import csv
import datetime as dt
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

UTC = dt.timezone.utc
MIN_SAMPLES = 3
METHODS = {'saml', 'local', 'oidc', 'certificate'}
MFA = {'passed', 'failed', 'not_performed', 'unknown'}
FIELDS = {'schema_version', 'event_id', 'event_time', 'gateway_id', 'user',
          'src_ip', 'result', 'auth_method', 'mfa_result', 'session_id'}
KEY = re.compile(r'[a-z0-9][a-z0-9_.@-]{0,63}\Z')
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z')
NETWORKS = tuple(ipaddress.ip_network(x) for x in
                 ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))
FLAGS = ('baseline_unknown', 'method_deviation', 'policy_unknown',
         'policy_violation', 'mfa_violation', 'telemetry_unknown', 'failed_mfa_on_success')


def parse_time(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value):
        raise ValueError('timestamp must be whole-second UTC Z')
    return dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=UTC)


def iso(value):
    return value.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def read_events(path):
    with Path(path).open() as handle:
        return [json.loads(line, object_pairs_hook=no_duplicate_keys)
                for line in handle if line.strip()]


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def write_csv(path, rows, fields):
    with Path(path).open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def normalize(raw):
    # Event IDs are mandatory even for invalid records: do not silently drop them.
    if not isinstance(raw, dict) or not isinstance(raw.get('event_id'), str) or not ID.fullmatch(raw['event_id']):
        raise ValueError('missing or invalid event_id; repair input before evaluation')
    event = {'event_id': raw['event_id'], 'valid': 0, 'parse_error': '',
             'event_epoch': 0, 'mfa_result': 'unknown', 'mfa_known': 0, 'mfa_note': 'missing'}
    errors = []
    if set(raw) - FIELDS:
        errors.append('unexpected_fields')
    if type(raw.get('schema_version')) is not int or raw['schema_version'] != 1:
        errors.append('schema_version')
    for field in ('gateway_id', 'user', 'auth_method', 'result'):
        value = raw.get(field)
        value = value.strip().lower() if isinstance(value, str) and value.isascii() else ''
        event[field] = value
        if not KEY.fullmatch(value):
            errors.append(field)
    if event['auth_method'] not in METHODS:
        errors.append('auth_method')
    if event['result'] not in {'success', 'failure'}:
        errors.append('result')
    try:
        event['event_epoch'] = int(parse_time(raw.get('event_time')).timestamp())
        event['event_time'] = raw['event_time']
    except ValueError:
        errors.append('event_time')
        event['event_time'] = ''
    ip = raw.get('src_ip')
    try:
        address = ipaddress.ip_address(ip) if isinstance(ip, str) else None
        if address is None or not any(address in network for network in NETWORKS):
            raise ValueError()
        event['src_ip'] = str(address)
    except ValueError:
        errors.append('src_ip')
        event['src_ip'] = ''
    session = raw.get('session_id')
    event['session_id'] = session if isinstance(session, str) and ID.fullmatch(session) else ''
    if not event['session_id']:
        errors.append('session_id')
    mfa = raw.get('mfa_result')
    if 'mfa_result' not in raw:
        event['mfa_note'] = 'missing'
    elif not isinstance(mfa, str):
        event['mfa_note'] = 'wrong_type'
    else:
        normalized = mfa.strip().lower() if mfa.isascii() else ''
        if normalized in MFA:
            event['mfa_result'] = normalized
            event['mfa_known'] = int(normalized != 'unknown')
            event['mfa_note'] = 'explicit_unknown' if normalized == 'unknown' else 'none'
        else:
            event['mfa_note'] = 'unsupported'
    # Missing/unsupported MFA is unknown telemetry, never silently treated as passed.
    event['parse_error'] = '|'.join(sorted(set(errors)))
    event['valid'] = int(not errors)
    return event


def prepare(raw_events):
    unique = {}
    counts = Counter()
    for raw in raw_events:
        event = normalize(raw)
        ident = event['event_id']
        encoded = canonical(raw)
        if ident in unique and unique[ident][0] != encoded:
            raise ValueError('conflicting duplicate event_id: ' + ident)
        unique[ident] = (encoded, event)
        counts[ident] += 1
    return [dict(unique[key][1], occurrences=counts[key]) for key in sorted(unique)]


def build_baseline(training, cutoff):
    cutoff_epoch = int(parse_time(cutoff).timestamp())
    groups = defaultdict(list)
    for event in prepare(training):
        if not event['valid'] or not event['mfa_known']:
            raise ValueError('training must contain valid known telemetry')
        if event['event_epoch'] >= cutoff_epoch:
            raise ValueError('training must precede frozen cutoff')
        if event['result'] == 'success':
            if event['mfa_result'] == 'failed':
                raise ValueError('successful training login reports failed MFA')
            groups[(event['gateway_id'], event['user'])].append(event)
    return [{'gateway_id': gateway, 'user': user,
             'sample_count': len(events), 'minimum_samples': MIN_SAMPLES,
             'observed_methods': '|'.join(sorted({e['auth_method'] for e in events})),
             'baseline_cutoff_epoch': cutoff_epoch}
            for (gateway, user), events in sorted(groups.items())]


def load_table(path, keys):
    with Path(path).open(newline='') as handle:
        rows = list(csv.DictReader(handle))
    result = {}
    for row in rows:
        key = tuple(row[k] for k in keys)
        if key in result:
            raise ValueError('duplicate lookup key: ' + str(key))
        if any(not KEY.fullmatch(k) for k in key):
            raise ValueError('lookup keys must already be normalized')
        result[key] = row
    return result


def load_lookups(directory):
    directory = Path(directory)
    baseline = load_table(directory / 'c07_baseline.csv', ('gateway_id', 'user'))
    policy = load_table(directory / 'c07_policy.csv', ('gateway_id', 'user'))
    exceptions = load_table(directory / 'c07_exceptions.csv', ('gateway_id', 'user', 'auth_method'))
    for row in baseline.values():
        if (int(row['sample_count']) < 0 or int(row['baseline_cutoff_epoch']) <= 0
                or int(row['minimum_samples']) < 1):
            raise ValueError('invalid baseline metadata')
        if not set(row['observed_methods'].split('|')) <= METHODS:
            raise ValueError('invalid observed methods')
    for row in policy.values():
        if not set(row['allowed_methods'].split('|')) <= METHODS or row['require_mfa'] not in {'0', '1'}:
            raise ValueError('invalid policy')
    for key, row in exceptions.items():
        if key[2] not in METHODS or not row['reason'].strip() or not ID.fullmatch(row['exception_id']):
            raise ValueError('invalid exception')
        if int(row['valid_from_epoch']) >= int(row['valid_to_epoch']):
            raise ValueError('invalid exception interval')
        if any(row[k] not in {'0', '1'} for k in ('allow_method', 'waive_mfa')):
            raise ValueError('invalid exception scope')
    return baseline, policy, exceptions


def decide(event, tables):
    baseline, policy, exceptions = tables
    result = {'event_id': event['event_id'], 'disposition': 'normal',
              'occurrences': event['occurrences'], 'exception_id': '',
              'exception_reason': '', 'exception_applied': 0,
              'parse_error': event['parse_error'], 'mfa_note': event['mfa_note']}
    result.update({flag: 0 for flag in FLAGS})
    if not event['valid']:
        result['disposition'] = 'invalid'
        return result
    if event['result'] != 'success':
        result['disposition'] = 'failed_login'
        return result
    key = (event['gateway_id'], event['user'])
    b, p = baseline.get(key), policy.get(key)
    baseline_known = (b is not None and int(b['sample_count']) >= int(b['minimum_samples'])
                      and event['event_epoch'] >= int(b['baseline_cutoff_epoch']))
    result['baseline_unknown'] = int(not baseline_known)
    result['method_deviation'] = int(baseline_known and event['auth_method'] not in b['observed_methods'].split('|'))
    result['policy_unknown'] = int(p is None)
    result['policy_violation'] = int(p is not None and event['auth_method'] not in p['allowed_methods'].split('|'))
    result['mfa_violation'] = int(p is not None and p['require_mfa'] == '1' and event['mfa_result'] != 'passed')
    result['telemetry_unknown'] = int(not event['mfa_known'])
    result['failed_mfa_on_success'] = int(event['mfa_result'] == 'failed')
    x = exceptions.get(key + (event['auth_method'],))
    active = (p is not None and x is not None and
              int(x['valid_from_epoch']) <= event['event_epoch'] < int(x['valid_to_epoch']))
    method_alarm = result['method_deviation'] or result['policy_violation']
    mfa_alarm = result['mfa_violation']
    waived_method = active and x['allow_method'] == '1' and method_alarm
    waived_mfa = (active and x['waive_mfa'] == '1' and mfa_alarm
                  and event['mfa_result'] == 'not_performed')
    if waived_method or waived_mfa:
        result.update(exception_applied=1, exception_id=x['exception_id'], exception_reason=x['reason'])
    if (result['failed_mfa_on_success'] or (method_alarm and not waived_method)
            or (mfa_alarm and not waived_mfa)):
        result['disposition'] = 'alert'
    elif any(result[k] for k in ('baseline_unknown', 'policy_unknown', 'telemetry_unknown')):
        result['disposition'] = 'review'
    elif result['exception_applied']:
        result['disposition'] = 'excepted'
    return result


def evaluate(events, tables):
    return [decide(e, tables) for e in prepare(events)]
