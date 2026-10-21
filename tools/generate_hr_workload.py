"""Generate human-like, reproducible HR activity; no AWS calls or real identities."""
import argparse
from copy import deepcopy
from datetime import date, datetime, time, timedelta, timezone
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[1]
ACTION_MAP = {
    'overview': ('GET', '/api/v1/hr/summary', 'hr:ViewCompanySummary'),
    'payroll': ('GET', '/api/v1/hr/payroll', 'hr:ViewPayrollRegister'),
    'employee': ('GET', '/api/v1/hr/employees/{employeeId}', 'hr:ReadEmployeeRecords'),
    'reviews': ('GET', '/api/v1/hr/reviews', 'hr:ListConfidentialReviews'),
    'review': ('GET', '/api/v1/hr/reviews/{employeeId}', 'hr:ReadConfidentialReview'),
    'audit': ('GET', '/api/v1/hr/audit', 'hr:ViewAudit'),
    'export': ('POST', '/api/v1/hr/payroll/export', 'hr:ExportPayroll'),
}
SCENARIOS = (
    'normal_hr_routine', 'legitimate_new_network', 'legitimate_new_device', 'legitimate_off_hours',
    'legitimate_infrequent_export', 'attack_unknown_network', 'attack_unknown_device', 'attack_off_hours',
    'attack_familiar_context_export', 'attack_familiar_context_read', 'attack_bulk_read_burst',
    'attack_repeated_exports', 'legitimate_mid_session_network_change', 'attack_mid_session_network_change',
    'attack_out_of_sequence_export',
)


def fingerprint(dataset):
    return hashlib.sha256(json.dumps(dataset, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_personas(config):
    if config.get('synthetic') is not True or not isinstance(config.get('personas'), list) or not config['personas']:
        raise ValueError('Supply a non-empty, explicitly synthetic persona configuration')
    seen = set()
    for person in config['personas']:
        if not re.fullmatch(r'[a-z][a-z0-9-]{1,40}', person.get('id', '')) or person['id'] in seen:
            raise ValueError('Persona IDs must be unique lowercase identifiers')
        seen.add(person['id'])
        if person.get('role') != 'hr':
            raise ValueError('This workload evaluates HR-authorized callers, separately from role-denial tests')
        offset = person.get('utc_offset_minutes')
        if type(offset) is not int or not -720 <= offset <= 840:
            raise ValueError('Invalid fixed timezone offset')
        if not person.get('workdays') or any(type(day) is not int or day not in range(7) for day in person['workdays']):
            raise ValueError('Workdays must use Python weekday numbers 0–6')
        if not person.get('session_starts_local'):
            raise ValueError('Each persona needs session start times')
        for value in person['session_starts_local']:
            parsed = time.fromisoformat(value)
            if parsed.tzinfo or not 6 <= parsed.hour <= 20:
                raise ValueError('Use local daytime session starts; 03:00 is reserved for off-hours scenarios')
        for day in person['workdays']:
            matches = [network for network in person.get('networks', []) if day in network['weekdays']]
            if len(matches) != 1:
                raise ValueError('Exactly one routine network must cover each workday')
        for network in person['networks']:
            address = ipaddress.ip_address(network['ip'])
            if address.version != 4 or not any(address in ipaddress.ip_network(block) for block in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')):
                raise ValueError('Synthetic networks must use documentation-only address ranges')
        if not person.get('devices') or any(not device.get('user_agent', '').startswith('LZTA-Synthetic/') for device in person['devices']):
            raise ValueError('Use explicitly synthetic device User-Agents')
        if 'employee' not in person.get('routine', []) or any(action not in ACTION_MAP for action in person['routine']):
            raise ValueError('Routine must include employee reads and use supported HR routes')
    return config


def build_workload(seed=2026, training_days=28, repeats=3, persona_config=None):
    if type(seed) is not int or type(training_days) is not int or not 7 <= training_days <= 90 or type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError('Use an integer seed, 7–90 training days, and 1–20 evaluation repeats')
    config = deepcopy(persona_config) if persona_config is not None else json.loads((ROOT / 'config/hr_personas.json').read_text(encoding='utf-8'))
    validate_personas(config)
    rng = random.Random(seed)
    dataset_id = f'lzta-hr-routines-v2-seed-{seed}-days-{training_days}-repeats-{repeats}'
    # Configuration fingerprint prevents event receipt collisions across persona variants.
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:10]
    dataset_id += '-' + config_hash
    start = date(2026, 9, 1)
    end = start + timedelta(days=training_days)
    records, cases, people, sessions = [], [], [], []

    def iso(value):
        return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

    def request(person, action, when, ip, agent):
        method, resource, action_name = ACTION_MAP[action]
        employee_id = f'NS-{rng.randint(1001, 1016)}'
        return {'user_id': person['profile_identity'], 'method': method, 'resource': resource,
                'path': resource.replace('{employeeId}', employee_id), 'action': action_name,
                'source_ip': ip, 'user_agent': agent, 'request_time': iso(when)}

    for definition in config['personas']:
        person = {**definition, 'profile_identity': 'arn:aws:iam::123456789012:user/lzta-experiment-v2/' + definition['id']}
        people.append(person)
        tz = timezone(timedelta(minutes=person['utc_offset_minutes']))
        counter = 0
        for offset in range(training_days):
            day = start + timedelta(days=offset)
            if day.weekday() not in person['workdays']:
                continue
            network = next(network for network in person['networks'] if day.weekday() in network['weekdays'])
            for session_index, anchor in enumerate(person['session_starts_local']):
                # Some optional later sessions are absent, producing ordinary day-to-day variation.
                if session_index > 0 and rng.random() < 0.18:
                    continue
                agent = rng.choice(person['devices'])['user_agent']
                when = datetime.combine(day, time.fromisoformat(anchor), tzinfo=tz) + timedelta(minutes=rng.randint(0, 14))
                session_id = f'train-{person["id"]}-{day}-{session_index}'
                routine = list(person['routine'])
                if person['monthly_export'] and session_index == 0 and (day.day == 25 or (day.weekday() == 4 and day.day in (23, 24))):
                    routine.insert(-1, 'export')
                for action in routine:
                    req = request(person, action, when, network['ip'], agent)
                    event_id = f'hr-v2-{seed}-{training_days}-{repeats}-{config_hash}-{person["id"]}-{counter:06d}'
                    counter += 1
                    records.append({'eventID': event_id, 'eventTime': req['request_time'], 'userIdentity': {'type': 'IAMUser', 'arn': person['profile_identity']},
                                    'sourceIPAddress': req['source_ip'], 'userAgent': agent,
                                    'eventSource': 'hr.synthetic.lzta.invalid', 'eventName': req['action'].split(':', 1)[1],
                                    'synthetic': True, 'syntheticContext': {'source': 'application_activity_adapter', 'session_id': session_id,
                                        'method': req['method'], 'resource': req['resource'], 'path': req['path']}})
                    when += timedelta(seconds=rng.randint(50, 210))

        evaluation_days, candidate = [], end + timedelta(days=3)
        while len(evaluation_days) < len(SCENARIOS) * repeats:
            if candidate.weekday() in person['workdays']:
                evaluation_days.append(candidate)
            candidate += timedelta(days=1)
        for repeat in range(repeats):
            for scenario_index, scenario in enumerate(SCENARIOS):
                day = evaluation_days[repeat * len(SCENARIOS) + scenario_index]
                when = datetime.combine(day, time.fromisoformat(person['session_starts_local'][0]), tzinfo=tz) + timedelta(minutes=5)
                network = next(network for network in person['networks'] if day.weekday() in network['weekdays'])
                ip, agent = network['ip'], person['devices'][0]['user_agent']
                routine = list(person['routine'])
                label = 'attack' if scenario.startswith('attack_') else 'legitimate'
                if scenario in ('legitimate_new_network', 'attack_unknown_network'):
                    ip = '203.0.113.90'
                if scenario in ('legitimate_new_device', 'attack_unknown_device'):
                    agent = 'LZTA-Synthetic/New-Unseen-Device'
                if scenario in ('legitimate_off_hours', 'attack_off_hours'):
                    when = datetime.combine(day, time(3, 15), tzinfo=tz)
                if scenario in ('legitimate_infrequent_export', 'attack_familiar_context_export'):
                    routine = ['overview', 'payroll', 'employee', 'export', 'audit']
                if scenario == 'attack_familiar_context_read':
                    routine = ['employee']
                if scenario == 'attack_out_of_sequence_export':
                    routine = ['export', 'payroll', 'employee']
                if scenario == 'attack_bulk_read_burst':
                    routine = ['employee'] * 24
                if scenario == 'attack_repeated_exports':
                    routine = ['export'] * 8
                session_id = f'eval-{person["id"]}-{scenario}-{repeat:02d}'
                case_ids = []
                for step, action in enumerate(routine):
                    changed_network = scenario in ('legitimate_mid_session_network_change', 'attack_mid_session_network_change') and step >= 2
                    observed_ip = '203.0.113.90' if changed_network else ip
                    step_label = 'legitimate' if scenario == 'attack_mid_session_network_change' and step < 2 else label
                    case_id = f'{session_id}-{step:03d}'
                    cases.append({'case_id': case_id, 'persona_id': person['id'], 'session_id': session_id, 'sequence': step,
                                  'scenario': scenario, 'label': step_label, 'request': request(person, action, when, observed_ip, agent)})
                    case_ids.append(case_id)
                    when += timedelta(milliseconds=150) if scenario == 'attack_bulk_read_burst' else timedelta(milliseconds=800) if scenario == 'attack_repeated_exports' else timedelta(seconds=rng.randint(50, 150))
                sessions.append({'session_id': session_id, 'persona_id': person['id'], 'scenario': scenario,
                                 'intent_label': label, 'case_ids': case_ids,
                                 'note': 'Session features are planned inputs; Stage 2 is not implemented.'})
    records.sort(key=lambda item: (item['eventTime'], item['eventID']))
    cases.sort(key=lambda item: (item['request']['request_time'], item['case_id']))
    return {'dataset_version': '2.0.0', 'dataset_id': dataset_id, 'synthetic': True, 'seed': seed,
            'parameters': {'training_start_local': start.isoformat(), 'training_days': training_days, 'evaluation_repeats': repeats,
                           'persona_config_sha256': config_hash}, 'personas': people,
            'rules': {'decision_policy': 'deny_on_any_anomaly', 'sensitive_actions': [value[2] for value in ACTION_MAP.values()]},
            'training': {'source': 'synthetic_application_activity_cloudtrail_shaped_adapter', 'records': records,
                         'note': 'Not genuine CloudTrail. hr:* routes are custom application actions; this shape reuses the existing feature extraction/ingestion code.'},
            'evaluation': {'cases': cases, 'sessions': sessions,
                           'label_semantics': 'Explicit generator-assigned scenario intent, not inferred from anomalies. Some legitimate and malicious contexts are intentionally indistinguishable.',
                           'context_note': 'Planned synthetic contexts only. Live tests must use valid authenticated identities and record API Gateway-observed IP, User-Agent and UTC time.'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=int, default=2026)
    parser.add_argument('--training-days', type=int, default=28)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--personas', type=Path, default=ROOT / 'config/hr_personas.json')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    dataset = build_workload(args.seed, args.training_days, args.repeats, json.loads(args.personas.read_text(encoding='utf-8')))
    output = args.output or ROOT / 'tests/simulations' / (dataset['dataset_id'] + '.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dataset, indent=2) + '\n', encoding='utf-8')
    training_file = output.with_suffix('.training.json.gz')
    training_file.write_bytes(gzip.compress(json.dumps({'Records': dataset['training']['records']}, sort_keys=True).encode(), mtime=0))
    print(json.dumps({'dataset': str(output), 'training_gzip': str(training_file), 'dataset_sha256': fingerprint(dataset),
                      'personas': len(dataset['personas']), 'training_records': len(dataset['training']['records']),
                      'evaluation_requests': len(dataset['evaluation']['cases']), 'evaluation_sessions': len(dataset['evaluation']['sessions'])}, indent=2))


if __name__ == '__main__':
    main()
