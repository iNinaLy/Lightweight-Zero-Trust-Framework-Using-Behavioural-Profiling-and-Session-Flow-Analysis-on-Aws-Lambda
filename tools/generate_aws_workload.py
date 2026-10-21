"""Generate fictional AWS-user routines and held-out behaviour/permission scenarios."""
import argparse
from copy import deepcopy
import gzip
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.generate_hr_workload import ACTION_MAP, build_workload, fingerprint

# Explicit synthetic mapping, including resource-scoped permission fixtures.
OPERATIONS = {
    'hr:ViewCompanySummary': ('sts:GetCallerIdentity', '*'),
    'hr:ViewPayrollRegister': ('s3:ListBuckets', '*'),
    'hr:ReadEmployeeRecords': ('s3:GetObject', 'arn:aws:s3:::lzta-synthetic-team/reports/report.json'),
    'hr:ListConfidentialReviews': ('ec2:DescribeInstances', '*'),
    'hr:ReadConfidentialReview': ('cloudwatch:GetMetricData', '*'),
    'hr:ViewAudit': ('cloudtrail:LookupEvents', '*'),
    'hr:ExportPayroll': ('s3:PutObject', 'arn:aws:s3:::lzta-synthetic-team/reports/output.json'),
}
SCENARIO_NAMES = {
    'normal_hr_routine': 'normal_aws_routine',
    'legitimate_new_network': 'legitimate_starts_hybrid',
    'legitimate_off_hours': 'legitimate_unexpected_overtime',
    'legitimate_infrequent_export': 'legitimate_first_time_permitted_write',
    'attack_bulk_read_burst': 'attack_bulk_object_reads',
    'attack_repeated_exports': 'attack_repeated_object_writes',
    'attack_out_of_sequence_export': 'attack_out_of_sequence_write',
    'attack_familiar_context_export': 'attack_familiar_context_write',
}


def build_aws_workload(seed=2026, training_days=28, repeats=3):
    config = json.loads((ROOT / 'config/aws_personas.json').read_text(encoding='utf-8'))
    # Reuse only the deterministic scheduling engine; all exported actions are AWS operations.
    scheduling = deepcopy(config)
    schedule_keys = {OPERATIONS[value[2]][0]: key for key, value in ACTION_MAP.items()}
    for person in scheduling['personas']:
        person['role'] = 'hr'
        person['routine'] = [schedule_keys[action] for action in person['routine']]
        person['monthly_export'] = person.pop('infrequent_write')
    data = build_workload(seed, training_days, repeats, scheduling)
    data['dataset_version'] = '3.0.0'
    data['dataset_id'] = data['dataset_id'].replace('hr-routines-v2', 'aws-routines-v3')
    identities = {}
    for person, definition in zip(data['personas'], config['personas']):
        old = person['profile_identity']
        person['role'] = definition['role']
        person['profile_identity'] = old.replace('lzta-experiment-v2', 'lzta-aws-experiment-v3')
        identities[old] = person['profile_identity']
        person['permitted_operations'] = [{'action': action, 'resource': resource} for action, resource in OPERATIONS.values()]
        person['routine'] = [OPERATIONS[ACTION_MAP[key][2]][0] for key in person['routine']]
    for event in data['training']['records']:
        action, resource = OPERATIONS['hr:' + event['eventName']]
        service, name = action.split(':')
        event['eventID'] = event['eventID'].replace('hr-v2', 'aws-v3')
        event['userIdentity']['arn'] = identities[event['userIdentity']['arn']]
        event['eventSource'], event['eventName'] = service + '.amazonaws.com', name
        event['awsRegion'] = 'us-east-1'
        event['requestParameters'] = {'syntheticResource': resource}
        context = event['syntheticContext']
        event['syntheticContext'] = {'source': 'synthetic_aws_activity', 'session_id': context['session_id'], 'resource': resource}
    for case in data['evaluation']['cases']:
        req = case['request']
        action, resource = OPERATIONS[req['action']]
        req['user_id'], req['action'], req['resource'] = identities[req['user_id']], action, resource
        req.pop('method'); req.pop('path')
        req['permission_allowed'] = True
        case['scenario'] = SCENARIO_NAMES.get(case['scenario'], case['scenario'])
        case['expected_two_stage'] = 'flag_and_continue' if case['label'] == 'legitimate' and case['scenario'] != 'normal_aws_routine' else 'allow' if case['label'] == 'legitimate' else 'detect_or_deny_if_session_evidence'
    for session in data['evaluation']['sessions']:
        session['scenario'] = SCENARIO_NAMES.get(session['scenario'], session['scenario'])
    # Paired changed-context sessions: benign first, then explicit out-of-scope activity.
    extra_cases, extra_sessions = [], []
    for session in data['evaluation']['sessions']:
        if session['scenario'] not in ('legitimate_starts_hybrid', 'legitimate_unexpected_overtime'):
            continue
        base = [case for case in data['evaluation']['cases'] if case['session_id'] == session['session_id']]
        copied = deepcopy(base)
        sid = session['session_id'] + '-scope-violation'
        for index, case in enumerate(copied):
            case.update(session_id=sid, case_id=f'{sid}-{index:03d}', scenario=session['scenario'].replace('legitimate_', 'attack_') + '_then_out_of_scope')
        last = copied[-1]
        last['label'] = 'attack'
        last['request'].update(action='iam:CreateUser', resource='arn:aws:iam::123456789012:user/unauthorized-new-user', permission_allowed=False)
        last['expected_two_stage'] = 'deny_by_permission_boundary'
        extra_cases.extend(copied)
        extra_sessions.append({'session_id': sid, 'persona_id': session['persona_id'], 'scenario': last['scenario'], 'intent_label': 'attack', 'case_ids': [case['case_id'] for case in copied], 'note': 'Initial changed context is legitimate; final action violates the permission fixture.'})
    data['evaluation']['cases'].extend(extra_cases)
    data['evaluation']['sessions'].extend(extra_sessions)
    data['evaluation']['cases'].sort(key=lambda case: (case['request']['request_time'], case['case_id']))
    data['rules']['sensitive_actions'] = sorted({action for action, _ in OPERATIONS.values()} | {'iam:CreateUser'})
    data['training']['source'] = 'synthetic_aws_cloudtrail_shaped_events'
    data['training']['note'] = 'Fictional AWS activity, not captured CloudTrail. S3 object activity requires data-event logging in a real experiment.'
    data['evaluation']['context_note'] = 'Offline AWS contexts and permission fixtures only; no IAM policy evaluation or direct-AWS enforcement is claimed.'
    data['evaluation']['two_stage_note'] = 'Expected outcomes are requirements, not a two-stage implementation. A context change alone is a flag, not proof of attack. Suspicious session activity requires detection evidence.'
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=int, default=2026)
    parser.add_argument('--training-days', type=int, default=28)
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    data = build_aws_workload(args.seed, args.training_days, args.repeats)
    path = ROOT / 'tests/simulations' / (data['dataset_id'] + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    path.with_suffix('.training.json.gz').write_bytes(gzip.compress(json.dumps({'Records': data['training']['records']}, sort_keys=True).encode(), mtime=0))
    print(json.dumps({'dataset': str(path), 'sha256': fingerprint(data), 'training': len(data['training']['records']), 'requests': len(data['evaluation']['cases'])}))


if __name__ == '__main__':
    main()
