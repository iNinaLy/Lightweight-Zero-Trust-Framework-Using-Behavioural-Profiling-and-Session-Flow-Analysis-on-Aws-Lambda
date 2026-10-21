"""Learn frozen profiles from synthetic training events and evaluate held-out HR requests."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))
from lzta.profiles import observation
from lzta.scoring import Request, Rules, evaluate
from tools.generate_hr_workload import ACTION_MAP, fingerprint


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timestamps must be timezone-aware')
    return result.astimezone(timezone.utc)


def learn_profiles(dataset):
    if dataset.get('synthetic') is not True or dataset.get('dataset_version') not in ('2.0.0', '3.0.0'):
        raise ValueError('Expected explicitly synthetic v2 workload')
    if dataset['training']['source'] not in ('synthetic_application_activity_cloudtrail_shaped_adapter', 'synthetic_aws_cloudtrail_shaped_events'):
        raise ValueError('Expected explicit application adapter source')
    identities = [person['profile_identity'] for person in dataset['personas']]
    if len(set(identities)) != len(identities):
        raise ValueError('Duplicate persona identity')
    profiles, receipts = {}, {}
    for event in dataset['training']['records']:
        item = observation(event)
        if not item or event.get('synthetic') is not True or item['userId'] not in identities:
            raise ValueError('Invalid training observation')
        signature = fingerprint(event)
        if item['eventId'] in receipts:
            if receipts[item['eventId']] != signature:
                raise ValueError('Conflicting duplicate training event')
            continue
        receipts[item['eventId']] = signature
        profile = profiles.setdefault(item['userId'], {'userId': item['userId'], 'knownIPs': set(),
            'userAgents': set(), 'hourHistogram': {}, 'actionCounts': {}})
        profile['knownIPs'].add(item['ip'])
        profile['userAgents'].add(item['userAgent'])
        for field, key in [('hourHistogram', item['hour']), ('actionCounts', item['action'])]:
            profile[field][key] = profile[field].get(key, 0) + 1
    if set(profiles) != set(identities):
        raise ValueError('Every persona needs training activity')
    return {identity: {key: sorted(value) if isinstance(value, set) else value for key, value in profile.items()}
            for identity, profile in sorted(profiles.items())}


def metrics(counts):
    result = {key: counts[key] for key in ('TP', 'FP', 'TN', 'FN')}
    result['requests'] = sum(result.values())
    result['false_positive_rate'] = counts['FP'] / (counts['FP'] + counts['TN']) if counts['FP'] + counts['TN'] else None
    result['false_negative_rate'] = counts['FN'] / (counts['FN'] + counts['TP']) if counts['FN'] + counts['TP'] else None
    return result


def evaluate_workload(dataset):
    profiles = learn_profiles(dataset)
    rules = Rules.from_dict(dataset['rules'])
    training_end = max(timestamp(event['eventTime']) for event in dataset['training']['records'])
    people = {person['id']: person['profile_identity'] for person in dataset['personas']}
    totals, by_person, by_scenario, decisions, seen = Counter(), {}, {}, [], set()
    routes = set(ACTION_MAP.values())
    for case in dataset['evaluation']['cases']:
        if case['case_id'] in seen or case['label'] not in ('legitimate', 'attack'):
            raise ValueError('Duplicate case ID or invalid intent label')
        seen.add(case['case_id'])
        req = case['request']
        when = timestamp(req['request_time'])
        if case['persona_id'] not in people or req['user_id'] != people[case['persona_id']]:
            raise ValueError('Unknown or mismatched evaluation identity')
        if when <= training_end:
            raise ValueError('Evaluation must occur after all training activity')
        if dataset['dataset_version'] == '3.0.0':
            from tools.generate_aws_workload import OPERATIONS
            allowed = set(OPERATIONS.values()) | {('iam:CreateUser', 'arn:aws:iam::123456789012:user/unauthorized-new-user')}
            if (req['action'], req['resource']) not in allowed:
                raise ValueError('Invalid AWS operation/resource')
            persona = next(person for person in dataset['personas'] if person['id'] == case['persona_id'])
            permission = {'action': req['action'], 'resource': req['resource']} in persona['permitted_operations']
            if type(req.get('permission_allowed')) is not bool or req['permission_allowed'] != permission:
                raise ValueError('Permission label contradicts persona permission fixture')
        elif (req['method'], req['resource'], req['action']) not in routes:
            raise ValueError('Invalid HR route/action mapping')
        decision = evaluate(Request(req['user_id'], req['source_ip'], req['user_agent'], req['action'], when), profiles[req['user_id']], rules)
        denied, attack = decision.verdict == 'Deny', case['label'] == 'attack'
        outcome = 'TP' if denied and attack else 'FP' if denied else 'FN' if attack else 'TN'
        totals[outcome] += 1
        by_person.setdefault(case['persona_id'], Counter())[outcome] += 1
        by_scenario.setdefault(case['scenario'], Counter())[outcome] += 1
        decisions.append({'case_id': case['case_id'], 'label': case['label'], 'verdict': decision.verdict,
                          'anomalies': list(decision.anomalies), 'outcome': outcome})
        if dataset['dataset_version'] == '3.0.0':
            decisions[-1]['permission_fixture'] = 'Allow' if permission else 'Deny'
            decisions[-1]['combined_baseline_verdict'] = decision.verdict if permission else 'Deny'
    return {'dataset_id': dataset['dataset_id'], 'dataset_sha256': fingerprint(dataset),
            'method': 'Production strict binary evaluator; frozen training-only profiles; request-level metrics; no Stage 2.',
            'rules': dataset['rules'], 'metrics': metrics(totals),
            'by_persona': {key: metrics(value) for key, value in sorted(by_person.items())},
            'by_scenario': {key: metrics(value) for key, value in sorted(by_scenario.items())},
            'profiles': profiles, 'decisions': decisions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = evaluate_workload(json.loads(args.dataset.read_text(encoding='utf-8')))
    output = args.output or ROOT / 'reports' / (report['dataset_id'] + '-baseline.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(output), 'metrics': report['metrics']}, indent=2))


if __name__ == '__main__':
    main()
