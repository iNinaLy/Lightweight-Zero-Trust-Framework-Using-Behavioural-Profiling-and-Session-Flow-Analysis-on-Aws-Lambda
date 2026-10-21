"""Reproducibility, holdout isolation and production aggregation parity."""
from copy import deepcopy
from datetime import timezone, timedelta
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hr_workload import build_workload
from tools.evaluate_hr_workload import evaluate_workload, learn_profiles, timestamp


class HRWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.dataset = build_workload(training_days=7, repeats=1)

    def test_reproducibility_and_realistic_session_context(self):
        self.assertEqual(self.dataset, build_workload(training_days=7, repeats=1))
        self.assertNotEqual(self.dataset, build_workload(seed=2027, training_days=7, repeats=1))
        sessions = {}
        for event in self.dataset['training']['records']:
            key = event['syntheticContext']['session_id']
            context = (event['sourceIPAddress'], event['userAgent'])
            self.assertEqual(sessions.setdefault(key, context), context)
            if 'sarah' in event['userIdentity']['arn']:
                local = timestamp(event['eventTime']).astimezone(timezone(timedelta(hours=8)))
                self.assertLess(local.weekday(), 5)
                self.assertIn(local.hour, (9, 11, 14, 16, 17))

    def test_profiles_only_learn_training_and_dedupe_replays(self):
        profiles = learn_profiles(self.dataset)
        self.dataset['evaluation']['cases'][0]['request']['source_ip'] = '203.0.113.199'
        self.assertEqual(profiles, learn_profiles(self.dataset))
        self.dataset['training']['records'].append(deepcopy(self.dataset['training']['records'][0]))
        self.assertEqual(profiles, learn_profiles(self.dataset))
        self.dataset['training']['records'][-1]['userAgent'] += '-conflict'
        with self.assertRaises(ValueError):
            learn_profiles(self.dataset)

    def test_invalid_evaluation_rejected(self):
        for mutation in ('label', 'identity', 'time', 'duplicate'):
            data = deepcopy(self.dataset)
            case = data['evaluation']['cases'][0]
            if mutation == 'label':
                case['label'] = 'typo'
            elif mutation == 'identity':
                case['request']['user_id'] = 'unknown'
            elif mutation == 'time':
                case['request']['request_time'] = data['training']['records'][0]['eventTime']
            else:
                data['evaluation']['cases'].append(deepcopy(case))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evaluate_workload(data)

    def test_familiar_context_attack_exposes_baseline_blind_spot(self):
        report = evaluate_workload(self.dataset)
        reads = report['by_scenario']['attack_familiar_context_read']
        self.assertEqual(reads['FN'], reads['requests'])
        self.assertEqual(sum(sum(p['actionCounts'].values()) for p in report['profiles'].values()),
                         len(self.dataset['training']['records']))

    def test_dynamodb_aggregation_matches_offline_and_replay_is_safe(self):
        import boto3
        from moto import mock_aws
        from lzta.profiles import ProfileStore, observation
        data = deepcopy(self.dataset)
        picked = {}
        for event in data['training']['records']:
            picked.setdefault(event['userIdentity']['arn'], event)
        data['training']['records'] = list(picked.values())
        with mock_aws():
            db = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
            table = db.create_table(TableName='profiles', KeySchema=[{'AttributeName': 'userId', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'userId', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
            client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
            store = ProfileStore(table, client)
            for event in data['training']['records']:
                self.assertTrue(store.add(observation(event)))
                self.assertFalse(store.add(observation(event)))
            for identity, expected in learn_profiles(data).items():
                actual = store.get(identity)
                actual['knownIPs'] = sorted(actual['knownIPs'])
                actual['userAgents'] = sorted(actual['userAgents'])
                self.assertEqual(actual, expected)
