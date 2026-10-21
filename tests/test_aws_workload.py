"""AWS routines and permission boundaries are independent of novelty."""
from copy import deepcopy
import unittest
from tools.generate_aws_workload import build_aws_workload
from tools.evaluate_hr_workload import evaluate_workload, learn_profiles, timestamp


class AWSWorkloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = build_aws_workload(training_days=7, repeats=1)

    def test_reproducible_aws_events_and_overtime_hybrid_learning(self):
        self.assertEqual(self.data, build_aws_workload(training_days=7, repeats=1))
        profiles = learn_profiles(self.data)
        people = {p['id']: profiles[p['profile_identity']] for p in self.data['personas']}
        # 19:00 and 20:00 Malaysia time are 11:00 and 12:00 UTC.
        self.assertTrue({'11', '12'} <= people['sarah-cloud-ops']['hourHistogram'].keys())
        self.assertEqual(people['mei-hybrid-engineer']['knownIPs'], ['192.0.2.10', '192.0.2.31'])
        self.assertEqual(people['amir-office-analyst']['knownIPs'], ['192.0.2.21'])
        self.assertTrue(all(e['eventSource'].endswith('.amazonaws.com') for e in self.data['training']['records']))
        self.assertTrue(all(not e['eventName'].startswith('ViewPayroll') for e in self.data['training']['records']))

    def test_context_change_then_scope_violation_has_distinct_expectations(self):
        cases = self.data['evaluation']['cases']
        for scenario in ('legitimate_starts_hybrid', 'legitimate_unexpected_overtime'):
            benign = [c for c in cases if c['scenario'] == scenario]
            self.assertTrue(benign)
            self.assertTrue(all(c['label'] == 'legitimate' and c['expected_two_stage'] == 'flag_and_continue' for c in benign))
        violations = [c for c in cases if not c['request']['permission_allowed']]
        self.assertTrue(violations)
        self.assertTrue(all(c['label'] == 'attack' and c['expected_two_stage'] == 'deny_by_permission_boundary' for c in violations))
        report = evaluate_workload(self.data)
        self.assertTrue(all(d['combined_baseline_verdict'] == 'Deny' for d in report['decisions'] if d['permission_fixture'] == 'Deny'))

    def test_permission_annotation_cannot_override_fixture(self):
        data = deepcopy(self.data)
        next(c for c in data['evaluation']['cases'] if not c['request']['permission_allowed'])['request']['permission_allowed'] = True
        with self.assertRaises(ValueError):
            evaluate_workload(data)
