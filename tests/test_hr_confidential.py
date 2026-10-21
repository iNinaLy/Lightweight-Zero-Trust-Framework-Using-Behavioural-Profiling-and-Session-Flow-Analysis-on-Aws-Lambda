"""Confidential company records require trusted HR role, plus upstream behavioural authorization."""
import base64
import contextlib
from datetime import datetime, timezone
import io
import json
import os
import unittest
from unittest.mock import patch
from unittest.mock import Mock
import test_portal
import test_lzta
from moto import mock_aws
from tools.seed_hr_console import fixtures
from lzta.portal import handle
from lzta.hr_confidential import COMPANY_PARTITION, payroll_csv


@mock_aws
class ConfidentialTests(unittest.TestCase):
    def setUp(self):
        test_portal.PortalTests.setUp(self)
        self.hr = test_portal.OWNER
        self.employee = 'arn:aws:iam::123456789012:user/ordinary'
        for owner, role in ((self.hr, 'hr'), (self.employee, 'employee')):
            self.table.put_item(Item={'ownerId': owner, 'entryId': 'employee#profile', 'portalRole': role,
                                      'name': 'Demo ' + role, 'synthetic': True})
        for item in fixtures(datetime(2026, 10, 21, tzinfo=timezone.utc)):
            self.table.put_item(Item=item)

    def call(self, method, resource, owner=None, employee_id='NS-1001', headers=None, body=None):
        event = {'httpMethod': method, 'resource': resource, 'headers': headers or {}, 'body': json.dumps(body) if body else None,
                 'pathParameters': {'employeeId': employee_id},
                 'requestContext': {'authorizer': {'principalId': owner or self.hr}, 'requestId': 'confidential-test'}}
        with contextlib.redirect_stdout(io.StringIO()):
            result = handle(event, self.table, self.s3, 'portal-test-files', test_portal.ORIGIN)
        return result['statusCode'], json.loads(result['body'])

    def test_hr_can_read_company_register_details_reviews_and_export(self):
        status, register = self.call('GET', '/api/v1/hr/payroll')
        self.assertEqual(status, 200)
        self.assertEqual(len(register['items']), 16)
        self.assertNotIn('bankAccount', register['items'][0])
        status, detail = self.call('GET', '/api/v1/hr/employees/{employeeId}')
        self.assertEqual(status, 200)
        self.assertTrue(detail['record']['bankAccount'].startswith('DEMO-BANK-'))
        self.assertEqual(self.call('GET', '/api/v1/hr/reviews')[0], 200)
        self.assertIn('managerNotes', self.call('GET', '/api/v1/hr/reviews/{employeeId}')[1]['record'])
        status, export = self.call('POST', '/api/v1/hr/payroll/export')
        self.assertEqual(status, 200)
        csv = base64.b64decode(export['contentBase64']).decode('utf-8-sig')
        self.assertEqual(export['recordCount'], 16)
        self.assertIn('DEMO-BANK-0001-NOT-VALID', csv)
        self.assertIn('DEMO ONLY - SYNTHETIC', csv)
        self.assertEqual(self.call('GET', '/api/v1/hr/summary')[1]['employeeCount'], 16)

    def test_employee_cannot_read_any_company_route_or_export_even_with_forged_role(self):
        for method, route in [('GET', '/api/v1/hr/summary'), ('GET', '/api/v1/hr/payroll'),
                              ('POST', '/api/v1/hr/payroll/export'), ('GET', '/api/v1/hr/employees/{employeeId}'),
                              ('GET', '/api/v1/hr/reviews'), ('GET', '/api/v1/hr/reviews/{employeeId}'),
                              ('GET', '/api/v1/hr/audit')]:
            with self.subTest(route=route), patch.object(self.table, 'query', wraps=self.table.query) as query:
                status, body = self.call(method, route, self.employee, headers={'X-Portal-Role': 'hr'}, body={'role': 'hr'})
                self.assertEqual(status, 403)
                self.assertEqual(body['reason'], 'hr_role_required')
                query.assert_not_called()
                self.assertNotIn('bankAccount', json.dumps(body))

    def test_missing_role_fails_closed_and_role_revocation_takes_effect(self):
        self.table.update_item(Key={'ownerId': self.hr, 'entryId': 'employee#profile'}, UpdateExpression='REMOVE portalRole')
        self.assertEqual(self.call('POST', '/api/v1/hr/payroll/export')[0], 403)

    def test_audit_records_real_exports_and_role_denials_without_payroll_payloads(self):
        self.call('POST', '/api/v1/hr/payroll/export')
        self.call('GET', '/api/v1/hr/payroll', self.employee)
        status, data = self.call('GET', '/api/v1/hr/audit')
        self.assertEqual(status, 200)
        self.assertTrue(any(item['action'] == 'payroll_export' and item['recordCount'] == 16 for item in data['items']))
        self.assertTrue(any(item['reason'] == 'hr_role_required' for item in data['items']))
        self.assertNotIn('DEMO-BANK-', json.dumps(data))

    def test_csv_formula_injection_is_neutralized_and_invalid_record_is_not_found(self):
        record = next(fixtures(datetime(2026, 10, 21, tzinfo=timezone.utc)))
        record['name'] = '=HYPERLINK("bad")'
        self.assertIn("'=HYPERLINK", payroll_csv([record]).decode('utf-8-sig'))
        self.assertEqual(self.call('GET', '/api/v1/hr/employees/{employeeId}', employee_id='../other')[0], 404)

    def test_employee_session_exposes_role_denial_even_when_behaviour_matches(self):
        from lzta import portal_session
        from lzta.scoring import Rules
        event = test_lzta.api_event()
        profile = {**test_lzta.PROFILE, 'userId': self.employee}
        config = {'identities': {'alice': self.employee}, 'issuer': 'https://issuer.example', 'audience': 'example',
                  'jwks_url': 'https://issuer.example/keys', 'rules': Rules.from_dict(test_lzta.CONFIG)}
        with patch.dict(os.environ, {'PORTAL_ORIGIN': test_portal.ORIGIN}), \
             patch.object(portal_session, 'settings', return_value=config), \
             patch.object(portal_session, 'verify', return_value='alice'), \
             patch.object(portal_session, 'store', return_value=Mock(get=Mock(return_value=profile))), \
             patch.object(portal_session, 'portal_clients', return_value=(self.table, None)):
            result = portal_session.lambda_handler(event, None)
        data = json.loads(result['body'])
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(data['decision'], 'Allow')
        self.assertFalse(data['roleAllowed'])
        self.assertEqual(data['role'], 'employee')

    def test_both_role_and_behaviour_are_required_for_export(self):
        from lzta.authorizer import authorize
        from lzta.scoring import Rules
        for owner, ip, expected in ((self.hr, '192.0.2.1', 200), (self.employee, '192.0.2.1', 403),
                                    (self.hr, '198.51.100.77', 403)):
            event = test_lzta.api_event()
            event.update(httpMethod='POST', resource='/api/v1/hr/payroll/export',
                         methodArn='arn:aws:execute-api:us-east-1:123456789012:api/demo/POST/api/v1/hr/payroll/export')
            event['requestContext']['identity']['sourceIp'] = ip
            profile = {**test_lzta.PROFILE, 'userId': owner, 'actionCounts': {'hr:ExportPayroll': 1}}
            config = {'identities': {'alice': owner}, 'actions': {'POST /api/v1/hr/payroll/export': 'hr:ExportPayroll'},
                      'issuer': 'https://issuer.example', 'audience': 'example', 'jwks_url': 'https://issuer.example/keys',
                      'rules': Rules.from_dict({'decision_policy': 'deny_on_any_anomaly', 'sensitive_actions': ['hr:ExportPayroll']})}
            with contextlib.redirect_stdout(io.StringIO()):
                result = authorize(event, config, Mock(get=Mock(return_value=profile)), verifier=Mock(return_value='alice'))
            effect = result['policyDocument']['Statement'][0]['Effect']
            actual = self.call('POST', '/api/v1/hr/payroll/export', owner)[0] if effect == 'Allow' else 403
            self.assertEqual(actual, expected)
