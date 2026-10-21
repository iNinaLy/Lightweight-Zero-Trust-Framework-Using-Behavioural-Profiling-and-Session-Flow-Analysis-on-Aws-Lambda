"""HR ownership, payroll privacy, leave state transitions, and input boundaries."""
import base64
from datetime import datetime, timedelta, timezone

import unittest
import test_portal
from moto import mock_aws

OWNER = test_portal.OWNER


@mock_aws
class HrTests(unittest.TestCase):
    def setUp(self):
        test_portal.PortalTests.setUp(self)
        for owner, name in ((OWNER, 'Aisha Rahman'), ('arn:aws:iam::123456789012:user/other', 'Other Employee')):
            self.table.put_item(Item={'ownerId': owner, 'entryId': 'employee#profile', 'name': name,
                                      'employeeId': name[:3], 'department': 'Product', 'annualLeaveEntitlement': 20})
        self.table.put_item(Item={
            'ownerId': OWNER, 'entryId': 'payslip#2026-09', 'id': '2026-09', 'period': '2026-09',
            'periodLabel': 'September 2026', 'paymentDate': '2026-09-25', 'basicPayCents': 620000,
            'allowanceCents': 30000, 'deductionsCents': {'Illustrative deduction': 93700}, 'netPayCents': 556300})
        tomorrow = datetime.now(timezone(timedelta(hours=8))).date() + timedelta(days=1)
        while tomorrow.weekday() > 4:
            tomorrow += timedelta(days=1)
        self.leave = {'type': 'Annual leave', 'startDate': tomorrow.isoformat(), 'endDate': tomorrow.isoformat(),
                      'reason': 'Family appointment'}

    def call_hr(self, method, resource, body=None, record_id=None, owner=OWNER):
        import contextlib
        import io
        import json
        from lzta.portal import handle
        from test_portal import ORIGIN
        event = {'httpMethod': method, 'resource': resource, 'body': json.dumps(body) if body is not None else None,
                 'pathParameters': {'leaveId': record_id, 'payslipId': record_id, 'policyId': record_id},
                 'requestContext': {'authorizer': {'principalId': owner}, 'requestId': 'hr-test'}}
        with contextlib.redirect_stdout(io.StringIO()):
            result = handle(event, self.table, self.s3, 'portal-test-files', ORIGIN)
        return result['statusCode'], json.loads(result['body'])

    def test_payroll_and_profile_are_owner_scoped(self):
        other = 'arn:aws:iam::123456789012:user/other'
        self.assertEqual(self.call_hr('GET', '/employee')[1]['employee']['name'], 'Aisha Rahman')
        self.assertEqual(self.call_hr('GET', '/employee', owner=other)[1]['employee']['name'], 'Other Employee')
        self.assertEqual(len(self.call_hr('GET', '/payslips')[1]['items']), 1)
        self.assertEqual(self.call_hr('GET', '/payslips', owner=other)[1]['items'], [])
        self.assertNotIn('deductionsCents', self.call_hr('GET', '/payslips')[1]['items'][0])
        self.assertEqual(self.call_hr('GET', '/payslips/{payslipId}', record_id='2026-09', owner=other)[0], 404)
        self.assertEqual(self.call_hr('GET', '/payslips/{payslipId}', record_id='2026-09')[1]['payslip']['netPayCents'], 556300)
        self.assertEqual(self.call_hr('GET', '/payslips/{payslipId}/download', record_id='2026-09', owner=other)[0], 404)
        status, data = self.call_hr('GET', '/payslips/{payslipId}/download', record_id='2026-09')
        self.assertEqual(status, 200)
        pdf = base64.b64decode(data['contentBase64'])
        self.assertTrue(pdf.startswith(b'%PDF-1.4'))
        self.assertTrue(pdf.endswith(b'%%EOF\n'))
        self.assertIn(b'Aisha Rahman', pdf)
        self.assertNotIn(b'Other Employee', pdf)
        self.assertIn(b'5,563.00', pdf)

    def test_leave_create_edit_cancel_and_cross_owner_denial(self):
        status, result = self.call_hr('POST', '/leave-requests', self.leave)
        self.assertEqual(status, 201)
        record_id = result['request']['id']
        self.assertEqual(result['request']['status'], 'Pending')
        self.assertNotIn('ownerId', result['request'])
        for method in ('PATCH', 'DELETE'):
            self.assertEqual(self.call_hr(method, '/leave-requests/{leaveId}', self.leave, record_id,
                                          owner='arn:aws:iam::123456789012:user/other')[0], 404)
        edited = {**self.leave, 'reason': 'Updated family appointment'}
        self.assertEqual(self.call_hr('PATCH', '/leave-requests/{leaveId}', edited, record_id)[1]['request']['reason'], edited['reason'])
        self.assertEqual(self.call_hr('DELETE', '/leave-requests/{leaveId}', record_id=record_id)[1]['request']['status'], 'Cancelled')
        self.assertEqual(self.call_hr('PATCH', '/leave-requests/{leaveId}', edited, record_id)[0], 403)
        self.assertEqual(len(self.call_hr('GET', '/leave-requests')[1]['items']), 1)

    def test_employees_cannot_self_approve_or_mutate_approved_leave(self):
        for field, value in [('status', 'Approved'), ('ownerId', 'other'), ('days', 0)]:
            self.assertEqual(self.call_hr('POST', '/leave-requests', {**self.leave, field: value})[0], 400)
        result = self.call_hr('POST', '/leave-requests', self.leave)[1]['request']
        self.table.update_item(Key={'ownerId': OWNER, 'entryId': 'leave#' + result['id']},
                               UpdateExpression='SET #status = :approved',
                               ExpressionAttributeNames={'#status': 'status'}, ExpressionAttributeValues={':approved': 'Approved'})
        self.assertEqual(self.call_hr('PATCH', '/leave-requests/{leaveId}', self.leave, result['id'])[0], 403)
        self.assertEqual(self.call_hr('DELETE', '/leave-requests/{leaveId}', record_id=result['id'])[0], 403)

    def test_leave_validation_and_policy_access(self):
        for changes in ({'endDate': '2020-01-01'}, {'reason': 'x'}, {'type': 'Fake type'}, {'startDate': '2026-99-99'}):
            self.assertEqual(self.call_hr('POST', '/leave-requests', {**self.leave, **changes})[0], 400)
        self.assertEqual(self.call_hr('POST', '/leave-requests', [])[0], 400)
        self.assertEqual(self.call_hr('GET', '/policies')[0], 200)
        self.assertEqual(self.call_hr('GET', '/policies/{policyId}', record_id='payroll-guide')[0], 200)
        self.assertEqual(self.call_hr('GET', '/policies/{policyId}', record_id='does-not-exist')[0], 404)
        self.assertEqual(self.call_hr('GET', '/employee', owner='arn:aws:iam::123456789012:user/unprovisioned')[0], 404)
