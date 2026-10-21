"""Portal data isolation and file lifecycle using emulated AWS storage."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import boto3
from moto import mock_aws
from lzta.portal import handle

OWNER = 'arn:aws:iam::123456789012:user/portal-demo'
ORIGIN = 'https://portal.example'


@mock_aws
class PortalTests(unittest.TestCase):
    def setUp(self):
        self.table = boto3.resource('dynamodb', region_name='us-east-1').create_table(
            TableName='documents', BillingMode='PAY_PER_REQUEST',
            KeySchema=[{'AttributeName': 'ownerId', 'KeyType': 'HASH'}, {'AttributeName': 'entryId', 'KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': name, 'AttributeType': 'S'} for name in ('ownerId', 'entryId')])
        self.s3 = boto3.client('s3', region_name='us-east-1')
        self.s3.create_bucket(Bucket='portal-test-files')

    def call(self, method, resource, body=None, document_id=None, owner=OWNER, query=None):
        event = {'httpMethod': method, 'resource': resource, 'body': json.dumps(body) if body is not None else None,
                 'pathParameters': {'documentId': document_id}, 'queryStringParameters': query,
                 'requestContext': {'authorizer': {'principalId': owner}, 'requestId': 'test-request',
                                    'identity': {'sourceIp': '192.0.2.1'}}}
        with contextlib.redirect_stdout(io.StringIO()):
            result = handle(event, self.table, self.s3, 'portal-test-files', ORIGIN)
        self.assertEqual(result['headers']['Access-Control-Allow-Origin'], ORIGIN)
        return result['statusCode'], json.loads(result['body'])

    def upload(self):
        status, body = self.call('POST', '/documents', {'name': 'plan.txt', 'category': 'Project',
                                                      'contentBase64': base64.b64encode(b'Project plan').decode()})
        self.assertEqual(status, 201)
        return body['document']['id']

    def test_document_lifecycle_and_activity(self):
        document_id = self.upload()
        status, listing = self.call('GET', '/documents')
        self.assertEqual(status, 200)
        self.assertEqual(listing['items'][0]['name'], 'plan.txt')
        self.assertNotIn('objectKey', listing['items'][0])
        self.assertEqual(self.call('PATCH', '/documents/{documentId}', {'name': 'updated.txt'}, document_id)[0], 200)
        status, body = self.call('GET', '/documents/{documentId}/download', document_id=document_id)
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(body['contentBase64']), b'Project plan')
        self.assertEqual(body['name'], 'updated.txt')
        self.assertEqual(self.call('DELETE', '/documents/{documentId}', document_id=document_id)[0], 200)
        self.assertEqual(self.call('GET', '/documents')[1]['items'], [])
        self.assertEqual(self.call('GET', '/documents/{documentId}/download', document_id=document_id)[0], 404)
        actions = {item['action'] for item in self.call('GET', '/activity')[1]['items']}
        self.assertEqual(actions, {'upload', 'rename', 'download', 'delete'})

    def test_other_user_cannot_read_change_or_delete_document(self):
        document_id = self.upload()
        other = 'arn:aws:iam::123456789012:user/other'
        self.assertEqual(self.call('GET', '/documents', owner=other)[1]['items'], [])
        self.assertEqual(self.call('GET', '/activity', owner=other)[1]['items'], [])
        for method, path, body in [('GET', '/documents/{documentId}/download', None),
                                   ('PATCH', '/documents/{documentId}', {'name': 'stolen.txt'}),
                                   ('DELETE', '/documents/{documentId}', None)]:
            self.assertEqual(self.call(method, path, body, document_id, other)[0], 404)
        self.assertEqual(self.call('GET', '/documents/{documentId}/download', document_id=document_id)[0], 200)

    def test_upload_validation_and_missing_identity(self):
        for body in ([], {}, {'name': '../bad.txt', 'contentBase64': 'eA=='},
                     {'name': 'file.txt', 'contentBase64': '%%%not-base64'},
                     {'name': 'file.txt', 'contentBase64': ''},
                     {'name': 'file.txt', 'contentBase64': 'eA==', 'category': 'Unknown'}):
            self.assertEqual(self.call('POST', '/documents', body)[0], 400)
        self.assertEqual(self.call('GET', '/documents', owner=None)[0], 401)
        self.assertEqual(self.call('GET', '/documents')[1]['items'], [])

    def test_pagination_cannot_cross_owners(self):
        cursor = base64.urlsafe_b64encode(json.dumps({'ownerId': 'other', 'entryId': 'document#test'}).encode()).decode()
        self.assertEqual(self.call('GET', '/documents', query={'cursor': cursor})[0], 400)

    def test_session_requires_jwt_and_never_writes_profile(self):
        from lzta import portal_session
        with patch.dict(os.environ, {'PORTAL_ORIGIN': ORIGIN}), patch.object(portal_session, 'settings', return_value={}), \
             patch.object(portal_session, 'store') as store:
            result = portal_session.lambda_handler({'headers': {}}, None)
        self.assertEqual(result['statusCode'], 401)
        store.assert_not_called()


if __name__ == '__main__':
    unittest.main()
