"""Real JWT crypto and emulated DynamoDB transaction checks; no AWS calls."""
import copy
from datetime import datetime, timedelta, timezone
import json
import gzip
import io
import contextlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import boto3
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from moto import mock_aws
from lzta.identity import verify
from lzta.profiles import ProfileStore, observation
from test_lzta import cloudtrail, USER


class JwtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def claims(self):
        now = datetime.now(timezone.utc)
        return {"sub": "alice", "iss": "https://issuer.example", "aud": "lzta",
                "iat": now, "exp": now + timedelta(minutes=5)}

    def verify_token(self, token):
        client = Mock()
        client.get_signing_key_from_jwt.return_value = Mock(key=self.key.public_key())
        with patch("lzta.identity.jwks_client", return_value=client):
            return verify(token, "https://issuer.example", "lzta", "https://issuer.example/keys")

    def test_valid_signed_jwt(self):
        token = jwt.encode(self.claims(), self.key, algorithm="RS256")
        self.assertEqual(self.verify_token(token), "alice")

    def test_expired_wrong_audience_and_issuer_rejected(self):
        for override in ({"exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
                         {"aud": "other"}, {"iss": "https://other.example"}):
            with self.subTest(override=override), self.assertRaises(jwt.InvalidTokenError):
                self.verify_token(jwt.encode({**self.claims(), **override}, self.key, algorithm="RS256"))

    def test_signature_and_algorithm_confusion_rejected(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for token in (jwt.encode(self.claims(), other_key, algorithm="RS256"),
                      jwt.encode(self.claims(), "test-secret-only-for-algorithm-rejection", algorithm="HS256")):
            with self.assertRaises(jwt.InvalidTokenError):
                self.verify_token(token)


@mock_aws
class DynamoTests(unittest.TestCase):
    def setUp(self):
        resource = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = resource.create_table(TableName="profiles", BillingMode="PAY_PER_REQUEST",
                    KeySchema=[{"AttributeName": "userId", "KeyType": "HASH"}],
                    AttributeDefinitions=[{"AttributeName": "userId", "AttributeType": "S"}])
        self.store = ProfileStore(self.table, boto3.client("dynamodb", region_name="us-east-1"))

    def test_atomic_counts_replay_and_out_of_order(self):
        self.assertTrue(self.store.add(observation(cloudtrail("first"))))
        self.assertFalse(self.store.add(observation(cloudtrail("first"))))
        later = cloudtrail("second")
        later.update(eventTime="2026-01-02T23:00:00Z", sourceIPAddress="198.51.100.2", eventName="GetObject")
        self.assertTrue(self.store.add(observation(later)))
        earlier = cloudtrail("third")
        earlier["eventTime"] = "2025-12-31T09:00:00Z"
        self.assertTrue(self.store.add(observation(earlier)))
        profile = self.store.get(USER)
        self.assertEqual(profile["knownIPs"], {"192.0.2.1", "198.51.100.2"})
        self.assertEqual(profile["hourHistogram"], {"9": 2, "23": 1})
        self.assertEqual(profile["actionCounts"], {"s3:ListBuckets": 2, "s3:GetObject": 1})
        self.assertEqual(self.table.scan()["Count"], 4)  # One profile, three receipts.

    def test_backend_errors_not_swallowed_as_duplicates(self):
        self.store.transaction_client = Mock()
        self.store.transaction_client.transact_write_items.side_effect = RuntimeError("database down")
        with self.assertRaises(RuntimeError):
            self.store.add(observation(cloudtrail()))

    def test_s3_to_profile_to_jwt_authorizer_handlers(self):
        from lzta import baseline, authorizer
        from test_lzta import api_event, CONFIG
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-cloudtrail-logs")
        prefix = "AWSLogs/123456789012/CloudTrail/"
        key = prefix + "us-east-1/example.json.gz"
        s3.put_object(Bucket="test-cloudtrail-logs", Key=key,
                      Body=gzip.compress(json.dumps({"Records": [cloudtrail()]}).encode()))
        env = {"AWS_DEFAULT_REGION": "us-east-1", "PROFILES_TABLE": "profiles",
               "LOG_BUCKET": "test-cloudtrail-logs", "LOG_PREFIX": prefix,
               "RISK_WEIGHTS_JSON": json.dumps(CONFIG["weights"]), "DENY_THRESHOLD": "70",
               "SENSITIVE_ACTIONS_JSON": '["iam:CreateUser"]',
               "IDENTITY_MAP_JSON": json.dumps({"alice": USER}),
               "ROUTE_ACTION_MAP_JSON": '{"GET /protected":"s3:ListBuckets"}',
               "JWT_ISSUER": "https://issuer.example", "JWT_AUDIENCE": "lzta",
               "JWT_JWKS_URL": "https://issuer.example/keys"}
        keypair = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        token = jwt.encode({"sub": "alice", "iss": env["JWT_ISSUER"], "aud": "lzta",
                            "iat": now, "exp": now + timedelta(minutes=5)}, keypair, algorithm="RS256")
        client = Mock()
        client.get_signing_key_from_jwt.return_value = Mock(key=keypair.public_key())
        caches = (baseline.clients, authorizer.settings, authorizer.store)
        for cached in caches:
            cached.cache_clear()
        try:
            with patch.dict(os.environ, env), patch("lzta.identity.jwks_client", return_value=client), contextlib.redirect_stdout(io.StringIO()):
                event = {"Records": [{"eventSource": "aws:s3", "eventName": "ObjectCreated:Put",
                         "s3": {"bucket": {"name": env["LOG_BUCKET"]}, "object": {"key": key}}}]}
                self.assertEqual(baseline.lambda_handler(event, None)["observations"], 1)
                self.assertEqual(baseline.lambda_handler(event, None)["observations"], 0)
                incoming = api_event()
                incoming["headers"]["Authorization"] = "Bearer " + token
                result = authorizer.lambda_handler(incoming, None)
                self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Allow")
                incoming["requestContext"]["identity"]["sourceIp"] = "198.51.100.2"
                incoming["requestContext"]["requestTimeEpoch"] += 14 * 3600 * 1000
                result = authorizer.lambda_handler(incoming, None)
                self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Deny")
        finally:
            for cached in caches:
                cached.cache_clear()


if __name__ == "__main__":
    unittest.main()
