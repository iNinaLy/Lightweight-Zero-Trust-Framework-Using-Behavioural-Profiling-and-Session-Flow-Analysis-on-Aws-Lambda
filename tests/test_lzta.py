import contextlib
import copy
from datetime import datetime, timezone
from decimal import Decimal
import gzip
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lzta.authorizer import authorize
from lzta.baseline import process
from lzta.profiles import observation, ProfileStore
from lzta.scoring import Decision, Request, Rules, evaluate

USER = "arn:aws:iam::123456789012:user/alice"
CONFIG = {"weights": {"unknown_ip": 50, "off_hours": 25, "unknown_user_agent": 15,
                      "unusual_sensitive_action": 30},
          "deny_threshold": 70, "deny_comparison": "gte", "sensitive_actions": ["iam:CreateUser"]}
PROFILE = {"userId": USER, "knownIPs": {"192.0.2.1"}, "userAgents": {"known-agent"},
           "hourHistogram": {"9": Decimal(4)}, "actionCounts": {"s3:ListBuckets": Decimal(4)}}


def request(**overrides):
    values = dict(user_id=USER, source_ip="192.0.2.1", user_agent="known-agent", action="s3:ListBuckets",
                  time=datetime(2026, 1, 1, 9, tzinfo=timezone.utc))
    values.update(overrides)
    return Request(**values)


def cloudtrail(event_id="event-1"):
    return {"eventID": event_id, "userIdentity": {"type": "IAMUser", "arn": USER},
            "sourceIPAddress": "192.0.2.1", "eventTime": "2026-01-01T09:00:00Z",
            "userAgent": "known-agent", "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets"}


def api_event():
    return {"type": "REQUEST", "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api/dev/GET/protected",
            "httpMethod": "GET", "resource": "/protected",
            "headers": {"Authorization": "Bearer signed-token", "User-Agent": "known-agent"},
            "requestContext": {"identity": {"sourceIp": "192.0.2.1"}, "requestId": "r1",
                               "requestTimeEpoch": 1767258000000}}


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.rules = Rules.from_dict(CONFIG)

    def test_normal_and_each_single_anomaly(self):
        for changes, score, signal in [({}, 0, None), ({"source_ip": "198.51.100.1"}, 50, "unknown_ip"),
                ({"user_agent": "new"}, 15, "unknown_user_agent"),
                ({"time": datetime(2026, 1, 1, 23, tzinfo=timezone.utc)}, 25, "off_hours"),
                ({"action": "iam:CreateUser"}, 30, "unusual_sensitive_action")]:
            with self.subTest(signal=signal):
                result = evaluate(request(**changes), PROFILE, self.rules)
                self.assertEqual(result.score, score)
                self.assertEqual(result.verdict, "Allow")
                self.assertEqual(result.anomalies, () if signal is None else (signal,))

    def test_exact_threshold_and_combinations(self):
        # 25 + 30 + 15 = 70, including no unknown-IP anomaly.
        result = evaluate(request(user_agent="new", action="iam:CreateUser",
                          time=datetime(2026, 1, 1, 23, tzinfo=timezone.utc)), PROFILE, self.rules)
        self.assertEqual((result.score, result.verdict), (70, "Deny"))
        result = evaluate(request(source_ip="198.51.100.1", user_agent="new"), PROFILE, self.rules)
        self.assertEqual((result.score, result.verdict), (65, "Allow"))
        result = evaluate(request(source_ip="198.51.100.1", action="iam:CreateUser"), PROFILE, self.rules)
        self.assertEqual((result.score, result.verdict), (80, "Deny"))

    def test_missing_or_corrupt_profile_denied(self):
        for item in (None, {}, {**PROFILE, "hourHistogram": {}}, {**PROFILE, "actionCounts": {"x": -1}},
                     {**PROFILE, "userId": "someone-else"}):
            self.assertEqual(evaluate(request(), item, self.rules).verdict, "Deny")

    def test_zero_frequency_is_off_hours(self):
        result = evaluate(request(), {**PROFILE, "hourHistogram": {"9": 0}}, self.rules)
        self.assertIn("off_hours", result.anomalies)

    def test_invalid_configuration_rejected(self):
        for weight in (None, True, -1, "NaN", "Infinity"):
            data = copy.deepcopy(CONFIG)
            data["weights"]["unknown_ip"] = weight
            with self.assertRaises(ValueError):
                Rules.from_dict(data)


class AuthorizerTests(unittest.TestCase):
    def setUp(self):
        self.config = {"rules": Rules.from_dict(CONFIG), "identities": {"alice": USER},
                       "actions": {"GET /protected": "s3:ListBuckets"},
                       "issuer": "https://issuer.example", "audience": "lzta", "jwks_url": "https://issuer.example/keys"}
        self.store = Mock()
        self.store.get.return_value = PROFILE
        self.verifier = Mock(return_value="alice")

    def run_auth(self, event):
        with contextlib.redirect_stdout(io.StringIO()) as logs:
            result = authorize(event, self.config, self.store, self.verifier)
        records = [json.loads(line) for line in logs.getvalue().splitlines()]
        self.assertNotIn("signed-token", logs.getvalue())
        return result, records[-1]

    def test_allow_policy_is_method_scoped(self):
        result, log = self.run_auth(api_event())
        self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Allow")
        self.assertEqual(result["policyDocument"]["Statement"][0]["Resource"], api_event()["methodArn"])
        self.assertEqual(log["riskScore"], 0)

    def test_spoofed_context_headers_ignored(self):
        event = api_event()
        event["headers"].update({"X-Forwarded-For": "192.0.2.1", "X-User-Id": "admin", "X-Action": "safe"})
        event["requestContext"]["identity"]["sourceIp"] = "198.51.100.1"
        event["requestContext"]["requestTimeEpoch"] += 14 * 3600 * 1000
        _, log = self.run_auth(event)
        self.assertEqual((log["riskScore"], log["verdict"]), (75, "Deny"))
        self.store.get.assert_called_once_with(USER)

    def test_invalid_token_denies_without_profile_read(self):
        self.verifier.side_effect = ValueError("bad token")
        _, log = self.run_auth(api_event())
        self.assertEqual(log["verdict"], "Deny")
        self.store.get.assert_not_called()

    def test_store_failure_denies(self):
        self.store.get.side_effect = RuntimeError("unavailable")
        _, log = self.run_auth(api_event())
        self.assertEqual(log["verdict"], "Deny")

    def test_unmapped_identity_and_route_deny(self):
        self.verifier.return_value = "unmapped"
        _, log = self.run_auth(api_event())
        self.assertEqual(log["anomalies"], ["unmapped_identity"])
        self.store.get.assert_not_called()
        self.verifier.return_value = "alice"
        event = api_event()
        event["resource"] = "/other"
        _, log = self.run_auth(event)
        self.assertEqual(log["anomalies"], ["unmapped_action"])


class IngestionTests(unittest.TestCase):
    def test_features_and_invalid_events(self):
        self.assertEqual(observation(cloudtrail())["action"], "s3:ListBuckets")
        for bad in ({}, None, {**cloudtrail(), "sourceIPAddress": "AWS Internal"},
                    {**cloudtrail(), "eventTime": "2026-01-01T09:00:00"}):
            self.assertIsNone(observation(bad))

    def test_gzip_s3_batch_and_duplicate_delivery(self):
        data = gzip.compress(json.dumps({"Records": [cloudtrail(), cloudtrail(), {}]}).encode())
        s3 = Mock()
        s3.get_object.side_effect = lambda **kw: {"Body": io.BytesIO(data)}
        store = Mock()
        seen = set()
        def add(item):
            if item["eventId"] in seen:
                return False
            seen.add(item["eventId"])
            return True
        store.add.side_effect = add
        event = {"Records": [{"eventSource": "aws:s3", "eventName": "ObjectCreated:Put",
                 "s3": {"bucket": {"name": "logs"}, "object": {"key": "prefix/log.json.gz"}}}]}
        with contextlib.redirect_stdout(io.StringIO()):
            first = process(event, s3, store, "logs", "prefix/")
            second = process(event, s3, store, "logs", "prefix/")
        self.assertEqual(first["observations"], 1)
        self.assertEqual(second["observations"], 0)
        self.assertEqual(first["skipped"], 1)
        with self.assertRaises(ValueError):
            process(event, s3, store, "another-bucket", "prefix/")


if __name__ == "__main__":
    unittest.main()
