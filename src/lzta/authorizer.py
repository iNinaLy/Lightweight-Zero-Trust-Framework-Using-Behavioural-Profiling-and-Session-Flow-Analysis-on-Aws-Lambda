"""Online pipeline: authenticated request -> profile -> deterministic Allow/Deny."""
import json
import os
import time
from datetime import datetime, timezone
from functools import lru_cache
from lzta.identity import verify
from lzta.logging import emit
from lzta.profiles import ProfileStore
from lzta.scoring import Request, Rules, evaluate, normalize_ip


def policy(user, effect, arn):
    return {"principalId": user, "policyDocument": {
        "Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke", "Effect": effect, "Resource": arn}]
    }}


def mapping(value, name):
    data = json.loads(value)
    if not isinstance(data, dict) or not data or any(
        not isinstance(k, str) or not k or not isinstance(v, str) or not v for k, v in data.items()
    ):
        raise ValueError(f"{name} must be a non-empty string mapping")
    return data


@lru_cache(maxsize=1)
def settings():
    identities = mapping(os.environ["IDENTITY_MAP_JSON"], "identity map")
    if any(not arn.startswith("arn:") for arn in identities.values()):
        raise ValueError("Identity mapping values must be CloudTrail principal ARNs")
    return {
        "rules": Rules.from_dict({
            "weights": json.loads(os.environ["RISK_WEIGHTS_JSON"]),
            "deny_threshold": os.environ["DENY_THRESHOLD"],
            "deny_comparison": "gte",
            "sensitive_actions": json.loads(os.environ["SENSITIVE_ACTIONS_JSON"]),
        }),
        "identities": identities,
        "actions": mapping(os.environ["ROUTE_ACTION_MAP_JSON"], "route action map"),
        "issuer": os.environ["JWT_ISSUER"], "audience": os.environ["JWT_AUDIENCE"],
        "jwks_url": os.environ["JWT_JWKS_URL"],
    }


@lru_cache(maxsize=1)
def store():
    import boto3
    return ProfileStore(boto3.resource("dynamodb").Table(os.environ["PROFILES_TABLE"]))


def authorize(event, config, profiles, verifier=verify):
    started = time.perf_counter()
    user, source, score, anomalies, verdict = "unauthenticated", None, None, ["invalid_request"], "Deny"
    arn = event.get("methodArn")
    if not isinstance(arn, str) or ":execute-api:" not in arn:
        raise ValueError("Missing API Gateway methodArn")
    try:
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        token = headers.get("authorization", "").split()
        if len(token) != 2 or token[0].lower() != "bearer":
            raise ValueError("Missing bearer token")
        subject = verifier(token[1], config["issuer"], config["audience"], config["jwks_url"])
        user = config["identities"].get(subject)
        if not user:
            user = "unmapped"
            anomalies = ["unmapped_identity"]
        else:
            context = event["requestContext"]
            source = normalize_ip(context["identity"]["sourceIp"])
            # No X-Forwarded-For or client-supplied time/action/identity headers.
            when = datetime.fromtimestamp(int(context["requestTimeEpoch"]) / 1000, timezone.utc)
            route = f'{event["httpMethod"]} {event["resource"]}'
            action = config["actions"].get(route)
            if not action:
                anomalies = ["unmapped_action"]
            else:
                agent = headers.get("user-agent", "")
                if not isinstance(agent, str) or not agent:
                    raise ValueError("Missing User-Agent")
                decision = evaluate(Request(user, source, agent, action, when), profiles.get(user), config["rules"])
                verdict, score, anomalies = decision.verdict, decision.score, list(decision.anomalies)
    except Exception as exc:
        # Backend, token, and input errors must never turn into an Allow.
        verdict, score, anomalies = "Deny", None, ["evaluation_error"]
        emit("authorization_error", errorType=type(exc).__name__)
    emit("access_decision", user=user, ip=source, riskScore=score, anomalies=anomalies,
         verdict=verdict, requestId=event.get("requestContext", {}).get("requestId"),
         durationMs=round((time.perf_counter() - started) * 1000, 3))
    return policy(user, verdict, arn)


def lambda_handler(event, context):
    try:
        config, profiles = settings(), store()
    except Exception as exc:
        emit("authorization_error", errorType=type(exc).__name__)
        emit("access_decision", user="unavailable", ip=None, riskScore=None,
             anomalies=["configuration_error"], verdict="Deny")
        return policy("unavailable", "Deny", event["methodArn"])
    return authorize(event, config, profiles)
