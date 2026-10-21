"""Authenticated session information; never enrolls or modifies behaviour profiles."""
from datetime import datetime, timezone
import os

from lzta.authorizer import settings, store
from lzta.identity import verify
from lzta.logging import emit
from lzta.portal import response, clients as portal_clients
from lzta.hr_confidential import identity
from lzta.scoring import Request, evaluate, normalize_ip


def lambda_handler(event, context):
    origin = os.environ["PORTAL_ORIGIN"]
    try:
        config = settings()
        headers = {key.lower(): value for key, value in (event.get("headers") or {}).items()}
        parts = headers.get("authorization", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return response(401, {"message": "Please sign in"}, origin)
        subject = verify(parts[1], config["issuer"], config["audience"], config["jwks_url"])
    except Exception as error:
        emit("portal_session_error", phase="authentication", errorType=type(error).__name__)
        return response(401, {"message": "Your session could not be verified. Please sign in again."}, origin)
    user = config["identities"].get(subject)
    if not user:
        return response(403, {"message": "This account is not configured for the demonstration workspace"}, origin)
    try:
        context = event["requestContext"]
        when = datetime.fromtimestamp(int(context["requestTimeEpoch"]) / 1000, timezone.utc)
        source = normalize_ip(context["identity"]["sourceIp"])
        agent = headers.get("user-agent", "")
        profile = store().get(user)
        decision = evaluate(Request(user, source, agent, "hr:ViewEmployee", when), profile, config["rules"])
        table, _ = portal_clients()
        actor = identity(table, user)
        return response(200, {"subject": subject, "decision": decision.verdict,
                              **actor, "roleAllowed": actor["role"] == "hr",
                              "anomalies": list(decision.anomalies), "profilePresent": bool(profile),
                              "observed": {"sourceIp": source, "userAgent": agent, "utcHour": when.hour},
                              "baselinePolicy": "deny_on_any_anomaly"}, origin)
    except Exception as error:
        emit("portal_session_error", phase="profile_lookup", errorType=type(error).__name__)
        return response(503, {"message": "Could not check your baseline. Please try again."}, origin)
