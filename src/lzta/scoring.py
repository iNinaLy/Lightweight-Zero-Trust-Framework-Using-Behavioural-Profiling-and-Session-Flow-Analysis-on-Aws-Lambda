"""Pure rule engine. Deployment configuration supplies every scoring value."""
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address

SIGNALS = ("unknown_ip", "off_hours", "unknown_user_agent", "unusual_sensitive_action")


def number(value):
    if isinstance(value, bool):
        raise ValueError("Boolean is not a scoring value")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("Invalid scoring value") from exc
    if not result.is_finite() or result < 0:
        raise ValueError("Scoring values must be finite and non-negative")
    return result


def normalize_ip(value):
    return str(ip_address(value))


@dataclass(frozen=True)
class Rules:
    weights: dict
    deny_threshold: Decimal
    deny_comparison: str
    sensitive_actions: frozenset

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) != {
            "weights", "deny_threshold", "deny_comparison", "sensitive_actions"
        }:
            raise ValueError("Incomplete or unknown scoring configuration fields")
        if not isinstance(data["weights"], dict) or set(data["weights"]) != set(SIGNALS):
            raise ValueError("All four signal weights must be explicitly configured")
        if data["deny_comparison"] not in ("gte", "gt"):
            raise ValueError("deny_comparison must be gte or gt")
        actions = data["sensitive_actions"]
        if not isinstance(actions, list) or any(not isinstance(a, str) or ":" not in a for a in actions):
            raise ValueError("sensitive_actions must be a list of service:Action strings")
        return cls({k: number(v) for k, v in data["weights"].items()},
                   number(data["deny_threshold"]), data["deny_comparison"], frozenset(actions))


@dataclass(frozen=True)
class Request:
    user_id: str
    source_ip: str
    user_agent: str
    action: str
    time: datetime


@dataclass(frozen=True)
class Decision:
    verdict: str
    score: Decimal | None
    anomalies: tuple


def evaluate(request, profile, rules):
    if not profile:
        return Decision("Deny", None, ("missing_profile",))
    fields = ("knownIPs", "userAgents")
    if any(not isinstance(profile.get(k), (set, frozenset, list, tuple)) or not profile[k]
           or any(not isinstance(v, str) for v in profile[k]) for k in fields):
        return Decision("Deny", None, ("invalid_profile",))
    for field in ("hourHistogram", "actionCounts"):
        values = profile.get(field)
        if not isinstance(values, dict) or not values:
            return Decision("Deny", None, ("invalid_profile",))
        try:
            if any(not isinstance(k, str) or number(v) != int(number(v)) for k, v in values.items()):
                raise ValueError("Invalid histogram")
        except (ValueError, TypeError):
            return Decision("Deny", None, ("invalid_profile",))
    if profile.get("userId") != request.user_id:
        return Decision("Deny", None, ("identity_mismatch",))
    if request.time.tzinfo is None:
        raise ValueError("Request time must be timezone-aware")
    from datetime import timezone
    checks = {
        "unknown_ip": normalize_ip(request.source_ip) not in profile["knownIPs"],
        "off_hours": number(profile["hourHistogram"].get(str(request.time.astimezone(timezone.utc).hour), 0)) == 0,
        "unknown_user_agent": request.user_agent not in profile["userAgents"],
        "unusual_sensitive_action": request.action in rules.sensitive_actions
        and number(profile["actionCounts"].get(request.action, 0)) == 0,
    }
    anomalies = tuple(name for name in SIGNALS if checks[name])
    score = sum((rules.weights[name] for name in anomalies), Decimal(0))
    denied = score >= rules.deny_threshold if rules.deny_comparison == "gte" else score > rules.deny_threshold
    return Decision("Deny" if denied else "Allow", score, anomalies)
