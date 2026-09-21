"""Strict binary baseline: any behavioral anomaly denies; no risk scoring."""
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address

SIGNALS = ("unknown_ip", "off_hours", "unknown_user_agent", "unusual_sensitive_action")

# Converts inputs to Python Decimal instances
def number(value):
    if isinstance(value, bool):
        raise ValueError("Boolean is not a profile count")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("Invalid profile count") from exc
    if not result.is_finite() or result < 0:
        raise ValueError("Profile counts must be finite and non-negative")
    return result

# Passes an IP string to standardize formatting
def normalize_ip(value):
    return str(ip_address(value))

# Holds the scoring rules loaded at startup
@dataclass(frozen=True)
class Rules:
    sensitive_actions: frozenset

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) != {"decision_policy", "sensitive_actions"}:
            raise ValueError("Expected decision_policy and sensitive_actions only; scoring settings are unsupported")
        if data["decision_policy"] != "deny_on_any_anomaly":
            raise ValueError("Only deny_on_any_anomaly is supported by this baseline")
        actions = data["sensitive_actions"]
        if not isinstance(actions, list) or any(not isinstance(a, str) or ":" not in a for a in actions):
            raise ValueError("sensitive_actions must be a list of service:Action strings")
        return cls(frozenset(actions))


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
    anomalies: tuple


def evaluate(request, profile, rules):
    if not profile:
        return Decision("Deny", ("missing_profile",))
    fields = ("knownIPs", "userAgents")
    if any(not isinstance(profile.get(k), (set, frozenset, list, tuple)) or not profile[k]
           or any(not isinstance(v, str) for v in profile[k]) for k in fields):
        return Decision("Deny", ("invalid_profile",))
    for field in ("hourHistogram", "actionCounts"):
        values = profile.get(field)
        if not isinstance(values, dict) or not values:
            return Decision("Deny", ("invalid_profile",))
        try:
            if any(not isinstance(k, str) or number(v) != int(number(v)) for k, v in values.items()):
                raise ValueError("Invalid histogram")
        except (ValueError, TypeError):
            return Decision("Deny", ("invalid_profile",))
    if profile.get("userId") != request.user_id:
        return Decision("Deny", ("identity_mismatch",))
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
    return Decision("Deny" if anomalies else "Allow", anomalies)
