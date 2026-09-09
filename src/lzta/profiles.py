"""CloudTrail feature extraction and atomic, replay-safe profile aggregation."""
from datetime import datetime, timezone
from lzta.scoring import normalize_ip


def observation(event):
    """Return a complete observation, or None for records without usable user context.

    Exact CloudTrail ARN is the profile key. Role sessions are not merged implicitly.
    Successful and failed user calls are both learned, as in the paper's raw-log model.
    """
    try:
        identity = event["userIdentity"]
        if identity.get("type") not in ("IAMUser", "AssumedRole", "FederatedUser", "Root"):
            return None
        user = identity["arn"]
        if not isinstance(user, str) or not user.startswith("arn:"):
            return None
        source = normalize_ip(event["sourceIPAddress"])
        when = datetime.fromisoformat(event["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
        agent = event["userAgent"]
        service = event["eventSource"].split(".")[0]
        action = event["eventName"]
        event_id = event["eventID"]
        if not all(isinstance(x, str) and x for x in (agent, service, action)):
            return None
        if not isinstance(event_id, str) or not event_id or len(event_id) > 128:
            return None
        return {
            "userId": user,
            "eventId": event_id,
            "ip": source,
            "userAgent": agent,
            "hour": str(when.astimezone(timezone.utc).hour),
            "action": f"{service}:{action}",
        }
    except (KeyError, ValueError, TypeError, AttributeError):
        return None


class ProfileStore:
    def __init__(self, table, transaction_client=None):
        self.table = table
        self.transaction_client = transaction_client

    def get(self, user):
        return self.table.get_item(Key={"userId": user}, ConsistentRead=True).get("Item")

    def add(self, item):
        """Atomically record event receipt and increment the profile exactly once.

        Receipt items share the table under event# IDs; they are not user profiles.
        Receipts deliberately do not expire, so old S3 object replays remain safe.
        """
        from boto3.dynamodb.types import TypeSerializer
        serialize = TypeSerializer().serialize
        user = item["userId"]
        # DynamoDB cannot set a nested map entry until its parent map exists.
        # Concurrent initialization is safe and preserves existing maps.
        self.table.update_item(
            Key={"userId": user},
            UpdateExpression="SET #hours = if_not_exists(#hours, :empty), #actions = if_not_exists(#actions, :empty)",
            ExpressionAttributeNames={"#hours": "hourHistogram", "#actions": "actionCounts"},
            ExpressionAttributeValues={":empty": {}},
        )
        values = {":zero": 0, ":one": 1, ":ips": {item["ip"]}, ":agents": {item["userAgent"]}}
        try:
            self.transaction_client.transact_write_items(TransactItems=[
                {"Put": {"TableName": self.table.name,
                         "Item": {"userId": serialize("event#" + item["eventId"])},
                         "ConditionExpression": "attribute_not_exists(userId)"}},
                {"Update": {"TableName": self.table.name, "Key": {"userId": serialize(user)},
                            "UpdateExpression": "SET #h.#hour = if_not_exists(#h.#hour, :zero) + :one, "
                                                "#a.#action = if_not_exists(#a.#action, :zero) + :one "
                                                "ADD #ips :ips, #agents :agents",
                            "ExpressionAttributeNames": {"#h": "hourHistogram", "#hour": item["hour"],
                                                         "#a": "actionCounts", "#action": item["action"],
                                                         "#ips": "knownIPs", "#agents": "userAgents"},
                            "ExpressionAttributeValues": {k: serialize(v) for k, v in values.items()}}},
            ])
        except Exception as exc:
            response = getattr(exc, "response", {})
            reasons = response.get("CancellationReasons", [])
            if response.get("Error", {}).get("Code") == "TransactionCanceledException" and reasons and reasons[0].get("Code") == "ConditionalCheckFailed":
                return False
            raise
        return True
