"""Protected demonstration resource. It does not execute privileged AWS actions."""
import json


def lambda_handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"message": "Access granted", "user": event.get("requestContext", {}).get("authorizer", {}).get("principalId")})}
