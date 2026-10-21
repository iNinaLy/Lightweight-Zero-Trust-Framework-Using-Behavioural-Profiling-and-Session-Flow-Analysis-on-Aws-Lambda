"""Owner-scoped document operations behind the behavioural authorizer."""
import base64
import binascii
from datetime import datetime, timezone
from decimal import Decimal
from functools import lru_cache
import hashlib
import json
import os
import re
import uuid

from lzta.logging import emit

MAX_FILE_BYTES = 1024 * 1024


@lru_cache(maxsize=1)
def clients():
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 2})
    return (boto3.resource("dynamodb", config=config).Table(os.environ["DOCUMENTS_TABLE"]),
            boto3.client("s3", config=config))


def response(status, payload, origin):
    return {"statusCode": status, "headers": {
        "Content-Type": "application/json", "Access-Control-Allow-Origin": origin,
        "Access-Control-Expose-Headers": "x-amzn-RequestId", "Cache-Control": "no-store",
        "Vary": "Origin",
    }, "body": json.dumps(payload, default=lambda value: int(value) if isinstance(value, Decimal) else str(value))}


def filename(value):
    if (not isinstance(value, str) or not value.strip() or len(value) > 180
            or re.search(r'[\x00-\x1f\x7f/\\]', value)):
        raise ValueError("Use a filename of 1–180 characters without slashes or control characters")
    return value.strip()


def public_document(item):
    return {key: item[key] for key in ("id", "name", "category", "size", "createdAt", "updatedAt")}


def handle(event, table, s3, bucket, origin):
    context = event.get("requestContext", {})
    owner = context.get("authorizer", {}).get("principalId")
    if not isinstance(owner, str) or not owner.startswith("arn:"):
        return response(401, {"message": "Sign in to continue"}, origin)
    method, resource = event.get("httpMethod"), event.get("resource")
    from lzta.hr_confidential import ROUTES, handle as confidential_handle
    if resource in ROUTES:
        return confidential_handle(event, table, owner, origin)
    if resource in ("/employee", "/payslips", "/payslips/{payslipId}", "/payslips/{payslipId}/download", "/policies",
                    "/policies/{policyId}", "/leave-requests", "/leave-requests/{leaveId}"):
        from lzta.hr import handle as hr_handle
        return hr_handle(event, table, owner, origin)
    now = datetime.now(timezone.utc).isoformat()

    def activity(action, name, document_id):
        record = {"ownerId": owner, "entryId": f"activity#{now}#{uuid.uuid4().hex}",
                  "action": action, "name": name, "documentId": document_id, "time": now,
                  "requestId": context.get("requestId", "")}
        table.put_item(Item=record)
        emit("portal_activity", user=owner, action=action, documentId=document_id,
             requestId=context.get("requestId"), sourceIp=context.get("identity", {}).get("sourceIp"))

    def get_document(document_id):
        if not isinstance(document_id, str) or not re.fullmatch(r"[0-9a-f]{32}", document_id):
            return None
        return table.get_item(Key={"ownerId": owner, "entryId": "document#" + document_id},
                              ConsistentRead=True).get("Item")

    if method == "GET" and resource in ("/documents", "/activity"):
        prefix = "document#" if resource == "/documents" else "activity#"
        options = {"KeyConditionExpression": "ownerId = :owner AND begins_with(entryId, :prefix)",
                   "ExpressionAttributeValues": {":owner": owner, ":prefix": prefix},
                   "Limit": 100, "ScanIndexForward": resource == "/documents", "ConsistentRead": True}
        cursor = (event.get("queryStringParameters") or {}).get("cursor")
        if cursor:
            try:
                key = json.loads(base64.urlsafe_b64decode(cursor))
                if key.get("ownerId") != owner or not key.get("entryId", "").startswith(prefix):
                    raise ValueError()
                options["ExclusiveStartKey"] = key
            except (ValueError, TypeError, AttributeError, binascii.Error):
                return response(400, {"message": "Invalid pagination cursor"}, origin)
        page = table.query(**options)
        items = page.get("Items", [])
        result = {"items": [public_document(item) for item in items] if resource == "/documents" else [
            {key: item[key] for key in ("action", "name", "documentId", "time", "requestId")} for item in items]}
        if page.get("LastEvaluatedKey"):
            result["nextCursor"] = base64.urlsafe_b64encode(json.dumps(page["LastEvaluatedKey"]).encode()).decode()
        if resource == "/documents":
            emit("portal_activity", user=owner, action="list", requestId=context.get("requestId"))
        return response(200, result, origin)

    try:
        body = json.loads(event.get("body") or "{}") if method in ("POST", "PATCH") else {}
        if not isinstance(body, dict):
            raise ValueError("Expected a JSON object")
        if method == "POST" and resource == "/documents":
            name = filename(body.get("name"))
            category = body.get("category", "General")
            if category not in ("General", "Finance", "Operations", "Project"):
                raise ValueError("Choose a valid category")
            encoded = body.get("contentBase64")
            if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_FILE_BYTES + 2) // 3):
                raise ValueError("Upload a file no larger than 1 MB")
            try:
                content = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                raise ValueError("File content must be valid base64") from None
            if not content or len(content) > MAX_FILE_BYTES:
                raise ValueError("Upload a non-empty file no larger than 1 MB")
            document_id = uuid.uuid4().hex
            key = hashlib.sha256(owner.encode()).hexdigest() + "/" + document_id
            item = {"ownerId": owner, "entryId": "document#" + document_id, "id": document_id,
                    "name": name, "category": category, "size": len(content), "objectKey": key,
                    "createdAt": now, "updatedAt": now}
            s3.put_object(Bucket=bucket, Key=key, Body=content, ContentType="application/octet-stream")
            try:
                table.put_item(Item=item, ConditionExpression="attribute_not_exists(entryId)")
            except Exception:
                s3.delete_object(Bucket=bucket, Key=key)
                raise
            activity("upload", name, document_id)
            return response(201, {"document": public_document(item)}, origin)

        document_id = (event.get("pathParameters") or {}).get("documentId")
        item = get_document(document_id)
        if not item:
            return response(404, {"message": "Document not found"}, origin)
        key = {"ownerId": owner, "entryId": item["entryId"]}
        if method == "GET" and resource == "/documents/{documentId}/download":
            obj = s3.get_object(Bucket=bucket, Key=item["objectKey"])
            try:
                content = obj["Body"].read(MAX_FILE_BYTES + 1)
            finally:
                obj["Body"].close()
            if len(content) > MAX_FILE_BYTES:
                raise ValueError("File exceeds the download limit")
            activity("download", item["name"], document_id)
            return response(200, {"name": item["name"], "contentBase64": base64.b64encode(content).decode()}, origin)
        if method == "PATCH" and resource == "/documents/{documentId}":
            name = filename(body.get("name"))
            table.update_item(Key=key, UpdateExpression="SET #name = :name, updatedAt = :updated",
                              ConditionExpression="attribute_exists(entryId)",
                              ExpressionAttributeNames={"#name": "name"},
                              ExpressionAttributeValues={":name": name, ":updated": now})
            activity("rename", name, document_id)
            return response(200, {"document": public_document({**item, "name": name, "updatedAt": now})}, origin)
        if method == "DELETE" and resource == "/documents/{documentId}":
            s3.delete_object(Bucket=bucket, Key=item["objectKey"])
            table.delete_item(Key=key, ConditionExpression="attribute_exists(entryId)")
            activity("delete", item["name"], document_id)
            return response(200, {"message": "Document deleted"}, origin)
        return response(404, {"message": "Route not found"}, origin)
    except (ValueError, TypeError) as error:
        return response(400, {"message": str(error)}, origin)


def lambda_handler(event, context):
    origin = os.environ["PORTAL_ORIGIN"]
    try:
        table, s3 = clients()
        return handle(event, table, s3, os.environ["DOCUMENTS_BUCKET"], origin)
    except Exception as error:
        emit("portal_error", errorType=type(error).__name__, requestId=event.get("requestContext", {}).get("requestId"))
        return response(503, {"message": "The document service is temporarily unavailable. Please try again."}, origin)
