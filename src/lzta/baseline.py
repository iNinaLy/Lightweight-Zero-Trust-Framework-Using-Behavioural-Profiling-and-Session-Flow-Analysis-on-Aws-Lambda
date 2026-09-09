"""Offline pipeline: CloudTrail gzip JSON in S3 -> UserBehaviorProfiles."""
import gzip
import json
import os
from functools import lru_cache
from urllib.parse import unquote_plus
from lzta.logging import emit
from lzta.profiles import ProfileStore, observation


@lru_cache(maxsize=1)
def clients():
    import boto3
    return boto3.client("s3"), ProfileStore(boto3.resource("dynamodb").Table(os.environ["PROFILES_TABLE"]), boto3.client("dynamodb"))


def process(event, s3, store, expected_bucket, expected_prefix):
    files, observations, skipped = 0, 0, 0
    for record in event.get("Records", []):
        if record.get("eventSource") != "aws:s3" or not record.get("eventName", "").startswith("ObjectCreated:"):
            continue
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        if bucket != expected_bucket or not key.startswith(expected_prefix) or not key.endswith(".json.gz"):
            raise ValueError("Unexpected source object")
        body = s3.get_object(Bucket=bucket, Key=key)["Body"]
        try:
            with gzip.GzipFile(fileobj=body) as stream:
                payload = json.load(stream)
        finally:
            body.close()
        if not isinstance(payload, dict) or not isinstance(payload.get("Records"), list):
            raise ValueError("Invalid CloudTrail log document")
        for record in payload["Records"]:
            item = observation(record)
            if item is None:
                skipped += 1
            elif store.add(item):
                observations += 1
        files += 1
    result = {"files": files, "observations": observations, "skipped": skipped}
    emit("baseline_batch", **result)
    return result


def lambda_handler(event, context):
    # S3 validation notifications have no Records and intentionally become a no-op.
    s3, store = clients()
    try:
        return process(event, s3, store, os.environ["LOG_BUCKET"], os.environ["LOG_PREFIX"])
    except Exception as exc:
        emit("baseline_error", errorType=type(exc).__name__)
        raise  # Preserve Lambda retry/failure-destination semantics.
