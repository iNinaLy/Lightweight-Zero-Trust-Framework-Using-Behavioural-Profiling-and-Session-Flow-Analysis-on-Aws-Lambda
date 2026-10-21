"""Generate reproducible synthetic training and labeled evaluation data."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]
USER = "arn:aws:iam::123456789012:user/lzta-synthetic"
BASELINE_IPS = ("192.0.2.10", "192.0.2.11")
USER_AGENT = "lzta-synthetic-agent/1.0"


def build_dataset(seed=2026, training_count=100, repeats=10):
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")
    if not isinstance(training_count, int) or isinstance(training_count, bool) or training_count < 1:
        raise ValueError("training_count must be a positive integer")
    if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 1:
        raise ValueError("repeats must be a positive integer")

    rng = random.Random(seed)
    training_start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    training_records = []
    for index in range(training_count):
        hour = (9, 10, 11, 13, 14, 15)[index % 6]
        event_time = training_start + timedelta(
            days=rng.randrange(30), hours=hour, minutes=rng.randrange(60)
        )
        training_records.append({
            "eventID": f"synthetic-training-{seed}-{index:06d}",
            "userIdentity": {"type": "IAMUser", "arn": USER},
            "sourceIPAddress": BASELINE_IPS[index % len(BASELINE_IPS)],
            "eventTime": event_time.isoformat().replace("+00:00", "Z"),
            "userAgent": USER_AGENT,
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
        })

    scenarios = (
        ("normal", "legitimate", BASELINE_IPS[0], USER_AGENT, 9, "s3:ListBuckets"),
        ("legitimate_new_ip", "legitimate", "203.0.113.10", USER_AGENT, 9, "s3:ListBuckets"),
        ("legitimate_new_device", "legitimate", BASELINE_IPS[0], "new-legitimate-agent/1.0", 9, "s3:ListBuckets"),
        ("legitimate_off_hours", "legitimate", BASELINE_IPS[0], USER_AGENT, 23, "s3:ListBuckets"),
        ("attack_unknown_ip", "attack", "198.51.100.50", USER_AGENT, 9, "s3:ListBuckets"),
        ("attack_unknown_device", "attack", BASELINE_IPS[0], "unknown-agent/1.0", 9, "s3:ListBuckets"),
        ("attack_off_hours", "attack", BASELINE_IPS[0], USER_AGENT, 23, "s3:ListBuckets"),
        ("attack_sensitive_action", "attack", BASELINE_IPS[0], USER_AGENT, 9, "iam:CreateUser"),
    )
    evaluation_cases = []
    for scenario, label, source_ip, agent, hour, action in scenarios:
        for repeat in range(repeats):
            request_time = datetime(2026, 2, 1, hour, tzinfo=timezone.utc)
            evaluation_cases.append({
                "case_id": f"{scenario}-{repeat:03d}",
                "scenario": scenario,
                "label": label,
                "request": {
                    "method": "GET",
                    "resource": "/protected",
                    "action": action,
                    "source_ip": source_ip,
                    "request_time": request_time.isoformat().replace("+00:00", "Z"),
                    "user_agent": agent,
                },
            })

    return {
        "dataset_version": "1.0.0",
        "dataset_id": f"lzta-synthetic-v1-seed-{seed}",
        "seed": seed,
        "profile_identity": USER,
        "training": {
            "source": "synthetic_cloudtrail",
            "records": training_records,
        },
        "evaluation": {
            "label_semantics": "Generator-assigned legitimate or attack scenario; labels are synthetic ground truth.",
            "request_context_note": "Planned synthetic context only; AWS runs must record API Gateway-observed IP and time.",
            "cases": evaluation_cases,
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--training-count", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    dataset = build_dataset(args.seed, args.training_count, args.repeats)
    output = args.output or ROOT / "tests" / "simulations" / f"{dataset['dataset_id']}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "dataset_id": dataset["dataset_id"],
        "output": str(output),
        "training_records": len(dataset["training"]["records"]),
        "evaluation_cases": len(dataset["evaluation"]["cases"]),
    }, indent=2))


if __name__ == "__main__":
    main()