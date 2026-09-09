"""Deterministic synthetic scenarios; output is not a reproduction of AWS measurements."""
import argparse
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lzta.scoring import Rules, Request, evaluate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=ROOT / "config/risk.json")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/simulation.json")
    args = parser.parse_args()
    rules = Rules.from_dict(json.loads(args.config.read_text()))
    user = "arn:aws:iam::123456789012:user/synthetic-user"
    baseline = {"userId": user, "knownIPs": ["192.0.2.1"], "userAgents": ["known-agent"],
                "hourHistogram": {"9": 10}, "actionCounts": {"s3:ListBuckets": 10}}
    normal = Request(user, "192.0.2.1", "known-agent", "s3:ListBuckets", datetime(2026, 1, 1, 9, tzinfo=timezone.utc))
    cases = {
        "normal": normal,
        "foreign_ip": replace(normal, source_ip="198.51.100.1"),
        "off_hours": replace(normal, time=normal.time.replace(hour=23)),
        "first_sensitive_action": replace(normal, action="iam:CreateUser"),
        "unknown_device": replace(normal, user_agent="unknown"),
        "foreign_ip_and_off_hours": replace(normal, source_ip="198.51.100.1", time=normal.time.replace(hour=23)),
        "off_hours_sensitive_action_unknown_device": replace(normal, time=normal.time.replace(hour=23), action="iam:CreateUser", user_agent="unknown"),
    }
    results = []
    for name, request in cases.items():
        outcomes = [evaluate(request, baseline, rules) for _ in range(10)]
        results.append({"scenario": name, "requests": len(outcomes), "score": float(outcomes[0].score),
                        "anomalies": outcomes[0].anomalies, "allowed": sum(x.verdict == "Allow" for x in outcomes),
                        "denied": sum(x.verdict == "Deny" for x in outcomes)})
    report = {"kind": "synthetic_local_rule_evaluation", "config": json.loads(args.config.read_text()),
              "note": "No AWS latency, cost, original dataset, or measured paper accuracy reproduced.", "scenarios": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
