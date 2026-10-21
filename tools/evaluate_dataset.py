"""Evaluate the strict single-stage baseline on a labeled synthetic dataset."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lzta.profiles import observation
from lzta.scoring import Request, Rules, evaluate


def run_experiment(dataset, rules):
    profile = {
        "userId": dataset["profile_identity"],
        "knownIPs": set(),
        "userAgents": set(),
        "hourHistogram": Counter(),
        "actionCounts": Counter(),
    }
    for event in dataset["training"]["records"]:
        item = observation(event)
        if item is None or item["userId"] != profile["userId"]:
            raise ValueError("Training data contains an invalid or unexpected identity record")
        profile["knownIPs"].add(item["ip"])
        profile["userAgents"].add(item["userAgent"])
        profile["hourHistogram"][item["hour"]] += 1
        profile["actionCounts"][item["action"]] += 1

    confusion = Counter()
    scenario_results = defaultdict(Counter)
    cases = dataset["evaluation"]["cases"]
    if not cases:
        raise ValueError("Evaluation dataset must contain at least one case")
    for case in cases:
        request_data = case["request"]
        request = Request(
            user_id=profile["userId"],
            source_ip=request_data["source_ip"],
            user_agent=request_data["user_agent"],
            action=request_data["action"],
            time=datetime.fromisoformat(request_data["request_time"].replace("Z", "+00:00")),
        )
        decision = evaluate(request, profile, rules)
        predicted = "attack" if decision.verdict == "Deny" else "legitimate"
        actual = case["label"]
        category = (
            "true_positive" if actual == "attack" and predicted == "attack" else
            "false_negative" if actual == "attack" else
            "true_negative" if predicted == "legitimate" else
            "false_positive"
        )
        confusion[category] += 1
        scenario_results[case["scenario"]][category] += 1
        scenario_results[case["scenario"]]["allow" if decision.verdict == "Allow" else "deny"] += 1

    return {
        "kind": "synthetic_labeled_baseline_experiment",
        "dataset_id": dataset["dataset_id"],
        "dataset_version": dataset["dataset_version"],
        "decision_policy": "deny_on_any_anomaly",
        "training_records": len(dataset["training"]["records"]),
        "evaluation_cases": len(cases),
        "metrics": {
            "true_positive": confusion["true_positive"],
            "false_positive": confusion["false_positive"],
            "true_negative": confusion["true_negative"],
            "false_negative": confusion["false_negative"],
            "false_positive_rate": confusion["false_positive"] / max(
                confusion["false_positive"] + confusion["true_negative"], 1
            ),
            "false_negative_rate": confusion["false_negative"] / max(
                confusion["false_negative"] + confusion["true_positive"], 1
            ),
        },
        "scenarios": {
            name: dict(sorted(counts.items()))
            for name, counts in sorted(scenario_results.items())
        },
        "limitations": [
            "Labels and workload are synthetic; these are not real-world detection accuracy.",
            "Local evaluation does not measure AWS latency or cost.",
            "Evaluation request contexts are planned inputs, not API Gateway observations.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--config", type=Path, default=ROOT / "config/risk.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    rules = Rules.from_dict(json.loads(args.config.read_text(encoding="utf-8")))
    report = run_experiment(dataset, rules)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()