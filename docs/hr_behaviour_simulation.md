# AWS behavioural simulation

The main experiment now models AWS users and AWS operations. The earlier HR-action v2 experiment is historical; the HR portal remains a separate protected application.

Personas are defined in `config/aws_personas.json`:

| Persona | Learned behaviour |
| --- | --- |
| Sarah, cloud operations | Frequent overtime at 19:00 and 20:00 Malaysia time, alongside daytime work |
| Amir, office analyst | Regular office IP/hours; later starts hybrid work or unexpected overtime |
| Mei, hybrid engineer | Office Monday/Wednesday/Friday; home Tuesday/Thursday; both IPs become familiar |
| Elena, regional auditor | Regular office and fixed UTC hours |

Their activities include STS identity checks, S3 bucket listing/object reads/writes, EC2 descriptions, CloudWatch metric reads and CloudTrail event lookup. Session timing, attendance and devices vary reproducibly. Identities, resources and documentation-range IPs are fictional. Training alone learns each profile; held-out requests cannot modify it.

## Intended two-stage behaviour

| Situation | Required outcome |
| --- | --- |
| Familiar overtime or established hybrid networks | Normal context |
| New home IP with normal permitted work | Flag for Stage 2 and continue |
| Unexpected overtime with normal permitted work | Flag for Stage 2 and continue |
| Suspicious burst, repetition or action sequence | Evaluate session evidence; deny when the eventual detection policy warrants it |
| Out-of-scope action | Deny at the permission boundary regardless of familiar context |

There are paired sessions for both starting hybrid work and unexpected overtime: legitimate changed-context activity versus the same activity followed by an unauthorized `iam:CreateUser` attempt. Initial steps remain legitimate; the offending action is labelled attack. Other scenarios include device changes, mid-session network changes, familiar-context attacks and bulk object reads/writes.

**These expected two-stage outcomes are requirements, not implemented detection results.** The evaluator runs the existing strict binary baseline, which still denies on any anomaly. Thresholds and Stage 2 remain unimplemented. Intent labels do not grant access or imply that identical contexts can be distinguished.

Permissions are separate, explicit action/resource fixtures. An unfamiliar `s3:PutObject` to the approved output resource is permitted; `iam:CreateUser` is outside scope. These fixtures are not deployed IAM policies or a complete IAM simulator. Reports show the behavioural verdict, permission-fixture verdict and combined verdict separately. Confusion metrics measure only the behavioural baseline.

## Reproduce

```powershell
python tools/generate_aws_workload.py
# Use the dataset path printed by the generator:
python tools/evaluate_aws_workload.py tests/simulations/DATASET-NAME.json
python -m unittest discover -s tests -q
```

Outputs include versioned JSON, a deterministic gzip training envelope, and a report with frozen profiles/rules, canonical dataset SHA-256, individual decisions and per-persona/scenario metrics. Exact training replays are deduplicated; conflicting receipts and train/test overlap are rejected. Earlier datasets remain separate.

These are synthetic CloudTrail-shaped AWS records, not captured AWS logs. Real S3 object activity requires appropriate CloudTrail data-event logging; management logging alone is insufficient. See [AWS S3 CloudTrail documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html).

These tools make no AWS calls, change no live profiles and start no logging. CloudTrail observes attempted/completed operations; the API Gateway authorizer does not intercept direct AWS Console/CLI activity. Direct AWS enforcement requires its own enforcement integration.

## Opt-in isolated AWS ingestion check

Unlike the local generator/evaluator, `tools/check_aws_ingestion.py DATASET_PATH` deploys the dedicated `lzta-isolated-ingestion-test` CloudFormation stack. It uses a private encrypted S3 input bucket, an on-demand DynamoDB table, a limited Lambda role and a seven-day log group. It reuses the deployed Linux dependency bundle and packages the current production ingestion source. No CloudTrail resource is created or enabled.

The check uploads only training records, waits for the real S3 notification/Lambda path to produce profiles identical to the local training-only aggregation, invokes the same object again and requires zero new observations with unchanged counts. It checks that the existing trail remains stopped. A successful run writes `reports/live-aws-ingestion-result.json`; the report lists resources and results. Resources remain deployed for inspection and later controlled experiments. This validates ingestion and replay safety, not Stage 2 or AWS-operation blocking.
