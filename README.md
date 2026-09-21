# LZTA: strict binary experimental baseline

This project implements a strict binary experimental baseline inspired by the serverless architecture described by Vivek S, Smitha Vinod, and Sreeja CS J in *Lightweight Zero Trust Access Control with Behavior-Based Anomaly Detection in Cloud* (CICN 2025), using the supplied paper text. This is the first implementation step: test the single-stage baseline before adding the planned two-stage FYP extension. Stage 2, the `SessionFlow` table, and escalation are not implemented yet. The original extension requirements remain in [the two-stage design notes](docs/original_two_stage_context.md).

**Offline:** CloudTrail → encrypted S3 → Python Lambda → `UserBehaviorProfiles`.

**Online:** API Gateway → JWT-verifying Lambda Authorizer → profile lookup → Allow/Deny → protected demonstration Lambda.

**Analytics:** structured authorizer logs → CloudWatch Logs Insights queries and dashboard.

The paper does not publish its code, full scoring configuration, identity mapping, or dataset. This is an executable implementation of the described architecture with explicit assumptions, not a claim that its reported accuracy, latency, or cost has been independently reproduced. See [reproduction notes](docs/paper_replication.md).

## Binary decision rule

**No detected anomaly: Allow. Any detected anomaly: Deny.** No weights, risk scores, thresholds, or escalation are used.

| Check | Deny condition |
| --- | --- |
| Source IP | Not in `knownIPs` |
| Access hour | UTC hour has zero observations in `hourHistogram` |
| Sensitive action | Configured sensitive action has zero occurrences in `actionCounts` |
| Device/User-Agent | Not in `userAgents` |

Missing/invalid profiles, invalid JWTs, unmapped identities/routes, and backend failures also deny. Known sensitive actions and new non-sensitive actions do not trigger the sensitive-action check.

The paper describes risk scoring and binary outputs, but does not establish this exact any-anomaly-denies rule. Label this implementation a **strict binary baseline inspired by the paper**, not the authors' original algorithm. Compare a later Stage 2 extension using the same authenticated requests, profiles, labels, and training/testing split. Rejecting more legitimate changes does not by itself prove that an extension is better.

`config/risk.json` declares `decision_policy: deny_on_any_anomaly` and the sensitive-action list. Old weighted configurations are rejected. Remove `RiskWeightsJson` and `DenyThreshold` from existing deployment parameter files. Redeploy to activate this change on AWS. The previous weighted version remains available in Git commit `c3becdb`.

## Local setup and verification

Use Python 3.14:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
cfn-lint infrastructure/template.yaml
python tools/simulate.py
```

Tests include actual RSA JWT signature verification and emulated DynamoDB transactions. They do not contact AWS. Simulation writes `reports/simulation.json` with explicitly synthetic results. A GitHub Actions validation workflow runs these checks.

## Configure and deploy

1. Install AWS SAM CLI, Docker (for the Linux Lambda build), and AWS CLI; configure your AWS account credentials.
2. Copy `config/deployment.example.json` to an untracked `config/deployment.local.json` and replace every placeholder.
3. Supply an RS256 JWT issuer, audience, and HTTPS JWKS URL. Map each verified JWT `sub` to its exact CloudTrail `userIdentity.arn`. A JWT application subject is not automatically an IAM identity. For assumed roles, exact session ARNs are distinct profiles.
4. Define the route-to-action mapping and sensitive-action list for your experiment. The examples use `GET /protected` → `s3:ListBuckets` for normal access and `iam:CreateUser` as the paper's sensitive action. The mock endpoint does not execute IAM operations.
5. Explicitly choose whether to capture data events. `true` enables S3 object, Lambda invocation, and DynamoDB item events across the account, excluding the framework's own resources. Other data-event types need additional selectors. Data events are billable; zero cost is not guaranteed.

```powershell
python tools/deploy.py --parameters config/deployment.local.json --region us-east-1 --validate-only
python tools/deploy.py --parameters config/deployment.local.json --region us-east-1
```

The deployment helper validates inputs, runs SAM lint/build, and asks SAM to show a changeset for confirmation. Nothing is deployed merely by running tests. The runtime pins boto3 and PyJWT; Lambda controls the Python patch release. Configure logging retention and data collection scope for your account.

## Establish a baseline and evaluate

Perform legitimate AWS calls using the same AWS principal configured in the JWT identity map, with the source IP, User-Agent, and UTC hours you intend to teach. CloudTrail gzip files arriving in S3 trigger automatic profile updates. CloudTrail delivery is asynchronous (typically around five minutes), not a strict five-minute schedule. Requests without a learned profile deny.

CloudTrail does **not** collect ordinary custom API Gateway endpoint invocations. Calling `/protected` alone does not train the profile. The paper combines AWS-operation baselines with application authorization; this repository implements that distinction rather than pretending the two event streams are identical.

For a controlled sensitive-action test, map the test route to `iam:CreateUser` before issuing the request. Do not perform that action in the training stream first and then expect it to remain unseen after ingestion. API Gateway cannot block a direct IAM Console operation; it enforces only requests passing through this API.

A caller supplies its JWT as a bearer token. For the paper's 30-request performance protocol, run the opt-in client against your deployed endpoint:

```powershell
# Set LZTA_JWT securely in your shell first. The tool never prints it.
python tools/benchmark.py https://YOUR-API.execute-api.us-east-1.amazonaws.com/dev/protected --user-agent YOUR-BASELINED-USER-AGENT
```

The benchmark measures client round-trip time, not Lambda duration. Use the deployed CloudWatch query/dashboard to inspect Lambda REPORT durations and initialization time separately. A first request is not automatically a cold start. Compare measured results with the paper only after running the AWS experiment.

See [directory architecture](directory_architecture.md), [infrastructure notes](docs/infrastructure.md), and [paper replication details](docs/paper_replication.md).
