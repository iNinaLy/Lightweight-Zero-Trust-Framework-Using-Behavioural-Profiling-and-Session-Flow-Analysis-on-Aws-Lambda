# LZTA: single-authorizer paper reproduction

This project implements the serverless architecture described by Vivek S, Smitha Vinod, and Sreeja CS J in *Lightweight Zero Trust Access Control with Behavior-Based Anomaly Detection in Cloud* (CICN 2025), using the supplied paper text. It replaces the earlier two-stage draft. There is no Stage 2, SessionFlow table, escalation path, or Firehose pipeline.

**Offline:** CloudTrail → encrypted S3 → Python Lambda → `UserBehaviorProfiles`.

**Online:** API Gateway → JWT-verifying Lambda Authorizer → profile lookup → Allow/Deny → protected demonstration Lambda.

**Analytics:** structured authorizer logs → CloudWatch Logs Insights queries and dashboard.

The paper does not publish its code, full scoring configuration, identity mapping, or dataset. This is an executable implementation of the described architecture with explicit assumptions, not a claim that its reported accuracy, latency, or cost has been independently reproduced. See [reproduction notes](docs/paper_replication.md).

## Your configured rules

| Anomaly | Points |
| --- | ---: |
| Unknown IP, compared with `knownIPs` | 50 |
| UTC hour with zero observations in `hourHistogram` | 25 |
| First-time sensitive action, compared with `actionCounts` | 30 |
| Unknown device/User-Agent, compared with `userAgents` | 15 |

Scores **below 70 Allow**, scores **70 or above Deny**. The former 20–69 escalation band now allows. Missing/invalid profiles, invalid JWTs, unmapped identities/routes, and backend errors deny regardless of scoring. These are implementation safeguards where the paper is silent.

With these settings, an unknown IP alone (50) **allows**. Unknown IP plus off-hours (75) **denies**. Thus your chosen rules do not reproduce the paper's unknown-IP-only denial. Configuration remains editable in [config/risk.json](config/risk.json); deployment parameters are separate and must be kept consistent if changed.

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
