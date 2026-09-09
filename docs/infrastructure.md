# Infrastructure and operational contracts

The SAM template provisions one multi-Region CloudTrail trail, encrypted/private S3 log storage, one `UserBehaviorProfiles` DynamoDB table, an offline baselining Lambda, one online JWT Lambda Authorizer, a protected mock Lambda/API, a failed-ingestion queue, log groups, Logs Insights queries, and a CloudWatch dashboard. IAM scopes the baseliner to the log prefix and profile writes; the authorizer can only read profiles. Neither function has permission to invoke an extra authorizer.

## Data collection

CloudTrail management events are collected across Regions, including global services. `CaptureDataEvents=true` additionally captures S3 object, Lambda invocation, and DynamoDB item events; it is an explicit deployment choice, without a default. AWS supports many other data-event resource types: this is not a universal all-data-event selector. Extend the template for additional types relevant to the experiment.

The log bucket, the three framework Lambdas, and the profile table are excluded from their corresponding data-event selectors to avoid self-generated logging loops. CloudTrail digest objects do not match the S3 notification prefix. Do not remove these exclusions while broadening collection. No CloudTrail event is represented as a custom application API request.

S3 object creation invokes the baseliner directly. It accepts gzip CloudTrail JSON under the configured account's `CloudTrail/` prefix, ignores unsupported identity/feature records, and propagates read/write failures for Lambda retries. Exhausted asynchronous failures go to the encrypted SQS queue. Operators must monitor this queue and replay the source S3 notification after correcting the cause; no automatic replay service is included. There is no periodic poller or configurable five-minute timer.

## Profile updates

User items have an exact CloudTrail ARN as `userId`, string sets `knownIPs`/`userAgents`, and integer maps `hourHistogram`/`actionCounts`. The action key is the CloudTrail service prefix plus event name (for example `iam:CreateUser`). Event hours use UTC. No frequency cutoff is inferred: an hour with zero count is off-hours. No profile expiry or sliding-window model is implied by the paper.

Each accepted CloudTrail event initializes absent count maps, then uses one DynamoDB transaction to conditionally insert an `event#<eventID>` receipt and increment the profile counts while adding IP/User-Agent set members. Replayed/duplicate events cannot increment counts twice. Receipts share the table but cannot be selected as profiles through the JWT mapping, which requires ARN values. Receipts have no TTL; retaining them preserves deduplication for arbitrarily old replays. Counts and memberships are insensitive to event arrival order.

The retained receipts grow with event count. Profiles also accumulate features and are subject to DynamoDB's item-size limit; an oversized update fails and is retried/reported rather than silently truncated. Retention, feature pruning, and baseline poisoning controls are not specified by the paper and need separate decisions for prolonged production use. The paper-style pipeline learns all accepted user events, including failed calls; malicious activity can therefore enter a baseline. Use controlled legitimate training for reproduction experiments.

## Online decision

A REQUEST authorizer checks signed RS256 JWTs using a configured HTTPS JWKS URL, issuer, audience, expiration, issued-at time, and subject. JWT `sub` is mapped explicitly to the CloudTrail principal ARN. JWKS data is cached; a key fetch may add network latency. No token or full event is logged. Cognito-style access tokens without the required `aud` claim need a provider-specific verifier; do not disable audience checks to make them pass.

The source IP and request time come from API Gateway request context. The action comes from a deployment-controlled method/resource mapping, not a client header. User-Agent is a spoofable behavioral signal, not device attestation. The final IAM policy is scoped to the current method ARN and authorizer caching is disabled. Missing identity/profile/action, malformed configuration, invalid JWTs, and backend failures deny. There is no low-score override for authentication failures.

User-supplied defaults are 50/25/30/15 points and a deny threshold of 70 (inclusive). There is no escalation band. `config/risk.json` drives local simulations; SAM parameters drive Lambda settings. Change both consistently for experiments.

## Deployment and lifecycle

`tools/deploy.py` reads the local JSON parameter file, validates scoring settings, runs SAM lint/build with a Linux container, and invokes a changeset-confirmed deploy. Use separate development AWS resources. The template does not create or replace a Region-wide API Gateway logging role: analytics come directly from Lambda decision logs, as in the paper.

Tables, S3 logs, and Lambda log groups are retained on stack deletion. Retained data can continue to incur charges. The SQS queue is not retained. No automatic cleanup or deployment was performed by this coding task. Data events, S3, DynamoDB transactions/receipts, CloudWatch queries/dashboard, and network requests may incur charges; the paper's $0 observation is not a service guarantee.

Unit/integration checks use local emulation. `cfn-lint` validates the SAM/CloudFormation structure, but a real SAM container build, AWS deployment, IAM exercise, and CloudWatch observations are still needed for an end-to-end deployment claim.

## Sources

* [CloudTrail API Gateway coverage](https://docs.aws.amazon.com/apigateway/latest/developerguide/cloudtrail.html)
* [CloudTrail advanced selectors](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html)
* [Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)
* [PyJWT verification](https://pyjwt.readthedocs.io/en/stable/usage.html)
