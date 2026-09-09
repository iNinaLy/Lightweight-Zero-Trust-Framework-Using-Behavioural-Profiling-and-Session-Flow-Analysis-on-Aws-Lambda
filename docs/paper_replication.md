# Paper reproduction: evidence, choices, and limits

Source: the user-provided Markdown of *Lightweight Zero Trust Access Control with Behavior-Based Anomaly Detection in Cloud*, Vivek S, Smitha Vinod, and Sreeja CS J, IEEE CICN 2025, pages 942–948. The Markdown includes two DOI strings (`10.1109/CICN.2025.161` and `10.1109/CICN67655.2025.11368052`) and figure captions but not the figure images. Bibliographic discrepancies have not been resolved by inventing content from missing images.

## What is implemented

| Paper component | Repository implementation |
| --- | --- |
| Section V-A: CloudTrail logs in encrypted S3; DynamoDB profiles | Multi-Region trail, S3 bucket/policy, `UserBehaviorProfiles` table |
| Section V-B: automatic gzip parsing and atomic profile updates | S3-triggered `lzta.baseline`, feature extraction, DynamoDB transactions |
| Section V-C: read-only Lambda Authorizer returning Allow/Deny | `lzta.authorizer`, signed JWT verification, configured behavioral rules |
| Section V-D: structured decision logs, Insights, dashboard | JSON logs, saved denial/latency queries, four dashboard widgets |
| Section VI: normal, foreign-IP, off-hours, sensitive-action experiments | Synthetic scenario runner; live endpoint benchmark and manual experiment procedure |

The paper's four conceptual components are implemented without the later two-stage extension. No machine learning, MFA escalation, or adaptive threshold system is added; the paper lists these as possible future work.

## Explicit reconstruction choices

The paper omits the precise rule implementation. The user supplied weights of 50 (unknown IP), 25 (off-hours), 30 (first sensitive action), and 15 (unknown User-Agent), and requested removal of escalation. The implementation uses Allow below 70 and Deny at or above 70. All four signals are summed. Off-hours means a UTC hour with zero observations in `hourHistogram`; the paper gives no frequency cutoff. A high-privilege action means membership in a configured sensitive-action list, with zero occurrences in `actionCounts`.

The user selected JWT authentication. RS256 verification with issuer/audience/JWKS settings and an explicit subject-to-CloudTrail-ARN map supplies the missing identity bridge. Missing profiles deny; there is no automatic trust-on-first-use. The request action is mapped by the operator from an API route. This concretizes the paper's unspecified phrase that an AWS action is part of a future API request's context.

Atomic event receipts are an implementation addition needed to stop S3/CloudTrail redelivery from inflating `hourHistogram` and `actionCounts`. The paper does not describe duplicate handling. They remain in the same DynamoDB table, with separate key prefixes.

The paper states that all management and data events were captured but does not enumerate data-event resource types. This template supports account-wide S3 object, Lambda invocation, and DynamoDB item data events as an explicit option. Other data types require additional selectors; it is not presented as coverage of every AWS service. Framework resources are excluded to prevent telemetry recursion. Data-event collection can cost money.

## Results that must not be conflated

The paper reports three attack scenarios tested ten times each, 6% false positives, and no false negatives, but does not supply the underlying confusion matrix, traffic corpus, or full counting protocol. The prose and figure captions also repeat/mismatch some attack descriptions and scores. Those details cannot be exactly reconstructed from this text.

Its performance table reports 30 requests, average authorizer duration 85.2 ms, maximum 123.5 ms, and cold-start latency 291.5 ms. The cold-start figure exceeds 150 ms, so the text does not support a universal <150 ms guarantee. It also reports zero observed cost over a 24-hour experiment. Neither measurement is asserted for this repository.

The synthetic report uses the user's rules and clearly labels its origin. A single foreign-IP request scores 50, off-hours alone 25, and first sensitive action alone 30: all allow. Thus it does not replicate the paper's isolated-attack denials or no-false-negative claim. Unknown IP plus off-hours scores 75 and denies; off-hours plus a sensitive action plus an unknown User-Agent scores exactly 70 and denies. These differences follow the user's configuration, not a test failure or a secretly altered threshold.

## AWS validation protocol

1. Configure an actual JWT issuer/audience/JWKS URL, subject-to-ARN mapping, route/action mapping, and AWS account/Region; deploy the stack after reviewing its changeset.
2. Generate controlled legitimate CloudTrail observations for that principal. Confirm the stored sets/counts before testing. Custom application HTTP calls do not generate this CloudTrail baseline.
3. Run normal access, change to another network, test outside learned UTC hours, and test a route mapped to an unseen sensitive action. Repeat each ten times, recording actual decisions and anomaly scores. Under the user's rule settings, isolated anomalies allow; combined anomalies are needed for a denial.
4. Run the opt-in 30-request client benchmark. Record its client round-trip timings separately from Lambda REPORT durations. Identify real initialization durations in CloudWatch; do not label the first request a cold start without evidence.
5. Build a labeled dataset before computing false-positive/false-negative rates, and retain its labels and confusion matrix. Do not substitute synthetic rule checks for detection accuracy.
6. Inspect the account's actual cost data for the same interval. No cost metric is fabricated by the local runner.

Profile learning includes raw user events, so attack observations can eventually become normal. For a controlled experiment, separate legitimate baseline collection from attack observations and document that methodology. The paper gives no poisoning-defense or profile-aging mechanism. Direct AWS Console operations are not blocked by this API authorizer; only requests traversing the configured API are enforced.
