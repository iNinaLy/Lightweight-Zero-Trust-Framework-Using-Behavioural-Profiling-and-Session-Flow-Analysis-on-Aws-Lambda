# Paper-inspired strict binary baseline: evidence, choices, and limits

Source: the user-provided Markdown of *Lightweight Zero Trust Access Control with Behavior-Based Anomaly Detection in Cloud*, Vivek S, Smitha Vinod, and Sreeja CS J, IEEE CICN 2025, pages 942–948. The Markdown includes two DOI strings (`10.1109/CICN.2025.161` and `10.1109/CICN67655.2025.11368052`) and figure captions but not the figure images. Bibliographic discrepancies have not been resolved by inventing content from missing images.

## What is implemented

| Paper component | Repository implementation |
| --- | --- |
| Section V-A: CloudTrail logs in encrypted S3; DynamoDB profiles | Multi-Region trail, S3 bucket/policy, `UserBehaviorProfiles` table |
| Section V-B: automatic gzip parsing and atomic profile updates | S3-triggered `lzta.baseline`, feature extraction, DynamoDB transactions |
| Section V-C: read-only Lambda Authorizer returning Allow/Deny | `lzta.authorizer`, signed JWT verification, configured behavioral rules |
| Section V-D: structured decision logs, Insights, dashboard | JSON logs, saved denial/latency queries, four dashboard widgets |
| Section VI: normal, foreign-IP, off-hours, sensitive-action experiments | Synthetic scenario runner; live endpoint benchmark and manual experiment procedure |

The paper's four conceptual components are implemented as the first step toward the FYP: test this baseline, then implement the planned two-stage extension, then compare both. The [original two-stage requirements](original_two_stage_context.md) remain the extension plan; they have not been abandoned. No machine learning, MFA escalation, or adaptive threshold system is added; the paper lists these as possible future work.

## Explicit reconstruction choices

The paper describes a risk score leading to Allow/Deny but omits the complete formula and threshold. At the user's request, this implementation now uses a **strict binary experimental baseline: deny if any anomaly is detected, otherwise allow**. This is a reconstruction choice, not a verified replication of the paper's original algorithm. The former weighted implementation remains in Git commit `c3becdb` and is not used at runtime.

Off-hours means a UTC hour with zero observations in `hourHistogram`; the paper gives no frequency cutoff. A sensitive action is an explicitly configured action with zero occurrences in `actionCounts`. IP and User-Agent checks use exact membership. No risk scores are computed or logged.

The user selected JWT authentication. RS256 verification with issuer/audience/JWKS settings and an explicit subject-to-CloudTrail-ARN map supplies the missing identity bridge. Missing profiles deny; there is no automatic trust-on-first-use. The request action is mapped by the operator from an API route. This concretizes the paper's unspecified phrase that an AWS action is part of a future API request's context.

Atomic event receipts are an implementation addition needed to stop S3/CloudTrail redelivery from inflating `hourHistogram` and `actionCounts`. The paper does not describe duplicate handling. They remain in the same DynamoDB table, with separate key prefixes.

The paper states that all management and data events were captured but does not enumerate data-event resource types. This template supports account-wide S3 object, Lambda invocation, and DynamoDB item data events as an explicit option. Other data types require additional selectors; it is not presented as coverage of every AWS service. Framework resources are excluded to prevent telemetry recursion. Data-event collection can cost money.

## Results that must not be conflated

The paper reports three attack scenarios tested ten times each, 6% false positives, and no false negatives, but does not supply the underlying confusion matrix, traffic corpus, or full counting protocol. The prose and figure captions also repeat/mismatch some attack descriptions and scores. Those details cannot be exactly reconstructed from this text.

Its performance table reports 30 requests, average authorizer duration 85.2 ms, maximum 123.5 ms, and cold-start latency 291.5 ms. The cold-start figure exceeds 150 ms, so the text does not support a universal <150 ms guarantee. It also reports zero observed cost over a 24-hour experiment. Neither measurement is asserted for this repository.

The synthetic report labels its origin and policy. Normal context allows; each isolated anomaly and every combination denies. These checks verify policy behavior, not detection accuracy or the paper's no-false-negative claim. A changed IP may be legitimate or malicious: a labeled evaluation must include both.

## Comparing a future Stage 2 extension

Freeze this policy, dataset, and training/testing split before comparing the extension. Use the same identities, profiles, request contexts, and ground-truth labels for both. Include legitimate new IPs/devices, off-hours work, attacks, and missing/stale history. Report false positives, false negatives, latency, and cost for both, plus the extension's escalation rate. Explain what new information Stage 2 adds. Avoid training on test events, tuning the baseline to favor Stage 2, or presenting synthetic rule checks as detection accuracy.

## Planned versions and Git workflow

Keep three approaches available for evaluation within one project:

| Approach | Decision method | Role |
| --- | --- | --- |
| Single-stage strict binary | Any detected anomaly denies | Current experimental baseline; not the paper's verified algorithm |
| Single-stage weighted | Combine anomaly weights and apply a threshold | Planned comparison baseline closer to the paper's described mechanism |
| Two-stage weighted | Stage 1 allows, denies, or escalates; Stage 2 checks session behaviour | Planned FYP contribution |

The earlier weighted implementation is preserved in commit `c3becdb`. It is not currently a separately selectable implementation alongside the binary baseline. Stage 2 remains unimplemented.

The intended workflow is to keep the completed approaches together on `main`, with separate decision modules, configurations, and result files. Share JWT verification, profile processing, logging, and test utilities where appropriate. Use temporary development branches while implementing the weighted baseline and Stage 2, then merge the tested work. Preserve tested milestones with Git tags so experiments can be reproduced. Branches separate development work; they do not need to permanently separate the three approaches. These branches, tags, and additional modules are a plan, not artifacts created by this note.

Finish validating the binary baseline first, then add the weighted baseline, then Stage 2. The primary contribution comparison should be single-stage weighted versus two-stage weighted: keep shared Stage 1 signals and weights consistent, and explicitly define the single-stage decision for requests that would enter the two-stage escalation band. Use the same labeled evaluation traffic and separate training data for all approaches. Report false positives, false negatives, latency, and cost rather than assuming that more permissive decisions indicate an improvement.

## AWS validation protocol

1. Configure an actual JWT issuer/audience/JWKS URL, subject-to-ARN mapping, route/action mapping, and AWS account/Region; deploy the stack after reviewing its changeset.
2. Generate controlled legitimate CloudTrail observations for that principal. Confirm the stored sets/counts before testing. Custom application HTTP calls do not generate this CloudTrail baseline.
3. Run normal access, change to another network, test outside learned UTC hours, and test a route mapped to an unseen sensitive action. Repeat each ten times, recording actual decisions and detected anomalies. Each isolated anomaly should deny under the strict baseline.
4. Run the opt-in 30-request client benchmark. Record its client round-trip timings separately from Lambda REPORT durations. Identify real initialization durations in CloudWatch; do not label the first request a cold start without evidence.
5. Build a labeled dataset before computing false-positive/false-negative rates, and retain its labels and confusion matrix. Do not substitute synthetic rule checks for detection accuracy.
6. Inspect the account's actual cost data for the same interval. No cost metric is fabricated by the local runner.

Profile learning includes raw user events, so attack observations can eventually become normal. For a controlled experiment, separate legitimate baseline collection from attack observations and document that methodology. The paper gives no poisoning-defense or profile-aging mechanism. Direct AWS Console operations are not blocked by this API authorizer; only requests traversing the configured API are enforced.
