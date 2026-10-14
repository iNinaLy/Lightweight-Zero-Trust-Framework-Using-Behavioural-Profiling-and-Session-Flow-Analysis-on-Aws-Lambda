# Planned FYP extension: original two-stage requirements

The two-stage design below remains the planned FYP extension. It is deferred until the current single-stage baseline has been tested, not abandoned or replaced as the final project objective. The original requirements below are preserved.

## Implementation sequence

Experiment methodology selected on 2026-10-14: use synthetic training activity and labeled evaluation workloads across the whole project, while still sending actual authenticated test requests through the deployed API. Apply the same datasets and evaluation conditions to the compared approaches. See [the selected experiment methodology](paper_replication.md#selected-experiment-methodology-2026-10-14) for training/testing separation, actual request-context constraints, and the planned Stage 2 session telemetry requirements. This decision updates the evaluation plan; the original architecture requirements below remain historical context.

1. Test the current paper-inspired single-stage baseline and record its behavior and limitations.
2. Preserve a reproducible baseline version, then implement the two-stage extension described below.
3. Compare both implementations using the same labeled requests, baseline data, and evaluation conditions.
4. After the backend work, including Stage 2 and comparison experiments, is complete, build and validate the FYP presentation interface described below.

## Presentation interface plan (2026-10-14)

The user requested a presentation interface for the complete FYP, to be implemented after the backend and Stage 2 work is finished. Planned features are Cognito sign-in, controlled synthetic scenario execution through actual authenticated API requests, Allow/Deny results with decision reasons and escalation details where applicable, behavior/session profile views, and comparison charts for the evaluated approaches. Show recorded experiment results separately from live request results. The backend remains responsible for authorization decisions; the interface displays actual outcomes.

Use the existing Cognito user pool. An additional user is not required merely to add an interface, but a dedicated demo user is planned for isolation of synthetic experiment profiles from real account activity. Its verified `sub` must be mapped to a separate experiment profile identity; creating a Cognito user does not create that DynamoDB profile. The demo user and interface have not yet been created. Configure the final interface callback/logout URLs and required API integration when implementing it.

The current code and SAM template implement only the baseline: `UserBehaviorProfiles` and one authorizer with a strict any-anomaly-denies policy. They do not yet implement the extension's `BehaviorProfiles`, `SessionFlow`, or escalation logic. The binary policy is an explicit experimental choice, not a verified copy of the paper's scoring algorithm.

Before implementing the extension, revisit the telemetry source for application requests and confirm the then-current weights, thresholds, and session parameters. The original CloudTrail pipeline descriptions below are retained as requirements context, not proof that CloudTrail supplies custom API Gateway endpoint requests.

# Setup, deployment, and testing instructions
# ROLE & CONTEXT SETUP: Lightweight Zero Trust Access (LZTA) Framework

You are assisting with a Final Year Project building a serverless, two-stage Lightweight Zero Trust Access (LZTA) framework for Cloud API security on AWS. This extends the single-stage model by Vivek et al. (2025).

---

### 1. CORE ARCHITECTURE & DATA FLOW
The framework consists of 3 distinct pipelines:
1. **Offline Pipeline 1 (Behavioral Baselines):**
   `CloudTrail` -> `S3` -> `Lambda (process-behavioral-logs)` -> `DynamoDB (BehaviorProfiles)`
   - *Schedule:* Periodic batch processing (~5 min log delivery).
2. **Offline Pipeline 2 (Session Tracking - Decoupled):**
   `CloudTrail (asynchronous event trigger)` -> `Lambda` -> `DynamoDB (SessionFlow)`
   - *Schedule:* Per-request async processing. Decoupled from the authorization path.
3. **Online Pipeline (Real-Time Enforcement):**
   `API Gateway` -> `Lambda Authorizer 1 (Stage 1)` -> [If Escalated] -> `Lambda Authorizer 2 (Stage 2)` -> `Allow (200 OK) / Deny (403 Forbidden)`

---

### 2. TWO-STAGE EVALUATION LOGIC
- **Stage 1 (Long-Term Behavioral Profiling):**
  - Evaluates request against user's historical profile in `BehaviorProfiles`.
  - *Signals:* Unknown IP, off-hours access, unrecognized device/User-Agent, first-time high-privilege action.
  - *Outcomes:* Low risk -> Allow | High risk -> Deny | Mid-range -> Escalate to Stage 2.
- **Stage 2 (Short-Term Session Flow Analysis):**
  - Evaluates escalated requests against recent session metrics in `SessionFlow`.
  - *Signals:* Excessive call rate (bursts), out-of-sequence access, repeated sensitive endpoint calls, mid-session source IP changes.
  - *Outcomes:* Below threshold -> Allow | Above threshold -> Deny.

---

### 3. TECHNICAL STACK & CONSTRAINTS
- **Language & SDK:** Python 3.14.6, `boto3` v1.43.36, AWS CLI v2
- **Services:** AWS Lambda, Amazon API Gateway, Amazon DynamoDB, AWS CloudTrail, Amazon S3, Amazon CloudWatch
- **Rule-Based Design:** Completely serverless, low-cost (AWS Free Tier target), low-latency (<150ms budget), deterministic, and rule-based (no machine learning/heavy inference models).

---

### 4. DYNAMIC VARIABLES & TERMINOLOGY RULES
- **Variable Handling:** Risk scores, weight values (e.g., +50 for Unknown IP), flush intervals, and escalation thresholds are *empirical design parameters currently being tuned*. Do NOT hardcode or assume threshold numbers unless I explicitly state them in a specific task.
- **Strict Terminology:** Always use exact terms: `Stage 1`, `Stage 2`, `BehaviorProfiles`, `SessionFlow`, `Offline Pipeline 1`, `Offline Pipeline 2`, `Online Pipeline`, `Lambda Authorizer 1`, `Lambda Authorizer 2`.

---

### INSTRUCTIONS FOR ASSISTING ME:
1. Maintain consistency with this architecture across all code generation, IaC templates, schema designs, and write-ups.
2. Flag any request that contradicts these core design decisions.
3. Before generating code or thesis sections, ask clarifying questions if dynamic thresholds or specific sub-components are unspecified.

Acknowledge that you have ingested this context and are ready for the first task.
