# Historical context — superseded by the user's single-authorizer paper replication request

This file is archived for reference, not the current implementation specification.

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
