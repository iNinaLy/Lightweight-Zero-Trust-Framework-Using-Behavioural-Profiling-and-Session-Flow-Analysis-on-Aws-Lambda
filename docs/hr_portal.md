# Northstar People: synthetic HR & payroll portal

Historical employee self-service version. On 2026-10-21 the user explicitly requested replacing the whole interface with an HR-staff confidential-data target. The current live site is the [HR operations console](hr_console.md); the self-service screens below are no longer in the website navigation. Their backend routes/data are retained for compatibility and regression checks.

The user selected this application scenario on 2026-10-21 to demonstrate credential-theft and insider-threat experiments through meaningful employee interactions. It replaces the document workspace's frontend on the same private Site:

https://lzta-document-workspace.divine-crab-2107.chatgpt.site

The Site ID, URL, audience, Cognito client, callback, and AWS stack identity are preserved. Sign-in returns to the website. `https://localhost` remains registered for the earlier CLI helper.

## Employee functions

| Screen | Working behaviour |
| --- | --- |
| Overview | Actual synthetic employee record, approved-leave balance, latest payslip summary, pending leave count, upcoming leave, and recorded HR activity |
| My payslips | Owner-scoped monthly summaries, detailed earnings/deductions, and a generated PDF download through the authorizer |
| Time off | Create and list requests; edit or cancel only your own Pending requests; filter by status |
| Company policies | Protected list and policy reader for fictional working arrangements, leave, payroll, and information security |
| My profile | Read-only employment details for the authenticated employee |
| Session & access | Actual API-observed context, strict baseline outcome, and this tab's API response history |

No frontend payroll/employee editor or manager approval role is provided. Employees cannot supply a different owner, change pay, or self-approve leave. New requests always start Pending; approved/cancelled records cannot be edited or cancelled again. Cancellation preserves the request and activity history. Conditional writes reject conflicting leave updates.

The annual leave allowance and used balance are synthetic fixture values. Pending requests do not reserve or reduce the displayed balance; this version does not enforce quota reservations or overlapping-request rules. Weekdays are counted; public holidays and half-days are not modelled. Dates for new/updated requests must be today or later in Malaysia time. Manager approval remains outside this employee demonstration.

## Data and authorization

`src/lzta/hr.py` handles the employee routes via the existing portal Lambda. All payroll and leave lookups use the principal from API Gateway's verified authorizer context as their DynamoDB owner partition. Client-supplied employee identities are never used to select another employee's records.

`infrastructure/portal.yaml` adds:

- `GET /employee`
- `GET /payslips`
- `GET /payslips/{payslipId}`
- `GET /payslips/{payslipId}/download`
- `GET /policies` and `GET /policies/{policyId}`
- `GET /leave-requests` and `POST /leave-requests`
- `PATCH /leave-requests/{leaveId}` and `DELETE /leave-requests/{leaveId}`

Each route has a distinct `hr:*` action mapping. Payroll listing, detail viewing, and download are configured as sensitive actions. The session endpoint checks common context against `hr:ViewEmployee`; an Allow there does not promise that every sensitive payroll action is familiar. Detailed payroll amounts are omitted from list responses and fetched through the protected detail route. PDF downloads are generated from that employee's synthetic record and pass through the authorizer; no public object URL bypasses authorization.

Application requests emit structured activity logs. Payroll views/downloads and leave mutations also create owner-scoped activity records. These are application observations, not CloudTrail events. `SessionFlow`, Stage 2, weighted scores, and session-hijacking detection are not implemented or claimed. The interface explicitly marks Stage 2 as planned.

## Fixtures and deployment

`tools/seed_hr_demo.py` provisions one fictional employee (Aisha Rahman), three completed monthly payslips, one historical approved annual-leave record, and one upcoming Pending record for each configured demonstration identity. Every fixture is marked synthetic. All amounts and deductions are illustrative, not actual salary or statutory/tax calculations.

The seeder preserves existing records, including leave edits/cancellations on repeated runs. It explicitly adds approved HR-action observations to the existing **synthetic portal** behaviour profile; it does not change its IP, User-Agent, or hour sets and does not touch real-account profiles. This is fixture provisioning, not automatic learning or the planned multi-person routine generator.

```powershell
python tools/deploy_portal.py --origin https://lzta-document-workspace.divine-crab-2107.chatgpt.site
python tools/seed_hr_demo.py
```

Backend changes deploy to the same isolated portal stack. Frontend changes use the Sites source/package/publication workflow for the retained `.openai/hosting.json` project ID. The baseline stack and stopped CloudTrail configuration are preserved. Legacy document routes/data are retained but no longer exposed in the main navigation.

## Validation

- 33 local tests pass. HR coverage includes cross-owner payroll/profile isolation, valid PDF output, restricted payroll detail responses, leave CRUD/state transitions, mass-assignment/self-approval rejection, date/input validation, policy access, and missing employee handling.
- Infrastructure lint and JavaScript/module syntax checks pass.
- Local Edge tests pass for signed-out navigation, mobile layout/navigation, the employee dashboard/profile, payslip detail and download controls, leave create/edit/cancel/filter flows, and the policy reader, with no runtime exceptions. Authenticated browser tests use explicitly injected local fixtures, never deployed mock APIs.
- Direct deployed-Lambda checks pass for employee/payslip/policy reads, generated PDF, cross-owner denial, leave create/edit/cancel, and rejected self-approval. The temporary verification request remains Cancelled for audit purposes.
- Live API CORS preflight succeeds on leave routes; an invalid payroll token receives 403 with CORS headers.
- Real browser Cognito sign-in and authenticated API usage require the user's interactive sign-in. Direct Lambda tests and local browser fixtures do not substitute for that end-to-end check.

The original versioned seed-2026 synthetic baseline dataset is unchanged. These UI fixtures are not an accuracy dataset, and the smoke checks do not establish detection accuracy or latency distributions.
