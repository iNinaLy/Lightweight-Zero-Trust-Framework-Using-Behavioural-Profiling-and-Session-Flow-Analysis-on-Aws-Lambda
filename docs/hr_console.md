# Northstar HR: confidential-data target

The user explicitly replaced the whole employee self-service website with an HR-staff console on 2026-10-21. Its purpose is to provide a broader confidential-data target for the LZTA experiment rather than a full production HR system.

Site: https://lzta-document-workspace.divine-crab-2107.chatgpt.site

The Site identity, owner-private audience, Cognito client/callback, and isolated AWS stack are preserved. No additional real users or AWS IAM roles are created. All personnel cases, payment details, tax identifiers, addresses, and salary figures are fictional. Account/identity fields use deliberately invalid `DEMO-*` placeholders. Payroll figures are illustrative, not real statutory calculations.

## Current screens

- HR overview: actual counts and gross payroll totals from the protected synthetic register.
- Payroll register: company-wide gross/net salaries, search, department filter, and links to confidential employee files.
- Employee records: employment details, synthetic identity/tax values, fictional home address, bank account placeholders, and payroll deductions.
- Restricted reviews: synthetic ratings, confidential management notes, fictional coaching/disciplinary cases, and background-screening placeholders.
- Protected full-register CSV export: explicit confirmation, separate sensitive-action mapping, backend role check, and recorded export audit. The export includes the entire register, independently of client-side search/filter state, and the confirmation says so. CSV formula injection is neutralized.
- Access audit: latest 100 actual HR-service reads, exports, and role denials, without copying confidential payroll field values into the log.
- Session & access: separate current context/HR-role decisions and actual API responses for the current tab. Stage 2 is clearly labelled planned.

There is no employee self-service navigation or payroll/role editor. Legacy document/self-service routes and data are retained for regression compatibility; the frontend is exclusively the HR operations console.

## Independent authorization requirements

API Gateway's uncached Lambda authorizer verifies the token, resolves the configured identity, and applies the existing strict binary behavioural baseline. All confidential actions have distinct `hr:*` mappings and are configured as sensitive actions.

`src/lzta/hr_confidential.py` then reads the trusted actor record (`ownerId = authenticated principal`, `entryId = employee#profile`) consistently from DynamoDB. It requires `portalRole == hr` before querying any shared company confidential records. A familiar employee is denied; an HR role does not bypass the authorizer. Headers, query strings, and request bodies cannot grant roles. No HTTP role-assignment endpoint is exposed, and the role lookup is not cached.

`GET /session` verifies the JWT itself, then returns only the caller's role and context outcome. It does not expose confidential company records and does not enroll or modify profiles. The UI enables confidential work only if both the role and current context are permitted; the server independently enforces every confidential request. The session context check does not guarantee that every separately sensitive action is familiar.

Shared confidential rows use the fixed internal partition `hr#synthetic-company`. Authenticated employee endpoints cannot choose that partition or mutate operator role records.

| Route | Action | Purpose |
| --- | --- | --- |
| `GET /api/v1/hr/summary` | `hr:ViewCompanySummary` | Company payroll totals/counts |
| `GET /api/v1/hr/payroll` | `hr:ViewPayrollRegister` | Company register, excluding full identity/payment fields |
| `POST /api/v1/hr/payroll/export` | `hr:ExportPayroll` | Full synthetic confidential CSV |
| `GET /api/v1/hr/employees/{employeeId}` | `hr:ReadEmployeeRecords` | Confidential payment/identity/personnel detail |
| `GET /api/v1/hr/reviews` | `hr:ListConfidentialReviews` | Restricted review summaries |
| `GET /api/v1/hr/reviews/{employeeId}` | `hr:ReadConfidentialReview` | Full confidential review/case |
| `GET /api/v1/hr/audit` | `hr:ViewAudit` | HR-service audit |

## Explicit fixture provisioning

```powershell
python tools/deploy_portal.py --origin https://lzta-document-workspace.divine-crab-2107.chatgpt.site
python tools/seed_hr_console.py --grant-demo-hr
```

The seeder creates 16 employee records and 16 review records without overwriting existing fixtures. It explicitly grants the existing isolated synthetic demo account the application HR role and display identity Sarah Tan / HR Operations Lead. This is an application role, not an AWS IAM role. The stored earlier employee profile is otherwise preserved.

The seeder adds approved observations for the new confidential actions only to the existing synthetic portal behaviour profile. It preserves IP, device, and access-hour sets and never edits real-account profiles. This is deliberate demo setup, not automatically learned human behaviour. Running the role-grant command again explicitly regrants the HR role, so it is not part of a normal user's workflow.

The original seed-2026 labelled dataset is unchanged. New company fixtures are not an accuracy dataset.

## Recorded verification

- 40 local tests pass. New coverage verifies all confidential routes reject employee roles (including forged role headers/body), missing/revoked HR roles fail closed, HR access works, full export contents are synthetic, CSV injection protection, and audit coverage. A combined authorization-path test verifies matching HR allowed, matching employee denied by role, and unfamiliar-IP HR denied by behaviour.
- A session test verifies matching behaviour can return Allow while independently returning `roleAllowed: false` for an employee.
- SAM infrastructure lint and browser module syntax checks pass.
- Local Edge browser checks pass for HR-only navigation, dashboard, mobile layout, payroll search/department filtering, confidential files, reviews, export confirmation/download request, audit, and separate role/context denial views. These authenticated browser checks use injected local fixtures, not deployed mock APIs.
- Direct deployed-Lambda verification reads the real 16-row synthetic company register, confidential employee/review detail, and full CSV. A temporary isolated employee-role fixture is denied on all seven confidential routes despite a forged HR-role header, then removed. Its audit records remain explicitly marked as operator verification.
- Live API export preflight succeeds; an invalid token receives 403. CORS is verified on both paths.

Direct Lambda verification uses trusted operator-supplied event contexts and is distinct from a real Cognito-authenticated API/browser run. Real browser sign-in still requires the user's interaction. The HR audit covers requests reaching the HR service; earlier behavioural denials remain in authorizer logs. It is not a complete account-wide security audit.

No weighted scores, Stage 2, burst detection, automatic role escalation, real payroll processing, or regulatory compliance certification is implemented or claimed. CloudTrail remains stopped, and the original baseline stack/identity mapping are preserved.
