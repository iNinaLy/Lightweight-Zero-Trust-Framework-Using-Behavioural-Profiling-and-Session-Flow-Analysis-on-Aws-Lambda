# Document portal

Historical implementation notes: the user subsequently selected an HR/payroll scenario on 2026-10-21. The live frontend is now [Northstar People](hr_portal.md) on the same Site and AWS stack. The document API and its stored data remain available for compatibility; document management is no longer the website's main interface. The checks and counts below describe the earlier document version.

Created at the user's request on 2026-10-21, bringing the document application forward from the earlier interface-after-Stage-2 plan.

Site: https://lzta-document-workspace.divine-crab-2107.chatgpt.site

The Site is owner-private. This outer hosting access check is separate from Cognito application sign-in. The frontend source and Sites repository are in `sites/lzta-document-portal`; `.openai/hosting.json` retains its Site identity. No connector or repository credential is included in the source.

## Implemented behaviour

- Browser sign-in through the existing Cognito pool/client, authorization code with S256 PKCE, state, and nonce. Callback code is removed from the address bar before token exchange. Tokens are held in tab session storage, never embedded in source or printed.
- The website root is the sign-in and sign-out destination. `https://localhost` remains an allowed callback for the earlier interactive helper. Existing Cognito settings were preserved during the update.
- Owner-scoped document list, upload, rename, download, and permanent delete. Files are limited to 1 MB and stored in private encrypted S3. Metadata and mutation activity are stored in DynamoDB. All document operations, including download, pass through the authorizer; no public or presigned object links bypass it.
- Search, category filtering, sorting, document pagination, and the latest 100 mutation activities. Activity pagination is available from the API; the initial interface displays only the latest page.
- Session/access view returns the authenticated user's actual API-observed context and strict baseline decision. The session endpoint verifies the JWT itself, returns only that user's context, and never enrolls or updates profiles. Signing in is not sufficient to access documents.
- Application activity is distinct from CloudTrail. Successful document requests emit application logs; authorizer decision logs also record denied attempts. No `SessionFlow` or Stage 2 logic is claimed.

## AWS isolation

`infrastructure/portal.yaml` defines a separate `lzta-document-portal` stack containing:

- A REST API with an uncached REQUEST authorizer and CORS limited to the website origin, including error responses.
- Separate authorizer, session, and document Lambdas, each allocated 512 MB.
- Separate `PortalProfiles`, document metadata/activity table, and private document bucket.
- Narrow IAM permissions for profile reads and document storage operations, and 14-day log retention.

The existing baseline stack, its identity mapping, and its learned profiles are not replaced. Deploying the portal does not start CloudTrail. No trail is created in the portal stack. File and table resources have retain policies. The separate private artifact bucket is retained outside the stack; its name is recorded in the ignored deployment report.

`tools/deploy_portal.py --origin <site-origin>` deploys this stack and updates the browser's public `config.json`. It reuses the verified Linux dependency bundle from the existing baseline Lambda, checks the pinned boto3 and PyJWT versions, and replaces the Python application modules with local source. It does not package Windows native crypto wheels. After changing backend source, rerun this helper; frontend changes require the normal Sites source/package/publication workflow. The helper does not reconfigure Cognito or reseed profiles on redeployment.

## Initial demonstration data

The configured existing Cognito subject maps to a distinct synthetic portal identity. The initial portal profile is explicitly marked `synthetic: true` and described as a seeded demonstration fixture. It contains the last API-observed client IP, two historically observed browser User-Agents, approved portal actions, and an illustrative 08:00–23:59 Malaysia-time window. This is neither learned application history nor the planned human-like multi-person dataset. All CRUD actions, including the sensitive delete action, have an initial approved observation for the demo.

Three clearly labelled demonstration documents were uploaded by an operator. A separate temporary document was used for live storage lifecycle verification and removed. The recorded operator-generated activity is setup activity, not evidence of real users' routines.

If a legitimate browser receives a denial, the session view reports the server-observed IP, User-Agent, UTC hour, and anomaly reasons. A trusted operator can adjust the isolated experiment fixture deliberately; the application never automatically trusts unfamiliar requests. Real account profiles should not be changed to make a demo pass.

## Verification and limits

- 29 local tests pass, including file lifecycle, cross-owner denial, upload validation, pagination isolation, and session authentication requirements. Infrastructure lint and browser JavaScript syntax checks pass.
- Deployed document Lambda successfully performed upload, rename, download, and delete with real S3/DynamoDB storage. This direct invocation verified the runtime and storage, independently of API authorization.
- Live API preflight returns 200 with the expected origin. Missing session token returns 401; an invalid document token returns 403. Both error responses include CORS headers.
- Edge desktop rendering and mobile layout/navigation passed. Browser-only API fixtures exercised document rendering, search, upload, rename, delete, and activity, with zero runtime exceptions. These fixtures were injected only into the local QA browser and are not deployed.
- End-to-end browser Cognito sign-in and subsequent protected document operations require the user's interactive sign-in and were not independently completed by the agent. They must not be conflated with the earlier CLI Allow/Deny smoke test.
- No shared-document permissions, administrator role, document preview, automatic baseline learning, weighted baseline, Stage 2, or experiment comparison dashboard is implemented by this portal.
