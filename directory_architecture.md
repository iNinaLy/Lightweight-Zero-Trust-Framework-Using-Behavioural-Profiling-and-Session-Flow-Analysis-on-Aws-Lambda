# Directory architecture

```text
lzta-framework/
├── .github/workflows/validate.yml       # Unit/integration tests, IaC lint, synthetic scenarios
├── infrastructure/
│   ├── template.yaml                   # SAM: CloudTrail, S3, DynamoDB, Lambdas, API, analytics
│   └── samconfig.toml                  # Build/deployment settings
├── src/
│   ├── requirements.txt                # Lambda dependencies
│   └── lzta/
│       ├── __init__.py
│       ├── baseline.py                 # Offline gzip CloudTrail ingestion
│       ├── profiles.py                 # Feature extraction and transactional profile updates
│       ├── scoring.py                  # Strict binary anomaly checks
│       ├── identity.py                 # RS256 JWT verification
│       ├── authorizer.py               # Single online Allow/Deny authorizer
│       ├── logging.py                  # Structured JSON decisions
│       └── target.py                   # Protected demonstration endpoint
├── config/
│   ├── risk.json                       # Binary policy and example sensitive action
│   └── deployment.example.json         # Explicit identity/provider/account placeholders
├── database/
│   └── user_behavior_profiles.schema.json
├── tests/
│   ├── test_lzta.py                    # Rules, request enforcement, ingestion
│   └── test_integrations.py            # RSA JWT and emulated DynamoDB transactions
├── tools/
│   ├── simulate.py                     # Local synthetic scenario report
│   ├── benchmark.py                    # Opt-in live 30-request timing
│   └── deploy.py                       # Parameter validation, SAM build/deploy
├── reports/simulation.json             # Generated local results, not paper measurements
├── docs/
│   ├── infrastructure.md
│   ├── paper_replication.md
│   └── original_two_stage_context.md   # Preserved requirements for the planned two-stage FYP extension
├── requirements.txt                    # Runtime dependency entry point
├── requirements-dev.txt                # Runtime + test/lint tooling
└── README.md
```

This directory structure describes the current baseline only. The empty Stage 1/Stage 2 and SessionFlow placeholders were removed during baseline implementation; the two-stage design itself remains planned. Test the baseline using `UserBehaviorProfiles` first, then implement the extension with `BehaviorProfiles`, `SessionFlow`, and conditional escalation. See `docs/original_two_stage_context.md` for its preserved requirements.

Current policy: any anomaly denies. This is a strict binary experimental baseline inspired by the paper, not a verified copy of its unspecified scoring algorithm.
