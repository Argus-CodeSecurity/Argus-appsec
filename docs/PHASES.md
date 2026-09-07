## Phase 4 - Continuous operations

| Item | Status |
|------|--------|
| Static asset inventory (`argus inventory`) | done |
| Configuration drift (`argus drift`) | done |
| Local continuous monitoring (`argus watch`) | done |
| Scan drift in SaaS UI | done |
| Server agent (`argus agent`) | done |
| Host posture (`argus server scan`) | done |
| File integrity monitoring (agent) | done |
| Scan profiles (`--profile`, `--deep`) | done |

## Phase 5 - Argus Cloud SaaS

| Item | Status |
|------|--------|
| Accounts + auth | done |
| Stripe billing | done |
| License issuance (Ed25519) | done |
| Scan ingest (`argus push`) | done |
| Dashboard + history | done |
| Organizations | done |
| Password reset flow | done |
| Email verification | done |
| CSP enforce toggle (`ENFORCE_CSP=1`) | done |
| Team invites | done (with seat limits) |
| Slack/webhook alerts on drift | done |
| Enterprise policy packs | done (`examples/policies/enterprise.yml`) |

## Commercial add-ons

| Package | Command | Status |
|---------|---------|--------|
| `argus-k8s` | `argus cluster` | done |
| `argus-cloud-aws` | `argus cloud-live` | done |
| `argus-cloud-azure` | `argus cloud-live-azure` | done |
| `argus-cloud-gcp` | `argus cloud-live-gcp` | done |
