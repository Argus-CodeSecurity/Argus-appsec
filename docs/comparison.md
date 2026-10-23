# How Nephilex compares

Nephilex is not trying to beat every specialist at its own game. The tools
below are excellent, and if one of them is your whole problem, use it. Nephilex's bet
is different: **one tool across the domains, that explains and fixes, and keeps
your code on your machine.** Here is the honest version.

## Where the specialists are stronger

| Tool | What it is genuinely better at |
| --- | --- |
| **Semgrep** | A huge, battle-tested SAST rule ecosystem and community rules; deep per-language coverage; a mature registry. If SAST rule breadth is the whole job, Semgrep leads. |
| **Trivy** | Container and image scanning, a mature and fast SCA, wide adoption, and a large maintainer team. For container-first workflows it is the default. |
| **Snyk** | A large curated vulnerability database, first-class IDE and PR integrations, developer UX, and enterprise features (SSO, reporting, policies). |
| **GitGuardian / TruffleHog** | Dedicated secrets coverage, real-time monitoring, and validated detectors at scale. |

Nephilex does not out-feature these in their home turf, and it says so.

## Where Nephilex is different

| Property | Nephilex | Typical specialist |
| --- | --- | --- |
| **Domains in one pass** | Secrets, SCA, SAST, taint, IaC, and LLM together, one severity model, one report | Usually one or two domains; you stitch several tools together |
| **Explanation** | Every finding: why, attacker path, business impact, CWE/OWASP | Often a rule id and a line number |
| **Fixes** | Deterministic, self-verified fixes that open a PR | Varies; many stop at detection |
| **AI / LLM coverage** | First-class OWASP-LLM-Top-10 scanner | Emerging or absent |
| **Privacy** | Offline by default; code never leaves the machine unless you opt into a cloud model | Often cloud-first |
| **Model** | Open-source core (Apache-2.0), self-hostable | Often proprietary / SaaS |

## When to choose Nephilex

- You want **one tool** across code, dependencies, secrets, IaC, and AI, instead
  of five dashboards and five bills.
- You want findings your developers will actually act on, because each one is
  **explained and often comes with the fix**.
- You are building **AI/LLM-heavy applications** and want that class of risk
  covered in the same pass.
- You need the scanner to run **offline / self-hosted** for privacy or
  compliance reasons.

## When to choose something else

- You need the deepest possible SAST rule coverage for one language today:
  reach for Semgrep.
- Your problem is container images and registries at scale: reach for Trivy.
- You need enterprise ASPM (SSO, policy engine, ticketing, dashboards) right now:
  a commercial platform will serve you better while Nephilex matures.

Honest positioning is the point. Nephilex is a strong, unified, explainable,
self-hostable scanner and fixer, in early alpha, that is especially good for
AI-era codebases. Pick the tool that fits the job.
