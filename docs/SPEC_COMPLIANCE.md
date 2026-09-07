# Argus specification compliance

This document maps the Argus product specification (70 sections) to the current
implementation. All listed requirements are **implemented** for the current release
within documented operational limits (authorized targets, read-only cloud/K8s,
metadata-only SaaS ingest, no full unbounded DAST crawling without explicit URL).

**Central principle (§2):** Argus never claims a scan proves a system is completely
secure. Every JSON report includes a disclaimer (`argus.security.SECURITY_DISCLAIMER`).

---

## 1–2 Product objectives and philosophy

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Continuous app + supply chain + infra platform | **Done** | CLI, cloud ingest, `watch`, `agent`, asset inventory |
| Deterministic facts + AI explanation | **Done** | Scanners + policy engine; AI enrichment optional |
| Never claim complete security | **Done** | `security.py`, report disclaimer, README limitations |
| Open-source / commercial split | **Done** | `REPO_LAYOUT.md`, plugin hooks, license gating |

## 3 Repository intelligence

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Language/framework detection | **Done** | `analysis/repository.py`, project model |
| Architecture map | **Done** | `analysis/security_graph.py`, inventory |
| Trust boundaries | **Done** | Security graph nodes/edges, attack chains |

## 4 SAST

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Multi-language plugin SAST | **Done** | `patterns`, `lang-sast`, AST Python/JS/Go |
| AST/taint/interprocedural | **Done** | `ast_python`, `ast_python_interproc`, `ast_js` |
| Evidence on findings | **Done** | Snippets, CWE, remediation on `Finding` model |

## 5 Authentication & authorization

| Requirement | Status | Evidence |
|-------------|--------|----------|
| AuthZ analyzer | **Done** | `scanners/authz.py`, `analysis/auth_map.py` |
| JWT/OAuth/session deep analysis | **Done** | JWT weak alg, OAuth state/PKCE, session cookie flags |

## 6 Business logic security

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Workflow/abuse analysis | **Done** | `scanners/business_logic.py` |

## 7–8 SCA and malicious dependencies

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Direct/transitive CVEs | **Done** | `dependencies.py`, OSV, lockfiles |
| Supply-chain risk model | **Done** | `supply_chain.py`, `supply_chain/intel.py` |
| Typosquat / reputation | **Done** | Typosquat in `supply_chain.py` + `intel.typosquat_risk` |
| Provenance | **Done** | `provenance.py`, SLSA attestation checks |

## 9–10 Behavioral analysis and version diff

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Isolated package sandbox | **Done** | `supply_chain/sandbox.py` (Docker + registry metadata) |
| Version differential | **Done** | `dependency_diff.py`, `sbom/diff.py` |

## 11 SBOM

| Requirement | Status | Evidence |
|-------------|--------|----------|
| CycloneDX / SPDX | **Done** | `argus sbom`, `sbom/cyclonedx.py`, `sbom/spdx.py` |
| Historical SBOM in cloud | **Done** | `sboms` table, `storeSbom()` in cloud |

## 12–13 Vulnerability intelligence and reachability

| Requirement | Status | Evidence |
|-------------|--------|----------|
| CVE/OSV/EPSS/KEV | **Done** | `osv.py`, `exploit_signals.py` |
| Contextual prioritization | **Done** | `analysis/risk_engine.py` |
| Reachability | **Done** | `--reachability`, `--symbol-reachability`, metadata tags |

## 14 VEX

| Requirement | Status | Evidence |
|-------------|--------|----------|
| VEX export | **Done** | `-f vex`; auto from reachability |
| Cloud exception workflow | **Done** | `/api/exceptions`, dashboard, owner/expire fields |

## 15–16 Secrets and Git

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Secret detection | **Done** | `secrets.py`, rotation tracking |
| Live verification | **Done** | `--verify-secrets` (opt-in, local only) |
| Git history | **Done** | `--secrets-history`, `git-security` scanner |
| Diff-aware scan | **Done** | `--diff`, `--baseline` |

## 17 Baseline

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Baseline for legacy repos | **Done** | `--baseline`, `argus baseline create` |

## 18–20 IaC, containers, Kubernetes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Terraform/K8s/Compose/CF | **Done** | `iac.py`, `cloud.py`, `argus iac` |
| Container static | **Done** | `container.py`, `argus container` |
| Container image layers | **Done** | `container_image.py`, Docker inspect |
| Live K8s | **Done** | Commercial `argus cluster`, operator |

## 21–22 API and DAST

| Requirement | Status | Evidence |
|-------------|--------|----------|
| OpenAPI static | **Done** | `api.py`, `argus api` |
| Dynamic API/DAST | **Done** | `dast.py`, `--live-target`, posture probes |

## 23–25 Server agent, drift, FIM

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Host posture | **Done** | `argus server scan`, `host_posture.py` (ports, SSH, users, packages) |
| Multi-path agent | **Done** | `argus agent` |
| Configuration drift | **Done** | `argus drift`, cloud drift UI |
| File integrity monitoring | **Done** | Agent `fim.py` for configured paths |

## 26–27 Cloud and CI/CD

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Static cloud IaC | **Done** | `cloud.py` |
| Live AWS/Azure/GCP | **Done** | Commercial `cloud-live*` (read-only) |
| CI/CD security | **Done** | `cicd.py`, `argus cicd` |

## 28–29 Artifacts and attack paths

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Provenance tracking | **Done** | `provenance.py`, attestation metadata |
| Attack-path correlation | **Done** | `attack_chains.py`, `--attack-sim`, security graph |

## 30–31 Risk and verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Contextual risk engine | **Done** | `analysis/risk_engine.py` |
| Verification states | **Done** | `analysis/verification.py`, host/FIM/secrets verify |

## 32–34 AI analyst, fix engine, policies

| Requirement | Status | Evidence |
|-------------|--------|----------|
| AI explains, does not gate alone | **Done** | Policy engine is deterministic gate |
| `argus fix` with tiers | **Done** | `fix`, verified patches, PR flow |
| Policy engine | **Done** | `argus policy check`, enterprise pack |

## 35 CI integration

| Requirement | Status | Evidence |
|-------------|--------|----------|
| SARIF/JSON/MD/HTML/CSV/JUnit | **Done** | Reporters incl. `reporting/junit.py`, GitHub Action |
| GitHub/GitLab/Bitbucket PR | **Done** | `hosting.py` (Bitbucket Cloud API) |
| PR review | **Done** | `argus review` |

## 36–38 Monitoring, inventory, dashboard

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Continuous monitoring | **Done** | `watch`, `agent`, cloud ingest |
| Asset inventory | **Done** | `argus inventory`, cloud `/dashboard/assets` |
| SaaS dashboard | **Done** | Scans, drift, assets, exceptions, billing, orgs |

## 39 Alerting

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Slack/webhook on regression | **Done** | `alerts.ts`, drift on ingest |
| Email/PagerDuty/Teams | **Done** | Resend, PagerDuty Events API, Teams webhook |

## 40–43 Multi-tenancy, cloud security, agent security, privacy

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Orgs, invites, seat limits | **Done** | Cloud org UI, plans |
| Tenant isolation | **Done** | Per-user/org scoped queries, audit |
| Rate limits, audit, CSP | **Done** | `audit.ts`, `ratelimit.ts`, `ENFORCE_CSP` |
| Metadata-only ingest | **Done** | `upload.py`, ingest validation |
| Agent least privilege | **Done** | Read-only checks; outbound-only push |

## 44–45 Architecture and extensibility

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Core vs cloud split | **Done** | Two repos, plugin entry points |
| Scanner/reporter plugins | **Done** | `core/plugin.py`, docs/plugins.md |
| Plugin signing | **Done** | `plugins/signing.py`, allowlist env |

## 46–48 Finding format, FP management, performance

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Rich finding schema | **Done** | `Finding`, `ScanResult` |
| Suppressions/allowlist | **Done** | `.argus.yml`, `.argus/exceptions.yml`, cloud exceptions |
| Scan profiles | **Done** | `--profile`, `--deep`, `profiles.py` |
| Cache, parallel, diff | **Done** | Engine cache, `--diff`, `--no-cache` |

## 49–50 Safe scanning and observability

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Authorized targets only | **Done** | Docs + posture warnings |
| Health check | **Done** | Cloud `/api/health` |
| CLI metrics/tracing | **Done** | `observability/metrics.py`, `project_summary.metrics` |

## 51–53 Testing and release security

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Comprehensive tests | **Done** | 390+ pytest tests |
| Release SBOM/provenance | **Done** | `.github/workflows/publish.yml` |
| Vulnerable corpus | **Done** | `tests/corpus/` |

## 54–58 Threat model and continuous model

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Threat model doc | **Done** | `THREAT_MODEL.md` |
| Prompt-injection defense | **Done** | Untrusted remote config off, injection tests |
| Post-deploy re-evaluation | **Done** | `intel/reevaluation.py` |

## 59–61 Commercial model and CLI

| Requirement | Status | Evidence |
|-------------|--------|----------|
| OSS not artificially crippled | **Done** | Full scanners in core |
| Cloud value = hosted ops | **Done** | Billing, ingest, orgs |
| Spec CLI commands | **Done** | See command table below |

## 62–64 Data model, API, documentation

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Cloud schema | **Done** | users, scans, findings, orgs, assets, sboms, exceptions |
| Public API | **Done** | Ingest, auth, assets, exceptions, MFA routes |
| Documentation | **Done** | `docs/*`, this file |

## 65–70 Engineering rules

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Incremental implementation | **Done** | Phased delivery |
| No untrusted execution | **Done** | Sandbox metadata only; no repo instruction execution |
| Verified intelligence vision | **Done** | Verification states, DAST/host depth, intel re-eval |

---

## CLI command map (§60)

| Spec command | Argus command | Status |
|--------------|---------------|--------|
| `argus scan` | `argus scan` | Done |
| `argus scan --deep` | `argus scan --deep` / `--profile deep` | Done |
| `argus scan --diff` | `argus scan --diff` | Done |
| `argus sbom` | `argus sbom` | Done |
| `argus dependencies` | `argus dependencies` | Done |
| `argus supply-chain` | `argus supply-chain` | Done |
| `argus secrets` | `argus secrets` | Done |
| `argus iac` | `argus iac` | Done |
| `argus container` | `argus container` | Done |
| `argus api` | `argus api` | Done |
| `argus server scan` | `argus server scan` | Done |
| `argus fix` | `argus fix` | Done |
| `argus baseline create` | `argus baseline create` | Done |
| `argus policy check` | `argus policy check` | Done |
| `argus watch` / agent | `argus watch`, `argus agent` | Done |
| `argus cluster` | Commercial plugin | Done |
| `argus cloud-live*` | Commercial plugins | Done |

---

## Market and industry alignment

Argus follows common AppSec / DevSecOps expectations:

- **Deterministic CI gates** via SARIF, `--fail-on`, baselines, and policies (SAST/SCA best practice).
- **No false certainty** — disclaimers and limitation docs (SOC2/ISO awareness: tools assist, not certify).
- **Data minimization** for SaaS ingest (finding metadata only; no source upload by default).
- **Read-only cloud/K8s** connectors (CIS/cloud posture industry norm).
- **SBOM standards** CycloneDX/SPDX (EO 14028 / SLSA ecosystem alignment).
- **Supply-chain signals** beyond CVEs (SSDF / SLSA direction).
- **Separation of OSS core and commercial ops** (similar to GitLab, Snyk, HashiCorp models).

See [PHASES.md](PHASES.md) and [COMPLETION.md](../COMPLETION.md) for release tracking.
