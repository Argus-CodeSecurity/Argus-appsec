# Infrastructure scanning

Argus checks deployment and platform configuration as part of a normal scan, or
through focused commands when you only want one area.

## Commands

| Command | Scanners | What it checks |
|---------|----------|----------------|
| `argus cicd .` | `cicd` | GitHub Actions, GitLab CI, Jenkinsfile |
| `argus container .` | `container`, `iac` | Docker Compose, Dockerfiles, Kubernetes manifests |
| `argus cloud .` | `cloud`, `iac` | Terraform and CloudFormation (AWS, Azure, GCP) |
| `argus infrastructure .` | `cicd`, `container`, `cloud`, `iac` | All infrastructure checks in one pass |
| `argus inventory .` | (analysis only) | Export languages, deps, CI/CD, container, IaC file lists |
| `argus scan .` | all | Includes infrastructure plus SAST, secrets, dependencies, etc. |

Common flags (same on each focused command):

```bash
argus cicd . --fail-on high          # exit 1 for High+ findings (CI gate)
argus container . -o report.json     # JSON output
argus cloud . --quiet                # suppress progress lines
```

## CI/CD scanner (`cicd`)

Targets workflow files under `.github/workflows/`, `.gitlab-ci.yml`, and
`Jenkinsfile`.

Examples of what it flags:

- `pull_request_target` with checkout of untrusted PR code
- Mutable action references (`uses: org/action@main` instead of a commit SHA)
- Over-broad `permissions:` blocks
- Untrusted GitHub event fields interpolated into `run:` scripts
- Hardcoded secrets in workflow YAML
- `curl | bash` in pipeline steps

Example in CI:

```yaml
- name: CI/CD security
  run: argus cicd . --fail-on high --quiet
```

See also [ci-cd.md](ci-cd.md) for the full GitHub Action and SARIF integration.

## Container scanner (`container` + `iac`)

The `container` scanner focuses on Compose and Dockerfile extras (privileged
services, host networking, `:latest` tags, secret-like environment variables).

The `iac` scanner covers the same Dockerfiles plus Kubernetes YAML and base
Terraform resource rules. `argus container` runs both so you get one command for
container posture.

Examples:

- Compose `privileged: true` or `network_mode: host`
- `image: nginx:latest` without a digest
- Dockerfile `ENV PASSWORD=...` committed in the image layer
- Kubernetes `privileged: true`, `runAsNonRoot: false`, `hostNetwork: true`

**Live cluster assessment** (running pods, RBAC, exposed services) is **not** in
the open-source core. That ships in the commercial `argus-k8s` add-on as
`argus cluster`.

## Cloud scanner (`cloud` + `iac`)

Static analysis of infrastructure-as-code. No cloud API credentials are used;
Argus reads files in the repository.

Examples:

- Security groups or firewall rules open to `0.0.0.0/0`
- Public S3 ACLs or disabled public access blocks
- Unencrypted RDS or storage
- IAM policies with `Action: *` on `Resource: *`
- Azure `allow_blob_public_access = true`
- GCP bucket bindings for `allUsers`

Read-only cloud API connectors (live AWS, Azure, and GCP posture) ship as commercial
add-ons: `argus cloud-live`, `argus cloud-live-azure`, and `argus cloud-live-gcp`.
Static IaC scanning stays in the open-source core.

## Tuning in `.argus.yml`

Focused commands honor project config for excludes and severity floors:

```yaml
min_severity: low
exclude_paths:
  - vendor/
  - "**/fixtures/**"
scanner_options:
  iac:
    # reserved for future per-scanner knobs
```

To run only infrastructure scanners in a full scan:

```bash
argus scan . -s cicd,container,cloud,iac
```

## Repository layout

If you maintain both the open-source core and commercial add-ons locally, see
[project-layout.md](project-layout.md) and [repository-split.md](repository-split.md).
