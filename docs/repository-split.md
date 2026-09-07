# Open source vs commercial split

Argus uses an **open-core** model. One public codebase (`argus-appsec`) and separate commercial packages you host and license yourself.

## Public repository (`Argus-appsec`)

**Push everything under the open-source project root** except local-only secrets.

| Include | Exclude |
|---------|---------|
| `src/argus/` | Any copy of `argus_k8s` or `argus-cloud` |
| `tests/`, `docs/`, `examples/` | `.env`, API keys, license signing private keys |
| `.github/workflows/` | Customer-specific license files |
| `README.md`, `LICENSE`, `THREAT_MODEL.md` | Paths listed in `.argus.yml` `exclude_paths` for dogfooding only |

The CLI exposes extension points so commercial code never needs to ship inside Apache-2.0:

- `argus.plugins` entry point (scanners, reporters, AI providers)
- `argus.commands` entry point (extra CLI commands, e.g. `argus cluster`)

## Commercial (private)

| Product | Purpose | Distribution |
|---------|---------|--------------|
| `argus-k8s` | Live Kubernetes cluster read-only assessment | Private PyPI or tarball + license file |
| `argus-cloud` | Accounts, billing, license issuance, scan history UI | Your SaaS deployment |

**Rule:** If commercial source is committed to the public repo, it becomes Apache-2.0 forever. Keep commercial code in a **private** remote (`argus-commercial/`). See [project-layout.md](project-layout.md) and [PUBLISHING.md](PUBLISHING.md).

## What customers install

**Free / open source:**

```bash
pip install argus-appsec
argus scan ./my-app
```

**Paid CLI add-on:**

```bash
pip install argus-appsec argus-k8s
export ARGUS_LICENSE="<token-from-argus-cloud>"
argus cluster
```

**Hosted platform:** customers use the web app for billing and license copy; optional `argus push` sends finding metadata (not source code) to `/api/scans`.

## Publishing checklist (open source)

1. Run tests: `pytest`
2. Bump version in `pyproject.toml`
3. Tag release on GitHub
4. CI publishes to PyPI and attaches SBOM
5. Verify paid add-ons still install against the new core version

## Publishing checklist (commercial)

1. Release `argus-appsec` first (core API stable)
2. Build and ship `argus-k8s` with updated public key if rotated
3. Deploy `argus-cloud`; run migrations; verify Stripe webhook + license issuance
4. Never commit `ARGUS_LICENSE_PRIVATE_KEY` or Stripe live keys to git
