# Recommended project layout

Argus uses an open-core model: one **public** tree and one **commercial** tree.

## Current layout (this workspace)

```
Argus Code/
  argus-appsec/                 # PUBLIC  - Apache-2.0 core
  argus-commercial/             # PRIVATE - proprietary products
    argus-k8s/                  # commercial CLI add-on
    argus-cloud/                # commercial SaaS
```

| Folder | Git remote | PyPI / deploy |
|--------|------------|---------------|
| `argus-appsec/` | Public GitHub `Argus-CodeSecurity/Argus-appsec` | `argus-appsec` on PyPI |
| `argus-commercial/` | Private git only | Private index or direct deploy |

## Two-repo model (recommended when pushing)

1. **`argus-appsec`** - only the Apache-2.0 tree (this folder's contents).
2. **`argus-commercial`** - `argus-k8s`, `argus-cloud`, internal runbooks.

Do not merge both into one public history.

## Push checklist

### Public (`argus-appsec`)

1. `cd argus-appsec && git init` (or clone the public remote)
2. `pytest`
3. Bump `pyproject.toml` version, update `CHANGELOG.md`
4. Tag release, push to GitHub, let CI publish PyPI

See [PUBLISHING.md](PUBLISHING.md) for the full list.

### Commercial (`argus-commercial`)

1. `cd argus-commercial && git init` (private remote only)
2. Confirm `.gitignore` excludes `keys/*.pem`, `.env`
3. Ship `argus-k8s` after the public core version it depends on is released
4. Deploy `argus-cloud` with secrets via the host (not git)

## What never crosses the boundary

| Never in `argus-appsec` | OK in `argus-commercial` |
|-------------------------|--------------------------|
| `argus_k8s` source | Full `argus-k8s` package |
| `argus-cloud` app | Full SaaS codebase |
| License signing private key | `keys/signing_private_key.pem` (gitignored) |

See [repository-split.md](repository-split.md).

## Local development

```bash
pip install -e ./argus-appsec[dev]
pip install -e ./argus-commercial/argus-k8s --no-deps
cd argus-commercial/argus-cloud && npm install && npm run dev
```
